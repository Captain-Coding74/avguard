"""Entry point: `python -m avguard` for the GUI, `--scan PATH` for the console.

The console mode exists so the scanner can be exercised without a display,
which is what makes it testable and scriptable.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import config, logsetup, scheduling
from .cloud import VirusTotalClient
from .instance import InstanceLock
from .protection import SelfProtection
from .quarantine import QuarantineError, QuarantineStore
from .scanner import Level, Scanner


def _console_scan(target: Path, quarantine_threats: bool, verbose: bool) -> int:
    logsetup.configure(level=logging.DEBUG if verbose else logging.INFO)
    logging.getLogger("avguard").addHandler(logging.StreamHandler(sys.stdout))

    cfg = config.Config.load()
    protection = SelfProtection()
    cloud = VirusTotalClient(cfg)
    scanner = Scanner(cfg, protection, cloud_lookup=cloud.reasons_for)
    store = QuarantineStore(protection=protection)

    if not scanner.rules:
        print("warning: YARA rules did not load; detection is reduced", file=sys.stderr)

    counts = {level: 0 for level in Level}
    threats = []

    def report(verdict) -> None:
        counts[verdict.level] += 1
        if verdict.level in (Level.MALICIOUS, Level.SUSPICIOUS):
            print(f"[{verdict.level.value.upper()}] {verdict.path}")
            for reason in verdict.reasons:
                print(f"    {reason}")
            if verdict.level is Level.MALICIOUS:
                threats.append(verdict)
        elif verbose:
            print(f"[{verdict.level.value}] {verdict.path}")

    scanner.scan_tree(target, on_verdict=report)
    cloud.save_cache()

    print()
    print(f"Examined : {sum(counts.values())} file(s)")
    print(f"Clean    : {counts[Level.CLEAN]}")
    print(f"Skipped  : {counts[Level.SKIPPED]}")
    print(f"Suspect  : {counts[Level.SUSPICIOUS]}")
    print(f"Threats  : {counts[Level.MALICIOUS]}")
    if counts[Level.ERROR]:
        print(f"Errors   : {counts[Level.ERROR]}")

    if threats and quarantine_threats:
        # Writing to the quarantine store needs the lock. Another AVGuard
        # holding it would otherwise rewrite the index from a stale snapshot
        # and destroy its records along with the user's originals.
        lock = InstanceLock()
        if not lock.acquire():
            print(
                f"\nAnother AVGuard is running (pid {lock.owner_pid or 0}).\n"
                "Nothing was moved: two processes writing to the quarantine\n"
                "store at once destroys its records. Close the other one\n"
                "and run this again.",
                file=sys.stderr,
            )
            return 2
        try:
            print()
            for verdict in threats:
                try:
                    store.quarantine(verdict.path, verdict.reasons)
                    print(f"quarantined: {verdict.path}")
                except QuarantineError as exc:
                    print(f"could not quarantine {verdict.path}: {exc}", file=sys.stderr)
        finally:
            lock.release()
    elif threats:
        print("\nNothing was moved. Pass --quarantine to act on these findings.")

    return 1 if threats else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="avguard", description="A small file scanner.")
    parser.add_argument("--scan", metavar="PATH", type=Path,
                        help="scan a file or folder in the console and exit")
    parser.add_argument("--quarantine", action="store_true",
                        help="with --scan, move anything detected into quarantine")
    parser.add_argument("--list-quarantine", action="store_true",
                        help="print the quarantine contents and exit")
    parser.add_argument("--export-all", metavar="DIR", type=Path,
                        help="write every quarantined file out to DIR and exit")
    parser.add_argument("--restore", metavar="ID",
                        help="restore one quarantined file by its id")
    parser.add_argument("--reload-rules", action="store_true",
                        help="recompile the rules and report what loaded")
    parser.add_argument("--schedule", choices=["status", "on", "off"],
                        help="start with Windows and run a daily scan")
    parser.add_argument("--schedule-path", metavar="DIR", type=Path,
                        help="folder for the daily scan (default: Downloads)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logsetup.install_excepthooks()
    config.ensure_directories()

    if args.list_quarantine:
        store = QuarantineStore(protection=SelfProtection())
        records = store.records()
        if not records:
            print("Quarantine is empty.")
            return 0
        for record in records:
            print(f"{record.entry_id}  {record.original_name}")
            print(f"    from    : {record.original_path}")
            print(f"    when    : {record.quarantined_at}")
            print(f"    reason  : {'; '.join(record.reasons) or '-'}")
        return 0

    if args.export_all:
        store = QuarantineStore(protection=SelfProtection())
        written = store.export_all(args.export_all)
        print(f"Wrote {len(written)} file(s) to {args.export_all}")
        for path in written:
            print(f"  {path.name}")
        if written:
            print("\nThese are the original, unmodified files. Handle them carefully.")
        return 0

    if args.restore:
        store = QuarantineStore(protection=SelfProtection())
        lock = InstanceLock()
        if not lock.acquire():
            print(f"Another AVGuard is running (pid {lock.owner_pid or 0}).", file=sys.stderr)
            return 2
        try:
            target = store.restore(args.restore)
        except QuarantineError as exc:
            print(f"Could not restore: {exc}", file=sys.stderr)
            return 1
        finally:
            lock.release()
        print(f"Restored to {target}")
        return 0

    if args.reload_rules:
        cfg = config.Config.load()
        scanner = Scanner(cfg, SelfProtection())
        ok = scanner.reload_rules()
        print(f"Rule files: {', '.join(p.name for p in scanner.rule_sources) or 'none'}")
        print("Loaded successfully." if ok else "Loading FAILED - see the log.")
        return 0 if ok else 1

    if args.schedule:
        target = args.schedule_path or (Path.home() / "Downloads")
        if args.schedule == "status":
            state = scheduling.status()
            print(f"Starts with Windows : {'yes' if state.starts_with_windows else 'no'}")
            print(f"Daily scan scheduled: {'yes' if state.scheduled_scan else 'no'}")
            if state.detail:
                print(state.detail)
            return 0
        if args.schedule == "on":
            ok_a, detail_a = scheduling.enable_start_with_windows()
            ok_b, detail_b = scheduling.enable_scheduled_scan(target)
            print(f"Start with Windows : {'yes' if ok_a else 'FAILED - ' + detail_a}")
            print(f"Daily scan of {target}: {detail_b if ok_b else 'FAILED - ' + detail_b}")
            print("\nThe scheduled scan only reports. It never moves files.")
            return 0 if (ok_a and ok_b) else 1
        ok_a, _ = scheduling.disable_start_with_windows()
        ok_b, _ = scheduling.disable_scheduled_scan()
        print("Removed." if (ok_a and ok_b) else "Partly removed - see the log.")
        return 0

    if args.scan:
        if not args.scan.exists():
            print(f"no such path: {args.scan}", file=sys.stderr)
            return 2
        return _console_scan(args.scan, args.quarantine, args.verbose)

    from .gui import main as gui_main
    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
