"""Entry point: `python -m avguard` for the GUI, `--scan PATH` for the console.

The console mode exists so the scanner can be exercised without a display,
which is what makes it testable and scriptable.
"""

from __future__ import annotations

import argparse
import os
import logging
import sys
from pathlib import Path

from . import fim, iocs
from . import config, logsetup, scheduling
from .cloud import VirusTotalClient
from .instance import InstanceLock
from .protection import SelfProtection
from . import rulepacks
from .quarantine import QuarantineError, QuarantineStore, RestoreIncomplete
from .scanner import Level, Scanner


def _console_scan(target: Path, quarantine_threats: bool, verbose: bool) -> int:
    logsetup.configure(level=logging.DEBUG if verbose else logging.INFO)
    logging.getLogger("avguard").addHandler(logging.StreamHandler(sys.stdout))

    cfg = config.Config.load()
    protection = SelfProtection()
    cloud = VirusTotalClient(cfg)
    scanner = Scanner(cfg, protection, cloud_lookup=cloud.reasons_for)
    store = QuarantineStore(protection=protection,
                            allowlist=scanner.allowlist)

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


def _packs_command(args) -> int:
    """List, add, remove or promote rule packs."""
    store = rulepacks.PackStore()
    action = args.packs
    rest = list(args.pack_args)

    if action == "list":
        if rest:
            # `--packs --licence MIT add folder` parsed as `--packs list` with
            # "add folder" left over, and silently listed. Leftovers are an
            # error, not a shrug.
            print(f"--packs list takes no arguments; unexpected: {' '.join(rest)}",
                  file=sys.stderr)
            print("did you mean:  --packs add <folder> --licence MIT", file=sys.stderr)
            return 2
        packs = store.packs()
        if not packs:
            print("No rule packs installed.")
            print("Add one with:  python -m avguard --packs add <folder> --licence MIT")
            return 0
        for pack in packs:
            print(f"{pack.name}")
            if pack.display_name and pack.display_name != pack.name:
                print(f"    added as: {pack.display_name}")
            print(f"    rules   : {pack.rule_count} in {pack.file_count} file(s)")
            print(f"    measured: {pack.false_positive_rate:.2%} of "
                  f"{pack.corpus_size} clean files flagged, when it was added")
            print(f"    licence : {pack.licence or unknown_text()}")
            print(f"    source  : {pack.source or unknown_text()}")
            print(f"    trusted : {pack.trusted}"
                  + ("" if pack.trusted else "   (reports only; nothing it finds is moved)"))
        return 0

    if action == "add":
        if not rest:
            print("give a folder of .yara files: --packs add <folder> --licence MIT",
                  file=sys.stderr)
            return 2
        folder = Path(rest[0])
        if not folder.is_dir():
            print(f"not a folder: {folder}", file=sys.stderr)
            return 2
        files = sorted(list(folder.glob("*.yara")) + list(folder.glob("*.yar")))
        if not files:
            print(f"no .yara or .yar files in {folder}", file=sys.stderr)
            return 2

        name = rest[1] if len(rest) > 1 else folder.name
        corpus = _clean_corpus()
        print(f"measuring {len(files)} file(s) against {len(corpus)} clean binaries "
              "from this machine...")
        admission = store.admit(name, files, corpus,
                                source=str(folder), licence=args.licence)
        for reason in admission.reasons:
            print(f"  {reason}")
        if not admission.accepted:
            print("Refused. Nothing was installed.", file=sys.stderr)
            return 1
        try:
            pack = store.install(name, files, admission,
                                 source=str(folder), licence=args.licence)
        except (rulepacks.PackError, OSError) as exc:
            # A refusal is an answer, not a traceback.
            print(f"Refused: {exc}", file=sys.stderr)
            print("Nothing was installed.", file=sys.stderr)
            return 1
        print(f"Installed {pack.name}.")
        print("It reports only. Nothing it finds will be moved until you run:")
        print(f"    python -m avguard --packs trust {pack.name}")
        return 0

    if action == "verify":
        packs = store.packs()
        if not packs:
            print("No rule packs installed.")
            return 0
        corpus = _clean_corpus()
        if not corpus:
            print("No clean binaries available to measure against.", file=sys.stderr)
            return 1
        print(f"re-measuring {len(packs)} pack(s) against {len(corpus)} clean "
              "binaries from this machine...")
        worst = 0
        for pack in packs:
            files = sorted(list(store.pack_dir(pack.name).glob("*.yara"))
                           + list(store.pack_dir(pack.name).glob("*.yar")))
            # Re-admit against today's corpus rather than trusting the number
            # recorded when it was installed. Software gets added to a machine,
            # and a pack's files can be edited after the fact.
            check = store.admit(pack.name, files, corpus,
                                source=pack.source, licence=pack.licence)
            if check.accepted:
                print(f"  {pack.name}: ok  "
                      f"({check.false_positive_rate:.2%} of {check.corpus_size} flagged, "
                      f"was {pack.false_positive_rate:.2%} at install)")
                continue

            worst = 1
            # Say what actually failed. This used to print "OVER THE CEILING
            # (0.00% of 400 flagged)" for a pack that failed to COMPILE --
            # a rate it had never measured, attributed to the wrong check.
            cause = check.reasons[0] if check.reasons else "failed for an unrecorded reason"
            measured = (f" ({check.false_positive_rate:.2%} of {check.corpus_size} flagged)"
                        if check.measured else "")
            print(f"  {pack.name}: FAILED{measured}")
            print(f"      {cause[:160]}")
            if pack.trusted:
                # A failing pack must not stay armed. The exit code now
                # corresponds to a change of state, not just a complaint.
                store.set_trusted(pack.name, False)
                print(f"      {pack.name} was trusted; it is reports-only until it passes again")
        if worst:
            print("\nA pack no longer meets the bar it was admitted under.",
                  file=sys.stderr)
            print("Remove it with:  python -m avguard --packs remove <name>",
                  file=sys.stderr)
        return worst

    if action in ("remove", "trust", "untrust"):
        if not rest:
            print(f"--packs {action} needs a pack name", file=sys.stderr)
            return 2
        name = rest[0]
        try:
            if action == "remove":
                if not store.remove(name):
                    print(f"no pack called {name!r}", file=sys.stderr)
                    return 1
                print(f"Removed {name}.")
            else:
                pack = store.set_trusted(name, action == "trust")
                if pack.trusted:
                    print(f"{pack.name} is now trusted: its rules can move files.")
                else:
                    print(f"{pack.name} now reports only.")
        except rulepacks.PackError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0

    print(f"unknown --packs action {action!r}", file=sys.stderr)
    return 2


def unknown_text() -> str:
    return "unknown"


def _fim_command(args) -> int:
    """Integrity monitoring from a terminal. Reports; never moves a file."""
    from datetime import datetime
    from .events import EventStore
    cfg = config.Config.load()
    store = fim.FimStore(excluded_globs=cfg.excluded_globs)

    if args.fim_baseline:
        roots = [Path(r) for r in args.fim_baseline]
        report = store.baseline(roots)
        for problem in report.errors:
            print(f"  skipped: {problem}", file=sys.stderr)
        if not report.roots:
            print("Nothing was baselined.", file=sys.stderr)
            return 1
        mb = report.bytes / (1024 * 1024)
        print(f"Baselined {report.files:,} file(s), {mb:,.1f} MB, under "
              f"{len(report.roots)} root(s) in {report.seconds:.1f}s:")
        for root in report.roots:
            print(f"    {root}")
        print("The baseline is signed. Check it with:  python -m avguard --fim-check")
        return 0

    if args.fim_check:
        report = store.check(fast=args.fast, events=EventStore())
        if report.integrity == fim.INTEGRITY_NO_BASELINE:
            print("No baseline. Create one with:  python -m avguard --fim-baseline <folder>",
                  file=sys.stderr)
            return 2
        integrity_event = report.integrity_event()
        if integrity_event is not None:
            print(f"BASELINE: {integrity_event.reasons[0]}")
            print()
        for change in report.changes:
            print(f"  {change.describe()}")
        for problem in report.errors:
            print(f"  error: {problem}", file=sys.stderr)
        print()
        mode = "size and mtime trusted (--fast)" if report.fast else "every file hashed"
        print(f"Examined {report.examined:,} baselined file(s), hashed {report.hashed:,}, "
              f"{mode}, {report.seconds:.1f}s")
        if report.changes:
            print(f"{len(report.modified)} modified, {len(report.added)} added, "
                  f"{len(report.removed)} removed. Nothing was moved; a check never does.")
            print("Accept a change you have looked at with:  python -m avguard --fim-accept <path>")
        else:
            print("No changes.")
        if integrity_event is not None:
            return 3
        return 1 if report.changes else 0

    if args.fim_accept:
        if not store.exists():
            print("No baseline to accept into.", file=sys.stderr)
            return 2
        for note in store.accept(Path(p) for p in args.fim_accept):
            print(f"  {note}")
        return 0

    if args.fim_schedule:
        if args.fim_schedule == "status":
            print("Daily integrity check scheduled: "
                  f"{'yes' if scheduling.scheduled_fim_check_exists() else 'no'}")
            return 0
        if args.fim_schedule == "on":
            ok, detail = scheduling.enable_scheduled_fim_check()
            print(f"Daily integrity check: {detail if ok else 'FAILED - ' + detail}")
            print("It records what changed and moves nothing.")
            return 0 if ok else 1
        ok, detail = scheduling.disable_scheduled_fim_check()
        print("Removed." if ok else f"Not removed: {detail}")
        return 0 if ok else 1

    # --fim-status
    if not store.exists():
        print("No baseline. Create one with:  python -m avguard --fim-baseline <folder>")
        return 0
    when = datetime.fromtimestamp(store.baselined_at()).strftime("%Y-%m-%d %H:%M")
    print(f"Baseline: {store.file_count():,} file(s), last baselined {when}, "
          f"signature {store.verify_integrity()}")
    for root in store.roots():
        print(f"    {root}")
    return 0


def _iocs_command(args) -> int:
    """The blocklist from a terminal: import, fetch, or say what it holds."""
    store = iocs.IocStore()
    if args.iocs_import:
        try:
            result = store.import_file(args.iocs_import, source=args.iocs_source)
        except OSError as exc:
            print(f"Could not read {args.iocs_import}: {exc}", file=sys.stderr)
            return 1
        print(result.describe())
        print(f"The blocklist holds {store.count():,} hash(es). A running AVGuard "
              "picks this up within a few seconds.")
        return 0

    if args.iocs_update:
        url = iocs.FEED_FULL_URL if args.iocs_full else iocs.FEED_RECENT_URL
        print(f"Fetching {url}")
        print("Nothing about this machine or its files is sent; the request carries "
              "only the previous download's ETag.")
        try:
            result = store.update_from_feed(full=args.iocs_full)
        except iocs.IocError as exc:
            print(f"Update failed: {exc}", file=sys.stderr)
            return 1
        if result.status == "unchanged":
            print("The feed has not changed since the last download. Nothing to do.")
        elif result.imported is not None:
            print(result.imported.describe())
        print(f"The blocklist holds {store.count():,} hash(es).")
        return 0

    from datetime import datetime
    print(f"Blocklist: {store.count():,} hash(es) in {store.path}")
    for source, count in store.sources().items():
        print(f"    {source:<16} {count:,}")
    state = store.feed_state()
    if state["checked_at"]:
        try:
            when = datetime.fromtimestamp(float(state["checked_at"])).strftime("%Y-%m-%d %H:%M")
        except (ValueError, OSError):
            when = state["checked_at"]
        print(f"Feed last checked: {when}  ({state['url'] or iocs.FEED_RECENT_URL})")
    else:
        print("Feed: never fetched. Turn it on in Settings, or run --iocs-update once.")
    return 0


def _clean_corpus(limit: int = 400, roots: list[Path] | None = None,
                  per_directory: int = 6) -> list[Path]:
    """Real binaries off this machine, to measure a candidate pack against.

    The same corpus idea the rule tests use: a pack is judged on the software
    actually installed here, not on a fixture somebody chose.

    Spread across programs, not piled in one folder. Measured before this:
    400 files, 331 of them from System32, the rest from six program
    directories -- the walk stopped at the first directory that filled the
    quota, and System32's root alone has thousands. A 5% pack ceiling
    measured against one vendor's binaries is weaker than it reads; what
    people download is Electron apps, Go binaries and installers. So: a few
    files per directory, the per-user Programs folder included, and System32
    held to a third while other software exists to fill the rest.
    """
    import random
    if roots is None:
        roots = [Path(r"C:/Program Files"), Path(r"C:/Program Files (x86)"),
                 Path(os.environ.get("LOCALAPPDATA", r"C:/nowhere")) / "Programs",
                 Path(r"C:/Windows/System32")]
    system_share = max(1, limit // 3)
    buckets: list[list[Path]] = []
    system_spare: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        is_system = "system32" in str(root).lower()
        # System32 is one vendor in one folder: it may fill the corpus alone
        # on a bare machine, but its bucket is capped below so that it does
        # not when other software exists. Everyone else gives a few per folder.
        cap_here = limit if is_system else per_directory
        rng = random.Random(20240607)
        taken: list[Path] = []
        productive = 0
        visited = 0
        for dirpath, dirnames, filenames in os.walk(root):
            # __pycache__ never holds a binary, and a per-user Python install
            # has thousands of them.
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            visited += 1
            eligible = sorted(f for f in filenames if f.lower().endswith((".exe", ".dll")))
            if not eligible:
                # The cap counted these. %LOCALAPPDATA%\Programs holds a
                # Python install -- thousands of directories with no .exe or
                # .dll in them -- and the walk burned its budget there before
                # reaching a single program, so the corpus was refilled from
                # System32: the skew this walk exists to remove.
                if visited >= 50_000:
                    break
                continue
            productive += 1
            rng.shuffle(eligible)  # not the alphabetical first few
            here = 0
            for filename in eligible:
                path = Path(dirpath) / filename
                try:
                    if path.stat().st_size > 16 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                taken.append(path)
                here += 1
                if here >= cap_here:
                    break
            if len(taken) >= limit or productive >= 4000 or visited >= 50_000:
                break
        rng.shuffle(taken)
        if is_system:
            system_spare = taken[system_share:]
            taken = taken[:system_share]
        buckets.append(taken)

    # Round-robin across roots so no single one dominates, then top up from
    # whatever is left, System32 last.
    corpus: list[Path] = []
    while len(corpus) < limit and any(buckets):
        for bucket in buckets:
            if bucket and len(corpus) < limit:
                corpus.append(bucket.pop())
    while len(corpus) < limit and system_spare:
        corpus.append(system_spare.pop())
    return corpus


def main(argv: list[str] | None = None) -> int:
    logsetup.install_excepthooks()
    result = _main(argv)
    # A command that has RETURNED has no business holding its log open. Not in
    # a finally: that ran before sys.excepthook, which then found the avguard
    # logger with no file handler, and a crash under the windowed build --
    # the case the hooks exist for -- left a 0-byte log. Measured: 0 bytes
    # versus 1,316 with the close out of the way. On the exception path the
    # interpreter's logging.shutdown() closes the handler after the hook.
    logsetup.close_file_handlers()
    return result


def _main(argv: list[str] | None = None) -> int:
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
    parser.add_argument("--packs", nargs="?", const="list", metavar="ACTION",
                        help="rule packs: list (default), add PATH, verify, "
                             "remove NAME, trust NAME, untrust NAME")
    parser.add_argument("pack_args", nargs="*", default=[],
                        help=argparse.SUPPRESS)
    parser.add_argument("--licence", "--license", dest="licence", default="",
                        help="with --packs add: the pack's licence, e.g. MIT")
    parser.add_argument("--iocs-import", metavar="FILE", type=Path,
                        help="add SHA-256 hashes to the local blocklist, one per line "
                             "(# starts a comment); a file whose hash is listed is MALICIOUS")
    parser.add_argument("--iocs-source", metavar="NAME", default="manual",
                        help="with --iocs-import: where these hashes came from (default: manual)")
    parser.add_argument("--iocs-update", action="store_true",
                        help="fetch the MalwareBazaar hash blocklist now: one HTTPS request "
                             "to bazaar.abuse.ch, carrying nothing about this machine")
    parser.add_argument("--iocs-full", action="store_true",
                        help="with --iocs-update: the full export (43 MB zipped) instead of "
                             "the last 48 hours; a one-time seed")
    parser.add_argument("--iocs-status", action="store_true",
                        help="how many hashes the blocklist holds, from where, and when "
                             "the feed was last checked")
    parser.add_argument("--fim-baseline", metavar="ROOT", nargs="+",
                        help="record the hash of every file under ROOT (repeatable) as the "
                             "baseline for --fim-check; a root already recorded is replaced")
    parser.add_argument("--fim-check", action="store_true",
                        help="report every file that differs from the baseline: modified, "
                             "added, removed. Records events and never moves a file")
    parser.add_argument("--fast", action="store_true",
                        help="with --fim-check: trust an unchanged size and mtime and skip "
                             "the read. Faster, and blind to a file whose mtime was reset "
                             "after it was modified -- the default hashes everything")
    parser.add_argument("--fim-accept", metavar="PATH", nargs="+",
                        help="re-baseline these paths after you have looked at the change, "
                             "so the alert stops repeating")
    parser.add_argument("--fim-status", action="store_true",
                        help="what the baseline covers and whether its signature holds")
    parser.add_argument("--fim-schedule", choices=["status", "on", "off"],
                        help="a daily unattended --fim-check (records only)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.pack_args and not args.packs:
        # `avguard scan C:/x` -- no dashes -- used to swallow both words into
        # the pack_args catch-all and quietly launch the GUI with nothing
        # scanned. A bare word the parser cannot place is a mistake to name.
        parser.error(f"unexpected arguments: {' '.join(args.pack_args)} "
                     "(commands are options, e.g. --scan PATH)")

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
        except RestoreIncomplete as exc:
            print(f"Restored to {exc.target}")
            print(f"WARNING: {exc}", file=sys.stderr)
            return 0
        except QuarantineError as exc:
            print(f"Could not restore: {exc}", file=sys.stderr)
            return 1
        finally:
            lock.release()
        print(f"Restored to {target}")
        return 0

    if args.iocs_import or args.iocs_update or args.iocs_status:
        return _iocs_command(args)

    if (args.fim_baseline or args.fim_check or args.fim_accept or args.fim_status
            or args.fim_schedule):
        return _fim_command(args)

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

    if args.packs:
        return _packs_command(args)

    if args.scan:
        if not args.scan.exists():
            print(f"no such path: {args.scan}", file=sys.stderr)
            return 2
        return _console_scan(args.scan, args.quarantine, args.verbose)

    from .gui import main as gui_main
    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
