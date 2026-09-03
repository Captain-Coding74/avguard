#!/usr/bin/env python
"""End-to-end checks against the real command line.

    python tools/ci_smoke.py

Deliberately Python rather than PowerShell. The PowerShell version of these
checks failed on CI for a reason that had nothing to do with AVGuard:
PowerShell 7.4 turns a native command's non-zero exit into a terminating error
when ErrorActionPreference is Stop, which GitHub Actions sets. `--scan` exits 1
when it finds something, which is correct and is the whole point of the check,
and pwsh killed the step before the assertions ran.

Python also means these run identically on a laptop, so a CI-only failure in
the checks themselves stops being a thing that can happen.

Everything happens in a temporary directory OUTSIDE the checkout. The checkout
is config.PROJECT_ROOT, and self-protection refuses the whole project tree
before a file is opened -- an earlier version of this script scanned a fixture
written next to the code, got SKIPPED, and reported success for a scanner that
had not looked at anything.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from avguard.scanner import SELFTEST_MARKER  # noqa: E402

failures: list[str] = []


def annotate(title: str, message: str) -> None:
    text = " ".join(message.split())
    if os.getenv("GITHUB_ACTIONS"):
        print(f"::error title={title}::{text}")
    else:
        print(f"  FAILED [{title}] {text}")


def check(title: str, condition: bool, detail: str) -> bool:
    if condition:
        print(f"  ok    {title}")
        return True
    failures.append(title)
    annotate(title, detail)
    return False


def run(*args: str) -> tuple[int, str]:
    """Run the CLI as a user would, and never let a non-zero exit kill us."""
    result = subprocess.run([sys.executable, "-m", "avguard", *args],
                            cwd=ROOT, capture_output=True, text=True, timeout=600)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="avguard-smoke-"))
    os.environ["AVGUARD_DATA"] = str(work / "data")
    print(f"working in {work}")

    # --- a detection is found, named, and reported with exit 1 --------------
    bad = work / "selftest.bin"
    bad.write_bytes(SELFTEST_MARKER)
    code, output = run("--scan", str(bad))
    # Asserting on the output as well as the code: an exit code alone would
    # still pass with detection removed entirely.
    check("the self-test marker is detected", "MALICIOUS" in output,
          f"expected MALICIOUS in the output, got: {output[-400:]}")
    check("a detection exits 1", code == 1, f"expected exit 1, got {code}")
    check("--scan alone moves nothing", bad.exists(),
          "the file was moved without --quarantine")

    # --- a clean file is examined, not merely skipped -----------------------
    good = work / "clean.txt"
    good.write_text("nothing to see here", encoding="utf-8")
    code, output = run("--scan", str(good))
    check("a clean file is not flagged", "MALICIOUS" not in output,
          f"a clean file was flagged: {output[-400:]}")
    check("a clean file is actually examined", "Clean    : 1" in output,
          f"the file was skipped rather than read: {output[-400:]}")
    check("a clean scan exits 0", code == 0, f"expected exit 0, got {code}")

    # --- the whole quarantine round trip ------------------------------------
    drop = work / "drop"
    drop.mkdir()
    threat = drop / "threat.bin"
    threat.write_bytes(SELFTEST_MARKER)

    code, output = run("--scan", str(drop), "--quarantine")
    check("a detection is quarantined", not threat.exists(),
          f"the file was not moved: {output[-400:]}")

    code, listing = run("--list-quarantine")
    check("--list-quarantine exits 0", code == 0, f"exit {code}: {listing[-300:]}")
    check("the quarantined file is listed", "threat.bin" in listing,
          f"not listed: {listing[-400:]}")

    entry_id = listing.strip().split()[0] if listing.strip() else ""
    code, output = run("--export-all", str(work / "rescued"))
    check("--export-all exits 0", code == 0,
          f"the documented exit door failed with {code}: {output[-400:]}")
    exported = list((work / "rescued").glob("*")) if (work / "rescued").exists() else []
    check("--export-all writes the file out", len(exported) == 1,
          f"expected one exported file, got {exported}")

    if entry_id:
        code, output = run("--restore", entry_id)
        check("--restore exits 0", code == 0, f"exit {code}: {output[-400:]}")
        check("--restore puts the file back", threat.exists(),
              "restore reported success but the file is not there")
        check("restored bytes are identical",
              threat.exists() and threat.read_bytes() == SELFTEST_MARKER,
              "the restored file does not match what was taken")

        # The restore should now be remembered, not undone a second later.
        code, output = run("--scan", str(drop))
        check("a restored file is not taken again", "MALICIOUS" not in output,
              f"the restored file was flagged again: {output[-400:]}")

    # --- rule packs: add, list, verify, refuse a duplicate, trust, remove -----
    # The audit noted ci_smoke never invoked --packs at all, so a CLI-only
    # breakage in the one feature that runs somebody else's code would have
    # reached users before it reached CI.
    pack_src = work / "packsrc"
    pack_src.mkdir()
    (pack_src / "smoke.yara").write_text(
        "rule Smoke_Pack_Rule {\n"
        "  meta:\n"
        '    description = "smoke test rule"\n'
        '    severity = "medium"\n'
        "  strings:\n"
        '    $a = "zz-smoke-needle-9c1e"\n'
        "  condition:\n"
        "    $a\n"
        "}\n", encoding="utf-8")

    code, output = run("--packs", "add", str(pack_src), "smokepack", "--licence", "MIT")
    check("--packs add admits a clean pack", code == 0,
          f"exit {code}: {output[-400:]}")

    code, listing = run("--packs", "list")
    check("--packs list shows the pack", "smokepack" in listing, listing[-300:])
    check("a new pack reports only", "reports only" in listing, listing[-300:])

    code, output = run("--packs", "add", str(pack_src), "smokepack", "--licence", "MIT")
    check("adding the same pack again is refused", code != 0,
          "a duplicate install must be refused, not silently overwrite")
    check("the refusal is a message, not a traceback",
          "Traceback" not in output and "already installed" in output,
          output[-400:])

    code, output = run("--packs", "verify")
    check("--packs verify passes a clean pack", code == 0, output[-300:])

    code, output = run("--packs", "trust", "smokepack")
    check("--packs trust exits 0", code == 0, output[-300:])
    code, listing = run("--packs", "list")
    check("a trusted pack says so", "trusted : True" in listing, listing[-300:])

    code, output = run("--packs", "remove", "smokepack")
    check("--packs remove exits 0", code == 0, output[-300:])
    code, listing = run("--packs", "list")
    check("a removed pack is gone", "smokepack" not in listing, listing[-300:])

    # --- the other commands at least run ------------------------------------
    for args, label in (
        (("--reload-rules",), "--reload-rules exits 0"),
        (("--schedule", "status"), "--schedule status exits 0"),
    ):
        code, output = run(*args)
        check(label, code == 0, f"exit {code}: {output[-300:]}")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for title in failures:
            print(f"  - {title}")
        return 1
    print("every end-to-end check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
