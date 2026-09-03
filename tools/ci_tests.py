#!/usr/bin/env python
"""Run the test suite and make any failure legible from outside the runner.

GitHub Actions logs need authentication to read, but check-run *annotations*
are public. A bare `python -m unittest` failing gives you exactly one line
through the API -- "Process completed with exit code 1" -- which is no use at
all when the suite passes on your machine and fails on the runner.

So this emits every failure as a workflow annotation, and prints a digest to
the step summary. Then diagnosing a CI-only failure does not require being the
person who owns the repository.

    python tools/ci_tests.py
    python tools/ci_tests.py --no-gui-deps

`--no-gui-deps` hides ttkbootstrap, pystray, Pillow and tkinter, reproducing
the Linux CI job on a Windows laptop. That job installs only the scanning
dependencies, so a test that reaches into the GUI passes here and fails there.
It has happened; this is how to find out before pushing rather than after.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MAX_ANNOTATIONS = 20        # GitHub stops showing them long before this
MAX_MESSAGE_CHARS = 900     # annotations are truncated past roughly this


def _annotate(level: str, title: str, message: str) -> None:
    """Emit a GitHub Actions annotation, or a plain line when run locally."""
    text = " ".join(message.split())[:MAX_MESSAGE_CHARS]
    if os.getenv("GITHUB_ACTIONS"):
        print(f"::{level} title={title}::{text}")
    else:
        print(f"[{level}] {title}: {text}")


def _summary(lines: list[str]) -> None:
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        pass


class _HideModules:
    """Import blocker, so the Linux job's world can be reproduced locally.

    Uses `find_spec`, which is the only finder hook the import system still
    consults. The first version of this class implemented `find_module` and
    `load_module` -- the protocol Python 3.12 removed -- so it silently blocked
    nothing at all. `--no-gui-deps` reported the whole suite passing while
    importing ttkbootstrap perfectly happily, and the Linux CI job then failed
    on exactly the import this was built to catch.

    A tool that reports success without doing its work is worse than no tool,
    because it gets believed. Hence the self-check below.
    """

    def __init__(self, names: set[str]) -> None:
        self.names = names

    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in self.names:
            raise ImportError(f"No module named {name!r} (hidden by --no-gui-deps)")
        return None


def _prove_blocking_works(names: set[str]) -> None:
    """Refuse to run rather than report a result the blocker did not produce.

    Every name, not `sorted(names)[0]`: that probed PIL alone, and on a box
    without Pillow it passed vacuously while the other three went unproven.
    find_spec through our finder raises ImportError for a hidden name and
    returns None for one that is merely absent, so the two are told apart.
    """
    import importlib.util
    unproven = []
    for name in sorted(names):
        try:
            importlib.util.find_spec(name)
        except ImportError:
            continue  # hidden, as intended
        unproven.append(name)
    if not unproven:
        return
    listed = ", ".join(unproven)
    print(f"::error title=--no-gui-deps is not working::{listed} not hidden; "
          "the check would report a pass it did not earn"
          if os.getenv("GITHUB_ACTIONS") else
          f"--no-gui-deps is not working: {listed} not hidden.")
    raise SystemExit(2)


GUI_DEPENDENCIES = {"ttkbootstrap", "pystray", "PIL", "tkinter"}


def main() -> int:
    if "--no-gui-deps" in sys.argv:
        sys.meta_path.insert(0, _HideModules(GUI_DEPENDENCIES))
        _prove_blocking_works(GUI_DEPENDENCIES)
        print(f"hiding {', '.join(sorted(GUI_DEPENDENCIES))} "
              "to reproduce the Linux CI job (blocking verified)")

    # No top_level_dir: tests/ has no __init__.py, and passing one makes
    # discovery refuse the directory outright. This matches how the suite is
    # run by hand: `python -m unittest discover -s tests` from the project root.
    os.chdir(ROOT)
    loader = unittest.TestLoader()
    suite = loader.discover("tests")

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    problems = [("error", t, e) for t, e in result.errors]
    problems += [("failure", t, e) for t, e in result.failures]

    summary = [
        "## Test results",
        "",
        f"- ran: **{result.testsRun}**",
        f"- failures: **{len(result.failures)}**",
        f"- errors: **{len(result.errors)}**",
        f"- skipped: **{len(result.skipped)}**",
        f"- python: {sys.version.split()[0]} on {sys.platform}",
    ]

    if result.skipped:
        summary += ["", "### Skipped", ""]
        for test, reason in result.skipped[:20]:
            summary.append(f"- `{test.id()}` - {reason}")

    if problems:
        summary += ["", "### Failures", ""]

    for level, test, traceback_text in problems[:MAX_ANNOTATIONS]:
        # The last line of a traceback is the assertion; the rest is noise.
        tail = [line for line in traceback_text.strip().splitlines() if line.strip()]
        message = tail[-1] if tail else "no detail"
        where = next((line.strip() for line in reversed(tail)
                      if line.strip().startswith("File ")), "")
        _annotate("error", test.id(), f"{message}  [{where}]")
        summary.append(f"- `{test.id()}`")
        summary.append(f"  - {message}")
        if where:
            summary.append(f"  - {where}")

    if len(problems) > MAX_ANNOTATIONS:
        _annotate("error", "more failures",
                  f"{len(problems) - MAX_ANNOTATIONS} further failures were not annotated")

    _summary(summary)

    if problems:
        print(f"\n{len(problems)} test(s) failed. Each one is annotated above.")
        return 1

    print(f"\nAll {result.testsRun} tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
