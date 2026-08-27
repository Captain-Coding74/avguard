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


def main() -> int:
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
