#!/usr/bin/env python
"""Build a single AVGuard.exe.

    python build.py

The result lands in dist/. It needs no Python installed on the target machine
and no administrator rights to run.

Two things this has to get right, both of which were bugs before:

  * the YARA rules must travel inside the bundle, and `config.PROJECT_ROOT`
    must resolve to the extraction directory when frozen, or the executable
    starts with no rules and says detection is reduced
  * everything writable already lives in %LOCALAPPDATA%/AVGuard rather than
    beside the program, so the executable can sit in Program Files without
    the first write failing
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME = "AVGuard"


def main() -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed.  pip install pyinstaller", file=sys.stderr)
        return 1

    rules = ROOT / "rules"
    if not any(rules.glob("*.yara")):
        print(f"no rule files in {rules}; refusing to build a scanner with no rules",
              file=sys.stderr)
        return 1

    for stale in (ROOT / "build", ROOT / "dist"):
        shutil.rmtree(stale, ignore_errors=True)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", NAME,
        # One file, no console. `logsetup.install_excepthooks()` is what makes
        # --windowed survivable: without a console, an unhandled exception has
        # nowhere to print, and the user just sees nothing happen.
        "--onefile", "--windowed",
        # The rules must be inside the bundle, at the path config expects.
        "--add-data", f"{rules}{';' if sys.platform == 'win32' else ':'}rules",
        # PyInstaller does not always follow these.
        "--hidden-import", "yara",
        "--hidden-import", "pefile",
        "--hidden-import", "pystray._win32",
        "--hidden-import", "PIL._tkinter_finder",
        "--collect-submodules", "ttkbootstrap",
        str(ROOT / "run.py"),
    ]

    print("Building. This takes a minute or two.")
    result = subprocess.run(args, cwd=ROOT)
    if result.returncode != 0:
        return result.returncode

    produced = ROOT / "dist" / (f"{NAME}.exe" if sys.platform == "win32" else NAME)
    if not produced.exists():
        print("the build reported success but produced nothing", file=sys.stderr)
        return 1

    size = produced.stat().st_size / (1024 * 1024)
    print(f"\nBuilt {produced}  ({size:.0f} MB)")
    print("Data, quarantine and logs go to %LOCALAPPDATA%/AVGuard, not next to the exe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
