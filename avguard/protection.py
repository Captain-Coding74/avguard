"""Self-protection: the guarantee that AVGuard never quarantines itself.

The original build had no such guarantee and destroyed itself. Its YARA
ruleset listed the strings ".locky", ".encrypted", ".crypt",
"CreateRemoteThread" and "WriteProcessMemory" in plain text, so the ruleset
matched its own file. The scanner moved rules into quarantine, YARA
compilation failed from then on, and detection silently stopped. The same
mechanism quarantined main.py, engine.py and the log.

The defence is one rule applied in one place: resolve the candidate path and
refuse it if it sits under any protected root. Every scan entry point calls
`is_protected` before opening a file, so a new caller cannot forget it.
"""

from __future__ import annotations

import fnmatch
import sys
from pathlib import Path
from typing import Iterable

from . import config


class SelfProtection:
    """Holds the set of paths the scanner is forbidden to touch."""

    def __init__(self, roots: Iterable[Path] | None = None) -> None:
        self._roots: set[Path] = set()
        for root in roots or self._default_roots():
            self.protect(root)

    @staticmethod
    def _default_roots() -> list[Path]:
        """Everything that belongs to AVGuard itself."""
        roots = [
            # The whole project, not just three subdirectories. docs/, tests/
            # and README.md were outside the guard, and docs/postmortem.md has
            # already been flagged once for quoting a signature it was
            # explaining. Our own repository is never the thing to quarantine.
            config.PROJECT_ROOT,
            config.PACKAGE_DIR,   # our own source
            config.DATA_DIR,      # quarantine store, logs, caches, config
            config.RULES_DIR,     # the shipped detection rules
            config.USER_RULES_DIR,  # rules the user added
        ]
        # The running script or frozen executable.
        try:
            roots.append(Path(sys.argv[0]).resolve())
        except (OSError, ValueError):
            pass
        if getattr(sys, "frozen", False):
            roots.append(Path(sys.executable).resolve())
        return roots

    def protect(self, path: Path | str) -> None:
        """Add a file or directory to the protected set."""
        try:
            self._roots.add(Path(path).resolve())
        except (OSError, ValueError):
            # An unresolvable path cannot be compared against, so ignore it
            # rather than letting a bad entry weaken the whole check.
            pass

    @property
    def roots(self) -> frozenset[Path]:
        return frozenset(self._roots)

    def is_protected(self, path: Path | str) -> bool:
        """True if `path` is one of our files, or lives inside one of our directories.

        Comparison is on fully resolved paths, so symlinks, junctions, relative
        paths and short 8.3 names all normalise to the same answer. The old
        build compared raw substrings, which both missed real matches and
        excluded innocent files whose path happened to contain the substring.
        """
        try:
            candidate = Path(path).resolve()
        except (OSError, ValueError):
            # If we cannot resolve it we cannot prove it is safe, so refuse it.
            return True

        for root in self._roots:
            if candidate == root:
                return True
            if root.is_dir() or not root.suffix:
                try:
                    if candidate.is_relative_to(root):
                        return True
                except ValueError:
                    continue
        return False


def matches_excluded_glob(path: Path | str, patterns: Iterable[str]) -> bool:
    """True if the path matches one of the user's exclusion globs.

    Checked with forward slashes so the patterns in config.json read the same
    on Windows as anywhere else.
    """
    text = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(text, pattern) for pattern in patterns)
