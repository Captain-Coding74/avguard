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
import os
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
        """Add a file or directory to the protected set.

        Both the absolute and the fully resolved form are stored. On Windows
        those can differ in ways that matter: a packaged or containerised app
        has AppData redirected, so `%LOCALAPPDATA%/AVGuard/logs/avguard.log`
        resolves to `.../Packages/<app>/LocalCache/Local/AVGuard/...`. Storing
        only one form meant the roots were held unredirected while candidates
        resolved redirected, and self-protection quietly stopped covering our
        own files -- but only the ones that existed, because `resolve()` on a
        missing path does not follow the redirection. Existing files being the
        unprotected ones is precisely backwards.
        """
        candidate = Path(path)
        for form in self._forms(candidate):
            self._roots.add(form)

    @staticmethod
    def _forms(path: Path) -> set[Path]:
        """Every spelling of a path this platform might hand us."""
        forms: set[Path] = set()
        try:
            forms.add(Path(os.path.abspath(path)))
        except (OSError, ValueError):
            pass
        try:
            forms.add(path.resolve())
        except (OSError, ValueError):
            pass
        return forms

    @property
    def roots(self) -> frozenset[Path]:
        return frozenset(self._roots)

    def is_protected(self, path: Path | str) -> bool:
        """True if `path` is one of our files, or lives inside one of our directories.

        Every form of the candidate is compared against every form of every
        root, and a match on any pair is enough. Comparison is case-insensitive
        on Windows, where two spellings of the same file differ only in case.
        """
        candidate_forms = self._forms(Path(path))
        if not candidate_forms:
            # If we cannot express it at all we cannot prove it is safe.
            return True

        for candidate in candidate_forms:
            for root in self._roots:
                if _same(candidate, root):
                    return True
                try:
                    if _within(candidate, root):
                        return True
                except ValueError:
                    continue
        return False


def path_forms(path: Path | str) -> set[Path]:
    """Every spelling of a path this platform might hand us.

    Public because more than one safety check needs it. Windows can give a
    file two true names: on a packaged or containerised app, AppData is
    redirected, and `resolve()` follows the redirection only for paths that
    already exist. So the same directory compares equal or not depending on
    which files happen to have been written into it -- a coin flip, and not one
    a guard should be decided by.
    """
    return SelfProtection._forms(Path(path))


def same_path(a: Path | str, b: Path | str) -> bool:
    """True if these name the same thing, in any spelling either might take."""
    return any(_same(x, y) for x in path_forms(a) for y in path_forms(b))


def path_within(candidate: Path | str, root: Path | str) -> bool:
    """True if `candidate` is inside `root`, in any spelling of either."""
    for form in path_forms(candidate):
        for base in path_forms(root):
            if _same(form, base) or _within(form, base):
                return True
    return False


def _normalise(path: Path) -> str:
    return os.path.normcase(str(path))


def _same(candidate: Path, root: Path) -> bool:
    return _normalise(candidate) == _normalise(root)


def _within(candidate: Path, root: Path) -> bool:
    """Is `candidate` inside `root`? Case-insensitive where the platform is.

    Path.is_relative_to is case-sensitive even on Windows, so two spellings of
    the same directory would not match.
    """
    root_text = _normalise(root).rstrip(os.sep + (os.altsep or ""))
    candidate_text = _normalise(candidate)
    return candidate_text.startswith(root_text + os.sep) or candidate_text == root_text


def matches_excluded_glob(path: Path | str, patterns: Iterable[str]) -> bool:
    """True if the path matches one of the user's exclusion globs.

    Checked with forward slashes so the patterns in config.json read the same
    on Windows as anywhere else.
    """
    text = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(text, pattern) for pattern in patterns)
