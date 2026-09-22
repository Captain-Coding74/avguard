"""Rule packs: using detection rules somebody else maintains.

The shipped ruleset catches test files and a handful of patterns. That is an
honest thing for five hand-written rules to do and a poor thing for an
antivirus to do, and the README has said so plainly rather than implying more.

Writing a real malware corpus is a different project. **Using one somebody else
already maintains is not** -- and the instruments that make it safe were built
over the previous three rounds:

  * a validator that refuses a ruleset matching AVGuard's own files, which is
    exactly how v1 destroyed itself
  * a corpus of real binaries off this machine that measures the true
    false-positive rate of every rule
  * a hard/heuristic split where nothing but explicit evidence moves a file

Importing rules is the first thing those instruments have really been for.

Measured before this was written, against ReversingLabs' MIT-licensed pack:
1,240 rules across 310 files, all compiling, every rule carrying a description,
**zero** false positives across 400 clean Windows binaries at 8 ms a file. The
rules are hex patterns matching compiled malware code, which is why they do not
fire on ordinary software. Proven live as well as quiet: blobs rebuilt from the
rules' own byte patterns matched 31 of 38 files probed, so "zero false
positives" is not the vacuous kind you get from rules that match nothing.

Two rules of the road, both deliberate:

**Nothing is fetched unless asked for.** No auto-update, no check on startup.
A scanner that changes its own detection logic overnight is a scanner that can
start eating files overnight.

**An imported rule can never move a file.** Third-party severities use
conventions this program knows nothing about, so `severity = "critical"` in
somebody else's file is capped to medium here. An imported pack reports until
it is promoted by name, having been watched doing so.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import config
from .protection import path_within, same_path

log = logging.getLogger(__name__)

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

PACKS_DIR = config.DATA_DIR / "packs"
PACKS_INDEX = PACKS_DIR / "packs.json"

# The same ceiling tests/test_rules.py holds the shipped rules to. A stranger's
# rules do not get an easier bar than our own.
MAX_FALSE_POSITIVE_RATE = 0.01

# And one for the pack as a whole. The per-rule ceiling alone let 120 narrow
# rules at 0.83% each flag every clean file on the machine and be admitted
# with "no rule over the ceiling". The aggregate was computed, printed, and
# compared to nothing.
MAX_PACK_FALSE_POSITIVE_RATE = 0.05

# Licences this project can redistribute alongside MIT code. A pack whose
# licence is unknown is refused rather than quietly vendored -- anyone who
# forks this repository inherits the problem otherwise.
KNOWN_GOOD_LICENCES = {
    "MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC",
    "CC0-1.0", "UNLICENSE",
}


class PackError(RuntimeError):
    """A pack could not be admitted. The message says what was measured."""


@dataclass
class RulePack:
    name: str
    source: str = ""
    licence: str = ""
    sha256: str = ""
    added_at: str = ""
    rule_count: int = 0
    file_count: int = 0
    false_positive_rate: float = 0.0
    corpus_size: int = 0

    # Until this is set, every rule in the pack is capped to medium and so can
    # never reach the quarantine threshold on its own.
    trusted: bool = False

    # The name the user typed. `name` is the directory-safe form of it, and
    # two different typed names can sanitise to the same directory.
    display_name: str = ""

    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Checked, not trusted, the way AllowEntry does it. `"trusted":
        # "false"` in a hand-edited index -- the case row 26 was about --
        # loaded as the truthy string: the pack's rules ran uncapped while
        # `--packs list` printed "trusted : false".
        for name in ("name", "source", "licence", "sha256", "added_at", "display_name"):
            value = getattr(self, name)
            if not isinstance(value, str):
                setattr(self, name, "" if value is None else str(value))
        for name in ("rule_count", "file_count", "corpus_size"):
            try:
                setattr(self, name, int(getattr(self, name)))
            except (TypeError, ValueError):
                setattr(self, name, 0)
        try:
            self.false_positive_rate = float(self.false_positive_rate)
        except (TypeError, ValueError):
            self.false_positive_rate = 0.0
        if not isinstance(self.trusted, bool):
            self.trusted = str(self.trusted).strip().lower() == "true"
        if not isinstance(self.notes, list):
            self.notes = []
        self.notes = [str(note) for note in self.notes]
        if not self.added_at:
            self.added_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    @property
    def when(self) -> str:
        return self.added_at[:19].replace("T", " ")

    def describe(self) -> str:
        trust = "trusted" if self.trusted else "reports only"
        return (f"{self.name}  ({self.rule_count} rules, {trust}, "
                f"{self.false_positive_rate:.2%} on {self.corpus_size} clean files)")


@dataclass
class Admission:
    """What happened when a pack was offered."""

    accepted: bool
    reasons: list[str] = field(default_factory=list)
    rule_count: int = 0
    file_count: int = 0
    false_positive_rate: float = 0.0
    corpus_size: int = 0
    # True once the rules were actually run over the corpus. corpus_size is
    # known before compiling, so it cannot tell a measured 0% from a pack
    # that never got that far -- which is what `verify` used to print.
    measured: bool = False
    offending: list[str] = field(default_factory=list)


class PackStore:
    """Packs on disk, and what is known about each."""

    def __init__(self, directory: Path = PACKS_DIR,
                 index_path: Path = PACKS_INDEX) -> None:
        self.directory = Path(directory)
        self.index_path = Path(index_path)
        self._stamp: tuple[int, int] | None = None
        self._lock = threading.RLock()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._packs: dict[str, RulePack] = {}
        self._load()

    # ---------------------------------------------------------------- index

    def _disk_stamp(self) -> tuple[int, int] | None:
        """Size and mtime of the index as it is on disk right now."""
        try:
            st = self.index_path.stat()
        except OSError:
            return None
        return (st.st_size, st.st_mtime_ns)

    def changed_on_disk(self) -> bool:
        """Has another process written the index since this one read it?"""
        return self._disk_stamp() != self._stamp

    def _load(self) -> None:
        self._stamp = self._disk_stamp()
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._packs = {}
            return
        if not isinstance(raw, dict):
            log.warning("pack index at %s is not a JSON object; ignoring it", self.index_path)
            self._packs = {}
            return
        packs: dict[str, RulePack] = {}
        for name, data in raw.items():
            if not isinstance(data, dict):
                log.warning("dropping a malformed pack record for %r", name)
                continue
            try:
                packs[name] = RulePack(**data)
            except TypeError:
                log.warning("dropping a malformed pack record for %r", name)
        self._packs = packs

    def _save(self) -> None:
        payload = {k: asdict(v) for k, v in self._packs.items()}
        config.atomic_write_text(self.index_path, json.dumps(payload, indent=2))
        self._stamp = self._disk_stamp()

    def reload(self) -> None:
        """Re-read the index, so another owner's change is visible.

        Settings built its own PackStore and wrote trust changes to disk that
        the running scanner never saw. The dangerous direction is trusted to
        reports-only: a user turns a pack off after a false positive and it
        keeps condemning for the rest of the session.
        """
        with self._lock:
            self._load()

    def pack_dir(self, name: str) -> Path:
        return self.directory / _safe_name(name)

    # ------------------------------------------------------------- querying

    def packs(self) -> list[RulePack]:
        with self._lock:
            return sorted(self._packs.values(), key=lambda p: p.name)

    def get(self, name: str) -> RulePack | None:
        with self._lock:
            return self._packs.get(name)

    def rule_files(self) -> list[Path]:
        """Every rule file from every installed pack."""
        found: list[Path] = []
        for pack in self.packs():
            directory = self.pack_dir(pack.name)
            if not directory.is_dir():
                continue
            found.extend(sorted(directory.glob("*.yara")))
            found.extend(sorted(directory.glob("*.yar")))
        return found

    def rule_files_for(self, name: str) -> list[Path]:
        """One pack's rule files, so the scanner can compile it on its own."""
        directory = self.pack_dir(name)
        if not directory.is_dir():
            return []
        return sorted(directory.glob("*.yara")) + sorted(directory.glob("*.yar"))

    def untrusted_namespaces(self) -> set[str]:
        """Resolved paths whose rules must be capped to medium.

        The scanner keys YARA namespaces on the resolved path, so this is
        exactly what it needs to know which matches came from a pack it has
        not been told to trust.
        """
        untrusted: set[str] = set()
        for pack in self.packs():
            if pack.trusted:
                continue
            directory = self.pack_dir(pack.name)
            if not directory.is_dir():
                continue
            for path in list(directory.glob("*.yara")) + list(directory.glob("*.yar")):
                untrusted.add(str(path.resolve()))
        return untrusted

    def owner_of(self, namespace: str) -> str:
        """Which pack a namespace belongs to, or "" for the shipped rules."""
        for pack in self.packs():
            if path_within(namespace, self.pack_dir(pack.name)):
                return pack.name
        return ""

    # ------------------------------------------------------------ admission

    def admit(
        self,
        name: str,
        rule_files: list[Path],
        corpus: list[Path],
        source: str = "",
        licence: str = "",
        protected_files: list[Path] | None = None,
    ) -> Admission:
        """Measure a candidate pack. Nothing is written unless it passes.

        The order matters: cheap structural checks first, then the corpus
        measurement, which is the expensive one and the one that actually
        decides whether these rules are usable on real software.
        """
        result = Admission(accepted=False, file_count=len(rule_files),
                           corpus_size=len(corpus))

        if yara is None:
            result.reasons.append("yara-python is not installed")
            return result
        if not rule_files:
            result.reasons.append("the pack contains no .yara or .yar files")
            return result

        licence_key = (licence or "").strip().upper()
        if licence_key not in KNOWN_GOOD_LICENCES:
            result.reasons.append(
                f"licence {licence or 'unknown'!r} is not one this project can "
                f"redistribute; known good: {', '.join(sorted(KNOWN_GOOD_LICENCES))}")
            return result

        namespaces = {str(p.resolve()): str(p) for p in rule_files}
        try:
            compiled = yara.compile(filepaths=namespaces)
        except yara.Error as exc:
            result.reasons.append(f"does not compile: {exc}")
            return result

        # From the compiled object, not a regex over the text. The regex
        # counted commented-out rules and could not see included ones; this
        # is exactly the set that will actually run.
        result.rule_count = sum(1 for _ in compiled)
        if not result.rule_count:
            result.reasons.append("compiles, but declares no rules")
            return result

        # It must not match us. This is the failure that ended v1.
        # The candidate's own source folder is excluded like its destination:
        # a pack unzipped anywhere under the checkout was refused for matching
        # its own files, since a plain text rule trivially matches the file
        # that declares it. Not when that folder contains the project or the
        # pack directory itself -- `--packs add .` must not switch the check
        # off.
        anchors = (config.PROJECT_ROOT, config.USER_RULES_DIR, self.directory)
        own_dirs = [d for d in {p.parent for p in rule_files}
                    if not any(path_within(anchor, d) for anchor in anchors)]
        for path in (protected_files if protected_files is not None
                     else _avguard_files(packs_dir=self.directory,
                                         exclude=[self.pack_dir(name), *own_dirs])):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            try:
                hits = [m.rule for m in compiled.match(data=data)]
            except Exception:
                continue
            if hits:
                result.reasons.append(
                    f"matches AVGuard's own {path.name}: {', '.join(hits[:3])}")
                result.offending.extend(hits[:3])
                return result

        # And the other direction. Pack beta was admitted because ITS rules
        # matched nothing of alpha's, while alpha's rules matched beta's file
        # text -- a description quoting the same string. The next verify
        # re-admitted alpha against a set that now held beta's file, and
        # disarmed alpha for something beta did. The pair is refused when it
        # is formed. Skipped when the caller supplies the protected set,
        # which is the tests' way of saying "not this check".
        if protected_files is None:
            reason = self._matched_by_installed_pack(name, rule_files)
            if reason:
                result.reasons.append(reason)
                return result

        # The measurement that decides it.
        flagged = 0
        per_rule: dict[str, int] = {}
        examined = 0
        for path in corpus:
            try:
                hits = compiled.match(filepath=str(path), timeout=60)
            except Exception:
                continue
            examined += 1
            if hits:
                flagged += 1
            for hit in hits:
                per_rule[hit.rule] = per_rule.get(hit.rule, 0) + 1

        result.corpus_size = examined
        if examined:
            result.false_positive_rate = flagged / examined
            result.measured = True

        if not examined:
            result.reasons.append(
                "no clean files were available to measure against; refusing "
                "rather than admitting rules nobody has checked")
            return result

        over = {rule: count for rule, count in per_rule.items()
                if count / examined > MAX_FALSE_POSITIVE_RATE}
        if over:
            worst = sorted(over.items(), key=lambda kv: -kv[1])[:5]
            result.offending = [r for r, _ in worst]
            result.reasons.append(
                f"{len(over)} rule(s) exceed the {MAX_FALSE_POSITIVE_RATE:.0%} "
                f"false-positive ceiling on {examined} clean files: "
                + ", ".join(f"{r} ({c / examined:.1%})" for r, c in worst))
            return result

        # Every rule is under its own ceiling; now the pack as a whole. Second
        # because the per-rule reason names the culprit, and this one only
        # applies when no single rule is to blame.
        if result.false_positive_rate > MAX_PACK_FALSE_POSITIVE_RATE:
            result.reasons.append(
                f"the pack as a whole flags {result.false_positive_rate:.1%} of "
                f"{examined} clean files, above the "
                f"{MAX_PACK_FALSE_POSITIVE_RATE:.0%} ceiling for a pack")
            worst = sorted(per_rule.items(), key=lambda kv: -kv[1])[:5]
            result.offending = [r for r, _ in worst]
            return result

        result.accepted = True
        result.reasons.append(
            f"{result.rule_count} rules, {result.false_positive_rate:.2%} of "
            f"{examined} clean files flagged, no rule over the ceiling")
        return result

    def _matched_by_installed_pack(self, name: str, rule_files: list[Path]) -> str:
        """Would an already-installed pack's rules fire on this candidate's files?"""
        candidate_dir = _safe_name(name)
        for other in self.packs():
            if other.name == candidate_dir:
                continue
            other_files = self.rule_files_for(other.name)
            if not other_files:
                continue
            try:
                other_rules = yara.compile(filepaths={str(f): str(f) for f in other_files})
            except yara.Error:
                continue  # a broken pack matches nothing; load_rules() names it
            for path in rule_files:
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                try:
                    hits = [m.rule for m in other_rules.match(data=data)]
                except Exception:
                    continue
                if hits:
                    return (f"would be matched by installed pack {other.name}'s rule "
                            f"{hits[0]}: {path.name}")
        return ""

    def install(self, name: str, rule_files: list[Path], admission: Admission,
                source: str = "", licence: str = "", replace: bool = False) -> RulePack:
        """Copy an admitted pack into place and record what was measured.

        Transactional. The first version did `rmtree(destination)` before it
        had read a single source byte, so three things went wrong:

          * installing a pack from its own directory -- a plausible way to
            refresh one -- deleted every rule file and then raised, leaving
            the index still claiming the pack was there
          * two typed names that sanitise to one directory clobbered each
            other, and the second install silently threw away a pack the
            user had promoted, trust flag and all
          * a pack that compiled in its source folder thanks to a relative
            `include` was admitted, copied flat, and never compiled again

        Now the files are copied into a staging directory beside the
        destination, compiled FROM that copy, and only then swapped into
        place. Any failure leaves the previous pack and the index untouched.
        """
        if not admission.accepted:
            raise PackError("refusing to install a pack that was not admitted")
        if yara is None:
            raise PackError("yara-python is not installed")
        if not rule_files:
            raise PackError("the pack contains no rule files")

        safe = _safe_name(name)
        destination = self.pack_dir(safe)

        for path in rule_files:
            if path_within(path, destination) or same_path(path, destination):
                raise PackError(
                    f"{path.name} is already inside the installed pack {safe!r}; "
                    "refusing to install a pack over itself")

        seen: dict[str, Path] = {}
        for path in rule_files:
            if path.name in seen:
                raise PackError(
                    f"two source files would both be installed as {path.name!r}: "
                    f"{seen[path.name]} and {path}")
            seen[path.name] = path

        with self._lock:
            self._load()   # never write over another owner's change
            existing = self._packs.get(safe)
            if existing is not None and not replace:
                typed = existing.display_name or existing.name
                raise PackError(
                    f"a pack is already installed as {safe!r} (added as {typed!r}); "
                    "remove it first, or install with replace=True")

            staging = self.directory / f".{safe}.staging"
            backup = self.directory / f".{safe}.previous"
            for leftover in (staging, backup):
                if leftover.exists():
                    shutil.rmtree(leftover, ignore_errors=True)
            staging.mkdir(parents=True)

            try:
                digest = hashlib.sha256()
                for path in sorted(rule_files, key=lambda p: p.name):
                    data = path.read_bytes()
                    digest.update(path.name.encode())
                    digest.update(data)
                    (staging / path.name).write_bytes(data)

                staged = sorted(staging.glob("*.yara")) + sorted(staging.glob("*.yar"))
                try:
                    yara.compile(filepaths={str(f.resolve()): str(f) for f in staged})
                except yara.Error as exc:
                    raise PackError(
                        "the pack was admitted but does not compile once installed "
                        "-- most likely an `include` of a file outside the pack: "
                        f"{exc}") from exc

                if destination.exists():
                    os.replace(destination, backup)
                try:
                    os.replace(staging, destination)
                except OSError:
                    if backup.exists():
                        os.replace(backup, destination)
                    raise
                if backup.exists():
                    shutil.rmtree(backup, ignore_errors=True)
            except BaseException:
                shutil.rmtree(staging, ignore_errors=True)
                raise

            pack = RulePack(
                name=safe,
                display_name=name,
                source=source,
                licence=licence,
                sha256=digest.hexdigest(),
                rule_count=admission.rule_count,
                file_count=len(rule_files),
                false_positive_rate=admission.false_positive_rate,
                corpus_size=admission.corpus_size,
                trusted=False,
                notes=list(admission.reasons),
            )
            self._packs[safe] = pack
            self._save()

        log.info("installed rule pack %s: %s", safe, pack.describe())
        return pack

    def remove(self, name: str) -> bool:
        safe = _safe_name(name)
        with self._lock:
            self._load()   # never write over another owner's change
            if safe not in self._packs:
                return False
            shutil.rmtree(self.pack_dir(safe), ignore_errors=True)
            del self._packs[safe]
            self._save()
        log.info("removed rule pack %s", safe)
        return True

    def set_trusted(self, name: str, trusted: bool) -> RulePack:
        """Let a pack's rules count for as much as their own metadata says.

        Separate and deliberate. Until this is called, nothing the pack says
        can move a file, however severe the rule claims to be.
        """
        safe = _safe_name(name)
        with self._lock:
            self._load()   # never write over another owner's change
            pack = self._packs.get(safe)
            if pack is None:
                raise PackError(f"no rule pack called {name!r}")
            pack.trusted = trusted
            self._save()
        log.warning("rule pack %s is now %s", safe,
                    "trusted to move files" if trusted else "reporting only")
        return pack


def _safe_name(name: str) -> str:
    """A pack name that is safe as a directory name."""
    cleaned = "".join(c if c.isalnum() or c in "-_." else "-" for c in name).strip("-.")
    return cleaned[:64] or "pack"


def _avguard_files(packs_dir: Path = PACKS_DIR,
                   exclude: Iterable[Path] = ()) -> list[Path]:
    """The files a pack must not match, for the reason v1 demonstrated.

    The whole project, the user's own rules, and every OTHER installed pack.
    It used to walk three directories; protection.py records the same mistake
    being made once for self-protection and fixed by covering everything.
    `exclude` holds the candidate pack's own directories -- its destination,
    and where it is being added from -- since a pack legitimately contains
    the strings it hunts for.
    """
    skip_dirs = {"__pycache__", "build", "dist", "node_modules"}
    excluded = [exclude] if isinstance(exclude, (str, Path)) else list(exclude)
    found: list[Path] = []

    def walk(directory: Path) -> None:
        if not directory.is_dir():
            return
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(directory).parts
            if any(part in skip_dirs for part in relative):
                continue
            # .git, .venv, and a pack's own `.name.staging` / `.name.previous`
            # leftovers: the last two blocked re-adding a pack, since the
            # CLI admits before install() clears them.
            if any(part.startswith(".") for part in relative):
                continue
            # Positive fixtures are supposed to match rules.
            if "must_match" in relative:
                continue
            if any(path_within(path, ex) for ex in excluded):
                continue
            found.append(path)

    walk(config.PROJECT_ROOT)
    walk(config.USER_RULES_DIR)
    walk(packs_dir)
    return found
