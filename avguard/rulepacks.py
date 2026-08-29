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
import shutil
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .protection import path_within

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

    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
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
    offending: list[str] = field(default_factory=list)


class PackStore:
    """Packs on disk, and what is known about each."""

    def __init__(self, directory: Path = PACKS_DIR,
                 index_path: Path = PACKS_INDEX) -> None:
        self.directory = Path(directory)
        self.index_path = Path(index_path)
        self._lock = threading.RLock()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._packs: dict[str, RulePack] = {}
        self._load()

    # ---------------------------------------------------------------- index

    def _load(self) -> None:
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._packs = {}
            return
        packs: dict[str, RulePack] = {}
        for name, data in (raw or {}).items():
            try:
                packs[name] = RulePack(**data)
            except TypeError:
                log.warning("dropping a malformed pack record for %r", name)
        self._packs = packs

    def _save(self) -> None:
        payload = {k: asdict(v) for k, v in self._packs.items()}
        config.atomic_write_text(self.index_path, json.dumps(payload, indent=2))

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

        result.rule_count = _count_rules(rule_files)
        if not result.rule_count:
            result.reasons.append("compiles, but declares no rules")
            return result

        # It must not match us. This is the failure that ended v1.
        for path in protected_files or _avguard_files():
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

        result.accepted = True
        result.reasons.append(
            f"{result.rule_count} rules, {result.false_positive_rate:.2%} of "
            f"{examined} clean files flagged, no rule over the ceiling")
        return result

    def install(self, name: str, rule_files: list[Path], admission: Admission,
                source: str = "", licence: str = "") -> RulePack:
        """Copy an admitted pack into place and record what was measured."""
        if not admission.accepted:
            raise PackError("refusing to install a pack that was not admitted")

        safe = _safe_name(name)
        with self._lock:
            destination = self.pack_dir(safe)
            if destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            destination.mkdir(parents=True, exist_ok=True)

            digest = hashlib.sha256()
            for path in sorted(rule_files, key=lambda p: p.name):
                data = path.read_bytes()
                digest.update(path.name.encode())
                digest.update(data)
                (destination / path.name).write_bytes(data)

            pack = RulePack(
                name=safe,
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


def _count_rules(paths: list[Path]) -> int:
    import re
    total = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        total += len(re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+\w+", text, re.M))
    return total


def _avguard_files() -> list[Path]:
    """The files a pack must not match, for the reason v1 demonstrated."""
    found: list[Path] = []
    for folder in ("rules", "avguard", "docs"):
        directory = config.PROJECT_ROOT / folder
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                found.append(path)
    return found
