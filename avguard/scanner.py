"""The scan pipeline: guards, then one read, then rules.

The original build read every file three times (once chunked for signatures,
once again for the SHA-256, and a third time inside YARA) and then made a
blocking network call. This version reads once and orders the checks cheapest
first, so most files are decided without any I/O at all.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

from . import allowlist as allowlist_module
from . import archives, config, peinfo, signing
from .protection import SelfProtection, matches_excluded_glob

log = logging.getLogger(__name__)

try:
    import yara
except ImportError:  # pragma: no cover - yara is a hard dependency in practice
    yara = None


class Level(str, Enum):
    """How a file came out of the pipeline."""

    CLEAN = "clean"
    SKIPPED = "skipped"
    SUSPICIOUS = "suspicious"   # reported, never auto-quarantined on its own
    MALICIOUS = "malicious"
    ERROR = "error"


# The EICAR test string, built from bytes so this source file is not itself a
# sample that other scanners will flag. Byte 11 is a backslash; the original
# YARA rule dropped it, which is why that rule never matched a real EICAR file.
EICAR = bytes([
    0x58, 0x35, 0x4F, 0x21, 0x50, 0x25, 0x40, 0x41, 0x50, 0x5B, 0x34, 0x5C,
    0x50, 0x5A, 0x58, 0x35, 0x34, 0x28, 0x50, 0x5E, 0x29, 0x37, 0x43, 0x43,
    0x29, 0x37, 0x7D, 0x24, 0x45, 0x49, 0x43, 0x41, 0x52, 0x2D, 0x53, 0x54,
    0x41, 0x4E, 0x44, 0x41, 0x52, 0x44, 0x2D, 0x41, 0x4E, 0x54, 0x49, 0x56,
    0x49, 0x52, 0x55, 0x53, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x46, 0x49,
    0x4C, 0x45, 0x21, 0x24, 0x48, 0x2B, 0x48, 0x2A,
])

# A harmless marker for checking that the scanner works. EICAR is the industry
# standard, but Windows Defender deletes an EICAR file the moment it is
# written, so on a protected machine you cannot use it to test your own
# scanner. This marker is ours alone and nothing else reacts to it.
SELFTEST_MARKER = b"AVGUARD-SELFTEST-MARKER-a41f9c2d-DO-NOT-PANIC"

# Name -> byte pattern. Deliberately short: local signatures are for things
# with an exact, unambiguous byte pattern. The old build listed the four-byte
# MZ header here, which flags every executable on Windows -- measured at
# 40 out of 40 genuine files in System32.
SIGNATURES: dict[str, bytes] = {
    "EICAR-Test-File": EICAR,
    "AVGuard-Selftest-Marker": SELFTEST_MARKER,
}

EXECUTABLE_SUFFIXES = frozenset(
    {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx"}
)


# How much each kind of evidence counts towards a verdict.
#
# The previous version treated every YARA hit as MALICIOUS, which meant "move
# the user's file". The rules already carried `severity` metadata and the code
# threw it away, so a rule the author marked "medium" was as decisive as an
# exact byte signature. Three ordinary CI scripts were being quarantined.
MALICIOUS_AT = 100
SUSPICIOUS_AT = 50

# Bump this whenever anything that decides a verdict changes: the scoring, the
# archive logic, the PE heuristics, the guards. Cached verdicts are conclusions
# drawn by a particular version of this code, and a conclusion outlives the
# reasoning that produced it unless something says otherwise.
#
# Learned by shipping it: the archive inspector stopped calling large resource
# packs "hostile", and the machine kept reporting the old verdict because the
# generation hash only covered the rule file.
DETECTION_VERSION = 6

# Heuristics never add up to a condemnation, however many of them agree.
#
# Found the hard way: cygwin1.dll trips the process-injection rule (medium, 50)
# AND has a writable-executable section plus a virtual-only section (50). Two
# independent heuristics, 100 points, and a universally used library would have
# been quarantined. Weak signals correlate -- an unusual binary trips several
# checks for one underlying reason -- so summing them manufactures confidence
# that does not exist. Only hard evidence can cross the line.
HEURISTIC_CAP = 75

WEIGHT_SIGNATURE = 100      # an exact byte match is not a judgement call
WEIGHT_ENTROPY = 25         # supporting evidence, never decisive alone
WEIGHT_PE_STRUCTURE = 50    # two structural oddities together; still not decisive
WEIGHT_ARCHIVE_PROBLEM = 50  # a bomb or a traversal name; SUSPICIOUS, never moved

# Keyed on the `severity` value in a rule's meta block.
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 100,
    "high": 100,
    "test": 100,            # EICAR and the selftest marker must stay decisive
    "medium": 50,
    "low": 25,
    "info": 10,
}
# A rule that does not declare a severity is not trusted to condemn on its own.
WEIGHT_UNLABELLED = 25


@dataclass(frozen=True)
class Finding:
    """One piece of evidence about a file.

    `hard` separates fact from opinion. An exact byte match, a rule its author
    marked high severity, or several cloud engines agreeing are facts. A
    section with odd flags, high entropy, or a medium-severity rule are
    opinions -- useful to report, never enough to move someone's file.
    """

    source: str        # "signature" | "yara" | "entropy" | "cloud" | "pe" | "archive"
    name: str
    weight: int
    detail: str = ""
    hard: bool = False

    def describe(self) -> str:
        return self.detail or f"{self.source} {self.name}"


@dataclass(frozen=True)
class FileFacts:
    """Everything one read of a file produced."""

    path: Path
    size: int
    mtime_ns: int
    sha256: str
    entropy: float
    signature_hits: tuple[str, ...] = ()
    data: bytes | None = None  # kept only for files small enough to buffer


@dataclass
class Verdict:
    path: Path
    level: Level
    reasons: list[str] = field(default_factory=list)
    facts: FileFacts | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def is_threat(self) -> bool:
        """The single gate on whether anything gets moved."""
        return self.level is Level.MALICIOUS

    def describe(self) -> str:
        if not self.reasons:
            return self.level.value
        return f"{self.level.value}: {'; '.join(self.reasons)}"


def decide(findings: Sequence[Finding], malicious_at: int = MALICIOUS_AT) -> Level:
    """Turn accumulated evidence into one verdict.

    Hard evidence -- a byte signature, a high-severity rule, cloud consensus --
    can reach MALICIOUS and so can cause a file to be moved. Heuristics are
    summed separately and capped below the threshold, so no pile of guesses
    ever adds up to a condemnation. A file can be as suspicious as you like and
    still not be touched.
    """
    if not findings:
        return Level.CLEAN

    hard = sum(f.weight for f in findings if f.hard)
    soft = min(sum(f.weight for f in findings if not f.hard), HEURISTIC_CAP)

    if hard >= malicious_at:
        return Level.MALICIOUS
    if hard + soft >= SUSPICIOUS_AT:
        return Level.SUSPICIOUS
    return Level.CLEAN


def _is_junction(path: Path) -> bool:
    """os.path.isjunction, but tolerant of interpreters that lack it.

    Added in Python 3.12. Calling it unguarded on 3.11 raises AttributeError
    once per file, which would fail every scan rather than degrade -- and a
    junction is a Windows reparse point, so on any other platform the honest
    answer is simply False.
    """
    checker = getattr(os.path, "isjunction", None)
    if checker is None:
        return False
    try:
        return bool(checker(path))
    except OSError:
        return False


def shannon_entropy(histogram: Sequence[int], total: int) -> float:
    """Bits of entropy per byte, 0.0 to 8.0.

    Packed or encrypted data sits above ~7.2; ordinary text and code sit well
    below it. Used only as a supporting signal, never on its own.
    """
    if total <= 0:
        return 0.0
    result = 0.0
    for count in histogram:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return result


class ScanCache:
    """Remembers verdicts so an unchanged file is not scanned twice.

    Keyed on path plus size plus mtime, which is what actually changes when a
    file is edited. In real-time mode this is the difference between scanning
    a file once and scanning it on every editor autosave.
    """

    # Bumped whenever a stored verdict would mean something different. Entries
    # written under an older schema are dropped rather than replayed.
    SCHEMA = 2

    def __init__(self, path: Path = config.SCAN_CACHE_PATH, max_entries: int = 20_000,
                 generation: str = "", ttl_days: int = 30):
        self._path = path
        self._max = max_entries
        self._generation = generation
        self._ttl_seconds = ttl_days * 24 * 3600
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}
        self._load()

    @staticmethod
    def _key(path: Path, size: int, mtime_ns: int) -> str:
        return f"{str(path).lower()}|{size}|{mtime_ns}"

    def _load(self) -> None:
        """Read the cache, discarding it if it was written by different logic.

        A cached verdict is a conclusion, not a fact. When the rules or the
        scoring change, every stored conclusion is stale -- and a stale
        MALICIOUS would be replayed without ever reopening the file.
        """
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._entries = {}
            return

        if not isinstance(raw, dict) or raw.get("schema") != self.SCHEMA:
            log.info("scan cache was written by an older version; starting fresh")
            self._entries = {}
            return

        if self._generation and raw.get("generation") != self._generation:
            log.info("detection rules changed since the cache was written; starting fresh")
            self._entries = {}
            return

        entries = raw.get("entries")
        self._entries = entries if isinstance(entries, dict) else {}

    def prune(self, now: float | None = None) -> int:
        """Drop entries that are too old, then the oldest if still over the cap.

        The cache is a durable inventory of the user's file paths, so it is not
        allowed to accumulate forever: on this machine it had reached 1,391
        absolute paths with no expiry and no way to clear it. Eviction is by
        age rather than by insertion order, so a file scanned once a year ago
        does not outlive one scanned yesterday.
        """
        now = now if now is not None else time.time()
        cutoff = now - self._ttl_seconds
        removed = 0
        with self._lock:
            for key in [k for k, v in self._entries.items()
                        if v.get("at", 0) < cutoff]:
                del self._entries[key]
                removed += 1
            if len(self._entries) > self._max:
                ordered = sorted(self._entries.items(), key=lambda kv: kv[1].get("at", 0))
                for key, _ in ordered[: len(self._entries) - self._max]:
                    del self._entries[key]
                    removed += 1
        return removed

    def clear(self) -> None:
        """Forget every cached verdict, and the path list with it."""
        with self._lock:
            self._entries = {}
        try:
            config.atomic_write_text(
                self._path,
                json.dumps({"schema": self.SCHEMA, "generation": self._generation,
                            "entries": {}}))
        except OSError as exc:
            log.warning("could not clear the scan cache: %s", exc)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def save(self) -> None:
        self.prune()
        with self._lock:
            snapshot = dict(self._entries)
        payload = {"schema": self.SCHEMA, "generation": self._generation, "entries": snapshot}
        try:
            config.atomic_write_text(self._path, json.dumps(payload))
        except OSError as exc:
            log.warning("could not save scan cache: %s", exc)

    def get(self, path: Path, size: int, mtime_ns: int) -> dict | None:
        with self._lock:
            return self._entries.get(self._key(path, size, mtime_ns))

    def put(self, path: Path, size: int, mtime_ns: int, level: Level,
            reasons: list[str], sha256: str) -> None:
        with self._lock:
            self._entries[self._key(path, size, mtime_ns)] = {
                "level": level.value,
                "reasons": reasons,
                "sha256": sha256,
                "at": time.time(),
            }

    def invalidate(self, path: Path) -> None:
        prefix = f"{str(path).lower()}|"
        with self._lock:
            for key in [k for k in self._entries if k.startswith(prefix)]:
                del self._entries[key]


class Scanner:
    """Runs the detection stages against one file at a time."""

    def __init__(
        self,
        cfg: config.Config,
        protection: SelfProtection,
        rules_path: Path = config.RULES_PATH,
        cache: ScanCache | None = None,
        cloud_lookup: Callable[[str, Path], list[str]] | None = None,
    ) -> None:
        self.cfg = cfg
        self.protection = protection
        self.cache = cache if cache is not None else ScanCache()
        self.cloud_lookup = cloud_lookup
        self.rules_path = rules_path
        self.rules = None
        self.rule_sources: list[Path] = []
        self.signatures = signing.SignatureChecker()
        self.allowlist = allowlist_module.Allowlist()
        self._max_signature = max((len(s) for s in SIGNATURES.values()), default=0)
        self.load_rules()
        if cache is None:
            # Built here rather than as a default argument so the cache can be
            # keyed on the ruleset that is actually loaded.
            self.cache = ScanCache(generation=self.detection_generation())

    # ---------------------------------------------------------------- rules

    def detection_generation(self) -> str:
        """A short hash of everything that decides a verdict.

        Covers DETECTION_VERSION, the ruleset text, the local signatures and
        the detection-related settings, so changing any of them invalidates
        every cached verdict instead of leaving the machine replaying
        conclusions drawn by logic that no longer exists.
        """
        digest = hashlib.sha256()
        digest.update(str(ScanCache.SCHEMA).encode())
        digest.update(f"detection={DETECTION_VERSION}".encode())
        for name, pattern in sorted(SIGNATURES.items()):
            digest.update(name.encode())
            digest.update(pattern)
        for weight_name, weight in sorted(SEVERITY_WEIGHTS.items()):
            digest.update(f"{weight_name}={weight}".encode())
        digest.update(f"pe={self.cfg.pe_analysis_enabled}".encode())
        digest.update(f"zip={self.cfg.archive_scanning_enabled}".encode())
        digest.update(f"signed={self.cfg.trust_signed_publishers}".encode())
        for path in self.rule_files():
            try:
                digest.update(path.name.encode())
                digest.update(path.read_bytes())
            except OSError:
                digest.update(b"<unreadable>")
        return digest.hexdigest()[:16]

    def rule_files(self) -> list[Path]:
        """Shipped rules first, then the user's own.

        The user's rules live in their data directory, so updating AVGuard
        replaces `rules/` without touching anything they wrote.
        """
        found: list[Path] = []
        for directory in (self.rules_path.parent, config.USER_RULES_DIR):
            if not directory.is_dir():
                continue
            found.extend(sorted(directory.glob("*.yara")))
            found.extend(sorted(directory.glob("*.yar")))
        return found

    def load_rules(self) -> bool:
        """Compile every ruleset, validate it, and only then adopt it.

        Three things this must not do, all of them learned from v1:

          * fail quietly. A compile error there set `yara_rules = None` and the
            scanner ran for weeks with its main engine off, saying nothing.
          * adopt a ruleset that matches AVGuard's own files. That is what let
            v1 quarantine its own rules and lose detection permanently.
          * throw away a working ruleset because a new one is broken. A bad
            edit to a user rule should cost you that rule, not all detection.
        """
        if yara is None:
            log.error("yara-python is not installed; rule matching is unavailable")
            return False

        sources = self.rule_files()
        if not sources:
            log.error("no rule files found in %s or %s; rule matching is unavailable",
                      self.rules_path.parent, config.USER_RULES_DIR)
            return False

        namespaces = {}
        for path in sources:
            namespaces[path.stem if path.name not in namespaces else str(path)] = str(path)

        try:
            candidate = yara.compile(filepaths=namespaces)
        except yara.Error as exc:
            self._report_rule_failure(f"rules failed to compile: {exc}")
            return False

        problem = self._validate_rules(candidate)
        if problem:
            self._report_rule_failure(problem)
            return False

        self.rules = candidate
        self.rule_sources = sources
        log.info("compiled %d rule file(s): %s", len(sources),
                 ", ".join(p.name for p in sources))
        return True

    def _validate_rules(self, candidate) -> str:
        """Check a candidate ruleset before adopting it.

        A rule that matches its own file is the v1 disaster in miniature. It is
        no longer fatal -- the whole project is under self-protection now, so
        the scanner cannot quarantine its own rules whatever they say -- but it
        is still a broken rule, because it will fire on any copy, backup or
        piece of documentation that quotes it.

        So the standard differs by author. Rules shipped with AVGuard are
        rejected outright, and the test harness enforces the same thing. Rules
        the user wrote are warned about and loaded, with the fix spelled out:
        rejecting somebody's first rule with a lecture just teaches them to
        turn validation off.
        """
        shipped = self.rules_path.parent.resolve()
        for path in self.rule_files():
            try:
                if not candidate.match(data=path.read_bytes()):
                    continue
            except Exception:
                continue
            if path.resolve().parent == shipped:
                return (f"refused: the shipped ruleset matches its own file "
                        f"{path.name}, which is how v1 destroyed itself")
            log.warning(
                "your rule file %s matches itself. It still loaded, but it will "
                "fire on any copy of itself. Write the indicator as hex "
                "({ 41 42 43 }) or as a regex with one bracketed character "
                "(/AB[C]/) so the literal never appears in the rule text.",
                path.name)

        try:
            for path in config.PACKAGE_DIR.glob("*.py"):
                if candidate.match(data=path.read_bytes()):
                    log.warning("a rule matches AVGuard's own source file %s", path.name)
        except Exception:
            pass
        return ""

    def _report_rule_failure(self, message: str) -> None:
        """Keep whatever was working, and be loud about what was not."""
        if self.rules is not None:
            log.error("%s -- keeping the previously loaded rules", message)
        else:
            log.error("%s -- no rules are loaded, detection is severely reduced", message)

    def reload_rules(self) -> bool:
        """Recompile from disk. Used by the Reload button and after an update."""
        previous = self.rules
        ok = self.load_rules()
        if not ok and previous is not None:
            self.rules = previous
        if ok:
            self.cache = ScanCache(path=self.cache._path,
                                   generation=self.detection_generation())
        return ok

    # ---------------------------------------------------------------- guards

    def _guard(self, path: Path) -> Verdict | None:
        """Cheap refusals, in order, before the file is opened."""
        if self.protection.is_protected(path):
            return Verdict(path, Level.SKIPPED, ["protected: belongs to AVGuard"])

        if matches_excluded_glob(path, self.cfg.excluded_globs):
            return Verdict(path, Level.SKIPPED, ["excluded by configuration"])

        try:
            stat = path.lstat()
        except OSError as exc:
            return Verdict(path, Level.ERROR, [f"cannot stat: {exc}"])

        # Do not follow reparse points out of the scan tree. os.path.islink is
        # False for a Windows junction and os.walk(followlinks=False) descends
        # straight through one, so a junction named "logs" pointing at
        # Documents would pull the whole folder into the scan.
        if path.is_symlink() or _is_junction(path):
            return Verdict(path, Level.SKIPPED, ["reparse point, not followed"])

        if not os.path.isfile(path):
            return Verdict(path, Level.SKIPPED, ["not a regular file"])

        if stat.st_size == 0:
            return Verdict(path, Level.CLEAN, ["empty file"])

        if stat.st_size > self.cfg.max_file_size:
            mb = stat.st_size / (1024 * 1024)
            return Verdict(path, Level.SKIPPED, [f"larger than the size cap ({mb:.0f} MB)"])

        return None

    # ------------------------------------------------------------ the read

    def _read_facts(self, path: Path, size: int, mtime_ns: int) -> FileFacts:
        """One pass over the file producing hash, signature hits and entropy.

        Signatures are matched across chunk boundaries by carrying the tail of
        each chunk forward. The old build compared each chunk in isolation, so
        a signature straddling a 4 KB boundary was missed.
        """
        digest = hashlib.sha256()
        histogram = [0] * 256
        hits: set[str] = set()
        overlap = b""
        carry = max(self._max_signature - 1, 0)
        buffered = bytearray() if size <= config.YARA_BUFFER_MAX else None

        with open(path, "rb") as handle:
            while chunk := handle.read(config.CHUNK_SIZE):
                digest.update(chunk)
                if buffered is not None:
                    buffered.extend(chunk)
                for byte in chunk:
                    histogram[byte] += 1
                window = overlap + chunk
                for name, pattern in SIGNATURES.items():
                    if name not in hits and pattern in window:
                        hits.add(name)
                overlap = window[-carry:] if carry else b""

        return FileFacts(
            path=path,
            size=size,
            mtime_ns=mtime_ns,
            sha256=digest.hexdigest(),
            entropy=shannon_entropy(histogram, size),
            signature_hits=tuple(sorted(hits)),
            data=bytes(buffered) if buffered is not None else None,
        )

    # ---------------------------------------------------------------- rules

    def _yara_matches(self, facts: FileFacts) -> list[Finding]:
        if self.rules is None:
            return []
        try:
            # Files small enough to buffer are matched from memory, so the
            # whole scan is genuinely one read.
            if facts.data is not None:
                matches = self.rules.match(data=facts.data)
            else:
                matches = self._match_large_file(facts)
        except Exception as exc:  # yara.Error, plus timeouts on huge files
            log.warning("YARA could not scan %s: %s", facts.path, exc)
            return []

        findings = []
        for match in matches:
            meta = dict(getattr(match, "meta", {}) or {})
            severity = str(meta.get("severity", "")).strip().lower()
            weight = SEVERITY_WEIGHTS.get(severity, WEIGHT_UNLABELLED)
            if severity and severity not in SEVERITY_WEIGHTS:
                log.warning("rule %s declares an unknown severity %r; scoring it as %d",
                            match.rule, severity, weight)
            description = str(meta.get("description", "")).strip()
            detail = description or f"matched rule {match.rule}"
            findings.append(Finding(
                "yara", match.rule, weight,
                f"{detail} (rule {match.rule}, {severity or 'unrated'})",
                hard=weight >= MALICIOUS_AT))
        return findings

    def _match_large_file(self, facts: FileFacts):
        """YARA-match a file too big to have been buffered during the read.

        `match(filepath=...)` is preferred because it lets YARA memory-map the
        file instead of us holding it. But yara-python cannot open a path
        containing non-ASCII characters on Windows -- it raises
        "could not open file" -- and the previous code logged that and moved
        on, so on a machine with, say, Thai filenames every file over the
        buffer limit silently skipped YARA altogether. A warning in a log is
        not a substitute for scanning the file.
        """
        try:
            return self.rules.match(filepath=str(facts.path), timeout=60)
        except yara.Error as exc:
            if "could not open file" not in str(exc):
                raise
        log.debug("YARA could not open %s by path; matching from memory instead",
                  facts.path)
        # Bounded by the guard: anything past cfg.max_file_size never gets here.
        with open(facts.path, "rb") as handle:
            data = handle.read(self.cfg.max_file_size)
        return self.rules.match(data=data)

    def _pe_findings(self, facts: FileFacts) -> list[Finding]:
        """Structural oddities in an executable.

        Reported only when two independent signals co-occur. One alone fires
        on 27.5% of clean Program Files binaries and means nothing; two fires
        on 0.25%. Weighted below the quarantine threshold either way, because
        legitimate software gets packed.
        """
        if not self.cfg.pe_analysis_enabled:
            return []
        if facts.path.suffix.lower() not in EXECUTABLE_SUFFIXES:
            return []
        report = peinfo.analyse(facts.path, facts.data)
        if not report.suspicious:
            return []
        return [Finding("pe", "structure", WEIGHT_PE_STRUCTURE,
                        f"unusual executable structure: {report.describe()}")]

    def _archive_findings(self, facts: FileFacts) -> list[Finding]:
        """Scan the contents of a container without unpacking it.

        Real-time protection watches Downloads, so a zipped sample is the
        common case rather than the exotic one. Members are matched in memory;
        nothing is written to disk at any point.
        """
        if not self.cfg.archive_scanning_enabled:
            return []
        if not archives.is_archive(facts.path):
            return []

        report = archives.inspect(facts.path)
        findings: list[Finding] = []

        for note in report.notes:
            # Limits of our own scan. Logged so a partial inspection is
            # visible, never scored -- they say nothing about the file.
            log.debug("%s: %s", facts.path.name, note)

        if report.problems:
            # Collapsed into ONE finding on purpose. A bomb and a traversal
            # name in the same archive is one observation about a hostile
            # container, and emitting one finding each would let structure
            # alone reach the quarantine threshold. Structure describes the
            # file; it never condemns it.
            findings.append(Finding(
                "archive", "structure", WEIGHT_ARCHIVE_PROBLEM,
                "archive is malformed or hostile: " + "; ".join(report.problems[:3])))

        for display, payload in archives.iter_nested(report):
            for name, pattern in SIGNATURES.items():
                if pattern in payload:
                    findings.append(Finding(
                        "signature", name, WEIGHT_SIGNATURE,
                        f"matched the byte signature for {name} inside {display}",
                        hard=True))
            if self.rules is not None:
                try:
                    matches = self.rules.match(data=payload)
                except Exception as exc:
                    log.debug("YARA could not scan %s: %s", display, exc)
                    continue
                for match in matches:
                    meta = dict(getattr(match, "meta", {}) or {})
                    severity = str(meta.get("severity", "")).strip().lower()
                    weight = SEVERITY_WEIGHTS.get(severity, WEIGHT_UNLABELLED)
                    description = str(meta.get("description", "")).strip() or match.rule
                    findings.append(Finding(
                        "yara", match.rule, weight,
                        f"{description} (rule {match.rule}, {severity or 'unrated'}) "
                        f"inside {display}",
                        hard=weight >= MALICIOUS_AT))

        if report.members and report.inspected:
            log.debug("%s: inspected %d of %d archive members",
                      facts.path.name, report.inspected, len(report.members))
        return findings

    def _publisher_trust(self, facts: FileFacts):
        """Authenticode result for a PE, or None if it is not one."""
        if facts.path.suffix.lower() not in EXECUTABLE_SUFFIXES:
            return None
        if not self.signatures.available:
            return None
        return self.signatures.check(facts.path, facts.size, facts.mtime_ns)

    def _wants_cloud_lookup(self, facts: FileFacts) -> bool:
        if not self.cfg.cloud_enabled or self.cloud_lookup is None:
            return False
        return facts.path.suffix.lower() in {e.lower() for e in self.cfg.cloud_extensions}

    # ------------------------------------------------------------- the scan

    def scan(self, path: Path | str, use_cache: bool = True) -> Verdict:
        """Run every stage against one file and return a single verdict."""
        path = Path(path)

        guard = self._guard(path)
        if guard is not None:
            return guard

        stat = path.stat()
        size, mtime_ns = stat.st_size, stat.st_mtime_ns

        if use_cache:
            cached = self.cache.get(path, size, mtime_ns)
            if cached:
                return Verdict(path, Level(cached["level"]), list(cached["reasons"]))

        try:
            facts = self._read_facts(path, size, mtime_ns)
        except (OSError, MemoryError) as exc:
            return Verdict(path, Level.ERROR, [f"cannot read: {exc}"])

        # A file the user restored by hand is a decision about these exact
        # bytes, and it outranks anything found below. Before this, restoring
        # something taught the scanner nothing and it was taken again about a
        # second later -- an argument the user could not win.
        allowed = self.allowlist.allows(facts.sha256)
        if allowed is not None:
            reason = (f"you chose to keep this file on {allowed.when}"
                      + (f" (it was flagged for {'; '.join(allowed.was_flagged_for)})"
                         if allowed.was_flagged_for else ""))
            verdict = Verdict(path, Level.CLEAN, [reason], facts,
                              [Finding("allowlist", "user-decision", 0, reason)])
            if use_cache:
                self.cache.put(path, size, mtime_ns, Level.CLEAN, [reason], facts.sha256)
            return verdict

        findings: list[Finding] = []

        for name in facts.signature_hits:
            findings.append(Finding("signature", name, WEIGHT_SIGNATURE,
                                    f"matched the byte signature for {name}", hard=True))

        findings.extend(self._yara_matches(facts))
        findings.extend(self._pe_findings(facts))
        findings.extend(self._archive_findings(facts))

        # Entropy is supporting evidence only. On its own a high-entropy file is
        # usually a zip, a JPEG or an installer, so it can raise a file to
        # SUSPICIOUS but never on its own to MALICIOUS.
        if facts.entropy > 7.2 and facts.path.suffix.lower() in EXECUTABLE_SUFFIXES:
            findings.append(Finding(
                "entropy", "high-entropy-executable", WEIGHT_ENTROPY,
                f"unusually high entropy for an executable "
                f"({facts.entropy:.2f}/8.00), which can mean it is packed"))

        # A recognised publisher does not clear a detection, but it does mean
        # "unusual" stops meaning "suspicious". Checked only when something has
        # already been flagged, because verification costs ~147 ms.
        signature = None
        if self.cfg.trust_signed_publishers and any(not f.hard for f in findings):
            signature = self._publisher_trust(facts)
            if signature is not None and signature.is_trusted:
                dropped = [f for f in findings if not f.hard]
                findings = [f for f in findings if f.hard]
                if dropped:
                    log.debug("%s is %s; %d heuristic finding(s) set aside",
                              facts.path.name, signature.detail, len(dropped))
                    findings.append(Finding(
                        "signature-trust", "publisher", 0,
                        f"{len(dropped)} heuristic concern(s) set aside because the file is "
                        f"{signature.detail}"))

        level = decide(findings, self.cfg.quarantine_threshold)

        # The cloud is asked only about files nothing local has decided on, so
        # a clean local verdict is what earns an API call, not a suspicious one.
        if level is Level.CLEAN and self._wants_cloud_lookup(facts):
            try:
                cloud_reasons = self.cloud_lookup(facts.sha256, facts.path)
            except Exception as exc:
                log.warning("cloud lookup failed for %s: %s", facts.path, exc)
                cloud_reasons = []
            for reason in cloud_reasons:
                findings.append(Finding("cloud", "virustotal", WEIGHT_SIGNATURE,
                                        reason, hard=True))
            if cloud_reasons:
                level = decide(findings, self.cfg.quarantine_threshold)

        reasons = [f.describe() for f in findings]
        verdict = Verdict(path, level, reasons, facts, findings)
        if use_cache:
            self.cache.put(path, size, mtime_ns, level, reasons, facts.sha256)
        return verdict

    # ------------------------------------------------------------ walking

    def iter_files(self, root: Path | str) -> Iterator[Path]:
        """Yield scannable files under `root`, pruning whole directories early.

        Pruning at the directory level means a protected or excluded tree is
        never descended into at all.
        """
        root = Path(root)
        if root.is_file():
            yield root
            return

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = [
                d for d in dirnames
                if not self.protection.is_protected(current / d)
                and not matches_excluded_glob(current / d, self.cfg.excluded_globs)
                and not (current / d).is_symlink()
                and not _is_junction(current / d)
            ]
            for name in filenames:
                yield current / name

    def scan_tree(
        self,
        root: Path | str,
        on_verdict: Callable[[Verdict], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
        workers: int | None = None,
    ) -> list[Verdict]:
        """Scan everything under `root`, reporting each verdict as it lands.

        Runs across a thread pool. Scanning is a mix of blocking file reads and
        YARA matching that releases the GIL, so threads genuinely help: this
        was a plain serial loop managing 24 MB/s while the worker pool sat
        unused except in real-time mode.

        `on_verdict` is called from worker threads and must be safe to call
        concurrently. The GUI's callback only queues work for the Tk thread.
        """
        workers = max(1, workers if workers is not None else self.cfg.worker_threads)
        results: list[Verdict] = []
        results_lock = threading.Lock()

        def work(path: Path) -> None:
            if should_stop is not None and should_stop():
                return
            try:
                verdict = self.scan(path)
            except Exception:
                log.exception("scan failed on %s", path)
                return
            with results_lock:
                results.append(verdict)
            if on_verdict is not None:
                on_verdict(verdict)

        if workers == 1:
            for path in self.iter_files(root):
                if should_stop is not None and should_stop():
                    log.info("scan of %s cancelled", root)
                    break
                work(path)
        else:
            with ThreadPoolExecutor(max_workers=workers,
                                    thread_name_prefix="avguard-tree") as pool:
                pending: set = set()
                for path in self.iter_files(root):
                    if should_stop is not None and should_stop():
                        log.info("scan of %s cancelled", root)
                        break
                    # Bounded so a huge tree does not queue millions of futures.
                    if len(pending) >= workers * 64:
                        done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    pending.add(pool.submit(work, path))
                for future in pending:
                    future.exception()

        self.cache.save()
        return results

    def count_files(self, root: Path | str) -> int:
        """Used to size the progress bar before a full scan starts."""
        return sum(1 for _ in self.iter_files(root))
