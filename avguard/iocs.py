"""A local blocklist of known-bad SHA-256 hashes.

The scanner has computed a SHA-256 for every file since v2 and did nothing
local with it except caching and the optional VirusTotal lookup. Matching a
hash against a list of confirmed malware is the cheapest real detection there
is: one indexed point lookup per file, offline, and the workflow a SOC calls
IOC matching. Threat-intelligence feeds publish these hashes for free.

Two rules from the rest of the program apply here unchanged:

  * a hash on the list is HARD evidence -- a confirmed sample is as decisive
    as a byte signature -- so a hit can move a file;
  * the list is detection logic, so its state is part of the detection
    generation: a file cached CLEAN before an import is judged again.

Nothing is fetched unless the user says so. The feed updater is off by
default, and turning it on names exactly what leaves the machine: an HTTPS
request to bazaar.abuse.ch carrying the previous download's ETag and nothing
about this machine or its files.

Why SQLite and not a set in memory: the full MalwareBazaar export is over a
million rows. Measured here with a million random digests: 100 MB on disk,
a point lookup of 4 us on a warm connection, and the process never holds the
list. Why a transaction and not "build beside and os.replace": Windows will
not replace a file another handle has open, and the running GUI holds one.
A transaction gives the same guarantee -- a bad download changes nothing --
without the file dance.

The same database holds a second, smaller table: TLSH digests of known
samples, for the similarity match in `avguard/tlsh.py`. A line of
`--iocs-import` that looks like a TLSH digest ("T1" + 70 hex, an optional
",family" after it) lands there instead of in the hash table. Those rows are
detection state too, so they are part of the generation token, and a change
to them is noticed by a running scanner the same way a hash import is.
"""

from __future__ import annotations

import io
import logging
import re
import sqlite3
import threading
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import config
from . import tlsh as tlsh_module

log = logging.getLogger(__name__)

IOC_DB_PATH = config.DATA_DIR / "iocs.sqlite"

FEED_SOURCE = "malwarebazaar"
FEED_RECENT_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
FEED_FULL_URL = "https://bazaar.abuse.ch/export/txt/sha256/full/"
# A captive portal, a maintenance page or a rate-limit notice parses to a
# handful of valid-looking lines at most. Below this the download is not the
# feed, and a download that is not the feed must not touch the list.
FEED_MIN_VALID_LINES = 100
FEED_INTERVAL_SECONDS = 24 * 3600
FEED_MAX_BYTES = 256 * 1024 * 1024
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 60
USER_AGENT = "AVGuard (https://github.com/Captain-Coding74/avguard)"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Past this many TLSH references the similarity match starts crying wolf.
# Measured with tools/tlsh_calibration.py: the chance that SOME reference
# sits within distance 30 of an unrelated file grows with the set, and 250
# references mark about 0.25% of clean executables SUSPICIOUS on resemblance
# alone on the Linux corpus and 1.5% on a Windows CI runner full of
# software (1,000 mark 1% and 5.7%; ROADMAP.md has both tables). The set is
# meant to be seeded by hand with families that matter here, not with a
# feed. Logged once, at load. (Cost is not the limit: 10,000 references
# measured 2.5 ms per digested file with numpy, 53 ms without.)
TLSH_WARN_REFERENCES = 250


class IocError(RuntimeError):
    """Something the blocklist could not do; the list is unchanged."""


class FeedError(IocError):
    """The feed could not be fetched or was not the feed."""


@dataclass
class ImportResult:
    source: str = ""
    lines: int = 0
    added: int = 0
    already_known: int = 0
    rejected: int = 0
    tlsh_added: int = 0
    tlsh_known: int = 0

    def describe(self) -> str:
        text = (f"{self.added:,} new hash(es) from source '{self.source}'; "
                f"{self.already_known:,} already known, {self.rejected:,} line(s) "
                f"rejected (not a SHA-256 or a TLSH digest)")
        if self.tlsh_added or self.tlsh_known:
            text += (f"; {self.tlsh_added:,} new TLSH reference(s), "
                     f"{self.tlsh_known:,} already known")
        return text


@dataclass
class ParsedLines:
    """What an import file held: hashes, TLSH references, and the rest."""

    hashes: list[bytes]
    tlsh: list[tuple[str, str]]   # (canonical digest, family)
    rejected: int
    seen: int


@dataclass
class TlshEntry:
    """One row of the reference table, as the Settings page lists it."""
    digest: str
    family: str
    source: str
    added_at: float

    @property
    def when(self) -> str:
        try:
            return datetime.fromtimestamp(self.added_at).strftime("%Y-%m-%d %H:%M")
        except (ValueError, OSError, OverflowError):
            return "unknown"


@dataclass
class ReferenceResult:
    """What came of marking a sample as a known one."""
    digest: str = ""
    added: bool = False
    known: bool = False
    reason: str = ""          # why no reference was added, when none was

    @property
    def ok(self) -> bool:
        return bool(self.digest)


_SIGNATURE_NAME = re.compile(r"byte signature for (\S+)")
_RULE_NAME = re.compile(r"\(rule ([^,)\s]+)")


def family_from_reasons(reasons: Iterable[str], fallback: str = "") -> str:
    """A family name to suggest for a quarantined file, from why it was taken.

    The byte signature's name, else the first YARA rule's name, else the
    fallback (the file's stem), else "quarantined". A suggestion: the dialog
    lets the user change it.
    """
    for reason in reasons:
        for pattern in (_SIGNATURE_NAME, _RULE_NAME):
            found = pattern.search(reason)
            if found:
                return found.group(1).strip()
    return fallback.strip() or "quarantined"


@dataclass
class FeedResult:
    status: str                       # "updated" | "unchanged" | "not due" | "disabled"
    url: str = ""
    imported: ImportResult | None = None


def parse_hashes(lines: Iterable[str]) -> tuple[list[bytes], int, int]:
    """Digests, lines rejected, lines seen. Comments and blanks are neither.

    Defensive on purpose: `#` comments, quotes, a trailing comma or a CSV
    tail are all stripped; what is left must be exactly 64 hex characters.
    """
    parsed = parse_lines(lines)
    return parsed.hashes, parsed.rejected + len(parsed.tlsh), parsed.seen


def parse_lines(lines: Iterable[str]) -> ParsedLines:
    """Every line is a SHA-256, a TLSH digest with an optional family, or rejected.

    A TLSH line is "T1" + 70 hex characters (the bare 70 are accepted too),
    then optionally a comma and the family name -- what MalwareBazaar calls
    the signature. Anything after a second comma is ignored, so a CSV row
    pasted from a report parses as long as the digest comes first.
    """
    digests: list[bytes] = []
    references: list[tuple[str, str]] = []
    rejected = 0
    seen = 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        seen += 1
        first, _, rest = line.partition(",")
        token = first.strip().strip("\"'")
        if _HEX64.match(token.lower()):
            digests.append(bytes.fromhex(token))
            continue
        canonical = tlsh_module.normalize(token)
        if canonical is not None:
            family = rest.split(",", 1)[0].strip().strip("\"'")
            references.append((canonical, family))
            continue
        rejected += 1
    return ParsedLines(digests, references, rejected, seen)


class IocStore:
    """Known-bad hashes on disk, looked up one at a time."""

    def __init__(self, path: Path = IOC_DB_PATH) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._warned = False

    # ------------------------------------------------------------ plumbing

    def _conn(self) -> sqlite3.Connection:
        """One connection per thread; sqlite3 objects do not cross threads."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=5)
            # WAL: readers on the worker threads never wait for an import.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS hashes("
                "digest BLOB PRIMARY KEY, source TEXT NOT NULL, added_at REAL NOT NULL"
                ") WITHOUT ROWID")
            conn.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS tlsh("
                "digest TEXT PRIMARY KEY, family TEXT NOT NULL, source TEXT NOT NULL, "
                "added_at REAL NOT NULL) WITHOUT ROWID")
            conn.commit()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def _get_meta(self, key: str, default: str = "") -> str:
        row = self._conn().execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    @staticmethod
    def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))

    def _bump(self, conn: sqlite3.Connection, delta: int) -> None:
        """Inside a write transaction: the list changed by `delta` rows."""
        self._set_meta(conn, "version", str(self.version() + 1))
        total = int(conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]) \
            if not self._get_meta("count") else self.count() + delta
        self._set_meta(conn, "count", str(max(0, total)))

    # -------------------------------------------------------------- reading

    def lookup(self, sha256_hex: str) -> str | None:
        """The source that lists this digest, or None. Never raises."""
        try:
            digest = bytes.fromhex(sha256_hex)
        except (TypeError, ValueError):
            return None
        try:
            row = self._conn().execute(
                "SELECT source FROM hashes WHERE digest = ?", (digest,)).fetchone()
        except sqlite3.Error as exc:
            if not self._warned:
                self._warned = True
                log.warning("blocklist lookup failed; treating as no match until it works: %s", exc)
            return None
        return row[0] if row else None

    def count(self) -> int:
        """Kept in meta by every write. COUNT(*) over a million rows is 53 ms
        (measured), and the generation is asked for it on every re-key."""
        try:
            recorded = self._get_meta("count")
            if recorded:
                return int(recorded)
            return int(self._conn().execute("SELECT COUNT(*) FROM hashes").fetchone()[0])
        except (sqlite3.Error, ValueError):
            return 0

    def sources(self) -> dict[str, int]:
        try:
            rows = self._conn().execute(
                "SELECT source, COUNT(*) FROM hashes GROUP BY source ORDER BY source").fetchall()
        except sqlite3.Error:
            return {}
        return {str(source): int(n) for source, n in rows}

    def version(self) -> int:
        """Bumped by every change, so a running scanner can notice one."""
        try:
            return int(self._get_meta("version", "0") or 0)
        except (sqlite3.Error, ValueError):
            return 0

    def generation_token(self) -> str:
        """What the detection generation folds in: the list's state, briefly.

        Skip this and a file cached CLEAN before a feed update replays CLEAN
        forever -- the DETECTION_VERSION incident with a different trigger.
        The TLSH references count too: a file cached CLEAN before a family's
        digest was imported must be measured against it.
        """
        return f"{self.version()}:{self.count()}:{self.tlsh_count()}"

    # ----------------------------------------------------------------- tlsh

    def tlsh_count(self) -> int:
        try:
            return int(self._conn().execute("SELECT COUNT(*) FROM tlsh").fetchone()[0])
        except sqlite3.Error:
            return 0

    def tlsh_references(self) -> "tlsh_module.ReferenceSet":
        """Every reference digest, as the object the scanner matches against.

        Loaded whole: the table is hand-seeded and small, and the match is a
        vectorised pass over all of it. Never raises; a broken table is an
        empty set and one warning.
        """
        try:
            rows = self._conn().execute(
                "SELECT digest, family, source FROM tlsh ORDER BY digest").fetchall()
        except sqlite3.Error as exc:
            if not self._warned:
                self._warned = True
                log.warning("TLSH references could not be read; similarity is off "
                            "until they can: %s", exc)
            return tlsh_module.ReferenceSet()
        references = tlsh_module.ReferenceSet(
            tlsh_module.Reference(str(d), str(f), str(s)) for d, f, s in rows)
        if len(references) > TLSH_WARN_REFERENCES:
            log.warning("%s TLSH references loaded; measured on benign software, every "
                        "250 references mark about 0.25%% of clean executables SUSPICIOUS "
                        "on resemblance alone on Linux and 1.5%% on Windows. Keep the set "
                        "to the families that matter here.", f"{len(references):,}")
        return references

    def import_tlsh(self, references: Iterable[tuple[str, str]], source: str) -> ImportResult:
        """Add (digest, family) pairs under one source. One transaction."""
        source = (source or "manual").strip() or "manual"
        rows = []
        for digest, family in references:
            canonical = tlsh_module.normalize(digest)
            if canonical is not None:
                rows.append((canonical, (family or "").strip(), source))
        result = ImportResult(source=source, lines=len(rows))
        with self._write_lock:
            conn = self._conn()
            before = conn.total_changes
            now = time.time()
            with conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO tlsh(digest, family, source, added_at) "
                    "VALUES (?, ?, ?, ?)",
                    ((d, f, s, now) for d, f, s in rows))
                added = conn.total_changes - before
                if added:
                    self._set_meta(conn, "version", str(self.version() + 1))
        result.tlsh_added = added
        result.tlsh_known = len(rows) - added
        return result

    def tlsh_entries(self) -> list[TlshEntry]:
        """Every reference, newest first: what Settings > Known samples shows."""
        try:
            rows = self._conn().execute(
                "SELECT digest, family, source, added_at FROM tlsh "
                "ORDER BY added_at DESC, digest").fetchall()
        except sqlite3.Error as exc:
            log.warning("TLSH references could not be listed: %s", exc)
            return []
        return [TlshEntry(str(d), str(f), str(s), float(a or 0.0)) for d, f, s, a in rows]

    def add_reference(self, data: bytes, family: str, source: str = "quarantine") -> ReferenceResult:
        """One reference from a sample's bytes: the Quarantine tab's "known sample".

        Refuses what the scanner could never match. Bytes above this backend's
        size cap are not digested at scan time, so a reference for them would
        sit in the table and fire on nothing; a digest that cannot be computed
        (too small, too uniform) is said so, not stored as nothing.
        """
        cap = tlsh_module.size_cap()
        if len(data) > cap:
            return ReferenceResult(reason=(
                f"{len(data):,} bytes is above the {cap // 1024:,} KB this backend digests "
                "at scan time, so nothing would ever be compared with it"))
        digest = tlsh_module.hash_bytes(data)
        if digest is None:
            return ReferenceResult(reason=(
                "too small or too uniform for a similarity digest (at least "
                f"{tlsh_module.MIN_BYTES} bytes, with some variety in them)"))
        result = self.import_tlsh([(digest, family)], source)
        return ReferenceResult(digest=digest, added=result.tlsh_added == 1,
                               known=result.tlsh_known == 1)

    def remove_tlsh(self, digest: str) -> bool:
        canonical = tlsh_module.normalize(digest)
        if canonical is None:
            return False
        with self._write_lock:
            conn = self._conn()
            with conn:
                cursor = conn.execute("DELETE FROM tlsh WHERE digest = ?", (canonical,))
                removed = cursor.rowcount > 0
                if removed:
                    self._set_meta(conn, "version", str(self.version() + 1))
        return removed

    # -------------------------------------------------------------- writing

    def import_digests(self, digests: Iterable[bytes], source: str) -> ImportResult:
        """Add digests under one source. One transaction: all or nothing."""
        source = (source or "manual").strip() or "manual"
        digests = list(digests)
        result = ImportResult(source=source, lines=len(digests))
        with self._write_lock:
            conn = self._conn()
            before = conn.total_changes
            now = time.time()
            with conn:  # commits, or rolls back on any exception
                conn.executemany(
                    "INSERT OR IGNORE INTO hashes(digest, source, added_at) VALUES (?, ?, ?)",
                    ((d, source, now) for d in digests))
                added = conn.total_changes - before
                if added:
                    self._bump(conn, added)
        result.added = added
        result.already_known = len(digests) - added
        return result

    def import_lines(self, lines: Iterable[str], source: str = "manual") -> ImportResult:
        parsed = parse_lines(lines)
        result = self.import_digests(parsed.hashes, source)
        if parsed.tlsh:
            references = self.import_tlsh(parsed.tlsh, source)
            result.tlsh_added = references.tlsh_added
            result.tlsh_known = references.tlsh_known
        result.lines = parsed.seen
        result.rejected = parsed.rejected
        return result

    def import_file(self, path: Path | str, source: str = "manual") -> ImportResult:
        """One hex SHA-256 or one TLSH digest per line; `#` starts a comment."""
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return self.import_lines(text.splitlines(), source)

    def remove(self, sha256_hex: str) -> bool:
        try:
            digest = bytes.fromhex(sha256_hex)
        except (TypeError, ValueError):
            return False
        with self._write_lock:
            conn = self._conn()
            with conn:
                cursor = conn.execute("DELETE FROM hashes WHERE digest = ?", (digest,))
                removed = cursor.rowcount > 0
                if removed:
                    self._bump(conn, -1)
        return removed

    def clear_source(self, source: str) -> int:
        with self._write_lock:
            conn = self._conn()
            with conn:
                cursor = conn.execute("DELETE FROM hashes WHERE source = ?", (source,))
                removed = cursor.rowcount
                if removed:
                    self._bump(conn, -removed)
                references = conn.execute("DELETE FROM tlsh WHERE source = ?", (source,)).rowcount
                if references and not removed:
                    self._set_meta(conn, "version", str(self.version() + 1))
        return removed + references

    # ----------------------------------------------------------------- feed

    def feed_state(self) -> dict[str, str]:
        try:
            return {
                "checked_at": self._get_meta("feed_checked_at"),
                "updated_at": self._get_meta("feed_updated_at"),
                "etag": self._get_meta("feed_etag"),
                "url": self._get_meta("feed_url"),
            }
        except sqlite3.Error:
            return {"checked_at": "", "updated_at": "", "etag": "", "url": ""}

    def feed_due(self, now: float | None = None) -> bool:
        """At most once a day, whatever the caller's enthusiasm."""
        now = time.time() if now is None else now
        try:
            checked = float(self._get_meta("feed_checked_at", "0") or 0)
        except ValueError:
            checked = 0.0
        return now - checked >= FEED_INTERVAL_SECONDS

    def update_from_feed(self, session=None, full: bool = False,
                         url: str | None = None) -> FeedResult:
        """Fetch the feed and merge it. Raises FeedError; the list is then unchanged.

        The request carries the previous download's ETag and nothing else
        about this machine. A 304 costs one round trip and changes nothing.
        The full export arrives zipped; both forms are parsed the same way,
        and a download with fewer than FEED_MIN_VALID_LINES valid hashes is
        refused whole.
        """
        import requests  # imported here so a bare install without it still scans

        url = url or (FEED_FULL_URL if full else FEED_RECENT_URL)
        session = session or requests.Session()
        headers = {"User-Agent": USER_AGENT}
        etag = self._get_meta("feed_etag")
        if etag and self._get_meta("feed_url") == url:
            headers["If-None-Match"] = etag
        try:
            response = session.get(url, headers=headers,
                                   timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), stream=True)
            try:
                if response.status_code == 304:
                    self._record_check(url)
                    return FeedResult(status="unchanged", url=url)
                if response.status_code != 200:
                    raise FeedError(f"{url} answered HTTP {response.status_code}")
                content = self._read_bounded(response)
            finally:
                response.close()
        except requests.RequestException as exc:
            raise FeedError(f"could not fetch {url}: {exc}") from exc

        if content[:2] == b"PK":
            content = _first_member(content)
        text = content.decode("utf-8", errors="replace")
        digests, rejected, seen = parse_hashes(text.splitlines())
        if len(digests) < FEED_MIN_VALID_LINES:
            raise FeedError(
                f"the download from {url} held {len(digests)} valid hash(es) in {seen} "
                f"line(s); that is not the feed (a captive portal or an error page, "
                f"most likely). The blocklist is unchanged.")

        result = self.import_digests(digests, FEED_SOURCE)
        result.lines = seen
        result.rejected = rejected
        with self._write_lock:
            conn = self._conn()
            with conn:
                self._set_meta(conn, "feed_etag", response.headers.get("ETag", "") or "")
                self._set_meta(conn, "feed_url", url)
                self._set_meta(conn, "feed_updated_at", str(time.time()))
                self._set_meta(conn, "feed_checked_at", str(time.time()))
        log.info("blocklist feed %s: %s", url, result.describe())
        return FeedResult(status="updated", url=url, imported=result)

    def _record_check(self, url: str) -> None:
        with self._write_lock:
            conn = self._conn()
            with conn:
                self._set_meta(conn, "feed_checked_at", str(time.time()))
                self._set_meta(conn, "feed_url", url)

    @staticmethod
    def _read_bounded(response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(64 * 1024):
            total += len(chunk)
            if total > FEED_MAX_BYTES:
                raise FeedError(f"the download exceeded {FEED_MAX_BYTES // (1024 * 1024)} MB")
            chunks.append(chunk)
        return b"".join(chunks)


def _first_member(content: bytes) -> bytes:
    """The text inside a zipped export, with the zip-bomb guard the scanner uses."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = [m for m in archive.infolist() if not m.is_dir()]
            if not members:
                raise FeedError("the zipped download holds no file")
            member = members[0]
            if member.file_size > FEED_MAX_BYTES:
                raise FeedError("the zipped download expands past the size limit")
            return archive.read(member)
    except zipfile.BadZipFile as exc:
        raise FeedError(f"the download is not a zip file: {exc}") from exc


def scheduled_update(store: IocStore, enabled: bool, session=None,
                     now: float | None = None) -> FeedResult:
    """The daily check, with the opt-in enforced here rather than by callers.

    A GUI that forgot to look at the setting would otherwise phone home on
    the user's behalf. Off means nothing is fetched, ever.
    """
    if not enabled:
        return FeedResult(status="disabled")
    if not store.feed_due(now):
        return FeedResult(status="not due")
    return store.update_from_feed(session=session)
