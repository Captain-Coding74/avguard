"""Where a file came from: the download mark, and what shares its bytes with
a member of a marked archive.

A browser writes an NTFS alternate stream named Zone.Identifier beside a
download: `[ZoneTransfer]`, `ZoneId=3` for the internet, and usually the
`HostUrl` it came from. SmartScreen looks for the mark before running a
program and Office opens a marked document in Protected View. Explorer's
own extraction keeps the mark on what it extracts; 7-Zip drops it unless
its "Propagate Zone.Id" option is on (off by default since 22.00), and most
other tools drop it. Python reads the stream with a plain open() on
Windows: `open(f"{path}:Zone.Identifier")`.

What this module does with it, all of it informational:

- `read_zone()` says whether a file is marked and the host it came from.
  The host only, checked to be a host: the URL (with its path and query,
  which can carry a session token or a name) appears nowhere in a verdict,
  an event, a log or a store, and a stream cut by the read limit loses its
  last line rather than mis-reading a username as a host.
- `ProvenanceStore` remembers the SHA-256 of every member the scanner
  looked at inside a marked archive, so that an unmarked program whose
  bytes equal such a member can be said to: "has the bytes of tool.exe
  from app.zip (downloaded from host) and carries no download mark". That
  is what was measured, and all that is said: the bytes match; whether
  the file was extracted from that archive or installed from elsewhere is
  not known, which is why nothing under the Windows or Program Files
  folders is said anything about.
- `write_zone()` puts the mark back on a file the quarantine restores or
  exports, with the zone only: a restored download should still be a
  download to SmartScreen.

Where a file came from is a fact about it and never evidence against it:
every finding this module feeds the scanner weighs 0 and is soft, and a
test asserts decide() is identical with and without them. The findings
are computed live on every scan, cache replay included, because the mark
is a separate stream the cache key cannot see and the store changes under
the cache. The absence of a mark says nothing: most extractions lose it.
The suffix sets below say which kinds a lost mark matters for; they come
from Microsoft's documentation of SmartScreen and Protected View and were
not measured here.
"""

from __future__ import annotations

import logging
import ntpath
import os
import re
import sqlite3
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from . import config

log = logging.getLogger("avguard.provenance")

ZONE_STREAM = "Zone.Identifier"
ZONE_NAMES = {0: "this computer", 1: "the local intranet", 2: "a trusted site",
              3: "the internet", 4: "a restricted site"}
ZONE_IDS = range(0, 5)
MARKED_FROM = 3                 # zones 3 and 4 are what SmartScreen asks about
MAX_STREAM_BYTES = 16384        # the stream is three short lines; a cut read drops its last line
MAX_HOST = 253
MAX_NAME = 80                   # a member name longer than this is shortened in a sentence
PROVENANCE_DB_PATH = config.DATA_DIR / "provenance.sqlite"
KEEP_DAYS = 90                  # a member hash older than this is forgotten, on read and on write
KEEP_ROWS = 50_000              # and the store never grows past this many
# Kinds the shell launches through SmartScreen's check, and kinds Office
# opens in Protected View. From the documentation, not measured here: a
# program or script that is run, a container Explorer mounts, a document.
PROGRAM_SUFFIXES = frozenset({
    ".exe", ".scr", ".com", ".msi", ".cpl", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url", ".msix", ".appx", ".application",
    ".appref-ms", ".msc", ".chm", ".iso", ".img", ".vhd", ".vhdx",
})
DOCUMENT_SUFFIXES = frozenset({
    ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm", ".rtf", ".xls", ".xlsx", ".xlsm", ".xlsb",
    ".xlam", ".xla", ".xll", ".ppt", ".pptx", ".pptm", ".ppsx", ".potx", ".potm", ".pub", ".vsdx",
    ".odt", ".ods", ".odp", ".accdb",
})
GATED_SUFFIXES = PROGRAM_SUFFIXES | DOCUMENT_SUFFIXES
# Where installed software lives. A file there with the bytes of a downloaded
# archive's member is an installed copy as often as an extracted one, and the
# module says only what it measured.
INSTALLED_ROOT_VARS = ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$|^[0-9a-f:.]+$")
_LINES = re.compile(r"\r\n|\n|\r")


@dataclass(frozen=True)
class Zone:
    zone_id: int
    host: str = ""              # the host of HostUrl, never the URL
    referrer_host: str = ""

    @property
    def marked(self) -> bool:
        return self.zone_id >= MARKED_FROM

    def describe(self) -> str:
        if self.host:
            return f"downloaded from {self.host}"
        return f"downloaded from {ZONE_NAMES.get(self.zone_id, f'zone {self.zone_id}')}"


@dataclass(frozen=True)
class Origin:
    """A member of a marked archive whose bytes an unmarked file shares."""
    sha256: str
    container: str              # the archive's path as it was when scanned
    member: str                 # the member's name inside it, as the archive walk names it
    host: str
    seen: float
    told: bool = False          # the user has had the History row for this file

    @property
    def container_name(self) -> str:
        return Path(self.container).name

    @property
    def member_name(self) -> str:
        """The member's own name: the last part of "outer.zip!inner/tool.exe"."""
        inner = self.member.rsplit("!", 1)[-1].replace("\\", "/").rstrip("/")
        name = inner.rsplit("/", 1)[-1] or self.member
        return name if len(name) <= MAX_NAME else name[:MAX_NAME - 3] + "..."

    def describe(self) -> str:
        source = f"downloaded from {self.host}" if self.host else "downloaded from the internet"
        gate = ("Office will not open it in Protected View" if is_document(self.member_name)
                else "SmartScreen will not ask before it runs")
        return (f"has the bytes of {self.member_name} from {self.container_name} ({source}) "
                f"and carries no download mark, so {gate}")


def stream_path(path: Path | str) -> str:
    return f"{path}:{ZONE_STREAM}"


def host_of(url: str) -> str:
    """The host of a URL and nothing else, or '' when there is none or what
    is there is not a host (about:internet, a cut line, control characters,
    a percent-escape, a 300-character label)."""
    try:
        host = (urlsplit(url.strip()).hostname or "").strip(".").lower()
    except ValueError:
        return ""
    if not host or len(host) > MAX_HOST:
        return ""
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return host if _HOST.match(ascii_host) else ""


def parse_zone(text: str) -> Zone | None:
    """The stream's text to a Zone; None when it is not a ZoneTransfer block.
    The first block and the first ZoneId in it are the ones that count, and
    only the line separators Windows writes split lines."""
    section = None
    zone_id = None
    host = referrer = ""
    for raw in _LINES.split(text):
        line = raw.strip().lstrip("\ufeff")
        if not line or line[0] in ";#":
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().lower()
            if section == "zonetransfer" and name != "zonetransfer":
                break                                  # the block ended
            section = name
            continue
        if section != "zonetransfer" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()
        if key == "zoneid" and zone_id is None:
            if not value.isdigit() or int(value) not in ZONE_IDS:
                return None
            zone_id = int(value)
        elif key == "hosturl" and not host:
            host = host_of(value)
        elif key == "referrerurl" and not referrer:
            referrer = host_of(value)
    if zone_id is None:
        return None
    return Zone(zone_id, host, referrer)


def read_zone(path: Path | str) -> Zone | None:
    """The file's download mark, or None when it has none (or cannot be read).
    Never raises. On Windows this reads the alternate stream; elsewhere the
    same name is an ordinary file beside the one asked about, which is what
    the tests use, and only a regular one is opened (a FIFO would block)."""
    stream = stream_path(path)
    try:
        if sys.platform != "win32" and not stat.S_ISREG(os.stat(stream).st_mode):
            return None
        with open(stream, "rb") as handle:
            raw = handle.read(MAX_STREAM_BYTES)
    except (OSError, ValueError):
        return None
    text = raw.decode("utf-8", "replace")
    if len(raw) >= MAX_STREAM_BYTES:
        # The read may have cut a line; a cut HostUrl would read its
        # username as the host, so the last line goes.
        text = text.rsplit("\n", 1)[0] if "\n" in text else ""
    return parse_zone(text)


def write_zone(path: Path | str, zone_id: int = MARKED_FROM) -> bool:
    """Put a mark on `path`: the zone only, no URL. Windows only; anywhere
    else the name would be a stray file, so nothing is written and False is
    returned. Never raises: the file is already where it should be, and a
    mark that could not be written is logged."""
    if sys.platform != "win32":
        return False
    try:
        with open(stream_path(path), "w", encoding="ascii", newline="") as handle:
            handle.write(f"[ZoneTransfer]\r\nZoneId={int(zone_id)}\r\n")
        return True
    except (OSError, ValueError) as exc:
        log.warning("could not mark %s as downloaded: %s", path, exc)
        return False


def is_gated(path: Path | str) -> bool:
    return Path(str(path)).suffix.lower() in GATED_SUFFIXES


def is_document(path: Path | str) -> bool:
    return Path(str(path)).suffix.lower() in DOCUMENT_SUFFIXES


def installed_roots() -> list[str]:
    roots = [os.environ.get("SystemRoot") or r"C:\Windows"]
    roots += [os.environ[name] for name in INSTALLED_ROOT_VARS[1:] if os.environ.get(name)]
    return [ntpath.normcase(ntpath.normpath(root)) for root in roots]


def is_installed(path: Path | str) -> bool:
    """Under the Windows folder or a Program Files folder: installed software,
    whose bytes may match a download without having come out of it."""
    text = ntpath.normcase(ntpath.normpath(str(path)))
    return any(text == root or text.startswith(root + "\\") for root in installed_roots())


def extracted_finding(findings) -> object | None:
    """The 'has the bytes of a marked archive's member' finding on a verdict, if any."""
    for finding in findings or ():
        if getattr(finding, "source", "") == "provenance" and getattr(finding, "name", "") == "extracted":
            return finding
    return None


class ProvenanceStore:
    """Member hashes of marked archives, on disk, looked up one at a time.
    One connection per thread, as the blocklist does; nothing here raises
    into a scan, and a store that cannot be opened is given up on for the
    life of the process rather than opened again for every file."""

    def __init__(self, path: Path = PROVENANCE_DB_PATH) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._warned = False
        self._broken = False

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        if self._broken:
            raise sqlite3.OperationalError("the provenance store could not be opened earlier")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=5)
        except (sqlite3.Error, OSError):
            self._broken = True
            raise
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS members("
                "digest TEXT PRIMARY KEY, container TEXT NOT NULL, member TEXT NOT NULL, "
                "host TEXT NOT NULL, seen REAL NOT NULL, told REAL NOT NULL DEFAULT 0) WITHOUT ROWID")
            conn.execute("CREATE INDEX IF NOT EXISTS members_seen ON members(seen)")
            conn.execute("CREATE INDEX IF NOT EXISTS members_container ON members(container)")
            conn.commit()
        except sqlite3.Error as exc:
            conn.close()
            # A file that is not a database stays that way; a lock is passing.
            if not isinstance(exc, sqlite3.OperationalError) or "locked" not in str(exc):
                self._broken = True
            raise
        self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @staticmethod
    def _cutoff() -> float:
        return time.time() - KEEP_DAYS * 86400

    def remember(self, members: Iterable[tuple[str, str]], container: Path | str, host: str) -> int:
        """Record (sha256, member name) pairs as having come out of `container`,
        which was downloaded from `host`. Returns how many were recorded."""
        rows = [(digest.lower(), str(container), member, host, time.time())
                for digest, member in members if digest]
        if not rows:
            return 0
        try:
            with self._write_lock:
                conn = self._conn()
                with conn:
                    conn.executemany(
                        "INSERT INTO members(digest, container, member, host, seen) VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT(digest) DO UPDATE SET container = excluded.container, "
                        "member = excluded.member, host = excluded.host, seen = excluded.seen", rows)
                    conn.execute("DELETE FROM members WHERE seen < ?", (self._cutoff(),))
                    over = conn.execute("SELECT 1 FROM members ORDER BY seen DESC LIMIT 1 OFFSET ?",
                                        (KEEP_ROWS,)).fetchone()
                    if over is not None:
                        conn.execute("DELETE FROM members WHERE digest IN ("
                                     "SELECT digest FROM members ORDER BY seen DESC LIMIT -1 OFFSET ?)",
                                     (KEEP_ROWS,))
        except (sqlite3.Error, OSError) as exc:
            self._warn(exc)
            return 0
        return len(rows)

    def lookup(self, sha256_hex: str) -> Origin | None:
        """The marked archive's member these bytes equal, or None; a row
        older than KEEP_DAYS is as good as gone. Never raises."""
        if not sha256_hex:
            return None
        try:
            row = self._conn().execute(
                "SELECT digest, container, member, host, seen, told FROM members "
                "WHERE digest = ? AND seen >= ?", (sha256_hex.lower(), self._cutoff())).fetchone()
        except (sqlite3.Error, OSError) as exc:
            self._warn(exc)
            return None
        if row is None:
            return None
        return Origin(row[0], row[1], row[2], row[3], float(row[4]), bool(row[5]))

    def touch_container(self, container: Path | str) -> bool:
        """An archive seen again: its members' date moves, so a download
        the scanner keeps meeting is not forgotten after ninety days.
        Returns whether any member of it is remembered at all."""
        try:
            with self._write_lock:
                conn = self._conn()
                with conn:
                    changed = conn.execute("UPDATE members SET seen = ? WHERE container = ?",
                                           (time.time(), str(container))).rowcount
        except (sqlite3.Error, OSError) as exc:
            self._warn(exc)
            return True                    # unknown; do not make the caller re-read for it
        return changed > 0

    def mark_told(self, sha256_hex: str) -> None:
        """The user has the History row for this file; it is not written again."""
        try:
            with self._write_lock:
                conn = self._conn()
                with conn:
                    conn.execute("UPDATE members SET told = ? WHERE digest = ?",
                                 (time.time(), sha256_hex.lower()))
        except (sqlite3.Error, OSError) as exc:
            self._warn(exc)

    def count(self) -> int:
        try:
            return int(self._conn().execute("SELECT COUNT(*) FROM members").fetchone()[0])
        except (sqlite3.Error, OSError):
            return 0

    def _warn(self, exc: Exception) -> None:
        if not self._warned:
            self._warned = True
            log.warning("the provenance store failed; where files came from is not kept until it works: %s", exc)
