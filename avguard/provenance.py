"""Where a file came from: the download mark, and what was extracted from a
marked archive.

A browser writes an NTFS alternate stream named Zone.Identifier beside a
download: `[ZoneTransfer]`, `ZoneId=3` for the internet, and usually the
`HostUrl` it came from. SmartScreen asks before running a marked program
and Office opens a marked document in Protected View; both gate on the
mark and on nothing else, and every extraction by 7-Zip (and most other
tools) loses it. Python reads the stream with a plain open() on Windows:
`open(f"{path}:Zone.Identifier")`.

What this module does with it, all of it informational:

- `read_zone()` says whether a file is marked and the host it came from.
  The host only: the URL (with its path and query, which can carry a
  session token or a name) appears nowhere in a verdict, an event, a log
  or a store.
- `ProvenanceStore` remembers the SHA-256 of every member the scanner
  looked inside a marked archive, so that an unmarked program whose bytes
  came out of such an archive can be said to have: that is the file
  SmartScreen will not ask about, and the user may want to know.
- `write_zone()` puts the mark back on a file the quarantine restores or
  exports, with the zone only: a restored download should still be a
  download to SmartScreen.

Where a file came from is a fact about it and never evidence against it:
every finding this module feeds the scanner weighs 0 and is soft, and a
test asserts decide() is identical with and without them. A mark is lost
by every honest extraction, so its absence says nothing, and its presence
says the user downloaded something, which is what browsers are for.
"""

from __future__ import annotations

import logging
import sqlite3
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
MARKED_FROM = 3                 # zones 3 and 4 are what SmartScreen asks about
MAX_STREAM_BYTES = 4096         # the stream is three short lines; anything longer is not one
PROVENANCE_DB_PATH = config.DATA_DIR / "provenance.sqlite"
KEEP_DAYS = 90                  # a member hash older than this is forgotten
KEEP_ROWS = 50_000              # and the store never grows past this many
# File kinds a lost mark matters for: SmartScreen asks about a program or a
# script from the internet, Office opens a document from the internet in
# Protected View. Anything else is read by something that does not look.
GATED_SUFFIXES = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx", ".pif",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url",
    ".jar", ".msix", ".appx",
    ".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlam",
    ".ppt", ".pptx", ".pptm", ".rtf", ".one",
})


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
    """Where an unmarked file's bytes came from: a member of a marked archive."""
    sha256: str
    container: str              # the archive's path as it was when scanned
    member: str                 # the member's name inside it
    host: str
    seen: float
    told: bool = False          # the user has had the History row for this file

    @property
    def container_name(self) -> str:
        return Path(self.container).name

    def describe(self) -> str:
        source = f"downloaded from {self.host}" if self.host else "downloaded from the internet"
        return (f"extracted from {self.container_name} ({source}); the extracted file "
                f"carries no download mark, so SmartScreen will not ask before it runs")


def stream_path(path: Path | str) -> str:
    return f"{path}:{ZONE_STREAM}"


def host_of(url: str) -> str:
    """The host of a URL and nothing else; '' for about:internet and the like."""
    try:
        return (urlsplit(url.strip()).hostname or "").strip(".").lower()
    except ValueError:
        return ""


def parse_zone(text: str) -> Zone | None:
    """The stream's text to a Zone; None when it is not a ZoneTransfer block."""
    section = ""
    zone_id = None
    host = referrer = ""
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "zonetransfer" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()
        if key == "zoneid":
            try:
                zone_id = int(value)
            except ValueError:
                return None
        elif key == "hosturl":
            host = host_of(value)
        elif key == "referrerurl":
            referrer = host_of(value)
    if zone_id is None:
        return None
    return Zone(zone_id, host, referrer)


def read_zone(path: Path | str) -> Zone | None:
    """The file's download mark, or None when it has none (or cannot be read).
    Never raises. On Windows this reads the alternate stream; elsewhere the
    same name is an ordinary file beside the one asked about, which is what
    the tests use."""
    try:
        with open(stream_path(path), "rb") as handle:
            raw = handle.read(MAX_STREAM_BYTES)
    except (OSError, ValueError):
        return None
    return parse_zone(raw.decode("utf-8", "replace"))


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
    return Path(path).suffix.lower() in GATED_SUFFIXES


def extracted_finding(findings) -> object | None:
    """The 'extracted from a marked archive' finding on a verdict, if any."""
    for finding in findings or ():
        if getattr(finding, "source", "") == "provenance" and getattr(finding, "name", "") == "extracted":
            return finding
    return None


class ProvenanceStore:
    """Member hashes of marked archives, on disk, looked up one at a time.
    One connection per thread, as the blocklist does; a write never raises
    into a scan."""

    def __init__(self, path: Path = PROVENANCE_DB_PATH) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._warned = False

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS members("
                "digest TEXT PRIMARY KEY, container TEXT NOT NULL, member TEXT NOT NULL, "
                "host TEXT NOT NULL, seen REAL NOT NULL, told REAL NOT NULL DEFAULT 0) WITHOUT ROWID")
            conn.commit()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

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
                    conn.execute("DELETE FROM members WHERE seen < ?", (time.time() - KEEP_DAYS * 86400,))
                    conn.execute("DELETE FROM members WHERE digest IN ("
                                 "SELECT digest FROM members ORDER BY seen DESC LIMIT -1 OFFSET ?)",
                                 (KEEP_ROWS,))
        except sqlite3.Error as exc:
            self._warn(exc)
            return 0
        return len(rows)

    def lookup(self, sha256_hex: str) -> Origin | None:
        """Where these bytes came out of, or None. Never raises."""
        if not sha256_hex:
            return None
        try:
            row = self._conn().execute(
                "SELECT digest, container, member, host, seen, told FROM members WHERE digest = ?",
                (sha256_hex.lower(),)).fetchone()
        except sqlite3.Error as exc:
            self._warn(exc)
            return None
        if row is None:
            return None
        return Origin(row[0], row[1], row[2], row[3], float(row[4]), bool(row[5]))

    def mark_told(self, sha256_hex: str) -> None:
        """The user has the History row for this file; it is not written again."""
        try:
            with self._write_lock:
                conn = self._conn()
                with conn:
                    conn.execute("UPDATE members SET told = ? WHERE digest = ?",
                                 (time.time(), sha256_hex.lower()))
        except sqlite3.Error as exc:
            self._warn(exc)

    def count(self) -> int:
        try:
            return int(self._conn().execute("SELECT COUNT(*) FROM members").fetchone()[0])
        except sqlite3.Error:
            return 0

    def _warn(self, exc: Exception) -> None:
        if not self._warned:
            self._warned = True
            log.warning("the provenance store failed; where files came from is not kept until it works: %s", exc)
