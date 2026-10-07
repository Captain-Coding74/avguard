"""File integrity monitoring: a baseline of hashes, and what changed since.

A scanner asks "is this file bad?". Integrity monitoring asks a different
question about files that should not change at all -- a web root, a folder
of scripts, a configuration tree: "is this still what it was?" Every change
is reported: modified (the hash differs), added (on disk, not in the
baseline), removed (in the baseline, gone from disk). Changed is not the
same as malicious, so a check NEVER quarantines. It records events and says
what it found; deciding is the user's.

Three things learned elsewhere in this program shape it:

  * **Timestomping is handled honestly.** An attacker who edits a file resets
    its mtime afterwards. So the default check hashes everything, and the
    `--fast` mode that trusts an unchanged size and mtime says exactly what
    it trades away. The test that proves the difference is in tests/test_fim.py.
  * **The baseline is a target.** Malware that edits a monitored file would
    next edit the baseline to hide it. The baseline lives under the data
    directory, inside self-protection, and it is signed: an HMAC-SHA256 over
    the database bytes, with a random key protected by Windows DPAPI (user
    scope). A signature that no longer matches does not stop a check; it is
    reported, loudly, as a change to the baseline itself.
  * **The limit of that, stated the way the README states the quarantine
    masking.** Code running as the same user can call the same DPAPI and
    re-sign a doctored baseline. The signature defends against other tools,
    casual edits, and a copied-in baseline from another machine -- not
    against an attacker who already owns the account.

State is SQLite rather than JSON so a check updates rows one at a time
instead of rewriting the whole file from a stale in-memory snapshot, which
is how quarantine records were once destroyed (ROADMAP.md, finding 3).
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import config
from .events import Event, EventStore
from .protection import matches_excluded_glob

log = logging.getLogger(__name__)

FIM_DIR = config.DATA_DIR / "fim"
BASELINE_NAME = "baseline.sqlite"
KEY_NAME = "baseline.key"
SIGNATURE_NAME = "baseline.hmac"
LOCK_NAME = "baseline.lock"
LOCK_WAIT = 5.0                 # seconds a writer or a check waits for the other
IN_USE = ("the baseline is in use by another AVGuard (the daily check, or a second window); "
          "try again in a moment")
KEY_DESCRIPTION = "AVGuard file-integrity baseline key"
CRYPTPROTECT_UI_FORBIDDEN = 0x01

INTEGRITY_OK = "ok"
INTEGRITY_TAMPERED = "tampered"
INTEGRITY_UNSIGNED = "unsigned"
INTEGRITY_KEY_UNREADABLE = "key-unreadable"
INTEGRITY_NO_BASELINE = "no-baseline"

# What each failed integrity state means, in the words the event, the CLI and
# the Integrity tab all use.
INTEGRITY_MESSAGES = {
    INTEGRITY_TAMPERED: "the baseline database was modified outside AVGuard: "
                        "its signature no longer matches",
    INTEGRITY_UNSIGNED: "the baseline has no signature file; it was created or "
                        "copied without AVGuard",
    INTEGRITY_KEY_UNREADABLE: "the baseline's signing key cannot be read (another "
                              "user's, or damaged); the signature cannot be checked",
}



class Refused(RuntimeError):
    """accept() wrote nothing: the baseline is in use, or its signature does
    not hold. Raised, not returned as a note: a note read as success, and the
    Integrity tab cleared the rows it had not accepted."""


# Hooks for a front end: progress(done, total) after each file, should_stop()
# polled before each one. The CLI passes neither; the Integrity tab passes both.
ProgressHook = Callable[[int, int], None]
StopHook = Callable[[], bool]


# ------------------------------------------------------------------ DPAPI

class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _crypt32():
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    blob_p = ctypes.POINTER(_DataBlob)
    crypt32.CryptProtectData.argtypes = [blob_p, ctypes.c_wchar_p, blob_p, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_uint32, blob_p]
    crypt32.CryptProtectData.restype = ctypes.c_int
    crypt32.CryptUnprotectData.argtypes = [blob_p, ctypes.POINTER(ctypes.c_wchar_p), blob_p,
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                           blob_p]
    crypt32.CryptUnprotectData.restype = ctypes.c_int
    return crypt32


def _blob_of(data: bytes) -> _DataBlob:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))


def _take(blob: _DataBlob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        ctypes.WinDLL("kernel32", use_last_error=True).LocalFree(blob.pbData)


def protect(data: bytes) -> bytes:
    """Wrap bytes so only this Windows user can unwrap them.

    Off Windows there is no DPAPI; the key is stored as it is, marked so, and
    the log says so once. The HMAC still catches edits by other tools; it
    just does not survive a copy of the data directory to another account.
    """
    if sys.platform != "win32":
        log.warning("no DPAPI on this platform; the baseline key is stored unprotected")
        return b"AVGUARD-RAW:" + data
    out = _DataBlob()
    ok = _crypt32().CryptProtectData(ctypes.byref(_blob_of(data)), KEY_DESCRIPTION, None,
                                     None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
    return _take(out)


def unprotect(blob: bytes) -> bytes:
    if blob.startswith(b"AVGUARD-RAW:"):
        return blob[len(b"AVGUARD-RAW:"):]
    if sys.platform != "win32":
        raise OSError("a DPAPI-protected key cannot be read on this platform")
    out = _DataBlob()
    description = ctypes.c_wchar_p()
    ok = _crypt32().CryptUnprotectData(ctypes.byref(_blob_of(blob)), ctypes.byref(description),
                                       None, None, None, CRYPTPROTECT_UI_FORBIDDEN,
                                       ctypes.byref(out))
    if description:
        ctypes.WinDLL("kernel32", use_last_error=True).LocalFree(description)
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData failed")
    return _take(out)


# --------------------------------------------------------------- reports

@dataclass
class Change:
    kind: str                 # modified | added | removed
    path: str
    old_sha256: str = ""
    new_sha256: str = ""
    old_size: int = 0
    new_size: int = 0

    def describe(self) -> str:
        if self.kind == "modified":
            return (f"MODIFIED  {self.path}  ({self.old_sha256[:12]} -> {self.new_sha256[:12]}, "
                    f"{self.old_size:,} -> {self.new_size:,} bytes)")
        if self.kind == "added":
            return f"ADDED     {self.path}  ({self.new_sha256[:12]}, {self.new_size:,} bytes)"
        return f"REMOVED   {self.path}  (was {self.old_sha256[:12]}, {self.old_size:,} bytes)"

    def as_event(self) -> Event:
        return Event(kind="fim", path=self.path, level=self.kind,
                     reasons=[self.describe()],
                     detail={"old_sha256": self.old_sha256, "new_sha256": self.new_sha256,
                             "old_size": self.old_size, "new_size": self.new_size})


@dataclass
class BaselineReport:
    roots: list[str] = field(default_factory=list)
    files: int = 0
    bytes: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    seconds: float = 0.0
    cancelled: bool = False      # stopped early; nothing was written
    key_replaced: bool = False   # the signing key could not be read and a new one signs this baseline
    in_use: bool = False         # another AVGuard held the lock; nothing was written
    # The previous baseline's signature state. When it did not hold, its rows
    # were not carried forward: nothing vouches for them, and signing them
    # with this baseline would launder whatever was done to them.
    integrity: str = INTEGRITY_OK
    dropped_roots: list[str] = field(default_factory=list)


class Accepted(list):
    """What accept() did, a line per path, and which paths it did not
    accept: a file it could not read was a line among the others, and the
    Integrity tab said "Accepted 2 change(s)" and cleared both rows."""

    def __init__(self) -> None:
        super().__init__()
        self.not_accepted: list[str] = []


@dataclass
class CheckReport:
    changes: list[Change] = field(default_factory=list)
    examined: int = 0
    hashed: int = 0
    errors: list[str] = field(default_factory=list)
    integrity: str = INTEGRITY_OK
    fast: bool = False
    seconds: float = 0.0
    cancelled: bool = False      # stopped early; nothing was recorded
    in_use: bool = False         # another AVGuard held the lock; nothing was checked

    def of(self, kind: str) -> list[Change]:
        return [c for c in self.changes if c.kind == kind]

    @property
    def modified(self) -> list[Change]:
        return self.of("modified")

    @property
    def added(self) -> list[Change]:
        return self.of("added")

    @property
    def removed(self) -> list[Change]:
        return self.of("removed")

    @property
    def clean(self) -> bool:
        return (not self.changes and self.integrity == INTEGRITY_OK and not self.cancelled
                and not self.in_use)

    def integrity_event(self) -> Event | None:
        if self.integrity in (INTEGRITY_OK, INTEGRITY_NO_BASELINE):
            return None
        return Event(kind="fim", level="tampered", reasons=[INTEGRITY_MESSAGES[self.integrity]],
                     detail={"integrity": self.integrity})


# ---------------------------------------------------------------- hashing

def hash_file(path: Path) -> tuple[str, int, int]:
    """Hash only. `_read_facts` also computes entropy and signature hits, which
    a baseline does not need; this reads at the disk's speed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(config.CHUNK_SIZE):
            digest.update(chunk)
    st = path.stat()
    return digest.hexdigest(), st.st_size, st.st_mtime_ns


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(os.path, "isjunction", None)
        return bool(is_junction and is_junction(path))
    except OSError:
        return True


def _key(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _real(path: str) -> str:
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):
        return _key(path)


def _one_root_per_tree(given: list[Path], recorded: list[str]) -> list[Path]:
    """The roots of one baseline call, each tree once: a root inside another
    given root goes, a repeated root goes, and a root that is another name
    for a folder already held (a symlink, a junction, an 8.3 name) is
    spelled under the root that holds it, so the text comparisons that
    follow see one tree. "web web/assets" recorded both and counted their
    files twice; a symlinked spelling gave two ADDED rows per new file.
    One realpath per root, not per row."""
    anchors = [(str(r), _real(str(r))) for r in recorded]
    out: list[Path] = []
    for root in given:
        real = _real(str(root))
        for anchor, anchor_real in anchors + [(str(r), _real(str(r))) for r in out]:
            if real == anchor_real or real.startswith(anchor_real.rstrip(os.sep) + os.sep):
                rest = real[len(anchor_real):].lstrip(os.sep)
                root = Path(anchor) / rest if rest else Path(anchor)
                break
        if not any(_under(str(root), str(kept)) for kept in out):
            out = [kept for kept in out if not _under(str(kept), str(root))] + [root]
    return out


def _under(path: str, root: str) -> bool:
    """`path` is `root` or inside it, by text: no resolve() and no stat, so
    it costs nothing per row (path_within on 60,000 rows held the lock six
    seconds)."""
    a, b = _key(path), _key(root).rstrip(os.sep)
    return a == b or a.startswith(b + os.sep)


# ------------------------------------------------------------------ store


class FileLock:
    """One writer at a time across processes: the window and the daily task
    share a database and its signature file, and a signature written over
    another writer's database reads as tampering. An OS lock on a file, so
    a process that dies releases it; the integrity stores in this module
    and in autoruns.py both take one."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None

    def acquire(self, timeout: float = LOCK_WAIT) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + timeout
        handle = open(self.path, "a+b")
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._handle = handle
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    handle.close()
                    return False
                time.sleep(0.1)

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()

class FimStore:
    """The baseline on disk, and the checks against it."""

    def __init__(self, directory: Path = FIM_DIR, excluded_globs: Iterable[str] = (),
                 key_protect: Callable[[bytes], bytes] = protect,
                 key_unprotect: Callable[[bytes], bytes] = unprotect) -> None:
        self.directory = Path(directory)
        self.excluded_globs = list(excluded_globs)
        self._protect = key_protect
        self._unprotect = key_unprotect
        # Both spellings of the data directory, computed once. Comparing every
        # walked path through path_within() resolved it against the disk
        # twice: measured at 1.34 s of a 1.64 s check over 2,000 files.
        self._data_keys = {os.path.normcase(os.path.abspath(str(config.DATA_DIR)))}
        try:
            self._data_keys.add(os.path.normcase(str(config.DATA_DIR.resolve())))
        except OSError:
            pass

    @property
    def db_path(self) -> Path:
        return self.directory / BASELINE_NAME

    @property
    def key_path(self) -> Path:
        return self.directory / KEY_NAME

    @property
    def signature_path(self) -> Path:
        return self.directory / SIGNATURE_NAME

    @property
    def lock_path(self) -> Path:
        return self.directory / LOCK_NAME

    def exists(self) -> bool:
        return self.db_path.is_file()

    # ------------------------------------------------------------ plumbing

    def _connect(self) -> sqlite3.Connection:
        self.directory.mkdir(parents=True, exist_ok=True)
        # Rollback journal, not WAL: after commit and close the database is
        # one file, which is what the signature covers.
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS files("
                         "path TEXT PRIMARY KEY, sha256 BLOB NOT NULL, size INTEGER NOT NULL, "
                         "mtime_ns INTEGER NOT NULL, baselined_at REAL NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS roots(path TEXT PRIMARY KEY, added_at REAL NOT NULL)")
            conn.commit()
        except BaseException:
            # A file that is not a database fails here, before the caller's
            # closing() has the connection: closed now, or its handle keeps
            # the file open (on Windows, unrenamable) until collected.
            conn.close()
            raise
        return conn

    def _excluded(self, path: Path) -> bool:
        # The data directory changes constantly (logs, caches, this very
        # baseline); monitoring it would report AVGuard's own work forever.
        text = os.path.normcase(os.path.abspath(str(path)))
        if any(text == key or text.startswith(key + os.sep) for key in self._data_keys):
            return True
        return matches_excluded_glob(path, self.excluded_globs)

    def _walk(self, root: Path, errors: list[str]) -> Iterable[Path]:
        """Every regular file under `root`, without following reparse points."""
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: errors.append(str(e))):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not _is_reparse_point(here / d) and not self._excluded(here / d))
            for name in sorted(filenames):
                path = here / name
                if self._excluded(path) or _is_reparse_point(path):
                    continue
                if not path.is_file():
                    continue
                yield path

    # ------------------------------------------------------------- reading

    def roots(self) -> list[str]:
        if not self.exists():
            return []
        try:
            with closing(self._connect()) as conn:
                return [row[0] for row in conn.execute("SELECT path FROM roots ORDER BY path")]
        except sqlite3.Error:
            return []

    def file_count(self) -> int:
        if not self.exists():
            return 0
        try:
            with closing(self._connect()) as conn:
                return int(conn.execute("SELECT COUNT(*) FROM files").fetchone()[0])
        except sqlite3.Error:
            return 0

    def baselined_at(self) -> float:
        if not self.exists():
            return 0.0
        try:
            with closing(self._connect()) as conn:
                row = conn.execute("SELECT MAX(baselined_at) FROM files").fetchone()
        except sqlite3.Error:
            return 0.0
        return float(row[0] or 0.0)

    # ------------------------------------------------------------ baseline

    def baseline(self, roots: Iterable[Path], progress: ProgressHook | None = None,
                 should_stop: StopHook | None = None,
                 events: EventStore | None = None) -> BaselineReport:
        """Record what the roots hold now. A root already recorded is replaced.

        The roots are walked first and hashed second, so `progress` knows the
        total from its first call. A stop before the end writes nothing: the
        baseline on disk, if there is one, stays exactly what it was.
        """
        started = time.monotonic()
        report = BaselineReport()
        rows: list[tuple[str, bytes, int, int, float]] = []
        now = time.time()
        wanted = _one_root_per_tree([Path(os.path.abspath(str(root))) for root in roots], self.roots())
        pending: list[Path] = []
        for root in wanted:
            if not root.is_dir():
                report.errors.append(f"not a directory: {root}")
                continue
            report.roots.append(str(root))
            pending.extend(self._walk(root, report.errors))
        for done, path in enumerate(pending, 1):
            if should_stop is not None and should_stop():
                report.cancelled = True
                report.seconds = time.monotonic() - started
                log.info("baseline cancelled after %d of %d file(s); nothing was written",
                         done - 1, len(pending))
                return report
            try:
                sha, size, mtime_ns = hash_file(path)
            except OSError as exc:
                report.errors.append(f"{path}: {exc}")
                report.skipped += 1
            else:
                rows.append((str(path), bytes.fromhex(sha), size, mtime_ns, now))
                report.bytes += size
            if progress is not None:
                progress(done, len(pending))
        if not report.roots:
            return report

        lock = FileLock(self.lock_path)
        if not lock.acquire(LOCK_WAIT):
            log.warning("baseline not written: %s", IN_USE)
            report.errors.append(IN_USE)
            report.in_use = True
            report.roots = []
            report.seconds = time.monotonic() - started
            return report
        try:
            # Checked before anything is written, under the lock. A baseline
            # of one folder used to re-sign every other folder's rows as they
            # stood, so a row doctored outside AVGuard, or a baseline copied
            # in without its signature, became genuine on the next ordinary
            # baseline and no check ever said so.
            report.integrity = self.verify_integrity()
            untrusted = report.integrity not in (INTEGRITY_OK, INTEGRITY_NO_BASELINE)
            with closing(self._connect()) as conn:
                with conn:
                    existing = [row[0] for row in conn.execute("SELECT path FROM files")]
                    recorded = [row[0] for row in conn.execute("SELECT path FROM roots")]
                    # Rows under a root being re-baselined go first, so a file that
                    # vanished since the last baseline is not carried forward.
                    # When the old signature did not hold, nothing is carried
                    # forward: what is not baselined again is dropped, and said.
                    stale = [p for p in existing
                             if untrusted or any(_under(p, root) for root in report.roots)]
                    conn.executemany("DELETE FROM files WHERE path = ?", ((p,) for p in stale))
                    conn.executemany(
                        "INSERT OR REPLACE INTO files(path, sha256, size, mtime_ns, baselined_at) "
                        "VALUES (?, ?, ?, ?, ?)", rows)
                    # One root per tree: a subfolder of a recorded root is not
                    # recorded again (every check walked it twice and reported
                    # each new file under it twice), and recorded roots inside
                    # one being baselined give way to it.
                    keep = [r for r in recorded if not untrusted
                            and not any(_under(r, root) for root in report.roots)]
                    report.dropped_roots = [r for r in recorded if untrusted
                                            and not any(_under(r, root) for root in report.roots)]
                    new_roots = [r for r in report.roots if not any(_under(r, k) for k in keep)]
                    conn.execute("DELETE FROM roots")
                    conn.executemany("INSERT OR REPLACE INTO roots(path, added_at) VALUES (?, ?)",
                                     [(r, now) for r in keep] + [(r, now) for r in new_roots])
            # A baseline is "record what is here now": a key that cannot be
            # read (another user's, or damaged) goes with the old baseline,
            # and the documented way out of key-unreadable is this call.
            report.key_replaced = self._sign(replace_unreadable_key=True)
        finally:
            lock.release()
        if untrusted:
            message = (f"{INTEGRITY_MESSAGES[report.integrity]}; it was not carried forward"
                       + (f", and {len(report.dropped_roots)} folder(s) not baselined again were dropped"
                          if report.dropped_roots else ""))
            log.warning("baseline: %s", message)
            if events is not None:
                events.record(Event(kind="fim", level="tampered", reasons=[message],
                                    detail={"integrity": report.integrity,
                                            "dropped_roots": report.dropped_roots}))
        report.files = len(rows)
        report.seconds = time.monotonic() - started
        log.info("baselined %d file(s) under %d root(s) in %.1fs",
                 report.files, len(report.roots), report.seconds)
        return report

    # --------------------------------------------------------------- check

    def check(self, fast: bool = False, events: EventStore | None = None,
              progress: ProgressHook | None = None,
              should_stop: StopHook | None = None) -> CheckReport:
        """What differs from the baseline. Records events; moves nothing.

        `fast` trusts an unchanged size and mtime and skips the read. That
        is exactly what an attacker restoring a file's timestamp defeats,
        which is why it is not the default.

        A stop before the end returns what was found so far, marked
        cancelled, and records none of it: a partial check is not a result,
        and an event is a claim.
        """
        started = time.monotonic()
        report = CheckReport(fast=fast)
        if not self.exists():
            report.integrity = INTEGRITY_NO_BASELINE
            return report
        # The lock covers the signature check and the row read only: the
        # milliseconds in which a baseline being written by the window and a
        # check run by the daily task could see each other's half-state. The
        # hashing that follows holds nothing.
        lock = FileLock(self.lock_path)
        if not lock.acquire(LOCK_WAIT):
            # Not a clean check: nothing was checked. It used to read "No
            # changes", exit 0, and under the daily task leave no trace.
            log.warning("integrity check not run: %s", IN_USE)
            report.errors.append(IN_USE)
            report.in_use = True
            report.seconds = time.monotonic() - started
            return report
        try:
            report.integrity = self.verify_integrity()
            with closing(self._connect()) as conn:
                rows = conn.execute("SELECT path, sha256, size, mtime_ns FROM files").fetchall()
                roots = [row[0] for row in conn.execute("SELECT path FROM roots")]
        except sqlite3.Error as exc:
            # A baseline damaged badly enough that SQLite cannot read it.
            # The signature check above already says so; the tamper event is
            # still recorded, and the check reports what it could not do
            # instead of raising out of a scheduled task into nothing.
            if report.integrity == INTEGRITY_OK:
                report.integrity = INTEGRITY_TAMPERED
            report.errors.append(f"the baseline cannot be read: {exc}")
            report.seconds = time.monotonic() - started
            if events is not None:
                integrity = report.integrity_event()
                if integrity is not None:
                    events.record(integrity)
            log.error("integrity check: the baseline cannot be read (%s)", exc)
            return report
        finally:
            lock.release()

        known: dict[str, tuple[str, str, int, int]] = {}
        for stored_path, sha, size, mtime_ns in rows:
            known[_key(stored_path)] = (stored_path, sha.hex(), int(size), int(mtime_ns))

        # Excluded since the baseline: neither checked nor reported as
        # removed. The user said "never look here".
        candidates = [entry for entry in known.values() if not self._excluded(Path(entry[0]))]
        # The roots are walked before anything is hashed, so the total is
        # known from the first progress call; the walk is the cheap part.
        fresh: list[Path] = []
        walked: set[str] = set()
        for root in roots:
            root_path = Path(root)
            if not root_path.is_dir():
                report.errors.append(f"root no longer exists: {root}")
                continue
            for path in self._walk(root_path, report.errors):
                key = _key(path)
                # A root inside another (a baseline from before roots were
                # kept one per tree) is walked once per root; a file is
                # reported once.
                if key not in known and key not in walked:
                    walked.add(key)
                    fresh.append(path)
        total = len(candidates) + len(fresh)
        done = 0

        def stopped() -> bool:
            if should_stop is None or not should_stop():
                return False
            report.cancelled = True
            report.seconds = time.monotonic() - started
            log.info("integrity check cancelled after %d of %d file(s); nothing was recorded",
                     done, total)
            return True

        for entry in candidates:
            if stopped():
                return report
            self._examine(report, *entry, fast=fast)
            done += 1
            if progress is not None:
                progress(done, total)

        for path in fresh:
            if stopped():
                return report
            try:
                new_sha, new_size, _ = hash_file(path)
            except OSError as exc:
                report.errors.append(f"{path}: {exc}")
            else:
                report.hashed += 1
                report.changes.append(Change("added", str(path), new_sha256=new_sha,
                                             new_size=new_size))
            done += 1
            if progress is not None:
                progress(done, total)

        report.seconds = time.monotonic() - started
        if events is not None:
            integrity = report.integrity_event()
            if integrity is not None:
                events.record(integrity)
            for change in report.changes:
                events.record(change.as_event())
        log.info("integrity check: %d examined, %d hashed, %d change(s), integrity %s, %.1fs",
                 report.examined, report.hashed, len(report.changes), report.integrity,
                 report.seconds)
        return report

    def _examine(self, report: CheckReport, stored_path: str, old_sha: str,
                 old_size: int, old_mtime: int, fast: bool) -> None:
        """One baselined file against the disk: removed, modified, or as it was."""
        path = Path(stored_path)
        report.examined += 1
        try:
            st = path.stat()
        except FileNotFoundError:
            report.changes.append(Change("removed", stored_path, old_sha256=old_sha,
                                         old_size=old_size))
            return
        except OSError as exc:
            report.errors.append(f"{stored_path}: {exc}")
            return
        if fast and st.st_size == old_size and st.st_mtime_ns == old_mtime:
            return
        try:
            new_sha, new_size, _ = hash_file(path)
        except OSError as exc:
            report.errors.append(f"{stored_path}: {exc}")
            return
        report.hashed += 1
        if new_sha != old_sha:
            report.changes.append(Change("modified", stored_path, old_sha256=old_sha,
                                         new_sha256=new_sha, old_size=old_size,
                                         new_size=new_size))

    # -------------------------------------------------------------- accept

    def accept(self, paths: Iterable[Path]) -> list[str]:
        """Re-baseline these paths after somebody looked at the change.

        A user action, never automatic: the alert stops repeating because a
        person decided it should. A path that is gone is dropped from the
        baseline; a new one is added; a changed one is re-hashed.

        Raises Refused, having written nothing, when another AVGuard holds
        the baseline or its signature does not hold: accepting into a
        baseline nobody can vouch for signed whatever had been done to it.
        The files are hashed before the lock is taken, so a large accept
        does not lock out the daily check.
        """
        done = Accepted()
        hashed: list[tuple[Path, tuple[str, int, int] | None]] = []
        for path in paths:
            path = Path(os.path.abspath(str(path)))
            if path.is_file():
                try:
                    hashed.append((path, hash_file(path)))
                except OSError as exc:
                    done.append(f"{path}: could not be read ({exc}); not accepted")
                    done.not_accepted.append(str(path))
            else:
                hashed.append((path, None))
        lock = FileLock(self.lock_path)
        if not lock.acquire(LOCK_WAIT):
            log.warning("accept refused: %s", IN_USE)
            raise Refused(f"Nothing was accepted: {IN_USE}.")
        try:
            integrity = self.verify_integrity()
            if integrity != INTEGRITY_OK:
                raise Refused(f"Nothing was accepted: {INTEGRITY_MESSAGES.get(integrity, integrity)}. "
                              "Check it to see what changed, or baseline again to start over.")
            with closing(self._connect()) as conn:
                with conn:
                    for path, facts in hashed:
                        if facts is not None:
                            sha, size, mtime_ns = facts
                            conn.execute(
                                "INSERT OR REPLACE INTO files(path, sha256, size, mtime_ns, "
                                "baselined_at) VALUES (?, ?, ?, ?, ?)",
                                (str(path), bytes.fromhex(sha), size, mtime_ns, time.time()))
                            done.append(f"accepted {path} ({sha[:12]})")
                        else:
                            removed = conn.execute("DELETE FROM files WHERE path = ?",
                                                   (str(path),)).rowcount
                            done.append(f"dropped {path} from the baseline"
                                        if removed else f"{path}: not in the baseline")
            try:
                self._sign()
            except (OSError, ValueError) as exc:
                # The rows are in; the signature is not. Said, not raised:
                # raising here lost the notes and left the user guessing.
                log.error("accept: the baseline was changed but not signed (%s)", exc)
                done.append("not signed: the baseline's signing key cannot be read; "
                            "baseline again to replace it")
        finally:
            lock.release()
        return done

    # ------------------------------------------------------------ integrity

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            return self._unprotect(self.key_path.read_bytes())
        key = secrets.token_bytes(32)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(self._protect(key))
        return key

    def _signature(self, key: bytes) -> str:
        return hmac.new(key, self.db_path.read_bytes(), hashlib.sha256).hexdigest()

    def _sign(self, replace_unreadable_key: bool = False) -> bool:
        """Sign the database. With `replace_unreadable_key`, a key that cannot
        be read is replaced by a fresh one and True is returned; otherwise
        the error is the caller's."""
        replaced = False
        try:
            key = self._load_or_create_key()
        except (OSError, ValueError):
            if not replace_unreadable_key:
                raise
            log.warning("the baseline's signing key could not be read; a new one replaces it")
            self.key_path.unlink(missing_ok=True)
            key = self._load_or_create_key()
            replaced = True
        config.atomic_write_text(self.signature_path, self._signature(key))
        return replaced

    def verify_integrity(self) -> str:
        if not self.exists():
            return INTEGRITY_NO_BASELINE
        if not self.signature_path.is_file() or not self.key_path.is_file():
            return INTEGRITY_UNSIGNED
        try:
            key = self._unprotect(self.key_path.read_bytes())
        except (OSError, ValueError):
            return INTEGRITY_KEY_UNREADABLE
        try:
            recorded = self.signature_path.read_text(encoding="ascii").strip()
        except (OSError, ValueError):
            # A signature file holding a byte that is not text (a disk error,
            # another tool, someone who wants AVGuard gone) is a signature
            # that does not hold. It raised, and the window never opened.
            return INTEGRITY_TAMPERED
        if hmac.compare_digest(recorded, self._signature(key)):
            return INTEGRITY_OK
        return INTEGRITY_TAMPERED
