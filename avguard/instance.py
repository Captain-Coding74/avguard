"""One writer at a time.

Two AVGuard processes sharing `data/` destroy each other's quarantine records.
Both load the index once at construction and later rewrite it whole, so the
second one to write erases whatever the first one added. Reproduced: the
original file is deleted, the masked payload is orphaned, and nothing in the
program can list or restore it. The README documents running a CLI scan while
the GUI is open, so this is a normal thing to do, not an exotic one.

Two defences, because either alone is not enough:

  * this lock, which stops the second process writing at all, and
  * `QuarantineStore` re-reading the index before every mutation, so losing
    the race is survivable rather than destructive.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from . import config

log = logging.getLogger(__name__)

LOCK_NAME = "avguard.lock"


class InstanceLock:
    """An advisory, exclusive, whole-file lock on `data/avguard.lock`.

    Uses `msvcrt.locking` on Windows and `fcntl.flock` elsewhere. The lock is
    released when the handle closes, including on an abrupt process exit, so a
    crash cannot leave a stale lock behind — which is the usual failing of the
    "write a PID file" approach.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else config.DATA_DIR / LOCK_NAME
        self._handle = None
        self.owner_pid: int | None = None

    def acquire(self) -> bool:
        """Take the lock. Returns False if another process already holds it."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Opened "r+b", not "a+": msvcrt.locking locks a byte range
            # starting at the CURRENT file position, and in append mode each
            # handle sits at its own end-of-file, so two processes would
            # happily lock different bytes and both think they had won.
            if not self.path.exists():
                self.path.touch()
            handle = open(self.path, "r+b")
        except OSError as exc:
            # A read-only or otherwise unusable data directory is a real
            # problem, but it is not this module's job to stop the program.
            log.warning("could not open the lock file at %s: %s", self.path, exc)
            return True

        if not self._try_lock(handle):
            try:
                # Read from byte 1: byte 0 is the locked one and reading it
                # while another process holds the lock fails.
                handle.seek(1)
                self.owner_pid = int((handle.read() or b"0").decode().strip() or 0) or None
            except (OSError, ValueError, UnicodeDecodeError):
                self.owner_pid = None
            handle.close()
            return False

        try:
            # Byte 0 stays locked; the pid is written after it so a waiting
            # process can say WHO holds the lock.
            handle.seek(1)
            handle.truncate(1)
            handle.write(str(os.getpid()).encode())
            handle.flush()
        except OSError:
            pass

        self._handle = handle
        return True

    @staticmethod
    def _try_lock(handle) -> bool:
        """Lock byte 0, from position 0, so every handle contends for the same byte."""
        try:
            import msvcrt
        except ImportError:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                return False
        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            import msvcrt
            self._handle.seek(0)
            msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        except (ImportError, OSError):
            pass
        try:
            self._handle.close()
        except OSError:
            pass
        self._handle = None

    @property
    def held(self) -> bool:
        return self._handle is not None

    def __enter__(self) -> "InstanceLock":
        self.acquired = self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
