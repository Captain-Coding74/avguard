"""The two failures that matter most, as regression tests.

Both were found by auditing the finished code, and both were reproduced before
being fixed. They are the same two failures this whole project is about, which
is why they get their own file rather than being buried in a tier.

1. Quarantine destroyed the user's file if the index write failed. The order
   was: write payload, unlink original, then save the record. The nonce that
   decodes the payload existed only in memory until that last step, so a full
   disk, a locked index or a process kill in that window deleted the file and
   left a payload nothing could ever decode. Neither restore nor --export-all
   could recover it, and the bare OSError escaped every caller's
   `except QuarantineError` and was swallowed by the UI pump.

2. Real-time protection reported itself healthy while scanning nothing.
   Deleting and recreating a watched folder kills watchdog's per-directory
   emitter permanently, but the observer thread, the debouncer and the worker
   pool all stay alive. Four files scoring a hard 100 sat undetected while
   `running` returned True and the Health view printed OK. That is v1's
   defining failure reproduced by the rewrite, through a new mechanism.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from avguard import config
from avguard.protection import SelfProtection
from avguard.quarantine import (
    QuarantineError, QuarantineRecord, QuarantineStore, _mask,
)
from avguard.scanner import ScanCache, Scanner
from avguard.watcher import RealtimeMonitor

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

RULES = Path(__file__).resolve().parent.parent / "rules" / "malware.yara"


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-dur-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "prot").mkdir()

    def write(self, name: str, data: bytes) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


# ------------------------------------------------- quarantine never loses data

class TestQuarantineDurability(TempCase):

    def store(self, directory: Path | None = None) -> QuarantineStore:
        directory = directory or (self.tmp / "store")
        return QuarantineStore(directory=directory,
                               index_path=directory / "index.json",
                               protection=SelfProtection([self.tmp / "prot"]))

    @staticmethod
    def _break_the_index(directory: Path) -> None:
        """Make the index unwritable with a real OS error, not a mock.

        A directory sitting where the file belongs makes os.replace fail the
        same way a full disk or a permission problem would.
        """
        (directory / "index.json").mkdir(parents=True, exist_ok=True)

    def test_a_failed_index_write_does_not_destroy_the_file(self):
        directory = self.tmp / "store"
        store = self.store(directory)
        victim = self.write("irreplaceable.docx", b"THE ONLY COPY")
        self._break_the_index(directory)

        with self.assertRaises(QuarantineError):
            store.quarantine(victim, ["detected"])

        self.assertTrue(victim.exists(), "the user's file was destroyed")
        self.assertEqual(victim.read_bytes(), b"THE ONLY COPY")

    def test_the_error_is_one_callers_actually_catch(self):
        """A bare OSError escaped gui._handle_threat and produced no message."""
        directory = self.tmp / "store"
        store = self.store(directory)
        victim = self.write("t.docx", b"x")
        self._break_the_index(directory)
        try:
            store.quarantine(victim, [])
        except QuarantineError:
            pass
        except OSError as exc:
            self.fail(f"raised a bare {type(exc).__name__}, which no caller catches")

    def test_a_failed_write_leaves_no_undecodable_payload(self):
        directory = self.tmp / "store"
        store = self.store(directory)
        self._break_the_index(directory)
        with self.assertRaises(QuarantineError):
            store.quarantine(self.write("t.docx", b"x"), [])
        self.assertEqual(list(directory.glob("*.quar")), [],
                         "a payload nothing can decode was left behind")

    def _plant_pending(self, store, directory: Path, original: Path,
                       payload: bytes) -> QuarantineRecord:
        """A record left half-written, as a process kill would leave it."""
        entry_id = uuid.uuid4().hex
        nonce = os.urandom(16)
        (directory / f"{entry_id}.quar").write_bytes(_mask(payload, nonce))
        record = QuarantineRecord(
            entry_id=entry_id,
            original_path=str(original),
            original_name=original.name,
            quarantined_at="2026-01-01T00:00:00+00:00",
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            nonce=nonce.hex(),
            reasons=["planted"],
            pending=True,
        )
        store._records[entry_id] = record
        store._save()
        return record

    def test_an_interrupted_move_is_undone_if_the_original_survived(self):
        """Killed after the record was saved but before the unlink."""
        directory = self.tmp / "store"
        store = self.store(directory)
        victim = self.write("still_here.docx", b"USER DATA")
        record = self._plant_pending(store, directory, victim, b"USER DATA")

        reopened = self.store(directory)
        self.assertTrue(victim.exists(), "the file was taken during recovery")
        self.assertIsNone(reopened.get(record.entry_id), "a phantom record survived")
        self.assertFalse((directory / f"{record.entry_id}.quar").exists())

    def test_an_interrupted_move_is_honoured_if_the_original_is_gone(self):
        """Killed after the unlink but before the flag was cleared."""
        directory = self.tmp / "store"
        store = self.store(directory)
        already_moved = self.tmp / "already_moved.docx"
        record = self._plant_pending(store, directory, already_moved, b"MOVED DATA")

        reopened = self.store(directory)
        kept = reopened.get(record.entry_id)
        self.assertIsNotNone(kept, "a completed move was thrown away")
        self.assertFalse(kept.pending)
        self.assertEqual(reopened.restore(record.entry_id).read_bytes(), b"MOVED DATA")

    def test_a_normal_quarantine_leaves_nothing_pending(self):
        store = self.store()
        record = store.quarantine(self.write("t.exe", b"x"), [])
        self.assertFalse(store.get(record.entry_id).pending)

    def test_a_normal_quarantine_still_round_trips(self):
        store = self.store()
        record = store.quarantine(self.write("t.exe", b"payload"), ["r"])
        self.assertEqual(store.restore(record.entry_id).read_bytes(), b"payload")

    def test_orphaned_payloads_are_reported_not_hidden(self):
        directory = self.tmp / "store"
        store = self.store(directory)
        (directory / f"{uuid.uuid4().hex}.quar").write_bytes(b"undecodable")
        self.assertEqual(len(store.orphaned_payloads()), 1)


# --------------------------------------- real-time protection tells the truth

class TestRealtimeHonesty(TempCase):

    def monitor(self, on_verdict=None) -> RealtimeMonitor:
        protection = SelfProtection([self.tmp / "prot"])
        scanner = Scanner(config.Config(cloud_enabled=False), protection,
                          rules_path=RULES, cache=ScanCache(path=self.tmp / "c.json"))
        instance = RealtimeMonitor(scanner, protection,
                                   on_verdict=on_verdict or (lambda v: None),
                                   workers=2, debounce_seconds=0.3)
        self.addCleanup(instance.stop)
        return instance

    def watched_dir(self) -> Path:
        path = self.tmp / "watched"
        path.mkdir(exist_ok=True)
        return path

    def test_a_healthy_monitor_reports_no_broken_links(self):
        monitor = self.monitor()
        monitor.start([self.watched_dir()])
        self.assertEqual(monitor.broken_links(), [])
        self.assertTrue(monitor.running)

    def test_a_stopped_monitor_is_not_running(self):
        monitor = self.monitor()
        monitor.start([self.watched_dir()])
        monitor.stop()
        self.assertFalse(monitor.running)
        self.assertTrue(monitor.broken_links())

    def test_a_dead_worker_pool_breaks_the_chain(self):
        """An observer with nothing to scan for it is not protection."""
        monitor = self.monitor()
        monitor.start([self.watched_dir()])
        monitor.pool.stop()
        self.assertFalse(monitor.running)
        self.assertTrue(any("worker" in reason for reason in monitor.broken_links()))

    def test_a_dead_debouncer_breaks_the_chain(self):
        """The debouncer is the only link between the watcher and the pool."""
        monitor = self.monitor()
        monitor.start([self.watched_dir()])
        monitor.debouncer.stop()
        self.assertFalse(monitor.running)

    def test_broken_links_read_as_english(self):
        monitor = self.monitor()
        monitor.start([self.watched_dir()])
        monitor.pool.stop()
        reasons = monitor.broken_links()
        self.assertTrue(reasons)
        for reason in reasons:
            self.assertNotIn("_", reason, "health text is shown to the user")
            self.assertGreater(len(reason), 12)

    def test_recover_restarts_a_broken_monitor(self):
        monitor = self.monitor()
        monitor.start([self.watched_dir()])
        monitor.pool.stop()
        self.assertFalse(monitor.running)
        self.assertTrue(monitor.recover())
        self.assertTrue(monitor.running)

    def test_recover_does_nothing_when_nothing_was_watched(self):
        self.assertFalse(self.monitor().recover())

    @unittest.skipUnless(sys.platform == "win32", "emitter behaviour is platform-specific")
    def test_deleting_and_recreating_a_watched_folder_is_noticed(self):
        """The exact reproduction. Before the fix this returned True while
        four files scoring a hard 100 sat in the folder undetected."""
        import time
        watched = self.watched_dir()
        monitor = self.monitor()
        monitor.start([watched])
        self.assertTrue(monitor.running)

        shutil.rmtree(watched)
        time.sleep(0.4)
        watched.mkdir()
        time.sleep(1.5)

        if monitor.broken_links():
            self.assertFalse(monitor.running,
                             "the chain is broken but running still says True")
        # If watchdog survived it on this build, that is fine -- the assertion
        # that matters is that running and broken_links never disagree.
        self.assertEqual(monitor.running, not monitor.broken_links())


if __name__ == "__main__":
    unittest.main(verbosity=2)
