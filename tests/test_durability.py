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
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolate the data directory BEFORE avguard is imported.
#
# config computes DATA_DIR at import time, so this has to happen first. Without
# it, any object built with its default path -- Scanner's Allowlist,
# QuarantineStore's, a PackStore -- reaches into the real
# %LOCALAPPDATA%/AVGuard. The suite silently wrote seven entries into the
# user's live allowlist that way, one of them the hash of SELFTEST_MARKER,
# which then suppressed its own detection and broke four unrelated tests.
#
# Per run, not a fixed path: a shared directory accumulates state between runs,
# and a stale entry from one run silently broke the next.
import os as _os
import tempfile as _tempfile

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)
def _remove_tree(path) -> None:
    """rmtree that copes with read-only files.

    Some tests make one on purpose, and rmtree(ignore_errors=True) then left
    the whole directory behind without a word: 122 of them in TEMP.
    """
    import shutil as _shutil
    import stat as _stat

    def writable_then(func, target, _exc):
        try:
            _os.chmod(target, _stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    _shutil.rmtree(path, onexc=writable_then)


if _os.environ["AVGUARD_DATA"] == _test_data:
    # This process made it, so this process removes it. 766 of these had
    # piled up in TEMP before this line existed, and the whole suite ran
    # three times slower for it.
    import atexit as _atexit
    _atexit.register(_remove_tree, _test_data)



from avguard import config
from avguard.protection import SelfProtection
from avguard.rulepacks import PackStore
from avguard.quarantine import (
    QuarantineError, QuarantineRecord, QuarantineStore, _mask,
)
from avguard.scanner import ScanCache, Scanner
from avguard.watcher import RealtimeMonitor

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

RULES = Path(__file__).resolve().parent.parent / "rules" / "malware.yara"


def _empty_packs(tmp: Path) -> PackStore:
    """An isolated pack store.

    Scanner used to build a real PackStore pointing at the user's data
    directory, so installing one real pack made three of these tests fail:
    they were measuring whatever happened to be on the machine. The store is
    injectable now, and tests inject an empty one.
    """
    return PackStore(directory=tmp / "packs", index_path=tmp / "packs" / "packs.json")


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-dur-"))
        self.addCleanup(_remove_tree, self.tmp)
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
        reopened.reconcile()                 # what the lock holder does at start
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
        reopened.reconcile()
        kept = reopened.get(record.entry_id)
        self.assertIsNotNone(kept, "a completed move was thrown away")
        self.assertFalse(kept.pending)
        self.assertEqual(reopened.restore(record.entry_id).read_bytes(), b"MOVED DATA")

    # ---- round six (docs/open-issues.md, rows 61 on) ----

    def test_a_store_built_without_the_lock_leaves_a_move_in_progress_alone(self):
        """A right-click scan, --list-quarantine or a second window builds a
        store. Built while the lock holder sat between its pending save and
        its unlink, it deleted the payload; the holder then unlinked the
        original. 28 to 50 files of 500 were lost that way under load."""
        directory = self.tmp / "store"
        holder = self.store(directory)
        victim = self.write("report.docx", b"THE ONLY COPY")
        record = self._plant_pending(holder, directory, victim, b"THE ONLY COPY")
        self.store(directory)                                   # the lockless reader
        self.assertTrue((directory / f"{record.entry_id}.quar").exists(), "the payload was deleted")
        self.assertIn(record.entry_id, json.loads((directory / "index.json").read_text()))

    def test_reconcile_leaves_a_different_file_at_the_old_path(self):
        """Killed after the unlink; the same name was downloaded again. The
        old rule (anything at the path means the move never happened)
        deleted the only copy of what was taken."""
        directory = self.tmp / "store"
        store = self.store(directory)
        path = self.tmp / "draft.docx"
        record = self._plant_pending(store, directory, path, b"WHAT WAS TAKEN")
        path.write_bytes(b"a new draft, saved since")
        reopened = self.store(directory)
        reopened.reconcile()
        self.assertEqual(path.read_bytes(), b"a new draft, saved since")
        kept = reopened.get(record.entry_id)
        self.assertIsNotNone(kept, "the only copy of what was taken was deleted")
        self.assertFalse(kept.pending)
        self.assertTrue((directory / f"{record.entry_id}.quar").exists())

    def test_a_record_another_process_removed_is_not_written_back(self):
        directory = self.tmp / "store"
        holder, second = self.store(directory), self.store(directory)
        taken = holder.quarantine(self.write("x.docx", b"x"), [])
        second.restore(taken.entry_id)
        holder.quarantine(self.write("y.exe", b"y"), [])
        on_disk = json.loads((directory / "index.json").read_text())
        self.assertNotIn(taken.entry_id, on_disk, "a restored file came back as held, with no payload")
        self.assertEqual(len(holder), 1)

    def test_an_index_with_a_byte_order_mark_is_read(self):
        directory = self.tmp / "store"
        store = self.store(directory)
        record = store.quarantine(self.write("thesis.docx", b"thesis"), [])
        index = directory / "index.json"
        index.write_bytes(b"\xef\xbb\xbf" + index.read_bytes())       # Notepad's "UTF-8"
        reopened = self.store(directory)
        self.assertIsNotNone(reopened.get(record.entry_id), "a BOM read as an empty index")
        reopened.quarantine(self.write("next.exe", b"n"), [])
        self.assertEqual(reopened.restore(record.entry_id).read_bytes(), b"thesis")

    def test_an_unreadable_index_is_set_aside_not_written_over(self):
        for name, damage in (("not utf-8", b'{"a": {"original_name": "\xe0\xb9\x84\xe0"}}'),
                             ("an array", b'[{"entry_id": "x"}]'), ("not json", b"{nope")):
            with self.subTest(damage=name):
                directory = self.tmp / f"store-{name.replace(' ', '-')}"
                directory.mkdir()
                (directory / "index.json").write_bytes(damage)
                store = self.store(directory)                   # no crash on start
                self.assertEqual(len(store), 0)
                self.assertIn("cannot be read", store.index_problem)
                store.quarantine(self.write(f"{name}.exe", b"new"), [])
                kept = list(directory.glob("index.json.unreadable-*"))
                self.assertEqual([p.read_bytes() for p in kept], [damage], "the bytes were written over")
                self.assertIn("kept as", store.index_problem)

    def test_the_payload_and_the_restored_file_are_flushed_first(self):
        """The journal makes a rename and an unlink durable, not the data:
        unflushed, a power cut after the unlink could leave a payload of
        zeros and no original."""
        if not Path("/proc/self/fd").is_dir():
            self.skipTest("needs /proc to name a file descriptor")
        steps = []
        real_fsync, real_unlink = os.fsync, Path.unlink

        def fsync(fd):
            steps.append(("fsync", os.readlink(f"/proc/self/fd/{fd}")))
            return real_fsync(fd)

        def unlink(path, missing_ok=False):
            steps.append(("unlink", str(path)))
            return real_unlink(path, missing_ok=missing_ok)
        store = self.store()
        victim = self.write("only_copy.docx", b"the user's bytes")
        with mock.patch("os.fsync", fsync), mock.patch.object(Path, "unlink", unlink):
            record = store.quarantine(victim, [])
            store.restore(record.entry_id)
        unlink_original = steps.index(("unlink", str(victim.resolve())))
        self.assertTrue(any(kind == "fsync" and "/store/.avg-" in what for kind, what in steps[:unlink_original]),
                        f"no payload fsync before the original went: {steps}")
        unlink_payload = next(i for i, (kind, what) in enumerate(steps) if kind == "unlink" and what.endswith(".quar"))
        self.assertTrue(any(kind == "fsync" and what.startswith(str(victim.parent.resolve()) + "/.avg-")
                            for kind, what in steps[unlink_original:unlink_payload]),
                        f"no fsync of the restored file before the payload went: {steps}")

    def test_a_file_changed_since_its_scan_is_not_moved(self):
        store = self.store()
        victim = self.write("notes.txt", b"what was scanned")
        judged = hashlib.sha256(b"what was scanned").hexdigest()
        victim.write_bytes(b"my notes, the forum paste removed")
        with self.assertRaises(QuarantineError) as caught:
            store.quarantine(victim, ["r"], expected_sha256=judged)
        self.assertIn("changed after it was scanned", str(caught.exception))
        self.assertTrue(victim.exists())
        self.assertEqual(len(store), 0)
        self.assertIsNotNone(store.quarantine(victim, ["r"], expected_sha256=hashlib.sha256(
            b"my notes, the forum paste removed").hexdigest()))

    def test_a_damaged_payload_is_not_exported_as_the_original(self):
        directory = self.tmp / "store"
        store = self.store(directory)
        good = store.quarantine(self.write("fine.pdf", b"fine"), [])
        bad = store.quarantine(self.write("contract.pdf", b"contract " * 300), [])
        payload = directory / f"{bad.entry_id}.quar"
        payload.write_bytes(payload.read_bytes()[: bad.size // 2])
        with self.assertRaises(QuarantineError):
            store.payload(bad.entry_id)
        report = store.export_all(self.tmp / "out")
        self.assertEqual([p.read_bytes() for p in report.written], [b"fine"])
        self.assertEqual([name for name, _ in report.failed], ["contract.pdf"])
        self.assertIn("integrity", report.failed[0][1])
        self.assertIsNotNone(good)

    def test_a_long_name_can_be_restored_and_exported(self):
        directory = self.tmp / "store"
        store = self.store(directory)
        name = "x" * 245 + ".pdf"                                   # 249, legal on NTFS and ext4
        record = store.quarantine(self.write(name, b"long"), [])
        report = store.export_all(self.tmp / "out")
        self.assertEqual(report.failed, [])
        self.assertTrue(report.written[0].name.endswith(".pdf"))
        self.assertLessEqual(len(report.written[0].name.encode()), 255)
        self.assertEqual(store.restore(record.entry_id).read_bytes(), b"long")

    def test_a_payload_that_cannot_be_removed_does_not_undo_the_restore(self):
        directory = self.tmp / "store"
        store = self.store(directory)
        record = store.quarantine(self.write("kept.docx", b"kept"), ["r"])
        real_unlink = Path.unlink

        def unlink(path, missing_ok=False):
            if str(path).endswith(".quar"):
                raise PermissionError(32, "being used by another process")
            return real_unlink(path, missing_ok=missing_ok)
        with mock.patch.object(Path, "unlink", unlink):
            target = store.restore(record.entry_id)
        self.assertEqual(target.read_bytes(), b"kept")
        self.assertIsNone(store.get(record.entry_id), "the record stayed listed")
        self.assertIsNotNone(store.allowlist.allows(record.sha256), "the decision was not recorded")
        self.assertEqual(len(store.orphaned_payloads()), 1, "the leftover is reported, not hidden")

    def test_a_relative_destination_is_refused(self):
        with self.assertRaises(QuarantineError) as caught:
            self.store()._validate_destination(Path("relative") / "x.exe")
        self.assertIn("relative", str(caught.exception))

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
                          rules_path=RULES, cache=ScanCache(path=self.tmp / "c.json"),
                              packs=_empty_packs(self.tmp))
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




# ------------------------------------------------- a restore is a decision

class TestAllowlist(TempCase):
    """Restoring taught the scanner nothing, so it took the file straight back.

    With automatic quarantine on, a restored file was detected again and
    removed within about a second, and the only escape was excluding its whole
    folder. That is not an argument the user can win.
    """

    def setUp(self) -> None:
        super().setUp()
        from avguard.allowlist import Allowlist
        self.allowlist = Allowlist(path=self.tmp / "allow.json")
        self.protection = SelfProtection([self.tmp / "prot"])
        self.scanner = Scanner(config.Config(cloud_enabled=False), self.protection,
                               rules_path=RULES,
                               cache=ScanCache(path=self.tmp / "c.json"),
                                   packs=_empty_packs(self.tmp))
        self.scanner.allowlist = self.allowlist
        self.store = QuarantineStore(directory=self.tmp / "store",
                                     index_path=self.tmp / "store" / "index.json",
                                     protection=self.protection,
                                     allowlist=self.allowlist)

    def marker(self, name: str = "kept.bin") -> Path:
        from avguard.scanner import SELFTEST_MARKER
        return self.write(name, SELFTEST_MARKER)

    def test_a_restored_file_is_not_taken_again(self):
        from avguard.scanner import Level
        target = self.marker()
        verdict = self.scanner.scan(target, use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)

        record = self.store.quarantine(target, verdict.reasons)
        restored = self.store.restore(record.entry_id)

        again = self.scanner.scan(restored, use_cache=False)
        self.assertIs(again.level, Level.CLEAN)
        self.assertFalse(again.is_threat)

    def test_the_verdict_says_why_it_is_clean(self):
        """An allowed file must never simply look clean."""
        target = self.marker()
        verdict = self.scanner.scan(target, use_cache=False)
        record = self.store.quarantine(target, verdict.reasons)
        restored = self.store.restore(record.entry_id)
        again = self.scanner.scan(restored, use_cache=False)
        self.assertIn("you chose to keep", again.reasons[0])

    def test_the_decision_expires_when_the_file_changes(self):
        from avguard.scanner import Level, SELFTEST_MARKER
        target = self.marker()
        verdict = self.scanner.scan(target, use_cache=False)
        record = self.store.quarantine(target, verdict.reasons)
        restored = self.store.restore(record.entry_id)

        restored.write_bytes(SELFTEST_MARKER + b"  now edited")
        self.assertIs(self.scanner.scan(restored, use_cache=False).level,
                      Level.MALICIOUS,
                      "the decision must cover exact bytes, not a filename")

    def test_allowing_one_file_does_not_allow_another(self):
        from avguard.scanner import Level
        first = self.marker("first.bin")
        verdict = self.scanner.scan(first, use_cache=False)
        record = self.store.quarantine(first, verdict.reasons)
        self.store.restore(record.entry_id)

        second = self.marker("second.bin")
        second.write_bytes(second.read_bytes() + b" different")
        self.assertIs(self.scanner.scan(second, use_cache=False).level, Level.MALICIOUS)

    def test_entries_are_reviewable(self):
        target = self.marker()
        verdict = self.scanner.scan(target, use_cache=False)
        record = self.store.quarantine(target, verdict.reasons)
        self.store.restore(record.entry_id)

        entries = self.allowlist.entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "kept.bin")
        self.assertTrue(entries[0].was_flagged_for, "a list of bare hashes is not reviewable")

    def test_a_decision_can_be_taken_back(self):
        from avguard.scanner import Level
        target = self.marker()
        verdict = self.scanner.scan(target, use_cache=False)
        record = self.store.quarantine(target, verdict.reasons)
        restored = self.store.restore(record.entry_id)

        digest = self.allowlist.entries()[0].sha256
        self.assertTrue(self.allowlist.remove(digest))
        self.assertIs(self.scanner.scan(restored, use_cache=False).level, Level.MALICIOUS)

    def test_a_corrupt_allowlist_does_not_break_scanning(self):
        from avguard.allowlist import Allowlist
        (self.tmp / "bad.json").write_text("{ not json at all")
        self.assertEqual(len(Allowlist(path=self.tmp / "bad.json")), 0)


# ------------------------------------- cached verdicts and rule namespaces

class TestCacheGeneration(TempCase):
    """A cached verdict is a conclusion drawn by a particular version.

    The GUI built its ScanCache without a generation, and the check that
    compares generations was itself guarded by `if self._generation` -- so an
    empty one meant "accept anything". The GUI replayed verdicts written under
    any ruleset for the full 30-day TTL, then wrote the empty generation back,
    which made the CLI discard its whole cache on the next run. The two entry
    points erased each other's work on every alternation.
    """

    def cache(self, generation: str = "") -> ScanCache:
        return ScanCache(path=self.tmp / "c.json", generation=generation)

    def test_a_cache_without_a_generation_refuses_foreign_entries(self):
        from avguard.scanner import Level
        first = self.cache("AAAA")
        first.put(Path("c:/x"), 1, 2, Level.CLEAN, ["old logic"], "h")
        first.save()
        self.assertIsNone(self.cache().get(Path("c:/x"), 1, 2),
                          "an unknown generation must not be read as 'anything goes'")

    def test_reading_with_no_generation_does_not_destroy_the_cache(self):
        from avguard.scanner import Level
        first = self.cache("AAAA")
        first.put(Path("c:/x"), 1, 2, Level.CLEAN, ["keep me"], "h")
        first.save()
        self.cache().save()          # the GUI's old behaviour
        self.assertIsNotNone(self.cache("AAAA").get(Path("c:/x"), 1, 2),
                             "one entry point wiped the other's cache")

    def test_the_threshold_is_part_of_the_generation(self):
        """The README calls it 'evidence needed before a file may be moved'."""
        protection = SelfProtection([self.tmp / "prot"])
        lenient = Scanner(config.Config(cloud_enabled=False, quarantine_threshold=50),
                          protection, rules_path=RULES,
                          cache=ScanCache(path=self.tmp / "a.json"),
                              packs=_empty_packs(self.tmp))
        strict = Scanner(config.Config(cloud_enabled=False, quarantine_threshold=100),
                         protection, rules_path=RULES,
                         cache=ScanCache(path=self.tmp / "b.json"),
                             packs=_empty_packs(self.tmp))
        self.assertNotEqual(lenient.detection_generation(),
                            strict.detection_generation())

    def test_rekeying_discards_verdicts_from_the_old_settings(self):
        from avguard.scanner import Level
        protection = SelfProtection([self.tmp / "prot"])
        scanner = Scanner(config.Config(cloud_enabled=False), protection,
                          rules_path=RULES,
                          cache=ScanCache(path=self.tmp / "c.json",
                                          generation="whatever"),
                                              packs=_empty_packs(self.tmp))
        scanner.cache.put(Path("c:/x"), 1, 2, Level.CLEAN, ["stale"], "h")
        scanner.cache.save()
        scanner.rekey_cache()
        self.assertIsNone(scanner.cache.get(Path("c:/x"), 1, 2))


class TestUserRuleNamespaces(TempCase):
    """A user rule file named malware.yara replaced the shipped ruleset.

    The namespace key compared path.name against a dict keyed by path.stem, so
    the collision guard never fired. EICAR stopped matching entirely while the
    log still reported two files compiled and the Health view listed both.
    """

    def setUp(self) -> None:
        super().setUp()
        self.user_rules = self.tmp / "user_rules"
        self.user_rules.mkdir()
        self._original = config.USER_RULES_DIR
        config.USER_RULES_DIR = self.user_rules
        self.addCleanup(setattr, config, "USER_RULES_DIR", self._original)

    def scanner(self) -> Scanner:
        return Scanner(config.Config(cloud_enabled=False),
                       SelfProtection([self.tmp / "prot"]),
                       rules_path=RULES,
                       cache=ScanCache(path=self.tmp / "c.json"),
                           packs=_empty_packs(self.tmp))

    def test_a_user_file_sharing_the_shipped_name_does_not_replace_it(self):
        from avguard.scanner import EICAR
        (self.user_rules / "malware.yara").write_text(
            'rule Mine {\n  meta:\n    description = "mine"\n    severity = "low"\n'
            '  strings:\n    $a = { 7A 7A 7A 51 51 }\n  condition:\n    $a\n}\n',
            encoding="utf-8")
        scanner = self.scanner()
        self.assertIsNotNone(scanner.rules)
        matched = [m.rule for m in scanner.rules.match(data=EICAR)]
        self.assertIn("Eicar_Test_File", matched,
                      "the shipped ruleset was silently replaced")

    def test_the_user_rule_loads_alongside_it(self):
        (self.user_rules / "malware.yara").write_text(
            'rule Mine {\n  meta:\n    description = "mine"\n    severity = "low"\n'
            '  strings:\n    $a = { 7A 7A 7A 51 51 }\n  condition:\n    $a\n}\n',
            encoding="utf-8")
        scanner = self.scanner()
        matched = [m.rule for m in scanner.rules.match(data=b"...zzzQQ...")]
        self.assertIn("Mine", matched)

    def test_both_files_are_reported_as_sources(self):
        (self.user_rules / "extra.yara").write_text(
            'rule Extra {\n  meta:\n    description = "x"\n    severity = "low"\n'
            '  strings:\n    $a = { 51 51 51 51 }\n  condition:\n    $a\n}\n',
            encoding="utf-8")
        self.assertEqual(len(self.scanner().rule_sources), 2)


# ------------------------------------- the window must always open

class TestStartupSurvival(TempCase):
    """A watch folder that has been deleted used to stop the app existing.

    start() built an Observer, never started it, then called stop(), which
    joined it -- RuntimeError out of start(), out of AVGuardApp.__init__, and
    the window never appeared. realtime_enabled defaults to true, so a removable
    drive or a cleared Downloads was enough. Under the --noconsole build there
    was no stderr to say why.
    """

    def monitor(self) -> RealtimeMonitor:
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "prot"]),
                          rules_path=RULES,
                          cache=ScanCache(path=self.tmp / "c.json"),
                              packs=_empty_packs(self.tmp))
        return RealtimeMonitor(scanner, SelfProtection([self.tmp / "prot"]),
                               on_verdict=lambda verdict: None)

    def test_starting_on_a_missing_folder_returns_empty(self):
        monitor = self.monitor()
        self.addCleanup(monitor.stop)
        self.assertEqual(monitor.start([self.tmp / "not-here"]), [])

    def test_starting_on_a_missing_folder_does_not_raise(self):
        monitor = self.monitor()
        try:
            monitor.start([self.tmp / "not-here"])
        except Exception as exc:
            self.fail(f"start() raised {type(exc).__name__}: {exc}")
        finally:
            monitor.stop()

    def test_stopping_a_never_started_monitor_does_not_raise(self):
        monitor = self.monitor()
        try:
            monitor.stop()
        except Exception as exc:
            self.fail(f"stop() raised {type(exc).__name__}: {exc}")

    def test_a_protected_folder_is_refused_out_loud(self):
        """Watching a folder inside the project protects nothing.

        Self-protection refuses the whole tree before a file is opened, so
        "clone the repo into Downloads and watch Downloads" watched something
        it would always skip. Appearing to work is the failure mode this
        project exists to avoid.
        """
        # The real default protection, which covers the whole project. The
        # temp-dir protection the other tests use would not cover it.
        scanner = Scanner(config.Config(cloud_enabled=False), SelfProtection(),
                          rules_path=RULES, cache=ScanCache(path=self.tmp / "p.json"),
                              packs=_empty_packs(self.tmp))
        monitor = RealtimeMonitor(scanner, SelfProtection(),
                                  on_verdict=lambda verdict: None)
        self.addCleanup(monitor.stop)
        watched = monitor.start([config.PROJECT_ROOT])
        self.assertEqual(watched, [])
        self.assertEqual([p.resolve() for p in monitor.refused],
                         [config.PROJECT_ROOT.resolve()])

    def test_a_good_folder_still_works_alongside_a_bad_one(self):
        good = self.tmp / "watched"
        good.mkdir()
        monitor = self.monitor()
        self.addCleanup(monitor.stop)
        watched = monitor.start([self.tmp / "gone", good])
        self.assertEqual([p.resolve() for p in watched], [good.resolve()])


class TestCrashesReachTheLog(TempCase):
    """install_excepthooks() was written, praised in two comments, and called
    from nowhere. Under pythonw there is no stderr, so a crash left no trace."""

    def test_both_entry_points_install_the_hooks(self):
        """Parsed from source rather than imported.

        The first version imported avguard.gui, which needs ttkbootstrap, and
        failed on the Linux CI job where the GUI dependencies are deliberately
        not installed. Whether a line exists in main() is a question about the
        source, so ask the source.
        """
        import ast
        package = Path(__file__).resolve().parent.parent / "avguard"
        for filename in ("gui.py", "__main__.py"):
            with self.subTest(entry_point=filename):
                tree = ast.parse((package / filename).read_text(encoding="utf-8"))
                main = next((node for node in tree.body
                             if isinstance(node, ast.FunctionDef) and node.name == "main"), None)
                self.assertIsNotNone(main, f"{filename} has no main()")
                calls = [ast.unparse(node) for node in ast.walk(main)
                         if isinstance(node, ast.Call)]
                self.assertTrue(
                    any("install_excepthooks" in call for call in calls),
                    f"{filename}:main() does not install the excepthooks")

    def test_an_unhandled_exception_is_written_down(self):
        import subprocess
        env = dict(os.environ, AVGUARD_DATA=str(self.tmp / "data"))
        code = (
            "import sys; sys.path.insert(0, %r);"
            "from avguard import config, logsetup;"
            "config.ensure_directories(); logsetup.configure();"
            "logsetup.install_excepthooks();"
            "raise ValueError('crash-with-no-console')" % str(Path(__file__).resolve().parent.parent)
        )
        subprocess.run([sys.executable, "-c", code], env=env,
                       capture_output=True, text=True, timeout=120)
        log_file = self.tmp / "data" / "logs" / "avguard.log"
        self.assertTrue(log_file.exists(), "no log file was written at all")
        self.assertIn("crash-with-no-console",
                      log_file.read_text(encoding="utf-8", errors="replace"))


# ------------------------------------------- self-protection across path forms

class TestProtectionAcrossPathForms(TempCase):
    """A path can have more than one true spelling, and Windows uses that.

    On a packaged or containerised app, AppData is redirected: the log at
    %LOCALAPPDATA%/AVGuard/logs/avguard.log resolves to
    .../Packages/<app>/LocalCache/Local/AVGuard/logs/avguard.log. Roots were
    stored in one form and candidates compared in another, so self-protection
    silently stopped covering our own files.

    Worse, it only affected files that EXIST -- resolve() on a missing path
    does not follow the redirection -- so a fresh install looked protected and
    a running one was not. That is v1's failure, reachable again through a
    platform detail nobody had looked at.
    """

    def test_a_directory_protects_a_file_inside_it(self):
        root = self.tmp / "data"
        (root / "logs").mkdir(parents=True)
        target = root / "logs" / "avguard.log"
        target.write_text("real, existing file")
        self.assertTrue(SelfProtection([root]).is_protected(target))

    def test_protection_survives_a_symlinked_root(self):
        """The shape of the redirection, as a link we can actually create."""
        real = self.tmp / "real_data"
        (real / "logs").mkdir(parents=True)
        target = real / "logs" / "avguard.log"
        target.write_text("x")

        link = self.tmp / "linked_data"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a directory symlink here")

        # Protected by the link, asked about via the real path, and the
        # reverse. Both must hold: the two are the same file.
        self.assertTrue(SelfProtection([link]).is_protected(target))
        self.assertTrue(
            SelfProtection([real]).is_protected(link / "logs" / "avguard.log"))

    def test_an_existing_file_is_as_protected_as_a_missing_one(self):
        """The bug made existing files the unprotected ones."""
        root = self.tmp / "data"
        root.mkdir()
        missing = root / "not_written_yet.json"
        present = root / "written.json"
        present.write_text("x")
        protection = SelfProtection([root])
        self.assertTrue(protection.is_protected(missing))
        self.assertTrue(protection.is_protected(present))

    @unittest.skipUnless(sys.platform == "win32", "case-insensitivity is a Windows thing")
    def test_case_does_not_defeat_protection(self):
        root = self.tmp / "Data"
        root.mkdir()
        target = root / "file.txt"
        target.write_text("x")
        protection = SelfProtection([root])
        self.assertTrue(protection.is_protected(Path(str(target).upper())))
        self.assertTrue(protection.is_protected(Path(str(target).lower())))

    def test_the_real_data_directory_is_protected_in_full(self):
        """The live check, against this machine's actual layout."""
        protection = SelfProtection()
        for path in (config.LOG_DIR / "avguard.log",
                     config.QUARANTINE_DIR / "anything.quar",
                     config.CONFIG_PATH,
                     config.SCAN_CACHE_PATH):
            with self.subTest(path=path.name):
                self.assertTrue(protection.is_protected(path),
                                f"{path} is not protected")

    def test_unrelated_files_are_still_scannable(self):
        """Protection that covers everything protects nothing."""
        protection = SelfProtection([self.tmp / "data"])
        self.assertFalse(protection.is_protected(self.tmp / "elsewhere" / "x.exe"))


class TestGuardsSurviveTwoSpellings(TempCase):
    """Every guard that gates a decision on a path, checked through a link.

    The self-protection hole was one instance of a class: a path can have more
    than one true spelling, `resolve()` follows a Windows AppData redirection
    only for paths that already exist, and so a comparison between a root and a
    candidate can silently be comparing two different spellings of the same
    place. Whether a guard fires then depends on which files happen to have
    been written, which is not a basis for a safety check.

    A directory symlink reproduces the shape portably.
    """

    def _linked(self) -> tuple[Path, Path]:
        real = self.tmp / "real"
        real.mkdir()
        link = self.tmp / "link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a directory symlink here")
        return real, link

    def test_restore_refuses_the_quarantine_directory_by_either_name(self):
        """Restoring into quarantine must be refused however it is spelled."""
        real, link = self._linked()
        store = QuarantineStore(directory=real, index_path=real / "index.json",
                                protection=SelfProtection([self.tmp / "prot"]))
        record = store.quarantine(self.write("threat.bin", b"payload"), [])

        for spelling, label in ((real / "sneaky.exe", "the real path"),
                                (link / "sneaky.exe", "the linked path")):
            with self.subTest(spelling=label):
                with self.assertRaises(QuarantineError) as caught:
                    store.restore(record.entry_id, spelling)
                self.assertIn("quarantine directory", str(caught.exception))

    def test_protection_covers_a_directory_by_either_name(self):
        real, link = self._linked()
        (real / "inner").mkdir()
        target = real / "inner" / "file.txt"
        target.write_text("x")
        for root, label in ((real, "real"), (link, "link")):
            with self.subTest(root=label):
                protection = SelfProtection([root])
                self.assertTrue(protection.is_protected(target))
                self.assertTrue(protection.is_protected(link / "inner" / "file.txt"))

    def test_pack_attribution_works_by_either_name(self):
        from avguard.rulepacks import PackStore
        real, link = self._linked()
        store = PackStore(directory=real, index_path=real / "packs.json")
        rule = self.write("src/pack.yara",
                          b'rule R { meta: description = "d" strings: $a = "zzz" condition: $a }')
        from avguard.rulepacks import Admission
        admission = Admission(accepted=True, rule_count=1, corpus_size=1)
        pack = store.install("p", [rule], admission, licence="MIT")

        inside = store.pack_dir(pack.name) / "pack.yara"
        linked = link / pack.name / "pack.yara"
        self.assertEqual(store.owner_of(str(inside)), pack.name)
        self.assertEqual(store.owner_of(str(linked)), pack.name,
                         "attribution must not depend on how the path is spelled")

    def test_an_unrelated_path_is_still_outside(self):
        """A comparison that says yes to everything guards nothing."""
        real, _link = self._linked()
        self.assertFalse(SelfProtection([real]).is_protected(self.tmp / "elsewhere.txt"))


# --------------------------------------------- round two: measured, then fixed

class TestExtendedLengthPrefix(TempCase):
    """`\\\\?\\C:\\x` and `C:\\x` are the same file. Measured before the fix:
    is_protected(), path_within() and same_path() all said False for a
    protected file spelled with the prefix -- a guard that a prefix defeats."""

    def setUp(self) -> None:
        super().setUp()
        self.root = self.tmp / "prot"
        (self.root / "rules").mkdir(parents=True, exist_ok=True)
        self.target = self.root / "rules" / "x.yara"
        self.target.write_text("x", encoding="utf-8")
        self.prefixed = Path(chr(92) * 2 + "?" + chr(92) + str(self.target))

    @unittest.skipUnless(sys.platform == "win32", "a Windows spelling")
    def test_the_prefixed_spelling_is_still_ours(self):
        from avguard.protection import path_within, same_path
        prot = SelfProtection([self.root])
        self.assertTrue(prot.is_protected(self.prefixed))
        self.assertTrue(path_within(self.prefixed, self.root))
        self.assertTrue(same_path(self.prefixed, self.target))

    def test_a_sibling_that_merely_starts_with_our_name_is_outside(self):
        from avguard.protection import path_within
        prot = SelfProtection([self.root])
        sibling = self.tmp / "prot2" / "rules" / "x.yara"
        sibling.parent.mkdir(parents=True)
        sibling.write_text("x", encoding="utf-8")
        self.assertFalse(prot.is_protected(sibling))
        self.assertFalse(path_within(sibling, self.root))

    @unittest.skipUnless(sys.platform == "win32", "a Windows spelling")
    def test_the_unc_marker_is_not_case_sensitive(self):
        """Windows accepts unc, Unc and UNC alike: measured, all six prefixed
        spellings of a UNC share stat to the same inode. The lowercase form
        used to miss the UNC branch and come back as a RELATIVE path (the
        marker and the share as ordinary components), anchored at the cwd."""
        from avguard.protection import _strip_extended_prefix
        expected = Path(chr(92) * 2 + "srv" + chr(92) + "sh" + chr(92) + "f.txt")
        for prefix in (chr(92) * 2 + "?" + chr(92), chr(92) * 2 + "." + chr(92)):
            for marker in ("UNC", "unc", "Unc"):
                spelling = Path(prefix + marker + chr(92) + "srv" + chr(92) + "sh"
                                + chr(92) + "f.txt")
                with self.subTest(spelling=str(spelling)):
                    stripped = _strip_extended_prefix(spelling)
                    self.assertEqual(stripped, expected)
                    self.assertTrue(stripped.is_absolute())

    def test_a_volume_or_device_spelling_is_not_made_relative(self):
        from avguard.protection import _strip_extended_prefix
        for text in (chr(92) * 2 + "?" + chr(92) + "Volume{0a1b}" + chr(92) + "x" + chr(92) + "y",
                     chr(92) * 2 + "?" + chr(92) + "GLOBALROOT" + chr(92) + "Device" + chr(92) + "z",
                     chr(92) * 2 + "." + chr(92) + "PhysicalDrive0"):
            with self.subTest(text=text):
                self.assertEqual(_strip_extended_prefix(Path(text)), Path(text))

    @unittest.skipUnless(sys.platform == "win32", "needs the volume API")
    def test_a_volume_guid_spelling_of_our_file_is_ours(self):
        """A legal name for every local file that skipped the guard entirely."""
        import ctypes
        drive = str(self.target)[:3]
        buffer = ctypes.create_unicode_buffer(64)
        ok = ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(drive, buffer, 64)
        if not ok:
            self.skipTest("GetVolumeNameForVolumeMountPointW failed")
        guid_spelling = Path(buffer.value + str(self.target)[3:])
        self.assertTrue(guid_spelling.exists(), "the spelling should open our file")
        prot = SelfProtection([self.root])
        self.assertTrue(prot.is_protected(guid_spelling))
        # And with the cwd inside the root, an unrelated volume spelling is
        # not swept in: it used to become <cwd>\Volume{...}\... and match.
        previous = os.getcwd()
        os.chdir(self.root)
        try:
            other = Path(buffer.value + "Windows" + chr(92) + "explorer.exe")
            self.assertFalse(prot.is_protected(other))
        finally:
            os.chdir(previous)



class TestAnExceptionCanBeUndone(TempCase):
    """A restore is a permanent, machine-wide exception. Before this it could
    not be seen or removed, the cache generation did not know about it, and a
    second copy of restored bytes kept whatever verdict the cache held."""

    def setUp(self) -> None:
        super().setUp()
        from avguard.allowlist import Allowlist
        self.allowlist = Allowlist(path=self.tmp / "allow.json")
        self.scanner = Scanner(config.Config(cloud_enabled=False),
                               SelfProtection([self.tmp / "prot"]),
                               rules_path=RULES,
                               cache=ScanCache(path=self.tmp / "c.json"),
                               packs=_empty_packs(self.tmp),
                               allowlist=self.allowlist)

    def test_the_generation_knows_about_exceptions(self):
        from avguard.scanner import SELFTEST_MARKER
        before = self.scanner.detection_generation()
        digest = hashlib.sha256(SELFTEST_MARKER).hexdigest()
        self.allowlist.add(digest, "kept.bin", ["marker"])
        self.assertNotEqual(before, self.scanner.detection_generation())
        self.allowlist.remove(digest)
        self.assertEqual(before, self.scanner.detection_generation())

    def test_a_second_copy_follows_the_decision_both_ways(self):
        from avguard.scanner import Level, SELFTEST_MARKER
        elsewhere = self.write("elsewhere.bin", SELFTEST_MARKER)
        self.assertIs(self.scanner.scan(elsewhere).level, Level.MALICIOUS)

        digest = hashlib.sha256(SELFTEST_MARKER).hexdigest()
        self.allowlist.add(digest, "kept.bin", ["marker"])
        # Round two needed a re-key here; round three made a cache hit defer
        # to the allowlist by digest, so the copy follows the decision at once.
        verdict = self.scanner.scan(elsewhere)
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertIn("you chose to keep", verdict.reasons[0])

        # And undone: the copy is judged on its bytes again.
        self.assertTrue(self.allowlist.remove(digest))
        self.assertIs(self.scanner.scan(elsewhere).level, Level.MALICIOUS)


class TestADecisionFromAnotherProcessIsSeen(TempCase):
    """`avguard --restore` in a terminal while the GUI is running. Measured
    before this: the running scanner kept saying MALICIOUS with the cache on,
    with it off, and for a fresh copy of the bytes -- and with automatic
    quarantine on it would have taken the restored file straight back."""

    def setUp(self) -> None:
        super().setUp()
        from unittest import mock
        from avguard.allowlist import Allowlist
        # The lookup throttles its stat; these tests act within a millisecond.
        patcher = mock.patch.object(Allowlist, "CHECK_INTERVAL", 0.0)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.allow_path = self.tmp / "allow.json"
        self.scanner = Scanner(config.Config(cloud_enabled=False),
                               SelfProtection([self.tmp / "prot"]),
                               rules_path=RULES,
                               cache=ScanCache(path=self.tmp / "c.json"),
                               packs=_empty_packs(self.tmp),
                               allowlist=Allowlist(path=self.allow_path))

    def _other_process(self):
        """A second Allowlist on the same file, standing in for the CLI."""
        from avguard.allowlist import Allowlist
        return Allowlist(path=self.allow_path)

    def test_a_restore_recorded_elsewhere_is_honoured_without_a_reload(self):
        from avguard.scanner import Level, SELFTEST_MARKER
        target = self.write("restored.bin", SELFTEST_MARKER)
        self.assertIs(self.scanner.scan(target).level, Level.MALICIOUS)  # now cached

        digest = hashlib.sha256(SELFTEST_MARKER).hexdigest()
        self._other_process().add(digest, "restored.bin", ["marker"])

        verdict = self.scanner.scan(target)  # cache on; nobody called reload
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertIn("you chose to keep", verdict.reasons[0])
        copy = self.write("copy.bin", SELFTEST_MARKER)
        self.assertIs(self.scanner.scan(copy).level, Level.CLEAN)

    def test_an_exception_withdrawn_elsewhere_is_honoured_too(self):
        from avguard.scanner import Level, SELFTEST_MARKER
        target = self.write("restored.bin", SELFTEST_MARKER)
        digest = hashlib.sha256(SELFTEST_MARKER).hexdigest()
        other = self._other_process()
        other.add(digest, "restored.bin", ["marker"])
        self.assertIs(self.scanner.scan(target).level, Level.CLEAN)  # cached, by exception

        self.assertTrue(other.remove(digest))
        self.assertIs(self.scanner.scan(target).level, Level.MALICIOUS)



class TestAPackDecisionFromAnotherProcessIsSeen(TempCase):
    """`--packs verify` in a terminal disarms a failing pack by writing
    trusted=false. A running GUI held its own PackStore in memory and kept
    condemning -- the failure round three fixed for the allowlist, one
    store over."""

    NEEDLE = "TRIPWIRE-" + "c0ffee11"

    def setUp(self) -> None:
        super().setUp()
        from unittest import mock
        from avguard import scanner as scanner_module
        from avguard.allowlist import Allowlist
        from avguard.rulepacks import Admission, PackStore
        self.store = PackStore(directory=self.tmp / "packs",
                               index_path=self.tmp / "packs" / "packs.json")
        rule = self.tmp / "pack.yara"
        rule.write_text("rule Stranger { meta: description = \"d\" severity = \"critical\" "
                        f"strings: $a = \"{self.NEEDLE}\" condition: $a }}", encoding="utf-8")
        self.store.install("stranger", [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1), licence="MIT")
        self.store.set_trusted("stranger", True)
        patcher = mock.patch.object(scanner_module, "PACKS_CHECK_INTERVAL", 0.0)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.scanner = Scanner(config.Config(cloud_enabled=False),
                               SelfProtection([self.tmp / "prot"]),
                               rules_path=RULES,
                               cache=ScanCache(path=self.tmp / "c.json"),
                               packs=self.store,
                               allowlist=Allowlist(path=self.tmp / "allow.json"))
        self.sample = self.write("sample.bin", self.NEEDLE.encode() + b" " * 32)

    def _other_process(self):
        from avguard.rulepacks import PackStore
        return PackStore(directory=self.store.directory, index_path=self.store.index_path)

    def test_a_disarm_written_elsewhere_stops_the_running_scanner_condemning(self):
        from avguard.scanner import Level
        self.assertIs(self.scanner.scan(self.sample).level, Level.MALICIOUS)
        self._other_process().set_trusted("stranger", False)
        verdict = self.scanner.scan(self.sample)      # cache on, nobody reloaded
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertFalse(verdict.is_threat)
        self._other_process().set_trusted("stranger", True)
        self.assertIs(self.scanner.scan(self.sample).level, Level.MALICIOUS)

    def test_a_pack_removed_elsewhere_does_not_go_on_running_uncapped(self):
        from avguard.scanner import Level
        self.assertIs(self.scanner.scan(self.sample).level, Level.MALICIOUS)
        self._other_process().remove("stranger")
        self.assertIs(self.scanner.scan(self.sample).level, Level.CLEAN,
                      "the removed pack's rules were still loaded")
        self.assertNotIn("stranger", self.scanner.pack_rule_counts)

    def test_a_pack_whose_directory_vanished_stays_capped_through_an_index_rewrite(self):
        """Measured on 9e2e271: a reports-only pack, its directory deleted,
        any other process rewriting the index -- MALICIOUS, hard. The cap
        set was rebuilt from the disk while the rules stayed loaded."""
        import shutil
        from avguard.scanner import Level
        self._other_process().set_trusted("stranger", False)
        self.assertIs(self.scanner.scan(self.sample, use_cache=False).level, Level.SUSPICIOUS)
        shutil.rmtree(self.store.pack_dir("stranger"))
        self._other_process().set_trusted("stranger", False)   # any rewrite at all
        verdict = self.scanner.scan(self.sample, use_cache=False)
        self.assertFalse(verdict.is_threat, "a reports-only pack moved a file")
        self.assertFalse(any(f.hard for f in verdict.findings))

    def test_a_pack_replaced_under_the_same_name_runs_the_new_rules_capped(self):
        """Measured on 9e2e271: remove and re-add under one name and the OLD
        rules kept running, uncapped, with the cache re-keyed to the new
        generation. Names compared equal; the pack state did not."""
        from avguard.scanner import Level
        from avguard.rulepacks import Admission
        other = self._other_process()
        other.set_trusted("stranger", False)
        self.assertIs(self.scanner.scan(self.sample, use_cache=False).level, Level.SUSPICIOUS)
        other.remove("stranger")
        replacement = self.tmp / "replacement.yara"
        replacement.write_text("rule Replacement { meta: description = \"d\" "
                               "severity = \"critical\" strings: $a = \""
                               + self.NEEDLE + "\" condition: $a }", encoding="utf-8")
        other.install("stranger", [replacement],
                      Admission(accepted=True, rule_count=1, corpus_size=1), licence="MIT")
        verdict = self.scanner.scan(self.sample, use_cache=False)
        self.assertEqual([f.name for f in verdict.findings if f.source == "yara"],
                         ["Replacement"], "the old rules were still running")
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertFalse(verdict.is_threat)

    def test_a_scan_in_flight_keeps_the_ruleset_it_started_with(self):
        """A match started on the old ruleset must be scored against the old
        cap set, whatever another worker swaps in meanwhile."""
        import dataclasses
        import threading
        from avguard.scanner import Level
        self._other_process().set_trusted("stranger", False)
        self.scanner.scan(self.sample, use_cache=False)          # loaded, capped
        started, gate = threading.Event(), threading.Event()
        inner = self.scanner._ruleset.rules

        class Held:
            def match(self, *args, **kwargs):
                result = inner.match(*args, **kwargs)
                started.set()
                gate.wait(timeout=10)
                return result

        self.scanner._ruleset = dataclasses.replace(self.scanner._ruleset, rules=Held())
        verdicts: list = []
        worker = threading.Thread(target=lambda: verdicts.append(
            self.scanner.scan(self.sample, use_cache=False)))
        worker.start()
        self.assertTrue(started.wait(timeout=10))
        self._other_process().remove("stranger")                 # gone from the index
        self.scanner._sync_packs(force=True)                     # reloads: rules gone
        gate.set()
        worker.join(timeout=10)
        self.assertEqual(len(verdicts), 1)
        self.assertIs(verdicts[0].level, Level.SUSPICIOUS,
                      "scored against a cap set from a different ruleset")
        self.assertFalse(verdicts[0].is_threat)


class TestAllowlistFilesAndSaves(TempCase):
    def test_a_non_utf8_file_is_an_empty_list(self):
        """UnicodeDecodeError is a ValueError, not a JSONDecodeError."""
        from avguard.allowlist import Allowlist
        path = self.tmp / "allow.json"
        path.write_bytes(b'{"\xff\xfe": {}}')
        self.assertEqual(len(Allowlist(path=path)), 0)

    def test_a_failed_save_leaves_no_phantom_decision(self):
        """add() used to log a warning, re-sync the stamp to the file it had
        not replaced, and serve the entry from memory until the next reload."""
        from unittest import mock
        from avguard import allowlist as allowlist_module
        from avguard.allowlist import Allowlist
        allow = Allowlist(path=self.tmp / "allow.json")
        with mock.patch.object(allowlist_module.config, "atomic_write_text",
                               side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                allow.add("a" * 64, "thing.bin", ["reason"])
        self.assertIsNone(allow.allows("a" * 64), "a decision that is not on disk was not made")
        self.assertEqual(allow.entries(), [])

    def test_a_restore_whose_decision_was_not_recorded_says_so(self):
        from unittest import mock
        from avguard.allowlist import Allowlist
        from avguard.quarantine import QuarantineError, QuarantineStore
        from avguard.scanner import SELFTEST_MARKER
        allow = Allowlist(path=self.tmp / "allow.json")
        store = QuarantineStore(directory=self.tmp / "store",
                                index_path=self.tmp / "store" / "index.json",
                                protection=SelfProtection([self.tmp / "prot"]),
                                allowlist=allow)
        target = self.write("kept.bin", SELFTEST_MARKER)
        record = store.quarantine(target, ["marker"])
        from avguard.quarantine import RestoreIncomplete
        with mock.patch.object(Allowlist, "_save", return_value=False):
            with self.assertRaises(RestoreIncomplete) as caught:
                store.restore(record.entry_id)
        self.assertIn("not recorded", str(caught.exception))
        # Not assertEqual: on the CI runner %TEMP% is spelled RUNNER~1 and
        # restore() answers with the long form. Same file, two spellings.
        from avguard.protection import same_path
        self.assertTrue(same_path(caught.exception.target, target),
                        f"{caught.exception.target} is not {target}")
        self.assertTrue(target.exists(), "the file itself must still be back")
        # Not a failed restore: the CLI says restored, warns, and exits 0.
        self.assertTrue(issubclass(RestoreIncomplete, RuntimeError))
        self.assertFalse(issubclass(RestoreIncomplete, QuarantineError))

    def test_the_stat_is_throttled(self):
        """Measured before: one stat per lookup, under the lock, 125 us of a
        739 us cache hit, serialised across the worker threads."""
        from unittest import mock
        from avguard.allowlist import Allowlist
        allow = Allowlist(path=self.tmp / "allow.json")
        real = allow._disk_stamp
        with mock.patch.object(allow, "_disk_stamp", wraps=real) as stamp:
            for _ in range(200):
                allow.allows("b" * 64)
        self.assertLessEqual(stamp.call_count, 2, "a stat on every lookup")


class TestTheWindowsQuarantineActions(TempCase):
    """Round six, the window's side: a second window could restore and
    delete while its Health row said it could not move files; restores and
    deletes reached neither History nor the forwarder though the README
    said a restore is POSTed; Export everything called damaged payloads
    "the original, unmodified files"; and the retention review the README
    described did not exist."""

    def setUp(self) -> None:
        super().setUp()
        try:
            from avguard import gui
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        from types import SimpleNamespace
        from avguard.allowlist import Allowlist
        from avguard.events import EventStore
        self.gui = gui
        directory = self.tmp / "store"
        self.store = QuarantineStore(directory=directory, index_path=directory / "index.json",
                                     protection=SelfProtection([self.tmp / "prot"]),
                                     allowlist=Allowlist(path=self.tmp / "allow.json"))
        self.events = EventStore(self.tmp / "events.jsonl")
        self.banners = []
        fake = SimpleNamespace(quarantine=self.store, events=self.events, has_lock=True,
                               lock=SimpleNamespace(owner_pid=4242), cfg=config.Config(),
                               _refresh_quarantine=lambda: None, _allowlist_changed=lambda: None,
                               _banner=lambda text, style="": self.banners.append((text, style)),
                               _banner_is_loud=lambda: False)
        for name in ("_without_the_lock", "_record_restore", "_held_for_review",
                     "_describe_quarantine_review"):
            setattr(fake, name, getattr(gui.AVGuardApp, name).__get__(fake))
        self.fake = fake

    def held(self, name: str, data: bytes):
        path = self.tmp / name
        path.write_bytes(data)
        return self.store.quarantine(path, ["a reason"])

    def test_a_window_without_the_lock_cannot_restore_or_delete(self):
        record = self.held("a.docx", b"a")
        self.fake.has_lock = False
        self.fake._selected_id = lambda: record.entry_id
        with mock.patch.object(self.gui, "Messagebox") as box:
            self.gui.AVGuardApp._restore_entry(self.fake, record.entry_id)
            self.gui.AVGuardApp._delete_selected(self.fake)
        self.assertEqual(box.show_info.call_count, 2)
        self.assertIn("pid 4242", box.show_info.call_args.args[0])
        box.yesno.assert_not_called()
        self.assertIsNotNone(self.store.get(record.entry_id), "a second window changed the store")
        self.assertFalse((self.tmp / "a.docx").exists())

    def test_a_restore_and_a_delete_reach_history_with_what_the_consent_names(self):
        kept, gone = self.held("kept.docx", b"kept"), self.held("gone.exe", b"gone")
        self.fake._selected_id = lambda: gone.entry_id
        with mock.patch.object(self.gui.Messagebox, "yesno", return_value="Yes"):
            self.gui.AVGuardApp._restore_entry(self.fake, kept.entry_id)
            self.gui.AVGuardApp._delete_selected(self.fake)
        restored, deleted = self.events.read(kinds={"restored"}), self.events.read(kinds={"deleted"})
        # The record's path, resolved when the file was taken (on the runner
        # TEMP is spelled RUNNER~1 and resolves to runneradmin).
        self.assertEqual([e.path for e in restored], [kept.original_path])
        self.assertEqual([e.path for e in deleted], [gone.original_path])
        self.assertEqual(restored[0].detail, {"sha256": kept.sha256, "from": "quarantine"})
        self.assertNotIn("entry_id", deleted[0].detail, "the consent does not name the store's ids")

    def test_export_everything_says_what_it_could_not_write(self):
        self.held("fine.pdf", b"fine")
        bad = self.held("contract.pdf", b"contract " * 50)
        payload = self.store._payload_path(bad.entry_id)
        payload.write_bytes(payload.read_bytes()[:10])
        with mock.patch.object(self.gui.filedialog, "askdirectory", return_value=str(self.tmp / "out")), \
                mock.patch.object(self.gui, "Messagebox") as box:
            self.gui.AVGuardApp._export_all(self.fake)
        box.show_info.assert_not_called()
        text = box.show_warning.call_args.args[0]
        self.assertIn("Wrote 1 of 2 file(s)", text)
        self.assertIn("contract.pdf: integrity check failed", text)

    def test_the_review_is_offered_and_nothing_is_deleted(self):
        record = self.held("old.exe", b"old")
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(timespec="seconds")
        self.store._records[record.entry_id].quarantined_at = old
        self.store._save()
        self.held("new.exe", b"new")
        self.assertIn("1 file(s) held longer than 90 days", self.fake._describe_quarantine_review())
        self.gui.AVGuardApp._offer_quarantine_review(self.fake)
        self.assertEqual(len(self.banners), 1)
        self.assertEqual(len(self.store), 2, "nothing is deleted for its age")
        self.fake.cfg.quarantine_review_days = 0
        self.assertIn("off", self.fake._describe_quarantine_review())


class TestASettingsFileThatCannotBeReadIsKept(TempCase):
    """Round six: allowlist.json, packs.json and config.json read a file
    they could not parse as empty, and the next save wrote over it. A
    byte-order mark (Notepad's old "UTF-8", PowerShell 5.1's Set-Content
    -Encoding UTF8) was enough: three kept decisions became one."""

    BOM = b"\xef\xbb\xbf"

    def test_a_byte_order_mark_is_read(self):
        from avguard.allowlist import Allowlist
        path = self.tmp / "allow.json"
        first = Allowlist(path=path)
        for digest in ("a" * 64, "b" * 64, "c" * 64):
            first.add(digest, f"{digest[0]}.exe")
        path.write_bytes(self.BOM + path.read_bytes())
        second = Allowlist(path=path)
        self.assertEqual(len(second), 3, "a BOM read as an empty allowlist")
        second.add("d" * 64, "next-restore.exe")
        self.assertEqual(len(json.loads(path.read_text(encoding="utf-8-sig"))), 4)

        settings = self.tmp / "config.json"
        settings.write_bytes(self.BOM + json.dumps({"auto_quarantine": True, "worker_threads": 3}).encode())
        loaded = config.Config.load(settings)
        self.assertEqual((loaded.auto_quarantine, loaded.worker_threads), (True, 3))

    def test_what_cannot_be_read_is_set_aside_before_a_save(self):
        from avguard.allowlist import Allowlist
        damage = b'{"\xe0\xb9": {"sha256": "x"}}'
        for name, write in (
                ("allowlist", lambda p: Allowlist(path=p).add("d" * 64, "next.exe")),
                ("config", lambda p: config.Config.load(p).save(p)),
                ("packs", lambda p: PackStore(directory=self.tmp / "packs", index_path=p)._save())):
            for label, bad in (("not utf-8", damage), ("an array", b"[1, 2]"), ("not json", b"{nope")):
                with self.subTest(file=name, damage=label):
                    path = self.tmp / name / f"{label.replace(' ', '-')}.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(bad)
                    write(path)                                  # no crash, and then:
                    kept = list(path.parent.glob(path.name + ".unreadable-*"))
                    self.assertEqual([p.read_bytes() for p in kept], [bad], "written over")
                    self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)

    def test_a_config_that_is_not_an_object_does_not_stop_the_program(self):
        settings = self.tmp / "config.json"
        settings.write_text("[]", encoding="utf-8")
        self.assertEqual(config.Config.load(settings), config.Config())


class TestLoopbackShares(unittest.TestCase):
    """The administrative share is a spelling of every local file."""

    def test_local_admin_share_maps_to_the_drive(self):
        from avguard.protection import _canonical_spelling
        bs = chr(92)
        for host in ("localhost", "127.0.0.1", "LOCALHOST"):
            spelling = Path(bs * 2 + host + bs + "C$" + bs + "Users" + bs + "x.txt")
            with self.subTest(host=host):
                self.assertEqual(_canonical_spelling(spelling),
                                 Path("C:" + bs + "Users" + bs + "x.txt"))
        prefixed = Path(bs * 2 + "?" + bs + "UNC" + bs + "localhost" + bs + "D$" + bs + "f")
        self.assertEqual(_canonical_spelling(prefixed), Path("D:" + bs + "f"))

    def test_a_real_share_is_left_alone(self):
        from avguard.protection import _canonical_spelling
        bs = chr(92)
        for text in (bs * 2 + "fileserver" + bs + "C$" + bs + "x",
                     bs * 2 + "localhost" + bs + "public" + bs + "x",
                     bs * 2 + "localhost" + bs + "CC$" + bs + "x"):
            with self.subTest(text=text):
                self.assertEqual(_canonical_spelling(Path(text)), Path(text))


if __name__ == "__main__":
    unittest.main(verbosity=2)
