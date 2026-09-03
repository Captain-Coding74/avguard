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

_os.environ.setdefault(
    "AVGUARD_DATA",
    _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}"))



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


if __name__ == "__main__":
    unittest.main(verbosity=2)
