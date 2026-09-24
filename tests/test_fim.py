"""File integrity monitoring: what changed, what was hidden, what was tampered with.

The acceptance list from docs/improvements.md, as tests: flip one byte, add
one file, delete one, and the report names exactly those three with the right
hashes; a modified file with its mtime restored is caught by the default check
and missed by --fast, both asserted; one byte of the baseline changed out of
band produces the tamper event on the next check.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import logging
import os
import queue
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolate the data directory BEFORE avguard is imported.
import os as _os
import tempfile as _tempfile

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)


def _remove_tree(path) -> None:
    """rmtree that copes with read-only files."""
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
    import atexit as _atexit
    _atexit.register(_remove_tree, _test_data)


from avguard import config, fim
from avguard.events import EventStore
from avguard.fim import FimStore

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stub_protect(data: bytes) -> bytes:
    """Reversible, so the HMAC logic runs on every platform. The real DPAPI
    path is exercised on Windows in TestTheKeyIsProtected."""
    return b"STUB:" + data[::-1]


def stub_unprotect(blob: bytes) -> bytes:
    if not blob.startswith(b"STUB:"):
        raise OSError("not a protected blob")   # what DPAPI does with garbage
    return blob[5:][::-1]


class FimCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-fim-"))
        self.addCleanup(_remove_tree, self.tmp)
        self.tree = self.tmp / "site"
        (self.tree / "sub").mkdir(parents=True)
        for index in range(6):
            (self.tree / f"f{index}.txt").write_bytes(b"content %d " % index * 50)
        (self.tree / "sub" / "deep.cfg").write_bytes(b"deep" * 100)
        self.store = FimStore(directory=self.tmp / "fim",
                              key_protect=stub_protect, key_unprotect=stub_unprotect)
        self.events = EventStore(path=self.tmp / "events.jsonl")

    def baseline(self) -> None:
        report = self.store.baseline([self.tree])
        self.assertEqual(report.errors, [])
        self.assertEqual(report.files, 7)


# ---------------------------------------------------------------- acceptance

class TestTheThreeKindsOfChange(FimCase):
    def test_a_clean_tree_reports_nothing(self):
        self.baseline()
        report = self.store.check(events=self.events)
        self.assertTrue(report.clean, [c.describe() for c in report.changes])
        self.assertEqual(report.examined, 7)
        self.assertEqual(self.events.read(kinds={"fim"}), [])

    def test_modified_added_and_removed_are_named_with_their_hashes(self):
        self.baseline()
        modified = self.tree / "f3.txt"
        old_sha = sha256_of(modified)
        modified.write_bytes(modified.read_bytes()[:-1] + b"!")   # one byte, same size
        added = self.tree / "sub" / "new.txt"
        added.write_bytes(b"brand new")
        removed = self.tree / "f5.txt"
        removed_sha = sha256_of(removed)
        removed.unlink()

        report = self.store.check(events=self.events)
        self.assertEqual({c.path for c in report.changes},
                         {str(modified), str(added), str(removed)})
        change = report.modified[0]
        self.assertEqual((change.old_sha256, change.new_sha256), (old_sha, sha256_of(modified)))
        self.assertEqual(report.added[0].new_sha256, sha256_of(added))
        self.assertEqual(report.removed[0].old_sha256, removed_sha)
        self.assertEqual(report.integrity, fim.INTEGRITY_OK)

        recorded = self.events.read(kinds={"fim"})
        self.assertEqual(sorted(e.level for e in recorded), ["added", "modified", "removed"])
        self.assertTrue(all(e.detail.get("old_sha256") is not None for e in recorded))

    def test_a_check_never_moves_anything(self):
        """Changed is not malicious. Ground rule 4."""
        self.baseline()
        (self.tree / "f0.txt").write_bytes(b"replaced entirely")
        self.store.check(events=self.events)
        self.assertTrue((self.tree / "f0.txt").exists())
        self.assertEqual((self.tree / "f0.txt").read_bytes(), b"replaced entirely")
        self.assertFalse(list((self.tmp / "fim").glob("*.quarantine")))


class TestTimestompingIsHandledHonestly(FimCase):
    def test_a_restored_mtime_fools_fast_and_not_the_default(self):
        self.baseline()
        target = self.tree / "f2.txt"
        before = target.stat()
        target.write_bytes(target.read_bytes()[:-1] + b"?")      # same size
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(target.stat().st_mtime_ns, before.st_mtime_ns, "the stomp did not take")

        default = self.store.check()
        self.assertEqual([c.path for c in default.modified], [str(target)],
                         "the default check must hash everything")
        fast = self.store.check(fast=True)
        self.assertEqual(fast.changes, [], "--fast trusts size and mtime; that is its trade")
        self.assertTrue(fast.fast)
        self.assertLess(fast.hashed, default.hashed)


class TestTheBaselineIsATarget(FimCase):
    def test_one_byte_changed_out_of_band_is_reported_as_tampering(self):
        self.baseline()
        self.assertEqual(self.store.verify_integrity(), fim.INTEGRITY_OK)
        data = bytearray(self.store.db_path.read_bytes())
        data[-1] ^= 0xFF
        self.store.db_path.write_bytes(bytes(data))
        report = self.store.check(events=self.events)
        self.assertEqual(report.integrity, fim.INTEGRITY_TAMPERED)
        tamper = [e for e in self.events.read(kinds={"fim"}) if e.level == "tampered"]
        self.assertEqual(len(tamper), 1)
        self.assertIn("outside AVGuard", tamper[0].reasons[0])

    def test_a_missing_signature_is_reported_not_ignored(self):
        self.baseline()
        self.store.signature_path.unlink()
        self.assertEqual(self.store.check().integrity, fim.INTEGRITY_UNSIGNED)

    def test_an_unreadable_key_is_reported_not_ignored(self):
        self.baseline()
        self.store.key_path.write_bytes(b"not a protected key")
        self.assertEqual(self.store.check().integrity, fim.INTEGRITY_KEY_UNREADABLE)

    def test_every_legitimate_write_re_signs(self):
        self.baseline()
        first = self.store.signature_path.read_text(encoding="utf-8")
        (self.tree / "f1.txt").write_bytes(b"changed")
        self.store.accept([self.tree / "f1.txt"])
        self.assertNotEqual(first, self.store.signature_path.read_text(encoding="utf-8"))
        self.assertEqual(self.store.verify_integrity(), fim.INTEGRITY_OK)


@unittest.skipUnless(sys.platform == "win32", "DPAPI is a Windows API")
class TestTheKeyIsProtected(unittest.TestCase):
    def test_the_real_dpapi_round_trip(self):
        key = os.urandom(32)
        blob = fim.protect(key)
        self.assertNotIn(key, blob, "the key is visible in the protected blob")
        self.assertGreater(len(blob), len(key))
        self.assertEqual(fim.unprotect(blob), key)

    def test_garbage_does_not_unprotect(self):
        with self.assertRaises(OSError):
            fim.unprotect(b"\x01\x02\x03 nonsense")


# ------------------------------------------------------------- exclusions

class TestExclusionsAreHonoured(FimCase):
    def test_excluded_paths_are_neither_baselined_nor_reported(self):
        store = FimStore(directory=self.tmp / "fim2",
                         excluded_globs=[str(self.tree / "sub").replace("\\", "/") + "/**"],
                         key_protect=stub_protect, key_unprotect=stub_unprotect)
        report = store.baseline([self.tree])
        self.assertEqual(report.files, 6, "sub/ should have been skipped")
        (self.tree / "sub" / "planted.txt").write_bytes(b"planted")
        self.assertEqual(store.check().changes, [])

    def test_removed_does_not_fire_for_a_path_excluded_since(self):
        self.baseline()
        self.store.excluded_globs = [str(self.tree / "sub").replace("\\", "/") + "/**"]
        (self.tree / "sub" / "deep.cfg").unlink()
        report = self.store.check()
        self.assertEqual(report.changes, [])

    def test_the_data_directory_is_never_monitored(self):
        """It changes constantly -- logs, caches, this baseline."""
        inside = config.DATA_DIR / "fim-probe"
        inside.mkdir(parents=True, exist_ok=True)
        self.addCleanup(_remove_tree, inside)
        (inside / "x.bin").write_bytes(b"x")
        report = self.store.baseline([inside])
        self.assertEqual(report.files, 0)


# ----------------------------------------------------------- the baseline

class TestBaselineUpkeep(FimCase):
    def test_a_second_baseline_replaces_rows_without_duplicating(self):
        self.baseline()
        (self.tree / "f4.txt").unlink()
        (self.tree / "extra.txt").write_bytes(b"extra")
        report = self.store.baseline([self.tree])
        self.assertEqual(report.files, 7)
        self.assertEqual(self.store.file_count(), 7)
        self.assertEqual(self.store.roots(), [str(self.tree)])
        self.assertEqual(self.store.check().changes, [])

    def test_accept_stops_the_alert_and_only_that_alert(self):
        self.baseline()
        (self.tree / "f1.txt").write_bytes(b"edited on purpose")
        (self.tree / "f2.txt").write_bytes(b"edited by somebody else")
        self.assertEqual(len(self.store.check().modified), 2)
        notes = self.store.accept([self.tree / "f1.txt"])
        self.assertTrue(notes[0].startswith("accepted"))
        report = self.store.check()
        self.assertEqual([c.path for c in report.modified], [str(self.tree / "f2.txt")])

    def test_accept_of_a_removed_path_drops_it(self):
        self.baseline()
        (self.tree / "f0.txt").unlink()
        self.assertEqual(len(self.store.check().removed), 1)
        self.store.accept([self.tree / "f0.txt"])
        self.assertEqual(self.store.check().changes, [])
        self.assertEqual(self.store.file_count(), 6)

    def test_no_baseline_is_said_plainly(self):
        report = self.store.check()
        self.assertEqual(report.integrity, fim.INTEGRITY_NO_BASELINE)
        self.assertFalse(self.store.exists())

    def test_reparse_points_are_not_followed(self):
        link = self.tree / "elsewhere"
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_bytes(b"not yours to hash")
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a symlink here")
        report = self.store.baseline([self.tree])
        self.assertEqual(report.files, 7, "the link was followed")


# ------------------------------------------------------------------- CLI

class TestTheCommandLine(FimCase):
    def _cli(self, *args: str) -> tuple[int, str]:
        import avguard.__main__ as cli
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(fim, "FIM_DIR", self.tmp / "cli-fim"), \
                mock.patch.object(fim, "protect", stub_protect), \
                mock.patch.object(fim, "unprotect", stub_unprotect), \
                mock.patch.object(FimStore.__init__, "__defaults__",
                                  (self.tmp / "cli-fim", (), stub_protect, stub_unprotect)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue() + err.getvalue()

    def test_baseline_check_accept_round_trip(self):
        code, output = self._cli("--fim-baseline", str(self.tree))
        self.assertEqual(code, 0, output)
        self.assertIn("7 file(s)", output)

        code, output = self._cli("--fim-check")
        self.assertEqual(code, 0, output)
        self.assertIn("no changes", output.lower())

        (self.tree / "f3.txt").write_bytes(b"edited")
        code, output = self._cli("--fim-check")
        self.assertEqual(code, 1, "changes found must be visible in the exit code")
        self.assertIn("MODIFIED", output)
        self.assertIn("f3.txt", output)
        self.assertNotIn("quarantine", output.lower())

        code, output = self._cli("--fim-accept", str(self.tree / "f3.txt"))
        self.assertEqual(code, 0, output)
        code, output = self._cli("--fim-check")
        self.assertEqual(code, 0, output)

    def test_fast_says_what_it_trades_away(self):
        import avguard.__main__ as cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--help"])
        self.assertIn("mtime", out.getvalue())

    def test_status_before_and_after(self):
        code, output = self._cli("--fim-status")
        self.assertEqual(code, 0)
        self.assertIn("no baseline", output.lower())
        self._cli("--fim-baseline", str(self.tree))
        code, output = self._cli("--fim-status")
        self.assertIn("7 file(s)", output)
        self.assertIn(str(self.tree), output)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ------------------------------------------------------- front-end hooks

class TestTheHooksAFrontEndNeeds(FimCase):
    """The Integrity tab runs baseline() and check() on a worker thread with a
    progress bar and a Cancel button. Both hooks are optional; the CLI passes
    neither, so every test above this class exercises the no-hook path."""

    def test_progress_counts_every_file_and_knows_the_total_from_the_first_call(self):
        calls: list[tuple[int, int]] = []
        self.store.baseline([self.tree], progress=lambda d, t: calls.append((d, t)))
        self.assertEqual(calls, [(i, 7) for i in range(1, 8)])
        (self.tree / "new.txt").write_bytes(b"new")
        calls.clear()
        report = self.store.check(progress=lambda d, t: calls.append((d, t)))
        self.assertEqual(calls, [(i, 8) for i in range(1, 9)],
                         "seven baselined files plus one new one, the total known up front")
        self.assertEqual([c.kind for c in report.changes], ["added"])

    def test_a_cancelled_first_baseline_writes_nothing(self):
        seen: list[int] = []
        report = self.store.baseline([self.tree], progress=lambda d, t: seen.append(d),
                                     should_stop=lambda: len(seen) >= 3)
        self.assertTrue(report.cancelled)
        self.assertEqual(seen, [1, 2, 3], "the stop is polled before each file")
        self.assertEqual(report.files, 0)
        self.assertFalse(self.store.exists())
        self.assertFalse(self.store.signature_path.exists())

    def test_a_cancelled_re_baseline_leaves_the_old_one_intact(self):
        self.baseline()
        before = self.store.db_path.read_bytes()
        signature = self.store.signature_path.read_text(encoding="utf-8")
        (self.tree / "f0.txt").write_bytes(b"changed")
        report = self.store.baseline([self.tree], should_stop=lambda: True)
        self.assertTrue(report.cancelled)
        self.assertEqual(self.store.db_path.read_bytes(), before)
        self.assertEqual(self.store.signature_path.read_text(encoding="utf-8"), signature)
        self.assertEqual(self.store.verify_integrity(), fim.INTEGRITY_OK)
        self.assertEqual([c.kind for c in self.store.check().changes], ["modified"],
                         "the old baseline still sees the change")

    def test_a_cancelled_check_records_nothing_and_is_not_clean(self):
        self.baseline()
        (self.tree / "f0.txt").write_bytes(b"changed")      # f0 is examined first
        seen: list[int] = []
        report = self.store.check(events=self.events, progress=lambda d, t: seen.append(d),
                                  should_stop=lambda: len(seen) >= 2)
        self.assertTrue(report.cancelled)
        self.assertFalse(report.clean)
        self.assertEqual([c.path for c in report.changes], [str(self.tree / "f0.txt")],
                         "what was found before the stop is reported, marked cancelled")
        self.assertEqual(self.events.read(kinds={"fim"}), [], "and none of it is recorded")
        self.store.check(events=self.events)
        self.assertEqual(len(self.events.read(kinds={"fim"})), 1, "a full check records it")

    def test_the_hooks_do_not_change_what_a_check_finds(self):
        self.baseline()
        modified = self.tree / "f3.txt"
        modified.write_bytes(modified.read_bytes()[:-1] + b"!")
        (self.tree / "sub" / "new.txt").write_bytes(b"brand new")
        (self.tree / "f5.txt").unlink()
        plain = self.store.check()
        hooked = self.store.check(progress=lambda d, t: None, should_stop=lambda: False)
        self.assertEqual([(c.kind, c.path, c.old_sha256, c.new_sha256) for c in plain.changes],
                         [(c.kind, c.path, c.old_sha256, c.new_sha256) for c in hooked.changes])
        self.assertEqual((plain.examined, plain.hashed), (hooked.examined, hooked.hashed))


class TestWhatTheTabSays(FimCase):
    """The panel's text is built by functions with no widgets in them, so
    the words are checked here, where tkinter need not be installed."""

    def _panel_module(self):
        try:
            from avguard import fimpanel
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        return fimpanel

    def test_the_summary_before_and_after_a_baseline_and_when_tampered(self):
        fimpanel = self._panel_module()
        ok, text = fimpanel.summarize(self.store)
        self.assertTrue(ok)
        self.assertIn("No baseline yet", text)
        self.baseline()
        ok, text = fimpanel.summarize(self.store)
        self.assertTrue(ok)
        self.assertIn("7 file(s) baselined", text)
        self.assertIn(str(self.tree), text)
        self.assertIn("Signature holds", text)
        data = bytearray(self.store.db_path.read_bytes())
        data[-1] ^= 0xFF
        self.store.db_path.write_bytes(bytes(data))
        ok, text = fimpanel.summarize(self.store)
        self.assertFalse(ok)
        self.assertIn("SIGNATURE TAMPERED", text)
        self.assertIn("outside AVGuard", text)

    def test_a_row_names_the_change_and_both_hashes(self):
        fimpanel = self._panel_module()
        change = fim.Change("modified", "C:/site/index.html", old_sha256="a" * 64,
                            new_sha256="b" * 64, old_size=1000, new_size=1200)
        self.assertEqual(fimpanel.row_for(change),
                         ("MODIFIED", "C:/site/index.html",
                          "aaaaaaaaaaaa -> bbbbbbbbbbbb, 1,000 -> 1,200 bytes"))
        self.assertEqual(fimpanel.row_for(fim.Change("added", "x", new_sha256="c" * 64,
                                                     new_size=5))[2], "cccccccccccc, 5 bytes")
        self.assertEqual(fimpanel.row_for(fim.Change("removed", "x", old_sha256="d" * 64,
                                                     old_size=6))[2], "was dddddddddddd, 6 bytes")
        deep = fim.Change("added", str(self.tree / "sub" / "new.txt"), new_sha256="e" * 64)
        self.assertEqual(fimpanel.row_for(deep, [str(self.tmp), str(self.tree)])[1],
                         os.path.join("sub", "new.txt"), "the deepest root wins")
        self.assertEqual(fimpanel.row_for(deep, [str(self.tmp / "elsewhere")])[1], deep.path,
                         "a path under no root is shown in full")

    def test_the_status_line_after_a_check(self):
        fimpanel = self._panel_module()
        self.baseline()
        self.assertIn("No changes", fimpanel.describe_check(self.store.check()))
        (self.tree / "f0.txt").write_bytes(b"changed")
        text = fimpanel.describe_check(self.store.check(fast=True))
        self.assertIn("1 modified, 0 added, 0 removed", text)
        self.assertIn("Nothing was moved", text)
        self.assertIn("size and date trusted", text)
        cancelled = self.store.check(should_stop=lambda: True)
        self.assertIn("cancelled", fimpanel.describe_check(cancelled))
        self.assertIn("nothing recorded", fimpanel.describe_check(cancelled))
        self.assertIn("No baseline", fimpanel.describe_check(
            fim.CheckReport(integrity=fim.INTEGRITY_NO_BASELINE)))
        self.store.signature_path.unlink()
        self.assertIn("BASELINE: the baseline has no signature file",
                      fimpanel.describe_check(self.store.check()))


class TestThePanelOnAWindow(FimCase):
    """The Integrity tab itself, on the shared withdrawn window: baseline,
    check and accept through its buttons' handlers, with the worker thread
    real and the window's pump played by wait()."""

    def setUp(self) -> None:
        super().setUp()
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        try:
            from avguard import fimpanel
            from guiroot import gui_root
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        try:
            self.root = gui_root()
        except Exception as exc:  # no display on this machine
            self.skipTest(f"no display: {exc}")
        self.fimpanel = fimpanel
        self.posted: "queue.Queue" = queue.Queue()
        self.panel = fimpanel.IntegrityPanel(
            self.root, store_factory=lambda: self.store, events=self.events,
            post=lambda fn, *args: self.posted.put((fn, args)))
        self.addCleanup(self.panel.destroy)

    def wait(self, timeout: float = 60.0) -> None:
        """Let the worker finish, then run what it posted, on this thread:
        what the window's pump does every 100 ms."""
        if self.panel._thread is not None:
            self.panel._thread.join(timeout)
        self.assertFalse(self.panel.busy, "the worker did not finish")
        while True:
            try:
                fn, args = self.posted.get_nowait()
            except queue.Empty:
                break
            fn(*args)
        self.root.update_idletasks()

    def state(self, button) -> str:
        return str(button.cget("state"))

    def test_baseline_check_accept_from_the_tab(self):
        panel = self.panel
        self.assertIn("No baseline yet", panel.summary_var.get())
        self.assertFalse(panel.check(), "nothing to check against yet")
        self.assertIn("No baseline", panel.status_var.get())

        self.assertTrue(panel.start_baseline(self.tree))
        self.assertEqual(self.state(panel.check_btn), "disabled")
        self.assertEqual(self.state(panel.cancel_btn), "normal")
        self.wait()
        self.assertEqual(self.state(panel.check_btn), "normal")
        self.assertEqual(self.state(panel.cancel_btn), "disabled")
        self.assertIn("7 file(s) baselined", panel.summary_var.get())
        self.assertIn("Baselined 7 file(s)", panel.status_var.get())
        self.assertEqual(self.store.verify_integrity(), fim.INTEGRITY_OK)

        self.assertTrue(panel.check())
        self.wait()
        self.assertEqual(panel.changes, [])
        self.assertIn("No changes", panel.status_var.get())

        target = self.tree / "f3.txt"
        target.write_bytes(b"edited")
        self.assertTrue(panel.check())
        self.wait()
        self.assertEqual([(c.kind, c.path) for c in panel.changes], [("modified", str(target))])
        row = panel.tree.item(panel.tree.get_children()[0], "values")
        self.assertEqual((row[0], row[1]), ("MODIFIED", "f3.txt"),
                         "shown relative to its root; the event carries the full path")
        self.assertIn("1 modified, 0 added, 0 removed", panel.status_var.get())
        self.assertEqual([e.level for e in self.events.read(kinds={"fim"})], ["modified"])
        self.assertEqual(target.read_bytes(), b"edited", "a check moves nothing")

        with mock.patch.object(self.fimpanel.Messagebox, "show_info") as info:
            self.assertFalse(panel.accept_selected(), "nothing selected")
        info.assert_called_once()
        panel.tree.selection_set(panel.tree.get_children())
        with mock.patch.object(self.fimpanel.Messagebox, "yesno", return_value="No"):
            self.assertFalse(panel.accept_selected(), "declined")
        self.assertEqual(len(panel.changes), 1)
        with mock.patch.object(self.fimpanel.Messagebox, "yesno", return_value="Yes"):
            self.assertTrue(panel.accept_selected())
        self.wait()
        self.assertEqual(panel.changes, [])
        self.assertIn("Accepted 1 change(s)", panel.status_var.get())
        self.assertTrue(self.store.check().clean, "the accepted change is the baseline now")
        self.assertEqual(self.store.verify_integrity(), fim.INTEGRITY_OK, "and it was re-signed")

    def test_a_tampered_baseline_turns_the_summary_red(self):
        self.baseline()
        data = bytearray(self.store.db_path.read_bytes())
        data[-1] ^= 0xFF
        self.store.db_path.write_bytes(bytes(data))
        self.assertTrue(self.panel.check())
        self.wait()
        self.assertIn("SIGNATURE TAMPERED", self.panel.summary_var.get())
        self.assertIn("danger", str(self.panel.summary.cget("style")))
        self.assertIn("BASELINE: the baseline database was modified outside AVGuard",
                      self.panel.status_var.get())
        self.assertEqual([e.level for e in self.events.read(kinds={"fim"})], ["tampered"])

    def _slow_check(self, started: "threading.Event", gate: "threading.Event"):
        """A check that waits at the gate, then runs for real."""
        real = self.store.check

        def check(**kwargs):
            started.set()
            while not gate.is_set() and not kwargs["should_stop"]():
                time.sleep(0.01)
            return real(**kwargs)
        return check

    def test_cancel_stops_a_running_check_and_records_nothing(self):
        self.baseline()
        (self.tree / "f0.txt").write_bytes(b"changed")
        started, gate = threading.Event(), threading.Event()
        with mock.patch.object(self.store, "check", self._slow_check(started, gate)):
            self.assertTrue(self.panel.check())
            self.assertTrue(started.wait(10))
            self.panel.cancel()
            self.wait()
        self.assertIn("cancelled", self.panel.status_var.get())
        self.assertIn("nothing recorded", self.panel.status_var.get())
        self.assertEqual(self.events.read(kinds={"fim"}), [])
        self.assertEqual(self.state(self.panel.cancel_btn), "disabled")
        self.assertEqual(self.state(self.panel.check_btn), "normal")

    def test_one_operation_at_a_time_and_stop_at_shutdown(self):
        self.baseline()
        started, gate = threading.Event(), threading.Event()
        with mock.patch.object(self.store, "check", self._slow_check(started, gate)):
            self.assertTrue(self.panel.check())
            self.assertTrue(started.wait(10))
            with mock.patch.object(self.fimpanel.Messagebox, "show_info") as info:
                self.assertFalse(self.panel.check())
                self.assertFalse(self.panel.start_baseline(self.tree))
            self.assertEqual(info.call_count, 2)
            self.panel.stop(timeout=10)       # what the window does at shutdown
            self.assertFalse(self.panel.busy)
            self.wait()
        self.assertIn("cancelled", self.panel.status_var.get())

    def test_the_tab_fits_beside_the_quarantine(self):
        """The right pane is two fifths of a 1,100 px window: about 430 px."""
        self.panel.update_idletasks()
        width, height = self.panel.winfo_reqwidth(), self.panel.winfo_reqheight()
        self.assertLessEqual(width, 430, f"the Integrity tab asks for {width} x {height} px")
        self.assertLessEqual(height, 420, f"the Integrity tab asks for {width} x {height} px")


class TestWhatTheHealthRowSays(FimCase):
    def test_the_health_row_names_the_tab(self):
        """AVGuardApp._describe_fim needs no window; hand it what it reads."""
        try:
            from avguard import gui
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        from types import SimpleNamespace
        fake = SimpleNamespace(_fim_store=lambda: self.store)
        text = gui.AVGuardApp._describe_fim(fake)
        self.assertIn("No baseline yet", text)
        self.assertIn("Integrity tab", text)
        self.assertIn("--fim-baseline", text)
        self.baseline()
        text = gui.AVGuardApp._describe_fim(fake)
        self.assertIn("7 file(s) baselined", text)
        self.assertIn("Signature holds", text)
        self.assertIn("Integrity tab", text)
        self.assertIn("--fim-check", text)
