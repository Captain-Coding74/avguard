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
import sys
import tempfile
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
