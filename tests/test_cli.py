"""Drive the command line the way a person does.

Nothing in the test suite ever called `main()`, and two bugs shipped straight
through that gap: `--export-all` and `--schedule on` both interpolated an
undefined name, so each one did its work correctly and then died with a
NameError and a non-zero exit. `--export-all` is the documented exit door for
the only copy of everything in quarantine.

The lesson is narrower than "test the CLI". It is that checking the first line
of stdout is not checking the command: the export printed "Wrote 1 file(s)"
and crashed on the next line, and a check that read only that first line
called it a pass. Every case here asserts the exit code as well.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os as _os
import tempfile as _tempfile

# Isolate the data directory before avguard is imported. See test_avguard.py
# for why: objects built with default paths otherwise reach into the user's
# real %LOCALAPPDATA%/AVGuard.
_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}")
_os.environ["AVGUARD_DATA"] = _test_data      # assigned: an inherited value may be real data
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



logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False


BS = chr(92)        # a backslash the Windows paths in these tests are spelled with

class CliCase(unittest.TestCase):
    """Each test runs main() in-process with the data directory redirected."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-cli-"))
        self.addCleanup(_remove_tree, self.tmp)
        # Cleanups run last-in first-out: the log file is closed before the
        # directory holding it is removed, or the removal quietly fails.
        from avguard import logsetup
        self.addCleanup(logsetup.close_file_handlers)

        self._saved_data = os.environ.get("AVGUARD_DATA")
        os.environ["AVGUARD_DATA"] = str(self.tmp / "data")
        self.addCleanup(self._restore_env)

        # config computes its paths at import, so the package is reloaded under
        # the redirected AVGUARD_DATA rather than writing into the real store.
        # The originals are put back afterwards: other test modules already
        # hold references to them, and simply deleting the entries left those
        # tests patching module objects nothing was using any more.
        self._saved_modules = {name: module for name, module in sys.modules.items()
                               if name.startswith("avguard")}
        for name in self._saved_modules:
            del sys.modules[name]

    def _restore_env(self) -> None:
        if self._saved_data is None:
            os.environ.pop("AVGUARD_DATA", None)
        else:
            os.environ["AVGUARD_DATA"] = self._saved_data
        for name in [m for m in list(sys.modules) if m.startswith("avguard")]:
            del sys.modules[name]
        sys.modules.update(self._saved_modules)

    def run_cli(self, *args: str) -> tuple[int, str]:
        """Return (exit code, combined output). Never lets an exception escape."""
        from avguard.__main__ import main
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(list(args))
        except SystemExit as exc:
            code = int(exc.code or 0)
        return code, out.getvalue() + err.getvalue()

    def marker_file(self, name: str = "threat.bin") -> Path:
        from avguard.scanner import SELFTEST_MARKER
        folder = self.tmp / "drop"
        folder.mkdir(exist_ok=True)
        path = folder / name
        path.write_bytes(SELFTEST_MARKER)
        return path


class TestScanning(CliCase):

    def test_a_clean_file_exits_zero(self):
        target = self.tmp / "clean.txt"
        target.write_text("nothing to see here")
        code, output = self.run_cli("--scan", str(target))
        self.assertEqual(code, 0, output)
        self.assertNotIn("MALICIOUS", output)

    def test_a_detection_exits_one_and_says_so(self):
        code, output = self.run_cli("--scan", str(self.marker_file().parent))
        self.assertEqual(code, 1, output)
        self.assertIn("MALICIOUS", output)

    def test_scanning_reports_without_moving_anything(self):
        target = self.marker_file()
        self.run_cli("--scan", str(target.parent))
        self.assertTrue(target.exists(), "--scan alone must never move a file")

    def test_a_program_extracted_from_a_download_gets_a_note(self):
        """The archive carries the download mark; the program 7-Zip took out
        of it does not, and SmartScreen will not ask. The terminal says so,
        at weight 0, and the exit code stays clean."""
        import zipfile
        from avguard import provenance
        folder = self.tmp / "dl"
        folder.mkdir()
        tool = b"MZ" + b"\x90" * 400
        archive = folder / "app.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("tool.exe", tool)
        with open(provenance.stream_path(archive), "w", newline="") as handle:
            handle.write("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://dl.example.test/app.zip?t=1\r\n")
        code, output = self.run_cli("--scan", str(archive))
        self.assertEqual(code, 0, output)
        extracted = folder / "tool.exe"
        extracted.write_bytes(tool)
        code, output = self.run_cli("--scan", str(extracted))
        self.assertEqual(code, 0, output)
        self.assertIn("[note]", output)
        self.assertIn("has the bytes of tool.exe from app.zip (downloaded from dl.example.test)", output)
        self.assertNotIn("?t=1", output, "the URL appears nowhere")
        code, output = self.run_cli("--scan", str(extracted), "--json")
        self.assertEqual(code, 0, output)
        self.assertIn('"text": "has the bytes of tool.exe from app.zip (downloaded from dl.example.test)', output,
                      "the account object carries the row")

    def test_a_missing_path_is_an_error_not_a_crash(self):
        code, output = self.run_cli("--scan", str(self.tmp / "does-not-exist"))
        self.assertEqual(code, 2)
        self.assertIn("no such path", output.lower())


class TestQuarantineCommands(CliCase):

    def test_quarantine_then_list_then_restore(self):
        target = self.marker_file()
        code, output = self.run_cli("--scan", str(target.parent), "--quarantine")
        self.assertEqual(code, 1, output)
        self.assertFalse(target.exists(), "the detection was not moved")

        code, listing = self.run_cli("--list-quarantine")
        self.assertEqual(code, 0, listing)
        self.assertIn("threat.bin", listing)

        entry_id = listing.strip().split()[0]
        code, output = self.run_cli("--restore", entry_id)
        self.assertEqual(code, 0, output)
        self.assertTrue(target.exists(), "restore did not put the file back")

    def test_export_all_exits_zero(self):
        """It printed 'Wrote 1 file(s)' and then died with a NameError.

        A check that read only the first line of stdout called that a pass.
        """
        self.run_cli("--scan", str(self.marker_file().parent), "--quarantine")
        code, output = self.run_cli("--export-all", str(self.tmp / "rescued"))
        self.assertEqual(code, 0, output)
        self.assertIn("Wrote 1 of 1 file", output)

    def test_export_all_exits_one_and_names_a_damaged_file(self):
        """Round six: a damaged payload was written out, counted, and called
        'the original, unmodified files'; exit 0."""
        self.run_cli("--scan", str(self.marker_file().parent), "--quarantine")
        payload = next((self.tmp / "data" / "quarantine").glob("*.quar"))
        payload.write_bytes(payload.read_bytes()[:-1])
        code, output = self.run_cli("--export-all", str(self.tmp / "rescued"))
        self.assertEqual(code, 1, output)
        self.assertIn("Wrote 0 of 1 file(s)", output)
        self.assertIn("not written: threat.bin: integrity check failed", output)
        self.assertNotIn("unmodified", output)

    def test_a_file_changed_during_the_scan_is_not_moved(self):
        """Round six: --scan --quarantine moved whatever was at the path when
        a long scan ended, on a verdict about other bytes."""
        from avguard import scanner as scanner_module
        target = self.marker_file()
        real = scanner_module.Scanner.scan_tree

        def scan_then_edit(scanner_self, *args, **kwargs):
            result = real(scanner_self, *args, **kwargs)
            target.write_bytes(b"my notes, the forum paste removed")
            return result
        with mock.patch.object(scanner_module.Scanner, "scan_tree", scan_then_edit):
            code, output = self.run_cli("--scan", str(target.parent), "--quarantine")
        self.assertTrue(target.exists(), output)
        self.assertEqual(target.read_bytes(), b"my notes, the forum paste removed")
        self.assertIn("changed after it was scanned", output)

    def test_export_all_actually_writes_the_bytes(self):
        from avguard.scanner import SELFTEST_MARKER
        self.run_cli("--scan", str(self.marker_file().parent), "--quarantine")
        destination = self.tmp / "rescued"
        self.run_cli("--export-all", str(destination))
        written = list(destination.glob("*"))
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0].read_bytes(), SELFTEST_MARKER)

    def test_export_all_on_an_empty_store_exits_zero(self):
        code, output = self.run_cli("--export-all", str(self.tmp / "rescued"))
        self.assertEqual(code, 0, output)

    def test_listing_an_empty_quarantine_exits_zero(self):
        code, output = self.run_cli("--list-quarantine")
        self.assertEqual(code, 0, output)
        self.assertIn("empty", output.lower())

    def test_restoring_an_unknown_id_fails_cleanly(self):
        code, output = self.run_cli("--restore", "0" * 32)
        self.assertEqual(code, 1)
        self.assertIn("could not restore", output.lower())


class TestTheAccount(CliCase):
    """--explain, --json and --explain-quarantine: the account of a verdict
    from the console, with the exit codes unchanged."""

    def test_explain_prints_the_account_and_keeps_the_exit_code(self):
        target = self.marker_file()
        code, output = self.run_cli("--scan", str(target), "--explain")
        self.assertEqual(code, 1, output)
        self.assertIn("an exact byte signature (AVGuard-Selftest-Marker)", output)
        self.assertIn("Counted: facts 100 + opinions 0 = 100", output)
        self.assertIn("Nothing was moved. Pass --quarantine", output)
        self.assertNotIn("%", output)
        self.assertTrue(target.exists())

    def test_json_is_one_object_per_file_with_the_findings(self):
        import json
        target = self.marker_file()
        (target.parent / "clean.txt").write_text("nothing here", encoding="utf-8")
        from avguard.__main__ import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--scan", str(target.parent), "--json"])
        self.assertEqual(code, 1)
        objects = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(sorted(o["level"] for o in objects), ["clean", "malicious"])
        bad = next(o for o in objects if o["level"] == "malicious")
        self.assertEqual(bad["rows"][0]["kind"], "fact")
        self.assertEqual((bad["tally"]["hard"], bad["tally"]["threshold"]), (100, 100))
        self.assertEqual(len(bad["sha256"]), 64)
        self.assertTrue(bad["consistent"])
        self.assertIn("Examined", err.getvalue(), "the summary went beside the objects, not among them")

    def test_json_lines_stay_whole_across_the_worker_threads(self):
        """scan_tree reports from four threads; without one lock and one
        write per line, 85 of 660 objects were unparsable here."""
        import json
        folder = self.tmp / "many"
        folder.mkdir()
        from avguard.scanner import SELFTEST_MARKER
        for index in range(240):
            (folder / f"c{index:03d}.txt").write_text(f"clean {index}", encoding="utf-8")
        for index in range(40):
            (folder / f"t{index:03d}.bin").write_bytes(SELFTEST_MARKER)
        from avguard.__main__ import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--scan", str(folder), "--json"])
        self.assertEqual(code, 1)
        lines = out.getvalue().split("\n")
        self.assertEqual(lines[-1], "", "ends with one newline")
        objects = [json.loads(line) for line in lines[:-1]]
        self.assertEqual(len(objects), 280, "one object per file, every one whole")
        self.assertEqual(sum(o["level"] == "malicious" for o in objects), 40)

    def test_json_and_explain_with_quarantine_say_what_the_command_did(self):
        import json
        target = self.marker_file()
        (target.parent / "clean.txt").write_text("nothing here", encoding="utf-8")
        from avguard.__main__ import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--scan", str(target.parent), "--json", "--quarantine"])
        self.assertEqual(code, 1)
        self.assertFalse(target.exists(), "moved")
        lines = out.getvalue().split("\n")
        self.assertNotIn("", lines[:-1], "no blank line among the objects")
        objects = [json.loads(line) for line in lines[:-1]]
        bad = next(o for o in objects if o["level"] == "malicious")
        self.assertEqual((bad["state"], bad["happened"][:12]), ("quarantined", "Quarantined."))
        self.assertIn("quarantined:", err.getvalue())

        again = self.marker_file("second.bin")
        code, output = self.run_cli("--scan", str(again), "--explain", "--quarantine")
        self.assertEqual(code, 1, output)
        self.assertIn("Quarantined. Restore puts it back", output)
        self.assertNotIn("Nothing was moved.", output)
        self.assertLess(output.index("quarantined:"), output.index("Quarantined. Restore"),
                        "the account follows the move it describes")

    def test_explain_quarantine_reads_the_record_and_its_evidence_without_the_lock(self):
        target = self.marker_file()
        code, output = self.run_cli("--scan", str(target), "--quarantine")
        self.assertEqual(code, 1, output)
        code, listing = self.run_cli("--list-quarantine")
        entry_id = listing.strip().split()[0]
        from avguard.instance import InstanceLock
        other = InstanceLock()
        self.assertTrue(other.acquire(), "the test holds the lock as another AVGuard would")
        try:
            code, output = self.run_cli("--explain-quarantine", entry_id)
        finally:
            other.release()
        self.assertEqual(code, 0, output)
        self.assertIn("an exact byte signature (AVGuard-Selftest-Marker)", output)
        self.assertIn("Quarantined. Restore puts it back", output)
        self.assertIn("SHA-256:", output)
        code, output = self.run_cli("--explain-quarantine", "no-such-id")
        self.assertEqual(code, 1)
        self.assertIn("no quarantined file", output)


class TestStartupCommands(CliCase):
    def test_status_and_changes_with_no_snapshot_exit_zero_and_say_how_to_take_one(self):
        for flag in ("--autoruns-status", "--autoruns-changes"):
            code, output = self.run_cli(flag)
            self.assertEqual(code, 0, output)
            self.assertIn("No snapshot. Take one with", output)

    @unittest.skipIf(sys.platform == "win32", "on Windows the collectors read the real machine")
    def test_a_snapshot_that_collects_nothing_exits_two_and_records_nothing(self):
        code, output = self.run_cli("--autoruns-snapshot", "-v")
        self.assertEqual(code, 2, output)
        self.assertIn("No snapshot was taken", output)
        self.assertIn("service", output, "the per-collector table printed")
        code, output = self.run_cli("--autoruns-status")
        self.assertIn("No snapshot", output)

    def test_a_removed_entry_is_not_called_under_the_windows_folder(self):
        from unittest import mock
        from avguard import autoruns
        from avguard.autoruns import Collected, Entry
        gone = Entry("run", "HKCU" + BS + "Run", "OneDrive", "C:" + BS + "Users" + BS + "me" + BS + "OneDrive.exe")
        kept = Entry("service", "HKLM" + BS + "Services", "Dhcp", "C:" + BS + "Windows" + BS + "System32" + BS + "svchost.exe -k x")
        with mock.patch.object(autoruns, "collect", side_effect=[Collected(entries=[gone, kept]),
                                                                  Collected(entries=[kept])]):
            code, output = self.run_cli("--autoruns-snapshot")
            self.assertEqual(code, 0, output)
            code, output = self.run_cli("--autoruns-snapshot")
        self.assertEqual(code, 1, output)
        self.assertIn("GONE", output)
        self.assertNotIn("under the Windows folder", output, "a removal is never announced; it was not under it")

    def test_changes_and_status_on_a_tampered_store_say_so_and_exit_three(self):
        from avguard import autoruns
        from avguard.autoruns import Collected, Entry
        store = autoruns.AutorunsStore()
        one = Entry("run", "HKCU" + BS + "Run", "App", "C:" + BS + "a.exe")
        store.snapshot(Collected(entries=[one]))
        store.snapshot(Collected(entries=[one, Entry("run", "HKCU" + BS + "Run", "New",
                                                       "C:" + BS + "Users" + BS + "me" + BS + "n.exe")]))
        code, output = self.run_cli("--autoruns-changes")
        self.assertEqual(code, 1, output)
        self.assertNotIn("SNAPSHOTS:", output)
        with open(store.db_path, "r+b") as handle:
            handle.seek(0, 2)
            handle.write(b"\0" * 16)
        code, output = self.run_cli("--autoruns-changes")
        self.assertEqual(code, 3, output)
        self.assertIn("SNAPSHOTS:", output)
        self.assertIn("NEW", output, "what is stored is still printed, under that word")
        code, output = self.run_cli("--autoruns-status")
        self.assertEqual(code, 3, output)
        self.assertIn("BAD", output)

    def test_an_unreadable_database_exits_three_and_says_how_to_start_again(self):
        from avguard import autoruns
        autoruns.AUTORUNS_DIR.mkdir(parents=True, exist_ok=True)
        (autoruns.AUTORUNS_DIR / autoruns.DB_NAME).write_bytes(b"not a database" * 50)
        for flag in ("--autoruns-status", "--autoruns-changes"):
            code, output = self.run_cli(flag)
            self.assertEqual(code, 3, output)
            self.assertIn("cannot be read", output)
            self.assertIn(autoruns.DB_NAME, output, "the file to move away is named")

    @unittest.skipUnless(sys.platform == "win32", "a real snapshot needs Windows")
    def test_a_real_snapshot_then_status_then_changes(self):
        code, output = self.run_cli("--autoruns-snapshot", "-v")
        self.assertEqual(code, 0, output)
        self.assertIn("first snapshot", output)
        code, output = self.run_cli("--autoruns-status")
        self.assertEqual(code, 0, output)
        self.assertIn("Last snapshot:", output)
        code, output = self.run_cli("--autoruns-snapshot")
        self.assertIn(code, (0, 1), output)
        code, output = self.run_cli("--autoruns-changes")
        self.assertIn(code, (0, 1), output)


class TestRuleCommands(CliCase):

    def test_reload_rules_exits_zero_and_names_the_files(self):
        code, output = self.run_cli("--reload-rules")
        self.assertEqual(code, 0, output)
        self.assertIn("malware.yara", output)


class TestScheduleCommands(CliCase):

    def test_schedule_status_exits_zero(self):
        """The other NameError. It reported correctly, then crashed."""
        code, output = self.run_cli("--schedule", "status")
        self.assertEqual(code, 0, output)
        self.assertIn("Starts with Windows", output)

    def test_schedule_off_is_safe_when_nothing_is_scheduled(self):
        code, output = self.run_cli("--schedule", "off")
        self.assertEqual(code, 0, output)


class TestTheCommandLineSettlesTheStore(CliCase):
    """Round seven: --scan --quarantine holds the lock and is meant to
    finish or undo a move a killed process left half done before it adds
    its own; nothing tested that it does, only the store's method."""

    def test_a_move_left_half_done_is_undone_before_new_ones(self):
        import hashlib
        import uuid
        from avguard import config
        from avguard.quarantine import QuarantineRecord, QuarantineStore, _mask
        config.ensure_directories()
        original = self.tmp / "kept.docx"
        original.write_bytes(b"the original survived the kill")
        store = QuarantineStore()
        entry_id, nonce = uuid.uuid4().hex, os.urandom(16)
        store._payload_path(entry_id).write_bytes(_mask(original.read_bytes(), nonce))
        store._records[entry_id] = QuarantineRecord(
            entry_id=entry_id, original_path=str(original), original_name=original.name,
            quarantined_at="2026-10-07T00:00:00+00:00", size=original.stat().st_size,
            sha256=hashlib.sha256(original.read_bytes()).hexdigest(), nonce=nonce.hex(),
            reasons=["planted"], pending=True)
        store._save()
        code, output = self.run_cli("--scan", str(self.marker_file().parent), "--quarantine")
        self.assertEqual(code, 1, output)
        after = QuarantineStore()
        self.assertIsNone(after.get(entry_id), "a move nobody finished is still listed as held")
        self.assertEqual(len(after), 1, output)
        self.assertTrue(original.exists())


class TestTheDailyScanCoversEveryWatchedFolder(CliCase):
    """Round six: "scan the watched folders once a day" scheduled a scan of
    the first of them only, and kept scanning it after the list changed."""

    def watched(self, *names: str) -> list[Path]:
        from avguard import config
        from avguard.scanner import SELFTEST_MARKER
        folders = []
        for name in names:
            folder = self.tmp / name
            folder.mkdir()
            (folder / f"{name}.bin").write_bytes(SELFTEST_MARKER)
            folders.append(folder)
        config.Config(watch_paths=[str(f) for f in folders]).save()
        return folders

    def test_scan_watched_reads_the_list_and_scans_each(self):
        self.watched("first", "second")
        code, output = self.run_cli("--scan-watched")
        self.assertEqual(code, 1, output)
        self.assertIn("first.bin", output)
        self.assertIn("second.bin", output, "only the first watched folder was scanned")

    def test_scan_watched_with_nothing_there_says_so(self):
        from avguard import config
        config.Config(watch_paths=[str(self.tmp / "gone")]).save()
        code, output = self.run_cli("--scan-watched")
        self.assertEqual(code, 2, output)
        self.assertIn("no watched folder exists", output)

    def test_the_task_runs_scan_watched_and_schedule_on_asks_for_it(self):
        from avguard import scheduling
        ran: list[list[str]] = []
        with mock.patch.object(scheduling.sys, "platform", "win32"), \
                mock.patch.object(scheduling, "_run", side_effect=lambda args: (ran.append(args), (True, ""))[1]):
            ok, _ = scheduling.enable_scheduled_scan(None)
        self.assertTrue(ok)
        command = ran[0][ran[0].index("/TR") + 1]
        self.assertTrue(command.endswith("--scan-watched"), command)
        with mock.patch.object(scheduling, "enable_start_with_windows", return_value=(True, "")), \
                mock.patch.object(scheduling, "enable_scheduled_scan", return_value=(True, "daily")) as daily:
            code, output = self.run_cli("--schedule", "on")
        self.assertEqual(code, 0, output)
        self.assertIsNone(daily.call_args.args[0], "a single folder was fixed into the task")
        self.assertIn("the watched folders", output)


class TestRoundSevenTheCommandLine(CliCase):
    """Round seven: --scan-watched scanned a folder inside another twice
    and skipped a missing one without a word; the daily scan, with no
    console, left no record anywhere but Task Scheduler's last result; a
    slow forwarding receiver held a command 12 s; --help described the old
    daily scan; the right-click entry under the windowed build showed
    nothing for a missing path; and nothing tested --iocs-status's gap
    line, --json with no console, or that the command line's quarantine
    reaches History."""

    def test_scan_watched_scans_each_tree_once_and_names_what_is_missing(self):
        from avguard import config
        from avguard.scanner import SELFTEST_MARKER
        outer = self.tmp / "home"
        inner = outer / "Downloads"
        inner.mkdir(parents=True)
        (inner / "threat.bin").write_bytes(SELFTEST_MARKER)
        config.Config(watch_paths=[str(outer), str(inner), str(self.tmp / "usb")]).save()
        code, output = self.run_cli("--scan-watched")
        self.assertEqual(code, 1, output)
        self.assertIn("Threats  : 1", output, "a folder inside another was scanned twice")
        self.assertIn(f"skipped: {self.tmp / 'usb'} does not exist", output)

    def test_a_scan_with_no_console_leaves_a_record_in_history(self):
        from avguard.__main__ import _console_scan
        from avguard.events import EventStore
        target = self.marker_file()
        with mock.patch.object(sys, "stdout", None):
            code = _console_scan(target.parent, False, False)
        self.assertEqual(code, 1)
        kinds = [e.kind for e in EventStore().read()]
        self.assertIn("detection", kinds, "the daily scan's threat reached no record")
        self.assertIn("scan_finished", kinds)

    def test_json_with_no_console_keeps_the_objects_for_the_summary(self):
        import avguard.__main__ as cli
        target = self.marker_file()
        kept = []
        with mock.patch.object(sys, "stdout", None), \
                mock.patch.object(cli, "_pause_for_the_user", side_effect=lambda t, lines: kept.extend(lines)):
            self.assertEqual(cli._console_scan(target.parent, False, False, pause=True, as_json=True), 1)
        self.assertTrue(any('"path"' in line for line in kept), "the object was lost with no console")

    def test_the_command_line_quarantine_is_in_history(self):
        from avguard.events import EventStore
        target = self.marker_file()
        code, output = self.run_cli("--scan", str(target.parent), "--quarantine")
        self.assertEqual(code, 1, output)
        self.assertIn(str(target), [e.path for e in EventStore().read(kinds={"quarantined"})])

    def test_forwarding_waits_seconds_not_twelve_and_says_what_it_dropped(self):
        import avguard.__main__ as cli
        from avguard import config, forward
        waited = []

        class Slow:
            pending = 4

            def __init__(self, url, **kwargs):
                self.url = url

            def wait_idle(self, timeout):
                waited.append(timeout)
                return False

            def stop(self):
                pass

            def submit(self, event):
                pass
        err = io.StringIO()
        with mock.patch.object(forward, "EventForwarder", Slow), contextlib.redirect_stderr(err):
            with cli._event_store(config.Config(event_forward_url="http://127.0.0.1:9/events")):
                pass
        self.assertLessEqual(waited[0], 3.0)
        self.assertIn("4 event(s) were recorded in History but not delivered", err.getvalue())

    def test_help_describes_the_daily_scan_as_it_is(self):
        code, output = self.run_cli("--help")
        self.assertIn("every watched folder", " ".join(output.split()))

    def test_a_missing_path_is_shown_by_the_right_click_entry(self):
        import avguard.__main__ as cli
        shown = []
        with mock.patch.object(cli, "_pause_for_the_user", side_effect=lambda target, lines: shown.append(lines)), \
                mock.patch.object(sys, "stdout", None):
            code = cli._main(["--scan", str(self.tmp / "gone.exe"), "--pause"])
        self.assertEqual(code, 2)
        self.assertIn("No such path", shown[0][0])

    def test_iocs_status_says_hashes_may_be_missing(self):
        import time
        from avguard import iocs
        store = iocs.IocStore()
        with store._write_lock, store._conn() as conn:
            store._set_meta(conn, "feed_checked_at", str(time.time()))
            store._set_meta(conn, "feed_gap_since", str(time.time() - 4 * 86400))
        store.close()
        code, output = self.run_cli("--iocs-status")
        self.assertEqual(code, 0, output)
        self.assertIn("may be missing", output)


class TestOutputSanity(CliCase):

    def test_no_command_output_contains_an_unformatted_placeholder(self):
        """The NameErrors were placeholders that never got substituted.

        Anything of the shape {NAME} reaching a user means a format string was
        built wrong, whether or not it happened to raise.
        """
        import re
        placeholder = re.compile(r"\{[A-Za-z_][A-Za-z_0-9]*\}")
        target = self.tmp / "clean.txt"
        target.write_text("x")
        commands = [
            ("--scan", str(target)),
            ("--list-quarantine",),
            ("--reload-rules",),
            ("--schedule", "status"),
            ("--export-all", str(self.tmp / "out")),
        ]
        for command in commands:
            with self.subTest(command=command[0]):
                _, output = self.run_cli(*command)
                found = placeholder.findall(output)
                self.assertEqual(found, [], f"unsubstituted placeholder in output: {found}")


class TestTheCorpusSpreadsAcrossPrograms(unittest.TestCase):
    """Measured before this: 400 files, 331 from System32, six program
    directories. A pack ceiling measured against one vendor's folder is
    weaker than it reads."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-corpus-"))
        self.addCleanup(_remove_tree, self.tmp)
        self.system = self.tmp / "System32"
        self.system.mkdir()
        for index in range(300):
            (self.system / f"s{index}.dll").write_bytes(b"MZ" + bytes([index % 251]) * 64)
        self.programs = self.tmp / "Program Files"
        for app in range(40):
            folder = self.programs / f"app{app}"
            folder.mkdir(parents=True)
            for index in range(12):
                (folder / f"a{index}.exe").write_bytes(b"MZ" * 40)

    def corpus(self):
        import avguard.__main__ as cli
        return cli._clean_corpus(limit=120, roots=[self.programs, self.system])

    def test_no_directory_dominates(self):
        from collections import Counter
        corpus = self.corpus()
        self.assertEqual(len(corpus), 120)
        by_dir = Counter(path.parent for path in corpus)
        self.assertLessEqual(by_dir[self.system], 40, "System32 is held to a third")
        program_dirs = {d for d in by_dir if d != self.system}
        self.assertLessEqual(max(by_dir[d] for d in program_dirs), 6)
        self.assertGreaterEqual(len(program_dirs), 13)

    def test_it_is_repeatable(self):
        """verify compares today's rate with the one at install; the sample
        must not drift between the two."""
        self.assertEqual(self.corpus(), self.corpus())

    def test_system32_fills_in_when_nothing_else_is_installed(self):
        import avguard.__main__ as cli
        alone = cli._clean_corpus(limit=120, roots=[self.system])
        self.assertEqual(len(alone), 120)


class TestTheLogIsClosedWhenACommandReturns(unittest.TestCase):
    """Every CLI verb left the log file open until the interpreter exited;
    test_cli leaked a directory per test because of it."""

    def test_no_file_handler_survives_main(self):
        import logging
        from logging.handlers import RotatingFileHandler
        import avguard.__main__ as cli
        tmp = Path(tempfile.mkdtemp(prefix="avguard-cli-"))
        self.addCleanup(_remove_tree, tmp)
        sample = tmp / "plain.txt"
        sample.write_text("nothing to see", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["--scan", str(sample)])
        open_logs = [h for h in logging.getLogger("avguard").handlers
                     if isinstance(h, RotatingFileHandler)]
        self.assertEqual(open_logs, [], "main() returned with its log file still open")



class TestACrashInsideMainReachesTheLog(unittest.TestCase):
    """main() closed the log in a finally, which ran before sys.excepthook;
    under the windowed build a crash then left a 0-byte log. Measured: 0
    bytes, against 1,316 with the close out of the way. The existing hook
    test never went through main() and could not see it."""

    def test_the_hook_still_finds_the_file_handler(self):
        import subprocess
        import textwrap
        tmp = Path(tempfile.mkdtemp(prefix="avguard-cli-"))
        self.addCleanup(_remove_tree, tmp)
        child = textwrap.dedent("""
            import avguard.__main__ as m
            from avguard import config, logsetup

            def boom(argv=None):
                config.ensure_directories()
                logsetup.configure()
                raise ValueError("boom-from-main")

            m._main = boom
            raise SystemExit(m.main([]))
        """)
        env = dict(os.environ, AVGUARD_DATA=str(tmp))
        proc = subprocess.run([sys.executable, "-c", child], env=env,
                              capture_output=True, text=True,
                              cwd=str(Path(__file__).resolve().parent.parent))
        self.assertNotEqual(proc.returncode, 0)
        log_file = tmp / "logs" / "avguard.log"
        self.assertTrue(log_file.exists(), proc.stderr[-500:])
        self.assertIn("boom-from-main", log_file.read_text(encoding="utf-8", errors="replace"),
                      "the crash never reached the log")


class TestTheCorpusWalkIsNotStarvedByEmptyDirectories(unittest.TestCase):
    """The 4,000-directory cap counted directories with nothing in them; a
    per-user Python install burned the budget before any program was seen."""

    def test_binaries_past_thousands_of_empty_directories_are_found(self):
        import avguard.__main__ as cli
        tmp = Path(tempfile.mkdtemp(prefix="avguard-corpus-"))
        self.addCleanup(_remove_tree, tmp)
        root = tmp / "Programs"
        python = root / "Python" / "Lib"
        python.mkdir(parents=True)
        for index in range(4100):
            (python / f"m{index:04d}").mkdir()
        for app in range(20):
            folder = root / "zapps" / f"app{app}"
            folder.mkdir(parents=True)
            (folder / "a.exe").write_bytes(b"MZ" * 40)
        corpus = cli._clean_corpus(limit=120, roots=[root])
        self.assertGreaterEqual(len(corpus), 20, "the walk gave up before the programs")


if __name__ == "__main__":
    unittest.main(verbosity=2)
