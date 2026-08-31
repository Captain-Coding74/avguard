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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os as _os
import tempfile as _tempfile

# Isolate the data directory before avguard is imported. See test_avguard.py
# for why: objects built with default paths otherwise reach into the user's
# real %LOCALAPPDATA%/AVGuard.
_os.environ.setdefault(
    "AVGUARD_DATA",
    _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}"))



logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False


class CliCase(unittest.TestCase):
    """Each test runs main() in-process with the data directory redirected."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

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
        self.assertIn("Wrote 1 file", output)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
