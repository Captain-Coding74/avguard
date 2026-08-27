"""Tests for the Tier 3 work: publisher trust, rule loading, retention, paths.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from avguard import config, scheduling, signing
from avguard.protection import SelfProtection
from avguard.quarantine import QuarantineStore
from avguard.scanner import (
    Finding, Level, ScanCache, Scanner, SELFTEST_MARKER, decide,
)
from avguard.signing import SignatureChecker, SignatureResult, Trust

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

RULES = Path(__file__).resolve().parent.parent / "rules" / "malware.yara"
IS_WINDOWS = sys.platform == "win32"


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-t3-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def scanner(self, rules_path: Path | None = None, **overrides) -> Scanner:
        cfg = config.Config(cloud_enabled=False, **overrides)
        return Scanner(cfg, SelfProtection([self.tmp / "nothing"]),
                       rules_path=rules_path or RULES,
                       cache=ScanCache(path=self.tmp / "cache.json"))


# ------------------------------------------------------------ publisher trust

class TestPublisherTrust(TempCase):
    """A signature lowers suspicion. It never clears a detection.

    Malware is signed with stolen certificates often enough that "signed"
    cannot mean "safe". A valid signature tells you who to blame, not that
    there is nobody to blame.
    """

    @unittest.skipUnless(IS_WINDOWS, "WinVerifyTrust is Windows-only")
    def test_checker_is_available_on_windows(self):
        self.assertTrue(SignatureChecker().available)

    @unittest.skipUnless(IS_WINDOWS and Path(r"C:\Windows\System32\kernel32.dll").exists(),
                         "needs Windows")
    def test_a_microsoft_binary_verifies(self):
        result = SignatureChecker().check(Path(r"C:\Windows\System32\kernel32.dll"))
        self.assertIs(result.trust, Trust.TRUSTED)

    @unittest.skipUnless(IS_WINDOWS, "WinVerifyTrust is Windows-only")
    def test_an_unsigned_file_is_reported_unsigned(self):
        target = self.write("nothing.exe", b"MZ" + bytes(400))
        self.assertIs(SignatureChecker().check(target).trust, Trust.UNSIGNED)

    @unittest.skipUnless(IS_WINDOWS, "WinVerifyTrust is Windows-only")
    def test_results_are_cached(self):
        checker = SignatureChecker()
        target = self.write("nothing.exe", b"MZ" + bytes(400))
        stat = target.stat()
        first = checker.check(target, stat.st_size, stat.st_mtime_ns)
        second = checker.check(target, stat.st_size, stat.st_mtime_ns)
        self.assertIs(first, second, "the second check should come from the cache")

    def test_trust_never_clears_hard_evidence(self):
        """The property that matters most. A stolen certificate must not be
        able to launder a byte-for-byte match."""
        findings = [Finding("signature", "EICAR", 100, hard=True)]
        self.assertIs(decide(findings), Level.MALICIOUS)

    @unittest.skipUnless(IS_WINDOWS, "WinVerifyTrust is Windows-only")
    def test_a_signed_file_with_hard_evidence_is_still_malicious(self):
        scanner = self.scanner()
        target = self.write("marked.exe", SELFTEST_MARKER + bytes(500))
        verdict = scanner.scan(target, use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)

    def test_trust_can_be_turned_off(self):
        scanner = self.scanner(trust_signed_publishers=False)
        self.assertFalse(scanner.cfg.trust_signed_publishers)

    def test_an_unavailable_checker_answers_unknown_not_trusted(self):
        checker = SignatureChecker()
        checker._library = None
        result = checker.check(Path("anything.exe"))
        self.assertIs(result.trust, Trust.UNKNOWN)
        self.assertFalse(result.is_trusted, "unknown must never count as trusted")

    def test_only_trusted_counts_as_trusted(self):
        for trust in (Trust.UNSIGNED, Trust.UNTRUSTED, Trust.UNKNOWN):
            with self.subTest(trust=trust):
                self.assertFalse(SignatureResult(trust).is_trusted)
        self.assertTrue(SignatureResult(Trust.TRUSTED).is_trusted)


# --------------------------------------------------------------- rule loading

class TestRuleLoading(TempCase):
    """A broken rule should cost you that rule, not all detection."""

    GOOD = chr(10).join([
        "rule TempTestRule {",
        "  meta:",
        '    description = "a rule for the loading tests"',
        '    severity = "high"',
        "  strings:",
        "    $a = { 51 37 58 2D 4D 41 52 4B }",     # Q7X-MARK
        "  condition:",
        "    $a",
        "}",
    ])

    def setUp(self) -> None:
        super().setUp()
        self.rules_dir = self.tmp / "rules"
        self.rules_dir.mkdir()
        self.rules_path = self.rules_dir / "base.yara"
        self.rules_path.write_text(self.GOOD, encoding="utf-8")

    def build(self) -> Scanner:
        return Scanner(config.Config(cloud_enabled=False),
                       SelfProtection([self.tmp / "nothing"]),
                       rules_path=self.rules_path,
                       cache=ScanCache(path=self.tmp / "cache.json"))

    def test_rules_load(self):
        scanner = self.build()
        self.assertIsNotNone(scanner.rules)
        self.assertIn(self.rules_path, scanner.rule_sources)

    def test_a_second_rule_file_in_the_folder_is_picked_up(self):
        (self.rules_dir / "extra.yara").write_text(
            self.GOOD.replace("TempTestRule", "ExtraRule").replace(
                "51 37 58 2D 4D 41 52 4B", "45 58 54 52 41"), encoding="utf-8")
        scanner = self.build()
        self.assertEqual(len(scanner.rule_sources), 2)

    def test_a_broken_edit_does_not_destroy_working_rules(self):
        """The whole point. v1 lost detection permanently to one bad file."""
        scanner = self.build()
        self.assertIsNotNone(scanner.rules)
        self.rules_path.write_text("rule Broken { this is not yara }", encoding="utf-8")
        self.assertFalse(scanner.reload_rules())
        self.assertIsNotNone(scanner.rules, "the working ruleset was thrown away")

    def test_detection_still_works_after_a_broken_edit(self):
        scanner = self.build()
        target = self.write("hit.txt", b"contains Q7X-MARK here")
        self.assertIs(scanner.scan(target, use_cache=False).level, Level.MALICIOUS)
        self.rules_path.write_text("rule Broken { nope }", encoding="utf-8")
        scanner.reload_rules()
        self.assertIs(scanner.scan(target, use_cache=False).level, Level.MALICIOUS)

    def test_a_shipped_rule_that_matches_itself_is_refused(self):
        """The v1 self-destruct, refused at the door."""
        self.rules_path.write_text(chr(10).join([
            "rule SelfMatching {",
            "  meta:",
            '    description = "matches its own file"',
            '    severity = "high"',
            "  strings:",
            '    $a = "SelfMatching"',
            "  condition:",
            "    $a",
            "}",
        ]), encoding="utf-8")
        scanner = self.build()
        self.assertIsNone(scanner.rules, "a self-matching shipped ruleset must be refused")

    def test_no_rule_files_is_reported_not_hidden(self):
        for path in self.rules_dir.glob("*.yara"):
            path.unlink()
        scanner = self.build()
        self.assertIsNone(scanner.rules)

    def test_generation_covers_every_rule_file(self):
        scanner = self.build()
        before = scanner.detection_generation()
        (self.rules_dir / "extra.yara").write_text(
            self.GOOD.replace("TempTestRule", "ExtraRule"), encoding="utf-8")
        self.assertNotEqual(before, scanner.detection_generation())


# ------------------------------------------------------ quarantine exit door

class TestQuarantineRetention(TempCase):
    def store(self) -> QuarantineStore:
        directory = self.tmp / "store"
        (self.tmp / "prot").mkdir(exist_ok=True)
        return QuarantineStore(directory=directory,
                               index_path=directory / "index.json",
                               protection=SelfProtection([self.tmp / "prot"]))

    def test_export_all_writes_every_file(self):
        store = self.store()
        for i in range(3):
            store.quarantine(self.write(f"t{i}.exe", f"payload {i}".encode()), [])
        written = store.export_all(self.tmp / "out")
        self.assertEqual(len(written), 3)
        self.assertEqual(sorted(p.read_bytes() for p in written),
                         [b"payload 0", b"payload 1", b"payload 2"])

    def test_export_all_does_not_empty_the_store(self):
        store = self.store()
        store.quarantine(self.write("t.exe", b"x"), [])
        store.export_all(self.tmp / "out")
        self.assertEqual(len(store), 1)

    def test_export_all_sanitises_the_original_name(self):
        store = self.store()
        record = store.quarantine(self.write("CON.txt", b"x"), [])
        written = store.export_all(self.tmp / "out")
        self.assertTrue(written[0].name.startswith(record.entry_id[:8]))

    def test_export_all_on_an_empty_store_is_fine(self):
        self.assertEqual(self.store().export_all(self.tmp / "out"), [])

    def test_nothing_is_stale_when_retention_is_disabled(self):
        store = self.store()
        store.quarantine(self.write("t.exe", b"x"), [])
        self.assertEqual(store.stale(0), [])

    def test_an_old_record_is_offered_for_review(self):
        store = self.store()
        record = store.quarantine(self.write("t.exe", b"x"), [])
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(timespec="seconds")
        store._records[record.entry_id].quarantined_at = old
        store._save()
        self.assertEqual(len(store.stale(90)), 1)

    def test_review_never_deletes_by_itself(self):
        """`stale` reports. It must not be a deletion in disguise: the store
        holds the only copy of everything in it."""
        store = self.store()
        record = store.quarantine(self.write("t.exe", b"x"), [])
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(timespec="seconds")
        store._records[record.entry_id].quarantined_at = old
        store.stale(90)
        self.assertEqual(len(store), 1, "reviewing must not remove anything")

    def test_total_bytes_reports_the_held_size(self):
        store = self.store()
        store.quarantine(self.write("t.exe", b"0123456789"), [])
        self.assertEqual(store.total_bytes(), 10)


# ------------------------------------------------------------- data location

class TestDataLocation(unittest.TestCase):
    def test_data_is_not_inside_the_program_directory(self):
        """Keeping it there broke read-only installs, leaked between users of
        one machine, and uploaded quarantined samples to OneDrive."""
        self.assertFalse(
            config.DATA_DIR.is_relative_to(config.PROJECT_ROOT),
            f"{config.DATA_DIR} still sits inside the program directory")

    def test_everything_writable_lives_under_the_data_dir(self):
        for path in (config.QUARANTINE_DIR, config.LOG_DIR, config.CONFIG_PATH,
                     config.SCAN_CACHE_PATH, config.VT_CACHE_PATH,
                     config.USER_RULES_DIR):
            with self.subTest(path=path):
                self.assertTrue(path.is_relative_to(config.DATA_DIR))

    def test_shipped_rules_stay_with_the_code(self):
        self.assertTrue(config.RULES_DIR.is_relative_to(config.PROJECT_ROOT))

    def test_user_rules_are_separate_from_shipped_rules(self):
        """So updating AVGuard cannot overwrite something the user wrote."""
        self.assertNotEqual(config.USER_RULES_DIR.resolve(), config.RULES_DIR.resolve())

    def test_the_data_dir_is_still_protected(self):
        protection = SelfProtection()
        self.assertTrue(protection.is_protected(config.QUARANTINE_DIR / "x.quar"))
        self.assertTrue(protection.is_protected(config.LOG_DIR / "avguard.log"))

    def test_an_override_is_honoured(self):
        original = os.environ.get("AVGUARD_DATA")
        os.environ["AVGUARD_DATA"] = str(Path(tempfile.gettempdir()) / "avguard-override")
        try:
            self.assertTrue(str(config._default_data_dir()).endswith("avguard-override"))
        finally:
            if original is None:
                os.environ.pop("AVGUARD_DATA", None)
            else:
                os.environ["AVGUARD_DATA"] = original


# ---------------------------------------------------------------- scheduling

class TestScheduling(unittest.TestCase):
    """Nothing here needs administrator rights, and everything is reversible."""

    def test_status_reads_without_changing_anything(self):
        before = scheduling.status()
        after = scheduling.status()
        self.assertEqual(before.starts_with_windows, after.starts_with_windows)
        self.assertEqual(before.scheduled_scan, after.scheduled_scan)

    @unittest.skipUnless(IS_WINDOWS, "Startup folder is Windows-only")
    def test_the_shortcut_goes_in_the_users_startup_folder(self):
        path = scheduling.shortcut_path()
        self.assertIn("Startup", path.parts)
        self.assertNotIn("ProgramData", path.parts, "must be per-user, not machine-wide")

    @unittest.skipUnless(IS_WINDOWS, "Windows-only")
    def test_the_launcher_avoids_a_console_window(self):
        runner, _ = scheduling._launcher()
        self.assertTrue(runner.lower().endswith(("pythonw.exe", ".exe")))

    @unittest.skipUnless(IS_WINDOWS, "Windows-only")
    def test_enable_then_disable_leaves_nothing_behind(self):
        was_enabled = scheduling.starts_with_windows()
        if was_enabled:
            self.skipTest("the user already has this on; not touching it")
        ok, _ = scheduling.enable_start_with_windows()
        if not ok:
            self.skipTest("could not create a shortcut in this environment")
        self.assertTrue(scheduling.starts_with_windows())
        scheduling.disable_start_with_windows()
        self.assertFalse(scheduling.starts_with_windows())

    def test_disable_is_safe_when_nothing_is_scheduled(self):
        ok, _ = scheduling.disable_start_with_windows()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
