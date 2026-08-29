"""Rule packs: admitting detection rules somebody else wrote.

The point of these tests is the refusals. Admitting a good pack is easy; the
value is that a bad one cannot get in, and that even a good one cannot move a
file until it is promoted by name.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import logging
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from avguard import config, rulepacks
from avguard.protection import SelfProtection
from avguard.rulepacks import Admission, PackError, PackStore
from avguard.scanner import Level, ScanCache, Scanner

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

TRIPWIRE = "TRIPWIRE-" + "7f3a2c9e"


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-packs-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = PackStore(directory=self.tmp / "packs",
                               index_path=self.tmp / "packs" / "packs.json")
        self.source = self.tmp / "src"
        self.source.mkdir()

    def rule_file(self, name: str, body: str) -> Path:
        path = self.source / name
        path.write_text(body, encoding="utf-8")
        return path

    def simple_rule(self, name: str = "pack.yara", severity: str = "medium",
                    needle: str = TRIPWIRE) -> Path:
        return self.rule_file(name, "\n".join([
            "rule Imported_Test_Rule {",
            "  meta:",
            '    description = "a rule from somebody else"',
            f'    severity = "{severity}"',
            "  strings:",
            f'    $a = "{needle}"',
            "  condition:",
            "    $a",
            "}",
        ]))

    def clean_corpus(self, count: int = 6) -> list[Path]:
        """Files that must not be flagged, standing in for real software."""
        corpus = []
        for index in range(count):
            path = self.tmp / f"clean{index}.bin"
            path.write_bytes(b"ordinary content %d " % index * 200)
            corpus.append(path)
        return corpus


# ------------------------------------------------------------- the refusals

class TestPackRefusals(TempCase):

    def test_a_pack_that_does_not_compile_is_refused(self):
        self.rule_file("broken.yara", "rule Broken { this is not yara }")
        admission = self.store.admit("broken", [self.source / "broken.yara"],
                                     self.clean_corpus(), licence="MIT")
        self.assertFalse(admission.accepted)
        self.assertIn("compile", " ".join(admission.reasons))

    def test_a_pack_with_an_unknown_licence_is_refused(self):
        """This repository is MIT; quietly vendoring incompatible rules would
        become the problem of anyone who forks it."""
        admission = self.store.admit("nolicence", [self.simple_rule()],
                                     self.clean_corpus(), licence="")
        self.assertFalse(admission.accepted)
        self.assertIn("licence", " ".join(admission.reasons))

    def test_a_copyleft_licence_is_refused(self):
        admission = self.store.admit("gpl", [self.simple_rule()],
                                     self.clean_corpus(), licence="GPL-3.0")
        self.assertFalse(admission.accepted)

    def test_an_over_broad_pack_is_refused_with_its_measurement(self):
        """The check that matters. A rule firing on ordinary software is
        exactly what must never reach the scanner."""
        self.rule_file("broad.yara", "\n".join([
            "rule Fires_On_Everything {",
            "  meta:",
            '    description = "matches ordinary content"',
            '    severity = "high"',
            "  strings:",
            '    $a = "ordinary content"',
            "  condition:",
            "    $a",
            "}",
        ]))
        admission = self.store.admit("broad", [self.source / "broad.yara"],
                                     self.clean_corpus(20), licence="MIT")
        self.assertFalse(admission.accepted)
        self.assertIn("false-positive ceiling", " ".join(admission.reasons))
        self.assertIn("Fires_On_Everything", admission.offending)
        self.assertGreater(admission.false_positive_rate, 0)

    def test_a_pack_matching_avguard_itself_is_refused(self):
        """v1 quarantined its own ruleset. An imported pack must not be able
        to recreate that from the outside."""
        marker = (config.PROJECT_ROOT / "rules" / "malware.yara")
        self.rule_file("selfmatch.yara", "\n".join([
            "rule Matches_Our_Own_Rules {",
            "  meta:",
            '    description = "matches AVGuard files"',
            '    severity = "high"',
            "  strings:",
            '    $a = "Eicar_Test_File"',
            "  condition:",
            "    $a",
            "}",
        ]))
        admission = self.store.admit(
            "selfmatch", [self.source / "selfmatch.yara"], self.clean_corpus(),
            licence="MIT", protected_files=[marker])
        self.assertFalse(admission.accepted)
        self.assertIn("matches AVGuard", " ".join(admission.reasons))

    def test_an_empty_pack_is_refused(self):
        admission = self.store.admit("empty", [], self.clean_corpus(), licence="MIT")
        self.assertFalse(admission.accepted)

    def test_a_pack_is_refused_when_there_is_nothing_to_measure_against(self):
        """Admitting rules nobody has checked is how this goes wrong."""
        admission = self.store.admit("unmeasured", [self.simple_rule()],
                                     corpus=[], licence="MIT")
        self.assertFalse(admission.accepted)
        self.assertIn("no clean files", " ".join(admission.reasons))

    def test_a_refused_pack_writes_nothing(self):
        before = set(self.store.directory.rglob("*"))
        self.store.admit("nolicence", [self.simple_rule()],
                         self.clean_corpus(), licence="")
        self.assertEqual(set(self.store.directory.rglob("*")), before)

    def test_installing_a_refused_pack_raises(self):
        with self.assertRaises(PackError):
            self.store.install("x", [self.simple_rule()],
                               Admission(accepted=False), licence="MIT")


# ------------------------------------------------------- admitting and trust

class TestPackLifecycle(TempCase):

    def admit_and_install(self, severity: str = "medium") -> None:
        rule = self.simple_rule(severity=severity)
        admission = self.store.admit("stranger", [rule], self.clean_corpus(),
                                     source="a folder", licence="MIT")
        self.assertTrue(admission.accepted, admission.reasons)
        return self.store.install("stranger", [rule], admission,
                                  source="a folder", licence="MIT")

    def test_a_good_pack_is_admitted(self):
        pack = self.admit_and_install()
        self.assertEqual(pack.rule_count, 1)
        self.assertEqual(pack.licence, "MIT")

    def test_a_new_pack_is_never_trusted(self):
        self.assertFalse(self.admit_and_install(severity="critical").trusted)

    def test_the_measurement_is_recorded(self):
        pack = self.admit_and_install()
        self.assertGreater(pack.corpus_size, 0)
        self.assertEqual(pack.false_positive_rate, 0.0)
        self.assertTrue(pack.notes)

    def test_an_untrusted_pack_contributes_untrusted_namespaces(self):
        self.admit_and_install()
        self.assertEqual(len(self.store.untrusted_namespaces()), 1)

    def test_promotion_clears_the_cap(self):
        self.admit_and_install()
        self.store.set_trusted("stranger", True)
        self.assertEqual(self.store.untrusted_namespaces(), set())

    def test_promotion_can_be_taken_back(self):
        self.admit_and_install()
        self.store.set_trusted("stranger", True)
        self.store.set_trusted("stranger", False)
        self.assertEqual(len(self.store.untrusted_namespaces()), 1)

    def test_removing_a_pack_deletes_its_rules(self):
        self.admit_and_install()
        self.assertTrue(self.store.remove("stranger"))
        self.assertEqual(self.store.packs(), [])
        self.assertEqual(self.store.rule_files(), [])

    def test_removing_something_absent_is_not_an_error(self):
        self.assertFalse(self.store.remove("never-existed"))

    def test_promoting_something_absent_raises(self):
        with self.assertRaises(PackError):
            self.store.set_trusted("never-existed", True)

    def test_the_index_survives_a_restart(self):
        self.admit_and_install()
        reopened = PackStore(directory=self.store.directory,
                             index_path=self.store.index_path)
        self.assertEqual(len(reopened.packs()), 1)

    def test_a_corrupt_index_does_not_break_startup(self):
        self.store.index_path.parent.mkdir(parents=True, exist_ok=True)
        self.store.index_path.write_text("{ not json")
        reopened = PackStore(directory=self.store.directory,
                             index_path=self.store.index_path)
        self.assertEqual(reopened.packs(), [])

    def test_a_hostile_pack_name_cannot_escape_the_directory(self):
        rule = self.simple_rule()
        admission = self.store.admit("../../escape", [rule], self.clean_corpus(),
                                     licence="MIT")
        pack = self.store.install("../../escape", [rule], admission, licence="MIT")
        self.assertTrue(
            self.store.pack_dir(pack.name).resolve().is_relative_to(
                self.store.directory.resolve()))


# ----------------------------------------------- what the scanner does with it

class TestImportedRulesCannotCondemn(TempCase):
    """The guarantee the whole feature rests on.

    A third-party severity follows conventions this program knows nothing
    about. Treating somebody else's "critical" as decisive would hand a
    stranger the power to delete things here.
    """

    def setUp(self) -> None:
        super().setUp()
        self.data = self.tmp / "data"
        self.target = self.tmp / "victim.txt"
        self.target.write_text(f"harmless text {TRIPWIRE} more text", encoding="utf-8")

    def scanner_with(self, trusted: bool) -> Scanner:
        rule = self.simple_rule(severity="critical")
        admission = self.store.admit("stranger", [rule], self.clean_corpus(),
                                     licence="MIT")
        self.store.install("stranger", [rule], admission, licence="MIT")
        if trusted:
            self.store.set_trusted("stranger", True)

        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "nothing"]),
                          cache=ScanCache(path=self.tmp / "c.json"))
        scanner.packs = self.store
        scanner.load_rules()
        return scanner

    def test_an_untrusted_critical_rule_only_reports(self):
        verdict = self.scanner_with(trusted=False).scan(self.target, use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertFalse(verdict.is_threat,
                         "a stranger's rule must not be able to move a file")

    def test_a_promoted_pack_can_condemn(self):
        verdict = self.scanner_with(trusted=True).scan(self.target, use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)

    def test_the_verdict_says_which_pack_found_it(self):
        verdict = self.scanner_with(trusted=False).scan(self.target, use_cache=False)
        self.assertIn("stranger", " ".join(verdict.reasons))

    def test_no_finding_from_an_untrusted_pack_is_hard(self):
        verdict = self.scanner_with(trusted=False).scan(self.target, use_cache=False)
        imported = [f for f in verdict.findings if f.source == "yara"]
        self.assertTrue(imported)
        self.assertFalse(any(f.hard for f in imported))

    def test_installing_a_pack_changes_the_cache_generation(self):
        """A cached verdict computed before a pack arrived is stale."""
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "nothing"]),
                          cache=ScanCache(path=self.tmp / "c.json"))
        scanner.packs = self.store
        before = scanner.detection_generation()

        rule = self.simple_rule()
        admission = self.store.admit("stranger", [rule], self.clean_corpus(),
                                     licence="MIT")
        self.store.install("stranger", [rule], admission, licence="MIT")
        self.assertNotEqual(before, scanner.detection_generation())


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPackReporting(TempCase):
    """What the interface says about packs, checked without opening a window.

    The Health view said "compiled from malware.yara" while 311 files and 1,240
    imported rules were loaded, and a GUI-only user had no way to learn that a
    pack was installed at all, let alone that it was reports-only. The window
    that exists to answer "is detection working" was answering it wrongly by
    omission.

    These test the strings, not the widgets: the logic is what was wrong, and
    it can be checked where tkinter is not installed.
    """

    def install(self, trusted: bool = False, rules: int = 3):
        rule = self.simple_rule()
        admission = self.store.admit("stranger", [rule], self.clean_corpus(),
                                     licence="MIT")
        pack = self.store.install("stranger", [rule], admission, licence="MIT")
        pack.rule_count = rules
        if trusted:
            self.store.set_trusted("stranger", True)
        return self.store.get("stranger")

    def test_a_pack_describes_its_trust_state(self):
        self.assertIn("reports only", self.install(trusted=False).describe())
        self.store.set_trusted("stranger", True)
        self.assertIn("trusted", self.store.get("stranger").describe())

    def test_a_pack_describes_what_it_was_measured_at(self):
        pack = self.install()
        self.assertIn("clean files", pack.describe())
        self.assertIn(f"{pack.corpus_size}", pack.describe())

    def test_an_untrusted_pack_says_so_prominently(self):
        """A user who thinks they are protected by a pack that reports only
        is worse off than one who knows they are not."""
        description = self.install(trusted=False).describe()
        self.assertNotIn("trusted", description.replace("reports only", ""))

    def test_the_store_reports_nothing_installed_honestly(self):
        self.assertEqual(self.store.packs(), [])
        self.assertEqual(self.store.rule_files(), [])
        self.assertEqual(self.store.untrusted_namespaces(), set())

    def test_rule_counts_survive_a_restart(self):
        self.install(rules=3)
        reopened = PackStore(directory=self.store.directory,
                             index_path=self.store.index_path)
        self.assertEqual(len(reopened.packs()), 1)
        self.assertGreater(reopened.packs()[0].rule_count, 0)
