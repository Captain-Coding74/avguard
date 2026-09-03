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

# Isolate the data directory BEFORE avguard is imported.
#
# config computes DATA_DIR at import time, so this has to happen first. Without
# it, any object built with its default path -- Scanner's Allowlist,
# QuarantineStore's, a PackStore -- reaches into the real
# %LOCALAPPDATA%/AVGuard. The suite silently wrote seven entries into the
# user's live allowlist that way, one of them the hash of SELFTEST_MARKER,
# which then suppressed its own detection and broke four unrelated tests.
#
# Patching each construction was tried first and missed one. Isolating the
# directory is the fix that cannot be missed.
import os as _os
import tempfile as _tempfile

# Per run, not a fixed path: a shared directory accumulates state between
# runs, and a stale allowlist entry from one run silently broke the next.
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



from avguard import config, rulepacks
from avguard.allowlist import Allowlist
from avguard.protection import SelfProtection
from avguard.quarantine import QuarantineStore
from avguard.rulepacks import Admission, PackError, PackStore
from avguard.scanner import Level, ScanCache, Scanner

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

TRIPWIRE = "TRIPWIRE-" + "7f3a2c9e"


# Needles are built by concatenation, like TRIPWIRE. The self-match check now
# walks the whole project including this file, so a literal here would be
# refused for matching the test that wrote it.
def _needle(tag: str) -> str:
    return "zz-" + tag + "-needle"


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-packs-"))
        self.addCleanup(_remove_tree, self.tmp)
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
        # protected_files=[]: a rule this broad also matches the project, and
        # this test is about the corpus measurement, not the self-match.
        admission = self.store.admit("broad", [self.source / "broad.yara"],
                                     self.clean_corpus(20), licence="MIT",
                                     protected_files=[])
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


class TestTheCapAppliesOnEveryPath(TempCase):
    """The guarantee, checked wherever a match can be scored.

    It held for loose files and not for archive members: `_archive_findings`
    was a second copy of the scoring loop, and when the cap was added it went
    into only one of them. A never-promoted pack's `severity = "critical"`
    scored 50 on a loose file and 100 on the identical bytes inside a zip, so
    the file was moved. Archive scanning is on by default and real-time
    watching is aimed at Downloads, so the uncapped path was the likely one.

    The class that was supposed to guard this tested only loose files. These
    tests exist so the next duplicated scoring loop is caught by the suite
    rather than by an audit.
    """

    PAD = b" padding so deflate changes the bytes " * 60

    def setUp(self) -> None:
        super().setUp()
        rule = self.simple_rule(severity="critical")
        admission = self.store.admit("stranger", [rule], self.clean_corpus(),
                                     licence="MIT")
        self.store.install("stranger", [rule], admission, licence="MIT")

    def scanner(self) -> Scanner:
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "nothing"]),
                          cache=ScanCache(path=self.tmp / f"c{id(self)}.json"),
                          packs=self.store)
        scanner.load_rules()
        return scanner

    def payload(self) -> bytes:
        return TRIPWIRE.encode() + self.PAD

    def loose(self) -> Path:
        target = self.tmp / "sample.txt"
        target.write_bytes(self.payload())
        return target

    def zipped(self, depth: int = 1) -> Path:
        import io
        import zipfile
        data = self.payload()
        for level in range(depth):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("sample.txt" if level == 0 else "inner.zip", data)
            data = buffer.getvalue()
        target = self.tmp / f"sample{depth}.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("sample.txt" if depth == 0 else "member.zip", data)
        return target

    def test_the_payload_is_not_visible_in_the_container(self):
        """Otherwise a plain signature match would look like the cap working."""
        self.assertNotIn(TRIPWIRE.encode(), self.zipped(1).read_bytes())

    def test_untrusted_cannot_condemn_a_loose_file(self):
        self.assertFalse(self.scanner().scan(self.loose(), use_cache=False).is_threat)

    def test_untrusted_cannot_condemn_inside_an_archive(self):
        """The case that was broken."""
        verdict = self.scanner().scan(self.zipped(1), use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertFalse(verdict.is_threat,
                         "an unpromoted pack moved a file because it was zipped")

    def test_untrusted_cannot_condemn_deeper_in(self):
        self.assertFalse(self.scanner().scan(self.zipped(2), use_cache=False).is_threat)

    def test_no_finding_from_an_untrusted_pack_is_ever_hard(self):
        for target in (self.loose(), self.zipped(1), self.zipped(2)):
            with self.subTest(target=target.name):
                findings = self.scanner().scan(target, use_cache=False).findings
                yara_findings = [f for f in findings if f.source == "yara"]
                self.assertTrue(yara_findings, "the rule should have matched")
                self.assertFalse(any(f.hard for f in yara_findings))

    def test_promotion_works_on_every_path_too(self):
        """The cap must lift uniformly, or trust would be as patchy as the cap."""
        self.store.set_trusted("stranger", True)
        for target in (self.loose(), self.zipped(1)):
            with self.subTest(target=target.name):
                self.assertTrue(self.scanner().scan(target, use_cache=False).is_threat)

    def test_an_archive_finding_names_the_pack_that_produced_it(self):
        """The archive path dropped the attribution as well as the cap."""
        verdict = self.scanner().scan(self.zipped(1), use_cache=False)
        self.assertIn("stranger", " ".join(verdict.reasons))


class TestSharedStateHasOneOwner(TempCase):
    """Objects that back a file on disk must not be built twice.

    Two failures, one shape. The Scanner and the QuarantineStore each built
    their own Allowlist, so `restore()` recorded a decision in one and `scan()`
    read from the other: in the running GUI a restored file was re-detected on
    the very next scan, which is the exact failure the allowlist exists to
    prevent. `Allowlist.reload()` was written for this and had zero call sites.

    Settings likewise built its own PackStore, so trusting or untrusting a pack
    wrote to disk and the running scanner never saw it. The dangerous direction
    is trusted to reports-only: a user turns a pack off after a false positive
    and it keeps condemning for the rest of the session.

    Both were invisible to the tests because the tests wired the objects
    together themselves -- they exercised an arrangement no entry point builds.
    """

    def test_a_restore_reaches_the_scanner_when_they_share_an_allowlist(self):
        from avguard.scanner import SELFTEST_MARKER
        # One Allowlist, shared between the two -- which is the point of the
        # test -- but isolated from every other test. Using the default meant
        # allowlisting the selftest marker for the whole process, and three
        # unrelated tests then found it CLEAN.
        shared = Allowlist(path=self.tmp / "allow.json")
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "prot"]),
                          cache=ScanCache(path=self.tmp / "c.json"),
                          packs=self.store,
                          allowlist=shared)
        store = QuarantineStore(directory=self.tmp / "q",
                                index_path=self.tmp / "q" / "index.json",
                                protection=SelfProtection([self.tmp / "prot"]),
                                allowlist=scanner.allowlist)
        self.assertIs(store.allowlist, scanner.allowlist)

        target = self.tmp / "kept.bin"
        target.write_bytes(SELFTEST_MARKER)
        record = store.quarantine(target, scanner.scan(target, use_cache=False).reasons)
        restored = store.restore(record.entry_id)

        verdict = scanner.scan(restored, use_cache=False)
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertFalse(verdict.is_threat)

    def test_a_second_allowlist_does_not_see_the_first(self):
        """Pins why sharing is required rather than merely tidy."""
        from avguard.allowlist import Allowlist
        shared = self.tmp / "allow.json"
        first, second = Allowlist(path=shared), Allowlist(path=shared)
        first.add("a" * 64, "thing.bin", ["reason"])
        self.assertIsNone(second.allows("a" * 64),
                          "a separate instance cannot see it without reload")
        second.reload()
        self.assertIsNotNone(second.allows("a" * 64))

    def test_pack_store_reload_picks_up_another_owners_change(self):
        rule = self.simple_rule()
        admission = self.store.admit("stranger", [rule], self.clean_corpus(),
                                     licence="MIT")
        self.store.install("stranger", [rule], admission, licence="MIT")

        other = PackStore(directory=self.store.directory,
                          index_path=self.store.index_path)
        other.set_trusted("stranger", True)

        self.assertFalse(self.store.get("stranger").trusted, "stale, as expected")
        self.store.reload()
        self.assertTrue(self.store.get("stranger").trusted)

    def test_a_mutation_does_not_clobber_another_owners_write(self):
        """set_trusted and remove read before they write."""
        rule = self.simple_rule()
        # protected_files=[]: both packs carry the same needle, so the second
        # would match the first's installed file. That refusal is right and is
        # tested in TestSelfMatchCoversTheWholeProject; this test is about the
        # index.
        admission = self.store.admit("one", [rule], self.clean_corpus(), licence="MIT",
                                     protected_files=[])
        self.store.install("one", [rule], admission, licence="MIT")

        other = PackStore(directory=self.store.directory,
                          index_path=self.store.index_path)
        two = self.rule_file("two.yara", (self.source / "pack.yara").read_text())
        other.install("two", [two],
                      other.admit("two", [two], self.clean_corpus(), licence="MIT",
                                  protected_files=[]),
                      licence="MIT")

        # self.store has never seen "two". Mutating it must not erase it.
        self.store.set_trusted("one", True)
        final = PackStore(directory=self.store.directory,
                          index_path=self.store.index_path)
        self.assertEqual({p.name for p in final.packs()}, {"one", "two"})


class TestABadPackCostsOnlyThatPack(TempCase):
    """load_rules() promised "a bad rule should cost you that rule, not all
    detection", and did not keep it.

    Every rule file was compiled in one yara.compile call, so a single
    unparsable pack file -- a truncated download, an upstream edit, a disk
    error -- aborted the whole thing. self.rules stayed None and every rule
    including the shipped EICAR rule went dark for the session, with only the
    hardcoded byte signatures still firing. Importing one real pack multiplied
    the files able to do that by 310, all maintained by somebody else.

    Verified: with one broken pack file, the shipped EICAR rule stopped
    matching. Compilation is staged now: our own rules first, then each pack
    on its own, and a pack that fails is left out, named, and shown in Health.
    """

    def _install(self, name: str, needle: str) -> None:
        rule = self.rule_file(f"{name}.yara", "\n".join([
            f"rule {name.title()}_Rule {{",
            "  meta:",
            '    description = "d"',
            '    severity = "medium"',
            "  strings:",
            f'    $a = "{needle}"',
            "  condition:",
            "    $a",
            "}",
        ]))
        self.store.install(name, [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")

    def _scanner(self, tag: str) -> Scanner:
        return Scanner(config.Config(cloud_enabled=False),
                       SelfProtection([self.tmp / "nothing"]),
                       cache=ScanCache(path=self.tmp / f"{tag}.json"),
                       packs=self.store,
                       allowlist=Allowlist(path=self.tmp / "allow.json"))

    def _break(self, name: str) -> None:
        (self.store.pack_dir(name) / f"{name}.yara").write_text(
            "rule Broken { this is not yara", encoding="utf-8")

    def test_the_shipped_rules_survive_a_broken_pack(self):
        """The case that was actually broken."""
        from avguard.scanner import EICAR
        self._install("vendor", "zz-vendor-needle")
        self._break("vendor")
        scanner = self._scanner("a")
        self.assertIsNotNone(scanner.rules, "all detection went dark")
        self.assertTrue(scanner.rules.match(data=EICAR),
                        "the shipped EICAR rule must keep firing")

    def test_a_healthy_pack_survives_a_broken_sibling(self):
        self._install("good", "zz-good-needle")
        self._install("bad", "zz-bad-needle")
        self._break("bad")
        scanner = self._scanner("b")
        self.assertTrue(scanner.rules.match(data=b"xx zz-good-needle xx"))

    def test_the_broken_pack_is_named_not_hidden(self):
        """A failure nobody can see is the v1 failure."""
        self._install("vendor", "zz-vendor-needle")
        self._break("vendor")
        scanner = self._scanner("c")
        self.assertIn("vendor", scanner.broken_packs)
        self.assertIn("syntax error", scanner.broken_packs["vendor"])

    def test_the_broken_pack_contributes_no_rules(self):
        self._install("vendor", "zz-vendor-needle")
        self._break("vendor")
        scanner = self._scanner("d")
        self.assertFalse(scanner.rules.match(data=b"xx zz-vendor-needle xx"))

    def test_a_healthy_load_reports_nothing_broken(self):
        self._install("vendor", "zz-vendor-needle")
        self.assertEqual(self._scanner("e").broken_packs, {})

    def test_our_own_rules_failing_is_still_loud(self):
        """Staging must not turn a real failure of OUR rules into a quiet one."""
        bad_rules = self.rule_file("own.yara", "rule Broken { this is not yara")
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "nothing"]),
                          rules_path=bad_rules,
                          cache=ScanCache(path=self.tmp / "f.json"),
                          packs=self.store,
                          allowlist=Allowlist(path=self.tmp / "allow.json"))
        self.assertIsNone(scanner.rules)


class TestEditingAnInstalledPackIsNoticed(TempCase):
    """detection_generation() skipped pack files in favour of the sha256
    recorded at install, which is never re-measured. Edit an installed pack's
    .yara and the scanner compiled the new rules while the generation stayed
    bit-identical -- so every verdict cached under the old rules was replayed
    for the full TTL. That is exactly the failure DETECTION_VERSION exists to
    prevent, reintroduced by a performance tweak.
    """

    def test_an_edited_pack_file_changes_the_generation(self):
        rule = self.simple_rule(needle="zz-original")
        self.store.install("vendor", [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "nothing"]),
                          cache=ScanCache(path=self.tmp / "g.json"),
                          packs=self.store,
                          allowlist=Allowlist(path=self.tmp / "allow.json"))
        before = scanner.detection_generation()

        installed = self.store.pack_dir("vendor") / "pack.yara"
        installed.write_text(installed.read_text(encoding="utf-8")
                             .replace("zz-original", "zz-edited"), encoding="utf-8")

        self.assertNotEqual(before, scanner.detection_generation(),
                            "an edited pack must invalidate the cache")


class TestInstallIsTransactional(TempCase):
    """install() used to rmtree the destination before reading a source byte.

    Three things fell out, all verified before this was written:

      * re-installing a pack from its own directory emptied it and then
        raised, with the index still claiming the pack was there
      * "ReversingLabs 2024" and "ReversingLabs+2024" sanitise to the same
        directory, and the second install silently overwrote the first --
        including its trusted flag
      * a pack that compiled in its source folder via a relative `include`
        was admitted, copied flat, and never compiled again

    Now the pack is staged, compiled FROM the staged copy, and swapped into
    place last. Any failure leaves the previous pack and the index untouched.
    """

    OK = Admission(accepted=True, rule_count=1, corpus_size=1)

    def _rule(self, name: str, needle: str, folder: str = "") -> Path:
        directory = self.source / folder if folder else self.source
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text("\n".join([
            f"rule R_{needle.replace('-', '_')} {{",
            "  meta:",
            '    description = "d"',
            '    severity = "medium"',
            "  strings:",
            f'    $a = "{needle}"',
            "  condition:",
            "    $a",
            "}",
        ]), encoding="utf-8")
        return path

    def test_a_name_collision_is_refused_not_clobbered(self):
        first = self._rule("a.yara", "zz-first")
        self.store.install("ReversingLabs 2024", [first], self.OK, licence="MIT")
        self.store.set_trusted("ReversingLabs 2024", True)

        second = self._rule("b.yara", "zz-second")
        with self.assertRaises(PackError) as caught:
            self.store.install("ReversingLabs+2024", [second], self.OK, licence="MIT")
        self.assertIn("already installed", str(caught.exception))
        self.assertIn("ReversingLabs 2024", str(caught.exception),
                      "the refusal must name what the user actually typed")

        survivor = self.store.packs()
        self.assertEqual(len(survivor), 1)
        self.assertTrue(survivor[0].trusted, "the promoted pack lost its trust flag")
        self.assertEqual([f.name for f in self.store.rule_files_for(survivor[0].name)],
                         ["a.yara"])

    def test_replace_is_an_explicit_choice(self):
        first = self._rule("a.yara", "zz-first")
        self.store.install("vendor", [first], self.OK, licence="MIT")
        second = self._rule("b.yara", "zz-second")
        pack = self.store.install("vendor", [second], self.OK, licence="MIT",
                                  replace=True)
        self.assertEqual([f.name for f in self.store.rule_files_for(pack.name)],
                         ["b.yara"])

    def test_installing_a_pack_over_itself_is_refused(self):
        """Re-installing from the pack's own directory used to empty it."""
        self.store.install("vendor", [self._rule("a.yara", "zz-a")], self.OK,
                           licence="MIT")
        own_files = self.store.rule_files_for("vendor")
        with self.assertRaises(PackError) as caught:
            self.store.install("vendor", own_files, self.OK, licence="MIT",
                               replace=True)
        self.assertIn("over itself", str(caught.exception))
        self.assertEqual([f.name for f in self.store.rule_files_for("vendor")],
                         ["a.yara"], "the pack was emptied")

    def test_a_pack_needing_an_include_is_refused_at_install(self):
        """Admitted in its source folder, it would never compile once copied."""
        (self.source / "lib").mkdir()
        (self.source / "lib" / "base.yar").write_text(
            'rule Base { meta: description="d" strings: $a="' + _needle("base")
            + '" condition: $a }',
            encoding="utf-8")
        main = self.source / "main.yara"
        main.write_text('include "./lib/base.yar"\n'
                        'rule Main { meta: description="d" strings: $a="'
                        + _needle("main") + '" condition: $a }', encoding="utf-8")

        admission = self.store.admit("inc", [main], self.clean_corpus(), licence="MIT")
        self.assertTrue(admission.accepted, "it does compile where it lives")

        with self.assertRaises(PackError) as caught:
            self.store.install("inc", [main], admission, licence="MIT")
        self.assertIn("does not compile once installed", str(caught.exception))
        self.assertIsNone(self.store.get("inc"))
        self.assertFalse(self.store.pack_dir("inc").exists(),
                         "a refused install must leave nothing behind")

    def test_a_failed_replace_leaves_the_previous_pack_intact(self):
        good = self._rule("a.yara", "zz-good")
        self.store.install("vendor", [good], self.OK, licence="MIT")
        self.store.set_trusted("vendor", True)

        broken = self.source / "broken.yara"
        broken.write_text('include "./nowhere.yar"\nrule X { condition: true }',
                          encoding="utf-8")
        with self.assertRaises(PackError):
            self.store.install("vendor", [broken], self.OK, licence="MIT",
                               replace=True)

        pack = self.store.get("vendor")
        self.assertIsNotNone(pack)
        self.assertTrue(pack.trusted)
        self.assertEqual([f.name for f in self.store.rule_files_for("vendor")],
                         ["a.yara"])

    def test_duplicate_basenames_are_refused(self):
        one = self._rule("x.yara", "zz-one", folder="a")
        two = self._rule("x.yara", "zz-two", folder="b")
        with self.assertRaises(PackError) as caught:
            self.store.install("vendor", [one, two], self.OK, licence="MIT")
        self.assertIn("both be installed as", str(caught.exception))

    def test_the_typed_name_is_kept_beside_the_safe_one(self):
        pack = self.store.install("ReversingLabs 2024", [self._rule("a.yara", "zz-a")],
                                  self.OK, licence="MIT")
        self.assertEqual(pack.display_name, "ReversingLabs 2024")
        self.assertNotEqual(pack.name, pack.display_name)

    def test_no_staging_directory_is_left_behind(self):
        self.store.install("vendor", [self._rule("a.yara", "zz-a")], self.OK,
                           licence="MIT")
        leftovers = [d.name for d in self.store.directory.iterdir()
                     if d.name.startswith(".")]
        self.assertEqual(leftovers, [])


# --------------------------------------------- the cheap fixes from the audit

class TestCloudIsAskedUnlessSomethingHardDecided(TempCase):
    """The VirusTotal lookup ran only when the local verdict was CLEAN.

    One capped 50-point finding from an unpromoted pack made a file
    SUSPICIOUS, so the cloud was never asked, and a sample VirusTotal would
    have condemned was left alone. Installing a reports-only pack REDUCED
    detection. "Reports only" must not mean "silences the engine that was
    going to condemn it".
    """

    def _scanner(self, trusted: bool, cloud_calls: list) -> Scanner:
        rule = self.rule_file("pack.yara", "\n".join([
            "rule Imported {",
            "  meta:",
            '    description = "d"',
            '    severity = "critical"',
            "  strings:",
            f'    $a = "{TRIPWIRE}"',
            "  condition:",
            "    $a",
            "}",
        ]))
        self.store.install("stranger", [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        if trusted:
            self.store.set_trusted("stranger", True)

        def cloud(sha256: str, path: Path) -> list[str]:
            cloud_calls.append(sha256)
            return ["VirusTotal: 9 of 70 engines flagged this file"]

        cfg = config.Config(cloud_enabled=True, cloud_extensions=[".exe"])
        return Scanner(cfg, SelfProtection([self.tmp / "nothing"]),
                       cache=ScanCache(path=self.tmp / "c.json"),
                       packs=self.store,
                       allowlist=Allowlist(path=self.tmp / "allow.json"),
                       cloud_lookup=cloud)

    def test_a_reports_only_hit_does_not_silence_the_cloud(self):
        calls: list = []
        scanner = self._scanner(trusted=False, cloud_calls=calls)
        target = self.tmp / "sample.exe"
        target.write_bytes(TRIPWIRE.encode() + b" " * 64)
        verdict = scanner.scan(target, use_cache=False)
        self.assertEqual(len(calls), 1, "the cloud was never asked")
        self.assertIs(verdict.level, Level.MALICIOUS,
                      "cloud consensus is hard evidence and must still condemn")

    def test_hard_local_evidence_does_not_waste_a_cloud_call(self):
        calls: list = []
        scanner = self._scanner(trusted=True, cloud_calls=calls)
        target = self.tmp / "sample.exe"
        target.write_bytes(TRIPWIRE.encode() + b" " * 64)
        scanner.scan(target, use_cache=False)
        self.assertEqual(calls, [], "already decided locally; the budget is finite")


class TestMalformedDataFilesDoNotKillStartup(TempCase):
    """A JSON array where an object was expected raised AttributeError out of
    Scanner.__init__ -- so out of the GUI constructor and every CLI verb.
    Under pythonw the user saw nothing. A bad file is an empty list."""

    def test_an_allowlist_that_is_a_list_loads_empty(self):
        path = self.tmp / "allow.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        self.assertEqual(len(Allowlist(path=path)), 0)

    def test_a_pack_index_that_is_a_number_loads_empty(self):
        index = self.tmp / "p" / "packs.json"
        index.parent.mkdir()
        index.write_text("42", encoding="utf-8")
        self.assertEqual(PackStore(directory=self.tmp / "p", index_path=index).packs(), [])

    def test_a_non_object_entry_is_dropped_not_fatal(self):
        path = self.tmp / "allow.json"
        path.write_text('{"a": [1], "b": {"sha256": "b", "name": "ok"}}', encoding="utf-8")
        allow = Allowlist(path=path)
        self.assertIsNone(allow.allows("a"))
        self.assertIsNotNone(allow.allows("b"))

    def test_a_wrongly_typed_field_does_not_crash_scan(self):
        """`"added_at": 12345` loaded fine and crashed scan() on `.when`."""
        path = self.tmp / "allow.json"
        path.write_text('{"h": {"sha256": "h", "name": "x", "added_at": 12345, '
                        '"was_flagged_for": "not-a-list"}}', encoding="utf-8")
        entry = Allowlist(path=path).allows("h")
        self.assertIsNotNone(entry)
        self.assertIsInstance(entry.when, str)
        self.assertEqual(entry.was_flagged_for, [])


class TestThePackAsAWholeHasACeiling(TempCase):
    """120 narrow rules at 0.83% each flagged every clean file and were
    admitted with "no rule over the ceiling". The aggregate was computed,
    printed, and compared to nothing."""

    def test_many_narrow_rules_that_together_flag_everything_are_refused(self):
        corpus = []
        body = []
        for index in range(120):
            needle = _needle(f"clean{index}")
            path = self.tmp / f"clean{index}.bin"
            path.write_bytes(f"ordinary content {needle} ".encode() * 40)
            corpus.append(path)
            body.append(f"rule Narrow_{index} {{ meta: description = \"d\" "
                        f"strings: $a = \"{needle}\" condition: $a }}")
        pack = self.rule_file("narrow.yara", "\n".join(body))
        admission = self.store.admit("narrow", [pack], corpus, licence="MIT")
        self.assertFalse(admission.accepted)
        self.assertIn("pack as a whole", " ".join(admission.reasons))
        # Every single rule is under the per-rule ceiling; that is the point.
        self.assertLess(1 / 120, rulepacks.MAX_FALSE_POSITIVE_RATE)


class TestRuleCountComesFromTheCompiler(TempCase):
    def test_a_commented_out_rule_is_not_counted(self):
        pack = self.rule_file("pack.yara", "\n".join([
            "/* rule Fake_One { condition: true } */",
            "// rule Fake_Two { condition: true }",
            f"rule Real {{ meta: description = \"d\" strings: $a = \"{_needle('real')}\" "
            "condition: $a }",
        ]))
        admission = self.store.admit("counted", [pack], self.clean_corpus(), licence="MIT")
        self.assertTrue(admission.accepted, admission.reasons)
        self.assertEqual(admission.rule_count, 1)


class TestSelfMatchCoversTheWholeProject(TempCase):
    """The check walked rules/, avguard/ and docs/ only."""

    def test_a_rule_matching_a_file_outside_those_three_dirs_is_refused(self):
        # This very test file lives in tests/, which the old walk never saw.
        pack = self.rule_file("pack.yara",
                              "rule Hits_Tests { meta: description = \"d\" "
                              "strings: $a = \"class TestSelfMatchCoversTheWholeProject\" "
                              "condition: $a }")
        admission = self.store.admit("tests", [pack], self.clean_corpus(), licence="MIT")
        self.assertFalse(admission.accepted)
        self.assertIn("matches AVGuard", " ".join(admission.reasons))

    def test_a_rule_matching_another_installed_pack_is_refused(self):
        first = self.rule_file("first.yara",
                               "rule First { meta: description = \"d\" "
                               f"strings: $a = \"{_needle('first')}\" condition: $a }}")
        self.store.install("first", [first],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        # The second pack's rule matches text that appears in the first pack's
        # rule FILE. Loading both would make the first pack a detection.
        second = self.rule_file("second.yara",
                                "rule Second { meta: description = \"d\" "
                                f"strings: $a = \"{_needle('first')[:-3]}\" condition: $a }}")
        admission = self.store.admit("second", [second], self.clean_corpus(), licence="MIT")
        self.assertFalse(admission.accepted)
        self.assertIn("first.yara", " ".join(admission.reasons))

    def test_a_pack_is_not_refused_for_matching_its_own_files_on_verify(self):
        """A pack legitimately contains the strings it hunts for."""
        rule = self.rule_file("own.yara",
                              "rule Own { meta: description = \"d\" "
                              f"strings: $a = \"{_needle('own')}\" condition: $a }}")
        self.store.install("own", [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        files = rulepacks._avguard_files(packs_dir=self.store.directory,
                                         exclude=self.store.pack_dir("own"))
        self.assertTrue(files, "the walk found nothing at all")
        self.assertFalse(any(self.store.pack_dir("own") in f.parents for f in files))
        # And re-admission of the installed copy passes for the same reason.
        again = self.store.admit("own", self.store.rule_files_for("own"),
                                 self.clean_corpus(), licence="MIT")
        self.assertTrue(again.accepted, again.reasons)


class TestStrayArgumentsAreRefused(unittest.TestCase):
    """`--packs --licence MIT add folder` listed packs and exited 0. `scan C:/x`
    launched the GUI with nothing scanned. A word the parser cannot place is
    a mistake to name, not to swallow."""

    def test_a_bare_command_word_is_an_error(self):
        import avguard.__main__ as cli
        with self.assertRaises(SystemExit) as caught:
            cli.main(["scan", "C:/nowhere"])
        self.assertEqual(caught.exception.code, 2)

    def test_list_with_leftovers_is_an_error(self):
        import io
        import contextlib
        import avguard.__main__ as cli
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(["--packs", "--licence", "MIT", "add", "somewhere"])
        self.assertEqual(code, 2)
        self.assertIn("unexpected", err.getvalue())


class TestHealthCountsWhatLoaded(TempCase):
    """The GUI summed rule_count from the index. A pack whose directory had been
    deleted still reported its rules as loaded. The facts the Health view now
    derives from are checked here, where tkinter is not needed."""

    def _scanner(self) -> Scanner:
        return Scanner(config.Config(cloud_enabled=False),
                       SelfProtection([self.tmp / "nothing"]),
                       cache=ScanCache(path=self.tmp / "c.json"),
                       packs=self.store,
                       allowlist=Allowlist(path=self.tmp / "allow.json"))

    def test_loaded_count_matches_the_compiled_ruleset(self):
        rule = self.simple_rule()
        self.store.install("vendor", [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        scanner = self._scanner()
        self.assertEqual(scanner.pack_rule_counts.get("vendor"), 1)
        self.assertNotIn("vendor", scanner.broken_packs)

    def test_a_vanished_pack_directory_loads_nothing(self):
        import shutil
        rule = self.simple_rule()
        self.store.install("vendor", [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        shutil.rmtree(self.store.pack_dir("vendor"))
        scanner = self._scanner()
        self.assertEqual(self.store.rule_files_for("vendor"), [])
        self.assertNotIn("vendor", scanner.pack_rule_counts)
        self.assertIsNotNone(scanner.rules, "the shipped rules must still load")
        self.assertEqual(self.store.get("vendor").rule_count, 1,
                         "the index still claims a rule; Health must not repeat it")


class TestVerifyReportsWhatItMeasured(unittest.TestCase):
    """`--packs verify` printed "OVER THE CEILING (0.00% of 400 flagged)" for
    a pack that had failed to COMPILE -- a rate it never measured, blamed on
    the wrong check -- and left the pack trusted. Exit 1 with no change of
    state is a complaint; a failing pack must be disarmed."""

    def setUp(self):
        import shutil
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-verify-"))
        self.addCleanup(_remove_tree, self.tmp)
        # The CLI builds its own PackStore on the per-process test data dir.
        self.store = rulepacks.PackStore()
        self.addCleanup(self._remove_pack)

    def _remove_pack(self):
        store = rulepacks.PackStore()
        if store.get("verifyme") is not None:
            store.remove("verifyme")

    def _corpus(self) -> list[Path]:
        files = []
        for index in range(3):
            path = self.tmp / f"clean{index}.bin"
            path.write_bytes(b"ordinary content " * 50)
            files.append(path)
        return files

    def test_a_pack_that_no_longer_compiles_is_named_and_disarmed(self):
        import contextlib
        import io
        from unittest import mock
        import avguard.__main__ as cli

        rule = self.tmp / "v.yara"
        rule.write_text('rule V { meta: description="d" strings: $a="'
                        + _needle("verify") + '" condition: $a }', encoding="utf-8")
        admission = self.store.admit("verifyme", [rule], self._corpus(), licence="MIT")
        self.assertTrue(admission.accepted, admission.reasons)
        self.store.install("verifyme", [rule], admission, licence="MIT")
        self.store.set_trusted("verifyme", True)

        installed = self.store.rule_files_for("verifyme")[0]
        installed.write_text(installed.read_text(encoding="utf-8")
                             + "\nrule Broken { condition: ", encoding="utf-8")

        out = io.StringIO()
        with mock.patch.object(cli, "_clean_corpus", return_value=self._corpus()), \
                contextlib.redirect_stdout(out):
            code = cli.main(["--packs", "verify"])
        text = out.getvalue()

        self.assertEqual(code, 1)
        self.assertIn("FAILED", text)
        self.assertIn("does not compile", text, "the real cause is named")
        self.assertNotIn("0.00%", text, "no rate was measured, so none is printed")
        self.assertFalse(rulepacks.PackStore().get("verifyme").trusted,
                         "a failing pack must not stay armed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
