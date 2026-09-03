"""A harness for the detection rules themselves.

This exists because of two measured failures.

v1's ruleset listed its indicators as plain strings, so it matched its own file.
The scanner quarantined the rules, YARA stopped compiling, and detection was
silently off for weeks.

v2's ruleset then flagged `kernel32.dll` and three ordinary CI scripts as
malicious. Both got through because the rules were checked against a handful of
hand-written samples, and a handful of samples cannot tell you a rule is
over-broad. Only a corpus can.

So this harness measures instead of asserting:

    * every rule declares severity and description
    * no rule matches AVGuard's own files
    * every sample in rules/must_match is caught by the rule that claims it
    * every sample in rules/must_not_match stays clean
    * a corpus of real binaries from this machine bounds the false-positive rate

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import os
import random
import re
import sys
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



import yara

from avguard import config
from avguard.protection import SelfProtection
from avguard.scanner import (
    EICAR, SEVERITY_WEIGHTS, Level, ScanCache, Scanner, decide, Finding,
)

# Samples that cannot live on disk, because a real antivirus deletes them
# before the test can read them. EICAR is the obvious one: writing it as a
# fixture file made this suite fail with "Invalid argument" on a machine
# running Defender. Held in memory and matched with data=.
VIRTUAL_MUST_MATCH: dict[str, bytes] = {
    "Eicar_Test_File": EICAR,
}

PROJECT = Path(__file__).resolve().parent.parent
RULES_PATH = PROJECT / "rules" / "malware.yara"
FIXTURES = Path(__file__).resolve().parent / "rules"

# Ceiling for the share of real, clean binaries any single rule may match.
# Nothing is auto-quarantined below MALICIOUS, but a rule that fires on more
# than this is noise rather than signal.
MAX_FALSE_POSITIVE_RATE = 0.01      # 1%

# No clean file may ever reach MALICIOUS. This one is absolute.
MAX_MALICIOUS_RATE = 0.0

CORPUS_ROOTS = [
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),
]
CORPUS_SIZE = 400
CORPUS_MAX_BYTES = 16 * 1024 * 1024


def _rule_names(text: str) -> list[str]:
    """Non-private rules declared in the ruleset."""
    return [
        m.group(1)
        for m in re.finditer(r"^(?!\s*private\s)(?:\s*)rule\s+(\w+)", text, re.MULTILINE)
    ]


def _private_rule_names(text: str) -> set[str]:
    return {m.group(1) for m in re.finditer(r"^\s*private\s+rule\s+(\w+)", text, re.MULTILINE)}


def _collect_corpus(limit: int = CORPUS_SIZE) -> list[Path]:
    """A sample of real executables from this machine.

    Deliberately drawn from the running system rather than checked in: the
    point is to be surprised by software nobody thought to write a fixture for.
    Sampled deterministically so a failure is reproducible.
    """
    found: list[Path] = []
    for root in CORPUS_ROOTS:
        if not root.is_dir():
            continue
        taken = 0
        for dirpath, dirnames, filenames in os.walk(root):
            for name in filenames:
                if not name.lower().endswith((".exe", ".dll")):
                    continue
                path = Path(dirpath) / name
                try:
                    if path.stat().st_size > CORPUS_MAX_BYTES:
                        continue
                except OSError:
                    continue
                found.append(path)
                taken += 1
            if taken > limit:
                break
    random.Random(20240607).shuffle(found)
    return found[:limit]


class TestRuleContract(unittest.TestCase):
    """Every rule must describe itself, because the score depends on it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = RULES_PATH.read_text(encoding="utf-8")
        cls.rules = yara.compile(filepath=str(RULES_PATH))
        cls.names = _rule_names(cls.text)
        cls.private = _private_rule_names(cls.text)

    def test_ruleset_compiles(self):
        self.assertIsNotNone(self.rules)

    def test_there_are_rules_to_test(self):
        self.assertGreater(len(self.names), 0)

    def test_every_rule_declares_a_known_severity(self):
        """An unlabelled rule silently scores 25 and can never act.

        Better to fail here than to ship a rule whose author thought it was
        decisive and whose weight says otherwise.
        """
        for name in self.names:
            if name in self.private:
                continue
            body = self._body(name)
            with self.subTest(rule=name):
                found = re.search(r'severity\s*=\s*"([^"]+)"', body)
                self.assertIsNotNone(found, f"rule {name} declares no severity")
                self.assertIn(found.group(1).lower(), SEVERITY_WEIGHTS,
                              f"rule {name} uses an unknown severity {found.group(1)!r}")

    def test_every_rule_declares_a_description(self):
        """The description is what the user is shown instead of a rule name."""
        for name in self.names:
            if name in self.private:
                continue
            with self.subTest(rule=name):
                self.assertRegex(self._body(name), r'description\s*=\s*"[^"]+"')

    def _body(self, name: str) -> str:
        start = self.text.index(f"rule {name}")
        nxt = self.text.find("\nrule ", start + 1)
        return self.text[start:nxt if nxt != -1 else len(self.text)]


class TestRulesDoNotMatchOurselves(unittest.TestCase):
    """v1 quarantined its own ruleset and lost detection entirely."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = yara.compile(filepath=str(RULES_PATH))

    def test_no_rule_matches_any_avguard_file(self):
        checked = 0
        for folder in ("rules", "avguard", "docs", "tests"):
            base = PROJECT / folder
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                if path.parent.name in ("must_match",):
                    continue          # these are supposed to match
                checked += 1
                with self.subTest(path=str(path.relative_to(PROJECT))):
                    matched = [m.rule for m in self.rules.match(data=path.read_bytes())]
                    self.assertEqual(matched, [], f"{path} matches its own rules")
        self.assertGreater(checked, 5, "the self-match check scanned almost nothing")


class TestFixtures(unittest.TestCase):
    """Samples on disk, named for the rule they are expected to exercise."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = yara.compile(filepath=str(RULES_PATH))

    def test_virtual_samples_are_caught(self):
        """Samples kept in memory because Defender deletes them from disk."""
        for rule_name, payload in VIRTUAL_MUST_MATCH.items():
            with self.subTest(rule=rule_name):
                matched = [m.rule for m in self.rules.match(data=payload)]
                self.assertIn(rule_name, matched)

    def test_every_rule_has_at_least_one_positive_sample(self):
        """A rule nothing exercises is a rule nobody knows still works."""
        text = RULES_PATH.read_text(encoding="utf-8")
        declared = set(_rule_names(text)) - _private_rule_names(text)
        covered = set(VIRTUAL_MUST_MATCH)
        for path in (FIXTURES / "must_match").glob("*"):
            if path.is_file():
                covered.add(path.name.split("__")[0])
        missing = declared - covered
        self.assertEqual(missing, set(),
                         f"these rules have no must_match sample: {sorted(missing)}")

    def test_must_match_samples_are_caught(self):
        folder = FIXTURES / "must_match"
        samples = sorted(p for p in folder.glob("*") if p.is_file())
        self.assertTrue(samples, f"no samples in {folder}")
        for path in samples:
            # Filename convention: <RuleName>__<anything>.<ext>
            expected = path.name.split("__")[0]
            with self.subTest(sample=path.name):
                matched = [m.rule for m in self.rules.match(data=path.read_bytes())]
                self.assertIn(expected, matched,
                              f"{path.name} should have matched {expected}, got {matched}")

    @unittest.skipUnless(Path(r"C:\Windows\System32\kernel32.dll").exists(),
                         "needs Windows")
    def test_the_live_system_kernel32_stays_clean(self):
        """The false positive that forced the export-table exclusion.

        Read from the running system rather than from a committed copy: a
        verbatim Microsoft binary does not belong in this repository, and the
        live file is the one that actually matters anyway.
        """
        target = Path(r"C:\Windows\System32\kernel32.dll")
        matched = [m.rule for m in self.rules.match(filepath=str(target), timeout=30)]
        self.assertEqual(matched, [],
                         f"kernel32.dll matched {matched}; it exports the very APIs "
                         "the injection rule hunts for")

    def test_must_not_match_samples_stay_clean(self):
        folder = FIXTURES / "must_not_match"
        samples = sorted(p for p in folder.glob("*") if p.is_file())
        self.assertTrue(samples, f"no samples in {folder}")
        for path in samples:
            with self.subTest(sample=path.name):
                matched = [m.rule for m in self.rules.match(data=path.read_bytes())]
                self.assertEqual(matched, [],
                                 f"{path.name} is benign but matched {matched}")


class TestBenignCorpus(unittest.TestCase):
    """The check a handful of fixtures cannot do.

    Both of the false positives this project has shipped -- v1's rules matching
    prose, and v2's rules matching kernel32.dll -- would have been caught here
    the first time the harness ran.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = _collect_corpus()
        cls.rules = yara.compile(filepath=str(RULES_PATH))
        cls.scanner = Scanner(
            config.Config(cloud_enabled=False),
            SelfProtection([PROJECT]),
            rules_path=RULES_PATH,
            cache=ScanCache(path=Path(os.devnull + ".nope")),
        )

    def test_corpus_was_found(self):
        if not self.corpus:
            self.skipTest("no Windows binaries available to sample")
        self.assertGreater(len(self.corpus), 50)

    def test_no_clean_binary_is_ever_called_malicious(self):
        """The one absolute rule: nothing here may be auto-quarantined."""
        if not self.corpus:
            self.skipTest("no corpus")
        malicious = []
        for path in self.corpus:
            try:
                verdict = self.scanner.scan(path, use_cache=False)
            except Exception:
                continue
            if verdict.level is Level.MALICIOUS:
                malicious.append((path, verdict.score, verdict.reasons))
        rate = len(malicious) / len(self.corpus)
        print(f"\n  corpus: {len(self.corpus)} real binaries, "
              f"{len(malicious)} called MALICIOUS ({rate:.2%})")
        for path, score, reasons in malicious[:5]:
            print(f"     {path} score={score} {reasons}")
        self.assertLessEqual(rate, MAX_MALICIOUS_RATE,
                             "a clean binary would be quarantined")

    def test_per_rule_false_positive_rate_is_bounded(self):
        if not self.corpus:
            self.skipTest("no corpus")
        counts: dict[str, int] = {}
        for path in self.corpus:
            try:
                matches = self.rules.match(filepath=str(path), timeout=20)
            except Exception:
                continue
            for match in matches:
                counts[match.rule] = counts.get(match.rule, 0) + 1

        total = len(self.corpus)
        print(f"  per-rule false positives across {total} clean binaries:")
        if not counts:
            print("     none")
        for rule, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"     {rule:<36} {count:>4}  ({count / total:.2%})")

        for rule, count in counts.items():
            with self.subTest(rule=rule):
                self.assertLessEqual(
                    count / total, MAX_FALSE_POSITIVE_RATE,
                    f"{rule} matches {count / total:.2%} of clean binaries, "
                    f"above the {MAX_FALSE_POSITIVE_RATE:.0%} ceiling",
                )


class TestScoring(unittest.TestCase):
    """The arithmetic that decides whether a file gets moved."""

    def test_a_medium_rule_alone_never_reaches_malicious(self):
        findings = [Finding("yara", "SomeMediumRule", SEVERITY_WEIGHTS["medium"])]
        self.assertIs(decide(findings), Level.SUSPICIOUS)

    def test_no_pile_of_heuristics_ever_condemns(self):
        """cygwin1.dll trips the injection rule AND two PE structure signals.

        Before the hard/soft split those summed to 100 and a universally used
        library would have been quarantined. Weak signals correlate, so summing
        them manufactures confidence that is not there.
        """
        findings = [
            Finding("yara", "A", SEVERITY_WEIGHTS["medium"]),
            Finding("yara", "B", SEVERITY_WEIGHTS["medium"]),
            Finding("pe", "structure", 50),
            Finding("entropy", "packed", 25),
            Finding("archive", "structure", 50),
        ]
        self.assertIs(decide(findings), Level.SUSPICIOUS)

    def test_a_signature_alone_is_decisive(self):
        self.assertIs(decide([Finding("signature", "EICAR", 100, hard=True)]),
                      Level.MALICIOUS)

    def test_a_high_severity_rule_alone_is_decisive(self):
        findings = [Finding("yara", "R", SEVERITY_WEIGHTS["high"], hard=True)]
        self.assertIs(decide(findings), Level.MALICIOUS)

    def test_hard_evidence_is_not_diluted_by_heuristics(self):
        findings = [Finding("signature", "EICAR", 100, hard=True),
                    Finding("pe", "structure", 50)]
        self.assertIs(decide(findings), Level.MALICIOUS)

    def test_heuristics_still_reach_suspicious(self):
        self.assertIs(decide([Finding("pe", "structure", 50)]), Level.SUSPICIOUS)

    def test_entropy_alone_is_not_even_suspicious(self):
        self.assertIs(decide([Finding("entropy", "packed", 25)]), Level.CLEAN)

    def test_entropy_plus_a_medium_rule_is_suspicious_not_malicious(self):
        findings = [Finding("entropy", "packed", 25),
                    Finding("yara", "R", SEVERITY_WEIGHTS["medium"])]
        self.assertIs(decide(findings), Level.SUSPICIOUS)

    def test_no_findings_is_clean(self):
        self.assertIs(decide([]), Level.CLEAN)

    def test_threshold_is_configurable(self):
        findings = [Finding("yara", "R", SEVERITY_WEIGHTS["medium"], hard=True)]
        self.assertIs(decide(findings, malicious_at=50), Level.MALICIOUS)




class TestInstalledPacks(unittest.TestCase):
    """Whatever packs are actually installed, held to the same bar.

    A pack is measured once, at admission, and then never again. That is not
    enough on its own: the corpus changes as software is installed, a pack's
    files can be edited afterwards, and a pack admitted against a small corpus
    was never really tested. So the suite re-measures what is installed rather
    than trusting a number recorded at some point in the past.

    Skips cleanly when nothing is installed, which is the case on CI.
    """

    @classmethod
    def setUpClass(cls) -> None:
        from avguard.rulepacks import PackStore
        cls.store = PackStore()
        cls.installed = cls.store.packs()
        cls.rule_files = cls.store.rule_files()
        cls.corpus = _collect_corpus()

    def setUp(self) -> None:
        if not self.installed:
            self.skipTest("no rule packs installed")
        if not self.rule_files:
            self.skipTest("installed packs have no rule files on disk")

    def _compiled(self):
        return yara.compile(filepaths={str(p.resolve()): str(p)
                                       for p in self.rule_files})

    def test_installed_packs_still_compile(self):
        """A pack whose files were edited after admission must not be silent."""
        self.assertIsNotNone(self._compiled())

    def test_no_installed_pack_matches_avguard_itself(self):
        """The v1 failure, arriving from outside instead of from our own rules."""
        compiled = self._compiled()
        for folder in ("rules", "avguard"):
            base = PROJECT / folder
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                with self.subTest(path=path.name):
                    self.assertEqual(
                        [m.rule for m in compiled.match(data=path.read_bytes())], [],
                        f"an installed pack matches AVGuard's own {path.name}")

    def test_installed_packs_stay_under_the_ceiling(self):
        if not self.corpus:
            self.skipTest("no clean binaries available to measure against")
        compiled = self._compiled()
        counts: dict[str, int] = {}
        examined = 0
        for path in self.corpus:
            try:
                matches = compiled.match(filepath=str(path), timeout=30)
            except Exception:
                continue
            examined += 1
            for match in matches:
                counts[match.rule] = counts.get(match.rule, 0) + 1

        names = ", ".join(p.name for p in self.installed)
        print(f"\n  installed packs ({names}) re-measured on {examined} clean binaries:")
        if not counts:
            print("     no rule fired")
        for rule, count in sorted(counts.items(), key=lambda kv: -kv[1])[:8]:
            print(f"     {rule:<46} {count:>3}  ({count / examined:.2%})")

        for rule, count in counts.items():
            with self.subTest(rule=rule):
                self.assertLessEqual(
                    count / examined, MAX_FALSE_POSITIVE_RATE,
                    f"{rule} now matches {count / examined:.2%} of clean binaries, "
                    f"above the {MAX_FALSE_POSITIVE_RATE:.0%} ceiling it was "
                    "admitted under")

    def test_every_installed_pack_records_what_it_was_measured_at(self):
        """A pack with no recorded measurement is one nobody checked."""
        for pack in self.installed:
            with self.subTest(pack=pack.name):
                self.assertGreater(pack.corpus_size, 0,
                                   f"{pack.name} has no recorded measurement")
                self.assertTrue(pack.licence, f"{pack.name} records no licence")


if __name__ == "__main__":
    unittest.main(verbosity=2)
