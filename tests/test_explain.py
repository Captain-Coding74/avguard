"""The account of a verdict (avguard/explain.py).

The point is that the account never says more than the scanner knows, and
that a replayed verdict knows as much as the first one. Before this, a
MALICIOUS verdict served from the cache came back with no findings and a
score of 0, and that 0 went into History and over the wire.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os as _os
import re
import sys
import tempfile as _tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-explain-data-{_os.getpid()}")
_os.environ["AVGUARD_DATA"] = _test_data      # assigned: an inherited value may be real data
if _os.environ["AVGUARD_DATA"] == _test_data:
    import atexit as _atexit
    import shutil as _shutil
    _atexit.register(lambda: _shutil.rmtree(_test_data, ignore_errors=True))

from avguard import config, explain
from avguard.allowlist import Allowlist
from avguard.events import Event, EventStore
from avguard.protection import SelfProtection
from avguard.quarantine import QuarantineStore
from avguard.scanner import (HEURISTIC_CAP, SELFTEST_MARKER, Finding, Level, ScanCache, Scanner,
                             decide, finding_from_dict, findings_from_dicts, findings_to_dicts)

# The shapes a verdict takes, as findings. Reason sentences are the scanner's own.
SIGNATURE = [Finding("signature", "AVGuard-Selftest-Marker", 100,
                     "matched the byte signature for AVGuard-Selftest-Marker", hard=True)]
ENCODED = [Finding("yara", "Suspicious_Script_Obfuscation", 50,
                   "encoded command (rule Suspicious_Script_Obfuscation, medium)", severity="medium")]
PE = [Finding("pe", "structure", 50, "unusual executable structure: writable code section")]
ENTROPY = [Finding("entropy", "high-entropy-executable", 25,
                   "unusually high entropy for an executable (7.60/8.00), which can mean it is packed")]
ARCHIVE = [Finding("archive", "structure", 50, "archive is malformed or hostile: traversal name")]
INJECTION = [Finding("yara", "Suspicious_Process_Injection_PE", 50,
                     "process injection imports (rule Suspicious_Process_Injection_PE, medium)",
                     severity="medium")]
CYGWIN = PE + INJECTION + ENTROPY + ARCHIVE          # 175 of opinions: capped, never moved
SIG_PLUS_PE = SIGNATURE + PE                           # score 150; what decided it is 100
IOC = [Finding("ioc", "smoke", 100, "SHA-256 is on the smoke blocklist", hard=True)]
CLOUD = [Finding("cloud", "virustotal", 100, "flagged by 14 engines on VirusTotal", hard=True)]
TLSH = [Finding("tlsh", "Fam", 50, "resembles a Fam sample: TLSH distance 12 (a near variant; "
                                   "reference from quarantine)")]
TRUST = [Finding("signature-trust", "publisher", 0,
                 "2 heuristic concern(s) set aside because the file is signed by Example Corp")]
ALLOW = [Finding("allowlist", "user-decision", 0, "you chose to keep this file on 2026-10-01")]
PACK = [Finding("yara", "Pack_Rule", 50, "x (rule Pack_Rule, critical, from the smokepack pack)",
                severity="critical", pack="smokepack")]
NOTED = [Finding("yara", "Noted", 50, "x (rule Noted, medium)", severity="medium",
                 notes=("https://example.test/why",))]
FIXTURES = {"signature": SIGNATURE, "encoded": ENCODED, "cygwin": CYGWIN, "sig+pe": SIG_PLUS_PE,
            "ioc": IOC, "cloud": CLOUD, "tlsh": TLSH, "trust": TRUST, "allow": ALLOW, "pack": PACK,
            "noted": NOTED, "empty": []}

CFG = config.Config(cloud_enabled=False)


def account_for(findings, cfg=CFG, packs=None, state=explain.REPORTED, **kw):
    level = decide(findings, cfg.quarantine_threshold).value
    return explain.explain("C:/drop/file.exe", level, [f.describe() for f in findings], findings, cfg,
                           packs=packs, sha256="ab" * 32, state=state, **kw)


class ScannerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(_tempfile.mkdtemp(prefix="avguard-explain-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.bad = self.tmp / "drop" / "threat.bin"
        self.bad.parent.mkdir()
        self.bad.write_bytes(SELFTEST_MARKER)
        # Everything this scanner remembers lives under tmp: a restore in one
        # test must not make the next test's scan CLEAN by exception.
        self.allowlist = Allowlist(self.tmp / "allow.sqlite")
        self.scanner = Scanner(CFG, SelfProtection(), cache=ScanCache(self.tmp / "cache.json",
                                                                       generation="test"),
                               allowlist=self.allowlist)

    def store(self) -> QuarantineStore:
        return QuarantineStore(self.tmp / "q", self.tmp / "q" / "index.json", protection=SelfProtection(),
                               allowlist=self.allowlist)


# ------------------------------------------------------------- the replay

class TestAReplayKnowsAsMuchAsTheFirstScan(ScannerCase):
    def test_a_cached_verdict_keeps_its_findings_score_and_digest(self):
        first = self.scanner.scan(self.bad)
        started = time.perf_counter()
        second = self.scanner.scan(self.bad)
        elapsed = time.perf_counter() - started
        self.assertIsNone(second.facts, "served from the cache, the file was not read")
        self.assertLess(elapsed, 0.05)
        self.assertEqual(second.findings, first.findings)
        self.assertEqual((second.level, second.score), (Level.MALICIOUS, 100))
        self.assertEqual(second.sha256, first.sha256)
        self.assertEqual(len(second.sha256), 64)

    def test_a_schema_three_cache_is_dropped_not_misread(self):
        path = self.tmp / "old.json"
        path.write_text(json.dumps({"schema": 3, "generation": "test", "entries": {
            "c:/x|1|2": {"level": "malicious", "reasons": ["old"], "sha256": "h", "allowed": False,
                         "at": time.time()}}}), encoding="utf-8")
        with self.assertLogs("avguard.scanner", level="INFO") as logged:
            cache = ScanCache(path, generation="test")
        self.assertEqual(len(cache), 0)
        self.assertTrue(any("starting fresh" in r.getMessage() for r in logged.records))

    def test_a_rule_note_reaches_the_finding_from_the_scanner(self):
        import shutil
        noted = Path("tests/rules/must_match/Ransomware_Note_And_Extensions__note.txt")
        target = self.tmp / "drop" / noted.name
        shutil.copy(noted, target)
        verdict = self.scanner.scan(target)
        rule = next(f for f in verdict.findings if f.source == "yara")
        self.assertEqual((rule.severity, rule.pack), ("medium", ""))
        self.assertTrue(any("somebody's writing" in n for n in rule.notes), rule.notes)

    def test_stored_findings_round_trip_and_a_malformed_one_is_a_line_not_a_crash(self):
        for name, findings in FIXTURES.items():
            with self.subTest(fixture=name):
                self.assertEqual(findings_from_dicts(findings_to_dicts(findings)), findings)
        self.assertEqual(finding_from_dict({"weight": float("inf")}).source, "stored", "Infinity is a JSON token")
        for junk in ({"weight": "heavy"}, "junk", None, {"notes": "not-a-list", "weight": 5}):
            with self.subTest(junk=junk):
                self.assertIsInstance(finding_from_dict(junk), Finding)
        self.assertEqual(finding_from_dict({"weight": "heavy"}).source, "stored")
        self.assertEqual(finding_from_dict({"notes": "not-a-list", "weight": 5}).notes, ())
        self.assertEqual(findings_from_dicts("not a list"), [])
        rows = explain.explain("x", "malicious", [], [finding_from_dict("junk")], CFG).rows
        self.assertEqual(rows[0].kind, explain.RECORDED)

    def test_the_cache_entry_cost_is_printed(self):
        self.scanner.scan(self.bad)
        self.scanner.cache.save()
        raw = json.loads((self.tmp / "cache.json").read_text(encoding="utf-8"))
        entry = next(iter(raw["entries"].values()))
        with_findings = len(json.dumps(entry))
        without = len(json.dumps({k: v for k, v in entry.items() if k != "findings"}))
        print(f"\n  cache entry with one finding: {with_findings} bytes ({with_findings - without} for the "
              f"finding); a clean entry adds {len(json.dumps({'findings': []})) - 2} bytes")
        self.assertEqual(raw["schema"], 4, "the schema the README and ROADMAP promise")


# -------------------------------------------------------- facts, opinions

class TestFactsAndOpinions(unittest.TestCase):
    def test_a_fact_is_told_apart_from_an_opinion_in_words(self):
        expected = {"signature": explain.FACT, "ioc": explain.FACT, "cloud": explain.FACT,
                    "encoded": explain.OPINION, "tlsh": explain.OPINION, "trust": explain.SET_ASIDE,
                    "allow": explain.YOUR_DECISION, "pack": explain.OPINION}
        for name, kind in expected.items():
            with self.subTest(source=name):
                self.assertEqual(account_for(FIXTURES[name]).rows[0].kind, kind)
        kinds = [row.kind for row in account_for(CYGWIN).rows]
        self.assertEqual(kinds, [explain.OPINION] * 4)
        hard_rule = [Finding("yara", "Critical", 100, "x (rule Critical, critical)", hard=True,
                             severity="critical")]
        self.assertEqual(account_for(hard_rule).rows[0].kind, explain.FACT)

    def test_the_tally_matches_decide_for_every_fixture(self):
        for name, findings in FIXTURES.items():
            with self.subTest(fixture=name):
                tally = explain.tally_of(findings, CFG.quarantine_threshold)
                self.assertEqual(tally.level(), decide(findings, CFG.quarantine_threshold))
                self.assertTrue(account_for(findings).consistent)
        cygwin = explain.tally_of(CYGWIN, 100)
        self.assertEqual((cygwin.soft, cygwin.soft_capped, cygwin.total), (175, HEURISTIC_CAP, 75))
        self.assertIn("capped at 75; 175 before the cap", cygwin.sentence())
        both = explain.tally_of(SIG_PLUS_PE, 100)
        self.assertEqual((both.hard, both.soft_capped, both.total), (100, 50, 150))
        self.assertEqual(both.level(), Level.MALICIOUS, "the facts alone decided it")
        self.assertIn("100 in facts alone moves a file", both.sentence())

    def test_the_threshold_comes_from_config_not_the_constant(self):
        strict = config.Config(cloud_enabled=False, quarantine_threshold=150)
        account = account_for(SIGNATURE, cfg=strict)
        self.assertIn("150 in facts alone moves a file", account.tally.sentence())
        self.assertEqual(account.level, Level.SUSPICIOUS.value)
        self.assertEqual(account.tally.level(), decide(SIGNATURE, 150))

    def test_a_pack_rule_names_its_pack_trust_and_measured_rate_with_corpus_size(self):
        untrusted = SimpleNamespace(get=lambda name: SimpleNamespace(
            trusted=False, false_positive_rate=0.0025, corpus_size=400))
        row = account_for(PACK, packs=untrusted).rows[0]
        self.assertIn("from the smokepack pack, which reports only", row.words)
        self.assertTrue(any("0.25% of 400 clean files" in n and "the whole pack, not this rule" in n
                            for n in row.notes), row.notes)
        trusted = SimpleNamespace(get=lambda name: SimpleNamespace(
            trusted=True, false_positive_rate=0.0, corpus_size=0))
        row = account_for(PACK, packs=trusted).rows[0]
        self.assertIn("which can move files", row.words)
        self.assertFalse(any("%" in n for n in row.notes), "no corpus, no rate")
        gone = SimpleNamespace(get=lambda name: None)
        self.assertIn("from the smokepack pack", account_for(PACK, packs=gone).rows[0].words)

    def test_the_account_invents_no_probability(self):
        packs = SimpleNamespace(get=lambda name: SimpleNamespace(
            trusted=False, false_positive_rate=0.0025, corpus_size=400))
        for name, findings in FIXTURES.items():
            text = explain.render_text(account_for(findings, packs=packs))
            for line in text.splitlines():
                with self.subTest(fixture=name, line=line[:60]):
                    if "%" in line:
                        self.assertIn("clean files", line)
                    self.assertIsNone(re.search(r"(confidence|probability)[^.\n]*\d|\d[^.\n]*(confidence|probability)",
                                                line, re.I))

    def test_rule_notes_reach_the_account_and_nothing_is_added_without_one(self):
        text = explain.render_text(account_for(NOTED))
        self.assertIn("note: https://example.test/why", text)
        signature = explain.render_text(account_for(SIGNATURE))
        self.assertNotIn("note:", signature)

    def test_a_tlsh_row_names_the_bands_and_that_resemblance_never_moves_a_file(self):
        row = account_for(TLSH).rows[0]
        self.assertEqual(row.words, "resemblance to a known Fam sample")
        self.assertTrue(any("near band ends at TLSH distance 30, the far band at 40" in n
                            and "never moves a file" in n for n in row.notes))

    def test_the_rendering_carries_the_limit_the_digest_and_the_meaning(self):
        text = explain.render_text(account_for(SIGNATURE, state=explain.QUARANTINED))
        self.assertIn("[MALICIOUS] C:/drop/file.exe", text)
        self.assertIn("Enough hard evidence to move the file.", text)
        self.assertIn("fact           100  an exact byte signature (AVGuard-Selftest-Marker)", text)
        self.assertIn("Counted: facts 100 + opinions 0 = 100", text)
        self.assertIn("Quarantined. Restore puts it back", text)
        self.assertIn("SHA-256: " + "ab" * 32, text)
        self.assertIn(explain.LIMIT, text)
        suspicious = explain.render_text(account_for(ENCODED, state=explain.SUSPICIOUS))
        self.assertIn("Reported and left alone: opinions never move a file.", suspicious)
        self.assertIn("opinion         50  rule Suspicious_Script_Obfuscation, severity medium", suspicious)
        self.assertIn("Left alone.", suspicious)

    def test_what_to_do_matches_the_state(self):
        cases = {explain.QUARANTINED: ("Quarantined.", {"Restore", "Mark as a known sample"}),
                 explain.REPORTED: ("Nothing was moved.", set()),
                 explain.SUSPICIOUS: ("Left alone", set()),
                 explain.KEPT: ("Kept because you chose to", {"Stop keeping it"})}
        for state, (happened, labels) in cases.items():
            with self.subTest(state=state):
                account = account_for(SIGNATURE, state=state)
                self.assertIn(happened, account.happened)
                found = {label for label, _ in account.actions}
                self.assertTrue(labels <= found, found)
                self.assertIn("Copy this account", found)
                if state != explain.KEPT:
                    self.assertIn("Never scan this folder", found)
        self.assertEqual(account_for(SIGNATURE, state=explain.OTHER).happened, "")

    def test_state_follows_the_verdict(self):
        from avguard.scanner import Verdict
        malicious = Verdict(Path("x"), Level.MALICIOUS, ["r"], None, SIGNATURE)
        self.assertEqual(explain.state_of(malicious), explain.REPORTED)
        self.assertEqual(explain.state_of(malicious, quarantined=True), explain.QUARANTINED)
        self.assertEqual(explain.state_of(Verdict(Path("x"), Level.SUSPICIOUS, ["r"], None, ENCODED)),
                         explain.SUSPICIOUS)
        self.assertEqual(explain.state_of(Verdict(Path("x"), Level.CLEAN, ["r"], None, ALLOW)), explain.KEPT)
        self.assertEqual(explain.state_of(Verdict(Path("x"), Level.CLEAN)), explain.OTHER)

    def test_a_record_or_event_without_evidence_says_so_and_invents_nothing(self):
        record = SimpleNamespace(original_path="C:/drop/old.exe", reasons=["matched the byte signature for X"],
                                 sha256="cd" * 32)
        account = explain.from_record(record, None, CFG)
        self.assertFalse(account.evidence_kept)
        self.assertFalse(account.consistent)
        self.assertEqual([r.kind for r in account.rows], [explain.RECORDED])
        text = explain.render_text(account)
        self.assertIn(explain.NOT_KEPT, text)
        self.assertNotIn("Counted:", text, "no arithmetic is shown for evidence that was not kept")
        self.assertIn("matched the byte signature for X", text)
        with_evidence = explain.from_record(record, findings_to_dicts(SIGNATURE), CFG)
        self.assertTrue(with_evidence.evidence_kept)
        self.assertEqual(with_evidence.rows[0].kind, explain.FACT)
        self.assertEqual(with_evidence.state, explain.QUARANTINED)

    def test_an_event_is_accounted_for_from_its_detail(self):
        detail = {"findings": findings_to_dicts(ENCODED), "hard": 0, "soft_capped": 50, "threshold": 100,
                  "sha256": "ef" * 32}
        new = explain.from_event(Event(kind="suspicious", path="C:/x", level="suspicious", score=50,
                                       reasons=[f.describe() for f in ENCODED], detail=detail), CFG)
        self.assertEqual((new.state, new.evidence_kept, new.sha256), (explain.SUSPICIOUS, True, "ef" * 32))
        old = explain.from_event(Event(kind="quarantined", path="C:/x", level="malicious", score=100,
                                       reasons=["old reason"]), CFG)
        self.assertEqual((old.state, old.evidence_kept, old.rows[0].text),
                         (explain.QUARANTINED, False, "old reason"))

    def test_tally_level_matches_decide_at_odd_thresholds(self):
        for threshold in (0, -5, 100.5, 150):
            for name, findings in FIXTURES.items():
                with self.subTest(threshold=threshold, fixture=name):
                    self.assertEqual(explain.tally_of(findings, threshold).level(),
                                     decide(findings, threshold))

    def test_findings_none_means_evidence_not_kept(self):
        account = explain.explain("x", "malicious", ["r1"], None, CFG)
        self.assertFalse(account.evidence_kept)
        self.assertEqual([r.kind for r in account.rows], [explain.RECORDED])
        self.assertNotIn("Counted:", explain.render_text(account))

    def test_a_clean_verdict_with_findings_says_so_and_a_kept_one_says_kept(self):
        below = account_for(ENTROPY, state=explain.OTHER)
        self.assertEqual((below.level, below.meaning), ("clean", explain.CLEAN_BELOW_THE_LINE))
        kept = account_for(ALLOW, state=explain.KEPT)
        self.assertEqual(kept.meaning, explain.CLEAN_KEPT)
        self.assertEqual(account_for([], state=explain.OTHER).meaning, "Nothing found.")

    def test_a_skipped_or_errored_file_keeps_its_reason(self):
        account = explain.explain("C:/big.iso", "skipped", ["larger than the size cap (3000 MB)"], [], CFG)
        text = explain.render_text(account)
        self.assertIn("Reasons:", text)
        self.assertIn("larger than the size cap", text)
        self.assertNotIn("Counted:", text)
        self.assertEqual(json.loads(explain.as_json(account))["reasons"], ["larger than the size cap (3000 MB)"])

    def test_a_detection_event_says_what_happened_or_nothing_about_a_move(self):
        detail = {"findings": findings_to_dicts(SIGNATURE), "threshold": 100, "sha256": "a" * 64}
        old = explain.from_event(Event(kind="detection", path="C:/x", level="malicious", score=100,
                                       reasons=["r"], detail=detail), CFG)
        self.assertEqual(old.state, explain.DETECTED)
        self.assertNotIn("Nothing was moved", old.happened)
        moved = explain.from_event(Event(kind="detection", path="C:/x", level="malicious", score=100,
                                         reasons=["r"], detail={**detail, "state": "quarantined"}), CFG)
        self.assertEqual(moved.state, explain.QUARANTINED)
        reported = explain.from_event(Event(kind="detection", path="C:/x", level="malicious", score=100,
                                            reasons=["r"], detail={**detail, "state": "reported"}), CFG)
        self.assertIn("Nothing was moved", reported.happened)

    def test_an_event_without_a_verdict_is_not_called_clean(self):
        summary = Event(kind="scan_finished", detail={"files": 120, "threats": 3})
        self.assertFalse(explain.is_verdict_event(summary))
        account = explain.from_event(summary, CFG)
        self.assertEqual((account.level, account.meaning), ("", ""))
        self.assertNotIn("CLEAN", explain.render_text(account))
        for kind in ("detection", "quarantined", "suspicious"):
            self.assertTrue(explain.is_verdict_event(Event(kind=kind, path="x", level="malicious")))

    def test_a_note_that_states_a_confidence_figure_is_left_out(self):
        loud = [Finding("yara", "R", 50, "d (rule R, medium)", severity="medium", pack="p",
                        notes=("95% confidence this is malware", "see https://example.test"))]
        text = explain.render_text(account_for(loud))
        self.assertNotIn("95%", text)
        self.assertIn(explain.NOTE_LEFT_OUT, text)
        self.assertIn("note: see https://example.test", text)

    def test_as_json_is_ascii_safe(self):
        account = explain.explain("C:/drop/clean-\u4e2d.txt", "clean", [], [], CFG)
        line = explain.as_json(account)
        self.assertTrue(line.isascii(), "a console code page that cannot encode a path must not lose the object")
        self.assertEqual(json.loads(line)["path"], "C:/drop/clean-\u4e2d.txt")

    def test_as_dict_is_json_and_as_json_round_trips(self):
        account = account_for(CYGWIN)
        data = json.loads(explain.as_json(account))
        self.assertEqual(data["level"], "suspicious")
        self.assertEqual(len(data["rows"]), 4)
        self.assertEqual(data["tally"]["soft_capped"], 75)
        self.assertTrue(data["consistent"])
        self.assertEqual(data["actions"][-1], ["Copy this account", "copy"])

    def test_the_rendering_cost_and_size_are_printed(self):
        worst = CYGWIN + TLSH + NOTED
        account = account_for(worst)
        n = 2000
        started = time.perf_counter()
        for _ in range(n):
            explain.render_text(account_for(worst))
        per = (time.perf_counter() - started) / n * 1e6
        text = explain.render_text(account)
        print(f"\n  explain()+render_text(): {per:.0f} us; worst account {len(text)} chars, "
              f"{len(text.splitlines())} lines")
        self.assertLess(per, 500, "25 us measured; a bound that something plausible can cross")


# -------------------------------------------------------- never changes

class TestExplainNeverChangesTheVerdict(ScannerCase):
    def test_level_findings_and_reasons_are_identical_before_and_after(self):
        verdict = self.scanner.scan(self.bad)
        before = (verdict.level, list(verdict.findings), list(verdict.reasons), verdict.sha256)
        explain.render_text(explain.from_verdict(verdict, CFG, self.scanner.packs))
        explain.as_json(explain.from_verdict(verdict, CFG, self.scanner.packs, quarantined=True))
        self.assertEqual((verdict.level, list(verdict.findings), list(verdict.reasons), verdict.sha256), before)

    def test_reason_strings_are_unchanged(self):
        verdict = self.scanner.scan(self.bad)
        self.assertEqual(verdict.reasons, ["matched the byte signature for AVGuard-Selftest-Marker"])
        self.assertEqual(verdict.findings[0].describe(), verdict.reasons[0])
        rule = Finding("yara", "R", 50, "d (rule R, medium)", severity="medium", pack="p",
                       notes=("n",))
        self.assertEqual(rule.describe(), "d (rule R, medium)", "the new fields change no sentence")


# ---------------------------------------------------- the evidence travels

class TestTheEvidenceTravels(ScannerCase):
    def evidence(self, threshold=100):
        return {"findings": findings_to_dicts(SIGNATURE), "hard": 100, "soft_capped": 0,
                "threshold": threshold, "sha256": "ab" * 32}

    def test_the_quarantine_store_keeps_evidence_beside_the_index_not_on_the_record(self):
        store = self.store()
        record = store.quarantine(self.bad, ["r"], evidence=self.evidence())
        index = json.loads((self.tmp / "q" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(set(index[record.entry_id]),
                         {"entry_id", "original_path", "original_name", "quarantined_at", "size",
                          "sha256", "nonce", "reasons", "pending"},
                         "no new field: an older AVGuard drops a record with one it does not know")
        self.assertEqual(store.evidence(record.entry_id), self.evidence())
        self.assertEqual(store.evidence_path.name, "index_evidence.json")
        self.assertIsNone(store.evidence("never-held"))
        account = explain.from_record(record, store.evidence(record.entry_id), CFG)
        self.assertTrue(account.evidence_kept)
        self.assertEqual(account.rows[0].kind, explain.FACT)

    def test_restore_and_delete_take_the_evidence_row_with_them(self):
        store = self.store()
        other = self.tmp / "drop" / "other.bin"
        other.write_bytes(SELFTEST_MARKER)
        first = store.quarantine(self.bad, ["r"], evidence=self.evidence())
        second = store.quarantine(other, ["r"], evidence=self.evidence())
        self.assertEqual(set(json.loads(store.evidence_path.read_text(encoding="utf-8"))),
                         {first.entry_id, second.entry_id})
        store.restore(first.entry_id)
        store.delete(second.entry_id)
        self.assertEqual(json.loads(store.evidence_path.read_text(encoding="utf-8")), {})
        self.assertIsNone(store.evidence(first.entry_id))

    def test_a_settled_index_is_read_not_rewritten(self):
        """--list-quarantine and --explain-quarantine hold no lock, so their
        constructor must not write; it used to save on every start."""
        store = self.store()
        store.quarantine(self.bad, ["r"], evidence=self.evidence())
        index = self.tmp / "q" / "index.json"
        before = index.stat().st_mtime_ns
        time.sleep(0.01)
        QuarantineStore(self.tmp / "q", index, protection=SelfProtection())
        self.assertEqual(index.stat().st_mtime_ns, before)

    def test_the_threshold_recorded_with_the_evidence_is_the_one_shown(self):
        strict = config.Config(cloud_enabled=False, quarantine_threshold=150)
        record = SimpleNamespace(original_path="C:/x", reasons=["r"], sha256="ab" * 32)
        account = explain.from_record(record, self.evidence(threshold=150), CFG)
        self.assertIn("150 in facts alone moves a file", account.tally.sentence())
        event = Event(kind="quarantined", path="C:/x", level="malicious", score=100, reasons=["r"],
                      detail=self.evidence(threshold=100))
        account = explain.from_event(event, strict)
        self.assertEqual(account.tally.threshold, 100, "the threshold it was decided with, not today's")
        self.assertTrue(account.consistent)

    def test_a_record_held_without_evidence_reads_as_not_kept(self):
        store = self.store()
        record = store.quarantine(self.bad, ["r"])
        self.assertIsNone(store.evidence(record.entry_id))
        self.assertFalse(explain.from_record(record, store.evidence(record.entry_id), CFG).evidence_kept)

    def test_a_failed_evidence_write_keeps_the_file_and_says_so(self):
        store = self.store()
        real = config.atomic_write_text

        def flaky(path, text):
            if "evidence" in str(path):
                raise OSError("disk full")
            return real(path, text)
        with mock.patch.object(config, "atomic_write_text", flaky), \
                self.assertLogs("avguard.quarantine", level="WARNING") as logged:
            record = store.quarantine(self.bad, ["r"], evidence=self.evidence())
        self.assertFalse(self.bad.exists(), "the file was taken")
        self.assertIsNotNone(store.get(record.entry_id))
        self.assertTrue(any("could not keep the evidence" in r.getMessage() for r in logged.records))

    def test_evidence_rows_for_gone_entries_are_pruned_on_the_next_keep(self):
        store = self.store()
        store.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        store.evidence_path.write_text(json.dumps({"stale": [{"source": "x"}]}), encoding="utf-8")
        record = store.quarantine(self.bad, ["r"], evidence=self.evidence())
        kept = json.loads(store.evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(set(kept), {record.entry_id})

    def test_the_event_detail_carries_the_evidence_and_the_arithmetic(self):
        verdict = self.scanner.scan(self.bad)
        detail = explain.evidence_detail(verdict, CFG)
        self.assertEqual(set(detail), {"findings", "hard", "soft_capped", "threshold", "sha256"})
        self.assertEqual((detail["hard"], detail["soft_capped"], detail["threshold"]), (100, 0, 100))
        replayed = self.scanner.scan(self.bad)
        self.assertIsNone(replayed.facts)
        self.assertEqual(len(explain.evidence_detail(replayed, CFG)["sha256"]), 64,
                         "a replay carries the digest; it used to carry nothing")
        events = EventStore(path=self.tmp / "events.jsonl")
        events.record(Event(kind="detection", path=str(self.bad), level="malicious", score=100,
                            reasons=verdict.reasons, detail=detail))
        back = events.read(kinds={"detection"})[0]
        self.assertEqual(findings_from_dicts(back.detail["findings"]), verdict.findings)
        line = json.loads((self.tmp / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(set(line), {"kind", "at", "path", "level", "score", "reasons", "detail"},
                         "the seven schema-1 fields, and nothing beside them")


# ---------------------------------------------------------- the window

class TestTheWindow(unittest.TestCase):
    def setUp(self) -> None:
        try:
            # One window root per process, imported one way: under
            # discover, "tests.guiroot" was a second module with a second
            # root, ttkbootstrap refused it, and this class was skipped in
            # every full run, on CI too (round seven).
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from guiroot import gui_root
            self.root = gui_root()
            from avguard import dialogs, gui
        except Exception as exc:                         # no GUI dependencies or no display
            self.skipTest(f"no window: {exc}")
        self.dialogs, self.gui = dialogs, gui
        self.tmp = Path(_tempfile.mkdtemp(prefix="avguard-explain-gui-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_the_account_dialog_shows_copies_and_runs_its_action(self):
        import tkinter as tk
        called: list[str] = []
        account = account_for(SIGNATURE, state=explain.QUARANTINED)
        started = time.perf_counter()
        dialog = self.dialogs.ExplanationDialog(self.root, account,
                                                {"exclude": lambda: called.append("exclude"),
                                                 "restore": lambda: called.append("restore")})
        dialog.update_idletasks()
        print(f"\n  account dialog built in {(time.perf_counter() - started) * 1e3:.0f} ms, "
              f"{dialog.winfo_reqwidth()}x{dialog.winfo_reqheight()}")
        body = dialog.winfo_children()[0]
        texts = [c for frame in body.winfo_children() for c in getattr(frame, "winfo_children", list)()
                 if isinstance(c, tk.Text)]
        self.assertIn("an exact byte signature", texts[0].get("1.0", "end"))
        self.assertEqual(str(texts[0].cget("state")), "disabled", "read-only")
        row = [w for w in body.winfo_children()
               if w.winfo_children() and all(c.winfo_class() == "TButton" for c in w.winfo_children())][0]
        buttons = {b.cget("text"): b for b in row.winfo_children()}
        self.assertEqual(set(buttons), {"Restore", "Never scan this folder", "Copy this account", "Close"},
                         "only the actions the caller can take, plus Copy and Close")
        dialog._copy()
        self.assertTrue(self.root.clipboard_get().startswith("[MALICIOUS] C:/drop/file.exe"))
        buttons["Restore"].invoke()
        self.assertEqual(called, ["restore"])
        self.assertFalse(dialog.winfo_exists())

    def test_history_opens_an_account_for_a_row(self):
        events = EventStore(path=self.tmp / "events.jsonl")
        events.record(Event(kind="detection", path="C:/x/a.exe", level="malicious", score=100,
                            reasons=["r"], detail={"findings": findings_to_dicts(SIGNATURE), "sha256": "a" * 64}))
        opened: list = []
        dialog = self.dialogs.HistoryDialog(self.root, events, lambda: None, on_open=opened.append)
        rows = dialog.tree.get_children()
        dialog.tree.selection_set(rows[0])
        dialog._open_selected()
        dialog.destroy()
        self.assertEqual(len(opened), 1)
        account = explain.from_event(opened[0], CFG)
        self.assertEqual((account.state, account.rows[0].kind), (explain.DETECTED, explain.FACT))

    def test_a_reported_threat_offers_why_and_never_scan_and_records_the_evidence(self):
        import tkinter as tk
        import ttkbootstrap as tb
        bad = self.tmp / "drop" / "threat.bin"
        bad.parent.mkdir()
        bad.write_bytes(SELFTEST_MARKER)
        cfg = config.Config(cloud_enabled=False, auto_quarantine=False)
        scanner = Scanner(cfg, SelfProtection(), cache=ScanCache(self.tmp / "c.json", generation="t"))
        verdict = scanner.scan(bad)
        events = EventStore(path=self.tmp / "events.jsonl")
        holder = tb.Frame(self.root)
        panes = tb.Frame(holder)
        panes.pack()
        var = tk.StringVar()
        banner = tb.Label(holder, textvariable=var)
        fake = SimpleNamespace(cfg=cfg, has_lock=True, events=events, scanner=scanner, _threats_this_scan=0, banner=banner,
                               banner_var=var, _panes=panes, tray=None, quarantine=None, cache=None)
        for name in ("_banner", "_offer_account", "_offer_exclusion", "_show_account"):
            setattr(fake, name, getattr(self.gui.AVGuardApp, name).__get__(fake))
        self.gui.AVGuardApp._handle_threat(fake, verdict)
        self.assertIn("not quarantined", var.get())
        self.assertEqual([w.cget("text") for w in banner.winfo_children()], ["Why?", "Never scan drop"])
        self.assertTrue(bad.exists(), "reported, not moved")
        event = events.read(kinds={"detection"})[0]
        self.assertEqual(set(event.detail), {"findings", "hard", "soft_capped", "threshold", "sha256", "state"})
        self.assertEqual(event.detail["state"], explain.REPORTED)
        holder.destroy()

    def test_an_automatic_quarantine_records_what_happened_and_offers_the_account_with_restore(self):
        import tkinter as tk
        import ttkbootstrap as tb
        bad = self.tmp / "drop" / "threat.bin"
        bad.parent.mkdir()
        bad.write_bytes(SELFTEST_MARKER)
        cfg = config.Config(cloud_enabled=False, auto_quarantine=True)
        scanner = Scanner(cfg, SelfProtection(), cache=ScanCache(self.tmp / "c.json", generation="t"))
        verdict = scanner.scan(bad)
        events = EventStore(path=self.tmp / "events.jsonl")
        store = QuarantineStore(self.tmp / "q", self.tmp / "q" / "index.json", protection=SelfProtection(),
                                allowlist=Allowlist(self.tmp / "allow.sqlite"))
        holder = tb.Frame(self.root)
        panes = tb.Frame(holder)
        panes.pack()
        var = tk.StringVar()
        banner = tb.Label(holder, textvariable=var)
        shown: list = []
        fake = SimpleNamespace(cfg=cfg, has_lock=True, events=events, scanner=scanner, _threats_this_scan=0, banner=banner,
                               banner_var=var, _panes=panes, tray=None, quarantine=store,
                               cache=scanner.cache, _refresh_quarantine=lambda: None,
                               _show_account=lambda a, e=None: shown.append((a, e)))
        for name in ("_banner", "_offer_account", "_offer_exclusion"):
            setattr(fake, name, getattr(self.gui.AVGuardApp, name).__get__(fake))
        self.gui.AVGuardApp._handle_threat(fake, verdict)
        self.assertFalse(bad.exists(), "moved")
        kinds = [(e.kind, e.detail["state"]) for e in events.read()]
        self.assertEqual(sorted(kinds), [("detection", "quarantined"), ("quarantined", "quarantined")],
                         "the detection row says the file was then moved")
        record = store.records()[0]
        self.assertEqual(store.evidence(record.entry_id)["findings"], findings_to_dicts(verdict.findings))
        why = [w for w in banner.winfo_children() if w.cget("text") == "Why?"][0]
        why.invoke()
        account, entry_id = shown[0]
        self.assertEqual((account.state, entry_id), (explain.QUARANTINED, record.entry_id))
        # "Why was this taken?" on the Quarantine tab reads the same evidence.
        fake._selected_id = lambda: record.entry_id
        self.gui.AVGuardApp._explain_selected(fake)
        self.assertEqual(shown[1][0].rows[0].kind, explain.FACT)
        self.assertTrue(shown[1][0].evidence_kept)
        holder.destroy()

    def test_history_opens_nothing_for_a_row_without_a_verdict_or_a_click_off_the_rows(self):
        events = EventStore(path=self.tmp / "events.jsonl")
        events.record(Event(kind="scan_finished", detail={"files": 3, "threats": 0}))
        events.record(Event(kind="detection", path="C:/x/a.exe", level="malicious", score=100,
                            reasons=["r"], detail={"findings": findings_to_dicts(SIGNATURE)}))
        opened: list = []
        dialog = self.dialogs.HistoryDialog(self.root, events, lambda: None, on_open=opened.append)
        rows = dialog.tree.get_children()
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(dialog._events), 1, "only the verdict row has an account")
        summary = next(iid for iid in rows if dialog.tree.item(iid, "values")[1] == "scan_finished")
        dialog.tree.selection_set(summary)
        dialog._open_selected()
        dialog._open_selected(SimpleNamespace(y=-5))          # a heading or empty space
        self.assertEqual(opened, [])
        dialog.destroy()



class TestADescriptionThatStatesAFigure(unittest.TestCase):
    """Round six: the confidence filter read a rule author's notes but not
    the rule's description, so a pack could put "97% confidence" into the
    account a line above the sentence saying it carries no such number."""

    def test_the_description_is_left_out_and_the_rule_still_named(self):
        loud = [Finding("yara", "Packed_Thing", 50, "97% confidence: packed malware (rule Packed_Thing, medium)",
                        severity="medium", pack="p")]
        text = explain.render_text(account_for(loud))
        self.assertNotIn("97%", text)
        self.assertIn(f"rule Packed_Thing matched {explain.DESCRIPTION_LEFT_OUT}", text)

    def test_a_bare_percentage_or_a_word_figure_is_left_out_too(self):
        for said in ("packed loader, 97% likely malicious", "seen in 97% of loaders",
                     "97 percent certain this is a loader",
                     "confidence 0.97", "9 in 10 of these are loaders"):
            with self.subTest(said=said):
                text = explain.render_text(account_for(
                    [Finding("yara", "R", 50, f"{said} (rule R, medium)", severity="medium")]))
                self.assertIn(explain.DESCRIPTION_LEFT_OUT, text)

    def test_a_percent_that_is_not_a_figure_is_kept_with_where_it_matched(self):
        """Round seven: any "%" (an %APPDATA% path, a %20 in a member's
        name) or any digit in the rule's name beside "probably" dropped an
        ordinary description and said it stated a confidence figure."""
        for detail in ("Script that writes under %APPDATA% (rule Env_v2, medium) inside invoice%20copy.zip!a.js",
                       "Probably a packed loader (rule Loader_v2, medium)",
                       "packed loader (rule Loader, medium) inside summer sale 50%.zip!readme.txt"):
            with self.subTest(detail=detail):
                text = explain.render_text(account_for([Finding("yara", "R", 50, detail, severity="medium")]))
                self.assertIn(detail, text)
                self.assertNotIn(explain.DESCRIPTION_LEFT_OUT, text)

    def test_the_json_object_and_recorded_reasons_carry_no_figure(self):
        loud = "97% confidence: packed loader (rule Loud, medium) inside a.zip!b"
        account = account_for([Finding("yara", "Loud", 50, loud, severity="medium")])
        self.assertNotIn("97%", explain.as_json(account))
        self.assertIn("inside a.zip!b", explain.as_json(account))
        recorded = explain.explain("C:/x", "suspicious", [loud], None, CFG)
        self.assertNotIn("97%", explain.render_text(recorded))
        self.assertNotIn("97%", explain.as_json(recorded))

    def test_an_ordinary_description_is_kept_and_the_scanner_own_words_are_not_filtered(self):
        plain = [Finding("yara", "R", 50, "a downloader seen in 2024 lures (rule R, medium)", severity="medium"),
                 Finding("signature", "S", 100, "matched 100% of signature S", hard=True)]
        text = explain.render_text(account_for(plain))
        self.assertIn("a downloader seen in 2024 lures", text)
        self.assertIn("matched 100% of signature S", text)


if __name__ == "__main__":
    unittest.main()
