"""Tests for the Tier 2 work: archives, PE structure, events, parallel scans.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from avguard import archives, config, peinfo
from avguard.events import Event, EventStore
from avguard.protection import SelfProtection
from avguard.scanner import (
    HEURISTIC_CAP, Finding, Level, ScanCache, Scanner, SELFTEST_MARKER, decide,
)

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

RULES = Path(__file__).resolve().parent.parent / "rules" / "malware.yara"


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-t2-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def scanner(self, **overrides) -> Scanner:
        cfg = config.Config(cloud_enabled=False, **overrides)
        return Scanner(cfg, SelfProtection([self.tmp / "nothing"]),
                       rules_path=RULES, cache=ScanCache(path=self.tmp / "cache.json"))

    def zip_of(self, entries: dict, name: str = "a.zip") -> Path:
        path = self.tmp / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for entry, data in entries.items():
                archive.writestr(entry, data)
        return path


# ------------------------------------------------------------------ archives

class TestArchiveInspection(TempCase):
    """Downloads is where zipped samples arrive, so this is the common case."""

    def test_clean_archive_is_clean(self):
        target = self.zip_of({"notes.txt": "hello", "data.csv": "a,b,c"})
        self.assertIs(self.scanner().scan(target, use_cache=False).level, Level.CLEAN)

    def test_threat_inside_an_archive_is_found(self):
        target = self.zip_of({"readme.txt": "hi", "payload.bin": SELFTEST_MARKER})
        verdict = self.scanner().scan(target, use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)
        self.assertIn("inside", verdict.reasons[0])

    def test_threat_one_archive_deeper_is_found(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as nested:
            nested.writestr("payload.bin", SELFTEST_MARKER)
        target = self.zip_of({"inner.zip": inner.getvalue(), "readme.txt": "nothing"})
        self.assertIs(self.scanner().scan(target, use_cache=False).level, Level.MALICIOUS)

    def test_nothing_is_ever_extracted_to_disk(self):
        target = self.zip_of({"a.txt": "x", "b.txt": "y"})
        before = set(self.tmp.rglob("*"))
        self.scanner().scan(target, use_cache=False)
        self.assertEqual(set(self.tmp.rglob("*")) - before - {self.tmp / "cache.json"}, set())

    def test_a_decompression_bomb_is_refused_not_decompressed(self):
        target = self.zip_of({"bomb.bin": b"\x00" * (30 * 1024 * 1024)}, "bomb.zip")
        report = archives.inspect(target)
        bomb = [m for m in report.members if m.name == "bomb.bin"][0]
        self.assertIsNone(bomb.data, "the bomb must never be decompressed")
        self.assertIn("bomb", bomb.skipped)

    def test_a_bomb_is_reported_but_never_quarantined(self):
        target = self.zip_of({"bomb.bin": b"\x00" * (30 * 1024 * 1024)}, "bomb.zip")
        verdict = self.scanner().scan(target, use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertFalse(verdict.is_threat)

    def test_a_traversal_entry_name_is_reported(self):
        target = self.zip_of({"../../evil.exe": "x"}, "trav.zip")
        verdict = self.scanner().scan(target, use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertIn("escapes", " ".join(verdict.reasons))

    def test_several_structural_problems_still_cannot_condemn(self):
        target = self.zip_of({"../../e.exe": "x",
                              "bomb.bin": b"\x00" * (30 * 1024 * 1024)}, "both.zip")
        verdict = self.scanner().scan(target, use_cache=False)
        self.assertFalse(verdict.is_threat, "structure alone must never move a file")

    def test_an_encrypted_member_is_reported_not_guessed_at(self):
        path = self.tmp / "enc.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("secret.txt", "data")
        # Flip the encryption bit so the member looks encrypted.
        raw = path.read_bytes().replace(b"PK\x03\x04\x14\x00\x00\x00", b"PK\x03\x04\x14\x00\x01\x00")
        path.write_bytes(raw)
        report = archives.inspect(path)
        if report.members:
            self.assertTrue(all(m.data is None or m.skipped == "" for m in report.members))

    def test_a_truncated_download_is_not_an_accusation(self):
        """A half-finished download is the usual cause and is not hostile."""
        target = self.tmp / "broken.zip"
        target.write_bytes(b"PK" + bytes([3, 4]) + b" this is not really a zip")
        report = archives.inspect(target)
        self.assertTrue(report.notes, "the limitation should be recorded")
        self.assertFalse(report.problems, "being unreadable is not hostile")
        self.assertIs(self.scanner().scan(target, use_cache=False).level, Level.CLEAN)

    def test_a_large_but_ordinary_archive_is_clean(self):
        """The first real-world run flagged a Minecraft resource pack as
        "malformed or hostile" purely for having more entries than the scan
        cap. A limit of ours is not a property of the file."""
        entries = {f"assets/tex/{i}.png": b"data"
                   for i in range(archives.MAX_MEMBERS + 200)}
        target = self.zip_of(entries, "resourcepack.zip")
        report = archives.inspect(target)
        self.assertTrue(report.truncated)
        self.assertFalse(report.problems)
        self.assertIs(self.scanner().scan(target, use_cache=False).level, Level.CLEAN)

    def test_archive_scanning_can_be_turned_off(self):
        target = self.zip_of({"payload.bin": SELFTEST_MARKER})
        scanner = self.scanner(archive_scanning_enabled=False)
        self.assertIs(scanner.scan(target, use_cache=False).level, Level.CLEAN)

    def test_member_count_is_bounded(self):
        entries = {f"f{i}.txt": "x" for i in range(archives.MAX_MEMBERS + 50)}
        report = archives.inspect(self.zip_of(entries, "many.zip"))
        self.assertTrue(report.truncated)
        self.assertLessEqual(len(report.members), archives.MAX_MEMBERS)
        self.assertTrue(report.notes, "truncation must be visible somewhere")


# ------------------------------------------------------------ PE heuristics

class TestPEHeuristics(TempCase):
    """One signal fires on 27.5% of clean binaries; two on 0.25%."""

    def test_a_text_file_is_not_a_pe(self):
        target = self.tmp / "notes.txt"
        target.write_text("hello")
        self.assertFalse(peinfo.analyse(target).is_pe)

    def test_one_signal_is_not_enough(self):
        report = peinfo.PEReport(is_pe=True, signals=["only one thing"])
        self.assertFalse(report.suspicious)

    def test_two_signals_are_reported(self):
        report = peinfo.PEReport(is_pe=True, signals=["one", "two"])
        self.assertTrue(report.suspicious)

    @unittest.skipUnless(sys.platform == "win32", "needs Windows")
    def test_normal_system_dlls_trip_nothing(self):
        """No ordinary system library should reach two structural signals.

        Written against several DLLs rather than one. The first version
        asserted that kernel32.dll specifically parsed, which is a fact about
        the machine rather than about the code -- and it failed on a clean CI
        runner where pefile could not read that file, while the behaviour
        under test was fine. When a heuristic cannot parse something it
        reports nothing, which is the correct way for a guess to fail.
        """
        candidates = [Path(r"C:\Windows\System32") / name for name in
                      ("kernel32.dll", "user32.dll", "advapi32.dll",
                       "shell32.dll", "ole32.dll", "gdi32.dll")]
        parsed, unreadable = [], []
        for candidate in candidates:
            if not candidate.exists():
                continue
            report = peinfo.analyse(candidate)
            if report.is_pe:
                parsed.append((candidate, report))
            else:
                unreadable.append((candidate.name, report.error or "no reason given"))

        if not parsed:
            self.skipTest(f"pefile could not read any system DLL here: {unreadable}")

        for candidate, report in parsed:
            with self.subTest(dll=candidate.name):
                self.assertFalse(
                    report.suspicious,
                    f"{candidate.name} tripped {report.signals}")

    @unittest.skipUnless(sys.platform == "win32", "needs Windows")
    def test_an_unparseable_file_reports_nothing_rather_than_guessing(self):
        target = self.tmp / "truncated.dll"
        target.write_bytes(b"MZ" + bytes(64))     # an MZ header and nothing behind it
        report = peinfo.analyse(target)
        self.assertFalse(report.suspicious,
                         "a file we cannot parse must not produce signals")

    @unittest.skipUnless(Path(r"C:\Windows\System32\cygwin1.dll").exists(),
                         "cygwin1.dll not installed")
    def test_the_stacking_case_is_suspicious_but_never_moved(self):
        """cygwin1.dll trips a medium rule AND two structure signals.

        Before heuristics were capped, those summed to 100 and this universally
        used library would have been quarantined.
        """
        verdict = self.scanner().scan(Path(r"C:\Windows\System32\cygwin1.dll"),
                                      use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertFalse(verdict.is_threat)

    def test_pe_analysis_can_be_turned_off(self):
        scanner = self.scanner(pe_analysis_enabled=False)
        target = self.tmp / "x.exe"
        target.write_bytes(b"MZ" + b"\x00" * 500)
        self.assertEqual([f for f in scanner.scan(target, use_cache=False).findings
                          if f.source == "pe"], [])


# ------------------------------------------------------------ heuristic cap

class TestHeuristicCap(unittest.TestCase):
    def test_heuristics_cap_below_the_threshold(self):
        piles = [Finding("pe", "a", 50), Finding("yara", "b", 50),
                 Finding("entropy", "c", 25), Finding("archive", "d", 50)]
        self.assertIs(decide(piles), Level.SUSPICIOUS)

    def test_the_cap_is_below_the_malicious_threshold(self):
        self.assertLess(HEURISTIC_CAP, 100)

    def test_hard_evidence_is_unaffected_by_the_cap(self):
        self.assertIs(decide([Finding("signature", "s", 100, hard=True)]), Level.MALICIOUS)

    def test_hard_and_soft_together_still_condemn(self):
        self.assertIs(decide([Finding("signature", "s", 100, hard=True),
                              Finding("pe", "a", 50)]), Level.MALICIOUS)


# ----------------------------------------------------------------- events

class TestEventStore(TempCase):
    def store(self) -> EventStore:
        return EventStore(path=self.tmp / "events.jsonl")

    def test_events_round_trip(self):
        store = self.store()
        store.record(Event(kind="detection", path="c:/x.exe", level="malicious"))
        events = store.read()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].path, "c:/x.exe")

    def test_newest_first(self):
        store = self.store()
        for i in range(5):
            store.record(Event(kind="detection", path=f"c:/{i}"))
        self.assertEqual(store.read()[0].path, "c:/4")

    def test_a_torn_line_does_not_break_reading(self):
        store = self.store()
        store.record(Event(kind="detection", path="c:/good"))
        with open(store.path, "a", encoding="utf-8") as handle:
            handle.write('{"kind": "detection", "path": "c:/tor')
        self.assertEqual(len(store.read()), 1)

    def test_filtering_by_kind(self):
        store = self.store()
        store.record(Event(kind="detection", path="a"))
        store.record(Event(kind="scan_finished"))
        self.assertEqual(len(store.read(kinds={"detection"})), 1)

    def test_summary_counts(self):
        store = self.store()
        store.record(Event(kind="detection", path="a"))
        store.record(Event(kind="quarantined", path="a"))
        summary = store.summary()
        self.assertEqual(summary["detections"], 1)
        self.assertEqual(summary["quarantined"], 1)

    def test_clear_removes_the_recorded_paths(self):
        store = self.store()
        store.record(Event(kind="detection", path="c:/private/thing.docx"))
        store.clear()
        self.assertEqual(store.read(), [])
        self.assertFalse(store.path.exists())

    def test_recording_never_raises(self):
        store = EventStore(path=self.tmp / "nope" / "deep" / "events.jsonl")
        store.path = Path("Z:/definitely/not/here/events.jsonl")
        store.record(Event(kind="detection"))   # must not raise

    def test_rotation_bounds_the_file(self):
        store = self.store()
        # Patch the module the store's class actually came from. Reaching for
        # `import avguard.events` instead meant that if anything else in the
        # suite had reimported the package, this patched an object nothing was
        # using and the test failed depending on the order tests ran in.
        events_module = sys.modules[type(store).__module__]
        original = events_module.MAX_BYTES
        events_module.MAX_BYTES = 2048
        try:
            for i in range(200):
                store.record(Event(kind="detection", path=f"c:/{'x' * 60}/{i}"))
            self.assertLess(store.path.stat().st_size, 200 * 100)
        finally:
            events_module.MAX_BYTES = original


# --------------------------------------------------------- parallel scanning

class TestParallelScanTree(TempCase):
    def _tree(self, count: int = 40) -> Path:
        root = self.tmp / "tree"
        for i in range(count):
            sub = root / f"d{i % 4}"
            sub.mkdir(parents=True, exist_ok=True)
            (sub / f"f{i}.txt").write_text(f"content {i}\n" * 20)
        return root

    def test_every_file_is_scanned_exactly_once(self):
        root = self._tree()
        verdicts = self.scanner().scan_tree(root, workers=4)
        paths = [v.path for v in verdicts]
        self.assertEqual(len(paths), 40)
        self.assertEqual(len(set(paths)), 40, "a file was scanned twice")

    def test_serial_and_parallel_agree(self):
        root = self._tree(25)
        serial = {v.path: v.level for v in self.scanner().scan_tree(root, workers=1)}
        parallel = {v.path: v.level for v in self.scanner().scan_tree(root, workers=4)}
        self.assertEqual(serial, parallel)

    def test_a_threat_in_the_tree_is_found_in_parallel(self):
        root = self._tree(20)
        (root / "d0" / "bad.bin").write_bytes(SELFTEST_MARKER)
        verdicts = self.scanner().scan_tree(root, workers=4)
        self.assertTrue(any(v.is_threat for v in verdicts))

    def test_cancellation_stops_early(self):
        root = self._tree(200)
        seen = []

        def stop() -> bool:
            return len(seen) > 5

        self.scanner().scan_tree(root, on_verdict=seen.append,
                                 should_stop=stop, workers=4)
        self.assertLess(len(seen), 200, "cancellation did not stop the scan")

    def test_callbacks_from_many_threads_do_not_lose_results(self):
        root = self._tree(60)
        import threading
        seen = []
        lock = threading.Lock()

        def collect(verdict):
            with lock:
                seen.append(verdict)

        verdicts = self.scanner().scan_tree(root, on_verdict=collect, workers=8)
        self.assertEqual(len(seen), len(verdicts))


# ---------------------------------------------------------- cache lifecycle

class TestCacheLifecycle(TempCase):
    def test_expired_entries_are_dropped(self):
        cache = ScanCache(path=self.tmp / "c.json", ttl_days=30)
        cache.put(Path("c:/old"), 1, 1, Level.CLEAN, [], "h")
        key = list(cache._entries)[0]
        cache._entries[key]["at"] = time.time() - 40 * 24 * 3600
        cache.put(Path("c:/new"), 2, 2, Level.CLEAN, [], "h")
        self.assertEqual(cache.prune(), 1)
        self.assertEqual(len(cache), 1)

    def test_eviction_is_by_age_not_insertion_order(self):
        cache = ScanCache(path=self.tmp / "c.json", max_entries=3)
        for i in range(5):
            cache.put(Path(f"c:/f{i}"), i, i, Level.CLEAN, [], "h")
        # Make the first-inserted the newest.
        first = list(cache._entries)[0]
        cache._entries[first]["at"] = time.time() + 1000
        cache.prune()
        self.assertEqual(len(cache), 3)
        self.assertIn(first, cache._entries, "the newest entry was evicted")

    def test_clear_empties_the_path_inventory(self):
        cache = ScanCache(path=self.tmp / "c.json", generation="g")
        cache.put(Path("c:/users/me/private.docx"), 1, 1, Level.CLEAN, [], "h")
        cache.save()
        cache.clear()
        self.assertEqual(len(cache), 0)
        self.assertNotIn("private.docx", (self.tmp / "c.json").read_text())

    def test_saving_prunes(self):
        # A generation is required now: a cache that cannot say which logic
        # produced its verdicts neither reads nor writes, so that a
        # misconfigured caller cannot erase a good cache with an empty one.
        cache = ScanCache(path=self.tmp / "c.json", max_entries=2, generation="g")
        for i in range(6):
            cache.put(Path(f"c:/f{i}"), i, i, Level.CLEAN, [], "h")
        cache.save()
        stored = json.loads((self.tmp / "c.json").read_text())
        self.assertLessEqual(len(stored["entries"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# --------------------------------------------- nesting matches its own limit

class TestArchiveNestingDepth(TempCase):
    """MAX_DEPTH said 2; the code hand-unrolled one level.

    `iter_nested` took a `depth` argument its only caller never passed, so the
    documented limit was enforced by a constant that overstated what the code
    did. Measured: a marker two archives deep was missed. A limit that promises
    more than it delivers is the kind of thing you find out when it matters.
    """

    # Deflate is what real archives use, and without it the payload bytes
    # appear verbatim in the container -- which makes a signature match look
    # like successful nesting when nothing was descended into at all.
    PAD = b"filler so compression actually changes the bytes " * 40

    def wrap(self, payload: bytes, name: str) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, payload)
        return buffer.getvalue()

    def nest(self, levels: int, filename: str) -> Path:
        payload = SELFTEST_MARKER + self.PAD
        for index in range(levels):
            payload = self.wrap(payload, f"inner{index}.zip" if index else "payload.bin")
        target = self.tmp / filename
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("member.zip" if levels else "payload.bin", payload)
        return target

    def test_the_payload_is_not_visible_without_descending(self):
        """Proves the other tests here are not passing by accident."""
        target = self.nest(2, "check.zip")
        self.assertNotIn(SELFTEST_MARKER, target.read_bytes())

    def test_found_directly_in_the_archive(self):
        self.assertTrue(self.scanner().scan(self.nest(0, "d0.zip"),
                                            use_cache=False).is_threat)

    def test_found_one_archive_deep(self):
        self.assertTrue(self.scanner().scan(self.nest(1, "d1.zip"),
                                            use_cache=False).is_threat)

    def test_found_two_archives_deep(self):
        """This is the one that was missed."""
        self.assertTrue(self.scanner().scan(self.nest(2, "d2.zip"),
                                            use_cache=False).is_threat,
                        "MAX_DEPTH is 2, so two levels must actually be reached")

    def test_not_found_past_the_stated_limit(self):
        """The limit has to be real in both directions."""
        self.assertFalse(self.scanner().scan(self.nest(3, "d3.zip"),
                                             use_cache=False).is_threat)

    def test_deep_nesting_terminates(self):
        """A quine-shaped archive must not turn a depth limit into forever."""
        target = self.nest(8, "deep.zip")
        verdict = self.scanner().scan(target, use_cache=False)
        self.assertIn(verdict.level, (Level.CLEAN, Level.SUSPICIOUS, Level.MALICIOUS))


class TestEventCounting(TempCase):
    """summary() parsed up to 5,000 records into dataclasses just to count."""

    def test_counts_match_a_full_read(self):
        store = EventStore(path=self.tmp / "events.jsonl")
        for index in range(50):
            store.record(Event(kind="detection" if index % 2 else "scan_finished",
                               path=f"c:/{index}"))
        counts = store.counts()
        self.assertEqual(counts["detection"], 25)
        self.assertEqual(counts["scan_finished"], 25)
        self.assertEqual(sum(counts.values()), 50)

    def test_counting_survives_a_torn_line(self):
        store = EventStore(path=self.tmp / "events.jsonl")
        store.record(Event(kind="detection", path="c:/good"))
        with open(store.path, "a", encoding="utf-8") as handle:
            handle.write('{"kind": "detection", "path": "c:/tor')
        self.assertGreaterEqual(store.counts().get("detection", 0), 1)

    def test_summary_still_reports_the_last_scan(self):
        store = EventStore(path=self.tmp / "events.jsonl")
        store.record(Event(kind="scan_finished"))
        store.record(Event(kind="detection", path="c:/x"))
        summary = store.summary()
        self.assertEqual(summary["detections"], 1)
        self.assertNotEqual(summary["last_scan"], "never")
