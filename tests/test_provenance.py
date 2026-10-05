"""Where a file came from (avguard/provenance.py): the download mark parsed,
read and written, the scanner's weight-0 findings and the invariant that they
change no verdict, the member store, the quarantine keeping the mark, the
window saying it once, and the timings.

The mark is an NTFS alternate stream. On Windows these tests write and read
the real stream; elsewhere the same name is an ordinary file beside the one
asked about, which read_zone() opens the same way.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import hashlib
import os as _os
import shutil
import sys
import tempfile as _tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-provenance-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)
if _os.environ["AVGUARD_DATA"] == _test_data:
    import atexit as _atexit
    _atexit.register(lambda: shutil.rmtree(_test_data, ignore_errors=True))

from avguard import config, provenance
from avguard.allowlist import Allowlist
from avguard.events import EventStore
from avguard.protection import SelfProtection
from avguard.provenance import ProvenanceStore, Zone, parse_zone, read_zone, write_zone
from avguard.quarantine import QuarantineStore
from avguard.scanner import SELFTEST_MARKER, Finding, Level, ScanCache, Scanner, Verdict, decide

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "malware.yara"
FIXTURES = Path(__file__).resolve().parent / "rules"
HOST_URL = "https://user:pw@Downloads.Example.test:8443/files/app.zip?token=sekrit-1"
HOST = "downloads.example.test"
WINDOWS = sys.platform == "win32"


def mark(path: Path, zone_id: int = 3, host_url: str | None = HOST_URL) -> None:
    """Put a download mark on `path`: the real stream on Windows, a sibling file elsewhere."""
    text = f"[ZoneTransfer]\r\nZoneId={zone_id}\r\n" + (f"HostUrl={host_url}\r\n" if host_url else "")
    with open(provenance.stream_path(path), "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def exe_bytes(seed: str) -> bytes:
    return b"MZ" + hashlib.sha256(seed.encode()).digest() * 40


class ProvenanceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(_tempfile.mkdtemp(prefix="avguard-prov-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = ProvenanceStore(self.tmp / "provenance.sqlite")
        self.addCleanup(self.store.close)

    def write(self, name: str, data: bytes) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


# ------------------------------------------------------------------ the mark

class TestTheMark(ProvenanceCase):
    def test_the_stream_is_parsed_and_only_the_host_is_kept(self):
        zone = parse_zone("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=" + HOST_URL + "\r\n")
        self.assertEqual(zone, Zone(3, HOST))
        self.assertTrue(zone.marked)
        self.assertEqual(zone.describe(), "downloaded from " + HOST)
        for secret in ("sekrit", "token", "user:pw", "/files/", "8443"):
            self.assertNotIn(secret, repr(zone) + zone.describe(), "the URL appears nowhere")

    def test_the_variants_browsers_write(self):
        self.assertEqual(parse_zone("\ufeff[zonetransfer]\nzoneid=3\nhosturl=about:internet\n"), Zone(3, ""))
        self.assertEqual(parse_zone("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a.example.test/x\r\n"
                                    "HostUrl=https://cdn.example.test/y\r\n"),
                         Zone(3, "cdn.example.test", "a.example.test"))
        self.assertEqual(parse_zone("[ZoneTransfer]\r\nZoneId=0\r\n").marked, False)
        self.assertEqual(parse_zone("[ZoneTransfer]\r\nZoneId=3\r\n").describe(), "downloaded from the internet")
        self.assertIsNone(parse_zone("[Other]\r\nZoneId=3\r\n"), "not a transfer block")
        self.assertIsNone(parse_zone("[ZoneTransfer]\r\nZoneId=three\r\n"))
        self.assertIsNone(parse_zone(""))
        self.assertIsNone(parse_zone("random bytes \x00\x01"))

    def test_read_zone_reads_the_stream_or_says_none(self):
        marked = self.write("marked.exe", exe_bytes("a"))
        mark(marked)
        self.assertEqual(read_zone(marked), Zone(3, HOST))
        plain = self.write("plain.exe", exe_bytes("b"))
        self.assertIsNone(read_zone(plain))
        self.assertIsNone(read_zone(self.tmp / "missing.exe"))
        huge = self.write("huge.exe", exe_bytes("c"))
        with open(provenance.stream_path(huge), "w", newline="") as handle:
            handle.write("[ZoneTransfer]\r\nZoneId=3\r\n" + "x" * (1 << 20))
        self.assertEqual(read_zone(huge).zone_id, 3, "only the first lines are read")

    def test_write_zone_marks_on_windows_and_writes_nothing_elsewhere(self):
        target = self.write("restored.exe", exe_bytes("d"))
        written = write_zone(target, 3)
        if WINDOWS:
            self.assertTrue(written)
            self.assertEqual(read_zone(target), Zone(3, ""), "the zone only; no URL")
        else:
            self.assertFalse(written)
            self.assertFalse(Path(provenance.stream_path(target)).exists(), "no stray file off Windows")
            self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["restored.exe"])

    def test_timings_are_printed(self):
        folder = self.tmp / "many"
        folder.mkdir()
        plain = [folder / f"p{i}.exe" for i in range(1000)]
        marked = [folder / f"m{i}.exe" for i in range(1000)]
        for path in plain + marked:
            path.write_bytes(b"MZ")
        for path in marked:
            mark(path)
        read_zone(marked[0]); read_zone(plain[0])
        started = time.perf_counter()
        hits = sum(1 for p in marked if read_zone(p) is not None)
        marked_us = (time.perf_counter() - started) / 1000 * 1e6
        started = time.perf_counter()
        misses = sum(1 for p in plain if read_zone(p) is None)
        plain_us = (time.perf_counter() - started) / 1000 * 1e6
        self.assertEqual((hits, misses), (1000, 1000))
        digests = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(1000)]
        self.store.lookup(digests[0])
        started = time.perf_counter()
        found = sum(1 for d in digests if self.store.lookup(d) is not None)
        lookup_us = (time.perf_counter() - started) / 1000 * 1e6
        self.assertEqual(found, 0)
        print(f"\n  read_zone: {marked_us:.0f} us per marked file, {plain_us:.0f} us per unmarked file "
              f"(1,000 each, warm, {'the real stream' if WINDOWS else 'a sibling file'}); "
              f"store lookup: {lookup_us:.0f} us per miss (1,000)")


# ------------------------------------------------------------------ the scan

class TestTheScannerSaysWhereAFileCameFrom(ProvenanceCase):
    def setUp(self) -> None:
        super().setUp()
        self.cfg = config.Config(cloud_enabled=False)
        self.protection = SelfProtection([self.tmp / "protected"])
        (self.tmp / "protected").mkdir()
        self.cache = ScanCache(path=self.tmp / "cache.json")
        self.scanner = Scanner(self.cfg, self.protection, rules_path=RULES, cache=self.cache,
                               allowlist=Allowlist(path=self.tmp / "allow.json"))
        self.scanner.provenance = self.store

    def provenance_of(self, verdict: Verdict) -> list[Finding]:
        return [f for f in verdict.findings if f.source == "provenance"]

    def test_a_clean_download_is_clean_with_nothing_said(self):
        path = self.write("Downloads" + _os.sep + "tool.exe", exe_bytes("clean"))
        mark(path)
        verdict = self.scanner.scan(path)
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertEqual(verdict.findings, [])
        self.assertEqual(verdict.reasons, [])

    def test_a_flagged_download_says_the_host_at_weight_zero(self):
        path = self.write("Downloads" + _os.sep + "bad.exe", SELFTEST_MARKER)
        mark(path)
        verdict = self.scanner.scan(path)
        self.assertIs(verdict.level, Level.MALICIOUS)
        found = self.provenance_of(verdict)
        self.assertEqual([(f.name, f.weight, f.hard) for f in found], [("downloaded", 0, False)])
        self.assertEqual(found[0].detail, "downloaded from " + HOST)
        self.assertIn("downloaded from " + HOST, verdict.reasons)
        for secret in ("sekrit", "token", "user:pw", "/files/"):
            self.assertNotIn(secret, " ".join(verdict.reasons))
        self.assertEqual(decide(verdict.findings, self.cfg.quarantine_threshold),
                         decide([f for f in verdict.findings if f.source != "provenance"],
                                self.cfg.quarantine_threshold))
        replay = self.scanner.scan(path)
        self.assertEqual([f.detail for f in self.provenance_of(replay)], ["downloaded from " + HOST],
                         "the cache replay knows where it came from too")

    def test_an_unmarked_flagged_file_says_nothing_about_where_it_came_from(self):
        path = self.write("bad.exe", SELFTEST_MARKER)
        verdict = self.scanner.scan(path)
        self.assertIs(verdict.level, Level.MALICIOUS)
        self.assertEqual(self.provenance_of(verdict), [])

    def test_no_verdict_moves_for_the_mark_over_every_fixture(self):
        """decide() with and without the provenance findings, and the level of
        a marked copy against an unmarked one, for every rule fixture and the
        self-test marker."""
        files = sorted((FIXTURES / "must_match").iterdir()) + sorted((FIXTURES / "must_not_match").iterdir())
        flagged = 0
        for source in files + [None]:
            if source is None:
                plain = self.write("plain" + _os.sep + "marker.exe", SELFTEST_MARKER)
                marked = self.write("marked" + _os.sep + "marker.exe", SELFTEST_MARKER)
            else:
                plain = self.write("plain" + _os.sep + source.name, source.read_bytes())
                marked = self.write("marked" + _os.sep + source.name, source.read_bytes())
            mark(marked)
            unmarked_verdict = self.scanner.scan(plain, use_cache=False)
            verdict = self.scanner.scan(marked, use_cache=False)
            with self.subTest(file=marked.name):
                self.assertIs(verdict.level, unmarked_verdict.level)
                self.assertEqual(decide(verdict.findings, self.cfg.quarantine_threshold), verdict.level)
                self.assertEqual(decide([f for f in verdict.findings if f.source != "provenance"],
                                        self.cfg.quarantine_threshold), verdict.level)
                self.assertEqual([f for f in verdict.findings if f.source != "provenance"],
                                 unmarked_verdict.findings, "the other findings are untouched")
                if verdict.level in (Level.MALICIOUS, Level.SUSPICIOUS):
                    flagged += 1
                    self.assertEqual([f.name for f in self.provenance_of(verdict)], ["downloaded"])
                else:
                    self.assertEqual(self.provenance_of(verdict), [])
        self.assertGreaterEqual(flagged, 2, "the fixtures must include flagged files, or this tests nothing")

    def archive(self, name: str, members: dict[str, bytes], marked: bool = True) -> Path:
        path = self.tmp / "Downloads" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for member, data in members.items():
                zf.writestr(member, data)
        if marked:
            mark(path)
        return path

    def test_what_came_out_of_a_downloaded_archive_is_remembered_and_said(self):
        tool = exe_bytes("tool")
        archive = self.archive("app.zip", {"app/tool.exe": tool, "app/readme.txt": b"read me",
                                           "app/macro.docm": b"PK\x03\x04 a document"})
        verdict = self.scanner.scan(archive)
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertEqual(self.store.count(), 3, "every member looked at is remembered")
        origin = self.store.lookup(hashlib.sha256(tool).hexdigest())
        self.assertEqual((origin.member, origin.host, origin.container),
                         ("app.zip!app/tool.exe", HOST, str(archive)), "the member as the archive walk names it")

        extracted = self.write("Extracted" + _os.sep + "tool.exe", tool)
        said = self.scanner.scan(extracted)
        self.assertIs(said.level, Level.CLEAN)
        found = self.provenance_of(said)
        self.assertEqual([(f.name, f.weight, f.hard) for f in found], [("extracted", 0, False)])
        self.assertIn("extracted from app.zip (downloaded from " + HOST + ")", found[0].detail)
        self.assertIn("carries no download mark", found[0].detail)
        self.assertEqual(decide(said.findings, self.cfg.quarantine_threshold), Level.CLEAN)
        self.assertIsNotNone(provenance.extracted_finding(said.findings))
        replay = self.scanner.scan(extracted)
        self.assertEqual(len(self.provenance_of(replay)), 1, "and on the replay")

        document = self.write("Extracted" + _os.sep + "macro.docm", b"PK\x03\x04 a document")
        self.assertEqual([f.name for f in self.provenance_of(self.scanner.scan(document))], ["extracted"],
                         "a document Protected View would have gated counts too")
        text = self.write("Extracted" + _os.sep + "readme.txt", b"read me")
        self.assertEqual(self.provenance_of(self.scanner.scan(text)), [], "nothing gates a text file")

    def test_an_extracted_file_that_kept_its_mark_is_not_said_twice(self):
        tool = exe_bytes("kept")
        self.archive("kept.zip", {"tool.exe": tool})
        self.scanner.scan(self.tmp / "Downloads" / "kept.zip")
        extracted = self.write("Extracted" + _os.sep + "tool.exe", tool)
        mark(extracted)                       # Explorer's own extraction keeps the mark
        verdict = self.scanner.scan(extracted)
        self.assertEqual(self.provenance_of(verdict), [], "the mark says it; SmartScreen will ask")

    def test_an_archive_without_a_mark_remembers_nothing(self):
        self.archive("local.zip", {"tool.exe": exe_bytes("local")}, marked=False)
        self.scanner.scan(self.tmp / "Downloads" / "local.zip")
        self.assertEqual(self.store.count(), 0)
        extracted = self.write("Extracted" + _os.sep + "tool.exe", exe_bytes("local"))
        self.assertEqual(self.provenance_of(self.scanner.scan(extracted)), [])

    def test_a_marked_archive_with_a_detection_inside_says_both(self):
        archive = self.archive("bad.zip", {"payload.exe": SELFTEST_MARKER})
        verdict = self.scanner.scan(archive)
        self.assertIs(verdict.level, Level.MALICIOUS)
        self.assertEqual([f.name for f in self.provenance_of(verdict)], ["downloaded"])
        self.assertEqual(self.store.count(), 1)


# ----------------------------------------------------------------- the store

class TestTheStore(ProvenanceCase):
    def test_remember_lookup_told_and_the_caps(self):
        self.assertEqual(self.store.remember([], "x.zip", HOST), 0)
        self.assertIsNone(self.store.lookup("ab" * 32))
        self.assertIsNone(self.store.lookup(""))
        kept = self.store.remember([("AB" * 32, "a.exe"), ("cd" * 32, "b.exe"), ("", "nothing")], "C:/x/app.zip", HOST)
        self.assertEqual(kept, 2)
        origin = self.store.lookup("ab" * 32)
        self.assertEqual((origin.member, origin.container_name, origin.told), ("a.exe", "app.zip", False))
        self.store.mark_told("ab" * 32)
        self.assertTrue(self.store.lookup("ab" * 32).told)
        self.store.remember([("ab" * 32, "a2.exe")], "C:/x/app2.zip", "")
        again = self.store.lookup("ab" * 32)
        self.assertEqual((again.member, again.container_name), ("a2.exe", "app2.zip"), "the latest container wins")
        self.assertIn("downloaded from the internet", again.describe())
        self.addCleanup(setattr, provenance, "KEEP_ROWS", provenance.KEEP_ROWS)
        provenance.KEEP_ROWS = 3
        self.store.remember([(f"{i:064x}", f"m{i}.exe") for i in range(5)], "C:/x/big.zip", HOST)
        self.assertEqual(self.store.count(), 3, "the newest rows are the ones kept")

    def test_a_broken_database_never_reaches_a_scan(self):
        path = self.tmp / "broken.sqlite"
        path.write_bytes(b"not a database" * 50)
        store = ProvenanceStore(path)
        self.addCleanup(store.close)
        self.assertIsNone(store.lookup("ab" * 32))
        self.assertEqual(store.remember([("ab" * 32, "a.exe")], "x.zip", HOST), 0)
        self.assertEqual(store.count(), 0)


# ------------------------------------------------------------ the quarantine

class TestTheQuarantineKeepsTheMark(ProvenanceCase):
    def setUp(self) -> None:
        super().setUp()
        qdir = self.tmp / "store"
        self.quarantine = QuarantineStore(directory=qdir, index_path=qdir / "index.json",
                                          protection=SelfProtection([self.tmp / "protected"]),
                                          allowlist=Allowlist(path=self.tmp / "allow.json"))
        self.written: list[tuple[str, int]] = []
        if not WINDOWS:
            real = provenance.write_zone

            def recording(path, zone_id=3):
                self.written.append((str(path), zone_id))
                return real(path, zone_id)
            self.addCleanup(setattr, provenance, "write_zone", provenance.write_zone)
            provenance.write_zone = recording

    def marked_after(self, path: Path, zone_id: int = 3) -> bool:
        if WINDOWS:
            zone = read_zone(path)
            return zone is not None and zone.zone_id == zone_id
        return (str(path), zone_id) in self.written

    def test_the_zone_is_kept_and_put_back_on_restore_and_export(self):
        target = self.write("Downloads" + _os.sep + "bad.exe", SELFTEST_MARKER)
        mark(target, 3)
        record = self.quarantine.quarantine(target, ["test"], evidence={"findings": [], "sha256": "x"})
        kept = self.quarantine.evidence(record.entry_id)
        self.assertEqual(kept["zone"], 3)
        self.assertEqual(kept["findings"], [], "the evidence given is still there")
        exported = self.quarantine.export(record.entry_id, self.tmp / "out" / "sample.exe")
        self.assertTrue(self.marked_after(exported), "an exported sample is still a download")
        restored = self.quarantine.restore(record.entry_id)
        self.assertEqual(restored.read_bytes(), SELFTEST_MARKER)
        self.assertTrue(self.marked_after(restored), "a restored download is still a download")
        self.assertIsNone(self.quarantine.evidence(record.entry_id))

    def test_a_file_without_a_mark_is_restored_without_one(self):
        target = self.write("local.exe", SELFTEST_MARKER)
        record = self.quarantine.quarantine(target, ["test"])
        self.assertIsNone(self.quarantine.evidence(record.entry_id), "nothing to keep, nothing kept")
        restored = self.quarantine.restore(record.entry_id)
        self.assertFalse(self.marked_after(restored))
        if WINDOWS:
            self.assertIsNone(read_zone(restored))


# ---------------------------------------------------------------- the window

class TestTheWindowSaysItOnce(ProvenanceCase):
    """_on_verdict and _report_extracted, called unbound on a stand-in window."""

    def setUp(self) -> None:
        super().setUp()
        try:
            from avguard import gui
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        self.gui = gui
        self.events = EventStore(path=self.tmp / "events.jsonl")
        self.banners: list[str] = []
        self.posted: list = []
        self.app = SimpleNamespace(
            events=self.events, scanner=SimpleNamespace(provenance=self.store),
            _provenance_banners=set(), _banner=lambda text, style="": self.banners.append(text),
            post=lambda fn, *args: self.posted.append((fn, args)), _report_extracted="extracted-handler")

    def verdict(self, name: str, seed: str, container: str) -> Verdict:
        data = exe_bytes(seed)
        digest = hashlib.sha256(data).hexdigest()
        self.store.remember([(digest, name)], container, HOST)
        origin = self.store.lookup(digest)
        finding = Finding("provenance", "extracted", 0, origin.describe())
        return Verdict(self.tmp / name, Level.CLEAN, [finding.describe()], findings=[finding], sha256=digest)

    def test_one_history_row_per_file_ever_and_one_banner_per_archive_per_session(self):
        report = self.gui.AVGuardApp._report_extracted
        first = self.verdict("tool.exe", "one", "C:/Users/me/Downloads/app.zip")
        report(self.app, first)
        report(self.app, first)
        self.assertEqual(len(self.events.read(kinds={"provenance"})), 1, "told once")
        self.assertEqual(len(self.banners), 1)
        self.assertIn("extracted from app.zip", self.banners[0])
        self.assertIn(HOST, self.banners[0])
        event = self.events.read(kinds={"provenance"})[0]
        self.assertEqual((event.level, event.detail["host"], event.detail["container"]),
                         ("extracted", HOST, "C:/Users/me/Downloads/app.zip"))
        second = self.verdict("helper.exe", "two", "C:/Users/me/Downloads/app.zip")
        report(self.app, second)
        self.assertEqual(len(self.events.read(kinds={"provenance"})), 2, "a row for each file")
        self.assertEqual(len(self.banners), 1, "one banner per archive")
        other = self.verdict("setup.exe", "three", "C:/Users/me/Downloads/other.zip")
        report(self.app, other)
        self.assertEqual(len(self.banners), 2)
        fresh = SimpleNamespace(**{**vars(self.app), "_provenance_banners": set()})
        report(fresh, first)
        self.assertEqual(len(self.events.read(kinds={"provenance"})), 3, "the store remembers it was told")
        self.assertEqual(len(self.banners), 3, "a new session gets its banner again")

    def test_a_clean_extracted_verdict_is_posted_and_a_plain_clean_one_is_not(self):
        on_verdict = self.gui.AVGuardApp._on_verdict
        on_verdict(self.app, self.verdict("tool.exe", "one", "C:/x/app.zip"))
        self.assertEqual([fn for fn, _ in self.posted], ["extracted-handler"])
        on_verdict(self.app, Verdict(self.tmp / "plain.exe", Level.CLEAN))
        self.assertEqual(len(self.posted), 1)


if __name__ == "__main__":
    unittest.main()
