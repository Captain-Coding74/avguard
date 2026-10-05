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

    def test_a_cut_stream_does_not_read_a_username_as_the_host(self):
        """A referrer long enough to push HostUrl past the read limit left
        the cut line parsed as a whole one, and urlsplit read the username
        of "https://alice.smith:pw@..." as the host."""
        limit = provenance.MAX_STREAM_BYTES
        head = "[ZoneTransfer]\r\nZoneId=3\r\n"
        referrer_start = "ReferrerUrl=https://r.example.test/"
        referrer = referrer_start + "a" * (limit - 30 - len(head) - len(referrer_start) - 2) + "\r\n"
        hosturl = "HostUrl=https://alice.smith:pw-hunter2@downloads.example.test/x\r\n"
        self.assertEqual(len(head) + len(referrer), limit - 30, "the cut lands inside the password")
        path = self.write("cut.exe", exe_bytes("cut"))
        with open(provenance.stream_path(path), "w", newline="") as handle:
            handle.write(head + referrer + hosturl)
        zone = read_zone(path)
        self.assertEqual(zone, Zone(3, "", "r.example.test"))
        self.assertNotIn("alice", repr(zone))

    def test_hosts_are_hosts(self):
        from avguard.provenance import host_of
        self.assertEqual(host_of("https://user:p@ss@Host.Example/x?y"), "host.example")
        self.assertEqual(host_of("https://[2001:db8::1]/"), "2001:db8::1")
        self.assertEqual(host_of("https://b\u00fccher.example/"), "b\u00fccher.example")
        for bad in ("https://ho\x00st.example/", "https://ho\x1bst.example/", "https://ho st.example/",
                    "https://ex%61mple.test/", "https://" + "a" * 300 + ".test/", "about:internet",
                    "file:///C:/x.zip", "data:text/plain,hi", "not a url", ""):
            with self.subTest(url=bad):
                self.assertEqual(host_of(bad), "")

    def test_the_first_block_and_the_first_zone_id_count(self):
        self.assertEqual(parse_zone("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://a.test/x\u2028ZoneId=0\r\n"),
                         Zone(3, "a.test"), "a Unicode separator inside a URL is not a line break")
        self.assertEqual(parse_zone("[ZoneTransfer]\r\nZoneId=3\r\nZoneId=0\r\n").zone_id, 3)
        self.assertEqual(parse_zone("[ZoneTransfer]\r\nZoneId=3\r\n[ZoneTransfer]\r\nZoneId=0\r\n").zone_id, 3)
        self.assertEqual(parse_zone("[ZoneTransfer]\r\nZoneId=3\r\n[Other]\r\nHostUrl=https://b.test/\r\n").host, "")
        self.assertIsNone(parse_zone("[ZoneTransfer]\r\nZoneId=99\r\n"), "not a zone Windows has")
        self.assertIsNone(parse_zone("[ZoneTransfer]\r\nZoneId=-1\r\n"))

    @unittest.skipIf(WINDOWS, "a stream cannot be a FIFO")
    def test_a_fifo_beside_the_file_does_not_block(self):
        path = self.write("fifo.exe", exe_bytes("fifo"))
        _os.mkfifo(provenance.stream_path(path))
        started = time.monotonic()
        self.assertIsNone(read_zone(path))
        self.assertLess(time.monotonic() - started, 2.0)

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
        self.assertIn("has the bytes of tool.exe from app.zip (downloaded from " + HOST + ")", found[0].detail)
        self.assertIn("carries no download mark, so SmartScreen will not ask", found[0].detail)
        self.assertEqual(decide(said.findings, self.cfg.quarantine_threshold), Level.CLEAN)
        self.assertIsNotNone(provenance.extracted_finding(said.findings))
        replay = self.scanner.scan(extracted)
        self.assertEqual(len(self.provenance_of(replay)), 1, "and on the replay")

        document = self.write("Extracted" + _os.sep + "macro.docm", b"PK\x03\x04 a document")
        said_of_document = self.provenance_of(self.scanner.scan(document))
        self.assertEqual([f.name for f in said_of_document], ["extracted"],
                         "a document Protected View would have gated counts too")
        self.assertIn("Office will not open it in Protected View", said_of_document[0].detail)
        self.assertNotIn("SmartScreen", said_of_document[0].detail, "a document is opened, not run")
        text = self.write("Extracted" + _os.sep + "readme.txt", b"read me")
        self.assertEqual(self.provenance_of(self.scanner.scan(text)), [], "nothing gates a text file")

    def test_the_note_follows_the_store_not_the_cache(self):
        """Walk order is arbitrary: the program may be scanned before its
        archive. The note is computed live on every scan, replay included,
        and never stored in the cache."""
        tool = exe_bytes("order")
        extracted = self.write("Extracted" + _os.sep + "tool.exe", tool)
        self.assertEqual(self.provenance_of(self.scanner.scan(extracted)), [], "the archive is not known yet")
        self.archive("app.zip", {"tool.exe": tool})
        self.scanner.scan(self.tmp / "Downloads" / "app.zip")
        replay = self.scanner.scan(extracted)
        self.assertIsNone(replay.facts, "a cache replay")
        self.assertEqual([f.name for f in self.provenance_of(replay)], ["extracted"], "and it knows now")
        stat = extracted.stat()
        cached = self.cache.get(extracted, stat.st_size, stat.st_mtime_ns)
        self.assertEqual([f for f in cached["findings"] if f.get("source") == "provenance"], [],
                         "the cache keeps the conclusion only")
        with self.store._conn() as conn:
            conn.execute("DELETE FROM members")
        self.assertEqual(self.provenance_of(self.scanner.scan(extracted)), [], "forgotten in the store, gone from the replay")

    def test_a_cached_archive_marked_later_is_read_again(self):
        tool = exe_bytes("later")
        archive = self.archive("later.zip", {"tool.exe": tool}, marked=False)
        self.scanner.scan(archive)
        self.assertEqual(self.store.count(), 0)
        mark(archive)
        replay = self.scanner.scan(archive)
        self.assertIsNotNone(replay.facts, "read afresh: the mark is new and nothing of it is remembered")
        self.assertEqual(self.store.count(), 1)
        self.assertIsNone(self.scanner.scan(archive).facts, "known now; the next one replays")

    def test_installed_copies_are_not_said_to_be_extracted(self):
        """The bytes match; whether they were extracted or installed is not
        known, so nothing under Program Files or the Windows folder is said."""
        program_files = self.tmp / "Program Files"
        self.addCleanup(_os.environ.pop, "ProgramFiles", None)
        _os.environ["ProgramFiles"] = str(program_files)
        tool = exe_bytes("vcruntime")
        self.archive("tool.zip", {"vcruntime140.dll": tool, "tool.exe": tool})
        self.scanner.scan(self.tmp / "Downloads" / "tool.zip")
        installed = self.write("Program Files" + _os.sep + "Vendor" + _os.sep + "tool.exe", tool)
        self.assertEqual(self.provenance_of(self.scanner.scan(installed)), [])
        desktop = self.write("Desktop" + _os.sep + "tool.exe", tool)
        self.assertEqual([f.name for f in self.provenance_of(self.scanner.scan(desktop))], ["extracted"])
        self.assertTrue(provenance.is_installed("C:" + "\\" + "Windows" + "\\" + "System32" + "\\" + "x.exe"))

    def test_an_extracted_copy_marked_from_this_computer_is_still_said(self):
        tool = exe_bytes("zone0")
        self.archive("zone0.zip", {"tool.exe": tool})
        self.scanner.scan(self.tmp / "Downloads" / "zone0.zip")
        extracted = self.write("Extracted" + _os.sep + "tool.exe", tool)
        mark(extracted, zone_id=0, host_url=None)
        self.assertEqual([f.name for f in self.provenance_of(self.scanner.scan(extracted))], ["extracted"],
                         "a zone SmartScreen does not ask about is no mark in its sense")

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

    def test_a_broken_database_never_reaches_a_scan_and_is_opened_once(self):
        import sqlite3
        from unittest import mock
        path = self.tmp / "broken.sqlite"
        path.write_bytes(b"not a database" * 50)
        store = ProvenanceStore(path)
        self.addCleanup(store.close)
        with mock.patch.object(sqlite3, "connect", wraps=sqlite3.connect) as connect:
            for _ in range(5):
                self.assertIsNone(store.lookup("ab" * 32))
            self.assertEqual(store.remember([("ab" * 32, "a.exe")], "x.zip", HOST), 0)
            self.assertEqual(store.count(), 0)
            store.mark_told("ab" * 32)
        self.assertEqual(connect.call_count, 1, "given up on, not opened again for every file")

    def test_a_store_whose_folder_cannot_be_made_never_raises(self):
        blocker = self.tmp / "notadir"
        blocker.write_bytes(b"a file where a folder should be")
        store = ProvenanceStore(blocker / "provenance.sqlite")
        self.assertIsNone(store.lookup("ab" * 32))
        self.assertEqual(store.remember([("ab" * 32, "a.exe")], "x.zip", HOST), 0)
        self.assertEqual(store.count(), 0)
        store.mark_told("ab" * 32)
        self.assertTrue(store.touch_container("x.zip"), "unknown is not 'none remembered'")

    def test_a_row_older_than_ninety_days_is_forgotten_on_read(self):
        self.store.remember([("ab" * 32, "old.exe")], "C:/x/old.zip", HOST)
        with self.store._conn() as conn:
            conn.execute("UPDATE members SET seen = ?", (time.time() - 100 * 86400,))
        self.assertIsNone(self.store.lookup("ab" * 32), "ninety days means ninety days, whoever asks")
        self.assertEqual(self.store.count(), 1, "the sweep itself happens on the next write")
        self.assertTrue(self.store.touch_container("C:/x/old.zip"), "an archive seen again is current again")
        self.assertIsNotNone(self.store.lookup("ab" * 32))
        self.assertFalse(self.store.touch_container("C:/x/unknown.zip"))


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

    def test_a_bare_list_of_findings_as_evidence_does_not_raise_after_the_move(self):
        target = self.write("Downloads" + _os.sep + "bad2.exe", SELFTEST_MARKER)
        mark(target, 3)
        record = self.quarantine.quarantine(target, ["test"], evidence=[{"source": "signature", "name": "x",
                                                                          "weight": 100, "hard": True}])
        kept = self.quarantine.evidence(record.entry_id)
        self.assertEqual(kept["zone"], 3)
        self.assertEqual(kept["findings"][0]["source"], "signature")
        self.assertFalse(target.exists())

    def test_a_file_without_a_mark_is_restored_without_one(self):
        target = self.write("local.exe", SELFTEST_MARKER)
        record = self.quarantine.quarantine(target, ["test"])
        self.assertIsNone(self.quarantine.evidence(record.entry_id), "nothing to keep, nothing kept")
        restored = self.quarantine.restore(record.entry_id)
        self.assertFalse(self.marked_after(restored))
        if WINDOWS:
            self.assertIsNone(read_zone(restored))


# -------------------------------------------------------------- the account

class TestTheHistoryRowHasAnAccount(ProvenanceCase):
    def test_a_provenance_event_opens_into_the_row_that_says_where_the_bytes_came_from(self):
        from avguard import explain
        from avguard.events import Event
        from avguard.scanner import findings_to_dicts
        self.store.remember([("ab" * 32, "app.zip!tool.exe")], "C:/Users/me/Downloads/app.zip", HOST)
        finding = Finding("provenance", "extracted", 0, self.store.lookup("ab" * 32).describe())
        event = Event(kind="provenance", path="C:/Users/me/Desktop/tool.exe", level="clean",
                      reasons=[finding.describe()],
                      detail={"sha256": "ab" * 32, "container": "C:/Users/me/Downloads/app.zip", "host": HOST,
                              "findings": findings_to_dicts([finding])})
        self.assertTrue(explain.is_verdict_event(event), "double-click opens it")
        account = explain.from_event(event, config.Config(cloud_enabled=False))
        self.assertEqual([(r.kind, r.weight) for r in account.rows], [("fact", 0)])
        self.assertIn("the download mark on the archive whose member has these bytes", account.rows[0].words)
        self.assertIn("has the bytes of tool.exe from app.zip", account.rows[0].text)
        self.assertTrue(account.consistent)
        self.assertNotIn("rule's author", explain.render_text(account))

    def test_a_percent_in_a_name_is_not_a_confidence_figure(self):
        from avguard import explain
        finding = Finding("provenance", "extracted", 0, "has the bytes of 100%.exe from Sale 50% off.zip",
                          notes=("the archive: C:/Users/me/Downloads/Sale 50% off.zip",))
        account = explain.explain("x.exe", "clean", [finding.describe()], [finding],
                                  config.Config(cloud_enabled=False))
        self.assertIn("the archive: C:/Users/me/Downloads/Sale 50% off.zip", account.rows[0].notes)
        yara = Finding("yara", "r", 50, "d", notes=("95% confident",))
        account = explain.explain("x.exe", "suspicious", [yara.describe()], [yara], config.Config(cloud_enabled=False))
        self.assertNotIn("95% confident", account.rows[0].notes, "a rule author's figure is still left out")


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
        self.forwarded: list = []

        class AnyForwarder:                  # records whatever method the store would call
            def __getattr__(inner, name):
                return lambda *args, **kwargs: self.forwarded.append((name, args))
        self.events = EventStore(path=self.tmp / "events.jsonl", forwarder=AnyForwarder())
        self.banners: list[str] = []
        self.posted: list = []
        self.app = SimpleNamespace(
            events=self.events, scanner=SimpleNamespace(provenance=self.store),
            _provenance_banners=set(), _banner=lambda text, style="": self.banners.append(text),
            _scan_active=False, _banner_is_loud=lambda: False,
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
        self.assertIn("has the bytes of tool.exe from app.zip", self.banners[0])
        self.assertIn(HOST, self.banners[0])
        event = self.events.read(kinds={"provenance"})[0]
        self.assertEqual((event.level, event.detail["host"], event.detail["container"]),
                         ("clean", HOST, "C:/Users/me/Downloads/app.zip"))
        self.assertEqual(event.detail["findings"][0]["name"], "extracted", "History can open an account for it")
        self.assertEqual(self.forwarded, [], "a clean file's row stays on this machine")
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

    def test_the_banner_waits_for_a_quiet_moment(self):
        report = self.gui.AVGuardApp._report_extracted
        verdict = self.verdict("tool.exe", "quiet", "C:/Users/me/Downloads/app.zip")
        self.app._scan_active = True
        report(self.app, verdict)
        self.assertEqual(len(self.events.read(kinds={"provenance"})), 1, "History has it whatever the moment")
        self.assertEqual(self.banners, [], "the scan summary would replace it unseen")
        self.assertEqual(self.app._provenance_banners, set(), "not consumed")
        self.app._scan_active = False
        self.app._banner_is_loud = lambda: True
        report(self.app, verdict)
        self.assertEqual(self.banners, [], "a threat's banner, with its buttons, is not replaced")
        self.app._banner_is_loud = lambda: False
        report(self.app, verdict)
        self.assertEqual(len(self.banners), 1)
        self.assertEqual(len(self.events.read(kinds={"provenance"})), 1, "still one row")

    def test_a_clean_extracted_verdict_is_posted_and_a_plain_clean_one_is_not(self):
        on_verdict = self.gui.AVGuardApp._on_verdict
        on_verdict(self.app, self.verdict("tool.exe", "one", "C:/x/app.zip"))
        self.assertEqual([fn for fn, _ in self.posted], ["extracted-handler"])
        on_verdict(self.app, Verdict(self.tmp / "plain.exe", Level.CLEAN))
        self.assertEqual(len(self.posted), 1)


if __name__ == "__main__":
    unittest.main()
