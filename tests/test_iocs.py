"""The hash blocklist: a hit condemns, the list is detection state, the feed is opt-in.

The point of these tests is the refusals and the invariants, not the happy
path. A malformed or truncated download must leave the list exactly as it
was; a file cached CLEAN before an import must be judged again; nothing is
fetched unless the user said so.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolate the data directory BEFORE avguard is imported: the blocklist lives
# there, and the real one must never be touched by a test.
import os as _os
import tempfile as _tempfile

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)


def _remove_tree(path) -> None:
    """rmtree that copes with read-only files."""
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
    import atexit as _atexit
    _atexit.register(_remove_tree, _test_data)


from avguard import config, iocs
from avguard import scanner as scanner_module
from avguard.allowlist import Allowlist
from avguard.iocs import FeedError, IocStore, parse_hashes, scheduled_update
from avguard.protection import SelfProtection
from avguard.rulepacks import PackStore
from avguard.scanner import Level, ScanCache, Scanner

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None) -> None:
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self.closed = False

    def iter_content(self, size: int):
        for start in range(0, len(self._body), size):
            yield self._body[start:start + size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Records what would have gone over the wire."""

    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.calls: list[dict] = []

    def get(self, url, headers=None, timeout=None, stream=False):
        self.calls.append({"url": url, "headers": dict(headers or {})})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def feed_body(count: int = 150, prefix: str = "") -> bytes:
    lines = ["#" * 64, "# MalwareBazaar recent malware samples (SHA256 hashes)", "#", "# sha256_hash"]
    for index in range(count):
        lines.append(sha256_of(f"{prefix}sample-{index}".encode()))
    return ("\n".join(lines) + "\n").encode()


class IocCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-iocs-"))
        self.addCleanup(_remove_tree, self.tmp)
        self.store = IocStore(path=self.tmp / "iocs.sqlite")
        self.addCleanup(self.store.close)

    def scanner(self) -> Scanner:
        return Scanner(config.Config(cloud_enabled=False),
                       SelfProtection([self.tmp / "nothing"]),
                       cache=ScanCache(path=self.tmp / "c.json"),
                       packs=PackStore(directory=self.tmp / "packs",
                                       index_path=self.tmp / "packs" / "packs.json"),
                       allowlist=Allowlist(path=self.tmp / "allow.json"),
                       iocs=self.store)

    def sample(self, name: str = "sample.bin", data: bytes = b"perfectly ordinary bytes " * 8) -> Path:
        path = self.tmp / name
        path.write_bytes(data)
        return path


# ----------------------------------------------------------------- verdicts

class TestAListedHashCondemns(IocCase):
    def test_a_hit_is_malicious_and_names_the_source(self):
        target = self.sample()
        scanner = self.scanner()
        self.assertIs(scanner.scan(target, use_cache=False).level, Level.CLEAN)

        self.store.import_lines([sha256_of(target.read_bytes())], source="unit-feed")
        verdict = scanner.scan(target, use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)
        self.assertTrue(verdict.is_threat)
        self.assertIn("unit-feed blocklist", " ".join(verdict.reasons))
        hit = [f for f in verdict.findings if f.source == "ioc"]
        self.assertEqual(len(hit), 1)
        self.assertTrue(hit[0].hard, "a confirmed-malware hash is hard evidence")

    def test_a_miss_changes_nothing(self):
        self.store.import_lines([sha256_of(b"something else")], source="unit-feed")
        verdict = self.scanner().scan(self.sample(), use_cache=False)
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertFalse([f for f in verdict.findings if f.source == "ioc"])

    def test_the_users_decision_outranks_the_list(self):
        """A restore is a decision about exact bytes; the list is somebody
        else's opinion about the same bytes."""
        target = self.sample()
        digest = sha256_of(target.read_bytes())
        self.store.import_lines([digest], source="unit-feed")
        scanner = self.scanner()
        scanner.allowlist.add(digest, "sample.bin", ["blocklist"])
        verdict = scanner.scan(target, use_cache=False)
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertIn("you chose to keep", verdict.reasons[0])

    def test_removing_the_row_returns_the_file_to_clean_with_the_cache_on(self):
        """Acceptance: the generation changes, so the cached MALICIOUS goes."""
        target = self.sample()
        digest = sha256_of(target.read_bytes())
        self.store.import_lines([digest], source="unit-feed")
        scanner = self.scanner()
        with mock.patch.object(scanner_module, "PACKS_CHECK_INTERVAL", 0.0):
            self.assertIs(scanner.scan(target).level, Level.MALICIOUS)   # cached now
            before = scanner.detection_generation()
            self.assertTrue(self.store.remove(digest))
            self.assertNotEqual(before, scanner.detection_generation())
            self.assertIs(scanner.scan(target).level, Level.CLEAN)

    def test_a_corrupt_database_is_a_miss_not_a_crash(self):
        (self.tmp / "iocs.sqlite").write_bytes(b"this is not a database" * 100)
        broken = IocStore(path=self.tmp / "iocs.sqlite")
        self.addCleanup(broken.close)
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "nothing"]),
                          cache=ScanCache(path=self.tmp / "c.json"),
                          packs=PackStore(directory=self.tmp / "packs",
                                          index_path=self.tmp / "packs" / "packs.json"),
                          allowlist=Allowlist(path=self.tmp / "allow.json"),
                          iocs=broken)
        self.assertIs(scanner.scan(self.sample(), use_cache=False).level, Level.CLEAN)
        self.assertEqual(broken.count(), 0)


# ------------------------------------------------------------ the generation

class TestTheListIsDetectionState(IocCase):
    def test_an_import_changes_the_generation(self):
        scanner = self.scanner()
        before = scanner.detection_generation()
        self.store.import_lines([sha256_of(b"x")], source="unit-feed")
        self.assertNotEqual(before, scanner.detection_generation())

    def test_an_import_that_adds_nothing_new_leaves_it_alone(self):
        self.store.import_lines([sha256_of(b"x")], source="unit-feed")
        scanner = self.scanner()
        before = scanner.detection_generation()
        result = self.store.import_lines([sha256_of(b"x")], source="unit-feed")
        self.assertEqual(result.added, 0)
        self.assertEqual(result.already_known, 1)
        self.assertEqual(before, scanner.detection_generation())

    def test_an_import_from_another_process_reaches_a_running_scanner(self):
        """`--iocs-import` in a terminal while the GUI runs, cache on."""
        target = self.sample()
        scanner = self.scanner()
        with mock.patch.object(scanner_module, "PACKS_CHECK_INTERVAL", 0.0):
            self.assertIs(scanner.scan(target).level, Level.CLEAN)    # cached CLEAN
            other = IocStore(path=self.store.path)
            self.addCleanup(other.close)
            other.import_lines([sha256_of(target.read_bytes())], source="terminal")
            self.assertIs(scanner.scan(target).level, Level.MALICIOUS,
                          "the cached CLEAN outlived the import")

    def test_count_is_kept_without_counting(self):
        digests = [sha256_of(f"{i}".encode()) for i in range(50)]
        self.store.import_lines(digests, source="a")
        self.store.import_lines(digests[:10], source="b")     # already known
        self.assertEqual(self.store.count(), 50)
        self.store.remove(digests[0])
        self.assertEqual(self.store.count(), 49)
        self.assertEqual(self.store.clear_source("a"), 49)
        self.assertEqual(self.store.count(), 0)
        self.assertEqual(self.store.sources(), {})


# ----------------------------------------------------------------- parsing

class TestParsing(unittest.TestCase):
    def test_only_sixty_four_hex_characters_count(self):
        good = sha256_of(b"ok")
        digests, rejected, seen = parse_hashes([
            good,
            good.upper(),
            good[:63],                       # one short
            good[:63] + "g",                 # not hex
            "  " + good + "  ",              # padded
            f'"{good}"',                     # quoted
            f"{good},Trojan.Agent,2026",     # a CSV tail
            "",
            "# a comment",
            "#" + good,
        ])
        self.assertEqual(seen, 7)
        self.assertEqual(rejected, 2)
        self.assertEqual(len(digests), 5)
        self.assertTrue(all(d == bytes.fromhex(good) for d in digests))

    def test_import_file_reports_lines_rejected(self):
        tmp = Path(tempfile.mkdtemp(prefix="avguard-iocs-"))
        store = IocStore(path=tmp / "iocs.sqlite")
        try:
            listing = tmp / "hashes.txt"
            listing.write_text("# threat intel, pasted\n" + sha256_of(b"a") + "\n"
                               "not-a-hash\n" + sha256_of(b"b") + "\n", encoding="utf-8")
            result = store.import_file(listing, source="pasted")
            self.assertEqual((result.added, result.rejected, result.lines), (2, 1, 3))
            self.assertEqual(store.sources(), {"pasted": 2})
        finally:
            store.close()
            _remove_tree(tmp)


# --------------------------------------------------------------------- feed

class TestTheFeedNeverHarmsTheList(IocCase):
    def test_a_real_looking_download_is_merged_and_the_etag_kept(self):
        session = FakeSession(FakeResponse(200, feed_body(150), {"ETag": '"abc-123"'}))
        result = self.store.update_from_feed(session=session)
        self.assertEqual(result.status, "updated")
        self.assertEqual(result.imported.added, 150)
        self.assertEqual(self.store.sources(), {iocs.FEED_SOURCE: 150})
        self.assertNotIn("If-None-Match", session.calls[0]["headers"])
        self.assertTrue(session.response.closed)

        again = FakeSession(FakeResponse(304))
        result = self.store.update_from_feed(session=again)
        self.assertEqual(result.status, "unchanged")
        self.assertEqual(again.calls[0]["headers"].get("If-None-Match"), '"abc-123"')
        self.assertEqual(self.store.count(), 150)

    def test_a_tiny_download_is_refused_whole(self):
        """A captive portal or an error page must not touch the list."""
        self.store.import_lines([sha256_of(b"kept")], source="manual")
        version = self.store.version()
        session = FakeSession(FakeResponse(200, b"<html>Sign in to the network</html>"))
        with self.assertRaises(FeedError) as caught:
            self.store.update_from_feed(session=session)
        self.assertIn("unchanged", str(caught.exception))
        self.assertEqual(self.store.count(), 1)
        self.assertEqual(self.store.version(), version)
        few = FakeSession(FakeResponse(200, feed_body(iocs.FEED_MIN_VALID_LINES - 1)))
        with self.assertRaises(FeedError):
            self.store.update_from_feed(session=few)
        self.assertEqual(self.store.count(), 1)

    def test_a_failed_fetch_leaves_the_list_alone(self):
        import requests
        self.store.import_lines([sha256_of(b"kept")], source="manual")
        session = FakeSession(requests.ConnectionError("network unreachable"))
        with self.assertRaises(FeedError):
            self.store.update_from_feed(session=session)
        self.assertEqual(self.store.count(), 1)
        for status in (403, 429, 500):
            with self.assertRaises(FeedError):
                self.store.update_from_feed(session=FakeSession(FakeResponse(status, b"x" * 10)))
        self.assertEqual(self.store.count(), 1)

    def test_a_failure_mid_write_rolls_back(self):
        """One transaction: a write that dies halfway leaves nothing behind."""
        self.store.import_lines([sha256_of(b"kept")], source="manual")
        version = self.store.version()
        good = [bytes.fromhex(sha256_of(f"{i}".encode())) for i in range(100)]
        with self.assertRaises(sqlite3.Error):
            self.store.import_digests(good + [object()], source="broken")  # type: ignore[list-item]
        self.assertEqual(self.store.count(), 1)
        self.assertEqual(self.store.version(), version)
        self.assertEqual(self.store.sources(), {"manual": 1})

    def test_the_full_export_arrives_zipped(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("full_sha256.txt", feed_body(200, prefix="full-"))
        session = FakeSession(FakeResponse(200, buffer.getvalue(), {"ETag": '"zip-1"'}))
        result = self.store.update_from_feed(session=session, full=True)
        self.assertEqual(result.imported.added, 200)
        self.assertEqual(session.calls[0]["url"], iocs.FEED_FULL_URL)

    def test_an_oversized_download_is_refused(self):
        with mock.patch.object(iocs, "FEED_MAX_BYTES", 1024):
            session = FakeSession(FakeResponse(200, feed_body(150)))
            with self.assertRaises(FeedError):
                self.store.update_from_feed(session=session)
        self.assertEqual(self.store.count(), 0)


class TestTheFeedIsOptIn(IocCase):
    def test_nothing_is_fetched_unless_enabled(self):
        session = FakeSession(FakeResponse(200, feed_body(150)))
        result = scheduled_update(self.store, enabled=False, session=session)
        self.assertEqual(result.status, "disabled")
        self.assertEqual(session.calls, [], "a request went out with the feed off")
        self.assertEqual(self.store.count(), 0)

    def test_at_most_once_a_day(self):
        session = FakeSession(FakeResponse(200, feed_body(150), {"ETag": '"e"'}))
        first = scheduled_update(self.store, enabled=True, session=session)
        self.assertEqual(first.status, "updated")
        second = scheduled_update(self.store, enabled=True, session=session)
        self.assertEqual(second.status, "not due")
        self.assertEqual(len(session.calls), 1)
        later = scheduled_update(self.store, enabled=True, session=session,
                                 now=__import__("time").time() + iocs.FEED_INTERVAL_SECONDS + 1)
        self.assertEqual(later.status, "updated")
        self.assertEqual(len(session.calls), 2)

    def test_the_default_setting_is_off(self):
        self.assertFalse(config.Config().ioc_feed_enabled)


class TestWhatTheUserIsTold(IocCase):
    def test_the_health_row_reads_as_english(self):
        """AVGuardApp._describe_iocs needs no window; hand it what it reads."""
        try:
            from avguard import gui
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        from types import SimpleNamespace
        fake = SimpleNamespace(scanner=SimpleNamespace(iocs=self.store),
                               cfg=config.Config(ioc_feed_enabled=False))
        text = gui.AVGuardApp._describe_iocs(fake)
        self.assertIn("empty", text)
        self.assertIn("nothing is fetched", text)
        self.store.import_lines([sha256_of(b"a"), sha256_of(b"b")], source="pasted")
        fake.cfg.ioc_feed_enabled = True
        text = gui.AVGuardApp._describe_iocs(fake)
        self.assertIn("2 hash(es)", text)
        self.assertIn("2 from pasted", text)
        self.assertIn("not fetched yet", text)

    def test_the_status_verb_on_an_empty_list(self):
        import contextlib
        import avguard.__main__ as cli
        out = io.StringIO()
        with mock.patch.object(iocs, "IOC_DB_PATH", self.tmp / "cli.sqlite"),                 mock.patch.object(iocs.IocStore.__init__, "__defaults__", (self.tmp / "cli.sqlite",)),                 contextlib.redirect_stdout(out):
            code = cli.main(["--iocs-status"])
        self.assertEqual(code, 0)
        self.assertIn("0 hash(es)", out.getvalue())
        self.assertIn("never fetched", out.getvalue())

    def test_import_of_a_missing_file_is_a_message_not_a_traceback(self):
        import contextlib
        import avguard.__main__ as cli
        err = io.StringIO()
        with mock.patch.object(iocs.IocStore.__init__, "__defaults__", (self.tmp / "cli.sqlite",)),                 contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["--iocs-import", str(self.tmp / "nowhere.txt")])
        self.assertEqual(code, 1)
        self.assertIn("Could not read", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
