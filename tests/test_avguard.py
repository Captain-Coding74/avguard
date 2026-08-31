"""Tests for AVGuard. Run with:  python -m unittest discover -s tests -v

Each test targets a specific defect the original build shipped with, so a
regression here means that bug has come back.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
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
_os.environ.setdefault(
    "AVGUARD_DATA",
    _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}"))



from avguard import config
from avguard.allowlist import Allowlist
from avguard.cloud import TokenBucket, VirusTotalClient
from avguard.protection import SelfProtection, matches_excluded_glob
from avguard.quarantine import QuarantineError, QuarantineStore, _mask
from avguard.scanner import (EICAR, SELFTEST_MARKER, SEVERITY_WEIGHTS, Level,
                             ScanCache, Scanner, shannon_entropy)
from avguard.watcher import RealtimeMonitor, ScanWorkerPool
from avguard.instance import InstanceLock

RULES = Path(__file__).resolve().parent.parent / "rules" / "malware.yara"


# Without this, warnings from the code under test go to logging's last-resort
# handler and scroll past the actual test results.
logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False


def _refuse_to_touch_real_data() -> None:
    """Fail loudly if a test is about to write into the user's real data.

    The suite silently wrote seven entries into
    %LOCALAPPDATA%/AVGuard/allowlist.json, because QuarantineStore builds a
    default Allowlist when it is not handed one. One of those entries was the
    hash of SELFTEST_MARKER, which then suppressed its own detection and broke
    four unrelated tests. A test that reaches into a user's real state is not
    a test, it is a side effect with an assertion attached.
    """
    import os
    from avguard import config
    override = os.getenv("AVGUARD_DATA")
    if not override:
        return
    if not str(config.DATA_DIR).startswith(str(pathlib.Path(override).resolve())):
        raise RuntimeError(
            f"AVGUARD_DATA is set to {override} but config.DATA_DIR is "
            f"{config.DATA_DIR}; the suite would write to the real location")


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path


# --------------------------------------------------------------- protection

class TestSelfProtection(TempCase):
    """The original build quarantined its own ruleset, source and log."""

    def setUp(self) -> None:
        super().setUp()
        self.app = self.tmp / "app"
        self.data = self.tmp / "app" / "data"
        self.rules = self.tmp / "app" / "rules"
        for d in (self.app, self.data, self.rules):
            d.mkdir(parents=True, exist_ok=True)
        self.protection = SelfProtection([self.app, self.data, self.rules])

    def test_protects_own_package_directory(self):
        self.assertTrue(self.protection.is_protected(self.app / "scanner.py"))

    def test_protects_nested_files(self):
        deep = self.data / "quarantine" / "abc.quar"
        deep.parent.mkdir(parents=True, exist_ok=True)
        deep.write_bytes(b"x")
        self.assertTrue(self.protection.is_protected(deep))

    def test_protects_the_ruleset(self):
        """The exact failure that disabled detection in the original build."""
        rules_file = self.rules / "malware.yara"
        rules_file.write_text("rule x { condition: true }")
        self.assertTrue(self.protection.is_protected(rules_file))

    def test_allows_unrelated_paths(self):
        other = self.tmp / "elsewhere" / "document.txt"
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_text("hello")
        self.assertFalse(self.protection.is_protected(other))

    def test_sibling_with_shared_prefix_is_not_protected(self):
        """The old code used substring matching, so 'app2' looked like 'app'."""
        sibling = self.tmp / "app2" / "notes.txt"
        sibling.parent.mkdir(parents=True, exist_ok=True)
        sibling.write_text("hello")
        self.assertFalse(self.protection.is_protected(sibling))

    def test_resolves_relative_and_dotted_paths(self):
        sneaky = self.app / "sub" / ".." / "scanner.py"
        self.assertTrue(self.protection.is_protected(sneaky))

    def test_excluded_globs_use_forward_slashes(self):
        self.assertTrue(matches_excluded_glob(
            r"C:\proj\__pycache__\x.pyc", ["**/__pycache__/**"]))
        self.assertFalse(matches_excluded_glob(
            r"C:\proj\src\x.py", ["**/__pycache__/**"]))


# ------------------------------------------------------------------ scanner

class TestScanner(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.cfg = config.Config(cloud_enabled=False)
        self.protection = SelfProtection([self.tmp / "protected"])
        (self.tmp / "protected").mkdir(exist_ok=True)
        self.cache = ScanCache(path=self.tmp / "cache.json")
        self.scanner = Scanner(self.cfg, self.protection,
                               rules_path=RULES, cache=self.cache)

    def test_rules_compile(self):
        self.assertIsNotNone(self.scanner.rules, "the shipped ruleset must compile")

    def test_detects_eicar_in_memory(self):
        """Checked against the YARA rule directly.

        An EICAR file cannot be written to disk on a machine running Defender:
        it is deleted before the scanner can open it. That is exactly why the
        selftest marker below exists.
        """
        matched = [m.rule for m in self.scanner.rules.match(data=EICAR)]
        self.assertIn("Eicar_Test_File", matched)

    def test_detects_the_selftest_marker_on_disk(self):
        target = self.write("sample.txt", SELFTEST_MARKER)
        verdict = self.scanner.scan(target)
        self.assertIs(verdict.level, Level.MALICIOUS)
        self.assertIn("AVGuard-Selftest-Marker", verdict.reasons[0])

    def test_clean_file_is_clean(self):
        target = self.write("notes.txt", "the quick brown fox\n" * 50)
        self.assertIs(self.scanner.scan(target).level, Level.CLEAN)

    def test_innocent_text_mentioning_ransomware_is_clean(self):
        """The old ruleset flagged any file containing '.encrypted' or '.crypt'."""
        target = self.write("backup.md",
                            "My backup script skips files ending in .encrypted or .crypt.\n"
                            "Ransomware sometimes appends .locky to your files.\n")
        self.assertIs(self.scanner.scan(target).level, Level.CLEAN)

    def test_benign_windows_api_source_is_clean(self):
        """The old rule fired on any file naming four very common Win32 calls."""
        target = self.write("loader.c",
                            '#include <windows.h>\n'
                            'HMODULE h = LoadLibraryA("plugin.dll");\n'
                            'FARPROC p = GetProcAddress(h, "init");\n')
        self.assertIs(self.scanner.scan(target).level, Level.CLEAN)

    def test_ruleset_does_not_detect_itself(self):
        """The exact self-destruct the original shipped with."""
        copy = self.write("rules_copy.yara", RULES.read_bytes())
        self.assertIs(self.scanner.scan(copy).level, Level.CLEAN)

    def test_signature_spanning_a_chunk_boundary(self):
        """The old loop compared each 4 KB chunk in isolation and missed these."""
        boundary = config.CHUNK_SIZE
        split_at = len(SELFTEST_MARKER) // 2
        data = b"A" * (boundary - split_at) + SELFTEST_MARKER + b"B" * 100
        target = self.write("straddle.bin", data)
        self.assertIs(self.scanner.scan(target).level, Level.MALICIOUS)

    def test_protected_file_is_never_scanned(self):
        target = self.tmp / "protected" / "rules.yara"
        target.write_bytes(SELFTEST_MARKER)
        verdict = self.scanner.scan(target)
        self.assertIs(verdict.level, Level.SKIPPED)
        self.assertIn("protected", verdict.reasons[0])

    def test_oversized_file_is_skipped_not_read(self):
        self.cfg.max_file_size = 128
        target = self.write("big.bin", b"x" * 4096)
        verdict = self.scanner.scan(target)
        self.assertIs(verdict.level, Level.SKIPPED)
        self.assertIn("size cap", verdict.reasons[0])

    def test_empty_file_is_clean(self):
        self.assertIs(self.scanner.scan(self.write("empty.txt", b"")).level, Level.CLEAN)

    def test_missing_file_reports_error_not_crash(self):
        verdict = self.scanner.scan(self.tmp / "nope.txt")
        self.assertIn(verdict.level, (Level.ERROR, Level.SKIPPED))

    def test_cache_prevents_a_second_read(self):
        target = self.write("cached.txt", "hello world")
        self.scanner.scan(target)
        target.chmod(0o444)
        opened = []
        real_open = open

        def counting_open(*args, **kwargs):
            opened.append(args[0])
            return real_open(*args, **kwargs)

        import builtins
        builtins.open = counting_open
        try:
            self.scanner.scan(target)
        finally:
            builtins.open = real_open
        self.assertEqual(opened, [], "a cached, unchanged file must not be reopened")

    def test_cache_is_invalidated_when_the_file_changes(self):
        target = self.write("changing.txt", "harmless")
        self.assertIs(self.scanner.scan(target).level, Level.CLEAN)
        time.sleep(0.01)
        target.write_bytes(SELFTEST_MARKER)
        os.utime(target, None)
        self.assertIs(self.scanner.scan(target).level, Level.MALICIOUS)

    def test_reason_never_contains_the_raw_signature(self):
        """The old build wrote the decoded EICAR string into its own log,
        which turned the log file itself into a detected sample."""
        target = self.write("sample.txt", SELFTEST_MARKER)
        verdict = self.scanner.scan(target)
        blob = json.dumps(verdict.reasons).encode()
        self.assertNotIn(SELFTEST_MARKER, blob)

    def test_iter_files_prunes_protected_directories(self):
        (self.tmp / "protected" / "deep").mkdir(parents=True, exist_ok=True)
        (self.tmp / "protected" / "deep" / "x.txt").write_text("x")
        self.write("visible.txt", "x")
        found = {p.name for p in self.scanner.iter_files(self.tmp)}
        self.assertIn("visible.txt", found)
        self.assertNotIn("x.txt", found)

    @unittest.skipUnless(sys.platform == "win32", "junctions are Windows-only")
    def test_junction_is_not_followed_out_of_the_scan_tree(self):
        """os.path.islink() is False for a junction and os.walk descends
        through one, so checking is_symlink() alone is not enough."""
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "private.txt").write_text("someone else's data")

        inside = self.tmp / "tree"
        inside.mkdir()
        (inside / "normal.txt").write_text("in the tree")

        link = inside / "shortcut"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            self.skipTest(f"could not create a junction: {result.stderr.strip()}")

        found = {p.name for p in self.scanner.iter_files(inside)}
        self.assertIn("normal.txt", found)
        self.assertNotIn("private.txt", found,
                         "the scan walked through a junction and out of the tree")

    def test_entropy_bounds(self):
        self.assertAlmostEqual(shannon_entropy([10], 10), 0.0)
        flat = [4] * 256
        self.assertAlmostEqual(shannon_entropy(flat, 1024), 8.0, places=6)


# --------------------------------------------------------------- quarantine

class TestQuarantine(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.qdir = self.tmp / "store"
        self.protection = SelfProtection([self.tmp / "protected"])
        (self.tmp / "protected").mkdir(exist_ok=True)
        self.store = QuarantineStore(
            directory=self.qdir,
            index_path=self.qdir / "index.json",
            protection=self.protection,
            allowlist=Allowlist(path=self.tmp / 'allow.json'))

    def test_quarantine_then_restore_round_trips_exactly(self):
        original = b"\x00\x01payload bytes\xff" * 40
        target = self.write("threat.exe", original)
        record = self.store.quarantine(target, ["test"])

        self.assertFalse(target.exists(), "the original must be removed")
        restored = self.store.restore(record.entry_id)
        self.assertEqual(restored.read_bytes(), original)
        self.assertEqual(len(self.store), 0)

    def test_stored_payload_is_not_the_original_bytes(self):
        """A live sample must not sit executable on disk."""
        original = b"MZ\x90\x00 this would run"
        target = self.write("threat.exe", original)
        record = self.store.quarantine(target, ["test"])
        payload = self.qdir / f"{record.entry_id}.quar"
        self.assertTrue(payload.exists())
        self.assertNotEqual(payload.read_bytes(), original)
        self.assertFalse(payload.read_bytes().startswith(b"MZ"))

    def test_stored_payload_has_a_non_executable_extension(self):
        target = self.write("threat.exe", b"data")
        record = self.store.quarantine(target, [])
        self.assertEqual((self.qdir / f"{record.entry_id}.quar").suffix, ".quar")

    def test_on_disk_name_never_uses_the_untrusted_filename(self):
        """Reserved device names and traversal in a filename must not reach disk."""
        target = self.write("CON.txt", b"data")
        record = self.store.quarantine(target, [])
        names = [p.name for p in self.qdir.iterdir()]
        self.assertIn(f"{record.entry_id}.quar", names)
        self.assertNotIn("CON.txt", names)

    def test_two_files_with_the_same_name_do_not_collide(self):
        """The old store keyed everything on the bare filename."""
        a = self.write("a/dup.txt", b"first")
        b = self.write("b/dup.txt", b"second")
        ra = self.store.quarantine(a, [])
        rb = self.store.quarantine(b, [])
        self.assertNotEqual(ra.entry_id, rb.entry_id)
        self.assertEqual(len(self.store), 2)
        self.assertEqual(self.store.restore(ra.entry_id).read_bytes(), b"first")
        self.assertEqual(self.store.restore(rb.entry_id).read_bytes(), b"second")

    def test_restore_refuses_a_unc_destination(self):
        target = self.write("threat.txt", b"data")
        record = self.store.quarantine(target, [])
        with self.assertRaises(QuarantineError) as ctx:
            self.store.restore(record.entry_id, r"\\attacker\share\evil.exe")
        self.assertIn("UNC", str(ctx.exception))

    def test_restore_refuses_a_protected_destination(self):
        target = self.write("threat.txt", b"data")
        record = self.store.quarantine(target, [])
        with self.assertRaises(QuarantineError):
            self.store.restore(record.entry_id, self.tmp / "protected" / "scanner.py")

    def test_restore_refuses_to_overwrite_an_existing_file(self):
        target = self.write("threat.txt", b"data")
        record = self.store.quarantine(target, [])
        self.write("threat.txt", b"something the user made since")
        with self.assertRaises(QuarantineError) as ctx:
            self.store.restore(record.entry_id)
        self.assertIn("already exists", str(ctx.exception))

    def test_restore_refuses_into_the_quarantine_directory(self):
        target = self.write("threat.txt", b"data")
        record = self.store.quarantine(target, [])
        with self.assertRaises(QuarantineError):
            self.store.restore(record.entry_id, self.qdir / "sneaky.exe")

    def test_restore_detects_a_tampered_payload(self):
        target = self.write("threat.txt", b"data")
        record = self.store.quarantine(target, [])
        payload = self.qdir / f"{record.entry_id}.quar"
        payload.write_bytes(b"tampered with")
        with self.assertRaises(QuarantineError) as ctx:
            self.store.restore(record.entry_id)
        self.assertIn("integrity", str(ctx.exception))

    def test_index_survives_a_restart(self):
        target = self.write("threat.txt", b"data")
        record = self.store.quarantine(target, ["reason"])
        reopened = QuarantineStore(directory=self.qdir,
                                   index_path=self.qdir / "index.json",
                                   protection=self.protection,
                                       allowlist=Allowlist(path=self.tmp / 'allow.json'))
        self.assertEqual(len(reopened), 1)
        self.assertEqual(reopened.get(record.entry_id).reasons, ["reason"])

    def test_corrupt_index_does_not_lose_the_process(self):
        (self.qdir / "index.json").write_text("{ this is not json")
        store = QuarantineStore(directory=self.qdir,
                                index_path=self.qdir / "index.json",
                                protection=self.protection,
                                    allowlist=Allowlist(path=self.tmp / 'allow.json'))
        self.assertEqual(len(store), 0)

    def test_refuses_to_quarantine_a_protected_file(self):
        protected = self.tmp / "protected" / "rules.yara"
        protected.write_bytes(SELFTEST_MARKER)
        with self.assertRaises(QuarantineError):
            self.store.quarantine(protected, ["would be a disaster"])
        self.assertTrue(protected.exists(), "our own file must still be there")

    def test_delete_removes_payload_and_record(self):
        target = self.write("threat.txt", b"data")
        record = self.store.quarantine(target, [])
        self.store.delete(record.entry_id)
        self.assertFalse((self.qdir / f"{record.entry_id}.quar").exists())
        self.assertEqual(len(self.store), 0)

    def test_export_writes_original_bytes_and_keeps_the_record(self):
        original = b"sample bytes"
        target = self.write("threat.txt", original)
        record = self.store.quarantine(target, [])
        out = self.store.export(record.entry_id, self.tmp / "out.sample")
        self.assertEqual(out.read_bytes(), original)
        self.assertEqual(len(self.store), 1)

    def test_mask_is_reversible_and_changes_the_bytes(self):
        data = b"A" * 100
        nonce = b"0123456789abcdef"
        masked = _mask(data, nonce)
        self.assertNotEqual(masked, data)
        self.assertEqual(_mask(masked, nonce), data)


# -------------------------------------------------------------------- cloud

class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.ok = 200 <= status_code < 300

    def json(self):
        return self._payload


class FakeSession:
    trust_env = True
    max_redirects = 30

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.headers_seen = []
        self.kwargs_seen = []

    def get(self, url, headers=None, timeout=None, allow_redirects=True, **kw):
        self.calls += 1
        self.headers_seen.append(headers)
        self.kwargs_seen.append({"timeout": timeout, "allow_redirects": allow_redirects})
        assert timeout is not None, "every request must carry a timeout"
        return self.responses.pop(0) if self.responses else FakeResponse(404)


def report(malicious, total=70):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": 0,
        "undetected": total - malicious, "harmless": 0}}}}


class TestTokenBucket(unittest.TestCase):
    def test_allows_only_the_configured_burst(self):
        bucket = TokenBucket(rate_per_minute=4)
        self.assertEqual(sum(bucket.try_acquire() for _ in range(10)), 4)

    def test_reports_the_wait_for_the_next_token(self):
        bucket = TokenBucket(rate_per_minute=4)
        for _ in range(4):
            bucket.try_acquire()
        self.assertGreater(bucket.seconds_until_token(), 0)


class TestVirusTotalClient(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.cfg = config.Config(cloud_enabled=True, cloud_daily_budget=100)
        os.environ["VT_API_KEY"] = "test-key-not-real"
        self.addCleanup(os.environ.pop, "VT_API_KEY", None)

    def client(self, session):
        return VirusTotalClient(self.cfg, cache_path=self.tmp / "vt.json", session=session)

    def test_disabled_by_default(self):
        cfg = config.Config()
        self.assertFalse(cfg.cloud_enabled,
                         "cloud lookups must be opt-in: hashes leave the machine")

    def test_result_is_cached_so_a_hash_costs_one_call(self):
        session = FakeSession([FakeResponse(200, report(9))])
        client = self.client(session)
        first = client.lookup("a" * 64)
        second = client.lookup("a" * 64)
        self.assertEqual(session.calls, 1)
        self.assertEqual(first.malicious, second.malicious, 9)

    def test_404_is_cached_too(self):
        session = FakeSession([FakeResponse(404)])
        client = self.client(session)
        client.lookup("b" * 64)
        client.lookup("b" * 64)
        self.assertEqual(session.calls, 1)

    def test_rate_limit_stops_the_fifth_call(self):
        session = FakeSession([FakeResponse(200, report(0)) for _ in range(10)])
        client = self.client(session)
        for i in range(10):
            client.lookup(f"{i:064d}")
        self.assertLessEqual(session.calls, 4)

    def test_daily_budget_is_enforced(self):
        self.cfg.cloud_daily_budget = 2
        session = FakeSession([FakeResponse(200, report(0)) for _ in range(10)])
        client = self.client(session)
        client.bucket = TokenBucket(rate_per_minute=1000)
        for i in range(10):
            client.lookup(f"{i:064d}")
        self.assertEqual(session.calls, 2)

    def test_429_triggers_a_cooldown(self):
        session = FakeSession([FakeResponse(429), FakeResponse(200, report(5))])
        client = self.client(session)
        self.assertIsNone(client.lookup("c" * 64))
        self.assertIsNone(client.lookup("d" * 64), "must back off after a 429")
        self.assertEqual(session.calls, 1)

    def test_bad_key_disables_cloud_for_the_session(self):
        session = FakeSession([FakeResponse(401)])
        client = self.client(session)
        client.lookup("e" * 64)
        self.assertFalse(self.cfg.cloud_enabled)

    def test_single_detection_is_not_treated_as_a_threat(self):
        session = FakeSession([FakeResponse(200, report(1))])
        client = self.client(session)
        self.assertEqual(client.reasons_for("f" * 64, Path("x.exe")), [])

    def test_several_detections_are_treated_as_a_threat(self):
        session = FakeSession([FakeResponse(200, report(12))])
        client = self.client(session)
        reasons = client.reasons_for("0" * 64, Path("x.exe"))
        self.assertEqual(len(reasons), 1)
        self.assertIn("12", reasons[0])

    def test_api_key_is_not_written_to_the_cache(self):
        session = FakeSession([FakeResponse(200, report(3))])
        client = self.client(session)
        client.lookup("9" * 64)
        client.save_cache()
        self.assertNotIn("test-key-not-real", (self.tmp / "vt.json").read_text())

    def test_request_carries_a_timeout(self):
        session = FakeSession([FakeResponse(200, report(0))])
        self.client(session).lookup("1" * 64)
        self.assertIsNotNone(session.kwargs_seen[0]["timeout"])

    def test_redirects_are_not_followed(self):
        """requests strips Authorization across hosts but not a custom
        x-apikey header, so a redirect would hand the key to the new host."""
        session = FakeSession([FakeResponse(200, report(0))])
        self.client(session).lookup("2" * 64)
        self.assertFalse(session.kwargs_seen[0]["allow_redirects"])

    def test_session_ignores_proxy_environment(self):
        """HTTPS_PROXY or REQUESTS_CA_BUNDLE must not be able to reroute
        or intercept a request that carries the API key."""
        session = FakeSession([])
        self.client(session)
        self.assertFalse(session.trust_env)

    def test_disabled_client_makes_no_request(self):
        self.cfg.cloud_enabled = False
        session = FakeSession([FakeResponse(200, report(9))])
        client = self.client(session)
        self.assertIsNone(client.lookup("a" * 64))
        self.assertEqual(session.calls, 0)


# ------------------------------------------------------------------ config

class TestConfig(TempCase):
    def test_atomic_write_replaces_cleanly(self):
        target = self.tmp / "sub" / "cfg.json"
        config.atomic_write_text(target, '{"a": 1}')
        self.assertEqual(json.loads(target.read_text()), {"a": 1})
        config.atomic_write_text(target, '{"a": 2}')
        self.assertEqual(json.loads(target.read_text()), {"a": 2})
        self.assertEqual(list(target.parent.glob("*.tmp")), [], "no temp files left behind")

    def test_unknown_keys_in_config_are_ignored(self):
        path = self.tmp / "cfg.json"
        path.write_text(json.dumps({"cloud_enabled": True, "who_knows": 42}))
        cfg = config.Config.load(path)
        self.assertTrue(cfg.cloud_enabled)

    def test_corrupt_config_falls_back_to_defaults(self):
        path = self.tmp / "cfg.json"
        path.write_text("not json at all")
        self.assertFalse(config.Config.load(path).cloud_enabled)

    def test_api_key_comes_from_the_environment_only(self):
        cfg = config.Config()
        os.environ.pop("VT_API_KEY", None)
        self.assertIsNone(cfg.vt_api_key)
        os.environ["VT_API_KEY"] = "abc"
        self.addCleanup(os.environ.pop, "VT_API_KEY", None)
        self.assertEqual(cfg.vt_api_key, "abc")


# --------------------------------------------------------------- real-time

class TestRealtimeMonitor(TempCase):
    """The original build scanned on the watchdog thread, so writing a log line
    produced the event that caused the next scan. Its log has 2021 lines of it."""

    def setUp(self) -> None:
        super().setUp()
        self.watched = self.tmp / "watched"
        self.protected = self.watched / "avguard_data"
        self.protected.mkdir(parents=True, exist_ok=True)

        self.cfg = config.Config(cloud_enabled=False)
        self.protection = SelfProtection([self.protected])
        self.scanner = Scanner(self.cfg, self.protection, rules_path=RULES,
                               cache=ScanCache(path=self.tmp / "cache.json"))
        self.verdicts = []
        self.lock = threading.Lock()

        def collect(verdict):
            with self.lock:
                self.verdicts.append(verdict)

        self.monitor = RealtimeMonitor(
            self.scanner, self.protection, on_verdict=collect,
            workers=2, debounce_seconds=0.3,
        )
        self.addCleanup(self.monitor.stop)

    def paths_seen(self):
        with self.lock:
            return [v.path.name for v in self.verdicts]

    def wait_for(self, predicate, timeout=8.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.1)
        return False

    def test_detects_a_file_dropped_into_the_watched_folder(self):
        self.assertTrue(self.monitor.start([self.watched]))
        (self.watched / "dropped.bin").write_bytes(SELFTEST_MARKER)
        self.assertTrue(
            self.wait_for(lambda: any(
                v.level is Level.MALICIOUS and v.path.name == "dropped.bin"
                for v in list(self.verdicts))),
            f"real-time scan never fired; saw {self.paths_seen()}")

    def test_writes_to_protected_paths_never_trigger_a_scan(self):
        """This is the loop-breaker: our own log writes must be invisible."""
        self.assertTrue(self.monitor.start([self.watched]))
        for i in range(12):
            (self.protected / "avguard.log").write_text(f"line {i}\n")
            time.sleep(0.02)
        time.sleep(1.5)
        self.assertEqual(
            [n for n in self.paths_seen() if n == "avguard.log"], [],
            "a write inside a protected directory must not queue a scan")

    def test_repeated_writes_are_debounced(self):
        self.assertTrue(self.monitor.start([self.watched]))
        target = self.watched / "busy.txt"
        for i in range(15):
            target.write_text(f"revision {i}\n")
            time.sleep(0.02)
        self.assertTrue(self.wait_for(lambda: "busy.txt" in self.paths_seen()))
        time.sleep(1.0)
        scans = self.paths_seen().count("busy.txt")
        self.assertLessEqual(scans, 3,
                             f"15 rapid writes should collapse to a couple of scans, got {scans}")

    def test_stop_leaves_no_threads_behind(self):
        self.monitor.start([self.watched])
        self.monitor.stop()
        time.sleep(0.3)
        leftover = [t.name for t in threading.enumerate() if t.name.startswith("avguard-")]
        self.assertEqual(leftover, [], f"threads still running after stop: {leftover}")

    def test_full_queue_drops_rather_than_blocking(self):
        pool = ScanWorkerPool(self.scanner, lambda v: None, workers=1, max_queued=2)
        self.assertTrue(pool.submit(Path("a")))
        self.assertTrue(pool.submit(Path("b")))
        self.assertFalse(pool.submit(Path("c")), "a full queue must refuse, not block")


# ------------------------------------------------------- concurrency safety

class TestInstanceLock(TempCase):
    """Two AVGuard processes sharing data/ destroyed each other's records."""

    def test_second_holder_is_refused(self):
        first, second = InstanceLock(self.tmp / "x.lock"), InstanceLock(self.tmp / "x.lock")
        self.assertTrue(first.acquire())
        self.assertFalse(second.acquire(), "a second holder must be refused")
        first.release()

    def test_lock_is_released_for_the_next_process(self):
        first, second = InstanceLock(self.tmp / "x.lock"), InstanceLock(self.tmp / "x.lock")
        first.acquire()
        first.release()
        self.assertTrue(second.acquire())
        second.release()

    def test_blocked_holder_learns_who_has_it(self):
        first, second = InstanceLock(self.tmp / "x.lock"), InstanceLock(self.tmp / "x.lock")
        first.acquire()
        second.acquire()
        self.assertEqual(second.owner_pid, os.getpid())
        first.release()

    def test_held_reports_state(self):
        lock = InstanceLock(self.tmp / "x.lock")
        self.assertFalse(lock.held)
        lock.acquire()
        self.assertTrue(lock.held)
        lock.release()
        self.assertFalse(lock.held)


class TestConcurrentQuarantine(TempCase):
    """The reproducer from ROADMAP.md finding 3, as a regression test."""

    def setUp(self) -> None:
        super().setUp()
        self.qdir = self.tmp / "store"
        (self.tmp / "protected").mkdir(exist_ok=True)
        self.protection = SelfProtection([self.tmp / "protected"])

    def store(self):
        return QuarantineStore(directory=self.qdir, index_path=self.qdir / "index.json",
                               protection=self.protection,
                                   allowlist=Allowlist(path=self.tmp / 'allow.json'))

    def test_a_stale_second_store_does_not_erase_the_first(self):
        gui, cli = self.store(), self.store()      # both opened before either writes
        a = self.write("important.docx", b"THE USER'S ONLY COPY")
        ra = gui.quarantine(a, ["gui"])
        b = self.write("other.exe", b"second file")
        rb = cli.quarantine(b, ["cli"])

        final = self.store()
        self.assertEqual(len(final), 2, "one process erased the other's record")
        self.assertIsNotNone(final.get(ra.entry_id))
        self.assertIsNotNone(final.get(rb.entry_id))

    def test_the_erased_record_is_still_restorable(self):
        gui, cli = self.store(), self.store()
        a = self.write("important.docx", b"THE USER'S ONLY COPY")
        ra = gui.quarantine(a, ["gui"])
        cli.quarantine(self.write("other.exe", b"x"), ["cli"])
        restored = self.store().restore(ra.entry_id)
        self.assertEqual(restored.read_bytes(), b"THE USER'S ONLY COPY")

    def test_a_merge_cannot_resurrect_a_deleted_record(self):
        one, two = self.store(), self.store()
        record = one.quarantine(self.write("gone.txt", b"x"), [])
        one.delete(record.entry_id)
        two.quarantine(self.write("other.txt", b"y"), [])
        one.quarantine(self.write("third.txt", b"z"), [])
        self.assertIsNone(self.store().get(record.entry_id))


# ---------------------------------------------------------- cache lifecycle

class TestScanCacheSchema(TempCase):
    """A cached verdict is a conclusion. When the logic changes it is stale."""

    def test_an_older_schema_is_discarded(self):
        path = self.tmp / "cache.json"
        path.write_text(json.dumps({"c:/x|1|2": {"level": "malicious",
                                                 "reasons": ["old logic"], "sha256": ""}}))
        cache = ScanCache(path=path)
        self.assertIsNone(cache.get(Path("c:/x"), 1, 2))

    def test_a_changed_ruleset_discards_the_cache(self):
        path = self.tmp / "cache.json"
        first = ScanCache(path=path, generation="aaaa")
        first.put(Path("c:/x"), 1, 2, Level.CLEAN, [], "hash")
        first.save()
        self.assertIsNotNone(ScanCache(path=path, generation="aaaa").get(Path("c:/x"), 1, 2))
        self.assertIsNone(ScanCache(path=path, generation="bbbb").get(Path("c:/x"), 1, 2))

    def test_a_matching_generation_keeps_the_cache(self):
        path = self.tmp / "cache.json"
        cache = ScanCache(path=path, generation="same")
        cache.put(Path("c:/y"), 3, 4, Level.CLEAN, ["fine"], "hash")
        cache.save()
        reopened = ScanCache(path=path, generation="same")
        self.assertEqual(reopened.get(Path("c:/y"), 3, 4)["reasons"], ["fine"])

    def test_generation_changes_when_the_ruleset_changes(self):
        cfg = config.Config(cloud_enabled=False)
        # Separate directories: rule_files() globs a whole directory, so two
        # rulesets sharing one folder are one ruleset as far as loading goes.
        rules_a = self.write("a/rules.yara", 'rule A { condition: false }')
        rules_b = self.write("b/rules.yara", 'rule B { condition: false }')
        prot = SelfProtection([self.tmp / "nothing"])
        one = Scanner(cfg, prot, rules_path=rules_a, cache=ScanCache(path=self.tmp / "1.json"))
        two = Scanner(cfg, prot, rules_path=rules_b, cache=ScanCache(path=self.tmp / "2.json"))
        # The files deliberately share a name and a size, and on a fast
        # filesystem they share an mtime to the nanosecond too. An earlier
        # optimisation hashed exactly those three things and made two different
        # rulesets look identical -- which would replay every cached verdict
        # from a ruleset no longer in use. CI caught it; this asserts the
        # collision cannot come back.
        self.assertEqual(rules_a.name, rules_b.name)
        self.assertEqual(rules_a.stat().st_size, rules_b.stat().st_size)
        self.assertNotEqual(one.detection_generation(), two.detection_generation())


# ------------------------------------------------------------ safe defaults

class TestSafeDefaults(unittest.TestCase):
    def test_auto_quarantine_is_off_until_asked(self):
        self.assertFalse(config.Config().auto_quarantine,
                         "the tool must not move files before anyone has been asked")

    def test_onboarding_starts_incomplete(self):
        self.assertFalse(config.Config().onboarding_completed)

    def test_the_threshold_needs_a_decisive_signal(self):
        cfg = config.Config()
        self.assertEqual(cfg.quarantine_threshold, 100)
        self.assertLess(SEVERITY_WEIGHTS["medium"], cfg.quarantine_threshold)

    def test_the_project_itself_is_protected(self):
        """docs/, tests/ and README.md were outside the guard."""
        protection = SelfProtection()
        for name in ("docs", "tests", "README.md", "ROADMAP.md", "rules/malware.yara"):
            with self.subTest(path=name):
                self.assertTrue(protection.is_protected(config.PROJECT_ROOT / name))

    def test_unrelated_paths_are_still_scannable(self):
        self.assertFalse(SelfProtection().is_protected(Path.home() / "Downloads" / "x.exe"))


# ------------------------------------------------- non-ASCII paths (Windows)

NEEDLE = b"NEEDLE-IN-A-BIG-FILE"

# Written as hex so the rule file does not contain the literal it hunts for.
# A self-matching rule is refused on load, which is exactly the check that
# stops a repeat of v1 quarantining its own ruleset.
RULE_SOURCE = chr(10).join([
    "rule BigFileNeedle {",
    "  meta:",
    '    description = "a needle for the non-ASCII path tests"',
    '    severity = "high"',
    "  strings:",
    "    $a = { " + " ".join(f"{b:02X}" for b in NEEDLE) + " }",
    "  condition:",
    "    $a",
    "}",
])


class TestNonAsciiPaths(TempCase):
    """yara-python cannot open a non-ASCII path on Windows.

    It raises "could not open file", which the scanner used to log and move on
    from -- so on a machine with Thai, Chinese or Cyrillic filenames, every
    file too large to buffer silently skipped YARA. Found while scanning this
    developer's own Downloads folder.
    """

    def setUp(self) -> None:
        super().setUp()
        self.rules_path = self.write("big.yara", RULE_SOURCE)
        self.cfg = config.Config(cloud_enabled=False)
        self.scanner = Scanner(self.cfg, SelfProtection([self.tmp / "none"]),
                               rules_path=self.rules_path,
                               cache=ScanCache(path=self.tmp / "c.json"))

    def _big(self, name: str) -> Path:
        # Over YARA_BUFFER_MAX, so it takes the match(filepath=) route.
        payload = b"A" * (config.YARA_BUFFER_MAX + 2048) + NEEDLE
        return self.write(name, payload)

    def test_large_ascii_named_file_is_matched(self):
        verdict = self.scanner.scan(self._big("plain.bin"), use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)

    def test_large_thai_named_file_is_matched(self):
        thai = "".join(chr(c) for c in (0x0E41, 0x0E19, 0x0E27, 0x0E40, 0x0E09, 0x0E25, 0x0E22))
        verdict = self.scanner.scan(self._big(thai + ".bin"), use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS,
                      "a non-ASCII filename must not silently skip YARA")

    def test_large_cyrillic_named_file_is_matched(self):
        name = "".join(chr(c) for c in (0x043E, 0x0442, 0x0447, 0x0451, 0x0442))
        verdict = self.scanner.scan(self._big(name + ".bin"), use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)

    def test_small_non_ascii_file_still_works(self):
        name = "".join(chr(c) for c in (0x4E2D, 0x6587))
        target = self.write(name + ".txt", NEEDLE)
        self.assertIs(self.scanner.scan(target, use_cache=False).level, Level.MALICIOUS)

if __name__ == "__main__":
    unittest.main(verbosity=2)
