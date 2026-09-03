"""The compiled-ruleset cache: a fast start that can never load stale rules.

Measured before it existed, with one real pack of 311 files: the first launch
of the day took 10 s and a warm one 1.1 s, of which the compile was 0.17 s.
The cost was the first touch of 310 small files. A saved ruleset is one file.

The point of these tests is not the speed. It is that every way the cache
could be wrong -- a file edited to the same size, a corrupt blob, a different
yara build, a write inside the timestamp tick -- falls back to compiling.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolate the data directory BEFORE avguard is imported: the cache lives there,
# and the real one must never be touched by a test.
import os as _os
import tempfile as _tempfile

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


from avguard import config
from avguard import scanner as scanner_module
from avguard.allowlist import Allowlist
from avguard.protection import SelfProtection
from avguard.rulepacks import Admission, PackStore
from avguard.scanner import Level, ScanCache, Scanner

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

TRIPWIRE = "TRIPWIRE-" + "7f3a2c9e"
OTHER = "TRIPWIRE-" + "b4e1d0a7"  # the same length, so an edit keeps the size


def rule_text(needle: str) -> str:
    return "\n".join([
        "rule Imported {",
        "  meta:",
        '    description = "from somebody else"',
        '    severity = "medium"',
        "  strings:",
        f'    $a = "{needle}"',
        "  condition:",
        "    $a",
        "}",
    ])


class CompiledCacheCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-ccache-"))
        self.addCleanup(_remove_tree, self.tmp)
        self.store = PackStore(directory=self.tmp / "packs",
                               index_path=self.tmp / "packs" / "packs.json")
        self._forget_cache()
        self.addCleanup(self._forget_cache)
        rule = self.tmp / "pack.yara"
        rule.write_text(rule_text(TRIPWIRE), encoding="utf-8")
        self.store.install("vendor", [rule],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        self.backdate()

    @staticmethod
    def _forget_cache() -> None:
        for path in (scanner_module.COMPILED_RULES_PATH,
                     scanner_module.COMPILED_MANIFEST_PATH):
            try:
                path.unlink()
            except OSError:
                pass

    def backdate(self, seconds: float = 30) -> None:
        """Pretend the pack files were written a while ago.

        A file written within two seconds of the cache is never trusted from
        its stat, by design, so a test of the fast path has to age its files.
        """
        stamp = time.time() - seconds
        for path in self.store.rule_files_for("vendor"):
            os.utime(path, (stamp, stamp))

    def scanner(self) -> Scanner:
        return Scanner(config.Config(cloud_enabled=False),
                       SelfProtection([self.tmp / "nothing"]),
                       cache=ScanCache(path=self.tmp / "c.json"),
                       packs=self.store,
                       allowlist=Allowlist(path=self.tmp / "allow.json"))

    def spy_on_fast_path(self) -> list:
        """Record what _adopt_compiled_cache returned on each construction."""
        outcomes: list = []
        original = Scanner._adopt_compiled_cache

        def spy(scanner_self):
            outcome = original(scanner_self)
            outcomes.append(outcome)
            return outcome

        patcher = mock.patch.object(Scanner, "_adopt_compiled_cache", spy)
        patcher.start()
        self.addCleanup(patcher.stop)
        return outcomes

    def sample(self, needle: str) -> Path:
        path = self.tmp / f"sample-{needle[-4:]}.bin"
        path.write_bytes(needle.encode() + b" " * 32)
        return path


class TestTheFastPath(CompiledCacheCase):
    def test_a_second_start_reads_no_rule_file(self):
        first = self.scanner()
        self.assertTrue(scanner_module.COMPILED_MANIFEST_PATH.exists(), "no cache was written")

        outcomes = self.spy_on_fast_path()
        reads: list[Path] = []
        real_read = Path.read_bytes

        def counting(path_self):
            if path_self.suffix.lower() in (".yara", ".yar"):
                reads.append(path_self)
            return real_read(path_self)

        with mock.patch.object(Path, "read_bytes", counting):
            second = self.scanner()

        self.assertEqual(outcomes, [True])
        self.assertEqual(reads, [], "the fast path read rule contents")
        self.assertIsNotNone(second.rules)
        self.assertEqual(second.pack_rule_counts, first.pack_rule_counts)
        self.assertEqual(second.rule_sources, first.rule_sources)
        # Or the ScanCache would be flushed on every other start.
        self.assertEqual(second.detection_generation(), first.detection_generation())

    def test_the_loaded_rules_still_score_by_the_store_s_trust_state(self):
        self.scanner()
        second = self.scanner()
        verdict = second.scan(self.sample(TRIPWIRE), use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS, "an unpromoted pack is capped")
        self.assertIn("from the vendor pack", " ".join(verdict.reasons))

        self.store.set_trusted("vendor", True)
        third = self.scanner()
        verdict = third.scan(self.sample(TRIPWIRE), use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS,
                      "medium stays medium; trust changes hard, not weight")
        self.assertFalse(third._untrusted_namespaces & set(third._pack_by_namespace),
                         "trust came from the cache, not the store")


class TestEveryWayItCouldBeStale(CompiledCacheCase):
    def test_an_edit_that_keeps_the_size_is_noticed(self):
        first = self.scanner()
        before = first.detection_generation()  # generation() re-hashes from disk
        rule = self.store.rule_files_for("vendor")[0]
        rule.write_text(rule_text(OTHER), encoding="utf-8")
        self.backdate(seconds=20)  # still old, merely different
        outcomes = self.spy_on_fast_path()
        second = self.scanner()
        self.assertEqual(outcomes, [False])
        self.assertNotEqual(before, second.detection_generation())
        self.assertIs(second.scan(self.sample(OTHER), use_cache=False).level, Level.SUSPICIOUS)
        self.assertIs(first.scan(self.sample(OTHER), use_cache=False).level, Level.CLEAN)

    def test_a_file_written_just_before_the_cache_is_not_trusted(self):
        """Two writes inside one timestamp tick look identical to stat()."""
        self.scanner()
        rule = self.store.rule_files_for("vendor")[0]
        rule.write_text(rule_text(TRIPWIRE), encoding="utf-8")  # fresh, not aged
        self.scanner()  # compiles, and writes a cache while the file is fresh
        outcomes = self.spy_on_fast_path()
        self.scanner()
        self.assertEqual(outcomes, [False], "a fresh file was trusted from its stat")

    def test_a_corrupt_blob_is_ignored(self):
        self.scanner()
        scanner_module.COMPILED_RULES_PATH.write_bytes(b"not a compiled ruleset")
        outcomes = self.spy_on_fast_path()
        second = self.scanner()
        self.assertEqual(outcomes, [False])
        self.assertIsNotNone(second.rules)
        self.assertEqual(second.pack_rule_counts.get("vendor"), 1)

    def test_a_cache_from_another_yara_build_is_ignored(self):
        self.scanner()
        manifest = json.loads(scanner_module.COMPILED_MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["yara"] = "0.0.0"
        scanner_module.COMPILED_MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(scanner_module.yara, "load",
                               side_effect=AssertionError("must not be loaded")):
            second = self.scanner()
        self.assertIsNotNone(second.rules)
        rewritten = json.loads(scanner_module.COMPILED_MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(rewritten["yara"], scanner_module.yara.__version__)

    def test_a_pack_added_since_is_noticed(self):
        self.scanner()
        extra = self.tmp / "extra.yara"
        extra.write_text(rule_text(OTHER).replace("Imported", "Extra"), encoding="utf-8")
        self.store.install("second", [extra],
                           Admission(accepted=True, rule_count=1, corpus_size=1),
                           licence="MIT")
        outcomes = self.spy_on_fast_path()
        second = self.scanner()
        self.assertEqual(outcomes, [False])
        self.assertEqual(second.pack_rule_counts.get("second"), 1)

    def test_reload_never_uses_the_cache(self):
        scanner = self.scanner()
        outcomes = self.spy_on_fast_path()
        self.assertTrue(scanner.reload_rules())
        self.assertEqual(outcomes, [], "reload took the fast path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
