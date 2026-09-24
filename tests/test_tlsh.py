"""TLSH: the digest is the reference's, a match is soft, the references are state.

Three things these tests hold the module to. The digest must equal what
Trend Micro's C++ produces, byte for byte, on every backend and however the
input is chunked -- recorded reference digests here, and the live library
when it is importable. A match is a guess about a family, so it can raise a
file to SUSPICIOUS and never on its own to MALICIOUS. And the reference
table decides verdicts, so importing into it changes the detection
generation and a running scanner notices.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os as _os
import tempfile as _tempfile

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)


def _remove_tree(path) -> None:
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


from avguard import config, iocs, tlsh  # noqa: E402
from avguard import scanner as scanner_module  # noqa: E402
from avguard.allowlist import Allowlist  # noqa: E402
from avguard.iocs import IocStore, parse_lines  # noqa: E402
from avguard.protection import SelfProtection  # noqa: E402
from avguard.rulepacks import PackStore  # noqa: E402
from avguard.scanner import Level, ScanCache, Scanner  # noqa: E402

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False


def chain(n: int, seed: bytes = b"avguard") -> bytes:
    """n deterministic, high-variety bytes: SHA-256 of a counter, concatenated."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        i += 1
    return bytes(out[:n])


def flipped(data: bytes, offset: int, mask: int = 0xFF) -> bytes:
    out = bytearray(data)
    out[offset] ^= mask
    return bytes(out)


# Digests produced by py-tlsh 5.0.0 (the reference C++), built from its sdist
# for this purpose, on the inputs the helpers above reproduce.
REFERENCE = {
    "chain10000": "T14B22B0C98EEB79030F8944F63ED31A6F34D6595AE15105FDB00026F2968AFEB5218772",
    "chain10000_flip1": "T1DE22BFC98EEB79030F8944F63ED31A6F34D6595AE15105FEB00026F2968AFEB5218772",
    "chain10000_flip100": "T13122BFCD8FEB69430E8A45E63ED3166B34D55D1EF29105FAB00026F2928AFE71258772",
    "chain10000_other": "T14122C1638DFE4581ED59D174FB0613D1CB406D902E12937C8CAA4A9DF730CBAE9F4642",
    "chain50": "T1D59002C598516A01E99510144935840BC8E8DD3A204A635219001005955931D2061839",
    "range256x4": "T16D119524E6514D7D1F175ADCD04E44DF554FCDE302C5002517F186D1C510294440ED1D",
    "text": "T1A231024A311C1794658A1888438D95B2D2C9C910612114116570604219482359CD8551",
    "chain300000": "T18E5423602513FF874ED6A0B89AE740F2B0B6AD37D61895AF1E035419732E266DC0D8CF",
}
# `tlsh.diff` from the same library on those digests.
REFERENCE_DISTANCES = {
    ("chain10000", "chain10000_flip1"): 3,
    ("chain10000", "chain10000_flip100"): 25,
    ("chain10000", "chain10000_other"): 215,
    ("chain10000", "text"): 456,
    ("text", "range256x4"): 294,
}


def inputs() -> dict[str, bytes]:
    base = chain(10000)
    sparse = bytearray(base)
    for i in range(0, 10000, 100):
        sparse[i] ^= 0x55
    return {
        "chain10000": base,
        "chain10000_flip1": flipped(base, 5000),
        "chain10000_flip100": bytes(sparse),
        "chain10000_other": chain(10000, b"other"),
        "chain50": chain(50),
        "range256x4": bytes(range(256)) * 4,
        "text": b"The quick brown fox jumps over the lazy dog. " * 40,
        "chain300000": chain(300000),
    }


BACKENDS = ["python"] + (["numpy"] if tlsh.np is not None else []) \
    + (["native"] if tlsh._native is not None else [])


def digest_in_chunks(data: bytes, chunk: int, which: str) -> str | None:
    hasher = tlsh.Hasher(which)
    for start in range(0, len(data), chunk):
        hasher.update(data[start:start + chunk])
    return hasher.final()


# ------------------------------------------------------------------ digest

class TestTheDigestIsTheReferences(unittest.TestCase):
    def test_recorded_reference_digests_on_every_backend(self):
        data = inputs()
        for name, want in REFERENCE.items():
            for which in BACKENDS:
                with self.subTest(input=name, backend=which):
                    self.assertEqual(tlsh.hash_bytes(data[name], which), want)

    def test_chunking_does_not_change_the_digest(self):
        """The five-byte window straddles chunk boundaries; the checksum
        chain crosses them; the batching buffer flushes in the middle."""
        data = inputs()
        for name in ("chain10000", "text", "chain300000"):
            for chunk in (1, 3, 64, 4096, 65536, 262143, 262144, 262145):
                if chunk < 64 and len(data[name]) > 20000:
                    continue
                for which in BACKENDS:
                    with self.subTest(input=name, chunk=chunk, backend=which):
                        self.assertEqual(digest_in_chunks(data[name], chunk, which),
                                         REFERENCE[name])

    def test_too_little_input_or_variety_is_no_digest_not_an_error(self):
        cases = {
            "empty": b"",
            "49 bytes": chain(49),
            "1000 zeros": bytes(1000),
            "four values": bytes([1, 2, 3, 4]) * 300,
        }
        for name, data in cases.items():
            for which in BACKENDS:
                with self.subTest(input=name, backend=which):
                    self.assertIsNone(tlsh.hash_bytes(data, which))
        self.assertIsNotNone(tlsh.hash_bytes(chain(50), "python"), "50 bytes is enough")

    def test_hash_file_reads_in_chunks_and_matches(self):
        tmp = Path(tempfile.mkdtemp(prefix="avguard-tlsh-"))
        self.addCleanup(_remove_tree, tmp)
        path = tmp / "sample.bin"
        path.write_bytes(inputs()["chain300000"])
        self.assertEqual(tlsh.hash_file(path, chunk_size=4096), REFERENCE["chain300000"])
        with self.assertRaises(OSError):
            tlsh.hash_file(tmp / "missing.bin")

    @unittest.skipUnless(tlsh._native is not None, "py-tlsh is not importable here")
    def test_the_pure_paths_agree_with_the_live_reference_on_real_files(self):
        """When the C++ library is here, check it directly: the tests' own
        source files, in every backend, chunked as the scanner chunks."""
        here = Path(__file__).resolve().parent
        for path in sorted(here.glob("*.py"))[:6]:
            data = path.read_bytes()
            want = tlsh._native.hash(data)
            want = None if want == "TNULL" else want
            for which in BACKENDS:
                with self.subTest(file=path.name, backend=which):
                    self.assertEqual(digest_in_chunks(data, 65536, which), want)


class TestTheDigestString(unittest.TestCase):
    def test_parse_round_trips_and_accepts_bare_and_lowercase(self):
        for name, digest in REFERENCE.items():
            with self.subTest(name=name):
                self.assertEqual(tlsh.Digest.parse(digest).hex(), digest)
                self.assertEqual(tlsh.normalize(digest.lower()), digest)
                self.assertEqual(tlsh.normalize(digest[2:]), digest)
                self.assertEqual(tlsh.normalize("  " + digest[2:].lower() + "\n"), digest)

    def test_what_is_not_a_digest(self):
        for text in ("", "TNULL", "T1" + "0" * 69, "T1" + "0" * 71, "0" * 64,
                     "T1" + "G" * 70, "T2" + "0" * 70):
            with self.subTest(text=text):
                self.assertFalse(tlsh.is_digest(text))
                with self.assertRaises(ValueError):
                    tlsh.Digest.parse(text)
        # A SHA-256 is 64 hex characters: never mistaken for a digest.
        self.assertFalse(tlsh.is_digest(hashlib.sha256(b"x").hexdigest()))


# ---------------------------------------------------------------- distance

class TestDistance(unittest.TestCase):
    def test_recorded_reference_distances(self):
        for (a, b), want in REFERENCE_DISTANCES.items():
            with self.subTest(pair=(a, b)):
                self.assertEqual(tlsh.distance(REFERENCE[a], REFERENCE[b]), want)
                self.assertEqual(tlsh.distance(REFERENCE[b], REFERENCE[a]), want)

    def test_identical_is_zero_and_the_order_is_variant_then_unrelated(self):
        base = REFERENCE["chain10000"]
        self.assertEqual(tlsh.distance(base, base), 0)
        near = tlsh.distance(base, REFERENCE["chain10000_flip1"])
        further = tlsh.distance(base, REFERENCE["chain10000_flip100"])
        unrelated = tlsh.distance(base, REFERENCE["chain10000_other"])
        self.assertLess(near, 10, "acceptance: one flipped byte scores under 10")
        self.assertLess(near, further)
        self.assertLess(further, scanner_module.TLSH_NEAR)
        self.assertGreater(unrelated, scanner_module.TLSH_FAR * 2)

    def test_length_can_be_left_out(self):
        a, b = REFERENCE["chain10000"], REFERENCE["chain300000"]
        with_length = tlsh.distance(a, b)
        without = tlsh.distance(a, b, length=False)
        self.assertGreater(with_length, without)

    @unittest.skipUnless(tlsh._native is not None, "py-tlsh is not importable here")
    def test_agrees_with_the_live_reference(self):
        digests = list(REFERENCE.values())
        for a in digests:
            for b in digests:
                with self.subTest(a=a[:10], b=b[:10]):
                    self.assertEqual(tlsh.distance(a, b), tlsh._native.diff(a, b))
                    self.assertEqual(tlsh.distance(a, b, length=False),
                                     tlsh._native.diffxlen(a, b))


class TestReferenceSet(unittest.TestCase):
    def references(self) -> tlsh.ReferenceSet:
        return tlsh.ReferenceSet(
            tlsh.Reference(REFERENCE[name], name, "unit")
            for name in ("chain10000_other", "text", "range256x4", "chain10000_flip100"))

    def test_nearest_is_the_closest_and_the_python_loop_agrees(self):
        refs = self.references()
        probe = REFERENCE["chain10000"]
        match = refs.nearest(probe)
        self.assertEqual(match.reference.family, "chain10000_flip100")
        self.assertEqual(match.distance, 25)
        everything = refs.distances(probe)
        self.assertEqual(len(everything), 4)
        self.assertEqual(min(everything), 25)
        if refs._np is not None:
            refs._np = None
            self.assertEqual(refs.nearest(probe), match)
            self.assertEqual(refs.distances(probe), everything)

    def test_an_empty_set_is_false_and_has_no_nearest(self):
        refs = tlsh.ReferenceSet()
        self.assertFalse(refs)
        self.assertEqual(len(refs), 0)
        self.assertIsNone(refs.nearest(REFERENCE["text"]))

    def test_malformed_references_are_dropped_not_fatal(self):
        refs = tlsh.ReferenceSet([tlsh.Reference("not a digest", "x", "s"),
                                  tlsh.Reference(REFERENCE["text"].lower(), "t", "s")])
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs.references[0].digest, REFERENCE["text"])


# ------------------------------------------------------------------- store

class TlshCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-tlsh-"))
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

    def sample(self, name: str, data: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(data)
        return path


class TestImportingReferences(TlshCase):
    def test_parse_sorts_hashes_references_and_the_rest(self):
        parsed = parse_lines([
            "# a comment",
            "",
            hashlib.sha256(b"a").hexdigest(),
            REFERENCE["text"] + ",AgentTesla",
            REFERENCE["chain50"].lower() + ", Quoted Family , ignored, columns",
            REFERENCE["range256x4"][2:],
            "not a hash at all",
            "T1" + "0" * 69,
        ])
        self.assertEqual(len(parsed.hashes), 1)
        self.assertEqual(parsed.tlsh, [(REFERENCE["text"], "AgentTesla"),
                                       (REFERENCE["chain50"], "Quoted Family"),
                                       (REFERENCE["range256x4"], "")])
        self.assertEqual(parsed.rejected, 2)
        self.assertEqual(parsed.seen, 6)

    def test_parse_hashes_still_counts_a_reference_line_as_not_a_sha256(self):
        digests, rejected, seen = iocs.parse_hashes([hashlib.sha256(b"a").hexdigest(),
                                                     REFERENCE["text"]])
        self.assertEqual((len(digests), rejected, seen), (1, 1, 2))

    def test_import_lines_routes_each_kind_and_reports_both(self):
        result = self.store.import_lines([
            hashlib.sha256(b"a").hexdigest(),
            REFERENCE["text"] + ",Family",
            REFERENCE["text"] + ",Family",
            "junk",
        ], source="unit")
        self.assertEqual((result.added, result.tlsh_added, result.tlsh_known, result.rejected),
                         (1, 1, 1, 1))
        self.assertIn("1 new TLSH reference(s)", result.describe())
        self.assertEqual(self.store.count(), 1)
        self.assertEqual(self.store.tlsh_count(), 1)
        refs = self.store.tlsh_references()
        self.assertEqual(refs.references, [tlsh.Reference(REFERENCE["text"], "Family", "unit")])

    def test_remove_and_clear_source_reach_the_references(self):
        self.store.import_lines([REFERENCE["text"] + ",F", REFERENCE["chain50"]], source="a")
        self.assertTrue(self.store.remove_tlsh(REFERENCE["text"].lower()))
        self.assertFalse(self.store.remove_tlsh(REFERENCE["text"]))
        self.assertEqual(self.store.tlsh_count(), 1)
        self.assertEqual(self.store.clear_source("a"), 1)
        self.assertEqual(self.store.tlsh_count(), 0)

    def test_a_reference_import_changes_the_generation_and_a_repeat_does_not(self):
        scanner = self.scanner()
        before = scanner.detection_generation()
        self.store.import_lines([REFERENCE["text"] + ",F"], source="unit")
        after = scanner.detection_generation()
        self.assertNotEqual(before, after)
        self.store.import_lines([REFERENCE["text"] + ",F"], source="unit")
        self.assertEqual(after, scanner.detection_generation())
        self.store.remove_tlsh(REFERENCE["text"])
        self.assertNotEqual(after, scanner.detection_generation())

    def test_a_large_table_logs_one_warning_at_load(self):
        with mock.patch.object(iocs, "TLSH_WARN_REFERENCES", 2):
            self.store.import_lines([REFERENCE[n] for n in ("text", "chain50", "range256x4")],
                                    source="unit")
            with self.assertLogs("avguard.iocs", level="WARNING") as captured:
                refs = self.store.tlsh_references()
        self.assertEqual(len(refs), 3)
        self.assertEqual(len(captured.records), 1)
        self.assertIn("3 TLSH references", captured.output[0])
        self.assertIn("1% of clean executables", captured.output[0])


# ---------------------------------------------------------------- verdicts

class TestAMatchIsSoft(TlshCase):
    def setUp(self) -> None:
        super().setUp()
        self.base = chain(20000, b"family")
        self.store.import_lines([tlsh.hash_bytes(self.base) + ",TestFamily"], source="unit")

    def test_acceptance_a_flipped_copy_is_suspicious_and_an_unrelated_file_is_clean(self):
        variant = self.sample("variant.bin", flipped(self.base, 777))
        other = self.sample("other.bin", chain(20000, b"unrelated"))
        scanner = self.scanner()
        with self.assertNoLogs("avguard", level="WARNING"):
            verdict = scanner.scan(variant, use_cache=False)
        self.assertIs(verdict.level, Level.SUSPICIOUS)
        self.assertFalse(verdict.is_threat, "similarity never moves a file")
        finding = [f for f in verdict.findings if f.source == "tlsh"]
        self.assertEqual(len(finding), 1)
        self.assertFalse(finding[0].hard)
        self.assertEqual(finding[0].name, "TestFamily")
        self.assertIn("TestFamily", verdict.reasons[0])
        self.assertLess(tlsh.distance(verdict.facts.tlsh, tlsh.hash_bytes(self.base)), 10)

        clean = scanner.scan(other, use_cache=False)
        self.assertIs(clean.level, Level.CLEAN)
        self.assertFalse([f for f in clean.findings if f.source == "tlsh"])
        self.assertIsNotNone(clean.facts.tlsh, "it was digested and measured; it just did not match")

    def test_a_lone_match_stays_below_malicious_whatever_the_distance(self):
        variant = self.sample("variant.bin", flipped(self.base, 777))
        for near, far in ((0, 0), (5, 10), (10_000, 10_000)):
            with self.subTest(near=near, far=far), \
                    mock.patch.object(scanner_module, "TLSH_NEAR", near), \
                    mock.patch.object(scanner_module, "TLSH_FAR", far):
                verdict = self.scanner().scan(variant, use_cache=False)
                self.assertIsNot(verdict.level, Level.MALICIOUS)
                self.assertLessEqual(
                    sum(f.weight for f in verdict.findings if not f.hard),
                    scanner_module.HEURISTIC_CAP)

    def test_the_far_band_is_supporting_evidence_only(self):
        """Between TLSH_NEAR and TLSH_FAR the finding is recorded at the
        lower weight, which on its own is below SUSPICIOUS, like entropy."""
        variant = self.sample("variant.bin", flipped(self.base, 777))
        with mock.patch.object(scanner_module, "TLSH_NEAR", -1):
            verdict = self.scanner().scan(variant, use_cache=False)
        finding = [f for f in verdict.findings if f.source == "tlsh"]
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0].weight, scanner_module.WEIGHT_TLSH_FAR)
        self.assertIn("loose resemblance", finding[0].detail)
        self.assertIs(verdict.level, Level.CLEAN)

    def test_a_trusted_publisher_sets_the_match_aside_like_any_heuristic(self):
        variant = self.sample("variant.bin", flipped(self.base, 777))
        scanner = self.scanner()
        trusted = mock.Mock(is_trusted=True, detail="signed by Example Corp")
        with mock.patch.object(scanner, "_publisher_trust", return_value=trusted):
            verdict = scanner.scan(variant, use_cache=False)
        self.assertIs(verdict.level, Level.CLEAN)
        self.assertFalse([f for f in verdict.findings if f.source == "tlsh"])
        self.assertIn("set aside", " ".join(verdict.reasons))

    def test_a_hard_finding_still_condemns_with_a_match_present(self):
        marker = self.sample("marked.bin", flipped(self.base, 777) + scanner_module.SELFTEST_MARKER)
        verdict = self.scanner().scan(marker, use_cache=False)
        self.assertIs(verdict.level, Level.MALICIOUS)
        self.assertTrue([f for f in verdict.findings if f.source == "signature"])


class TestWhenAFileIsDigested(TlshCase):
    def test_nothing_is_digested_without_references(self):
        scanner = self.scanner()
        verdict = scanner.scan(self.sample("a.bin", chain(20000)), use_cache=False)
        self.assertIsNone(verdict.facts.tlsh)
        self.assertFalse(scanner._wants_tlsh(20000, scanner._tlsh_refs))

    def test_the_size_cap_and_the_minimum_apply(self):
        self.store.import_lines([REFERENCE["text"]], source="unit")
        scanner = self.scanner()
        cap = tlsh.size_cap()
        cases = {
            "under the minimum": (tlsh.MIN_BYTES - 1, False),
            "at the minimum": (tlsh.MIN_BYTES, True),
            "at the cap": (cap, True),
            "over the cap": (cap + 1, False),
        }
        for name, (size, wanted) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(scanner._wants_tlsh(size, scanner._tlsh_refs), wanted)

    def test_too_small_and_too_uniform_files_scan_without_warnings(self):
        self.store.import_lines([REFERENCE["text"]], source="unit")
        scanner = self.scanner()
        tiny = self.sample("tiny.bin", b"x" * 10)
        uniform = self.sample("uniform.bin", bytes(4000))
        for path in (tiny, uniform):
            with self.subTest(file=path.name), self.assertNoLogs("avguard", level="WARNING"):
                verdict = scanner.scan(path, use_cache=False)
            self.assertIs(verdict.level, Level.CLEAN)
            self.assertIsNone(verdict.facts.tlsh)

    def test_a_reference_imported_from_another_process_reaches_a_running_scanner(self):
        """`--iocs-import` in a terminal while the GUI runs, cache on: the
        cached CLEAN is dropped and the file measured against the new row."""
        base = chain(20000, b"family")
        variant = self.sample("variant.bin", flipped(base, 1))
        scanner = self.scanner()
        with mock.patch.object(scanner_module, "PACKS_CHECK_INTERVAL", 0.0):
            self.assertIs(scanner.scan(variant).level, Level.CLEAN)   # cached, no digest
            other = IocStore(path=self.store.path)
            self.addCleanup(other.close)
            other.import_lines([tlsh.hash_bytes(base) + ",Family"], source="terminal")
            self.assertIs(scanner.scan(variant).level, Level.SUSPICIOUS,
                          "the cached CLEAN outlived the import")
            self.assertEqual(len(scanner._tlsh_refs), 1)

    def test_the_backend_cap_is_part_of_the_generation(self):
        scanner = self.scanner()
        before = scanner.detection_generation()
        with mock.patch.dict(tlsh.SIZE_CAPS, {tlsh.backend(): 1}):
            self.assertNotEqual(before, scanner.detection_generation())


# --------------------------------------------------------------------- CLI

class TestTheCommandLine(TlshCase):
    def run_main(self, *argv: str) -> tuple[int, str]:
        import io
        from contextlib import redirect_stdout
        from avguard.__main__ import main
        out = io.StringIO()
        with redirect_stdout(out), \
                mock.patch.object(iocs, "IocStore", lambda *a, **k: self.store):
            code = main(list(argv))
        return code, out.getvalue()

    def test_tlsh_prints_a_digest_per_file_and_explains_the_undigestable(self):
        folder = self.tmp / "samples"
        folder.mkdir()
        (folder / "a.bin").write_bytes(inputs()["text"])
        (folder / "tiny.bin").write_bytes(b"xy")
        code, out = self.run_main("--tlsh", str(folder))
        self.assertEqual(code, 0)
        self.assertIn(REFERENCE["text"] + "  # ", out)
        self.assertIn("tiny.bin: no digest", out)

    def test_the_printed_line_imports_as_a_reference(self):
        target = self.sample("a.bin", inputs()["text"])
        code, out = self.run_main("--tlsh", str(target))
        self.assertEqual(code, 0)
        listing = self.tmp / "refs.txt"
        listing.write_text(out.splitlines()[0].split("  #")[0] + ",Family\n", encoding="utf-8")
        code, out = self.run_main("--iocs-import", str(listing), "--iocs-source", "cli")
        self.assertEqual(code, 0)
        self.assertIn("1 new TLSH reference(s)", out)
        self.assertEqual(self.store.tlsh_references().references,
                         [tlsh.Reference(REFERENCE["text"], "Family", "cli")])
        code, out = self.run_main("--iocs-status")
        self.assertEqual(code, 0)
        self.assertIn("TLSH references: 1", out)


if __name__ == "__main__":
    unittest.main()
