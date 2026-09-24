"""TLSH, the locality-sensitive hash, without a compiled dependency.

SHA-256 matches identical bytes and nothing else: one flipped byte defeats
the hash blocklist. TLSH (Trend Micro Locality Sensitive Hash) digests a
file so that similar inputs land a small *distance* apart, which is how a
known family's next variant gets caught by the previous one's digest.

Why this is written out here rather than imported: `py-tlsh` ships no wheel
for any interpreter on any platform, its sdist needs a C++ compiler, and a
user's Windows box has none. The plan's first attempt stopped there with a
pure-Python digest measured at 0.9 MB/s. This module is that digest done
with the vectorised primitives the interpreter already has -- `bytes.translate`
for the Pearson gathers, big-int XOR, and numpy for the bucket histogram
when it is installed -- and it is bit-identical to the reference C++ on every
input the tests throw at it (the reference was built here to check).

The one part that stays a Python loop is the checksum, a one-byte chain
where every step depends on the last; nothing vectorises that. It bounds
the digest at roughly 30 MB/s on this machine, the numpy bucket pass at
about 35 MB/s, so the two together run near 16 MB/s; without numpy the
histogram falls to `Counter` and the whole digest to 2.4 MB/s. If `py-tlsh`
IS importable (someone with a compiler built it) it is used and runs at
about 120 MB/s. Each backend gets a size cap that keeps one digest near a
tenth of a second, in `SIZE_CAPS`; the scanner computes no digest at all
unless a reference set exists, so a machine that never imports one pays
nothing.

Digest format: "T1" + 70 hex characters, the same string MalwareBazaar and
the `tlsh` command line print, so digests copied from either match here.
Distance is the reference `totalDiff` with length included: 0 for identical
digests, single digits for a small patch, a few hundred for unrelated files.
"""

from __future__ import annotations

import bisect
import logging
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, NamedTuple

log = logging.getLogger(__name__)

try:
    import numpy as np
except ImportError:  # the pure path is slower, never wrong
    np = None

try:
    import tlsh as _native  # py-tlsh, when someone had a compiler
    if (getattr(_native, "__file__", None) == __file__
            or not hasattr(_native, "Tlsh") or not hasattr(_native, "hash")):
        _native = None
except ImportError:
    _native = None


# The reference refuses to digest fewer bytes than this (`MIN_DATA_LENGTH`).
MIN_BYTES = 50
# Two hex characters per byte: 1 checksum, 1 length, 1 quartile ratios, 32 code.
HEX_LEN = 70
PREFIX = "T1"

# One digest costs about a tenth of a second at the top of each cap, on the
# backend's measured rate (4 MB of random bytes, three runs, the best):
# py-tlsh 119 MB/s, numpy 16 MB/s, plain Python 2.4 MB/s. Above the cap the
# file is scanned without a digest; that is recorded on the facts as None.
SIZE_CAPS = {
    "native": 16 * 1024 * 1024,
    "numpy": 2 * 1024 * 1024,
    "python": 256 * 1024,
}
# Bytes handed to the vectorised stages at a time. The scanner reads 64 KB
# chunks; batching four of them cuts the per-call overhead of the numpy
# stages without holding anything a human would notice.
BATCH_BYTES = 256 * 1024

# Pearson's sample random table, verbatim from tlsh_impl.cpp.
V_TABLE = bytes([
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
])
_V_LIST = list(V_TABLE)

# The reference's `topval` table: the length byte is the index of the first
# entry at or above the length, which is log_1.5 of it, rounded.
TOPVAL = (
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110,
    1443, 1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772,
    7450, 8195, 9014, 9916, 10907, 11998, 13198, 14518, 15970, 17567, 19323,
    21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422, 45564, 50121,
    55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183, 130002,
    143002, 157302, 173032, 190335, 209369, 230306, 253337, 278670, 306538,
    337191, 370911, 408002, 448802, 493682, 543050, 597356, 657091, 722800,
    795081, 874589, 962048, 1058252, 1164078, 1280486, 1408534, 1549388,
    1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320, 3321252,
    3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394,
    7831333, 8614467, 9475909, 10423501, 11465851, 12612437, 13873681,
    15261050, 16787154, 18465870, 20312458, 22343706, 24578077, 27035886,
    29739474, 32713425, 35984770, 39583245, 43541573, 47895730, 52685306,
    57953837, 63749221, 70124148, 77136564, 84850228, 93335252, 102668779,
    112935659, 124229227, 136652151, 150317384, 165349128, 181884040,
    200072456, 220079703, 242087671, 266296456, 292926096, 322218735,
    354440623, 389884688, 428873168, 471760495, 518936559, 570830240,
    627913311, 690704607, 759775136, 835752671, 919327967, 1011260767,
    1112386880, 1223623232, 1345985727, 1480584256, 1628642751, 1791507135,
    1970657856, 2167723648, 2384496256, 2622945920, 2885240448, 3173764736,
    3491141248, 3840255616, 4224281216,
)

# The six bucket triples over a five-byte window, as (salt, back1, back2):
# the newest byte, the byte `back1` positions earlier, the byte `back2`
# earlier. The salts are v_table[2], [3], [5], [7], [11], [13], which is the
# reference's `fast_b_mapping` with its first lookup folded in.
_TRIPLES = ((49, 1, 2), (12, 1, 3), (178, 2, 3), (166, 2, 4), (84, 1, 4), (230, 3, 4))
_CHECKSUM_SALT = 1   # v_table[0]
# First-stage tables: STAGE1[salt][byte] = v_table[salt ^ byte].
_STAGE1 = {salt: bytes(V_TABLE[salt ^ v] for v in range(256))
           for salt in (_CHECKSUM_SALT,) + tuple(t[0] for t in _TRIPLES)}

# Distance between two code bytes: four 2-bit lanes, |a - b| per lane with a
# difference of 3 counted as 6. The reference keeps this as a 256x256 table
# generated by gen_arr2.cpp; built here the same way.
def _lane_distance(x: int, y: int) -> int:
    total = 0
    for shift in (0, 2, 4, 6):
        d = abs(((x >> shift) & 3) - ((y >> shift) & 3))
        total += 6 if d == 3 else d
    return total


_PAIRS = bytes(_lane_distance(x, y) for x in range(256) for y in range(256))

if np is not None:
    _T_NP = np.frombuffer(V_TABLE, dtype=np.uint8)
    _PAIRS_NP = np.frombuffer(_PAIRS, dtype=np.uint8).reshape(256, 256)


def backend() -> str:
    """Which implementation digests here: "native", "numpy" or "python"."""
    if _native is not None:
        return "native"
    return "numpy" if np is not None else "python"


def size_cap(which: str | None = None) -> int:
    return SIZE_CAPS[which or backend()]


# ------------------------------------------------------------------ digest


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR of two equal-length byte strings, at C speed through big ints."""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _chain(k: bytes, checksum: int) -> int:
    """The checksum: c = T[k ^ c] for every k. Sequential by construction."""
    table = _V_LIST
    for kv in k:
        checksum = table[kv ^ checksum]
    return checksum


def _length_byte(length: int) -> int:
    return min(bisect.bisect_left(TOPVAL, length), 255)


def _swap_nibbles(value: int) -> int:
    return ((value & 0xF0) >> 4) | ((value & 0x0F) << 4)


def _finish(buckets: list[int], checksum: int, length: int) -> str | None:
    """The reference `final()`: quartiles, the 2-bit code, the header."""
    if length < MIN_BYTES:
        return None
    used = buckets[:128]
    ordered = sorted(used)
    q1, q2, q3 = ordered[31], ordered[63], ordered[95]
    if q3 == 0:
        return None
    if sum(1 for v in used if v > 0) <= 64:
        # "buckets must be more than 50% non-zero": too little variety in
        # the input for the digest to mean anything.
        return None
    code = bytearray(32)
    for i in range(32):
        h = 0
        for j in range(4):
            k = used[4 * i + j]
            if k > q3:
                h += 3 << (2 * j)
            elif k > q2:
                h += 2 << (2 * j)
            elif k > q1:
                h += 1 << (2 * j)
        code[i] = h
    q1ratio = (q1 * 100 // q3) % 16
    q2ratio = (q2 * 100 // q3) % 16
    return Digest(checksum, _length_byte(length), q1ratio, q2ratio, bytes(code)).hex()


class _PythonHasher:
    """The digest from the interpreter's own vectorised primitives."""

    backend = "python"

    def __init__(self) -> None:
        self.buckets = [0] * 256
        self.checksum = 0
        self.length = 0
        self._pending: list[bytes] = []
        self._pending_len = 0
        self._tail = b""   # the last four bytes seen: the window straddles chunks

    def update(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.length += len(chunk)
        self._pending.append(bytes(chunk))
        self._pending_len += len(chunk)
        if self._pending_len >= BATCH_BYTES:
            self._flush()

    def _flush(self) -> None:
        if not self._pending:
            return
        data = self._tail + b"".join(self._pending)
        self._pending = []
        self._pending_len = 0
        if len(data) < 5:
            self._tail = data
            return
        self._consume(data)
        self._tail = data[-4:]

    def _stages(self, data: bytes) -> tuple[list[bytes], bytes]:
        """The six bucket streams and the checksum stream for one batch.

        Each stream is `v_table[v_table[STAGE1[salt][newest] ^ b] ^ c]` over
        every position: three table gathers and two XORs, all at C speed.
        """
        x = (data[4:], data[3:-1], data[2:-2], data[1:-3], data[:-4])
        table = V_TABLE
        streams = []
        for salt, back1, back2 in _TRIPLES:
            h = _xor(x[0].translate(_STAGE1[salt]), x[back1]).translate(table)
            streams.append(_xor(h, x[back2]).translate(table))
        k = _xor(x[0].translate(_STAGE1[_CHECKSUM_SALT]), x[1]).translate(table)
        return streams, k

    def _consume(self, data: bytes) -> None:
        streams, k = self._stages(data)
        buckets = self.buckets
        for value, n in Counter(b"".join(streams)).items():
            buckets[value] += n
        self.checksum = _chain(k, self.checksum)

    def final(self) -> str | None:
        self._flush()
        return _finish(list(self.buckets), self.checksum, self.length)


class _NumpyHasher(_PythonHasher):
    """Same stages; the histogram and the XORs go through numpy."""

    backend = "numpy"

    def __init__(self) -> None:
        super().__init__()
        self._counts = np.zeros(256, dtype=np.int64)

    def _consume(self, data: bytes) -> None:
        arr = np.frombuffer(data, dtype=np.uint8)
        x = (arr[4:], arr[3:-1], arr[2:-2], arr[1:-3], arr[:-4])
        newest = data[4:]
        table = V_TABLE
        counts = self._counts
        for salt, back1, back2 in _TRIPLES:
            h = np.frombuffer(newest.translate(_STAGE1[salt]), dtype=np.uint8) ^ x[back1]
            h = np.frombuffer(h.tobytes().translate(table), dtype=np.uint8) ^ x[back2]
            h = np.frombuffer(h.tobytes().translate(table), dtype=np.uint8)
            counts += np.bincount(h, minlength=256)
        k = np.frombuffer(newest.translate(_STAGE1[_CHECKSUM_SALT]), dtype=np.uint8) ^ x[1]
        self.checksum = _chain(k.tobytes().translate(table), self.checksum)

    def final(self) -> str | None:
        self._flush()
        return _finish(self._counts.tolist(), self.checksum, self.length)


class _NativeHasher:
    """py-tlsh, when it is importable.

    Fed in batches, never a few bytes at a time: the reference's streaming
    update gives a different digest from its one-shot `hash()` when the
    input arrives in tiny chunks (measured here: 1-, 2-, 3-, 4-, 6- and
    7-byte chunks all differ, a short tail after a long chunk does not; the
    pure paths above agree with `hash()` on every chunking tried). The
    scanner's 64 KB chunks never hit it; a caller's might.
    """

    backend = "native"

    def __init__(self) -> None:
        self._impl = _native.Tlsh()
        self.length = 0
        self._pending: list[bytes] = []
        self._pending_len = 0

    def update(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.length += len(chunk)
        self._pending.append(bytes(chunk))
        self._pending_len += len(chunk)
        if self._pending_len >= BATCH_BYTES:
            self._flush()

    def _flush(self) -> None:
        if self._pending:
            self._impl.update(b"".join(self._pending))
            self._pending = []
            self._pending_len = 0

    def final(self) -> str | None:
        self._flush()
        if self.length < MIN_BYTES:
            return None
        try:
            self._impl.final()
        except ValueError:
            return None
        valid = self._impl.is_valid   # a property in py-tlsh 5, a method before it
        if not (valid() if callable(valid) else valid):
            return None
        digest = self._impl.hexdigest()
        return None if not digest or digest == "TNULL" else digest.upper()


def Hasher(which: str | None = None):
    """A streaming digest: `update(chunk)` as the bytes go by, `final()` once.

    `final()` returns the "T1..." string, or None when the reference would
    return TNULL: fewer than 50 bytes, or too little variety for the
    quartiles to mean anything. Neither is an error; it is recorded as no
    digest and the file scans on without one.
    """
    which = which or backend()
    if which == "native":
        if _native is None:
            raise RuntimeError("py-tlsh is not importable here")
        return _NativeHasher()
    if which == "numpy":
        if np is None:
            raise RuntimeError("numpy is not importable here")
        return _NumpyHasher()
    if which == "python":
        return _PythonHasher()
    raise ValueError(f"unknown TLSH backend {which!r}")


def hash_bytes(data: bytes, which: str | None = None) -> str | None:
    hasher = Hasher(which)
    hasher.update(data)
    return hasher.final()


def hash_file(path: Path | str, chunk_size: int = 64 * 1024,
              which: str | None = None) -> str | None:
    """The digest of a file, read in chunks. Raises OSError like open()."""
    hasher = Hasher(which)
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            hasher.update(chunk)
    return hasher.final()


# ----------------------------------------------------------------- digests


@dataclass(frozen=True)
class Digest:
    """A parsed digest in the reference's internal order."""

    checksum: int
    lvalue: int
    q1ratio: int
    q2ratio: int
    code: bytes   # 32 bytes, bucket order (the hex string prints them reversed)

    def hex(self) -> str:
        header = bytes([_swap_nibbles(self.checksum), _swap_nibbles(self.lvalue),
                        _swap_nibbles(self.q1ratio | (self.q2ratio << 4))])
        return PREFIX + header.hex().upper() + bytes(reversed(self.code)).hex().upper()

    @classmethod
    def parse(cls, text: str) -> "Digest":
        """Accepts "T1" + 70 hex or the bare 70 hex, either case. Raises ValueError."""
        digest = normalize(text)
        if digest is None:
            raise ValueError(f"not a TLSH digest: {text!r}")
        raw = bytes.fromhex(digest[len(PREFIX):])
        qb = _swap_nibbles(raw[2])
        return cls(_swap_nibbles(raw[0]), _swap_nibbles(raw[1]),
                   qb & 0x0F, qb >> 4, bytes(reversed(raw[3:])))


def normalize(text: str) -> str | None:
    """The canonical "T1..." spelling of a digest string, or None."""
    token = (text or "").strip().upper()
    if token.startswith(PREFIX):
        token = token[len(PREFIX):]
    if len(token) != HEX_LEN:
        return None
    try:
        bytes.fromhex(token)
    except ValueError:
        return None
    return PREFIX + token


def is_digest(text: str) -> bool:
    return normalize(text) is not None


def _mod_diff(x: int, y: int, wrap: int) -> int:
    d = abs(x - y)
    return min(d, wrap - d)


def distance(a: "Digest | str", b: "Digest | str", length: bool = True) -> int:
    """The reference `totalDiff`: 0 for identical, hundreds for unrelated.

    `length=False` is `diffxlen`, which ignores the file-size byte; the
    scanner uses the default, because a variant padded to ten times the
    size is not the same family in the way the thresholds were measured.
    """
    if isinstance(a, str):
        a = Digest.parse(a)
    if isinstance(b, str):
        b = Digest.parse(b)
    total = 0
    if length:
        ld = _mod_diff(a.lvalue, b.lvalue, 256)
        total = ld if ld <= 1 else ld * 12
    q1 = _mod_diff(a.q1ratio, b.q1ratio, 16)
    total += q1 if q1 <= 1 else (q1 - 1) * 12
    q2 = _mod_diff(a.q2ratio, b.q2ratio, 16)
    total += q2 if q2 <= 1 else (q2 - 1) * 12
    if a.checksum != b.checksum:
        total += 1
    pairs = _PAIRS
    total += sum(pairs[(x << 8) | y] for x, y in zip(a.code, b.code))
    return total


# ---------------------------------------------------------------- matching


class Reference(NamedTuple):
    digest: str
    family: str
    source: str


class Match(NamedTuple):
    distance: int
    reference: Reference


class ReferenceSet:
    """Known-bad digests, matched against a file's digest in one pass.

    With numpy the pass is one gather over an (N, 32) table -- 10,000
    references cost about a millisecond per file; without it, a Python loop
    at about 5 us per reference. Either way it only runs for files that
    have a digest, and a digest is only computed when this set is not empty.
    """

    def __init__(self, references: Iterable[Reference] = ()) -> None:
        self.references: list[Reference] = []
        parsed: list[Digest] = []
        for ref in references:
            canonical = normalize(ref.digest)
            if canonical is None:
                continue
            self.references.append(Reference(canonical, ref.family, ref.source))
            parsed.append(Digest.parse(canonical))
        self._parsed = parsed
        self._np = None
        if np is not None and parsed:
            self._np = (
                np.frombuffer(b"".join(d.code for d in parsed), dtype=np.uint8)
                .reshape(len(parsed), 32),
                np.array([d.lvalue for d in parsed], dtype=np.int32),
                np.array([d.q1ratio for d in parsed], dtype=np.int32),
                np.array([d.q2ratio for d in parsed], dtype=np.int32),
                np.array([d.checksum for d in parsed], dtype=np.int32),
            )

    def __len__(self) -> int:
        return len(self.references)

    def __bool__(self) -> bool:
        return bool(self.references)

    def distances(self, digest: "Digest | str") -> list[int]:
        """The distance from `digest` to every reference, in reference order."""
        if isinstance(digest, str):
            digest = Digest.parse(digest)
        if self._np is not None:
            return self._distances_np(digest).tolist()
        return [distance(digest, parsed) for parsed in self._parsed]

    def nearest(self, digest: "Digest | str") -> Match | None:
        """The closest reference and its distance, or None for an empty set."""
        if not self.references:
            return None
        if isinstance(digest, str):
            digest = Digest.parse(digest)
        if self._np is not None:
            total = self._distances_np(digest)
            index = int(np.argmin(total))
            return Match(int(total[index]), self.references[index])
        best = None
        for ref, parsed in zip(self.references, self._parsed):
            d = distance(digest, parsed)
            if best is None or d < best.distance:
                best = Match(d, ref)
        return best

    def _distances_np(self, digest: Digest):
        """`distance()` against every reference at once: one (N, 32) gather."""
        codes, lvalues, q1s, q2s, checksums = self._np
        code = np.frombuffer(digest.code, dtype=np.uint8)
        body = _PAIRS_NP[codes, code[None, :]].sum(axis=1, dtype=np.int32)

        def wrapped(values, mine, wrap):
            d = np.abs(values - mine)
            return np.minimum(d, wrap - d)

        ld = wrapped(lvalues, digest.lvalue, 256)
        total = np.where(ld <= 1, ld, ld * 12)
        q1 = wrapped(q1s, digest.q1ratio, 16)
        total = total + np.where(q1 <= 1, q1, (q1 - 1) * 12)
        q2 = wrapped(q2s, digest.q2ratio, 16)
        total = total + np.where(q2 <= 1, q2, (q2 - 1) * 12)
        return total + (checksums != digest.checksum) + body
