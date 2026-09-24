"""Measure the TLSH thresholds against benign files, before trusting them.

The plan's thresholds (30 near, 60 far) are folklore until measured. This
walks the benign corpus the rule tests use -- real software installed on
this machine, a few files per directory -- digests every file, and then
answers the question the thresholds depend on: how often do two UNRELATED
benign files score within a given distance of each other? That is the
false-positive probability per (file, reference) pair; with a reference set
of K samples the chance a benign file trips at least one is 1 - (1 - p)^K.

Byte-identical files are counted once (a machine holds many copies of the
same WHEEL file, the same logo, the same licence), and two files from the
same directory are excluded from the "unrelated" count and reported
separately as "same package": one product's files, or the 200 glibc
character-set modules built from one template, are the same code, and
scoring close is the digest doing its job, not a false positive. A malware
reference never sits in the benign file's own directory, so the unrelated
rate is the one a reference set would produce. What is left under a
threshold is listed by name, so the reader can judge whether it is unrelated.

`--binaries` keeps only executables (ELF or PE by magic), which share
headers, startup code and runtime stubs and so are the harder case.

Also reported: what a real variant scores. Each corpus file is patched in
three ways (one byte flipped; one byte in every 4 KB; a 1% random overwrite)
and the distance to the original recorded, so the two thresholds can be
placed between "a patched copy" and "an unrelated file" with numbers.

Run:  python tools/tlsh_calibration.py [--roots DIR ...] [--limit N]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from avguard import tlsh  # noqa: E402
from avguard.__main__ import _clean_corpus  # noqa: E402

THRESHOLDS = (10, 20, 30, 40, 50, 60, 80, 100)


def default_roots() -> list[Path]:
    if os.name == "nt":
        return [Path(r"C:/Program Files"), Path(r"C:/Program Files (x86)"),
                Path(os.environ.get("LOCALAPPDATA", r"C:/nowhere")) / "Programs",
                Path(r"C:/Windows/System32")]
    return [Path("/usr/bin"), Path("/usr/lib"), Path("/usr/share"), Path("/usr/local")]


def is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return head == b"\x7fELF" or head[:2] == b"MZ"


def digestible(path: Path) -> bool:
    """What the scanner would digest on this backend: not too small, not over the cap."""
    try:
        return tlsh.MIN_BYTES <= path.stat().st_size <= tlsh.size_cap()
    except OSError:
        return False


def corpus(roots: list[Path], limit: int, per_directory: int, binaries: bool) -> list[Path]:
    if os.name == "nt" and not binaries:
        # The size filter below applied off Windows only; here the sampler
        # took every .exe and .dll, cap or no cap, so files the scanner never
        # digests were in the measurement. Sample twice the limit and keep
        # what fits.
        picked = _clean_corpus(limit=limit * 2, roots=roots, per_directory=per_directory)
        return [path for path in picked if digestible(path)][:limit]
    # Off Windows the .exe/.dll filter of _clean_corpus finds nothing; take
    # whatever real files these roots hold, a few per directory, under the cap.
    rng = random.Random(20240607)
    picked: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            files = sorted(filenames)
            rng.shuffle(files)
            taken = 0
            for name in files:
                path = Path(dirpath) / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    size = path.stat().st_size
                except OSError:
                    continue
                if not (tlsh.MIN_BYTES <= size <= tlsh.size_cap()):
                    continue          # the same rule digestible() applies on Windows
                if binaries and not is_binary(path):
                    continue
                picked.append(path)
                taken += 1
                if taken >= per_directory or len(picked) >= limit:
                    break
            if len(picked) >= limit:
                return picked
    return picked


def dedupe(files: list[Path]) -> tuple[list[Path], int]:
    """One path per distinct content; how many copies were dropped."""
    seen: set[str] = set()
    kept: list[Path] = []
    dropped = 0
    for path in files:
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
        if digest in seen:
            dropped += 1
            continue
        seen.add(digest)
        kept.append(path)
    return kept, dropped


def package_key(path: Path) -> str:
    """Files in one directory are one package: not an unrelated pair."""
    return str(path.parent).lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--roots", nargs="+", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=2000)
    parser.add_argument("--per-directory", type=int, default=6)
    parser.add_argument("--variants", type=int, default=300,
                        help="how many corpus files to patch for the variant measurement")
    parser.add_argument("--binaries", action="store_true",
                        help="executables only (ELF or PE magic), the harder case")
    parser.add_argument("--band", nargs=2, type=int, metavar=("LOW", "HIGH"), action="append",
                        help="also list a sample of unrelated pairs scoring in [LOW, HIGH]")
    args = parser.parse_args(argv)

    roots = args.roots or default_roots()
    per_directory = args.per_directory
    if args.binaries and per_directory == parser.get_default("per_directory"):
        per_directory = args.limit   # /usr/bin is one directory with a thousand programs
    files = corpus(roots, args.limit, per_directory, args.binaries)
    files, copies = dedupe(files)
    print(f"backend {tlsh.backend()}, size cap {tlsh.size_cap() // 1024} KB")
    print(f"corpus: {len(files)} distinct files ({copies} byte-identical copies dropped) from "
          f"{', '.join(str(r) for r in roots if r.is_dir())}"
          + (", executables only" if args.binaries else ""))

    started = time.perf_counter()
    digests: list[tuple[Path, str]] = []
    undigestable = 0
    total_bytes = 0
    for path in files:
        try:
            digest = tlsh.hash_file(path)
            total_bytes += path.stat().st_size
        except OSError:
            continue
        if digest is None:
            undigestable += 1
            continue
        digests.append((path, digest))
    elapsed = time.perf_counter() - started
    print(f"digested {len(digests)} files, {total_bytes / 2**20:.0f} MB in {elapsed:.1f} s "
          f"({total_bytes / elapsed / 1e6:.1f} MB/s); {undigestable} too small or too uniform")

    # Pairwise distances between unrelated files, through the same matcher
    # the scanner uses: each file against the set of all the others.
    references = tlsh.ReferenceSet(
        tlsh.Reference(d, "", str(p)) for p, d in digests)
    parsed = [tlsh.Digest.parse(d) for _, d in digests]
    started = time.perf_counter()
    unrelated_hits = {t: 0 for t in THRESHOLDS}
    related_hits = {t: 0 for t in THRESHOLDS}
    unrelated_pairs = 0
    related_pairs = 0
    closest_unrelated: list[tuple[int, str, str]] = []
    keys = [package_key(p) for p, _ in digests]
    for i, mine in enumerate(parsed):
        total = references.distances(mine)
        for j in range(i + 1, len(parsed)):
            d = total[j]
            related = keys[i] == keys[j]
            if related:
                related_pairs += 1
                bucket = related_hits
            else:
                unrelated_pairs += 1
                bucket = unrelated_hits
                if d <= 100:
                    closest_unrelated.append((d, str(digests[i][0]), str(digests[j][0])))
            for t in THRESHOLDS:
                if d <= t:
                    bucket[t] += 1
    print(f"pairwise: {unrelated_pairs:,} unrelated pairs, {related_pairs:,} same-package pairs, "
          f"{time.perf_counter() - started:.1f} s")

    # What a patched copy scores.
    rng = random.Random(1)
    sample = digests[:args.variants]
    variant_scores: dict[str, list[int]] = {"1 byte": [], "1 byte per 4 KB": [], "1% overwritten": []}
    for path, digest in sample:
        try:
            data = bytearray(path.read_bytes())
        except OSError:
            continue
        if len(data) < 64:
            continue
        one = bytearray(data); one[rng.randrange(len(one))] ^= 0xFF
        sparse = bytearray(data)
        for offset in range(0, len(sparse), 4096):
            sparse[offset] ^= 0x55
        heavy = bytearray(data)
        for _ in range(max(1, len(heavy) // 100)):
            heavy[rng.randrange(len(heavy))] = rng.getrandbits(8)
        for label, patched in (("1 byte", one), ("1 byte per 4 KB", sparse), ("1% overwritten", heavy)):
            other = tlsh.hash_bytes(bytes(patched))
            if other is not None:
                variant_scores[label].append(tlsh.distance(digest, other))

    print()
    print("distance   unrelated pairs within it     per-pair rate   benign files tripped by a")
    print("                                                         reference set of 100 / 1,000 / 10,000")
    for t in THRESHOLDS:
        p = unrelated_hits[t] / unrelated_pairs if unrelated_pairs else 0.0
        trip = [1 - (1 - p) ** k for k in (100, 1000, 10000)]
        print(f"  <= {t:<4} {unrelated_hits[t]:>12,} of {unrelated_pairs:<12,} "
              f"{p:12.2e}   {trip[0]:6.2%} / {trip[1]:6.2%} / {trip[2]:6.2%}")
    print()
    print("same-package pairs (files of one directory) within each distance:")
    print("  " + "  ".join(f"<={t}: {related_hits[t]:,}" for t in THRESHOLDS) + f"  of {related_pairs:,}")
    print()
    print("what a patched copy of a corpus file scores against the original:")
    for label, scores in variant_scores.items():
        if not scores:
            continue
        scores.sort()
        median = scores[len(scores) // 2]
        p90 = scores[int(len(scores) * 0.9)]
        p99 = scores[int(len(scores) * 0.99)]
        print(f"  {label:<18} n={len(scores):<4} min {scores[0]:>3}  median {median:>3}  "
              f"90th {p90:>3}  99th {p99:>3}  max {scores[-1]:>3}   "
              + "  ".join(f"over {t}: {sum(s > t for s in scores)}" for t in (30, 40, 60)))
    print()
    closest_unrelated.sort()
    print("closest unrelated pairs (distance, sizes, paths):")
    for d, a, b in closest_unrelated[:20]:
        print(f"  {d:>4}  {os.path.getsize(a):>9,} B  {a}\n        {os.path.getsize(b):>9,} B  {b}")
    for low, high in args.band or ():
        band = [p for p in closest_unrelated if low <= p[0] <= high]
        rng.shuffle(band)
        print(f"\n{len(band)} unrelated pairs scoring {low}..{high}; a sample:")
        for d, a, b in sorted(band[:15]):
            print(f"  {d:>4}  {os.path.getsize(a):>9,} B  {a}\n        {os.path.getsize(b):>9,} B  {b}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
