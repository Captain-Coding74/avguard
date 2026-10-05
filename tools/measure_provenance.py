"""The two provenance timings the ROADMAP cites, as a command.

    python tools/measure_provenance.py [FOLDER]

Scans FOLDER (default: this repository's own files, a quarter of them
renamed .exe so the gated path runs) with the cache off, three times with
the provenance pass and three without, and prints the per-file delta; then
times a marked and an unmarked 50 x 200 KB archive. Writes only under a
temporary directory and AVGUARD_DATA, which it points at a temporary
directory unless already set.
"""

from __future__ import annotations

import os
import random
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("AVGUARD_DATA", tempfile.mkdtemp(prefix="avguard-measure-data-"))

from avguard import config, provenance                       # noqa: E402
from avguard.protection import SelfProtection                # noqa: E402
from avguard.scanner import ScanCache, Scanner               # noqa: E402


def main(argv: list[str]) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="avguard-measure-"))
    try:
        cfg = config.Config(cloud_enabled=False)
        scanner = Scanner(cfg, SelfProtection([tmp / "protected"]), rules_path=ROOT / "rules" / "malware.yara",
                          cache=ScanCache(path=tmp / "cache.json"))
        scanner.provenance = provenance.ProvenanceStore(tmp / "provenance.sqlite")
        source = Path(argv[1]) if len(argv) > 1 else ROOT
        files = [p for p in source.rglob("*") if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts]
        corpus = []
        for index, path in enumerate(files):
            dest = tmp / "corpus" / (path.name + (".exe" if len(argv) == 1 and index % 4 == 0 else ""))
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(path, dest)
            corpus.append(dest)
        print(f"corpus: {len(corpus)} files, {sum(p.stat().st_size for p in corpus) / 1e6:.1f} MB, "
              f"{sum(1 for p in corpus if provenance.is_gated(p))} gated by suffix")

        def run(label: str) -> float:
            best = min(_timed(scanner, corpus) for _ in range(3))
            print(f"{label}: {best:.3f}s, {best / len(corpus) * 1e6:.0f} us per file (best of 3, cache off)")
            return best

        with_pass = run("with the provenance pass")
        original = Scanner._provenance_findings
        Scanner._provenance_findings = lambda self, path, sha256, level: []
        try:
            without = run("without it")
        finally:
            Scanner._provenance_findings = original
        print(f"delta: {(with_pass - without) / len(corpus) * 1e6:.0f} us per file")

        rnd = random.Random(1)
        members = {f"app/m{i}.exe": bytes(rnd.getrandbits(8) for _ in range(200_000)) for i in range(50)}
        plain, marked = _archive(tmp / "plain.zip", members, False), _archive(tmp / "marked.zip", members, True)
        t_plain = min(_timed(scanner, [plain]) for _ in range(5))
        t_marked = min(_timed(scanner, [marked]) for _ in range(5))
        print(f"archive of 50 x 200 KB members: {t_plain * 1e3:.0f} ms unmarked, {t_marked * 1e3:.0f} ms marked "
              f"(hashing and remembering the members): delta {(t_marked - t_plain) * 1e3:.0f} ms")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _timed(scanner: Scanner, paths: list[Path]) -> float:
    started = time.perf_counter()
    for path in paths:
        scanner.scan(path, use_cache=False)
    return time.perf_counter() - started


def _archive(path: Path, members: dict[str, bytes], marked: bool) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    if marked:
        with open(provenance.stream_path(path), "w", newline="") as handle:
            handle.write("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://downloads.example.test/x.zip\r\n")
    return path


if __name__ == "__main__":
    sys.exit(main(sys.argv))
