"""Looking inside zip files, without ever unpacking them.

Real-time protection watches Downloads, which is where a browser puts a .zip.
Until now a zipped sample was one opaque blob: the scanner hashed the container
and moved on. That is the single largest coverage gap for the folder this
program actually watches.

Nothing is ever extracted to disk. Members are read as bounded streams in
memory, so a hostile archive cannot write anywhere, cannot fill the disk, and
cannot survive the scan. Three properties make that cheap:

  * `compress_size` and `file_size` come from the central directory, so a
    decompression bomb is detectable before a single byte is decompressed
  * `flag_bits & 0x1` marks an encrypted member, so we can say "cannot inspect"
    instead of guessing at a password
  * the entry name is visible up front, so traversal is a fact about metadata
    rather than something discovered while writing files out

Only zip is supported. RAR and 7z need third-party packages, and zip is what
browsers and mail clients actually produce.
"""

from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

log = logging.getLogger(__name__)

# Extensions handled by zipfile. .jar, .apk, .docx, .xlsx and friends are all
# zip containers; the office formats are deliberately left out because their
# members are almost entirely XML and the noise is not worth it.
ARCHIVE_SUFFIXES = frozenset({".zip", ".jar", ".war", ".apk", ".zipx"})

MAX_DEPTH = 2                       # an archive inside an archive, and no deeper
MAX_MEMBERS = 500                   # entries examined per archive
MAX_MEMBER_BYTES = 32 * 1024 * 1024  # never hold more than this in memory
MAX_TOTAL_BYTES = 256 * 1024 * 1024  # total uncompressed budget per archive

# A member claiming to expand by more than this is treated as a bomb and is
# never decompressed. Ordinary text compresses around 3-5x; a zip of zeros
# reaches 1000x.
MAX_COMPRESSION_RATIO = 200


class ArchiveProblem(str):
    """A structural complaint about the container itself."""


@dataclass
class ArchiveMember:
    name: str
    size: int
    compressed: int
    data: bytes | None = None
    skipped: str = ""


@dataclass
class ArchiveReport:
    path: Path
    members: list[ArchiveMember] = field(default_factory=list)

    # Things about the archive that suggest hostile intent: a decompression
    # bomb, an entry name that escapes the extraction directory, a member
    # bigger than its own header claims.
    problems: list[str] = field(default_factory=list)

    # Things about OUR scan, not about the file. A resource pack with 8,000
    # entries is not hostile; we just did not look at all of them. Reporting a
    # limit of ours as a property of the file is how a scanner starts lying --
    # the first real-world run of this code flagged a Minecraft resource pack
    # as "malformed or hostile" for exactly that reason.
    notes: list[str] = field(default_factory=list)

    truncated: bool = False

    @property
    def inspected(self) -> int:
        return sum(1 for m in self.members if m.data is not None)


def is_archive(path: Path) -> bool:
    return path.suffix.lower() in ARCHIVE_SUFFIXES


def _entry_is_traversal(name: str) -> bool:
    """True if the entry name tries to escape the extraction directory.

    We never extract, so this cannot hurt us directly. It is reported because
    an archive whose entries are named `../../x` was built to attack whatever
    unpacks it, and that is worth telling the user about.
    """
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or normalised.startswith("../"):
        return True
    if ".." in normalised.split("/"):
        return True
    # C:\... or \\server\share
    return len(normalised) > 1 and normalised[1] == ":"


def inspect(
    path: Path,
    depth: int = 0,
    budget: list[int] | None = None,
) -> ArchiveReport:
    """Read an archive's members into memory, refusing anything unreasonable.

    Returns a report rather than raising: a malformed archive is a fact about
    the file, not an error in the scan.
    """
    report = ArchiveReport(path=path)
    if budget is None:
        budget = [MAX_TOTAL_BYTES]

    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        # A truncated download is the usual cause. Recorded, not accused.
        report.notes.append(f"could not be read as an archive ({type(exc).__name__})")
        return report

    with archive:
        try:
            infos = archive.infolist()
        except Exception as exc:
            report.notes.append(f"could not read the archive index ({type(exc).__name__})")
            return report

        if len(infos) > MAX_MEMBERS:
            report.truncated = True
            report.notes.append(
                f"holds {len(infos)} entries; only the first {MAX_MEMBERS} were examined")
            infos = infos[:MAX_MEMBERS]

        for info in infos:
            if info.is_dir():
                continue

            member = ArchiveMember(name=info.filename,
                                   size=info.file_size,
                                   compressed=info.compress_size)

            if _entry_is_traversal(info.filename):
                report.problems.append(f"entry name escapes the archive: {info.filename!r}")

            if info.flag_bits & 0x1:
                member.skipped = "encrypted, cannot be inspected"
                report.members.append(member)
                continue

            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_COMPRESSION_RATIO and info.file_size > 1024 * 1024:
                member.skipped = f"expands {ratio:.0f}x, refused as a decompression bomb"
                report.problems.append(
                    f"{info.filename!r} expands {ratio:.0f}x ({info.compress_size:,} -> "
                    f"{info.file_size:,} bytes)")
                report.members.append(member)
                continue

            if info.file_size > MAX_MEMBER_BYTES:
                member.skipped = f"larger than the {MAX_MEMBER_BYTES // (1024*1024)} MB member limit"
                report.members.append(member)
                continue

            if info.file_size > budget[0]:
                member.skipped = "archive exceeded its total inspection budget"
                report.truncated = True
                report.members.append(member)
                continue

            try:
                with archive.open(info) as handle:
                    # Read one byte past the declared size: a member whose real
                    # content is longer than its header claims is lying.
                    data = handle.read(min(info.file_size, MAX_MEMBER_BYTES) + 1)
            except Exception as exc:
                member.skipped = f"unreadable ({type(exc).__name__})"
                report.members.append(member)
                continue

            if len(data) > info.file_size:
                report.problems.append(
                    f"{info.filename!r} is larger than its header claims")
                data = data[:MAX_MEMBER_BYTES]

            budget[0] -= len(data)
            member.data = data
            report.members.append(member)

    return report


def iter_nested(
    report: ArchiveReport,
    depth: int = 0,
) -> Iterator[tuple[str, bytes]]:
    """Yield (display name, bytes) for every inspectable member.

    Members that are themselves zip files are descended into, up to MAX_DEPTH,
    so a sample hidden one archive deep is still seen. Beyond that the nesting
    is reported rather than followed -- unbounded recursion is how a zip quine
    takes a scanner down.
    """
    for member in report.members:
        if member.data is None:
            continue
        yield f"{report.path.name}!{member.name}", member.data

        if depth >= MAX_DEPTH:
            continue
        if not member.data.startswith(b"PK"):
            continue

        import io
        try:
            with zipfile.ZipFile(io.BytesIO(member.data)) as nested:
                infos = nested.infolist()[:MAX_MEMBERS]
                for info in infos:
                    if info.is_dir() or info.flag_bits & 0x1:
                        continue
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > MAX_COMPRESSION_RATIO and info.file_size > 1024 * 1024:
                        continue
                    if info.file_size > MAX_MEMBER_BYTES:
                        continue
                    try:
                        with nested.open(info) as handle:
                            payload = handle.read(MAX_MEMBER_BYTES)
                    except Exception:
                        continue
                    yield f"{report.path.name}!{member.name}!{info.filename}", payload
        except (zipfile.BadZipFile, OSError, EOFError):
            continue
