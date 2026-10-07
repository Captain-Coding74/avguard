"""Looking inside zip files, without ever unpacking them.

Real-time protection watches Downloads, which is where a browser puts a .zip.
Until now a zipped sample was one opaque blob: the scanner hashed the container
and moved on. That is the single largest coverage gap for the folder this
program actually watches.

Nothing is ever extracted to disk. Members are read as bounded streams in
memory, so a hostile archive cannot write anywhere, cannot fill the disk, and
cannot survive the scan. Three properties make that cheap:

  * `compress_size` and `file_size` come from the central directory, so an
    honest decompression bomb is refused before a byte is decompressed. They
    are claims, not facts: every member is decompressed by `_read_member`,
    which stops at a ceiling counted in the bytes it actually produces, so a
    header that lies about its size gets no further than one that does not.
    (zipfile's own reader bounds its output only for DEFLATE: a bzip2 member
    declaring 100 bytes was decompressed whole, 4 GiB from a 3 KB download.)
  * `flag_bits & 0x1` marks an encrypted member, so we can say "cannot inspect"
    instead of guessing at a password
  * the entry name is visible up front, so traversal is a fact about metadata
    rather than something discovered while writing files out

Only zip is supported. RAR and 7z need third-party packages, and zip is what
browsers and mail clients actually produce.
"""

from __future__ import annotations

import bz2
import io
import logging
import lzma
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

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


class _MemberError(Exception):
    """A member that could not be read; the message says why."""


def _decompress(method: int, raw: bytes, limit: int) -> tuple[bytes, bool]:
    """Up to `limit` + 1 bytes from `raw`, and whether its stream ended
    inside `raw`. The ceiling is on the output: nothing a header says is
    consulted."""
    if method == zipfile.ZIP_STORED:
        return raw[:limit + 1], True
    if method == zipfile.ZIP_DEFLATED:
        decompressor = zlib.decompressobj(-15)
        return decompressor.decompress(raw, limit + 1), decompressor.eof
    if method == zipfile.ZIP_BZIP2:
        decompressor = bz2.BZ2Decompressor()
        return decompressor.decompress(raw, max_length=limit + 1), decompressor.eof
    if method == zipfile.ZIP_LZMA:
        if len(raw) < 4:
            raise _MemberError("truncated LZMA header")
        size = struct.unpack("<H", raw[2:4])[0]
        filters = [lzma._decode_filter_properties(lzma.FILTER_LZMA1, raw[4:4 + size])]  # as zipfile does
        decompressor = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
        return decompressor.decompress(raw[4 + size:], max_length=limit + 1), decompressor.eof
    raise _MemberError(f"compression method {method} is not supported")


def _sizes_disagree(produced: int, whole: bool, declared: int) -> str:
    """Why a member's output and its header disagree, or "". Larger is
    always a lie; smaller only once the stream ended (a member cut short
    by our own limit is not)."""
    if produced > declared:
        return "larger than its header claims"
    if whole and produced < declared:
        return "smaller than its header claims"
    return ""


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> tuple[bytes, str]:
    """Up to `limit` bytes of a member, decompressed here with a ceiling on
    the output, and how its size disagrees with its header ("" when not).

    The compressed bytes are read from the member's local header in the
    archive itself, capped, and handed to a decompressor that is asked for
    at most `limit` + 1 bytes: what the central directory claims decides
    nothing about how much is decompressed, in either direction. A member
    declaring more than the limit is read to the limit, not skipped: a
    45-byte member claiming 33 MB hid the marker unzip extracted.
    """
    if info.flag_bits & 0x1:
        # zipfile.open refused these; reading the bytes directly must too.
        raise _MemberError("encrypted")
    fp = archive.fp
    if fp is None:
        raise _MemberError("archive closed")
    fp.seek(info.header_offset)
    header = fp.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise _MemberError("no local header")
    name_length, extra_length = struct.unpack("<HH", header[26:30])
    fp.seek(info.header_offset + 30 + name_length + extra_length)
    raw = fp.read(min(info.compress_size, limit + 1024 * 1024))
    data, whole = _decompress(info.compress_type, raw, limit)
    if info.compress_type == zipfile.ZIP_STORED:
        whole = len(raw) == info.compress_size
    disagree = _sizes_disagree(len(data), whole, info.file_size)
    if not disagree and whole and len(data) == info.file_size and zlib.crc32(data) != info.CRC:
        raise _MemberError("CRC mismatch")
    return data[:limit], disagree


def _local_members(fp, limit_of) -> Iterator[tuple[str, int, int, bytes | None, str]]:
    """The members as their local headers give them, front to back:
    (name, declared size, compressed size, bytes or None, why not / why odd).

    What unzip reads. Used when zipfile refuses the archive: a central
    directory naming one entry it will not parse (a name flagged UTF-8 that
    is not, a "version needed" of 25.5) left every member unread and the
    archive CLEAN, while unzip extracted the marker from it. `limit_of()`
    is the byte ceiling for the next member (the budget left).
    """
    position = 0
    for _ in range(MAX_MEMBERS):
        fp.seek(position)
        header = fp.read(30)
        if len(header) < 30 or header[:4] != b"PK\x03\x04":
            return
        (flags, method, _time, _date, _crc, compressed, size,
         name_length, extra_length) = struct.unpack("<HHHHIIIHH", header[6:30])
        raw_name = fp.read(name_length)
        fp.read(extra_length)
        name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", errors="replace")
        start = position + 30 + name_length + extra_length
        if flags & 0x8 or compressed == 0xFFFFFFFF:
            # Sizes after the data, or in a zip64 field: where the next
            # header starts is not known from here. Read this one, stop.
            compressed = -1
        limit = limit_of()
        if flags & 0x1:
            yield name, size, max(compressed, 0), None, "encrypted, cannot be inspected"
        elif limit <= 0:
            yield name, size, max(compressed, 0), None, "archive exceeded its total inspection budget"
        else:
            fp.seek(start)
            raw = fp.read(limit + 1024 * 1024 if compressed < 0 else min(compressed, limit + 1024 * 1024))
            try:
                data, whole = _decompress(method, raw, limit)
            except _MemberError as exc:
                yield name, size, max(compressed, 0), None, f"unreadable ({exc})"
            except Exception as exc:
                yield name, size, max(compressed, 0), None, f"unreadable ({type(exc).__name__})"
            else:
                if method == zipfile.ZIP_STORED and compressed >= 0:
                    whole = len(raw) == compressed
                odd = "" if compressed < 0 else _sizes_disagree(len(data), whole, size)
                yield name, size, max(compressed, 0), data[:limit], odd
        if compressed < 0:
            return
        position = start + compressed


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
        handle = open(path, "rb")
    except OSError as exc:
        report.notes.append(f"could not be opened ({exc})")
        return report
    with handle:
        _inspect_into(report, handle, budget, nested="")
    return report


def _inspect_into(report: ArchiveReport, fp, budget: list[int], nested: str) -> None:
    """The members of the zip in `fp`, into `report`. One reader for the
    file and for an archive inside it: the second was a copy that kept
    fewer checks, and its problems were never read by anyone."""
    where = f" inside {nested}" if nested else ""
    try:
        archive = zipfile.ZipFile(fp)
        infos = archive.infolist()
    except zipfile.BadZipFile as exc:
        # No readable central directory: a truncated download, usually.
        # Recorded, not accused; what the local headers hold is still read.
        report.notes.append(f"could not be read as an archive{where} ({exc}); "
                            "members were read from their local headers")
        _inspect_local(report, fp, budget, where)
        return
    except Exception as exc:
        # A directory zipfile refuses to parse (UnicodeDecodeError for a
        # name flagged UTF-8 that is not, NotImplementedError for a version
        # it does not know) while unzip extracts the members: built that way.
        report.problems.append(f"its directory holds an entry this reader refuses{where} "
                               f"({type(exc).__name__}); the members were read from their local headers")
        _inspect_local(report, fp, budget, where)
        return

    with archive:
        if len(infos) > MAX_MEMBERS:
            report.truncated = True
            report.notes.append(
                f"holds {len(infos)} entries{where}; only the first {MAX_MEMBERS} were examined")
            infos = infos[:MAX_MEMBERS]

        for info in infos:
            if info.is_dir():
                continue
            member = ArchiveMember(name=info.filename, size=info.file_size, compressed=info.compress_size)
            report.members.append(member)

            if _entry_is_traversal(info.filename):
                report.problems.append(f"entry name escapes the archive{where}: {info.filename!r}")

            if info.flag_bits & 0x1:
                member.skipped = "encrypted, cannot be inspected"
                continue

            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_COMPRESSION_RATIO and info.file_size > 1024 * 1024:
                # Said, and still read to the ceiling: the read is bounded by
                # what it produces, so refusing it protected nothing, and a
                # 45-byte member claiming 33 MB hid what unzip extracted.
                report.problems.append(
                    f"{info.filename!r}{where} expands {ratio:.0f}x ({info.compress_size:,} -> "
                    f"{info.file_size:,} bytes)")

            if budget[0] <= 0:
                member.skipped = "archive exceeded its total inspection budget"
                report.truncated = True
                continue

            limit = min(MAX_MEMBER_BYTES, budget[0])
            try:
                data, disagree = _read_member(archive, info, limit)
            except Exception as exc:
                member.skipped = f"unreadable ({exc if isinstance(exc, _MemberError) else type(exc).__name__})"
                continue
            if disagree:
                report.problems.append(
                    f"{info.filename!r}{where} is {disagree} ({info.file_size:,} bytes declared)")
            if info.file_size > limit and not disagree:
                report.notes.append(f"{info.filename}{where}: only the first {limit // (1024 * 1024)} MB inspected")
            budget[0] -= len(data)          # what was produced, not what was claimed
            member.data = data


def _inspect_local(report: ArchiveReport, fp, budget: list[int], where: str) -> None:
    for name, size, compressed, data, why in _local_members(fp, lambda: min(MAX_MEMBER_BYTES, budget[0])):
        member = ArchiveMember(name=name, size=size, compressed=compressed, data=data)
        report.members.append(member)
        if _entry_is_traversal(name):
            report.problems.append(f"entry name escapes the archive{where}: {name!r}")
        if data is None:
            member.skipped = why
            continue
        if why:
            report.problems.append(f"{name!r}{where} is {why} ({size:,} bytes declared)")
        budget[0] -= len(data)


def iter_nested(
    report: ArchiveReport,
    depth: int = 0,
) -> Iterator[tuple[str, bytes]]:
    """Yield (display name, bytes) for every inspectable member, recursively.

    Genuinely recursive now. The previous version took a `depth` argument its
    only caller never passed and hand-unrolled exactly one level of nesting,
    while MAX_DEPTH said 2 and this docstring said "up to MAX_DEPTH". Measured:
    a marker two archives deep was missed. A limit that overstates what the
    code does is worse than a smaller limit stated honestly, because it is the
    kind of thing you only find out when it matters.

    `budget` bounds the total work regardless of shape, so a zip quine cannot
    turn a bounded depth into unbounded effort. Problems found in an archive
    inside this one are added to `report.problems` as the walk finds them,
    so read them once the walk is done: one zip deeper, a lying header, a
    bomb and a traversal name were all found and thrown away.
    """
    yield from _walk(report, report, depth, [MAX_TOTAL_BYTES])


def _walk(
    report: ArchiveReport,
    top: ArchiveReport,
    depth: int,
    budget: list[int],
) -> Iterator[tuple[str, bytes]]:
    for member in report.members:
        if member.data is None:
            continue

        yield f"{report.path.name}!{member.name}", member.data

        if depth >= MAX_DEPTH:
            continue
        if not member.data.startswith(b"PK"):
            continue
        if budget[0] <= 0:
            continue

        nested = _inspect_bytes(member.data, Path(f"{report.path.name}!{member.name}"), budget)
        top.problems.extend(nested.problems)
        top.notes.extend(nested.notes)
        top.truncated = top.truncated or nested.truncated
        for name, payload in _walk(nested, top, depth + 1, budget):
            yield name, payload


def _inspect_bytes(data: bytes, display: Path, budget: list[int]) -> ArchiveReport:
    """inspect(), for an archive already held in memory, with the same checks."""
    report = ArchiveReport(path=display)
    _inspect_into(report, io.BytesIO(data), budget, nested=display.name)
    return report
