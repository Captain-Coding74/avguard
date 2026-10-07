"""A quarantine store that neutralises what it holds.

Three things the original store got wrong:

1. It wrote the file to `quarantine/<name>_<timestamp>` but looked it up again
   at `quarantine/<name>`, so restore and delete could never find anything.
2. It kept the original bytes and the original extension, so a live sample sat
   executable in a subfolder of the user's project.
3. It read `original_path` straight out of a JSON file that lives inside the
   quarantine directory and passed it to shutil.move with no validation.

Here every entry gets a random id for its on-disk name, so an untrusted
filename never reaches the filesystem; the payload is XOR-masked with a
per-file keystream so it is not directly executable and will not trip other
scanners; and restore validates the destination and verifies the hash.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config, provenance
from .allowlist import Allowlist
from .protection import SelfProtection, path_within

log = logging.getLogger(__name__)

MASK_BLOCK = 32  # SHA-256 digest size


class RestoreIncomplete(RuntimeError):
    """The file is back and its record consumed, but the decision to keep it
    could not be recorded. Not a QuarantineError: callers treated that as a
    failed restore and told the user so, with exit code 1 and a message that
    contradicted itself."""

    def __init__(self, target: Path, reason: str) -> None:
        super().__init__(f"restored to {target}, but the decision to keep it was not "
                         f"recorded ({reason}); it may be flagged again")
        self.target = target


class QuarantineError(RuntimeError):
    """Raised when a quarantine or restore cannot be completed safely."""


@dataclass
class ExportReport:
    """What export_all wrote, and what it could not, with the reason."""
    written: list[Path] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)     # (original name, reason)


def _export_name(record: "QuarantineRecord") -> str:
    """A safe file name for an exported copy: the id's first eight
    characters, then the original basename reduced to letters, digits and
    "._- ", cut to fit 255 bytes with its extension kept. The name went in
    whole before, and a held file whose name was near the limit could not be
    exported at all."""
    prefix = f"{record.entry_id[:8]}_"
    safe = "".join(c for c in record.original_name if c.isalnum() or c in "._- ").strip(" .") or "recovered"
    stem, dot, extension = safe.rpartition(".")
    if not dot or not stem or len(extension) > 16:
        stem, extension = safe, ""
    else:
        extension = "." + extension
    while stem and len((prefix + stem + extension).encode("utf-8")) > 255:
        stem = stem[:-1]
    return prefix + (stem or "recovered") + extension


def _holds(path: Path, sha256: str) -> bool:
    """Whether `path` is a regular file whose bytes hash to `sha256`."""
    try:
        if not path.is_file():
            return False
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(config.CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest() == sha256
    except OSError:
        return False


def _keystream(nonce: bytes, length: int) -> bytes:
    """Deterministic mask bytes derived from a per-file nonce.

    This is obfuscation, not encryption: the point is that the stored file
    cannot be run by a double-click and does not look like the original to
    another scanner. It is reversible by design so restore works.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(nonce + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:length])


def _mask(data: bytes, nonce: bytes) -> bytes:
    """XOR with the keystream, as one integer: the same bytes as a byte-wise
    loop, which took 0.63 s for 8 MB, most of the time between reading a
    file and removing it."""
    if not data:
        return b""
    stream = _keystream(nonce, len(data))
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


def _identity(stat: os.stat_result) -> tuple:
    """Which file a path names, and whether it was written: a save by
    rename gives a new file id, a write in place a new size or time."""
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


class _Changed(Exception):
    """The path no longer names the file that was read."""


@dataclass
class QuarantineRecord:
    entry_id: str
    original_path: str
    original_name: str
    quarantined_at: str
    size: int
    sha256: str
    nonce: str
    reasons: list[str] = field(default_factory=list)

    # True between "payload written" and "original removed". The nonce that
    # decodes the payload lives only in this record, so it has to reach disk
    # before the original is destroyed -- otherwise an index write that fails
    # at the wrong moment takes the user's file with it.
    pending: bool = False

    @property
    def display(self) -> str:
        when = self.quarantined_at[:19].replace("T", " ")
        return f"{self.original_name}  -  {when}"


class QuarantineStore:
    """Holds detected files and can put them back."""

    def __init__(
        self,
        directory: Path = config.QUARANTINE_DIR,
        index_path: Path = config.QUARANTINE_INDEX,
        protection: SelfProtection | None = None,
        allowlist: Allowlist | None = None,
    ) -> None:
        self.allowlist = allowlist if allowlist is not None else Allowlist()
        self.directory = Path(directory)
        self.index_path = Path(index_path)
        self.protection = protection
        self._lock = threading.RLock()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, QuarantineRecord] = {}
        self._deleted: set[str] = set()
        # The ids the index held when this process last read or wrote it: an
        # id that was there and is gone now was removed by another process,
        # and must not be written back from memory.
        self._seen_on_disk: set[str] = set()
        # Why the index could not be read, for Health; "" when it could.
        self.index_problem = ""
        self._load()

    # --------------------------------------------------------------- index

    def _read_index(self) -> tuple[dict[str, QuarantineRecord], bool]:
        """The records on disk, and whether the index could be understood.
        An unreadable index is reported (index_problem) and read as no
        records, and _save sets it aside before writing: the nonces in it
        exist nowhere else. A read that fails for another reason (a locked
        file) raises OSError."""
        try:
            raw = config.read_json_object(self.index_path) or {}
        except config.UnreadableJSON as exc:
            if not self.index_problem:
                log.error("the quarantine index cannot be read: %s", exc)
            self.index_problem = f"the quarantine index cannot be read ({exc})"
            return {}, False
        records: dict[str, QuarantineRecord] = {}
        for entry_id, data in raw.items():
            try:
                if not isinstance(data, dict):
                    raise TypeError("not an object")
                records[entry_id] = QuarantineRecord(**data)
            except TypeError:
                log.warning("dropping malformed quarantine record %s", entry_id)
        return records, True

    def _load(self) -> None:
        # Construction never reconciles and never writes: read-only commands,
        # a right-click scan and a second window all build a store, and none
        # of them holds the lock (see reconcile()).
        try:
            self._records, readable = self._read_index()
        except OSError as exc:
            log.error("could not read the quarantine index: %s", exc)
            self._records, readable = {}, False
        self._seen_on_disk = set(self._records) if readable else set()

    def reconcile(self) -> None:
        """Finish or undo a move a killed process left half done. Only the
        holder of the instance lock may call this.

        A pending record means the payload was written and the original may
        or may not have been removed. It is also the normal state of the lock
        holder's own quarantine in progress, which is why construction no
        longer does this: a right-click scan building a store in that moment
        deleted the payload, and the holder then unlinked the original.

        If the file at the old path is the one that was taken (same digest),
        the move never completed: drop our copy and leave the user's file
        alone. Otherwise the move completed, and whatever sits at that path
        now (the same name downloaded again, a new draft) is a different file
        and is left alone too; only the flag is cleared.
        """
        with self._lock:
            try:
                self._reload_and_merge()
            except QuarantineError as exc:
                log.error("could not reconcile the quarantine index: %s", exc)
                return
            changed = False
            for entry_id, record in list(self._records.items()):
                if not record.pending:
                    continue
                changed = True
                original = Path(record.original_path)
                if _holds(original, record.sha256):
                    log.warning("undoing an interrupted quarantine of %s; your file was "
                                "never removed", record.original_path)
                    self._payload_path(entry_id).unlink(missing_ok=True)
                    del self._records[entry_id]
                    self._deleted.add(entry_id)
                else:
                    if original.exists():
                        log.warning("completing an interrupted quarantine of %s; a different file "
                                    "now at that path was left alone", record.original_name)
                    else:
                        log.info("completing an interrupted quarantine of %s", record.original_name)
                    record.pending = False
            if not changed:
                return
            try:
                self._save()
            except QuarantineError as exc:
                log.error("could not write the reconciled index: %s", exc)

    def orphaned_payloads(self) -> list[Path]:
        """Stored payloads with no record, which nothing can decode.

        Reported rather than deleted. They are unreadable without their nonce,
        but they are also the last trace that something was taken, and a
        program that silently removes evidence of its own failure is worse
        than one that leaves a puzzle.
        """
        known = {f"{entry_id}.quar" for entry_id in self._records}
        return [p for p in self.directory.glob("*.quar") if p.name not in known]

    def _reload_and_merge(self) -> None:
        """Re-read the index from disk, keeping anything we do not know about.

        Every mutation calls this first. Without it, two processes each hold a
        snapshot taken at construction and the second to write erases the
        other's records -- deleting the user's originals and orphaning the
        stored payloads. `InstanceLock` normally prevents the race; this makes
        losing it survivable.
        """
        try:
            on_disk, readable = self._read_index()
        except OSError as exc:
            # Treating this as an empty index meant the save that follows
            # wrote this process's snapshot over everyone else's records.
            raise QuarantineError(f"could not read the quarantine index: {exc}") from exc

        # Anything on disk we have not seen is another process's work: keep it.
        for entry_id, record in on_disk.items():
            self._records.setdefault(entry_id, record)

        # Anything that was on disk at our last read and is gone now, another
        # process restored or deleted: writing it back from memory listed a
        # held file whose payload no longer existed. (Not when the index
        # could not be read: then memory is the best copy there is.)
        if readable:
            for entry_id in list(self._records):
                if entry_id in self._seen_on_disk and entry_id not in on_disk:
                    del self._records[entry_id]
            self._seen_on_disk = set(on_disk)

        # Anything we deleted this session stays deleted; `_deleted` records
        # that so a merge cannot resurrect it.
        for entry_id in self._deleted:
            self._records.pop(entry_id, None)

    def _save(self) -> None:
        """Persist the index, turning any I/O failure into a QuarantineError.

        This used to raise a bare OSError. Every caller catches only
        QuarantineError, so a full disk escaped gui._handle_threat entirely and
        was swallowed by the UI pump's generic handler -- no banner, no event,
        no notification, and the user's file already gone.
        """
        payload = {k: asdict(v) for k, v in self._records.items()}
        try:
            aside = config.set_aside_if_unreadable(self.index_path)
            config.atomic_write_text(self.index_path, json.dumps(payload, indent=2))
        except OSError as exc:
            raise QuarantineError(f"could not write the quarantine index: {exc}") from exc
        if aside is not None:
            self.index_problem = (f"the quarantine index could not be read and was kept as {aside.name}; "
                                  "files held before then are not listed")
        self._seen_on_disk = set(self._records)

    def _payload_path(self, entry_id: str) -> Path:
        # The id is a UUID4 hex string, so this name can never contain a path
        # separator, a "..", a reserved Windows device name or a trailing dot.
        return self.directory / f"{entry_id}.quar"

    # ------------------------------------------------------------ querying

    def records(self) -> list[QuarantineRecord]:
        with self._lock:
            self._reload_and_merge()
            return sorted(self._records.values(), key=lambda r: r.quarantined_at, reverse=True)

    # ------------------------------------------------------------ evidence

    @property
    def evidence_path(self) -> Path:
        return self.index_path.with_name(self.index_path.stem + "_evidence.json")

    def _read_evidence(self) -> dict:
        try:
            return config.read_json_object(self.evidence_path) or {}
        except config.UnreadableJSON as exc:
            log.error("the kept evidence could not be read (%s); it is set aside before the next write", exc)
            return {}
        except OSError:
            return {}

    def _write_evidence(self, kept: dict) -> None:
        # Read strictly, and set aside before a write: a byte-order mark read
        # as {} and the next quarantine wrote over every held file's findings
        # and its download mark.
        config.set_aside_if_unreadable(self.evidence_path)
        config.atomic_write_text(self.evidence_path, json.dumps(kept))

    def _keep_evidence(self, entry_id: str, evidence) -> None:
        """Best effort and never raises: the account of a verdict is worth
        keeping, the file it belongs to is worth more, and by the time this
        runs the file is safely in the store."""
        if evidence is None:
            return
        try:
            kept = self._read_evidence()
            kept[entry_id] = evidence
            # Rows for entries that no longer exist go with them.
            kept = {k: v for k, v in kept.items() if k in self._records}
            self._write_evidence(kept)
        except (OSError, TypeError, ValueError) as exc:
            log.warning("could not keep the evidence for %s: %s", entry_id, exc)

    def _forget_evidence(self, entry_id: str) -> None:
        """A restored or deleted file takes its evidence row with it."""
        kept = self._read_evidence()
        if entry_id not in kept:
            return
        del kept[entry_id]
        try:
            self._write_evidence(kept)
        except OSError as exc:
            log.warning("could not drop the evidence for %s: %s", entry_id, exc)

    def evidence(self, entry_id: str):
        """What was kept behind a held file (the dict evidence_detail()
        produced, or a bare list of findings), or None when nothing was: a
        record from before evidence was kept, or a failed write."""
        found = self._read_evidence().get(entry_id)
        return found if isinstance(found, (dict, list)) else None

    def get(self, entry_id: str) -> QuarantineRecord | None:
        with self._lock:
            return self._records.get(entry_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ---------------------------------------------------------- quarantine

    def quarantine(self, path: Path | str, reasons: list[str] | None = None,
                   evidence: dict | None = None, expected_sha256: str | None = None) -> QuarantineRecord:
        """Move `path` into the store, masked, and record how to undo it.

        `evidence` is what explain.evidence_detail() produced for the verdict
        (its findings, the threshold it was decided with, its digest); it is
        kept in a sidecar beside the index, never on the record, because an
        older AVGuard reading an index row with a field it does not know
        drops that row (see _reload_and_merge) and would then save the index
        without it.

        `expected_sha256` is the digest the verdict was reached on. A file
        that no longer has it changed after it was judged (a long scan, a
        save in between), and is not moved on a verdict about other bytes.
        """
        source = Path(path).resolve()

        if self.protection is not None and self.protection.is_protected(source):
            raise QuarantineError(f"refusing to quarantine a protected path: {source}")
        if not source.is_file():
            raise QuarantineError(f"not a file: {source}")

        with self._lock:
            self._reload_and_merge()
            try:
                read_as = _identity(os.stat(source))
                data = source.read_bytes()
            except OSError as exc:
                raise QuarantineError(f"could not read {source}: {exc}") from exc
            digest = hashlib.sha256(data).hexdigest()
            if expected_sha256 and digest != expected_sha256:
                raise QuarantineError(f"{source.name} changed after it was scanned; it was not moved")

            entry_id = uuid.uuid4().hex
            nonce = os.urandom(16)
            payload = self._payload_path(entry_id)

            # Write the masked copy first and only unlink the original once it
            # is safely on disk, so a crash cannot lose the file entirely.
            # "On disk" means flushed: the rename and the unlink are journalled,
            # the data is not, and a power cut could leave zeros.
            try:
                config.atomic_write_bytes(payload, _mask(data, nonce))
            except OSError as exc:
                raise QuarantineError(f"could not write quarantine payload: {exc}") from exc

            record = QuarantineRecord(
                entry_id=entry_id,
                original_path=str(source),
                original_name=source.name,
                quarantined_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                size=len(data),
                sha256=digest,
                nonce=nonce.hex(),
                reasons=list(reasons or []),
                pending=True,
            )
            self._records[entry_id] = record

            # The record reaches disk BEFORE the original is destroyed. The
            # nonce that decodes the payload exists nowhere else, so unlinking
            # first meant a failed index write -- a full disk, a locked file, a
            # process kill -- destroyed the user's file and left a payload
            # nothing could ever decode. Reproduced, then fixed by reordering.
            try:
                self._save()
            except QuarantineError:
                del self._records[entry_id]
                payload.unlink(missing_ok=True)
                raise

            # The download mark is a stream of the file and goes with it when
            # the file is unlinked; read first, kept with the evidence, so a
            # restore can put it back.
            zone = provenance.read_zone(source)
            try:
                # The file read seconds ago, or nothing: an editor's save by
                # rename, or a download over the name, landing between the
                # read and here was unlinked, and only the old bytes were
                # held. What remains is the moment between this stat and the
                # unlink.
                if _identity(os.stat(source)) != read_as:
                    raise _Changed()
                source.unlink()
            except (OSError, _Changed) as exc:
                del self._records[entry_id]
                payload.unlink(missing_ok=True)
                try:
                    self._save()
                except QuarantineError:
                    pass
                if isinstance(exc, _Changed):
                    raise QuarantineError(f"{source.name} changed while it was being moved; it was not moved") from None
                raise QuarantineError(f"could not remove original {source}: {exc}") from exc

            # The move is complete. If clearing the flag fails, the next start
            # reconciles it: the original is gone, so the record is honoured.
            record.pending = False
            try:
                self._save()
            except QuarantineError as exc:
                log.warning("quarantine of %s completed but the index was not updated: %s",
                            source.name, exc)

        log.warning("quarantined %s (%s)", source, "; ".join(record.reasons) or "no reason given")
        if zone is not None and zone.marked:
            # Never raises: the file is in the store by now. A bare list of
            # findings, a form evidence() documents, is wrapped first.
            try:
                evidence = ({"findings": list(evidence)} if isinstance(evidence, list)
                            else dict(evidence or {}))
                evidence["zone"] = zone.zone_id
            except (TypeError, ValueError) as exc:
                log.warning("could not keep the download mark for %s: %s", entry_id, exc)
        self._keep_evidence(entry_id, evidence)
        return record

    # ------------------------------------------------------------- restore

    def _validate_destination(self, destination: Path) -> Path:
        """Refuse any destination that would let the index write where it likes.

        The index sits inside the quarantine directory, next to content that
        came from somewhere untrusted. Treat every path in it as attacker
        controlled.
        """
        raw = str(destination)

        if raw.startswith("\\\\") or raw.startswith("//"):
            raise QuarantineError("refusing to restore to a UNC network path")

        # Before resolve(), which makes every path absolute against the
        # working directory: checked after it, this never fired.
        if not Path(destination).is_absolute():
            raise QuarantineError("refusing to restore to a relative path")

        try:
            resolved = Path(destination).resolve()
        except (OSError, ValueError) as exc:
            raise QuarantineError(f"unusable destination path: {exc}") from exc

        # path_within, not is_relative_to: the destination does not exist yet
        # while the quarantine directory does, and on Windows `resolve()`
        # follows AppData redirection only for paths that already exist. The
        # two sides were being compared in different spellings, so whether this
        # guard fired at all depended on which files happened to be there.
        if path_within(resolved, self.directory):
            raise QuarantineError("refusing to restore into the quarantine directory")

        if self.protection is not None and self.protection.is_protected(resolved):
            raise QuarantineError("refusing to restore over a protected AVGuard path")

        if resolved.exists():
            raise QuarantineError(f"a file already exists at {resolved}")

        return resolved

    def restore(self, entry_id: str, destination: Path | str | None = None) -> Path:
        """Put a quarantined file back, verifying it is byte-for-byte what we took."""
        with self._lock:
            self._reload_and_merge()
            record = self._records.get(entry_id)
            if record is None:
                raise QuarantineError(f"no quarantine record with id {entry_id}")

            payload = self._payload_path(entry_id)
            if not payload.is_file():
                del self._records[entry_id]
                self._deleted.add(entry_id)
                self._save()
                raise QuarantineError(
                    f"quarantined payload for '{record.original_name}' is missing; record removed"
                )

            target = self._validate_destination(destination or record.original_path)

            data = _mask(payload.read_bytes(), bytes.fromhex(record.nonce))
            if hashlib.sha256(data).hexdigest() != record.sha256:
                raise QuarantineError(
                    f"integrity check failed for '{record.original_name}'; "
                    "the quarantined copy has been altered and will not be restored"
                )

            try:
                # Flushed before the payload goes: until then the payload is
                # the only durable copy. Written through a short temporary
                # name; the file's own name plus ".restoring" was over the
                # 255-character limit for a name near it. Never over a file
                # saved under that name since _validate_destination looked.
                config.atomic_write_bytes(target, data, replace=False)
            except FileExistsError:
                raise QuarantineError(f"a file already exists at {target}") from None
            except OSError as exc:
                raise QuarantineError(f"could not write {target}: {exc}") from exc
            self._remark(entry_id, target)

            try:
                payload.unlink(missing_ok=True)
            except OSError as exc:
                # The file is back and verified. A payload another program
                # holds open stays behind as an orphan (Health lists those);
                # escaping here left the record listed and the decision to
                # keep the file unrecorded, so it was taken again.
                log.warning("restored %s, but its stored copy could not be removed: %s",
                            record.original_name, exc)
            del self._records[entry_id]
            self._deleted.add(entry_id)
            self._save()
            self._forget_evidence(entry_id)

        # Remember the decision, or the next scan takes it straight back.
        try:
            self.allowlist.add(record.sha256, record.original_name, record.reasons)
        except OSError as exc:
            # The file IS back. Saying so, and that the decision was not
            # recorded, beats a restore that reports success and a file that
            # is flagged again within the second.
            log.error("restored %s to %s, but %s", record.original_name, target, exc)
            raise RestoreIncomplete(target, str(exc)) from exc

        log.info("restored %s to %s", record.original_name, target)
        return target

    # -------------------------------------------------------------- delete

    def delete(self, entry_id: str) -> str:
        """Permanently remove a quarantined file."""
        with self._lock:
            self._reload_and_merge()
            record = self._records.get(entry_id)
            if record is None:
                raise QuarantineError(f"no quarantine record with id {entry_id}")
            self._payload_path(entry_id).unlink(missing_ok=True)
            del self._records[entry_id]
            self._deleted.add(entry_id)
            self._save()
            self._forget_evidence(entry_id)
        log.info("deleted quarantined file %s", record.original_name)
        return record.original_name

    def export_all(self, destination: Path | str) -> ExportReport:
        """Write every held file out, unmasked, into one folder.

        The store holds the only copy of everything in it. Without this,
        uninstalling AVGuard -- or deleting a folder the README describes with
        the word "cache" -- destroys the lot with no way to get it back. A
        quarantine has to have an exit door.
        """
        target = Path(destination)
        target.mkdir(parents=True, exist_ok=True)
        report = ExportReport()
        for record in self.records():
            # The stored name is a UUID, so rebuild a safe filename from the
            # original basename rather than trusting it wholesale.
            out = target / _export_name(record)
            try:
                report.written.append(self.export(record.entry_id, out))
            except (QuarantineError, OSError) as exc:
                log.error("could not export %s: %s", record.original_name, exc)
                report.failed.append((record.original_name, str(exc)))
        return report

    def stale(self, older_than_days: int) -> list[QuarantineRecord]:
        """Records held longer than `older_than_days`."""
        if older_than_days <= 0:
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        old: list[QuarantineRecord] = []
        for record in self.records():
            try:
                when = datetime.fromisoformat(record.quarantined_at)
            except ValueError:
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when < cutoff:
                old.append(record)
        return old

    def total_bytes(self) -> int:
        return sum(record.size for record in self.records())

    def payload(self, entry_id: str) -> bytes:
        """The original bytes, unmasked, in memory: for a digest, not for disk.

        The Quarantine tab's "known sample" reads a file this way to seed the
        similarity match. Nothing is written anywhere and the record is not
        touched. Verified against the recorded digest, as restore is: export
        wrote a damaged payload out as "the original, unmodified file".
        """
        with self._lock:
            record = self._records.get(entry_id)
            if record is None:
                raise QuarantineError(f"no quarantine record with id {entry_id}")
            try:
                data = _mask(self._payload_path(entry_id).read_bytes(), bytes.fromhex(record.nonce))
            except (OSError, ValueError) as exc:
                raise QuarantineError(f"could not read the stored copy of '{record.original_name}': {exc}") from exc
            if hashlib.sha256(data).hexdigest() != record.sha256:
                raise QuarantineError(f"integrity check failed for '{record.original_name}'; "
                                      "the stored copy has been altered")
            return data

    def export(self, entry_id: str, destination: Path | str) -> Path:
        """Write the original bytes out for analysis, without touching the record.

        Kept separate from restore so pulling a sample out for inspection is a
        deliberate, differently named action.
        """
        data = self.payload(entry_id)
        target = Path(destination)
        config.atomic_write_bytes(target, data)
        self._remark(entry_id, target)
        return target

    def _remark(self, entry_id: str, target: Path) -> None:
        """A download is still a download: the zone the file carried when it
        was taken goes back on the restored or exported copy. The zone only;
        the URL was never kept. Writing bytes drops the stream, which is why
        this exists (os.replace within a volume would have kept it)."""
        kept = self.evidence(entry_id)
        zone = kept.get("zone") if isinstance(kept, dict) else None
        if isinstance(zone, int) and zone >= provenance.MARKED_FROM:
            provenance.write_zone(target, zone)
