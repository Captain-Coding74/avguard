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
import shutil
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config
from .protection import SelfProtection

log = logging.getLogger(__name__)

MASK_BLOCK = 32  # SHA-256 digest size


class QuarantineError(RuntimeError):
    """Raised when a quarantine or restore cannot be completed safely."""


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
    stream = _keystream(nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


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
    ) -> None:
        self.directory = Path(directory)
        self.index_path = Path(index_path)
        self.protection = protection
        self._lock = threading.RLock()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, QuarantineRecord] = {}
        self._deleted: set[str] = set()
        self._load()

    # --------------------------------------------------------------- index

    def _load(self) -> None:
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._records = {}
            return
        records: dict[str, QuarantineRecord] = {}
        for entry_id, data in (raw or {}).items():
            try:
                records[entry_id] = QuarantineRecord(**data)
            except TypeError:
                log.warning("dropping malformed quarantine record %s", entry_id)
        self._records = records
        self._reconcile()

    def _reconcile(self) -> None:
        """Finish or undo any move that was interrupted last time.

        A pending record means the payload was written but we cannot be sure
        the original was removed. If the original is still there, the move
        never completed: drop our copy and leave the user's file alone. If it
        is gone, the move did complete and only the flag was never cleared.
        """
        for entry_id, record in list(self._records.items()):
            if not record.pending:
                continue
            try:
                original_still_there = Path(record.original_path).exists()
            except OSError:
                original_still_there = False

            if original_still_there:
                log.warning("undoing an interrupted quarantine of %s; your file was "
                            "never removed", record.original_path)
                self._payload_path(entry_id).unlink(missing_ok=True)
                del self._records[entry_id]
            else:
                log.info("completing an interrupted quarantine of %s", record.original_name)
                record.pending = False
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
        on_disk: dict[str, QuarantineRecord] = {}
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        for entry_id, data in (raw or {}).items():
            try:
                on_disk[entry_id] = QuarantineRecord(**data)
            except TypeError:
                log.warning("dropping malformed quarantine record %s", entry_id)

        # Anything on disk we have not seen is another process's work: keep it.
        for entry_id, record in on_disk.items():
            self._records.setdefault(entry_id, record)

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
            config.atomic_write_text(self.index_path, json.dumps(payload, indent=2))
        except OSError as exc:
            raise QuarantineError(f"could not write the quarantine index: {exc}") from exc

    def _payload_path(self, entry_id: str) -> Path:
        # The id is a UUID4 hex string, so this name can never contain a path
        # separator, a "..", a reserved Windows device name or a trailing dot.
        return self.directory / f"{entry_id}.quar"

    # ------------------------------------------------------------ querying

    def records(self) -> list[QuarantineRecord]:
        with self._lock:
            self._reload_and_merge()
            return sorted(self._records.values(), key=lambda r: r.quarantined_at, reverse=True)

    def get(self, entry_id: str) -> QuarantineRecord | None:
        with self._lock:
            return self._records.get(entry_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ---------------------------------------------------------- quarantine

    def quarantine(self, path: Path | str, reasons: list[str] | None = None) -> QuarantineRecord:
        """Move `path` into the store, masked, and record how to undo it."""
        source = Path(path).resolve()

        if self.protection is not None and self.protection.is_protected(source):
            raise QuarantineError(f"refusing to quarantine a protected path: {source}")
        if not source.is_file():
            raise QuarantineError(f"not a file: {source}")

        with self._lock:
            self._reload_and_merge()
            data = source.read_bytes()
            digest = hashlib.sha256(data).hexdigest()

            entry_id = uuid.uuid4().hex
            nonce = os.urandom(16)
            payload = self._payload_path(entry_id)

            # Write the masked copy first and only unlink the original once it
            # is safely on disk, so a crash cannot lose the file entirely.
            tmp = payload.with_suffix(".quar.tmp")
            try:
                tmp.write_bytes(_mask(data, nonce))
                os.replace(tmp, payload)
            except OSError as exc:
                tmp.unlink(missing_ok=True)
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

            try:
                source.unlink()
            except OSError as exc:
                del self._records[entry_id]
                payload.unlink(missing_ok=True)
                try:
                    self._save()
                except QuarantineError:
                    pass
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

        try:
            resolved = Path(destination).resolve()
        except (OSError, ValueError) as exc:
            raise QuarantineError(f"unusable destination path: {exc}") from exc

        if not resolved.is_absolute():
            raise QuarantineError("refusing to restore to a relative path")

        try:
            if resolved.is_relative_to(self.directory.resolve()):
                raise QuarantineError("refusing to restore into the quarantine directory")
        except ValueError:
            pass

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
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_name(target.name + ".restoring")
                tmp.write_bytes(data)
                os.replace(tmp, target)
            except OSError as exc:
                raise QuarantineError(f"could not write {target}: {exc}") from exc

            payload.unlink(missing_ok=True)
            del self._records[entry_id]
            self._deleted.add(entry_id)
            self._save()

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
        log.info("deleted quarantined file %s", record.original_name)
        return record.original_name

    def export_all(self, destination: Path | str) -> list[Path]:
        """Write every held file out, unmasked, into one folder.

        The store holds the only copy of everything in it. Without this,
        uninstalling AVGuard -- or deleting a folder the README describes with
        the word "cache" -- destroys the lot with no way to get it back. A
        quarantine has to have an exit door.
        """
        target = Path(destination)
        target.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for record in self.records():
            # The stored name is a UUID, so rebuild a safe filename from the
            # original basename rather than trusting it wholesale.
            safe = "".join(c for c in record.original_name
                           if c.isalnum() or c in "._- ") or "recovered"
            out = target / f"{record.entry_id[:8]}_{safe}"
            try:
                written.append(self.export(record.entry_id, out))
            except (QuarantineError, OSError) as exc:
                log.error("could not export %s: %s", record.original_name, exc)
        return written

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

    def export(self, entry_id: str, destination: Path | str) -> Path:
        """Write the original bytes out for analysis, without touching the record.

        Kept separate from restore so pulling a sample out for inspection is a
        deliberate, differently named action.
        """
        with self._lock:
            record = self._records.get(entry_id)
            if record is None:
                raise QuarantineError(f"no quarantine record with id {entry_id}")
            payload = self._payload_path(entry_id)
            data = _mask(payload.read_bytes(), bytes.fromhex(record.nonce))
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target
