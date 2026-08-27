"""A durable record of what the scanner actually did.

The rotating text log is for reading; this is for querying. It answers "what
happened while I was away", "when did this file first get flagged", and "is
detection still working" -- none of which a 2,000-line GUI widget or a 4 MB
text log can answer once they have wrapped.

JSON Lines, one event per line, so the file can be appended to safely, read
back incrementally, and truncated from the front without parsing all of it.
Written under data/, which is protected, so recording an event can never
trigger a scan -- the mistake that gave v1 a 2,021-line log of itself.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from . import config

log = logging.getLogger(__name__)

EVENTS_DIR = config.DATA_DIR / "events"
EVENTS_FILE = EVENTS_DIR / "events.jsonl"

MAX_BYTES = 4 * 1024 * 1024      # rotate past this
BACKUP_COUNT = 2


@dataclass
class Event:
    kind: str                     # scan_started | scan_finished | detection |
                                  # quarantined | restored | deleted | health
    at: str = ""
    path: str = ""
    level: str = ""
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.at:
            self.at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    @property
    def when(self) -> str:
        return self.at[:19].replace("T", " ")


class EventStore:
    """Append-only history, rotated by size."""

    def __init__(self, path: Path = EVENTS_FILE) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: Event) -> None:
        """Append one event. Never raises: history must not break a scan."""
        line = json.dumps(asdict(event), ensure_ascii=False)
        try:
            with self._lock:
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except OSError as exc:
            log.warning("could not record an event: %s", exc)

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.stat().st_size < MAX_BYTES:
                return
        except OSError:
            return
        for index in range(BACKUP_COUNT - 1, 0, -1):
            older = self.path.with_suffix(f".{index}.jsonl")
            newer = self.path.with_suffix(f".{index + 1}.jsonl")
            if older.exists():
                try:
                    older.replace(newer)
                except OSError:
                    pass
        try:
            self.path.replace(self.path.with_suffix(".1.jsonl"))
        except OSError:
            pass

    def read(self, limit: int = 500, kinds: set[str] | None = None) -> list[Event]:
        """Most recent events first.

        Reads the current file only. Rotated history stays on disk for anyone
        who wants it but is not loaded into the interface.
        """
        events: list[Event] = []
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError:
            return []

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue          # a torn final line after a hard kill
            if kinds and raw.get("kind") not in kinds:
                continue
            try:
                events.append(Event(**raw))
            except TypeError:
                continue
            if len(events) >= limit:
                break
        return events

    def summary(self, limit: int = 5000) -> dict:
        """Counts for the health view."""
        counts: dict[str, int] = {}
        detections = 0
        last_scan = ""
        for event in self.read(limit=limit):
            counts[event.kind] = counts.get(event.kind, 0) + 1
            if event.kind == "detection":
                detections += 1
            if event.kind == "scan_finished" and not last_scan:
                last_scan = event.when
        return {
            "events": sum(counts.values()),
            "detections": detections,
            "quarantined": counts.get("quarantined", 0),
            "last_scan": last_scan or "never",
            "kinds": counts,
        }

    def clear(self) -> None:
        """Forget everything, including rotated history.

        The record contains file paths, which is personal data. Being able to
        erase it is part of keeping it.
        """
        with self._lock:
            for candidate in [self.path] + [
                self.path.with_suffix(f".{i}.jsonl") for i in range(1, BACKUP_COUNT + 2)
            ]:
                try:
                    candidate.unlink(missing_ok=True)
                except OSError as exc:
                    log.warning("could not delete %s: %s", candidate, exc)
