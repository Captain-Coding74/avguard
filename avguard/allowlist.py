"""Files the user has explicitly said are fine.

Restoring something from quarantine used to teach the scanner nothing. With
automatic quarantine on, the restored file was detected again and taken away
within about a second, and the only escape was excluding its entire folder.
That is not a disagreement the user can win.

So a restore is recorded as a decision, keyed on the SHA-256 of the exact bytes
that were restored. It is deliberately narrow:

  * one exact file, not a name, not a folder, not a publisher
  * editing the file changes its hash, so the decision expires by itself
  * the entry says when it was added and what it was flagged for, so a list of
    them is reviewable rather than a pile of opaque hashes

It does override a detection, including a byte-signature match, because the
user looked at this exact file and said keep it. That is the strongest signal
about intent this program can receive, and a scanner that overrules it is one
people learn to switch off. The reason is always shown in the verdict, so an
allowed file never looks merely clean.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config

log = logging.getLogger(__name__)

ALLOWLIST_PATH = config.DATA_DIR / "allowlist.json"


@dataclass
class AllowEntry:
    sha256: str
    name: str = ""
    added_at: str = ""
    was_flagged_for: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.added_at:
            self.added_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    @property
    def when(self) -> str:
        return self.added_at[:19].replace("T", " ")


class Allowlist:
    """Hashes the user has decided to keep."""

    def __init__(self, path: Path = ALLOWLIST_PATH) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._entries: dict[str, AllowEntry] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._entries = {}
            return
        entries: dict[str, AllowEntry] = {}
        for digest, data in (raw or {}).items():
            try:
                entries[digest] = AllowEntry(**data)
            except TypeError:
                log.warning("dropping a malformed allowlist entry for %s", digest[:12])
        self._entries = entries

    def _save(self) -> None:
        payload = {k: asdict(v) for k, v in self._entries.items()}
        try:
            config.atomic_write_text(self.path, json.dumps(payload, indent=2))
        except OSError as exc:
            log.warning("could not save the allowlist: %s", exc)

    def reload(self) -> None:
        """Pick up decisions another AVGuard process recorded."""
        with self._lock:
            self._load()

    def allows(self, sha256: str) -> AllowEntry | None:
        with self._lock:
            return self._entries.get(sha256)

    def add(self, sha256: str, name: str = "", reasons: list[str] | None = None) -> AllowEntry:
        with self._lock:
            self._load()          # never clobber another process's decision
            entry = AllowEntry(sha256=sha256, name=name,
                               was_flagged_for=list(reasons or []))
            self._entries[sha256] = entry
            self._save()
        log.info("allowing %s from now on (%s)", name or sha256[:12], sha256[:12])
        return entry

    def remove(self, sha256: str) -> bool:
        with self._lock:
            self._load()
            if sha256 not in self._entries:
                return False
            del self._entries[sha256]
            self._save()
        log.info("no longer allowing %s", sha256[:12])
        return True

    def entries(self) -> list[AllowEntry]:
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: e.added_at, reverse=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
