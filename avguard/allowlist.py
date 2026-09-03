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
        # Field types are checked, not trusted. `"added_at": 12345` loaded fine
        # and then crashed scan() the moment `.when` sliced it.
        if not isinstance(self.sha256, str):
            self.sha256 = str(self.sha256)
        if not isinstance(self.name, str):
            self.name = str(self.name)
        if not isinstance(self.added_at, str):
            self.added_at = ""
        if not isinstance(self.was_flagged_for, list):
            self.was_flagged_for = []
        self.was_flagged_for = [str(x) for x in self.was_flagged_for]
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
        self._stamp: tuple[int, int] | None = None
        self._load()

    def _disk_stamp(self) -> tuple[int, int] | None:
        """Size and mtime of the file as it is on disk right now."""
        try:
            st = self.path.stat()
        except OSError:
            return None
        return (st.st_size, st.st_mtime_ns)

    def _load(self) -> None:
        self._stamp = self._disk_stamp()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._entries = {}
            return
        if not isinstance(raw, dict):
            # A JSON array, number or string here raised AttributeError out of
            # Scanner.__init__ -- so out of the GUI constructor and every CLI
            # verb. Under pythonw the user saw nothing, and the cure was
            # hand-editing a file in AppData. A bad file is an empty list.
            log.warning("allowlist at %s is not a JSON object; ignoring it", self.path)
            self._entries = {}
            return
        entries: dict[str, AllowEntry] = {}
        for digest, data in raw.items():
            if not isinstance(data, dict):
                log.warning("dropping a malformed allowlist entry for %s", str(digest)[:12])
                continue
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
        self._stamp = self._disk_stamp()

    def reload(self) -> None:
        """Pick up decisions another AVGuard process recorded."""
        with self._lock:
            self._load()

    def allows(self, sha256: str) -> AllowEntry | None:
        with self._lock:
            # Another AVGuard process -- `--restore` in a terminal while the
            # GUI is running -- records its decisions in this same file.
            # Measured before this: a running scanner kept condemning bytes
            # the user had just restored elsewhere, and with automatic
            # quarantine on would have taken them straight back. One stat()
            # per lookup is nothing next to the read that precedes it.
            if self._disk_stamp() != self._stamp:
                self._load()
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
