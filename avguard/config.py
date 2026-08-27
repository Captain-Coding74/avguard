"""Where AVGuard keeps its files, and the settings the user can change."""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

APP_NAME = "AVGuard"

PACKAGE_DIR = Path(__file__).resolve().parent

# When frozen by PyInstaller the code runs from a temporary extraction
# directory, and `__file__.parent.parent` points somewhere meaningless. The
# bundled rules live under `sys._MEIPASS`, so that is the project root.
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    PROJECT_ROOT = Path(sys._MEIPASS)
else:
    PROJECT_ROOT = PACKAGE_DIR.parent


def _default_data_dir() -> Path:
    """Where AVGuard keeps everything it writes.

    Deliberately NOT inside the program directory any more. Keeping it there
    meant four separate problems:

      * installing to Program Files made the first write fail, and under
        pythonw.exe that is a silent non-start with no window and no log
      * every user of the machine shared one quarantine store, one another's
        filenames and original paths visible in the list
      * a project folder inside Documents is inside OneDrive by default, so
        quarantined samples and the index naming every nonce were being
        uploaded to somebody's cloud
      * it cannot be frozen into a single executable

    `AVGUARD_DATA` overrides it, which is what the tests use and what a
    portable install on a USB stick would set.
    """
    override = os.getenv("AVGUARD_DATA")
    if override:
        return Path(override).expanduser().resolve()
    base = os.getenv("LOCALAPPDATA")
    if base:
        return Path(base) / APP_NAME
    return Path.home() / ".local" / "share" / "avguard"


DATA_DIR = _default_data_dir()
LEGACY_DATA_DIR = PROJECT_ROOT / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_DIR = DATA_DIR / "logs"
# Shipped rules travel with the code; the user's own rules live in their data
# directory so an update to AVGuard cannot overwrite them.
RULES_DIR = PROJECT_ROOT / "rules"
USER_RULES_DIR = DATA_DIR / "rules"

CONFIG_PATH = DATA_DIR / "config.json"
QUARANTINE_INDEX = QUARANTINE_DIR / "index.json"
VT_CACHE_PATH = DATA_DIR / "vt_cache.json"
SCAN_CACHE_PATH = DATA_DIR / "scan_cache.json"
RULES_PATH = RULES_DIR / "malware.yara"

CHUNK_SIZE = 64 * 1024

# Buffer files up to this size in memory so the hash, the signature sweep and
# the YARA match all run off one read. Larger files fall back to streaming.
YARA_BUFFER_MAX = 8 * 1024 * 1024


def atomic_write_text(path: Path, text: str) -> None:
    """Write a file so a crash mid-write cannot leave a half-written file.

    The old build wrote quarantine_data.json in place; an interrupted write
    left invalid JSON and the whole quarantine index was silently dropped on
    the next start.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@dataclass
class Config:
    """User-tunable settings, persisted to data/config.json."""

    # Hashes of the user's files are sent to a third party, so this is off
    # until it is switched on deliberately.
    cloud_enabled: bool = False
    cloud_daily_budget: int = 400
    cloud_cache_ttl_hours: int = 168

    # Anything bigger is recorded as skipped rather than read.
    max_file_size: int = 64 * 1024 * 1024

    worker_threads: int = 4
    debounce_seconds: float = 1.5

    realtime_enabled: bool = True
    watch_paths: list[str] = field(default_factory=list)

    # When false a detection is reported but the file is left alone.
    #
    # Off until the user is asked. This program moves files out from under
    # people, and the previous default did that on first launch having never
    # said so -- which quarantined ordinary CI scripts on a developer machine.
    auto_quarantine: bool = False

    # Evidence needed before a file is called malicious and may be moved.
    # See scanner.SEVERITY_WEIGHTS: a byte signature or a high-severity rule
    # scores 100 on its own; a medium rule scores 50 and needs corroboration.
    quarantine_threshold: int = 100

    # Set once the first-run dialog has been answered.
    onboarding_completed: bool = False

    # Look inside .zip containers. Downloads is where zipped samples arrive,
    # so this is on; members are read in memory and never extracted.
    archive_scanning_enabled: bool = True

    # Structural heuristics on executables. Reported, never auto-quarantined.
    pe_analysis_enabled: bool = True

    # Let a valid Authenticode signature set heuristic concerns aside. It can
    # never clear a byte signature, a high-severity rule, or cloud consensus:
    # malware does get signed with stolen certificates.
    trust_signed_publishers: bool = True

    # Quarantined files older than this are offered for review. Never deleted
    # automatically: the store holds the only copy of everything in it, and a
    # program that silently destroys the user's files after 90 days is worse
    # than one that fills a folder.
    quarantine_review_days: int = 90

    # Skipped before the file is ever opened.
    excluded_globs: list[str] = field(
        default_factory=lambda: [
            "**/__pycache__/**",
            "**/.git/**",
            "**/node_modules/**",
            "**/.venv/**",
            "**/System Volume Information/**",
            "**/$RECYCLE.BIN/**",
        ]
    )

    # Only these extensions get a cloud lookup, and only when nothing local
    # already decided. Keeps the API budget for files that could execute.
    cloud_extensions: list[str] = field(
        default_factory=lambda: [
            ".exe", ".dll", ".sys", ".scr", ".com", ".msi",
            ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar",
        ]
    )

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "Config":
        """Read config.json, falling back to defaults for anything missing."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        known = {f for f in cls().__dict__}
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self, path: Path = CONFIG_PATH) -> None:
        atomic_write_text(path, json.dumps(asdict(self), indent=2))

    @property
    def vt_api_key(self) -> str | None:
        """Read from the environment only, so the key is never written to disk."""
        return os.getenv("VT_API_KEY") or None


def migrate_legacy_data() -> bool:
    """Move a `data/` folder from the program directory to the new home.

    Runs once. Anything already at the destination wins, so this can never
    overwrite a newer store with an older one.
    """
    if not LEGACY_DATA_DIR.is_dir() or LEGACY_DATA_DIR.resolve() == DATA_DIR.resolve():
        return False

    moved = False
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for item in LEGACY_DATA_DIR.iterdir():
        destination = DATA_DIR / item.name
        if destination.exists():
            continue
        try:
            shutil.move(str(item), str(destination))
            moved = True
        except (OSError, shutil.Error):
            # A locked file (the previous lock file, typically) is not worth
            # failing a startup over.
            continue
    if moved:
        logging.getLogger("avguard").info(
            "moved existing data from %s to %s", LEGACY_DATA_DIR, DATA_DIR)
    try:
        LEGACY_DATA_DIR.rmdir()
    except OSError:
        pass
    return moved


def ensure_directories() -> Config:
    """Create the data directories and make sure config.json really exists.

    It used to be written only when a setting changed, so a fresh install had
    no config.json at all while the README and the VirusTotal dialog both told
    the user to go and look at it.
    """
    migrate_legacy_data()
    for directory in (DATA_DIR, QUARANTINE_DIR, LOG_DIR, USER_RULES_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    cfg = Config.load()
    if not CONFIG_PATH.exists():
        try:
            cfg.save()
        except OSError:
            pass  # a read-only install still runs, it just cannot remember
    return cfg
