"""Where AVGuard keeps its files, and the settings the user can change."""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass, field, fields
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


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """atomic_write_text for bytes, and durable: the data is flushed to the
    disk before the rename, and the rename itself where the platform allows.

    For a file that becomes the only copy of something once a later step
    runs (a quarantined payload before its original is unlinked, a restored
    file before its payload is). The journal makes the rename and the unlink
    durable, not the data, so without the fsync a power cut after the unlink
    could leave a payload of zeros and no original.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # A short name: the file it stands in for may already be at the 255
    # character limit, and its name plus a suffix would be over it.
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".avg-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> None:
    """Make a rename in `directory` durable. POSIX only: Windows cannot open
    a directory for flushing, and NTFS journals the rename itself."""
    if os.name != "posix":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class UnreadableJSON(ValueError):
    """A settings or store file that exists but is not one JSON object."""


def read_json_object(path: Path) -> dict | None:
    """The JSON object in `path`, or None when there is no such file.

    A byte-order mark is accepted: Notepad's old "UTF-8" and PowerShell 5.1's
    Set-Content -Encoding UTF8 both write one, and the file is otherwise
    intact. Anything else that is not one JSON object raises UnreadableJSON,
    so a caller never mistakes a file it cannot read for an empty one and
    then saves over it: that is how index.json lost every nonce it held.
    Other OSErrors (a locked file) propagate as they are.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return None
    except UnicodeDecodeError as exc:
        raise UnreadableJSON(f"{path.name} is not UTF-8 text (byte {exc.start})") from exc
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise UnreadableJSON(f"{path.name} is not valid JSON ({exc})") from exc
    if not isinstance(raw, dict):
        raise UnreadableJSON(f"{path.name} holds a JSON {type(raw).__name__}, not an object")
    return raw


def set_aside_if_unreadable(path: Path) -> Path | None:
    """Before `path` is written: if what is there now cannot be read, rename
    it to <name>.unreadable-<UTC time> and return the new path, so bytes that
    were not understood are kept for the user instead of written over.
    Raises OSError if it cannot be moved, which stops the write."""
    try:
        read_json_object(path)
        return None
    except UnreadableJSON:
        pass
    except OSError:
        return None             # the write that follows will say what is wrong
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    aside = path.with_name(f"{path.name}.unreadable-{stamp}")
    os.replace(path, aside)
    logging.getLogger(__name__).error(
        "%s could not be read and was kept as %s; a new one is being started", path, aside.name)
    return aside


def _fits(value, default) -> bool:
    """Whether `value` has the type of `default`: a bool is a bool (not 0 or
    "false"), an int an int (not a bool), a float accepts an int, a list of
    strings is a list of strings."""
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, int):
        return isinstance(value, int) and not isinstance(value, bool)
    if isinstance(default, float):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    return False


@dataclass
class Config:
    """User-tunable settings, persisted to data/config.json."""

    # Not a field (no annotation), so never written to config.json: why the
    # file could not be read at load, for the window to say. "" when it could.
    load_problem = ""

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

    # The paste guard (avguard/clipguard.py): read the text on the clipboard,
    # on this PC only, for the shape of a paste-and-run scam command. Off in
    # the file because turning clipboard reading on silently at an upgrade is
    # the "having told the user neither" failure; the first-run dialog offers
    # it pre-ticked with the sentence that says what it reads, and an
    # existing install is offered it once (paste_guard_offered).
    paste_guard_enabled: bool = False
    paste_guard_offered: bool = False

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

    # The MalwareBazaar hash blocklist, fetched at most once a day while this
    # is on. Off by default: nothing is fetched until the user says so, and
    # turning it on names exactly what leaves the machine (an ETag, nothing
    # else). Imported hashes work with this off.
    ioc_feed_enabled: bool = False

    # Where scan events are POSTed as JSON (Network Watchdog's server, for
    # instance). Empty means off. Setting it is a consent action: the file
    # path, the verdict, the file's SHA-256 and the evidence behind the
    # verdict (findings with their weights, severities, packs and notes, the
    # totals, the threshold) leave the machine for every event; paste-guard
    # events never do.
    event_forward_url: str = ""

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "Config":
        """Read config.json, falling back to defaults for anything missing.

        A file that cannot be read gives the defaults, is logged, and is
        named in `load_problem` for the window to say; save() sets it aside
        before writing, so the user's settings are never silently replaced
        by the defaults (a byte-order mark used to do it).

        Each value must have its default's type, or it is dropped and logged:
        "false" in quotes is a non-empty string, which turned automatic
        quarantine on while Settings showed it off, and the VirusTotal, feed
        and paste-guard switches on without their consent dialogs.
        """
        log = logging.getLogger(__name__)
        try:
            raw = read_json_object(path) or {}
        except (OSError, UnreadableJSON) as exc:
            log.error("could not read %s (%s); using the defaults", path, exc)
            loaded = cls()
            loaded.load_problem = (f"{path.name} could not be read ({exc}); AVGuard is using its "
                                   "defaults, and your file is kept beside it when settings are next saved")
            return loaded
        defaults = cls()
        names = {f.name for f in fields(cls)}
        accepted = {}
        for key, value in raw.items():
            if key not in names:
                continue
            if _fits(value, getattr(defaults, key)):
                accepted[key] = value
            else:
                log.warning("config.json: %s = %r is not a %s; the default is used",
                            key, value, type(getattr(defaults, key)).__name__)
        return cls(**accepted)

    def save(self, path: Path = CONFIG_PATH) -> None:
        set_aside_if_unreadable(path)
        atomic_write_text(path, json.dumps(asdict(self), indent=2))

    def save_changes(self, changes: dict, path: Path = CONFIG_PATH) -> None:
        """Write only `changes`, onto the file as it is on disk now, and take
        them into this object only once that has worked.

        Saving this whole object wrote back whatever another AVGuard had
        saved since it was loaded, and a failed save left the changes live
        anyway: Settings said "could not save", Cancel was pressed, and the
        clipboard was read and files moved regardless. Raises OSError, with
        this object untouched.
        """
        names = {f.name for f in fields(Config)}
        for key, value in changes.items():
            if key not in names or not _fits(value, getattr(Config(), key)):
                raise TypeError(f"{key} = {value!r} is not a setting of its type")
        fresh = Config.load(path)
        if fresh.load_problem:
            fresh = Config(**asdict(self))      # the file is unreadable: this object is the copy there is
        for key, value in changes.items():
            setattr(fresh, key, value)
        fresh.save(path)
        for key, value in changes.items():
            setattr(self, key, value)

    @property
    def vt_api_key(self) -> str | None:
        """Read from the environment only, so the key is never written to disk."""
        return os.getenv("VT_API_KEY") or None


def watch_targets(cfg: "Config") -> list[Path]:
    """The folders real-time protection watches, and the daily scan scans:
    the user's, or Downloads when they named none. One answer for both, so
    "the watched folders" means the same folders in the window and the task."""
    if cfg.watch_paths:
        return [Path(p) for p in cfg.watch_paths]
    downloads = Path.home() / "Downloads"
    return [downloads] if downloads.is_dir() else []


def migrate_legacy_data() -> bool:
    """Move a `data/` folder from the program directory to the new home.

    Runs once. Anything already at the destination wins, so this can never
    overwrite a newer store with an older one.
    """
    if not LEGACY_DATA_DIR.is_dir() or LEGACY_DATA_DIR.resolve() == DATA_DIR.resolve():
        return False
    if os.getenv("AVGUARD_DATA"):
        # Only the default home is a migration target. With an explicit
        # location (the tests' per-run temp directory, the smoke check's work
        # directory, a portable stick) the old install's quarantine, the only
        # copy of every held file, was moved there and deleted with it.
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
