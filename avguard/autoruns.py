"""What starts with Windows, and what changed since the last look.

Almost every piece of commodity malware that wants to survive a reboot
registers itself in one of a few user-mode places: a Run or RunOnce value,
the Startup folder, a scheduled task, or, once it has administrator rights,
a service or a task under \\Microsoft\\Windows\\ with a plausible name. None
of those writes is a file arriving in Downloads, so the scanner never sees
it. This module reads those places at a point in time, the way Sysinternals
Autoruns does as a standard user, keeps a snapshot, and reports what differs
from the previous one: added, removed, or changed in a way that matters.

It is the file-integrity baseline's design applied to configuration: a
signed SQLite store under the data directory, a diff that records events
and never produces a Finding, never moves anything, never needs elevation,
a driver, a hook or process telemetry. Snapshot-to-snapshot rather than
baseline-until-accepted, because startup state drifts legitimately (an
update rewrites a dozen tasks) and the honest record is "what is new since
yesterday", not "what differs from a day in March".

What counts as a change: the command or image path, the arguments, whether
the entry is enabled, a task's triggers and run level, a service's start
type. What does not: a task's last-run time or result, a registration date,
a description. Those sit in `detail` and never reach the fingerprint.

Every Windows call is behind an injectable: the registry module, the
Startup folders, the system root and the `schtasks` runner are parameters
with Windows defaults, so the whole module runs on Linux against fakes and
the collectors run for real on the Windows runner.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import logging
import ntpath
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from . import config, fim
from .events import Event, EventStore

log = logging.getLogger("avguard.autoruns")

AUTORUNS_DIR = config.DATA_DIR / "autoruns"
DB_NAME = "snapshots.sqlite"
KEY_NAME = "snapshots.key"
SIGNATURE_NAME = "snapshots.hmac"
LOCK_NAME = "snapshots.lock"
LOCK_WAIT = 5.0                 # seconds a snapshot waits for another to finish
KEEP_SNAPSHOTS = 30             # a month of daily snapshots; older ones are pruned
MAX_STARTUP_FILE = 4 * 1024 * 1024   # a Startup-folder file larger than this is named, not hashed

KIND_RUN = "run"
KIND_STARTUP = "startup"
KIND_TASK = "task"
KIND_SERVICE = "service"
KINDS = (KIND_RUN, KIND_STARTUP, KIND_TASK, KIND_SERVICE)

HKCU = "HKCU"
HKLM = "HKLM"
RUN_KEYS = (r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
APPROVED_RUN = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
APPROVED_RUN32 = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
APPROVED_FOLDER = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
SERVICE_START = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
SERVICE_TYPE = {1: "kernel driver", 2: "file system driver", 16: "own process", 32: "shared process",
                80: "user service", 96: "user service", 208: "user service instance",
                224: "user service instance", 272: "own process, interactive",
                288: "shared process, interactive"}
# Bit 0x80 marks a per-logon instance of a user service (CDPUserSvc_3f2a1 and
# the like): a fresh name at every sign-in, the template's image. The template
# is collected; an instance would be NEW and GONE every day.
SERVICE_INSTANCE_BIT = 0x80
# Folders under the Windows folder an ordinary user can write to. A program
# there is not what an update looks like, whatever its parent folder.
WRITABLE_UNDER_ROOT = ("temp", "tasks", "tracing", "debug", "registration\\crmlog", "system32\\tasks",
                       "system32\\spool\\drivers\\color", "system32\\com\\dmp", "system32\\fxstmp",
                       "syswow64\\tasks", "syswow64\\com\\dmp", "syswow64\\fxstmp")
TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
# schtasks writes a comment naming each task before its XML. The blocks are
# cut at those comments, not at "</Task>": a Performance Monitor task's
# CDATA holds a data-collector definition with its own <Task></Task>
# inside, and cutting at the first "</Task>" left the Windows runner with an
# "unclosed CDATA section" for it.
_TASK_NAMES = re.compile(r"<!--\s*(\\[^>]*?)\s*-->")

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

# The same words the file-integrity baseline uses for its own state.
INTEGRITY_OK = fim.INTEGRITY_OK
INTEGRITY_TAMPERED = fim.INTEGRITY_TAMPERED
INTEGRITY_UNSIGNED = fim.INTEGRITY_UNSIGNED
INTEGRITY_KEY_UNREADABLE = fim.INTEGRITY_KEY_UNREADABLE
INTEGRITY_NO_SNAPSHOT = "no-snapshot"
INTEGRITY_MESSAGES = {
    INTEGRITY_TAMPERED: "the startup snapshots were modified outside AVGuard: "
                        "their signature no longer matches",
    INTEGRITY_UNSIGNED: "the startup snapshots have no signature file; they were created or "
                        "copied without AVGuard",
    INTEGRITY_KEY_UNREADABLE: "the snapshots' signing key cannot be read (another user's, or "
                              "damaged); the signature cannot be checked",
}


# ------------------------------------------------------------------ entries

@dataclass(frozen=True)
class Entry:
    """One thing set to start. `value` is the command, image or target;
    `extra` is what else counts toward a change (arguments, triggers, a
    service's start type); `detail` is everything that does not."""
    kind: str
    location: str
    name: str
    value: str
    enabled: bool = True
    extra: str = ""
    detail: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def key(self) -> str:
        """Identity across snapshots: where it is and what it is called."""
        return f"{self.kind}|{self.location.lower()}|{self.name.lower()}"

    @property
    def fingerprint(self) -> str:
        counted = [self.kind, self.location.lower(), self.name.lower(), self.value,
                   bool(self.enabled), self.extra]
        return hashlib.sha256(json.dumps(counted, ensure_ascii=False).encode("utf-8")).hexdigest()

    @property
    def target(self) -> str:
        """The program that would run: a Startup-folder entry is its own file,
        an svchost-hosted service is the DLL svchost loads, else the command's
        program."""
        if self.kind == KIND_STARTUP:
            return self.value
        host = target_of(self.value)
        dll = self.detail.get("service_dll") if isinstance(self.detail, dict) else ""
        if dll and ntpath.basename(host).lower() == "svchost.exe":
            return target_of(str(dll))
        return host

    def paths(self) -> list[str]:
        """Every path-like thing in the entry: the target and any drive-rooted
        argument (rundll32's DLL, cmd's script, powershell's -File)."""
        if self.kind == KIND_STARTUP:
            return [self.value]                # the file is the whole story
        found = [self.target] if self.target else []
        for token in _PATH_TOKENS.findall(ntpath.expandvars(self.value or "")):
            if token.lower() not in (f.lower() for f in found):
                found.append(token)
        return found

    def describe(self) -> str:
        state = "" if self.enabled else " (disabled)"
        return f"{self.kind} {ntpath.join(self.location, self.name)}{state}: {self.value}"


_QUOTED = re.compile(r'^\s*"([^"]+)"')
_EXECUTABLE = re.compile(r'^\s*(.+?\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|msi|scr|dll|sys|hta|lnk|url))\b', re.I)
_PATH_TOKENS = re.compile(r'[A-Za-z]:\\[^\s",;]+')


def target_of(command: str) -> str:
    """The program a command string runs, as well as it can be told without
    executing anything: a quoted path, else the text up to an executable
    suffix, else the first token. Environment variables are expanded."""
    # ntpath throughout: these are Windows paths whatever this runs on, and
    # the tests run on Linux against the same strings.
    text = ntpath.expandvars(command or "").strip()
    if not text:
        return ""
    found = _QUOTED.match(text) or _EXECUTABLE.match(text)
    target = found.group(1) if found else text.split(" ", 1)[0]
    # A service image path may be written as \??\C:\... or \SystemRoot\...
    if target.startswith(("\\??\\", "\\\\?\\")):
        target = target[4:]
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if target.lower().startswith("\\systemroot\\"):
        target = root + target[len("\\systemroot"):]
    elif target.lower().startswith("system32\\"):
        target = ntpath.join(root, target)
    return target.strip()


def under_system_root(target: str, system_root: str | None = None) -> bool:
    root = ntpath.normcase(ntpath.normpath(system_root or os.environ.get("SystemRoot", r"C:\Windows")))
    path = ntpath.normcase(ntpath.normpath(target or ""))
    return bool(path) and (path == root or path.startswith(root + "\\"))


def in_writable_system_folder(target: str, system_root: str | None = None) -> bool:
    """Under the Windows folder, but in a subfolder any user can write to."""
    root = ntpath.normcase(ntpath.normpath(system_root or os.environ.get("SystemRoot", r"C:\Windows")))
    path = ntpath.normcase(ntpath.normpath(target or ""))
    return any(path.startswith(root + "\\" + folder + "\\") for folder in WRITABLE_UNDER_ROOT)


# ------------------------------------------------------------------- changes

@dataclass
class Change:
    kind: str                      # added | removed | modified
    entry: Entry                   # the current entry (for removed: the old one)
    old: Entry | None = None       # for modified: what it was

    def describe(self) -> str:
        # ntpath.join: a task in the library's root has the location "\\"
        # and must read "\\Name", not "\\\\Name".
        where = f"{self.entry.kind} {ntpath.join(self.entry.location, self.entry.name)}"
        if self.kind == "added":
            state = "" if self.entry.enabled else ", disabled"
            return f"NEW       {where}: {self.entry.value}{state}"
        if self.kind == "removed":
            return f"GONE      {where}: was {self.entry.value}"
        return f"CHANGED   {where}: {'; '.join(self.parts()) or 'changed'}"

    def parts(self) -> list[str]:
        """What changed in a modified entry, as old -> new fragments; the tab
        shows them without the sentence around them."""
        parts: list[str] = []
        if self.old is not None:
            if self.old.value != self.entry.value:
                parts.append(f"{self.old.value} -> {self.entry.value}")
            if self.old.enabled != self.entry.enabled:
                parts.append("enabled" if self.entry.enabled else "disabled")
            if self.old.extra != self.entry.extra:
                parts.append(f"{self.old.extra or '(none)'} -> {self.entry.extra or '(none)'}")
        return parts

    def worth_a_look(self, system_root: str | None = None, trusted: Callable[[str], bool] | None = None) -> bool:
        """Whether this deserves a banner, not only a row. A change whose
        target is a trusted-signed program under the system root is what a
        Windows update looks like; it is recorded and
        shown, never shouted. `trusted` answers for the signature when a
        checker is available; without one, the system root alone is quiet,
        which is the measured trade until the owner's fourteen days are in."""
        if self.kind == "removed":
            return False
        paths = self.entry.paths()
        if not paths:
            return True
        for path in paths:
            # Every path the command names has to be under the Windows folder
            # and outside its user-writable corners: rundll32 is signed, the
            # DLL it is handed under the profile is the point.
            if not under_system_root(path, system_root) or in_writable_system_folder(path, system_root):
                return True
        if trusted is None:
            return False
        try:
            return not trusted(paths[0])
        except Exception:                      # a checker that fails says nothing
            return True

    def as_event(self) -> Event:
        detail = {"kind": self.entry.kind, "location": self.entry.location, "name": self.entry.name,
                  "value": self.entry.value, "enabled": self.entry.enabled, "extra": self.entry.extra,
                  "target": self.entry.target}
        if self.old is not None:
            detail["old"] = {"value": self.old.value, "enabled": self.old.enabled, "extra": self.old.extra}
        return Event(kind="autoruns", path=self.entry.target, level=self.kind,
                     reasons=[self.describe()], detail=detail)


def diff(before: Sequence[Entry], after: Sequence[Entry]) -> list[Change]:
    """What is new, gone or changed between two snapshots, keyed on where an
    entry is and what it is called; order: added, modified, removed."""
    old = {e.key: e for e in _unique(before)}
    new = {e.key: e for e in _unique(after)}
    changes: list[Change] = []
    for key in sorted(new.keys() - old.keys()):
        changes.append(Change("added", new[key]))
    for key in sorted(new.keys() & old.keys()):
        if new[key].fingerprint != old[key].fingerprint:
            changes.append(Change("modified", new[key], old[key]))
    for key in sorted(old.keys() - new.keys()):
        changes.append(Change("removed", old[key]))
    return changes


# ---------------------------------------------------------------- collectors

def _default_registry():
    try:
        import winreg
    except ImportError:
        return None
    return winreg


def _reg_root(registry, name: str):
    return registry.HKEY_CURRENT_USER if name == HKCU else registry.HKEY_LOCAL_MACHINE


def _values(registry, root_name: str, sub_key: str, view: int = 0) -> dict[str, tuple[object, int]]:
    """Every value under a key as {name: (data, type)}, {} when the key is
    missing or unreadable (the caller decides whether that is an error)."""
    out: dict[str, tuple[object, int]] = {}
    access = registry.KEY_READ | view
    try:
        with registry.OpenKey(_reg_root(registry, root_name), sub_key, 0, access) as key:
            index = 0
            while True:
                try:
                    name, data, kind = registry.EnumValue(key, index)
                except OSError:
                    break
                out[name] = (data, kind)
                index += 1
    except OSError:
        return {}
    return out


def _subkeys(registry, root_name: str, sub_key: str) -> list[str]:
    names: list[str] = []
    try:
        with registry.OpenKey(_reg_root(registry, root_name), sub_key, 0, registry.KEY_READ) as key:
            index = 0
            while True:
                try:
                    names.append(registry.EnumKey(key, index))
                except OSError:
                    break
                index += 1
    except OSError:
        return []
    return names


def _approved(registry, root_name: str, sub_key: str, view: int = 0) -> dict[str, bool]:
    """Task Manager's Startup page records an entry it disabled here: a
    binary value whose first byte has its low bit set when disabled (3 or 7)
    and clear when enabled (2 or 6)."""
    out: dict[str, bool] = {}
    for name, (data, _kind) in _values(registry, root_name, sub_key, view).items():
        if isinstance(data, (bytes, bytearray)) and data:
            out[name.lower()] = not (data[0] & 1)
    return out


def collect_run_keys(registry=None, errors: list[str] | None = None) -> list[Entry]:
    """Run and RunOnce for the user and the machine, the machine's in both
    registry views, with Task Manager's enabled flag applied."""
    registry = registry if registry is not None else _default_registry()
    if registry is None:
        return []
    errors = errors if errors is not None else []
    entries: list[Entry] = []
    views = [(0, "")]
    if hasattr(registry, "KEY_WOW64_64KEY") and hasattr(registry, "KEY_WOW64_32KEY"):
        views = [(registry.KEY_WOW64_64KEY, ""), (registry.KEY_WOW64_32KEY, " (32-bit)")]
    for root_name in (HKCU, HKLM):
        approved = dict(_approved(registry, root_name, APPROVED_RUN))
        approved.update(_approved(registry, root_name, APPROVED_RUN32))
        for sub_key in RUN_KEYS:
            for view, label in (views if root_name == HKLM else [(0, "")]):
                for name, (data, _kind) in _values(registry, root_name, sub_key, view).items():
                    # An empty value starts nothing; a command in the key's
                    # unnamed default value is unusual and all the more worth a row.
                    if not isinstance(data, str) or not data.strip():
                        continue
                    location = f"{root_name}\\{sub_key}{label}"
                    shown = name or "(Default)"
                    entries.append(Entry(KIND_RUN, location, shown, data,
                                         enabled=approved.get(shown.lower(), True)))
    return entries


def collect_startup_folders(folders: Iterable[tuple[str, Path]] | None = None, registry=None,
                            errors: list[str] | None = None) -> list[Entry]:
    """Files in the user's and the machine's Startup folders, hashed so a
    rewritten shortcut counts as changed."""
    errors = errors if errors is not None else []
    if folders is None:
        folders = default_startup_folders()
    approved: dict[str, bool] = {}
    registry = registry if registry is not None else _default_registry()
    if registry is not None:
        for root_name in (HKCU, HKLM):
            approved.update(_approved(registry, root_name, APPROVED_FOLDER))
    entries: list[Entry] = []
    unlisted: list[str] = []
    for label, folder in folders:
        folder = Path(folder)
        if not folder.is_dir():
            continue                           # no folder is not an error; a user may not have one
        try:
            names = sorted(p for p in folder.iterdir() if p.is_file())
        except OSError as exc:
            unlisted.append(f"{folder}: {exc}")  # a folder that is there and cannot be listed is
            continue                             # not an empty one
        for path in names:
            if path.name.lower() == "desktop.ini":
                continue
            try:
                size = path.stat().st_size
                digest = hashlib.sha256(path.read_bytes()).hexdigest() if size <= MAX_STARTUP_FILE else ""
            except OSError as exc:
                errors.append(f"{path}: {exc}")
                continue
            entries.append(Entry(KIND_STARTUP, f"Startup ({label})", path.name, str(path),
                                 enabled=approved.get(path.name.lower(), True),
                                 extra=f"sha256 {digest[:16]}" if digest else f"{size} bytes",
                                 detail={"size": size, "sha256": digest}))
    if unlisted:
        raise CollectorFailed("a Startup folder could not be listed: " + "; ".join(unlisted))
    return entries


def default_startup_folders() -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("ProgramData")
    tail = Path("Microsoft") / "Windows" / "Start Menu" / "Programs" / "Startup"
    if appdata:
        out.append(("user", Path(appdata) / tail))
    if programdata:
        out.append(("all users", Path(programdata) / tail))
    return out


def collect_services(registry=None, errors: list[str] | None = None) -> list[Entry]:
    """Every service and driver with an image path, from the registry: no
    elevation needed to read it, and a new kernel driver is the most
    interesting persistence of all."""
    registry = registry if registry is not None else _default_registry()
    if registry is None:
        return []
    errors = errors if errors is not None else []
    entries: list[Entry] = []
    for name in _subkeys(registry, HKLM, SERVICES_KEY):
        values = _values(registry, HKLM, f"{SERVICES_KEY}\\{name}")
        start = values.get("Start", (3, 0))[0]
        kind = values.get("Type", (0, 0))[0]
        start = int(start) if isinstance(start, int) else 3
        kind = int(kind) if isinstance(kind, int) else 0
        if kind & SERVICE_INSTANCE_BIT:
            continue                           # a per-logon instance; its template is collected
        image = values.get("ImagePath", ("", 0))[0]
        implied = False
        if not isinstance(image, str) or not image:
            if kind not in (1, 2):
                continue                       # neither an image nor a driver: not a service
            # A driver key without an ImagePath is loaded from the default place.
            image = f"\\SystemRoot\\System32\\drivers\\{name}.sys"
            implied = True
        display = values.get("DisplayName", ("", 0))[0]
        detail = {"display_name": display if isinstance(display, str) else "", "start": start,
                  "type": kind, "implied": implied}
        extra = f"start {SERVICE_START.get(start, start)}; type {SERVICE_TYPE.get(kind, kind)}"
        # An svchost-hosted service's code is the DLL its Parameters name;
        # the image path says only "svchost". The DLL counts, and is the target.
        dll = _values(registry, HKLM, f"{SERVICES_KEY}\\{name}\\Parameters").get("ServiceDll", ("", 0))[0]
        if isinstance(dll, str) and dll.strip():
            detail["service_dll"] = dll
            extra += f"; dll {dll}"
        entries.append(Entry(KIND_SERVICE, f"{HKLM}\\{SERVICES_KEY}", name, image, enabled=start != 4,
                             extra=extra, detail=detail))
    return entries


class CollectorFailed(RuntimeError):
    """A collector could not do its job; what it would have found is unknown,
    which is not the same as nothing."""


def run_schtasks() -> bytes:
    """`schtasks /Query /XML ONE`, raw bytes: the caller decodes. A non-zero
    exit with no task in the output is a failure, said with schtasks' words."""
    result = subprocess.run(["schtasks", "/Query", "/XML", "ONE"], capture_output=True,
                            timeout=120, creationflags=_NO_WINDOW)
    out = result.stdout or b""
    if result.returncode != 0 and b"<Task" not in out:
        words = decode_console(result.stderr or out).strip().splitlines()
        raise CollectorFailed(f"schtasks exited {result.returncode}: {words[0][:160] if words else 'no output'}")
    return out


def decode_console(raw: bytes) -> str:
    """schtasks writes in the console's code page (its XML header's UTF-16
    claim notwithstanding), unless it was redirected with a BOM."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    codepage = None
    if sys.platform == "win32":
        try:
            # 0 when this process has no console (the window under pythonw,
            # the scheduled run); the hidden console a child gets then uses
            # the OEM page, so decode with that and every context agrees.
            codepage = ctypes.windll.kernel32.GetConsoleOutputCP() or ctypes.windll.kernel32.GetOEMCP()
        except Exception:
            codepage = None
    for encoding in ([f"cp{codepage}"] if codepage else []) + ["utf-8", "mbcs" if sys.platform == "win32" else "latin-1"]:
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _text(element, tag: str) -> str:
    found = element.find(f".//{TASK_NS}{tag}") if element is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


def parse_tasks(xml_text: str, errors: list[str] | None = None) -> list[Entry]:
    """Entries from `schtasks /Query /XML ONE` output: one per task, named by
    the comment schtasks writes before it. Counted: the actions, enabled,
    the triggers and the run level. Not counted: author, date, description."""
    errors = errors if errors is not None else []
    entries: list[Entry] = []
    pieces = _TASK_NAMES.split(xml_text)
    # pieces: [before the first comment, name, block, name, block, ...]
    for full_name, block in zip(pieces[1::2], pieces[2::2]):
        full_name = full_name.strip()
        block = block.split("</Tasks>", 1)[0].strip()
        start = block.find("<Task")
        if start < 0:
            errors.append(f"task {full_name}: no XML followed its name")
            continue
        try:
            task = ET.fromstring(block[start:])
        except ET.ParseError as exc:
            errors.append(f"task {full_name}: unreadable XML ({exc})")
            continue
        folder, _, name = full_name.rpartition("\\")
        actions: list[str] = []
        for exec_ in task.iter(f"{TASK_NS}Exec"):
            command = _text(exec_, "Command")
            arguments = _text(exec_, "Arguments")
            actions.append(f"{command} {arguments}".strip())
        for handler in task.iter(f"{TASK_NS}ComHandler"):
            actions.append(f"COM {_text(handler, 'ClassId')} {_text(handler, 'Data')}".strip())
        settings = task.find(f"{TASK_NS}Settings")
        enabled = _text(settings, "Enabled").lower() != "false" if settings is not None else True
        triggers = []
        triggers_el = task.find(f"{TASK_NS}Triggers")
        if triggers_el is not None:
            for trigger in triggers_el:
                tag = trigger.tag.replace(TASK_NS, "")
                on = _text(trigger, "Enabled").lower() != "false"
                start = _text(trigger, "StartBoundary")
                interval = _text(trigger, "Interval")
                triggers.append(f"{tag}{'' if on else '(off)'}{'@' + start if start else ''}"
                                f"{'/' + interval if interval else ''}")
        # The account is the Principal's. A LogonTrigger carries a UserId of
        # its own (run when this user signs in), which is not who it runs as.
        principals = task.find(f"{TASK_NS}Principals")
        run_level = _text(principals, "RunLevel")
        user = _text(principals, "UserId")
        extra = "; ".join(filter(None, [", ".join(triggers), run_level, user]))
        entries.append(Entry(KIND_TASK, folder or "\\", name, " | ".join(actions) or "(no action)",
                             enabled=enabled, extra=extra,
                             detail={"author": _text(task, "Author"), "date": _text(task, "Date"),
                                     "description": _text(task, "Description")[:200]}))
    return entries


def collect_tasks(runner: Callable[[], bytes] | None = None, errors: list[str] | None = None) -> list[Entry]:
    errors = errors if errors is not None else []
    runner = runner if runner is not None else run_schtasks
    try:
        raw = runner()
    except (OSError, subprocess.SubprocessError, CollectorFailed) as exc:
        raise CollectorFailed(f"schtasks could not be run: {exc}") from exc
    text = decode_console(raw)
    entries = parse_tasks(text, errors)
    if not entries:
        # No machine has no tasks: an empty answer is a failed read, and a
        # failed read must not become a snapshot in which every task is gone.
        first = text.strip().splitlines()[0][:120] if text.strip() else "nothing"
        raise CollectorFailed(f"schtasks returned {first!r}, no tasks")
    return entries


@dataclass
class Collected:
    entries: list[Entry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    seconds: dict[str, float] = field(default_factory=dict)      # per collector
    counts: dict[str, int] = field(default_factory=dict)
    failed: set[str] = field(default_factory=set)                # kinds whose collector could not read


def collect(registry=None, startup_folders=None, schtasks_runner=None,
            kinds: Iterable[str] = KINDS) -> Collected:
    """Every collector, timed; one failing does not stop the others."""
    result = Collected()
    jobs = {
        KIND_RUN: lambda errs: collect_run_keys(registry, errs),
        KIND_STARTUP: lambda errs: collect_startup_folders(startup_folders, registry, errs),
        KIND_SERVICE: lambda errs: collect_services(registry, errs),
        KIND_TASK: lambda errs: collect_tasks(schtasks_runner, errs),
    }
    for kind in kinds:
        started = time.perf_counter()
        errs: list[str] = []
        try:
            found = jobs[kind](errs)
        except CollectorFailed as exc:
            errs.append(f"{kind}: {exc}")
            result.failed.add(kind)
            found = []
        except Exception as exc:          # a collector is never allowed to take the snapshot down
            log.exception("the %s collector failed", kind)
            errs.append(f"{kind}: {exc}")
            result.failed.add(kind)
            found = []
        if kind == KIND_SERVICE and not found and kind not in result.failed \
                and (registry is not None or sys.platform == "win32"):
            # A Windows machine has services; none read means the read failed.
            errs.append("service: the Services key could not be read")
            result.failed.add(kind)
        result.entries.extend(found)
        result.errors.extend(errs)
        result.seconds[kind] = time.perf_counter() - started
        result.counts[kind] = len(found)
    return result


# -------------------------------------------------------------------- store

@dataclass
class Snapshot:
    id: int
    taken_at: float
    entries: int
    seconds: float = 0.0
    failed: tuple[str, ...] = ()      # kinds whose collector could not read that day


@dataclass
class SnapshotReport:
    snapshot: Snapshot | None = None
    changes: list[Change] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    seconds: dict[str, float] = field(default_factory=dict)
    first: bool = False                    # nothing to compare with yet
    integrity: str = INTEGRITY_OK
    carried: dict[str, int] = field(default_factory=dict)   # kind -> entries kept from the previous snapshot
    loud: list[Change] | None = None       # judged worth a banner by the window's worker; None: nobody judged

    def of(self, kind: str) -> list[Change]:
        return [c for c in self.changes if c.kind == kind]

    def integrity_event(self) -> Event | None:
        if self.integrity in (INTEGRITY_OK, INTEGRITY_NO_SNAPSHOT):
            return None
        return Event(kind="autoruns", level="tampered", reasons=[INTEGRITY_MESSAGES[self.integrity]],
                     detail={"integrity": self.integrity})


def _unique(entries: Iterable[Entry]) -> list[Entry]:
    """One entry per key, the first kept: the one rule for the diff, the
    stored rows and the count, so a duplicate cannot flap CHANGED."""
    seen: dict[str, Entry] = {}
    for entry in entries:
        seen.setdefault(entry.key, entry)
    return list(seen.values())


class AutorunsStore:
    """The snapshots on disk, signed like the file-integrity baseline."""

    def __init__(self, directory: Path = AUTORUNS_DIR, keep: int = KEEP_SNAPSHOTS,
                 key_protect: Callable[[bytes], bytes] = fim.protect,
                 key_unprotect: Callable[[bytes], bytes] = fim.unprotect) -> None:
        self.directory = Path(directory)
        self.keep = keep
        self._protect = key_protect
        self._unprotect = key_unprotect

    @property
    def db_path(self) -> Path:
        return self.directory / DB_NAME

    @property
    def key_path(self) -> Path:
        return self.directory / KEY_NAME

    @property
    def signature_path(self) -> Path:
        return self.directory / SIGNATURE_NAME

    def exists(self) -> bool:
        return self.db_path.is_file()

    def _connect(self) -> sqlite3.Connection:
        self.directory.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("CREATE TABLE IF NOT EXISTS snapshots("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT, taken_at REAL NOT NULL, "
                     "entries INTEGER NOT NULL, seconds REAL NOT NULL, errors TEXT NOT NULL, "
                     "failed TEXT NOT NULL DEFAULT '')")
        if "failed" not in {row[1] for row in conn.execute("PRAGMA table_info(snapshots)")}:
            conn.execute("ALTER TABLE snapshots ADD COLUMN failed TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE TABLE IF NOT EXISTS entries("
                     "snapshot_id INTEGER NOT NULL, key TEXT NOT NULL, kind TEXT NOT NULL, "
                     "location TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, "
                     "enabled INTEGER NOT NULL, extra TEXT NOT NULL, detail TEXT NOT NULL, "
                     "fingerprint TEXT NOT NULL, PRIMARY KEY(snapshot_id, key))")
        conn.commit()
        return conn

    # ------------------------------------------------------------ reading

    def unreadable(self) -> str | None:
        """Why SQLite cannot open the database, or None when it can (or when
        there is none). An unreadable file is not an empty one."""
        if not self.exists():
            return None
        try:
            with closing(self._connect()) as conn:
                conn.execute("SELECT count(*) FROM snapshots").fetchone()
        except sqlite3.Error as exc:
            return str(exc)
        return None

    def snapshots(self) -> list[Snapshot]:
        if not self.exists():
            return []
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute("SELECT id, taken_at, entries, seconds, failed FROM snapshots "
                                    "ORDER BY id").fetchall()
        except sqlite3.Error:
            return []
        out = []
        for r in rows:
            try:
                kinds = tuple(str(k) for k in json.loads(r[4])) if r[4] else ()
            except ValueError:
                kinds = ()
            out.append(Snapshot(int(r[0]), float(r[1]), int(r[2]), float(r[3]), kinds))
        return out

    def latest(self) -> Snapshot | None:
        found = self.snapshots()
        return found[-1] if found else None

    def entries(self, snapshot_id: int | None = None) -> list[Entry]:
        if snapshot_id is None:
            latest = self.latest()
            if latest is None:
                return []
            snapshot_id = latest.id
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute("SELECT kind, location, name, value, enabled, extra, detail "
                                    "FROM entries WHERE snapshot_id = ? ORDER BY key",
                                    (snapshot_id,)).fetchall()
        except sqlite3.Error:
            return []
        out: list[Entry] = []
        for kind, location, name, value, enabled, extra, detail in rows:
            try:
                parsed = json.loads(detail) if detail else {}
            except ValueError:
                parsed = {}
            out.append(Entry(kind, location, name, value, bool(enabled), extra,
                             parsed if isinstance(parsed, dict) else {}))
        return out

    def last_changes(self) -> list[Change]:
        """The difference between the two most recent snapshots, recomputed
        from what is stored: what the tab shows when it opens."""
        found = self.snapshots()
        if len(found) < 2:
            return []
        return diff(self.entries(found[-2].id), self.entries(found[-1].id))

    # ------------------------------------------------------------ writing

    def snapshot(self, collected: Collected, events: EventStore | None = None) -> SnapshotReport:
        """Store what was collected, diff it against the previous snapshot,
        record the changes as events, sign. Nothing is stored when nothing
        at all was collected: an empty snapshot would report everything as
        gone next time. One snapshot at a time: the window and the daily
        task share the files."""
        report = SnapshotReport(errors=list(collected.errors), counts=dict(collected.counts),
                                seconds=dict(collected.seconds))
        report.integrity = self.verify_integrity() if self.exists() else INTEGRITY_NO_SNAPSHOT
        if not collected.entries:
            report.errors.append("nothing was collected; the snapshot was not recorded")
            return report
        lock = fim.FileLock(self.directory / LOCK_NAME)
        if not lock.acquire(LOCK_WAIT):
            report.errors.append("another snapshot is being taken; this one was not recorded")
            return report
        try:
            return self._snapshot(collected, events, report)
        finally:
            lock.release()

    def _snapshot(self, collected: Collected, events: EventStore | None, report: SnapshotReport) -> SnapshotReport:
        if not self.exists():
            report.integrity = INTEGRITY_OK
        broken = self.unreadable()
        if broken is not None:
            # SQLite cannot open the file. The signature check already says
            # tampered unless the file was swapped and re-signed; either
            # way nothing is compared with it or written over it, the
            # tamper event is recorded, and the report says what could not
            # be done instead of raising out of the daily task into nothing.
            if report.integrity == INTEGRITY_OK:
                report.integrity = INTEGRITY_TAMPERED
            report.errors.append(f"the previous snapshots cannot be read ({broken}); "
                                 "the snapshot was not recorded")
            log.error("startup snapshot: the previous snapshots cannot be read (%s)", broken)
            self._record(report, events)
            return report
        latest = self.latest()
        previous = self.entries(latest.id) if latest is not None else []
        report.first = latest is None
        entries = _unique(collected.entries)
        # A kind whose collector failed is unknown today, not empty: the
        # previous snapshot's entries of that kind are kept, so nothing is
        # reported gone for a read that did not happen, and said so.
        fresh = {e.key for e in entries}
        for kind in sorted(collected.failed):
            kept = [e for e in previous if e.kind == kind and e.key not in fresh]
            if kept:
                entries.extend(kept)
                report.carried[kind] = len(kept)
                report.errors.append(f"{kind}: not read this time; the previous snapshot's "
                                     f"{len(kept)} kept")
        # A kind the previous snapshot could not read, with nothing to
        # carry, is read for the first time now: recorded, not compared,
        # or every task would be NEW the day after a bad first read.
        first_read = {kind for kind in (latest.failed if latest is not None else ())
                      if kind not in collected.failed and not any(e.kind == kind for e in previous)}
        if latest is not None:
            changes = diff(previous, entries)
            for kind in sorted(first_read):
                skipped = sum(1 for c in changes if c.entry.kind == kind)
                if skipped:
                    report.errors.append(f"{kind}: read for the first time; {skipped} recorded, not compared")
            report.changes = [c for c in changes if c.entry.kind not in first_read]

        taken_at = time.time()
        total_seconds = sum(collected.seconds.values())
        failed = sorted(collected.failed)
        with closing(self._connect()) as conn:
            with conn:
                cursor = conn.execute(
                    "INSERT INTO snapshots(taken_at, entries, seconds, errors, failed) VALUES (?, ?, ?, ?, ?)",
                    (taken_at, len(entries), total_seconds, json.dumps(collected.errors), json.dumps(failed)))
                snapshot_id = int(cursor.lastrowid)
                for entry in entries:
                    conn.execute(
                        "INSERT INTO entries(snapshot_id, key, kind, location, name, value, enabled, "
                        "extra, detail, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (snapshot_id, entry.key, entry.kind, entry.location, entry.name, entry.value,
                         int(entry.enabled), entry.extra, json.dumps(entry.detail, ensure_ascii=False),
                         entry.fingerprint))
                old_ids = [r[0] for r in conn.execute(
                    "SELECT id FROM snapshots ORDER BY id DESC LIMIT -1 OFFSET ?", (self.keep,))]
                for old_id in old_ids:
                    conn.execute("DELETE FROM entries WHERE snapshot_id = ?", (old_id,))
                    conn.execute("DELETE FROM snapshots WHERE id = ?", (old_id,))
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute("VACUUM")
        except sqlite3.Error:
            pass
        try:
            self._sign()
        except (OSError, ValueError) as exc:
            # The key is another user's or damaged. The snapshot is kept,
            # unsigned; the report and the events still go out, and the
            # next check says key-unreadable, which is true.
            report.integrity = INTEGRITY_KEY_UNREADABLE
            report.errors.append("the signing key cannot be read; the snapshot was recorded "
                                 f"but not signed: {exc}")
            log.error("startup snapshot: the signing key cannot be read (%s)", exc)
        report.snapshot = Snapshot(snapshot_id, taken_at, len(entries), total_seconds, tuple(failed))
        self._record(report, events)
        return report

    @staticmethod
    def _record(report: SnapshotReport, events: EventStore | None) -> None:
        if events is None:
            return
        integrity = report.integrity_event()
        if integrity is not None:
            events.record(integrity)
        for change in report.changes:
            events.record(change.as_event())

    # ---------------------------------------------------------- integrity

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            return self._unprotect(self.key_path.read_bytes())
        key = secrets.token_bytes(32)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(self._protect(key))
        return key

    def _signature(self, key: bytes) -> str:
        return hmac.new(key, self.db_path.read_bytes(), hashlib.sha256).hexdigest()

    def _sign(self) -> None:
        key = self._load_or_create_key()
        config.atomic_write_text(self.signature_path, self._signature(key))

    def verify_integrity(self) -> str:
        if not self.exists():
            return INTEGRITY_NO_SNAPSHOT
        if not self.signature_path.is_file() or not self.key_path.is_file():
            return INTEGRITY_UNSIGNED
        try:
            key = self._unprotect(self.key_path.read_bytes())
        except (OSError, ValueError):
            return INTEGRITY_KEY_UNREADABLE
        recorded = self.signature_path.read_text(encoding="utf-8").strip()
        if hmac.compare_digest(recorded, self._signature(key)):
            return INTEGRITY_OK
        return INTEGRITY_TAMPERED


# ------------------------------------------------------------------- words

def summarize(store: AutorunsStore) -> tuple[bool, str]:
    """One line for Health and the tab: (ok, text)."""
    if store.exists():
        # The signature first: a file that is there and fails its check is
        # not "no snapshot yet", whether or not SQLite can open it.
        integrity = store.verify_integrity()
        if integrity != INTEGRITY_OK:
            return False, INTEGRITY_MESSAGES.get(integrity, integrity)
        broken = store.unreadable()
        if broken is not None:
            return False, f"the startup snapshots cannot be read: {broken}"
    latest = store.latest()
    if latest is None:
        return True, "no snapshot yet"
    integrity = store.verify_integrity()
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(latest.taken_at))
    if integrity != INTEGRITY_OK:
        return False, INTEGRITY_MESSAGES.get(integrity, integrity)
    count = len(store.snapshots())
    return True, (f"{latest.entries:,} startup item(s) in the snapshot of {when}; "
                  f"{count} snapshot(s) kept")


def describe_report(report: SnapshotReport) -> str:
    # The integrity word leads, on every surface: a snapshot over a tampered
    # store re-signs it, and the status line is where the user would miss it.
    integrity = report.integrity_event()
    lead = f"SNAPSHOTS: {integrity.reasons[0]}. " if integrity is not None else ""
    if report.snapshot is None:
        return lead + "No snapshot was taken: " + ("; ".join(report.errors) or "nothing was collected")
    parts = [f"{report.snapshot.entries:,} startup item(s)"]
    if report.first:
        parts.append("first snapshot, nothing to compare with yet")
    elif report.changes:
        parts.append(f"{len(report.of('added'))} new, {len(report.of('modified'))} changed, "
                     f"{len(report.of('removed'))} gone since the previous snapshot")
    else:
        parts.append("nothing changed since the previous snapshot")
    if report.carried:
        parts.append("kept from the previous snapshot because they could not be read: "
                     + ", ".join(f"{n} {kind}" for kind, n in report.carried.items()))
    if report.errors:
        parts.append(f"{len(report.errors)} collector note(s)")
    return lead + "; ".join(parts) + "."
