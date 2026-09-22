"""'Scan with AVGuard' in Explorer's right-click menu.

The GUI and the CLI both require going to AVGuard. The Windows antivirus
gesture is right-clicking a suspicious download. Two per-user registry keys
under HKCU\\Software\\Classes -- one for files, one for folders -- add the
entry with no administrator rights, and removing them removes exactly the
entry and nothing else.

What the entry runs is the console scanner with `--pause`, so the result
stays on screen: a console window that closes when the scan ends would show
nothing, and the windowed build has no console at all, so `--pause` shows
the summary in a small window instead. If the AVGuard window is open the
scan still runs; only moving a file is refused, because two processes
writing the quarantine store at once destroy its records (the single-
instance lock in instance.py, which the CLI already honours).

Every registry call goes through `registry`, which defaults to winreg on
Windows and to nothing elsewhere. The tests hand in a dict-backed fake and
never touch the real registry.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

log = logging.getLogger(__name__)

VERB = "AVGuard.Scan"
LABEL = "Scan with AVGuard"
KEY_PATHS = (
    "Software\\Classes\\*\\shell\\" + VERB,
    "Software\\Classes\\Directory\\shell\\" + VERB,
)


def _default_registry():
    try:
        import winreg
    except ImportError:
        return None
    return winreg


def runner() -> tuple[str, list[str]]:
    """The executable that scans, and the arguments before `--scan`.

    Frozen: the one executable. Otherwise python.exe, deliberately not
    pythonw.exe: the result has to be visible.
    """
    if getattr(sys, "frozen", False):
        return sys.executable, []
    interpreter = Path(sys.executable)
    if interpreter.name.lower() == "pythonw.exe":
        console = interpreter.with_name("python.exe")
        if console.exists():
            interpreter = console
    return str(interpreter), ["-m", "avguard"]


def _quote(text: str) -> str:
    # A Windows path cannot contain a double quote, so wrapping is enough;
    # spaces and non-ASCII (Thai, Chinese) pass through untouched.
    return f'"{text}"'


def command_string() -> str:
    exe, args = runner()
    return " ".join([_quote(exe), *args, "--scan", '"%1"', "--pause"])


def icon_string() -> str:
    exe, _ = runner()
    return _quote(exe)


def install(registry=None) -> tuple[bool, str]:
    """Write the two keys for the current user."""
    reg = registry if registry is not None else _default_registry()
    if reg is None:
        return False, "only supported on Windows"
    command = command_string()
    try:
        for key_path in KEY_PATHS:
            with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_WRITE) as key:
                reg.SetValueEx(key, "", 0, reg.REG_SZ, LABEL)
                reg.SetValueEx(key, "MUIVerb", 0, reg.REG_SZ, LABEL)
                reg.SetValueEx(key, "Icon", 0, reg.REG_SZ, icon_string())
                with reg.CreateKeyEx(key, "command", 0, reg.KEY_WRITE) as command_key:
                    reg.SetValueEx(command_key, "", 0, reg.REG_SZ, command)
    except OSError as exc:
        return False, f"could not write the registry keys: {exc}"
    log.info("right-click scan installed for this user: %s", command)
    return True, f"installed for this user; it runs: {command}"


def uninstall(registry=None) -> tuple[bool, str]:
    """Delete exactly the two keys, command subkey first. Absent is fine."""
    reg = registry if registry is not None else _default_registry()
    if reg is None:
        return False, "only supported on Windows"
    try:
        for key_path in KEY_PATHS:
            for sub_path in (key_path + "\\command", key_path):
                try:
                    reg.DeleteKey(reg.HKEY_CURRENT_USER, sub_path)
                except FileNotFoundError:
                    pass
    except OSError as exc:
        return False, f"could not remove the registry keys: {exc}"
    log.info("right-click scan removed for this user")
    return True, "removed"


def installed(registry=None) -> bool:
    reg = registry if registry is not None else _default_registry()
    if reg is None:
        return False
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, KEY_PATHS[0] + "\\command", 0, reg.KEY_READ) as key:
            value, _ = reg.QueryValueEx(key, "")
    except OSError:
        return False
    return bool(value)
