"""Starting with Windows, and running a scan on a schedule.

Both are done without administrator rights, which rules out a service and
rules out the machine-wide `HKLM` Run key. What is left:

  * **Start with Windows** -- a `.lnk` in the user's Startup folder. Visible in
    Task Manager's Startup tab, removable by the user without going anywhere
    near this program, and needing no elevation. The `HKCU\\...\\Run` registry
    key would also work, but a shortcut is something the user can see, inspect
    and delete in Explorer, and that matters for a program that watches files.

  * **Scheduled scan** -- `schtasks`, which is the built-in scheduler and can
    create a per-user task with no elevation.

Both are entirely optional, both are reversible from inside the program, and
neither is turned on by anything except the user asking for it.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import config

log = logging.getLogger(__name__)

TASK_NAME = "AVGuard Scheduled Scan"
SHORTCUT_NAME = "AVGuard.lnk"

# Hidden window so a subprocess call never flashes a console at the user.
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


@dataclass
class ScheduleStatus:
    starts_with_windows: bool = False
    scheduled_scan: bool = False
    detail: str = ""


def _startup_dir() -> Path:
    appdata = os.getenv("APPDATA")
    base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    return base / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def shortcut_path() -> Path:
    return _startup_dir() / SHORTCUT_NAME


def _launcher() -> tuple[str, str]:
    """The command that starts AVGuard, and its arguments.

    Prefers `pythonw.exe` so no console window appears. That is also why
    `logsetup.install_excepthooks()` exists: under pythonw there is no stderr,
    so a crash would otherwise leave no trace at all.
    """
    if getattr(sys, "frozen", False):
        return sys.executable, ""
    interpreter = Path(sys.executable)
    windowless = interpreter.with_name("pythonw.exe")
    runner = windowless if windowless.exists() else interpreter
    return str(runner), f'-m avguard'


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=30,
                                creationflags=_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output.strip()


# ----------------------------------------------------------- start with Windows

def starts_with_windows() -> bool:
    return shortcut_path().exists()


def enable_start_with_windows() -> tuple[bool, str]:
    """Write a shortcut into the user's Startup folder."""
    if sys.platform != "win32":
        return False, "only supported on Windows"

    target, arguments = _launcher()
    link = shortcut_path()
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"could not reach the Startup folder: {exc}"

    # Built through the Windows shell rather than by writing .lnk bytes by hand.
    script = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{link}');"
        "$s.TargetPath = '{target}';"
        "$s.Arguments = '{arguments}';"
        "$s.WorkingDirectory = '{cwd}';"
        "$s.Description = 'AVGuard file scanner';"
        "$s.Save()"
    ).format(link=str(link).replace("'", "''"),
             target=target.replace("'", "''"),
             arguments=arguments.replace("'", "''"),
             cwd=str(config.PROJECT_ROOT).replace("'", "''"))

    ok, output = _run(["powershell", "-NoProfile", "-NonInteractive",
                       "-ExecutionPolicy", "Bypass", "-Command", script])
    if not ok:
        return False, output or "could not create the shortcut"
    if not link.exists():
        return False, "the shortcut was not created"
    log.info("AVGuard will start with Windows (%s)", link)
    return True, str(link)


def disable_start_with_windows() -> tuple[bool, str]:
    link = shortcut_path()
    try:
        link.unlink(missing_ok=True)
    except OSError as exc:
        return False, str(exc)
    log.info("AVGuard will no longer start with Windows")
    return True, "removed"


# --------------------------------------------------------------- scheduled scan

def scheduled_scan_exists() -> bool:
    ok, _ = _run(["schtasks", "/Query", "/TN", TASK_NAME])
    return ok


def enable_scheduled_scan(target: Path, time_of_day: str = "12:00") -> tuple[bool, str]:
    """Create a daily per-user scan task.

    The task only ever *reports*. It deliberately does not pass --quarantine:
    a scan running unattended, with nobody to read the result, is the last
    place that should be allowed to move somebody's files.
    """
    if sys.platform != "win32":
        return False, "only supported on Windows"

    runner, _ = _launcher()
    command = f'"{runner}" -m avguard --scan "{target}"'

    ok, output = _run(["schtasks", "/Create", "/F", "/SC", "DAILY",
                       "/TN", TASK_NAME, "/TR", command, "/ST", time_of_day])
    if not ok:
        return False, output or "schtasks refused to create the task"
    log.info("scheduled a daily scan of %s at %s", target, time_of_day)
    return True, f"daily at {time_of_day}"


def disable_scheduled_scan() -> tuple[bool, str]:
    ok, output = _run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME])
    if not ok and "cannot find" not in output.lower():
        return False, output
    log.info("removed the scheduled scan")
    return True, "removed"


def status() -> ScheduleStatus:
    if sys.platform != "win32":
        return ScheduleStatus(detail="scheduling is only supported on Windows")
    return ScheduleStatus(
        starts_with_windows=starts_with_windows(),
        scheduled_scan=scheduled_scan_exists(),
    )
