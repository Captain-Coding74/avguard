"""The paste guard: a warning when the clipboard holds a paste-and-run command.

The attack this is for (ClickFix, FileFix, the fake CAPTCHA): a web page puts
a command on the clipboard with one click and tells the user to press Win+R,
Ctrl+V, Enter. No file is downloaded until the user has run it, so a file
scanner sees nothing until it is too late. This module reads the clipboard
when it changes and, when the text has the shape of such a command, says so
in plain words, in the seconds between the copy and the Enter.

What it refuses to do, by design. It never writes or clears the clipboard
(a test reads this file and asserts the calls are absent). It never keeps
the text: the event carries the shape of the command, the host it names and
the program that wrote the clipboard, not the command. It never sends
anything. It produces no Finding and no Verdict, so it can never move a
file. It reads nothing when it is off, nothing that was already on the
clipboard when AVGuard started, and nothing an application has marked as
private (the two formats password managers set). It is AVGuard's first
non-file input, and the README says so.

Cost: one user32 call every half second (GetClipboardSequenceNumber needs
no window); the clipboard is opened only when that number changes. No
thread and no timed wait: the tick runs on the Tk thread through after(),
for the reason recorded in ROADMAP.md under "The watcher waits without a
timeout".
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import config
from .events import Event, EventStore

log = logging.getLogger("avguard.clipguard")

WARNING = "warning"
NOTICE = "notice"

# Text longer than this is skipped and counted, never reported: a paste-and-run
# command is a few hundred bytes, a copied log file is not our business.
MAX_TEXT_CHARS = 32_768
PREVIEW_CHARS = 160
# Health goes red only after this many consecutive failed reads: one
# collision with an application holding the clipboard is invisible, a
# clipboard stuck open is loud.
HEALTH_FAILURE_STREAK = 20

CF_UNICODETEXT = 13
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
# Formats an application adds beside its text to say "do not monitor this":
# KeePass sets the first, 1Password and others the second. Present means the
# text is not read at all.
EXCLUSION_FORMATS = ("Clipboard Viewer Ignore", "ExcludeClipboardContentFromMonitorProcessing")

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\ufeff\u00ad"))

# A Run-box or address-bar command has to name a program. That is the central
# false-positive control: an install line typed into an open shell, a
# password, a URL on its own name none of these and match nothing.
_LAUNCHER = re.compile(
    r"(?<![\w.-])(powershell|pwsh|mshta|cmd|wscript|cscript|rundll32|regsvr32|msiexec|"
    r"certutil|bitsadmin|conhost|curl|forfiles|explorer|wmic|msbuild|installutil)(?:\.exe)?(?![\w-])")
_PROTOCOL = re.compile(r"(?<![\w-])(search-ms|ms-appinstaller|ms-msdt|ms-officecmd|ms-search):")
_RUNS_WHAT_IT_FETCHES = {"mshta", "msiexec", "rundll32", "regsvr32", "wscript", "cscript",
                         "msbuild", "installutil", "wmic"}
# The base64 literal is written with one bracketed character so the exact byte
# sequence a shipped YARA rule hunts for never appears in AVGuard's own source
# (rules/malware.yara does the same to itself); the compiled regex is unchanged.
_ENCODED = re.compile(r"(?:^|\s)[-/]e(?:c|n[a-z]*)?\s+[a-z0-9+/=]{40,}|frombase64strin[g]\s*\(|\[convert\]::frombase64")
_FETCH = re.compile(r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|"
                    r"downloaddata|openread|webclient|start-bitstransfer|httpclient|curl|wget|urlcache|"
                    r"/transfer|webrequest)\b")
_EXEC = re.compile(r"\b(?:iex|invoke-expression|start-process|saps|invoke-item|invoke-command|icm|start|call)\b"
                   r"|\.invoke\s*\(|scriptblock\]::create|cmd\s*/[ckr]\b|\|\s*(?:cmd|powershell|pwsh|sh|bash|zsh)\b|&\s*\(")
_URL = re.compile(r"(?:https?|ftps?|wss?)://([^\s/\"'<>()\\]+)")
_BARE_HOST = re.compile(r"(?<![\w@.\\/-])((?:[a-z0-9-]+\.)+(?:[a-z]{2,}|invalid|test)|\d{1,3}(?:\.\d{1,3}){3})(?::\d{2,5})?/[^\s\"'<>()]+")
# A share at an IP address or a WebDAV port is how a lure delivers a script;
# a share by host name is how a company does, so only the first two count.
_WEBDAV_UNC = re.compile(r"\\\\(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+@(?:ssl@)?\d+|[a-z0-9.-]+@ssl)(?:\\|/)")
_INLINE_HTA = re.compile(r"mshta(?:\.exe)?\s+[\"']?(?:vbscript|javascript):")
_HIDDEN = re.compile(r"(?:^|\s)-w(?:indowstyle|in)?\s+(?:h(?:idden)?|1)\b|\bstart\s+/min\b|--headless\b|(?:^|\s)-noni(?:nteractive)?\b")
_DROP = re.compile(r"%(?:temp|tmp|appdata|localappdata|public|programdata)%|\$env:(?:temp|tmp|appdata|localappdata|public|programdata)\b|c:\\users\\public|\\appdata\\(?:local|roaming)\\")
_LURE_COMMENT = re.compile(r"(?:^|\s)(?:#|rem\b)[^\n]*?(?:robot|captcha|turnstile|cloudflare|ray id|verif|human)")
_LURE_MARK = re.compile(r"[\u2705\u2714\u2713\u2611\U0001f512\U0001f6e1]")
_PADDED_COMMENT = re.compile(r"\S[ \t]{12,}#")
_CHARCODE = re.compile(r"\[char\]")
_OBFUSCATION = re.compile(r"-bxor\b|\[array\]::reverse|\[string\]::join|-join\s*\(?\s*\[char\]|\.replace\([^)]*\)\.replace\(")

_LAUNCHER_WORDS = {
    "powershell": "PowerShell", "pwsh": "PowerShell", "mshta": "mshta", "cmd": "the command prompt",
    "wscript": "Windows Script Host", "cscript": "Windows Script Host", "rundll32": "rundll32",
    "regsvr32": "regsvr32", "msiexec": "the Windows Installer", "certutil": "certutil",
    "bitsadmin": "bitsadmin", "conhost": "a hidden console", "curl": "curl", "forfiles": "forfiles",
    "explorer": "Explorer", "wmic": "WMI", "msbuild": "MSBuild", "installutil": "InstallUtil",
}


# ------------------------------------------------------------ classifier

def normalize(text: str) -> str:
    """What the matcher sees: compatibility-folded, zero-width characters and
    cmd caret escapes removed, blank runs kept (the padded comment needs them)."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    text = re.sub(r"\^(?=[^\s^])", "", text)
    return text[:MAX_TEXT_CHARS + 1]


@dataclass(frozen=True)
class Match:
    """A command the guard would warn about, and why. Carries no text beyond
    the on-screen preview, which is never stored."""
    tier: str
    signals: tuple[str, ...]
    launcher: str
    host: str
    sha256: str
    chars: int
    preview: str

    def does(self) -> str:
        """What the command would do, in the words of the banner."""
        who = _LAUNCHER_WORDS.get(self.launcher, self.launcher)
        hidden = "hidden window" in self.signals
        where = f" from {self.host}" if self.host else ""
        if "encoded command" in self.signals:
            return f"start {who}{' hidden' if hidden else ''} and run an encoded command{where}"
        if "remote HTML application" in self.signals or "inline mshta script" in self.signals:
            return f"run an HTML application{where or ' from an inline script'} through mshta"
        if "remote installer package" in self.signals:
            return f"install a package{where} through the Windows Installer"
        if "script from a share at an address" in self.signals:
            return f"run a script from a network share at an address through {who}"
        if "program dropped in a temporary folder" in self.signals:
            return f"download a program{where} into a temporary folder and run it"
        if "obfuscated" in self.signals:
            return f"start {who} and run an obfuscated command{where}"
        if "protocol handler to a remote location" in self.signals:
            return f"open a remote location{where} through the {self.launcher} handler"
        return f"start {who}{' hidden' if hidden else ''} and run code fetched{where}"

    def sentence(self, owner: str | None) -> str:
        who = f"it was copied from {owner}" if owner else \
            "the program that put it there could not be identified"
        if self.tier == WARNING:
            return (f"The clipboard holds a command that would {self.does()}; {who}. This is the "
                    "shape of a fake-CAPTCHA or 'fix this error' scam. If you did not write this "
                    "command yourself, do not paste it.")
        where = f" from {self.host}" if self.host else ""
        return (f"The clipboard holds a {_LAUNCHER_WORDS.get(self.launcher, self.launcher)} command "
                f"that downloads and runs code{where}; {who}. Installers are often shared this way; "
                "a scam page uses the same shape. Paste it only if you trust where you copied it from.")


def classify(text: str) -> Match | None:
    """The shape of a paste-and-run command, or None. Pure; runs anywhere."""
    kept = normalize(text)
    flat = re.sub(r"\s+", " ", kept).strip()
    low = flat.lower()
    if not low:
        return None

    launcher = ""
    found = _LAUNCHER.search(low)
    protocol = _PROTOCOL.search(low)
    if found and (not protocol or found.start() < protocol.start()):
        launcher = found.group(1)
    elif protocol:
        launcher = protocol.group(1) + ":"
    if not launcher:
        return None

    url = _URL.search(low)
    bare = _BARE_HOST.search(low) if not url else None
    host = ""
    if url:
        host = url.group(1).rsplit("@", 1)[-1].split(":", 1)[0]
    elif bare:
        host = bare.group(1)
    unc = _WEBDAV_UNC.search(low)
    remote = bool(host) or bool(unc)
    fetch = remote or bool(_FETCH.search(low))
    runs = bool(_EXEC.search(low)) or launcher in _RUNS_WHAT_IT_FETCHES
    hidden = bool(_HIDDEN.search(low))

    signals: list[str] = []
    if _ENCODED.search(low):
        signals.append("encoded command")
    if launcher == "mshta" and _INLINE_HTA.search(low):
        signals.append("inline mshta script")
    elif launcher == "mshta" and remote:
        signals.append("remote HTML application")
    if launcher == "msiexec" and remote:
        signals.append("remote installer package")
    if launcher in ("rundll32", "regsvr32") and remote:
        signals.append("remote library through " + launcher)
    if unc and launcher in ("wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec",
                            "powershell", "pwsh", "cmd", "explorer", "conhost"):
        signals.append("script from a share at an address")
    if hidden and (remote or fetch):
        signals.append("hidden window")
    if _DROP.search(low) and runs and (fetch or remote):
        signals.append("program dropped in a temporary folder")
    if _LURE_COMMENT.search(low) or _LURE_MARK.search(kept):
        signals.append("fake-verification comment")
    if _PADDED_COMMENT.search(kept):
        signals.append("padded comment")
    if len(_CHARCODE.findall(low)) >= 3 or _OBFUSCATION.search(low):
        signals.append("obfuscated")
    if launcher.endswith(":") and remote:
        signals.append("protocol handler to a remote location")

    if signals:
        tier = WARNING
    elif fetch and runs:
        tier = NOTICE
        signals = ["fetches and runs code"]
    else:
        return None
    return Match(tier=tier, signals=tuple(signals), launcher=launcher, host=host,
                 sha256=hashlib.sha256(flat.encode("utf-8")).hexdigest(), chars=len(flat),
                 preview=flat[:PREVIEW_CHARS])


# ------------------------------------------------------------- sources

@dataclass(frozen=True)
class ClipText:
    text: str
    owner: str | None            # the program that wrote the clipboard, if it can be told
    excluded: bool = False       # an application asked monitors not to read it
    truncated: bool = False      # longer than MAX_TEXT_CHARS; the text here is empty
    chars: int = 0


class ClipboardBusy(RuntimeError):
    """Another application holds the clipboard open; try again next tick."""


class FakeClipboard:
    """A clipboard for tests: every call counted, every state settable."""

    available = True

    def __init__(self, text: str = "", sequence: int = 1, owner: str | None = "test.exe") -> None:
        self.text = text
        self.sequence_value = sequence
        self.owner = owner
        self.excluded = False
        self.busy = False
        self.is_text = True
        self.sequence_calls = 0
        self.read_calls = 0

    def put(self, text: str, owner: str | None = "test.exe") -> None:
        self.text, self.owner = text, owner
        self.sequence_value += 1

    def sequence(self) -> int:
        self.sequence_calls += 1
        return self.sequence_value

    def read(self) -> ClipText | None:
        self.read_calls += 1
        if self.busy:
            raise ClipboardBusy("held by another application")
        if self.excluded:
            return ClipText("", self.owner, excluded=True)
        if not self.is_text:
            return None
        if len(self.text) > MAX_TEXT_CHARS:
            return ClipText("", self.owner, truncated=True, chars=len(self.text))
        return ClipText(self.text, self.owner, chars=len(self.text))


class WindowsClipboard:
    """The real one, through user32 and kernel32. Reads only."""

    available = sys.platform == "win32"

    def __init__(self) -> None:
        self._user32 = None
        self._kernel32 = None
        self._exclusion_formats: tuple[int, ...] = ()
        if self.available:
            self._bind()

    def _bind(self) -> None:
        wt = ctypes.wintypes  # type: ignore[attr-defined]
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.GetClipboardSequenceNumber.restype = wt.DWORD
        user32.OpenClipboard.argtypes = [wt.HWND]
        user32.OpenClipboard.restype = wt.BOOL
        user32.CloseClipboard.restype = wt.BOOL
        user32.IsClipboardFormatAvailable.argtypes = [wt.UINT]
        user32.IsClipboardFormatAvailable.restype = wt.BOOL
        user32.GetClipboardData.argtypes = [wt.UINT]
        user32.GetClipboardData.restype = wt.HANDLE
        user32.RegisterClipboardFormatW.argtypes = [wt.LPCWSTR]
        user32.RegisterClipboardFormatW.restype = wt.UINT
        user32.GetClipboardOwner.restype = wt.HWND
        user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        user32.GetWindowThreadProcessId.restype = wt.DWORD
        kernel32.GlobalSize.argtypes = [wt.HGLOBAL]
        kernel32.GlobalSize.restype = ctypes.c_size_t
        kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalLock.restype = wt.LPVOID
        kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalUnlock.restype = wt.BOOL
        kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        kernel32.OpenProcess.restype = wt.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR,
                                                        ctypes.POINTER(wt.DWORD)]
        kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
        kernel32.CloseHandle.argtypes = [wt.HANDLE]
        kernel32.CloseHandle.restype = wt.BOOL
        self._user32, self._kernel32 = user32, kernel32
        self._exclusion_formats = tuple(user32.RegisterClipboardFormatW(name)
                                        for name in EXCLUSION_FORMATS)

    def sequence(self) -> int:
        """Changes on every clipboard write; 0 when this process may not read it."""
        return int(self._user32.GetClipboardSequenceNumber())

    def read(self) -> ClipText | None:
        """The text on the clipboard, or None when it holds something else.
        Raises ClipboardBusy when another application has it open."""
        user32, kernel32 = self._user32, self._kernel32
        if not user32.OpenClipboard(None):
            raise ClipboardBusy(f"OpenClipboard failed (error {ctypes.get_last_error()})")
        try:
            owner = self._owner()
            if any(user32.IsClipboardFormatAvailable(fmt) for fmt in self._exclusion_formats if fmt):
                return ClipText("", owner, excluded=True)
            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return None
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            chars = int(kernel32.GlobalSize(handle)) // 2
            if chars > MAX_TEXT_CHARS:
                return ClipText("", owner, truncated=True, chars=chars)
            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                return None
            try:
                text = ctypes.wstring_at(pointer, chars)
            finally:
                kernel32.GlobalUnlock(handle)
            text = text.split("\0", 1)[0]
            return ClipText(text, owner, chars=len(text))
        finally:
            user32.CloseClipboard()

    def _owner(self) -> str | None:
        """The program whose window owns the clipboard, by image name, or None."""
        user32, kernel32 = self._user32, self._kernel32
        try:
            hwnd = user32.GetClipboardOwner()
            if not hwnd:
                return None
            pid = ctypes.wintypes.DWORD(0)  # type: ignore[attr-defined]
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not pid.value:
                return None
            process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
            if not process:
                return None
            try:
                buffer = ctypes.create_unicode_buffer(32768)
                size = ctypes.wintypes.DWORD(len(buffer))  # type: ignore[attr-defined]
                if not kernel32.QueryFullProcessImageNameW(process, 0, buffer, ctypes.byref(size)):
                    return None
                return os.path.basename(buffer.value).lower() or None
            finally:
                kernel32.CloseHandle(process)
        except (OSError, ValueError, AttributeError):
            return None


# --------------------------------------------------------------- guard

@dataclass
class Counters:
    changes_seen: int = 0
    texts_read: int = 0
    skipped_excluded: int = 0
    skipped_not_text: int = 0
    skipped_too_long: int = 0
    ignored: int = 0
    notices: int = 0
    warnings: int = 0
    read_failures: int = 0
    consecutive_failures: int = 0
    last_error: str = ""
    zero_sequence: bool = False


class PasteGuard:
    """Owns the tick, the counters and the ignore list. One instance per window.

    `notify(match, clip)` is called on the thread that called tick(), which in
    the GUI is the Tk thread, so it may touch widgets directly.
    """

    def __init__(self, source, events: EventStore | None,
                 notify: Callable[[Match, ClipText], None] | None = None,
                 ignore_path: Path | None = None) -> None:
        self.source = source
        self.events = events
        self.notify = notify
        self.ignore_path = Path(ignore_path) if ignore_path else config.DATA_DIR / "clipboard_ignore.json"
        self.counters = Counters()
        self._last_sequence: int | None = None
        self._ignored: set[str] = set()
        self._ignore_mtime: float | None = None

    # ---------------------------------------------------------------- tick

    def tick(self) -> Match | None:
        """One poll. Reads the clipboard only when its sequence number moved."""
        if not getattr(self.source, "available", False):
            return None
        sequence = self.source.sequence()
        if sequence == 0:
            # No access to the clipboard at all (a locked session, a service
            # desktop). Said in Health rather than silently read as "quiet".
            self.counters.zero_sequence = True
            return None
        self.counters.zero_sequence = False
        if self._last_sequence is None:
            # Whatever was on the clipboard when AVGuard started is not examined.
            self._last_sequence = sequence
            return None
        if sequence == self._last_sequence:
            return None
        try:
            clip = self.source.read()
        except ClipboardBusy as exc:
            self.counters.read_failures += 1
            self.counters.consecutive_failures += 1
            self.counters.last_error = str(exc)
            return None          # the sequence stays unmoved, so the next tick retries
        self._last_sequence = sequence
        self.counters.changes_seen += 1
        self.counters.consecutive_failures = 0
        if clip is None:
            self.counters.skipped_not_text += 1
            return None
        if clip.excluded:
            self.counters.skipped_excluded += 1
            return None
        if clip.truncated:
            self.counters.skipped_too_long += 1
            log.debug("clipboard text of %d characters skipped (above %d)", clip.chars, MAX_TEXT_CHARS)
            return None
        self.counters.texts_read += 1
        match = classify(clip.text)
        if match is None:
            return None
        if match.sha256 in self.ignored():
            self.counters.ignored += 1
            return None
        if match.tier == WARNING:
            self.counters.warnings += 1
        else:
            self.counters.notices += 1
        if self.events is not None:
            self.events.record(Event(
                kind="clipboard", path="", level=match.tier, score=0,
                reasons=[match.sentence(clip.owner)],
                detail={"signals": list(match.signals), "launcher": match.launcher, "host": match.host,
                        "owner": clip.owner or "", "sha256": match.sha256, "chars": match.chars,
                        "sequence": sequence}))
        if self.notify is not None:
            self.notify(match, clip)
        return match

    # ---------------------------------------------------------- ignore list

    def ignored(self) -> set[str]:
        """SHA-256s of normalized texts the user said not to warn about again."""
        try:
            mtime = self.ignore_path.stat().st_mtime
        except OSError:
            self._ignored, self._ignore_mtime = set(), None
            return self._ignored
        if mtime != self._ignore_mtime:
            try:
                raw = json.loads(self.ignore_path.read_text(encoding="utf-8"))
                self._ignored = {str(item) for item in raw} if isinstance(raw, list) else set()
            except (OSError, ValueError) as exc:
                log.warning("the clipboard ignore list could not be read (%s); treating it as empty", exc)
                self._ignored = set()
            self._ignore_mtime = mtime
        return self._ignored

    def ignore(self, match: Match) -> None:
        """Never warn about this exact text again. A user action."""
        current = set(self.ignored())
        current.add(match.sha256)
        self.ignore_path.parent.mkdir(parents=True, exist_ok=True)
        config.atomic_write_text(self.ignore_path, json.dumps(sorted(current), indent=1))
        self._ignore_mtime = None

    # --------------------------------------------------------------- health

    @property
    def healthy(self) -> bool:
        return (not self.counters.zero_sequence
                and self.counters.consecutive_failures < HEALTH_FAILURE_STREAK)

    def describe(self) -> str:
        c = self.counters
        if c.zero_sequence:
            return ("the clipboard cannot be read from this session (sequence number 0); "
                    "nothing is being checked")
        if c.consecutive_failures >= HEALTH_FAILURE_STREAK:
            return (f"the clipboard has been held open by another program for "
                    f"{c.consecutive_failures} checks ({c.last_error}); nothing is being checked")
        skipped = c.skipped_excluded + c.skipped_not_text + c.skipped_too_long
        return (f"on: {c.changes_seen} change(s) seen, {c.texts_read} read as text, {skipped} skipped "
                f"(private, not text or too long), {c.notices} notice(s), {c.warnings} warning(s); "
                "nothing is kept and nothing leaves this machine")
