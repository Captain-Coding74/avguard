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
                    r"webrequest)\b|(?<!\S)/transfer\b")
# "start" the verb, not Start-Sleep or Start-Service.
_EXEC = re.compile(r"\b(?:iex|invoke-expression|start-process|saps|invoke-item|invoke-command|icm|call)\b"
                   r"|\bstart\b(?!-)|\.invoke\s*\(|scriptblock\]::create|cmd\s*/[ckr]\b"
                   r"|\|\s*(?:cmd|powershell|pwsh|sh|bash|zsh)\b|&\s*\(")
# A program file named right after a command separator is run: the second
# half of "fetch it, then run it" when no verb says so.
_RUN_FILE = re.compile(r"[&;|]\s*\"?[^\s\"&|;]+\.(?:exe|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|scr|com)\"?"
                       r"(?=[\s&|;]|$)")
# The host stops at the first character that cannot be in one, so a lure
# written "https://a|iex" names the host "a", not "a|iex".
# ...and the authority ends at the first "/", "?" or "#" before the user part
# is cut away, or "https://evil.invalid#@example.com/x" (fetched from
# evil.invalid) would be reported as example.com.
_URL = re.compile(r"(?:https?|ftps?|wss?)://(?:[^\s/?#@\"'<>()\\]*@)?([\w.-]+|\[[0-9a-f:.]+\])")
_URL_TOKEN = re.compile(r"(?:https?|ftps?|wss?)://[^\s\"'<>|&;()]+")
_BARE_HOST = re.compile(r"(?<![\w@.\\/-])((?:[a-z0-9-]+\.)+(?:[a-z]{2,}|invalid|test)|\d{1,3}(?:\.\d{1,3}){3})(?::\d{2,5})?/[^\s\"'<>()]+")
# A share at an IP address or a WebDAV port is how a lure delivers a script;
# a share by host name is how a company does, so only the first two count.
_WEBDAV_UNC = re.compile(r"\\\\(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+@(?:ssl@)?\d+|[a-z0-9.-]+@ssl)(?:\\|/)")
_INLINE_HTA = re.compile(r"mshta(?:\.exe)?\s+[\"']?(?:vbscript|javascript):")


def _prefixes(word: str, shortest: int) -> str:
    """PowerShell takes any unambiguous prefix of a parameter or an enum value,
    so "-w hid", "-window Hidden" and "-noni" all mean the whole word."""
    return "|".join(word[:n] for n in range(len(word), shortest - 1, -1))


_HIDDEN = re.compile(rf"(?:^|\s)-(?:{_prefixes('windowstyle', 1)})\s+(?:{_prefixes('hidden', 1)}|1)\b"
                     rf"|\bstart\s+/min\b|--headless\b|(?:^|\s)-(?:{_prefixes('noninteractive', 3)})\b")
_DROP = re.compile(r"%(?:temp|tmp|appdata|localappdata|public|programdata)%|\$env:(?:temp|tmp|appdata|localappdata|public|programdata)\b|c:\\users\\public|\\appdata\\(?:local|roaming)\\")
# Matched line by line: the comment and the lure words must share a line.
# The words are the lure's, not any comment's: "# verify the server is up"
# is a comment.
# The Thai twins of those words, each a phrase, not a word: Thai writes no
# spaces between words, so every alternative is a substring, and "bot" alone
# is inside "chatbot", "automated program" inside "run the program
# automatically", "verify" inside every honest "confirm that the server is
# up". Each phrase is the text of a real verification widget in Thai (Google
# reCAPTCHA's checkbox, hCaptcha's, Cloudflare's challenge page, ALTCHA's and
# Anubis's) or of the one Thai localization table found in public ClickFix
# kits; each was put to a skeptic who looked for it in honest Thai developer
# comments. What was refused, and why, is in ROADMAP.md ("Thai lure words").
# Segments may be written with a space between them; a zero-width space,
# which Thai pages put between words, is gone after normalize().
_THAI_LURE_PHRASES = (
    ("ไม่ใช่", "หุ่นยนต์"),                       # not a robot (the kit, widgets)
    ("ไม่ใช่", "โปรแกรม", "อัตโนมัติ"),           # not an automated program (reCAPTCHA v2)
    ("ไม่ใช่", "บอท"), ("ไม่ใช่", "บอต"), ("ไม่ใช่", "บ็อต"),   # not a bot (ALTCHA, Anubis)
    ("ฉัน", "ไม่ใช่"),                            # I am not
    ("เป็น", "มนุษย์"),                           # are human (hCaptcha, Cloudflare)
    ("รหัส", "ยืนยัน"),                           # verification code (the kit's tail)
    ("การ", "เข้าชม", "ที่", "ผิดปกติ"),          # unusual traffic (Google's block page)
    ("ตรวจสอบ", "ความปลอดภัย", "ของ", "การเชื่อมต่อ", "ของ", "คุณ"),   # security check of your connection
)


def _thai_alternatives(phrases) -> str:
    """The phrases as regex alternatives, in the form normalize() leaves text
    in. NFKC splits SARA AM (U+0E33) into NIKHAHIT + SARA AA, the one Thai
    character it changes, so a literal typed with it would never match
    normalized text; folding the pattern the same way makes either spelling
    match. Thai has no case, so lower() changes nothing here."""
    return "|".join(" ?".join(re.escape(unicodedata.normalize("NFKC", part)) for part in phrase)
                    for phrase in phrases)


_LURE_COMMENT = re.compile(
    r"(?:^|\s)(?:#|rem\b)[^\n]*?(?:robot|captcha|turnstile|cloudflare|ray id|"
    r"verif(?:y|ication) (?:you|that you|your|i am|i'm|id\b|code\b|hash\b|step\b|token\b|complete|required|success)|"
    r"(?:are|am|a|not) human|human verification|i am not|i'm not|press enter|unusual traffic|security check|"
    # "Cloud Identificator: 2031" (Unit 42, July 2025; Microsoft, August 2025):
    # the one reported English tail none of the words above caught. Never
    # bare "identificator", which is Romanian and Italian and ordinary in
    # non-native English comments; "cloud" whole, so "icloud" is not it.
    r"\bcloud ?identificator|"
    + _thai_alternatives(_THAI_LURE_PHRASES) + ")")
_LURE_MARK = re.compile(r"[\u2705\u2714\u2713\u2611\U0001f512\U0001f6e1]")
_PADDED_COMMENT = re.compile(r"\S[ \t]{12,}#")
_CHARCODE = re.compile(r"\[char\]")
_OBFUSCATION = re.compile(r"-bxor\b|\[array\]::reverse|\[string\]::join|-join\s*\(?\s*\[char\]|\.replace\([^)]*\)\.replace\(")

# Tokens after which the next word is a command: "cmd /c powershell", "start
# powershell", "conhost --headless powershell", "a && b".
# (No encoded-command flag here: a base64 blob follows it, never a launcher,
# and the literal is one a shipped rule hunts for in AVGuard's own source.)
_COMMAND_LEADERS = {"/c", "/k", "/r", "/min", "--headless", "&&", "||", "|", ";", "start", "call",
                    "-command", "-c", "-file"}


_POSITION_CHARS = "\"'\\/@&|;(=\n"


def _in_command_position(lines: str, start: int) -> bool:
    """Whether what begins at `start` sits where a command sits: at the start
    of the text or of a line, after a path separator, quote or hand-off
    character, or after a token that hands over to a command.

    A Run-box string begins with its program, or reaches it through a path, a
    quote or a hand-off token; a lure's instructions put the command on its
    own line. A launcher word in the middle of a sentence ("open cmd and run
    powershell to check") is prose, and prose with a URL and the word "start"
    in it used to earn a notice.
    """
    before = lines[:start]
    if not before.strip():
        return True
    previous = before[-1]
    if previous in _POSITION_CHARS:
        return True
    if previous == " ":
        token = before.split()[-1]
        return token in _COMMAND_LEADERS or token.endswith(("&&", "||", "|", ";"))
    return False


def _launcher(lines: str) -> str:
    """The first launcher, else the first protocol handler, in command
    position; else empty. A launcher word inside a URL
    (github.com/PowerShell/PowerShell) is a path, not a program."""
    urls = [found.span() for found in _URL_TOKEN.finditer(lines)]

    def inside_url(position: int) -> bool:
        return any(start <= position < end for start, end in urls)

    for found in _LAUNCHER.finditer(lines):
        if not inside_url(found.start()) and _in_command_position(lines, found.start()):
            return found.group(1)
    for found in _PROTOCOL.finditer(lines):
        if not inside_url(found.start()) and _in_command_position(lines, found.start()):
            return found.group(1) + ":"      # a URI pasted into Run is its own launcher
    return ""


def _is_loopback(host: str) -> bool:
    """This machine is not a remote location."""
    return host in ("localhost", "::1", "0.0.0.0", "[::1]") or host.startswith("127.")


_LAUNCHER_WORDS = {
    "powershell": "PowerShell", "pwsh": "PowerShell", "mshta": "mshta", "cmd": "the command prompt",
    "wscript": "Windows Script Host", "cscript": "Windows Script Host", "rundll32": "rundll32",
    "regsvr32": "regsvr32", "msiexec": "the Windows Installer", "certutil": "certutil",
    "bitsadmin": "bitsadmin", "conhost": "a console", "curl": "curl", "forfiles": "forfiles",
    "explorer": "Explorer", "wmic": "WMI", "msbuild": "MSBuild", "installutil": "InstallUtil",
}


# ------------------------------------------------------------ classifier

def normalize(text: str) -> str:
    """What the matcher sees: compatibility-folded, every Unicode format
    character (category Cf: zero-width joiners, bidi controls, the soft
    hyphen, tag characters) and cmd caret escapes removed, blank runs kept
    (the padded comment needs them). Nothing in Cf can appear in a command
    that runs; anything in Cf can hide one from a pattern."""
    if not text.isascii():
        # Half of a UTF-16 pair, which a clipboard can hold, has no UTF-8
        # form and would stop the hash below; it becomes U+FFFD here.
        text = text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
        text = unicodedata.normalize("NFKC", text)
        text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = re.sub(r"\^(?=[^\s^])", "", text)
    return text[:MAX_TEXT_CHARS + 1]


@dataclass(frozen=True)
class Match:
    """A command the guard would warn about, and why. Carries the launcher,
    the host, the signals and a hash for the ignore list, never the text."""
    tier: str
    signals: tuple[str, ...]
    launcher: str
    host: str
    sha256: str
    chars: int

    def does(self) -> str:
        """What the command would do, in the words of the banner."""
        who = _LAUNCHER_WORDS.get(self.launcher, self.launcher)
        hidden = " in a hidden window" if "hidden window" in self.signals else ""
        where = f" from {self.host}" if self.host else ""
        if "encoded command" in self.signals:
            return f"start {who}{hidden} and run an encoded command{where}"
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
        return f"start {who}{hidden} and run code it downloads{where}"

    def sentence(self, owner: str | None) -> str:
        wrote = f"it was copied from {owner}" if owner else \
            "the program that put it there could not be identified"
        if self.tier == WARNING:
            return (f"The clipboard holds a command that would {self.does()}; {wrote}. This is the "
                    "shape of a fake-CAPTCHA or 'fix this error' scam. If you did not write this "
                    "command yourself, do not paste it.")
        where = f" from {self.host}" if self.host else ""
        return (f"The clipboard holds a command that starts "
                f"{_LAUNCHER_WORDS.get(self.launcher, self.launcher)} and downloads and runs code"
                f"{where}; {wrote}. Installers are often shared this way; a scam page uses the same "
                "shape. Paste it only if you trust where you copied it from.")


def classify(text: str) -> Match | None:
    """The shape of a paste-and-run command, or None. Pure; runs anywhere."""
    kept = normalize(text)
    # `spaced` keeps line breaks (a line start is a command position, and a
    # lure comment has to share its line with its words); `flat` is one line.
    spaced = re.sub(r"\s*\n\s*", "\n", re.sub(r"[^\S\n]+", " ", kept)).strip()
    flat = spaced.replace("\n", " ")
    low = flat.lower()
    if not low:
        return None

    launcher = _launcher(spaced.lower())
    if not launcher:
        return None

    url = _URL.search(low)
    bare = _BARE_HOST.search(low) if not url else None
    host = url.group(1) if url else bare.group(1) if bare else ""
    local = _is_loopback(host)
    if local or len(host) > 253:
        host = ""                     # this machine, or not a host name at all
    unc = _WEBDAV_UNC.search(low)
    remote = (bool(url or bare) and not local) or bool(unc)
    fetch = remote or bool(_FETCH.search(low))
    runs = bool(_EXEC.search(low)) or bool(_RUN_FILE.search(low)) or launcher in _RUNS_WHAT_IT_FETCHES
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
    if launcher.endswith(":") and remote:
        signals.append("protocol handler to a remote location")
    # The dressing: a comment, a checkmark, padding, obfuscation. Each is a
    # strong sign on a command that fetches and runs or already looks wrong,
    # and none is one on its own: "curl -I https://example.com # verify the
    # server is up" is a comment, "1 -bxor 2" is arithmetic.
    if signals or (fetch and runs):
        if _LURE_COMMENT.search(spaced.lower()) or _LURE_MARK.search(kept):
            signals.append("fake-verification comment")
        if _PADDED_COMMENT.search(kept):
            signals.append("padded comment")
        if len(_CHARCODE.findall(low)) >= 3 or _OBFUSCATION.search(low):
            signals.append("obfuscated")

    if signals:
        tier = WARNING
    elif fetch and runs:
        tier = NOTICE
        signals = ["fetches and runs code"]
    else:
        return None
    return Match(tier=tier, signals=tuple(signals), launcher=launcher, host=host,
                 sha256=hashlib.sha256(flat.encode("utf-8")).hexdigest(), chars=len(flat))


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


def _last_error() -> int:
    return getattr(ctypes, "get_last_error", lambda: 0)()


class WindowsClipboard:
    """The real one, through user32 and kernel32. Reads only."""

    available = sys.platform == "win32"
    unavailable_reason = "unavailable on this platform"

    def __init__(self) -> None:
        self._user32 = None
        self._kernel32 = None
        self._wt = None
        self._exclusion_formats: tuple[int, ...] = ()
        if self.available:
            self._bind()
            self._register_exclusion_formats()

    def _bind(self) -> None:
        # `import ctypes` does not import the wintypes submodule; done here so
        # the module imports everywhere and binds only where it can run.
        import ctypes.wintypes as wt
        self._wt = wt
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
        user32.IsHungAppWindow.argtypes = [wt.HWND]
        user32.IsHungAppWindow.restype = wt.BOOL
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

    def _register_exclusion_formats(self) -> None:
        """The two privacy formats, by number. If either cannot be registered
        the guard cannot honour it, so it reads nothing rather than read what
        a password manager asked it not to."""
        formats = tuple(int(self._user32.RegisterClipboardFormatW(name)) for name in EXCLUSION_FORMATS)
        if not all(formats):
            self.available = False
            self.unavailable_reason = ("the clipboard's privacy formats could not be registered "
                                       f"(error {_last_error()}), so the clipboard is not read")
            log.error("paste guard: %s", self.unavailable_reason)
        self._exclusion_formats = formats

    def sequence(self) -> int:
        """Changes on every clipboard write; 0 when this process may not read it."""
        return int(self._user32.GetClipboardSequenceNumber())

    def read(self) -> ClipText | None:
        """The text on the clipboard, or None when it holds something else.
        Raises ClipboardBusy when another application has it open."""
        user32, kernel32 = self._user32, self._kernel32
        if not user32.OpenClipboard(None):
            raise ClipboardBusy(f"OpenClipboard failed (error {_last_error()})")
        try:
            hwnd = user32.GetClipboardOwner()
            owner = self._image_name(hwnd) if hwnd else None
            if any(user32.IsClipboardFormatAvailable(fmt) for fmt in self._exclusion_formats):
                return ClipText("", owner, excluded=True)
            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return None
            if hwnd and user32.IsHungAppWindow(hwnd):
                # An owner that delayed rendering and stopped answering would
                # hold GetClipboardData, and this thread, until it recovers.
                raise ClipboardBusy("the clipboard's owner is not responding")
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
                # From the raw UTF-16 bytes rather than through wchar_t: half
                # of a surrogate pair becomes U+FFFD here, not a str that can
                # neither be hashed nor written as UTF-8.
                text = ctypes.string_at(pointer, chars * 2).decode("utf-16-le", "replace")
            finally:
                kernel32.GlobalUnlock(handle)
            text = text.split("\0", 1)[0]
            return ClipText(text, owner, chars=len(text))
        finally:
            user32.CloseClipboard()

    def _image_name(self, hwnd) -> str | None:
        """The program behind a window, by image name, or None."""
        user32, kernel32 = self._user32, self._kernel32
        try:
            pid = self._wt.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not pid.value:
                return None
            process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
            if not process:
                return None
            try:
                buffer = ctypes.create_unicode_buffer(32768)
                size = self._wt.DWORD(len(buffer))
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
        try:
            sequence = self.source.sequence()
        except Exception as exc:                  # a binding or OS failure: counted, not fatal
            self._failed(exc, unexpected=True)
            return None
        # 0 is what a window station reports before anything has been copied
        # on it, and also what one reports to a process that may not read its
        # clipboard. The two cannot be told apart from here, so Health says
        # both and the number is tracked like any other.
        self.counters.zero_sequence = sequence == 0
        if self._last_sequence is None:
            # Whatever was on the clipboard when AVGuard started is not examined.
            self._last_sequence = sequence
            return None
        if sequence == self._last_sequence:
            return None
        try:
            clip = self.source.read()
        except ClipboardBusy as exc:
            self._failed(exc)
            return None          # the sequence stays unmoved, so the next tick retries
        except Exception as exc:                  # a binding or OS failure: counted, not fatal
            self._failed(exc, unexpected=True)
            self._last_sequence = sequence        # and not retried twice a second
            return None
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
            # Recorded for History and never forwarded, whatever forwarding
            # URL is set: "sends nothing" is the guard's promise, and a hash
            # or length of a short command is a lookup away from the command,
            # so neither is here either.
            self.events.record(Event(
                kind="clipboard", path="", level=match.tier, score=0,
                reasons=[match.sentence(clip.owner)],
                detail={"signals": list(match.signals), "launcher": match.launcher,
                        "host": match.host, "owner": clip.owner or ""}), forward=False)
        if self.notify is not None:
            self.notify(match, clip)
        return match

    def disarm(self) -> None:
        """Forget where the clipboard was. Called on every tick while the guard
        is off, so what was copied in the meantime is never examined: the
        first tick after it comes back only records the sequence number."""
        self._last_sequence = None

    def _failed(self, exc: BaseException, unexpected: bool = False) -> None:
        c = self.counters
        c.read_failures += 1
        c.consecutive_failures += 1
        c.last_error = f"{type(exc).__name__}: {exc}" if unexpected else str(exc)
        if unexpected:
            # The traceback once per streak: a guard that fails on every tick
            # must not write a hundred and twenty of them a minute.
            (log.exception if c.consecutive_failures == 1 else log.debug)(
                "the clipboard could not be read: %s", c.last_error)

    # ---------------------------------------------------------- ignore list

    def ignored(self) -> set[str]:
        """SHA-256s of normalized texts the user said not to warn about again.
        Unkeyed: the file sits beside the configuration, and a key beside it
        would protect it from nobody who can read it. It never leaves disk."""
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
        return self.counters.consecutive_failures < HEALTH_FAILURE_STREAK

    def describe(self) -> str:
        c = self.counters
        if c.zero_sequence:
            return ("waiting: the clipboard's sequence number is 0, so either nothing has been "
                    "copied since sign-in or this session may not read the clipboard; "
                    "nothing has been checked yet")
        if c.consecutive_failures >= HEALTH_FAILURE_STREAK:
            return (f"the clipboard could not be read for {c.consecutive_failures} checks in a row "
                    f"({c.last_error}); nothing is being checked")
        skipped = c.skipped_excluded + c.skipped_not_text + c.skipped_too_long
        return (f"on: {c.changes_seen} change(s) seen, {c.texts_read} read as text, {skipped} skipped "
                f"(private, not text or too long), {c.notices} notice(s), {c.warnings} warning(s); "
                "nothing is kept and nothing leaves this machine")
