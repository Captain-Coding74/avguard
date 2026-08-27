"""Authenticode signature checking, via WinVerifyTrust.

What this is for, precisely: **lowering** suspicion on software that a
recognised publisher signed. It is never allowed to raise it, and never allowed
to clear a real detection.

That restraint is not caution for its own sake. Malware gets signed with stolen
or fraudulently obtained certificates regularly enough that "signed" cannot
mean "safe". A valid signature tells you who to blame, not that there is nobody
to blame. So a trusted signature here suppresses *heuristics* -- entropy, odd
section flags, medium-severity rules -- and nothing else. A byte signature, a
high-severity rule, or several VirusTotal engines agreeing all still stand.

Measured on this machine:

    third-party binaries in Program Files   22 of 25 verified
    Windows binaries in System32            11 of 30 verified
    cost                                    ~147 ms per file

The System32 number is not a failure: Windows signs most of its own files
through security catalogues rather than embedding a signature, and reading
those needs the CryptCATAdmin APIs. Catalogue support is deliberately not
implemented -- the value here is trusting things the user downloaded, and
downloads carry embedded signatures.

At 147 ms a file this is far too slow to run on everything, so it runs only
when something has already been flagged, and the result is cached.
"""

from __future__ import annotations

import ctypes
import logging
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"


class Trust(str, Enum):
    TRUSTED = "trusted"           # signed, chain verifies, publisher recognised
    UNSIGNED = "unsigned"
    UNTRUSTED = "untrusted"       # signed, but expired / bad digest / bad root
    UNKNOWN = "unknown"           # we could not tell; treat exactly as unsigned


@dataclass(frozen=True)
class SignatureResult:
    trust: Trust
    detail: str = ""

    @property
    def is_trusted(self) -> bool:
        return self.trust is Trust.TRUSTED


# WinVerifyTrust return codes worth naming.
_STATUS = {
    0x00000000: (Trust.TRUSTED, "signed by a recognised publisher"),
    0x800B0100: (Trust.UNSIGNED, "no embedded signature"),
    0x800B0101: (Trust.UNTRUSTED, "the signing certificate has expired"),
    0x800B0109: (Trust.UNTRUSTED, "the certificate chain ends in an untrusted root"),
    0x800B010A: (Trust.UNTRUSTED, "the certificate chain is incomplete"),
    0x80096010: (Trust.UNTRUSTED, "the file has been altered since it was signed"),
    0x800B0004: (Trust.UNTRUSTED, "the subject is not trusted for this action"),
}


if IS_WINDOWS:
    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_byte * 8)]

    class _FileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(_GUID))]

    class _TrustData(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(_FileInfo)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    _ACTION_GENERIC_VERIFY_V2 = _GUID(
        0x00AAC56B, 0xCD44, 0x11D0,
        (ctypes.c_byte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    _WTD_UI_NONE = 2
    _WTD_REVOKE_NONE = 0            # no network calls: this must not phone out
    _WTD_CHOICE_FILE = 1
    _WTD_STATEACTION_VERIFY = 1
    _WTD_STATEACTION_CLOSE = 2
    _WTD_SAFER_FLAG = 0x100


class SignatureChecker:
    """Cached Authenticode verification."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._cache: dict[str, SignatureResult] = {}
        self._max = max_entries
        self._lock = threading.Lock()
        self._library = None
        if IS_WINDOWS:
            try:
                self._library = ctypes.WinDLL("wintrust")
                self._library.WinVerifyTrust.argtypes = [
                    wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p]
                self._library.WinVerifyTrust.restype = ctypes.c_long
            except (OSError, AttributeError) as exc:
                log.info("Authenticode checking unavailable: %s", exc)
                self._library = None

    @property
    def available(self) -> bool:
        return self._library is not None

    @staticmethod
    def _key(path: Path, size: int, mtime_ns: int) -> str:
        return f"{str(path).lower()}|{size}|{mtime_ns}"

    def check(self, path: Path, size: int = 0, mtime_ns: int = 0) -> SignatureResult:
        """Verify `path`. Never raises; UNKNOWN is a normal answer."""
        if not self.available:
            return SignatureResult(Trust.UNKNOWN, "signature checking not available")

        key = self._key(path, size, mtime_ns)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached

        result = self._verify(path)

        with self._lock:
            if len(self._cache) >= self._max:
                self._cache.clear()      # cheap bound; verification is idempotent
            self._cache[key] = result
        return result

    def _verify(self, path: Path) -> SignatureResult:
        info = _FileInfo(ctypes.sizeof(_FileInfo), str(path), None, None)
        data = _TrustData()
        data.cbStruct = ctypes.sizeof(_TrustData)
        data.dwUIChoice = _WTD_UI_NONE
        data.fdwRevocationChecks = _WTD_REVOKE_NONE
        data.dwUnionChoice = _WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(info)
        data.dwStateAction = _WTD_STATEACTION_VERIFY
        data.dwProvFlags = _WTD_SAFER_FLAG

        try:
            code = self._library.WinVerifyTrust(
                None, ctypes.byref(_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data)
            ) & 0xFFFFFFFF
        except OSError as exc:
            return SignatureResult(Trust.UNKNOWN, f"verification failed ({exc})")
        finally:
            # The verify call allocates state that must be released, or the
            # process leaks a handle per file scanned.
            try:
                data.dwStateAction = _WTD_STATEACTION_CLOSE
                self._library.WinVerifyTrust(
                    None, ctypes.byref(_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
            except OSError:
                pass

        trust, detail = _STATUS.get(code, (Trust.UNKNOWN, f"status 0x{code:08X}"))
        return SignatureResult(trust, detail)
