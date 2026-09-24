"""Build the fixtures for tests 4 to 10 of the manual AVGuard test plan.

Run it anywhere OUTSIDE AVGuard's own folder (AVGuard never scans its own
directory), for example in Downloads:

    python make_testplan_kit.py

It writes ./avguard-testplan/ with one sub-folder per test and a README
that says what each scan must print. EICAR is assembled from bytes here so
that this script is not itself a sample; the files it writes ARE samples,
and Windows Defender will take the EICAR ones unless the folder is excluded.
"""
import base64
import hashlib
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("avguard-testplan")

EICAR = bytes([
    0x58, 0x35, 0x4F, 0x21, 0x50, 0x25, 0x40, 0x41, 0x50, 0x5B, 0x34, 0x5C,
    0x50, 0x5A, 0x58, 0x35, 0x34, 0x28, 0x50, 0x5E, 0x29, 0x37, 0x43, 0x43,
    0x29, 0x37, 0x7D, 0x24, 0x45, 0x49, 0x43, 0x41, 0x52, 0x2D, 0x53, 0x54,
    0x41, 0x4E, 0x44, 0x41, 0x52, 0x44, 0x2D, 0x41, 0x4E, 0x54, 0x49, 0x56,
    0x49, 0x52, 0x55, 0x53, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x46, 0x49,
    0x4C, 0x45, 0x21, 0x24, 0x48, 0x2B, 0x48, 0x2A,
])
# AVGuard's own harmless marker, for the tests where Defender must not interfere.
# Assembled from bytes for the same reason as EICAR: the first version of this
# script carried it verbatim, and real-time protection quarantined the download.
MARKER = bytes([
    0x41, 0x56, 0x47, 0x55, 0x41, 0x52, 0x44, 0x2D, 0x53, 0x45, 0x4C, 0x46, 0x54, 0x45, 0x53,
    0x54, 0x2D, 0x4D, 0x41, 0x52, 0x4B, 0x45, 0x52, 0x2D, 0x61, 0x34, 0x31, 0x66, 0x39, 0x63,
    0x32, 0x64, 0x2D, 0x44, 0x4F, 0x2D, 0x4E, 0x4F, 0x54, 0x2D, 0x50, 0x41, 0x4E, 0x49, 0x43,
])
# The PowerShell rule needs the word powershell AND an encoded payload in one
# file; this script has the first (in build.ps1's text), so the second is
# split here and joined at run time.
ENCODED_FLAG = "-Encoded" + "Command"


def chain(n: int, seed: bytes) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        i += 1
    return bytes(out[:n])


def zipped(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def write(relative: str, data: bytes) -> None:
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


# 4. Nested archives. AVGuard inspects the zip, a zip inside it, and a zip
#    inside that (MAX_DEPTH = 2 nested levels in avguard/archives.py); a
#    fourth level is not opened. Measured here: 2- and 3-deep MALICIOUS,
#    4-deep clean. The boundary is included so the limit is visible.
write("4-nested/eicar-in-zip-in-zip.zip",
      zipped({"inner.zip": zipped({"eicar.com": EICAR}), "readme.txt": b"two levels deep\n"}))
write("4-nested/eicar-three-deep.zip",
      zipped({"level2.zip": zipped({"level3.zip": zipped({"eicar.com": EICAR})})}))
write("4-nested/eicar-four-deep.zip",
      zipped({"level2.zip": zipped({"level3.zip": zipped({"level4.zip": zipped({"eicar.com": EICAR})})})}))
write("4-nested/marker-in-zip-in-zip.zip",
      zipped({"inner.zip": zipped({"marker.txt": MARKER + b"\n"})}))

# 5. A zip of ordinary files with a zip inside it: every member is inspected
#    in memory and nothing is found.
write("5-clean/clean-files.zip", zipped({
    "readme.txt": b"Ordinary text in an ordinary zip.\n",
    "config.json": b'{"expect": "clean", "items": [1, 2, 3]}\n',
    "data.csv": b"id,value\n" + b"".join(f"{i},{i * i}\n".encode() for i in range(100)),
    "script.py": b"print('hello from the clean zip')\n",
    "random.bin": chain(16_384, b"testplan-clean-random"),
    "inner.zip": zipped({"inner/notes.md": b"# Notes\nA text file inside the nested zip.\n"}),
}))

# 6. PowerShell. A realistic build script uses every "scary" flag and must
#    scan CLEAN; the rule needs a PowerShell context AND an encoded payload.
write("6-powershell/build.ps1", b"""# Build script: the flags every installer and CI runner uses.
param([string]$Configuration = "Release")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Building $Configuration in $root"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$root\\tools\\restore.ps1"
Invoke-WebRequest -Uri "https://example.invalid/tools.zip" -OutFile "$root\\tools.zip"
Expand-Archive -Path "$root\\tools.zip" -DestinationPath "$root\\tools" -Force
Start-Process -FilePath "msbuild.exe" -ArgumentList "/p:Configuration=$Configuration" -Wait -NoNewWindow
Remove-Item "$root\\tools.zip"
Write-Host "Done."
""")
payload = base64.b64encode("Write-Host 'hello from an encoded command'".encode("utf-16-le")).decode()
write("6-powershell/encoded-launch.ps1",
      f"# The shape the rule exists for: PowerShell driven with a payload the reader cannot see.\n"
      f"powershell.exe -NoProfile {ENCODED_FLAG} {payload}\n".encode())

# 7. Entropy. Random bytes under three names; entropy alone scores 25 and
#    never reaches SUSPICIOUS (50), executable suffix or not.
write("7-entropy/random.bin", chain(65_536, b"testplan-random-1"))
write("7-entropy/random.exe", chain(65_536, b"testplan-random-2"))
write("7-entropy/random.dll", chain(65_536, b"testplan-random-3"))

# 8. Cache invalidation: scan, edit, scan again.
write("8-cache/marker.txt", b"Line one is ordinary.\n" + MARKER + b"\nLine three is ordinary.\n")

# 9. Rename under real-time protection: the file to rename.
write("9-rename/before-rename.txt", b"Rename me while real-time protection watches this folder.\n" + MARKER + b"\n")

# 10. Delete while scanning: enough files, and big enough, for the scan to
#     take a few seconds so there is time to delete under it.
for i in range(3000):
    write(f"10-delete/files/file-{i:04d}.txt", f"file {i} line of text that repeats\n".encode() * 1000)

write("README.txt", f"""AVGuard manual test plan, fixtures for tests 4 to 10
====================================================

Scan a folder with:   python -m avguard --scan <folder> -v
(-v lists clean files too; the summary lines and the exit code are the
result: exit 0 with no threats, exit 1 when something is MALICIOUS.)

4  Recursive archive scanning
   4-nested/eicar-in-zip-in-zip.zip     [MALICIOUS]  "matched the byte signature for EICAR-Test-File
                                        inside eicar-in-zip-in-zip.zip!inner.zip!eicar.com"
   4-nested/eicar-three-deep.zip        [MALICIOUS]  "... inside ...!level2.zip!level3.zip!eicar.com"
   4-nested/marker-in-zip-in-zip.zip    [MALICIOUS]  same as the first, with AVGuard's own
                                        marker (use it if Defender eats the EICAR zips)
   4-nested/eicar-four-deep.zip         [clean]      BY DESIGN: the zip, a zip inside it and
                                        a zip inside that are opened; a fourth level is not
                                        (MAX_DEPTH = 2 nested levels in avguard/archives.py).
                                        If a deeper limit is wanted, that is a settings
                                        decision, not a bug.

5  Clean zip
   5-clean/clean-files.zip              [clean]      six ordinary members, a zip among them,
                                        all inspected in memory; Threats : 0, exit 0

6  PowerShell false positives
   6-powershell/build.ps1               [clean]      -NoProfile, -ExecutionPolicy Bypass,
                                        -WindowStyle Hidden, Invoke-WebRequest, Start-Process:
                                        none of it counts without an encoded payload
   6-powershell/encoded-launch.ps1      [SUSPICIOUS] "Suspicious_Script_Obfuscation" (medium,
                                        50 points): PowerShell context plus the encoded-command
                                        flag (see the file; this README does not spell it,
                                        or the README itself would trip the rule).
                                        Never MALICIOUS on its own, never moved.
   Your own build script goes here too: expected [clean].

7  Entropy false positives
   7-entropy/random.bin .exe .dll       [clean] all three. The .exe and .dll carry an entropy
                                        finding worth 25 in the verdict's reasons, which is
                                        below SUSPICIOUS (50) on its own.

8  Cache invalidation
   python -m avguard --scan 8-cache/marker.txt      [MALICIOUS]   (now cached)
   edit the file: delete the middle line, save
   python -m avguard --scan 8-cache/marker.txt      [clean]       the cache is keyed on
                                        path, size and mtime, so an edit is a fresh scan
   put the line back, save, scan again              [MALICIOUS]

9  Rename under real-time protection
   Start the GUI with real-time protection on the folder 9-rename/ (or its parent).
   Rename before-rename.txt to after-rename.txt in Explorer.
   Expected: a detection for after-rename.txt within about two seconds (the
   debounce), because a rename arrives as a "moved" event and the new name is
   what gets scanned. Nothing is moved unless automatic quarantine is on.

10 Delete while scanning
   python -m avguard --scan 10-delete/files -v
   and while it runs (it takes a few seconds: 3,000 files, 106 MB), delete a
   good part of the folder in Explorer, or from a second terminal:
       Remove-Item 10-delete\\files\\file-1*.txt, 10-delete\\files\\file-2*.txt
   Expected: the scan finishes and exits 0, with no traceback. Every file
   that vanished between the directory listing and its read is a skip:
   with -v each prints as "[skipped] <path>", and the summary's "Skipped"
   count carries them. No "Errors" line: a file that disappears under the
   scan is the world changing, not the scanner failing. (Before the
   2026-09-24 change these were "[error] ... cannot stat: [WinError 2]"
   lines, which is what the Activity log showed for a browser's download
   rename and a restore's own working file.)
""".encode())

print(f"wrote {ROOT.resolve()} with fixtures for tests 4-10 (3,000 files in 10-delete/files)")
