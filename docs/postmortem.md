# What went wrong with the first version

Everything below was measured from the files in this project, not guessed.
The old code is still here (`main.py`, `engine.py`, `handler.py`, `app.py`,
`vt_scanner.py`, `yara_scanner.py`, `malware.yara`, `quarantine/`) so you can
check any of it yourself.

## The short version

The scanner detected threats 381 times and successfully quarantined **zero** of
them. It spent most of its runtime scanning one file — its own log — over and
over, and it had already eaten its own YARA ruleset, which silently switched off
most of its detection weeks before.

## The numbers, from `antivirus_log.txt`

| Measurement | Value |
|---|---|
| Lines in the log | 2,021 |
| `THREAT DETECTED` lines | 381 |
| `--> Quarantined` lines | **0** |
| `Could not read file ... [WinError 32]` | 380 |
| Scan events | 666 |
| Distinct files actually scanned | **13** |
| Scans of `antivirus_log.txt` alone | **622** |
| VirusTotal API calls | 284 |
| Calls that produced a usable verdict | **0** |

## The five bugs behind those numbers

### 1. The ruleset detected itself, and that killed detection

`malware.yara` listed its indicators as plain strings. The rule
`Ransomware_File_Extension` matched on the bare text `.locky`, `.encrypted` or
`.crypt`; `Code_Injection_Indicators` matched when `CreateRemoteThread`,
`WriteProcessMemory`, `LoadLibraryA` and `GetProcAddress` all appeared. Those
strings appear in the rule file itself. Compiling the ruleset and scanning it
produces:

```
Ruleset scanning ITSELF -> ['Eicar_Test_File', 'Suspicious_Script_Behavior',
                            'Ransomware_File_Extension', 'Code_Injection_Indicators']
```

All four rules. So the scanner moved `malware.yar` into `quarantine/`, where it
still sits. `quarantine/quarantine_data.json` records the moment:
`2025-09-07T14:47:31`.

From then on `yara.compile(filepath='./malware.yar')` raised, `main.py:83` set
`self.yara_rules = None`, and `main.py:164`'s `if self.yara_rules:` quietly
skipped every YARA scan. The failure was logged once and never mentioned again.

### 2. The EICAR rule could never have matched anyway

The real EICAR test string is 68 bytes and contains a backslash at index 11.
Written with a gap around that character, so that this document is not itself
an EICAR sample:

```
X5O!P%@AP[4 \ PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
            ^
            index 11 - the character the old rule dropped
```

The rule in `malware.yara:11` is 67 bytes. The backslash is missing. It matches
nothing. (The Python signature list in `main.py:57` had it right — only the YARA
copy was wrong.)

> Writing the string out in full is exactly the mistake bug 5 below describes:
> the first draft of this document contained the real 68 bytes, and AVGuard
> correctly flagged it. Hence the gap. `avguard/scanner.py` stores EICAR as a
> byte list for the same reason, and a detection is logged by *name*, never by
> pattern.

Meanwhile the rules that *did* work fired on innocent files:

| Content | Old ruleset says |
|---|---|
| Real EICAR file | clean — missed it |
| `"My backup script skips files ending in .encrypted or .crypt."` | **Ransomware_File_Extension** |
| A README explaining that ransomware appends `.locky` | **Ransomware_File_Extension** |
| Ordinary C source calling `LoadLibraryA` / `GetProcAddress` | **Code_Injection_Indicators** |

The detection was inverted: blind to the one thing it was meant to catch, noisy
about ordinary text.

### 3. Quarantine moved files while they were still open

`scan_file` opened the file at `main.py:153` and called `quarantine_file` at
`main.py:158` — still inside the `with` block. On Windows `shutil.move` cannot
rename a file the same process holds open, so it fell back to copy-then-delete.
The copy succeeded; the delete raised `PermissionError [WinError 32]`.

The result: **the threat was copied into `quarantine/` and left in place at the
same time**, and because the exception skipped `main.py:221-234`, no record was
written, no popup shown, and no list updated. That is the 381-detections /
0-quarantines / 380-WinError-32 pattern in the table.

You can see the duplication on disk right now: `engine.py`, `main.py` and
`antivirus_log.txt` each exist both in the project root and in `quarantine/`.

### 4. Restore and Delete could never have worked

`quarantine_file` wrote to `quarantine/<name>_<timestamp>` (`main.py:216`) but
recorded the entry under the bare `<name>` (`main.py:224`). Both `restore_file`
(`main.py:245`) and `delete_quarantined_file` (`main.py:268`) then looked for
`quarantine/<name>` — a path that was never written.

Both functions treat "not found" as a reason to delete the record, so pressing
Restore threw away the only copy of the original path, leaving an orphaned file
in quarantine that nothing could ever put back.

Worse, `original_path` was read straight out of `quarantine_data.json` — a file
living inside the quarantine directory — and passed to `shutil.move` with no
validation at all. Anything that could edit that JSON could have the tool write
a file wherever it liked.

### 5. The log fed itself

`main.py:466` watched the project folder recursively. The log lived in that
folder. `handler.py` scanned on every modify event with no exclusions.

So: scan a file → write a log line → the log is modified → scan the log →
write a log line → ...

622 of 666 scan events were the log scanning itself. And because
`engine.py:101` wrote the *decoded signature* into the log message, the log
came to contain the real EICAR string **381 times**. The scanner was
manufacturing the very pattern it kept detecting.

Each turn of that loop also spent a VirusTotal call. The free tier allows 4 per
minute; the loop ran at roughly 25 iterations per second. All 284 calls came
back unusable, and the code reported every failure — rate limits, 404s, network
errors alike — as the same reassuring line: *"Cloud scan inconclusive or file
not found in VirusTotal database."*

## What is in `quarantine/` (none of it is malware)

Every file in that folder is your own work, taken by the tool from itself:

| File | What it actually is |
|---|---|
| `malware.yar` | The ruleset, detected by its own rules |
| `main.py` | An older revision of your entry point |
| `engine.py` | An older revision of the engine |
| `engine.cpython-313.pyc` | Bytecode of `engine.py`; contains the EICAR bytes and the `MZ` header from its own signature list |
| `antivirus_log.txt` | A copy of the log |
| `quarantine_data.json` | The old index, which records only one of the six |

`engine.py` also listed `b'\x4d\x5a\x90\x00'` — the DOS/PE header — as a malware
signature. Tested against genuine Windows system executables:

```
engine.py MZ signature vs 40 genuine Windows system executables:
  flagged as MALWARE: 40/40  (100%)
```

Pointed at `C:\Windows\System32`, that build would have tried to quarantine the
operating system.

## What replaces it

See [../README.md](../README.md). The short answer: `avguard/`, with a
self-protection rule that is checked before any file is opened, a quarantine
store that neutralises what it holds and verifies a hash before restoring, a
rewritten ruleset that does not match itself, and 66 tests — most of which exist
specifically to fail if one of the bugs above comes back.
