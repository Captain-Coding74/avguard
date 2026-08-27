# What to improve next

Everything here comes from measuring the current code, not from reading it and
guessing. Where a number appears, the check that produced it is described so you
can re-run it.

The ranking rule: **does it stop the tool hurting the user, or make a failure
loud?** Anything that only makes AVGuard bigger lost to anything that makes it
honest. v1 died of silent failure and unjustified confidence. Both are back, in
new places.

---

## What I measured

| # | Finding | Severity | Evidence |
|---|---|---|---|
| 1 | Ordinary CI and build scripts are flagged **MALICIOUS** and auto-quarantined | critical | 3 of 3 realistic samples |
| 2 | `Suspicious_Process_Injection_PE` false-positives on **kernel32.dll** | critical | 16 hits in 8,843 clean binaries |
| 3 | Two AVGuard processes at once **destroy quarantine records** | critical | reproduced; original deleted, unrecoverable |
| 4 | YARA `severity` metadata is parsed and then thrown away | high | `scanner.py:312` returns `m.rule` only |
| 5 | If the UI pump ever raises, it stops forever and nothing says so | high | `gui.py:253` sits outside both `try` blocks |
| 6 | `data/config.json` is never written; the README says it is | medium | file absent after many runs |
| 7 | `data/scan_cache.json` holds 1,391 absolute paths, no expiry, no way to clear | medium | 286,893 bytes on disk |
| 8 | `docs/`, `tests/` and `README.md` are outside self-protection | medium | `SelfProtection().is_protected()` returns False |
| 9 | Full scans are single-threaded; the worker pool is used only for real-time | medium | 24.2 MB/s, 27.8 ms per file |
| 10 | Files over 8 MB with a non-ASCII name **silently skip YARA entirely** | high | found scanning this machine's own Downloads |

### Finding 1, in full

    deploy.ps1   Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File .\build.ps1"
    ci.cmd       powershell -NoProfile -ExecutionPolicy Bypass -Command "& { .\test.ps1 }"
    install.bat  powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File setup.ps1

All three scan **MALICIOUS**. `auto_quarantine` defaults to true and the GUI
starts real-time protection without asking, so on a developer's machine these
get moved out from under them.

`Suspicious_Script_Obfuscation` fires on `powershell` plus any 2 of six flags.
But `-NoProfile`, `-ExecutionPolicy Bypass` and `-WindowStyle Hidden` are what
every legitimate installer and CI runner on Windows uses. Only `-EncodedCommand`
and `FromBase64String` indicate actual obfuscation. The rule counts weak signals
as though they were strong ones.

### Finding 2, in full

I previously validated this ruleset against 150 System32 binaries and reported
zero false positives. That was a sample-size artifact. Across 8,843 files:

    Suspicious_Process_Injection_PE: 16 hit(s)
        C:\Windows\System32\apphelp.dll
        C:\Windows\System32\cygwin1.dll
        C:\Windows\System32\dbgeng.dll
        C:\Windows\System32\Faultrep.dll
        C:\Windows\System32\kernel32.dll

`kernel32.dll` exports `OpenProcess`, `WriteProcessMemory`, `CreateRemoteThread`
and `VirtualAllocEx`, so of course it contains all four strings. A rule that
matches the library *defining* an API cannot tell a caller from the
implementation. **The README's "0 false positives" claim is wrong and gets
corrected as part of this work.**

### Finding 3, in full

    gui = QuarantineStore(...)      # the GUI is running
    cli = QuarantineStore(...)      # you start a CLI scan in a terminal
    gui.quarantine(important.docx)  # the GUI detects and quarantines
    cli.quarantine(other.exe)       # the CLI rewrites the index from ITS stale snapshot

    records in index        : 1
    gui's file has a record : False
    gui's payload on disk   : True
    original still on disk  : False

The user's file is deleted, the masked payload is orphaned, and nothing in the
program can list or restore it. `README.md` documents running a CLI scan as a
normal thing to do. Both `QuarantineStore` instances load the index once at
construction and later rewrite it whole from memory.

### Finding 10, found while verifying the rest

Scanning this developer's real Downloads folder produced:

    YARA could not scan ...แนวเฉลยข้อสอบ... : could not open file

`yara-python` cannot open a path containing non-ASCII characters on Windows.
Files small enough to buffer are matched with `data=` and were fine; anything
over the 8 MB buffer limit took the `match(filepath=)` route, failed, and was
logged and skipped. On a machine with Thai, Chinese or Cyrillic filenames --
this one -- every large file was going unscanned by the rules, and the only
sign was a warning in a log.

Fixed as part of Tier 1 rather than deferred: it is the same failure shape as
v1, detection quietly not happening while the program reports success. The
scanner now falls back to matching from memory, bounded by the size cap the
guard already enforces. A rescan of the same 5,369 files reports zero open
failures.

### One claim I checked and rejected

`ScanWorkerPool.stop()` looked like it should leak sentinel values that poison a
later `start()`, leaving a pool that accepts work and scans nothing. I tested it
six times: zero leaks, workers alive, files scanned. A worker parked in
`get(timeout=0.5)` does receive the sentinel. Worth making explicit (Tier 2),
but it is not a live defect and is not treated as one here.

---

## Tier 1 — build now  ✅ done

All five items are built, and every claim below was re-measured afterwards:

| Was | Now |
|---|---|
| 3 of 3 ordinary CI scripts called MALICIOUS | all 3 CLEAN |
| 16 false positives in 8,843 clean binaries, `kernel32.dll` among them | 0 reach MALICIOUS; 13 are SUSPICIOUS and never moved |
| Two processes destroyed quarantine records | both records kept, both files restorable |
| YARA `severity` ignored | drives a weighted score; a medium rule cannot move a file |
| UI pump could die silently | survived 3 induced failures and kept draining |
| `data/config.json` never written | written on first run |
| `docs/`, `tests/`, `README.md` unprotected | whole project protected |
| 66 tests | 106 tests, plus a 400-binary rule corpus |
| Large non-ASCII-named files skipped YARA | matched from memory; 0 failures across 5,369 real files |


Five items. All about the tool being safe and honest. None adds a dependency.

### 1. Severity-aware verdicts

Every YARA hit currently means MALICIOUS, which means "move the user's file".
The rules already carry `severity` metadata and the code discards it at
`scanner.py:312`.

Replace the boolean with a score:

- `Finding(source, name, weight, detail)`, accumulated into `Verdict.findings`
- signature hits, and `severity` of `high` / `critical` / `test` → 100
- `medium` → 50, `low` → 25, **missing severity → 25** (an unlabelled rule is
  not trusted to condemn)
- entropy → 25
- 100 or more is MALICIOUS, 50 or more is SUSPICIOUS, otherwise CLEAN

Only a signature or a high-severity rule reaches MALICIOUS alone. Two medium
signals together can. `Verdict.is_threat` stays the single gate on quarantine.
Rule `description` metadata finally reaches the user instead of a bare rule name.

The scan cache stores verdicts, and this changes what a stored verdict means, so
the cache gains a `schema` version plus a `generation` hash over the rule files.
A mismatch drops every entry. Without that, the 1,391 cached results on this
machine keep being replayed under the old logic.

**Done:** the three scripts above scan SUSPICIOUS with `is_threat` False; EICAR
and the selftest marker stay MALICIOUS; the existing tests pass unchanged.

### 2. Fix the two rules that cry wolf

- `Suspicious_Script_Obfuscation`: require actual obfuscation — `-EncodedCommand`,
  `-enc`, or `FromBase64String`. Execution-policy and window-style flags become
  supporting evidence that cannot fire on their own.
- `Suspicious_Process_Injection_PE`: exclude the case where a file *exports* the
  APIs rather than importing them, and drop its severity so it can never
  self-quarantine. A hobby scanner should not be condemning system DLLs.

**Done:** a sweep of `C:\Windows` and both `Program Files` trees produces zero
MALICIOUS verdicts, and that number is printed by the harness in item 5 rather
than asserted in prose.

### 3. One instance at a time

An exclusive lock file in `data/`, taken by both entry points.

- GUI already running and launched again → tell the user, exit
- CLI while the GUI holds the lock → scanning still runs, but anything that
  writes to quarantine refuses with a clear message

Plus defence in depth inside `QuarantineStore`: re-read the index immediately
before every mutation, so a stale snapshot cannot erase someone else's record.
The lock prevents the race; the reload means losing the race is not fatal.

**Done:** the reproducer above ends with 2 records and both files restorable.

### 4. Make failure loud again

- Wrap `_append_log` in `_pump` and reschedule from a `finally`. The pump must
  be unkillable; if it dies the program looks alive while doing nothing, which
  is exactly how v1 failed.
- Install `sys.excepthook` and `threading.excepthook` that log to the rotating
  file, before anything reaches a stderr that does not exist under `pythonw.exe`.
- Write `data/config.json` on first run so finding 6 stops being true, and make
  the VirusTotal consent dialog name the extensions inline instead of pointing
  at a file that was never created.
- Add `PROJECT_ROOT` to self-protection so `docs/`, `tests/` and `README.md`
  cannot be quarantined.

**Done:** an exception raised inside `_append_log` leaves the pump running and a
line in the log.

### 5. A rule test harness with a corpus

The item that would have caught findings 1 and 2 automatically, and the one that
stops the v1 class of bug returning as rules are added.

    tests/
      rules/
        must_match/       samples every listed rule is required to detect
        must_not_match/   benign samples that must stay clean
      test_rules.py

The harness checks:

- every non-private rule declares `severity` and `description`
- no rule matches any file in `rules/`, `avguard/`, `docs/` or `tests/`
- every `must_match` sample hits its named rule
- every `must_not_match` sample is clean
- a **benign corpus** sampled from this machine's own `System32` and
  `Program Files`, with a per-rule false-positive rate printed and a ceiling
  that fails the build

Adding a rule then tells you immediately whether it is over-broad, instead of
you finding out when it moves someone's file.

**Done:** the test run reports corpus size and measured false-positive rate, and
fails if any rule exceeds the ceiling.

---

## Tier 2 — next  ✅ done

All seven items built. Two things went wrong during the work and are worth
recording, because both were the same mistake in new clothes.

**Heuristics were able to condemn.** `cygwin1.dll` trips the process-injection
rule (medium, 50) *and* has a writable-executable section plus a virtual-only
section (50). Those summed to 100, and a universally used library would have
been quarantined. Weak signals correlate — an unusual binary trips several
checks for one underlying reason — so adding them up manufactures confidence
that is not there. Findings are now split into `hard` (a byte signature, a
high-severity rule, cloud consensus) and heuristic, and the heuristic total is
capped at 75, below the threshold. **No pile of guesses can move a file.**

**A limit of ours was reported as a property of the file.** The first real run
flagged an 8,635-entry Minecraft resource pack as "malformed or hostile" — for
the sole reason that it has more entries than the 500 the scanner examines.
`ArchiveReport` now separates `problems` (bombs, traversal names) from `notes`
(our own truncation), and only `problems` score.

A third thing surfaced only because the fix did not take effect: the cache
generation hash covered the rule file but not the detection *code*, so the
machine kept replaying the old resource-pack verdict. There is now a
`DETECTION_VERSION` in the hash.

| Item | Result |
|---|---|
| Archive inspection | 92/92 members of real Downloads zips read in memory, 0 extracted to disk; nested threats found one level deep |
| PE heuristics | 0.17% of 600 clean binaries trip 2+ signals; never reach MALICIOUS |
| Scan history | JSON Lines event store, rotated, clearable |
| Parallel full scans | 2.5x faster (22.8s → 9.2s on 138 MB); 8 workers gives nothing more, so 4 stays the default |
| Settings and exclusions | settings window, plus one-click "never scan this folder" from a detection |
| Cache lifecycle | 30-day expiry, age-based eviction, `clear()` |
| Pool re-entrancy | 4 clean stop/start cycles; queue rebuilt rather than reused |
| Tests | 108 → **148** |

---

### Original plan


- **Archive inspection.** Real-time watches Downloads, which is where browsers
  put `.zip` files, and a zipped sample is currently one opaque blob. The stdlib
  gives everything needed without extracting to disk: `compress_size` and
  `file_size` from the central directory make a zip-bomb guard free,
  `flag_bits & 0x1` detects encryption, and traversal is visible in the entry
  name. Members stream in memory under a hard cap. Depth limit 2.
- **PE structure heuristics, as SUSPICIOUS only.** Measured on 400 clean
  binaries: W+X sections, virtual-only sections, high-entropy sections, absent
  import table. Any *one* fires on 27.5% of clean Program Files binaries, which
  is useless. **Two or more fires on 0.25%**, one file in 400. That combination
  is worth reporting and never worth auto-quarantining. `pefile` is already
  installed.
- **Scan history.** A JSON Lines event store in `data/events/`, so "what
  happened while I was away" has an answer outliving a 2,000-line widget.
- **Parallel full scans.** `scan_tree` is a plain loop; the worker pool exists
  and is used only for real-time. 201 MB currently takes 8.3 s.
- **Settings and exclusions in the GUI**, including "exclude this folder"
  offered from a detection. The recovery path for a false positive is currently
  to hand-edit JSON.
- **Cache as personal data.** `scan_cache.json` is a durable inventory of file
  paths. It needs an expiry, a size bound better than "keep the newest half",
  and a Clear button.
- Make `ScanWorkerPool.stop()` and `start()` explicitly re-entrant.

## Tier 3 — someday  ✅ done

All five items built, and the whole thing now packages into one executable.

| Item | Result |
|---|---|
| Publisher trust | halves the noise: 0.40% → 0.20% suspicious across 500 clean binaries, at no measurable time cost |
| Scheduled scans and startup | Startup-folder shortcut plus a `schtasks` daily task, no admin rights, both reversible from inside and outside the program |
| Rule updates | any number of `.yara` files, user rules kept separate from shipped ones, validated before adoption, working rules kept when a new one is broken |
| Quarantine exit door | `Export everything...` in the GUI, `--export-all` in the CLI, plus a retention review that never deletes |
| Packaging | one 28 MB `AVGuard.exe`, rules bundled inside, verified from an unrelated directory |
| Data location | moved out of the program directory to `%LOCALAPPDATA%/AVGuard`, with a one-time migration |
| Tests | 148 → **183** |

### The rule that shaped the Authenticode work

A valid signature tells you **who to blame, not that there is nobody to
blame**. Malware is signed with stolen certificates often enough that "signed"
cannot mean "safe". So a trusted signature here sets *heuristics* aside —
entropy, odd section flags, medium-severity rules — and touches nothing else. A
byte signature, a high-severity rule, or three VirusTotal engines agreeing all
still stand. That falls out of the hard/soft split from Tier 2, which turned
out to be the right shape for this too.

Measured: embedded signatures verify 22 of 25 third-party binaries but only 11
of 30 in System32, because Windows signs most of its own files through
catalogues. Catalogue support is deliberately skipped — the value is trusting
things the user *downloaded*, and downloads carry embedded signatures.

### Two decisions worth recording

**The scheduled scan never passes `--quarantine`.** An unattended scan, with
nobody reading the result, is the last thing that should be moving files.

**A user's own rule is advised, not rejected, when it matches itself.** Shipped
rules are refused outright and the harness enforces it, but rejecting
somebody's first rule with a lecture just teaches them to switch validation
off — and self-protection, not the validator, is what actually prevents the v1
disaster now.

---

### Original plan


- **Authenticode publisher trust.** Prototyped: `wintrust.dll` through ctypes
  works, about 147 ms per file, embedded signatures only — 22 of 25 third-party
  binaries verified, but only 11 of 30 System32 files, because Windows signs
  those through catalogs. Useful to *lower* suspicion on signed downloads and to
  skip cloud lookups. It must never suppress a signature or rule hit: malware
  gets signed with stolen certificates.
- Scheduled scans through `schtasks`, run-at-startup through the Startup folder.
- Rule updates: a `rules/` directory compiled together, user rules kept separate
  from shipped ones, validated before adoption with rollback on failure.
- Quarantine retention, plus `Export all` and `--export-all` so the store is not
  a one-way door.
- Packaging with PyInstaller, and moving `data/` to `%LOCALAPPDATA%`.

## Deliberately not doing

- **Real-time process, memory or kernel monitoring.** Needs a driver and admin
  rights. Out of scope for a Python hobby tool, and the honest version of this
  program does not pretend to be an EDR.
- **Catalog signature verification.** `CryptCATAdmin` would close the System32
  gap, but the value is in trusting third-party downloads, which embedded
  signatures already cover.
- **Our own signature feed.** Distributing signatures is a whole product.
- **RAR and 7z support.** Both need third-party packages. Zip covers what
  browsers actually produce.
- **Calling the quarantine masking "encryption".** It is XOR against a
  keystream, the nonce sits beside it in the index, and anyone with local access
  can reverse it. It exists so a stored sample cannot be double-clicked and does
  not trip other scanners. The README says that and nothing more.
