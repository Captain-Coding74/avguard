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

## Tier 4 — the improvements plan

[docs/improvements.md](docs/improvements.md) is a five-item plan handed to
this project on 2026-09-22; each item lands here with what was measured. (Its
preface says a numpy histogram shipped separately. It had not: nothing in
`avguard/` imported numpy until item 5, which uses it when present and works
without it. The histogram followed in the commit after item 5; see "The
histogram, vectorised" below.)

| Item | Result |
|---|---|
| 1. IOC hash blocklist | SQLite, one lookup per file: 7 µs against a million rows, and no measurable cost inside a scan (551 µs against 550 µs, warm). Manual import, an opt-in MalwareBazaar feed (1,484 hashes in 1 s live; a truncated download changes nothing), and the list is part of the detection generation. Tests 377 → **400** |
| 2. File integrity monitoring | A signed SQLite baseline (HMAC-SHA256, key under DPAPI) of every file under chosen roots; a check names modified, added and removed files with old and new hashes, records events, and never moves anything. Default hashes everything, `--fast` trusts size and mtime and says what that trades away; both asserted against a file whose mtime was put back. 2,000 files / 596 MB: baseline 1.0 s warm, check 0.73 s, `--fast` 0.21 s. Tests 400 → **421**. The GUI tab the plan asked for came two days later ("The Integrity tab", below). Tests 491 → **506** |
| 3. Event bridge to Network Watchdog | Every recorded event is POSTed as JSON (schema 1, frozen) to a URL that is empty by default and set only past a yes/no naming what leaves the machine. A bounded queue and a daemon thread: `record()` is 170 µs without a forwarder, 258 µs with a dead endpoint; 601 events into a blocked endpoint kept the newest 500. Tests 431 → **437** |
| 4. Explorer right-click scan | Two per-user registry keys, no administrator rights, tested against a fake of winreg; `--pause` keeps the result on screen, in a window when there is no console. **Not yet checked on a real Explorer**: writing to the user's registry was left to the user. Tests 437 → **449** |
| 5. Fuzzy hashing with TLSH | Built without the dependency, two days after being set aside for want of it. `avguard/tlsh.py` is the digest in Python -- `bytes.translate` for the Pearson gathers, numpy for the histogram -- and it is bit-identical to the reference C++ on every input and chunking tried (the reference was built from source here to check). 16.5 MB/s with numpy, 2.4 MB/s without, 119 MB/s if `py-tlsh` happens to be importable, so each backend has a size cap that keeps one digest near 100 ms. A hand-seeded reference table in the blocklist database; the nearest reference is one soft finding. The thresholds were measured, not inherited: 30 for a near variant stands, the far band moves from 60 to 40, because at 60 one clean executable in thirty would be tagged per hundred references. Tests 449 → **481** |

**The baseline's signature has a stated limit.** Code running as the same
user can call the same DPAPI and re-sign a doctored baseline. It defends
against other tools, casual edits and a baseline copied in from elsewhere --
not against an attacker who already owns the account. The README says so the
way it says the quarantine masking is masking.

**A transaction beat the file swap.** The plan asked for "build beside and
`os.replace`". Windows refuses to replace a file another handle has open, and
the running GUI holds the database open; a SQLite transaction gives the same
guarantee without that fight.

**The TLSH blocker was the loop, not the algorithm.** The first attempt at
item 5 measured a byte-at-a-time Python digest at 0.9 MB/s and stopped.
The digest is six Pearson-table gathers per byte plus a histogram, and the
interpreter already has both at C speed: `bytes.translate` is the gather,
big-int XOR is the XOR, `np.bincount` is the histogram. The one piece that
stays a loop is the one-byte checksum chain, where each step depends on the
last; it caps the whole thing at about 30 MB/s and is why the numpy path
lands at 16.5 MB/s rather than 100. Correctness was not taken on trust: the
reference library was built from its sdist on this machine (a Linux box with
a compiler) and every backend was checked against it on random data, text,
low-variety input, real files, and chunk sizes from 1 byte to 1 MB, digest
for digest and distance for distance. One thing that check found was in the
reference: its own streaming `update()` gives a different digest from its
one-shot `hash()` when fed chunks shorter than its five-byte window, so the
native backend batches its input.

**The thresholds were folklore, and one of them was wrong.**
`tools/tlsh_calibration.py` digests the software installed on the machine,
scores every pair of files from different directories, and patches each
file three ways to see what a variant scores. This machine is Linux, so the
corpus is ELF; on Windows the same command takes the plan's Program Files
and System32 roots, and re-running it there is one command. It was run
there two days later: the next paragraph.

| distance | unrelated executable pairs (of 976,529) | unrelated pairs, all kinds (of 1,963,623) | clean executables tagged per 100 references |
|---|---|---|---|
| ≤ 10 | 9 | 15 | 0.09% |
| ≤ 20 | 10 | 73 | 0.10% |
| ≤ 30 | 10 | 98 | 0.10% |
| ≤ 40 | 12 | 143 | 0.12% |
| ≤ 50 | 55 | 272 | 0.56% |
| ≤ 60 | 323 | 627 | 3.25% |
| ≤ 80 | 3,302 | 4,261 | 28.7% |

Every executable pair under 30 is the same code in two places (perl's
modules and perl-base's copies of them); the first genuinely unrelated pair
scores 35, two 14 KB programs that are mostly ELF boilerplate, and past 50
that is what the band is made of. A copy with one byte changed scores 5 at
most; one byte changed per 4 KB, 18 at most; 1% of the bytes overwritten, a
median of 10 and a 90th percentile of 25. So the near band stays at 30 and
the far band ends at 40, where it is as clean as the near band; at the
plan's 60 a hundred references would tag one clean executable in thirty
with a finding that, together with the entropy of a packed file, reaches
SUSPICIOUS. The rate grows with the set -- every 1,000 references, about 1%
of clean executables on resemblance alone -- so the store warns (at 250
now, a number the Windows run set) and the README says to keep the set to
the families that matter.

**The same calibration on Windows, 2026-09-24.** This session has no
Windows machine, so `.github/workflows/calibration.yml` runs the tool by
hand on the CI runner: a Windows box with Visual Studio Enterprise and its
language packs, four Android NDKs, the Azure and AWS command lines and the
rest, which is not the owner's desktop but is the plan's corpus (Program
Files, Program Files (x86), System32). The reference library built there
in 13 s, so the digest ran native: 1,984 distinct .exe and .dll files,
1,176 MB, in 9 s. Three runs, each about three minutes of runner time.

The first table read thirty times worse than Linux at 30, and the reason
took two more runs to pin down. It was not the small files: counting only
pairs where both files are at least 64 KB made the rate higher, not lower.
It was the same file in several places. The runner holds the Android NDK
four times over and four releases of SQL Server Integration Services, and
every pair under 10 was `glslc.exe` beside `glslc.exe`, `python311.dll`
beside `python311.dll` in the next version's directory, a version string
apart: the digest doing what it is for. 1,606 of the 1,576,943 unrelated
pairs share a file name, and they are 421 of the 513 pairs under 30. So the
table has a column for every pair, one for pairs whose file names differ,
and what the second means for a reference set.

| distance | unrelated pairs (of 1,576,943) | with different names (of 1,575,337) | clean executables tagged per 100 references, different names |
|---|---|---|---|
| ≤ 10 | 174 | 4 | 0.03% |
| ≤ 20 | 349 | 31 | 0.20% |
| ≤ 30 | 513 | 92 | 0.58% |
| ≤ 40 | 1,055 | 466 | 2.92% |
| ≤ 50 | 3,773 | 2,965 | 17.2% |
| ≤ 60 | 9,276 | 8,301 | 41.0% |
| ≤ 80 | 22,711 | 21,572 | 74.8% |

Even the different-name pairs under 20 are one code base under two names:
`cpack.exe` and `ctest.exe` (CMake's tools, the same static library in
each), `llvm-lipo.exe` and `llvm-nm.exe`, `yasm.exe` and `vsyasm.exe`,
the pip launcher stub as `pywin32_postinstall.exe` and as `normalizer.exe`,
Git's `git-lfs.exe` and `bash.exe` in `Git\cmd` (both the 43 KB launcher),
`pywintypes313.dll` and `pywintypes314.dll`. The 30 to 40 band is another
thing entirely: 561 pairs, and every one sampled is a 15 KB .NET satellite
resource assembly beside another, PE and CLR boilerplate with a few
strings in it, alike because there is nothing else in them. A patched copy
scores as it did on Linux: one byte changed, 8 at most; a byte per 4 KB,
10 at most; 1% overwritten, a median of 7, a 90th percentile of 19 and a
99th of 57.

What that decides. The near band stays at 30: 0.58% of clean executables
per hundred references on this corpus, six times the Linux rate, and the
pairs under it are shared code, which a malware reference is not; 20 would
halve that and lose one heavy variant in ten. The far band stays at 40,
with its Linux description withdrawn: it is not "as clean as the near
band" here, it is five times noisier, and what it picks up is tiny
resource-only assemblies, which never carry the entropy finding it was
meant to reinforce, so on a machine like this a hundred references put a
25-point "loose resemblance" on 3% of clean executables and move none of
them past CLEAN. It buys four of three hundred heavy variants. Ending it
at 30 would be cheaper and would be a detection change; it is recorded
here as the first thing to try if the far band ever proves noisy in use.
One number did move: the store's warning, which said 1,000 references
mark about 1% of clean executables, now comes at 250, because on this
corpus 1,000 mark 5.7% and 250 mark 1.5% (0.25% on Linux). Neither
threshold changed, so `DETECTION_VERSION` did not. The tool gained the
size and file-name splits on the way, and a fix: on Windows it had sampled
every .exe and .dll regardless of the digest's size cap.

**What the digest costs, and what it does not.** `_read_facts` on a 2 MB
file: 139 ms without the digest, 259 ms with it; on 64 MB, 4.2 s against
8.5 s, which is why 64 MB is over the cap and gets no digest. The facts
pass itself ran at 16 MB/s because the entropy histogram was a Python loop
over every byte -- the numpy histogram the plan's preface calls shipped was
the obvious next step once numpy was listed, and it is the next entry.
Nothing is digested until a reference exists: an empty table costs nothing,
which is the state every install starts in. Matching is one vectorised pass:
10,000 references cost 2.5 ms per digested file with numpy and 53 ms
without.

**The histogram, vectorised.** The one-pass read behind every verdict
counted bytes with `for byte in chunk: histogram[byte] += 1`, and that loop
was most of the pass. Replaced with `np.bincount` over each chunk when numpy
is importable; the loop stays as the fallback and a test holds both to the
same 256 counts on a file with every byte value across more than one chunk.
Not a detection change: the counts are identical integers, so the entropy
is bit-identical and `DETECTION_VERSION` stays at 15. Measured with the
same files, best of three, `_read_facts` alone:

| file | byte loop | `np.bincount` | speedup |
|---|---|---|---|
| 64 MB | 3.73 s, 18 MB/s | 0.32 s, 207 MB/s | 11.5× |
| 2 MB | 120 ms | 14 ms | 8.8× |
| 256 KB | 13 ms | 1 ms | 9.0× |

A whole scan, cache off, of 978 shared libraries (220 MB) with YARA and
everything else in the pipeline: 15.9 s with the loop, 2.5 s with numpy,
14 against 92 MB/s. The TLSH digest's own cost is unchanged (its 16 MB/s
is the checksum chain, not the histogram), so its size caps stand; a
digested 2 MB file now costs 14 ms of facts plus 120 ms of digest rather
than 120 plus 120. Tests 481 → **482**.

**The watcher waits without a timeout.** Run #34's Windows failure
([docs/next-5.md](docs/next-5.md)) was CPython's parking lot dying --
`_PySemaphore_Wakeup: ReleaseSemaphore failed (error: 6)` -- as `stop()`
woke a scan worker sitting in `queue.get(timeout=0.5)`; the debouncer's
`Event.wait(0.25)` had the same shape, a timed wait that another thread
wakes. Both are gone. Workers block on the queue with no timeout and leave
on a sentinel that always has room: the queue holds the backlog plus one
slot per worker and `submit()` stops at the backlog. The debouncer waits
untimed while nothing is pending and, while something is, naps for at
most 0.1 s in a `time.sleep` that nothing wakes; a touch only ever pushes
a deadline later, so the earliest one cannot move under it. The crash
does not reproduce on Linux, so the claim rests on the mechanism, not a
repro: the timed waits that expired twice a second per worker and four
times a second in the debouncer, all suite long, no longer exist. The
joins inside `stop()` keep their timeouts; they expire only when a thread
is already stuck, which is the case they exist for.

Measured, before and after: `stop()` with four idle workers 0.48 and
0.64 ms; with two workers mid-scan and eighteen queued, 150 ms both ways
and two of twenty scanned both ways -- the backlog was always abandoned,
and a test now says so; a 0.3 s debounce fires at 303 ms instead of 502,
the old 0.25 s tick having rounded it up; an idle pool and debouncer cost
0.1 ms of CPU per five seconds instead of 5.4. A test holds every `get()`
the workers make to a blocking one, and another gives three workers a
one-slot queue and checks all three leave. Tests 482 → **486**.

**A file that vanishes under the scan is a skip, not an error.** The
Activity log during the manual test plan showed red `cannot stat:
[WinError 2]` lines for a browser download being renamed out from under
the watcher and for a restore's own `.restoring` working file: files this
program or the user had just moved, reported as failures of the scan.
Editors, browsers and the quarantine all create files that live for a
moment, and under real-time protection every one reaches a worker. Now
`FileNotFoundError` at any point -- the guard's `lstat`, the `stat` before
the read, the read itself, or the second open a large file gets for YARA
and an archive gets for inspection -- is a SKIPPED verdict with the reason
"vanished before it could be scanned" or "vanished while it was being
scanned". The GUI logs a skip at debug, so the red lines are gone; every
other `OSError` (a lock, a permission) is still an error, and a test says
so. Not a detection change and not cached, so no version bump. Measured
with the test plan's fixture, 2,000 of 3,000 files deleted under a running
scan: before, `Examined 3000, Clean 1326, Skipped 2, Errors 1672`; after,
`Examined 3000, Clean 1093, Skipped 1907, Errors 0`, exit 0 both times,
no traceback either time. Six tests, one replacing the old "error or skip"
one and one a tree scan that empties the folder from inside its own
callback. Tests 486 → **491**.

**The Integrity tab, 2026-09-24.** Item 2's text said "CLI first, GUI tab
after it works". The tab is `avguard/fimpanel.py`, a page beside Quarantine
in the main window: the baseline's state on one line, the changes with both
hashes, Check now, Accept selected, Cancel, Baseline a folder, and the
`--fast` trade as a switch with its cost written next to it. It runs the
same `FimStore` as the CLI on a worker thread and reports through the
window's `post()`, so no widget is touched off the GUI thread. The engine
gained two optional hooks for it, `progress(done, total)` and
`should_stop()`, and now walks the roots before it hashes anything so the
total is known from the first call. Measured over 2,000 files / 131 MB,
warm: baseline 0.53 s without the hooks and 0.52 s with them, a check
0.45 s either way, `--fast` 0.06 s either way; five or six progress posts
per run, because the hook is rate-limited to ten a second (the window's
pump drains 200 callables a tick, and a post per file would have left the
bar minutes behind the work); the pre-walk is 30 ms of that check; the
refresh the tab does on the GUI thread after each operation (count, roots,
date and the HMAC over a 384 KB baseline) is 2 ms. A cancelled baseline
writes nothing and a cancelled check records nothing, both asserted.

Two things the window found. The tab's first layout asked for 439 px of
height, and at the window's minimum size that pushed the scan buttons off
the bottom; it asks for five list rows now, not ten, and wraps its text to
the width the pane gives (418 px at 900 x 560, everything visible). And
`tb.PanedWindow`, which the main window had used since v1, is not a name
ttkbootstrap 2.x exports: 1.x re-exported tkinter.ttk, which has the
alias, 2.x exports only `Panedwindow`, and `requirements.txt`'s `>=1.14.0`
resolves to 2.x on a fresh install today, where the window never opened.
Nothing had caught it because no test built the main window; one now reads
every `tb.<Name>` the GUI modules use and asks the installed ttkbootstrap
for each. The same 2.x prints, at every window, that the "darkly" theme
name is a legacy alias planned for removal in 3.0, so `requirements.txt`
now holds the package below 3: the next fresh install gets what was
exercised here, and 3.x waits until the theme is chosen against it. The tab was driven on a real window under Xvfb here (baseline,
three changes, check, accept; Health and History opened beside it) and the
suite's window tests run on the Windows CI runner, which has a display. Not
yet on the owner's desktop.

**Marking a known sample from the window, 2026-09-24.** The reference
table is empty until somebody fills it, by design, and filling it meant
`--tlsh` on a sample and `--iocs-import` of the line it printed. The
Quarantine tab has a fourth button now, *Mark as a known sample*: it reads
the quarantined file's bytes back in memory (`QuarantineStore.payload`,
which `export` now shares; nothing is written), suggests a family name from
what caught the file (the byte signature's name, else the first rule's,
else the file's stem), and hands the bytes to `IocStore.add_reference`,
which refuses what the scanner could never match (above the backend's
size cap, or too small for a digest) with the reason, and otherwise adds
one row under the source `quarantine`. `Scanner.adopt_iocs` then reloads
the references and re-keys the cache in this process instead of at the
next two-second check, an event of kind `reference` goes to the History,
and the banner says what will happen. Nothing is moved on resemblance,
as before. Driven on a real window under Xvfb: a 64 KB sample quarantined
for the selftest marker, a copy of it with the marker broken and one more
byte changed scanning CLEAN; the button pressed with the dialog answered,
9 ms from click to the scanner holding the row (digest, import, adopt,
re-key); the copy scanning SUSPICIOUS, "resembles a Selftest-Family
sample: TLSH distance 2". Tests 506 → **512**.

**Settings > Known samples, 2026-09-24.** The button above adds a
reference from the window; this page shows and undoes them there. It is
the "Kept files" page's shape: a list of every reference with its family,
source and date (`IocStore.tlsh_entries`, newest first), a Remove button
that confirms, and rows that remember their digest rather than their
number, so a reference landing underneath the open dialog cannot shift
the target (the kept-files lesson, tested the same way). A removal bumps
the store's version, and the window's `_references_changed` has the
scanner adopt it at once and re-key its cache, so a verdict cached
SUSPICIOUS on resemblance to the removed row is gone rather than replayed
for the cache's lifetime; that is a test. Measured on the real window
under Xvfb with 1,003 references, four times the warning point: the
Settings dialog builds in 23 ms, the list alone in 8 ms. Tests
512 → **516**.

**The manual test plan, 2026-09-24.** Ten tests, written by the project's
owner, of what a user would do to a scanner. Tests 1 to 3 were run on
their Windows machine with the GUI and recorded as passed in their plan;
the Activity log they shared shows test 2 (an EICAR zip detected inside
`eicar_com2.zip!eicar_com.zip!eicar.com` and quarantined). Tests 4 to 8
and 10 were run here, on Linux, through the CLI against the code on main;
test 9 needs the Windows desktop and was not run here. The fixtures come
from `tools/make_testplan_kit.py`, which writes one folder for each of
tests 4 to 10 and a README with the expected output; EICAR and the selftest marker are
assembled from bytes there, because the first version of that script
carried the marker verbatim and real-time protection quarantined the
download of the script itself, which is test 1 passing in an
inconvenient place.

| # | Test | Expected | Result |
|---|---|---|---|
| 1 | Selftest marker | THREAT | Passed (owner's run): hard signature |
| 2 | EICAR zip under real-time protection | THREAT, quarantined | Passed (owner's run): the archive is inspected in memory and moved |
| 3 | Synthetic injector PE | SUSPICIOUS | Passed (owner's run): a medium PE heuristic, never MALICIOUS alone |
| 4 | EICAR in a nested zip | THREAT | Passed: two and three levels deep are MALICIOUS, the member path printed as `eicar-in-zip-in-zip.zip!inner.zip!eicar.com`. A fourth level is not opened (`MAX_DEPTH` in `archives.py`); the kit's four-deep zip scans clean by design |
| 5 | Zip of clean files | CLEAN | Passed: 12 members of 7 kinds, a nested zip among them, all inspected, exit 0; the kit's `5-clean/` zip is the same test in six members |
| 6 | Clean PowerShell build script | CLEAN | Passed: `-NoProfile`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `Invoke-WebRequest` and `Start-Process` together score nothing; the same context plus an encoded-command flag is SUSPICIOUS (medium), and stays short of MALICIOUS |
| 7 | Random 64 KB blob | CLEAN | Passed as `.bin`, `.exe` and `.dll`: entropy alone is 25 and SUSPICIOUS starts at 50 |
| 8 | Modify a detected file | re-scanned | Passed: MALICIOUS, the marker line removed → CLEAN, put back → MALICIOUS. The cache is keyed on path, size and mtime |
| 9 | Rename a detected file under real-time protection | THREAT | Passed, headlessly: a `RealtimeMonitor` on a folder holding a marker file, the file renamed, and a MALICIOUS verdict for the new name 0.35 s later with a 0.3 s debounce, nothing moved. A rename arrives as a `moved` event and the destination is what is scanned; it is a new path, so the cache cannot answer for it. Not repeated in the GUI here |
| 10 | Delete files during a scan | graceful skip | Failed as written before `23b2e12`: a vanished file was an ERROR. Now a skip; 2,000 of 3,000 files deleted under a running scan gives `Examined 3000, Clean 1093, Skipped 1907, Errors 0`, exit 0, no traceback |

The plan found one thing to change (test 10) and one thing to know
(the nesting limit in test 4). The other expectations held as written.

**The paste guard, 2026-10-04.** The first thing AVGuard watches that is
not a file. The ClickFix scam (and FileFix) copies a command to the
clipboard and talks the user into pressing Win+R and pasting it; no file is
written until the user has already run it, so every file stage is blind to
it. `avguard/clipguard.py` reads the clipboard when its sequence number
moves (one `user32.GetClipboardSequenceNumber` call per 500 ms tick, the
clipboard opened only on a change) and classifies the text: a launcher
program (powershell, mshta, cmd, wscript, rundll32, regsvr32, msiexec,
certutil, bitsadmin, curl, a protocol handler) together with a signal an
honestly pasted command has no reason for (an encoded blob, a remote .hta
or .msi or a share at an address, a hidden window with remote content, a
program dropped under a temp folder and run, a fake-verification comment
tail, the FileFix padded comment, char-code obfuscation) is a warning; a
launcher that merely fetches and runs is a quieter notice, because that is
the shape of the install one-liners developers paste. It is advisory and
outside the scoring model: no Finding, no Verdict, `detection_generation()`
unchanged with and without it (a test asserts this), so `DETECTION_VERSION`
is not bumped, for the reason the numpy histogram and the vanished-file skip
were not. It keeps none of the text (the event carries the signals, the
host and the owning program, never the command), sends nothing, reads
nothing while off, nothing present at startup, and nothing an application
marked private (the two formats KeePass and 1Password set). On the Tk
thread through `after()`, no worker and no timed wait, for the reason in
"The watcher waits without a timeout". Off in the config; the first-run
dialog offers it pre-ticked, an existing install is offered it once, and
Settings states the trade.

Measured here on Linux (the classifier is pure and runs anywhere):
`classify()` 32 us on a lure, 13 us on an ordinary command, 0.8 ms over
16 KB of non-matching text. Over the fixture corpora, 22 of 22 ClickFix and
FileFix shapes reach warning and 0 of 31 legitimate lines do, with 3
of those (the bun, uv and pnpm install lines) landing at notice and counted.
The two first-draft mistakes the project's own history predicted are
fixtures that must not warn: a hidden window alone (the install.bat shape
from Finding 1) and a local .hta or .msi. The ctypes clipboard reader and
the owner attribution run only on Windows; the Linux import job asserts
`WindowsClipboard().available` is false. Not yet measured on the owner's
desktop: the cost of the live tick over a session, what `GetClipboardOwner`
resolves to when a browser's JavaScript writes the clipboard, and which
password managers set which private-format marker. Until those run the
first-run default stays pre-ticked on the strength of the corpus, and the
ROADMAP says "not yet on the owner's desktop". Tests 516 -> 551.

Three things a second read found before the first commit had finished its
CI run, each now a test. The Windows clipboard reader used `ctypes.wintypes`
without importing that submodule: on Linux the reader never binds, so every
test stayed green while the real window would have failed to open on
Windows; a Windows-only test now constructs the reader, polls it and reads
it on the runner's desktop. A launcher word in a sentence earned a notice
("open cmd and start https://..." names a launcher, a URL and the word
start); a launcher now counts only in command position, at the start of
the text, after a path or a quote, or after a hand-off token such as `/c`
or `start`, and two prose fixtures must stay silent. And a banner's button
outlived its message, so "Don't warn about this text again" would have sat
beside "Scan complete"; a banner now clears the previous one's button.

**The paste guard, second reading, 2026-10-04.** Asked whether the code was
right rather than whether it worked, a five-lens adversarial read (the Win32
calls, the classifier, the window, privacy, the tests) returned 47 findings,
several the same defect seen through two lenses. Each was reproduced against
the shipped code before anything changed; the ones that reproduced are now
tests, and the fixes are in `avguard/clipguard.py`, `gui.py`, `events.py`
and `tests/test_clipguard.py`.

The classifier. The dressing signals (lure comment, checkmark, padded
comment, obfuscation) fired on a launcher alone, so `curl -I
https://example.com # verify the server is up` was a warning; they count
only on a command that fetches and runs or already carries a structural
signal, the lure words are the lure's ("verify you", "not a robot", "ray
id"), not any "verif", and a program file named after a command separator
(`& %TEMP%\\a.exe`) counts as the run so the gate does not lose the
fetch-then-run-by-name shape. A launcher word inside a URL path
(`github.com/PowerShell/PowerShell`) and a protocol handler in prose were
command positions, while a command on its own line after "press Win+R and
paste:" was not; a URL is never a position now and a line start always is.
The host regex admitted `|;?#&`, so `https://a|iex` named the host "a|iex",
and it cut the user part before the fragment, so `https://evil.invalid#@
example.com/x` (fetched from evil.invalid) was reported as example.com; the
authority ends at `/`, `?` or `#`, the host at the first character that
cannot be in one, loopback is not remote and 254 characters is not a host.
`\\bstart\\b` matched `Start-Service`; `/transfer` could never match after a
space; `-w hid` and `-window hidden` (PowerShell takes any prefix) were not
hidden; eleven hand-picked zero-width characters were stripped where every
Unicode format character (bidi controls, tag characters) is now; a lure
comment matched across lines; and a lone UTF-16 surrogate, which a clipboard
can hold, raised at the hash with the warning lost and the sequence already
advanced (the one finding both refuters confirmed before the run hit its
limit: the clipboard is decoded from its UTF-16 bytes with replacement, and
`normalize()` does the same for any source). The sentences read "start a
hidden console hidden" and "a the command prompt command".

The reader. `GetClipboardData` on a delayed-rendering owner that has
stopped answering holds the calling thread, which is the Tk thread;
`IsHungAppWindow` is asked first and such an owner is a retry, not a wait.
A `RegisterClipboardFormatW` that returned 0 meant a privacy format silently
not honoured; it turns the guard off with the reason in Health. Sequence
number 0 was read as "no access" and shown red; it is also what a window
station reports before its first copy, so Health says both and the first
copy is examined.

The window and privacy. Turning the guard off and on again read whatever
was copied while it was off: the guard forgets its sequence number on every
tick it is off. Closing the first-run dialog with the X applied the
pre-ticked box and turned clipboard reading on; dismissal turns nothing on,
and the one-time banner offers the guard on the next start. "Sends nothing"
was false with event forwarding on, because the clipboard event went
through the same store; `EventStore.record(..., forward=False)` keeps it on
this machine whatever address is set, and the consent sentence says so. The
event carried a SHA-256 and the length of the command, a lookup away from
the command; the detail is signals, launcher, host and owning program, and
a test pins that set. The one-time offer replaced a startup warning
("YARA rules failed to load") and marked itself done before it could be
seen; it waits for an empty banner and is marked when shown. An error other
than a busy clipboard logged a traceback twice a second and never reached
Health; counted, logged once per streak, red after the streak. A failed
save left the guard running while the dialog said it could not save. A
notice could not be silenced though the README promised the button. A
160-character preview of the text lived in memory behind the button for
nothing. Refused: an HMAC-keyed ignore hash, because the key would sit
beside the file it protects, the hash never leaves disk, and it is no
longer in the event.

The tests. The detection-unchanged test compared a value with itself. The
window's off switch, the enforcement point of "reads nothing while off",
had no test. A fixture named for a signal proved only that something warned:
most carried `-w hidden`, and a mutation run deleted nine detector pieces
with the corpus green. The reader's call order was untested anywhere, and
the Windows runner test asserted tautologies. Now every must_warn fixture
claims the signal it is named for and every signal has a fixture (five
isolating fixtures added); the reader runs on every platform against a fake
user32 with the call order asserted and the privacy format checked before
the data is touched; the Windows runner writes known UTF-16 bytes to the
clipboard and reads them back through the guard; the window's tick, Health
row, first-run choice, offer and enable path run on a fake self and the
banner's button on the shared withdrawn root; `unittest.main()` is at the
end of the file; the self-match exclusion names the one directory; the
smoke check's quiet case is a launcher line and a notice case is added.

Measured here: `classify()` 32 us on the lure, 20 us on an ordinary
launcher line, 6.5 us on a line with no launcher, 1.3 ms over 16 KB of text
and 2.9 ms when that text is not ASCII (the format-character filter), all
against a 500 ms tick. Corpus: 33 of 33 must_warn fixtures warn with the
signal they are named for; 0 of 38 must_not_warn lines warn, 4 at notice
(the bun, uv and pnpm install lines and a loopback dev server). On the
Windows runner `GetClipboardSequenceNumber` costs 0.93 us per call over
100,000 calls, so the idle poll is 2 us a second. Tests 551 -> 593. Still
not measured on the owner's desktop: the live tick over a session, what
`GetClipboardOwner` resolves to for a browser's write, which password
managers set which marker.

**Explain why, 2026-10-04.** Every verdict can now be opened into an
account of its evidence: `avguard/explain.py`, tkinter-free, turns the
findings back into the model that decided them. Each finding is a fact or
an opinion (hard or soft, the vocabulary `Finding`'s own docstring already
used), with where it came from in words (an exact byte signature, a hash
blocklist and its source, a rule with its declared severity and pack, the
executable's structure, resemblance to a known sample with the two bands
named) and what it weighed; the tally is `decide()`'s arithmetic, facts
against the configured threshold and opinions capped at 75, not
`Verdict.score`, which is the uncapped sum and would read 150 for a file
with a signature and an odd structure; the level has one sentence of
meaning; what can be done depends on what happened (quarantined, reported,
left alone, kept). Surfaces: a "Why?" button beside every detection banner,
including a reported-only threat and, under real-time protection, a
SUSPICIOUS file, both of which now also get "Never scan" (before this only
an automatic quarantine offered a way out); "Why was this taken?" on the
Quarantine tab; a double-click on a History row, which is also where the
reasons of an event with a path can finally be read; `--scan --explain`,
`--scan --json` (one object per file, the log and the summary on stderr)
and `--explain-quarantine ID`, read-only and without the instance lock.
Refused, with a test: a confidence number. The only percentage an account
can carry is a pack's measured admission rate, with its corpus size, said
to be the pack's and not the rule's.

It started from a lie, measured here: the first scan of the self-test
marker was MALICIOUS with one hard finding of 100; the second, served from
the cache in 0.15 ms, was MALICIOUS with `findings=[]`, `score=0` and no
digest, and that 0 is what `_handle_threat` wrote to History and what
event forwarding sent. The cache now keeps the findings (`ScanCache.SCHEMA`
3 -> 4, so every cached verdict is forgotten once on upgrade; the schema is
part of `detection_generation()`, so no process can replay a schema-3
entry, and `DETECTION_VERSION` stays 15 because the same bytes still yield
the same level and reasons), a replay rebuilds the Verdict with its
findings and `sha256`, and `Finding` gained `severity`, `pack` and `notes`
(a rule's `note` and `reference` meta, which reached nobody before) with
defaults, so no constructor and no reason sentence changed; a test holds
the sentences byte-identical.

The evidence travels. Detection, suspicious and quarantined events carry
`detail.findings`, `hard`, `soft_capped`, `threshold` and `sha256`, inside
`detail` so the seven schema-1 fields stay what they are (a test pins the
set); the forwarding consent sentence and the README now name the evidence
as something that leaves the machine, and the paste guard's events stay
local as before. A quarantined file's evidence lives in a sidecar
(`quarantine/index_evidence.json`), not on the record: the design put it
on `QuarantineRecord`, and `_reload_and_merge` drops any index row with a
field it does not know and would then save the index without it, so an
older AVGuard started after a newer one would have lost the user's held
files from view. The sidecar write is best effort and never raises; a
record without one reads as "recorded before evidence was kept", as does
an event without detail, and nothing is invented for either.

Measured here (Linux; the module is pure and the numbers are the same
shape on Windows): a cache hit 66 us before and 69 us after per `scan()`
over 1,000; `EventStore.record()` 23 us without and 33 us with the
evidence in detail, 311 bytes more per detection line; a cache entry 427
bytes with one finding (212 of them the finding) and 14 bytes more for a
clean entry; `explain()` plus `render_text()` 9 us on the self-test
verdict and 25 us on the worst fixture (four opinions, a resemblance and a
noted rule: 1,742 characters, 23 lines); the account dialog 18 ms to build
on a warm root under Xvfb, 712x412 requested. Tests 593 -> 624: the replay
keeps its findings; a schema-3 cache is dropped with the log line; the
tally reproduces `decide()` for every fixture shape including the capped
pile and the signature-plus-structure file; the threshold comes from the
config; a pack rule names its pack, trust and rate with corpus size; no
line of any rendering carries a percentage without "clean files" or a
number beside "confidence" or "probability"; the sidecar and its failure;
the event detail through the store; the dialog, History and the
reported-threat banner on the shared root; the three console verbs,
`--explain-quarantine` with another instance holding the lock. Read, not
measured: the wording of the ten fixture accounts. Not yet on the owner's
desktop: the one-time cache drop on a real Downloads folder, the dialog at
the main window's minimum size with a long path, and whether the "Why?"
button is found.

**The account, second reading, 2026-10-04.** The same four-lens
adversarial read the paste guard had (the scanner and stores, the account
module, the window, privacy and the tests), with every finding reproduced
here before anything changed. What was wrong, in order of weight.

The console. `--json` reported from the scanner's four worker threads with
`print()`, two writes per line, so objects merged and lines went missing:
85 of 660 objects unparsable on a 660-file folder here. One lock and one
write per line now, for `--explain` too. With `--quarantine`, `--explain`
and `--json` printed "Nothing was moved." for a file the same command then
moved; the account of a MALICIOUS file now waits for the quarantine step
and says what happened, "Quarantined." on success and "Nothing was moved."
when the lock was refused or the store raised. A blank line still reached
stdout under `--json --quarantine`. `as_json` wrote raw characters, so a
Windows console code page that cannot encode a path would have lost that
object; it is ASCII-safe now and `json.loads` restores every character.

The window and History. Every History row opened an account, so a scan
summary or a restore read "[CLEAN] Nothing found."; only detection,
suspicious and quarantined rows open one now, a double-click opens the row
under the pointer rather than whatever was selected before, and an event
with no level has no meaning invented for it. The detection row of a file
that was then quarantined read "Nothing was moved."; the window records
what happened in the event (`detail.state`), and an older detection event
with no state reads "Detected", a sentence that claims nothing about a
move. `_report_suspicious` gated on the worker thread being alive, which
every small scan had already outlived when its own verdicts were pumped,
so the banner it was meant to suppress during a scan was shown and then
torn down by "Scan complete"; the gate is a flag the window owns between
`_start_scan` and `_scan_finished`. A detection whose quarantine failed got
neither "Why?" nor "Never scan". The dialog, shrunk to the minimum it
allowed, lost its button row and clipped its note: the buttons and the note
are packed first from the bottom so the text absorbs the shrink, Close is
packed before the actions so it keeps its place, and the minimum width is
the one at which the five buttons fit, 660, checked on a mapped root under
Xvfb at 780x500 and 660x360.

The account and the stores. A History account recomputed the tally with
today's threshold, so after a change to `quarantine_threshold` the level
line and the counted line contradicted each other; the threshold the
verdict was decided with travels with the evidence (events already carried
it; the quarantine sidecar now holds the whole `evidence_detail`, not a
bare list) and is the one shown. A CLEAN verdict with findings under the
reporting line, or kept by the user's decision, said "Nothing found."; it
says which it was. A skipped or unreadable file's one sentence of reason
was dropped from `--json`; the account carries the reasons. `Tally.level()`
disagreed with `decide()` at a threshold of 0 or 100.5 and with no
findings; it carries the finding count and the threshold as given, and a
test runs every fixture at four thresholds. `findings=None` was rendered
as evidence kept. A rule author's note is relayed verbatim, so a pack rule
could put "95% confidence" in the account; such a note is replaced by one
line saying it was left out and why. A shipped rule's note carried a
hex-escaped apostrophe ("somebody E2 80 99 s writing"). `finding_from_dict`
raised `OverflowError` on a weight of Infinity, a JSON token, in the
verdict path. Restore and delete left the evidence row in the sidecar;
they take it with them. The store's constructor rewrote a settled index on
every start, so `--list-quarantine` and `--explain-quarantine` were not the
read-only commands their comments claimed; `_reconcile` saves only when it
changed something. Three forwarding sentences (the Settings label, the
README, the module and config comments) still said "the rule names and the
SHA-256" when the evidence had started to leave; all four now say what
does. Three assertions that could not fail (a schema compared with the
constant that wrote it, a digest compared with its own copy, a time bound
eighty times the measurement) are now ones that can.

Tests 624 -> 640, among them: 280 objects whole across the worker threads;
`--json --quarantine` with no blank line and state "quarantined"; the
threshold from the evidence; "detected" against "quarantined" from
`detail.state`; nothing opened for a summary row or a click off the rows;
an automatic quarantine driven through the window with the sidecar read
back and the "Why?" account carrying the entry id; a settled index's mtime
unchanged by a second constructor; a rule note reaching the finding from a
scan; a confidence note left out; ASCII-safe JSON; every fixture against
four thresholds. Green on 3.13 (GUI hidden) and 3.12 with a display.

**What starts with Windows, 2026-10-04.** The persistence diff from
docs/next-6.md, and Phase 4's "persistence diff" in docs/suite-roadmap.md.
`avguard/autoruns.py` reads the places commodity malware uses to survive a
reboot, at a point in time and as a standard user: the Run and RunOnce
keys for the user and the machine (the machine's in both registry views,
with Task Manager's enabled flag from StartupApproved applied), the two
Startup folders (each file hashed, so a rewritten shortcut counts), every
scheduled task through `schtasks /Query /XML ONE` (decoded with the
console code page; the XML header's UTF-16 claim is not what the console
writes), and every service and driver with an image path, from the
registry. Each is an `Entry` whose key is where it is and what it is
called, and whose fingerprint is what counts: the command, the arguments,
enabled or not, a task's triggers and run level, a service's start type.
A last-run time, a registration date or a description sits in `detail`
and never reaches the fingerprint. Snapshots live in a signed SQLite store
under the data directory (`AutorunsStore`, the integrity baseline's key,
signature and tamper states reused by name), thirty kept, and each new one
is diffed against the previous: added, modified with old and new, removed.
Every change is an event of kind `autoruns`; a change whose command names
only programs under the system root is a grey row and a History event,
never a banner, because that is what an update looks like. Without a
signature checker the system root alone keeps a change quiet, stated as
the trade until the owner's fourteen days of changes say whether it holds
(the second reading below sharpened the rule). Surfaces: a Startup tab beside Integrity
(`avguard/startuppanel.py`, the Integrity tab's design: a worker thread,
`post()`, the last diff on open, Snapshot now), a Health row,
`--autoruns-snapshot` (with `-v` a per-collector table of counts and
milliseconds), `--autoruns-status`, `--autoruns-changes` and
`--autoruns-schedule on|off|status`, which registers a daily snapshot
with the Task Scheduler in the records-only pattern of the integrity
check. No Settings toggle, as the baseline has none: the tab and the
schedule verb are the switches. Every Windows call is behind an
injectable (the registry module, the Startup folders, the `schtasks`
runner), so the whole module runs on Linux against a dict-backed registry
and a `schtasks` fixture, and the collectors run for real on the Windows
runner, where a test takes two snapshots seconds apart and requires them
to differ in nothing.

It produces no Finding, never moves or disables anything, needs no
elevation, driver or hook, and reads nothing that is not configuration:
the recorded "no process monitoring" decision is not reopened, and the
suite roadmap says when it will be (Phase 3). Nothing is stored when
nothing at all was collected, because an empty snapshot would report every
entry as gone the next day; a collector that fails is noted and the others
still run.

Measured on the Windows runner (run #56, printed by the runner's own
test): 898 entries in one snapshot, of them 687 services and drivers in
54 ms, 208 scheduled tasks in 323 ms (`schtasks` is the whole cost), 2 Run
values in 28 ms and 1 Startup file in 1 ms; two snapshots seconds apart
differed in nothing; the database was 843,776 bytes after the two. The
same run found the first defect: one task, Server Manager Performance
Monitor, came back "unreadable XML (unclosed CDATA section)", because the
splitter cut each task at the first `</Task>` and that task's CDATA holds
a data-collector definition with a `<Task></Task>` of its own; the blocks
are now cut at the comments `schtasks` writes before each task, and a
fixture with that CDATA is in the tests. Here on Linux, against the fakes:
a database of 20,480 bytes after one snapshot of 8 entries and 114,688
after thirty; the collectors and the diff in well under a millisecond on
the fixture. Tests 640 -> 668: the
collectors against the fake in both registry views with the disabled flag,
services and drivers with the start and type words, the Startup folders
with the hash and the skipped desktop.ini, the tasks from the fixture with
triggers, run level and the uncounted date and description, console
decoding in four encodings, a failing collector isolated, the diff rules,
the quiet rule with and without a checker, the store's first snapshot,
second snapshot, empty collection, pruning, tamper and re-signing, the tab
through its button on the shared root with the quiet row grey, and the
console verbs. Not yet on the owner's desktop: a fortnight of real daily
diffs, which is what decides whether the quiet rule is enough.

**The startup snapshot, second reading, 2026-10-04.** Four adversarial
lenses over the working tree (the collectors; the store and the diff; the
window and the CLI; privacy and the tests): 33 findings, 6 of them one
defect seen from two sides, 27 distinct, each reproduced before it was
fixed and each fixed with a test. Measured: 34 of the tests written for
this reading fail against the previous commit (`python3.13 -m unittest
tests.test_autoruns tests.test_cli` on a `git archive HEAD` with the new
test files copied in: 26 failures, 8 errors; the window tests were skipped
in that run, which had no display). What mattered most:

- A collector that could not read became an empty kind. `schtasks`
  timing out or refusing, an empty answer, or a Startup folder that cannot
  be listed stored a snapshot with none of that kind, reported every one
  GONE with an event each, and NEW again the day after: 208 and 208 on the
  runner's numbers, the third-party ones loud. A failed read now raises
  `CollectorFailed`, is carried in `Collected.failed` and in the snapshot
  row; the previous snapshot's entries of that kind are kept and the report
  says so; a kind read for the first time after a bad first read is
  recorded, not compared. `run_schtasks` raises on a non-zero exit, and
  "no tasks at all" is a failed read, because no machine has none.
- The quiet rule judged only the host program. `rundll32`, `cmd /c`,
  `powershell -File`, `wscript`, `regsvr32` and `mshta` handed a file under
  the profile were grey, with or without a checker, as were programs in the
  user-writable corners of the Windows folder (Temp, Tasks, tracing, the
  spool colour folder). `Entry.paths()` lists every drive-rooted path in
  the command and all of them must sit under the root and outside those
  corners. An svchost-hosted service was judged by svchost:
  `Parameters\ServiceDll` is now read, counted in the fingerprint and used
  as the target, so a hijacked ServiceDll is CHANGED and a new service with
  a DLL under the profile is loud.
- In the window the checker made it worse, not better. `is_trusted` is
  true only for an embedded signature and this file's own measurement is
  11 of 30 System32 files, so most update changes would have been
  announced. Only a signature that fails (`Trust.UNTRUSTED`) makes a
  system-root change loud now, and the checker is asked on the snapshot's
  worker, never on the GUI thread: the reviewer measured 40 changes with a
  20 ms stub freezing the window for 0.81 s, which at the checker's real
  147 ms per cold file is about six seconds. The list the tab opens on uses
  the system-root rule alone.
- The store raised out of the daily task on a database SQLite cannot open
  (`DatabaseError` from `_connect`) and on a signing key it cannot
  unprotect (after the row was written, before the events), while the tab
  and `--autoruns-status` called the same store "no snapshot yet". Both
  now mirror `fim.check()`: the unreadable database is reported, left
  where it is and never written over, the tamper event recorded; the
  unreadable key keeps the snapshot and the events and reports
  key-unreadable; `summarize()` checks the signature before it says "no
  snapshot yet"; the CLI exits 3 and names the file to move away.
  `describe_report()` leads with the integrity word, so the tab no longer
  shows a tamper vanish under "nothing changed" after the re-sign;
  `--autoruns-changes` prints a tampered store's diff under that word and
  exits 3; the daily task configures the log file it had not.
- Smaller, each with its test: the window and the daily task could sign
  over each other's writes (an OS lock on `snapshots.lock` for the whole of
  a snapshot, five seconds' wait, then "another snapshot is being taken");
  duplicate keys kept by one rule, first wins, for the diff, the rows and
  the count; a task in the library root read `\\Name`; a removed entry was
  annotated "under the Windows folder" wherever it was and greyed in the
  tab; `StartupApproved` with a first byte of 7 read as enabled (the low
  bit decides); a command in a Run key's unnamed default value was dropped
  (kept as "(Default)"); per-logon user-service instances
  (`CDPUserSvc_3f2a1`, type bit 0x80) would have been NEW and GONE at every
  sign-in (skipped; the template is collected); a driver key without an
  ImagePath was invisible (`\SystemRoot\System32\drivers\<name>.sys`, noted
  as implied); a Startup file's target was `...\Windows\Start` (the file is
  its own target); the task account was the first `UserId` in the task,
  which a LogonTrigger can own (the Principal's now); `GetConsoleOutputCP()`
  is 0 under pythonw, so the tab and the daily task decoded `schtasks` with
  the ANSI page and a console run with the OEM page, and a non-ASCII task
  name had two identities (`GetOEMCP()` when there is no console; this one
  rests on the Win32 documentation, since the runner has a console); a
  row's detail was cut at the first ": " inside the entry's name.
- Consent. A startup change leaves the machine with its full command line,
  arguments included, and the account a task runs as, and the forwarding
  sentence did not say so. It does now in the four places it is stated
  (the consent dialog, the Settings label, forward.py, the README), and
  the README section says what the snapshot keeps.

Numbers that moved were re-measured: the fixture's database is 118,784
bytes after thirty snapshots (was 114,688; the ServiceDll in `extra`),
20,480 after one; tests 668 -> 695, both suites green. "A dozen times a
month" is gone from the README, the docstrings and this file until the
fortnight counts it. On the Windows runner (run #58; the test now asserts
that no collector failed and no task was unreadable, instead of printing
it): 901 entries in one snapshot, of them 689 services and drivers in
67 ms (a net two more than run #56, after the implied driver keys were
added and the per-logon instances dropped), 209 scheduled tasks in 297 ms
(the Performance Monitor task now among them), 2 Run values and 1 Startup
file in 1 ms each; no collector note; two snapshots seconds apart differed
in nothing; the database was 917,504 bytes after the two, and the
fixture's 122,880 after thirty there against 118,784 here, the file
systems allocating pages differently. 695 tests, 17 skipped, in 208 s on
the runner. Not changed: whether the quiet rule is enough is still the
owner's fourteen days.

**The baseline store, the same three gaps, 2026-10-04.** The startup
snapshot's review named three defects in `fim.py` as "the same shape,
outside this change"; they are inside it now. A key that cannot be
unprotected raised out of `baseline()` and `accept()` after the rows were
written, so the documented way out of key-unreadable, baselining again,
was itself broken: `baseline()` now replaces a key it cannot read and
says so (`BaselineReport.key_replaced`, one line from `--fim-baseline`),
because a baseline is "record what is here now" and the key belongs with
the old one; `accept()` keeps the rows and returns "not signed; baseline
again to replace it" instead of a traceback. The window and the daily
check shared the database and the signature with nothing between them, so
a check landing in the milliseconds between a baseline's commit and its
signature would have recorded a false tamper event: `FileLock`, the OS
lock the snapshot store took, now lives in `fim.py` and both stores use
it; a writer holds it for its write and signature, a check for its
signature check and row read only (the hashing holds nothing), and the
one that cannot get it within five seconds says "in use" and does
nothing. `--fim-*` configured no log, so a check failing under pythonw
left no trace; it configures one, as the window does. Four tests: the key
replaced once and only when it had to be, the acceptance kept and said
unsigned, the lock refusing a second writer and a check and letting the
next one through, the console verbs configuring the log. Tests 695 ->
699, both suites green. The snapshot store keeps its unattended rule
(recorded unsigned, reported) and `--autoruns-status` now names the
folder to move away to start again. Not measured: the race itself, which
the reviewer replayed by hand on the snapshot store and which the lock
makes impossible rather than rare.

**Where a file came from, 2026-10-05.** Item 4 of docs/next-6.md, built
reduced as it was planned. A browser writes an NTFS stream named
`Zone.Identifier` beside a download (`[ZoneTransfer]`, `ZoneId=3`, usually
a `HostUrl`); SmartScreen looks for the mark before running a program and
Office opens a marked document in Protected View; Explorer's extraction
keeps the mark, 7-Zip's drops it unless its propagate option is on, most
other tools drop it. `avguard/provenance.py`
reads the stream with a plain `open()` (on Linux the same name is a
sibling file, which is what the tests use), parses it to a `Zone` that
keeps the host and never the URL, and gives the scanner two findings,
both weight 0 and soft: "downloaded from host" on a verdict that is
already SUSPICIOUS or MALICIOUS, and "extracted from x.zip (downloaded
from host); carries no download mark, so SmartScreen will not ask before
it runs" on a clean program, script or Office document whose bytes equal a
member of a marked archive (reworded in the second reading, below, to
"has the bytes of"). The second is possible because
`_archive_findings` hashes every member it looks at inside a marked
archive and `ProvenanceStore` (`provenance.sqlite` under the data
directory, ninety days, fifty thousand rows, one connection per thread
like the blocklist) remembers them. Surfaces: the account's row ("the
download mark on the file" / "on the archive this was extracted from",
with the line that where a file came from weighs nothing), the event
detail through `evidence_detail`, a `[note]` line from `--scan`, and in
the window one History event of kind `provenance` per file ever (the
store remembers it was told) and one banner per archive per session, no
tray notice, nothing moved. The quarantine reads the zone before it
unlinks the source, keeps it in the evidence sidecar, and puts it back on
restore and export (`write_zone`, the zone only, Windows only): a restored
download is still a download to SmartScreen, which the byte copy had
silently undone. The consent sentences, in their four places, now name
the host and the archive. No `DETECTION_VERSION` bump: no verdict's level
moves, which a test asserts over every rule fixture and the self-test
marker, with and without the mark, and `decide()` is called twice per
verdict in that test, with and without the provenance rows; and since the
second reading the provenance rows are computed on every scan, a cache
replay included, and never stored in the cache, so an entry written before
this existed replays exactly as a new one does.

Measured here (Linux, python3.13, `tests.test_provenance` prints the
first two): `read_zone` 17 us per marked file and 6 us per unmarked one,
1,000 of each, warm, the stream a sibling file; a store lookup 6 us per
miss; over a 167-file corpus (this repository's own files, a quarter of
them renamed .exe so the gated path runs, 1.5 MB, the cache off, best of
three) the whole provenance pass costs 47 us per file (929 against 882);
hashing and remembering the 50 members of a marked 10 MB archive adds
29 ms to a 156 ms scan. On the Windows runner (run #61), where the
stream is real: `read_zone` 58 us per marked file and 16 us per unmarked
one, 1,000 of each, warm; a store lookup 4 us per miss; the quarantine
round trip there reads the zone back off the restored and the exported
file. Not measured: the owner's real Downloads zips. Tests 699 -> 719,
both suites green here and 719 in 191 s on the runner.

**Where a file came from, second reading, 2026-10-05.** Three adversarial
lenses over the change (the scanner and privacy; the surfaces; the tests
and the claims): 30 findings, 23 distinct, each reproduced with a script
before it was fixed and each fixed with a test. Measured: 19 of the
assertions written for this reading fail against the previous commit (15
tests; `python3.13 -m unittest tests.test_provenance tests.test_cli` on a
`git archive HEAD` with the new test files copied in), and one more, the
FIFO test, blocks the old code forever. What mattered most:

- The note said too much. A digest match is "has the bytes of tool.exe
  from app.zip (downloaded from host)", not "extracted from": a
  redistributable DLL that a downloaded zip carries and an installer also
  puts under Program Files has the same bytes, and the old sentence
  asserted an extraction nobody measured. The sentence now says what was
  measured, a document gets "Office will not open it in Protected View"
  instead of "SmartScreen will not ask before it runs", and nothing under
  the Windows or Program Files folders is said anything about.
- The rows lived in the cache. A program scanned before its archive (walk
  order under `scan_tree` is arbitrary: 57 of 60 notes on the reviewer's
  first pass) was cached without the note for thirty days; a flagged file
  cached before the change replayed without "downloaded from"; an archive
  marked after it was cached never had its members remembered. The rows
  are now computed on every scan, replay included, and never stored (the
  cache keeps the conclusion), a replayed marked archive the store does not
  know is read afresh, and one it knows has its members' date moved. That
  is also why `DETECTION_VERSION` stays at 15: an entry written before this
  existed replays exactly as a new one does.
- A clean file's path, hash and archive left the machine under a consent
  that never named them: the provenance event for a clean file is recorded
  with `forward=False`, as the paste guard's are, and the four consent
  sentences now say so and name the member's name that a flagged
  download's evidence carries.
- The stream read 4,096 bytes and parsed the cut line whole, so a referrer
  long enough to push `HostUrl` past the limit had `urlsplit` read the
  username of `https://alice.smith:pw@...` as the host, and a cut in
  `ZoneId=` unmarked the file. The limit is 16 KiB, a full read drops its
  last line, and a host is accepted only if it is one (DNS labels or an IP
  literal, 253 characters at most; a control character, a space, a
  percent-escape or `about:internet` is no host). Lines split on the
  separators Windows writes, not on U+2028; the first block and its first
  `ZoneId` count; a zone outside 0-4 is not a mark.
- A corrupt `provenance.sqlite` opened and abandoned one connection per
  lookup, that is per flagged or gated file (five lookups, five
  connections, five reclaimed by the collector); the store now closes the
  connection it could not use and gives up for the life of the process, and
  catches `OSError` from a folder it cannot make. The row cap sorted the
  whole table on every marked archive once full (73 ms at 50,000 rows, the
  GUI thread waiting behind `mark_told` for up to 92 ms): an index on
  `seen`, the cap checked before the sweep, and the ninety days applied on
  read as well as on write.
- The banner shown during a full scan was replaced by "Scan complete"
  before anyone saw it and the archive counted as announced for the
  session; under real-time protection it replaced a threat's banner and
  destroyed its Why? and Never-scan buttons. The History row is recorded
  whatever the moment; the banner waits for one with no scan running and no
  danger or warning banner showing, and the archive is counted only when
  it was shown. The History row itself showed nothing but the path and
  opened into nothing: the event now carries the finding and `provenance`
  is a verdict kind, so a double-click opens the account with the row.
- The account's confidence filter, written for a rule author's note, ate a
  path with a `%` or a name like `confidential_2024` and said a rule author
  had stated a confidence figure; it applies to YARA findings only now, and
  provenance findings carry no notes (the full archive path and the member
  name, 60 KB of it in one reviewer's zip, no longer ride in the evidence).
- `quarantine()` raised after the file was moved when the evidence was the
  documented bare-list form and the file was marked; it wraps the list and
  cannot raise there now. An extracted copy carrying a zone of 0, 1 or 2
  was said nothing about; only a mark SmartScreen asks about ends the
  lookup. On Linux a FIFO named like the stream blocked `read_zone` and the
  scan behind it; only a regular file is opened there.
- Three claims were false and are gone from the README, the docstring,
  this file and the plan: Protected View does not open on the mark "and
  nothing else"; 7-Zip has propagated the mark since 22.00 when asked (off
  by default), and Explorer's own extraction keeps it; "every honest
  extraction loses it" was contradicted by a test's own comment. The suffix
  sets were revised (drivers, DLLs, `.jar` and `.one` out; Office and ODF
  documents, `.chm`, `.msc`, `.application`, mounted containers in) and
  are said to come from the documentation, not from a measurement here,
  which is still owed on the runner.

The two timings the paragraph above cites now have a command,
`python tools/measure_provenance.py`; run again after the reading it
reports the provenance pass at 975 against 1,022 us per file, that is
inside the noise of a scan that costs a millisecond per file (47 us more in
one run, 47 us less in another), and 34 ms for the marked 10 MB archive.
Still owed, as the plan asked: the 978-file corpus and the owner's real
Downloads zips. Tests 719 -> 733, both suites green.


**Thai lure words, 2026-10-07.** Item 5 of docs/next-6.md, the one part of
the Thai threat pack with a surface: the paste guard's comment rule in Thai.
Researched before it was written, by a workflow of four researchers (the
official Thai strings lures copy; Thai campaign reports; Thai orthography
and NFKC; honest Thai developer comments), an editor, and one skeptic per
proposed phrase told to refute it on attestation, spelling and false
positives. 27 phrases were proposed and 8 kept.

What the research found, and did not. No Thai CERT, Thai press or vendor
report the researchers could reach attests a Thai-language lure page or a
Thai comment appended to a pasted command: every Thai-facing campaign they
found from 2024 to 2026 showed an English reCAPTCHA- or Cloudflare-styled
page, and the Thai verbs in the reports are the reporters' paraphrase. The
kits that localise by browser language leave Thai out wherever their lists
could be read (17 languages in one, 6 in another). What exists is one Thai
localization table, byte-identical in three public ClickFix lure-page
repositories and one captured sample, whose appended tail is the Thai twin
of the English fixture ("ฉันไม่ใช่หุ่นยนต์ - รหัสยืนยัน reCAPTCHA:"); the
skeptics who opened it found the tail on the page, as what the Run box will
"show", not on the clipboard. And the real widgets ship Thai: reCAPTCHA's
checkbox reads "ฉันไม่ใช่โปรแกรมอัตโนมัติ", hCaptcha's "ยืนยันว่าคุณเป็นมนุษย์",
an archived Cloudflare challenge page "กำลังตรวจสอบว่าคุณเป็นมนุษย์", ALTCHA's
"ฉันไม่ใช่บอท". So a lure that copies a widget would show Thai to a Thai
browser, and the words are bought ahead of an attack that has not been
reported. Most Thai news, CERT and vendor pages were behind this session's
egress filter and are known from titles and search excerpts only.

The rule. Eight phrases, each counting alone on a line that already
fetches and runs code, the same gate as the English words: not a robot,
not an automated program, not a bot (three spellings), I am not, are
human, verification code, Google's unusual traffic, and Cloudflare's
security check of your connection. They are phrases, not words, because
Thai writes no spaces between words and every alternative is a substring:
"bot" is inside "chatbot", "automated program" inside "run the program
automatically", "human" inside "human-readable". Refused, on the
false-positive researcher's evidence from Thai GitHub comments and the
skeptics': bare ยืนยัน (confirm) and ตรวจสอบ (check), the two most common
words in honest Thai comments on install lines; ยืนยันตัวตน (authenticate),
the step after an install; สำเร็จ (success); กด Enter (press Enter); bare
หุ่นยนต์ (robot) and บอท (bot); the short ตรวจสอบความปลอดภัย (security
check), found on an honest line above an audit command; and the lure page's
own headings ("verification steps", "verification window", "complete the
verification", "verification successful"), which are page text, never the
pasted line, and generic Thai UI words. Three of those refusals are
stricter than their English twins ("robot", "press enter" and "security
check" count alone); the English words are left as they were. Segments may
be separated by a space; a zero-width space, which Thai pages put between
words, is gone after `normalize()`. NFKC splits sara am (U+0E33) into two
characters and a pattern typed with it would never match; none of the eight
phrases contains it, and `_thai_alternatives()` folds the pattern the same
way so a future one would match both spellings, which a test checks.

Measured, over every fixture with the previous commit's classifier and this
one (`git archive HEAD`, then `classify()` on each file under both): the 7
Thai lure fixtures warn 0 times before and 7 after; the 33 English lure
fixtures warn 33 times before and after with identical signals; the 5
honest Thai lines and the 38 other legitimate lines warn 0 times before and
after. Each phrase is also tested alone, with a space and with a zero-width
space between its parts, and 19 honest Thai comments are tested to stay a
notice. Tests 733 -> 736, both suites green. Not measured: a Thai lure in the wild, because
none has been reported. Found in passing and left for its own change: the
English tail "Cloud identificator: XXXX" that Microsoft reported in August
2025 matches none of the English words; only its checkmark catches it.

**Cloud identificator, 2026-10-07.** That change. Two researchers and two
skeptics read the reported English tails against the rule: Microsoft's
August 2025 post (four forms), Unit 42's July 2025 report, ClickGrab's
nightly captures of live lure sites ("Verification Hash", "Captcha
Verification Hash") and the open-source reCAPTCHA Phish kit. Every one
already matched through "robot", "verification", "a human" or "security
check" except one: "Cloud Identificator: 2031", which Unit 42 saw with no
checkmark at all and Microsoft with one. Bare "identificator" is refused:
about 280 shell and 40 PowerShell files on GitHub use it, as non-native
English for "identifier", as the Romanian word and as the stem of the
Italian one, and the comment gate covers the whole paste. "cloud
identificator" occurs in 25 GitHub files, 23 of them threat intelligence
or detection rules and 2 an argparse help string, none in a shell
comment; the token is `\bcloud ?identificator`, so "icloud" and
"yandexcloudidentificator" are not it. Measured over every fixture with the
previous and this classifier: the new Unit 42 fixture warns 0 -> 1; the 40
other lure fixtures 40 -> 40 with identical signals; the 43 legitimate
lines and the new honest "manifest identificator" line 0 -> 0. Tests
751 -> 752, both suites green.


**The swap guard, 2026-10-07.** Item 6 of docs/next-6.md, measured before
it was built, as the plan asked, on the Windows runner instead of the
owner's machine. A test (the test writes the clipboard; the module never
does) wrote two BIP-173 test-vector addresses D ms apart under a poll every
500 ms at a random phase. Run #67: one write moved
`GetClipboardSequenceNumber` by 5 with one format and with three, emptying
alone by 1, and nothing on the runner wrote again within a second; the
original address was read before the swap 0 of 6 times at 0 ms and at
50 ms, 4 of 6 at 200 ms and at 400 ms, 6 of 6 at 600 ms. In every trial the
poll saw one or the other, but a swap between two ticks shows only as a
larger jump of the sequence number, and research on the counter (Microsoft's
documentation and Wine's conformance tests) says it counts clipboard calls,
not copies: a browser's or Office's single copy jumps it as far. So the
guard can recognise only a swap it saw both halves of. Research on
clippers, from vendor reports, puts that in context: the event-driven ones
(clipboard listeners and viewers) rewrite within milliseconds and are not
seen; the polling ones sleep 200 to 500 ms, so a 500 ms tick reads their
victim's address about a fifth to a half of the time; Laplas, which looks a
lookalike up on a server, took about 5 s in one published test. By the
plan's own sentence that made it a README line; the owner asked for the
guard, so it is built and the README says what it cannot see.

The rule, in `PasteGuard.tick()` on the text the tick already read, with no
second reader, no listener, no hook and no clipboard write: an address
(`avguard/wallets.py`: Base58Check for Bitcoin, Litecoin, Dogecoin and
Tron; bech32 and bech32m for Bitcoin and Litecoin segwit; Ethereum with
EIP-55 through a pure-Python Keccak) followed within 2.5 s by a different
address of the same family, written by another program. Not a swap: the
same program writing both (two addresses copied in one wallet), a
remote-desktop or virtual-machine forwarder or a clipboard manager as the
writer (by image name, which a determined program could borrow), another
family, the same address in another case, anything copied in between, or
2.5 s passed. Named in the banner: a replacement that shares two characters
at each end with the original after the family's prefix (the lookalike
clippers' choice), and a near copy that fails its checksum (Microsoft's
2026 table says one stealer changes only the last character of a bech32
address, which leaves an invalid string). No owner on either write is
neither exempt nor a sign: Bitwarden writes that way too. The last address
lives in memory for the window and is forgotten when the guard is off; the
History event carries the family, the seconds and the two program names,
never an address, and is never forwarded. The banner has no "don't warn
again" button: the text it would silence is the replacement.

Found by the same research and fixed here: the guard honoured the two
monitor-exclusion formats KeePass and 1Password set, but not
`CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard`, which
Chromium's password manager and Bitwarden set to 0 on a copied password; it
was reading those passwords (and keeping nothing, but reading them). A 0 in
either, or a value that cannot be read, is now private, checked after the
hung-owner check so no data is asked of a hung program; a history format
that cannot be registered turns the reader off, as the other two do.

Tests: the rule on a fake clipboard with a controllable clock (a swap, the
event with no address in it and not forwarded, a lookalike and an invalid
lookalike, eight things that are not a swap, off forgetting the address,
writes with no owner), the privacy formats through the fake user32 (four
zero or unreadable forms private, the text never read, nothing asked of a
hung owner, a 1 read normally), the window's banner, and on the runner a
swap on the real clipboard and a password marked the way Chromium marks it.
The runner measurement stays, trimmed to 0, 200 and 600 ms, and now asserts
the premise the guard rests on: a swap a tick and more after the copy is
always seen. Not measured: a real clipper (none was run), what owner a
browser's or a wallet's copy reports on a desktop, the program behind a
Windows clipboard-history paste, and the false-positive count over the
owner's real copying. Tests 752 -> 762, both suites green.

**The swap guard, second reading, 2026-10-07.** Three adversarial reviews
of 0365a94 (the rule and its false positives, the reader and privacy, the
tests against the claims) and a design note found that the first version
kept less than it promised and trusted more than it said. This supersedes
three sentences above: the lookalike label is gone, the forwarder list is
no longer trusted by name alone, and "lives in memory for the window" is
now true. What was found and changed:

- The last address was held until the next text read, not for the window:
  an hour of idle ticks still held it, and a private copy, an image or
  over-long text between two addresses left the first one armed, so A,
  then a password, then B warned. It now expires on every tick past the
  window, on every change the guard does not read as text, and when the
  guard is off. The window is measured from when the change was first
  seen, not from the read that a busy clipboard delayed.
- The writer was compared by image name, so a second process named
  `electrum.exe` was "the same program". It is now the process id; a write
  with no owner is never the same as anything.
- The forwarder list trusted five AutoHotkey names, under which every
  script runs, and trusted every name from any folder. AutoHotkey is gone
  (a test pins that no script host is listed), and each remaining name is
  trusted only from the Windows folder outside its user-writable corners
  (the startup snapshot's list, copied and pinned equal by a test) or from
  Program Files. A per-user install of a clipboard manager now warns.
- After a swap, the replacement became the baseline, so the user re-copying
  the original was reported as a second swap that named their own browser
  as the replacer. The original coming back within the window is now not a
  swap.
- The lookalike label (two characters shared at each end) was silent for
  the clippers the guard sees best, which match the first two characters
  including the fixed prefix or only the last one, and its "once in eleven
  million" was wrong for every alphabet (one in about 16,000 for bech32 v0,
  the reviewer's Monte Carlo). It is gone; the banner instead tells the
  user to compare every character. `Swap` no longer carries a SHA-256 of
  the replacement, which the public ledger could reverse.
- The banner sentence had a stray ",." in every plain swap and gave a
  read-to-read time as time since the copy. It now leads with the writer
  ("The clipboard names X as the writer of a different Bitcoin address,
  0.5 s after AVGuard read the one you copied from Y"), so the 120-character
  History cell shows the writer. The log line names only the coin, because
  avguard.log outlives Clear history.
- The history and cloud formats: a value other than 1 (Microsoft defines
  only 0 and 1) is now private, not only 0.
- `wallets.family` accepted a non-ASCII string: KELVIN SIGN (U+212A) is its
  own upper case and lowers to "k", so an all-caps bech32 string with it
  passed. Input is ASCII only. Addresses are compared by decoded payload
  (version and hash, witness version and program, the twenty Ethereum
  bytes), so all-caps bech32 and an EIP-55 address and its lowercase are
  each one address, and a Base58 Litecoin address that begins "LTC" is no
  longer compared without case.
- The tests: the lookalike test skipped on every run (its search found a
  pair at try 1,611,322 of 5000), so the invalid-near-copy path was never
  exercised, and mutants that disabled it survived the suite. It is now a
  fixed specification pair (BIP-173's `...v8f3t4` and `...v8f3t5`) and runs
  everywhere. `tests/test_wallets.py` used the genesis-block address and a
  vanity address; it now uses only the projects' own vectors (Bitcoin Core
  and Litecoin Core `key_io_valid.json`, Dogecoin `base58_keys_valid.json`,
  BIP-173 and BIP-350 valid and invalid lists, EIP-55, TronWeb's test
  string), checks the Keccak permutation against `hashlib.sha3_256` at
  seven sizes either side of the rate by switching the padding byte, and
  rejects 20,000 random Base58 strings and every clipboard fixture. The
  runner's swap test retries a busy read instead of passing on one; the
  harness asserts only on trials with no busy read, at 1000 ms (two ticks)
  instead of 600 ms. The off test gained a positive control; the window's
  edge, the Health count, the tray text and every forwarder name in and
  out of Program Files are tested.

Measured: run against 0365a94, 22 of the 130 test methods in the two files
fail. Six fail on an assertion (two history-format values read as public,
KELVIN SIGN, a script host listed, Tron's payload key, the "LTC1" case
fold); the rest error on the fake clipboard's new process-id and path
arguments, so the behaviour was checked with probes written to 0365a94's
own API: an hour of idle ticks still held the address; A, a private copy,
then B warned; a second `electrum.exe` was trusted; `autohotkey64.exe` and
`ditto.exe` from any folder were trusted; re-copying the original after a
swap warned again and named the browser. All six probes give the right
answer on this commit. `python3.13 -m unittest discover -s tests`: 762 ->
786, both suites green.

Corrections to the record above. `avguard/wallets.py` (9771c15) was
written before the measurement and the check after it; the "+5 per write"
was first printed by run #65, which then failed on its own harness. "A
fifth to a half" is not a measurement: it is P/1000 for a clipper that
polls every P ms under a uniform random phase, computed, not run. The
runner's rows are counts, 4 of 6 at 200 and at 400 ms in run #67 and 2 of
4 at 200 ms in run #69, not "two times in three". The plan's own rule
made an only-slow-clippers answer a README sentence; the owner asked for
the guard anyway, in this session ("do the clipboard-swap guard next"), so
it is built and the README now states its misses: an address inside a
sentence or a `bitcoin:` link, a lookup slower than 2.5 s, a clipper
inside the browser (one process writes both), a private replacement, and
Monero, Solana, XRP and Bitcoin Cash. Still not measured: a real
clipper's timing, the owner a browser's or a wallet's copy reports on a
desktop, the program behind a Win+V paste, how far one Office or browser
copy moves the sequence number (only plain one- and three-format writes
were), and false positives over the owner's ordinary copying. Not
reproduced here and noted: a history format offered by delayed rendering
makes the read wait on its owner's code, and the hung-owner check only
catches an owner hung for 5 s or more.

## Deliberately not doing

The paste guard (above) is the one input that is not a file; it watches a user-mode clipboard buffer through documented calls, with no driver, no hook and no process telemetry, so it does not reopen the first decision here. The EDR-shaped extensions of it are refused by name: no keyboard hook to see Win+R, no automation of the Run dialog, no watching what the user then runs.

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
