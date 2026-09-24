# What to build next

Instructions for an AI coding agent working in this repository. Read this
whole file before writing anything. ROADMAP.md records what was already
built and why; every tier there is done. Nothing below repeats it. The scan
throughput work (numpy histogram in `avguard/scanner.py`) shipped separately
and is out of scope here.

## Ground rules for working in this repo

These come from ROADMAP.md and the code itself. They are not optional.

1. **Measure, then claim.** Every performance or accuracy statement in a
   commit message carries a number and the command that produced it. "Faster"
   without a benchmark does not land.
2. **Hard vs soft findings.** A byte signature, a high-severity rule, cloud
   consensus: `hard=True`, may reach MALICIOUS. Everything heuristic is soft
   and the soft total is capped at 75, below the quarantine threshold. No
   pile of guesses moves a file. New detections must declare which side they
   are on and why.
3. **Detection changes invalidate the cache.** Any change to what a verdict
   means bumps `DETECTION_VERSION` and feeds `Scanner.detection_generation()`.
   The resource-pack incident in ROADMAP.md is what happens otherwise.
4. **Unattended code never moves files.** Scheduled scans do not pass
   quarantine flags. The same applies to everything below.
5. **Network is opt-in.** Anything that phones home gets a consent dialog
   that names exactly what leaves the machine, following the VirusTotal
   pattern in `avguard/cloud.py`.
6. **Validate, then swap.** Anything downloaded is checked before adoption
   and the previous good state survives a bad download. `rulepacks.py` shows
   the shape: build alongside, verify, `os.replace`.
7. **New data lives under `config.DATA_DIR`** so self-protection covers it
   and recording state can never trigger a scan.
8. **Each item lands with tests** in `tests/`, follows the existing style
   (behaviour-named test methods, subTest for cases), and adds a short
   ROADMAP.md entry in the same measured voice: what was found, what was
   built, what the numbers were.

Suggested order: item 1, then 2, then 3, then 4, then 5. Item 1 is the
smallest step to new detection value. Item 2 is the flagship feature. Items
3 and 4 are small. Item 5 needs calibration time and goes last.

---

## 1. IOC hash blocklist with feed ingestion  (effort: S, ~half a day)  — DONE

### Why

The scanner already computes SHA-256 for every file and does nothing local
with it except caching and VirusTotal. A local blocklist of known-bad hashes
is the cheapest real detection there is: one indexed lookup per file, works
offline, and it is the exact workflow a SOC calls IOC matching. Threat intel
feeds publish these hashes for free.

### What exists

- `FileFacts.sha256` in `avguard/scanner.py`, computed in `_read_facts`.
- The validate-then-swap pattern in `avguard/rulepacks.py`.
- The consent pattern and `requests` dependency in `avguard/cloud.py`.

### Build

New module `avguard/iocs.py`.

- **Store:** SQLite at `DATA_DIR / "iocs.sqlite"` (stdlib `sqlite3`, no new
  dependency). One table: `hashes(digest BLOB PRIMARY KEY, source TEXT,
  added_at REAL)`. Digests stored as 32 raw bytes, not hex text. Do not load
  the set into memory; an indexed point lookup is microseconds and the full
  MalwareBazaar dump is over a million rows.
- **Lookup:** in the scan pipeline, after facts are read and before YARA,
  `SELECT 1 FROM hashes WHERE digest = ?`. On hit, emit
  `Finding("ioc", source, 100, f"SHA-256 is on the {source} blocklist",
  hard=True)`. A confirmed-malware hash is as strong as a byte signature.
- **Manual import:** CLI `--iocs-import FILE` accepting one hex SHA-256 per
  line, `#` comments ignored. Useful on its own for CTF work and pasted
  threat intel, and it makes the feed updater testable.
- **Feed updater, opt-in:** MalwareBazaar publishes SHA-256 exports at
  `https://bazaar.abuse.ch/export/txt/sha256/recent/` (last 48 hours, small)
  and `.../sha256/full/` (zipped, large). Default to recent, fetched at most
  daily; offer full as a one-time seed. Send If-None-Match with the stored
  ETag. Parse defensively: strip comments, require exactly 64 hex chars per
  line, and reject the whole download if fewer than 100 valid lines survive
  (a captive portal or error page must not empty the blocklist). Build the
  new table beside the old and `os.replace` on success; any failure keeps
  the previous database and logs one warning.
- **The trap to not fall into:** the blocklist is detection logic, so its
  state must be part of `Scanner.detection_generation()`. Fold in a value
  that changes when the database does (row count plus the updater's
  last-modified stamp is enough). Skip this and a file cached CLEAN before a
  feed update replays CLEAN forever. This is finding-shaped exactly like the
  `DETECTION_VERSION` incident in ROADMAP.md.

### Acceptance

- A file whose hash is in the database scans MALICIOUS with the IOC finding
  named in the verdict; removing the row and rescanning (cache cleared by
  the generation change) returns CLEAN.
- A malformed feed download leaves the previous database intact.
- Updating the feed changes `detection_generation()`.
- Feed fetching never runs unless the user opted in.

### Tests

`tests/test_iocs.py`: hit, miss, hex validation, comment handling, the
reject-tiny-download guard, atomic swap on failure (simulate with a download
that raises mid-write), and a generation-change assertion.

### Built  (2026-09-22)

`avguard/iocs.py`; `--iocs-import FILE [--iocs-source NAME]`, `--iocs-update
[--iocs-full]`, `--iocs-status`; a Settings switch with the consent text next
to it; a Health row; `tests/test_iocs.py` (23 tests) and a smoke round trip.
Two deviations from the text above, both for a measured reason:

- **A transaction, not `os.replace`.** Windows will not replace a file that
  another handle has open, and the running GUI holds one. One SQLite
  transaction gives the same guarantee -- a bad or truncated download changes
  nothing -- without the file dance. Tested with a write that dies halfway:
  count and version unchanged.
- **The recent export merges; no feed ever deletes.** Replacing the feed's
  rows with the last 48 hours would forget every older hash on each update.
  A download with fewer than 100 valid hashes is refused whole.

Numbers: a million random digests import in 11.6 s and take 126 MB; a lookup
is 7 us on a warm connection (289 us if a connection were opened per call, so
there is one per thread); `COUNT(*)` on a million rows is 53 ms, so the count
is kept in a meta row and the generation token is the list's version.
Inside `scan()`, cache off, 300 warm files, three rounds: median 551 us with
an empty list, 550 us with a million rows -- no measurable cost. The live
feed parsed cleanly: 1,484 hashes in 1 s, then a 304 on the second call.

---

## 2. File Integrity Monitoring  (effort: L, a weekend)  — DONE

### Why

This is the feature that moves AVGuard from "malware scanner" toward "host
security suite". A FIM baselines the hashes of files that should not change
and alerts when they do. It is a standard blue-team control, it appears in
Security+, and every mechanism it needs already exists in this codebase:
chunked hashing, the events store, exclusion globs, scheduled tasks.

### What exists

- Chunked SHA-256 in `scanner.py` (write a hash-only reader; `_read_facts`
  also computes entropy and signature hits, which FIM does not need).
- `avguard/events.py` JSON Lines store for durable findings.
- `matches_excluded_glob` in `avguard/protection.py`.
- The `schtasks` integration from Tier 3 for scheduled checks.
- The lesson from quarantine finding 3: never rewrite shared state from a
  stale in-memory snapshot.

### Build

New module `avguard/fim.py`, CLI first, GUI tab after it works.

- **Baseline:** `--fim-baseline ROOT [ROOT...]` walks the roots (reusing the
  exclusion globs), hashes every file, and writes
  `DATA_DIR / "fim" / "baseline.sqlite"`: `files(path TEXT PRIMARY KEY,
  sha256 BLOB, size INTEGER, mtime_ns INTEGER, baselined_at REAL)`. SQLite
  rather than JSON so a check can update rows incrementally instead of
  rewriting the whole file from memory.
- **Check:** `--fim-check` re-hashes everything in the baseline and re-walks
  the roots. Report three kinds of change: MODIFIED (hash differs), ADDED
  (on disk, not in baseline), REMOVED (in baseline, gone from disk). Each
  becomes an event (`kind="fim"`) with old and new hash, and a console
  summary. A FIM check **never quarantines**; changed is not the same as
  malicious, and ground rule 4 applies.
- **Timestomping, handled honestly:** attackers reset mtime after modifying
  a file. So the default check ignores mtime and hashes everything. Offer
  `--fast` that skips files whose size and mtime are unchanged, and document
  in its help text exactly what that trades away. Write the test that proves
  the difference: a modified file with restored mtime is caught by the
  default check and missed by `--fast`.
- **The baseline is a target.** Malware that edits a monitored file would
  next edit the baseline to hide it. Two layers: the baseline lives under
  `DATA_DIR` (already inside self-protection), and its integrity is verified
  with an HMAC. Key management without inventing crypto: generate a random
  32-byte key once, protect it with Windows DPAPI (`CryptProtectData` via
  ctypes, user scope, no new dependency), store the protected blob beside
  the baseline, and store `HMAC-SHA256(key, baseline bytes)` in a sidecar
  updated on every legitimate write. On load, a mismatch does not stop the
  check; it emits a loud event: the baseline itself was modified outside
  AVGuard. Document the limit the same way README documents the quarantine
  XOR: code running as the same user can replay this API, so the HMAC
  defends against tampering by other tools and casual edits, not against an
  attacker who already owns the account.
- **Scheduling:** wire `--fim-check` into the existing `schtasks` daily task
  as an option. Unattended, so it records events and moves nothing.
- **Update flow:** `--fim-accept PATH` re-baselines one path after the user
  reviews a change, so the alert does not repeat forever. Accepting is a
  user action, never automatic.

### Acceptance

On a seeded temp tree: flip one byte in one file, add one file, delete one
file, run the check, and the report names exactly those three with correct
old and new hashes. Restore a modified file's mtime; default check still
reports it, `--fast` does not, and both behaviours are asserted. Corrupt one
byte of the baseline database out of band; the next check emits the
tamper event.

### Tests

`tests/test_fim.py` covering the acceptance list, plus: excluded globs are
honoured during baseline and check, REMOVED does not fire for excluded
paths, and a second baseline run replaces rows without duplicating them.
Mock DPAPI on non-Windows CI with a reversible stub so the HMAC logic runs
everywhere and the ctypes path is exercised only on the Windows runner.

### Built  (2026-09-22)

`avguard/fim.py`; `--fim-baseline ROOT...`, `--fim-check [--fast]`,
`--fim-accept PATH...`, `--fim-status`, `--fim-schedule status|on|off` (a
second `schtasks` task, records only); a Health row; `tests/test_fim.py` (21
tests: the acceptance list, exclusions, the second-baseline replace, the real
DPAPI round trip on Windows, a reversible stub everywhere else, and the CLI
round trip). CLI first, as the text says; the GUI tab followed on
2026-09-24: `avguard/fimpanel.py`, the Integrity tab beside Quarantine in
the main window, measured in ROADMAP.md under "The Integrity tab".

Two things found while building:

- **A baseline damaged badly enough that SQLite cannot read it** made the
  first version of `check()` raise instead of report. The signature check
  runs before the rows are read, so the tamper event is recorded and the
  check says what it could not do; a scheduled task raising into nothing is
  the v1 failure shape.
- **Excluding the data directory cost 1.34 s of a 1.64 s check** over 2,000
  files, because every path was resolved against the disk twice through
  `path_within`. The data directory's spellings are computed once and
  compared as text: the same check is 0.21 s.

Numbers, 2,000 files / 596 MB: baseline 21 s on cold files (28 MB/s -- the
first touch, the on-access scanner's cost, the same thing the compiled-rule
cache was built around) and 1.0 s warm (577 MB/s); a full check 0.73 s
(818 MB/s); `--fast` 0.21 s with nothing hashed. A DPAPI-protected key is
332 bytes.

---

## 3. Event bridge to Network Watchdog  (effort: S, ~2 hours)  — DONE

### Why

AVGuard is the host layer and Network Watchdog is the network layer of one
home suite. The watchdog's server cannot see host detections today. The
events store already records them; forwarding is a small step that makes the
two projects one product.

### Build

- Config gains `event_forward_url: str = ""`. Empty means off. Enabling it
  is a settings action with the same consent framing as VirusTotal: state
  that scan events (path, verdict, rule names, hashes) will be POSTed to
  that URL.
- On each event append in `events.py`, also enqueue the event dict, plus
  `"schema": 1`, to a forwarder thread that POSTs JSON with a 2-second
  timeout. Freeze the current event fields as schema 1 in a comment; the
  watchdog will parse them.
- **Never block the scan path.** Bounded queue, drop-oldest on overflow,
  failures logged at debug and dropped. The GUI pump lesson from ROADMAP.md
  applies: a dead or slow endpoint must not be visible in scan behaviour at
  all.

### Acceptance

With a local HTTP test server, a scan produces POSTs matching the events
file. Kill the server mid-scan; the scan finishes at the same speed and the
log shows dropped forwards at debug level only.

### Tests

`tests/test_event_forward.py` with `http.server` in a thread: delivery,
schema field present, queue overflow drops oldest, dead endpoint changes
nothing about verdicts or timing.

### Built  (2026-09-22)

`avguard/forward.py` (`EventForwarder`: a bounded queue of 500, drop-oldest,
a daemon thread posting JSON with a two-second timeout, failures at debug
level); `EventStore(forwarder=...)` hands each event over after writing it;
`event_forward_url` in the config, empty by default; a URL field in
Settings with a yes/no that names what leaves the machine; a Health row;
`tests/test_event_forward.py` (6 tests, an `http.server` on 127.0.0.1).
Schema 1 is frozen in a comment above `Event`.

Measured: `record()` is 170 us without a forwarder and 258 us with a dead
endpoint, the difference being the queue. A closed local port does not
refuse on this Windows -- the connect runs to its full timeout -- so a dead
endpoint drains at one event per timeout on the worker thread, which the
caller never feels; 601 events into a blocked endpoint: submit() returned
in under a second, the newest 500 kept, the oldest 100 dropped.

---

## 4. Explorer right-click scan  (effort: S, ~2 hours)  — DONE

### Why

The GUI and CLI both require going to AVGuard. The standard Windows AV
gesture is right-clicking a suspicious download. Per-user registry keys make
this work without admin rights.

### Build

- `avguard/shellext.py` using stdlib `winreg`. Install writes
  `HKCU\Software\Classes\*\shell\AVGuard.Scan` and
  `HKCU\Software\Classes\Directory\shell\AVGuard.Scan`: `MUIVerb` of
  "Scan with AVGuard", `Icon` pointing at the executable, and a `command`
  of `"<exe>" --scan "%1"`. Resolve `<exe>` from `sys.executable` when
  frozen, else the `python -m avguard` form.
- Uninstall deletes exactly those keys and nothing else. Expose both as a
  checkbox in settings and as `--install-context-menu` /
  `--remove-context-menu`.
- The single-instance lock from Tier 1 already defines what happens when the
  GUI is running: the scan runs, quarantine writes refuse. State that in the
  help text rather than reinventing it.

### Acceptance

After install, the keys exist with the right command string; after remove,
they are gone. Invoking the command form scans the target. On a machine, the
menu entry appears for files and folders (manual check, note it in the
ROADMAP entry).

### Tests

`tests/test_shellext.py`: registry writes and removals against `winreg`
mocked with a dict-backed fake, command-string quoting for paths with
spaces and Thai characters, frozen vs unfrozen executable resolution.

### Built  (2026-09-22)

`avguard/shellext.py` (two per-user keys under `HKCU\Software\Classes`,
`MUIVerb`, `Icon`, `command`; install, uninstall, installed, all through an
injectable registry); `--install-context-menu`, `--remove-context-menu`; a
checkbox in Settings; a Health row; `tests/test_shellext.py` (12 tests
against a dict-backed fake of winreg).

One addition the text did not ask for, because the entry would have been
useless without it: `--pause`. The command runs `python.exe` (never
`pythonw.exe`) with `--scan "%1" --pause`; a console that closes when the
scan ends shows nothing, and the windowed build has no console, so
`--pause` waits for Enter where there is a terminal and shows the summary
in a small window where there is none. Its help text says what happens
when the AVGuard window is open: the scan runs, only moving a file is
refused.

**Not checked on a real Explorer.** Writing to the user's registry is not
this session's to do; the tests prove the exact keys and strings against
the fake. The manual check is one right-click away.

---

## 5. Fuzzy hashing with TLSH  (effort: M, a day plus calibration)  — DONE

### Why

SHA-256 matches only identical bytes; a one-byte change defeats item 1.
TLSH produces a locality-sensitive digest where similar files score a small
distance, so known-family variants become detectable. This is the standard
next rung above exact-hash IOCs.

### What exists

- The one-pass chunked read in `_read_facts`, which TLSH can join:
  `py-tlsh` supports streaming (`update(chunk)` then `final()`).
- The soft-finding cap from Tier 2, which is exactly where similarity
  belongs.

### Build

- Dependency: `py-tlsh` (wheels exist for Windows; pin in
  `requirements.txt` with a comment). Import guarded like numpy: absent
  means the feature is off, never an error.
- Compute the TLSH digest inside `_read_facts` alongside SHA-256 and store
  it on `FileFacts`. TLSH returns TNULL for inputs under 50 bytes or with
  too little variance; treat that as "no digest" silently. **Measure the
  cost:** benchmark `_read_facts` on the 64 MB file before and after. If
  throughput drops below 200 MB/s, compute TLSH only for files under a size
  cap and record the cap and the numbers in the commit.
- Reference set: a `tlsh(digest TEXT, family TEXT, source TEXT)` table in
  the item-1 database, filled by `--iocs-import` when a line looks like a
  TLSH digest (starts with `T1`, 72 hex chars) with an optional
  `,family` suffix. MalwareBazaar's per-sample API includes TLSH values for
  seeding by hand; no automatic feed in this item.
- Matching: for each scanned file with a digest, compute `diff()` against
  the reference set. This is a linear pass, so it only runs when the table
  is non-empty; log a startup warning above 10,000 entries. Distance at or
  under 30 emits a soft `Finding("tlsh", family, 50, ...)`; 31 to 60 emits
  weight 25. **These thresholds are folklore.** Before adopting them, run
  the existing benign corpus harness from Tier 1 against a seeded reference
  set and print the false-positive rate per threshold, the same way rule
  over-breadth is measured. Adjust until the corpus is clean, and put the
  measured table in the ROADMAP entry.
- Verdict semantics: similarity is a guess, so the findings are soft, the
  75-point heuristic cap applies, and a TLSH match alone can reach
  SUSPICIOUS and never MALICIOUS. If a hard signal is also present the file
  was already condemned without TLSH's help.
- The reference table is detection state: fold it into
  `detection_generation()` exactly as in item 1.

### Acceptance

A file and a copy with one flipped byte score distance under 10 and the
copy is flagged SUSPICIOUS against a seeded reference. Two unrelated random
files score large distance and stay CLEAN. Sub-50-byte files scan without
warnings. The corpus false-positive run is recorded with its numbers.

### Tests

`tests/test_tlsh.py`: distance ordering (identical < near-variant <
unrelated), TNULL handling, the soft cap keeping a lone match below
MALICIOUS, generation change on reference update, and a skip marker when
`py-tlsh` is absent so bare installs stay green.

### Built  (2026-09-24)

`avguard/tlsh.py`: the digest, the distance and the vectorised match, with
no compiled dependency; a `tlsh` table in the blocklist database, filled by
`--iocs-import` from lines of `T1` + 70 hex with an optional `,family`;
`--tlsh PATH...` to print digests for seeding; the nearest reference as one
soft finding in `scan()`; `--iocs-status` and the Health row report the
count; `tests/test_tlsh.py` (32 tests); `tools/tlsh_calibration.py` for the
thresholds. The measurements and the table are in ROADMAP.md.

Five deviations from the text above, each for a measured reason:

- **No `py-tlsh`.** It has no wheel for any interpreter on any platform and
  its sdist needs a compiler. The digest is written here instead, from the
  reference source, and checked against the reference built from that
  source: bit-identical on every backend and every chunking tried. If
  `py-tlsh` is importable anyway it is used (119 MB/s); numpy is listed in
  `requirements.txt` as the accelerator (16.5 MB/s against 2.4 MB/s).
- **A size cap per backend, and no digest without a reference.** 200 MB/s
  was never on the table: the facts pass itself runs at 16 MB/s. The cap
  keeps one digest near 100 ms (16 MB native, 2 MB numpy, 256 KB plain), and
  nothing is digested until the reference table has a row, so an install
  that never seeds one pays nothing.
- **The far band is 40, not 60.** At 60, one clean executable in thirty is
  tagged per hundred references, and the pairs are unrelated modules that
  share only ELF boilerplate; at 40 the band is as clean as the near band.
- **The warning is about false positives, not cost.** With the match
  vectorised, 10,000 references cost 2.5 ms per file; what grows with the
  set is the chance that some reference sits near an unrelated file, about
  1% of clean executables per 1,000 references. The store warns at 1,000.
- **The corpus was ELF.** This session ran on Linux, so the calibration
  used the software here. The tool takes the plan's Windows roots by default
  on Windows, and re-running it there is one command.

### First attempt  (2026-09-22): not built, and why

Measured, in the order the text asks for:

- `pip download py-tlsh --only-binary :all:` finds nothing for Python 3.13
  on Windows; the index has only the sdist (`py_tlsh-5.0.0.tar.gz`). The
  text's "wheels exist for Windows" was true for older interpreters.
- The sdist needs a C++ compiler. `pip install py-tlsh` in a fresh venv
  here fails at "Failed building wheel for py-tlsh". Nothing on this
  machine builds it, and nothing on a user's machine would either.
- A pure-Python implementation is the only dependency-free route. Its
  inner loop -- six Pearson lookups per byte over 3-byte windows, plus the
  checksum -- runs at **0.9 MB/s** in CPython 3.13 on this machine. The
  text's own floor is 200 MB/s; a 1 MB file would cost a second, and the
  size cap that keeps it affordable would exclude the executables it is
  meant for.

What would unblock it: a `py-tlsh` wheel for the interpreter in
`requirements.txt`, or the vendored C++ behind a small extension built in
CI and shipped with the executable. Both are a packaging decision, not an
afternoon. The reference-set table, the `--iocs-import` extension and the
soft-finding semantics are designed and small; the digest is the blocker.

*(What unblocked it, two days later: the 0.9 MB/s was the byte loop, not
the algorithm. Written with the interpreter's vectorised primitives the same
digest runs at 16.5 MB/s; see above.)*

---

## Explicitly out of scope

The "deliberately not doing" list at the end of ROADMAP.md stands: no
kernel or process monitoring, no catalog signature verification, no
self-hosted signature distribution, no RAR or 7z, and the quarantine
masking stays described as masking. Nothing above requires reopening any
of those decisions.
