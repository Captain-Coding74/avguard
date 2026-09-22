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

## 1. IOC hash blocklist with feed ingestion  (effort: S, ~half a day)

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

---

## 2. File Integrity Monitoring  (effort: L, a weekend)

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

---

## 3. Event bridge to Network Watchdog  (effort: S, ~2 hours)

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

---

## 4. Explorer right-click scan  (effort: S, ~2 hours)

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

---

## 5. Fuzzy hashing with TLSH  (effort: M, a day plus calibration)

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

---

## Explicitly out of scope

The "deliberately not doing" list at the end of ROADMAP.md stands: no
kernel or process monitoring, no catalog signature verification, no
self-hosted signature distribution, no RAR or 7z, and the quarantine
masking stays described as masking. Nothing above requires reopening any
of those decisions.
