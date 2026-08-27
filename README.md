# AVGuard

[![tests](https://github.com/Captain-Coding74/avguard/actions/workflows/tests.yml/badge.svg)](https://github.com/Captain-Coding74/avguard/actions/workflows/tests.yml)

A small file scanner for Windows: local signatures, YARA rules, an optional
VirusTotal lookup, real-time folder monitoring, and a quarantine you can
actually undo.

This is version 2. Version 1 is still in this folder and is described in
[docs/postmortem.md](docs/postmortem.md) — worth reading, because most of the
design decisions here are direct answers to something that went wrong there.

## Running it

```bash
pip install -r requirements.txt
```

```bash
python run.py
```

Console mode, no GUI:

```bash
python -m avguard --scan "C:\Users\you\Downloads"
```

That reports what it finds and moves nothing. Add `--quarantine` to act on the
findings (it will refuse if the GUI is open, because two processes writing to
the quarantine store at once destroys its records):

```bash
python -m avguard --scan "C:\Users\you\Downloads" --quarantine
```

Other flags:

| Flag | What it does |
|---|---|
| `--list-quarantine` | print what is held, with ids |
| `--restore ID` | put one file back |
| `--export-all DIR` | write everything held out to a folder |
| `--reload-rules` | recompile the rules and report what loaded |
| `--schedule status\|on\|off` | start with Windows, and a daily scan |
| `-v` | show clean files too |

`--export-all` matters more than it looks. The quarantine holds the only copy
of everything in it, so without an exit door, uninstalling would destroy the
lot.

## Checking that it works

Real antivirus is tested with the EICAR file, but Windows Defender deletes an
EICAR file before your own scanner can open it. So AVGuard also recognises a
harmless marker of its own that nothing else reacts to:

```bash
python -c "from avguard.scanner import SELFTEST_MARKER; open('selftest.txt','wb').write(SELFTEST_MARKER)"
python -m avguard --scan selftest.txt
```

That should report `[MALICIOUS] selftest.txt` with reason
`signature AVGuard-Selftest-Marker`.

## Tests

```bash
python -m unittest discover -s tests
```

No test dependencies beyond the stdlib. Most tests name the specific bug they
exist to prevent, and the run prints the rule corpus size and the measured
false-positive rate rather than asserting a number that can go stale.

CI runs the same suite on a clean `windows-latest` runner. That matters more
than it sounds: the rule corpus samples real binaries from whatever machine it
runs on, so CI is sampling a *different* set of clean software than this
developer's laptop. It is a second opinion on whether a rule is over-broad, not
a repeat of the same measurement. A separate Linux job checks the package still
imports where it cannot actually run.

## How it is put together

| Module | Responsibility |
|---|---|
| `avguard/config.py` | Where files live, user settings, atomic writes |
| `avguard/protection.py` | The rule that stops the scanner touching its own files |
| `avguard/scanner.py` | Guards, one read per file, signatures, YARA, entropy |
| `avguard/quarantine.py` | Neutralised storage, validated restore |
| `avguard/cloud.py` | VirusTotal: opt-in, rate limited, cached |
| `avguard/watcher.py` | Filesystem events, debounce, worker pool |
| `avguard/gui.py` | Tkinter front end |
| `avguard/logsetup.py` | Rotating log file, the GUI feed, and the excepthooks |
| `avguard/instance.py` | The lock that keeps one writer at a time |
| `avguard/archives.py` | Reads inside .zip files without unpacking them |
| `avguard/peinfo.py` | Structural signals from an executable |
| `avguard/events.py` | The durable history behind the History window |
| `avguard/dialogs.py` | Settings, History and Health windows |
| `avguard/signing.py` | Authenticode checks, to lower suspicion on signed software |
| `avguard/scheduling.py` | Start with Windows, and the daily scan |
| `rules/malware.yara` | Detection rules |

Data lives in `%LOCALAPPDATA%/AVGuard` — quarantine store, logs, caches,
`config.json` and your own rules. That whole directory is protected, which is
what makes writing a log line safe. It is deliberately **not** inside the
program folder: keeping it there broke read-only installs, let every user of a
machine see one another's quarantined filenames, and uploaded quarantined
samples to OneDrive when the project sat in Documents. An existing `data/`
folder is migrated on first run.

Set `AVGUARD_DATA` to put it somewhere else — a USB stick, for instance.

### The things that matter

**Self-protection is checked before a file is opened.** `SelfProtection`
resolves the path and refuses it if it sits anywhere under the project — source,
rules, data, docs, tests, the README. It compares resolved paths, not
substrings, so `app2` is not mistaken for `app` and `sub/../scanner.py` is still
recognised. Version 1 quarantined its own ruleset and lost YARA detection
entirely; that cannot happen here.

**Guesses can never move a file.** Evidence is split in two. Hard evidence —
an exact byte match, a rule marked `severity = "high"`, several VirusTotal
engines agreeing — can reach MALICIOUS. Everything else is a heuristic, and the
heuristic total is capped below the threshold no matter how many agree. A file
can be as suspicious as you like and still not be touched.

This is not theoretical. `cygwin1.dll` trips the process-injection rule *and*
two structural checks; before the cap those summed to a condemnation and a
library half the world uses would have been quarantined. Weak signals
correlate, so summing them invents confidence.

**Nothing is moved on weak evidence.** Every piece of evidence carries a weight
and a verdict is a sum, not a boolean. An exact byte signature or a rule its
author marked `severity = "high"` scores 100 and is decisive on its own. A
`medium` rule scores 50: reported as SUSPICIOUS, never moved, unless something
else corroborates it. High entropy scores 25 and cannot raise an alarm by
itself.

    signature or high-severity rule   100  ->  MALICIOUS, may be quarantined
    medium rule                        50  ->  SUSPICIOUS, reported only
    low rule / unlabelled rule         25
    high entropy                       25

The threshold is `quarantine_threshold` in `data/config.json`. Before this,
every rule hit meant MALICIOUS, which meant "move the user's file" — and three
out of three ordinary CI scripts were being moved.

**One read per file.** Version 1 read every file three times — once for
signatures, once for the SHA-256, once inside YARA — then made a blocking
network call. Here a single pass produces the hash, the signature hits and the
entropy together, and files under 8 MB are matched by YARA from that same
buffer. Signature matching carries an overlap between chunks, so a pattern
straddling a chunk boundary is still found.

**Nothing is scanned twice for no reason.** Verdicts are cached against
`(path, size, mtime)`. Editing a file invalidates its entry; saving it in an
editor does not cause four scans, because filesystem events are debounced.

**Quarantine is reversible and inert.** Each entry gets a random id, so an
untrusted filename never reaches the filesystem — no `CON.txt`, no `..`, no
collisions between two files with the same name. The stored payload is XOR-masked
with a per-file keystream and given a `.quar` extension, so it is not something
you can run by accident and not something another scanner will flag. Restore
refuses UNC paths, refuses to overwrite an existing file, refuses to write into
a protected directory, and verifies the SHA-256 before putting anything back.
If you want the original bytes for analysis, that is a separate `Export`
action.

**"Protection is on" has to mean something can actually scan.** Deleting and
recreating a watched folder kills watchdog's per-directory emitter permanently,
while the observer thread, the debouncer and the worker pool all stay alive and
healthy-looking. Measured: four files scoring a hard 100 sat in the watched
folder undetected while the header said protection was on. `running` now proves
every link in the chain, the Health window names whichever one is broken in
plain words, and a check every thirty seconds puts it back.

**Failures are loud.** The UI pump reschedules itself from a `finally`, so a
formatting error in one log line cannot silently stop the program draining its
queues while the window still looks alive. `sys.excepthook` and
`threading.excepthook` write to the rotating log, because under `pythonw.exe`
there is no stderr for a traceback to reach. A YARA ruleset that fails to
compile puts a banner on the window instead of a single line in a log nobody
reads.

**The record reaches disk before your file is destroyed.** Quarantine used to
write the masked payload, delete your original, and *then* save the record. The
nonce that decodes the payload existed nowhere but memory in between, so a full
disk or a process kill in that window deleted your file and left something
nothing could ever decode — not restore, not `--export-all`, not by hand. The
order is now: write payload, save the record marked pending, delete the
original, clear the flag. An interrupted move is reconciled on the next start:
if your file is still there the move is undone, if it is gone the move is
honoured.

**One writer at a time.** Both entry points take an exclusive lock on
`data/avguard.lock`. Two AVGuard processes sharing the quarantine store used to
destroy each other's records: each loaded the index once and later rewrote it
whole, so the second to write erased the first's entries — deleting the user's
originals and orphaning the stored payloads. The lock prevents that, and the
store now re-reads and merges the index before every change so losing the race
is survivable rather than destructive.

**The observer thread does no work.** Watchdog events only record a path. A
debouncer collapses the burst that one file save produces, and a small pool of
worker threads scans. Nothing touches a Tk widget from a worker thread; UI work
is queued and run by the GUI thread. Version 1 called a modal dialog from a
watchdog callback and blocked its own event dispatch.

## Signed software

A valid Authenticode signature tells you **who to blame, not that there is
nobody to blame** — malware gets signed with stolen certificates. So a
recognised publisher sets heuristic concerns aside and nothing more. A byte
signature, a high-severity rule, or several VirusTotal engines agreeing all
still stand, signed or not.

Measured on this machine, it halves the noise: 0.40% of clean binaries came out
suspicious without it, 0.20% with it. Checking costs about 150 ms, so it runs
only after something has already been flagged, and the result is cached.

## Building an executable

```bash
python build.py
```

Produces one `dist/AVGuard.exe` (about 28 MB) with the rules inside it. Needs
no Python on the target machine and no administrator rights.

## VirusTotal

Off by default. Turning it on sends the SHA-256 of a file to a third party,
which is a decision rather than a default.

When enabled it needs `VT_API_KEY` in the environment — never in a config file:

```bash
setx VT_API_KEY "your-key-here"
```

The free tier allows 4 requests a minute and 500 a day. A token bucket enforces
the per-minute rate, a persistent daily budget stops at 400, and results are
cached for a week (including "VirusTotal has never seen this hash", which is
also worth not paying for twice). Only files that nothing local has already
decided about, and whose extension is in `cloud_extensions`, are looked up at
all.

Three or more engines must agree before a file is called malicious. One or two
detections out of seventy is normal for installers and unsigned binaries, and
version 1's `if malicious_count > 0` would have quarantined them.

## Settings

`data/config.json` is written on first run. Useful keys:

| Key | Default | Meaning |
|---|---|---|
| `cloud_enabled` | `false` | Send hashes to VirusTotal |
| `realtime_enabled` | `true` | Watch folders for new files |
| `watch_paths` | `[]` | Folders to watch; empty means Downloads only |
| `auto_quarantine` | `false` | Act on detections, or just report them. Set by the first-run dialog. |
| `max_file_size` | 64 MB | Anything larger is skipped, not read |
| `quarantine_threshold` | `100` | Evidence needed before a file may be moved |
| `worker_threads` | `4` | Scanning threads |
| `debounce_seconds` | `1.5` | How long to wait for writes to settle |
| `archive_scanning_enabled` | `true` | Look inside .zip files |
| `pe_analysis_enabled` | `true` | Structural checks on executables |
| `trust_signed_publishers` | `true` | Let a valid signature set heuristics aside |
| `quarantine_review_days` | `90` | Age at which held files are offered for review |

Most of these have a **Settings** window now; the rest stay in the file
because a wrong value would fail quietly.

Real-time protection watches Downloads and nothing else unless you add paths.
That is deliberate — Downloads is where files arrive from outside the machine,
and watching Documents by default means a false positive moves something you
wrote.

## Writing rules

`rules/malware.yara`. Two habits that version 1's ruleset lacked:

**Don't let the rule match itself.** Write indicators as hex or as a regex with
a bracketed character (`/p[o]wershell/i`), so the literal you are hunting never
appears verbatim in the rule file. Version 1's rules matched their own file and
the scanner quarantined them.

**Require context.** A bare common string is not a detection. Anchor extensions
to a filename shape, demand several indicators together, require the file to be
a PE, and put a `filesize` bound on the rule. `LoadLibraryA` and
`GetProcAddress` are in essentially every Windows binary and carry no signal.

The ruleset is checked by `tests/test_rules.py`, which samples 400 real
binaries from this machine and prints the measured false-positive rate per
rule. Nothing is asserted in prose here, because prose is how the last
false-positive claim went stale: an earlier version of this file said "0 false
positives on 120 binaries", and a wider sweep of 8,843 binaries then found 16,
`kernel32.dll` among them.

## The leftovers from version 1

Still present, not touched, safe to remove when you have looked at them:

- `main.py`, `engine.py`, `handler.py`, `app.py`, `vt_scanner.py`,
  `yara_scanner.py` — superseded by `avguard/`
- `malware.yara` in the project root — superseded by `rules/malware.yara`
- `antivirus_log.txt` — the evidence in the postmortem. It contains the real
  EICAR string 381 times, so a scan of this folder will flag it. That is a
  correct detection of a legacy file, not a bug.
- `quarantine/` — six files, all of them your own project, taken by the tool
  from itself. `docs/postmortem.md` lists what each one is. None of it is
  malware.
- `app website version/app.html` — a mock UI with no backend

`data/` is the new home for everything the running program writes.

## License

MIT — see [LICENSE](LICENSE). Use it, change it, ship it.

The "no warranty" clause is not boilerplate here. This program moves people's
files. It is a hobby scanner with two byte signatures and five rules, not a
replacement for the antivirus your operating system already runs, and it is
built on the assumption that a false positive is worse than a missed
detection. Read [docs/postmortem.md](docs/postmortem.md) before you trust it
with anything you cannot replace.
