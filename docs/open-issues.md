# Open issues

From a six-lens adversarial audit of the finished code, run once all three
tiers were built and the repository was public. 66 findings raised, 65
confirmed, 1 refuted.

Every entry below was reproduced before being written down. Where something
says "verified", there was a script that made it happen. The ones already fixed
keep their reproduction as a regression test, because a bug that is fixed
without a test is a bug that is waiting.

Ranked by the same rule as everything else in this project:

1. does it lose the user's data
2. does it make the program lie about its own state
3. does it break for somebody who is not this developer
4. does it embarrass the project in public

---

## Fixed

| # | What | Where it is now tested |
|---|---|---|
| 1 | Quarantine destroyed the file if the index write failed | `tests/test_durability.py` |
| 2 | Real-time protection reported healthy while scanning nothing | `tests/test_durability.py` |
| 3 | A text rule could quarantine a security incident report | `tests/test_rules.py` |
| 4 | Restoring a file was not remembered, so it was taken again | `tests/test_durability.py` |
| 5 | The GUI replayed stale verdicts and destroyed the CLI's cache | `tests/test_tier3.py` |
| 6 | A user rule named `malware.yara` erased the shipped ruleset | `tests/test_tier3.py` |
| 7 | The package could not be imported off Windows | CI, `imports cleanly (linux)` |
| 8 | `os.path.isjunction` called unguarded on Python 3.11 | `tests/test_tier3.py` |
| 9 | Two CLI commands crashed after doing their work | `tests/test_tier3.py` |

### Notes worth keeping

**Quarantine (1).** The order was: write payload, unlink original, save record.
The nonce that decodes the payload lived only in memory until that last step,
so a full disk or a process kill in the window deleted the file and left a
payload nothing could ever decode — not restore, not `--export-all`, not by
hand. The `OSError` was also bare, so it escaped every caller's
`except QuarantineError` and was swallowed by the UI pump: the user saw a
threat line and then nothing at all.

**The heuristic cap.** `cygwin1.dll` trips the injection rule (medium, 50) and
has both a writable-executable section and a virtual-only section (50). Those
summed to 100 and a library half the world uses would have been quarantined.
Weak signals correlate — an unusual binary trips several checks for one
underlying reason — so summing them manufactures confidence that is not there.
Findings are now split `hard` and heuristic, and heuristics cap below the
threshold. **No pile of guesses can move a file.**

---

## Open

### A. `RealtimeMonitor.start()` crashes, and nothing records it

**Verified.** Starting on a folder that no longer exists raises
`RuntimeError: cannot join thread before it is started` — `start()` builds an
`Observer()`, never starts it, then calls `stop()`, which joins it. `stop()`
raises the same way on its own.

Two things make this worse than an ugly traceback:

- `realtime_enabled` defaults to `true`, and `gui._start_realtime` does not
  guard the call. A watch folder that has been deleted since it was configured
  — a removable drive, a cleared Downloads — makes `AVGuardApp.__init__` raise
  and **the window never appears at all.**
- `logsetup.install_excepthooks()` is defined, is referred to approvingly in
  two comments, and **is called from nowhere.** `build.py` produces a
  `--noconsole` executable, so under `pythonw` there is no stderr: the user
  double-clicks and nothing happens, forever, with no log line.

**Fix.** Guard the join in `stop()` with `is_alive()` and wrap the teardown.
Wrap `monitor.start(...)` in `gui._start_realtime` and treat a failure exactly
like an empty result — log it, untick the toggle, banner it. Call
`logsetup.install_excepthooks()` at the top of both `main()` functions.

**Test.** `mon.start([missing])` returns `[]` without raising; `stop()` on a
never-started monitor does not raise; a GUI whose watch path does not exist
still constructs.

### B. Watching a folder inside the project scans nothing, silently

**Verified earlier, in CI.** `SelfProtection` covers the whole project, and it
is checked before a file is opened. So "clone the repo into Downloads, watch
Downloads" watches a tree it will always refuse. `start()` accepts the path
without comment.

This is the same shape as the CI failure that scanned inside the checkout and
reported success for a scanner that had not looked at anything.

**Fix.** `start()` returns protected paths separately so the caller can say so.

### C. The detection ceiling is not stated anywhere

With the cloud lookup off, the only things that can reach MALICIOUS are EICAR,
the self-test marker, and — since the ransomware rule was correctly demoted —
nothing else. Every heuristic reports and none condemns. That is the right
design for a hobby scanner and it is why 8,843 clean binaries produce zero
false positives.

It is also not written down anywhere, and a scanner that quietly implies more
than it does is the thing this project exists to not be.

**Fix.** State it plainly in the README, next to the self-test instructions.
One honest paragraph is a better look than an implication.

### D. Smaller, real, not urgent

- `_settings_saved` restarts the monitor but does not re-read `watch_paths`
  from disk if another process changed them.
- `detection_generation()` reads every rule file on construction; on a large
  user rules directory that is measurable.
- `EventStore.summary()` reads up to 5,000 events to count them.
- `archives.iter_nested` takes a `depth` parameter that its only caller never
  passes, so the documented depth limit is enforced by a constant instead.

---

## Deliberately not doing

**Chasing real-malware detection.** The rules catch test files and patterns,
not live threats. Fixing that means building and maintaining a real corpus,
which is a different project with a different time commitment. The honest move
is item C: say what it does.

**Catalogue signature verification.** `CryptCATAdmin` would close the System32
gap, but the value of Authenticode here is trusting things the user downloaded,
and downloads carry embedded signatures.

**Performance work.** The per-byte entropy histogram is GIL-bound and caps
thread scaling; `is_protected` resolves paths before consulting its cache. Both
measured, neither loses data nor lies, and the scanner is already faster than
anyone needs for a Downloads folder.

**RAR and 7z.** Both need third-party packages. Zip is what browsers produce.
