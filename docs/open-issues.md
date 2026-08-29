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
| 10 | The app failed to start if a watched folder had been deleted | `tests/test_durability.py` |
| 11 | A crash left no trace at all under the windowless build | `tests/test_durability.py` |
| 12 | Watching a folder inside the project protected nothing, silently | `tests/test_durability.py` |
| 13 | Self-protection missed our own **existing** files under path redirection | `tests/test_durability.py` |
| 14 | The Health view understated what rules were loaded | `tests/test_rulepacks.py` |
| 15 | `--no-gui-deps` blocked nothing, so its passes were unearned | `tests/test_tier3.py` |

### Notes worth keeping

**Path redirection (13).** `%LOCALAPPDATA%/AVGuard/logs/avguard.log` resolves,
on a packaged or containerised app, to
`.../Packages/<app>/LocalCache/Local/AVGuard/logs/avguard.log`. Protected roots
were stored in one form and candidates compared in another, so `is_relative_to`
returned False and self-protection stopped covering AVGuard's own files.

The sting is which files: `resolve()` follows the redirection only for paths
that **exist**, so a missing path stayed unredirected and matched, while the
live log, cache and config did not. Existing files were the unprotected ones,
which is exactly backwards, and it is v1's failure reachable again through a
platform detail nobody had looked at. Protection now stores and compares every
form of every path, case-insensitively where the platform is.

It surfaced because a test failed *only* when run alone. In the full suite it
passed, for ordering reasons — which is its own lesson about trusting a green
suite over a green test.

Having found one instance, the class was worth sweeping. Two other guards
compared paths the same way: the check that refuses restoring a file *into* the
quarantine directory, and rule-pack attribution. Both happened to work on this
machine today, and both would have stopped working once a file was written into
the wrong directory — a guard whose behaviour depends on unrelated filesystem
history is not a guard. `protection.path_within` is now the one place that
answers "is this inside that", and the tests exercise every guard through a
symlink so the two-spellings case is covered portably rather than only where
the redirection happens to exist.

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

### A. Smaller, real, not urgent

All four now fixed. Kept here with what they turned out to be, because one of
them was not the tidying job it looked like.

| # | What | Outcome |
|---|---|---|
| A1 | `_settings_saved` restarted the monitor without re-reading `watch_paths` | Reloads `Config` first, so a folder another process added is not silently reverted |
| A2 | `detection_generation()` read every rule file on construction | Hashes `(name, size, mtime)`, falling back to contents when the stat fails |
| A3 | `EventStore.summary()` parsed 5,000 records to count them | `counts()` scans lines without building dataclasses |
| A4 | `archives.iter_nested` took a `depth` its caller never passed | **Was a real detection gap.** See below |

**A4 was not cosmetic.** `MAX_DEPTH = 2` and the docstring both promised "an
archive inside an archive", but the code hand-unrolled exactly one level and
the `depth` parameter was dead. A marker two archives deep was missed.

It nearly escaped notice twice over: the first test of it passed because the
nested zips were written uncompressed, so the payload bytes sat verbatim in the
container and a plain signature match looked like successful traversal. Only
with deflate — what real archives use — did the gap appear. `iter_nested` is
genuinely recursive now, bounded by a shared byte budget as well as by depth,
and the tests assert the limit in **both** directions: two deep is found, three
deep is not, and a separate test proves the payload is not visible without
descending.

Nothing left open loses data, lies about protection, or stops the program
starting. That was the bar for calling the audit finished.

---

## Deliberately not doing

**Chasing real-malware detection.** The rules catch test files and patterns,
not live threats. Fixing that means building and maintaining a real corpus,
which is a different project with a different time commitment. The honest move
was to say so plainly, which the README now does under "What it actually
detects".

**Catalogue signature verification.** `CryptCATAdmin` would close the System32
gap, but the value of Authenticode here is trusting things the user downloaded,
and downloads carry embedded signatures.

**Performance work.** The per-byte entropy histogram is GIL-bound and caps
thread scaling; `is_protected` resolves paths before consulting its cache. Both
measured, neither loses data nor lies, and the scanner is already faster than
anyone needs for a Downloads folder.

**RAR and 7z.** Both need third-party packages. Zip is what browsers produce.
