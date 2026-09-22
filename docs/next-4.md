# What comes next, round four

Written 2026-09-22. Rounds two and three ([next-2.md](next-2.md),
[next-3.md](next-3.md)) were then put through an adversarial review: six
reviewers, one dimension each, over the diff since `050dd94`, and every
finding handed to two refuters told to prove it wrong. Fifteen verdicts came
back; not one refuted its claim. Those are the items below, with the
refuters' own reproductions as the measurements. A few smaller findings the
refuters never reached are included where the mechanism is plain from the
code and the fix is a few lines.

The repository also moved from `C:\AntiVirus made by myself` to
`C:\AntiVirusmadebymyself`; nothing in it depends on its own path.

Ranked as before: can a file be moved that should not be, or a decision
lost; then does the program lie; then does it break for somebody else.

---

## A. A crash under `pythonw` leaves an empty log  — DONE

**Measured.** `main()` wrapped `_main()` in `try/finally` and closed the
rotating log handler in the `finally`. Python runs the `finally` before the
exception leaves `main()`, so by the time `sys.excepthook` runs the `avguard`
logger has `propagate=False` and no file handler. Reproduced with the real
`main()` and `AVGuardApp` replaced by a class that raises after logging is
configured: `avguard.log` exists and is **0 bytes**; with the close
neutralised, 1,316 bytes including `CRITICAL avguard: unhandled exception`
and the traceback. The `--windowed` build has no stderr, so this is the exact
case the hooks exist for, and round three introduced it while fixing the
leaked log file.

**Fix.** Close the log on the normal-return path only. An exception leaves
the handler for the hook; the interpreter's `logging.shutdown` closes it.

**Tests.** A child process runs the real `main()` with `_main` replaced by
something that configures logging and raises; the log must contain the
message. The existing test bypassed `main()` and could not see this.

**Measured after.** The child's log contains the message and the traceback;
the same child against the previous commit leaves the 0-byte file.

---

## B. A compile refused only by the two-second rule leaves the stale blob forever  — DONE

**Measured.** The manifest's per-file size, mtime and hash were taken *after*
`yara.compile()`, with validation in between. A rule file rewritten in that
window gives a manifest describing the new content beside a blob compiled
from the old. The next start correctly refuses it (the file is within two
seconds of the cache), recompiles correctly, and then
`_compiled_cache_is_current` sees a manifest identical to the one on disk and
keeps the **old blob**, re-stamping only the clock. Every start after that
loads rules that no longer exist on disk. Reproduced by both refuters; the
refused manifest had `saved_at - mtime` of about 30 ms.

Two smaller things in the same code: `compiled_sha256` was hashed from the
shared file after `os.replace`, so two processes compiling at once could bind
one's manifest to the other's blob; and the per-file hash memo survived
`reload_rules()`, so a stat-preserving edit was compiled but neither the
generation nor the blob changed.

**Fix.** Stat witnesses are taken before the compile, so anything written
after them shows as a mismatch. A previous manifest that itself fails the
two-second rule cannot vouch for its blob. The blob's hash comes from the
bytes this process wrote, before the swap. Reload clears the memo. Malformed
manifest fields fall back to a compile instead of raising out of
`Scanner.__init__`.

**Tests.** The exact sequence: compile, rewrite within the window, start
(refused), start again must load the *new* rules. A manifest with
`"saved_at_ns": null` compiles instead of crashing.

**Measured after.** The bad state built directly on disk: the second start
is refused and rewrites, the third adopts and matches the new needle, not
the old. Against the previous commit the third start matched the old one.
A start with the ReversingLabs pack still adopts the cache in 0.24 s; the
witnesses cost 311 stats it was already paying.

---

## C. The self-match check refuses honest packs and disarms trusted ones  — DONE

**Measured.** `_avguard_files()` walks the whole checkout and excludes only
the *destination* directory. A pack unzipped anywhere under the checkout --
`python -m avguard --packs add vendor-rules --licence MIT`, run from the
checkout the README says to run it from -- is refused for matching its own
source files. Reproduced.

And the check is one-directional: pack `beta` is admitted if *its* rules
match nothing of `alpha`'s, even when `alpha`'s rules match `beta`'s file
text (a description quoting an IOC string). The next `--packs verify`
re-admits `alpha` against a set that now contains `beta`'s file, fails the
self-match, and round two's disarm branch revokes `alpha`'s trust for
something `beta` did. Reproduced by both refuters. Also: leftover
`.<name>.staging` directories were in the protected set, blocking a re-add
before `install()` could clear them; and `"trusted": "false"` in a
hand-edited index loaded as the truthy string, arming a pack `--packs list`
said was reports-only.

**Fix.** The candidate's own source folder is excluded alongside its
destination, unless that folder contains the project. Dot-directories are
skipped. Admission checks the other direction too, so the pair is refused
when it is formed. `RulePack` coerces its field types the way `AllowEntry`
already does.

---

## D. Health describes a ruleset that was never adopted, or one that is still loaded  — DONE

**Measured.** `load_rules()` reset `broken_packs` and `pack_rule_counts` on
`self` before the combined compile and validation could still refuse the
load; `reload_rules()` restored only `rules`. After a refused reload, Health
reported the counts and cleared FAILED states of the attempt. And the packs
row decided "DIRECTORY MISSING, 0 rules loaded" from the disk, while the
rules `load_rules()` compiled last were still matching -- and, if trusted,
still able to move files. Both reproduced.

The same class, one step further: `--packs verify` in a terminal disarms a
failing pack by writing `trusted=false`, and a running GUI holds its own
`PackStore` in memory and keeps condemning. Round three fixed exactly this
for the allowlist.

**Fix.** Per-pack results are accumulated in locals and committed with the
ruleset. Health says what is actually loaded: "removed from disk, but N rules
are still loaded until Reload". The scanner notices `packs.json` changing on
disk (one stat, at most every two seconds): a trust change re-derives the
cap and re-keys the cache; a pack added or removed triggers a reload, so a
removed reports-only pack's rules cannot go on running uncapped.

---

## E. "Stop keeping" can remove the wrong exception  — DONE

**Measured.** The listbox was filled from one snapshot of `entries()`, and
the button indexed a *fresh* `entries()` with the row number. The dialog is
not modal and the allowlist is the scanner's shared object: a restore from
the main window, or a real-time scan reloading after another process's
`--restore`, inserts a newer entry at the top and every row shifts down.
The user confirms "stop keeping v1" and v2 is removed. Reproduced.

**Fix.** Rows are bound to digests at refresh time. If the selected digest is
gone by the time the button is pressed, the list is refreshed and the user
told, and nothing is removed.

---

## F. Smaller, from the same review  — DONE

- **`\\?\unc\` walked past the guard.** The UNC marker was compared
  case-sensitively; Windows accepts `unc`, `Unc` and `UNC` alike (all six
  spellings `os.stat` to the same inode). The lowercase form was stripped to
  the *relative* path `unc\srv\share\...` and anchored at the cwd. And a
  `\\?\Volume{GUID}\` spelling -- a legal name for every local file -- was
  made relative the same way. The marker is compared case-insensitively;
  spellings that are not a drive or UNC are left whole, and whatever
  `realpath` answers is stripped again on the way out.
- **A non-UTF-8 `allowlist.json` still crashed startup**: `UnicodeDecodeError`
  is not a `JSONDecodeError`. Caught.
- **A failed save left a phantom decision**: `add()` logged a warning,
  re-synced the stamp to the unchanged file, and served the entry from memory
  until the next reload. Now the phantom is dropped and `add()` raises, so a
  restore can say the file is back but the decision was not recorded.
- **One `stat()` per lookup, under the lock**: measured at 125 µs of a
  739 µs cache hit, serialised across the worker threads. Checked at most
  every 100 ms instead.
- **The corpus walk's 4,000-directory cap** counted directories with nothing
  in them; a per-user Python install burned the budget before any binary was
  found. It counts productive directories now, with a raw ceiling as the
  backstop.
  **Measured after:** 400 files in 0.9 s, 100 from each root, 18 top-level
  program folders and 186 leaf directories outside System32, at most 6 per
  leaf, identical on a second call; and a synthetic tree with 4,100 empty
  directories before the programs no longer starves the walk.
- **The allowlist throttle, measured honestly:** on this machine a cache-hit
  `scan()` is 200 µs throttled against 208 µs with a stat on every lookup.
  The 125 µs figure came from the reviewer's own run; here the stat is
  8 µs. Kept, because it also takes the lock off the worker threads for the
  99 lookups in 100 that cannot have changed anything, but it is insurance,
  not a speed-up worth a sentence in the README.
- **The trust-state cache test used a medium rule**, which scores the same
  capped or not. It uses a critical one. **The yara-build test's mock error
  was swallowed** by the very `except Exception` under test; it asserts the
  call count instead. **The lookalike-spelling test asserted nothing** on any
  platform; replaced by the UNC and volume-GUID tests above.

---

## Not done from the review

- **Files pulled in by `include`** are invisible to the manifest, so an edit
  to one is not seen until Reload. yara-python does not report includes;
  recorded in [open-issues.md](open-issues.md) as a known limit.
- **A directory literally named `prot.`** is folded onto `prot` by the
  prefix strip. The guard errs towards protection, which costs nothing.

## Order

A, B, C, D, E, F. A is a silent crash. B loads stale rules, the failure
this project exists to not have. C and D are the pack machinery lying. E is
a decision lost. F is the sweep.

## Verification

377 tests in both modes and the smoke check, green. The review script that
found all of this is reused on this round's diff before the next plan starts.

## After this

[improvements.md](improvements.md) is the next plan, written separately:
five new capabilities, in its own order.
