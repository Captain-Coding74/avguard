# What comes next, round five

Written 2026-09-22, after round four was put through the same adversarial
review it came out of. Three reviewers over `376c93e..9e2e271`; the refuters
were lost to a usage limit, so every claim below was reproduced by hand
before it was accepted, and two were not: the loopback share does not exist
on this machine (kept as a cheap mapping with a text-level test), and the
thread races are argued from the code rather than caught in the act.

The headline: **the pack sync added in round four was designed wrong.** It
derived the cap set from the disk instead of from the rules it had loaded,
and it changed the ruleset, the cap set and the cache from worker threads
with no coordination. Two measured consequences, both of which let a
reports-only pack move a file.

---

## A. The sync uncaps rules it never unloaded  — DONE

**Measured.** A reports-only pack with one `critical` rule, loaded and
scoring SUSPICIOUS. Delete its directory; have any other process rewrite
`packs.json` (a trust toggle, a `verify`, an unrelated pack's install). The
next scan: **MALICIOUS, hard**. The sync saw the index change, took the
trust branch, and rebuilt the cap set from `untrusted_namespaces()` -- which
reads the disk, where the pack's files no longer are -- while the rules
compiled from those files stayed loaded. Namespaces with no entry in the
cap set score as shipped rules.

Same shape, other order: remove a pack and add a different one **under the
same name** (the documented way to refresh a pack). Names compare equal, so
the trust branch runs again: the OLD rules keep running, now uncapped if the
file names changed, and the cache is re-keyed to the NEW generation, so
verdicts from rules that no longer exist are stored under a generation every
later process trusts. Measured: MALICIOUS, hard, from rule `Old`.

**Fix.** The cap set is derived from the *loaded* ruleset: every namespace
the compile produced is mapped to its pack at load time, and a namespace is
untrusted unless the index says its pack is trusted -- a pack absent from
the index is capped, not free. The sync compares each pack's recorded hash
and file list against what was loaded: any difference is a reload; only a
pure trust change is a re-derivation.

**Measured after.** The same two probes. Directory vanished, index
rewritten: the sync sees the pack's files gone, reloads, and the pack drops
out -- CLEAN, nothing hard, nothing of it loaded. Replaced under the same
name: SUSPICIOUS from the new rule, not the old one, nothing hard. Both are
tests now and fail against `9e2e271`.

---

## B. Worker threads change what a scan in flight is reading  — DONE

**Argued from the code.** `scan()` reads `self.rules`, then later
`self._untrusted_namespaces`, then `self.cache` twice. The sync, running on
another worker, assigns those three separately. A YARA match started on the
old ruleset can be scored against the new cap set (a removed pack's rule,
uncapped for the length of the window); a verdict scored under the old trust
state can be stored into the re-keyed cache and persisted under the new
generation, then replayed by every process for thirty days.

**Fix.** One immutable `Ruleset` object -- rules, cap set, namespace map,
sources, and the pack state it was built from -- swapped as a single
reference. A scan takes its snapshot of the ruleset and the cache once, at
the start, and uses nothing else. A verdict from an old snapshot goes into
the old cache object, which is never saved again: lost, not misfiled.
`load_rules()` only ever assigns on success, so "keep the previous ruleset"
is no longer a restore step that could itself race.

**Tested.** A match held in flight while another thread removes the pack
and forces the sync: the verdict is scored against the ruleset the scan
started with, capped, not a threat.

---

## C. Smaller, all reproduced  — DONE

- **A rule file that appears between `own` and the witnesses** is witnessed
  but not compiled, and a compile slower than two seconds then lets every
  later start adopt a blob without it. Witnesses first.
- **`1e999` in a pack record** raised `OverflowError` out of the coercion
  added in round four, and out of every entry point. Caught.
- **`_safe_name` was not idempotent**: strip, then truncate to 64, can leave
  a trailing `-` that a second call strips again. The symmetric check
  compared a pack's index name with `_safe_name(name)` and, for such a name,
  checked the pack against itself and disarmed it on `verify`. Truncate, then
  strip.
- **The index stamp missed same-size rewrites in the same tick**: 4 of 200
  here, 39 of 200 on the reviewer's run. The stamp includes a hash of the
  file, which is two kilobytes.
- **The dot-path skip** dropped `.github`, `.gitignore` and `.gitattributes`
  from the self-match set. Only `.git`, `.venv` and the pack store's own
  dot-directories are skipped now.
- **`\\localhost\C$\...`** is a spelling of every local file that the guard
  did not recognise. Not reproducible here (the share is off), mapped to the
  drive letter anyway for `localhost`, `127.0.0.1`, `::1` and this machine's
  name.
- **A restore whose decision could not be recorded** was reported as a failed
  restore with a self-contradictory message and exit 1, while the file was
  back and the record consumed. It is reported as what it is: restored, with
  a loud warning.
- **The stop-keeping test proved nothing inside one second**: three entries
  added in the same second sort as a tie, so the old row-index code removed
  the right file anyway. The test gives them distinct timestamps.

## Verification

The suite in both modes and the smoke check: 431 tests. The two measured
scenarios above, and the in-flight race, are tests that fail against
`9e2e271`.

## The CI failures, resolved and not

Run #30 (this round's commit) failed on Windows and, with the harness now
writing UTF-8, said why: a test compared the path `restore()` returned
with the test's temp path as text, and the runner spells `%TEMP%` with an
8.3 short name (`RUNNER~1`) while `restore()` answers with the long form.
Same file, two spellings -- compared with `same_path` now, as everything
else in the program compares paths.

Run #29 (the item-2 commit, `bfb2405`) failed with exit code 1 and no
annotation, before the UTF-8 change, and its log needs a login this session
does not have: https://github.com/Captain-Coding74/avguard/actions/runs/35738302825.
The one mechanism that produces "exit 1, no annotation" is the reporter
raising while printing a failure message the runner's cp1252 console could
not encode, which the UTF-8 change closes. If a later run fails, its
annotation will say what.

*Later (2026-09-24):* a second mechanism, and probably the real one. Run
#34, the push of the TLSH commit to main, failed on Windows with exit 1
and no annotation after the same tree had passed the full suite on its
pull request eight minutes earlier. The log shows not a test failure but
the interpreter dying: `Fatal Python error: _PySemaphore_Wakeup:
parking_lot: ReleaseSemaphore failed (error: 6)` -- ERROR_INVALID_HANDLE
-- in the main thread inside `queue.put_nowait` → `Condition.notify`, as a
test's cleanup stopped a realtime monitor whose two workers were parked in
`queue.get(timeout=0.5)`. That is CPython 3.13's threading internals on
Windows (a timed wait racing a wake-up), in `watcher.py`, which the commit
did not touch; a fatal error prints to stderr and produces no annotation,
which is exactly run #29's shape. What this program can do about it is
stop the workers without a timed wait -- `queue.get()` blocking on a
sentinel, or `Queue.shutdown()` on 3.13 -- and that is a change to the
watcher's stop protocol to be made and measured on its own, not folded
into an unrelated commit. Until then a run that dies this way is re-run
once, and the second run is the answer.
