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

## Not resolved

The Windows CI job for the item-2 commit (`bfb2405`, run #29) failed with
exit code 1 and no per-test annotation, which the harness prints for every
failing test. The job log needs a GitHub login this session does not have.
Locally the same commit passes 421 tests in both modes. The harness now
writes its output as UTF-8 with replacement, so a failure message that the
runner's console could not encode cannot itself be the reason the
annotation is missing; if run #30 fails the same way, the log at
https://github.com/Captain-Coding74/avguard/actions/runs/35738302825 is the
place to look.
