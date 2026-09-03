# What comes next, round two

Written after the rule-pack audit's nine cheap items landed (open-issues.md
rows 25-33). Everything here was measured first, on this machine, on
2026-09-03. Two of the audit's "leave alone" calls turned out to be wrong once
measured, and two items it deferred are now earned by work that has landed.

Ranked the same way as before: can something move a file it should not, then
can the user lose a decision, then does it break for someone who is not me.

---

## A. `\\?\` paths walk straight past self-protection  — DONE

**Measured.** With a protected directory `R` and a file `R\rules\x.yara`:

    is_protected(R\rules\x.yara)        True
    is_protected(\\?\R\rules\x.yara)    False
    path_within(\\?\R\..., R)            False
    same_path(\\?\R\rules\x.yara, ...)   False

The audit filed this under "leave alone" because the trigger it imagined was
an attacker-controlled quarantine index. It is not the only trigger: the
extended-length prefix is a legal spelling of any Windows path, `--scan`
accepts whatever the user types, and every guard in `protection.py` compares
text. A guard that a prefix defeats is a guard with a hole in it.

**Fix.** `SelfProtection._forms()` strips `\\?\` (and turns `\\?\UNC\` back
into `\\`) before generating spellings, so the prefixed form compares equal to
the plain one everywhere `path_forms` is used. Five lines.

**Tests.** `is_protected`, `path_within` and `same_path` each with the
prefixed spelling; plus the two cases the audit asked for when protection.py
was next touched: `<dir> \rules\x.yara` (trailing space in the component) and
`<dir>..\rules\x.yara` (a sibling whose name merely starts with ours) are both
*outside*.

---

## B. A restore is a permanent machine-wide exception nobody can see  — DONE

**Measured.** `Allowlist.entries()` and `Allowlist.remove()` have no caller
outside the tests. The restore confirmation says "Put X back at Y" and nothing
about the exception it creates. `detection_generation()` has no allowlist
term, and `scan()` caches an allowlisted verdict as CLEAN by path -- so if an
exception *could* be removed, the file would stay CLEAN from the cache until
its entry expired, and a second copy of restored bytes elsewhere keeps its
cached MALICIOUS. Single ownership (row 19) was the prerequisite; it landed.

**Fix.**
- Settings gains "Files you chose to keep": every exception with the name, the
  date, and what it was flagged for, and a "Stop keeping" button that calls
  `Allowlist.remove()`. The dialog is handed the scanner's allowlist, the same
  way it is handed the scanner's pack store, and an `on_allowlist_changed`
  callback re-keys the cache.
- The restore confirmation says what it does: the file will not be flagged
  again, anywhere on this PC, until the exception is removed in Settings.
- The sorted digests of the allowlist go into `detection_generation()`, so
  adding or removing an exception invalidates every cached verdict that could
  have depended on it. `restore()` already invalidates the one path; this
  covers the copies.

**Tests.** Remove an exception, re-scan with the cache on, MALICIOUS again.
Restore a file, scan an untouched second copy of the same bytes with the cache
on, CLEAN. The confirmation text mentions "anywhere on this PC".

---

## C. Ten seconds before the window appears  — DONE

**Measured.** With the ReversingLabs pack installed (311 files, 1,240 rules):

    Scanner()   first launch, files cold    10.15 s
    Scanner()   warm, under the profiler     1.12 s   (compile 0.40 s of it)
    reload_rules()                           1.03 s
    fresh copy of the pack, first read       4.93 s   second read 0.04 s
    yara.compile of those files, warm        0.17 s
    rules.save()  4.1 MB                     0.00 s   yara.load()  0.02 s

The audit guessed the per-pack compile would "cut most of it for free". It
did not, because the cost was never the compile: it is the first touch of 310
small files, which on Windows means the on-access scanner looking at each one.
Part 3 of next.md said "performance work: not doing" about GIL-bound scanning
throughput; this is a different thing, and it is the first impression.

**Fix.** A compiled-ruleset cache in the data directory: `rules.save()` after
a successful load, beside a manifest of every source file's `(size, mtime_ns,
sha256)`. On the next start, `stat()` each file (311 stats, no reads); if all
match the manifest, `yara.load()` the compiled file and derive the generation
from the manifest's hashes. Any mismatch, a missing or unreadable cache, or a
`yara.load` error (a different yara-python version) falls back to the normal
path, which then rewrites the cache. `--reload-rules` and the GUI reload
bypass it, so an edit that preserves size and mtime -- which a copy can -- is
still one keypress away from being seen. Validation ran when the cache was
written; unchanged inputs give the same answer, and re-running it would read
every file, which is the cost being removed. Untrusted namespaces and pack counts come
from the store and the manifest, not from the compile.

**Tests.** A second construction reads no rule file contents (count
`read_bytes` calls). Change one byte in one pack file keeping its size: mtime
changes, recompile. Corrupt the cache file: recompile, no crash. Cache from a
different `yara.__version__` tag: recompile. And the generation is identical
whichever path produced it, or the ScanCache would be flushed every other
start.

**Measured after.** A fresh copy of the pack in an isolated data directory,
each start in its own process:

    start 1   compiles, writes the cache     8.24 s
    start 2   cache, blob read for the first time   0.27 s
    start 3   cache, everything warm          0.24 s
    start 4   cache deleted, files warm       0.92 s

The window appears in a quarter of a second instead of ten. The first launch
after a pack is added or edited still pays for the compile, once.

One more thing the test suite taught: a compile whose inputs match the blob
already on disk does not rewrite it -- only the manifest's clock moves.
Rewriting an identical binary file on every start made the on-access scanner
look at it every time, and a start refused only by the two-second rule needs
a fresh timestamp, not a fresh blob, for the next one to be trusted.

---

## D. The clean corpus is 83% System32  — DONE

**Measured.** `_clean_corpus()` returned 400 files: 331 from System32, 69 from
Program Files, across **six** distinct program directories. The walk breaks
after the first directory that pushes it past the limit, and System32's root
alone has thousands.

The audit deferred this until the aggregate ceiling existed; it exists (row
27). A 5% pack ceiling measured against one directory of Microsoft binaries
is weaker than it reads: a pack that flags Electron apps, Go binaries, or
installers -- the things people actually download -- would pass.

**Fix.** Cap files per directory (six) and keep walking, under a file budget
per root, so the corpus spans many programs instead of one folder. Add
`%LOCALAPPDATA%\Programs`, where per-user installs go. Hold System32 to at
most a third. Keep the fixed seed: `verify` must be repeatable.

**Tests.** On a synthetic tree, no directory contributes more than the cap
and the System32 share is bounded; the sample is identical on a second call,
because `verify` compares today's rate with the one at install.

**Measured after.** 400 files in 1.2 s: 100 each from Program Files, Program
Files (x86), `%LOCALAPPDATA%\Programs` and System32. Seventeen top-level
program folders where there were six, 193 leaf directories outside System32,
never more than six files from any of them. Each directory's listing is
shuffled with the fixed seed before taking, so it is not the alphabetical
first few either.

---

## E. `owner_of()` is a linear scan per match  — DONE

**Measured.** 0.30 ms per call (the audit said 1.58; one pack, warm), on
every YARA match, on the real-time worker threads: 152 ms per 500 matches for
an answer that only changes when the ruleset does.

**Fix.** `load_rules()` already builds the per-pack file lists; record
`{resolved path: pack name}` at the same time and look the owner up in
`_finding_from_match`. `PackStore.owner_of()` stays for callers outside the
scanner.

**Tests.** The attribution still says "from the X pack", from the compiled
cache as well as from a compile.

**Measured after.** A dict lookup. The 0.30 ms per match is gone, and the
`load_rules()` that builds the dict was already resolving those paths.

---

## F. `--no-gui-deps` proves blocking with one name  — DONE

`_prove_blocking_works` probes `sorted(names)[0]` -- `PIL` -- and only that.
On a box without Pillow the probe passes vacuously and the other three names
are unproven. `importlib.util.find_spec` through our finder raises
`ImportError` for a hidden name and returns `None` for an absent one, which
distinguishes the two; probe every name that way.

---

## Order

A, B, C, D, E, F. A is safety and five lines. B is a user's decision they
cannot see or undo. C is what the user sees first. D, E, F are earned but
nobody is harmed while they wait.

## Still not doing

Part 3 of [next.md](next.md) stands, with the one clarification above: C is
not scanning-throughput work, it is first-launch work, and it was measured.
