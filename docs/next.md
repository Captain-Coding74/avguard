# What next

Three tiers are built, the audit is closed, CI is green on two platforms.
What follows is the next chapter, in the order I would do it.

The ranking rule has not changed:

1. does it lose the user's data
2. does it make the program lie about its own state
3. does it break for somebody who is not this developer
4. does it embarrass the project in public

Nothing below scores on 1 or 2 — those are all fixed. So this round is about
the honest gap: **AVGuard barely detects anything real, and the README says
so.** Closing that is the only change left that would make it a different
program rather than a tidier one.

---

## Part 1 — close the four open items

Small, real, an hour's work. Listed in
[open-issues.md](open-issues.md) under "Smaller, real, not urgent".

| # | What | Fix |
|---|---|---|
| A1 | `_settings_saved` restarts the monitor without re-reading `watch_paths` from disk | Reload `Config` before restarting, so a change another process made is not silently reverted |
| A2 | `detection_generation()` reads every rule file on construction | Hash `(path, size, mtime)` instead of contents; fall back to contents when the stat is unavailable |
| A3 | `EventStore.summary()` reads up to 5,000 events to count them | Keep a running counter in a small sidecar, rebuilt on rotation |
| A4 | `archives.iter_nested` takes a `depth` its only caller never passes | Either thread it through or delete the parameter — a limit enforced by a constant that pretends to be a parameter is a lie in the signature |

A4 is the one worth caring about: the docstring promises a configurable depth
and the code has a fixed one. Everything else here is tidying.

**Done when:** all four fixed, tests still green in both modes, and the
"Smaller, real" section of open-issues.md is empty.

---

## Part 2 — rule packs  DONE

Measured first, as the plan said. Both questions came back favourable:

- **ReversingLabs' pack is MIT**, so a permissively licensed pack does exist.
- **Zero false positives** across 400 clean binaries, at 8 ms a file, for 1,240
  rules in 310 files.

That zero was checked for the vacuous kind: blobs rebuilt from the rules' own
byte patterns matched 31 of 38 files probed, so the pack is demonstrably live
rather than merely quiet. The rules are hex patterns matching compiled malware
code, which is exactly why they do not fire on ordinary software.

Built as specified, plus one thing the plan did not anticipate: `Scanner` was
reaching into the real pack store by default, so installing a pack broke three
existing tests that were silently measuring whatever happened to be on the
machine. The store is injectable now.

## Part 2 — the original plan

This is the chapter that matters, and it is the one previously written off as
"a different project". That was half right. Writing and maintaining a malware
corpus *is* a different project. **Using one somebody else already maintains is
not** — and the machinery that makes doing it safely is already built here.

### Why this is now reasonable

Three things exist today that did not when this was deferred:

- a **validator** that refuses a ruleset which matches its own files, which is
  how v1 destroyed itself
- a **400-binary corpus** that measures the real false-positive rate of every
  rule, and fails the build over a ceiling
- a **hard/heuristic split** where nothing but a byte signature or an
  explicitly-trusted rule can move a file

So the risk of importing somebody else's rules — that they are over-broad and
start eating files — is exactly the risk this project has spent three rounds
building instruments against. Importing rules is the first thing those
instruments have been *for*.

### The shape

A new `avguard/rulepacks.py` and a `--rules` CLI verb.

**Getting a pack.** From a local file or a URL, always deliberately. No
auto-update, no phoning home on startup, nothing fetched unless the user asked
for it by name. A scanner that silently changes its own detection logic
overnight is a scanner that can silently start eating files overnight.

**Admitting a pack.** A pack is not trusted because of where it came from. It
is admitted only if it passes, in this order:

1. it compiles, on its own, in its own namespace
2. no rule in it matches any AVGuard file, or any file in the other packs
3. every non-private rule declares a `description`
4. measured against the local benign corpus, no rule exceeds the
   false-positive ceiling
5. the whole pack, applied to the corpus, produces **zero** MALICIOUS verdicts

Fail any of those and the pack is refused with the measurement printed, and
nothing on disk changes. This is the same bar the shipped ruleset is held to
by `tests/test_rules.py`; there is no reason a stranger's rules should clear a
lower one.

**Trusting a pack.** Imported rules are forced to `medium` regardless of what
their own metadata claims. Third-party severities use conventions this program
knows nothing about, and `severity = "critical"` in somebody else's file must
not be able to move a file here. So an imported pack **reports and never
quarantines** until the user promotes it explicitly, per pack, having seen it
run. That promotion is a separate, named action.

**Recording a pack.** Name, source, licence, SHA-256, when it was added, how
many rules, and the measured false-positive rate at admission. Listed by
`--rules list`, removable by `--rules remove`. A pack whose licence is unknown
is not admitted, because this repository is MIT and quietly vendoring
incompatible rules would be a real problem for anyone who forks it.

**Rolling back.** Packs live in their own directory. Removing one is deleting
a file and recompiling. A pack that breaks compilation after a later change
gets reported and skipped rather than taking the whole ruleset down — which
already works, since each file compiles into its own namespace.

### What has to be measured before building it

Two questions decide whether this is worth doing at all, and neither is
answerable from an armchair:

- **What false-positive rate does a real public ruleset have against 400 clean
  Windows binaries?** If a well-regarded pack trips 10% of them, the honest
  finding is that general-purpose rules are unusable at this scale and the
  chapter stops there — which is itself worth writing down.
- **Are there packs with a licence compatible with MIT redistribution?**
  Several large collections are permissively licensed; some well-known ones
  are not. If the answer is no, the feature ships as "point it at a pack you
  have" and nothing is vendored.

**Measure first, build second.** If the numbers are bad, Part 2 becomes a
paragraph in the README explaining why, and that is a perfectly good outcome.

**Done when:** a pack can be admitted, listed, promoted and removed; a
deliberately over-broad pack is refused with its measured rate; the corpus test
covers imported packs as well as shipped ones; and the README states what
changed about what this program detects.

---

## Part 3 — still not doing

Unchanged from [open-issues.md](open-issues.md), and worth restating so the
scope stays honest:

- **Writing an original malware corpus.** Using someone else's is Part 2.
  Maintaining your own is a job.
- **Catalogue signature verification.** The value of Authenticode here is
  trusting downloads, and downloads carry embedded signatures.
- **Performance work.** Measured, GIL-bound, and already faster than a
  Downloads folder needs.
- **RAR and 7z.** Third-party packages for formats browsers do not produce.
- **Anything resembling an EDR.** No drivers, no process monitoring, no memory
  scanning. This is a file scanner and the README says exactly that.
