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

## Part 1 — close the four open items  DONE

Small, real, an hour's work. Listed in
[open-issues.md](open-issues.md) under "Smaller, real, not urgent".

| # | What | Fix |
|---|---|---|
| A1 | `_settings_saved` restarts the monitor without re-reading `watch_paths` from disk | Reload `Config` before restarting, so a change another process made is not silently reverted |
| A2 | `detection_generation()` reads every rule file on construction | Hash `(path, size, mtime)` instead of contents; fall back to contents when the stat is unavailable |
| A3 | `EventStore.summary()` reads up to 5,000 events to count them | Keep a running counter in a small sidecar, rebuilt on rotation |
| A4 | `archives.iter_nested` takes a `depth` its only caller never passes | Either thread it through or delete the parameter — a limit enforced by a constant that pretends to be a parameter is a lie in the signature |

All four done. A4 was filed as tidying and turned out to be a real detection
gap: `MAX_DEPTH = 2` promised "an archive inside an archive" while the code
unrolled exactly one level, so a marker two archives deep was missed. It nearly
escaped a second time because the first check used uncompressed zips, where the
payload bytes sit verbatim in the container and an ordinary signature match
looks exactly like successful traversal. See
[open-issues.md](open-issues.md).

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

### What it looks like now

```bash
python -m avguard --packs add path/to/rules --licence MIT
python -m avguard --packs list
python -m avguard --packs verify        # re-measure against today's corpus
python -m avguard --packs trust <name>  # let its rules move files
```

A pack is admitted only if it compiles, carries descriptions, matches none of
AVGuard's own files, and stays under the same 1% false-positive ceiling the
shipped rules face — measured against real binaries from the machine it is
being installed on. Refused packs print their measurement and write nothing.

An imported rule cannot move a file whatever severity it claims, until the pack
is promoted by name. Nothing is ever fetched unless asked for.

**One thing the plan promised and the first pass missed:** the corpus test only
covered the shipped ruleset, so a pack was measured once at admission and never
again. Software gets installed on a machine and a pack's files can be edited
afterwards, so a number recorded months ago is not evidence about today.
`tests/test_rules.py` now re-measures whatever packs are installed, and
`--packs verify` is the same check on demand.

---

> Round two, written after this was all done and measured: [next-2.md](next-2.md).

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
