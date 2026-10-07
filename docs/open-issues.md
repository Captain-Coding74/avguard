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
| 16 | **An unpromoted rule pack could quarantine a file, if it was zipped** | `tests/test_rulepacks.py` |
| 17 | A restore was recorded in one Allowlist and read from another, so it never took effect | `tests/test_rulepacks.py` |
| 18 | Settings wrote pack trust changes the running scanner never saw | `tests/test_rulepacks.py` |
| 19 | **The test suite wrote into the user's real allowlist** | every test module isolates `AVGUARD_DATA` |
| 20 | **One broken pack file switched off every rule, the shipped ones included** | `tests/test_rulepacks.py` |
| 21 | Editing an installed pack left the cache generation unchanged | `tests/test_rulepacks.py` |
| 22 | Two pack names that sanitise alike: the second install silently overwrote a promoted pack | `tests/test_rulepacks.py` |
| 23 | Re-installing a pack from its own directory emptied it | `tests/test_rulepacks.py` |
| 24 | A pack using `include` was admitted, then never compiled once installed | `tests/test_rulepacks.py` |
| 25 | **Installing a reports-only pack silenced the VirusTotal lookup for anything it flagged** | `tests/test_rulepacks.py` |
| 26 | A malformed `allowlist.json` or `packs.json` crashed every entry point at startup | `tests/test_rulepacks.py` |
| 27 | A pack of narrow rules could flag every clean file and pass: the aggregate rate was computed and compared to nothing | `tests/test_rulepacks.py` |
| 28 | `--packs verify` printed a rate it never measured, blamed the wrong check, and left a failing pack trusted | `tests/test_rulepacks.py` |
| 29 | Pack rule counts came from a regex that counted commented-out rules and missed included ones | `tests/test_rulepacks.py` |
| 30 | `--packs --licence MIT add <dir>` silently listed; `avguard scan X` silently launched the GUI | `tests/test_rulepacks.py` |
| 31 | `if __name__ == "__main__":` sat above half the classes in five test files, so direct execution skipped them | `python tests/test_*.py` now runs every class |
| 32 | The self-match check walked three directories; a pack matching `tests/`, `tools/` or another installed pack passed | `tests/test_rulepacks.py` |
| 33 | Health summed the pack index's `rule_count`: a pack whose directory had been deleted still reported its rules as loaded | `tests/test_rulepacks.py` |
| 34 | **`\\?\`-prefixed paths walked straight past self-protection** | `tests/test_durability.py` |
| 35 | A restore was a permanent, machine-wide exception nobody could see or undo, and the cache did not know it existed | `tests/test_durability.py` |
| 36 | The first launch of the day took ten seconds before the window appeared | `tests/test_compiled_cache.py` |
| 37 | The clean corpus was 83% System32, across six program folders | `tests/test_cli.py` |
| 38 | `owner_of()` was a linear scan with a path resolution on every YARA match | `tests/test_compiled_cache.py` |
| 39 | `--no-gui-deps` proved its blocking with one name and passed vacuously without Pillow | `tools/ci_tests.py` self-check |
| 40 | **A restore made from the command line never reached a running GUI; with auto-quarantine on it would be taken straight back** | `tests/test_durability.py` |
| 41 | The Settings window asked for 1,438 px on a 1,080 px screen; Save and Cancel were off the bottom | `tests/test_tier3.py` |
| 42 | The shipped rules were measured against a corpus that was 90% System32 and SysWOW64 | `tests/test_rules.py` |
| 43 | Every CLI verb held its log file open after returning | `tests/test_cli.py` |
| 44 | **A crash under the windowed build left a 0-byte log: the handler was closed in a `finally` before `sys.excepthook` ran** | `tests/test_cli.py` |
| 45 | **A compile refused only by the two-second rule kept the stale blob forever** | `tests/test_compiled_cache.py` |
| 46 | `\\?\unc\` and `\\?\Volume{GUID}\` spellings were stripped to cwd-relative paths and walked past self-protection | `tests/test_durability.py` |
| 47 | A pack added from inside the checkout was refused for matching its own source files | `tests/test_rulepacks.py` |
| 48 | The cross-pack self-match ran one way, so `verify` disarmed a trusted pack for a string a later pack quoted | `tests/test_rulepacks.py` |
| 49 | A refused reload left Health describing the attempt; a deleted pack directory read as "0 rules loaded" while its rules still matched | `tests/test_compiled_cache.py` |
| 50 | A trust change written by `--packs verify` in another process never reached a running scanner | `tests/test_durability.py` |
| 51 | "Stop keeping" indexed a fresh list with a stale row number and could remove the wrong exception | `tests/test_tier3.py` |
| 52 | A failed allowlist save left a phantom decision; a non-UTF-8 file crashed startup; `"trusted": "false"` armed a pack | `tests/test_durability.py`, `tests/test_rulepacks.py` |
| 53 | **The pack sync derived the cap set from the disk: a reports-only pack whose directory vanished, or was replaced under its own name, ran uncapped** | `tests/test_durability.py` |
| 54 | **The ruleset, the cap set and the cache were swapped separately from worker threads; a scan in flight could mix them** | `tests/test_durability.py` |
| 55 | A rule file appearing between the compile's listing and the cache's witnesses was witnessed but never compiled | reordered; argued |
| 56 | `1e999` in a pack record raised `OverflowError` out of every entry point | `tests/test_rulepacks.py` |
| 57 | `_safe_name` was not idempotent, so `verify` checked a long-named pack against itself and disarmed it | `tests/test_rulepacks.py` |
| 58 | The index stamp missed a same-size rewrite in the same tick (4 of 200) | `tests/test_rulepacks.py` |
| 59 | The dot-path skip dropped `.github` and `.gitignore` from the self-match set | `tests/test_rulepacks.py` |
| 60 | A restore whose decision was not recorded was reported as a failed restore | `tests/test_durability.py` |
| 61 | **A store built without the lock reconciled the index and deleted a quarantine in progress (33 and 22 of 500 files lost under stress, 0 after); reconcile deleted the only copy whenever any file sat at the old path** | `tests/test_durability.py` |
| 62 | **An index, allowlist, pack index or config with a BOM, a non-UTF-8 byte or a non-object was read as empty and then saved over: every held file's nonce, every kept decision** | `tests/test_durability.py` |
| 63 | **The payload, and the restored file, were never flushed before the unlink that made each the only copy** | `tests/test_durability.py` |
| 64 | **`--scan --quarantine` and the window moved whatever was at the path when the move ran, not the bytes the verdict was reached on** | `tests/test_durability.py`, `tests/test_cli.py` |
| 65 | Export wrote damaged payloads as "the original, unmodified files"; `--export-all` exited 0 with one of three not written | `tests/test_durability.py`, `tests/test_cli.py` |
| 66 | A second window could restore and delete; the lock holder then wrote the removed record back | `tests/test_durability.py` |
| 67 | The retention review the README and ROADMAP described did not exist | `tests/test_durability.py` |
| 68 | A name near 255 characters could be neither restored nor exported; a payload another program held undid a finished restore; the relative-destination check ran after `resolve()` and never fired | `tests/test_durability.py` |
| 69 | **Baselining any folder, or accepting any change, re-signed a doctored, unsigned or copied-in baseline, so the tamper was never reported** | `tests/test_fim.py` |
| 70 | A check locked out for 5 s said "No changes", exit 0; the tab's Accept said "Accepted N change(s)" and cleared rows it had not accepted | `tests/test_fim.py` |
| 71 | A kind read empty once and then not at all swallowed the next new startup entry; after a failed listing the tab called every task NEW | `tests/test_autoruns.py` |
| 72 | Two overlapping startup snapshots recorded a false "modified outside AVGuard" (15 of 30 pairs): the signature was checked before the lock | `tests/test_autoruns.py` |
| 73 | A subfolder baselined beside its parent was walked twice by every check: one new file, two ADDED rows and two events | `tests/test_fim.py` |
| 74 | A non-text byte in `baseline.hmac` or `snapshots.hmac` stopped the window opening and killed the daily tasks before they recorded anything | `tests/test_fim.py`, `tests/test_autoruns.py` |
| 75 | Under the packaged `AVGuard.exe` the three daily tasks ran `-m avguard`, which its parser rejects: they never ran | `tests/test_fim.py` |
| 76 | **`config.json` was trusted as found: `"false"` in quotes turned automatic quarantine on while Settings showed it off; a BOM or a trailing comma read as "no config", and first run then saved defaults over the user's folders** | `tests/test_durability.py` |
| 77 | **A second window wrote `auto_quarantine=false` into the user's config and ran a second watcher: every detection recorded twice, once as "not moved"** | `tests/test_durability.py` |
| 78 | **Any CLI verb with `AVGUARD_DATA` set moved an old install's `data/` into it, so the test suite and the smoke check deleted the only copy of its quarantine** | `tests/test_durability.py` |
| 79 | When Settings could not save, the switches the user changed were already live; Cancel left the clipboard being read and files being moved | `tests/test_durability.py` |
| 80 | The Explorer verb and the daily tasks ran `-m avguard`, which needs the checkout as the working directory; Explorer starts in the clicked folder, Task Scheduler in System32 | `tests/test_shellext.py` |
| 81 | Under the windowed build or pythonw every `--scan` died at its first printed line: the right-click entry showed nothing, the daily scan reported nothing | `tests/test_shellext.py` |
| 82 | Clear history said it removed the scan cache's paths too; it removed only `events.jsonl` | `tests/test_durability.py` |
| 83 | `--schedule off` said "Partly removed - see the log", exited 0 and logged nothing | `tests/test_durability.py` |
| 84 | Two processes sharing `avguard.log` on Windows: past 1 MB every record was lost and two of three backups deleted | `tests/test_durability.py` |
| 85 | With no tray icon, closing withdrew the window beyond reach, still holding the lock | `tests/test_durability.py` |
| 86 | A lying zip header (bzip2 declaring 100 bytes) defeated every bomb guard: 3 KB, CLEAN in 57.7 s at 8.2 GB; now SUSPICIOUS in 0.2 s at 106 MB. The "larger than its header claims" check could never fire | `tests/test_tier2.py` |
| 87 | Whether VirusTotal is asked was not in the cache generation: a file cached CLEAN with lookups off replayed CLEAN for 30 days after they were switched on | `tests/test_tier2.py` |
| 88 | The VirusTotal client kept the Config the window had replaced, and a rejected key wrote `cloud_enabled=False` into it | `tests/test_durability.py`, `tests/test_avguard.py` |
| 89 | The daily budget of 400 lookups was per process (window plus right-click scans: 800), and the window's exit erased the console's cache | `tests/test_avguard.py` |
| 90 | The "once a day" blocklist download ran once per launch, never again in a window left open | `tests/test_durability.py` |
| 91 | The feed request and the event POST attached a `~/.netrc` "default" login for another service | `tests/test_iocs.py`, `tests/test_event_forward.py` |
| 92 | Restores and deletions were never recorded, though the README said a restore is POSTed; forwarding sent more than its consent named (a TLSH digest and family, a startup item's triggers, run level and DLL) | `tests/test_durability.py` |
| 93 | A damaged or encrypted zipped feed escaped as `zlib.error` or `RuntimeError`, past every `except IocError` | `tests/test_iocs.py` |
| 94 | A zip with one malformed central-directory entry made `scan()` raise: no verdict for the archive, "Threats: 0", exit 0, a signature in a sibling member lost with it | `tests/test_tier2.py` |
| 95 | A typo in one of the user's rule files switched off every shipped rule for the session (0 rules loaded, 5 after) | `tests/test_durability.py` |
| 96 | One malformed `scan_cache.json` entry crashed every console scan after its work (exit 1), and the cache could never be saved again | `tests/test_tier2.py` |
| 97 | A line torn mid-character, or one mistyped record, in `events.jsonl` stopped History opening for good | `tests/test_tier2.py` |
| 98 | A confidence figure in a rule's description reached the account, which promises never to carry one | `tests/test_explain.py` |
| 99 | The daily integrity check, the startup snapshot and CLI restores were never forwarded, though the README and the consent said every event goes | `tests/test_event_forward.py` |
| 100 | "Scan the watched folders once a day" scheduled a scan of the first watched folder only, and kept scanning it after the list changed | `tests/test_cli.py` |
| 101 | A watched folder missing at logon was dropped for the session while Health said OK; "Never scan" beside a detection could exclude the watched folder itself, silently | `tests/test_durability.py` |
| 102 | The daily export holds 48 hours; a PC that missed more lost those hashes for good while Health said "last checked" today | `tests/test_iocs.py` |
| 103 | README: "only EICAR and the marker can reach MALICIOUS" was false; the user rules folder was printed with a line break in place of `\r` | read, corrected |
| 104 | `tests/test_avguard.py`'s real-data guard was defined and never called, and named an unimported `pathlib` | it runs at import now |
| 105 | **Quarantine checked the digest when it read a file, then unlinked whatever had the name seconds later: an editor's save by rename in between was destroyed (5 of 5 CLI runs)** | `tests/test_durability.py` |
| 106 | **A restore checked that nothing had the name before a multi-second unmask, then replaced the file the user saved there** | `tests/test_durability.py` |
| 107 | **The evidence beside the quarantine index, and the clipboard's "never warn again" list, read a BOM as empty and were written over** | `tests/test_durability.py` |
| 108 | **A mistyped config value was a log line; the next unrelated save wrote the default over it (the user's folders, exclusions)** | `tests/test_durability.py` |
| 109 | **A window started without the lock never took it: when the holder closed, nothing protected, and every surface said the other window did** | `tests/test_durability.py` |
| 110 | **Settings and "Never scan" wrote every shown value from their window's start-time copy; Settings saved in the second window never reached the first** | `tests/test_durability.py` |
| 111 | Two set-asides in the same second kept only the second | `tests/test_durability.py` |
| 112 | The three "failed index write" tests broke the read, not the write: the handler they are named for was untested | `tests/test_durability.py` |
| 113 | A FIM accept with an unreadable file said "Accepted 2" and cleared both rows; `--fim-accept` exited 0 | `tests/test_fim.py` |
| 114 | A locked-out Check cleared the rows being reviewed; "web web/assets" in one call, or a symlinked spelling, was two trees | `tests/test_fim.py` |
| 115 | A startup kind that failed for 30 days was a "first read" again and its new task unreported; a snapshot that timed out verified without the lock (false tamper, exit 3) | `tests/test_autoruns.py` |
| 116 | **What one archive down was found to be (a lying header, a bomb, a traversal name) was thrown away** | `tests/test_tier2.py` |
| 117 | **Row 94's crafted zips with DEFLATED members were CLEAN, cached, "Threats: 0"; unzip extracted the marker** | `tests/test_tier2.py` |
| 118 | **A member declaring more than 32 MB, or a bomb's expansion, was skipped unread: a header could hide what unzip extracts** | `tests/test_tier2.py` |
| 119 | **The VirusTotal budget never reset in a window past midnight (a regression from row 89)** | `tests/test_avguard.py` |
| 120 | **A lookup asked for and not answered was cached CLEAN for 30 days** | `tests/test_tier2.py` |
| 121 | A damaged `vt_cache.json` raised KeyError: every `--scan` exited 1 and the window did not start (a regression) | `tests/test_avguard.py` |
| 122 | A user rule matching text in the shipped rule file refused the whole load; a malformed cache entry was replayed and dropped the threat in the window | `tests/test_durability.py`, `tests/test_tier2.py` |
| 123 | A path with a lone surrogate raised out of History, so the next threat was not quarantined; a zip64 feed escaped as OverflowError | `tests/test_tier2.py`, `tests/test_iocs.py` |
| 124 | A failed feed request was retried hourly (README: once a day) | `tests/test_iocs.py` |
| 125 | The confidence filter dropped ordinary descriptions (%APPDATA%, a %20 member name, a digit in the rule's name) and missed "97 percent" and the JSON reasons | `tests/test_explain.py` |
| 126 | Two of round six's own tests could not fail (a CLEAN never cached; a compiled ruleset never adopted) | `tests/test_tier2.py`, `tests/test_durability.py` |
| 127 | `--scan-watched` scanned a folder inside another twice and skipped a missing one unsaid | `tests/test_cli.py` |
| 128 | The daily scan, with no console, left no record; a slow receiver held a verb 12 s | `tests/test_cli.py` |
| 129 | Turning real-time on with the folder missing saved "off"; Settings never started protection that was not running | `tests/test_durability.py` |
| 130 | `--schedule off` read schtasks's English; registrations from before row 80 kept "-m avguard" and Health said installed | `tests/test_shellext.py` |
| 131 | Clear history's cache wipe was undone by any scan that had loaded the cache before it | `tests/test_tier2.py` |
| 132 | The forwarding consent did not name integrity events, health events or scan summaries | `tests/test_durability.py` |
| 133 | `test_explain.TestTheWindow` (5) and a clipguard test were skipped in every full run, CI included: two window roots | `tests/test_explain.py` |
| 134 | The real-data guard could not fire (setdefault kept an inherited AVGUARD_DATA) | `tests/test_avguard.py` |
| 135 | Window code no test reached: Health's real-time row, the ticks, first run, the VirusTotal switch, restore with a warning, shutdown | `tests/test_durability.py` |
| 136 | Small gaps: the directory fsync, a damaged store's handle, the log's backoff, `_fits` for floats and text, the launcher test that could not fail on Windows, the compressed-read cap | `tests/test_durability.py`, `tests/test_tier3.py`, `tests/test_tier2.py` |
| 137 | README: a rule of your own marked critical or test is hard too; 8c1aaa9's count (831, not 832) | read, corrected |

### Notes worth keeping

**Round seven (105-137).** Round six's tests lens and most of its
skeptics died on a usage limit, so it was run again: three lenses mutating
the round-six code and three attacking its fixes, each in its own copy of
701de96, with a skeptic for the worst of each. 119 findings, every one
reproduced here before it was fixed, every reported mutant applied to the
new code and seen killed by a test: 85 mutants, all killed, 7 of them only
after the first draft of their test was fixed. The two rank-1 bugs were in
the moment between deciding and acting: a digest checked at read and a path
unlinked seconds later, an absence checked before the unmask and a file
replaced after it. Both now check at the act. The other lesson is about
tests: six of the window's tests were skipped in every full run by a
duplicated import, three named for a guard broke the read instead of the
write, two of round six's own could not fail, and the guard meant to keep the
suite out of real data held by construction. A test is not evidence until
something it covers has been broken and it has failed.

**Round six (61-104).** Nine lenses over the whole codebase, each
running its own reproduction scripts against a copy of 70f9c41: quarantine,
stores, pipeline, network, shell, window, claims, tests and hostile input.
Every finding was reproduced again by hand before it was fixed, and its test
was run against the code before the fix and seen to fail there: 17, 14, 12,
12, 16 and 3 methods across the six commits. The tests lens and most of the
skeptics did not finish (the run hit a usage limit), so this round's second
opinion is the failing test, not an independent refuter. The one lens that
did not report is the obvious next audit: vacuous and mutant-surviving
tests. Row 104 is one of those, found by lint.

What the round was mostly about: a file the program reads being trusted as
written. A BOM, a quoted `"false"`, a torn character, a mistyped record, a
zip header that lies, a signature file holding a non-text byte. Each one was
read as empty, as true, as a crash, or as clean, and some were then saved
over. The rule now: read it strictly, say what could not be read, set it
aside before anything is written over it, and never let one bad record take
down the others. The second theme was "says so" (60 before this). A lock
timeout said "No changes", a missing folder said "watching", a partial
removal exited 0. Each is a state now, with its own words and exit code.

Measured, before and after: lockless reconcile 33 and 22 of 500 files lost,
then 0 and 0; flushing about 1 ms per quarantined file; FIM lock hold on a
20,000-file re-baseline 1.77 s to 0.23 s, on a 1 GiB accept 1.01 s to
0.02 s; the zip bombs 12.9-57.7 s at 2-8 GB CLEAN, then 0.2-1.9 s at 106-329
MB SUSPICIOUS.

**Round four's sync was designed wrong (53, 54).** Reviewed the way rounds
two and three were. It rebuilt the cap set from the files on disk while the
rules compiled from those files stayed loaded, so a namespace with no entry
in the cap set scored as a shipped rule: a reports-only pack's `critical`
rule moved a file once its directory was gone and any process rewrote the
index, and a pack replaced under its own name kept the OLD rules running
uncapped with the cache re-keyed to the NEW generation. Both measured. And
it assigned the rules, the cap set and the cache as three attributes from
worker threads, so a scan in flight could read any mix of them. There is
one `Ruleset` object now, swapped as one reference; the cap is derived from
the loaded namespaces and the index's trust flags, with an unknown pack
capped; the sync compares each pack's recorded hash and file list with what
was loaded and reloads on any difference; and a scan takes its ruleset and
its cache once. Plan and numbers in [next-5.md](next-5.md).

**Rounds two and three, reviewed (44-52).** Six reviewers over the diff
since `050dd94`, two refuters per finding told to prove it wrong: fifteen
verdicts, none refuted. Two matter most. Round three's fix for a leaked log
file closed the handler in a `finally`, which runs before `sys.excepthook`,
so a crash under the windowed build -- the case the hook exists for -- left
an empty log (44). And the compiled-rule cache took its stat witnesses after
the compile; a file rewritten in that window produced a manifest for the new
content beside a blob of the old, and the recovery path then trusted the
matching manifest and kept the old blob on every later start (45): the
stale-rules failure this project exists to not have, introduced by the
change that made startup fast. Witnesses are taken before the compile, and a
manifest that itself fails the two-second rule cannot vouch for a blob.
The rest is the pack machinery lying in small ways, and a decision
(trust, or an exception) made in one process not reaching another -- the
same class as row 40, fixed the same way. Plan and measurements in
[next-4.md](next-4.md).

**A decision is a decision in every process (40).** Row 19 gave the
allowlist one owner per process, and the cross-process case was left to a
`reload()` nobody called. Measured: with the GUI running, `--restore` in a
terminal recorded the exception and the GUI's scanner went on saying
MALICIOUS -- cache on, cache off, and for a fresh copy. Two fixes, in
[next-3.md](next-3.md): the allowlist reloads itself when its file's size or
mtime has changed (one stat per lookup), and a cache hit defers to the
allowlist by the digest the entry stores, in both directions -- a cached
MALICIOUS whose bytes are now allowed is not returned, and a cached CLEAN
that was clean only by exception is not returned once the exception is gone.

**Round two was measured first (34-39).** The plan, the numbers before, and
the numbers after are in [next-2.md](next-2.md). Two of the audit's "leave
alone" calls were wrong once measured: the `\\?\` prefix is a legal spelling
of any path, not an index attack, and it defeated every guard in
protection.py; and the ten-second first launch was never the compile (0.17 s)
but the first touch of 310 small files, which a compiled-ruleset cache
replaces with one -- 8.24 s became 0.27 s. The cache is trusted only when
every rule file's size and mtime match what was recorded, none was written
within two seconds of the cache, and the blob's own hash matches the
manifest; reload never uses it. A restore can now be seen and undone under
Settings, and the exception digests are part of the detection generation, so
undoing one reaches every cached copy, not only the path that was put back.

**"Reports only" reduced detection (25).** The cloud lookup ran only when the
local verdict was CLEAN. One capped 50-point finding from an unpromoted pack
made a file SUSPICIOUS, so VirusTotal was never asked, and a sample it would
have condemned was left alone. The gate is now "nothing hard has decided",
which is what it always meant: a reports-only pack must not silence the engine
that was going to condemn the file, and hard local evidence still saves the
call.

**The pack ceiling that was never compared (27, 28, 29).** `admit()` held each
rule to 1% and computed the pack's aggregate rate, printed it, and compared it
to nothing. 120 narrow rules at 0.83% each flagged every clean file on the
machine and were admitted with "no rule over the ceiling". The per-rule check
still runs first, because it names the culprit; a 5% pack ceiling runs after
it for the case where no single rule is to blame. `verify` then printed "OVER
THE CEILING (0.00% of 400 flagged)" for a pack that had failed to *compile*:
`corpus_size` was known before compiling, so it could not tell a measured zero
from a pack that never got that far. `Admission.measured` can. And a pack that
failed verification stayed trusted -- exit 1 was a complaint, not a change of
state. It is now set back to reports-only, and says so. The rule count came
from a regex over the text; it comes from the compiled object now, which is
exactly the set that runs.

**The self-match check had the protection.py bug (32).** It walked `rules/`,
`avguard/` and `docs/` -- the same "three directories" mistake self-protection
made once and fixed by covering everything. It walks the whole project, the
user's rules, and every *other* installed pack now; a pack's own directory is
excluded on re-verification, since a pack legitimately contains the strings it
hunts for. Widening it found four tests and the smoke check whose needles were
literals in the files that wrote them, which is what `TRIPWIRE` was already
built by concatenation to avoid.

**Health counted the wrong thing (33).** It summed `rule_count` from the pack
index, so a pack whose directory had been deleted reported 1,240 rules loaded.
`yara.Rule` does not expose its namespace, so the count cannot be derived from
the combined ruleset; `load_rules()` already compiles each pack alone, and
records what that compile produced. That is what is running, which is the only
number the Health view exists to report.

**A bad file is an empty list (26).** A JSON array where an object was expected
raised `AttributeError` out of `Scanner.__init__` -- so out of the GUI
constructor and every CLI verb. Under `pythonw` the user saw nothing and the
cure was hand-editing a file in AppData. Both loaders check the shape and drop
malformed entries with a warning, and `AllowEntry` checks its field types,
because `"added_at": 12345` loaded fine and crashed `scan()` on `.when`.

**install() was not a transaction (22, 23, 24).** It ran `rmtree(destination)`
before reading a single source byte. Re-installing a pack from its own
directory -- a plausible way to refresh one -- deleted every rule file and then
raised, leaving the index still claiming the pack existed. "ReversingLabs 2024"
and "ReversingLabs+2024" sanitise to one directory, so the second install
silently threw away the first, trusted flag and all. And a pack that compiled
in its source folder via a relative `include` was admitted, copied flat, and
never compiled again -- an `Admission` was a boolean, not a receipt for what
was actually installed.

The pack is staged beside its destination, compiled FROM the staged copy, and
swapped into place last; any failure leaves the previous pack and the index
untouched. Collisions and self-overwrites are refused by name, with the name
the user actually typed kept beside the directory-safe one. The smoke check
now runs a full `--packs` round trip; the audit noted it had never invoked
`--packs` at all.

**One compile for everything (20, 21).** `load_rules()` promised "a bad rule
should cost you that rule, not all detection" and compiled every file in one
`yara.compile` call, so a single unparsable pack file -- a truncated download,
an upstream edit, a disk error -- aborted the lot. Verified: with one broken
pack file the shipped EICAR rule stopped matching, and only the hardcoded byte
signatures still fired. Importing a real pack multiplied the files able to do
that by 310, all maintained by somebody else.

Compilation is staged now: our own rules first, then each pack on its own, and
a pack that fails is left out, named in the log, and shown red in Health. The
generation hash also skipped pack files in favour of the sha256 recorded at
install -- so an edited pack compiled new rules under a bit-identical
generation and every cached verdict was replayed. It hashes the contents again;
3 MB of rules costs milliseconds, a stale cache costs trust.

**Shared state with two owners (17, 18, 19).** Three faults, one shape: an
object that backs a file on disk was constructed twice.

`Scanner` and `QuarantineStore` each built their own `Allowlist`, so `restore()`
recorded a decision in one and `scan()` read from the other. In the running GUI
a restored file was re-detected on the very next scan -- the exact failure the
allowlist exists to prevent. `Allowlist.reload()` had been written for this and
had **zero call sites**. Settings built its own `PackStore` the same way, so
turning a pack off after a false positive wrote to disk while the scanner
carried on condemning.

Neither was visible to the tests, because the tests wired the objects together
themselves. They exercised an arrangement no entry point builds.

The third was worse. Because `QuarantineStore` builds a default `Allowlist`
when it is not handed one, the suite had been writing into the user's live
`%LOCALAPPDATA%/AVGuard/allowlist.json` -- seven entries, one of them the hash
of `SELFTEST_MARKER`, which then suppressed its own detection and broke four
unrelated tests. Patching each construction was tried first and missed one.
Every test module now sets `AVGUARD_DATA` to a per-run directory *before*
importing avguard, which is the fix that cannot be missed: a shared fixed path
also accumulated state between runs.

**The archive path (16).** The headline guarantee of rule packs is that an
imported rule cannot move a file until the pack is promoted by name. It held
for loose files and not for archive members, because `_archive_findings` was a
second copy of the scoring loop and the cap went into only one of them. A
never-promoted pack's `severity = "critical"` scored 50 on a loose file and 100
on the identical bytes inside a zip -- so the file was moved. Archive scanning
is on by default and real-time watching is aimed at Downloads, which is where
zips arrive, so the uncapped path was the likely one rather than the exotic one.

I had claimed this guarantee verified "in both directions". It was: both
directions of *promotion*, on one of two code paths. The fix is not a second
copy of the cap but a single `_finding_from_match` that every path goes
through, because duplicated logic is where invariants go to die.

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

### C. Known limits

**Rule files pulled in by `include`** are neither in the compiled-rule
manifest nor in the detection generation: yara-python does not report what a
rule file included. An edit to an included file is compiled on the next
Reload, not the next start. A rule file itself edited is always noticed.

### B. Seen once, not reproduced

**`Fatal Python error: _PySemaphore_Wakeup: parking_lot: ReleaseSemaphore failed`**
during `tests/test_durability.py`, in `WorkerPool.stop()` -> `Queue.put_nowait`
-> `Condition.notify`, on Python 3.13.3 / Windows 11. One full-suite run in four
died there; the module alone passed four times in a row, and the same suite was
green in the two runs either side of it. The crash is inside the interpreter's
parking lot -- a waiter whose per-thread semaphore handle is no longer valid --
not in code this project controls; `stop()` does nothing beyond a sentinel per
worker and a bounded `join`. `WorkerPool.stop()` also runs when settings are
saved and on exit, so if it recurs in the application it would take the process
with it. Worth knowing: whether it recurs on a newer 3.13.x, which CI runs on.

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
