# What comes next, round six

Written 2026-10-04, from a seven-way design review of the feature list the
owner pasted: a paste-and-run guard, a crypto clipboard-swap guard, a
persistence diff, a per-machine behaviour baseline, an "explain why" mode,
a download-provenance (Mark-of-the-Web) chain, and a Thai-focused threat
pack. One grounding pass read the ground rules and the tree; seven
assessors each took one idea against them; refuters were to attack every
assessment through two lenses. The refuters finished for two ideas (the
two clipboard ones) and were then lost to a usage limit, as round five's
were. So: the first item below is built, measured and twice re-read; the
clipboard-swap item carries its refutations; the other five are
assessments that nobody has yet tried to knock down, and they say so.

The ranking rule is the ROADMAP's: does it stop the tool hurting the user,
or make a failure loud? Honesty beats growth. That order, not the order
the list arrived in, is the order here.

---

## 1. The paste guard (ClickFix / FileFix)  — DONE

Built first, as asked, in `2572ff6`, read again in `21cf070`, and put
through a five-lens adversarial review in `4d4726c`. The record is in
ROADMAP.md under "The paste guard" and "The paste guard, second reading";
the short form: a 500 ms poll of `GetClipboardSequenceNumber` on the Tk
thread, the clipboard opened only on a change, a pure classifier that
wants a launcher in command position plus a signal an honest command has no
reason for, a quieter notice for the install one-liners developers paste,
no Finding and no Verdict, nothing kept, nothing sent (the event is
recorded for History and never forwarded), nothing read while off or
present at startup or marked private. 33 of 33 lure fixtures warn with the
signal they are named for; 0 of 38 legitimate lines warn (4 notices). The
second reading found 47 things, among them a host that could be spoofed
with `#@`, dressing signals that fired on a launcher alone, text copied
while the guard was off being read when it came back on, the first-run
dialog's close button turning it on, and "sends nothing" being false with
event forwarding on. All fixed and tested; 551 -> 593 tests.

Still owed, on the owner's desktop: the live tick over a day, what
`GetClipboardOwner` resolves to for a browser's write, which password
managers set which private-format marker.

## 2. "Explain why" — DONE, reduced as planned

Built the same day; the record is in ROADMAP.md under "Explain why". The one
departure from the shape below: a quarantined file's evidence lives in a
sidecar beside the index, not on the record, because an older AVGuard drops
an index row with a field it does not know. The confidence number stayed
refused. What was planned:


**The honesty bug it starts from, measured in this checkout.** A file that
scans MALICIOUS with one hard finding (the self-test marker: `signature`,
weight 100, hard) scans MALICIOUS again from the cache 0.19 ms later with
`findings=[]` and `score=0`. The encoded-PowerShell fixture: 50, then 0.
That 0 is what the event store writes and what event forwarding sends.
The program says MALICIOUS and, asked why, says nothing. By the ranking
rule that is a lie about its own state, which is why this ranks above the
larger items.

**What to build.** A tkinter-free `avguard/explain.py` (added to the Linux
import list): an `Explanation` with one sentence per level (MALICIOUS
"enough hard evidence to move the file"; SUSPICIOUS "reported and left
alone: opinions never move a file"; CLEAN by exception "kept because you
said so on {date}") and rows of kind fact, opinion, set aside or your
decision, each with its source in words, its weight, where it came from
(signature, blocklist and its source, rule name with severity and pack,
PE structure, archive structure, TLSH distance, entropy, VirusTotal).
The account shows `decide()`'s arithmetic, the hard total and the soft
total capped at 75, not `Verdict.score`, which is the uncapped sum and
would read "150 of 100" for a signature-plus-PE file. The cache keeps the
findings (a `ScanCache` schema bump, so a replay knows as much as the
first scan), `QuarantineRecord` gains the field with a default, the event
detail carries the rows, `--scan --explain` prints them, and one
ttkbootstrap Toplevel shows them from the Quarantine tab and History.

**Refused inside it:** a confidence percentage. It would be v1's
"unjustified confidence" in a new place, quoted in bug reports as if
measured. The account says fact or opinion and shows the weights; that is
all the scanner knows.

**Rules:** no new Finding, no weight changed; a test asserts `explain()`
leaves `verdict.level` and `verdict.findings` identical on every fixture.
The cache schema change bumps `DETECTION_VERSION` for the reason ground
rule 3 gives. **Measure first:** count the owner's real events with level
malicious or suspicious and score 0, and reproduce the 100-then-0 in a
test before the change and 100-then-100 after. Effort M, no dependency.

## 3. Persistence diff (what starts with Windows) — DONE

Built the same day as the account; the record is in ROADMAP.md under
"What starts with Windows". As shaped below, with two departures: there is
no Settings toggle (the integrity baseline has none either; the tab and
the schedule verb are the switches), and the quiet rule without a
signature checker is "under the Windows folder" alone, stated as the trade
until the owner's fourteen days of changes are in. What was planned:


**Why it fits.** Of the seven, the repository is already most of the way
to this one: `fim.py` is the diff engine with its events, HMAC-signed
store, cancellation and never-moves invariants debugged; `scheduling.py`
already wraps `schtasks` and already builds a records-only daily task;
`shellext.py` established injectable, fake-tested registry access;
`fimpanel.py` is the tab to copy. Nothing in the tree enumerates a Run
key, a scheduled task, a service or a Startup folder today (grep
confirmed), and almost every piece of commodity malware that wants to
survive a reboot writes one of them from user mode (ATT&CK T1547.001,
T1053.005).

**Shape.** `avguard/autoruns.py`, stdlib only, `winreg` imported inside a
function so the module imports on Linux. `Entry(kind: run|startup|task|
service, location, name, value, enabled, detail, fingerprint)` where the
fingerprint is a SHA-256 over the fields that matter (kind, location,
name, value, arguments, enabled, triggers) and `detail` carries what must
not count as a change (a task's next-run and last-run times, its last
result). A snapshot a day through the existing records-only task;
snapshot-to-snapshot diff, not fixed-baseline-until-accepted, because
startup state legitimately drifts. Collectors: HKCU and HKLM Run and
RunOnce (both WOW64 views), the two Startup folders, services from the
registry, tasks through `schtasks /Query /XML ONE` decoded with the
console code page. Store under `DATA_DIR/autoruns`, signed like FIM's. A
tab beside Integrity, a Health row, a Settings toggle, a CLI verb,
History events of kind `autoruns` with old and new.

**The noise it must survive.** Patch Tuesday rewrites a dozen tasks under
`\Microsoft\Windows\` and re-types services. They go in the tab and
History (that is the honest record) with no banner and no tray notice
when the target is Microsoft-signed under `%SystemRoot%`; a 14-day count
on the owner's machine sets the banner rule, and if it still nags, the
feature drops to event-only.

**Rules.** It reads configuration at a point in time, as Sysinternals
Autoruns does as a standard user: no driver, no elevation, no hook, no
process telemetry, so it does not reopen "no process monitoring". It
produces events, never a Finding, never a move. **Measure first:**
`--autoruns-snapshot -v` printing per-collector wall time and entry
count, the XML byte count, the database size after 1 and after 30
snapshots, and two snapshots seconds apart on an idle machine differing
in nothing. Effort L, no dependency.

## 4. Download provenance (Mark-of-the-Web) — DONE, reduced as planned

Built 2026-10-05; the record is in ROADMAP.md under "Where a file came
from". As shaped below, with two departures: the restored or exported
file gets the zone back and nothing else (the URL was never kept, so there
is nothing else to put back), and the "downloaded from" row is added only
to a verdict that is already SUSPICIOUS or MALICIOUS, so a clean download's
verdict stays empty and the mark is read for flagged files and for the
kinds a lost mark matters for (programs, scripts, Office documents), not
for every file. The sentence below that "every 7-Zip extraction loses it"
was stale when written: 7-Zip 22.00 can propagate the mark, off by default,
and Explorer's own extraction keeps it. What was planned:


**What is right in the proposal.** The mark is an NTFS named stream a
browser writes on a download (`[ZoneTransfer]`, `ZoneId=3`, often
`HostUrl=` and `ReferrerUrl=`), SmartScreen and Office's Protected View
gate on it and nothing else, and every 7-Zip extraction loses it. Python
reads it with no ctypes at all: `open(f"{path}:Zone.Identifier")`. The
archive member bytes are already in memory in `archives.py`, so tying an
extracted executable back to the zip it came from is one hash per
member. Nothing in the tree reads a stream today.

**What is wrong in it.** "Flag" cannot mean a scored finding: the mark is
lost by every honest extraction, and the README says a false positive is
worse than a miss. So: informational, weight 0, hard False, a test
asserting `decide()` is identical with and without provenance findings.
When a file is already SUSPICIOUS or MALICIOUS the verdict carries
"downloaded from example.test" (host only, never the URL, which appears
nowhere in the verdict, event, log or store). An extracted, unmarked
executable whose container was marked gets one banner per container per
session and a History row, no tray notice.

**Something it found in passing, worth fixing on its own:** quarantine
restore and export copy bytes (`shutil.copy`, `write_bytes`) and so drop
the mark; `os.replace` within a volume keeps it. A restored download
should still be a download to SmartScreen.

**Measure first:** `read_zone` on 1,000 marked and 1,000 unmarked files
warm, the facts-pass delta per file over the 978-file corpus with the
cache off, the member-hashing delta on the real Downloads zips. Effort M,
no dependency, Windows-only reader behind `available`.

## 5. Thai-focused threat pack — build the one part with a surface

**The proposal fails the project's own tests before any skeptic.** The
Thai campaigns of 2023-2026 are real and under-served, and almost none
touch a Windows file: the dominant lure delivers an Android APK through
LINE or SMS. A phishing-domain list has no surface here (the scanner
never sees a URL, the paste guard refuses bare URLs by design, the hosts
file needs administrator rights, anything upstream of the browser is a
driver or an extension) and would be the daily-refreshed feed the ROADMAP
refuses. A Thai YARA pack has no sample set to write `must_match`
fixtures from and no corpus to measure against; any future pack arrives
third-party through `--packs add`, capped and measured like every pack.

**The part with a surface:** Thai lure vocabulary in the paste guard's
`_LURE_COMMENT` (robot, captcha, verify, human, "I am not", in the forms
a Thai ClickFix tail uses), with NFKC in `normalize()` already folding
the two spellings of sara am, four Thai `must_warn` fixtures and one
`must_not_warn` (a Thai developer's own commented one-liner gets the same
bar English gets). Effort S; it can ride with any paste-guard commit.
Measured claim to make: 0 of 4 Thai fixtures WARNING before, 4 of 4
after, the English twins unchanged.

## 6. Crypto clipboard-swap guard — reduced, and measure the tick first

The two refutations that did run agree on the design flaw: the assessment
drew a second clipboard reader (a 50 ms daemon thread with its own
OpenClipboard, toggle, Health row and consent) for a repository that
already has one. Two readers would each open the clipboard on every
change and make AVGuard its own "another application holds the
clipboard". The right shape is a second pure classifier, `family(text)`,
beside `classify()`, with the swap check inside `PasteGuard.tick()` on the
same read: a wallet-shaped string replaced within a short window by a
different address of the same family (Base58Check and bech32 for Bitcoin,
Litecoin's versions, Ethereum's EIP-55, Tron's, with checksums verified so
a one-character change is not an address).

**The open question that decides whether it is worth building:** the
guard polls at 500 ms. A clipper that rewrites the clipboard within
milliseconds of the copy leaves only the attacker's address for the poll
to see, and a swap cannot be recognised without the original. Before any
code: a throwaway test clipper on the owner's machine swapping at 50, 200
and 600 ms, and the count of swaps the 500 ms tick can see at all. If the
answer is "only slow ones", the feature is a sentence in the README, not
a module. Effort M if built, no dependency.

## 7. Per-machine behaviour baseline — do not

Programs that open connections or spawn children they never have before
is the post-execution gap, and it is real. But the honest version of
behaviour monitoring is event-driven and needs ETW kernel providers or a
driver, both of which need admin; what Python can do from user mode is
poll `GetExtendedTcpTable` and the Toolhelp snapshot, which observes
state, not events, and misses anything shorter than the poll. The
deviation it can report is "first time ever", which fires once for every
newly installed program, forever. This reopens a decision the project has
recorded three times (ROADMAP "Deliberately not doing", docs/next.md
Part 3, docs/improvements.md), and the reason given there still holds.
Not built; the entry stands.

---

## The order

Explain why (an honesty bug, measured), then the persistence diff, then
provenance reduced, with the Thai lure words riding along. The swap guard
waits for its measurement. The baseline is refused. Each lands under the
ground rules: a number and the command in the commit, a `DETECTION_VERSION`
bump where a verdict's meaning moves (the cache schema in item 2), events
and tabs that never move a file, data under `DATA_DIR`, a ROADMAP
paragraph with what was measured and what was not.
