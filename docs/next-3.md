# What comes next, round three

Written on 2026-09-03 after round two ([next-2.md](next-2.md)) landed. Every
item was measured on this machine before it was written down; the numbers are
below each one, and the "after" numbers are added when the item is built.

Ranked as before: can a file be moved that should not be, or a decision lost;
then does the program mislead; then does it break for somebody who is not me.

---

## A. A decision made in another process never reaches a running scanner  — DONE

**Measured.** One scanner object standing in for the running GUI, a second
`Allowlist` on the same file standing in for `avguard --restore` in another
window:

    GUI scanner, before the other process restores   MALICIOUS
    other process records the exception on disk       1 entry
    GUI scanner, same path, cache on                   MALICIOUS
    GUI scanner, same path, cache off                  MALICIOUS
    GUI scanner, a fresh copy of the same bytes        MALICIOUS

With real-time protection and automatic quarantine on, a restore made from
the command line is taken straight back by the GUI within a second. That is
the exact failure the allowlist exists to prevent (row 19), in cross-process
form. Two causes: the scanner's `Allowlist` reads its file once, at
construction, and `Allowlist.reload()` is called only by the Settings dialog;
and a cached verdict is returned before the allowlist is consulted at all.

**Fix.**
- `Allowlist` remembers the size and mtime of the file it loaded and reloads
  when `allows()` finds them changed: one `stat()` per lookup, which a scan
  that has just read the whole file will not notice.
- A cache hit is checked against the allowlist by the digest the entry
  already stores: a cached MALICIOUS whose bytes are now allowed is not
  returned, and a cached CLEAN that was *only* clean by exception (the entry
  says so) is not returned once the exception is gone. The cache stays a
  cache; the decision stays with the allowlist.

**Tests.** The probe above, both directions, with the cache on. And the
in-process case from round two still passes, so re-keying on change is not
what was holding it up.

**Measured after.** The same probe: MALICIOUS before the other process
restores; CLEAN with the cache on, CLEAN for a fresh copy, "you chose to
keep" in the reason, and MALICIOUS again the moment the other process
withdraws the exception. Nobody called reload() or re-keyed anything. The
round-two test that expected a re-key to be necessary was updated to expect
the better behaviour, and the one that pinned "a second instance cannot see
it without reload" now pins the opposite.

---

## B. The Settings window is taller than the screen  — DONE

**Measured.** `SettingsDialog.winfo_reqheight()` with three kept files and no
packs: **1438 px**, on a 1080 px screen. Round two's "Files you chose to keep"
frame added about 150 px of that; the window was already past 1080 without it,
so Save and Cancel have been below the bottom edge of a laptop display for a
while, and the dialog is not resizable. The Health window asks for 787 px,
which fits.

**Fix.** A `ttk.Notebook`: Protection, Folders (watched and never-scanned),
Running by itself, Rule packs, Kept files. Save and Cancel stay below the
tabs. Nothing about `_save` changes; the widgets keep their names.

**Tests.** The dialog's requested height is under 720 px with three kept
files and two packs, measured the same way.

**Measured after.** 577 x 599 px, from 573 x 1438. The tallest tab is
Folders, with both lists on it.

---

## C. The shipped rules are held to the corpus the packs were  — DONE

**Measured.** `tests/test_rules.py` builds its own corpus with the same
walker round two replaced in `_clean_corpus()`, and it has the same skew:
400 files, **217 from System32, 143 from SysWOW64, 40 from Program Files
across five program folders**, 189 MB. The shipped rules' 1% ceiling and the
"no clean file is ever MALICIOUS" rule are measured almost entirely against
Microsoft's own binaries. Round two fixed this for packs (row 37) and left
the harness for our own rules as it was, which is the easier bar.

Also the reason the suite takes 40 s on this module: `TestBenignCorpus`
runs the full pipeline over 189 MB. That part is the test's value and stays.

**Fix.** One corpus builder. `test_rules` calls `avguard.__main__._clean_corpus()`
instead of its own walk, so the shipped rules and the packs are measured
against the same spread of software.

**Tests.** The existing ones, against the new corpus -- which is the point:
if a shipped rule fires on something in Program Files, this is where it
shows.

**Measured after.** 400 files, 350 MB (was 189): 100 each from Program
Files, Program Files (x86), the per-user Programs folder and System32. The
shipped rules flag none of it as MALICIOUS. The module takes 71 s instead of
40, because Program Files binaries are larger than System32's DLLs and the
benign-corpus test runs the whole pipeline over every one; that is the cost
of measuring against what people actually run, and it is paid once per suite.

---

## D. `test_cli` leaves a directory behind for every test  — DONE

**Measured.** After three full runs, 14 `avguard-cli-*` directories remained
in TEMP; a run of the module alone leaves 7, each holding exactly one file,
`data\logs\avguard.log`, and every one deletes fine a moment later. The
`avguard` logger's `RotatingFileHandler` stays open after `main()` returns,
and `logsetup.configure()` only closes it when the *next* test calls it --
after the previous test's cleanup has already tried and given up.

**Fix.** `logsetup.close_file_handlers()`, called when `main()` returns (a
command-line verb should not hold its log open after it is done) and from
`test_cli`'s cleanup before the directory is removed.

**Tests.** The module leaves nothing in TEMP, and `main()` returns with no
rotating file handler on the `avguard` logger.

**Measured after.** A run of the module alone: 4 `avguard-cli-*` directories
in TEMP before, 4 after -- the four being leftovers from runs made before the
fix. Nothing new is left behind.

---

## Order

A, B, C, D. A is a decision lost. B is a window the user cannot use. C is
the harness being honest. D is hygiene.
