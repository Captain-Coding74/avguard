"""The Integrity tab: file-integrity monitoring, driven from the window.

The same FimStore the CLI uses, with the two things a window needs that a
terminal does not. A check hashes every file under the baseline's roots, so
it runs on a worker thread the way a scan does; and everything it changes on
screen comes back through the window's `post()`, so no widget is touched off
the GUI thread (the rule gui.py exists to enforce).

Nothing here moves a file. A check reports, and accepting a change is a
button a person presses, which re-signs the baseline exactly as
`--fim-accept` does.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog
from typing import Callable, Iterable

import ttkbootstrap as tb
from ttkbootstrap.constants import BOTH, DISABLED, END, HORIZONTAL, LEFT, NORMAL, RIGHT, VERTICAL, X, Y
from ttkbootstrap.dialogs import Messagebox

from . import fim
from .events import EventStore

log = logging.getLogger("avguard.fimpanel")

# Seconds between progress posts. A check over small files hashes thousands
# a second, and the window's pump drains 200 callables per 100 ms tick; one
# post per file would leave the bar minutes behind the work.
PROGRESS_INTERVAL = 0.1
KIND_COLOURS = {"modified": "#ffd166", "added": "#4dd0e1", "removed": "#ff6b6b"}
# The tab sits in the right pane, two fifths of a 1,100 px window: about
# 420 px of it. Everything that wraps, wraps at this.
WRAP = 380
CHR_NL = chr(10)


# ------------------------------------------------------------ pure helpers
# No widgets in these three, so they are tested where tkinter is not installed.

def summarize(store: fim.FimStore) -> tuple[bool, str]:
    """(all is well, one line on the baseline) for the tab and the Health row."""
    if not store.exists():
        return True, ("No baseline yet. Baseline a folder whose files should not change, "
                      "then check it whenever you like.")
    try:
        when = datetime.fromtimestamp(store.baselined_at()).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError):
        when = "unknown"
    roots = store.roots()
    where = ", ".join(roots[:3]) + (f" and {len(roots) - 3} more" if len(roots) > 3 else "")
    head = f"{store.file_count():,} file(s) baselined {when} under {where}."
    integrity = store.verify_integrity()
    if integrity == fim.INTEGRITY_OK:
        return True, f"{head} Signature holds."
    return False, f"{head} SIGNATURE {integrity.upper()}: {fim.INTEGRITY_MESSAGES[integrity]}."


def row_for(change: fim.Change, roots: Iterable[str] = ()) -> tuple[str, str, str]:
    """(kind, path, detail) for one row of the changes list.

    The path is shown relative to the baseline root it is under, when one is
    given: the pane is 400 px wide and the root is the same for every row.
    The event and the log carry the full path.
    """
    shown = change.path
    normalized = os.path.normcase(change.path)
    for root in sorted(roots, key=len, reverse=True):      # the deepest root wins
        if normalized.startswith(os.path.normcase(root).rstrip(os.sep) + os.sep):
            shown = change.path[len(root.rstrip(os.sep)) + 1:]
            break
    if change.kind == "modified":
        detail = (f"{change.old_sha256[:12]} -> {change.new_sha256[:12]}, "
                  f"{change.old_size:,} -> {change.new_size:,} bytes")
    elif change.kind == "added":
        detail = f"{change.new_sha256[:12]}, {change.new_size:,} bytes"
    else:
        detail = f"was {change.old_sha256[:12]}, {change.old_size:,} bytes"
    return change.kind.upper(), shown, detail


def describe_check(report: fim.CheckReport) -> str:
    """The status line under the list, in the CLI's words."""
    if report.integrity == fim.INTEGRITY_NO_BASELINE:
        return "No baseline to check against. Baseline a folder first."
    parts: list[str] = []
    integrity = report.integrity_event()
    if integrity is not None:
        parts.append(f"BASELINE: {integrity.reasons[0]}.")
    if report.cancelled:
        parts.append(f"Check cancelled: {len(report.changes)} change(s) found before it "
                     "stopped, nothing recorded.")
        return " ".join(parts)
    mode = "size and date trusted" if report.fast else "every file hashed"
    parts.append(f"Examined {report.examined:,} baselined file(s), hashed {report.hashed:,} "
                 f"({mode}) in {report.seconds:.1f} s.")
    if report.changes:
        parts.append(f"{len(report.modified)} modified, {len(report.added)} added, "
                     f"{len(report.removed)} removed. Nothing was moved; select a change "
                     "you have looked at and accept it.")
    else:
        parts.append("No changes.")
    if report.errors:
        parts.append(f"{len(report.errors)} path(s) could not be read; see the log.")
    return " ".join(parts)


# ------------------------------------------------------------------ panel

class IntegrityPanel(tb.Frame):
    """The tab. `store_factory` builds a FimStore with the current exclusions,
    `events` is the window's store (so a check's events are recorded and
    forwarded like any other), and `post` is the window's thread bridge."""

    def __init__(self, parent, *, store_factory: Callable[[], fim.FimStore],
                 events: EventStore, post: Callable[..., None], **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._store_factory = store_factory
        self._events = events
        self._post = post
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._changes: list[fim.Change] = []
        self._roots: list[str] = []
        self._build()
        self.refresh()

    def _build(self) -> None:
        self.summary_var = tk.StringVar()
        self.summary = tb.Label(self, textvariable=self.summary_var, bootstyle="secondary",
                                wraplength=WRAP, justify="left", anchor="w")
        self.summary.pack(fill=X, pady=(0, 6))
        self._wrapped: list[tb.Label] = [self.summary]

        wrap = tb.Frame(self)
        wrap.pack(fill=BOTH, expand=True)
        # Five rows requested; the pane gives it whatever is left. With the
        # default ten the tab asked for more height than the window's minimum
        # size leaves, and the buttons under it went off the bottom.
        self.tree = tb.Treeview(wrap, columns=("kind", "file", "detail"), show="headings",
                                selectmode="extended", height=5)
        self.tree.heading("kind", text="Change")
        self.tree.heading("file", text="File")
        self.tree.heading("detail", text="Was -> now")
        self.tree.column("kind", width=80, anchor="w", stretch=False)
        self.tree.column("file", width=170, anchor="w")
        self.tree.column("detail", width=120, anchor="w")
        for kind, colour in KIND_COLOURS.items():
            self.tree.tag_configure(kind, foreground=colour)
        scroll = tb.Scrollbar(wrap, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=RIGHT, fill=Y)
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)

        self.status_var = tk.StringVar(value="")
        status = tb.Label(self, textvariable=self.status_var, bootstyle="secondary",
                          wraplength=WRAP, justify="left", anchor="w")
        status.pack(fill=X, pady=(6, 0))
        self._wrapped.append(status)
        self.progress = tb.Progressbar(self, orient=HORIZONTAL, mode="determinate",
                                       bootstyle="info")
        self.progress.pack(fill=X, pady=(6, 0))

        buttons = tb.Frame(self, padding=(0, 8))
        buttons.pack(fill=X)
        self.check_btn = tb.Button(buttons, text="Check now", bootstyle="info",
                                   command=self.check)
        self.check_btn.pack(side=LEFT, expand=True, fill=X, padx=2)
        self.accept_btn = tb.Button(buttons, text="Accept selected", bootstyle="success-outline",
                                    command=self.accept_selected)
        self.accept_btn.pack(side=LEFT, expand=True, fill=X, padx=2)
        self.cancel_btn = tb.Button(buttons, text="Cancel", bootstyle="warning-outline",
                                    command=self.cancel, state=DISABLED)
        self.cancel_btn.pack(side=LEFT, expand=True, fill=X, padx=2)

        second = tb.Frame(self)
        second.pack(fill=X)
        self.baseline_btn = tb.Button(second, text="Baseline a folder...",
                                      bootstyle="secondary-outline", command=self.baseline)
        self.baseline_btn.pack(side=LEFT, padx=2)
        # The trade is stated next to the switch, the way --fast's help states it.
        self.fast_var = tk.BooleanVar(value=False)
        tb.Checkbutton(second, text="Trust size and date", variable=self.fast_var,
                       bootstyle="round-toggle").pack(side=LEFT, padx=(12, 2))
        trade = tb.Label(self, bootstyle="secondary", wraplength=WRAP, justify="left",
                         text=("Trusting size and date skips the read: faster, and exactly what "
                               "an attacker who edits a file and puts its timestamp back defeats."))
        trade.pack(anchor="w", padx=2, pady=(4, 0))
        self._wrapped.append(trade)
        self.bind("<Configure>", self._reflow)

    def _reflow(self, event) -> None:
        """Wrap the text to the width the pane actually gives, not a guess."""
        width = max(WRAP, event.width - 12)
        for label in self._wrapped:
            label.configure(wraplength=width)

    # ------------------------------------------------------------- state

    def refresh(self) -> None:
        """Re-read the baseline on disk. GUI thread only."""
        ok, text = summarize(self._store_factory())
        self.summary_var.set(text)
        self.summary.configure(bootstyle="secondary" if ok else "danger")

    @property
    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def changes(self) -> list[fim.Change]:
        """What the list shows, in row order, accepted rows left out."""
        return [self._changes[int(iid)] for iid in self.tree.get_children()]

    def _set_busy(self, busy: bool) -> None:
        state = DISABLED if busy else NORMAL
        for button in (self.check_btn, self.accept_btn, self.baseline_btn):
            button.config(state=state)
        self.cancel_btn.config(state=NORMAL if busy else DISABLED)
        if not busy:
            self.progress.config(value=0)

    def _start(self, name: str, work: Callable[[], None]) -> bool:
        """One operation at a time; the buttons say so while it runs."""
        if self.busy:
            Messagebox.show_info("An integrity check or baseline is already running.",
                                 "AVGuard", parent=self.winfo_toplevel())
            return False
        self._cancel.clear()
        self._set_busy(True)
        self.progress.config(value=0, maximum=100)
        self._thread = threading.Thread(target=self._guarded, args=(work,),
                                        name=f"avguard-fim-{name}", daemon=True)
        self._thread.start()
        return True

    def _guarded(self, work: Callable[[], None]) -> None:
        """Worker thread. Every UI change goes through self._post."""
        try:
            work()
        except Exception:
            log.exception("integrity operation failed")
            self._post(self._failed)

    def _failed(self) -> None:
        self._set_busy(False)
        self.status_var.set("That did not finish; the log says why.")

    def _progress_hook(self, verb: str) -> fim.ProgressHook:
        """A rate-limited progress callback, called on the worker thread."""
        last = 0.0

        def hook(done: int, total: int) -> None:
            nonlocal last
            now = time.monotonic()
            if done < total and now - last < PROGRESS_INTERVAL:
                return
            last = now
            self._post(self._show_progress, verb, done, total)
        return hook

    def _show_progress(self, verb: str, done: int, total: int) -> None:
        self.progress.config(maximum=max(1, total), value=done)
        self.status_var.set(f"{verb} {done:,} of {total:,} file(s)...")

    def cancel(self) -> None:
        self._cancel.set()
        if self.busy:
            self.status_var.set("Stopping after the file in hand...")

    def stop(self, timeout: float = 5.0) -> None:
        """At shutdown: ask the worker to stop, and wait for it."""
        self._cancel.set()
        if self.busy:
            self._thread.join(timeout=timeout)

    def _clear_rows(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._changes = []

    def _add_row(self, change: fim.Change) -> None:
        # The row's id is its index into self._changes, which is never
        # reordered: an accepted row is deleted from the tree and the others
        # keep their ids. Indexing a fresh list by row number is how the
        # kept-files dialog once removed the wrong file.
        index = len(self._changes)
        self._changes.append(change)
        kind, path, detail = row_for(change, self._roots)
        self.tree.insert("", END, iid=str(index), values=(kind, path, detail), tags=(change.kind,))

    # ---------------------------------------------------------- baseline

    def baseline(self) -> None:
        chosen = filedialog.askdirectory(
            title="Record every file under this folder as the baseline",
            parent=self.winfo_toplevel())
        if chosen:
            self.start_baseline(Path(chosen))

    def start_baseline(self, folder: Path) -> bool:
        store = self._store_factory()

        def work() -> None:
            report = store.baseline([folder], progress=self._progress_hook("Hashed"),
                                    should_stop=self._cancel.is_set)
            self._post(self._baseline_finished, folder, report)
        return self._start("baseline", work)

    def _baseline_finished(self, folder: Path, report: fim.BaselineReport) -> None:
        self._set_busy(False)
        self.refresh()
        for problem in report.errors:
            log.warning("baseline: %s", problem)
        if report.cancelled:
            self.status_var.set("Baseline cancelled; nothing was written.")
            return
        if not report.roots:
            self.status_var.set(f"Nothing was baselined: {'; '.join(report.errors)}")
            return
        # The list was measured against the old baseline; it no longer applies.
        self._clear_rows()
        mb = report.bytes / (1024 * 1024)
        skipped = f", {report.skipped} unreadable file(s) skipped" if report.skipped else ""
        self.status_var.set(f"Baselined {report.files:,} file(s), {mb:,.1f} MB, under {folder} "
                            f"in {report.seconds:.1f} s{skipped}. The baseline is signed.")

    # ------------------------------------------------------------- check

    def check(self) -> bool:
        store = self._store_factory()
        if not store.exists():
            self.status_var.set(describe_check(fim.CheckReport(integrity=fim.INTEGRITY_NO_BASELINE)))
            return False
        fast = bool(self.fast_var.get())

        def work() -> None:
            report = store.check(fast=fast, events=self._events,
                                 progress=self._progress_hook("Checked"),
                                 should_stop=self._cancel.is_set)
            self._post(self._check_finished, report)
        return self._start("check", work)

    def _check_finished(self, report: fim.CheckReport) -> None:
        self._set_busy(False)
        self.refresh()
        self._roots = self._store_factory().roots()
        self._clear_rows()
        for change in report.changes:
            self._add_row(change)
        for problem in report.errors:
            log.warning("integrity check: %s", problem)
        self.status_var.set(describe_check(report))

    # ------------------------------------------------------------ accept

    def accept_selected(self) -> bool:
        iids = list(self.tree.selection())
        if not iids:
            Messagebox.show_info("Select a change in the list first.", "AVGuard",
                                 parent=self.winfo_toplevel())
            return False
        selected = [self._changes[int(iid)] for iid in iids]
        answer = Messagebox.yesno(
            f"Accept {len(selected)} change(s) into the baseline?" + CHR_NL + CHR_NL
            + "They will not be reported again. Accept only what you have looked at: a "
              "change you cannot explain is the reason this list exists.",
            "Accept these changes?", parent=self.winfo_toplevel())
        if answer != "Yes":
            return False
        store = self._store_factory()
        paths = [Path(change.path) for change in selected]

        def work() -> None:
            notes = store.accept(paths)
            self._post(self._accept_finished, iids, notes)
        return self._start("accept", work)

    def _accept_finished(self, iids: list[str], notes: list[str]) -> None:
        self._set_busy(False)
        for note in notes:
            log.info("integrity: %s", note)
        for iid in iids:
            if self.tree.exists(iid):
                self.tree.delete(iid)
        self.refresh()
        left = len(self.tree.get_children())
        self.status_var.set(f"Accepted {len(iids)} change(s) into the baseline; "
                            f"{left} left in the list." if left else
                            f"Accepted {len(iids)} change(s) into the baseline. The list is empty.")
