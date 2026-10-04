"""The Startup tab: what starts with Windows, and what changed since the
previous snapshot. The Integrity tab's design applied to configuration.

The snapshot runs on a thread of its own and reports through the window's
post(), like a check; the list shows the last diff; a change whose target
is a trusted program under the system root is a row and a History event,
never a banner, because that is what an update looks like. The window's
signature checker is asked on the snapshot's worker, never on the GUI
thread; the list the tab opens on is judged by the system-root rule alone.
The tab moves nothing and cannot: a snapshot reads.
"""

from __future__ import annotations

import logging
import threading
import time
import tkinter as tk
from typing import Callable

import ttkbootstrap as tb
from ttkbootstrap.constants import BOTH, DISABLED, END, HORIZONTAL, LEFT, NORMAL, RIGHT, VERTICAL, X, Y
from ttkbootstrap.dialogs import Messagebox

from . import autoruns
from .events import EventStore

log = logging.getLogger("avguard.startuppanel")

KIND_COLOURS = {"added": "#4dd0e1", "modified": "#ffd166", "removed": "#ff6b6b"}
WORDS = {"added": "new", "modified": "changed", "removed": "gone"}
WRAP = 380


def row_for(change: autoruns.Change) -> tuple[str, str, str]:
    """(what happened, what it is, the detail) for one row of the list."""
    entry = change.entry
    what = f"{entry.kind}: {entry.name}"
    if change.kind == "added":
        detail = entry.value + ("" if entry.enabled else " (disabled)")
    elif change.kind == "removed":
        detail = f"was {entry.value}"
    else:
        detail = "; ".join(change.parts()) or "changed"
    return WORDS[change.kind], what, detail


class StartupPanel(tb.Frame):
    """`store_factory` builds the store, `collect` gathers the entries (the
    real collectors by default; a test passes its own), `trusted` answers
    for a target's signature when the window has a checker, `on_report` is
    told about every finished snapshot so the window can decide on a banner."""

    def __init__(self, parent, *, store_factory: Callable[[], autoruns.AutorunsStore],
                 events: EventStore, post: Callable[..., None],
                 collect: Callable[[], autoruns.Collected] = autoruns.collect,
                 trusted: Callable[[str], bool] | None = None,
                 on_report: Callable[[autoruns.SnapshotReport], None] | None = None,
                 system_root: str | None = None, **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._store_factory = store_factory
        self._events = events
        self._post = post
        self._collect = collect
        self._trusted = trusted
        self._on_report = on_report
        self._system_root = system_root
        self._thread: threading.Thread | None = None
        self._changes: list[autoruns.Change] = []
        self.last_report: autoruns.SnapshotReport | None = None
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
        self.tree = tb.Treeview(wrap, columns=("change", "what", "detail"), show="headings",
                                selectmode="browse", height=5)
        self.tree.heading("change", text="Change")
        self.tree.heading("what", text="Startup item")
        self.tree.heading("detail", text="Detail")
        self.tree.column("change", width=70, anchor="w", stretch=False)
        self.tree.column("what", width=170, anchor="w")
        self.tree.column("detail", width=140, anchor="w")
        for kind, colour in KIND_COLOURS.items():
            self.tree.tag_configure(kind, foreground=colour)
        self.tree.tag_configure("quiet", foreground="#8a8f98")
        scroll = tb.Scrollbar(wrap, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=RIGHT, fill=Y)
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)

        self.status_var = tk.StringVar(value="")
        status = tb.Label(self, textvariable=self.status_var, bootstyle="secondary",
                          wraplength=WRAP, justify="left", anchor="w")
        status.pack(fill=X, pady=(6, 0))
        self._wrapped.append(status)
        self.progress = tb.Progressbar(self, orient=HORIZONTAL, mode="indeterminate", bootstyle="info")
        self.progress.pack(fill=X, pady=(6, 0))

        buttons = tb.Frame(self, padding=(0, 8))
        buttons.pack(fill=X)
        self.snapshot_btn = tb.Button(buttons, text="Snapshot now", bootstyle="info",
                                      command=self.snapshot)
        self.snapshot_btn.pack(side=LEFT, expand=True, fill=X, padx=2)
        note = tb.Label(self, bootstyle="secondary", wraplength=WRAP, justify="left",
                        text=("Run keys, the Startup folders, scheduled tasks and services, read as "
                              "they are and compared with the previous snapshot. Nothing is moved or "
                              "changed. A change under the Windows folder is listed in grey and "
                              "recorded, not announced, unless the program's signature fails: that "
                              "is what an update looks like."))
        note.pack(anchor="w", padx=2, pady=(4, 0))
        self._wrapped.append(note)
        self.bind("<Configure>", self._reflow)

    def _reflow(self, event) -> None:
        width = max(WRAP, event.width - 12)
        for label in self._wrapped:
            label.configure(wraplength=width)

    # ------------------------------------------------------------- state

    def refresh(self) -> None:
        """Re-read the store: the summary line and the last diff. GUI thread only."""
        store = self._store_factory()
        ok, text = autoruns.summarize(store)
        self.summary_var.set(text)
        self.summary.configure(bootstyle="secondary" if ok else "danger")
        self._show_changes(store.last_changes())

    @property
    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def changes(self) -> list[autoruns.Change]:
        return list(self._changes)

    def judge(self, changes: list[autoruns.Change]) -> list[autoruns.Change]:
        """The changes worth a banner, asked with the checker: worker only,
        at the checker's price per file."""
        return [c for c in changes if c.worth_a_look(self._system_root, self._trusted)]

    def _show_changes(self, changes: list[autoruns.Change],
                      loud: list[autoruns.Change] | None = None) -> None:
        """`loud` is what a worker judged worth a banner; without it the
        system-root rule alone decides the grey, which is cheap enough for
        this thread. A removal is never announced and still gets its own
        colour: grey means "under the Windows folder", and a gone entry
        from the profile was not."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._changes = list(changes)
        loud_ids = {id(c) for c in loud} if loud is not None else None
        for index, change in enumerate(self._changes):
            if change.kind == "removed":
                quiet = False
            elif loud_ids is not None:
                quiet = id(change) not in loud_ids
            else:
                quiet = not change.worth_a_look(self._system_root)
            tags = ("quiet",) if quiet else (change.kind,)
            self.tree.insert("", END, iid=str(index), values=row_for(change), tags=tags)

    def _set_busy(self, busy: bool) -> None:
        self.snapshot_btn.config(state=DISABLED if busy else NORMAL)
        if busy:
            self.progress.start(80)
        else:
            self.progress.stop()

    # ---------------------------------------------------------- snapshot

    def snapshot(self) -> bool:
        if self.busy:
            Messagebox.show_info("A snapshot is already being taken.", "AVGuard",
                                 parent=self.winfo_toplevel())
            return False
        self._set_busy(True)
        self.status_var.set("Reading what starts with Windows...")
        store = self._store_factory()

        def work() -> None:
            try:
                started = time.monotonic()
                collected = self._collect()
                report = store.snapshot(collected, events=self._events)
                report.loud = self.judge(report.changes)
                self._post(self._finished, report, time.monotonic() - started)
            except Exception:
                log.exception("the startup snapshot failed")
                self._post(self._failed)
        self._thread = threading.Thread(target=work, name="avguard-autoruns", daemon=True)
        self._thread.start()
        return True

    def _finished(self, report: autoruns.SnapshotReport, seconds: float) -> None:
        self._set_busy(False)
        self.last_report = report
        store = self._store_factory()
        ok, text = autoruns.summarize(store)
        self.summary_var.set(text)
        self.summary.configure(bootstyle="secondary" if ok else "danger")
        if report.snapshot is not None:
            self._show_changes(report.changes, report.loud)
        else:
            self._show_changes(store.last_changes())
        for note in report.errors:
            log.warning("startup snapshot: %s", note)
        self.status_var.set(autoruns.describe_report(report) + f" ({seconds:.1f}s)")
        if self._on_report is not None:
            self._on_report(report)

    def _failed(self) -> None:
        self._set_busy(False)
        self.status_var.set("That did not finish; the log says why.")

    def stop(self, timeout: float = 5.0) -> None:
        """At shutdown: a snapshot cannot be interrupted, only waited for."""
        if self.busy:
            self._thread.join(timeout=timeout)
