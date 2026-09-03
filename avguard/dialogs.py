"""Settings, history and health windows.

Kept out of gui.py so that file stays about the main window and the thread
bridge. Everything here runs on the GUI thread; nothing in this module starts a
thread or touches the filesystem outside config and the event store.
"""

from __future__ import annotations

import logging
from pathlib import Path
from tkinter import filedialog

import tkinter as tk
import ttkbootstrap as tb
from ttkbootstrap.constants import BOTH, END, LEFT, RIGHT, VERTICAL, X, Y
from ttkbootstrap.dialogs import Messagebox

from . import allowlist as allowlist_module, config, rulepacks, scheduling

log = logging.getLogger("avguard.dialogs")

CHR_NL = chr(10)


class SettingsDialog(tb.Toplevel):
    """Edit the settings worth editing.

    Not every field in `Config` is here. Things a wrong value would break
    quietly -- `quarantine_threshold`, `cloud_extensions` -- stay in the JSON
    file, where changing them is a deliberate act.
    """

    def __init__(self, parent, cfg: config.Config, on_saved,
                 pack_store=None, on_packs_changed=None,
                 allowlist=None, on_allowlist_changed=None) -> None:
        super().__init__(title="Settings", transient=parent, resizable=(False, False))
        self.cfg = cfg
        self._on_saved = on_saved
        self._on_packs_changed = on_packs_changed
        self._on_allowlist_changed = on_allowlist_changed

        body = tb.Frame(self, padding=18)
        body.pack(fill=BOTH, expand=True)

        tb.Label(body, text="Settings", font=("Segoe UI", 14, "bold")).pack(anchor="w")

        # --- protection ---------------------------------------------------
        block = tb.Labelframe(body, text="Protection", padding=12)
        block.pack(fill=X, pady=(12, 8))

        self.auto_var = tk.BooleanVar(value=cfg.auto_quarantine)
        tb.Checkbutton(block, text="Move detected files into quarantine automatically",
                       variable=self.auto_var, bootstyle="round-toggle").pack(anchor="w", pady=2)
        tb.Label(block, bootstyle="secondary", wraplength=520, justify="left",
                 text=("When this is off, detections are reported and nothing is "
                       "moved. Only strong evidence can trigger a move either "
                       "way; guesses never do.")).pack(anchor="w", pady=(0, 8))

        self.archives_var = tk.BooleanVar(value=cfg.archive_scanning_enabled)
        tb.Checkbutton(block, text="Look inside .zip files",
                       variable=self.archives_var, bootstyle="round-toggle").pack(anchor="w", pady=2)

        self.pe_var = tk.BooleanVar(value=cfg.pe_analysis_enabled)
        tb.Checkbutton(block, text="Check the structure of executables",
                       variable=self.pe_var, bootstyle="round-toggle").pack(anchor="w", pady=2)

        # --- watched folders ----------------------------------------------
        watch = tb.Labelframe(body, text="Folders watched in real time", padding=12)
        watch.pack(fill=X, pady=8)

        self.watch_list = tk.Listbox(watch, height=4, bg="#12161c", fg="#cfd8dc",
                                     relief="flat", highlightthickness=0)
        self.watch_list.pack(fill=X)
        for entry in cfg.watch_paths or [str(Path.home() / "Downloads")]:
            self.watch_list.insert(END, entry)

        row = tb.Frame(watch, padding=(0, 6, 0, 0))
        row.pack(fill=X)
        tb.Button(row, text="Add folder", bootstyle="secondary-outline",
                  command=self._add_watch).pack(side=LEFT, padx=(0, 4))
        tb.Button(row, text="Remove", bootstyle="secondary-outline",
                  command=lambda: self._remove(self.watch_list)).pack(side=LEFT)
        tb.Label(watch, bootstyle="secondary", wraplength=520, justify="left",
                 text="Empty means Downloads only.").pack(anchor="w", pady=(6, 0))

        # --- exclusions ----------------------------------------------------
        excl = tb.Labelframe(body, text="Never scanned", padding=12)
        excl.pack(fill=X, pady=8)

        self.excl_list = tk.Listbox(excl, height=5, bg="#12161c", fg="#cfd8dc",
                                    relief="flat", highlightthickness=0)
        self.excl_list.pack(fill=X)
        for pattern in cfg.excluded_globs:
            self.excl_list.insert(END, pattern)

        row = tb.Frame(excl, padding=(0, 6, 0, 0))
        row.pack(fill=X)
        tb.Button(row, text="Exclude a folder", bootstyle="secondary-outline",
                  command=self._add_exclusion).pack(side=LEFT, padx=(0, 4))
        tb.Button(row, text="Remove", bootstyle="secondary-outline",
                  command=lambda: self._remove(self.excl_list)).pack(side=LEFT)

        # --- startup and schedule -------------------------------------------
        auto = tb.Labelframe(body, text="Running by itself", padding=12)
        auto.pack(fill=X, pady=8)

        state = scheduling.status()
        self.startup_var = tk.BooleanVar(value=state.starts_with_windows)
        tb.Checkbutton(auto, text="Start AVGuard when Windows starts",
                       variable=self.startup_var,
                       bootstyle="round-toggle").pack(anchor="w", pady=2)

        self.daily_var = tk.BooleanVar(value=state.scheduled_scan)
        tb.Checkbutton(auto, text="Scan the watched folders once a day",
                       variable=self.daily_var,
                       bootstyle="round-toggle").pack(anchor="w", pady=2)
        tb.Label(auto, bootstyle="secondary", wraplength=520, justify="left",
                 text=("Neither needs administrator rights. The daily scan only "
                       "reports -- an unattended scan with nobody reading the "
                       "result is the last thing that should be moving files. "
                       "You can remove both from Task Manager's Startup tab and "
                       "Task Scheduler without opening AVGuard.")
                 ).pack(anchor="w", pady=(6, 0))

        # --- rule packs ------------------------------------------------------
        packs_frame = tb.Labelframe(body, text="Rule packs", padding=12)
        packs_frame.pack(fill=X, pady=8)

        # Handed the scanner's store, not a second one. A private copy
        # wrote trust changes to disk that the running scanner never saw.
        self.pack_store = pack_store if pack_store is not None else rulepacks.PackStore()
        self.pack_list = tk.Listbox(packs_frame, height=3, bg="#12161c", fg="#cfd8dc",
                                    relief="flat", highlightthickness=0)
        self.pack_list.pack(fill=X)
        self._refresh_packs()

        row = tb.Frame(packs_frame, padding=(0, 6, 0, 0))
        row.pack(fill=X)
        tb.Button(row, text="Trust", bootstyle="warning-outline",
                  command=lambda: self._set_pack_trust(True)).pack(side=LEFT, padx=(0, 4))
        tb.Button(row, text="Report only", bootstyle="secondary-outline",
                  command=lambda: self._set_pack_trust(False)).pack(side=LEFT, padx=(0, 4))
        tb.Button(row, text="Remove", bootstyle="danger-outline",
                  command=self._remove_pack).pack(side=LEFT)
        tb.Label(packs_frame, bootstyle="secondary", wraplength=520, justify="left",
                 text=("A pack reports only until you trust it: until then nothing "
                       "it finds is moved, whatever severity its rules claim. Add "
                       "one from a terminal, which is where the measurement "
                       "against your own files happens:" + CHR_NL
                       + "    python -m avguard --packs add <folder> --licence MIT")
                 ).pack(anchor="w", pady=(6, 0))

        # --- files the user chose to keep -----------------------------------
        # A restore is a permanent, machine-wide exception for those exact
        # bytes. Until this frame existed it could not be seen or undone: the
        # allowlist's entries() and remove() had no caller outside the tests.
        keep_frame = tb.Labelframe(body, text="Files you chose to keep", padding=12)
        keep_frame.pack(fill=X, pady=8)
        # The scanner's allowlist, for the same reason as the pack store.
        self.allowlist = (allowlist if allowlist is not None
                          else allowlist_module.Allowlist())
        self.keep_list = tk.Listbox(keep_frame, height=3, bg="#12161c", fg="#cfd8dc",
                                    relief="flat", highlightthickness=0)
        self.keep_list.pack(fill=X)
        self._refresh_allowlist()
        row = tb.Frame(keep_frame, padding=(0, 6, 0, 0))
        row.pack(fill=X)
        tb.Button(row, text="Stop keeping", bootstyle="danger-outline",
                  command=self._stop_keeping).pack(side=LEFT)
        tb.Label(keep_frame, bootstyle="secondary", wraplength=520, justify="left",
                 text=("Restoring a file from quarantine records a decision about "
                       "those exact bytes: they are not flagged again, anywhere on "
                       "this PC, until the entry is removed here. Editing the file "
                       "changes its bytes and ends the exception by itself.")
                 ).pack(anchor="w", pady=(6, 0))

        # --- buttons -------------------------------------------------------
        actions = tb.Frame(body, padding=(0, 14, 0, 0))
        actions.pack(fill=X)
        tb.Button(actions, text="Save", bootstyle="success",
                  command=self._save).pack(side=RIGHT, padx=(6, 0))
        tb.Button(actions, text="Cancel", bootstyle="secondary-outline",
                  command=self.destroy).pack(side=RIGHT)

    def _refresh_packs(self) -> None:
        self.pack_list.delete(0, END)
        packs = self.pack_store.packs()
        if not packs:
            self.pack_list.insert(END, "  (none installed)")
            return
        for pack in packs:
            state = "trusted, can move files" if pack.trusted else "reports only"
            self.pack_list.insert(
                END, f"{pack.name}  -  {pack.rule_count:,} rules, {state}")

    def _selected_pack(self):
        selection = self.pack_list.curselection()
        packs = self.pack_store.packs()
        if not selection or not packs:
            Messagebox.show_info("Select a rule pack first.", "AVGuard", parent=self)
            return None
        index = selection[0]
        return packs[index] if index < len(packs) else None

    def _set_pack_trust(self, trusted: bool) -> None:
        pack = self._selected_pack()
        if pack is None:
            return
        if trusted:
            answer = Messagebox.yesno(
                f"Let {pack.name} move files?" + CHR_NL + CHR_NL
                + f"It contains {pack.rule_count:,} rules written by somebody else. "
                  "When it was added, it flagged "
                  f"{pack.false_positive_rate:.2%} of {pack.corpus_size} clean "
                  "files on this machine." + CHR_NL + CHR_NL
                + "Until now its detections have only been reported.",
                "Trust this pack?", parent=self)
            if answer != "Yes":
                return
        try:
            self.pack_store.set_trusted(pack.name, trusted)
            if self._on_packs_changed:
                self._on_packs_changed()
        except rulepacks.PackError as exc:
            Messagebox.show_error(str(exc), "AVGuard", parent=self)
            return
        self._refresh_packs()

    def _remove_pack(self) -> None:
        pack = self._selected_pack()
        if pack is None:
            return
        if Messagebox.yesno(
                f"Remove {pack.name} and its {pack.rule_count:,} rules?",
                "Remove this pack?", parent=self) != "Yes":
            return
        self.pack_store.remove(pack.name)
        if self._on_packs_changed:
            self._on_packs_changed()
        self._refresh_packs()

    def _refresh_allowlist(self) -> None:
        self.keep_list.delete(0, END)
        self.allowlist.reload()
        entries = self.allowlist.entries()
        if not entries:
            self.keep_list.insert(END, "  (none - nothing has been restored)")
            return
        for entry in entries:
            flagged = "; ".join(entry.was_flagged_for)[:60] or "no reason recorded"
            self.keep_list.insert(
                END, f"{entry.name or entry.sha256[:12]}  -  kept {entry.when}, "
                     f"was flagged for: {flagged}")

    def _stop_keeping(self) -> None:
        selection = self.keep_list.curselection()
        entries = self.allowlist.entries()
        if not selection or not entries or selection[0] >= len(entries):
            Messagebox.show_info("Select a kept file first.", "AVGuard", parent=self)
            return
        entry = entries[selection[0]]
        if Messagebox.yesno(
                f"Stop keeping '{entry.name or entry.sha256[:12]}'?" + CHR_NL + CHR_NL
                + "If a file with these exact bytes is found again it will be "
                  "flagged, and moved if the evidence is hard enough.",
                "Remove this exception?", parent=self) != "Yes":
            return
        self.allowlist.remove(entry.sha256)
        if self._on_allowlist_changed:
            self._on_allowlist_changed()
        self._refresh_allowlist()

    def _add_watch(self) -> None:
        chosen = filedialog.askdirectory(title="Watch this folder", parent=self)
        if chosen:
            self.watch_list.insert(END, chosen)

    def _add_exclusion(self) -> None:
        chosen = filedialog.askdirectory(title="Never scan this folder", parent=self)
        if chosen:
            self.excl_list.insert(END, glob_for(chosen))

    @staticmethod
    def _remove(listbox: tk.Listbox) -> None:
        for index in reversed(listbox.curselection()):
            listbox.delete(index)

    def _apply_scheduling(self) -> list[str]:
        """Only touch the system when the toggle actually changed."""
        problems: list[str] = []
        state = scheduling.status()

        if self.startup_var.get() != state.starts_with_windows:
            if self.startup_var.get():
                ok, detail = scheduling.enable_start_with_windows()
            else:
                ok, detail = scheduling.disable_start_with_windows()
            if not ok:
                problems.append(f"start with Windows: {detail}")

        if self.daily_var.get() != state.scheduled_scan:
            if self.daily_var.get():
                targets = self.cfg.watch_paths or [str(Path.home() / "Downloads")]
                ok, detail = scheduling.enable_scheduled_scan(Path(targets[0]))
            else:
                ok, detail = scheduling.disable_scheduled_scan()
            if not ok:
                problems.append(f"daily scan: {detail}")
        return problems

    def _save(self) -> None:
        self.cfg.auto_quarantine = self.auto_var.get()
        self.cfg.archive_scanning_enabled = self.archives_var.get()
        self.cfg.pe_analysis_enabled = self.pe_var.get()
        self.cfg.watch_paths = list(self.watch_list.get(0, END))
        self.cfg.excluded_globs = list(self.excl_list.get(0, END))
        try:
            self.cfg.save()
        except OSError as exc:
            Messagebox.show_error(f"Could not save settings: {exc}", "AVGuard", parent=self)
            return

        problems = self._apply_scheduling()
        if problems:
            Messagebox.show_warning(
                "Settings were saved, but some of it could not be applied:" + CHR_NL + CHR_NL
                + CHR_NL.join(problems),
                "Partly applied", parent=self)
        self.destroy()
        self._on_saved()


def glob_for(folder: str | Path) -> str:
    """The exclusion pattern for a folder, in the form the matcher expects."""
    return str(folder).replace("\\", "/").rstrip("/") + "/**"


class HistoryDialog(tb.Toplevel):
    """What the scanner has done, beyond what the log widget still holds."""

    def __init__(self, parent, store, on_cleared) -> None:
        super().__init__(title="History", transient=parent)
        self.store = store
        self._on_cleared = on_cleared
        self.geometry("900x520")

        body = tb.Frame(self, padding=14)
        body.pack(fill=BOTH, expand=True)

        summary = store.summary()
        tb.Label(body, text="History", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tb.Label(body, bootstyle="secondary", text=(
            f"{summary['events']} events kept  |  {summary['detections']} detections  |  "
            f"{summary['quarantined']} quarantined  |  last scan: {summary['last_scan']}"
        )).pack(anchor="w", pady=(2, 10))

        self.tree = tb.Treeview(body, columns=("when", "kind", "level", "detail"),
                                show="headings", selectmode="browse")
        for column, heading, width in (
            ("when", "When", 150), ("kind", "Event", 110),
            ("level", "Verdict", 100), ("detail", "File", 460),
        ):
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, anchor="w")
        scroll = tb.Scrollbar(body, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=RIGHT, fill=Y)
        self.tree.pack(fill=BOTH, expand=True)

        for event in store.read(limit=1000):
            self.tree.insert("", END, values=(
                event.when, event.kind, event.level or "-",
                event.path or "; ".join(event.reasons)[:120]))

        actions = tb.Frame(body, padding=(0, 12, 0, 0))
        actions.pack(fill=X)
        tb.Label(actions, bootstyle="secondary", wraplength=560, justify="left",
                 text=("This history and the scan cache both record file paths "
                       "from this machine. Clearing removes them.")
                 ).pack(side=LEFT, fill=X, expand=True)
        tb.Button(actions, text="Clear history", bootstyle="danger-outline",
                  command=self._clear).pack(side=RIGHT)

    def _clear(self) -> None:
        if Messagebox.yesno("Delete the recorded history from this machine?",
                            "Clear history", parent=self) != "Yes":
            return
        self.store.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._on_cleared()


class HealthDialog(tb.Toplevel):
    """Answers "is it actually working?".

    v1 ran for weeks with YARA switched off after a compile failure, reporting
    nothing wrong. Every row here is a thing that can silently stop working.
    """

    def __init__(self, parent, checks: list[tuple[str, bool, str]],
                 on_reload_rules=None) -> None:
        super().__init__(title="Health", transient=parent, resizable=(False, False))

        body = tb.Frame(self, padding=18)
        body.pack(fill=BOTH, expand=True)
        tb.Label(body, text="Health", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tb.Label(body, bootstyle="secondary", wraplength=540, justify="left",
                 text="Everything below can fail quietly. This is where it stops being quiet."
                 ).pack(anchor="w", pady=(2, 12))

        for label, ok, detail in checks:
            row = tb.Frame(body)
            row.pack(fill=X, pady=3)
            tb.Label(row, text="OK" if ok else "FAILED", width=8,
                     bootstyle="success" if ok else "danger").pack(side=LEFT)
            tb.Label(row, text=label, width=26, anchor="w").pack(side=LEFT)
            tb.Label(row, text=detail, bootstyle="secondary", anchor="w",
                     wraplength=340, justify="left").pack(side=LEFT, fill=X, expand=True)

        actions = tb.Frame(body, padding=(0, 14, 0, 0))
        actions.pack(fill=X)
        if on_reload_rules is not None:
            # Lives here because this is where you come when detection looks
            # wrong. Editing a rule file and pressing this beats restarting.
            tb.Button(actions, text="Reload rules from disk",
                      bootstyle="info-outline",
                      command=lambda: (on_reload_rules(), self.destroy())
                      ).pack(side=LEFT)
        tb.Button(actions, text="Close", bootstyle="secondary",
                  command=self.destroy).pack(side=RIGHT)
