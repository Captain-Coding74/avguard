"""The Tkinter front end.

The rule this file exists to enforce: Tk widgets are touched only from the
thread that created them. Scans, watchdog callbacks and worker threads never
call a widget directly. They put a callable on `_ui_queue`, and `_pump` -- which
runs on the GUI thread via `after` -- drains it.

The original build called status_label.config, progress_bar.start and a modal
Messagebox straight from worker threads, which on Windows shows up as the
window freezing or the dialog never appearing.
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

import ttkbootstrap as tb
from ttkbootstrap.constants import (
    BOTH, DISABLED, END, HORIZONTAL, LEFT, NORMAL, RIGHT, VERTICAL, X, Y
)
from ttkbootstrap.dialogs import Messagebox

from . import config, dialogs, logsetup, scheduling
from .events import Event, EventStore
from .cloud import VirusTotalClient
from .instance import InstanceLock
from .protection import SelfProtection
from .quarantine import QuarantineError, QuarantineStore
from .scanner import Level, ScanCache, Scanner, Verdict
from .watcher import RealtimeMonitor

log = logging.getLogger("avguard.gui")

MAX_LOG_LINES = 2000
UI_TICK_MS = 100
MAX_DRAIN_PER_TICK = 200

# How often to prove real-time protection is still working. A watched folder
# being deleted and recreated kills watchdog's emitter silently, and the old
# status check could not see it.
HEALTH_TICK_MS = 30_000

LEVEL_TAGS = {
    logging.ERROR: ("error", "#ff6b6b"),
    logging.WARNING: ("threat", "#ffd166"),
    logging.INFO: ("info", "#cfd8dc"),
    logging.DEBUG: ("debug", "#78909c"),
}


class AVGuardApp(tb.Window):
    def __init__(self) -> None:
        super().__init__(themename="darkly")
        self.title("AVGuard")
        self.geometry("1100x720")
        self.minsize(900, 560)

        config.ensure_directories()

        # Logging is configured first so that everything built below -- in
        # particular the YARA compile, which can fail -- reports into the GUI
        # log rather than into a handler that does not exist yet.
        self._log_queue: queue.Queue = queue.Queue(maxsize=5000)
        self._ui_queue: queue.Queue = queue.Queue()
        logsetup.configure(self._log_queue)

        self.cfg = config.Config.load()
        self.protection = SelfProtection()
        self.events = EventStore()

        self.cloud = VirusTotalClient(self.cfg)
        # The Scanner is built FIRST and owns the shared state. The quarantine
        # store and the settings dialog are handed its objects rather than
        # constructing their own. Two Allowlists over one file meant a restore
        # was recorded in one and read from the other, so a restored file was
        # re-detected on the very next scan -- the exact failure the allowlist
        # exists to prevent. Two PackStores meant a trust change in Settings
        # never reached the running scanner.
        self.scanner = Scanner(
            self.cfg,
            self.protection,
            cloud_lookup=self.cloud.reasons_for,
        )
        self.quarantine = QuarantineStore(protection=self.protection,
                                          allowlist=self.scanner.allowlist)
        # Adopt the Scanner's cache rather than handing it one. Building a
        # ScanCache here meant it had no generation, and a cache with no
        # generation accepted verdicts written under any ruleset for the full
        # 30-day TTL -- then wrote the empty generation back, destroying the
        # CLI's cache on its next run. The two entry points were erasing each
        # other's work on every alternation.
        self.cache = self.scanner.cache

        self.monitor = RealtimeMonitor(
            self.scanner,
            self.protection,
            on_verdict=self._on_verdict,
            workers=self.cfg.worker_threads,
            debounce_seconds=self.cfg.debounce_seconds,
        )

        # One writer at a time. A second AVGuard sharing data/ would rewrite
        # the quarantine index from its own stale snapshot.
        self.lock = InstanceLock()
        self.has_lock = self.lock.acquire()

        self._shutting_down = False
        self._scan_thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._threats_this_scan = 0

        self._build_widgets()
        self._build_tray()
        self.protocol("WM_DELETE_WINDOW", self._hide)

        self.after(UI_TICK_MS, self._pump)
        self.after(HEALTH_TICK_MS, self._check_realtime_health)
        self._refresh_quarantine()

        if not self.scanner.rules:
            self._banner(
                "YARA rules failed to load - detection is reduced. See the log.",
                "inverse-danger",
            )
        if not self.has_lock:
            self._banner(
                f"Another AVGuard is already running (pid {self.lock.owner_pid or 0}). "
                "This window will scan and report, but will not move any files.",
                "inverse-warning",
            )
            self.cfg.auto_quarantine = False

        if not self.cfg.onboarding_completed:
            self.after(300, self._ask_first_run)
        elif self.cfg.realtime_enabled:
            self._start_realtime()

    # ------------------------------------------------------------- widgets

    def _build_widgets(self) -> None:
        outer = tb.Frame(self, padding=12)
        outer.pack(fill=BOTH, expand=True)

        header = tb.Frame(outer)
        header.pack(fill=X, pady=(0, 10))

        tb.Label(header, text="AVGuard", font=("Segoe UI", 18, "bold")).pack(side=LEFT)

        self.status_var = tk.StringVar(value="Idle")
        tb.Label(header, textvariable=self.status_var, bootstyle="secondary").pack(side=LEFT, padx=16)

        self.realtime_var = tk.BooleanVar(value=self.cfg.realtime_enabled)
        tb.Checkbutton(
            header, text="Real-time protection", variable=self.realtime_var,
            bootstyle="round-toggle", command=self._toggle_realtime,
        ).pack(side=RIGHT, padx=6)

        self.cloud_var = tk.BooleanVar(value=self.cfg.cloud_enabled)
        tb.Checkbutton(
            header, text="VirusTotal lookups", variable=self.cloud_var,
            bootstyle="round-toggle", command=self._toggle_cloud,
        ).pack(side=RIGHT, padx=6)

        self.banner_var = tk.StringVar(value="")
        self.banner = tb.Label(outer, textvariable=self.banner_var, bootstyle="inverse-secondary",
                               padding=8, anchor="w")

        panes = tb.PanedWindow(outer, orient=HORIZONTAL)
        panes.pack(fill=BOTH, expand=True)
        self._panes = panes

        # --- log ---------------------------------------------------------
        left = tb.Frame(panes, padding=(0, 0, 8, 0))
        panes.add(left, weight=3)
        tb.Label(left, text="Activity", font=("Segoe UI", 11, "bold")).pack(fill=X, pady=(0, 4))

        log_wrap = tb.Frame(left)
        log_wrap.pack(fill=BOTH, expand=True)
        self.log_text = tk.Text(
            log_wrap, state=DISABLED, wrap="word", relief="flat",
            bg="#12161c", fg="#cfd8dc", insertbackground="#cfd8dc",
            font=("Cascadia Mono", 9), padx=8, pady=6,
        )
        scroll = tb.Scrollbar(log_wrap, orient=VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side=RIGHT, fill=Y)
        self.log_text.pack(side=LEFT, fill=BOTH, expand=True)
        for tag, colour in LEVEL_TAGS.values():
            self.log_text.tag_configure(tag, foreground=colour)

        # --- quarantine --------------------------------------------------
        right = tb.Frame(panes, padding=(8, 0, 0, 0))
        panes.add(right, weight=2)
        tb.Label(right, text="Quarantine", font=("Segoe UI", 11, "bold")).pack(fill=X, pady=(0, 4))

        self.tree = tb.Treeview(
            right, columns=("detected", "when"), show="tree headings", selectmode="browse",
        )
        self.tree.heading("#0", text="File")
        self.tree.heading("detected", text="Detected as")
        self.tree.heading("when", text="Quarantined")
        self.tree.column("#0", width=190, anchor="w")
        self.tree.column("detected", width=190, anchor="w")
        self.tree.column("when", width=130, anchor="w")
        self.tree.pack(fill=BOTH, expand=True)

        qbtns = tb.Frame(right, padding=(0, 8))
        qbtns.pack(fill=X)
        tb.Button(qbtns, text="Restore", bootstyle="success-outline",
                  command=self._restore_selected).pack(side=LEFT, expand=True, fill=X, padx=2)
        tb.Button(qbtns, text="Export copy", bootstyle="secondary-outline",
                  command=self._export_selected).pack(side=LEFT, expand=True, fill=X, padx=2)
        tb.Button(qbtns, text="Delete", bootstyle="danger-outline",
                  command=self._delete_selected).pack(side=LEFT, expand=True, fill=X, padx=2)

        tb.Button(right, text="Export everything...", bootstyle="secondary-outline",
                  command=self._export_all).pack(fill=X, pady=(0, 4))

        # --- controls ----------------------------------------------------
        controls = tb.Frame(outer, padding=(0, 10, 0, 0))
        controls.pack(fill=X)

        self.scan_folder_btn = tb.Button(controls, text="Scan a folder...", bootstyle="info",
                                         command=self._scan_folder)
        self.scan_folder_btn.pack(side=LEFT, expand=True, fill=X, padx=(0, 4))

        self.scan_file_btn = tb.Button(controls, text="Scan a file...", bootstyle="primary",
                                       command=self._scan_file)
        self.scan_file_btn.pack(side=LEFT, expand=True, fill=X, padx=4)

        self.cancel_btn = tb.Button(controls, text="Cancel", bootstyle="warning-outline",
                                    command=self._cancel_scan, state=DISABLED)
        self.cancel_btn.pack(side=LEFT, expand=True, fill=X, padx=4)

        tb.Button(controls, text="History", bootstyle="secondary-outline",
                  command=self._show_history).pack(side=LEFT, expand=True, fill=X, padx=4)

        tb.Button(controls, text="Health", bootstyle="secondary-outline",
                  command=self._show_health).pack(side=LEFT, expand=True, fill=X, padx=4)

        tb.Button(controls, text="Settings", bootstyle="secondary-outline",
                  command=self._show_settings).pack(side=LEFT, expand=True, fill=X, padx=(4, 0))

        self.progress = tb.Progressbar(outer, orient=HORIZONTAL, mode="determinate", bootstyle="info")
        self.progress.pack(fill=X, pady=(10, 0))

    def _build_tray(self) -> None:
        """The tray icon is optional; a failure here must not stop the app."""
        self.tray = None
        try:
            import pystray
            from PIL import Image, ImageDraw

            image = Image.new("RGB", (64, 64), "#12161c")
            draw = ImageDraw.Draw(image)
            draw.ellipse((10, 10, 54, 54), fill="#2ecc71")
            draw.text((26, 22), "A", fill="#12161c")

            self.tray = pystray.Icon(
                "avguard", image, "AVGuard",
                menu=pystray.Menu(
                    pystray.MenuItem("Show", lambda *_: self.post(self._show), default=True),
                    pystray.MenuItem("Hide", lambda *_: self.post(self._hide)),
                    pystray.MenuItem("Quit", lambda *_: self.post(self.shutdown)),
                ),
            )
            threading.Thread(target=self.tray.run, name="avguard-tray", daemon=True).start()
        except Exception as exc:
            log.warning("system tray unavailable: %s", exc)

    # ------------------------------------------------------- thread bridge

    def post(self, fn, *args) -> None:
        """Ask the GUI thread to run `fn`. Safe to call from any thread."""
        self._ui_queue.put((fn, args))

    def _pump(self) -> None:
        """Drain both queues on the GUI thread, a bounded amount per tick."""
        for _ in range(MAX_DRAIN_PER_TICK):
            try:
                fn, args = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception:
                log.exception("UI callback failed")

        try:
            lines = []
            for _ in range(MAX_DRAIN_PER_TICK):
                try:
                    lines.append(self._log_queue.get_nowait())
                except queue.Empty:
                    break
            if lines:
                self._append_log(lines)
        except Exception:
            log.exception("could not render log lines")
        finally:
            # Rescheduled from `finally` so the pump cannot die. If this call
            # is ever skipped, the queues stop draining forever: workers keep
            # detecting, nothing is quarantined, and the window still looks
            # alive. That is exactly how v1 failed, and it must not be
            # reachable from a formatting error in a log line.
            if not self._shutting_down:
                self.after(UI_TICK_MS, self._pump)

    def _append_log(self, lines: list[tuple[int, str]]) -> None:
        self.log_text.config(state=NORMAL)
        for levelno, message in lines:
            tag = LEVEL_TAGS.get(levelno, LEVEL_TAGS[logging.INFO])[0]
            self.log_text.insert(END, message + "\n", tag)

        # Keep the widget bounded. The old build inserted forever, so a long
        # session grew the Text widget without limit.
        excess = int(self.log_text.index("end-1c").split(".")[0]) - MAX_LOG_LINES
        if excess > 0:
            self.log_text.delete("1.0", f"{excess + 1}.0")

        self.log_text.see(END)
        self.log_text.config(state=DISABLED)

    def _banner(self, text: str, style: str = "inverse-warning") -> None:
        """Show a one-line notice above the panes, replacing any previous one."""
        self.banner_var.set(text)
        self.banner.configure(bootstyle=style)
        self.banner.pack(fill=X, pady=(0, 8), before=self._panes)

    # ----------------------------------------------------------- first run

    def _ask_first_run(self) -> None:
        """Ask before anything is ever moved.

        The previous default was to start real-time protection and quarantine
        automatically, having told the user neither. On a developer machine
        that moved ordinary build scripts. Runs on the GUI thread, before any
        worker thread starts.
        """
        targets = self._watch_targets()
        where = "\n".join(f"    {p}" for p in targets) or "    (no folder found to watch)"

        window = tb.Toplevel(title="Welcome to AVGuard")
        window.transient(self)
        window.grab_set()
        window.resizable(False, False)

        body = tb.Frame(window, padding=20)
        body.pack(fill=BOTH, expand=True)

        tb.Label(body, text="Before AVGuard starts",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tb.Label(
            body, justify="left", wraplength=520,
            text=(
                "AVGuard will watch this folder for new files:\n\n"
                f"{where}\n\n"
                "When it finds something it is confident about, it can move "
                "the file into its quarantine at\n"
                f"    {config.QUARANTINE_DIR}\n\n"
                "Quarantined files are kept, not deleted, and you can put "
                "them back from the Quarantine panel. Nothing is sent "
                "anywhere unless you turn on VirusTotal lookups yourself.\n\n"
                "How would you like to start?"
            ),
        ).pack(anchor="w", pady=(10, 16))

        def finish(auto: bool) -> None:
            window.grab_release()
            window.destroy()
            self._apply_first_run(auto)

        buttons = tb.Frame(body)
        buttons.pack(fill=X)
        tb.Button(buttons, text="Watch and tell me", bootstyle="success",
                  command=lambda: finish(False)).pack(side=LEFT, expand=True, fill=X, padx=(0, 6))
        tb.Button(buttons, text="Watch and quarantine automatically", bootstyle="warning",
                  command=lambda: finish(True)).pack(side=LEFT, expand=True, fill=X)

        # Closing the window without choosing is the cautious answer.
        window.protocol("WM_DELETE_WINDOW", lambda: finish(False))

    def _apply_first_run(self, auto_quarantine: bool) -> None:
        self.cfg.auto_quarantine = auto_quarantine and self.has_lock
        self.cfg.onboarding_completed = True
        try:
            self.cfg.save()
        except OSError as exc:
            log.warning("could not save your choice: %s", exc)
        log.info("first run: automatic quarantine is %s",
                 "on" if self.cfg.auto_quarantine else "off (detections will be reported only)")
        if self.cfg.realtime_enabled:
            self._start_realtime()

    # ---------------------------------------------------------- detections

    def _on_verdict(self, verdict: Verdict) -> None:
        """Called on worker threads. Only queues work for the GUI thread."""
        if verdict.level is Level.MALICIOUS:
            log.warning("THREAT %s - %s", verdict.path, "; ".join(verdict.reasons))
            self.post(self._handle_threat, verdict)
        elif verdict.level is Level.SUSPICIOUS:
            log.warning("suspicious %s - %s", verdict.path, "; ".join(verdict.reasons))
            self.events.record(Event(
                kind="suspicious", path=str(verdict.path), level=verdict.level.value,
                score=verdict.score, reasons=list(verdict.reasons)))
        elif verdict.level is Level.ERROR:
            log.error("%s - %s", verdict.path, "; ".join(verdict.reasons))
        else:
            log.debug("%s - %s", verdict.path, verdict.level.value)

    def _handle_threat(self, verdict: Verdict) -> None:
        """Runs on the GUI thread."""
        self._threats_this_scan += 1
        self.events.record(Event(
            kind="detection", path=str(verdict.path), level=verdict.level.value,
            score=verdict.score, reasons=list(verdict.reasons)))

        if not self.cfg.auto_quarantine:
            self._banner(f"Threat found in {verdict.path.name} (not quarantined - "
                         f"automatic quarantine is off)", "inverse-danger")
            return

        try:
            self.quarantine.quarantine(verdict.path, verdict.reasons)
        except QuarantineError as exc:
            log.error("could not quarantine %s: %s", verdict.path, exc)
            self._banner(f"Could not quarantine {verdict.path.name}: {exc}", "inverse-danger")
            return

        self.events.record(Event(
            kind="quarantined", path=str(verdict.path), level=verdict.level.value,
            score=verdict.score, reasons=list(verdict.reasons)))
        self.cache.invalidate(verdict.path)
        self._refresh_quarantine()
        self._banner(f"Quarantined {verdict.path.name} - {'; '.join(verdict.reasons)}",
                     "inverse-danger")
        self._offer_exclusion(verdict.path.parent)

        # A tray notification instead of a modal dialog. During a scan a modal
        # would appear once per detection and block the scan behind it.
        if self.tray is not None:
            try:
                self.tray.notify(f"Quarantined {verdict.path.name}", "AVGuard")
            except Exception:
                pass

    # -------------------------------------------------------------- scans

    def _set_scanning(self, scanning: bool) -> None:
        state = DISABLED if scanning else NORMAL
        self.scan_folder_btn.config(state=state)
        self.scan_file_btn.config(state=state)
        self.cancel_btn.config(state=NORMAL if scanning else DISABLED)

    def _scan_folder(self) -> None:
        chosen = filedialog.askdirectory(title="Choose a folder to scan")
        if chosen:
            self._start_scan(Path(chosen))

    def _scan_file(self) -> None:
        chosen = filedialog.askopenfilename(title="Choose a file to scan")
        if chosen:
            self._start_scan(Path(chosen))

    def _start_scan(self, target: Path) -> None:
        if self._scan_thread is not None and self._scan_thread.is_alive():
            Messagebox.show_info("A scan is already running.", "AVGuard", parent=self)
            return
        self._cancel.clear()
        self._threats_this_scan = 0
        self._set_scanning(True)
        self.status_var.set(f"Scanning {target}")
        self.progress.config(value=0, maximum=100)
        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(target,), name="avguard-fullscan", daemon=True
        )
        self._scan_thread.start()

    def _run_scan(self, target: Path) -> None:
        """Worker thread. Every UI change goes through self.post."""
        try:
            if target.is_file():
                total = 1
            else:
                self.post(self.status_var.set, f"Counting files in {target}...")
                total = max(1, self.scanner.count_files(target))

            self.post(self.progress.config, {"maximum": total, "value": 0})

            done = 0

            def report(verdict: Verdict) -> None:
                nonlocal done
                done += 1
                self._on_verdict(verdict)
                if done % 10 == 0 or done == total:
                    self.post(self.progress.config, {"value": done})
                    self.post(self.status_var.set, f"Scanned {done} of {total}")

            self.scanner.scan_tree(target, on_verdict=report,
                                   should_stop=self._cancel.is_set)
            self.cache.save()
            self.cloud.save_cache()

            cancelled = self._cancel.is_set()
            self.post(self._scan_finished, done, cancelled)
        except Exception:
            log.exception("scan of %s failed", target)
            self.post(self._scan_finished, 0, True)

    def _scan_finished(self, scanned: int, cancelled: bool) -> None:
        self.events.record(Event(
            kind="scan_finished",
            detail={"files": scanned, "threats": self._threats_this_scan,
                    "cancelled": cancelled}))
        self._set_scanning(False)
        self.progress.config(value=0)
        word = "cancelled" if cancelled else "complete"
        self.status_var.set(f"Scan {word} - {scanned} files, {self._threats_this_scan} threat(s)")
        log.info("scan %s: %d file(s) examined, %d threat(s)",
                 word, scanned, self._threats_this_scan)
        if self._threats_this_scan == 0 and not cancelled:
            self._banner(f"Scan complete. {scanned} files checked, nothing found.",
                         "inverse-success")

    def _cancel_scan(self) -> None:
        self._cancel.set()
        self.status_var.set("Cancelling...")

    # ---------------------------------------------------------- real-time

    def _watch_targets(self) -> list[Path]:
        """Downloads only, unless the user names folders in data/config.json.

        Deliberately narrow. Downloads is where files actually arrive from
        outside the machine, and watching Documents by default means any false
        positive moves something the user wrote. Quarantine is reversible here,
        but the cheapest way to not lose someone's work is to not touch it.
        """
        if self.cfg.watch_paths:
            return [Path(p) for p in self.cfg.watch_paths]
        downloads = Path.home() / "Downloads"
        return [downloads] if downloads.is_dir() else []

    def _start_realtime(self) -> None:
        """Start watching, and never let a failure here stop the window opening.

        A watch folder configured once and deleted since -- a removable drive,
        a cleared Downloads -- used to raise out of monitor.start(), out of
        __init__, and the window simply never appeared. Under pythonw there was
        no stderr to say why.
        """
        try:
            watched = self.monitor.start(self._watch_targets())
        except Exception:
            log.exception("real-time protection could not start")
            watched = []

        refused = list(getattr(self.monitor, "refused", []))
        if watched:
            self.status_var.set("Real-time protection on")
            if refused:
                self._banner(
                    f"Not watching {refused[0]} - it is inside AVGuard's own "
                    "folder, which is never scanned.", "inverse-warning")
        else:
            log.warning("no folder could be watched; real-time protection is off")
            self.realtime_var.set(False)
            self.cfg.realtime_enabled = False
            detail = (f"{refused[0]} is inside AVGuard's own folder"
                      if refused else "the folder does not exist")
            self._banner(
                f"Real-time protection is off: {detail}. "
                "Choose a folder in Settings.", "inverse-warning")

    def _toggle_realtime(self) -> None:
        if self.realtime_var.get():
            self._start_realtime()
        else:
            self.monitor.stop()
            self.status_var.set("Real-time protection off")
        self.cfg.realtime_enabled = self.realtime_var.get()
        self.cfg.save()

    def _toggle_cloud(self) -> None:
        enabled = self.cloud_var.get()
        if enabled and not self.cfg.vt_api_key:
            Messagebox.show_warning(
                "Set the VT_API_KEY environment variable, then restart AVGuard.",
                "No VirusTotal API key", parent=self,
            )
            self.cloud_var.set(False)
            return
        if enabled:
            kinds = ", ".join(self.cfg.cloud_extensions)
            Messagebox.show_info(
                "AVGuard will send the SHA-256 hash of a file to VirusTotal - "
                "the hash, never the file itself.\n\n"
                f"Only these kinds of file are looked up:\n{kinds}\n\n"
                "and only when nothing on this machine has already decided "
                "about them.",
                "VirusTotal lookups enabled", parent=self,
            )
        self.cfg.cloud_enabled = enabled
        self.cfg.save()

    # --------------------------------------------------------- quarantine

    def _refresh_quarantine(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for record in self.quarantine.records():
            self.tree.insert(
                "", END, iid=record.entry_id, text=record.original_name,
                values=("; ".join(record.reasons) or "-",
                        record.quarantined_at[:19].replace("T", " ")),
            )

    def _selected_id(self) -> str | None:
        selection = self.tree.selection()
        if not selection:
            Messagebox.show_info("Select a quarantined file first.", "AVGuard", parent=self)
            return None
        return selection[0]

    def _restore_selected(self) -> None:
        entry_id = self._selected_id()
        if entry_id is None:
            return
        record = self.quarantine.get(entry_id)
        confirm = Messagebox.yesno(
            f"Put '{record.original_name}' back at:\n{record.original_path}\n\n"
            f"It was quarantined for: {'; '.join(record.reasons) or 'no reason given'}",
            "Restore this file?", parent=self,
        )
        if confirm != "Yes":
            return
        try:
            target = self.quarantine.restore(entry_id)
        except QuarantineError as exc:
            Messagebox.show_error(str(exc), "Restore failed", parent=self)
            log.error("restore failed: %s", exc)
        else:
            self.cache.invalidate(target)
            log.info("restored %s", target)
        self._refresh_quarantine()

    def _delete_selected(self) -> None:
        entry_id = self._selected_id()
        if entry_id is None:
            return
        record = self.quarantine.get(entry_id)
        confirm = Messagebox.yesno(
            f"Permanently delete '{record.original_name}'? This cannot be undone.",
            "Delete permanently?", parent=self,
        )
        if confirm != "Yes":
            return
        try:
            self.quarantine.delete(entry_id)
        except QuarantineError as exc:
            Messagebox.show_error(str(exc), "Delete failed", parent=self)
        self._refresh_quarantine()

    def _export_selected(self) -> None:
        entry_id = self._selected_id()
        if entry_id is None:
            return
        record = self.quarantine.get(entry_id)
        destination = filedialog.asksaveasfilename(
            title="Export the original bytes",
            initialfile=record.original_name + ".sample",
        )
        if not destination:
            return
        try:
            self.quarantine.export(entry_id, destination)
        except (QuarantineError, OSError) as exc:
            Messagebox.show_error(str(exc), "Export failed", parent=self)
        else:
            Messagebox.show_info(
                f"Wrote the original bytes to:\n{destination}\n\n"
                "This is the unmodified file. Handle it carefully.",
                "Exported", parent=self,
            )

    def _open_logs(self) -> None:
        import subprocess
        try:
            subprocess.Popen(["explorer", str(config.LOG_DIR)])
        except OSError as exc:
            Messagebox.show_error(f"Could not open {config.LOG_DIR}: {exc}", "AVGuard", parent=self)

    def _offer_exclusion(self, folder: Path) -> None:
        """A one-click way to say "that was wrong".

        Shown next to the banner rather than as a modal, so it never
        interrupts a running scan.
        """
        for child in self.banner.winfo_children():
            child.destroy()
        tb.Button(self.banner, text=f"Never scan {folder.name}",
                  bootstyle="light-outline",
                  command=lambda f=folder: self._exclude_folder(f)).pack(side=RIGHT, padx=6)

    def _export_all(self) -> None:
        """The exit door.

        The store holds the only copy of everything in it, so uninstalling or
        deleting the data folder would otherwise destroy the lot.
        """
        if len(self.quarantine) == 0:
            Messagebox.show_info("Quarantine is empty.", "AVGuard", parent=self)
            return
        destination = filedialog.askdirectory(title="Write every quarantined file here")
        if not destination:
            return
        written = self.quarantine.export_all(destination)
        Messagebox.show_info(
            f"Wrote {len(written)} file(s) to:" + chr(10) + f"{destination}" + chr(10) + chr(10)
            + "These are the original, unmodified files. Handle them carefully.",
            "Exported", parent=self)

    def _reload_rules(self) -> None:
        if self.scanner.reload_rules():
            names = ", ".join(p.name for p in self.scanner.rule_sources)
            self.cache = self.scanner.cache
            self._banner(f"Rules reloaded: {names}", "inverse-success")
        else:
            self._banner("Rules failed to load - the previous ones are still in use. "
                         "See the log.", "inverse-danger")
    def _check_realtime_health(self) -> None:
        """Notice the watcher dying, and put it back.

        Reproduced before this existed: deleting and recreating the watched
        folder left four files scoring a hard 100 sitting undetected while the
        header said "Real-time protection on". Reporting the truth is the
        minimum; restoring the protection is the point.
        """
        try:
            if self.realtime_var.get() and self._watch_targets():
                broken = self.monitor.broken_links()
                if broken and not self._shutting_down:
                    log.warning("real-time protection stopped working: %s",
                                "; ".join(broken))
                    self.events.record(Event(kind="health",
                                             detail={"broken": broken}))
                    if self.monitor.recover():
                        self._banner("Real-time protection stopped and was restarted.",
                                     "inverse-warning")
                    else:
                        self._banner("Real-time protection has stopped: "
                                     + "; ".join(broken), "inverse-danger")
        except Exception:
            log.exception("the real-time health check failed")
        finally:
            if not self._shutting_down:
                self.after(HEALTH_TICK_MS, self._check_realtime_health)
    # ------------------------------------------------------------- windows

    def _show_settings(self) -> None:
        dialogs.SettingsDialog(self, self.cfg, self._settings_saved,
                               pack_store=self.scanner.packs,
                               on_packs_changed=self._packs_changed)

    def _packs_changed(self) -> None:
        """A pack was trusted, untrusted or removed. Adopt it now.

        Trust changes must not wait for Save: the dialog writes to disk
        immediately, and until the ruleset is recompiled the running scanner
        keeps scoring by the old trust state. The dangerous direction is
        trusted to reports-only -- a user turning a pack off after a false
        positive, while it carries on condemning.
        """
        self.scanner.reload_rules()
        self.scanner.rekey_cache()
        self.cache = self.scanner.cache
        log.info("rule packs changed; ruleset and cache rebuilt")

    def _settings_saved(self) -> None:
        """Apply what can be applied live, and say what cannot."""
        self.scanner.cfg = self.cfg
        # Ticking "look inside .zip files" changes what a clean verdict means,
        # so every verdict stored under the old setting has to go.
        discarded = self.scanner.rekey_cache()
        self.cache = self.scanner.cache
        if discarded:
            log.info("settings changed; discarded %d cached verdict(s)", discarded)
        log.info("settings saved")
        if self.monitor.running:
            # Re-read from disk before restarting. The in-memory Config was
            # loaded at startup, so restarting from it would silently revert a
            # watch folder another AVGuard process added in the meantime.
            self.cfg = config.Config.load()
            self.scanner.cfg = self.cfg
            self.monitor.stop()
            self._start_realtime()
        self._banner("Settings saved.", "inverse-success")

    def _show_history(self) -> None:
        dialogs.HistoryDialog(self, self.events, self._history_cleared)

    def _history_cleared(self) -> None:
        log.info("history cleared at the user's request")
        self._banner("History cleared.", "inverse-secondary")

    def _describe_rules(self) -> str:
        """What is actually loaded, not just the shipped file.

        This row said "compiled from malware.yara" while 311 files and 1,240
        imported rules were loaded. The Health view exists to answer whether
        detection is working, and understating what is loaded is a way of
        answering it wrongly.
        """
        total = len(self.scanner.rule_sources)
        imported = sum(p.rule_count for p in self.scanner.packs.packs())
        if not imported:
            return f"{total} file(s), all shipped with AVGuard"
        return (f"{total} file(s): the shipped ruleset plus "
                f"{imported:,} rules from {len(self.scanner.packs.packs())} pack(s)")

    def _describe_packs(self) -> str:
        packs = self.scanner.packs.packs()
        if not packs:
            return ("none installed - detection is whatever the shipped rules "
                    "catch. Add one with: avguard --packs add <folder>")
        parts = []
        for pack in packs:
            broken = self.scanner.broken_packs.get(pack.name)
            if broken:
                # Left out of the ruleset, and said so here rather than only in
                # a log nobody reads. The rest of detection is unaffected.
                parts.append(f"{pack.name}: FAILED TO COMPILE, left out - {broken[:60]}")
                continue
            state = "can move files" if pack.trusted else "reports only"
            parts.append(f"{pack.name} ({pack.rule_count:,} rules, {state})")
        return "; ".join(parts)
    def _show_health(self) -> None:
        """Every row is something that has failed silently before."""
        rules_ok = self.scanner.rules is not None
        broken = self.monitor.broken_links()
        watching = not broken and bool(self.monitor.watched)
        workers = self.monitor.pool.alive_workers
        checks = [
            ("Detection rules", rules_ok, self._describe_rules() if rules_ok
             else "FAILED TO COMPILE - most detection is off. See the log."),
            ("Rule packs", not self.scanner.broken_packs, self._describe_packs()),
            ("Real-time protection", watching,
             f"watching {len(self.monitor.watched)} folder(s)" if watching
             else ("; ".join(broken) if broken else "not running")),
            ("Scan workers", (not self.monitor.watched) or workers > 0,
             f"{workers} alive" if workers else "idle, nothing to do"),
            ("Quarantine store", self.has_lock,
             f"{len(self.quarantine)} item(s) held" if self.has_lock
             else "another AVGuard holds the lock; this window cannot move files"),
            ("Automatic quarantine", True,
             "on" if self.cfg.auto_quarantine else "off - detections are reported only"),
            ("VirusTotal", True,
             f"on, {self.cloud.spent_today} lookup(s) today" if self.cfg.cloud_enabled
             else "off - no hashes leave this machine"),
            ("Scan cache", True, f"{len(self.cache)} remembered verdict(s)"),
            ("Quarantine integrity", not self.quarantine.orphaned_payloads(),
             "every stored file has a record"
             if not self.quarantine.orphaned_payloads()
             else f"{len(self.quarantine.orphaned_payloads())} stored file(s) have no "
                  "record and cannot be decoded; see the log"),
            ("Publisher trust", self.scanner.signatures.available,
             "Authenticode checking is available" if self.scanner.signatures.available
             else "unavailable on this system"),
            ("Rule files", bool(self.scanner.rule_sources),
             ", ".join(p.name for p in self.scanner.rule_sources) or "none loaded"),
            ("Starts with Windows", True,
             "yes" if scheduling.starts_with_windows() else "no"),
            ("Data folder", True, str(config.DATA_DIR)),
        ]
        dialogs.HealthDialog(self, checks, on_reload_rules=self._reload_rules)

    def _exclude_folder(self, folder: Path) -> None:
        """The recovery path for a false positive.

        Offered from the detection itself, because the alternative was to
        hand-edit a JSON file the user had never been told about.
        """
        pattern = dialogs.glob_for(folder)
        if pattern in self.cfg.excluded_globs:
            return
        self.cfg.excluded_globs.append(pattern)
        try:
            self.cfg.save()
        except OSError as exc:
            Messagebox.show_error(f"Could not save: {exc}", "AVGuard", parent=self)
            return
        self.cache.invalidate(folder)
        log.info("excluded %s from future scans", folder)
        self._banner(f"{folder} will not be scanned again.", "inverse-secondary")
    # ---------------------------------------------------------- lifecycle

    def _show(self) -> None:
        self.deiconify()
        self.lift()

    def _hide(self) -> None:
        self.withdraw()

    def shutdown(self) -> None:
        """Stop every thread we started, then close. Runs on the GUI thread."""
        log.info("shutting down")
        self._shutting_down = True
        self._cancel.set()
        try:
            self.monitor.stop()
        except Exception:
            log.exception("error stopping the monitor")
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=5)
        try:
            self.cache.save()
            self.cloud.save_cache()
            self.cfg.save()
        except Exception:
            log.exception("error saving state")
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass
        try:
            self.lock.release()
        except Exception:
            pass
        self.quit()
        self.destroy()


def main() -> int:
    # Called here, finally. Under the --noconsole executable build.py produces
    # there is no stderr, so without these a crash is completely silent: the
    # user double-clicks and nothing happens, with no log line to explain it.
    logsetup.install_excepthooks()
    config.ensure_directories()
    app = AVGuardApp()
    app._show()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app.shutdown()
    return 0
