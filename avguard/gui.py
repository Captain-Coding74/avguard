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
from datetime import datetime
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

import ttkbootstrap as tb
from ttkbootstrap.constants import (
    BOTH, DISABLED, END, HORIZONTAL, LEFT, NORMAL, RIGHT, VERTICAL, X, Y
)
from ttkbootstrap.dialogs import Messagebox, Querybox

from . import (autoruns, clipguard, config, dialogs, explain, fimpanel, logsetup, provenance, scheduling,
               signing, startuppanel)
from .events import Event, EventStore
from .cloud import VirusTotalClient
from . import iocs as iocs_module
from . import fim as fim_module
from . import forward as forward_module
from . import shellext
from .instance import InstanceLock
from .protection import SelfProtection
from .quarantine import QuarantineError, QuarantineStore, RestoreIncomplete
from .scanner import Level, Scanner, Verdict, findings_to_dicts
from .watcher import RealtimeMonitor

log = logging.getLogger("avguard.gui")

MAX_LOG_LINES = 2000
UI_TICK_MS = 100
MAX_DRAIN_PER_TICK = 200

# How often to prove real-time protection is still working. A watched folder
# being deleted and recreated kills watchdog's emitter silently, and the old
# status check could not see it.
HEALTH_TICK_MS = 30_000
FEED_TICK_MS = 5_000          # the daily blocklist check, once the window is up
# The paste guard's poll: one user32 call per tick, the clipboard opened only
# when its sequence number has moved. On the Tk thread, no worker.
CLIPBOARD_TICK_MS = 500

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
        # Off until a URL is set; the dialog asks for consent before one is.
        self.forwarder = (forward_module.EventForwarder(self.cfg.event_forward_url)
                          if self.cfg.event_forward_url else None)
        self.events = EventStore(forwarder=self.forwarder)

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
        if self.has_lock:
            # Only the lock holder finishes or undoes a move a killed process
            # left half done; a window without the lock leaves it alone.
            self.quarantine.reconcile()

        # The paste guard reads the clipboard only while cfg.paste_guard_enabled
        # is set; the tick checks that before touching the source.
        self.pasteguard = clipguard.PasteGuard(clipguard.WindowsClipboard(), self.events,
                                               notify=self._paste_warning)
        self._clipboard_tick_failed = False

        self._shutting_down = False
        self._scan_thread: threading.Thread | None = None
        # True from _start_scan to _scan_finished, on the GUI thread. The
        # thread's is_alive() is the wrong gate: the worker posts its last
        # verdicts and _scan_finished together and exits before the pump
        # drains them, so every small scan looked finished to its own verdicts.
        self._scan_active = False
        self._cancel = threading.Event()
        self._threats_this_scan = 0
        # Archives whose extracted, unmarked programs have had their banner
        # this session: one per archive, not one per file.
        self._provenance_banners: set[str] = set()
        self._banner_style = ""

        self._build_widgets()
        self._build_tray()
        self.protocol("WM_DELETE_WINDOW", self._hide)

        self.after(UI_TICK_MS, self._pump)
        self.after(HEALTH_TICK_MS, self._check_realtime_health)
        self.after(FEED_TICK_MS, self._update_blocklist_feed)
        self.after(CLIPBOARD_TICK_MS, self._tick_clipboard)
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
        else:
            if self.cfg.realtime_enabled:
                self._start_realtime()
            if not self.cfg.paste_guard_offered:
                # An existing install: offered once, never switched on behind
                # the user's back.
                self.after(600, self._offer_paste_guard)
            else:
                self.after(600, self._offer_quarantine_review)

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

        # Panedwindow, not PanedWindow: ttkbootstrap 2.x exports only the
        # first, and 1.x exports both. With the alias the window never opened.
        panes = tb.Panedwindow(outer, orient=HORIZONTAL)
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

        # --- quarantine and integrity ------------------------------------
        right = tb.Frame(panes, padding=(8, 0, 0, 0))
        panes.add(right, weight=2)
        self.tabs = tb.Notebook(right)
        self.tabs.pack(fill=BOTH, expand=True)
        quarantine = tb.Frame(self.tabs, padding=(0, 8, 0, 0))
        self.tabs.add(quarantine, text="Quarantine")

        self.tree = tb.Treeview(
            quarantine, columns=("detected", "when"), show="tree headings", selectmode="browse",
        )
        self.tree.heading("#0", text="File")
        self.tree.heading("detected", text="Detected as")
        self.tree.heading("when", text="Quarantined")
        self.tree.column("#0", width=190, anchor="w")
        self.tree.column("detected", width=190, anchor="w")
        self.tree.column("when", width=130, anchor="w")
        self.tree.pack(fill=BOTH, expand=True)

        qbtns = tb.Frame(quarantine, padding=(0, 8))
        qbtns.pack(fill=X)
        tb.Button(qbtns, text="Restore", bootstyle="success-outline",
                  command=self._restore_selected).pack(side=LEFT, expand=True, fill=X, padx=2)
        tb.Button(qbtns, text="Export copy", bootstyle="secondary-outline",
                  command=self._export_selected).pack(side=LEFT, expand=True, fill=X, padx=2)
        tb.Button(qbtns, text="Delete", bootstyle="danger-outline",
                  command=self._delete_selected).pack(side=LEFT, expand=True, fill=X, padx=2)

        tb.Button(quarantine, text="Export everything...", bootstyle="secondary-outline",
                  command=self._export_all).pack(fill=X, pady=(0, 4))
        tb.Button(quarantine, text="Mark as a known sample...", bootstyle="info-outline",
                  command=self._mark_known_sample).pack(fill=X, pady=(0, 4))
        tb.Button(quarantine, text="Why was this taken?", bootstyle="info-outline",
                  command=self._explain_selected).pack(fill=X, pady=(0, 4))

        # The file-integrity baseline, beside the quarantine because both are
        # things the user comes back to look at. Its work runs on a thread of
        # its own and reports through self.post, like a scan.
        self.integrity = fimpanel.IntegrityPanel(
            self.tabs, store_factory=self._fim_store, events=self.events, post=self.post,
            padding=(0, 8, 0, 0))
        self.tabs.add(self.integrity, text="Integrity")

        # What starts with Windows, beside the integrity baseline: the same
        # design applied to configuration. A snapshot reads and compares;
        # it moves nothing and cannot.
        self.startup = startuppanel.StartupPanel(
            self.tabs, store_factory=self._autoruns_store, events=self.events, post=self.post,
            trusted=self._startup_trusted(), on_report=self._startup_report, padding=(0, 8, 0, 0))
        self.tabs.add(self.startup, text="Startup")

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
        """Show a one-line notice above the panes, replacing any previous one.

        Any button the previous banner carried goes with it: "Don't warn
        about this text again" must not sit beside "Scan complete". A caller
        that wants a button adds it after this call.
        """
        for child in self.banner.winfo_children():
            child.destroy()
        self.banner_var.set(text)
        self.banner.configure(bootstyle=style)
        self._banner_style = style
        self.banner.pack(fill=X, pady=(0, 8), before=self._panes)

    def _banner_is_loud(self) -> bool:
        """A threat or a warning is showing, with its buttons: a notice must
        not replace it."""
        try:
            return self._banner_style in ("inverse-danger", "inverse-warning") and bool(self.banner.winfo_ismapped())
        except Exception:
            return False

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

        paste_var = tk.BooleanVar(value=True)
        tb.Checkbutton(
            body, variable=paste_var, bootstyle="round-toggle",
            text="Also watch what you copy: paste-and-run commands and replaced crypto addresses",
        ).pack(anchor="w", pady=(0, 2))
        tb.Label(body, bootstyle="secondary", wraplength=520, justify="left",
                 text=("The fake-CAPTCHA scam copies a command and tells you to paste it into "
                       "the Run box; clipboard-hijacking malware swaps a crypto address you copied "
                       "for its own. AVGuard would look at text you copy, on this PC, for both; it "
                       "keeps none of it beyond a few seconds in memory and sends nothing."
                       )).pack(anchor="w", pady=(0, 14))

        def finish(auto: bool, chosen: bool = True) -> None:
            window.grab_release()
            window.destroy()
            self._apply_first_run(auto, paste_var.get() if chosen else None)

        buttons = tb.Frame(body)
        buttons.pack(fill=X)
        tb.Button(buttons, text="Watch and tell me", bootstyle="success",
                  command=lambda: finish(False)).pack(side=LEFT, expand=True, fill=X, padx=(0, 6))
        tb.Button(buttons, text="Watch and quarantine automatically", bootstyle="warning",
                  command=lambda: finish(True)).pack(side=LEFT, expand=True, fill=X)

        # Closing the window without choosing is the cautious answer for both
        # switches: nothing is moved and nothing is read. The pre-ticked box
        # is not a yes; the one-time banner offers the guard on the next start.
        window.protocol("WM_DELETE_WINDOW", lambda: finish(False, chosen=False))

    def _apply_first_run(self, auto_quarantine: bool, paste_guard: bool | None = False) -> None:
        """`paste_guard` None means the dialog was dismissed without a choice."""
        self.cfg.auto_quarantine = auto_quarantine and self.has_lock
        self.cfg.onboarding_completed = True
        self.cfg.paste_guard_enabled = bool(paste_guard)
        self.cfg.paste_guard_offered = paste_guard is not None
        try:
            self.cfg.save()
        except OSError as exc:
            log.warning("could not save your choice: %s", exc)
        log.info("first run: automatic quarantine is %s; the paste guard is %s",
                 "on" if self.cfg.auto_quarantine else "off (detections will be reported only)",
                 "on" if self.cfg.paste_guard_enabled else "off")
        if self.cfg.realtime_enabled:
            self._start_realtime()

    # --------------------------------------------------------- paste guard

    def _tick_clipboard(self) -> None:
        """The paste guard's poll. Nothing is touched while the guard is off,
        and the guard forgets where the clipboard was, so text copied while
        it was off is never examined when it comes back on.

        Rescheduled from `finally` for the reason _pump is: a tick that
        dies takes the guard with it and the Health row would still read on.
        """
        try:
            if self.cfg.paste_guard_enabled and not self._shutting_down:
                self.pasteguard.tick()
            else:
                self.pasteguard.disarm()
            self._clipboard_tick_failed = False
        except Exception:
            if not getattr(self, "_clipboard_tick_failed", False):
                log.exception("the paste guard's tick failed")
            self._clipboard_tick_failed = True       # the traceback once, not twice a second
        finally:
            if not self._shutting_down:
                self.after(CLIPBOARD_TICK_MS, self._tick_clipboard)

    def _paste_warning(self, match, clip: clipguard.ClipText) -> None:
        """On the GUI thread (the tick runs there). Says it; moves nothing."""
        sentence = match.sentence(clip.owner)
        if isinstance(match, clipguard.Swap):
            # No "don't warn again": the text it would silence is the
            # replacement, and nothing about it is worth trusting. The log
            # line names neither program: it outlives "Clear history".
            log.warning("PASTE GUARD: a %s address on the clipboard was replaced; the account is in History",
                        match.family)
            self._banner(sentence, "inverse-danger")
            if self.tray is not None:
                try:
                    self.tray.notify("The crypto address on your clipboard was replaced", "AVGuard")
                except Exception:
                    pass
            return
        if match.tier == clipguard.WARNING:
            log.warning("PASTE GUARD: %s", sentence)
            self._banner(sentence, "inverse-danger")
            if self.tray is not None:
                try:
                    self.tray.notify("A paste-and-run command is in your clipboard", "AVGuard")
                except Exception:
                    pass
        else:
            log.info("paste guard: %s", sentence)
            self._banner(sentence, "inverse-warning")
        # The button on both tiers: the honest install line a developer pastes
        # every week is the notice, and that is the one worth silencing.
        tb.Button(self.banner, text="Don't warn about this text again", bootstyle="light-outline",
                  command=lambda m=match: self._ignore_paste_text(m)).pack(side=RIGHT, padx=6)

    def _ignore_paste_text(self, match: clipguard.Match) -> None:
        try:
            self.pasteguard.ignore(match)
        except OSError as exc:
            Messagebox.show_error(f"Could not record that: {exc}", "AVGuard", parent=self)
            return
        self._banner("That exact text will not be warned about again.", "inverse-secondary")

    def _offer_paste_guard(self) -> None:
        """One banner, once, for an install that predates the guard.

        Shown only when no other banner is up (a startup warning outranks a
        feature notice) and recorded as offered only once it has been shown;
        otherwise the next start tries again.
        """
        if self.banner.winfo_ismapped() and self.banner_var.get():
            return
        self.cfg.paste_guard_offered = True
        try:
            self.cfg.save()
        except OSError as exc:
            log.warning("could not record the paste-guard offer: %s", exc)
        self._banner("New: AVGuard can warn when the clipboard holds a paste-and-run command "
                     "(the fake-CAPTCHA scam) or when a crypto address you copied is replaced. It "
                     "would look at text you copy, on this PC only, keep none of it beyond a few "
                     "seconds in memory and send nothing.", "inverse-secondary")
        tb.Button(self.banner, text="Turn it on", bootstyle="light-outline",
                  command=self._enable_paste_guard).pack(side=RIGHT, padx=6)

    def _enable_paste_guard(self) -> None:
        self.cfg.paste_guard_enabled = True
        try:
            self.cfg.save()
        except OSError as exc:
            self.cfg.paste_guard_enabled = False     # what is shown is what runs
            Messagebox.show_error(f"Could not save, so the guard stays off: {exc}", "AVGuard", parent=self)
            return
        log.info("paste guard turned on")
        self._banner("The paste guard is on. It can be turned off in Settings.", "inverse-success")

    def _describe_paste_guard(self) -> tuple[bool, str]:
        if not self.cfg.paste_guard_enabled:
            return True, "off - the clipboard is never opened"
        if not self.pasteguard.source.available:
            # Off Windows there is no clipboard to read, and that is fine; on
            # Windows a reader that turned itself off (a privacy format it
            # could not register) is a guard that is on and reads nothing.
            reason = getattr(self.pasteguard.source, "unavailable_reason", "unavailable on this platform")
            return sys.platform != "win32", reason
        return self.pasteguard.healthy, self.pasteguard.describe()

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
                score=verdict.score, reasons=list(verdict.reasons),
                detail=explain.evidence_detail(verdict, self.cfg)))
            self.post(self._report_suspicious, verdict)
        elif verdict.level is Level.CLEAN and provenance.extracted_finding(verdict.findings) is not None:
            self.post(self._report_extracted, verdict)
        elif verdict.level is Level.ERROR:
            log.error("%s - %s", verdict.path, "; ".join(verdict.reasons))
        else:
            log.debug("%s - %s", verdict.path, verdict.level.value)

    def _report_suspicious(self, verdict: Verdict) -> None:
        """On the GUI thread. Under real-time protection a SUSPICIOUS file used
        to reach only the Activity line and History; one banner now says it
        was reported and not moved, with the account and the way out behind
        it. During a full scan the summary line stays and History carries
        each one, so a folder of unusual files does not churn the banner."""
        if self._scan_active:
            return
        self._banner(f"Unusual file reported, not moved: {verdict.path.name}", "inverse-warning")
        self._offer_account(explain.from_verdict(verdict, self.cfg, self.scanner.packs))
        self._offer_exclusion(verdict.path.parent)

    def _report_extracted(self, verdict: Verdict) -> None:
        """On the GUI thread. A clean program or document whose bytes equal a
        member of a downloaded archive and that carries no download mark:
        SmartScreen will not ask about it, so AVGuard says so, once. One
        History row per file, ever (the store remembers it was told), kept
        on this machine like the paste guard's; one banner per archive per
        session, at a quiet moment; no tray notice; nothing moved."""
        finding = provenance.extracted_finding(verdict.findings)
        origin = self.scanner.provenance.lookup(verdict.sha256)
        if finding is None or origin is None:
            return
        if not origin.told:
            self.events.record(Event(
                kind="provenance", path=str(verdict.path), level=verdict.level.value,
                reasons=[finding.describe()],
                detail={"sha256": verdict.sha256, "container": origin.container, "host": origin.host,
                        "findings": findings_to_dicts([finding])}), forward=False)
            self.scanner.provenance.mark_told(verdict.sha256)
        # The banner waits for a quiet moment: during a scan the summary
        # would replace it unseen, and a threat's banner, with its buttons,
        # is not replaced by a notice. History has the row either way.
        if self._scan_active or self._banner_is_loud() or origin.container in self._provenance_banners:
            return
        self._provenance_banners.add(origin.container)
        self._banner(f"From a download: {verdict.path.name} {finding.describe()}. Nothing was changed.",
                     "inverse-info")

    def _handle_threat(self, verdict: Verdict) -> None:
        """Runs on the GUI thread."""
        self._threats_this_scan += 1
        # The evidence rides inside `detail` (the event's seven fields are
        # schema 1 and stay so), so History can account for the verdict later;
        # `state` says what happened, so the detection row of a file that was
        # then quarantined does not read "nothing was moved".
        detail = explain.evidence_detail(verdict, self.cfg)
        record = None
        failure = ""
        if self.cfg.auto_quarantine:
            try:
                record = self.quarantine.quarantine(verdict.path, verdict.reasons, evidence=detail,
                                                    expected_sha256=verdict.sha256)
            except QuarantineError as exc:
                log.error("could not quarantine %s: %s", verdict.path, exc)
                failure = str(exc)
        state = explain.QUARANTINED if record is not None else explain.REPORTED
        self.events.record(Event(
            kind="detection", path=str(verdict.path), level=verdict.level.value,
            score=verdict.score, reasons=list(verdict.reasons), detail={**detail, "state": state}))

        if record is None:
            if failure:
                self._banner(f"Could not quarantine {verdict.path.name}: {failure}", "inverse-danger")
            else:
                self._banner(f"Threat found in {verdict.path.name} (not quarantined - "
                             f"automatic quarantine is off)", "inverse-danger")
            # The account and the way out, for a reported threat as much as
            # for a quarantined one; before this only a quarantine offered them.
            self._offer_account(explain.from_verdict(verdict, self.cfg, self.scanner.packs))
            self._offer_exclusion(verdict.path.parent)
            return

        self.events.record(Event(
            kind="quarantined", path=str(verdict.path), level=verdict.level.value,
            score=verdict.score, reasons=list(verdict.reasons), detail={**detail, "state": state}))
        self.cache.invalidate(verdict.path)
        self._refresh_quarantine()
        self._banner(f"Quarantined {verdict.path.name} - {'; '.join(verdict.reasons)}",
                     "inverse-danger")
        self._offer_account(explain.from_verdict(verdict, self.cfg, self.scanner.packs,
                                                 quarantined=True), entry_id=record.entry_id)
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
        self._scan_active = True
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
        self._scan_active = False
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
        if entry_id is not None:
            self._restore_entry(entry_id)

    def _without_the_lock(self, what: str) -> bool:
        """True, after saying so, when another AVGuard holds the lock. Two
        processes writing the quarantine store is what the lock prevents, and
        Restore and Delete in a second window did exactly that."""
        if self.has_lock:
            return False
        Messagebox.show_info(
            f"Another AVGuard is running (pid {self.lock.owner_pid or 0}) and holds the quarantine. "
            f"{what} in that window, so two programs never change the store at once.",
            "AVGuard", parent=self)
        return True

    def _restore_entry(self, entry_id: str) -> None:
        if self._without_the_lock("Restore the file"):
            return
        record = self.quarantine.get(entry_id)
        if record is None:
            Messagebox.show_info("That entry is already gone.", "AVGuard", parent=self)
            self._refresh_quarantine()
            return
        confirm = Messagebox.yesno(
            f"Put '{record.original_name}' back at:\n{record.original_path}\n\n"
            f"It was quarantined for: {'; '.join(record.reasons) or 'no reason given'}\n\n"
            "AVGuard will not flag this file again, anywhere on this PC, until you "
            "remove it under Settings > Files you chose to keep.",
            "Restore this file?", parent=self,
        )
        if confirm != "Yes":
            return
        try:
            target = self.quarantine.restore(entry_id)
        except RestoreIncomplete as exc:
            # The file is back; the exception for it is not. Say exactly that.
            self._record_restore(record, exc.target)
            Messagebox.show_warning(str(exc), "Restored, with a warning", parent=self)
            self._allowlist_changed()
            self._refresh_quarantine()
            return
        except QuarantineError as exc:
            Messagebox.show_error(str(exc), "Restore failed", parent=self)
            log.error("restore failed: %s", exc)
        else:
            # restore() recorded an exception for these bytes. Re-key rather
            # than invalidate one path: every copy anywhere is judged afresh.
            self._record_restore(record, target)
            self._allowlist_changed()
            log.info("restored %s", target)
        self._refresh_quarantine()

    def _record_restore(self, record, target: Path) -> None:
        """History, and the forwarder when one is set: the README has said a
        restore is POSTed since forwarding shipped, and nothing recorded one.
        The path, the verdict and the digest, which the consent names."""
        self.events.record(Event(kind="restored", path=str(target), reasons=list(record.reasons),
                                 detail={"sha256": record.sha256, "from": "quarantine"}))

    def _delete_selected(self) -> None:
        entry_id = self._selected_id()
        if entry_id is None or self._without_the_lock("Delete it"):
            return
        record = self.quarantine.get(entry_id)
        if record is None:
            Messagebox.show_info("That entry is already gone.", "AVGuard", parent=self)
            self._refresh_quarantine()
            return
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
        else:
            self.events.record(Event(kind="deleted", path=record.original_path,
                                     reasons=list(record.reasons),
                                     detail={"sha256": record.sha256, "from": "quarantine"}))
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

    def _mark_known_sample(self) -> None:
        """Seed the similarity match from a file already judged bad.

        The reference set is empty until somebody fills it, and until this
        button that meant two commands in a terminal. A quarantined file is
        one the user has looked at; its digest under a family name makes the
        next variant of it a soft finding. Nothing is moved on resemblance.
        """
        entry_id = self._selected_id()
        if entry_id is not None:
            self._mark_known_entry(entry_id)

    def _mark_known_entry(self, entry_id: str) -> None:
        record = self.quarantine.get(entry_id)
        if record is None:
            Messagebox.show_info("That entry is already gone.", "AVGuard", parent=self)
            self._refresh_quarantine()
            return
        suggested = iocs_module.family_from_reasons(record.reasons, Path(record.original_name).stem)
        family = Querybox.get_string(
            prompt=(f"Family name for '{record.original_name}'." + chr(10) + chr(10)
                    + "Files that resemble it will be reported as SUSPICIOUS under this "
                      "name. Resemblance alone never moves a file."),
            title="Mark as a known sample", initialvalue=suggested, parent=self)
        if family is None:
            return
        family = family.strip() or suggested
        try:
            data = self.quarantine.payload(entry_id)
        except (QuarantineError, OSError) as exc:
            Messagebox.show_error(str(exc), "Could not read the sample", parent=self)
            return
        result = self.scanner.iocs.add_reference(data, family, source="quarantine")
        if not result.ok:
            Messagebox.show_warning(f"'{record.original_name}' was not added: {result.reason}.",
                                    "No reference added", parent=self)
            return
        if result.known:
            self._banner(f"'{record.original_name}' is already a known sample.", "inverse-secondary")
            return
        self.events.record(Event(
            kind="reference", path=record.original_path,
            reasons=[f"marked as a known sample of {family}"],
            detail={"digest": result.digest, "family": family, "entry_id": entry_id}))
        # The scanner reloads its references and re-keys the cache, so a copy
        # cached CLEAN a minute ago is measured against the new row next time.
        self.scanner.adopt_iocs()
        self.cache = self.scanner.cache
        log.info("known sample: %s added as %s (%s...)", record.original_name, family,
                 result.digest[:14])
        self._banner(f"'{record.original_name}' is now a known sample of {family}: files that "
                     "resemble it will be reported.", "inverse-success")

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
        report = self.quarantine.export_all(destination)
        nl = chr(10)
        held = len(report.written) + len(report.failed)
        text = f"Wrote {len(report.written)} of {held} file(s) to:{nl}{destination}"
        if report.written:
            text += f"{nl}{nl}These are the original, unmodified files (each checked against its digest). Handle them carefully."
        if report.failed:
            text += f"{nl}{nl}Not written:" + "".join(f"{nl}  {name}: {why}" for name, why in report.failed[:10])
            if len(report.failed) > 10:
                text += f"{nl}  and {len(report.failed) - 10} more (see the log)"
            Messagebox.show_warning(text, "Exported, with failures", parent=self)
        else:
            Messagebox.show_info(text, "Exported", parent=self)

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
                               on_packs_changed=self._packs_changed,
                               allowlist=self.scanner.allowlist,
                               on_allowlist_changed=self._allowlist_changed,
                               ioc_store=self.scanner.iocs,
                               on_references_changed=self._references_changed)

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

    def _allowlist_changed(self) -> None:
        """An exception was added or removed. Every cached verdict goes.

        The generation includes the exception digests, so re-keying discards
        every verdict that could have depended on one -- a second copy of
        restored bytes elsewhere, a copy that was CLEAN only by exception.
        Invalidating the one path a restore put back was not enough.
        """
        discarded = self.scanner.rekey_cache()
        self.cache = self.scanner.cache
        log.info("kept-files list changed; %d cached verdict(s) discarded", discarded)

    def _references_changed(self) -> None:
        """A known sample was removed in Settings: the scanner adopts it now.

        A verdict cached SUSPICIOUS on resemblance to the removed row would
        otherwise replay for the cache's lifetime; re-keying drops it.
        """
        self.scanner.adopt_iocs()
        self.cache = self.scanner.cache
        log.info("known samples changed; references reloaded and cache rebuilt")

    def _forwarding_changed(self) -> None:
        """The URL changed in Settings: the old forwarder stops, a new one starts."""
        url = self.cfg.event_forward_url
        current = self.forwarder.url if self.forwarder is not None else ""
        if url == current:
            return
        if self.forwarder is not None:
            self.forwarder.stop()
        self.forwarder = forward_module.EventForwarder(url) if url else None
        self.events.forwarder = self.forwarder
        log.info("event forwarding %s", f"to {url}" if url else "off")

    def _settings_saved(self) -> None:
        """Apply what can be applied live, and say what cannot."""
        self.scanner.cfg = self.cfg
        self._forwarding_changed()
        # Ticking "look inside .zip files" changes what a clean verdict means,
        # so every verdict stored under the old setting has to go.
        discarded = self.scanner.rekey_cache()
        self.cache = self.scanner.cache
        if discarded:
            log.info("settings changed; discarded %d cached verdict(s)", discarded)
        log.info("settings saved")
        self._update_blocklist_feed()
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
        dialogs.HistoryDialog(self, self.events, self._history_cleared, on_open=self._explain_event)

    # ------------------------------------------------------------ accounts

    def _offer_account(self, account: explain.Explanation, entry_id: str | None = None) -> None:
        """The "Why?" button beside a detection banner. Packed after the
        banner, which cleared the previous one's buttons."""
        tb.Button(self.banner, text="Why?", bootstyle="light-outline",
                  command=lambda a=account, e=entry_id: self._show_account(a, e)
                  ).pack(side=RIGHT, padx=6)

    def _show_account(self, account: explain.Explanation, entry_id: str | None = None) -> None:
        """The dialog, with only the actions the window can take from here."""
        actions = {"exclude": lambda: self._exclude_folder(Path(account.path).parent)}
        if entry_id is not None:
            actions["restore"] = lambda: self._restore_entry(entry_id)
            actions["reference"] = lambda: self._mark_known_entry(entry_id)
        dialogs.ExplanationDialog(self, account, actions)

    def _explain_selected(self) -> None:
        entry_id = self._selected_id()
        if entry_id is None:
            return
        record = self.quarantine.get(entry_id)
        if record is None:
            Messagebox.show_info("That entry is already gone.", "AVGuard", parent=self)
            self._refresh_quarantine()
            return
        account = explain.from_record(record, self.quarantine.evidence(entry_id), self.cfg,
                                      self.scanner.packs)
        self._show_account(account, entry_id)

    def _explain_event(self, event: Event) -> None:
        self._show_account(explain.from_event(event, self.cfg, self.scanner.packs))

    def _history_cleared(self) -> None:
        log.info("history cleared at the user's request")
        self._banner("History cleared.", "inverse-secondary")

    def _describe_rules(self) -> str:
        """What is actually loaded, derived from the compiled ruleset.

        This row said "compiled from malware.yara" while 311 files and 1,240
        imported rules were loaded. Then it summed rule_count from the pack
        index, so a pack whose directory had been deleted still reported its
        1,240 rules as loaded. The Health view exists to answer whether
        detection is working; both were ways of answering it wrongly.
        """
        rules = self.scanner.rules
        total_rules = sum(1 for _ in rules) if rules is not None else 0
        total_files = len(self.scanner.rule_sources)
        counts = self.scanner.pack_rule_counts
        imported = sum(counts.values())
        if not imported:
            return f"{total_rules:,} rules from {total_files} file(s), all shipped with AVGuard"
        return (f"{total_rules:,} rules from {total_files} file(s): the shipped "
                f"ruleset plus {imported:,} loaded from {len(counts)} pack(s)")

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
            loaded = self.scanner.pack_rule_counts.get(pack.name, 0)
            state = "can move files" if pack.trusted else "reports only"
            if not self.scanner.packs.rule_files_for(pack.name):
                # The disk and the loaded ruleset disagree. Deleting a pack's
                # directory unloads nothing; this row used to say "0 rules
                # loaded" while those rules were still matching -- and, if
                # trusted, still moving files.
                where = ("DIRECTORY MISSING"
                         if not self.scanner.packs.pack_dir(pack.name).is_dir()
                         else "NO RULE FILES on disk")
                if loaded:
                    parts.append(f"{pack.name}: {where}, but {loaded:,} rules are still "
                                 f"loaded ({state}) until Reload rules")
                else:
                    parts.append(f"{pack.name}: {where}, 0 rules loaded "
                                 f"(index says {pack.rule_count:,})")
                continue
            parts.append(f"{pack.name} ({loaded:,} rules loaded, {state})")
        return "; ".join(parts)

    def _describe_iocs(self) -> str:
        store = self.scanner.iocs
        total = store.count()
        state = store.feed_state()
        if self.cfg.ioc_feed_enabled:
            if state["checked_at"]:
                try:
                    when = datetime.fromtimestamp(float(state["checked_at"])).strftime("%Y-%m-%d %H:%M")
                except (ValueError, OSError):
                    when = "unknown"
                feed = f"daily feed on, last checked {when}"
            else:
                feed = "daily feed on, not fetched yet"
        else:
            feed = "daily feed off - nothing is fetched"
        references = store.tlsh_count()
        similarity = (f"; {references:,} TLSH reference(s) for similarity"
                      if references else "")
        if not total:
            return f"empty; {feed}{similarity}. Import hashes with: avguard --iocs-import <file>"
        by_source = ", ".join(f"{n:,} from {source}" for source, n in store.sources().items())
        return f"{total:,} hash(es) ({by_source}); {feed}{similarity}"

    def _update_blocklist_feed(self) -> None:
        """The daily feed check: off the GUI thread, and only when opted in.

        The opt-in is enforced inside iocs.scheduled_update as well, so a
        GUI that forgot to look at the setting could not phone home.
        """
        if not self.cfg.ioc_feed_enabled or not self.scanner.iocs.feed_due():
            return
        store = self.scanner.iocs

        def work() -> None:
            try:
                result = iocs_module.scheduled_update(store, enabled=self.cfg.ioc_feed_enabled)
            except iocs_module.IocError as exc:
                log.warning("blocklist feed: %s", exc)
                return
            if result.status == "updated" and result.imported is not None:
                log.info("blocklist updated: %s", result.imported.describe())
                self.post(self._blocklist_changed)

        threading.Thread(target=work, name="avguard-iocs-feed", daemon=True).start()

    def _blocklist_changed(self) -> None:
        """New hashes: every cached verdict that predates them goes."""
        discarded = self.scanner.rekey_cache()
        self.cache = self.scanner.cache
        log.info("blocklist changed; %d cached verdict(s) discarded", discarded)

    def _fim_store(self):
        return fim_module.FimStore(excluded_globs=self.cfg.excluded_globs)

    # ------------------------------------------------------------ startup

    def _autoruns_store(self):
        return autoruns.AutorunsStore()

    def _startup_trusted(self):
        """Answers whether a startup item's target under the Windows folder
        may stay quiet, through the scanner's Authenticode checker; None
        where there is none, and then the system root alone keeps a change
        quiet. Only a signature that FAILS makes the change loud: most of
        Windows is catalogue-signed, which this checker cannot verify and
        reports as unsigned (11 of 30 System32 files verified, ROADMAP),
        and calling that untrusted would announce most updates. The panel
        asks on its worker; a check costs about 150 ms per cold file."""
        checker = self.scanner.signatures
        if not getattr(checker, "available", False):
            return None

        def trusted(target: str) -> bool:
            path = Path(target)
            stat = path.stat()
            return checker.check(path, stat.st_size, stat.st_mtime_ns).trust is not signing.Trust.UNTRUSTED
        return trusted

    def _startup_report(self, report) -> None:
        """After a snapshot from the tab: one banner for what is worth a look.
        Everything is in the tab and History whether or not it is announced.
        The panel's worker judged the changes; the checker is not asked
        again on this thread."""
        loud = report.loud
        if loud is None:
            trusted = self._startup_trusted()
            loud = [c for c in report.changes if c.worth_a_look(trusted=trusted)]
        if not loud:
            return
        first = loud[0].describe()
        more = f" and {len(loud) - 1} more" if len(loud) > 1 else ""
        self._banner(f"Startup change worth a look: {first}{more}. Nothing was changed; "
                     "see the Startup tab.", "inverse-warning")

    def _autoruns_ok(self) -> bool:
        store = self._autoruns_store()
        return not store.exists() or store.verify_integrity() == autoruns.INTEGRITY_OK

    def _describe_autoruns(self) -> str:
        _ok, text = autoruns.summarize(self._autoruns_store())
        if not self._autoruns_store().exists():
            return text + " (the Startup tab, or: avguard --autoruns-snapshot)"
        return text

    def _fim_ok(self) -> bool:
        """Red only when a baseline exists and its signature does not hold."""
        store = self._fim_store()
        return not store.exists() or store.verify_integrity() == fim_module.INTEGRITY_OK

    def _held_for_review(self) -> list:
        try:
            return self.quarantine.stale(self.cfg.quarantine_review_days)
        except (TypeError, ValueError):
            return []

    def _describe_quarantine_review(self) -> str:
        """The retention review the README promised: offered, never acted on.
        Nothing is deleted after any number of days; the store holds the
        only copy of everything in it."""
        days = self.cfg.quarantine_review_days
        if not isinstance(days, int) or days <= 0:
            return "off (quarantine_review_days is 0)"
        old = self._held_for_review()
        if not old:
            return f"nothing held longer than {days} days"
        return (f"{len(old)} file(s) held longer than {days} days: restore, export or delete "
                "them on the Quarantine tab. Nothing is deleted automatically.")

    def _offer_quarantine_review(self) -> None:
        """Once per start, quietly, and never over a louder banner."""
        if self._banner_is_loud() or not self._held_for_review():
            return
        self._banner(self._describe_quarantine_review(), "inverse-secondary")

    def _describe_quarantine_integrity(self) -> tuple[bool, str]:
        problem = self.quarantine.index_problem
        orphans = self.quarantine.orphaned_payloads()
        if problem:
            return False, problem + "; see the log"
        if orphans:
            return False, (f"{len(orphans)} stored file(s) have no record and cannot be decoded; "
                           "see the log")
        return True, "every stored file has a record"

    def _describe_fim(self) -> str:
        store = self._fim_store()
        _ok, text = fimpanel.summarize(store)
        if not store.exists():
            return text + " (the Integrity tab, or: avguard --fim-baseline <folder>)"
        return text + " Check it on the Integrity tab, or with: avguard --fim-check"

    def _packs_ok(self) -> bool:
        """Red if any pack is broken or has vanished from disk."""
        if self.scanner.broken_packs:
            return False
        return all(self.scanner.packs.rule_files_for(p.name)
                   for p in self.scanner.packs.packs())

    def _show_health(self) -> None:
        """Every row is something that has failed silently before."""
        rules_ok = self.scanner.rules is not None
        broken = self.monitor.broken_links()
        watching = not broken and bool(self.monitor.watched)
        workers = self.monitor.pool.alive_workers
        checks = [
            ("Detection rules", rules_ok, self._describe_rules() if rules_ok
             else "FAILED TO COMPILE - most detection is off. See the log."),
            ("Rule packs", self._packs_ok(), self._describe_packs()),
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
            ("Hash blocklist", True, self._describe_iocs()),
            ("Paste guard", *self._describe_paste_guard()),
            ("File integrity", self._fim_ok(), self._describe_fim()),
            ("Startup items", self._autoruns_ok(), self._describe_autoruns()),
            ("Event forwarding", True,
             f"on -> {self.forwarder.url}: {self.forwarder.describe()}"
             if self.forwarder is not None else "off - nothing is sent"),
            ("Right-click scan", True,
             "installed for this user" if shellext.installed() else "not installed"),
            ("Scan cache", True, f"{len(self.cache)} remembered verdict(s)"),
            ("Quarantine integrity", *self._describe_quarantine_integrity()),
            ("Quarantine review", True, self._describe_quarantine_review()),
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
            self.integrity.stop(timeout=5)
        except Exception:
            log.exception("error stopping the integrity worker")
        try:
            self.startup.stop(timeout=5)
        except Exception:
            log.exception("error stopping the startup snapshot")
        try:
            self.cache.save()
            self.cloud.save_cache()
            self.cfg.save()
        except Exception:
            log.exception("error saving state")
        if self.forwarder is not None:
            try:
                self.forwarder.stop()
            except Exception:
                pass
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
