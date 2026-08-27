"""Real-time monitoring: watch, debounce, queue, then scan on worker threads.

The original build called scan_file directly from watchdog's dispatch thread,
and that scan made a blocking network request. Two things followed. Events
piled up behind every scan, and because writing to antivirus_log.txt was
itself a filesystem event inside the watched tree, each scan produced the
event that triggered the next one. The log in this project has 2021 lines of
that loop.

Here the observer thread only records a path. A debouncer collapses the burst
of events a single file save produces, and a small pool of worker threads does
the actual scanning.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .protection import SelfProtection
from .scanner import Scanner, Verdict

log = logging.getLogger(__name__)


class Debouncer:
    """Collapses repeated events for the same path into one call.

    Saving a file in an editor typically produces several modify events plus a
    rename. Without this the scanner runs three or four times per save.
    """

    def __init__(self, delay: float, sink: Callable[[Path], None]) -> None:
        self.delay = delay
        self._sink = sink
        self._pending: dict[Path, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="avguard-debounce", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def touch(self, path: Path) -> None:
        with self._lock:
            self._pending[path] = time.monotonic() + self.delay

    def _run(self) -> None:
        while not self._stop.wait(0.25):
            now = time.monotonic()
            with self._lock:
                due = [p for p, deadline in self._pending.items() if deadline <= now]
                for path in due:
                    del self._pending[path]
            for path in due:
                try:
                    self._sink(path)
                except Exception:
                    log.exception("debounced dispatch failed for %s", path)


class ScanWorkerPool:
    """A bounded queue drained by a fixed number of scanning threads."""

    def __init__(
        self,
        scanner: Scanner,
        on_verdict: Callable[[Verdict], None],
        workers: int = 4,
        max_queued: int = 2000,
    ) -> None:
        self.scanner = scanner
        self.on_verdict = on_verdict
        self.workers = max(1, workers)
        self._max_queued = max_queued
        self._queue: queue.Queue[Path | None] = queue.Queue(maxsize=max_queued)
        self._threads: list[threading.Thread] = []
        self._running = threading.Event()
        self._lifecycle = threading.Lock()
        self._dropped = 0

    def start(self) -> None:
        """Start the workers. Safe to call again after `stop()`.

        The queue is rebuilt rather than reused. A worker that exits without
        consuming its sentinel would otherwise leave a `None` behind, and the
        first worker of the next run would swallow it and exit immediately --
        giving a pool that accepts work and scans nothing while the interface
        says protection is on. That is v1's failure shape, so the restart path
        is made structurally incapable of it rather than merely tested.
        """
        with self._lifecycle:
            if self._threads:
                return
            self._queue = queue.Queue(maxsize=self._max_queued)
            self._running.set()
            for index in range(self.workers):
                thread = threading.Thread(
                    target=self._run, name=f"avguard-scan-{index}", daemon=True
                )
                thread.start()
                self._threads.append(thread)

    def stop(self, timeout: float = 5.0) -> None:
        with self._lifecycle:
            self._running.clear()
            for _ in self._threads:
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    pass
            deadline = time.monotonic() + timeout
            for thread in self._threads:
                thread.join(timeout=max(0.1, deadline - time.monotonic()))
            still_alive = [t for t in self._threads if t.is_alive()]
            if still_alive:
                log.warning("%d scan worker(s) did not stop within %.0fs",
                            len(still_alive), timeout)
            self._threads.clear()

    @property
    def running(self) -> bool:
        """True only if workers actually exist and are alive.

        Checked by the health view: 'real-time protection is on' must mean
        something is able to scan, not merely that an observer thread exists.
        """
        return bool(self._threads) and any(t.is_alive() for t in self._threads)

    @property
    def alive_workers(self) -> int:
        return sum(1 for t in self._threads if t.is_alive())

    def submit(self, path: Path) -> bool:
        """Queue a path. Returns False if the queue is full.

        Dropping is deliberate: a full queue means events are arriving faster
        than they can be scanned, and blocking here would stall the watcher.
        Anything dropped is still caught by the next full scan.
        """
        try:
            self._queue.put_nowait(path)
            return True
        except queue.Full:
            self._dropped += 1
            if self._dropped % 100 == 1:
                log.warning("scan queue full; %d event(s) dropped so far", self._dropped)
            return False

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    def _run(self) -> None:
        while self._running.is_set():
            try:
                path = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if path is None:
                self._queue.task_done()
                break
            try:
                verdict = self.scanner.scan(path)
                self.on_verdict(verdict)
            except Exception:
                log.exception("scan worker failed on %s", path)
            finally:
                self._queue.task_done()


class _Handler(FileSystemEventHandler):
    """Records paths. Does no work of its own, so dispatch never blocks."""

    def __init__(self, protection: SelfProtection, touch: Callable[[Path], None]) -> None:
        self.protection = protection
        self._touch = touch

    def _record(self, raw_path: str) -> None:
        path = Path(raw_path)
        # Checked here as well as in the scanner so our own writes -- log
        # rotation, cache saves, the quarantine index -- never even reach the
        # queue. This is what breaks the scan/log/scan feedback loop.
        if self.protection.is_protected(path):
            return
        self._touch(path)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(getattr(event, "dest_path", event.src_path))


class RealtimeMonitor:
    """Owns the observer, the debouncer and the worker pool as one unit."""

    def __init__(
        self,
        scanner: Scanner,
        protection: SelfProtection,
        on_verdict: Callable[[Verdict], None],
        workers: int = 4,
        debounce_seconds: float = 1.5,
    ) -> None:
        self.scanner = scanner
        self.protection = protection
        self.pool = ScanWorkerPool(scanner, on_verdict, workers=workers)
        self.debouncer = Debouncer(debounce_seconds, self.pool.submit)
        self._observer: Observer | None = None
        self._watched: list[Path] = []

    @property
    def running(self) -> bool:
        """Both halves must be alive.

        An observer thread with no live workers still reported "on" while
        nothing was being scanned. Saying protection is running has to mean
        something can actually scan.
        """
        observing = self._observer is not None and self._observer.is_alive()
        return observing and self.pool.running

    @property
    def watched(self) -> list[Path]:
        return list(self._watched)

    def start(self, paths: list[Path]) -> list[Path]:
        """Begin watching. Returns the paths actually being watched."""
        if self.running:
            return self._watched

        self.pool.start()
        self.debouncer.start()

        handler = _Handler(self.protection, self.debouncer.touch)
        self._observer = Observer()
        self._watched = []

        for path in paths:
            path = Path(path)
            if not path.is_dir():
                log.warning("cannot watch %s: not a directory", path)
                continue
            try:
                self._observer.schedule(handler, str(path), recursive=True)
                self._watched.append(path)
            except OSError as exc:
                log.error("cannot watch %s: %s", path, exc)

        if not self._watched:
            self.stop()
            return []

        self._observer.start()
        log.info("real-time monitoring started on: %s",
                 ", ".join(str(p) for p in self._watched))
        return self._watched

    def stop(self) -> None:
        """Shut everything down in order, and actually join the threads.

        The old build never stopped its observer at all; it also called
        .stop() on an attribute that was always None, so exit left a live
        watchdog thread behind.
        """
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self.debouncer.stop()
        self.pool.stop()
        self._watched = []
        log.info("real-time monitoring stopped")
