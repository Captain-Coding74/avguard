"""Logging: one rotating file, plus a bounded feed for the GUI.

The original build had two half-finished logging paths. main.py created
antivirus_log.txt and then never wrote to it, while engine.py appended to it
on every message from whatever thread happened to be running. Because that
file sat inside the watched directory, each write produced a filesystem event
that triggered another scan.

Here logs go to data/logs, which is a protected directory, so writing a log
line can never cause a scan.
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import config

FILE_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
GUI_FORMAT = "%(asctime)s  %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

MAX_BYTES = 1024 * 1024
BACKUP_COUNT = 3


class QueueLogHandler(logging.Handler):
    """Feeds formatted lines to the GUI through a bounded queue.

    Bounded on purpose: if something starts logging in a tight loop, old lines
    are dropped rather than growing the queue until the process runs out of
    memory. The GUI is a view, not the record of what happened -- the file is.
    """

    def __init__(self, sink: queue.Queue, maxsize: int = 5000):
        super().__init__()
        self.sink = sink
        self.maxsize = maxsize

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
        except Exception:
            return
        try:
            self.sink.put_nowait((record.levelno, message))
        except queue.Full:
            try:
                self.sink.get_nowait()          # drop the oldest
                self.sink.put_nowait((record.levelno, message))
            except (queue.Empty, queue.Full):
                pass


class SharedRotatingFileHandler(RotatingFileHandler):
    """A rotating log that several AVGuard processes write at once: the
    window, a right-click scan, the daily tasks.

    On Windows a file another process holds open cannot be renamed. The
    standard rollover shifts the backups first and renames the live file
    last, so with a second process attached it failed on every record once
    the log passed MAX_BYTES: each attempt deleted the oldest backup and
    lost the record (simulated: three records, all lost, two backups gone).
    Here the live file is moved first. If it cannot be, nothing is shifted,
    the record is written to the live file anyway, and rotation is tried
    again a minute later."""

    RETRY_SECONDS = 60.0

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._blocked_until = 0.0

    def shouldRollover(self, record) -> bool:
        if time.monotonic() < self._blocked_until:
            return False
        return bool(super().shouldRollover(record))

    def doRollover(self) -> None:
        if self.stream:
            self.stream.close()
            self.stream = None
        moving = self.baseFilename + ".rotating"
        try:
            os.replace(self.baseFilename, moving)
        except OSError:
            self._blocked_until = time.monotonic() + self.RETRY_SECONDS
            if not self.delay:
                self.stream = self._open()
            return
        for index in range(self.backupCount - 1, 0, -1):
            older = self.rotation_filename(f"{self.baseFilename}.{index}")
            if os.path.exists(older):
                try:
                    os.replace(older, self.rotation_filename(f"{self.baseFilename}.{index + 1}"))
                except OSError:
                    pass
        try:
            os.replace(moving, self.rotation_filename(self.baseFilename + ".1"))
        except OSError:
            pass                       # kept as .rotating; nothing is lost
        if not self.delay:
            self.stream = self._open()


def configure(gui_queue: queue.Queue | None = None, level: int = logging.INFO) -> logging.Logger:
    """Set up the `avguard` logger. Safe to call more than once."""
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("avguard")
    logger.setLevel(level)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    file_handler = SharedRotatingFileHandler(
        config.LOG_DIR / "avguard.log",
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(FILE_FORMAT, DATE_FORMAT))
    logger.addHandler(file_handler)

    if gui_queue is not None:
        gui_handler = QueueLogHandler(gui_queue)
        gui_handler.setFormatter(logging.Formatter(GUI_FORMAT, DATE_FORMAT))
        logger.addHandler(gui_handler)

    return logger


def close_file_handlers() -> None:
    """Close the log file.

    A command-line verb that returns without doing this holds the file open
    until the interpreter exits. test_cli left a directory behind for every
    test that way, deletable only once the next test's configure() had
    closed the previous handler.
    """
    logger = logging.getLogger("avguard")
    for handler in list(logger.handlers):
        if isinstance(handler, RotatingFileHandler):
            logger.removeHandler(handler)
            handler.close()


def log_path() -> Path:
    return config.LOG_DIR / "avguard.log"


def install_excepthooks() -> None:
    """Send otherwise-unhandled exceptions to the log file.

    Under pythonw.exe there is no console, so a traceback printed to stderr
    goes nowhere at all: the user double-clicks, nothing appears, and there is
    no record of why. These hooks make sure the last thing a dying process
    does is write down what killed it.
    """
    logger = logging.getLogger("avguard")

    previous = sys.excepthook

    def handle(exc_type, exc, tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            previous(exc_type, exc, tb)
            return
        logger.critical("unhandled exception", exc_info=(exc_type, exc, tb))
        previous(exc_type, exc, tb)

    sys.excepthook = handle

    def handle_thread(args) -> None:
        if issubclass(args.exc_type, SystemExit):
            return
        logger.critical("unhandled exception in thread %s",
                        getattr(args.thread, "name", "?"),
                        exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

    threading.excepthook = handle_thread
