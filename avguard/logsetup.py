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
import queue
import sys
import threading
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


def configure(gui_queue: queue.Queue | None = None, level: int = logging.INFO) -> logging.Logger:
    """Set up the `avguard` logger. Safe to call more than once."""
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("avguard")
    logger.setLevel(level)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    file_handler = RotatingFileHandler(
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
