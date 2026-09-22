"""Forwarding scan events to another program, without it ever being noticed.

AVGuard is the host layer and Network Watchdog is the network layer of one
home setup. The events store already records every detection; posting each
one to a URL is a small step that lets the two see each other. Off until a
URL is set, and setting one names exactly what leaves the machine: the file
path, the verdict, the rule names and the file's SHA-256.

The rule that shapes this module is the GUI pump's: the scan path must not
be able to see a dead or slow endpoint at all. So `submit()` puts the event
on a bounded queue and returns; a daemon thread does the posting with a
two-second timeout; a full queue drops the OLDEST event rather than block; a
failure is logged at debug level and forgotten. A scan runs at the same
speed with the watchdog down as with it up.
"""

from __future__ import annotations

import collections
import logging
import threading

log = logging.getLogger(__name__)

# The wire format. Every posted object is one Event (see events.py, whose
# comment freezes the field names as schema 1) plus this key.
SCHEMA = 1
DEFAULT_QUEUE_SIZE = 500
DEFAULT_TIMEOUT = 2.0


class EventForwarder:
    """POSTs events as JSON, from its own thread, dropping rather than waiting."""

    def __init__(self, url: str, session=None, queue_size: int = DEFAULT_QUEUE_SIZE,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self.url = url
        self.timeout = timeout
        self._session = session
        self._queue: collections.deque = collections.deque(maxlen=queue_size)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._in_flight = False
        self.sent = 0
        self.dropped = 0
        self.failed = 0
        self._thread = threading.Thread(target=self._run, name="avguard-forward", daemon=True)
        self._thread.start()

    # ------------------------------------------------------------ callers

    def submit(self, event: dict) -> None:
        """Queue one event. Never blocks, never raises to the caller."""
        payload = dict(event)
        payload["schema"] = SCHEMA
        with self._lock:
            if len(self._queue) == self._queue.maxlen:
                # deque(maxlen) discards the oldest on append; count it.
                self.dropped += 1
            self._queue.append(payload)
        self._wake.set()

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._queue) + (1 if self._in_flight else 0)

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """For tests: True once nothing is queued or in flight."""
        deadline = threading.Event()
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.pending == 0:
                return True
            deadline.wait(0.02)
        return self.pending == 0

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout)

    # ------------------------------------------------------------- worker

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=0.5)
            self._wake.clear()
            while not self._stop.is_set():
                with self._lock:
                    if not self._queue:
                        break
                    payload = self._queue.popleft()
                    self._in_flight = True
                try:
                    self._post(payload)
                finally:
                    with self._lock:
                        self._in_flight = False

    def _post(self, payload: dict) -> None:
        try:
            if self._session is None:
                import requests  # here, so a bare install without it still scans
                self._session = requests.Session()
            response = self._session.post(self.url, json=payload,
                                          timeout=(self.timeout, self.timeout))
            try:
                ok = 200 <= int(response.status_code) < 300
            finally:
                close = getattr(response, "close", None)
                if close:
                    close()
        except Exception as exc:  # anything at all: the scan must not care
            self.failed += 1
            log.debug("event not forwarded to %s: %s", self.url, exc)
            return
        if ok:
            self.sent += 1
        else:
            self.failed += 1
            log.debug("event not accepted by %s: HTTP %s", self.url, response.status_code)

    def describe(self) -> str:
        return f"{self.sent} sent, {self.dropped} dropped, {self.failed} failed"
