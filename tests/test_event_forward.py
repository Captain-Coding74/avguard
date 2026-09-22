"""Event forwarding: delivered when it can be, dropped when it cannot, never felt.

The property that matters is the last one. A dead or slow endpoint must not
be visible in scan behaviour at all: record() returns at once, the queue is
bounded and drops the oldest, failures are debug-level noise.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolate the data directory BEFORE avguard is imported.
import os as _os
import tempfile as _tempfile

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-test-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)


def _remove_tree(path) -> None:
    """rmtree that copes with read-only files."""
    import shutil as _shutil
    import stat as _stat

    def writable_then(func, target, _exc):
        try:
            _os.chmod(target, _stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    _shutil.rmtree(path, onexc=writable_then)


if _os.environ["AVGUARD_DATA"] == _test_data:
    import atexit as _atexit
    _atexit.register(_remove_tree, _test_data)


from avguard import config, forward
from avguard.events import Event, EventStore
from avguard.forward import EventForwarder

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False


class Receiver:
    """An HTTP server on 127.0.0.1 that keeps every POST body."""

    def __init__(self) -> None:
        self.bodies: list[dict] = []
        self.lock = threading.Lock()
        bodies, lock = self.bodies, self.lock

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                with lock:
                    bodies.append(json.loads(raw.decode("utf-8")))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/events"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ForwardCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="avguard-fwd-"))
        self.addCleanup(_remove_tree, self.tmp)

    def forwarder(self, url: str, **kwargs) -> EventForwarder:
        fwd = EventForwarder(url, **kwargs)
        self.addCleanup(fwd.stop)
        return fwd


class TestDelivery(ForwardCase):
    def test_every_recorded_event_arrives_with_schema_one(self):
        receiver = Receiver()
        self.addCleanup(receiver.stop)
        fwd = self.forwarder(receiver.url)
        store = EventStore(path=self.tmp / "events.jsonl", forwarder=fwd)
        for index in range(5):
            store.record(Event(kind="detection", path=f"C:\\\\x\\\\f{index}.exe",
                               level="malicious", score=100, reasons=["signature X"],
                               detail={"sha256": "ab" * 32}))
        self.assertTrue(fwd.wait_idle(10), "events never finished posting")

        on_disk = [json.loads(line) for line in
                   (self.tmp / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        with receiver.lock:
            received = list(receiver.bodies)
        self.assertEqual(len(received), 5)
        for disk, wire in zip(on_disk, received):
            self.assertEqual(wire["schema"], forward.SCHEMA)
            for key in ("kind", "at", "path", "level", "score", "reasons", "detail"):
                self.assertEqual(wire[key], disk[key], key)
        self.assertEqual(fwd.sent, 5)
        self.assertEqual((fwd.dropped, fwd.failed), (0, 0))

    def test_a_store_without_a_forwarder_is_unchanged(self):
        store = EventStore(path=self.tmp / "events.jsonl")
        store.record(Event(kind="health", reasons=["ok"]))
        self.assertEqual(len(store.read()), 1)
        self.assertIsNone(store.forwarder)


class TestNothingReachesTheScanPath(ForwardCase):
    def test_a_full_queue_drops_the_oldest(self):
        gate = threading.Event()

        class BlockingSession:
            posted: list[dict] = []

            def post(self, url, json=None, timeout=None):
                gate.wait(20)
                BlockingSession.posted.append(json)
                return type("R", (), {"status_code": 204, "close": lambda self: None})()

        BlockingSession.posted = []
        fwd = self.forwarder("http://127.0.0.1:1/x", session=BlockingSession(), queue_size=500)
        fwd.submit({"kind": "t", "detail": {"id": 0}})
        for _ in range(500):                      # until the worker holds item 0
            if fwd._in_flight:
                break
            time.sleep(0.01)
        self.assertTrue(fwd._in_flight, "the worker never took the first event")
        started = time.perf_counter()
        for index in range(1, 601):
            fwd.submit({"kind": "t", "detail": {"id": index}})
        took = time.perf_counter() - started
        self.assertLess(took, 1.0, "submit() waited on the blocked endpoint")
        self.assertEqual(fwd.dropped, 100)
        gate.set()
        self.assertTrue(fwd.wait_idle(20))
        ids = sorted(p["detail"]["id"] for p in BlockingSession.posted)
        self.assertEqual(ids[0], 0, "the one in flight is delivered")
        self.assertEqual(ids[1:], list(range(101, 601)), "the newest 500 are kept")
        self.assertEqual(fwd.sent, 501)

    def test_a_dead_endpoint_changes_nothing(self):
        # Measured: a closed local port does not refuse on this Windows; the
        # connect runs to its full timeout. So the worker drains a dead
        # endpoint at one event per timeout, which the caller never feels.
        fwd = self.forwarder(f"http://127.0.0.1:{closed_port()}/events", timeout=0.1)
        store = EventStore(path=self.tmp / "events.jsonl", forwarder=fwd)
        started = time.perf_counter()
        for index in range(40):
            store.record(Event(kind="detection", path=f"f{index}", level="clean"))
        per_call = (time.perf_counter() - started) / 40
        self.assertLess(per_call, 0.05, f"record() took {per_call * 1000:.0f} ms with a dead endpoint")
        self.assertEqual(len(store.read()), 40, "the history must still be written")
        self.assertTrue(fwd.wait_idle(30))
        self.assertEqual(fwd.sent, 0)
        self.assertEqual(fwd.failed + fwd.dropped, 40)

    def test_a_scan_is_not_affected_by_forwarding(self):
        from avguard import scanner as scanner_module
        from avguard.allowlist import Allowlist
        from avguard.protection import SelfProtection
        from avguard.rulepacks import PackStore
        from avguard.scanner import Level, ScanCache, Scanner
        fwd = self.forwarder(f"http://127.0.0.1:{closed_port()}/events", timeout=0.5)
        store = EventStore(path=self.tmp / "events.jsonl", forwarder=fwd)
        scanner = Scanner(config.Config(cloud_enabled=False),
                          SelfProtection([self.tmp / "nothing"]),
                          cache=ScanCache(path=self.tmp / "c.json"),
                          packs=PackStore(directory=self.tmp / "packs",
                                          index_path=self.tmp / "packs" / "packs.json"),
                          allowlist=Allowlist(path=self.tmp / "allow.json"))
        sample = self.tmp / "plain.txt"
        sample.write_bytes(b"nothing here " * 20)
        verdict = scanner.scan(sample, use_cache=False)
        store.record(Event(kind="scan_finished", detail={"level": verdict.level.value}))
        self.assertIs(verdict.level, Level.CLEAN)

    def test_the_default_is_off(self):
        self.assertEqual(config.Config().event_forward_url, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
