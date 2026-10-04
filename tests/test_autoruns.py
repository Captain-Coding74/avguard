"""What starts with Windows (avguard/autoruns.py): the collectors against a
dict-backed registry and a schtasks fixture, the diff rules, the signed
store, and what deserves a banner. On the Windows runner the collectors also
run for real and two snapshots seconds apart must differ in nothing.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os as _os
import sys
import tempfile as _tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-autoruns-data-{_os.getpid()}")
_os.environ.setdefault("AVGUARD_DATA", _test_data)
if _os.environ["AVGUARD_DATA"] == _test_data:
    import atexit as _atexit
    import shutil as _shutil
    _atexit.register(lambda: _shutil.rmtree(_test_data, ignore_errors=True))

from avguard import autoruns
from avguard.autoruns import Entry, diff
from avguard.events import EventStore

FIXTURE = Path(__file__).resolve().parent / "autoruns" / "schtasks.xml"
BS = chr(92)
ROOT = "C:" + BS + "Windows"


def stub_protect(data: bytes) -> bytes:
    return b"STUB!" + data[::-1]


def stub_unprotect(blob: bytes) -> bytes:
    if not blob.startswith(b"STUB!"):
        raise OSError("not a protected blob")
    return blob[5:][::-1]


class FakeKey:
    def __init__(self, path: str) -> None:
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeRegistry:
    """Enough of winreg to read keys and values, in two views, with its errors."""

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    KEY_WOW64_32KEY = 0x0200
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4

    def __init__(self) -> None:
        self.keys: dict[str, dict[str, tuple[object, int]]] = {}
        self.spelling: dict[str, str] = {}        # lower-cased path -> as it was written

    @staticmethod
    def _path(root, sub_key: str, view: int = 0) -> str:
        base = root if isinstance(root, str) else root.path
        tag = "|32" if view & 0x0200 else ""
        return (f"{base}{BS}{sub_key}" if sub_key else base).lower() + tag

    def put(self, root: str, sub_key: str, name: str, data, kind: int = 1, view: int = 0) -> None:
        path = self._path(root, sub_key, view)
        spelled = f"{root}{BS}{sub_key}".split(BS)
        parts = path.split("|")[0].split(BS)
        for depth in range(1, len(parts) + 1):
            lowered = BS.join(parts[:depth])
            self.keys.setdefault(lowered + ("|32" if view & 0x0200 else ""), {})
            self.spelling.setdefault(lowered, BS.join(spelled[:depth]))
        self.keys[path][name] = (data, kind)

    def OpenKey(self, root, sub_key, reserved=0, access=0):
        path = self._path(root, sub_key, access)
        if path not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified", path)
        return FakeKey(path)

    def EnumValue(self, key, index):
        items = list(self.keys[key.path].items())
        if index >= len(items):
            raise OSError(259, "No more data is available")
        name, (data, kind) = items[index]
        return name, data, kind

    def EnumKey(self, key, index):
        prefix = key.path.split("|")[0] + BS
        children = sorted({other[len(prefix):].split(BS)[0] for other in self.keys
                           if other.startswith(prefix) and "|" not in other})
        if index >= len(children):
            raise OSError(259, "No more data is available")
        return self.spelling[prefix + children[index]].rsplit(BS, 1)[-1]   # the registry keeps the case

    def CloseKey(self, key):
        pass


def populated_registry() -> FakeRegistry:
    reg = FakeRegistry()
    run = autoruns.RUN_KEYS[0]
    reg.put("HKCU", run, "OneDrive", "C:" + BS + "Users" + BS + "me" + BS + "OneDrive.exe /background")
    reg.put("HKCU", autoruns.RUN_KEYS[1], "", "", kind=1)       # an empty RunOnce value: skipped
    reg.put("HKLM", run, "SecurityHealth", "%windir%" + BS + "system32" + BS + "SecurityHealthSystray.exe",
            kind=2, view=0x0100)
    reg.put("HKLM", run, "Vendor Updater", "C:" + BS + "Program Files (x86)" + BS + "Vendor" + BS + "upd.exe",
            view=0x0200)
    reg.put("HKCU", autoruns.APPROVED_RUN, "OneDrive", bytes([3, 0, 0, 0, 0, 0, 0, 0]), kind=3)
    services = autoruns.SERVICES_KEY
    reg.put("HKLM", services + BS + "Dhcp", "ImagePath",
            "%SystemRoot%" + BS + "system32" + BS + "svchost.exe -k LocalServiceNetworkRestricted", kind=2)
    reg.put("HKLM", services + BS + "Dhcp", "Start", 2, kind=4)
    reg.put("HKLM", services + BS + "Dhcp", "Type", 32, kind=4)
    reg.put("HKLM", services + BS + "Dhcp", "DisplayName", "DHCP Client")
    reg.put("HKLM", services + BS + "evildrv", "ImagePath",
            BS + "??" + BS + "C:" + BS + "Users" + BS + "me" + BS + "AppData" + BS + "Local" + BS + "Temp" + BS + "evildrv.sys")
    reg.put("HKLM", services + BS + "evildrv", "Start", 1, kind=4)
    reg.put("HKLM", services + BS + "evildrv", "Type", 1, kind=4)
    reg.put("HKLM", services + BS + "Dhcp" + BS + "Parameters", "ServiceDll", "dhcpcore.dll", kind=2)
    reg.put("HKLM", services + BS + "NoImage", "Start", 3, kind=4)   # no ImagePath: not an entry
    return reg


def fixture_runner(encoding: str = "utf-16"):
    text = FIXTURE.read_text(encoding="utf-8")
    return lambda: text.encode(encoding)


class AutorunsCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(_tempfile.mkdtemp(prefix="avguard-autoruns-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.registry = populated_registry()
        self.startup = self.tmp / "Startup"
        self.startup.mkdir()
        (self.startup / "desktop.ini").write_text("[.ShellClassInfo]", encoding="utf-8")
        (self.startup / "Sync.lnk").write_bytes(b"L\x00\x00\x00shortcut bytes")
        self.folders = [("user", self.startup), ("all users", self.tmp / "no-such-folder")]
        self.store = autoruns.AutorunsStore(self.tmp / "autoruns", key_protect=stub_protect,
                                            key_unprotect=stub_unprotect)
        self.events = EventStore(path=self.tmp / "events.jsonl")
        self._old_root = _os.environ.get("SystemRoot")
        _os.environ["SystemRoot"] = ROOT
        _os.environ["windir"] = ROOT
        self.addCleanup(self._restore_root)

    def _restore_root(self) -> None:
        if self._old_root is None:
            _os.environ.pop("SystemRoot", None)
        else:
            _os.environ["SystemRoot"] = self._old_root

    def collect(self, registry=None, runner=None) -> autoruns.Collected:
        return autoruns.collect(registry=registry or self.registry, startup_folders=self.folders,
                                schtasks_runner=runner or fixture_runner())


# ------------------------------------------------------------- collectors

class TestTheCollectors(AutorunsCase):
    def test_run_keys_in_both_views_with_task_managers_disabled_flag(self):
        entries = autoruns.collect_run_keys(self.registry)
        by_name = {e.name: e for e in entries}
        self.assertEqual(set(by_name), {"OneDrive", "SecurityHealth", "Vendor Updater"},
                         "an empty RunOnce value is not an entry")
        self.assertFalse(by_name["OneDrive"].enabled, "Task Manager's Startup page turned it off")
        self.assertTrue(by_name["SecurityHealth"].enabled)
        self.assertIn("(32-bit)", by_name["Vendor Updater"].location)
        self.assertTrue(by_name["SecurityHealth"].location.startswith("HKLM"))
        self.assertEqual(by_name["SecurityHealth"].target, ROOT + BS + "system32" + BS + "SecurityHealthSystray.exe")

    def test_services_and_drivers_from_the_registry(self):
        entries = autoruns.collect_services(self.registry)
        by_name = {e.name: e for e in entries}
        self.assertEqual(set(by_name), {"Dhcp", "evildrv"}, "a key with no ImagePath is not a service")
        self.assertEqual(by_name["Dhcp"].extra, "start automatic; type shared process")
        self.assertEqual(by_name["Dhcp"].detail["display_name"], "DHCP Client")
        self.assertEqual(by_name["evildrv"].extra, "start system; type kernel driver")
        self.assertEqual(by_name["evildrv"].target, "C:" + BS + "Users" + BS + "me" + BS + "AppData" + BS
                         + "Local" + BS + "Temp" + BS + "evildrv.sys")
        self.registry.put("HKLM", autoruns.SERVICES_KEY + BS + "Dhcp", "Start", 4, kind=4)
        self.assertFalse({e.name: e for e in autoruns.collect_services(self.registry)}["Dhcp"].enabled)

    def test_startup_folders_hash_their_files_and_skip_desktop_ini(self):
        errors: list[str] = []
        entries = autoruns.collect_startup_folders(self.folders, self.registry, errors)
        self.assertEqual([e.name for e in entries], ["Sync.lnk"])
        self.assertEqual(errors, [], "a missing folder is not an error")
        self.assertTrue(entries[0].extra.startswith("sha256 "))
        self.assertEqual(entries[0].location, "Startup (user)")
        (self.startup / "Sync.lnk").write_bytes(b"L\x00\x00\x00different target")
        changed = autoruns.collect_startup_folders(self.folders, self.registry)
        self.assertNotEqual(changed[0].fingerprint, entries[0].fingerprint, "a rewritten shortcut counts")

    def test_tasks_from_the_schtasks_fixture(self):
        errors: list[str] = []
        entries = autoruns.collect_tasks(fixture_runner(), errors)
        self.assertEqual(errors, [])
        by_name = {e.name: e for e in entries}
        self.assertEqual(set(by_name), {"ScheduledDefrag", "Updater"})
        defrag = by_name["ScheduledDefrag"]
        self.assertEqual(defrag.location, BS + "Microsoft" + BS + "Windows" + BS + "Defrag")
        self.assertEqual(defrag.value, "%windir%" + BS + "system32" + BS + "defrag.exe -c -h -o -$")
        self.assertTrue(defrag.enabled)
        self.assertIn("CalendarTrigger@2020-01-01T01:00:00", defrag.extra)
        self.assertIn("HighestAvailable", defrag.extra)
        self.assertEqual(defrag.detail["author"], "Microsoft Corporation")
        self.assertEqual(defrag.target, ROOT + BS + "system32" + BS + "defrag.exe")
        updater = by_name["Updater"]
        self.assertEqual(updater.location, BS)
        self.assertFalse(updater.enabled)
        self.assertIn("LogonTrigger", updater.extra)
        self.assertIn("TimeTrigger@2026-10-01T09:00:00/PT10M", updater.extra)

    def test_the_date_and_description_are_not_counted_but_the_action_is(self):
        text = FIXTURE.read_text(encoding="utf-8")
        before = autoruns.parse_tasks(text)
        later = autoruns.parse_tasks(text.replace("2026-10-01T09:00:00</Date>", "2026-10-03T09:00:00</Date>")
                                     .replace("optimizes local", "defragments local"))
        self.assertEqual(diff(before, later), [], "a date or a description is not a change")
        changed = autoruns.parse_tasks(text.replace("upd.exe</Command>", "upd2.exe</Command>"))
        self.assertEqual([(c.kind, c.entry.name) for c in diff(before, changed)], [("modified", "Updater")])

    def test_a_task_whose_cdata_holds_a_task_element_is_still_read(self):
        """The Windows runner's Performance Monitor task: its ComHandler Data is
        a data-collector definition in CDATA with <Task></Task> inside, and a
        splitter that cut at the first </Task> reported it unreadable."""
        text = FIXTURE.read_text(encoding="utf-8")
        pla = ('<!-- ' + BS + 'Microsoft' + BS + 'Windows' + BS + 'PLA' + BS + 'Server Manager Performance Monitor -->\n'
               '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
               '<Settings><Enabled>true</Enabled></Settings>'
               '<Actions><ComHandler><ClassId>{abc}</ClassId><Data><![CDATA[<DataCollectorSet>'
               '<Task></Task><TaskArguments>-x</TaskArguments></DataCollectorSet>]]></Data></ComHandler></Actions>'
               '</Task>\n')
        errors: list[str] = []
        entries = autoruns.parse_tasks(text.replace("</Tasks>", pla + "</Tasks>"), errors)
        self.assertEqual(errors, [])
        self.assertEqual(len(entries), 3)
        pla_entry = next(e for e in entries if e.name == "Server Manager Performance Monitor")
        self.assertTrue(pla_entry.value.startswith("COM {abc}"))
        self.assertIn("<Task></Task>", pla_entry.value, "the data is kept as the action's text")
        broken = autoruns.parse_tasks(text.replace("</Settings>", "</Setting>", 1), errors)
        self.assertEqual(len(broken), 1)
        self.assertTrue(any("unreadable XML" in e for e in errors))

    def test_console_output_is_decoded_whatever_its_encoding(self):
        text = FIXTURE.read_text(encoding="utf-8")
        for encoding in ("utf-16", "utf-8-sig", "utf-8", "cp1252"):
            with self.subTest(encoding=encoding):
                decoded = autoruns.decode_console(text.encode(encoding))
                self.assertEqual(len(autoruns.parse_tasks(decoded)), 2)

    def test_a_failing_collector_does_not_take_the_others_down(self):
        def broken() -> bytes:
            raise OSError("schtasks is not here")
        collected = self.collect(runner=broken)
        self.assertEqual(collected.counts[autoruns.KIND_TASK], 0)
        self.assertTrue(any("schtasks could not be run" in e for e in collected.errors))
        self.assertEqual(collected.counts[autoruns.KIND_SERVICE], 2)
        self.assertEqual(set(collected.seconds), set(autoruns.KINDS), "every collector is timed")

    @unittest.skipIf(sys.platform == "win32", "off Windows there is no winreg to fall back to")
    def test_no_registry_means_no_registry_entries_and_no_error(self):
        self.assertEqual(autoruns.collect_run_keys(registry=None), [])
        self.assertEqual(autoruns.collect_services(registry=None), [])
        collected = autoruns.collect(registry=None, startup_folders=self.folders,
                                     schtasks_runner=fixture_runner())
        self.assertEqual((collected.counts["run"], collected.counts["service"], collected.counts["task"]),
                         (0, 0, 2))


# ------------------------------------------------------------------ diff

class TestTheDiff(unittest.TestCase):
    def entry(self, **kw) -> Entry:
        base = dict(kind="run", location="HKCU" + BS + "Run", name="App", value="C:" + BS + "app.exe",
                    enabled=True, extra="", detail={})
        base.update(kw)
        return Entry(**base)

    def test_identical_snapshots_differ_in_nothing(self):
        self.assertEqual(diff([self.entry()], [self.entry(detail={"x": 1})]), [])

    def test_added_modified_and_removed_in_that_order(self):
        before = [self.entry(), self.entry(name="Old")]
        after = [self.entry(value="C:" + BS + "other.exe"), self.entry(name="New")]
        kinds = [(c.kind, c.entry.name) for c in diff(before, after)]
        self.assertEqual(kinds, [("added", "New"), ("modified", "App"), ("removed", "Old")])
        changed = diff(before, after)[1]
        self.assertEqual(changed.old.value, "C:" + BS + "app.exe")
        self.assertIn("CHANGED", changed.describe())
        self.assertIn("app.exe -> ", changed.describe())

    def test_enabled_and_extra_count_and_names_compare_without_case(self):
        self.assertEqual(diff([self.entry()], [self.entry(name="APP")]), [])
        self.assertEqual([c.kind for c in diff([self.entry()], [self.entry(enabled=False)])], ["modified"])
        self.assertIn("disabled", diff([self.entry()], [self.entry(enabled=False)])[0].describe())
        self.assertEqual([c.kind for c in diff([self.entry()], [self.entry(extra="start manual")])], ["modified"])

    def test_the_event_names_the_target_and_carries_old_and_new(self):
        change = diff([self.entry()], [self.entry(value='"C:' + BS + 'new app.exe" /q')])[0]
        event = change.as_event()
        self.assertEqual((event.kind, event.level), ("autoruns", "modified"))
        self.assertEqual(event.path, "C:" + BS + "new app.exe")
        self.assertEqual(event.detail["old"]["value"], "C:" + BS + "app.exe")
        self.assertEqual(event.reasons, [change.describe()])


# ----------------------------------------------------------- worth a look

class TestWhatDeservesABanner(unittest.TestCase):
    def change(self, value: str, kind: str = "added") -> autoruns.Change:
        return autoruns.Change(kind, Entry("run", "HKLM" + BS + "Run", "X", value))

    def test_a_trusted_program_under_the_system_root_is_quiet(self):
        inside = self.change(ROOT + BS + "System32" + BS + "svchost.exe -k x")
        outside = self.change("C:" + BS + "Users" + BS + "me" + BS + "AppData" + BS + "x.exe")
        self.assertFalse(inside.worth_a_look(ROOT), "no checker: the system root alone is quiet")
        self.assertTrue(outside.worth_a_look(ROOT))
        self.assertFalse(inside.worth_a_look(ROOT, trusted=lambda t: True))
        self.assertTrue(inside.worth_a_look(ROOT, trusted=lambda t: False), "unsigned under the root is loud")
        self.assertTrue(outside.worth_a_look(ROOT, trusted=lambda t: True), "outside the root is loud even if signed")

    def test_removed_and_unreadable_targets(self):
        self.assertFalse(self.change(ROOT + BS + "a.exe", kind="removed").worth_a_look(ROOT))
        self.assertTrue(self.change("").worth_a_look(ROOT), "no target: nothing vouches for it")

        def broken(target: str) -> bool:
            raise OSError("no signature API")
        self.assertTrue(self.change(ROOT + BS + "a.exe").worth_a_look(ROOT, trusted=broken))


# ----------------------------------------------------------------- store

class TestTheStore(AutorunsCase):
    def test_the_first_snapshot_compares_with_nothing_and_records_no_event(self):
        report = self.store.snapshot(self.collect(), events=self.events)
        self.assertTrue(report.first)
        self.assertEqual(report.changes, [])
        self.assertEqual(report.snapshot.entries, 8)
        self.assertEqual(self.events.read(kinds={"autoruns"}), [])
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_OK)
        self.assertIn("first snapshot", autoruns.describe_report(report))

    def test_the_second_snapshot_shows_only_what_is_new(self):
        self.store.snapshot(self.collect(), events=self.events)
        self.registry.put("HKCU", autoruns.RUN_KEYS[0], "Dropper", "C:" + BS + "Users" + BS + "me" + BS + "d.exe")
        self.registry.put("HKLM", autoruns.SERVICES_KEY + BS + "Dhcp", "Start", 4, kind=4)
        report = self.store.snapshot(self.collect(), events=self.events)
        self.assertFalse(report.first)
        self.assertEqual([(c.kind, c.entry.name) for c in report.changes],
                         [("added", "Dropper"), ("modified", "Dhcp")])
        recorded = self.events.read(kinds={"autoruns"})
        self.assertEqual(len(recorded), 2)
        self.assertEqual({e.level for e in recorded}, {"added", "modified"})
        self.assertEqual(self.store.last_changes()[0].entry.name, "Dropper", "recomputed from what is stored")
        self.assertIn("1 new, 1 changed, 0 gone", autoruns.describe_report(report))
        third = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual(third.changes, [], "nothing new, nothing said")
        self.assertEqual(len(self.events.read(kinds={"autoruns"})), 2)

    def test_nothing_collected_records_no_snapshot(self):
        empty = autoruns.Collected(errors=["schtasks could not be run: x"])
        report = self.store.snapshot(empty, events=self.events)
        self.assertIsNone(report.snapshot)
        self.assertFalse(self.store.exists())
        self.assertTrue(any("not recorded" in e for e in report.errors))
        self.assertIn("No snapshot was taken", autoruns.describe_report(report))

    def test_old_snapshots_are_pruned_and_entries_round_trip(self):
        store = autoruns.AutorunsStore(self.tmp / "small", keep=2, key_protect=stub_protect,
                                       key_unprotect=stub_unprotect)
        for _ in range(4):
            store.snapshot(self.collect())
        kept = store.snapshots()
        self.assertEqual(len(kept), 2)
        self.assertEqual([s.id for s in kept], [3, 4])
        entries = store.entries()
        self.assertEqual(len(entries), 8)
        dhcp = next(e for e in entries if e.name == "Dhcp")
        self.assertEqual(dhcp.detail["display_name"], "DHCP Client")
        self.assertEqual(dhcp.fingerprint, next(e for e in self.collect().entries if e.name == "Dhcp").fingerprint)

    def test_a_modified_database_is_called_tampered_and_the_next_snapshot_says_so(self):
        self.store.snapshot(self.collect())
        with open(self.store.db_path, "r+b") as handle:
            handle.seek(0, 2)
            handle.write(b"\0" * 16)
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_TAMPERED)
        ok, text = autoruns.summarize(self.store)
        self.assertFalse(ok)
        self.assertIn("modified outside AVGuard", text)
        report = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual(report.integrity, autoruns.INTEGRITY_TAMPERED)
        tamper = [e for e in self.events.read(kinds={"autoruns"}) if e.level == "tampered"]
        self.assertEqual(len(tamper), 1)
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_OK, "re-signed by the new snapshot")
        self.store.signature_path.unlink()
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_UNSIGNED)

    def test_summarize_and_sizes_are_printed(self):
        self.assertEqual(autoruns.summarize(self.store), (True, "no snapshot yet"))
        self.store.snapshot(self.collect())
        ok, text = autoruns.summarize(self.store)
        self.assertTrue(ok)
        self.assertIn("8 startup item(s)", text)
        one = self.store.db_path.stat().st_size
        for _ in range(29):
            self.store.snapshot(self.collect())
        print(f"\n  snapshot database: {one:,} bytes after 1 snapshot of 8 entries, "
              f"{self.store.db_path.stat().st_size:,} after 30")


# ------------------------------------------------------------- the tab

class TestTheTabOnAWindow(AutorunsCase):
    """The Startup tab on the shared withdrawn window: a snapshot through its
    button's handler, the worker real, the window's pump played by wait()."""

    def setUp(self) -> None:
        super().setUp()
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        try:
            from avguard import startuppanel
            from guiroot import gui_root
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        try:
            self.root = gui_root()
        except Exception as exc:
            self.skipTest(f"no display: {exc}")
        import queue
        self.posted: "queue.Queue" = queue.Queue()
        self.reports: list = []
        self.panel = startuppanel.StartupPanel(
            self.root, store_factory=lambda: self.store, events=self.events,
            post=lambda fn, *args: self.posted.put((fn, args)),
            collect=lambda: self.collect(), on_report=self.reports.append, system_root=ROOT)
        self.addCleanup(self.panel.destroy)

    def wait(self, timeout: float = 30.0) -> None:
        if self.panel._thread is not None:
            self.panel._thread.join(timeout)
        self.assertFalse(self.panel.busy, "the worker did not finish")
        while not self.posted.empty():
            fn, args = self.posted.get_nowait()
            fn(*args)
        self.root.update_idletasks()

    def test_a_snapshot_through_the_button_lists_what_is_new_and_greys_the_quiet(self):
        self.assertEqual(self.panel.summary_var.get(), "no snapshot yet")
        self.assertTrue(self.panel.snapshot())
        wait = self.wait()
        self.assertIn("first snapshot", self.panel.status_var.get())
        self.assertEqual(self.panel.tree.get_children(), ())
        self.registry.put("HKCU", autoruns.RUN_KEYS[0], "Dropper", "C:" + BS + "Users" + BS + "me" + BS + "d.exe")
        self.registry.put("HKLM", autoruns.RUN_KEYS[0], "WinHelper",
                          ROOT + BS + "System32" + BS + "helper.exe", view=0x0100)
        self.panel.snapshot()
        self.wait()
        rows = {self.panel.tree.item(iid, "values")[1]: self.panel.tree.item(iid, "tags")
                for iid in self.panel.tree.get_children()}
        self.assertEqual(rows, {"run: Dropper": ("added",), "run: WinHelper": ("quiet",)})
        self.assertIn("2 new, 0 changed, 0 gone", self.panel.status_var.get())
        self.assertEqual(len(self.reports), 2)
        loud = [c.entry.name for c in self.reports[-1].changes if c.worth_a_look(ROOT)]
        self.assertEqual(loud, ["Dropper"], "the system-root item is recorded, not announced")
        self.assertEqual(str(self.panel.snapshot_btn.cget("state")), "normal")
        self.assertEqual(len(self.events.read(kinds={"autoruns"})), 2)

    def test_the_tab_opens_on_the_last_diff(self):
        self.store.snapshot(self.collect())
        self.registry.put("HKCU", autoruns.RUN_KEYS[0], "Late", "C:" + BS + "late.exe")
        self.store.snapshot(self.collect())
        self.panel.refresh()
        self.assertEqual([self.panel.tree.item(i, "values")[1] for i in self.panel.tree.get_children()],
                         ["run: Late"])

    def test_a_snapshot_that_collects_nothing_says_so_and_keeps_the_button(self):
        self.panel._collect = lambda: autoruns.Collected(errors=["schtasks could not be run: x"])
        self.panel.snapshot()
        self.wait()
        self.assertIn("No snapshot was taken", self.panel.status_var.get())
        self.assertFalse(self.store.exists())
        self.assertEqual(str(self.panel.snapshot_btn.cget("state")), "normal")


# ------------------------------------------------------ the Windows runner

@unittest.skipUnless(sys.platform == "win32", "the collectors read Windows")
class TestOnTheWindowsRunner(unittest.TestCase):
    def test_two_real_snapshots_seconds_apart_differ_in_nothing(self):
        tmp = Path(_tempfile.mkdtemp(prefix="avguard-autoruns-win-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        store = autoruns.AutorunsStore(tmp / "autoruns")
        first = autoruns.collect()
        print("\n  collected on the runner: " + ", ".join(
            f"{kind} {first.counts[kind]} in {first.seconds[kind] * 1e3:.0f} ms" for kind in autoruns.KINDS))
        for note in first.errors[:5]:
            print(f"  note: {note}")
        self.assertGreater(first.counts[autoruns.KIND_SERVICE], 50, "a Windows machine has services")
        self.assertGreater(first.counts[autoruns.KIND_TASK], 0, "and scheduled tasks")
        report = store.snapshot(first)
        self.assertTrue(report.first)
        second = store.snapshot(autoruns.collect())
        for change in second.changes:
            print(f"  changed between two snapshots: {change.describe()}")
        self.assertEqual(second.changes, [])
        print(f"  database: {store.db_path.stat().st_size:,} bytes after two snapshots of "
              f"{report.snapshot.entries:,} entries")
        self.assertEqual(store.verify_integrity(), autoruns.INTEGRITY_OK)


if __name__ == "__main__":
    unittest.main()
