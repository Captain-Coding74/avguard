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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_test_data = _os.path.join(_tempfile.gettempdir(), f"avguard-autoruns-data-{_os.getpid()}")
_os.environ["AVGUARD_DATA"] = _test_data      # assigned: an inherited value may be real data
if _os.environ["AVGUARD_DATA"] == _test_data:
    import atexit as _atexit
    import shutil as _shutil
    _atexit.register(lambda: _shutil.rmtree(_test_data, ignore_errors=True))

from avguard import autoruns, fim
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
    reg.put("HKLM", services + BS + "Dhcp" + BS + "Parameters", "ServiceDll",
            "%SystemRoot%" + BS + "system32" + BS + "dhcpcore.dll", kind=2)
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
        self.assertEqual(by_name["Dhcp"].extra, "start automatic; type shared process; dll %SystemRoot%"
                         + BS + "system32" + BS + "dhcpcore.dll")
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

    def test_the_account_is_the_principal_s_not_a_logon_trigger_s(self):
        """schtasks writes Triggers before Principals, and a LogonTrigger may
        carry a UserId of its own: whose sign-in starts it, not who it runs as."""
        text = FIXTURE.read_text(encoding="utf-8")

        def task(user: str) -> str:
            return ('<!-- ' + BS + 'Updater2 -->\n'
                    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                    '<Triggers><LogonTrigger><UserId>DESKTOP' + BS + 'me</UserId></LogonTrigger></Triggers>'
                    '<Principals><Principal id="Author"><UserId>' + user + '</UserId>'
                    '<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>'
                    '<Settings><Enabled>true</Enabled></Settings>'
                    '<Actions><Exec><Command>C:' + BS + 'u.exe</Command></Exec></Actions></Task>\n')
        before = autoruns.parse_tasks(text.replace("</Tasks>", task("DESKTOP" + BS + "me") + "</Tasks>"))
        after = autoruns.parse_tasks(text.replace("</Tasks>", task("S-1-5-18") + "</Tasks>"))
        self.assertIn("S-1-5-18", next(e for e in after if e.name == "Updater2").extra)
        self.assertEqual([(c.kind, c.entry.name) for c in diff(before, after)], [("modified", "Updater2")],
                         "running as SYSTEM instead of the user is a change")

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
        self.assertEqual(collected.failed, {autoruns.KIND_TASK}, "unknown today, which is not empty")
        self.assertEqual(set(collected.seconds), set(autoruns.KINDS), "every collector is timed")

    def test_an_empty_or_failed_schtasks_answer_is_a_failed_read_not_an_empty_one(self):
        with self.assertRaises(autoruns.CollectorFailed):
            autoruns.collect_tasks(lambda: b"")
        with self.assertRaises(autoruns.CollectorFailed) as caught:
            autoruns.collect_tasks(lambda: b"ERROR: Access is denied.\r\n")
        self.assertIn("Access is denied", str(caught.exception))
        collected = self.collect(runner=lambda: b"")
        self.assertEqual(collected.failed, {autoruns.KIND_TASK})
        self.assertEqual(collected.counts[autoruns.KIND_TASK], 0)
        self.assertTrue(any(e.startswith("task:") for e in collected.errors))

    def test_an_svchost_hosted_service_is_its_dll(self):
        """The image path says svchost; the code that runs is Parameters\\ServiceDll."""
        entries = autoruns.collect_services(self.registry)
        dhcp = {e.name: e for e in entries}["Dhcp"]
        self.assertEqual(dhcp.target, ROOT + BS + "system32" + BS + "dhcpcore.dll")
        self.assertEqual(dhcp.detail["service_dll"], "%SystemRoot%" + BS + "system32" + BS + "dhcpcore.dll")
        evil = "C:" + BS + "Users" + BS + "me" + BS + "AppData" + BS + "Roaming" + BS + "evil.dll"
        self.registry.put("HKLM", autoruns.SERVICES_KEY + BS + "Dhcp" + BS + "Parameters", "ServiceDll", evil, kind=2)
        hijacked = diff(entries, autoruns.collect_services(self.registry))
        self.assertEqual([(c.kind, c.entry.name) for c in hijacked], [("modified", "Dhcp")])
        self.assertTrue(hijacked[0].worth_a_look(ROOT, trusted=lambda t: True),
                        "svchost is signed; the DLL under the profile is the point")
        self.assertEqual(hijacked[0].as_event().path, evil)
        bare = Entry("service", "x", "Svc", "%SystemRoot%" + BS + "system32" + BS + "svchost.exe -k g",
                     detail={"service_dll": "core.dll"})
        self.assertTrue(autoruns.Change("added", bare).worth_a_look(ROOT),
                        "a DLL named without a folder: nothing vouches for where it comes from")

    def test_per_logon_service_instances_are_not_entries(self):
        services = autoruns.SERVICES_KEY
        image = "%SystemRoot%" + BS + "system32" + BS + "svchost.exe -k UnistackSvcGroup"
        for name, kind in (("CDPUserSvc", 0x60), ("CDPUserSvc_3f2a1", 0xE0)):
            self.registry.put("HKLM", services + BS + name, "ImagePath", image, kind=2)
            self.registry.put("HKLM", services + BS + name, "Start", 2, kind=4)
            self.registry.put("HKLM", services + BS + name, "Type", kind, kind=4)
        names = {e.name for e in autoruns.collect_services(self.registry)}
        self.assertIn("CDPUserSvc", names)
        self.assertNotIn("CDPUserSvc_3f2a1", names, "a fresh name at every sign-in; its template is collected")
        self.assertEqual(autoruns.SERVICE_TYPE[0xE0], "user service instance")

    def test_a_driver_without_an_image_path_loads_from_the_drivers_folder(self):
        self.registry.put("HKLM", autoruns.SERVICES_KEY + BS + "Beep", "Type", 1, kind=4)
        self.registry.put("HKLM", autoruns.SERVICES_KEY + BS + "Beep", "Start", 1, kind=4)
        by_name = {e.name: e for e in autoruns.collect_services(self.registry)}
        self.assertIn("Beep", by_name)
        self.assertNotIn("NoImage", by_name, "neither an image nor a driver type")
        self.assertEqual(by_name["Beep"].value, BS + "SystemRoot" + BS + "System32" + BS + "drivers" + BS + "Beep.sys")
        self.assertEqual(by_name["Beep"].target, ROOT + BS + "System32" + BS + "drivers" + BS + "Beep.sys")
        self.assertTrue(by_name["Beep"].detail["implied"])

    def test_task_manager_s_disabled_flag_is_the_low_bit(self):
        for first, enabled in ((2, True), (3, False), (6, True), (7, False)):
            with self.subTest(first=first):
                self.registry.put("HKCU", autoruns.APPROVED_RUN, "OneDrive", bytes([first] + [0] * 11), kind=3)
                by_name = {e.name: e for e in autoruns.collect_run_keys(self.registry)}
                self.assertEqual(by_name["OneDrive"].enabled, enabled)

    def test_a_command_in_a_run_key_s_default_value_is_an_entry(self):
        self.registry.put("HKLM", autoruns.RUN_KEYS[0], "", "C:" + BS + "odd" + BS + "d.exe", view=0x0100)
        by_name = {e.name: e for e in autoruns.collect_run_keys(self.registry)}
        self.assertEqual(by_name["(Default)"].value, "C:" + BS + "odd" + BS + "d.exe")
        self.assertNotIn("", by_name, "the empty RunOnce default is still nothing")

    def test_a_startup_file_is_its_own_target(self):
        deep = self.tmp / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        deep.mkdir(parents=True)
        (deep / "Vendor Tray.lnk").write_bytes(b"L\x00\x00\x00")
        entry = autoruns.collect_startup_folders([("user", deep)], self.registry)[0]
        self.assertEqual(entry.target, str(deep / "Vendor Tray.lnk"))
        self.assertEqual(entry.paths(), [str(deep / "Vendor Tray.lnk")])
        self.assertEqual(autoruns.Change("added", entry).as_event().path, str(deep / "Vendor Tray.lnk"))

    def test_a_startup_folder_that_cannot_be_listed_is_a_failed_read(self):
        from unittest import mock
        with mock.patch.object(autoruns.Path, "iterdir", side_effect=PermissionError(13, "Access is denied")):
            with self.assertRaises(autoruns.CollectorFailed):
                autoruns.collect_startup_folders(self.folders, self.registry)
            collected = self.collect()
        self.assertEqual(collected.failed, {autoruns.KIND_STARTUP})
        self.assertEqual(collected.counts[autoruns.KIND_TASK], 2, "the others still read")

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

    def test_a_task_in_the_library_root_reads_with_one_backslash(self):
        change = autoruns.Change("added", Entry("task", BS, "Updater", "C:" + BS + "u.exe"))
        self.assertIn("task " + BS + "Updater:", change.describe())
        self.assertNotIn(BS + BS, change.describe())
        nested = autoruns.Change("added", Entry("task", BS + "Microsoft" + BS + "Windows", "Defrag", "x"))
        self.assertIn("task " + BS + "Microsoft" + BS + "Windows" + BS + "Defrag:", nested.describe())


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

    def test_the_payload_counts_not_only_the_host(self):
        sys32 = ROOT + BS + "System32" + BS
        profile = "C:" + BS + "Users" + BS + "me" + BS + "AppData" + BS + "Roaming" + BS
        loud = [sys32 + "rundll32.exe " + profile + "x.dll,Run",
                '"' + sys32 + 'cmd.exe" /c ' + profile + "go.bat",
                sys32 + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe -File C:" + BS + "ProgramData" + BS + "s.ps1",
                sys32 + "wscript.exe " + profile + "a.vbs",
                sys32 + "regsvr32.exe /s " + profile + "b.dll",
                sys32 + "mshta.exe " + profile + "c.hta"]
        for value in loud:
            with self.subTest(value=value):
                self.assertTrue(self.change(value).worth_a_look(ROOT))
                self.assertTrue(self.change(value).worth_a_look(ROOT, trusted=lambda t: True),
                                "the host is signed; the payload is the point")
        quiet = sys32 + "rundll32.exe " + sys32 + "shell32.dll,Control_RunDLL"
        self.assertFalse(self.change(quiet).worth_a_look(ROOT))
        self.assertTrue(self.change(quiet).worth_a_look(ROOT, trusted=lambda t: False))

    def test_user_writable_corners_of_the_windows_folder_are_loud(self):
        for sub in ("Temp", "Tasks", "tracing", "System32" + BS + "Tasks",
                    "System32" + BS + "spool" + BS + "drivers" + BS + "color"):
            with self.subTest(sub=sub):
                self.assertTrue(self.change(ROOT + BS + sub + BS + "x.exe").worth_a_look(ROOT, trusted=lambda t: True))
        self.assertFalse(self.change(ROOT + BS + "System32" + BS + "x.exe").worth_a_look(ROOT, trusted=lambda t: True))


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
        self.assertTrue(autoruns.describe_report(report).startswith("SNAPSHOTS: the startup snapshots were modified"),
                        "the status line says it too, or the tab would show it vanish")
        self.store.signature_path.unlink()
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_UNSIGNED)

    def test_a_failed_collector_keeps_the_previous_snapshot_s_entries(self):
        self.store.snapshot(self.collect(), events=self.events)
        report = self.store.snapshot(self.collect(runner=lambda: b""), events=self.events)
        self.assertEqual(report.changes, [], "a read that did not happen is not two tasks gone")
        self.assertEqual(report.carried, {autoruns.KIND_TASK: 2})
        self.assertEqual(report.snapshot.entries, 8)
        self.assertEqual(report.snapshot.failed, (autoruns.KIND_TASK,))
        self.assertIn("kept from the previous snapshot", autoruns.describe_report(report))
        self.assertEqual(self.events.read(kinds={"autoruns"}), [])
        self.assertEqual(len([e for e in self.store.entries() if e.kind == "task"]), 2)
        back = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual(back.changes, [], "and nothing is new when schtasks answers again")

    def test_a_kind_first_read_after_a_bad_first_read_is_recorded_not_compared(self):
        first = self.store.snapshot(self.collect(runner=lambda: b""), events=self.events)
        self.assertEqual((first.snapshot.entries, first.carried), (6, {}))
        second = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual(second.changes, [], "two tasks read for the first time are not two NEW rows")
        self.assertTrue(any("read for the first time" in e for e in second.errors))
        self.assertEqual(second.snapshot.entries, 8)
        self.assertEqual(self.events.read(kinds={"autoruns"}), [])
        self.registry.put("HKCU", autoruns.RUN_KEYS[0], "Dropper", "C:" + BS + "d.exe")
        third = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual([(c.kind, c.entry.name) for c in third.changes], [("added", "Dropper")])

    def test_an_unreadable_database_is_reported_and_not_written_over(self):
        self.store.snapshot(self.collect())
        self.store.db_path.write_bytes(b"not a database at all" * 100)
        self.assertIsNotNone(self.store.unreadable())
        ok, text = autoruns.summarize(self.store)
        self.assertFalse(ok)
        self.assertIn("modified outside AVGuard", text)
        report = self.store.snapshot(self.collect(), events=self.events)
        self.assertIsNone(report.snapshot)
        self.assertEqual(report.integrity, autoruns.INTEGRITY_TAMPERED)
        self.assertTrue(any("cannot be read" in e for e in report.errors))
        self.assertTrue(autoruns.describe_report(report).startswith("SNAPSHOTS:"))
        self.assertEqual([e.level for e in self.events.read(kinds={"autoruns"})], ["tampered"])
        self.assertEqual(self.store.db_path.read_bytes(), b"not a database at all" * 100, "left for the user")
        self.assertEqual(self.store.snapshots(), [])

    def test_an_unreadable_key_keeps_the_snapshot_and_the_events(self):
        self.store.snapshot(self.collect())
        self.store.key_path.write_bytes(b"garbage")
        self.registry.put("HKCU", autoruns.RUN_KEYS[0], "Dropper", "C:" + BS + "d.exe")
        report = self.store.snapshot(self.collect(), events=self.events)
        self.assertIsNotNone(report.snapshot)
        self.assertEqual(report.integrity, autoruns.INTEGRITY_KEY_UNREADABLE)
        self.assertTrue(any("not signed" in e for e in report.errors))
        self.assertEqual([(c.kind, c.entry.name) for c in report.changes], [("added", "Dropper")])
        self.assertEqual(sorted(e.level for e in self.events.read(kinds={"autoruns"})), ["added", "tampered"])
        self.assertEqual(len(self.store.snapshots()), 2)
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_KEY_UNREADABLE)
        self.assertIn("signing key", autoruns.describe_report(report).split(".")[0])

    def test_a_file_with_no_snapshot_in_it_is_not_no_snapshot_yet(self):
        self.store.snapshot(self.collect())
        self.store.db_path.write_bytes(b"")
        ok, text = autoruns.summarize(self.store)
        self.assertFalse(ok)
        self.assertIn("modified outside AVGuard", text, "its signature says what it is")

    def test_one_snapshot_at_a_time(self):
        self.store.snapshot(self.collect())
        other = fim.FileLock(self.store.directory / autoruns.LOCK_NAME)
        self.assertTrue(other.acquire(0.1))
        self.addCleanup(other.release)
        self.addCleanup(setattr, autoruns, "LOCK_WAIT", autoruns.LOCK_WAIT)
        autoruns.LOCK_WAIT = 0.3
        report = self.store.snapshot(self.collect(), events=self.events)
        self.assertIsNone(report.snapshot)
        self.assertTrue(any("another snapshot" in e for e in report.errors))
        self.assertEqual(len(self.store.snapshots()), 1)
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_OK)
        other.release()
        self.assertIsNotNone(self.store.snapshot(self.collect()).snapshot)

    def test_duplicate_keys_are_stored_once_and_do_not_flap(self):
        twice = autoruns.Collected(entries=[Entry("run", "HKCU" + BS + "Run", "App", "C:" + BS + "a.exe"),
                                            Entry("run", "HKCU" + BS + "Run", "APP", "C:" + BS + "b.exe")])
        first = self.store.snapshot(twice)
        self.assertEqual(first.snapshot.entries, 1)
        self.assertEqual(self.store.latest().entries, 1)
        self.assertEqual([e.value for e in self.store.entries()], ["C:" + BS + "a.exe"])
        self.assertEqual(self.store.snapshot(twice).changes, [])

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

class TestRoundSixSnapshots(AutorunsCase):
    """Round six: the first-read rule could not tell a kind never read from
    one read fine and empty; the tab recomputed changes without that rule;
    two overlapping snapshots recorded a false tamper; and a signature file
    that was not text raised instead of reading as tampered."""

    def test_an_empty_kind_read_once_then_not_still_reports_what_appears_next(self):
        (self.startup / "Sync.lnk").unlink()
        self.store.snapshot(self.collect(), events=self.events)          # Startup read fine, empty
        with mock.patch.object(Path, "iterdir", side_effect=PermissionError(13, "denied")):
            collected = self.collect()
        day2 = self.store.snapshot(collected, events=self.events)
        self.assertIn(autoruns.KIND_STARTUP, day2.snapshot.failed)
        (self.startup / "svchost.lnk").write_bytes(b"L\x00\x00\x00 a new shortcut")
        day3 = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual([(c.kind, c.entry.name) for c in day3.changes], [("added", "svchost.lnk")],
                         "swallowed as a first read")
        self.assertEqual([e.level for e in self.events.read(kinds={"autoruns"})], ["added"])

    def test_the_tab_agrees_with_the_snapshot_after_a_failed_first_read(self):
        self.store.snapshot(self.collect(runner=lambda: b""), events=self.events)
        second = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual(second.changes, [])
        self.assertEqual(self.store.last_changes(), [], "every task was NEW on the tab")
        self.registry.put("HKCU", autoruns.RUN_KEYS[0], "Dropper", "C:" + BS + "d.exe")
        self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual([(c.kind, c.entry.name) for c in self.store.last_changes()], [("added", "Dropper")])

    def test_two_overlapping_snapshots_record_no_false_tamper(self):
        import threading
        self.store.snapshot(self.collect())
        other = autoruns.AutorunsStore(self.store.directory, key_protect=stub_protect,
                                       key_unprotect=stub_unprotect)
        real_sign = autoruns.AutorunsStore._sign
        signing = threading.Event()

        def slow_sign(store):
            if store is self.store:
                signing.set()               # committed, not yet signed: the window the race lives in
                time.sleep(0.6)
            return real_sign(store)
        with mock.patch.object(autoruns.AutorunsStore, "_sign", slow_sign):
            first = threading.Thread(target=self.store.snapshot, args=(self.collect(),),
                                     kwargs={"events": self.events})
            first.start()
            self.assertTrue(signing.wait(5))
            report = other.snapshot(self.collect(), events=self.events)
            first.join(10)
        self.assertEqual(report.integrity, autoruns.INTEGRITY_OK)
        self.assertEqual([e.level for e in self.events.read(kinds={"autoruns"})], [])
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_OK)

    def test_a_signature_that_is_not_text_is_tampered_not_a_crash(self):
        self.store.snapshot(self.collect())
        self.store.signature_path.write_bytes(b"\xff\xfe\x00junk")
        self.assertEqual(self.store.verify_integrity(), autoruns.INTEGRITY_TAMPERED)
        ok, text = autoruns.summarize(self.store)
        self.assertFalse(ok)
        report = self.store.snapshot(self.collect(), events=self.events)
        self.assertEqual(report.integrity, autoruns.INTEGRITY_TAMPERED)
        self.assertEqual([e.level for e in self.events.read(kinds={"autoruns"})], ["tampered"])


class TestRoundSevenSnapshots(AutorunsCase):
    """Round seven: after a kind failed to read for as many days as are
    kept, no stored snapshot had read it, its recovery counted as a first
    read, and an entry added meanwhile was recorded unreported; and a
    snapshot that timed out on the lock verified the signature without it,
    reading the holder's unsigned rows as "modified outside AVGuard"."""

    def test_a_kind_that_failed_for_longer_than_is_kept_is_still_compared(self):
        store = autoruns.AutorunsStore(self.tmp / "kept3", keep=3, key_protect=stub_protect,
                                       key_unprotect=stub_unprotect)
        store.snapshot(self.collect(), events=self.events)                  # Startup read once
        with mock.patch.object(Path, "iterdir", side_effect=PermissionError(13, "denied")):
            for _ in range(4):
                store.snapshot(self.collect(), events=self.events)
        (self.startup / "svchost.lnk").write_bytes(b"L\x00\x00\x00 a new shortcut")
        report = store.snapshot(self.collect(), events=self.events)
        self.assertEqual([(c.kind, c.entry.name) for c in report.changes], [("added", "svchost.lnk")],
                         "recorded as a first read and never reported")
        self.assertLessEqual(len(store.snapshots()), 4, "pruning kept more than one extra snapshot")

    def test_a_snapshot_that_cannot_get_the_lock_reads_nothing(self):
        self.store.snapshot(self.collect())
        holder = autoruns.fim.FileLock(self.store.directory / autoruns.LOCK_NAME)
        self.assertTrue(holder.acquire(0.1))
        self.addCleanup(holder.release)
        self.addCleanup(setattr, autoruns, "LOCK_WAIT", autoruns.LOCK_WAIT)
        autoruns.LOCK_WAIT = 0.2
        with mock.patch.object(autoruns.AutorunsStore, "verify_integrity",
                               return_value=autoruns.INTEGRITY_TAMPERED) as verified:
            report = self.store.snapshot(self.collect(), events=self.events)
        verified.assert_not_called()
        self.assertTrue(report.in_use)
        self.assertIsNone(report.integrity_event())
        self.assertNotIn("SNAPSHOTS", autoruns.describe_report(report))
        self.assertEqual(self.events.read(kinds={"autoruns"}), [])


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

    def test_a_gone_row_keeps_its_colour_and_the_checker_is_asked_on_the_worker(self):
        import threading
        asked: list[str] = []

        def trusted(target: str) -> bool:
            asked.append(threading.current_thread().name)
            return True
        self.panel._trusted = trusted
        self.panel.snapshot()
        self.wait()
        self.registry.keys[FakeRegistry._path("HKCU", autoruns.RUN_KEYS[0])].pop("OneDrive")
        self.registry.put("HKLM", autoruns.RUN_KEYS[0], "WinHelper",
                          ROOT + BS + "System32" + BS + "helper.exe", view=0x0100)
        self.panel.snapshot()
        self.wait()
        rows = {self.panel.tree.item(iid, "values")[1]: self.panel.tree.item(iid, "tags")
                for iid in self.panel.tree.get_children()}
        self.assertEqual(rows, {"run: OneDrive": ("removed",), "run: WinHelper": ("quiet",)},
                         "gone is gone, in its own colour; grey means under the Windows folder")
        self.assertEqual(set(asked), {"avguard-autoruns"}, "the checker runs on the worker, never the GUI thread")
        self.assertEqual(self.reports[-1].loud, [], "judged before the report reached the window")
        before = len(asked)
        self.panel.refresh()
        self.assertEqual(len(asked), before, "the list the tab opens on does not ask the checker")
        self.assertEqual({self.panel.tree.item(iid, "values")[1] for iid in self.panel.tree.get_children()},
                         {"run: OneDrive", "run: WinHelper"})

    def test_a_row_s_detail_is_built_from_the_entries_not_the_sentence(self):
        from avguard.startuppanel import row_for
        old = Entry("run", "HKCU" + BS + "Run", "Update: check", "C:" + BS + "a.exe")
        new = Entry("run", "HKCU" + BS + "Run", "Update: check", "C:" + BS + "b.exe")
        self.assertEqual(row_for(autoruns.Change("modified", new, old)),
                         ("changed", "run: Update: check", "C:" + BS + "a.exe -> C:" + BS + "b.exe"))

    def test_the_tab_opens_on_the_last_diff(self):
        self.store.snapshot(self.collect())
        self.registry.put("HKCU", autoruns.RUN_KEYS[0], "Late", "C:" + BS + "late.exe")
        self.store.snapshot(self.collect())
        self.panel.refresh()
        self.assertEqual([self.panel.tree.item(i, "values")[1] for i in self.panel.tree.get_children()],
                         ["run: Late"])

    def test_an_unreadable_database_shows_red_and_the_snapshot_says_why(self):
        self.store.snapshot(self.collect())
        self.store.db_path.write_bytes(b"not a database" * 50)
        self.panel.refresh()
        self.assertIn("modified outside AVGuard", self.panel.summary_var.get())
        self.panel.snapshot()
        self.wait()
        self.assertTrue(self.panel.status_var.get().startswith("SNAPSHOTS:"), self.panel.status_var.get())
        self.assertIn("not recorded", self.panel.status_var.get())
        self.assertEqual(str(self.panel.snapshot_btn.cget("state")), "normal")

    def test_a_snapshot_that_collects_nothing_says_so_and_keeps_the_button(self):
        self.panel._collect = lambda: autoruns.Collected(errors=["schtasks could not be run: x"])
        self.panel.snapshot()
        self.wait()
        self.assertIn("No snapshot was taken", self.panel.status_var.get())
        self.assertFalse(self.store.exists())
        self.assertEqual(str(self.panel.snapshot_btn.cget("state")), "normal")


# ------------------------------------------------------ the window's rule

class TestTheWindowsCheckerRule(unittest.TestCase):
    """The closure the window hands the tab, called unbound on a stand-in:
    only a signature that fails makes a change under the Windows folder
    loud, because the checker cannot verify catalogue-signed files."""

    def setUp(self) -> None:
        try:
            from avguard import gui, signing
        except ImportError:
            self.skipTest("GUI dependencies are not installed")
        self.gui, self.signing = gui, signing
        self.tmp = Path(_tempfile.mkdtemp(prefix="avguard-trust-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_only_a_failing_signature_makes_a_system_root_change_loud(self):
        from types import SimpleNamespace
        Trust = self.signing.Trust
        target = self.tmp / "x.exe"
        target.write_bytes(b"MZ")
        answer = {}

        class FakeChecker:
            available = True

            def check(self, path, size=0, mtime_ns=0):
                return SimpleNamespace(trust=answer["trust"], is_trusted=answer["trust"] is Trust.TRUSTED)
        app = SimpleNamespace(scanner=SimpleNamespace(signatures=FakeChecker()))
        trusted = self.gui.AVGuardApp._startup_trusted(app)
        for trust, quiet in ((Trust.TRUSTED, True), (Trust.UNSIGNED, True), (Trust.UNTRUSTED, False)):
            answer["trust"] = trust
            self.assertEqual(trusted(str(target)), quiet, trust)
        none = SimpleNamespace(scanner=SimpleNamespace(signatures=SimpleNamespace(available=False)))
        self.assertIsNone(self.gui.AVGuardApp._startup_trusted(none))

    def test_the_banner_takes_the_worker_s_judgement(self):
        from types import SimpleNamespace
        banners: list[str] = []
        app = SimpleNamespace(_banner=lambda text, style: banners.append(text), _startup_trusted=lambda: None)
        loud = autoruns.Change("added", Entry("run", "HKCU" + BS + "Run", "Dropper", "C:" + BS + "d.exe"))
        quiet = autoruns.Change("added", Entry("run", "HKLM" + BS + "Run", "Helper", ROOT + BS + "h.exe"))
        self.gui.AVGuardApp._startup_report(app, autoruns.SnapshotReport(changes=[quiet, loud], loud=[loud]))
        self.assertEqual(len(banners), 1)
        self.assertIn("Dropper", banners[0])
        self.gui.AVGuardApp._startup_report(app, autoruns.SnapshotReport(changes=[loud], loud=[]))
        self.assertEqual(len(banners), 1, "what the worker judged quiet is not announced here")
        self.gui.AVGuardApp._startup_report(app, autoruns.SnapshotReport(changes=[quiet, loud], loud=None))
        self.assertEqual(len(banners), 2, "nobody judged: the system-root rule decides")


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
        self.assertEqual(first.failed, set(), first.errors)
        self.assertFalse([e for e in first.errors if "unreadable XML" in e],
                         "a task the parser cannot read is a defect, not a note: " + "; ".join(first.errors))
        report = store.snapshot(first)
        self.assertTrue(report.first)
        second = store.snapshot(autoruns.collect())
        for change in second.changes:
            print(f"  changed between two snapshots: {change.describe()}")
        if second.changes:
            # The runner is a live machine: a task an updater registers
            # between two collections is real and does not repeat; a diff
            # that flaps repeats on the third collection.
            third = store.snapshot(autoruns.collect())
            self.assertEqual(third.changes, [], "a change that repeats is the diff's, not the machine's")
        print(f"  database: {store.db_path.stat().st_size:,} bytes after two snapshots of "
              f"{report.snapshot.entries:,} entries")
        self.assertEqual(store.verify_integrity(), autoruns.INTEGRITY_OK)


if __name__ == "__main__":
    unittest.main()
