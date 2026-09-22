"""The right-click entry: exactly two keys written, exactly two removed, never the real registry.

Every test runs against a dict-backed fake of winreg. The manual check --
does the entry appear in Explorer -- is the user's, and ROADMAP.md says so.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


from avguard import shellext

logging.getLogger("avguard").addHandler(logging.NullHandler())
logging.getLogger("avguard").propagate = False

BS = chr(92)


class FakeKey:
    def __init__(self, registry, path: str) -> None:
        self.registry = registry
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeRegistry:
    """Enough of winreg to write, read and delete keys, with its errors."""

    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 0x20019
    KEY_WRITE = 0x20006
    REG_SZ = 1

    def __init__(self) -> None:
        self.keys: dict[str, dict[str, tuple[int, str]]] = {}

    @staticmethod
    def _join(root, sub_key: str) -> str:
        base = root if isinstance(root, str) else root.path
        return f"{base}{BS}{sub_key}" if sub_key else base

    def CreateKeyEx(self, root, sub_key, reserved=0, access=0):
        path = self._join(root, sub_key)
        parts = path.split(BS)
        for depth in range(1, len(parts) + 1):
            self.keys.setdefault(BS.join(parts[:depth]), {})
        return FakeKey(self, path)

    def OpenKey(self, root, sub_key, reserved=0, access=0):
        path = self._join(root, sub_key)
        if path not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified", path)
        return FakeKey(self, path)

    def SetValueEx(self, key, name, reserved, kind, value):
        self.keys[key.path][name] = (kind, value)

    def QueryValueEx(self, key, name):
        try:
            kind, value = self.keys[key.path][name]
        except KeyError:
            raise FileNotFoundError(2, "value not found", name) from None
        return value, kind

    def DeleteKey(self, root, sub_key):
        path = self._join(root, sub_key)
        if path not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified", path)
        if any(other.startswith(path + BS) for other in self.keys):
            raise PermissionError(5, "Access is denied: the key has subkeys", path)
        del self.keys[path]

    def CloseKey(self, key):
        pass


HKCU_STAR = "HKCU" + BS + "Software" + BS + "Classes" + BS + "*" + BS + "shell" + BS + "AVGuard.Scan"
HKCU_DIR = "HKCU" + BS + "Software" + BS + "Classes" + BS + "Directory" + BS + "shell" + BS + "AVGuard.Scan"


class TestInstallAndRemove(unittest.TestCase):
    def setUp(self) -> None:
        self.reg = FakeRegistry()
        self.reg.CreateKeyEx("HKCU", "Software" + BS + "Classes" + BS + "*" + BS + "shell" + BS + "Other")
        self.reg.SetValueEx(FakeKey(self.reg, "HKCU" + BS + "Software" + BS + "Classes" + BS + "*"
                                    + BS + "shell" + BS + "Other"), "", 0, 1, "Somebody else's verb")

    def test_install_writes_exactly_the_two_keys(self):
        ok, detail = shellext.install(registry=self.reg)
        self.assertTrue(ok, detail)
        for key in (HKCU_STAR, HKCU_DIR):
            with self.subTest(key=key):
                values = self.reg.keys[key]
                self.assertEqual(values["MUIVerb"], (1, "Scan with AVGuard"))
                self.assertEqual(values[""], (1, "Scan with AVGuard"))
                self.assertIn("Icon", values)
                command = self.reg.keys[key + BS + "command"][""][1]
                self.assertEqual(command, shellext.command_string())
                self.assertIn('--scan "%1" --pause', command)
        self.assertTrue(shellext.installed(registry=self.reg))

    def test_remove_deletes_them_and_leaves_the_neighbour(self):
        shellext.install(registry=self.reg)
        ok, detail = shellext.uninstall(registry=self.reg)
        self.assertTrue(ok, detail)
        self.assertNotIn(HKCU_STAR, self.reg.keys)
        self.assertNotIn(HKCU_STAR + BS + "command", self.reg.keys)
        self.assertNotIn(HKCU_DIR, self.reg.keys)
        self.assertIn("HKCU" + BS + "Software" + BS + "Classes" + BS + "*" + BS + "shell" + BS + "Other",
                      self.reg.keys)
        self.assertFalse(shellext.installed(registry=self.reg))

    def test_remove_when_not_installed_is_fine(self):
        ok, _ = shellext.uninstall(registry=self.reg)
        self.assertTrue(ok)
        self.assertFalse(shellext.installed(registry=self.reg))

    def test_install_twice_is_idempotent(self):
        shellext.install(registry=self.reg)
        before = dict(self.reg.keys)
        shellext.install(registry=self.reg)
        self.assertEqual(self.reg.keys, before)

    def test_no_registry_means_not_supported(self):
        with mock.patch.object(shellext, "_default_registry", return_value=None):
            self.assertEqual(shellext.install(), (False, "only supported on Windows"))
            self.assertFalse(shellext.installed())


class TestTheCommandString(unittest.TestCase):
    def test_spaces_and_thai_characters_survive_quoting(self):
        exe = "C:" + BS + "Program Files" + BS + "โปรแกรม" + BS + "python.exe"
        with mock.patch.object(sys, "executable", exe), \
                mock.patch.object(sys, "frozen", False, create=True):
            command = shellext.command_string()
        self.assertTrue(command.startswith(f'"{exe}" -m avguard --scan "%1" --pause'), command)

    def test_frozen_runs_the_executable_itself(self):
        exe = "C:" + BS + "AVGuard" + BS + "AVGuard.exe"
        with mock.patch.object(sys, "executable", exe), \
                mock.patch.object(sys, "frozen", True, create=True):
            self.assertEqual(shellext.command_string(), f'"{exe}" --scan "%1" --pause')
            self.assertEqual(shellext.icon_string(), f'"{exe}"')

    def test_pythonw_is_swapped_for_python_when_present(self):
        tmp = Path(tempfile.mkdtemp(prefix="avguard-shell-"))
        self.addCleanup(_remove_tree, tmp)
        (tmp / "python.exe").write_bytes(b"MZ")
        (tmp / "pythonw.exe").write_bytes(b"MZ")
        with mock.patch.object(sys, "executable", str(tmp / "pythonw.exe")), \
                mock.patch.object(sys, "frozen", False, create=True):
            exe, args = shellext.runner()
        self.assertEqual(Path(exe).name, "python.exe", "the result has to be visible")
        self.assertEqual(args, ["-m", "avguard"])


class TestTheCommandLine(unittest.TestCase):
    def _cli(self, *args: str, registry=None) -> tuple[int, str]:
        import avguard.__main__ as cli
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(shellext, "_default_registry", return_value=registry), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue() + err.getvalue()

    def test_install_and_remove_flags(self):
        reg = FakeRegistry()
        code, output = self._cli("--install-context-menu", registry=reg)
        self.assertEqual(code, 0, output)
        self.assertIn("installed for this user", output)
        self.assertTrue(shellext.installed(registry=reg))
        code, output = self._cli("--remove-context-menu", registry=reg)
        self.assertEqual(code, 0, output)
        self.assertFalse(shellext.installed(registry=reg))

    def test_install_off_windows_fails_plainly(self):
        code, output = self._cli("--install-context-menu", registry=None)
        self.assertEqual(code, 1)
        self.assertIn("only supported on Windows", output)

    def test_pause_returns_at_once_without_a_terminal(self):
        import avguard.__main__ as cli
        tmp = Path(tempfile.mkdtemp(prefix="avguard-pause-"))
        self.addCleanup(_remove_tree, tmp)
        sample = tmp / "plain.txt"
        sample.write_text("nothing to see", encoding="utf-8")
        fake_stdin = io.StringIO()   # isatty() is False
        with mock.patch.object(sys, "stdin", fake_stdin), \
                mock.patch("builtins.input", side_effect=AssertionError("must not wait")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["--scan", str(sample), "--pause"])
        self.assertEqual(code, 0)

    def test_pause_with_no_console_shows_a_window(self):
        transcript = ["[CLEAN] x", "Examined : 1 file(s)"]
        shown: list[tuple[str, str]] = []
        fake_messagebox = mock.MagicMock(showinfo=lambda title, text: shown.append((title, text)))
        # `from tkinter import messagebox` reads the attribute off the package
        # first, so the fake package must carry the fake submodule.
        fake_tk = mock.MagicMock(messagebox=fake_messagebox)
        import avguard.__main__ as cli
        with mock.patch.dict(sys.modules, {"tkinter": fake_tk, "tkinter.messagebox": fake_messagebox}), \
                mock.patch.object(sys, "stdout", None):
            cli._pause_for_the_user(Path("C:/x/thing.exe"), transcript)
        self.assertEqual(len(shown), 1)
        self.assertIn("thing.exe", shown[0][0])
        self.assertIn("Examined : 1 file(s)", shown[0][1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
