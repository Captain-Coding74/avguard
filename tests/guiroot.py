"""One withdrawn ttkbootstrap Window for the whole test process.

ttkbootstrap's Style is a singleton that remembers the interpreter it
registered its layouts with; a second Window in the same process raised
"Layout Round.Toggle not found". So every test module that needs a window
takes this one. Created on first use, destroyed at exit. Not a test module:
discovery collects test*.py, and this is imported by them.
"""

from __future__ import annotations

_GUI_ROOT = None


def gui_root():
    """The shared window, or an exception when there is no display."""
    global _GUI_ROOT
    if _GUI_ROOT is None:
        import atexit
        import ttkbootstrap as tb
        _GUI_ROOT = tb.Window(themename="darkly")
        _GUI_ROOT.withdraw()

        def _close() -> None:
            try:
                _GUI_ROOT.destroy()
            except Exception:
                pass
        atexit.register(_close)
    return _GUI_ROOT
