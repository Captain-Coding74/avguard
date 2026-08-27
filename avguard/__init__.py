"""AVGuard - a small, honest file scanner.

This package replaces the original single-file prototype. The pieces are split
so each one can be tested on its own:

    config      where everything lives on disk, and the user's settings
    protection  the rule that stops the scanner eating its own files
    scanner     one read of a file -> hash, signatures, entropy, YARA
    quarantine  a store that neutralises what it holds and can restore it
    cloud       VirusTotal, rate limited, cached, and off by default
    watcher     watchdog events -> debounced work queue -> worker threads
    gui         Tkinter front end; every widget touch happens on the GUI thread
"""

__version__ = "2.0.0"
