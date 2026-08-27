from watchdog.events import FileSystemEventHandler

class AntivirusEventHandler(FileSystemEventHandler):
    """
    Handles file system events and triggers the scan.
    """
    def __init__(self, scanner_engine):
        self.scanner_engine = scanner_engine

    def on_created(self, event):
        """Called when a file or directory is created."""
        if not event.is_directory:
            self.scanner_engine.scan_file(event.src_path)

    def on_modified(self, event):
        """Called when a file or directory is modified."""
        if not event.is_directory:
            self.scanner_engine.scan_file(event.src_path)
