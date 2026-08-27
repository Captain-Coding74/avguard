import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from engine import AntivirusEngine
import os

class AntivirusEventHandler(FileSystemEventHandler):
    """
    Handles file system events and triggers the antivirus engine.
    """
    def __init__(self, engine, excluded_paths):
        self.engine = engine
        self.excluded_paths = excluded_paths

    def on_modified(self, event):
        if not event.is_directory and not self._is_excluded(event.src_path):
            self.engine.scan_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory and not self._is_excluded(event.src_path):
            self.engine.scan_file(event.src_path)
            
    def _is_excluded(self, path):
        """Checks if a file path should be excluded from scanning."""
        # Check if any part of the path matches an excluded name.
        return any(excluded in path for excluded in self.excluded_paths)

class App:
    """
    Main application orchestrator.
    Manages the real-time file system observer and the core antivirus engine.
    """
    def __init__(self, directory_to_watch):
        self.directory_to_watch = directory_to_watch
        self.observer = Observer()
        self.engine = None
        self.event_handler = None
        
        # New: List of files and directories to exclude from the watcher.
        self.excluded_paths = ["antivirus_log.txt", "__pycache__"]
        
    def run(self, log_widget):
        """
        Sets up the observer and starts monitoring in a separate thread.
        This allows the main GUI loop to run without blocking.
        """
        self.engine = AntivirusEngine(log_widget)
        self.event_handler = AntivirusEventHandler(self.engine, self.excluded_paths)
        
        self.observer.schedule(self.event_handler, self.directory_to_watch, recursive=True)
        
        # Start the observer in a separate thread
        threading.Thread(target=self.observer.start, daemon=True).start()
        
        self.engine.log_message(f"Antivirus engine initialized. Monitoring '{self.directory_to_watch}'...")

    def stop(self):
        """Stops the observer."""
        self.observer.stop()
        self.observer.join()
        
    def scan_directory_full(self, path):
        """Performs a full, non-realtime scan of a directory."""
        self.engine.log_message(f"Starting full scan of: {path}")
        for root, _, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                self.engine.scan_file(filepath)
        self.engine.log_message("Full scan complete.")
