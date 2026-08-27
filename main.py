import tkinter as tk
from tkinter import filedialog, ttk
import threading
import os
import sys
import time
import shutil
import hashlib
import requests
import pystray
from PIL import Image, ImageDraw
from datetime import datetime
import queue
from pathlib import Path
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yara

# ttkbootstrap is a modern, themed extension for Tkinter
from ttkbootstrap import Style, Window, ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox

# Import the VirusTotal scanner utility
from vt_scanner import scan_hash_with_virustotal

# We use a queue to safely communicate between the scanning thread and the GUI thread
message_queue = queue.Queue()

# --- AntivirusEventHandler Class ---
class AntivirusEventHandler(FileSystemEventHandler):
    """
    A file system event handler that triggers an antivirus scan
    on file creation or modification events.
    """
    def __init__(self, engine):
        self.engine = engine

    def on_created(self, event):
        if not event.is_directory:
            self.engine.scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.engine.scan_file(event.src_path)

# --- AntivirusEngine Class ---
class AntivirusEngine:
    """
    Core engine for signature and behavioral-based scanning.
    This class handles all the core logic, including scanning,
    quarantine management, and logging to a file.
    """
    def __init__(self, app_instance):
        self.signatures = [
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            b"test_malware_signature_123"
        ]
        self.quarantine_dir = "quarantine"
        self.app = app_instance
        self.quarantined_files = self._load_quarantined_files()

        self.excluded_dirs = [self.quarantine_dir, "__pycache__"]
        self.excluded_files = ["antivirus_log.txt", os.path.basename(sys.argv[0])]
        
        self.vt_api_key = os.getenv("VT_API_KEY")

        if not self.vt_api_key:
            self.app.log_message("ERROR: VirusTotal API key not found. Please set the 'VT_API_KEY' environment variable.", is_error=True)
            
        self._create_quarantine_dir()
        self._create_antivirus_log()
        self._compile_yara_rules()

    def _compile_yara_rules(self):
        """Compiles YARA rules from a file."""
        try:
            self.yara_rules = yara.compile(filepath='./malware.yar')
            self.app.log_message("YARA rules compiled successfully.")
        except yara.Error as e:
            self.app.log_message(f"ERROR: YARA compilation error: {e}", is_error=True)
            self.yara_rules = None

    def _load_quarantined_files(self):
        """Loads quarantined file data from a JSON file."""
        try:
            quarantine_data_path = os.path.join(self.quarantine_dir, 'quarantine_data.json')
            if os.path.exists(quarantine_data_path):
                with open(quarantine_data_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except json.JSONDecodeError:
            self.app.log_message("ERROR: Failed to load quarantine data. File might be corrupted.", is_error=True)
            return {}
        except FileNotFoundError:
            return {}

    def _save_quarantined_files(self):
        """Saves quarantined file data to a JSON file."""
        quarantine_data_path = os.path.join(self.quarantine_dir, 'quarantine_data.json')
        try:
            with open(quarantine_data_path, 'w', encoding='utf-8') as f:
                json.dump(self.quarantined_files, f, indent=4)
        except IOError as e:
            self.app.log_message(f"ERROR: Failed to save quarantine data: {e}", is_error=True)
            
    def _create_quarantine_dir(self):
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
            self.app.log_message(f"Created quarantine directory at '{self.quarantine_dir}'")
        else:
            self.app.log_message(f"Using existing quarantine directory at '{self.quarantine_dir}'")

    def _create_antivirus_log(self):
        """Creates the log file if it doesn't exist."""
        log_file_path = "antivirus_log.txt"
        if not os.path.exists(log_file_path):
            with open(log_file_path, "w", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Antivirus Log Started.\n")

    def start_full_scan(self, directory):
        """
        Performs a full scan of a given directory and its subdirectories.
        """
        self.app.log_message(f"Starting full scan of: {directory}")
        files_to_scan = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
            for file in files:
                filepath = os.path.join(root, file)
                if not any(excluded in filepath for excluded in self.excluded_files):
                    files_to_scan.append(filepath)

        self.app.set_progress_bar_max(len(files_to_scan))
        scanned_count = 0
        for filepath in files_to_scan:
            self.scan_file(filepath)
            scanned_count += 1
            self.app.update_progress(scanned_count)
        self.app.log_message("Full scan complete.")

    def scan_file(self, filepath):
        """Scans a single file for known signatures."""
        if not os.path.isfile(filepath):
            return

        self.app.log_message(f"[*] Scanning file: {filepath}")
        
        # Local Signature Scan
        chunk_size = 4096
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(chunk_size):
                    for signature in self.signatures:
                        if signature in chunk:
                            self.app.log_message(f" --> THREAT DETECTED (Local Signature): Found signature '{signature.decode(errors='ignore')}'", is_threat=True)
                            self.quarantine_file(filepath)
                            return
        except IOError as e:
            self.app.log_message(f" --> ERROR: Could not read file '{filepath}': {e}", is_error=True)
            
        # YARA Scan
        if self.yara_rules:
            try:
                yara_matches = self.yara_rules.match(filepath=filepath)
                if yara_matches:
                    self.app.log_message(f" --> THREAT DETECTED (YARA): Matched rule '{yara_matches[0].rule}'", is_threat=True)
                    self.quarantine_file(filepath)
                    return
            except yara.Error as e:
                self.app.log_message(f" --> ERROR: YARA scan error for {filepath}: {e}", is_error=True)

        # VirusTotal Cloud Scan
        if self.vt_api_key:
            self._virustotal_scan(filepath)
        else:
            self.app.log_message(" --> Skipping VirusTotal scan: API key not set.")

    def _virustotal_scan(self, filepath):
        """Computes file hash and sends it to VirusTotal API."""
        self.app.log_message(" --> Starting VirusTotal cloud scan...")
        
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
        except IOError as e:
            self.app.log_message(f" --> ERROR: Could not compute hash for '{filepath}': {e}", is_error=True)
            return
            
        try:
            api_results = scan_hash_with_virustotal(file_hash, self.vt_api_key)
        except requests.exceptions.RequestException as e:
            self.app.log_message(f" --> ERROR: VirusTotal API request failed: {e}", is_error=True)
            return
        
        if api_results and api_results.get("data"):
            attributes = api_results.get("data", {}).get("attributes", {})
            malicious_count = attributes.get("last_analysis_stats", {}).get("malicious", 0)

            if malicious_count > 0:
                self.app.log_message(f" --> THREAT DETECTED (Cloud): {malicious_count} engines flagged this file.", is_threat=True)
                self.quarantine_file(filepath)
            else:
                self.app.log_message(" --> No threats detected by VirusTotal.")
        else:
            self.app.log_message(" --> Cloud scan inconclusive or file not found in VirusTotal database.")

    def quarantine_file(self, filepath):
        """Moves a detected malicious file to the quarantine directory."""
        filename = os.path.basename(filepath)
        # Avoid overwriting files by appending timestamp
        quarantine_path = os.path.join(self.quarantine_dir, f"{filename}_{int(time.time())}")
        
        try:
            shutil.move(filepath, quarantine_path)
            
            if filename not in self.quarantined_files:
                file_stats = os.stat(quarantine_path)
                file_hash = self._calculate_hash(quarantine_path)
                self.quarantined_files[filename] = {
                    "original_path": str(Path(filepath).resolve()),
                    "quarantined_at": datetime.now().isoformat(),
                    "size": file_stats.st_size,
                    "hash": file_hash
                }
            
            self._save_quarantined_files()
            self.app.log_message(f" --> Quarantined '{filename}'")
            self.app.show_threat_popup(filename)
            self.app.update_quarantine_list()
        except shutil.Error as e:
            self.app.log_message(f" --> ERROR: Could not move '{filename}' to quarantine: {e}", is_error=True)

    def restore_file(self, filename):
        """Restores a quarantined file to its original location."""
        if filename not in self.quarantined_files:
            self.app.log_message(f" --> ERROR: File '{filename}' not found in quarantine records.", is_error=True)
            return

        original_path = self.quarantined_files[filename]["original_path"]
        quarantine_path = os.path.join(self.quarantine_dir, filename)
        
        if not os.path.exists(quarantine_path):
            self.app.log_message(f" --> ERROR: Quarantined file '{filename}' does not exist.", is_error=True)
            del self.quarantined_files[filename]
            self._save_quarantined_files()
            return

        try:
            shutil.move(quarantine_path, original_path)
            del self.quarantined_files[filename]
            self._save_quarantined_files()
            self.app.log_message(f" --> RESTORED: '{filename}' restored to '{original_path}'")
            self.app.update_quarantine_list()
        except shutil.Error as e:
            self.app.log_message(f" --> ERROR: Could not restore '{filename}': {e}", is_error=True)

    def delete_quarantined_file(self, filename):
        """Deletes a file from the quarantine directory permanently."""
        if filename not in self.quarantined_files:
            self.app.log_message(f" --> ERROR: File '{filename}' not found in quarantine records.", is_error=True)
            return

        quarantine_path = os.path.join(self.quarantine_dir, filename)
        
        if not os.path.exists(quarantine_path):
            self.app.log_message(f" --> ERROR: Quarantined file '{filename}' does not exist.", is_error=True)
            del self.quarantined_files[filename]
            self._save_quarantined_files()
            return

        try:
            os.remove(quarantine_path)
            del self.quarantined_files[filename]
            self._save_quarantined_files()
            self.app.log_message(f" --> DELETED: '{filename}' was permanently removed from quarantine.")
            self.app.update_quarantine_list()
        except OSError as e:
            self.app.log_message(f" --> ERROR: Could not permanently delete '{filename}': {e}", is_error=True)
            
    def list_quarantined_files(self):
        return list(self.quarantined_files.keys())
    
    def _calculate_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except IOError:
            return None

# --- Main App Class for GUI ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.style = Style(theme="cyborg")
        self.title("Antivirus GUI")
        self.geometry("1000x700")

        self.antivirus_engine = AntivirusEngine(self)
        self.logging_enabled = False
        self.file_watcher_thread = None

        self.create_widgets()
        self.create_tray_icon()
        self.protocol("WM_DELETE_WINDOW", self.hide_window)
        
        self.withdraw()
        self.update_quarantine_list()
        self.after(100, self.process_queue)
        self.start_real_time_scan()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=BOTH, expand=True)

        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=BOTH, expand=True)
        
        log_frame = ttk.Frame(content_frame, padding=10)
        log_frame.pack(fill=BOTH, expand=True, side=LEFT)
        
        log_label = ttk.Label(log_frame, text="Antivirus Log", font=("Arial", 12, "bold"))
        log_label.pack(fill=X, pady=(0, 5))
        
        self.log_text = tk.Text(log_frame, state='disabled', wrap='word', bg='black', fg='white')
        self.log_text.pack(fill=BOTH, expand=True)
        self.log_scrollbar = ttk.Scrollbar(self.log_text, orient=VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.log_scrollbar.set)
        self.log_scrollbar.pack(side=RIGHT, fill=Y)

        quarantine_frame = ttk.Frame(content_frame, padding=10)
        quarantine_frame.pack(fill=BOTH, expand=True, side=RIGHT)
        
        quarantine_label = ttk.Label(quarantine_frame, text="Quarantined Files", font=("Arial", 12, "bold"))
        quarantine_label.pack(fill=X, pady=(0, 5))
        
        self.quarantine_listbox = tk.Listbox(quarantine_frame, bg='black', fg='white', selectmode=tk.SINGLE)
        self.quarantine_listbox.pack(fill=BOTH, expand=True)
        
        quarantine_button_frame = ttk.Frame(quarantine_frame, padding=(0, 5))
        quarantine_button_frame.pack(fill=X)

        restore_button = ttk.Button(quarantine_button_frame, text="Restore File", command=self.restore_selected_file, style='success')
        restore_button.pack(side=LEFT, expand=True, fill=X)
        
        delete_button = ttk.Button(quarantine_button_frame, text="Delete Permanently", command=self.delete_selected_file, style='danger')
        delete_button.pack(side=LEFT, expand=True, fill=X)
        
        control_frame = ttk.Frame(main_frame, padding=(0, 10))
        control_frame.pack(fill=X)
        
        full_scan_button = ttk.Button(control_frame, text="Start Full Scan", command=self.start_full_scan, style='info')
        full_scan_button.pack(side=LEFT, padx=(0, 5), expand=True, fill=X)

        manual_scan_button = ttk.Button(control_frame, text="Select & Scan File", command=self.scan_single_file, style='primary')
        manual_scan_button.pack(side=LEFT, padx=5, expand=True, fill=X)
        
        self.status_label = ttk.Label(control_frame, text="Status: Idle", font=("Arial", 10), style='success')
        self.status_label.pack(side=RIGHT, padx=5, fill=X)
        
        self.progress_bar = ttk.Progressbar(main_frame, orient=HORIZONTAL, mode='determinate')
        self.progress_bar.pack(fill=X, pady=5)
        
    def create_tray_icon(self):
        width, height = 64, 64
        icon_image = Image.new('RGB', (width, height), 'black')
        draw = ImageDraw.Draw(icon_image)
        draw.rectangle((10, 10, 54, 54), fill='red')
        
        menu = (
            pystray.MenuItem("Show Window", self.show_window),
            pystray.MenuItem("Hide Window", self.hide_window),
            pystray.MenuItem("Exit", self.exit_app)
        )
        self.tray_icon = pystray.Icon("antivirus", icon_image, "Antivirus", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def show_window(self, icon=None, item=None):
        self.deiconify()

    def hide_window(self, icon=None, item=None):
        self.withdraw()
    
    def exit_app(self, icon=None, item=None):
        if self.file_watcher_thread and self.file_watcher_thread.is_alive():
            self.file_watcher_thread.stop()
            self.file_watcher_thread.join()
        self.tray_icon.stop()
        self.destroy()
        sys.exit(0)
        
    def log_message(self, message, is_error=False, is_threat=False):
        message_queue.put((message, is_error, is_threat))
        
    def process_queue(self):
        while not message_queue.empty():
            message, is_error, is_threat = message_queue.get()
            self.log_text.config(state='normal')
            self.log_text.insert('end', message + '\n')
            self.log_text.see('end')
            self.log_text.config(state='disabled')
        self.after(100, self.process_queue)

    def set_progress_bar_max(self, total_files):
        self.progress_bar.config(maximum=total_files)

    def update_progress(self, scanned_count):
        self.progress_bar.config(value=scanned_count)

    def show_threat_popup(self, filename):
        Messagebox.show_warning(
            title="Threat Detected!",
            message=f"Threat found in file: {filename}\nFile has been quarantined.",
            parent=self
        )

    def _threaded_scan(self, path=None, manual=False):
        if not manual:
            self.status_label.config(text="Status: Real-time scanning started.")
            self.antivirus_engine.start_full_scan(path)
            self.status_label.config(text="Status: Idle.")
        else:
            self.logging_enabled = True
            self.status_label.config(text="Status: Scanning...")
            self.progress_bar.config(mode='indeterminate')
            self.progress_bar.start()

            if path and os.path.isfile(path):
                self.antivirus_engine.scan_file(path)
            else:
                self.antivirus_engine.start_full_scan(os.path.dirname(os.path.abspath(__file__)))

            self.progress_bar.stop()
            self.progress_bar.config(mode='determinate', value=0)
            self.status_label.config(text="Status: Scan Complete")
            self.logging_enabled = False
            self.update_quarantine_list()

    def start_full_scan(self):
        self.log_message("Starting full scan...")
        scan_path = os.path.dirname(os.path.abspath(__file__))
        scan_thread = threading.Thread(target=self._threaded_scan, args=(scan_path, True), daemon=True)
        scan_thread.start()

    def scan_single_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.log_message(f"Starting manual scan for: {filepath}")
            scan_thread = threading.Thread(target=self._threaded_scan, args=(filepath, True), daemon=True)
            scan_thread.start()

    def start_real_time_scan(self):
        from handler import AntivirusEventHandler
        from watchdog.observers import Observer

        self.log_message(f"Real-time scan started on: '{os.path.abspath(os.path.dirname(__file__))}'")
        self.real_time_observer = Observer()
        self.event_handler = AntivirusEventHandler(self.antivirus_engine)
        self.real_time_observer.schedule(self.event_handler, os.path.dirname(os.path.abspath(__file__)), recursive=True)
        self.real_time_observer.start()

    def update_quarantine_list(self):
        self.quarantine_listbox.delete(0, tk.END)
        files = self.antivirus_engine.list_quarantined_files()
        for filename in files:
            self.quarantine_listbox.insert(tk.END, filename)

    def restore_selected_file(self):
        selected_index = self.quarantine_listbox.curselection()
        if selected_index:
            filename = self.quarantine_listbox.get(selected_index[0])
            self.antivirus_engine.restore_file(filename)
            self.update_quarantine_list()

    def delete_selected_file(self):
        selected_index = self.quarantine_listbox.curselection()
        if selected_index:
            filename = self.quarantine_listbox.get(selected_index[0])
            self.antivirus_engine.delete_quarantined_file(filename)
            self.update_quarantine_list()

if __name__ == "__main__":
    app = App()
    app.mainloop()
