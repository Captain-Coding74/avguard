import os
import shutil
import hashlib
import requests
import sys
from vt_scanner import scan_hash_with_virustotal
import threading
from datetime import datetime

class AntivirusEngine:
    """
    Core engine for signature and behavioral-based scanning.
    This is separated from the UI for a cleaner design.
    """
    def __init__(self, app_log):
        """
        Initializes the engine with a reference to the main application's log.
        """
        # A unique signature that is unlikely to cause a false positive.
        self.signatures = [
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            b'\x4d\x5a\x90\x00'
        ]
        # Common suspicious behavior patterns
        self.behavior_patterns = []
        self.quarantine_dir = "quarantine"
        self.log = app_log
        
        # New: A dictionary to store the original paths of quarantined files for restoration.
        self.quarantined_files = {}

        # Exclude directories to avoid scanning internal files or creating an endless loop.
        self.excluded_dirs = [self.quarantine_dir, "__pycache__"]
        self.excluded_files = ["antivirus_log.txt", os.path.basename(sys.argv[0])]
        
        # Ensure the quarantine directory exists
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
            self.log_message(f"Created quarantine directory at '{self.quarantine_dir}'")
        else:
            self.log_message(f"Using existing quarantine directory at '{self.quarantine_dir}'")
        
        # New: Get VirusTotal API key from environment variable
        self.vt_api_key = os.getenv("VT_API_KEY")

        if not self.vt_api_key:
            self.log_message("ERROR: VirusTotal API key not found. Please set the 'VT_API_KEY' environment variable.")
            sys.exit(1)

    def log_message(self, message):
        """Helper to append a message to the shared application log and a log file."""
        # Log to the GUI
        self.log.config(state='normal')
        self.log.insert('end', message + '\n')
        self.log.see('end')
        self.log.config(state='disabled')
        
        # Also log to a file for historical reference
        with open("antivirus_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    
    def start_scan(self, directory):
        """
        Performs a full scan of a given directory and its subdirectories.
        """
        self.log_message(f"Starting full scan of: {directory}")
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
            for file in files:
                filepath = os.path.join(root, file)
                self.scan_file(filepath)
        self.log_message("Full scan complete.")

    def scan_file(self, filepath):
        """
        Scans a single file for known signatures and suspicious behavior.
        Now handles both text and binary files.
        """
        # Exclude internal files from the scan to prevent recursion
        if any(excluded in filepath for excluded in self.excluded_files):
            return

        # Don't scan the current running script.
        if os.path.abspath(filepath) == os.path.abspath(sys.argv[0]):
            return

        if not os.path.isfile(filepath):
            return

        self.log_message(f"[*] Scanning file: {filepath}")

        # The size of chunks to read from the file. This is a memory optimization for large files.
        chunk_size = 4096
        
        try:
            with open(filepath, "rb") as f: # Open file in binary mode
                while chunk := f.read(chunk_size):
                    # Signature-based detection for binary data
                    for signature in self.signatures:
                        if signature in chunk:
                            self.log_message(f"  --> THREAT DETECTED (Local): Found signature '{signature.decode(errors='ignore')}'")
                            self.quarantine_file(filepath)
                            return
                    
                    # Heuristic/Behavioral-based detection for text data
                    try:
                        text_chunk = chunk.decode('utf-8', errors='ignore')
                        for pattern in self.behavior_patterns:
                            if pattern in text_chunk:
                                self.log_message(f"  --> SUSPICIOUS BEHAVIOR (Local): Found pattern '{pattern}'")
                                self.quarantine_file(filepath)
                                return
                    except UnicodeDecodeError:
                        continue

            # After local scan, check with VirusTotal if no local threat was found
            self._virustotal_scan(filepath)

        except IOError as e:
            self.log_message(f"  --> ERROR: Could not read file '{filepath}': {e}")
            
    def _virustotal_scan(self, filepath):
        """Computes file hash and sends it to VirusTotal API."""
        self.log_message("  --> Starting VirusTotal cloud scan...")
        
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
        except IOError as e:
            self.log_message(f"  --> ERROR: Could not compute hash for '{filepath}': {e}")
            return
            
        try:
            api_results = scan_hash_with_virustotal(file_hash, self.vt_api_key)
        except requests.exceptions.RequestException as e:
            self.log_message(f"  --> ERROR: VirusTotal API request failed: {e}")
            return

        if api_results and api_results.get("data"):
            attributes = api_results.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious_count = last_analysis_stats.get("malicious", 0)

            if malicious_count > 0:
                self.log_message(f"  --> THREAT DETECTED (Cloud): {malicious_count} antivirus engines flagged this file.")
                self.quarantine_file(filepath)
            else:
                self.log_message("  --> No threats detected by VirusTotal.")
        else:
            self.log_message("  --> Cloud scan inconclusive or file not found in VirusTotal database.")

    def quarantine_file(self, filepath):
        """Moves a detected malicious file to the quarantine directory."""
        filename = os.path.basename(filepath)
        quarantine_path = os.path.join(self.quarantine_dir, filename)
        
        try:
            # Store the original path, timestamp, size, and hash for restoration
            if filename not in self.quarantined_files:
                file_stats = os.stat(filepath)
                file_hash = self._calculate_hash(filepath)
                self.quarantined_files[filename] = {
                    "original_path": filepath,
                    "quarantined_at": datetime.now().isoformat(),
                    "size": file_stats.st_size,
                    "hash": file_hash
                }
            
            shutil.move(filepath, quarantine_path)
            self.log_message(f"  --> Quarantined '{filename}'")
        except shutil.Error as e:
            self.log_message(f"  --> ERROR: Could not move '{filename}' to quarantine: {e}")

    def restore_file(self, filename):
        """Restores a quarantined file to its original location."""
        if filename not in self.quarantined_files:
            self.log_message(f"  --> ERROR: File '{filename}' not found in quarantine records.")
            return

        original_path = self.quarantined_files[filename]["original_path"]
        quarantine_path = os.path.join(self.quarantine_dir, filename)
        
        if not os.path.exists(quarantine_path):
            self.log_message(f"  --> ERROR: Quarantined file '{filename}' does not exist.")
            del self.quarantined_files[filename]
            return

        try:
            shutil.move(quarantine_path, original_path)
            del self.quarantined_files[filename]
            self.log_message(f"  --> RESTORED: '{filename}' restored to '{original_path}'")
        except shutil.Error as e:
            self.log_message(f"  --> ERROR: Could not restore '{filename}': {e}")

    def delete_quarantined_file(self, filename):
        """Deletes a file from the quarantine directory permanently."""
        if filename not in self.quarantined_files:
            self.log_message(f"  --> ERROR: File '{filename}' not found in quarantine records.")
            return

        quarantine_path = os.path.join(self.quarantine_dir, filename)
        
        if not os.path.exists(quarantine_path):
            self.log_message(f"  --> ERROR: Quarantined file '{filename}' does not exist.")
            del self.quarantined_files[filename]
            return

        try:
            os.remove(quarantine_path)
            del self.quarantined_files[filename]
            self.log_message(f"  --> DELETED: '{filename}' was permanently removed from quarantine.")
        except OSError as e:
            self.log_message(f"  --> ERROR: Could not permanently delete '{filename}': {e}")
            
    def list_quarantined_files(self):
        """Returns a list of files in the quarantine directory."""
        return list(self.quarantined_files.keys())
    
    def _calculate_hash(self, filepath):
        """Calculates the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except IOError:
            return None
