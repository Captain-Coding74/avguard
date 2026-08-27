import yara
import os
import sys

# This module handles all the YARA logic, including compiling
# the rules and scanning files for matches.

# Compiled rules are stored at the module level for efficiency.
# The rules are compiled once when the module is imported.
try:
    _yara_rules = yara.compile(filepath='./malware.yar')
except yara.Error as e:
    _yara_rules = None
    print(f"ERROR: YARA compilation error on import: {e}", file=sys.stderr)


def scan_with_yara(filepath, log_message):
    """
    Scans a file using the compiled YARA rules.
    Returns a list of matching rules or an empty list if no matches are found.
    """
    if _yara_rules is None:
        log_message(f"ERROR: YARA rules not loaded, skipping scan for {filepath}", is_error=True)
        return []

    if not os.path.exists(filepath):
        log_message(f"ERROR: File not found: {filepath}", is_error=True)
        return []

    try:
        matches = _yara_rules.match(filepath=filepath)
        return matches
    except yara.Error as e:
        log_message(f"ERROR: YARA scan error for {filepath}: {e}", is_error=True)
        return []
