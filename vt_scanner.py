import requests

def scan_hash_with_virustotal(file_hash, api_key):
    """
    Sends a file hash to the VirusTotal API for analysis.
    Returns the scan results, or None if the request fails.
    """
    if not api_key:
        print("  --> ERROR: VirusTotal API key is not configured.")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"  --> ERROR: VirusTotal API request failed: {e}")
        return None