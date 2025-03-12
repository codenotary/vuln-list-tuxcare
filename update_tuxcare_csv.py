#!/usr/bin/env python3
import os
import sys
import requests
import hashlib
import time
from datetime import datetime

# URL for the TuxCare CSV (replace with actual URL when known)
CSV_URL = "https://cve.tuxcare.com/els/download-csv"  # Replace with actual URL
LOCAL_CSV_PATH = "tuxcare.csv"
NEW_CSV_PATH = "tuxcare.csv.new"
UPDATED_CSV_PATH = "tuxcare_updated.csv"

def download_csv():
    """Download the CSV file from the TuxCare website"""
    try:
        print(f"Downloading CSV from {CSV_URL}...")
        response = requests.get(CSV_URL, timeout=60)
        response.raise_for_status()
        
        # Save to a new file
        with open(NEW_CSV_PATH, 'wb') as f:
            f.write(response.content)
        
        print(f"CSV downloaded successfully to {NEW_CSV_PATH}")
        return True
    except Exception as e:
        print(f"Error downloading CSV: {e}")
        return False

def check_for_changes():
    """Check if the downloaded CSV is different from the existing one"""
    if not os.path.exists(LOCAL_CSV_PATH):
        print(f"No existing CSV found at {LOCAL_CSV_PATH}, will use the new one")
        os.rename(NEW_CSV_PATH, UPDATED_CSV_PATH)
        return True
    
    with open(LOCAL_CSV_PATH, 'rb') as f:
        old_hash = hashlib.sha256(f.read()).hexdigest()
    
    with open(NEW_CSV_PATH, 'rb') as f:
        new_hash = hashlib.sha256(f.read()).hexdigest()
    
    if old_hash != new_hash:
        print("CSV has changed, will update the data")
        os.rename(NEW_CSV_PATH, UPDATED_CSV_PATH)
        return True
    else:
        print("No changes detected in the CSV")
        os.remove(NEW_CSV_PATH)
        return False

def main():
    """Main function to update the CSV file"""
    print(f"Starting CSV update at {datetime.now().isoformat()}")
    
    success = download_csv()
    if not success:
        print("Failed to download CSV, exiting")
        sys.exit(1)
    
    changes = check_for_changes()
    
    if changes:
        print("CSV has been updated and is ready for conversion")
    else:
        print("No changes detected, skipping conversion")
    
    print(f"CSV update process completed at {datetime.now().isoformat()}")

if __name__ == "__main__":
    main()