#!/usr/bin/env python3
import csv
import json
import os
import sys
import argparse
from datetime import datetime

def parse_os_name(os_name):
    """
    Parse OS name into components for directory structure
    Examples:
    - 'AlmaLinux 9.2 ESU' -> 'AlmaLinux', '9.2', 'ESU'
    - 'CentOS Stream 8 ELS' -> 'CentOS', 'Stream8', 'ELS'
    - 'Oracle Linux 7 ELS' -> 'OracleLinux', '7', 'ELS'
    """
    parts = os_name.split()
    
    # Handle special case for CentOS Stream
    if len(parts) >= 2 and parts[0] == 'CentOS' and parts[1] == 'Stream':
        distro = parts[0]
        version = f"{parts[1]}{parts[2]}"
        variant = parts[3] if len(parts) > 3 else ""
    # Handle case for Oracle Linux 
    elif len(parts) >= 2 and parts[0] == 'Oracle' and parts[1] == 'Linux':
        distro = "OracleLinux"  # Combine the words to avoid extra directory level
        version = parts[2] if len(parts) > 2 else ""
        variant = parts[3] if len(parts) > 3 else ""
    # Normal case like 'AlmaLinux 9.2 ESU'
    else:
        distro = parts[0]
        version = parts[1] if len(parts) > 1 else ""
        variant = parts[2] if len(parts) > 2 else ""
        
    return distro, version, variant

def convert_csv_to_json(csv_file_path):
    """
    Read CVE data from CSV file and convert to list of dictionaries
    """
    try:
        with open(csv_file_path, 'r', newline='', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            data = list(reader)
            print(f"Successfully read {len(data)} entries from CSV file")
            return data
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)

def create_json_files(data, base_dir="./"):
    """
    Create JSON files in the specified directory structure
    Structure: tuxcare/DISTRO/VERSION/VARIANT/YYYY/CVE-NAME.json
    For example: tuxcare/AlmaLinux/9.2/ESU/2025/CVE-2025-21785.json
    Only overwrites files if content has changed.
    """
    # Track created files to avoid duplicates
    created_files = set()
    file_count = 0
    unchanged_count = 0
    
    for entry in data:
        try:
            cve = entry['CVE']
            os_name = entry['OS name']
            # Extract year from the Last updated field
            year = entry['Last updated'][:4]
            
            # Parse OS name into components
            distro, version, variant = parse_os_name(os_name)
            
            # Create the directory path
            if variant:
                dir_path = os.path.join(base_dir, "tuxcare", distro, version, variant, year)
            else:
                dir_path = os.path.join(base_dir, "tuxcare", distro, version, year)
                
            os.makedirs(dir_path, exist_ok=True)
            
            # Create the file path
            file_path = os.path.join(dir_path, f"{cve}.json")
            
            # Skip if we've already created this file
            if file_path in created_files:
                continue
            
            # Generate new content
            new_content = json.dumps(entry, indent=2)
            
            # Check if file exists and compare content
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        existing_content = f.read()
                        
                    # Skip if content is unchanged
                    if existing_content == new_content:
                        created_files.add(file_path)
                        unchanged_count += 1
                        continue
                except Exception as e:
                    # If reading fails, proceed with writing the file
                    print(f"Warning: Could not read existing file {file_path}: {e}")
            
            # Write the JSON file (only if new or content changed)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            created_files.add(file_path)
            file_count += 1
            
            # Print progress every 10 files
            if (file_count + unchanged_count) % 10 == 0:
                print(f"Progress: {file_count} files created/updated, {unchanged_count} unchanged")
        except KeyError as e:
            print(f"Warning: Missing field {e} in entry, skipping")
            continue
        except Exception as e:
            print(f"Error processing entry {entry.get('CVE', 'unknown')}: {e}")
            continue
    
    print(f"\nCompleted: {file_count} JSON files created/updated, {unchanged_count} files unchanged")
    return file_count

def print_sample_entry(data, os_name):
    """Print a sample entry for the specified OS"""
    sample_entry = next((entry for entry in data if entry.get('OS name') == os_name), None)
    if sample_entry:
        print(f"\nSample JSON for {os_name}:")
        print(json.dumps(sample_entry, indent=2))
        
        # Also show the file path with the new structure
        year = sample_entry['Last updated'][:4]
        cve = sample_entry['CVE']
        
        # Parse OS name into components
        distro, version, variant = parse_os_name(os_name)
        
        # Create the file path with the new structure
        if variant:
            file_path = f"tuxcare/{distro}/{version}/{variant}/{year}/{cve}.json"
        else:
            file_path = f"tuxcare/{distro}/{version}/{year}/{cve}.json"
            
        print(f"\nFile will be saved as: {file_path}")
    else:
        print(f"\nNo entries found for OS: {os_name}")

def list_os_names(data):
    """List all unique OS names in the data"""
    os_names = set(entry.get('OS name', '') for entry in data)
    print("\nAvailable OS names in the data:")
    for name in sorted(os_names):
        if name:
            print(f"  - {name}")
            # Also show how it would be parsed
            distro, version, variant = parse_os_name(name)
            if variant:
                path = f"tuxcare/{distro}/{version}/{variant}/YYYY/CVE-XXXX.json"
            else:
                path = f"tuxcare/{distro}/{version}/YYYY/CVE-XXXX.json"
            print(f"    → {path}")

def main():
    """Main function to process the CSV file and create JSON files"""
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Convert CVE CSV data to JSON files with structured folders')
    parser.add_argument('csv_file', help='Path to the CSV file to process')
    parser.add_argument('--os', help='Filter by specific OS name')
    parser.add_argument('--output-dir', default='./', help='Base directory for output files')
    parser.add_argument('--sample', help='Show sample output for specified OS without creating files')
    parser.add_argument('--list-os', action='store_true', help='List all OS names in the data')
    
    args = parser.parse_args()
    
    # Verify the CSV file exists
    if not os.path.isfile(args.csv_file):
        print(f"Error: CSV file '{args.csv_file}' not found")
        sys.exit(1)
    
    print(f"Processing CSV file: {args.csv_file}")
    
    # Convert CSV to JSON
    data = convert_csv_to_json(args.csv_file)
    
    # List OS names if requested
    if args.list_os:
        list_os_names(data)
        return
    
    # Filter for specific OS if requested
    if args.os:
        filtered_data = [entry for entry in data if entry.get('OS name') == args.os]
        print(f"Filtered to {len(filtered_data)} entries for OS: {args.os}")
        data = filtered_data
        
        if not filtered_data:
            print(f"Warning: No entries found for OS: {args.os}")
            list_os_names(data)
            return
    
    # If sample flag is provided, just show a sample without creating files
    if args.sample:
        print_sample_entry(data, args.sample)
        return
    
    # Create JSON files with the specified directory structure
    create_json_files(data, args.output_dir)
    

if __name__ == "__main__":
    main()
