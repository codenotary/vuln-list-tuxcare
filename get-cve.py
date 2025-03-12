#!/usr/bin/env python3

import os
import json
import sys
import glob
from datetime import datetime

def find_cve_file(cve_id, source=None):
    """Find the JSON file for a given CVE ID in the repository.
    
    Args:
        cve_id (str): The CVE ID to search for
        source (str, optional): Limit search to a specific source (nvd, ghsa, alpine, debian, ubuntu, etc.)
    """
    # Normalize CVE ID format
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        print(f"Error: Invalid CVE ID format. Expected format: CVE-YYYY-NNNN")
        return None
    
    # Extract the year from the CVE ID
    try:
        year = cve_id.split("-")[1]
    except IndexError:
        print(f"Error: Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN")
        return None
    
    repo_root = os.path.dirname(os.path.abspath(__file__))
    
    # Check NVD directory if source is None or 'nvd'
    if source is None or source.lower() == 'nvd':
        nvd_path = os.path.join(repo_root, "nvd", year, f"{cve_id}.json")
        if os.path.exists(nvd_path):
            return nvd_path
    
    # Check Ubuntu directory if source is None or 'ubuntu'
    if source is None or source.lower() == 'ubuntu':
        ubuntu_path = os.path.join(repo_root, "ubuntu", year, f"{cve_id}.json")
        if os.path.exists(ubuntu_path):
            return ubuntu_path
    
    # Check Debian directory if source is None or 'debian'
    if source is None or source.lower() == 'debian':
        debian_path = os.path.join(repo_root, "debian", year, f"{cve_id}.json")
        if os.path.exists(debian_path):
            return debian_path
    
    # Search in GHSA files if source is None or 'ghsa'
    if source is None or source.lower() == 'ghsa':
        ghsa_base = os.path.join(repo_root, "ghsa")
        if os.path.exists(ghsa_base):
            for ecosystem_dir in os.listdir(ghsa_base):
                ecosystem_path = os.path.join(ghsa_base, ecosystem_dir)
                if os.path.isdir(ecosystem_path):
                    # Use glob to recursively find all JSON files
                    for json_file in glob.glob(os.path.join(ecosystem_path, "**/*.json"), recursive=True):
                        try:
                            with open(json_file, 'r') as f:
                                data = json.load(f)
                                # Check if this GHSA entry references our CVE
                                if "Advisory" in data and "Identifiers" in data["Advisory"]:
                                    for identifier in data["Advisory"]["Identifiers"]:
                                        if identifier.get("Type") == "CVE" and identifier.get("Value") == cve_id:
                                            return json_file
                        except (json.JSONDecodeError, IOError) as e:
                            print(f"Warning: Could not parse {json_file}: {e}")
    
    # Check other sources based on the source parameter
    if source is None or source.lower() in ['alpine', 'amazon', 'oracle', 'photon', 'redhat', 'suse']:
        # The actual source name as it appears in the directory structure
        source_dir = source.lower() if source else None
        
        # For each possible source directory
        for dir_name in [source_dir] if source_dir else ['alpine', 'amazon', 'oracle', 'photon', 'redhat', 'suse']:
            source_base = os.path.join(repo_root, dir_name)
            if os.path.exists(source_base):
                # Search through all subdirectories
                for root, dirs, files in os.walk(source_base):
                    for file in files:
                        if file.endswith('.json'):
                            json_file = os.path.join(root, file)
                            try:
                                with open(json_file, 'r') as f:
                                    data = json.load(f)
                                    # Alpine format
                                    if "secfixes" in data:
                                        for version, cves in data["secfixes"].items():
                                            if cve_id in cves:
                                                return json_file
                                    # Other formats might have different structures
                                    # Add more format checks here as needed
                            except (json.JSONDecodeError, IOError) as e:
                                print(f"Warning: Could not parse {json_file}: {e}")
    
    # If we get here, the CVE wasn't found
    return None

def get_cve_info(cve_id, source=None):
    """Get the JSON content for a given CVE ID.
    
    Args:
        cve_id (str): The CVE ID to search for
        source (str, optional): Limit search to a specific source (nvd, ghsa, alpine, debian, ubuntu, etc.)
    """
    file_path = find_cve_file(cve_id, source)
    if not file_path:
        print(f"Error: Could not find data for {cve_id}" + (f" in {source}" if source else ""))
        return None
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            # Add source information to help identify where this data came from
            if "nvd" in file_path:
                data["_source"] = "NVD (National Vulnerability Database)"
            elif "ghsa" in file_path:
                data["_source"] = "GHSA (GitHub Security Advisory)"
            elif "alpine" in file_path:
                data["_source"] = f"Alpine Linux ({os.path.basename(os.path.dirname(os.path.dirname(file_path)))}/{os.path.basename(os.path.dirname(file_path))})"
            elif "debian" in file_path:
                data["_source"] = "Debian Linux"
            elif "ubuntu" in file_path:
                data["_source"] = "Ubuntu Linux"
            elif "amazon" in file_path:
                data["_source"] = "Amazon Linux"
            elif "oracle" in file_path:
                data["_source"] = "Oracle Linux"
            elif "photon" in file_path:
                data["_source"] = "VMware Photon OS"
            elif "redhat" in file_path:
                data["_source"] = "Red Hat Linux"
            elif "suse" in file_path:
                data["_source"] = "SUSE Linux"
            else:
                data["_source"] = "Unknown Source"
            return data
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error: Could not read or parse {file_path}: {e}")
        return None

def print_cve_info(cve_data, format_json=True):
    """Print the CVE information in a readable format."""
    if not cve_data:
        return
    
    # Always print full JSON output
    print(json.dumps(cve_data, indent=2))

def print_help():
    """Print help information for the script."""
    print("""USAGE:  
  get-cve.py <CVE-ID> [options]
""")
    print("""ARGUMENTS:
  <CVE-ID>              The CVE ID to search for (e.g., CVE-2022-1664)
""")
    print("""OPTIONS:
  --help                Display this help message
  --source SOURCE       Limit search to a specific source
""")
    print("""AVAILABLE SOURCES:
  nvd                   National Vulnerability Database
  ghsa                  GitHub Security Advisories
  alpine                Alpine Linux vulnerabilities
  debian                Debian Linux vulnerabilities
  ubuntu                Ubuntu Linux vulnerabilities
  amazon                Amazon Linux vulnerabilities
  oracle                Oracle Linux vulnerabilities
  photon                VMware Photon OS vulnerabilities
  redhat                Red Hat Linux vulnerabilities
  suse                  SUSE Linux vulnerabilities
""")
    print("""EXAMPLES:
  get-cve.py CVE-2022-1664
  get-cve.py CVE-2022-1664 --source alpine
  get-cve.py CVE-2022-1664 --source nvd
""")

def main():
    """Main function to handle command line arguments."""
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return 0 if "--help" in sys.argv else 1
    
    cve_id = sys.argv[1]
    source = None
    
    # Check if source is specified
    if len(sys.argv) > 2 and sys.argv[2] == "--source" and len(sys.argv) > 3:
        source = sys.argv[3]
    
    cve_data = get_cve_info(cve_id, source)
    if cve_data:
        print_cve_info(cve_data)
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
