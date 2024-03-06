# Description of the script
DESCRIPTION = """
This script fetches JSON data from a URL, downloads associated files, and scans archives for keywords.
***Note: the output will default to key-value pair searches first. If you want full free text search, which can be a little messy, 
please use the --free-text switch after the keyword switch***
"""

# Version control
VERSION = "1.0.1"

import argparse
import os
import requests
from urllib.parse import urljoin
from urllib3.exceptions import InsecureRequestWarning
import tarfile
import re
import sys

def fetch_json(url):
    try:
        # Suppress Cert Warnings
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error fetching JSON:", e)
        return None

def download_files(base_url, urls):
    newly_downloaded_files = []
    existing_files = []
    for url in urls:
        full_url = urljoin(base_url, url)
        filename = os.path.basename(full_url)
        if not os.path.exists(filename):
            try:
                response = requests.get(full_url, verify=False)
                response.raise_for_status()
                with open(filename, 'wb') as file:
                    file.write(response.content)
                print(f"File downloaded: {filename}")
                newly_downloaded_files.append(filename)
            except requests.exceptions.RequestException as e:
                print(f"Error downloading file from {full_url}: {e}")
        else:
            print(f"File '{filename}' already exists. Skipping download.")
            existing_files.append(filename)
    return newly_downloaded_files, existing_files

def parse_and_download(json_data, base_url, url):
    newly_downloaded_files = []
    existing_files = []
    for key, value in json_data.items():
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    for k, v in entry.items():
                        if k == "urls":
                            print(f"\nProcessing entry under key '{key}':")
                            new_files, existing = download_files(base_url, v)
                            newly_downloaded_files.extend(new_files)
                            existing_files.extend(existing)
                        else:
                            print(f"{k}: {v}")
                    print()  # Print an empty line for readability
    return newly_downloaded_files, existing_files

def scan_archive(tgz_file, keywords):
    found_keywords = []
    # Open the .tgz file
    with tarfile.open(tgz_file, "r:gz") as tar:
        for member in tar.getmembers():
            # Skip directories
            if member.isdir():
                continue
            # Extract file from archive
            file_content = tar.extractfile(member)
            if file_content:
                # Read and decode content
                content = file_content.read().decode('utf-8', errors='ignore')
                # Split content by lines and search for key-value pairs
                for line in content.split('\n'):
                    for keyword in keywords:
                        # Search for key-value pairs containing the keyword
                        match = re.search(rf'(\b{keyword}\b)\s*:\s*(.*)', line, re.IGNORECASE)
                        if match and match.group(1) and match.group(2) and match.group(2).strip():
                            value = match.group(2).strip()
                            if any(c.isalnum() for c in value):
                                print(f"Found '{match.group(1)}' in '{member.name}': '{value}'")
                                found_keywords.append((match.group(1), value))
    return found_keywords

def scan_archive_free_text(tgz_file, keywords):
    found_keywords = []
    # Open the .tgz file
    with tarfile.open(tgz_file, "r:gz") as tar:
        for member in tar.getmembers():
            # Skip directories
            if member.isdir():
                continue
            # Extract file from archive
            file_content = tar.extractfile(member)
            if file_content:
                # Read and decode content
                content = file_content.read().decode('utf-8', errors='ignore')
                # Search for free text containing the keyword
                for line in content.split('\n'):
                    for keyword in keywords:
                        if keyword.lower() in line.lower():
                            print(f"Found '{keyword}' keyword in free text in '{member.name}': '{line.strip()}'")
                            found_keywords.append((keyword, line.strip()))
    return found_keywords

def print_border(content):
    border = '-' * (len(content) + 4)
    print(f"\n{border}\n  {content}\n{border}")

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("-u", "--url", help="URL of the JSON file", required=True)
    parser.add_argument("-k", "--keywords", nargs='+', help="Keywords to search for in archives", required=True)
    parser.add_argument("--free-text", action="store_true", help="Enable free text search in archives")
    args = parser.parse_args()

    # Fetch JSON data and download associated files
    json_data = fetch_json(args.url)
    if json_data:
        print_border("JSON data retrieved successfully")
        base_url = '/'.join(args.url.split('/')[:-1])  # Extracting base URL
        
        # Download files
        newly_downloaded_files, existing_files = parse_and_download(json_data, base_url, args.url)
        
        # Separate output for newly downloaded files
        print_border("Newly downloaded files")
        for file in newly_downloaded_files:
            print(file)
        print(f"Total newly downloaded files: {len(newly_downloaded_files)}")
        
        # Separate output for existing files
        print_border("Existing files")
        for file in existing_files:
            print(file)
        print(f"Total existing files: {len(existing_files)}")
        
        # Combine newly downloaded and existing files for keyword search
        all_files = newly_downloaded_files + existing_files
        
        # Scan each downloaded archive for keywords
        for file in all_files:
            print_border(f"Scanning {file} for keywords")
            if args.free_text:
                keywords_found = scan_archive_free_text(file, args.keywords)
            else:
                keywords_found = scan_archive(file, args.keywords)
            if not keywords_found:
                print("No keywords found.")
                
    else:
        print("Failed to retrieve JSON data.")

if __name__ == "__main__":
    main()
