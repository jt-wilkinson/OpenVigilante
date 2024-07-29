import tkinter as tk
from tkinter import filedialog
import hashlib
import requests
from collections import defaultdict

# Function to select a file
def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename()  # Open file dialog and get the file path
    return file_path

# Function to hash the file using MD5
def hash_file(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

# Function to check the hash with VirusTotal
def check_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return response.json() if response.status_code in {400, 403, 404} else None
    
# Function to print the VirusTotal report
def print_report(vt_result):
    if 'data' in vt_result:
        attributes = vt_result['data']['attributes']
        print("\nVirusTotal Report:")
        print(f"MD5: {attributes.get('md5')}")
        print(f"SHA-1: {attributes.get('sha1')}")
        print(f"SHA-256: {attributes.get('sha256')}")
        print(f"First Submission: {attributes.get('first_submission_date')}")
        print(f"Last Analysis Date: {attributes.get('last_analysis_date')}")
        print(f"Total Scans: {len(attributes.get('last_analysis_results', {}))}")
        
        print("\nScan Summary:")
        scan_summary = defaultdict(int)
        for result in attributes.get('last_analysis_results', {}).values():
            scan_summary[result['category']] += 1
        
        for category, count in scan_summary.items():
            print(f"{category.capitalize()}: {count}")
    else:
        print("Error:", vt_result.get('error', {}).get('message', 'Unknown error'))

# Main function
def main():
    api_key = "YOUR_API_KEY"
    print("Please select a file to hash:")
    file_path = select_file()
    if file_path:
        file_hash = hash_file(file_path)
        print(f"The MD5 hash of the file is: {file_hash}")
        print("Checking the hash with VirusTotal...")
        vt_result = check_virustotal(file_hash, api_key)
        
        if vt_result:
            print_report(vt_result)
        else:
            print("Failed to retrieve the report from VirusTotal.")
    else:
        print("No file selected.")

if __name__ == "__main__":
    main()