# OpenVigilante

OpenVigilante is a Python script that allows users to select a file, compute its MD5 hash, and check the hash against VirusTotal's database to determine if the file is malicious.

## Features

- Select a file using a graphical file dialog.
- Compute the MD5 hash of the selected file.
- Check the file hash against VirusTotal's database.
- Display a summarized report of the VirusTotal scan results.

## Prerequisites

- Python 3.x
- The following Python packages:
  - `tkinter`
  - `hashlib`
  - `requests`
- A VirusTotal API key

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/jt-wilkinson/OpenVigilante.git
    cd OpenVigilante
    ```

2. Install the required packages:

    ```sh
    pip install requests
    ```

## Usage

1. Obtain your VirusTotal API key from the [VirusTotal website](https://www.virustotal.com/).

2. Replace `YOUR_VIRUSTOTAL_API_KEY` in the script with your actual VirusTotal API key.

3. Run the script:

    ```sh
    python hash_file_virustotal.py
    ```

4. Select the file you want to check when prompted.

5. The script will compute the MD5 hash of the file and check it against VirusTotal's database.

6. The summarized report of the scan results will be displayed, showing the counts of different scan categories (e.g., undetected, malicious, type-unsupported).

## Example Output

