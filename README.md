# Subdomain CLI Tool

A simple yet effective command-line tool written in Python for discovering subdomains of a given domain. It utilizes both active (DNS brute-forcing) and passive (crt.sh) methods.

## Features

*   **Passive Discovery:** Fetches subdomains from [crt.sh](https://crt.sh/) Certificate Transparency logs.
*   **Active Discovery:** Performs DNS brute-forcing using a provided wordlist.
*   **Multithreaded Brute-Forcing:** Speeds up active scanning.
*   **Configurable:**
    *   Specify target domain.
    *   Provide a custom wordlist.
    *   Set the number of threads for brute-forcing.
    *   Adjust DNS resolution timeout.
    *   Output results to a file.
    *   Choose between passive-only, active-only, or combined modes.
    *   Verbose mode for detailed logging.
*   **Cross-Platform:** Runs on any system with Python 3 and `requests` installed.

## Prerequisites

*   **Python 3.x**
*   **pip** (Python package installer)
*   The **`requests`** library

## Installation

1.  **Clone the repository or download the script:**
    ```bash
    # If you have it in a git repo:
    # git clone https://github.com/your-username/subdomain-cli-tool.git
    # cd subdomain-cli-tool

    # Otherwise, just ensure subdomain_cli.py is in your current directory
    ```

2.  **Install dependencies:**
    It's recommended to use a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install requests
    ```
    Or, install globally (not recommended for all projects, but fine for a single script):
    ```bash
    pip install requests
    ```

3.  **(Optional) Make the script executable (Linux/macOS):**
    ```bash
    chmod +x subdomain_cli.py
    ```

## Usage

You can run the script using `python3 subdomain_cli.py` or `./subdomain_cli.py` (if executable).

```bash
./subdomain_cli.py -h

Passive discovery only for example.com:
./subdomain_cli.py -d example.com --passive-only
.
.
.
.
Active brute-force discovery for example.com using wordlist.txt:
./subdomain_cli.py -d example.com -w /path/to/your/wordlist.txt --active-only
.
.
.
.
Combined passive and active discovery, saving results to found.txt:
./subdomain_cli.py -d example.com -w /path/to/your/wordlist.txt -o found.txt
(If --passive-only or --active-only are not specified, it will run passive discovery, and also active discovery if a wordlist is provided.)
.
.
.
.
Combined discovery with 20 threads and verbose output:
./subdomain_cli.py -d example.com -w /path/to/your/wordlist.txt -t 20 -v
.
.
.
.
Passive discovery with verbose output and results saved:
./subdomain_cli.py -d example.com --passive-only -v -o passive_results.txt
