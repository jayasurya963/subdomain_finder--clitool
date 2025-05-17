#!/usr/bin/env python3

import argparse
import socket
import requests
import concurrent.futures
import sys
import time
from queue import Queue

# --- Configuration ---
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 2  # seconds for DNS resolution
CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
USER_AGENT = "SubdomainCLI/1.0 (+https://github.com/yourusername/subdomain_cli)" # Be a good internet citizen

# --- Helper Functions ---
def print_message(message, verbose=False, is_verbose_msg=False):
    """Prints messages, respecting verbosity."""
    if is_verbose_msg:
        if verbose:
            print(f"[*] {message}", file=sys.stderr)
    else:
        print(message)

def resolve_subdomain(subdomain_to_check, timeout, verbose):
    """Attempts to resolve a subdomain. Returns IP if successful, None otherwise."""
    try:
        # Using gethostbyname_ex for potentially more info, though gethostbyname is often enough
        # It also helps to distinguish between NXDOMAIN and other errors better than gethostbyname alone.
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(subdomain_to_check)
        print_message(f"Resolved: {subdomain_to_check} -> {ipaddrlist[0]}", verbose, is_verbose_msg=True)
        return subdomain_to_check # Return the subdomain itself if found
    except socket.gaierror: # Host not found (NXDOMAIN)
        print_message(f"No record for: {subdomain_to_check}", verbose, is_verbose_msg=True)
        return None
    except socket.timeout:
        print_message(f"Timeout resolving: {subdomain_to_check}", verbose, is_verbose_msg=True)
        return None
    except Exception as e:
        print_message(f"Error resolving {subdomain_to_check}: {e}", verbose, is_verbose_msg=True)
        return None

def worker_bruteforce(domain, word_queue, found_subdomains_set, results_list, timeout, verbose):
    """Worker function for threaded brute-forcing."""
    while not word_queue.empty():
        try:
            word = word_queue.get_nowait()
        except Exception: # Should ideally be queue.Empty, but get_nowait can be tricky
            return

        subdomain = f"{word}.{domain}"
        if resolve_subdomain(subdomain, timeout, verbose):
            if subdomain not in found_subdomains_set:
                found_subdomains_set.add(subdomain)
                results_list.append(subdomain)
        word_queue.task_done()


def brute_force_subdomains(domain, wordlist_path, num_threads, timeout, verbose):
    """
    Performs DNS brute-forcing for subdomains.
    Returns a list of found subdomains.
    """
    found_subdomains_set = set() # For quick deduplication during threading
    results_list = []
    word_queue = Queue()

    print_message(f"Starting DNS brute-force for {domain} with {num_threads} threads...", verbose, is_verbose_msg=True)

    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
            if not words:
                print_message("Wordlist is empty or contains only whitespace.", verbose, is_verbose_msg=True)
                return []
            for word in words:
                word_queue.put(word)
    except FileNotFoundError:
        print_message(f"Error: Wordlist file not found at '{wordlist_path}'", file=sys.stderr)
        return []
    except Exception as e:
        print_message(f"Error reading wordlist: {e}", file=sys.stderr)
        return []

    print_message(f"Loaded {word_queue.qsize()} words from wordlist.", verbose, is_verbose_msg=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for _ in range(num_threads):
            futures.append(executor.submit(worker_bruteforce, domain, word_queue, found_subdomains_set, results_list, timeout, verbose))

        # Wait for all tasks in the queue to be processed
        word_queue.join()

        # Optional: Wait for futures to complete (they should if queue.join() worked)
        # for future in concurrent.futures.as_completed(futures):
        #     pass

    print_message("DNS brute-force scan complete.", verbose, is_verbose_msg=True)
    return results_list

def fetch_crtsh_subdomains(domain, verbose):
    """
    Fetches subdomains from crt.sh.
    Returns a list of unique subdomains.
    """
    print_message(f"Fetching subdomains from crt.sh for {domain}...", verbose, is_verbose_msg=True)
    found_subdomains = set()
    url = CRTSH_URL.format(domain=domain)
    headers = {'User-Agent': USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=15) # Increased timeout for crt.sh
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        
        data = response.json()
        for entry in data:
            name_value = entry.get('name_value', '')
            # crt.sh can return multiple subdomains in one name_value, newline separated
            subdomains_in_entry = name_value.split('\n')
            for sub in subdomains_in_entry:
                sub = sub.strip()
                # Ensure it's actually a subdomain of the target and not the target itself or a wildcard entry
                if sub and domain in sub and sub != domain and not sub.startswith('*.'):
                    found_subdomains.add(sub)
                    
    except requests.exceptions.RequestException as e:
        print_message(f"Error fetching from crt.sh: {e}", file=sys.stderr)
    except ValueError: # Includes JSONDecodeError
        print_message(f"Error parsing JSON response from crt.sh. Response text: {response.text[:200]}...", file=sys.stderr)
    except Exception as e:
        print_message(f"An unexpected error occurred with crt.sh: {e}", file=sys.stderr)


    print_message(f"Found {len(found_subdomains)} unique subdomains from crt.sh.", verbose, is_verbose_msg=True)
    return list(found_subdomains)

def main():
    parser = argparse.ArgumentParser(description="CLI Subdomain Finder Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to a wordlist file for brute-forcing")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Number of threads for brute-forcing (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"DNS resolution timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--passive-only", action="store_true", help="Only perform passive discovery (crt.sh)")
    parser.add_argument("--active-only", action="store_true", help="Only perform active discovery (DNS brute-force)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if args.passive_only and args.active_only:
        print_message("Error: Cannot use --passive-only and --active-only together.", file=sys.stderr)
        sys.exit(1)

    if args.active_only and not args.wordlist:
        print_message("Error: --wordlist is required for --active-only mode.", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    # If neither --passive-only nor --active-only is specified, and no wordlist, default to passive
    run_passive = True
    run_active = bool(args.wordlist) # Only run active if wordlist is provided

    if args.passive_only:
        run_active = False
    if args.active_only:
        run_passive = False


    all_found_subdomains = set()
    start_time = time.time()

    # Set global socket timeout
    socket.setdefaulttimeout(args.timeout)

    if run_passive:
        crtsh_results = fetch_crtsh_subdomains(args.domain, args.verbose)
        for sub in crtsh_results:
            all_found_subdomains.add(sub)

    if run_active:
        if not args.wordlist:
            print_message("Warning: No wordlist provided. Skipping DNS brute-force. Use -w to specify one.", file=sys.stderr)
        else:
            bruteforce_results = brute_force_subdomains(args.domain, args.wordlist, args.threads, args.timeout, args.verbose)
            for sub in bruteforce_results:
                all_found_subdomains.add(sub)
    
    if not all_found_subdomains:
        print_message(f"\nNo subdomains found for {args.domain}.", verbose=True) # Always print this if nothing found
    else:
        print_message(f"\n--- Found {len(all_found_subdomains)} Unique Subdomain(s) ---", verbose=True)
        sorted_subdomains = sorted(list(all_found_subdomains))
        for sub in sorted_subdomains:
            print(sub) # Print to stdout for easy piping

        if args.output:
            try:
                with open(args.output, 'w') as f:
                    for sub in sorted_subdomains:
                        f.write(sub + '\n')
                print_message(f"\nResults saved to {args.output}", verbose=True)
            except IOError as e:
                print_message(f"Error writing to output file {args.output}: {e}", file=sys.stderr)

    end_time = time.time()
    print_message(f"Scan completed in {end_time - start_time:.2f} seconds.", args.verbose, is_verbose_msg=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_message("\nProcess interrupted by user. Exiting.", file=sys.stderr)
        sys.exit(1)