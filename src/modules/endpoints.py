import subprocess
import socket
import json
import os
"""
This module provides functionality to read JSON files, check domain accessibility, and scan endpoints using ffuf.
Functions:
    read_json(file_path): Reads and returns the content of a JSON file.
    is_domain_accessible(domain): Checks if the given domain is accessible.
    check_endpoints(subdomain, wordlist_path): Scans the given subdomain for endpoints using ffuf and returns the results.
    main(subdomains): Main function to check multiple subdomains and print accessible endpoints.
Exceptions:
    socket.error: Raised when there is an error with socket operations.
    socket.gaierror: Raised when there is an address-related error with socket operations.
    socket.timeout: Raised when a socket operation times out.
    ConnectionRefusedError: Raised when a connection attempt is refused.
    Exception: Raised when there is an error reading ffuf results.
"""

def read_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def is_domain_accessible(domain):
    try:
        socket.create_connection((domain, 443), timeout=30)
        return True
    except (socket.error, socket.gaierror, socket.timeout, ConnectionRefusedError):
        return False

def check_endpoints(subdomain):
    results = {}
    wordlist_path = os.getenv('DIRECTORY_WORDLIST')
    url = subdomain if subdomain.startswith(('http://', 'https://')) else f"https://{subdomain}"
    domain_accessible = is_domain_accessible(subdomain)
    if domain_accessible:
        command = f"ffuf -w {wordlist_path} -u {url}/FUZZ -o /tmp/ffuf_results.json -s -of json"
        subprocess.run(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        try:
            results_raw = read_json("/tmp/ffuf_results.json")
            for result in results_raw.get("results", []):
                status_code = result.get("status")
                if status_code in [200, 301, 302]:
                    results[result["url"]] = status_code
            return results
        except Exception as e:
            print(f"[bold red][-]Error reading ffuf results: {e}[/bold red]")
    return {}


def main(subdomains):
    output_dict = {}
    for subdomain in subdomains:
        if is_domain_accessible(subdomain):
            results = check_endpoints(subdomain)
            print(f"[+] Found {len(results)} endpoints for {subdomain}")
            output_dict.update(results)
    
    for url, status_code in output_dict.items():
        if(status_code == 200 or status_code == 301 or status_code == 302):
            print(f"  {url} - Status Code: {status_code}")
        else:
            print(f"  {url} - Status Code: {status_code}")