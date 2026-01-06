import subprocess
import socket
import json
import os
import tempfile
import time
import hashlib
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
    """Read JSON file with error handling"""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"[-] Invalid JSON in {file_path}: {e}")
        return None
    except Exception as e:
        print(f"[-] Error reading {file_path}: {e}")
        return None

def is_domain_accessible(domain):
    try:
        socket.create_connection((domain, 443), timeout=30)
        return True
    except (socket.error, socket.gaierror, socket.timeout, ConnectionRefusedError):
        return False

def get_wordlist_path():
    """Get wordlist path with fallback and validation"""
    wordlist_path = os.getenv('DIRECTORY_WORDLIST')
    
    # Fallback to default wordlist path if environment variable is not set
    if not wordlist_path:
        wordlist_path = "/etc/config/wordlist.txt"
        print(f"[+] Using default wordlist path: {wordlist_path}")
    
    return wordlist_path

def check_endpoints(subdomain):
    """Check endpoints for a subdomain using ffuf with robust error handling"""
    results = {}
    wordlist_path = get_wordlist_path()
    
    if not os.path.exists(wordlist_path):
        print(f"[-] Wordlist not found: {wordlist_path}")
        print(f"[-] Please ensure the wordlist file exists or set DIRECTORY_WORDLIST environment variable")
        return results
    
    url = subdomain if subdomain.startswith(('http://', 'https://')) else f"https://{subdomain}"
    domain_accessible = is_domain_accessible(subdomain)
    
    if not domain_accessible:
        print(f"[-] Domain not accessible: {subdomain}")
        return results
    
    # Create unique temporary file for this scan
    domain_hash = hashlib.md5(subdomain.encode()).hexdigest()[:8]
    timestamp = int(time.time())
    temp_file = f"/tmp/ffuf_results_{domain_hash}_{timestamp}.json"
    
    try:
        # Build ffuf command with better error handling
        command = [
            "ffuf",
            "-w", wordlist_path,
            "-u", f"{url}/FUZZ",
            "-o", temp_file,
            "-s",  # Silent mode
            "-of", "json",
            "-t", "50",  # Threads
            "-timeout", "10",  # Timeout per request
            "-rate", "100"  # Requests per second
        ]
        
        print(f"[+] Running ffuf scan for {subdomain}")
        
        # Run ffuf command
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300  # 5 minute timeout for entire scan
        )
        
        # Check if ffuf completed successfully
        if process.returncode != 0:
            print(f"[-] ffuf failed for {subdomain}: {process.stderr}")
            return results
        
        # Wait a moment for file to be written
        time.sleep(1)
        
        # Read results with robust error handling
        results_raw = read_json(temp_file)
        if results_raw is None:
            print(f"[-] Failed to read ffuf results for {subdomain}")
            return results
        
        # Parse results - only report 2xx and 3xx status codes
        for result in results_raw.get("results", []):
            status_code = result.get("status")
            endpoint_url = result.get("url", "")
            
            # Only include 2xx and 3xx status codes
            if 200 <= status_code < 400:
                # Extract just the endpoint path from the full URL
                endpoint = endpoint_url.replace(url, "").strip("/")
                if endpoint:  # Only add non-empty endpoints
                    results[endpoint] = status_code
        
        return results
        
    except subprocess.TimeoutExpired:
        print(f"[-] ffuf scan timed out for {subdomain}")
        return results
    except Exception as e:
        print(f"[-] Unexpected error scanning {subdomain}: {e}")
        return results
    finally:
        # Clean up temporary file
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except Exception as e:
            print(f"[-] Failed to clean up {temp_file}: {e}")


def main(subdomains):
    """Main function to check multiple subdomains with robust error handling"""
    if not subdomains:
        print("[bold red][-] No subdomains provided[/bold red]")
        return {}
    
    output_dict = {}
    total_subdomains = len(subdomains)
    
    print(f"[bold blue][+] Starting endpoint scan for {total_subdomains} subdomains[/bold blue]")
    
    for i, subdomain in enumerate(subdomains, 1):
        print(f"[bold blue][+] Processing {i}/{total_subdomains}: {subdomain}[/bold blue]")
        
        try:
            if is_domain_accessible(subdomain):
                results = check_endpoints(subdomain)
                if results:
                    print(f"[bold green][+] Found {len(results)} endpoints for {subdomain}[/bold green]")
                    output_dict[subdomain] = results
                else:
                    print(f"[bold yellow][-] No endpoints found for {subdomain}[/bold yellow]")
            else:
                print(f"[bold red][-] Domain not accessible: {subdomain}[/bold red]")
        except Exception as e:
            print(f"[bold red][-] Error processing {subdomain}: {e}[/bold red]")
            continue
    
    # Print summary
    total_endpoints = sum(len(endpoints) for endpoints in output_dict.values())
    print(f"\n[bold green][+] Scan completed! Found {total_endpoints} total endpoints across {len(output_dict)} domains[/bold green]")
    
    # Print detailed results
    for subdomain, endpoints in output_dict.items():
        print(f"\n[bold blue]Results for {subdomain}:[/bold blue]")
        for endpoint, status_code in endpoints.items():
            if 200 <= status_code < 300:
                print(f"  [green]✓[/green] {endpoint} - Status: {status_code}")
            elif 300 <= status_code < 400:
                print(f"  [blue]→[/blue] {endpoint} - Status: {status_code}")
            else:
                print(f"  [yellow]⚠[/yellow] {endpoint} - Status: {status_code}")
    
    return output_dict