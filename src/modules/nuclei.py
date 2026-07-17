import subprocess
import re
import socket
import json
from rich import print
"""
This module provides functionality to validate IP addresses and domains, check domain accessibility, determine target type, and run the Nuclei tool for vulnerability scanning.
Functions:
    is_valid_ip(ip): Checks if the given IP address is valid.
    is_domain_accessible(domain): Checks if the given domain is accessible.
    is_valid_domain(domain): Validates the given domain and checks its accessibility.
    determine_target_type(target): Determines if the target is an IP address or a domain.
    run_nuclei(target, template_path): Executes the Nuclei tool with the specified target and template path, parses the JSON output, and returns a list of results.
Exceptions:
    socket.error: Raised when there is an error with socket operations.
    socket.gaierror: Raised when there is an address-related error with socket operations.
    socket.timeout: Raised when a socket operation times out.
    ConnectionRefusedError: Raised when a connection attempt is refused.
    subprocess.CalledProcessError: Raised when there is an error during the execution of the Nuclei command.
"""

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_domain_accessible(domain):
    try:
        for port in [80, 443]:
            try:
                with socket.create_connection((domain, port), timeout=10) as s:
                    return True
            except (socket.error, socket.timeout):
                continue
        return False
    except Exception:
        return False

def is_valid_domain(domain):
    domain_regex = r"^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$"
    if re.match(domain_regex, domain):
        return True  
    return False
    
def determine_target_type(target):
    if is_valid_ip(target):
        return "IP"
    elif is_valid_domain(target):
        return "Domain"
    else:
        return None

def update_nuclei_templates():
    try:
        proc = subprocess.run(['nuclei', '-ut'], capture_output=True, text=True)
        if "Successfully updated" in proc.stderr:
            print("[bold cyan][!] New CVE templates were downloaded![/bold cyan]")
        else:
            print("[bold white][-] Templates already up to date.[/bold white]")
    except Exception as e:
        print(f"Update failed: {e}")

NUCLEI_TIMEOUT = 600


def run_nuclei(target, template_path):
    command = [
        "nuclei", "-nc", "-j",
        "-target", target,
        "-t", template_path,
        "-as", "-nm", "-rl", "150",
        "-c", "25", "-retries", "2",
        "-timeout", "5",
        "-s", "critical,high,medium,low",
        "-etags", "tpsa",          # exclude third-party security assessment templates
    ]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT,
        )

        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        print(f"[bold green][+] Nuclei Scan Completed For {target} ![/bold green]")
        return results

    except subprocess.TimeoutExpired:
        print(f"[bold red][-] Nuclei timed out for {target} after {NUCLEI_TIMEOUT}s[/bold red]")
        return []
    except OSError as e:
        print(f"[bold red][-] Nuclei OS error for {target}: {e}[/bold red]")
        return []
    except Exception as e:
        print(f"[bold red][-] Nuclei error for {target}: {e}[/bold red]")
        return []