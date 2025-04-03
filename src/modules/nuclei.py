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
        if socket.create_connection((domain, 80), timeout=60) or socket.create_connection((domain, 443), timeout=60):
            return True
        else:
            return False
        
    except (socket.error, socket.gaierror, socket.timeout, ConnectionRefusedError):
        return False

def is_valid_domain(domain):
    domain_regex = r"^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$"
    if re.match(domain_regex, domain):
        return is_domain_accessible(domain)
    return False
def determine_target_type(target):
    if is_valid_ip(target):
        return "IP"
    elif is_valid_domain(target):
        return "Domain"
    else:
        return None

def run_nuclei(target, template_path):
    command = f'nuclei -nc -silent -j -target {target} -t {template_path}'
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        results = []

        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            
            line = line.strip()
            if not line:
                continue   
            try:
                x = json.loads(line)   
                res = [
                    str(x.get('template-id', 'N/A')),
                    str(x.get('matcher-status', 'N/A')),
                    str(x['info'].get('reference', 'NOT FOUND')),
                    str(x['info'].get('description', 'NOT FOUND')),
                    str(x.get('request', 'N/A')),
    ]
                results.append(res)

            except json.JSONDecodeError as e:
                print(f"Error parsing JSON: {e} - Line: {line}")

        process.communicate()
        print(f"[bold green][+] Nuclei Scan Completed For {target} ![/bold green]")
        return results

    except subprocess.CalledProcessError as e:
        print(f"Error running Nuclei: {e.output}")

        
    except subprocess.CalledProcessError as e:
        
        print(f"Error running Nuclei: {e.output}")