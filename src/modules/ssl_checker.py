import subprocess
import json
from datetime import datetime, timezone

"""
This module provides functions to extract TLS information from a list of hosts using the tlsx command.
Functions:
    extract_tls_info(hosts): Extracts TLS information for the given list of hosts and returns a list of dictionaries with the extracted data.
    main(): Main function to read hosts from a file, extract TLS information, and print the results in a formatted table.
Exceptions:
    Exception: Raised when there is an error during the extraction process.
"""


def extract_tls_info(hosts):
    try:
        all_extracted_data=[]
        for host in hosts:
            tlsx_command = f"echo {host} | tlsx -json -silent"
            process = subprocess.run(tlsx_command, shell=True, capture_output=True, text=True)
        
            if process.returncode != 0:
                print(f"Error running tlsx: {process.stderr}")
                return []
            
            tlsx_output = process.stdout
            tls_entries = [json.loads(line) for line in tlsx_output.splitlines() if line.strip()]
            for entry in tls_entries:
                hostname = entry.get("host", "Unknown")
                not_before = entry.get("not_before", "Unknown")
                not_after = entry.get("not_after", "Unknown")
                subject_cn = entry.get("subject_cn", "Unknown")
                issuer_org = ", ".join(entry.get("issuer_org", ["Unknown"]))
                expired = entry.get("expired", "false")
                
                if expired == "false":
                    not_after_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
                    not_after_date = not_after_date.replace(tzinfo=timezone.utc)
                    current_date = datetime.now(timezone.utc)
                    
                    days_until_expiry = (not_after_date - current_date).days
                else:
                    days_until_expiry = 0
                
                all_extracted_data.append({
                    "hostname": hostname,
                    "not_before": not_before,
                    "not_after": not_after,
                    "subject_cn": subject_cn,
                    "issuer_org": issuer_org,
                    "days_until_expiry": days_until_expiry,
                    "expired": expired
                })
            
        return all_extracted_data

    except Exception as e:
        print(f"Error: {e}")
        return []

def main():
    hosts_file = []
    tls_info = extract_tls_info(hosts_file)
    if tls_info:
        print(f"{'Hostname':<30} {'Not Before':<25} {'Not After':<25} {'Subject CN':<30} {'Issuer Org':<30} {'Days Until Expiry':<20}")
        print("="*160)
        for info in tls_info:
            print(f"{info['hostname']:<30} {info['not_before']:<25} {info['not_after']:<25} {info['subject_cn']:<30} {info['issuer_org']:<30} {info['days_until_expiry']:<20}")
    else:
        print("No data extracted.")
