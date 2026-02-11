import argparse
from banner import banner
import os
import argparse
import asyncio
from dotenv import load_dotenv
from modules.cloudflare import Cloudflare
from system.db import *
from modules.gcp import GCP
from modules import endpoints
from modules.portscan import PortScan
from modules.wayback import GAU
from modules.nuclei import *
from modules.ssl_checker import extract_tls_info
from rich.table import Table
from rich.console import Console
from rich.text import Text
from rich import print
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from datetime import datetime
import time
import concurrent.futures
from system import utils as system
from rich_tools import *
from modules import firewall
import csv
import pandas as pd
from modules.technology import BuiltWithScanner
from modules.dangling_dns import get_dangling_dns_dict, save_dangling_to_csv
import socket
from urllib.parse import urlparse

"""
Appollo 
This script provides a comprehensive reconnaissance tool that performs various scans and updates for DNS records, port scanning, wayback URLs, directory scanning, and nuclei scans for CVEs. The results are processed and can be sent to Slack, saved to CSV files, and Jira issues can be created for new findings.
Classes:
    Appollo: Main class that handles the scanning and updating logic.
Functions:
    convert_to_csv(data, output_file): Converts scan results to a CSV file.
Usage:
    Run the script with appropriate arguments to perform different types of scans and updates.
Arguments:
    -t, --target: Target domain, IP, CIDR, or any asset which is supported by Appollo.
    -U, --update-inventory: Update Inventory Records.
    -ps, --port-scan: Run port scan logic.
    -ws, --wayback-scan: Run wayback scan logic.
    -ds, --dir-scan: Run directory scan logic.
    -A, --complete-scan: Run Complete scan for all known assets in inventory.
    -ns, --nuclei-scan: Run nuclei scans for CVEs.
"""



class Appollo:
    def __init__(self, args) -> None:
        load_dotenv(args.env)
        self.jira = system.get_jira_client()
        self.label = "appollo-scan"
        self.args = args

    def scan_ports(self, ip):
        ports = PortScan().run(ip, "-p 1-9999")
        open_ports = []
        cloudflare_ports = [ 8080, 8880, 2052, 2082, 2086, 2095,2053, 2083, 2087, 2096, 8443, 2053, 2082, 2083, 2087, 2096, 844]
        open_ports = [port for port in ports if port not in cloudflare_ports]
        return open_ports
        
    def table_to_df(self, table: Table) -> pd.DataFrame:
        table_data = {
            x.header: [Text.from_markup(y).plain for y in x.cells] for x in table.columns
        }
        return pd.DataFrame(table_data)
    
 
    def run(self):
        gcp_ip = []
        cloud_command = f"gcloud auth activate-service-account --key-file={os.getenv('SVC_ACCOUNT')}"
        os.system(f"{cloud_command} > /dev/null 2>&1")
        print("[bold green][+] Service Account Activated[/bold green]")
        # Predefine to avoid UnboundLocalError when not set in some branches

        if self.args.update_inventory:
            self.label = "dns_records"
            print("[bold blue][+] Updating Cloudflare IP/DNS Records[/bold blue]")
            Cloudflare().run()
            print("[bold blue][+] Updating GCP IP/DNS Records[/bold blue]") 
            GCP().run(max_workers=275)


            table = Table(title="DNS Records")
            table.add_column("Zone Name", style="yellow")
            table.add_column("Name", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Content", style="blue")
            table.add_column("Proxied", style="blue")
            table.add_column("Resource Type", style="cyan")
            table.add_column("Source", style="red")

            collection = MongoDB().set_collection("DNS")
            cloudflare_records = collection.find({"source": "cloudflare"})
            gcp_records = collection.find({"source": "GCP"})

            for record in cloudflare_records:
                for r in record.get('records', []):
                    for dns in r.get('records', []):
                        table.add_row(
                        dns.get('zone_name', ''),
                        dns.get('name', ''),
                        dns.get('type', ''),
                        dns.get('content', ''),
                        str(dns.get('proxied', '')),
                        'cloudflare_dns',
                        record.get('source', '')
                        )

            for record in gcp_records:
                # Handle new GCP format where records are stored per project
                for project_record in record.get('records', []):
                    project_id = project_record.get('project_id', '')
                    for r in project_record.get('records', []):
                        ip_list = r.get('Rrdatas', [])
                        if ip_list:
                            for ip in ip_list:
                                table.add_row(
                                    project_id,  # Use project_id as Zone Name
                                    r.get('Name', ''),
                                    r.get('Type', ''),
                                    ip,
                                    '',
                                    'gcp_dns',
                                    record.get('source', '')
                                )
            print(table)

            # Create IP Records table with resource types
            ip_table = Table(title="IP Records with Resource Types")
            ip_table.add_column("Source", style="yellow")
            ip_table.add_column("IP Address", style="green")
            ip_table.add_column("Resource Type", style="blue")
            ip_table.add_column("Resource Name", style="cyan")
            ip_table.add_column("Additional Info", style="magenta")

            # Process Cloudflare IP records
            ip_collection = MongoDB().set_collection("IP Records")
            cloudflare_ip_records = ip_collection.find({"source": "cloudflare"})
            for record in cloudflare_ip_records:
                for sub_record in record.get('records', []):
                    for ip_record in sub_record.get('ip', []):
                        ip_table.add_row(
                            "Cloudflare",
                            ip_record.get('ip', ''),
                            ip_record.get('resource_type', 'cloudflare_dns'),
                            ip_record.get('name', ''),
                            f"Proxied: {ip_record.get('proxied', False)}, TTL: {ip_record.get('ttl', 1)}"
                        )

            # Process GCP IP records
            gcp_ip_records = ip_collection.find({"source": "GCP"})
            for record in gcp_ip_records:
                for project_record in record.get('records', []):
                    project_id = project_record.get('project_id', '')
                    ip_details = project_record.get('ip_details', {})
                    for ip, details in ip_details.items():
                        additional_info = f"Region: {details.get('region', 'N/A')}"
                        if details.get('resource_type') == 'vm_external':
                            additional_info += f", Zone: {details.get('zone', 'N/A')}, Machine: {details.get('machine_type', 'N/A')}"
                        elif details.get('resource_type') == 'load_balancer':
                            additional_info += f", Scheme: {details.get('load_balancing_scheme', 'N/A')}"
                        elif details.get('resource_type') == 'cloud_sql':
                            additional_info += f", Version: {details.get('database_version', 'N/A')}"
                        
                        ip_table.add_row(
                            f"GCP ({project_id})",
                            ip,
                            details.get('resource_type', 'unknown'),
                            details.get('resource_name', ''),
                            additional_info
                        )

            print(ip_table)

            data = self.table_to_df(table)
            new_data_rows = []  # Use a list to collect new rows
            dns_file_path_ = "dns-records.csv"
            
            # Store DNS records in MongoDB with duplicate prevention
            dns_collection = MongoDB().set_collection("DNS Records")
            
            # Create unique index on hash field to prevent duplicates at database level
            try:
                dns_collection.create_index("hash", unique=True)
                print("[bold blue][+] Created unique index on hash field[/bold blue]")
            except Exception as e:
                # Index might already exist, that's fine
                pass
            
            # Prepare all DNS records for MongoDB (full inventory)
            all_dns_records = []
            for _, row in data.iterrows():
                record_data = {
                    'zone_name': row['Zone Name'],
                    'name': row['Name'],
                    'type': row['Type'],
                    'content': row['Content'],
                    'proxied': row['Proxied'],
                    'resource_type': row['Resource Type'],
                    'source': row['Source'],
                    'timestamp': datetime.now()
                }
                all_dns_records.append(record_data)
            
            # Get only NEW/CHANGED records for Jira alerts (delta)
            delta_records = system.get_delta_dns_records(all_dns_records, "All")  # Check against all sources
            
            # Store ALL records in MongoDB (full inventory) using upsert
            stored_count = 0
            skipped_count = 0
            
            for record_data in all_dns_records:
                # Calculate hash for deduplication
                record_hash = system.calculate_hash(record_data)
                record_data['hash'] = record_hash
                
                try:
                    # Use upsert with hash as unique identifier
                    result = dns_collection.update_one(
                        {"hash": record_hash}, 
                        {"$set": record_data}, 
                        upsert=True
                    )
                    
                    if result.upserted_id:
                        stored_count += 1
                    elif result.modified_count > 0:
                        stored_count += 1  # Count updates as stored
                    else:
                        skipped_count += 1
                        
                except Exception as e:
                    print(f"[bold yellow][!] Error upserting DNS record: {e}[/bold yellow]")
                    skipped_count += 1
            
            # Prepare delta records for Jira alerts
            new_data_rows = []
            for record in delta_records:
                new_data_rows.append(record)
            
            # Create new_data DataFrame from collected rows (delta records only)
            try:
                if new_data_rows:
                    new_data = pd.DataFrame(new_data_rows)
                    # Rename columns to match expected format for downstream processing
                    column_mapping = {
                        'zone_name': 'Zone Name',
                        'name': 'Name', 
                        'type': 'Type',
                        'content': 'Content',
                        'proxied': 'Proxied',
                        'resource_type': 'Resource Type',
                        'source': 'Source'
                    }
                    new_data = new_data.rename(columns=column_mapping)
                    print(f"[bold blue][+] Created DataFrame with {len(new_data_rows)} new/changed records for alerts[/bold blue]")
                else:
                    new_data = pd.DataFrame(columns=['Zone Name', 'Name', 'Type', 'Content', 'Proxied', 'Resource Type', 'Source'])
                    print("[bold yellow][+] No new/changed records found, creating empty DataFrame[/bold yellow]")
            except Exception as e:
                print(f"[bold red][-] Error creating DataFrame: {e}[/bold red]")
                new_data = pd.DataFrame(columns=['Zone Name', 'Name', 'Type', 'Content', 'Proxied', 'Resource Type', 'Source'])
            
            # Report storage results
            if stored_count > 0 or skipped_count > 0:
                print(f"[bold green][+] DNS Records Inventory: {stored_count} records stored/updated, {skipped_count} unchanged[/bold green]")
            
            # Report delta results
            if len(new_data_rows) > 0:
                print(f"[bold cyan][+] Delta Records: {len(new_data_rows)} new/changed records found for Jira alerts[/bold cyan]")
            else:
                print("[bold yellow][+] No new/changed DNS records found - no Jira alerts needed[/bold yellow]")
                    
            # Final safety check - ensure new_data is always a valid DataFrame
            if new_data is None:
                print("[bold red][-] new_data is None, creating empty DataFrame[/bold red]")
                new_data = pd.DataFrame(columns=['Zone Name', 'Name', 'Type', 'Content', 'Proxied', 'Resource Type', 'Source'])
            
            # Check if new_data is not empty and is a valid DataFrame
            if new_data is not None and not new_data.empty and 'Content' in new_data.columns:
                # Filter out private IPs only for A records
                try:
                    # Create a mask for A records with private IPs
                    private_ip_mask = new_data.apply(
                        lambda row: (
                            row['Type'] == 'A' and 
                            pd.notna(row['Content']) and 
                            system.is_private_ip(row['Content'])
                        ), axis=1
                    )
                    # Filter out private IPs (keep all non-A records and A records with public IPs)
                    public_data = new_data[~private_ip_mask]
                    print(f"[bold blue][+] Filtered out {private_ip_mask.sum()} private IP records, keeping {len(public_data)} public records[/bold blue]")
                except Exception as e:
                    print(f"[bold red][-] Error filtering private IPs: {e}[/bold red]")
                    public_data = new_data  # Use all data if filtering fails
                
                table_content = "|| Zone Name || Name || Type || Content || Proxied || Resource Type || Source ||\n"
                for _, row in public_data.iterrows():
                    table_content += f"| {row['Zone Name']} | {row['Name']} | {row['Type']} | {row['Content']} | {row['Proxied']} | {row['Resource Type']} | {row['Source']} |\n"

                new_data.to_csv(dns_file_path_, index=False)
                system.upload_file_to_slack(dns_file_path_,"DNS Records")
                
                # Check if content is too long for Jira description
                if len(table_content) > 32000:  # Leave some buffer
                    # Create Jira issue with short description and attach CSV
                    jira_issue = system.create_jira_issue(
                        self.jira,
                        "APOC",
                        f"[DNS Records] {len(new_data)} new/changed records detected",
                        f"New or changed DNS records detected in inventory scan. Please check the attached CSV file for details.\n\nDelta records: {len(new_data)}\n\nNote: This only includes NEW or CHANGED records, not the complete inventory.",
                        "Bug",
                        self.label
                    )
                    # Attach the CSV file
                    issue_id = jira_issue.key
                    self.jira.add_attachment(issue=issue_id, attachment=dns_file_path_)
                    print(f"[bold green][+] Jira ticket created successfully for new DNS records (with CSV attachment)[/bold green]")
                else:
                    # Use table content in description
                    jira_issue = system.create_jira_issue(
                        self.jira,
                        "APOC",
                        f"[DNS Records] {len(new_data)} new/changed records detected",
                        f"New or changed DNS records detected in inventory scan:\n\n{table_content}\n\nNote: This only includes NEW or CHANGED records, not the complete inventory.",
                        "Bug",
                        self.label
                    )
                    print(f"[bold green][+] Jira ticket created successfully for new DNS records[/bold green]")
            else:
                print("[bold yellow][+] No new DNS records to process for alerts[/bold yellow]")
            

#****************************** SSL Checker ********************
        if self.args.ssl_checker:
            self.label = "ssl_checker"
            whitelisted_domains = []
            # Add subdomains for whitelisted domains
            whitelisted_subdomains = []
            for domain in whitelisted_domains:
                whitelisted_subdomains.append(f"*.{domain}")
            whitelisted_domains.extend(whitelisted_subdomains)
            
            def is_whitelisted(domain_name, whitelist):
                """Check if a domain is whitelisted, including wildcard subdomain matching"""
                if domain_name in whitelist:
                    return True
                # Check wildcard patterns
                for pattern in whitelist:
                    if pattern.startswith('*.'):
                        base_domain = pattern[2:]  # Remove '*.'
                        if domain_name.endswith('.' + base_domain) or domain_name == base_domain:
                            return True
                return False
            target = []
            ssl_collection = MongoDB().set_collection("SSL Certificates")
            if self.args.complete_scan:
                print("[bold blue][+] Running SSL checker on all domains[/bold blue]")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_dns = dns_collection.find({'source': 'GCP'})

                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            ip = r.get('content', '')
                            if r.get('type') == 'A' and not ip.startswith(('10.', '192.168', '127.')):
                                if not is_whitelisted(r.get('name'), whitelisted_domains):
                                    target.append(r.get('name'))
                        target.append(record.get('domain'))

                for records in gcp_dns:
                    # Handle new GCP format where records are stored per project
                    for project_record in records.get('records', []):
                        for record in project_record.get('records', []):
                            ip_list = record.get('Rrdatas', [])
                            if ip_list and record.get('Type') == 'A':
                                for ip in ip_list:
                                    if not ip.startswith(('10.', '192.168', '127.')):
                                        if not is_whitelisted(record.get('Name'), whitelisted_domains):
                                            target.append(record.get('Name'))
            else:
                if self.args.target:
                    target.append(self.args.target)
                    print(f"[bold blue][+] Starting SSL scan on {self.args.target}[/bold blue]")
                else:
                    print("[bold red][+] No target provided [/bold red]")

            tls_info = extract_tls_info(target)
            if tls_info:
                new_tls_hash = system.calculate_hash(''.join(f"{info['hostname']}{info['not_after']}" for info in tls_info))
                is_alert_sent = system.check_if_hash_exists(new_tls_hash)

                if not is_alert_sent:
                    table = Table(title="SSL Certificate Information")
                    table.add_column("Hostname", style="yellow")
                    table.add_column("Not Before", style="green")
                    table.add_column("Not After", style="blue")
                    table.add_column("Subject CN", style="magenta")
                    table.add_column("Issuer Org", style="cyan")
                    table.add_column("Days Until Expiry", style="red")
                    table.add_column("Certificate Expired", style="purple")

                    for info in tls_info:
                        table.add_row(info['hostname'], info['not_before'], info['not_after'], info['subject_cn'], info['issuer_org'], str(info['days_until_expiry']), str(info['expired']))
                        ssl_collection.update_one({"hostname": info['hostname']}, {"$set": info}, upsert=True)

                        expiry_date = datetime.strptime(info['not_after'], '%Y-%m-%dT%H:%M:%SZ')
                        days_left = (expiry_date - datetime.utcnow()).days
                        if days_left <= 15:
                            system.create_jira_issue(
                                self.jira,
                                "APOC",
                                f"[SSL Certificate Expiry] {info['hostname']} has SSL Certificate Expiry",
                                f"{info['hostname']} has {info['days_until_expiry']} days until expiry.",
                                "Bug",
                                self.label
                            )
                            print(f"[bold green][+] Jira ticket created for {info['hostname']} with expiry in {info['days_until_expiry']} days")

                    system.send_slack_alert("SSL checker completed successfully ")
                    print(table)
                else:
                    print(f"[bold green][+] Jira ticket already created for {info['hostname']}[/bold green]")
            else:
                print("[bold red][-] No SSL information found[/bold red]")

#************************** PORT SCAN **************************

        if self.args.port_scan:
            self.label = "port_scan"
            domains = []
            ip_domain = {}
            results = {}
            csv_file_path = "port_scan.csv"
            port_collection = MongoDB().set_collection("Port Scans")
            previous_csv_file_path = "/etc/config/previous_port_scan.csv"

            for file_path in [previous_csv_file_path, csv_file_path]:
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write("Domain,IP,Port\n")

            if self.args.complete_scan:
                print("[bold blue][+] Running Complete Port Scan [/bold blue]")
                ip_collection = MongoDB().set_collection("IP Records")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = ip_collection.find({'source': 'cloudflare'})
                gcp_records = dns_collection.find({'source':'GCP'})
                gcp_ip = ip_collection.find({'source':'GCP'})

            
                for record in cloudflare_records:
                    for sub_record in record.get('records', []):
                        for r in sub_record['ip']:
                            print(system.is_private_ip(r['ip']))
                            if not system.is_private_ip(r['ip']):
                                ip_domain[r['name']]=r['ip']
                                domains.append(r['name'])

                # Process GCP DNS records using current schema from modules/gcp.py
                # Each doc has: { project_id, source:'GCP', records:[{name,type,ttl,data,zone}], ... }
                for record in gcp_records:
                    for rr in record.get('records', []):
                        if rr.get('type') == 'A':
                            ip_value = rr.get('data')
                            if ip_value and not system.is_private_ip(ip_value):
                                name = (rr.get('name') or '').rstrip('.')
                                if name:
                                    ip_domain[name] = ip_value
                                    domains.append(name)
                
                # Process GCP IP inventory (not DNS records) using current schema
                # Each doc has: { project_id, source:'GCP', resource_types: { type: [ips] }, ... }
                for record in gcp_ip:
                    project_id = record.get('project_id', '')
                    resource_types = record.get('resource_types', {})
                    for ip_list in resource_types.values():
                        for ip in ip_list:
                            if not system.is_private_ip(ip):
                                domain_name = f"{project_id}.gcp.internal"
                                ip_domain[domain_name] = ip
                                domains.append(domain_name)
   
            else:
                if not self.args.target:
                    print("[bold red][-] No target provided[/bold red]")
                    return
                # If target is a file path, read targets from file
                if os.path.isfile(self.args.target):
                    target_file = self.args.target
                    print(f"[bold blue][+] Loading targets from {target_file}[/bold blue]")
                    try:
                        with open(target_file, 'r') as f:
                            for line in f:
                                raw = line.strip()
                                if not raw or raw.startswith('#'):
                                    continue
                                host = raw
                                # Allow URL inputs; extract hostname
                                if '://' in raw:
                                    try:
                                        parsed = urlparse(raw)
                                        host = parsed.hostname or raw
                                    except Exception:
                                        host = raw
                                try:
                                    ip = socket.gethostbyname(host)
                                    ip_domain[host] = ip
                                    domains.append(host)
                                except socket.gaierror:
                                    print(f"[bold yellow][!] Skipping unresolved target: {host}")
                    except Exception as e:
                        print(f"[bold red][-] Failed to read targets file {target_file}: {e}[/bold red]")
                        return
                    if not domains:
                        print("[bold red][-] No valid targets found in file[/bold red]")
                        return
                    print(f"[bold blue][+] Running Port scan on {len(domains)} targets from file[/bold blue]")
                else:
                    # Single target mode
                    try:
                        host = self.args.target
                        if '://' in host:
                            try:
                                host = urlparse(host).hostname or host
                            except Exception:
                                pass
                        ip = socket.gethostbyname(host)
                        ip_domain[host] = ip
                        domains.append(host)
                        print(f"[bold blue][+] Running Port scan on {host}[/bold blue]")
                    except socket.gaierror:
                        print(f"[bold red][-] Unable to resolve {self.args.target}[/bold red]")
                        return
            table = Table(title="Port Scans")
            table.add_column("Domain", style="green")
            table.add_column("IP", style="yellow")
            table.add_column("Open Ports", style="blue")

            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {executor.submit(self.scan_ports, domain): domain for domain in domains}
                for future in concurrent.futures.as_completed(futures):
                    domain = futures[future]
                    try:
                        result = future.result()
                        ip = ip_domain.get(domain, '')
                        results[domain] = {'ip': ip, 'ports': result or []}
                    except Exception as e:
                        print(f"[bold red][-] Error scanning {domain}: {e}[/bold red]")

            previous_results = system.read_from_csv(previous_csv_file_path)
            delta_ports = system.get_delta_ports(results, previous_results)

            for domain, data in results.items():
                query = {"domain": domain}
                update = {"$set": {"ip": data['ip'], "domain": domain,"ports": data['ports']}}
                port_collection.update_one(query, update, upsert=True)
                table.add_row(domain, data['ip'], ",".join(map(str, data['ports'])))
            print(table)

            if delta_ports:
                system.save_port_scan_to_csv(delta_ports, previous_csv_file_path)
                for domain, ports in delta_ports.items():
                    ip = ports.get("ip", "")
                    open_ports = ",".join(map(str, ports.get("ports", [])))
                    table_content = f"|| Domain || IP || Open Ports ||\n| {domain} | {ip} | {open_ports} |\n"

                    if not system.check_if_hash_exists(system.calculate_hash([domain, ip, open_ports])):
                        jira_issue = system.create_jira_issue(
                            self.jira,
                            "APOC",
                            f"[Open Ports] {domain} has critical open ports",
                            f"The following ports are open for {domain}:\n\n{table_content}",
                            "Bug",
                            self.label
                        )
                        print(f"[bold green][+] Jira ticket created successfully for {domain} with open ports[/bold green]")
                    else:
                        print(f"[bold yellow][+] Jira ticket already exists for {domain}[/bold yellow]")

                system.send_slack_alert(f"Port scan completed successfully at {datetime.now()}")
            else:
                print("[bold red][-] No new open ports found.[/bold red]")

#********************* FIREWALL PORT SCAN ************************
        if self.args.firewall_port_scan:
                    self.label = "firewall_port_scan"
                    svc_path = os.getenv('SVC_ACCOUNT')
                    if not svc_path or not os.path.exists(svc_path):
                        print("[bold red][-] Service account JSON not found. Set SVC_ACCOUNT env var.[/bold red]")
                        return
                    credentials = firewall.service_account.Credentials.from_service_account_file(svc_path, scopes=firewall.SCOPES)
                    crm_service = firewall.get_service("cloudresourcemanager", "v1", credentials)
                    compute_service = firewall.get_service("compute", "v1", credentials)
                    # Determine targets similar to firewall_test (projects -> instances)
                    projects = firewall.list_projects(crm_service)
                    print(f"[bold blue][+] Found {len(projects)} projects[/bold blue]")
                    table = Table(title="Firewall Port Scans (firewall_test mode)")
                    table.add_column("Project", style="cyan")
                    table.add_column("Instance/Resource", style="green")
                    table.add_column("Type", style="blue")
                    table.add_column("IP", style="yellow")
                    table.add_column("Open Ports", style="magenta")
                    results = {}
                    previous_csv_file_path = "/etc/config/previous_port_scan.csv"
                    if not os.path.exists(previous_csv_file_path):
                        with open(previous_csv_file_path, 'w') as f:
                            f.write("Domain,IP,Port\n")
                    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
                        proj_task = progress.add_task("Enumerating projects...", total=len(projects))
                        for project in projects:
                            if project.startswith("sys-") or project.startswith("gcp-sa-"):
                                progress.update(proj_task, advance=1)
                                continue
                            instances = firewall.list_instances(compute_service, project)
                            # Also include Load Balancers and Static IPs (public only)
                            try:
                                lb_instances = firewall.list_load_balancer_ips(compute_service, project)
                                filtered_lb = []
                                for inst in lb_instances:
                                    ip_val = inst.get("ip")
                                    if isinstance(ip_val, str) and firewall._is_valid_ip_literal(ip_val) and not firewall._is_private_ip(ip_val):
                                        filtered_lb.append(inst)
                                # Map LB records to the same structure as instances
                                for lb in filtered_lb:
                                    instances.append({
                                        "project": lb.get("project", project),
                                        "name": lb.get("name", "LoadBalancer"),
                                        "ip": lb.get("ip"),
                                        "type": lb.get("type", "Load Balancer"),
                                    })
                            except Exception:
                                pass
                            # Include additional GCP assets (Cloud SQL, VPN, NAT, Forwarding, Static)
                            try:
                                # Ensure downstream libs see the same service account
                                if svc_path:
                                    os.environ["SVC_ACCOUNT"] = svc_path
                                gcp_client = GCP()
                                extra_assets = firewall.list_additional_assets_via_gcp(gcp_client, project, include_lb_and_static=True)
                                # Deduplicate by IP
                                seen_ips = {i.get("ip") for i in instances if isinstance(i.get("ip"), str)}
                                for asset in extra_assets:
                                    ip_val = asset.get("ip")
                                    if not isinstance(ip_val, str) or not firewall._is_valid_ip_literal(ip_val) or firewall._is_private_ip(ip_val):
                                        continue
                                    if ip_val in seen_ips:
                                        continue
                                    instances.append({
                                        "project": asset.get("project", project),
                                        "name": asset.get("name") or asset.get("type") or "Resource",
                                        "ip": ip_val,
                                        "type": asset.get("type", "Resource"),
                                    })
                                    seen_ips.add(ip_val)
                            except Exception:
                                pass
                            if not instances:
                                progress.update(proj_task, advance=1)
                                continue
                            # Use ports explicitly listed in internet-facing firewall rules for this project
                            fw_rules = firewall.list_firewall_rules(compute_service, project)
                            internet_facing_rules = []
                            for rule in fw_rules:
                                if rule.get("direction") == "INGRESS" and not rule.get("disabled", False):
                                    sources = rule.get("sourceRanges", [])
                                    if "0.0.0.0/0" in sources or any("0.0.0.0" in src for src in sources):
                                        internet_facing_rules.append(rule)
                            ports_to_scan = firewall.extract_tcp_ports_from_firewall_rules(internet_facing_rules, max_ports=500)
                            if not ports_to_scan:
                                ports_to_scan = firewall.TOP_PORTS
                            inst_task = progress.add_task(f"Scanning instances in {project}...", total=len(instances))
                            with concurrent.futures.ThreadPoolExecutor() as executor:
                                futures = {executor.submit(firewall.scan_instance, inst["ip"], ports_to_scan): inst for inst in instances}
                                for future in concurrent.futures.as_completed(futures):
                                    inst = futures[future]
                                    open_ports = future.result() or []
                                    domain = inst["name"]
                                    ip = inst["ip"]
                                    resource_type = inst.get("type", "VM Instance")
                                    results[domain] = {"project": project, "type": resource_type, "ip": ip, "ports": open_ports}
                                    table.add_row(project, domain, resource_type, ip, ",".join(map(str, open_ports)) or "-")
                                    progress.update(inst_task, advance=1)
                            progress.update(proj_task, advance=1)
                    print(table)
                    # Preserve delta/Jira/Slack behavior
                    previous_results = system.read_from_csv(previous_csv_file_path)
                    delta_ports = system.get_delta_ports(results, previous_results)
                    port_collection = MongoDB().set_collection("Port Scans")
                    for domain, data in results.items():
                        query = {"project": data.get("project", ""), "domain": domain}
                        update = {"$set": {"project": data.get("project", ""), "domain": domain, "type": data.get("type", "VM Instance"), "ip": data['ip'], "ports": data['ports'], "last_updated": datetime.utcnow()}}
                        port_collection.update_one(query, update, upsert=True)
                    if delta_ports:
                        system.save_port_scan_to_csv(delta_ports, previous_csv_file_path)
                        for domain, ports in delta_ports.items():
                            ip = ports.get("ip", "")
                            open_ports = ",".join(map(str, ports.get("ports", [])))
                            project_name = results.get(domain, {}).get("project", domain)
                            table_content = f"|| Project || IP || Open Ports ||\n| {project_name} | {ip} | {open_ports} |\n"
                            if not system.check_if_hash_exists(system.calculate_hash([domain, ip, open_ports])):
                                jira_issue = system.create_jira_issue(
                                    self.jira,
                                    "APOC",
                                    f"[Open Ports] {domain} has critical open ports",
                                    f"The following ports are open for {domain}:\n\n{table_content}",
                                    "Bug",
                                    self.label
                                )
                                print(f"[bold green][+] Jira ticket created successfully for {domain} with open ports[/bold green]")
                            else:
                                print(f"[bold yellow][+] Jira ticket already exists for {domain}[/bold yellow]")
                        system.send_slack_alert(f"Firewall port scan completed successfully at {datetime.now()}")
                    else:
                        print("[bold red][-] No new open ports found.[/bold red]")
#********************* WAYBACK SCAN ************************
        if self.args.wayback_scan:
            self.label = "wayback_scan"
            domains = set()
            csv_file_path = "wayback_urls.csv"
            previous_csv_file_path = "/etc/config/previous_wayback_results.csv"

            for file_path in [csv_file_path, previous_csv_file_path]:
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write("Domain,Links\n")

            table = Table(title="Wayback Scans")
            table.add_column("Domain", style="green")
            table.add_column("Links", style="blue")

            if self.args.complete_scan:
                print("[bold blue][+] Running complete Wayback scan for all assets[/bold blue]")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_dns = dns_collection.find({'source': 'GCP'})

                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            ip = r.get('content', '')
                            if r.get('type') == 'A' and not ip.startswith(('10.', '192.168', '127.')):
                                domains.add(r.get('name'))
                        domains.add(record.get('domain'))

                for records in gcp_dns:
                    # Handle new GCP format where records are stored per project
                    for project_record in records.get('records', []):
                        for record in project_record.get('records', []):
                            ip_list = record.get('Rrdatas', [])
                            if ip_list and record.get('Type') == 'A':
                                for ip in ip_list:
                                    if not ip.startswith(('10.', '192.168', '127.')):
                                        domains.add(record.get('Name'))

            else:
                if self.args.target:
                    print(f"[bold blue][+] Running Wayback scan for {self.args.target} [/bold blue]")
                    domains.add(self.args.target)
                else:
                    print("[bold red][-] No target provided[/bold red]")
                    return

            wayback_results = asyncio.run(GAU().run(domains))

            for domain, links in wayback_results.items():
                for link in links:
                    table.add_row(domain, link)

            previous_wayback_results = system.read_from_csv(previous_csv_file_path)
            new_links = system.get_delta_links(wayback_results, previous_wayback_results)
            new_links_hash = system.calculate_hash(str(new_links))
            is_alert_sent = system.check_if_hash_exists(new_links_hash)
            wayback_collection = MongoDB().set_collection("Wayback Results")

            if new_links and not is_alert_sent:
                system.save_wayback_to_csv(new_links, previous_csv_file_path)

                for domain, links in new_links.items():
                    query = {"domain": domain}
                    update = {"$set": {"domain": domain, "urls": links}}
                    wayback_collection.update_one(query, update, upsert=True)

                    table_content = "|| Domain || Links ||\n"
                    table_content += "".join([f"| {domain} | {link} |\n" for link in links])
                    
                    # Check if content is too long for Jira description
                    if len(table_content) > 32000:  # Leave some buffer
                        # Create Jira issue with short description and attach CSV
                        jira_issue = system.create_jira_issue(
                            self.jira, 'APOC', f'[Wayback URLs] {domain} has new Wayback URLs',
                            f"{domain} has {len(links)} new URLs indexed. Please check the attached CSV file for details.", 'Bug', self.label
                        )
                        issue_id = jira_issue.key
                        self.jira.add_attachment(issue=issue_id, attachment=csv_file_path)
                        print(f"[bold green][+] Jira ticket created successfully for {domain} (with CSV attachment)[/bold green]")
                    elif table_content and len(links) > 1:
                        # Use table content in description
                        system.create_jira_issue(
                            self.jira, 'APOC', f'[Wayback URLs] {domain} has new Wayback URLs',
                            f"{domain} has {len(links)} new URLs indexed.\n\n{table_content}", "Bug", self.label
                        )
                        print(f"[bold green][+] Jira Ticket Created Successfully for {domain}[/bold green]")
                    else:
                        print(f"[bold red][-] No new wayback links found for {domain} to create Jira Ticket[/bold red]")

                system.send_slack_alert(f"Wayback scan completed successfully at {datetime.now()}")
            else:
                print("[bold green][+] No new wayback links found[/bold green]")

            print(table)

#*********************** TECHNOLOGY SCAN ************************
        if self.args.tech_scan:
            self.label = "tech_scan"
            csv_file_path = "tech-scan.csv"
            domains = []

            if(not(os.path.exists(csv_file_path))):
                with open(csv_file_path, 'w') as f:
                    f.write("Domain,Technology,Type,Content\n")

            if self.args.complete_scan:
                print("[bold green][+] Running complete Technology scan[/bold green]")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_records = dns_collection.find({'source': 'GCP'})

                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            if(r.get('type')=='A'):
                                if r.get('content')[:3] != '10.' and r.get('content')[:8] != '192.168' and r.get('content')[:4] != '127.':
                                    domains.append(r.get('name'))
                        domains.append(record.get('domain'))

                for records in gcp_records:
                    # Handle new GCP format where records are stored per project
                    for project_record in records.get('records', []):
                        for record in project_record.get('records', []):
                            if record.get('Type') == 'A':
                                ip_list = record.get('Rrdatas', [])
                                if ip_list:
                                    for ip in ip_list:
                                        if not ip.startswith(('10.', '192.168', '127.')):
                                            domains.append(record.get('Name'))
            else:
                
                if self.args.target:
                    domains.append(self.args.target)
                else:
                    print("[bold red][-] No target provided[/bold red]")
                    return
            
            print(f"[bold blue][+] Running Technology scan on {', '.join(domains)}[/bold blue]")
            
            builtwith = BuiltWithScanner(domains).scan()

            table = Table(title="Technology Scans")
            table.add_column("Domain", style="yellow")
            table.add_column("Technology", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Content", style="magenta")

            
            for domain, techs in builtwith.items():
                query = {"domain": domain}
                update = {"$set": {"domain": domain, "technologies": techs, "source": "BuiltWith"}}
                collection = MongoDB().set_collection("Technology Scans")
                collection.update_one(query, update, upsert=True)

                for _, tech_list in techs.items():
                    for tech in tech_list:
                        table.add_row(
                            domain,
                            tech.get("name", ""),
                            tech.get("tag", ""),
                            tech.get("description", "")
                        )
                
            new_data = self.table_to_df(table)
            new_data.to_csv(csv_file_path, index=False)
            print(table)

            alert_sent = False   

            for _, row in new_data.iterrows():
                lrow = list(row.to_numpy())
                hash = system.calculate_hash(lrow)
                is_alert_sent = system.check_if_hash_exists(hash)

                if not is_alert_sent:
                    system.add_hash_to_db(hash)
                    alert_sent = True   

            if not alert_sent: 
                system.send_slack_alert(f"Technology scan completed successfully at {datetime.now()}")
            else:
                system.send_slack_alert(f"Technology scan completed successfully at {datetime.now()}")

#*********************** DIRECTORY SCAN ************************     
       

        if self.args.dir_scan:
            self.label = "dir_scan"
            targets=[]
            results = {}
            dir_collection = MongoDB().set_collection("Exposed Endpoints")
            is_alert_sent = False

            if self.args.complete_scan:
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})

                # Only process Cloudflare records with public IPs
                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            if r.get('type') == 'A' and not r.get('content').startswith(('10.', '192.168', '127.')):
                                targets.append(r.get('name'))
                        # Also add the domain if it has public IP
                        domain = record.get('domain')
                        if domain and domain not in targets:
                            targets.append(domain)
            else:
                if self.args.target:
                    targets.append(self.args.target)
                else:
                    print("[bold red][-] No target provided[/bold red]")
                    return

            print(f"[bold blue][+] Found {len(targets)} Cloudflare DNS records with public IPs to scan[/bold blue]")

            # Process targets in batches of 20 for parallel processing
            batch_size = 20
            all_tasks = []
            
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i + batch_size]
                print(f"[bold blue][+] Processing batch {i//batch_size + 1}/{(len(targets) + batch_size - 1)//batch_size} ({len(batch)} targets)[/bold blue]")
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    batch_tasks = []
                    for target in batch:
                        print(f"[bold blue][+] Starting Directory scan for {target}[/bold blue]")
                        task = executor.submit(endpoints.check_endpoints, target)
                        batch_tasks.append((task, target))
                    
                    # Wait for all tasks in this batch to complete
                    for future, target in batch_tasks:
                        all_tasks.append((future, target))

            # Process all results after all batches are completed
            print(f"[bold blue][+] Processing results for all {len(all_tasks)} targets[/bold blue]")
            
            table = Table(title="Directory Scans")
            table.add_column("Domain", style="white")
            table.add_column("Endpoint", style="green")
            table.add_column("Full URL", style="cyan")
            table.add_column("Status code", style="blue")

            for future, target in all_tasks:
                result = future.result()
                table_content = "|| Domain || Endpoint || Full URL || Status Code ||\n"
                new_endpoints_found = 0
                total_endpoints = len(result) if result else 0

                if result:
                    print(f"[bold green][+] Found {total_endpoints} exposed endpoints for domain: {target}[/bold green]")
                    results[target] = result

                    for endpoint, status_code in result.items():
                        # Create full URL by combining domain and endpoint
                        full_url = f"https://{target}{endpoint}" if endpoint.startswith('/') else f"https://{target}/{endpoint}"
                        table.add_row(target, endpoint, full_url, str(status_code))

                        if endpoint:
                            query = {"domain": target, "endpoint": endpoint}
                            update = {"$set": {"domain": target, "endpoint": endpoint, "full_url": full_url, "status code": str(status_code)}}
                            dir_collection.update_one(query, update, upsert=True)

                            row = pd.DataFrame({
                                'Domain': [target],
                                'Endpoint': [endpoint],
                                'Full URL': [full_url],
                                'Status code': [str(status_code)]
                            })

                            hash_value = system.calculate_hash(row.values.tolist())
                            if not system.check_if_hash_exists(hash_value):
                                system.add_hash_to_db(hash_value)
                                new_endpoints_found += 1
                                table_content += f"| {target} | {endpoint} | {full_url} | {status_code} |\n"

                    # Only create Jira ticket if new endpoints were found
                    if new_endpoints_found > 0:
                        print(f"[bold blue][+] {new_endpoints_found} new endpoints found for {target}[/bold blue]")
                        
                        # Check if content is too long for Jira description
                        if len(table_content) > 32000:  # Leave some buffer
                            # Create Jira issue with short description and attach CSV
                            jira_issue = system.create_jira_issue(
                                self.jira,
                                'APOC',
                                f'[Exposed Endpoints] {target} has {new_endpoints_found} new exposed directories',
                                f"Found {new_endpoints_found} new exposed endpoints for {target}. Please check the attached CSV file for details.",
                                issue_type="Bug",
                                label=self.label
                            )
                            # Create CSV file for attachment
                            csv_file_path = f"exposed_endpoints_{target}.csv"
                            with open(csv_file_path, 'w', newline='') as csvfile:
                                import csv
                                writer = csv.writer(csvfile)
                                writer.writerow(['Domain', 'Endpoint', 'Full URL', 'Status Code'])
                                for endpoint, status_code in result.items():
                                    # Create full URL by combining domain and endpoint
                                    full_url = f"https://{target}{endpoint}" if endpoint.startswith('/') else f"https://{target}/{endpoint}"
                                    writer.writerow([target, endpoint, full_url, status_code])
                            
                            issue_id = jira_issue.key
                            self.jira.add_attachment(issue=issue_id, attachment=csv_file_path)
                            print(f"[bold blue][+] JIRA ticket created for {target}: {jira_issue.key} (with CSV attachment)")
                        else:
                            # Use table content in description
                            jira_issue = system.create_jira_issue(
                                self.jira,
                                'APOC',
                                f'[Exposed Endpoints] {target} has {new_endpoints_found} new exposed directories',
                                table_content,
                                issue_type="Bug",
                                label=self.label
                            )
                            print(f"[bold blue][+] JIRA ticket created for {target}: {jira_issue.key}")
                        system.send_slack_alert(f"Found {new_endpoints_found} new exposed endpoints for {target}. Visit JIRA {jira_issue.key}")
                    else:
                        print(f"[bold yellow][-] All {total_endpoints} endpoints for {target} already exist in database[/bold yellow]")
                else:
                    print(f"[bold red][-] No exposed endpoints found for {target}[/bold red]")
                    table.add_row(target, "N/A", "N/A", "N/A")

            print(table)

#*********************** NUCLEI SCAN ************************  
        if self.args.nuclei_scan:
            self.label = "nuclei_scan"
            nuclei_template = os.getenv('NUCLEI_TEMPLATE')
            targets = []
            ip_domain = {}
            results = {}

            if self.args.complete_scan:
                print(f"[bold green][+] Running complete Nuclei scan [/bold green]")
                ip_collection = MongoDB().set_collection("IP Records")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = ip_collection.find({'source': 'cloudflare'})
                gcp_records = dns_collection.find({'source': 'GCP'})
                # GCP IP inventory is stored in IP Records with 'resource_types' per project
                gcp_ip = ip_collection.find({'source': 'GCP'})

                for record in cloudflare_records:
                    for sub_record in record.get('records', []):
                        for r in sub_record['ip']:
                            if not (r['ip'].startswith(('10.', '192.168', '127.'))):
                                ip_domain[r['name']] = r['ip']
                                targets.append(r['name'])

                # Process GCP DNS records using current schema from modules/gcp.py
                # Each doc has: { project_id, source:'GCP', records:[{name,type,ttl,data,zone}], ... }
                for record in gcp_records:
                    for rr in record.get('records', []):
                        if rr.get('type') == 'A':
                            ip_value = rr.get('data')
                            if ip_value and not ip_value.startswith(('10.', '192.168', '127.')):
                                name = (rr.get('name') or '').rstrip('.')
                                if name:
                                    ip_domain[name] = ip_value
                                    targets.append(name)
                
                # Process GCP IP inventory (not DNS records) using current schema
                # Each doc has: { project_id, source:'GCP', resource_types: { type: [ips] }, ... }
                for record in gcp_ip:
                    project_id = record.get('project_id', '')
                    resource_types = record.get('resource_types', {})
                    for ip_list in resource_types.values():
                        for ip in ip_list:
                            if not ip.startswith(('10.', '192.168', '127.')):
                                domain_name = f"{project_id}.gcp.internal"
                                ip_domain[domain_name] = ip
                                targets.append(domain_name)
            else:
                if self.args.target:
                    targets.append(self.args.target)
                else:
                    print(f"[bold red][-] No target provided[/bold red]")
                    return

            targets = list(set(targets))
            print(f"[bold green][+] Running Nuclei scan for {self.args.target}[/bold green]")

            table = Table(title="Nuclei Scan Results")
            table.add_column("URL", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Vulnerability", style="magenta")
            table.add_column("Exploit URL", style="yellow")
            table.add_column("Description", style="blue")
            table.add_column("Request", style="white")


            with concurrent.futures.ThreadPoolExecutor() as executor:

                tasks = {executor.submit(run_nuclei, target, nuclei_template): target for target in targets}

                for future in concurrent.futures.as_completed(tasks):
                    target = tasks[future]
                    try:
                        result = future.result()
                        results[target] = result if result else []
                    except Exception as e:
                        print(f"[bold red][-] Error processing target {target}: {str(e)}[/bold red]")
                if any(results.values()):
                    csv_file_path = "nuclei.csv"
                    system.convert_to_csv(results, csv_file_path)
                    hash = system.calculate_hash(results)
                    is_alert_sent = system.check_if_hash_exists(hash)
                    text = "Nuclei Scans!"

                    table_content = ""
                    for target, vulnerabilities in results.items():
                        for vuln in vulnerabilities:
                            table.add_row(target, vuln[0], vuln[1], str(vuln[2]), vuln[3], vuln[4])
                            table_content += f"| {target} | {vuln[0]} | {vuln[1]} | {str(vuln[2])} | {vuln[3]} | {vuln[4]} |\n"
                    print(table)
                    if not is_alert_sent:
                        system.upload_file_to_slack(csv_file_path, text)
                        system.add_hash_to_db(hash)
                        
                        # Check if content is too long for Jira description
                        if len(table_content) > 32000:  # Leave some buffer
                            # Create Jira issue with short description and attach CSV
                            jira_issue = system.create_jira_issue(
                                self.jira,
                                'APOC',
                                f'[Nuclei Scan] {self.args.target} has vulnerabilities',
                                f"Vulnerabilities found for {self.args.target}. Please check the attached CSV file for details.",
                                issue_type="Bug",
                                label=self.label
                            )
                            issue_id = jira_issue.key
                            self.jira.add_attachment(issue=issue_id, attachment=csv_file_path)
                            print(f"[bold green][+] Jira ticket created for {target} (with CSV attachment)[/bold green]")
                        else:
                            # Use table content in description
                            jira_issue = system.create_jira_issue(
                                self.jira,
                                'APOC',
                                f'[Nuclei Scan] {self.args.target} has vulnerabilities',
                                table_content,
                                issue_type="Bug",
                                label=self.label
                            )
                            print(f"[bold green][+] Jira ticket created for {target} [/bold green]")
                    else:
                        print(f"[bold red][-] Jira ticket already exists for {target}[/bold red]")
#*********************** DANGLING DNS SCAN ************************     

        if self.args.dangling_dns:
            self.label = "dangling_dns"
            csv_file_path = "dangling_dns.csv"
            previous_csv_file_path = "/etc/config/previous_dangling_dns.csv"

            for file_path in [csv_file_path, previous_csv_file_path]:
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write("Domain,IP\n")

            if self.args.complete_scan:
                print("[bold blue][+] Running complete dangling DNS scan using direct API calls[/bold blue]")
                print("[bold green][+] Using real-time Cloudflare and GCP API data[/bold green]")
            else:
                if self.args.target:
                    print(f"[bold blue][+] Running dangling DNS scan for {self.args.target}[/bold blue]")
                    print("[bold green][+] Using real-time Cloudflare and GCP API data[/bold green]")
                else:
                    print("[bold red][-] No target provided[/bold red]")
                    return

            print("[bold blue][+] Starting dangling DNS analysis using direct API calls...[/bold blue]")
            # Always use API approach - domains parameter is ignored for backward compatibility
            results = get_dangling_dns_dict(domains=None, force_update=False)
            save_dangling_to_csv(results, csv_file_path)
            # Check for new results by comparing with previous CSV
            # This replaces the old get_delta_links() function which was designed for the old format
            previous_results = {}
            if os.path.exists(previous_csv_file_path) and os.path.getsize(previous_csv_file_path) > 0:
                try:
                    df = pd.read_csv(previous_csv_file_path)
                    if not df.empty and 'cloudflare_ips' in df.columns:
                        for _, row in df.iterrows():
                            domain = row['Domain']
                            cf_ips = eval(row['cloudflare_ips']) if pd.notna(row['cloudflare_ips']) else []
                            gcp_ips = eval(row['gcp_ips']) if pd.notna(row['gcp_ips']) else []
                            previous_results[domain] = {
                                'cloudflare_ips': cf_ips,
                                'gcp_ips': gcp_ips,
                                'status': row.get('status', 'unknown')
                            }
                except Exception as e:
                    print(f"[bold yellow]Warning: Could not read previous results: {str(e)}[/bold yellow]")
            
            # Find new/changed results
            delta = {}
            for domain, current_data in results.items():
                if domain not in previous_results:
                    # Domain is completely new
                    delta[domain] = current_data
                else:
                    # Check if the data has changed
                    prev_data = previous_results[domain]
                    if (current_data['cloudflare_ips'] != prev_data['cloudflare_ips'] or 
                        current_data['gcp_ips'] != prev_data['gcp_ips'] or
                        current_data['status'] != prev_data['status']):
                        delta[domain] = current_data
            
            delta_hash = system.calculate_hash(str(delta))
            is_alert_sent = system.check_if_hash_exists(delta_hash)
            collection = MongoDB().set_collection("Dangling DNS")
            table = Table(title="Dangling DNS Records")
            table.add_column("Domain", style="yellow")
            table.add_column("Cloudflare IPs", style="cyan")
            table.add_column("GCP IPs", style="magenta")
            table.add_column("Status", style="red")
            table_content = "|| Domain || Cloudflare IPs || GCP IPs || Status ||\n"
            
            # Process results in the new format
            for domain, details in results.items():
                cloudflare_ips = ", ".join(details.get('cloudflare_ips', [])) if isinstance(details, dict) else ""
                gcp_ips = ", ".join(details.get('gcp_ips', [])) if isinstance(details, dict) else ""
                status = details.get('status', 'unknown') if isinstance(details, dict) else ""
                
                table.add_row(
                    domain,
                    cloudflare_ips or "None",
                    gcp_ips or "None",
                    status
                )
                
                # Update MongoDB with the complete record
                query = {"domain": domain}
                update = {
                    "$set": {
                        "domain": domain,
                        "cloudflare_ips": details.get('cloudflare_ips', []) if isinstance(details, dict) else [],
                        "gcp_ips": details.get('gcp_ips', []) if isinstance(details, dict) else [],
                        "status": status,
                        "last_updated": datetime.utcnow()
                    }
                }
                collection.update_one(query, update, upsert=True)
                
            print(table)
            
            if delta and not is_alert_sent:
                save_dangling_to_csv(delta, previous_csv_file_path)
                
                # Prepare table content for new delta records
                delta_table_content = "|| Domain || Cloudflare IPs || GCP IPs || Status ||\n"
                for domain, details in delta.items():
                    if isinstance(details, dict):
                        # New format with structured data
                        cloudflare_ips = ", ".join(details.get('cloudflare_ips', []))
                        gcp_ips = ", ".join(details.get('gcp_ips', []))
                        status = details.get('status', 'unknown')
                        delta_table_content += f"| {domain} | {cloudflare_ips or 'None'} | {gcp_ips or 'None'} | {status} |\n"
                    else:
                        # Fallback for old format
                        delta_table_content += f"| {domain} | {details} | None | unknown |\n"
                
                # Check if content is too long for Jira description
                if len(delta_table_content) > 32000:  # Leave some buffer
                    # Create Jira issue with short description and attach CSV
                    jira_issue = system.create_jira_issue(
                        self.jira,
                        'APOC',
                        '[Dangling DNS] New potential dangling DNS records found',
                        f"New dangling DNS records found. Please check the attached CSV file for details.\n\nTotal records: {len(delta)}",
                        issue_type="Bug",
                        label=self.label
                    )
                    # Attach the CSV file
                    issue_id = jira_issue.key
                    self.jira.add_attachment(issue=issue_id, attachment=csv_file_path)
                    print(f"[bold green][+] Jira ticket created for new dangling DNS records: {jira_issue.key} (with CSV attachment)[/bold green]")
                else:
                    # Use table content in description
                    jira_issue = system.create_jira_issue(
                        self.jira,
                        'APOC',
                        '[Dangling DNS] New potential dangling DNS records found',
                        delta_table_content,
                        issue_type="Bug",
                        label=self.label
                    )
                    print(f"[bold green][+] Jira ticket created for new dangling DNS records: {jira_issue.key}[/bold green]")
                
                system.send_slack_alert(f"Dangling DNS scan completed successfully at {datetime.now()}")
                system.add_hash_to_db(delta_hash)
            else:
                print("[bold green][+] No new dangling DNS records found![/bold green]")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Appollo - Reconnaissance Tool")
    parser.add_argument('-e',"--env", action="store", required=True, help="Path to the .env file")
    parser.add_argument("-t","--target", action="store", help="Target domain, IP, CIDR, or any asset which is supported by Appollo")
    parser.add_argument("-U","--update-inventory", action="store_true", help="Update Inventory Records")
    parser.add_argument("-sc","--ssl-checker", action="store_true", help="Run SSL Checker")
    parser.add_argument("-ps","--port-scan", action="store_true", help="Run port scan logic")
    parser.add_argument("-ws","--wayback-scan", action="store_true", help="Run wayback scan logic")
    parser.add_argument("-fs","--firewall-port-scan", action="store_true", help="Run port scan based on firewall rules")
    parser.add_argument("-ts","--tech-scan", action="store_true", help="Run Technology scan")
    parser.add_argument("-ds","--dir-scan", action="store_true", help="Run directory scan logic")
    parser.add_argument("-ns","--nuclei-scan", action="store_true", help="Run nuclei scans for CVE's")
    parser.add_argument("-dd","--dangling-dns", action="store_true", help="Run dangling DNS scan")
    parser.add_argument("-A","--complete-scan", action="store_true", help="Run Complete scan for all known assets in inventory")

    args = parser.parse_args()

    appollo = Appollo(args)
    appollo.run()
   

