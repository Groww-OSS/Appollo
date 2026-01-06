"""
Dangling DNS Detection Module
=============================

This module detects dangling DNS records by comparing Cloudflare DNS records
against public IPs from Google Cloud Platform (GCP) projects. A "dangling" DNS
record points to an IP address that is no longer associated with any active
GCP resource, which can pose security risks (subdomain takeover vulnerabilities).

Features:
---------
- Fetches all DNS zones from Cloudflare automatically (or specific zones)
- Collects public IPs from all GCP projects (VMs, Load Balancers, Static IPs)
- Identifies DNS A/AAAA records pointing to IPs not found in GCP
- Supports IP whitelisting to exclude known external IPs
- Deduplication via hash-based tracking to avoid repeated alerts

Required Environment Variables:
-------------------------------
    CLOUDFLARE_API_KEY : str
        Cloudflare API token with Zone:Read and DNS:Read permissions.
        Create at: https://dash.cloudflare.com/profile/api-tokens
    
    SVC_ACCOUNT : str
        Path to GCP service account JSON key file.
        Required IAM roles: compute.viewer, resourcemanager.projectViewer
        Default: ./credentials/gcp-service-account.json

Optional Environment Variables:
-------------------------------
    WHITELIST_FILE : str
        Path to a file containing IPs/CIDRs to exclude from dangling detection.
        One entry per line, supports # comments.
        Default: ./config/whitelist.txt
    
    MAX_WORKERS : int
        Maximum parallel workers for GCP API calls.
        Default: 200

Usage:
------
    from modules.dangling_dns import get_dangling_dns_dict
    
    # Check all Cloudflare zones accessible by API token
    results = get_dangling_dns_dict()
    
    # Check specific zones only
    results = get_dangling_dns_dict(zone_names=['example.com', 'mysite.org'])
    
    # Force re-scan even if data hasn't changed
    results = get_dangling_dns_dict(force_update=True)

Author: Appollo Security
License: MIT
"""

import ipaddress
import requests
import google.auth
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import concurrent.futures
import os
import pandas as pd
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console
from system.db import MongoDB
from system.utils import calculate_hash, check_if_hash_exists, add_hash_to_db

console = Console()

# Configuration via environment variables with sensible defaults
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '200'))
WHITELIST_FILE = os.getenv('WHITELIST_FILE', '/etc/config/whitelist.txt')
SVC_ACCOUNT = os.getenv('SVC_ACCOUNT', '/etc/config/creds.json')

def load_whitelist():
    whitelist = set()
    if WHITELIST_FILE and os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    whitelist.add(line)
    else:
        console.print(f"[bold yellow][-] Whitelist file not found at {WHITELIST_FILE}, using empty whitelist[/bold yellow]")
    return whitelist

def preprocess_whitelist(whitelist):
    ip_set = set()
    cidr_list = []
    
    # Process entries in parallel for better performance
    def process_entry(entry):
        if '/' in entry:
            try:
                return ('cidr', ipaddress.ip_network(entry, strict=False))
            except Exception:
                return None
        else:
            return ('ip', entry)
    
    # Use list comprehension for faster processing
    processed_entries = [process_entry(entry) for entry in whitelist]
    
    for result in processed_entries:
        if result:
            entry_type, value = result
            if entry_type == 'cidr':
                cidr_list.append(value)
            else:
                ip_set.add(value)
    
    return ip_set, cidr_list

def is_whitelisted_fast(ip, ip_set, cidr_list):
    # Fast path: check if IP is directly in the set
    if ip in ip_set:
        return True
    
    # Only try to parse IP if we have CIDR networks to check
    if cidr_list:
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Use any() for faster iteration
            return any(ip_obj in net for net in cidr_list)
        except Exception:
            pass
    return False

def is_valid_ip(ip):
    """Check if the IP address is valid"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_cloudflare_zone_id(headers, zone_name):
    """Get Cloudflare zone ID for a given zone name"""
    url = "https://api.cloudflare.com/client/v4/zones"
    params = {'name': zone_name}
    res = requests.get(url, headers=headers, params=params)
    res.raise_for_status()
    return res.json()['result'][0]['id']

def get_all_cloudflare_zones(headers):
    """Get all Cloudflare zones accessible by the API token"""
    url = "https://api.cloudflare.com/client/v4/zones"
    zones = []
    page = 1
    while True:
        res = requests.get(url, headers=headers, params={"page": page, "per_page": 50})
        res.raise_for_status()
        data = res.json()
        zones.extend(data['result'])
        if page >= data['result_info']['total_pages']:
            break
        page += 1
    return zones

def get_dns_records(headers, zone_id):
    """Get all DNS records from Cloudflare for a zone"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    records = []
    page = 1
    while True:
        res = requests.get(url, headers=headers, params={"page": page, "per_page": 100})
        res.raise_for_status()
        data = res.json()['result']
        if not data:
            break
        records.extend(data)
        page += 1
    return records

def list_gcp_projects(credentials):
    """List all active GCP projects (excluding sys-* projects)"""
    crm = build('cloudresourcemanager', 'v1', credentials=credentials)
    projects = []
    req = crm.projects().list()
    while req is not None:
        res = req.execute()
        for proj in res.get('projects', []):
            pid = proj['projectId']
            if proj['lifecycleState'] == 'ACTIVE' and not pid.startswith("sys-"):
                projects.append(pid)
        req = crm.projects().list_next(previous_request=req, previous_response=res)
    return projects

def get_project_ips(credentials, project_id):
    """Get all public IPs for a GCP project (VMs, load balancers, static IPs)"""
    compute = build('compute', 'v1', credentials=credentials)
    ips = set()

    # Static IPs
    req = compute.addresses().aggregatedList(project=project_id)
    while req is not None:
        res = req.execute()
        for _, scope in res.get('items', {}).items():
            for addr in scope.get('addresses', []):
                if 'address' in addr:
                    ips.add(addr['address'])
        req = compute.addresses().aggregatedList_next(previous_request=req, previous_response=res)

    # VM Instance IPs
    zones_req = compute.zones().list(project=project_id)
    zones = zones_req.execute().get('items', [])
    for zone in zones:
        zone_name = zone['name']
        try:
            vms = compute.instances().list(project=project_id, zone=zone_name).execute()
            for vm in vms.get('items', []):
                for iface in vm.get('networkInterfaces', []):
                    for ac in iface.get('accessConfigs', []):
                        if 'natIP' in ac:
                            ips.add(ac['natIP'])
        except Exception:
            continue  # skip zones with no instances

    # Load Balancer IPs (Forwarding Rules)
    fr_req = compute.forwardingRules().aggregatedList(project=project_id)
    while fr_req is not None:
        fr_res = fr_req.execute()
        for _, scope in fr_res.get('items', {}).items():
            for fr in scope.get('forwardingRules', []):
                if 'IPAddress' in fr:
                    ips.add(fr['IPAddress'])
        fr_req = compute.forwardingRules().aggregatedList_next(previous_request=fr_req, previous_response=fr_res)

    return ips

def is_public_ip(ip):
    """Check if an IP address is public/global"""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False  # Not a valid IP

def get_all_gcp_ips(credentials, max_workers=300):
    """Get all public IPs from all GCP projects"""
    console.print("[bold blue] Listing GCP projects...[/bold blue]")
    projects = list_gcp_projects(credentials)
    console.print(f"[green]✓ Found {len(projects)} eligible GCP projects[/green]")
    
    if not projects:
        console.print("[yellow]  No GCP projects found[/yellow]")
        return {}
    
    all_project_ips = {}
    completed = 0
    
    def fetch_ips(project_id):
        nonlocal completed
        try:
            ips = get_project_ips(credentials, project_id)
            completed += 1
            return project_id, ips
        except Exception as e:
            completed += 1
            # Extract clean message
            err_msg = str(e)
            if "accessNotConfigured" in err_msg:
                console.print(f"[yellow]{project_id}: Compute Engine API not enabled ({completed}/{len(projects)})[/yellow]")
            else:
                console.print(f"[red] {project_id}: Error fetching IPs ({completed}/{len(projects)})[/red]")
            return project_id, set()
    
    console.print(f"[bold blue] Collecting IPs in parallel using {max_workers} workers...[/bold blue]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = list(executor.map(fetch_ips, projects))
        all_project_ips = dict(futures)
    
    # Calculate total IPs
    total_ips = sum(len(ips) for ips in all_project_ips.values())
    projects_with_ips = len([p for p in all_project_ips.values() if p])
    
    console.print(f"[green]✓ Completed! Found {total_ips} total IPs across {projects_with_ips} projects[/green]")
    
    return all_project_ips

def debug_dns_records(zone_name=None, limit=10):
    """
    Debug function to inspect DNS records and help troubleshoot issues.
    If zone_name is not provided, fetches all zones from Cloudflare API.
    """
    try:
        cloudflare_token = os.getenv('CLOUDFLARE_API_KEY')
        if not cloudflare_token:
            console.print("[bold red]Error: CLOUDFLARE_API_KEY environment variable not set[/bold red]")
            console.print("[dim]Create an API token at: https://dash.cloudflare.com/profile/api-tokens[/dim]")
            return False
        
        if not os.path.exists(SVC_ACCOUNT):
            console.print(f"[bold red]Error: GCP service account file not found: {SVC_ACCOUNT}[/bold red]")
            console.print("[dim]Set SVC_ACCOUNT environment variable to the correct path[/dim]")
            return False
        
        console.print("[bold blue]=== DNS Records Debug ===[/bold blue]")
        
        # Setup connections
        headers = {
            "Authorization": f"Bearer {cloudflare_token}",
            "Content-Type": "application/json"
        }
        credentials, _ = google.auth.load_credentials_from_file(SVC_ACCOUNT)
        
        # Get Cloudflare DNS records - fetch all zones if not specified
        if zone_name:
            zones_to_check = [{'name': zone_name}]
            console.print(f"[dim]Using specified zone: {zone_name}[/dim]")
        else:
            console.print("[dim]Fetching all zones from Cloudflare API...[/dim]")
            zones_to_check = get_all_cloudflare_zones(headers)
            console.print(f"[dim]Found {len(zones_to_check)} zones[/dim]")
        
        dns_records = []
        for zone in zones_to_check:
            zn = zone['name']
            console.print(f"[dim]Fetching DNS records for zone: {zn}[/dim]")
            try:
                zone_id = get_cloudflare_zone_id(headers, zn)
                zone_records = get_dns_records(headers, zone_id)
                dns_records.extend(zone_records)
                console.print(f"[dim]  → Found {len(zone_records)} records[/dim]")
            except Exception as e:
                console.print(f"[bold red]Zone Error for {zn}: {str(e)}[/bold red]")
                continue
        
        console.print(f"[dim]Total Cloudflare DNS records: {len(dns_records)}[/dim]")
        
        # Get GCP IPs
        console.print("[dim]Fetching GCP project IPs...[/dim]")
        all_project_ips = get_all_gcp_ips(credentials, max_workers=300)
        
        # Calculate total public IPs
        all_ips = set()
        for ips in all_project_ips.values():
            all_ips.update(ip for ip in ips if is_public_ip(ip))
        console.print(f"[dim]Total GCP public IPs: {len(all_ips)}[/dim]")
        
        # Show sample DNS records
        if dns_records:
            zone_label = zone_name if zone_name else f"{len(zones_to_check)} zones"
            console.print(f"\n[bold]Sample DNS records from {zone_label}:[/bold]")
            for i, record in enumerate(dns_records[:limit]):
                if record['type'] in ['A', 'AAAA']:
                    console.print(f"  {record['name']} ({record['type']}) -> {record['content']}")
        
        # Show sample GCP IPs
        if all_ips:
            console.print(f"\n[bold]Sample GCP public IPs:[/bold]")
            for i, ip in enumerate(list(all_ips)[:limit]):
                console.print(f"  {ip}")
        
        # Show project breakdown
        console.print(f"\n[bold]GCP Projects with IPs:[/bold]")
        for project_id, ips in all_project_ips.items():
            public_ips = [ip for ip in ips if is_public_ip(ip)]
            if public_ips:
                console.print(f"  {project_id}: {len(public_ips)} public IPs")
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]Error in debug function: {str(e)}[/bold red]")
        return False

def check_existing_results_hash(dns_data):
    """
    Check if the DNS data has already been processed by calculating its hash
    and checking if it exists in the hash database.
    """
    try:
        # Calculate hash of the DNS data
        data_hash = calculate_hash(dns_data)
        
        # Check if this hash already exists
        if check_if_hash_exists(data_hash):
            return True, data_hash
        else:
            return False, data_hash
    except Exception as e:
        console.print(f"[bold red]Error checking hash: {str(e)}[/bold red]")
        return False, None

def find_dangling_records(dns_records, all_project_ips_map, whitelist_ips=None):
    """Find DNS records that point to IPs not found in any GCP project"""
    dangling = []
    all_ips = set()
    for ips in all_project_ips_map.values():
        all_ips.update(ip for ip in ips if is_public_ip(ip))

    processed = 0
    skipped_private = 0
    skipped_whitelist = 0
    skipped_type = 0
    
    for rec in dns_records:
        processed += 1
            
        if rec['type'] not in ['A', 'AAAA']:
            skipped_type += 1
            continue

        target_ip = rec['content']
        if not is_public_ip(target_ip):
            skipped_private += 1
            continue  # Skip internal/private IPs
        
        # Check if IP is whitelisted
        if whitelist_ips and is_whitelisted_fast(target_ip, whitelist_ips[0], whitelist_ips[1]):
            skipped_whitelist += 1
            continue

        if target_ip not in all_ips:
            found_in = [pid for pid, ips in all_project_ips_map.items() if target_ip in ips]
            dangling.append({
                'name': rec['name'],
                'type': rec['type'],
                'target': target_ip,
                'found_in_projects': found_in,
            })
    
    console.print(f"[dim]   ✓ Analysis complete:[/dim]")
    console.print(f"[dim]     - Processed: {processed} records[/dim]")
    console.print(f"[dim]     - Skipped (non-A/AAAA): {skipped_type}[/dim]")
    console.print(f"[dim]     - Skipped (private IPs): {skipped_private}[/dim]")
    console.print(f"[dim]     - Skipped (whitelisted): {skipped_whitelist}[/dim]")
    console.print(f"[dim]     - Dangling found: {len(dangling)}[/dim]")
    
    return dangling

def get_dangling_dns_dict(domains=None, force_update=False, max_workers=300, zone_names=None):
    """
    Find dangling DNS records by comparing Cloudflare DNS records with all GCP project IPs.
    Always uses direct API calls for the most accurate and up-to-date results.
    
    Args:
        domains: List of domains to check (for backward compatibility, not used in new logic)
        force_update: Force update even if data was recently processed
        max_workers: Maximum number of parallel workers for GCP API calls
        zone_names: Optional list of specific zone names to check. If None, fetches all zones from API.
    
    Returns:
        Dictionary of dangling DNS records
    """
    # Startup banner
    console.print("\n[bold blue] Starting Dangling DNS Detection Scan[/bold blue]")
    console.print("[dim]=" * 50 + "[/dim]")
    
    console.print(f"[bold]Max Workers:[/bold] {max_workers}")
    console.print(f"[bold]Force Update:[/bold] {force_update}")
    if zone_names:
        console.print(f"[bold]Target Zones:[/bold] {', '.join(zone_names)}")
    else:
        console.print("[bold]Target Zones:[/bold] All zones (fetched from Cloudflare API)")
    if domains:
        console.print(f"[bold]Domains Parameter:[/bold] {len(domains)} domains (legacy parameter, not used)")
    console.print("[dim]=" * 50 + "[/dim]\n")
    
    # Always use direct API approach for the most accurate results
    console.print("[bold green]✓ Using direct API approach for real-time data[/bold green]")
    return get_dangling_dns_from_apis(zone_names, force_update, max_workers)

def get_dangling_dns_from_apis(zone_names, force_update, max_workers):
    """Get dangling DNS records using direct Cloudflare and GCP API calls.
    
    Args:
        zone_names: Optional list of zone names to check. If None, fetches all zones from API.
        force_update: Force update even if data was recently processed
        max_workers: Maximum number of parallel workers for GCP API calls
    """
    cloudflare_token = os.getenv('CLOUDFLARE_API_KEY')
    if not cloudflare_token:
        console.print("[bold red] Error: CLOUDFLARE_API_KEY environment variable not set[/bold red]")
        console.print("[dim]Create an API token at: https://dash.cloudflare.com/profile/api-tokens[/dim]")
        return {}
    
    if not os.path.exists(SVC_ACCOUNT):
        console.print(f"[bold red] Error: GCP service account file not found: {SVC_ACCOUNT}[/bold red]")
        console.print("[dim]Set SVC_ACCOUNT environment variable to the correct path[/dim]")
        return {}
    
    # Load whitelist
    console.print("[bold blue] Loading whitelist...[/bold blue]")
    whitelist = load_whitelist()
    ip_set, cidr_list = preprocess_whitelist(whitelist)
    console.print(f"[green]✓ Loaded {len(whitelist)} whitelist entries[/green]")
    
    # Setup headers
    console.print("[bold blue] Setting up Cloudflare connection...[/bold blue]")
    headers = {
        "Authorization": f"Bearer {cloudflare_token}",
        "Content-Type": "application/json"
    }
    console.print("[green]✓ Cloudflare headers configured[/green]")
    
    # Setup GCP credentials
    console.print("[bold blue] Setting up GCP connection...[/bold blue]")
    try:
        credentials, _ = google.auth.load_credentials_from_file(SVC_ACCOUNT)
        console.print("[green] GCP credentials loaded successfully[/green]")
    except Exception as e:
        console.print(f"[bold red] Error setting up GCP: {str(e)}[/bold red]")
        return {}
    
    # Determine which zones to check
    console.print("[bold blue] Fetching Cloudflare zones...[/bold blue]")
    try:
        if zone_names:
            # Use provided zone names
            zones_to_check = [{'name': zn} for zn in zone_names]
            console.print(f"[green]✓ Using {len(zones_to_check)} specified zone(s)[/green]")
        else:
            # Fetch all zones from Cloudflare API
            zones_to_check = get_all_cloudflare_zones(headers)
            console.print(f"[green]✓ Found {len(zones_to_check)} zones from Cloudflare API[/green]")
        
        for zone in zones_to_check:
            # Zone names are available in logs if needed, avoid verbose per-zone printing
            _ = zone['name']
    except Exception as e:
        console.print(f"[bold red] Error fetching zones: {str(e)}[/bold red]")
        return {}
    
    # Fetch DNS records from all zones
    console.print("[bold blue] Fetching DNS records from Cloudflare...[/bold blue]")
    dns_records = []
    zone_names_processed = []
    try:
        for zone in zones_to_check:
            zone_name = zone['name']
            try:
                zone_id = get_cloudflare_zone_id(headers, zone_name)
                zone_records = get_dns_records(headers, zone_id)
                dns_records.extend(zone_records)
                zone_names_processed.append(zone_name)
            except Exception as e:
                console.print(f"[yellow] {zone_name}: {str(e)}[/yellow]")
                continue
        
        console.print(f"[green]✓ Found {len(dns_records)} total DNS records from {len(zone_names_processed)} zone(s)[/green]")
        
        # Show breakdown by type
        a_records = [r for r in dns_records if r['type'] == 'A']
        aaaa_records = [r for r in dns_records if r['type'] == 'AAAA']
        console.print(f"[dim]   - A records: {len(a_records)}[/dim]")
        console.print(f"[dim]   - AAAA records: {len(aaaa_records)}[/dim]")
    except Exception as e:
        console.print(f"[bold red] Error fetching DNS records: {str(e)}[/bold red]")
        return {}
    
    console.print("[bold blue] Fetching GCP project IPs...[/bold blue]")
    try:
        all_project_ips = get_all_gcp_ips(credentials, max_workers)
        console.print(f"[green] Completed GCP IP collection[/green]")
    except Exception as e:
        console.print(f"[bold red] Error fetching GCP IPs: {str(e)}[/bold red]")
        return {}
    
    # Check for hash deduplication
    console.print("[bold blue] Processing collected data...[/bold blue]")
    all_ips = set()
    for ips in all_project_ips.values():
        all_ips.update(ip for ip in ips if is_public_ip(ip))
    
    console.print(f"[dim]   - Total public IPs from GCP: {len(all_ips)}[/dim]")
    console.print(f"[dim]   - Whitelist entries: {len(whitelist)}[/dim]")
    
    dns_data = {
        'zone_names': sorted(zone_names_processed),
        'dns_records': sorted([(r['name'], r['type'], r['content']) for r in dns_records]),
        'gcp_ips': sorted(list(all_ips)),
        'whitelist': sorted(list(whitelist))
    }
    
    console.print("[bold blue] Checking for duplicate data...[/bold blue]")
    is_processed, data_hash = check_existing_results_hash(dns_data)
    if is_processed and not force_update:
        console.print("[bold yellow] DNS data already processed. No new changes detected.[/bold yellow]")
        return {}
    
    if not is_processed:
        console.print(f"[green]✓ Processing new DNS data (hash: {data_hash[:8]}...)[/green]")
    else:
        console.print(f"[green]✓ Force update enabled, reprocessing data[/green]")
    
    console.print("[bold blue] Analyzing for dangling DNS records...[/bold blue]")
    try:
        dangling_records = find_dangling_records(dns_records, all_project_ips, (ip_set, cidr_list))
        console.print(f"[green]✓ Analysis complete! Found {len(dangling_records)} potential dangling records[/green]")
    except Exception as e:
        console.print(f"[bold red] Error analyzing dangling records: {str(e)}[/bold red]")
        return {}
    
    # Convert to result format
    console.print("[bold blue] Converting results to standard format...[/bold blue]")
    result = {}
    for record in dangling_records:
        result[record['name']] = {
            'cloudflare_ips': [record['target']],
            'gcp_ips': [],
            'status': 'dangling',
            'type': record['type']
        }
    console.print(f"[green] Converted {len(result)} records to result format[/green]")
    
    # Store the hash to mark this data as processed
    if data_hash and not is_processed:
        console.print("[bold blue] Storing hash for future deduplication...[/bold blue]")
        try:
            add_hash_to_db(data_hash)
            console.print(f"[green] Stored hash {data_hash[:8]}... for future deduplication[/green]")
        except Exception as e:
            console.print(f"[bold red] Warning: Failed to store hash: {str(e)}[/bold red]")
    
    # Final summary
    console.print(f"\n[bold green] SCAN COMPLETE! Found {len(result)} dangling DNS entries[/bold green]")
    if result:
        console.print("[bold yellow] Dangling DNS records detected - review required![/bold yellow]")
    else:
        console.print("[bold green] No dangling DNS records found - all good![/bold green]")
    
    return result

def get_dangling_dns_from_mongodb(domains, force_update):
    """Get dangling DNS records using MongoDB data (legacy approach)"""
    console = Console()
    
    console.print("[bold blue] Fetching DNS records from MongoDB...[/bold blue]")
    
    try:
        dns_collection = MongoDB().set_collection("DNS")
        ip_collection = MongoDB().set_collection("IP Records")
        
        # Get Cloudflare DNS records
        cloudflare_records = dns_collection.find({'source': 'cloudflare'})
        cf_domains = set()
        cf_domain_ips = {}  # domain -> set of IPs
        
        for records in cloudflare_records:
            for record in records.get('records', []):
                domain_name = record.get('domain', '')
                if domain_name:
                    cf_domains.add(domain_name)
                    cf_domain_ips[domain_name] = set()
                
                for r in record.get('records', []):
                    ip = r.get('content', '')
                    if r.get('type') == 'A' and not ip.startswith(('10.', '192.168', '127.')):
                        domain = r.get('name', '')
                        if domain:
                            cf_domains.add(domain)
                            if domain not in cf_domain_ips:
                                cf_domain_ips[domain] = set()
                            cf_domain_ips[domain].add(ip)
        
        # Get GCP DNS records
        gcp_dns = dns_collection.find({'source': 'GCP'})
        gcp_domains = set()
        gcp_domain_ips = {}  # domain -> set of IPs
        
        for records in gcp_dns:
            for project_record in records.get('records', []):
                for record in project_record.get('records', []):
                    ip_list = record.get('Rrdatas', [])
                    if ip_list and record.get('Type') == 'A':
                        domain = record.get('Name', '')
                        if domain:
                            gcp_domains.add(domain)
                            if domain not in gcp_domain_ips:
                                gcp_domain_ips[domain] = set()
                            for ip in ip_list:
                                if not ip.startswith(('10.', '192.168', '127.')):
                                    gcp_domain_ips[domain].add(ip)
        
        # Get GCP IP records for additional IP validation
        gcp_ip_records = ip_collection.find({'source': 'GCP'})
        all_gcp_ips = set()
        
        for records in gcp_ip_records:
            for record in records.get('records', []):
                ip_details = record.get('ip_details', {})
                for ip in ip_details.keys():
                    if not ip.startswith(('10.', '192.168', '127.')):
                        all_gcp_ips.add(ip)
        
        console.print(f"[green] Found {len(cf_domains)} Cloudflare domains[/green]")
        console.print(f"[green] Found {len(gcp_domains)} GCP domains[/green]")
        console.print(f"[green] Found {len(all_gcp_ips)} total GCP IPs[/green]")
        
        # Find dangling domains - domains in Cloudflare but not in GCP
        dangling_domains = cf_domains - gcp_domains
        
        # Also check for domains where IPs don't match
        for domain in cf_domains.intersection(gcp_domains):
            cf_ips = cf_domain_ips.get(domain, set())
            gcp_ips = gcp_domain_ips.get(domain, set())
            
            # If Cloudflare IPs are not in GCP IPs, it's dangling
            if cf_ips and not cf_ips.intersection(gcp_ips) and not cf_ips.intersection(all_gcp_ips):
                dangling_domains.add(domain)
        
        # Convert to result format
        result = {}
        for domain in dangling_domains:
            cf_ips = list(cf_domain_ips.get(domain, set()))
            gcp_ips = list(gcp_domain_ips.get(domain, set()))
            
            result[domain] = {
                'cloudflare_ips': cf_ips if cf_ips else ['unknown'],
                'gcp_ips': gcp_ips,
                'status': 'dangling',
                'type': 'A'
            }
        
        console.print(f"[green]✓ Found {len(result)} dangling DNS entries[/green]")
        return result
        
    except Exception as e:
        console.print(f"[bold red] Error fetching from MongoDB: {str(e)}[/bold red]")
        return {}

def get_dangling_dns_dict_legacy(domains=None, force_update=False):
    """
    Legacy function for backward compatibility with the old interface.
    This function maintains the same signature as the original but uses the new logic.
    """
    return get_dangling_dns_dict(domains=domains, force_update=force_update, max_workers=300)

def save_dangling_to_csv(data, file_path):
    console = Console()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Saving results to CSV...", total=1)
        
        if not data:
            progress.update(task, description="No data to save!")
            console.print("[bold yellow]No dangling DNS entries found to save[/bold yellow]")
            return
            
        try:
            # Check if data is in the new format (with cloudflare_ips, gcp_ips, status)
            if isinstance(next(iter(data.values())), dict):
                rows = []
                for domain, details in data.items():
                    row = {
                        'Domain': domain,
                        'Type': details.get('type', 'A'),
                        'IP': details.get('cloudflare_ips', [''])[0] if details.get('cloudflare_ips') else '',
                        'cloudflare_ips': str(details.get('cloudflare_ips', [])),
                        'gcp_ips': str(details.get('gcp_ips', [])),
                        'status': details.get('status', 'unknown')
                    }
                    rows.append(row)
                df = pd.DataFrame(rows)
            else:
                # Fallback to old format if needed
                rows = [{'Domain': domain, 'IP': ip} 
                       for domain, ips in data.items() 
                       for ip in (ips if isinstance(ips, list) else [])]
                df = pd.DataFrame(rows)
            
            # Only try to create directory if file_path contains a directory
            dir_path = os.path.dirname(file_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                
            df.to_csv(file_path, index=False)
            progress.update(task, description="Results saved successfully!")
            console.print(f"[bold green]Results saved to {file_path}[/bold green]")
            console.print(f"[dim]Saved {len(df)} entries[/dim]")
            
        except Exception as e:
            progress.update(task, description=f"Error saving results: {str(e)}")
            console.print(f"[bold red]Error saving results: {str(e)}[/bold red]")
            raise
            
        progress.update(task, completed=1)

def get_new_dangling_dns_only(domains=None, force_update=False, csv_file_path=None):
    """
    Get only new dangling DNS results by comparing with previous results.
    This function avoids returning the same results repeatedly.
    """
    console = Console()
    
    # Get current results
    current_results = get_dangling_dns_dict(domains, force_update)
    
    if not current_results:
        return {}
    
    # If no CSV file path provided, return all current results
    if not csv_file_path:
        return current_results
    
    # Check for previous results in CSV
    previous_results = {}
    if os.path.exists(csv_file_path) and os.path.getsize(csv_file_path) > 0:
        try:
            df = pd.read_csv(csv_file_path)
            if not df.empty and 'cloudflare_ips' in df.columns and 'gcp_ips' in df.columns:
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
            console.print(f"[bold red] Warning: Could not read previous results from {csv_file_path}: {str(e)}[/bold red]")
    
    # Find new results only
    new_results = {}
    for domain, current_data in current_results.items():
        if domain not in previous_results:
            # Domain is completely new
            new_results[domain] = current_data
        else:
            # Check if the data has changed
            prev_data = previous_results[domain]
            if (current_data['cloudflare_ips'] != prev_data['cloudflare_ips'] or 
                current_data['gcp_ips'] != prev_data['gcp_ips'] or
                current_data['status'] != prev_data['status']):
                new_results[domain] = current_data
    
    if new_results:
        console.print(f"[bold green] Found {len(new_results)} new/changed dangling DNS entries[/bold green]")
    else:
        console.print("[bold yellow] No new dangling DNS entries found[/bold yellow]")
    
    return new_results


def test_dangling_dns_logic():
    """
    Test function to verify the dangling DNS logic works correctly
    """
    console = Console()
    
    console.print("[bold blue]=== Testing Dangling DNS Logic ===[/bold blue]")
    
    # Test with sample data
    sample_dns_records = [
        {'name': 'test1.example.com', 'type': 'A', 'content': '1.2.3.4'},
        {'name': 'test2.example.com', 'type': 'A', 'content': '10.0.0.1'},  # Private IP
        {'name': 'test3.example.com', 'type': 'CNAME', 'content': 'example.com'},  # Not A/AAAA
        {'name': 'test4.example.com', 'type': 'A', 'content': '8.8.8.8'},  # Public IP not in GCP
    ]
    
    sample_gcp_ips = {'1.2.3.4', '5.6.7.8', '9.10.11.12'}  # Only first IP exists in GCP
    
    # Test the logic
    dangling = find_dangling_records(sample_dns_records, sample_gcp_ips)
    
    console.print(f"[dim] Sample DNS records: {len(sample_dns_records)}[/dim]")
    console.print(f"[dim] Sample GCP IPs: {len(sample_gcp_ips)}[/dim]")
    console.print(f"[dim] Found dangling records: {len(dangling)}[/dim]")
    
    for record in dangling:
        console.print(f"  - {record['name']} ({record['type']}) -> {record['target']}")
    
    # Expected: test4.example.com should be dangling (8.8.8.8 not in GCP)
    expected_dangling = 1
    if len(dangling) == expected_dangling:
        console.print("[bold green] Logic test passed![/bold green]")
        return True
    else:
        console.print(f"[bold red] Logic test failed! Expected {expected_dangling} dangling records, got {len(dangling)}[/bold red]")
        return False

def clear_dns_hash_database():
    """
    Clear the DNS hash database to reset deduplication state.
    This is useful for testing or when you want to reprocess all data.
    """
    console = Console()
    
    try:
        # Import here to avoid circular imports
        from system.utils import clear_hash_database
        clear_hash_database()
        console.print("[bold green] DNS hash database cleared successfully[/bold green]")
        return True
    except ImportError:
        console.print("[bold red] Could not import clear_hash_database function[/bold red]")
        return False
    except Exception as e:
        console.print(f"[bold red] Error clearing hash database: {str(e)}[/bold red]")
        return False

def get_dns_hash_status():
    """
    Get the current status of DNS hash deduplication.
    Returns information about stored hashes.
    """
    console = Console()
    
    try:
        # Import here to avoid circular imports
        from system.utils import get_hash_database_info
        info = get_hash_database_info()
        console.print(f"[dim]Hash database info: {info}[/dim]")
        return info
    except ImportError:
        console.print("[bold red] Could not import get_hash_database_info function[/bold red]")
        return None
    except Exception as e:
        console.print(f"[bold red] Error getting hash database info: {str(e)}[/bold red]")
        return None