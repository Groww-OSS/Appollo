import json
import csv
import socket
import time
import argparse
import concurrent.futures
import os
import sys
import ipaddress
from google.oauth2 import service_account
from google.auth import default as google_auth_default
from googleapiclient import discovery
from rich.console import Console
from rich.table import Table
from googleapiclient.errors import HttpError
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn



# ---------- CONFIG ----------
SERVICE_ACCOUNT_FILE = "/etc/config/creds.json"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
TIMEOUT = 1   
TOP_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443]  # common ports
GKE_PORTS = [22, 80, 443, 6443, 8080, 8443, 10250, 10255, 10256] + list(range(1, 65335))  # GKE + NodePort sample
MAX_WORKERS = 20  
CSV_FILE = "gcp_open_ports.csv"
JSON_FILE = "gcp_open_ports.json"
# ----------------------------

console = Console()

# Try to import GCP asset discovery helpers from local src root
try:
    MODULES_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if MODULES_ROOT not in sys.path:
        sys.path.append(MODULES_ROOT)
    from modules.gcp import GCP   
except Exception:
    GCP = None 

def retry_api_call(func, max_retries=3, backoff_factor=2):
    """Retry API calls with exponential backoff for transient errors."""
    for attempt in range(max_retries):
        try:
            return func()
        except HttpError as e:
            status = e.resp.status
            
            if status == 403:  
                raise
            elif status == 404:  
                raise
            
            if status in [429, 500, 502, 503, 504]:
                if attempt < max_retries - 1:
                    wait_time = backoff_factor ** attempt
                    console.log(f"[yellow]HTTP {status} error, retrying in {wait_time}s... (attempt {attempt + 1}/{max_retries})[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    console.log(f"[red]Max retries exceeded for HTTP {status} error[/red]")
                    raise
            else:
                raise
        except Exception as e:
       
            raise

def get_service(api, version, credentials):
    return discovery.build(api, version, credentials=credentials, cache_discovery=False)

def list_projects(crm_service, org_id=None, project_filter=None):
    """List projects, optionally filtered by organization or specific project list."""
    projects = []
    request = crm_service.projects().list()
    while request is not None:
        response = request.execute()
        for proj in response.get("projects", []):
            if proj["lifecycleState"] == "ACTIVE":
                project_id = proj["projectId"]
                if project_filter:
                    if project_id in project_filter:
                        projects.append(project_id)
                    continue
    
                if org_id:
                    parent = proj.get("parent", {})
                    if parent.get("type") == "organization" and parent.get("id") == org_id:
                        projects.append(project_id)
                else:
                    projects.append(project_id)
                    
        request = crm_service.projects().list_next(previous_request=request, previous_response=response)
    return projects

def get_organizations(crm_service):
    """List project parents to help identify organization structure."""
    try:
        console.log("[yellow] Note: Direct organization listing not available in CRM v1 API[/yellow]")
        console.log("[cyan] Analyzing project parents to identify organizations...[/cyan]")
        
        orgs = {}
        request = crm_service.projects().list()
        while request is not None:
            response = request.execute()
            for proj in response.get("projects", []):
                if proj["lifecycleState"] == "ACTIVE":
                    parent = proj.get("parent", {})
                    if parent.get("type") == "organization":
                        org_id = parent.get("id")
                        if org_id and org_id not in orgs:
                            orgs[org_id] = {
                                "id": org_id,
                                "projects": [],
                                "displayName": f"Organization {org_id}"
                            }
                        if org_id:
                            orgs[org_id]["projects"].append(proj["projectId"])
            request = crm_service.projects().list_next(previous_request=request, previous_response=response)
        
        return list(orgs.values())
    except HttpError as e:
        console.log(f"[yellow]Cannot analyze project structure: {e}[/yellow]")
        return []

def list_firewall_rules(compute_service, project_id):
    def _fetch_rules():
        request = compute_service.firewalls().list(project=project_id)
        print(request)
        rules = []
        while request is not None:
            response = request.execute()
            rules.extend(response.get("items", []))
            print(rules)
            request = compute_service.firewalls().list_next(previous_request=request, previous_response=response)
        return rules
    
    try:
        return retry_api_call(_fetch_rules)
    except HttpError as e:
        if e.resp.status == 403:
            console.log(f"[yellow]Skipping {project_id}: Compute API not enabled[/yellow]")
            return []
        else:
            console.log(f"[red]Error fetching firewall rules for {project_id}: {e}[/red]")
            return []


def list_load_balancer_ips(compute_service, project_id):
    """List Load Balancer and forwarding rule IPs."""
    try:
        lb_ips = []
        request = compute_service.forwardingRules().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            for region, data in response.get("items", {}).items():
                for rule in data.get("forwardingRules", []):
                    if "IPAddress" in rule:
                        lb_ips.append({
                            "project": project_id,
                            "name": rule["name"], 
                            "ip": rule["IPAddress"],
                            "type": "Load Balancer"
                        })
            request = compute_service.forwardingRules().aggregatedList_next(previous_request=request, previous_response=response)
        
        request = compute_service.addresses().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            for region, data in response.get("items", {}).items():
                for addr in data.get("addresses", []):
                    if "address" in addr:
                        lb_ips.append({
                            "project": project_id,
                            "name": addr["name"],
                            "ip": addr["address"],
                            "type": "Static IP"
                        })
            request = compute_service.addresses().aggregatedList_next(previous_request=request, previous_response=response)
                        
        return lb_ips
    except HttpError as e:
        console.log(f"[yellow]Cannot fetch load balancer IPs for {project_id}: {e}[/yellow]")
        return []

def list_instances(compute_service, project_id):
    def _fetch_instances():
        request = compute_service.instances().aggregatedList(project=project_id)
        instances = []
        while request is not None:
            response = request.execute()
            for zone, data in response.get("items", {}).items():
                for inst in data.get("instances", []):
                    ip = None
                    if "networkInterfaces" in inst:
                        for nic in inst["networkInterfaces"]:
                            if "accessConfigs" in nic:
                                ip = nic["accessConfigs"][0].get("natIP")
                    if ip:
                        instances.append({"project": project_id, "name": inst["name"], "ip": ip})
            request = compute_service.instances().aggregatedList_next(previous_request=request, previous_response=response)
        return instances
    
    try:
        return retry_api_call(_fetch_instances)
    except HttpError as e:
        if e.resp.status == 403:
            console.log(f"[yellow]Skipping {project_id}: Compute API not enabled[/yellow]")
            return []
        else:
            console.log(f"[red]Error fetching instances for {project_id}: {e}[/red]")
            return []


def _is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except Exception:
        return False


def list_additional_assets_via_gcp(gcp_client, project_id, include_lb_and_static=True):
    """Use modules.gcp.GCP helpers to collect additional asset IPs for scanning.

    Returns a list of dicts with keys: project, name, type, ip
    """
    assets = []
    if not gcp_client:
        return assets

    seen_ips = set()

    # Forwarding rules (LB) and Static IPs (respect flag)
    try:
        if include_lb_and_static:
            for ip in gcp_client.get_forwarding_rule_ips(project_id):
                if not _is_private_ip(str(ip)) and ip not in seen_ips:
                    assets.append({"project": project_id, "name": "Forwarding Rule", "type": "Load Balancer", "ip": str(ip)})
                    seen_ips.add(ip)
            for ip in gcp_client.get_static_ips(project_id):
                if not _is_private_ip(str(ip)) and ip not in seen_ips:
                    assets.append({"project": project_id, "name": "Static IP", "type": "Static IP", "ip": str(ip)})
                    seen_ips.add(ip)
    except Exception:
        pass

    # SQL instances
    try:
        for ip in gcp_client.get_sql_ips(project_id):
            if not _is_private_ip(str(ip)) and ip not in seen_ips:
                assets.append({"project": project_id, "name": "SQL Instance", "type": "Cloud SQL", "ip": str(ip)})
                seen_ips.add(ip)
    except Exception:
        pass

    # VPN gateways
    try:
        for ip in gcp_client.get_vpn_ips(project_id):
            if not _is_private_ip(str(ip)) and ip not in seen_ips:
                assets.append({"project": project_id, "name": "VPN Gateway", "type": "VPN", "ip": str(ip)})
                seen_ips.add(ip)
    except Exception:
        pass

    # Cloud NAT IPs
    try:
        for ip in gcp_client.get_nat_ips(project_id):
            if not _is_private_ip(str(ip)) and ip not in seen_ips:
                assets.append({"project": project_id, "name": "Cloud NAT", "type": "NAT", "ip": str(ip)})
                seen_ips.add(ip)
    except Exception:
        pass

    return assets


def _is_valid_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def check_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return port
    except:
        return None

def reverse_dns_lookup(ip):
    return []

def format_firewall_rules(fw_rules):
    """Format firewall rules into a detailed, table-friendly string.

    Shows all rules without truncation: all sources, all allowed/denied entries.
    """
    if not fw_rules:
        return "No internet-facing rules"

    formatted_rules = []
    for rule in fw_rules:  # Show all rules
        parts = []

        # Rule name (avoid excessive truncation; still trim extremely long names)
        name = rule.get('name', 'unnamed')
        if isinstance(name, str) and len(name) > 60:
            name = name[:57] + "..."
        parts.append(f"{name}")

        # Priority and direction
        priority = rule.get('priority', 1000)
        direction = rule.get('direction', 'INGRESS')
        parts.append(f"({direction}:{priority})")

        # Source info
        sources = rule.get('sourceRanges', []) or []
        if '0.0.0.0/0' in sources:
            parts.append("FROM:Internet")
        else:
            parts.append(f"FROM:{','.join(sources)}" if sources else "FROM:Unknown")

        # Allowed ports/protocols (full)
        allowed_items = []
        for allow in rule.get('allowed', []) or []:
            protocol = (allow.get('IPProtocol') or 'tcp').upper()
            ports = allow.get('ports', []) or []
            if not ports:
                allowed_items.append(f"{protocol}:ALL")
            elif protocol.lower() == 'all':
                allowed_items.append("ALL_PROTOCOLS")
            else:
                allowed_items.append(f"{protocol}:{','.join(ports)}")
        if allowed_items:
            parts.append(f"ALLOW:{' '.join(allowed_items)}")

        # Denied rules (full)
        denied_items = []
        for deny in rule.get('denied', []) or []:
            protocol = (deny.get('IPProtocol') or 'tcp').upper()
            ports = deny.get('ports', []) or []
            if not ports:
                denied_items.append(f"{protocol}:ALL")
            else:
                denied_items.append(f"{protocol}:{','.join(ports)}")
        if denied_items:
            parts.append(f"DENY:{' '.join(denied_items)}")

        formatted_rules.append(' '.join(parts))

    return '\n'.join(formatted_rules)

def scan_instance(ip, ports):
    console.log(f"[cyan] Starting port scan[/cyan] ip={ip} total_ports={len(ports)}")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    console.log(f"[green]Completed port scan[/green] ip={ip} open_ports={len(open_ports)}")
    return open_ports

def _parse_port_spec(port_spec):
    """Parse a simple port spec like '1-3000' or comma-separated values into a list of ints."""
    if isinstance(port_spec, list):
        return [int(p) for p in port_spec if isinstance(p, int) or (isinstance(p, str) and p.isdigit())]
    if isinstance(port_spec, int):
        return [port_spec]
    if not isinstance(port_spec, str):
        return TOP_PORTS
    tokens = [t.strip() for t in port_spec.split(',') if t.strip()]
    ports = []
    for token in tokens if tokens else [port_spec.strip()]:
        if '-' in token:
            try:
                start_str, end_str = token.split('-', 1)
                start = max(1, int(start_str))
                end = min(65535, int(end_str))
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            except Exception:
                continue
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    ports.append(p)
            except Exception:
                continue
    return sorted(list(dict.fromkeys(ports))) if ports else TOP_PORTS

def scan_ports_for_target(target, port_spec="0-3000"):
    """Scan TCP ports for a target (IP or hostname) and return list of open ports.

    - target: IP address or DNS name
    - port_spec: e.g., '0-3000', '22,80,443', or list[int]
    """
    try:
        console.log(f"[blue]scan_ports_for_target called[/blue] target={target} port_spec={port_spec}")
        ip = target
        # Resolve if it's not an IP literal
        if isinstance(target, str) and not any(c.isalpha() is False for c in target if c not in '.:'):
            # rudimentary: if it has letters, treat as hostname
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                ip = target
        elif isinstance(target, str) and any(c.isalpha() for c in target):
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                ip = target
        console.log(f"[cyan]Resolved target[/cyan] target={target} ip={ip}")
        ports = _parse_port_spec(port_spec) if port_spec else TOP_PORTS
        console.log(f"[cyan]Parsed ports[/cyan] count={len(ports)} example={ports[:10]}")
        return scan_instance(ip, ports)
    except Exception as e:
        console.log(f"[red]scan_ports_for_target failed[/red] target={target} error={e}")
        return []

def extract_tcp_ports_from_firewall_rules(fw_rules, max_ports=500):
    """Extract a deduplicated, capped list of TCP ports explicitly listed in firewall rules.

    - Expands ranges like "80-90" up to max_ports total across the project
    - Ignores rules that allow all ports (no explicit ports) to avoid 1..65535 scans
    - Only considers TCP protocol
    """
    collected_ports = []
    seen_ports = set()

    for rule in fw_rules:
        for allow in rule.get('allowed', []):
            protocol = (allow.get('IPProtocol') or '').lower()
            if protocol != 'tcp':
                continue
            ports = allow.get('ports', [])
            if not ports:
                # This implies all TCP ports; skip to avoid full-range scans
                console.log("[yellow]Firewall rule allows all TCP ports; skipping full-range expansion[/yellow]")
                continue
            for token in ports:
                if len(collected_ports) >= max_ports:
                    break
                if '-' in token:
                    try:
                        start_str, end_str = token.split('-', 1)
                        start = int(start_str)
                        end = int(end_str)
                        if start > end:
                            start, end = end, start
                        for p in range(start, end + 1):
                            if len(collected_ports) >= max_ports:
                                break
                            if 1 <= p <= 65535 and p not in seen_ports:
                                seen_ports.add(p)
                                collected_ports.append(p)
                    except Exception:
                        continue
                else:
                    try:
                        p = int(token)
                        if 1 <= p <= 65535 and p not in seen_ports:
                            seen_ports.add(p)
                            collected_ports.append(p)
                    except Exception:
                        continue

    if collected_ports and len(collected_ports) == max_ports:
        console.log(f"[yellow]Reached max firewall ports cap ({max_ports}); some ports omitted[/yellow]")
    return sorted(collected_ports)

def main():
    parser = argparse.ArgumentParser(description="GCP Firewall and Port Scanner")
    parser.add_argument("--svc", default=SERVICE_ACCOUNT_FILE, help="Service account JSON file")
    parser.add_argument("--project", help="Single project ID to scan (recommended for testing)")
    parser.add_argument("--projects", help="Comma-separated list of multiple project IDs to scan")
    parser.add_argument("--org-id", help="Filter projects by organization ID")
    parser.add_argument("--list-orgs", action="store_true", help="List available organizations and exit")
    parser.add_argument("--list-projects", type=int, metavar="N", help="List first N project names and exit")
    parser.add_argument("--max-projects", type=int, default=None, help="Limit number of projects to scan (for testing)")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Max parallel workers")
    parser.add_argument("--gke-scan", action="store_true", help="Use GKE/Kubernetes specific ports (includes NodePort range 30000-30100)")
    parser.add_argument("--check-lb", action="store_true", help="Also scan Load Balancer and Static IP addresses")
    parser.add_argument("--all-projects", action="store_true", help="Scan all accessible projects (overrides other filters)")
    parser.add_argument("--firewall-ports", action="store_true", help="Scan only TCP ports explicitly listed in internet-facing firewall rules")
    parser.add_argument("--max-scan-ports", type=int, default=500, help="Cap on number of ports expanded from firewall rules per project")
    args = parser.parse_args()

    try:
        credentials = service_account.Credentials.from_service_account_file(
            args.svc, scopes=SCOPES
        )
    except Exception as e:
        console.log(f"[yellow]Falling back to Application Default Credentials: {e}[/yellow]")
        credentials, _ = google_auth_default(scopes=SCOPES)

    crm_service = get_service("cloudresourcemanager", "v1", credentials)
    compute_service = get_service("compute", "v1", credentials)

    # Ensure GCP helper uses same service account if provided
    if GCP is not None:
        try:
            if args.svc and os.path.exists(args.svc):
                os.environ["SVC_ACCOUNT"] = args.svc
        except Exception:
            pass
        try:
            gcp_client = GCP()
        except Exception:
            gcp_client = None
    else:
        gcp_client = None

    # List organizations if requested
    if args.list_orgs:
        orgs = get_organizations(crm_service)
        if orgs:
            console.print("\n[bold cyan]Organizations Found:[/bold cyan]")
            for org in orgs:
                project_count = len(org.get('projects', []))
                console.print(f"  [green]ID: {org['id']}[/green] - {org['displayName']} ({project_count} projects)")
                if project_count <= 10:  # Show project names if not too many
                    for proj in org.get('projects', [])[:5]:
                        console.print(f"    • {proj}")
                    if project_count > 5:
                        console.print(f"    • ... and {project_count - 5} more")
            
            console.print(f"\n[bold yellow]Usage Examples:[/bold yellow]")
            console.print(f"# Test a single project (recommended):")
            console.print(f"python3 src/modules/firewall_test.py --project YOUR_PROJECT_ID")
            console.print(f"# Test GKE cluster (includes NodePort range):")
            console.print(f"python3 src/modules/firewall_test.py --project YOUR_PROJECT_ID --gke-scan")
            console.print(f"# Include Load Balancers and Static IPs:")
            console.print(f"python3 src/modules/firewall_test.py --project YOUR_PROJECT_ID --check-lb")
            console.print(f"# Test a specific organization:")
            console.print(f"python3 src/modules/firewall_test.py --org-id YOUR_ORG_ID --max-projects 3")
            console.print(f"# Test multiple specific projects:")
            console.print(f"python3 src/modules/firewall_test.py --projects 'project1,project2,project3'")
            console.print(f"# Test all accessible projects:")
            console.print(f"python3 src/modules/firewall_test.py --all-projects")
        else:
            console.print("[yellow]No organizations found. Projects might not be under organizations.[/yellow]")
            console.print("[cyan]Try testing with a single project instead:[/cyan]")
            console.print("python3 src/modules/firewall_test.py --project 'your-project-id'")
            console.print("python3 src/modules/firewall_test.py --project 'your-project-id' --gke-scan  # For GKE clusters")
            console.print("python3 src/modules/firewall_test.py --project 'your-project-id' --check-lb  # Include Load Balancers")
        return

    # List projects if requested
    if args.list_projects:
        projects = list_projects(crm_service)
        count = min(args.list_projects, len(projects))
        console.print(f"\n[bold cyan]First {count} Projects Available:[/bold cyan]")
        for i, proj in enumerate(projects[:count], 1):
            console.print(f"  {i:2d}. {proj}")
        if len(projects) > count:
            console.print(f"     ... and {len(projects) - count} more projects")
        
        console.print(f"\n[bold yellow]Usage Examples:[/bold yellow]")
        console.print(f"# Test a single project:")
        if projects:
            console.print(f"python3 src/modules/firewall_test.py --project '{projects[0]}'")
            console.print(f"# Test GKE/Kubernetes cluster (more ports):")
            console.print(f"python3 src/modules/firewall_test.py --project '{projects[0]}' --gke-scan")
            console.print(f"# Include Load Balancers:")
            console.print(f"python3 src/modules/firewall_test.py --project '{projects[0]}' --check-lb")
        console.print(f"# Test first 3 projects:")
        console.print(f"python3 src/modules/firewall_test.py --max-projects 3")
        console.print(f"# Test multiple specific projects:")
        if projects:
            sample_projects = projects[:2]
            console.print(f"python3 src/modules/firewall_test.py --projects '{','.join(sample_projects)}'")
        console.print(f"# Test all projects (limit to first 3 for testing):")
        console.print(f"python3 src/modules/firewall_test.py --all-projects --max-projects 3")
        return

    # Parse project filter
    project_filter = None
    org_filter = args.org_id
    
    # Single project takes priority (for easy testing)
    if args.all_projects:
        console.log(f"[cyan]Testing all accessible projects[/cyan]")
        org_filter = None
        project_filter = None
    elif args.project:
        project_filter = [args.project.strip()]
        console.log(f"[cyan]Testing single project: {args.project}[/cyan]")
    elif args.projects:
        project_filter = [p.strip() for p in args.projects.split(",")]
        console.log(f"[cyan]Testing multiple projects: {project_filter}[/cyan]")

    # Get projects with filters
    projects = list_projects(crm_service, org_id=org_filter, project_filter=project_filter)
    
    if args.max_projects and len(projects) > args.max_projects:
        projects = projects[:args.max_projects]
        console.log(f"[yellow]Limited to first {args.max_projects} projects for testing[/yellow]")
    
    if org_filter:
        console.log(f"[cyan]Found {len(projects)} projects in organization {org_filter}[/cyan]")
    else:
        if args.all_projects:
            console.log(f"[cyan]Found {len(projects)} projects across all accessible organizations[/cyan]")
        else:
            console.log(f"Found {len(projects)} projects")
        
    if not projects:
        console.log("[red]No projects found with current filters[/red]")
        return

    # Generate unique output filenames for testing
    suffix = ""
    if args.project:
        suffix = f"_{args.project}"
    elif args.org_id:
        suffix = f"_org_{args.org_id}"
    elif args.projects:
        suffix = f"_projects_{len(project_filter)}"
    elif args.all_projects:
        suffix = f"_all"
    elif args.max_projects:
        suffix = f"_limited_{args.max_projects}"
    
    csv_file = f"gcp_open_ports{suffix}.csv"
    json_file = f"gcp_open_ports{suffix}.json"

    table = Table(title="GCP Security Analysis: Instances & Firewall Rules")
    table.add_column("Project", style="cyan")
    table.add_column("Instance/Resource", style="green")
    table.add_column("Type", style="blue")
    table.add_column("IP", style="magenta")
    table.add_column("Firewall Rules", style="yellow", max_width=70)
    table.add_column("Confirmed Open Ports", style="red")

    results = []  # store results for export
    skipped_projects = 0
    scanned_projects = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        proj_task = progress.add_task("Scanning projects...", total=len(projects))

        for project in projects:
            # Skip system projects
            if project.startswith("sys-") or project.startswith("gcp-sa-"):
                console.log(f"[yellow]Skipping system project {project}[/yellow]")
                skipped_projects += 1
                progress.update(proj_task, advance=1)
                continue

            console.log(f"[blue]Scanning project:[/blue] {project}")
            fw_rules = list_firewall_rules(compute_service, project)
            
            # Collect internet-facing firewall rules
            internet_facing_rules = []
            for rule in fw_rules:
                if rule.get("direction") == "INGRESS" and not rule.get("disabled", False):
                    sources = rule.get("sourceRanges", [])
                    if "0.0.0.0/0" in sources or any("0.0.0.0" in src for src in sources):
                        # This rule allows traffic from the internet
                        internet_facing_rules.append(rule)
            
            # Format firewall rules for display
            firewall_display = format_firewall_rules(internet_facing_rules)
            
            instances = list_instances(compute_service, project)

            # Also check load balancers if requested (existing path)
            if args.check_lb:
                lb_instances = list_load_balancer_ips(compute_service, project)
                # Filter only entries with valid public IPs
                filtered_lb = []
                for inst in lb_instances:
                    ip_val = inst.get("ip")
                    if isinstance(ip_val, str) and _is_valid_ip_literal(ip_val) and not _is_private_ip(ip_val):
                        filtered_lb.append(inst)
                instances.extend(filtered_lb)

            # Augment with additional assets from modules.gcp (SQL, VPN, NAT, Forwarding, Static)
            try:
                # Always include LB and Static IPs regardless of --check-lb flag
                extra_assets = list_additional_assets_via_gcp(gcp_client, project, include_lb_and_static=True)
                # Deduplicate by IP against existing instances
                seen_ips = {i.get("ip") for i in instances if isinstance(i.get("ip"), str)}
                for asset in extra_assets:
                    ip_val = asset.get("ip")
                    if not isinstance(ip_val, str) or not _is_valid_ip_literal(ip_val) or _is_private_ip(ip_val):
                        continue
                    if ip_val not in seen_ips:
                        # Map to common structure used below
                        instances.append({
                            "project": asset["project"],
                            "name": asset.get("name") or asset.get("type") or "Resource",
                            "ip": ip_val,
                            "type": asset.get("type") or "Resource",
                        })
                        seen_ips.add(ip_val)
            except Exception:
                pass

            # Show firewall rules even if no instances found
            if not instances and internet_facing_rules:
                # Add a row just for the firewall rules
                row = {
                    "project": project,
                    "instance": "No public instances",
                    "type": "Firewall Only",
                    "ip": "-",
                    "firewall_rules": firewall_display,
                    "confirmed_open_ports": [],
                }
                results.append(row)
                table.add_row(
                    row["project"],
                    row["instance"],
                    row["type"],
                    row["ip"],
                    firewall_display,
                    "-"
                )
                progress.update(proj_task, advance=1)
                continue
            elif not instances:
                progress.update(proj_task, advance=1)
                continue

            scanned_projects += 1

            # Add a subtask for instance scanning
            inst_task = progress.add_task(f"Scanning instances in {project}...", total=len(instances))

            # Choose port list based on scan type
            if args.firewall_ports:
                ports_to_scan = extract_tcp_ports_from_firewall_rules(internet_facing_rules, max_ports=args.max_scan_ports)
                if not ports_to_scan:
                    console.log("[yellow]No explicit TCP ports found in firewall rules; falling back to TOP_PORTS[/yellow]")
                    ports_to_scan = TOP_PORTS
            elif args.gke_scan:
                ports_to_scan = GKE_PORTS
                console.log(f"[yellow]Using GKE-specific port scan ({len(ports_to_scan)} ports including NodePort range)[/yellow]")
            else:
                ports_to_scan = TOP_PORTS
            
            # Parallelize instance scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {executor.submit(scan_instance, inst["ip"], ports_to_scan): inst for inst in instances}
                for future in concurrent.futures.as_completed(futures):
                    inst = futures[future]
                    open_ports = future.result()
                    resource_type = inst.get("type", "VM Instance")  # Default to VM Instance
                    row = {
                        "project": inst["project"],
                        "instance": inst["name"],
                        "type": resource_type,
                        "ip": inst["ip"],
                        "firewall_rules": firewall_display,
                        "confirmed_open_ports": open_ports if open_ports else [],
                    }
                    results.append(row)
                    
                    # Format open ports for display
                    open_ports_display = ",".join(map(str, open_ports)) if open_ports else "-"
                    
                    table.add_row(
                        row["project"],
                        row["instance"],
                        row["type"],
                        row["ip"],
                        firewall_display,
                        open_ports_display
                    )
                    progress.update(inst_task, advance=1)

            progress.update(proj_task, advance=1)

    # Print table
    console.print(table)

    # Save CSV
    with open(csv_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["project", "instance", "type", "ip", "firewall_rules", "confirmed_open_ports"])
        writer.writeheader()
        for r in results:
            writer.writerow({
                "project": r["project"],
                "instance": r["instance"],
                "type": r["type"],
                "ip": r["ip"],
                "firewall_rules": r["firewall_rules"].replace('\n', ' || '),  # Replace newlines for CSV
                "confirmed_open_ports": ",".join(map(str, r["confirmed_open_ports"]))
            })

    # Save JSON
    with open(json_file, "w") as jf:
        json.dump(results, jf, indent=2)
    
    console.log(f"[green]Exported results to {csv_file} and {json_file}[/green]")

if __name__ == "__main__":
    main()


