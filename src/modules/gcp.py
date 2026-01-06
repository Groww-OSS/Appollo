import os
import google.auth
from googleapiclient.discovery import build
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import ipaddress
from datetime import datetime
from system.db import MongoDB


"""
This module provides functionality to interact with Google Cloud Platform (GCP) services, including listing projects, zones, and fetching various records such as compute instances, forwarding rules, compute addresses, SQL instances, VPN tunnels, and DNS records.

Classes:
    GCP: A class to encapsulate methods for interacting with GCP services.

Functions:
    list_projects(self): Lists all GCP projects.
    list_zones(self, project_id): Lists all DNS managed zones for a given project.
    extract_compute_instance_fields(self, entry): Extracts relevant fields from a compute instance entry.
    extract_forwarding_rule_fields(self, entry): Extracts relevant fields from a forwarding rule entry.
    extract_compute_address_fields(self, entry): Extracts relevant fields from a compute address entry.
    extract_sql_instance_fields(self, entry): Extracts relevant fields from a SQL instance entry.
    extract_vpn_tunnel_fields(self, entry): Extracts relevant fields from a VPN tunnel entry.
    run_gcloud_command(self, command, project_id, extract_fields=None): Runs a gcloud command and processes the output.
    fetch_ip_records(self, project_id): Fetches IP-related records for a given project.
    fetch_dns_records(self, project_id, zone): Fetches DNS records for a given project and zone.
    fetch_project_dns_records(self, project_id): Fetches DNS records for all zones in a given project.
    run(self): Main method to fetch and store IP and DNS records for all projects in MongoDB.

Exceptions:
    subprocess.CalledProcessError: Raised when there is an error during the execution of a subprocess command.
    json.decoder.JSONDecodeError: Raised when there is an error decoding JSON output.
"""

class GCP:
    def __init__(self):
        self.credentials = None
        self.crm = None
        self.compute = None
        self.dns = None
        self.sql = None
        self._setup_credentials()

    def _setup_credentials(self):
        """Setup GCP credentials"""
        try:
            creds_file = os.getenv('SVC_ACCOUNT', '/etc/config/creds.json')
            if not os.path.exists(creds_file):
                print(f"[bold red]Error: GCP service account file not found: {creds_file}[/bold red]")
                return False
            
            self.credentials, _ = google.auth.load_credentials_from_file(creds_file)
            self.crm = build('cloudresourcemanager', 'v1', credentials=self.credentials, cache_discovery=False)
            self.compute = build('compute', 'v1', credentials=self.credentials, cache_discovery=False)
            self.dns = build('dns', 'v1', credentials=self.credentials, cache_discovery=False)
            self.sql = build('sqladmin', 'v1', credentials=self.credentials, cache_discovery=False)
            return True
        except Exception as e:
            print(f"[bold red]Error setting up GCP credentials: {str(e)}[/bold red]")
            return False

    def list_projects(self):
        """List all active GCP projects (excluding sys-* projects)"""
        projects = []
        req = self.crm.projects().list()
        while req is not None:
            res = req.execute()
            for proj in res.get('projects', []):
                pid = proj['projectId']
                if proj['lifecycleState'] == 'ACTIVE' and not pid.startswith('sys-'):
                    projects.append(pid)
            req = self.crm.projects().list_next(previous_request=req, previous_response=res)
        return projects

    def get_project_ips(self, project_id):
        """Get all public IPs for a GCP project (VMs, load balancers, static IPs, VPN tunnels, etc.)"""
        compute = build('compute', 'v1', credentials=self.credentials, cache_discovery=False)
        ip_details = {
            'static_ip': set(),
            'vm_external': set(),
            'load_balancer': set(),
            'vpn_gateway': set(),
            'cloud_sql': set(),
            'cloud_nat': set(),
            'other_network': set()
        }
        console = Console()

        # Static IPs
        console.print(f"[dim]      📍 Fetching static IPs for {project_id}...[/dim]")
        req = compute.addresses().aggregatedList(project=project_id)
        static_count = 0
        while req is not None:
            res = req.execute()
            for _, scope in res.get('items', {}).items():
                for addr in scope.get('addresses', []):
                    if 'address' in addr:
                        ip_details['static_ip'].add(addr['address'])
                        static_count += 1
            req = compute.addresses().aggregatedList_next(previous_request=req, previous_response=res)
        console.print(f"[dim]      ✓ Found {static_count} static IPs[/dim]")

        # VM Instance IPs
        console.print(f"[dim]      🖥️  Fetching VM instance IPs for {project_id}...[/dim]")
        zones_req = compute.zones().list(project=project_id)
        zones = zones_req.execute().get('items', [])
        vm_count = 0
        for zone in zones:
            zone_name = zone['name']
            try:
                vms = compute.instances().list(project=project_id, zone=zone_name).execute()
                for vm in vms.get('items', []):
                    for iface in vm.get('networkInterfaces', []):
                        for ac in iface.get('accessConfigs', []):
                            if 'natIP' in ac:
                                ip_details['vm_external'].add(ac['natIP'])
                                vm_count += 1
            except Exception:
                continue  # skip zones with no instances
        console.print(f"[dim]      ✓ Found {vm_count} VM instance IPs[/dim]")
        
        # Load Balancer IPs (Forwarding Rules)
        console.print(f"[dim]      ⚖️  Fetching load balancer IPs for {project_id}...[/dim]")
        fr_req = compute.forwardingRules().aggregatedList(project=project_id)
        lb_count = 0
        while fr_req is not None:
            fr_res = fr_req.execute()
            for _, scope in fr_res.get('items', {}).items():
                for fr in scope.get('forwardingRules', []):
                    if 'IPAddress' in fr:
                        ip_details['load_balancer'].add(fr['IPAddress'])
                        lb_count += 1
            fr_req = compute.forwardingRules().aggregatedList_next(previous_request=fr_req, previous_response=fr_res)
        console.print(f"[dim]      ✓ Found {lb_count} load balancer IPs[/dim]")
        
        # VPN Gateway IPs
        console.print(f"[dim]      🔒 Fetching VPN gateway IPs for {project_id}...[/dim]")
        try:
            vpn_req = compute.vpnGateways().aggregatedList(project=project_id)
            vpn_count = 0
            while vpn_req is not None:
                vpn_res = vpn_req.execute()
                for _, scope in vpn_res.get('items', {}).items():
                    for vpn in scope.get('vpnGateways', []):
                        if 'vpnInterfaces' in vpn:
                            for vpn_iface in vpn['vpnInterfaces']:
                                if 'ipAddress' in vpn_iface:
                                    ip_details['vpn_gateway'].add(vpn_iface['ipAddress'])
                                    vpn_count += 1
                vpn_req = compute.vpnGateways().aggregatedList_next(previous_request=vpn_req, previous_response=vpn_res)
            console.print(f"[dim]      ✓ Found {vpn_count} VPN gateway IPs[/dim]")
        except Exception as e:
            if "accessNotConfigured" not in str(e) and "API has not been used" not in str(e):
                console.print(f"[yellow]    ⚠️  {project_id}: VPN Gateway IPs error: {str(e)[:100]}...[/yellow]")
        
        # Cloud SQL Instance IPs
        console.print(f"[dim]      🗄️  Fetching Cloud SQL IPs for {project_id}...[/dim]")
        try:
            sql_service = build('sqladmin', 'v1', credentials=self.credentials, cache_discovery=False)
            sql_req = sql_service.instances().list(project=project_id)
            sql_res = sql_req.execute()
            sql_count = 0
            for instance in sql_res.get('items', []):
                if 'ipAddresses' in instance:
                    for ip_info in instance['ipAddresses']:
                        if 'ipAddress' in ip_info:
                            ip_details['cloud_sql'].add(ip_info['ipAddress'])
                            sql_count += 1
            console.print(f"[dim]      ✓ Found {sql_count} Cloud SQL IPs[/dim]")
        except Exception as e:
            if "accessNotConfigured" not in str(e) and "API has not been used" not in str(e):
                console.print(f"[yellow]    ⚠️  {project_id}: Cloud SQL IPs error: {str(e)[:100]}...[/yellow]")

        # Cloud NAT Gateway IPs
        console.print(f"[dim]      🌐 Fetching Cloud NAT IPs for {project_id}...[/dim]")
        try:
            nat_req = compute.routers().aggregatedList(project=project_id)
            nat_count = 0
            while nat_req is not None:
                nat_res = nat_req.execute()
                for _, scope in nat_res.get('items', {}).items():
                    for router in scope.get('routers', []):
                        if 'nats' in router:
                            for nat in router['nats']:
                                if 'natIps' in nat:
                                    for nat_ip in nat['natIps']:
                                        ip_details['cloud_nat'].add(nat_ip)
                                        nat_count += 1
                nat_req = compute.routers().aggregatedList_next(previous_request=nat_req, previous_response=nat_res)
            console.print(f"[dim]      ✓ Found {nat_count} Cloud NAT IPs[/dim]")
        except Exception as e:
            if "accessNotConfigured" not in str(e) and "API has not been used" not in str(e):
                console.print(f"[yellow]    ⚠️  {project_id}: Cloud NAT IPs error: {str(e)[:100]}...[/yellow]")
        
        # External IPs from Network Interfaces (for other compute resources)
        console.print(f"[dim]      🔗 Fetching other network interface IPs for {project_id}...[/dim]")
        try:
            other_count = 0
            for zone in zones:
                zone_name = zone['name']
                try:
                    # Check for managed instance groups
                    mig_req = compute.instanceGroups().list(project=project_id, zone=zone_name)
                    mig_res = mig_req.execute()
                    for mig in mig_res.get('items', []):
                        # Get instances in the group
                        instances_req = compute.instanceGroups().listInstances(
                            project=project_id, zone=zone_name, instanceGroup=mig['name']
                        )
                        instances_res = instances_req.execute()
                        for instance in instances_res.get('items', []):
                            if 'instance' in instance:
                                instance_name = instance['instance'].split('/')[-1]
                                # Get the actual instance details
                                try:
                                    vm_detail = compute.instances().get(
                                        project=project_id, zone=zone_name, instance=instance_name
                                    ).execute()
                                    for iface in vm_detail.get('networkInterfaces', []):
                                        for ac in iface.get('accessConfigs', []):
                                            if 'natIP' in ac:
                                                ip_details['other_network'].add(ac['natIP'])
                                                other_count += 1
                                except Exception:
                                    continue
                except Exception:
                    continue
            console.print(f"[dim]      ✓ Found {other_count} other network interface IPs[/dim]")
        except Exception as e:
            if "accessNotConfigured" not in str(e) and "API has not been used" not in str(e):
                console.print(f"[yellow]    ⚠️  {project_id}: Other network IPs error: {str(e)[:100]}...[/yellow]")

        return ip_details

    def is_public_ip(self, ip):
        """Check if an IP address is public/global"""
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False  # Not a valid IP

    def get_project_ips_parallel(self, project_id):
        """Fetch all public IPs for a GCP project with resource type tracking"""
        return self.get_project_ips(project_id)

    def fetch_project_dns_records(self, project_id):
        """Fetch DNS records for a GCP project"""
        try:
            dns_service = build('dns', 'v1', credentials=self.credentials, cache_discovery=False)
            managed_zones = dns_service.managedZones().list(project=project_id).execute()
            records = []
            
            for zone in managed_zones.get('managedZones', []):
                zone_name = zone['name']
                dns_name = zone['dnsName']
                
                # Get all record sets for this zone
                record_sets = dns_service.resourceRecordSets().list(
                    project=project_id, managedZone=zone_name
                ).execute()
                
                for record_set in record_sets.get('rrsets', []):
                    record_type = record_set.get('type', '')
                    name = record_set.get('name', '')
                    ttl = record_set.get('ttl', 0)
                    rrdatas = record_set.get('rrdatas', [])
                    
                    for rrdata in rrdatas:
                        records.append({
                            'name': name,
                            'type': record_type,
                            'ttl': ttl,
                            'data': rrdata,
                            'zone': dns_name
                        })
            
            return records
        except Exception as e:
            if "accessNotConfigured" not in str(e) and "API has not been used" not in str(e):
                console = Console()
                console.print(f"[yellow]    ⚠️  {project_id}: DNS records error: {str(e)[:100]}...[/yellow]")
            return []

    def run(self, max_workers=None):
        """Run GCP inventory scan with resource type tracking"""
        if max_workers is None:
            max_workers = 300
        
        console = Console()
        console.print("[bold blue]🔍 Starting GCP inventory scan with resource type tracking...[/bold blue]")
        
        # Get all projects
        projects = self.list_projects()
        console.print(f"[bold blue]📋 Found {len(projects)} active GCP projects[/bold blue]")
        
        if not projects:
            console.print("[bold yellow]⚠️  No active projects found[/bold yellow]")
            return
        
        # Fetch IPs and DNS records in parallel
        all_project_ips = {}
        all_project_dns = {}
        projects_without_ips = 0
        
        def fetch_ips(project_id):
            try:
                return project_id, self.get_project_ips_parallel(project_id)
            except Exception as e:
                if "accessNotConfigured" not in str(e) and "API has not been used" not in str(e):
                    console.print(f"[yellow]    ⚠️  {project_id}: IPs error: {str(e)[:100]}...[/yellow]")
                return project_id, None
        
        def fetch_dns(project_id):
            try:
                return project_id, self.fetch_project_dns_records(project_id)
            except Exception as e:
                if "accessNotConfigured" not in str(e) and "API has not been used" not in str(e):
                    console.print(f"[yellow]    ⚠️  {project_id}: DNS error: {str(e)[:100]}...[/yellow]")
                return project_id, []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Fetching GCP resources...", total=len(projects))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit IP fetching tasks
                ip_futures = {executor.submit(fetch_ips, project_id): project_id for project_id in projects}
                
                # Submit DNS fetching tasks
                dns_futures = {executor.submit(fetch_dns, project_id): project_id for project_id in projects}
                
                # Collect IP results
                for future in as_completed(ip_futures):
                    project_id, ips = future.result()
                    if ips:
                        all_project_ips[project_id] = ips
                    else:
                        projects_without_ips += 1
                    progress.advance(task)
                
                # Collect DNS results
                for future in as_completed(dns_futures):
                    project_id, dns_records = future.result()
                    if dns_records:
                        all_project_dns[project_id] = dns_records
                    progress.advance(task)
        
        # Store IPs in MongoDB
        console.print("[bold blue]💾 Storing IPs in MongoDB...[/bold blue]")
        mongo = MongoDB()
        ip_collection = mongo.set_collection("IP Records")
        
        new_ip_records = []
        for project_id, ip_details in all_project_ips.items():
            if ip_details:
                # Convert sets to lists for JSON serialization and calculate totals
                resource_types = {}
                total_count = 0
                
                for resource_type, ip_set in ip_details.items():
                    if ip_set:  # Only include non-empty sets
                        ip_list = list(ip_set)
                        resource_types[resource_type] = ip_list
                        total_count += len(ip_list)
                
                if total_count > 0:  # Only create record if there are IPs
                    record_data = {
                        'project_id': project_id,
                        'source': 'GCP',
                        'resource_types': resource_types,
                        'total_count': total_count,
                        'timestamp': datetime.now()
                    }
                    new_ip_records.append(record_data)
        
        if new_ip_records:
            try:
                # Use upsert to prevent duplicates - update existing or insert new
                stored_count = 0
                skipped_count = 0
                
                for record in new_ip_records:
                    try:
                        # Use project_id and source as unique identifier
                        query = {"project_id": record["project_id"], "source": "GCP"}
                        update = {"$set": record}
                        result = ip_collection.update_one(query, update, upsert=True)
                        
                        if result.upserted_id:
                            stored_count += 1
                        elif result.modified_count > 0:
                            stored_count += 1  # Count updates as stored
                        else:
                            skipped_count += 1
                            
                    except Exception as e:
                        print(f"[bold yellow][!] Error upserting GCP IP record for {record['project_id']}: {e}[/bold yellow]")
                        skipped_count += 1
                
                if stored_count > 0:
                    print(f"[bold blue][+] GCP IP Records: {stored_count} stored/updated, {skipped_count} skipped[/bold blue]")
                else:
                    print("[bold yellow][+] All GCP IP records already exist[/bold yellow]")
                    
            except Exception as e:
                print(f"[bold red]❌ Error storing GCP IP records: {str(e)}[/bold red]")
        else:
            print("[bold yellow][+] No GCP IP records found to store[/bold yellow]")
        
        # Store DNS records in MongoDB (both collections for consistency)
        console.print("[bold blue]💾 Storing DNS records in MongoDB...[/bold blue]")
        dns_collection = mongo.set_collection("DNS")
        
        new_dns_records = []
        for project_id, dns_records in all_project_dns.items():
            if dns_records:
                record_data = {
                    'project_id': project_id,
                    'source': 'GCP',
                    'records': dns_records,
                    'count': len(dns_records),
                    'timestamp': datetime.now()
                }
                new_dns_records.append(record_data)
        
        if new_dns_records:
            try:
                # Use upsert to prevent duplicates - update existing or insert new
                stored_count = 0
                skipped_count = 0
                
                for record in new_dns_records:
                    try:
                        # Use project_id and source as unique identifier
                        query = {"project_id": record["project_id"], "source": "GCP"}
                        update = {"$set": record}
                        result = dns_collection.update_one(query, update, upsert=True)
                        
                        if result.upserted_id:
                            stored_count += 1
                        elif result.modified_count > 0:
                            stored_count += 1  # Count updates as stored
                        else:
                            skipped_count += 1
                            
                    except Exception as e:
                        print(f"[bold yellow][!] Error upserting GCP DNS record for {record['project_id']}: {e}[/bold yellow]")
                        skipped_count += 1
                
                if stored_count > 0:
                    print(f"[bold blue][+] GCP DNS Records: {stored_count} stored/updated, {skipped_count} skipped[/bold blue]")
                else:
                    print("[bold yellow][+] All GCP DNS records already exist[/bold yellow]")
                    
            except Exception as e:
                print(f"[bold red]❌ Error storing GCP DNS records: {str(e)}[/bold red]")
        else:
            print("[bold yellow][+] No GCP DNS records found to store[/bold yellow]")
        
        # Store individual DNS records in DNS Records collection
        console.print("[bold blue]💾 Storing individual DNS records in DNS Records collection...[/bold blue]")
        dns_records_collection = mongo.set_collection("DNS Records")
        
        individual_dns_records = []
        for project_id, dns_records in all_project_dns.items():
            if dns_records:
                for dns_record in dns_records:
                    # Convert GCP DNS format to consistent format
                    name = dns_record.get('name', '')
                    record_type = dns_record.get('type', '')
                    ttl = dns_record.get('ttl', 300)
                    data = dns_record.get('data', '')
                    zone = dns_record.get('zone', '')
                    
                    # Create individual record
                    individual_record = {
                        'zone_name': project_id,  # Use project_id as zone_name
                        'name': name,
                        'type': record_type,
                        'content': data,
                        'proxied': '',  # GCP DNS records are not proxied
                        'resource_type': 'gcp_dns',
                        'source': 'GCP',
                        'ttl': ttl,
                        'zone': zone,
                        'timestamp': datetime.now()
                    }
                    
                    # Calculate hash for deduplication
                    from system.utils import calculate_hash, check_if_hash_exists, add_hash_to_db
                    record_hash = calculate_hash(individual_record)
                    individual_record['hash'] = record_hash
                    
                    # Check if this record already exists
                    if not check_if_hash_exists(record_hash):
                        individual_dns_records.append(individual_record)
                        add_hash_to_db(record_hash)
        
        if individual_dns_records:
            try:
                # Use upsert with hash as unique identifier to prevent duplicates
                stored_count = 0
                skipped_count = 0
                
                for record in individual_dns_records:
                    try:
                        # Use hash as unique identifier for deduplication
                        query = {"hash": record["hash"]}
                        update = {"$set": record}
                        result = dns_records_collection.update_one(query, update, upsert=True)
                        
                        if result.upserted_id:
                            stored_count += 1
                        elif result.modified_count > 0:
                            stored_count += 1  # Count updates as stored
                        else:
                            skipped_count += 1
                            
                    except Exception as e:
                        print(f"[bold yellow][!] Error upserting individual DNS record: {e}[/bold yellow]")
                        skipped_count += 1
                
                if stored_count > 0:
                    print(f"[bold blue][+] GCP Individual DNS Records: {stored_count} stored/updated, {skipped_count} duplicates skipped[/bold blue]")
                else:
                    print("[bold yellow][+] All GCP individual DNS records already exist[/bold yellow]")
                    
            except Exception as e:
                print(f"[bold red]❌ Error storing individual DNS records: {str(e)}[/bold red]")
        else:
            print("[bold yellow][+] No new individual DNS records found to store[/bold yellow]")
        
        # Display summary
        console.print(f"[bold green]✅ GCP inventory scan completed![/bold green]")
        console.print(f"[dim] - Projects with IPs: {len(all_project_ips)}[/dim]")
        console.print(f"[dim] - Projects with DNS: {len(all_project_dns)}[/dim]")
        console.print(f"[dim] - Projects without IPs: {projects_without_ips} (likely API access issues)[/dim]")
        
        # Show resource type breakdown
        if all_project_ips:
            console.print("\n[bold blue]📊 Resource Type Summary:[/bold blue]")
            resource_totals = {
                'static_ip': 0,
                'vm_external': 0,
                'load_balancer': 0,
                'vpn_gateway': 0,
                'cloud_sql': 0,
                'cloud_nat': 0,
                'other_network': 0
            }
            
            for project_id, ip_details in all_project_ips.items():
                for resource_type, ip_set in ip_details.items():
                    resource_totals[resource_type] += len(ip_set)
            
            for resource_type, count in resource_totals.items():
                if count > 0:
                    console.print(f"[dim]  {resource_type}: {count} IPs[/dim]")
        
        return all_project_ips, all_project_dns
