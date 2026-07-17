import os
import json
import socket
import subprocess
import google.auth
import logging
import threading
from googleapiclient.discovery import build
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich import print
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import ipaddress
from datetime import datetime
from system.db import MongoDB
from system.utils import calculate_hash, check_if_hash_exists, add_hash_to_db
import dotenv
import argparse

# Allowlist of project-ID prefixes that belong to the org.
# Prevents foreign GCP projects (e.g. those visible via broad org-level IAM)
# from being scanned as if they belong to the org.
# Set GCP_ORG_PROJECT_PREFIXES env var as a comma-separated list to override.
def _load_org_prefixes() -> tuple:
    env_val = os.environ.get("GCP_ORG_PROJECT_PREFIXES", "").strip()
    if env_val:
        return tuple(p.strip() for p in env_val.split(",") if p.strip())
    return ()

_ORG_PROJECT_PREFIXES = _load_org_prefixes()

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
    SOURCE = "GCP"

    def __init__(self):
        self.credentials = None
        self._thread_local = threading.local()
        self.logger = logging.getLogger("gcp_collector")
        self._setup_credentials()

    def _get_client(self, service_name, version):
        """Get or create a thread-safe client for the current thread."""
        attr_name = f"client_{service_name}"
        if not hasattr(self._thread_local, attr_name):
            client = build(service_name, version, credentials=self.credentials, cache_discovery=False)
            setattr(self._thread_local, attr_name, client)
        return getattr(self._thread_local, attr_name)

    def _setup_credentials(self):
        """Setup GCP credentials"""
        try:
            creds_file = os.getenv('SVC_ACCOUNT', '/etc/config/creds.json')
            if not os.path.exists(creds_file):
                print(f"[bold red]CRITICAL: GCP service account file not found: {creds_file}[/bold red]")
                return False
            
            self.credentials, _ = google.auth.load_credentials_from_file(creds_file)
            return True
        except Exception as e:
            print(f"[bold red]Error setting up GCP credentials: {str(e)}[/bold red]")
            return False

    def list_projects(self):
        """List all active GCP projects across the entire org hierarchy (excluding sys-* projects).
        Uses cloudresourcemanager v3 projects().search() which traverses org > folder > project
        hierarchy, unlike v1 projects().list() which only returns projects with direct SA grants.
        """
        projects = []
        try:
            crm = build('cloudresourcemanager', 'v3', credentials=self.credentials, cache_discovery=False)
            req = crm.projects().search()
            while req is not None:
                res = req.execute()
                for proj in res.get('projects', []):
                    pid = proj.get('projectId', '')
                    state = proj.get('state', '')
                    if state == 'ACTIVE' and pid and not pid.startswith('sys-'):
                        projects.append(pid)
                req = crm.projects().search_next(previous_request=req, previous_response=res)
            return projects
        except Exception as e:
            print(f"[bold red][-] Error listing projects: {e}[/bold red]")
            return []

    def _handle_api_error(self, project_id, service_name, error):
        """Helper to handle and filter common GCP API errors."""
        msg = str(error)
        _SILENT = (
            "accessNotConfigured", "API has not been used",
            "has not been used in project", "SERVICE_DISABLED",
            "is disabled", "not enabled", "RESOURCE_PROJECT_INVALID",
            "Permission denied on 'locations/-'",  # Dataproc/regional APIs not accessible via wildcard
        )
        if not any(p in msg for p in _SILENT):
            print(f"[yellow]    ⚠️  [{project_id}] {service_name} error: {msg[:80]}...[/yellow]")

    def get_project_ips(self, project_id):
        """Get all public IPs for a GCP project (VMs, load balancers, static IPs, VPN tunnels, etc.)"""
        compute = self._get_client('compute', 'v1')
        ip_details = {
            'static_ip': set(),
            'vm_external': set(),
            'load_balancer': set(),
            'vpn_gateway': set(),
            'cloud_sql': set(),
            'cloud_nat': set(),
            'cloud_run': set(),
            'gke_cluster': set(),
            'gke_nodes': set(),
            'app_engine': set(),
            'memorystore': set(),
            'filestore': set(),
            'vertex_ai': set(),
            'api_gateway': set(),
            'dataflow': set(),
            'dataproc': set(),
            'data_fusion': set(),
            'cloud_functions': set(),
            'other_network': set()
        }

        # 1. Static Addresses
        try:
            req = compute.addresses().aggregatedList(project=project_id)
            while req is not None:
                res = req.execute()
                for _, scope in res.get('items', {}).items():
                    for addr in scope.get('addresses', []):
                        if 'address' in addr:
                            ip_details['static_ip'].add(addr['address'])
                req = compute.addresses().aggregatedList_next(previous_request=req, previous_response=res)
            if ip_details['static_ip']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['static_ip'])} Static IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Static IPs", e)

        # 2. VM Instances 
        try:
            req = compute.instances().aggregatedList(project=project_id)
            while req is not None:
                res = req.execute()
                for _, scope in res.get('items', {}).items():
                    for vm in scope.get('instances', []):
                        for iface in vm.get('networkInterfaces', []):
                            for ac in iface.get('accessConfigs', []):
                                if 'natIP' in ac:
                                    ip_details['vm_external'].add(ac['natIP'])
                req = compute.instances().aggregatedList_next(previous_request=req, previous_response=res)
            if ip_details['vm_external']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['vm_external'])} VM IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "VM Instances", e)
        
        # 3. Forwarding Rules / Load Balancers  
        try:
            fr_req = compute.forwardingRules().aggregatedList(project=project_id)
            while fr_req is not None:
                fr_res = fr_req.execute()
                for _, scope in fr_res.get('items', {}).items():
                    for fr in scope.get('forwardingRules', []):
                        if 'IPAddress' in fr:
                            ip_details['load_balancer'].add(fr['IPAddress'])
                fr_req = compute.forwardingRules().aggregatedList_next(previous_request=fr_req, previous_response=fr_res)
            if ip_details['load_balancer']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['load_balancer'])} Load Balancer IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Load Balancer", e)
        
        # 4. VPN Gateway IPs
        try:
            vpn_req = compute.vpnGateways().aggregatedList(project=project_id)
            while vpn_req is not None:
                vpn_res = vpn_req.execute()
                for _, scope in vpn_res.get('items', {}).items():
                    for vpn in scope.get('vpnGateways', []):
                        if 'vpnInterfaces' in vpn:
                            for vpn_iface in vpn['vpnInterfaces']:
                                if 'ipAddress' in vpn_iface:
                                    ip_details['vpn_gateway'].add(vpn_iface['ipAddress'])
                vpn_req = compute.vpnGateways().aggregatedList_next(previous_request=vpn_req, previous_response=vpn_res)
            if ip_details['vpn_gateway']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['vpn_gateway'])} VPN Gateway IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "VPN Gateway", e)
        
        # 5. Cloud SQL Instance IPs
        try:
            sql_service = self._get_client('sqladmin', 'v1')
            sql_req = sql_service.instances().list(project=project_id)
            sql_res = sql_req.execute()
            for instance in sql_res.get('items', []):
                if 'ipAddresses' in instance:
                    for ip_info in instance['ipAddresses']:
                        if 'ipAddress' in ip_info:
                            ip_details['cloud_sql'].add(ip_info['ipAddress'])
            if ip_details['cloud_sql']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['cloud_sql'])} Cloud SQL IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Cloud SQL", e)

        # 6. Cloud NAT Gateway IPs
        try:
            nat_req = compute.routers().aggregatedList(project=project_id)
            while nat_req is not None:
                nat_res = nat_req.execute()
                for _, scope in nat_res.get('items', {}).items():
                    for router in scope.get('routers', []):
                        if 'nats' in router:
                            for nat in router['nats']:
                                if 'natIps' in nat:
                                    for nat_ip in nat['natIps']:
                                        ip_details['cloud_nat'].add(nat_ip)
                nat_req = compute.routers().aggregatedList_next(previous_request=nat_req, previous_response=nat_res)
            if ip_details['cloud_nat']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['cloud_nat'])} Cloud NAT IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Cloud NAT", e)

        # 7. Cloud Run Services
        try:
            result = subprocess.run(
                ["gcloud", "run", "services", "list", f"--project={project_id}",
                 "--platform=managed", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                services = json.loads(result.stdout) if result.stdout.strip() else []
                for svc in services:
                    status = svc.get("status") or {}
                    url = status.get("url", "")
                    if not url:
                        continue
                    meta = svc.get("metadata") or {}
                    annotations = meta.get("annotations") or {}
                    ingress = annotations.get("run.googleapis.com/ingress", "all")
                    if ingress == "internal":
                        continue
                    try:
                        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
                        ips = socket.gethostbyname_ex(hostname)[2]
                        for ip in ips:
                            if self.is_public_ip(ip):
                                ip_details['cloud_run'].add(ip)
                    except Exception:
                        pass
                if ip_details['cloud_run']:
                    print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['cloud_run'])} Cloud Run IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Cloud Run", e)

        # 8. GKE Clusters
        try:
            container = self._get_client('container', 'v1')
            clusters_req = container.projects().locations().clusters().list(
                parent=f"projects/{project_id}/locations/-"
            )
            clusters_res = clusters_req.execute()
            for cluster in clusters_res.get('clusters', []):
                endpoint = cluster.get('endpoint', '')
                if endpoint and self.is_public_ip(endpoint):
                    ip_details['gke_cluster'].add(endpoint)
                private_cluster = cluster.get('privateClusterConfig', {})
                public_endpoint = private_cluster.get('publicEndpoint', '')
                if public_endpoint and self.is_public_ip(public_endpoint):
                    ip_details['gke_cluster'].add(public_endpoint)
            if ip_details['gke_cluster']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['gke_cluster'])} GKE cluster IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "GKE Clusters", e)

        # 9. GKE Node Pool IPs (from VMs that are part of GKE clusters)
        try:
            compute = self._get_client('compute', 'v1')
            req = compute.instances().aggregatedList(project=project_id)
            while req is not None:
                res = req.execute()
                for _, scope in res.get('items', {}).items():
                    for vm in scope.get('instances', []):
                        labels = vm.get('labels', {})
                        if 'goog-gke-node' in labels or any(k.startswith('goog-gke') for k in labels):
                            for iface in vm.get('networkInterfaces', []):
                                for ac in iface.get('accessConfigs', []):
                                    if 'natIP' in ac:
                                        ip_details['gke_nodes'].add(ac['natIP'])
                req = compute.instances().aggregatedList_next(previous_request=req, previous_response=res)
            if ip_details['gke_nodes']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['gke_nodes'])} GKE node IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "GKE Nodes", e)

        # 10. App Engine Services
        try:
            if not project_id.startswith(_ORG_PROJECT_PREFIXES):
                print(f"[dim]    - [{project_id}] Skipping App Engine (not an org project)[/dim]")
            else:
                result = subprocess.run(
                    ["gcloud", "app", "services", "list", f"--project={project_id}",
                     "--format=json"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout.strip():
                    services = json.loads(result.stdout) if result.stdout.strip() else []
                    for svc in services:
                        name = svc.get("id", "")
                        if not name:
                            continue
                        try:
                            hostname = f"{name}-dot-{project_id}.appspot.com"
                            ips = socket.gethostbyname_ex(hostname)[2]
                            for ip in ips:
                                if self.is_public_ip(ip):
                                    ip_details['app_engine'].add(ip)
                        except Exception:
                            pass
                    if ip_details['app_engine']:
                        print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['app_engine'])} App Engine IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "App Engine", e)

        # 11. Memorystore (Redis/Memcached)
        try:


            result = subprocess.run(
                ["gcloud", "redis", "instances", "list", f"--project={project_id}",
                 "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():

                instances = json.loads(result.stdout) if result.stdout.strip() else []
                for inst in instances:
                    host = inst.get("host", "")
                    if host and inst.get("connectMode", "") == "PUBLIC_ENDPOINT":
                        try:
                            ips = socket.gethostbyname_ex(host)[2]
                            for ip in ips:
                                if self.is_public_ip(ip):
                                    ip_details['memorystore'].add(ip)
                        except Exception:
                            pass
            result = subprocess.run(
                ["gcloud", "memcache", "instances", "list", f"--project={project_id}",
                 "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                instances = json.loads(result.stdout) if result.stdout.strip() else []
                for inst in instances:
                    dns = inst.get("memcacheFullQualifiedDomainName", "")
                    if dns:
                        try:
                            ips = socket.gethostbyname_ex(dns)[2]
                            for ip in ips:
                                if self.is_public_ip(ip):
                                    ip_details['memorystore'].add(ip)
                        except Exception:
                            pass
            if ip_details['memorystore']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['memorystore'])} Memorystore IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Memorystore", e)

        # 12. Filestore
        try:
            result = subprocess.run(
                ["gcloud", "filestore", "instances", "list", f"--project={project_id}",
                 "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                instances = json.loads(result.stdout) if result.stdout.strip() else []
                for inst in instances:
                    networks = inst.get("networks", [])
                    for net in networks:
                        for ip in net.get("ipAddresses", []):
                            if self.is_public_ip(ip):
                                ip_details['filestore'].add(ip)
            if ip_details['filestore']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['filestore'])} Filestore IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Filestore", e)

        # 13. Vertex AI Endpoints
        try:


            result = subprocess.run(
                ["gcloud", "ai", "endpoints", "list", f"--project={project_id}",
                 "--region=-", "--format=json"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                endpoints = json.loads(result.stdout) if result.stdout.strip() else []
                for ep in endpoints:
                    name = ep.get("name", "")
                    if not name:
                        continue
                    result2 = subprocess.run(
                        ["gcloud", "ai", "endpoints", "describe", name.split("/")[-1],
                         f"--project={project_id}", f"--region={name.split('/')[3] if len(name.split('/')) > 3 else 'us-central1'}",
                         "--format=json"],
                        capture_output=True, text=True, timeout=30
                    )
                    if result2.returncode == 0 and result2.stdout.strip():
                        ep_detail = json.loads(result2.stdout)
                        network = ep_detail.get("network", "")
                        if not network:
                            try:
                                hostname = f"{name.split('/')[-1]}.aiplatform.googleapis.com"
                                ips = socket.gethostbyname_ex(hostname)[2]
                                for ip in ips:
                                    if self.is_public_ip(ip):
                                        ip_details['vertex_ai'].add(ip)
                            except Exception:
                                pass
            if ip_details['vertex_ai']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['vertex_ai'])} Vertex AI IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Vertex AI", e)

        # 14. API Gateway
        try:


            result = subprocess.run(
                ["gcloud", "api-gateway", "gateways", "list", f"--project={project_id}",
                 "--location=-", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                gateways = json.loads(result.stdout) if result.stdout.strip() else []
                for gw in gateways:
                    gateway_uri = gw.get("gatewayConfig", {}).get("gatewayUri", "")
                    if gateway_uri:
                        try:
                            hostname = gateway_uri.replace("https://", "").split("/")[0]
                            ips = socket.gethostbyname_ex(hostname)[2]
                            for ip in ips:
                                if self.is_public_ip(ip):
                                    ip_details['api_gateway'].add(ip)
                        except Exception:
                            pass
            if ip_details['api_gateway']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['api_gateway'])} API Gateway IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "API Gateway", e)

        # 15. Dataflow Workers
        try:
            dataflow = self._get_client('dataflow', 'v1b3')
            req = dataflow.projects().locations().jobs().list(
                projectId=project_id,
                location='-',
                filter='ACTIVE'
            )
            res = req.execute()
            for job in res.get('jobs', []):
                job_id = job.get('id')
                location = job.get('location', 'us-central1')
                try:
                    job_detail = dataflow.projects().locations().jobs().get(
                        projectId=project_id,
                        location=location,
                        jobId=job_id
                    ).execute()
                    for worker in job_detail.get('pipelineDescription', {}).get('workerPools', []):
                        ip = worker.get('workerIpAddress')
                        if ip and self.is_public_ip(ip):
                            ip_details['dataflow'].add(ip)
                except Exception:
                    pass
            if ip_details['dataflow']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['dataflow'])} Dataflow IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Dataflow", e)

        # 16. Dataproc Clusters
        try:


            result = subprocess.run(
                ["gcloud", "dataproc", "clusters", "list", f"--project={project_id}",
                 "--region=-", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                clusters = json.loads(result.stdout) if result.stdout.strip() else []
                for cluster in clusters:
                    config = cluster.get("config", {})
                    master_cfg = config.get("masterConfig", {})
                    for inst in master_cfg.get("instanceNames", []):
                        try:
                            hostname = f"{inst}.c.{project_id}.internal"
                            result2 = subprocess.run(
                                ["gcloud", "compute", "instances", "describe", inst,
                                 f"--project={project_id}", f"--zone={cluster.get('clusterName', '').split('-')[0] if '-' in cluster.get('clusterName', '') else 'us-central1-a'}",
                                 "--format=json"],
                                capture_output=True, text=True, timeout=30
                            )
                            if result2.returncode == 0 and result2.stdout.strip():
                                inst_detail = json.loads(result2.stdout)
                                for iface in inst_detail.get("networkInterfaces", []):
                                    for ac in iface.get("accessConfigs", []):
                                        if "natIP" in ac and self.is_public_ip(ac["natIP"]):
                                            ip_details['dataproc'].add(ac["natIP"])
                        except Exception:
                            pass
            if ip_details['dataproc']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['dataproc'])} Dataproc IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Dataproc", e)

        # 17. Data Fusion
        try:
            datafusion = self._get_client('datafusion', 'v1')
            req = datafusion.projects().locations().instances().list(
                parent=f"projects/{project_id}/locations/-"
            )
            res = req.execute()
            for inst in res.get('instances', []):
                if inst.get('state') == 'ACTIVE':
                    endpoint = inst.get('serviceEndpoint', '')
                    if endpoint:
                        try:
                
                            hostname = endpoint.replace("https://", "").replace("http://", "").split("/")[0]
                            ips = socket.gethostbyname_ex(hostname)[2]
                            for ip in ips:
                                if self.is_public_ip(ip):
                                    ip_details['data_fusion'].add(ip)
                        except Exception:
                            pass
            if ip_details['data_fusion']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['data_fusion'])} Data Fusion IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Data Fusion", e)

        # 18. Cloud Functions (2nd Gen)
        try:


            result = subprocess.run(
                ["gcloud", "functions", "list", f"--project={project_id}",
                 "--gen2", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                functions = json.loads(result.stdout) if result.stdout.strip() else []
                for fn in functions:
                    build_config = fn.get("buildConfig", {})
                    service_config = fn.get("serviceConfig", {})
                    uri = service_config.get("uri", "") or build_config.get("build", "")
                    if uri:
                        try:
                            hostname = uri.replace("https://", "").replace("http://", "").split("/")[0]
                            ips = socket.gethostbyname_ex(hostname)[2]
                            for ip in ips:
                                if self.is_public_ip(ip):
                                    ip_details['cloud_functions'].add(ip)
                        except Exception:
                            pass
            if ip_details['cloud_functions']:
                print(f"[dim]    - [{project_id}] ✓ Found {len(ip_details['cloud_functions'])} Cloud Functions (2nd Gen) IPs[/dim]")
        except Exception as e:
            self._handle_api_error(project_id, "Cloud Functions 2nd Gen", e)

        return ip_details

    def is_public_ip(self, ip):
        """Check if an IP address is public/global"""
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False 

    def fetch_project_dns_records(self, project_id):
        """Fetch DNS records for a GCP project (with full pagination for zones and record sets)"""
        try:
            dns_service = self._get_client('dns', 'v1')
            records = []

            # Paginate through managed zones
            zones_req = dns_service.managedZones().list(project=project_id)
            while zones_req is not None:
                zones_res = zones_req.execute()
                for zone in zones_res.get('managedZones', []):
                    zone_name = zone['name']
                    dns_name = zone['dnsName']

                    # Paginate through record sets within each zone
                    rrs_req = dns_service.resourceRecordSets().list(
                        project=project_id, managedZone=zone_name
                    )
                    while rrs_req is not None:
                        rrs_res = rrs_req.execute()
                        for record_set in rrs_res.get('rrsets', []):
                            record_type = record_set.get('type', '')
                            name = record_set.get('name', '')
                            ttl = record_set.get('ttl', 0)
                            for rrdata in record_set.get('rrdatas', []):
                                records.append({
                                    'name': name,
                                    'type': record_type,
                                    'ttl': ttl,
                                    'data': rrdata,
                                    'zone': dns_name
                                })
                        rrs_req = dns_service.resourceRecordSets().list_next(
                            previous_request=rrs_req, previous_response=rrs_res
                        )

                zones_req = dns_service.managedZones().list_next(
                    previous_request=zones_req, previous_response=zones_res
                )

            if records:
                print(f"[dim]    - [{project_id}] ✓ Found {len(records)} DNS records[/dim]")
            return records
        except Exception as e:
            self._handle_api_error(project_id, "DNS Records", e)
            return []

    def fetch_cloud_services_urls(self, project_id):
        """Fetch Cloud Run and Cloud Functions URLs for a GCP project"""



        
        urls = []
        
        # Cloud Run Services
        try:
            result = subprocess.run(
                ["gcloud", "run", "services", "list", f"--project={project_id}",
                 "--platform=managed", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                services = json.loads(result.stdout)
                for svc in services:
                    status = svc.get("status") or {}
                    meta = svc.get("metadata") or {}
                    annotations = meta.get("annotations") or {}
                    
                    url = status.get("url", "")
                    if not url:
                        continue
                    
                    ingress = annotations.get("run.googleapis.com/ingress", "all")
                    if ingress == "internal":
                        continue
                    
                    svc_name = meta.get("name", "")
                    region = meta.get("labels", {}).get("cloud.googleapis.com/location", "")
                    
                    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
                    try:
                        ips = socket.gethostbyname_ex(hostname)[2]
                        ip = ips[0] if ips else ""
                    except Exception:
                        ip = ""
                    
                    urls.append({
                        'name': f"{svc_name}.cloudrun.dev",
                        'type': 'CNAME',
                        'ttl': 0,
                        'data': hostname,
                        'zone': 'cloudrun.dev',
                        'ip': ip,
                        'resource_type': 'cloud_run',
                        'url': url,
                        'region': region
                    })
        except Exception as e:
            self._handle_api_error(project_id, "Cloud Run URLs", e)
        
        # Cloud Functions (2nd gen - via Cloud Run)
        try:
            result = subprocess.run(
                ["gcloud", "functions", "list", f"--project={project_id}",
                 "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                functions = json.loads(result.stdout)
                for fn in functions:
                    url = fn.get("httpsTrigger", {}).get("url", "")
                    if not url:
                        continue
                    
                    name = fn.get("name", "")
                    region = fn.get("region", "")
                    
                    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
                    try:
                        ips = socket.gethostbyname_ex(hostname)[2]
                        ip = ips[0] if ips else ""
                    except Exception:
                        ip = ""
                    
                    urls.append({
                        'name': hostname,
                        'type': 'CNAME',
                        'ttl': 0,
                        'data': hostname,
                        'zone': 'cloudfunctions.net',
                        'ip': ip,
                        'resource_type': 'cloud_function',
                        'url': url,
                        'region': region
                    })
        except Exception as e:
            self._handle_api_error(project_id, "Cloud Functions URLs", e)
        
        # App Engine Services
        try:
            if not project_id.startswith(_ORG_PROJECT_PREFIXES):
                print(f"[dim]    - [{project_id}] Skipping App Engine URLs (not an org project)[/dim]")
            else:
                result = subprocess.run(
                    ["gcloud", "app", "services", "list", f"--project={project_id}",
                     "--format=json"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout.strip():
                    services = json.loads(result.stdout)
                    for svc in services:
                        name = svc.get("id", "")
                        if not name:
                            continue

                        url = f"https://{name}-dot-{project_id}.appspot.com"

                        try:
                            hostname = f"{name}-dot-{project_id}.appspot.com"
                            ips = socket.gethostbyname_ex(hostname)[2]
                            ip = ips[0] if ips else ""
                        except Exception:
                            ip = ""
                            hostname = f"{name}-dot-{project_id}.appspot.com"

                        urls.append({
                            'name': hostname,
                            'type': 'CNAME',
                            'ttl': 0,
                            'data': hostname,
                            'zone': 'appspot.com',
                            'ip': ip,
                            'resource_type': 'app_engine',
                            'url': url,
                            'region': 'global'
                        })
        except Exception as e:
            self._handle_api_error(project_id, "App Engine URLs", e)
        
        # Vertex AI Endpoints
        try:
            result = subprocess.run(
                ["gcloud", "ai", "endpoints", "list", f"--project={project_id}",
                 "--region=-", "--format=json"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                endpoints = json.loads(result.stdout) if result.stdout.strip() else []
                for ep in endpoints:
                    name = ep.get("name", "").split("/")[-1]
                    region = ep.get("name", "").split("/")[3] if len(ep.get("name", "").split("/")) > 3 else ""
                    display_name = ep.get("displayName", name)
                    url = f"https://{region}-aiplatform.googleapis.com/v1/{ep.get('name', '')}"
                    hostname = f"{region}-aiplatform.googleapis.com"
                    try:
                        ips = socket.gethostbyname_ex(hostname)[2]
                        ip = ips[0] if ips else ""
                    except Exception:
                        ip = ""
                    urls.append({
                        'name': f"{display_name}.aiplatform.googleapis.com",
                        'type': 'CNAME',
                        'ttl': 0,
                        'data': hostname,
                        'zone': 'aiplatform.googleapis.com',
                        'ip': ip,
                        'resource_type': 'vertex_ai',
                        'url': url,
                        'region': region
                    })
        except Exception as e:
            self._handle_api_error(project_id, "Vertex AI URLs", e)
        
        # API Gateway
        try:
            result = subprocess.run(
                ["gcloud", "api-gateway", "gateways", "list", f"--project={project_id}",
                 "--location=-", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                gateways = json.loads(result.stdout) if result.stdout.strip() else []
                for gw in gateways:
                    gateway_uri = gw.get("gatewayConfig", {}).get("gatewayUri", "")
                    display_name = gw.get("displayName", gw.get("name", "").split("/")[-1])
                    region = gw.get("location", "")
                    if gateway_uri:
                        hostname = gateway_uri.replace("https://", "").replace("http://", "").split("/")[0]
                        try:
                            ips = socket.gethostbyname_ex(hostname)[2]
                            ip = ips[0] if ips else ""
                        except Exception:
                            ip = ""
                        urls.append({
                            'name': hostname,
                            'type': 'CNAME',
                            'ttl': 0,
                            'data': hostname,
                            'zone': 'apigateway.googleapis.com',
                            'ip': ip,
                            'resource_type': 'api_gateway',
                            'url': gateway_uri,
                            'region': region
                        })
        except Exception as e:
            self._handle_api_error(project_id, "API Gateway URLs", e)
        
        # Memorystore (Redis public endpoints)
        try:
            result = subprocess.run(
                ["gcloud", "redis", "instances", "list", f"--project={project_id}",
                 "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                instances = json.loads(result.stdout) if result.stdout.strip() else []
                for inst in instances:
                    if inst.get("connectMode", "") == "PUBLIC_ENDPOINT":
                        host = inst.get("host", "")
                        name = inst.get("name", "").split("/")[-1]
                        region = inst.get("locationId", "")
                        port = inst.get("port", 6379)
                        if host:
                            try:
                                ips = socket.gethostbyname_ex(host)[2]
                                ip = ips[0] if ips else ""
                            except Exception:
                                ip = ""
                            urls.append({
                                'name': f"{name}.redis.instances.cloud.google.com",
                                'type': 'A',
                                'ttl': 0,
                                'data': ip or host,
                                'zone': 'redis.instances.cloud.google.com',
                                'ip': ip,
                                'resource_type': 'memorystore_redis',
                                'url': f"redis://{host}:{port}",
                                'region': region
                            })
        except Exception as e:
            self._handle_api_error(project_id, "Memorystore URLs", e)
        
        # Data Fusion Instances
        try:
            result = subprocess.run(
                ["gcloud", "data-fusion", "instances", "list", f"--project={project_id}",
                 "--location=-", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                instances = json.loads(result.stdout) if result.stdout.strip() else []
                for inst in instances:
                    if inst.get("state") == "ACTIVE":
                        endpoint = inst.get("serviceEndpoint", "")
                        name = inst.get("name", "").split("/")[-1]
                        region = inst.get("location", "")
                        if endpoint:
                            hostname = endpoint.replace("https://", "").replace("http://", "").split("/")[0]
                            try:
                                ips = socket.gethostbyname_ex(hostname)[2]
                                ip = ips[0] if ips else ""
                            except Exception:
                                ip = ""
                            urls.append({
                                'name': hostname,
                                'type': 'CNAME',
                                'ttl': 0,
                                'data': hostname,
                                'zone': 'datafusion.googleapis.com',
                                'ip': ip,
                                'resource_type': 'data_fusion',
                                'url': endpoint,
                                'region': region
                            })
        except Exception as e:
            self._handle_api_error(project_id, "Data Fusion URLs", e)
        
        # Cloud Functions (2nd Gen)
        try:
            result = subprocess.run(
                ["gcloud", "functions", "list", f"--project={project_id}",
                 "--gen2", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                functions = json.loads(result.stdout) if result.stdout.strip() else []
                for fn in functions:
                    service_config = fn.get("serviceConfig", {})
                    uri = service_config.get("uri", "")
                    name = fn.get("name", "").split("/")[-1]
                    region = fn.get("environment", "").split("/")[-1] if "/" in fn.get("environment", "") else ""
                    if uri:
                        hostname = uri.replace("https://", "").replace("http://", "").split("/")[0]
                        try:
                            ips = socket.gethostbyname_ex(hostname)[2]
                            ip = ips[0] if ips else ""
                        except Exception:
                            ip = ""
                        urls.append({
                            'name': hostname,
                            'type': 'CNAME',
                            'ttl': 0,
                            'data': hostname,
                            'zone': 'cloudfunctions.net',
                            'ip': ip,
                            'resource_type': 'cloud_function_gen2',
                            'url': uri,
                            'region': region
                        })
        except Exception as e:
            self._handle_api_error(project_id, "Cloud Functions Gen2 URLs", e)
        
        if urls:
            print(f"[dim]    - [{project_id}] ✓ Found {len(urls)} Cloud Service URLs[/dim]")
        
        return urls

    def cleanup_stale_data(self, active_projects):
        """Mark data for projects that are no longer active or accessible as archived."""
        if not active_projects:
            return

        try:
            mongo = MongoDB()
            archive_data = {
                "$set": {
                    "status": "archived",
                    "archived_at": datetime.now()
                }
            }
            
            ip_col = mongo.set_collection("Prod IP Records")
            res_ip = ip_col.update_many({
                "source": self.SOURCE,
                "project_id": {"$nin": active_projects},
                "status": {"$ne": "archived"}
            }, archive_data)

            dns_col = mongo.set_collection("Prod DNS")
            res_dns = dns_col.update_many({
                "source": self.SOURCE,
                "project_id": {"$nin": active_projects},
                "status": {"$ne": "archived"}
            }, archive_data)


            dns_rec_col = mongo.set_collection("Prod DNS Records")
            res_rec = dns_rec_col.update_many({
                "source": self.SOURCE,
                "project_id": {"$nin": active_projects},
                "status": {"$ne": "archived"}
            }, archive_data)

            if res_ip.modified_count > 0 or res_dns.modified_count > 0 or res_rec.modified_count > 0:
                print(f"[bold yellow]  Archiving stale {self.SOURCE} data...[/bold yellow]")
                if res_ip.modified_count > 0:
                    print(f"[dim] - Archived {res_ip.modified_count} stale project records in 'IP Records'[/dim]")
                if res_dns.modified_count > 0:
                    print(f"[dim] - Archived {res_dns.modified_count} stale project records in 'DNS'[/dim]")
                if res_rec.modified_count > 0:
                    print(f"[dim] - Archived {res_rec.modified_count} stale individual records in 'DNS Records'[/dim]")

        except Exception as e:
            print(f"[bold red][-] Error during stale data cleanup: {e}[/bold red]")

    def run(self, max_workers=None):
        """Run GCP inventory scan with resource type tracking"""
        if max_workers is None:
            max_workers = 20  
        
        console = Console()
        print(f"[bold blue][+] Starting {self.SOURCE} inventory scan...[/bold blue]")
        
        projects = self.list_projects()
        print(f"[bold blue][+] Found {len(projects)} active {self.SOURCE} projects[/bold blue]")
        
        if not projects:
            print("[bold yellow][!] No active projects found[/bold yellow]")
            return
        
        all_project_ips = {}
        all_project_dns = {}
        all_project_cloud_urls = {}
        projects_without_ips = 0
        
        def fetch_ips(project_id):
            try:
                return project_id, self.get_project_ips(project_id)
            except Exception as e:
                self._handle_api_error(project_id, "IP Discovery", e)
                return project_id, None
        
        def fetch_dns(project_id):
            try:
                return project_id, self.fetch_project_dns_records(project_id)
            except Exception as e:
                self._handle_api_error(project_id, "DNS Discovery", e)
                return project_id, []
        
        def fetch_cloud_urls(project_id):
            try:
                return project_id, self.fetch_cloud_services_urls(project_id)
            except Exception as e:
                self._handle_api_error(project_id, "Cloud URLs Discovery", e)
                return project_id, []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Fetching {self.SOURCE} resources...", total=len(projects) * 3)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                ip_futures = {executor.submit(fetch_ips, project_id): project_id for project_id in projects}
                dns_futures = {executor.submit(fetch_dns, project_id): project_id for project_id in projects}
                cloud_url_futures = {executor.submit(fetch_cloud_urls, project_id): project_id for project_id in projects}
                for future in as_completed(ip_futures):
                    project_id, ips = future.result()
                    if ips:
                        all_project_ips[project_id] = ips
                    else:
                        projects_without_ips += 1
                    progress.advance(task)
                
                for future in as_completed(dns_futures):
                    project_id, dns_records = future.result()
                    if dns_records:
                        all_project_dns[project_id] = dns_records
                    progress.advance(task)
                
                for future in as_completed(cloud_url_futures):
                    project_id, cloud_urls = future.result()
                    if cloud_urls:
                        all_project_cloud_urls[project_id] = cloud_urls
                    progress.advance(task)
        
        print(f"[bold blue][+] Storing {self.SOURCE} data in MongoDB...[/bold blue]")
        mongo = MongoDB()
        ip_collection = mongo.set_collection("Prod IP Records")
        
        new_ip_records = []
        for project_id, ip_details in all_project_ips.items():
            if ip_details:
                resource_types = {}
                total_count = 0
                
                for resource_type, ip_set in ip_details.items():
                    if ip_set:  
                        ip_list = list(ip_set)
                        resource_types[resource_type] = ip_list
                        total_count += len(ip_list)
                
                if total_count > 0: 
                    record_data = {
                        'project_id': project_id,
                        'source': self.SOURCE,
                        'resource_types': resource_types,
                        'total_count': total_count,
                        'status': 'active',
                        'timestamp': datetime.now()
                    }
                    new_ip_records.append(record_data)
        
        if new_ip_records:
            try:
                stored_count = 0
                skipped_count = 0
                
                for record in new_ip_records:
                    try:
                        query = {"project_id": record["project_id"], "source": self.SOURCE}
                        timestamp = record.pop('timestamp', datetime.now())
                        update = {
                            "$set": record,
                            "$setOnInsert": {"timestamp": timestamp}
                        }
                        result = ip_collection.update_one(query, update, upsert=True)
                        
                        if result.upserted_id or result.modified_count > 0:
                            stored_count += 1  
                        else:
                            skipped_count += 1
                            
                    except Exception as e:
                        print(f"[bold yellow] [{record['project_id']}] Error upserting IP record: {e}[/bold yellow]")
                        skipped_count += 1
                
                if stored_count > 0:
                    print(f"[green]✓ {self.SOURCE} IP Records: {stored_count} stored/updated[/green]")
                if skipped_count > 0:
                    print(f"[yellow] {self.SOURCE} IP Records: {skipped_count} unchanged/skipped[/yellow]")
                    
            except Exception as e:
                print(f"[bold red][-] Error storing {self.SOURCE} IP records: {str(e)}[/bold red]")
        
        dns_collection = mongo.set_collection("Prod DNS")
        new_dns_records = []
        for project_id, dns_records in all_project_dns.items():
            if dns_records:
                record_data = {
                    'project_id': project_id,
                    'source': self.SOURCE,
                    'records': dns_records,
                    'count': len(dns_records),
                    'status': 'active',
                    'timestamp': datetime.now()
                }
                new_dns_records.append(record_data)
        
        if new_dns_records:
            try:
                stored_count = 0
                skipped_count = 0
                
                for record in new_dns_records:
                    try:
                        query = {"project_id": record["project_id"], "source": self.SOURCE}
                        timestamp = record.pop('timestamp', datetime.now())
                        update = {
                            "$set": record,
                            "$setOnInsert": {"timestamp": timestamp}
                        }
                        result = dns_collection.update_one(query, update, upsert=True)
                        
                        if result.upserted_id or result.modified_count > 0:
                            stored_count += 1  
                        else:
                            skipped_count += 1
                            
                    except Exception as e:
                        print(f"[bold yellow] [{record['project_id']}] Error upserting DNS record: {e}[/bold yellow]")
                        skipped_count += 1
                
                if stored_count > 0:
                    print(f"[green]✓ {self.SOURCE} Bulk DNS Records: {stored_count} stored/updated[/green]")
                if skipped_count > 0:
                    print(f"[yellow] {self.SOURCE} Bulk DNS Records: {skipped_count} unchanged/skipped[/yellow]")
                    
            except Exception as e:
                print(f"[bold red][-] Error storing {self.SOURCE} DNS records: {str(e)}[/bold red]")
        
        dns_records_collection = mongo.set_collection("Prod DNS Records")
        individual_dns_records = []
        for project_id, dns_records in all_project_dns.items():
            if dns_records:
                for dns_record in dns_records:
                    dns_zone = dns_record.get('zone', '').rstrip('.')
                    record_data = {
                        'zone_name': dns_zone or project_id,
                        'name': dns_record.get('name', ''),
                        'type': dns_record.get('type', ''),
                        'content': dns_record.get('data', ''),
                        'proxied': '',
                        'resource_type': 'gcp_dns',
                        'source': self.SOURCE,
                        'zone': dns_record.get('zone', ''),
                        'project_id': project_id,
                    }
                    record_hash = calculate_hash(record_data)
                    
                    individual_record = record_data.copy()
                    individual_record['hash'] = record_hash
                    individual_record['status'] = 'active'
                    individual_record['timestamp'] = datetime.now()
                    individual_record['ttl'] = dns_record.get('ttl', 300)

                    individual_dns_records.append(individual_record)
        
        if individual_dns_records:
            try:
                stored_count = 0
                skipped_count = 0
                
                for record in individual_dns_records:
                    try:
                        query = {"hash": record["hash"]}
                        # Separate volatile fields from static fields
                        timestamp = record.pop('timestamp', datetime.now())
                        
                        update = {
                            "$set": record, # Update all data fields
                            "$setOnInsert": {"timestamp": timestamp} # ONLY set timestamp when first created
                        }
                        result = dns_records_collection.update_one(query, update, upsert=True)
                        
                        if result.upserted_id or result.modified_count > 0:
                            stored_count += 1  
                        else:
                            skipped_count += 1
                            
                    except Exception as e:
                        print(f"[bold yellow] Error upserting individual DNS record: {e}[/bold yellow]")
                        skipped_count += 1
                
                if stored_count > 0:
                    print(f"[green]✓ {self.SOURCE} Individual DNS Records: {stored_count} stored/updated[/green]")
                if skipped_count > 0:
                    print(f"[yellow] {self.SOURCE} Individual DNS Records: {skipped_count} unchanged/skipped[/yellow]")
                    
            except Exception as e:
                print(f"[bold red][-] Error storing individual DNS records: {str(e)}[/bold red]")
        
        if all_project_cloud_urls:
            cloud_url_records = []
            for project_id, urls in all_project_cloud_urls.items():
                if urls:
                    for url_record in urls:
                        record_data = {
                            'zone_name': url_record.get('zone', 'cloud-services'),
                            'name': url_record.get('name', ''),
                            'type': url_record.get('type', 'CNAME'),
                            'content': url_record.get('ip', '') or url_record.get('data', ''),
                            'proxied': '',
                            'resource_type': url_record.get('resource_type', 'cloud_run'),
                            'source': self.SOURCE,
                            'url': url_record.get('url', ''),
                            'region': url_record.get('region', ''),
                            'project_id': project_id,
                        }
                        record_hash = calculate_hash(record_data)
                        
                        individual_record = record_data.copy()
                        individual_record['hash'] = record_hash
                        individual_record['status'] = 'active'
                        individual_record['timestamp'] = datetime.now()
                        individual_record['ttl'] = url_record.get('ttl', 0)
                        
                        cloud_url_records.append(individual_record)
            
            if cloud_url_records:
                try:
                    stored_count = 0
                    skipped_count = 0
                    
                    for record in cloud_url_records:
                        try:
                            query = {"hash": record["hash"]}
                            timestamp = record.pop('timestamp', datetime.now())
                            
                            update = {
                                "$set": record,
                                "$setOnInsert": {"timestamp": timestamp}
                            }
                            result = dns_records_collection.update_one(query, update, upsert=True)
                            
                            if result.upserted_id or result.modified_count > 0:
                                stored_count += 1
                            else:
                                skipped_count += 1
                                
                        except Exception as e:
                            skipped_count += 1
                    
                    if stored_count > 0:
                        print(f"[green]✓ {self.SOURCE} Cloud Service URLs: {stored_count} stored/updated[/green]")
                    if skipped_count > 0:
                        print(f"[yellow] {self.SOURCE} Cloud Service URLs: {skipped_count} unchanged/skipped[/yellow]")
                        
                except Exception as e:
                    print(f"[bold red][-] Error storing cloud URL records: {str(e)}[/bold red]")

        all_ips = set()
        observations_count = 0
        category_unique = {
            'static_ip': set(),
            'vm_external': set(),
            'load_balancer': set(),
            'vpn_gateway': set(),
            'cloud_sql': set(),
            'cloud_nat': set(),
            'cloud_run': set(),
            'gke_cluster': set(),
            'gke_nodes': set(),
            'app_engine': set(),
            'memorystore': set(),
            'filestore': set(),
            'vertex_ai': set(),
            'api_gateway': set(),
            'dataflow': set(),
            'dataproc': set(),
            'data_fusion': set(),
            'cloud_functions': set(),
            'other_network': set()
        }
        
        for ip_details in all_project_ips.values():
            if ip_details:
                for cat, ip_set in ip_details.items():
                    observations_count += len(ip_set)
                    for ip in ip_set:
                        all_ips.add(ip)
                        if cat in category_unique:
                            category_unique[cat].add(ip)
        
        total_unique_ips = len(all_ips)
        total_dns_records = sum(len(records) for records in all_project_dns.values())
        total_cloud_urls = sum(len(urls) for urls in all_project_cloud_urls.values())

        print("\n[bold blue]📊 GCP Total Inventory Statistics (Public + Internal):[/bold blue]")
        print(f"[dim] - Total Projects Scanned: {len(projects)}[/dim]")
        print(f"[dim] - Total IP Assets Found:  {observations_count} (including overlaps)[/dim]")
        print(f"[bold green] - Unique IP Targets:     {total_unique_ips} (de-duplicated)[/bold green]")
        for cat, ip_set in category_unique.items():
            if ip_set:
                clean_name = cat.replace('_', ' ').title()
                print(f"[dim]   └─ {clean_name}: {len(ip_set)}[/dim]")
        print(f"[dim] - Total DNS Records Found: {total_dns_records}[/dim]")
        if total_cloud_urls > 0:
            print(f"[dim] - Total Cloud Service URLs: {total_cloud_urls}[/dim]")

        print(f"\n[bold green]  {self.SOURCE} inventory scan completed![/bold green]")
        
        self.cleanup_stale_data(projects)
        
        return all_project_ips, all_project_dns

