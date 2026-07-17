import json
import shutil
import socket
import subprocess
import tempfile
import time
import csv
import argparse
import concurrent.futures
import os
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime

from google.oauth2 import service_account
from google.auth import default as google_auth_default
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from system.db import MongoDB
from system.utils import calculate_hash, is_private_ip
from modules.gcp import GCP

console = Console()


# ── Shared naabu batch scanner ───────────────────────────────────────────────

_NAABU_TIMEOUT = 1800  # seconds per batch (30 min for large inventories)

# Security-focused port list covering the most common attack surface exposure.
# ~40 ports vs top-1000 = 25x fewer checks without missing real findings.
SECURITY_PORTS = sorted([
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 2375, 2376, 3000,
    3306, 3389, 4848, 5432, 5900, 5984, 6379, 7001,
    7474, 8080, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017, 28017, 50070, 50075,
])


def _naabu_scan_batch(targets: list, ports: list = None,
                      top_ports: int = 100, concurrency: int = 300) -> dict:
    """
    Run naabu against a list of targets in a single subprocess.
    Much faster than Python socket connects — naabu uses SYN/connect scanning
    with tuned concurrency and handles retries internally.

    Args:
        targets:     list of IPs or hostnames
        ports:       explicit port list to scan (overrides top_ports)
        top_ports:   use naabu's top-N list when no explicit ports given
        concurrency: naabu -c flag (threads inside naabu)

    Returns:
        {target: [open_port_ints]}  — target matches the input string
    """
    if not targets:
        return {}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(str(t) for t in targets))
        list_file = f.name

    cmd = [
        "naabu", "-list", list_file,
        "-json", "-silent",
        "-c",       str(concurrency),
        "-retries", "1",
        "-timeout", "3",
    ]
    if ports:
        cmd += ["-p", ",".join(map(str, ports))]
    else:
        cmd += ["-top-ports", str(top_ports)]

    out_file = None
    results: dict[str, list] = {}
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as of:
            out_file = of.name

        # Write stdout to a temp file to avoid pipe buffer exhaustion (EPIPE/broken pipe)
        # when naabu produces large output scanning many targets.
        with open(out_file, "w") as stdout_fh:
            proc = subprocess.run(
                cmd,
                stdout=stdout_fh,
                stderr=subprocess.DEVNULL,
                timeout=_NAABU_TIMEOUT,
            )

        with open(out_file) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("["):
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    port = data.get("port")
                    if host and port:
                        results.setdefault(host, []).append(int(port))
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue
    except subprocess.TimeoutExpired:
        console.log(f"[yellow]naabu timed out after {_NAABU_TIMEOUT}s[/yellow]")
    except FileNotFoundError:
        console.log("[red]naabu not found in PATH — port confirmation unavailable[/red]")
    finally:
        for path in (list_file, out_file):
            try:
                if path:
                    os.unlink(path)
            except Exception:
                pass

    return {k: sorted(v) for k, v in results.items()}

class FirewallScanner:
    """
    A modular scanner to analyze GCP firewall rules and perform port scans
    on public-facing cloud assets.
    """
    
    SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
    TIMEOUT = 3.0
    TOP_PORTS = SECURITY_PORTS  # use curated security-focused list (includes RDP, SMB, etc.)
    GKE_PORTS = [22, 80, 443, 6443, 8080, 8443, 10250, 10255, 10256] + list(range(30000, 32768)) # Common NodePort range
    DB_COLLECTION = "Prod Firewall Port"

    def __init__(self, svc_account_path=None):
        self.svc_account_path = svc_account_path or os.getenv('SVC_ACCOUNT', '/etc/config/creds.json')
        self.credentials = self._setup_credentials()
        self.crm_service = self._get_service("cloudresourcemanager", "v1")
        self.compute_service = self._get_service("compute", "v1")
        self.gcp_helper = self._initialize_gcp_helper()
        
    def _setup_credentials(self):
        """Setup GCP credentials from service account file or default environment."""
        try:
            if os.path.exists(self.svc_account_path):
                return service_account.Credentials.from_service_account_file(
                    self.svc_account_path, scopes=self.SCOPES
                )
            else:
                console.log(f"[yellow]Service account file not found at {self.svc_account_path}, falling back to defaults[/yellow]")
                credentials, _ = google_auth_default(scopes=self.SCOPES)
                return credentials
        except Exception as e:
            console.log(f"[red]Failed to setup GCP credentials: {e}[/red]")
            return None

    def _get_service(self, api_name, version):
        """Build a GCP service discovery object."""
        if not self.credentials:
            return None
        try:
            import httplib2
            import google_auth_httplib2
            authed_http = google_auth_httplib2.AuthorizedHttp(
                self.credentials, http=httplib2.Http(timeout=30)
            )
            return discovery.build(api_name, version, http=authed_http, cache_discovery=False)
        except Exception as e:
            console.log(f"[red]Failed to build service {api_name}: {e}[/red]")
            return None

    def _initialize_gcp_helper(self):
        """Initialize the shared GCP asset discovery helper."""
        if GCP is None:
            return None
        try:
            if self.svc_account_path:
                os.environ["SVC_ACCOUNT"] = self.svc_account_path
            return GCP()
        except Exception as e:
            console.log(f"[red]Failed to initialize GCP helper: {e}[/red]")
            return None

    def _retry_api_call(self, func, max_retries=3, backoff_factor=2):
        """Generic retry wrapper for GCP API calls."""
        for attempt in range(max_retries):
            try:
                return func()
            except HttpError as e:
                status = e.resp.status
                if status in [429, 500, 502, 503, 504]:
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor ** attempt
                        time.sleep(wait_time)
                        continue
                raise
            except (TimeoutError, OSError) as e:
                # Network-level timeout (httplib2 / SSL) — skip rather than crash
                console.log(f"[yellow]GCP API network timeout on attempt {attempt + 1}: {e}[/yellow]")
                if attempt < max_retries - 1:
                    time.sleep(backoff_factor ** attempt)
                    continue
                raise
            except Exception:
                raise
        return None

    def list_projects(self, org_id=None, project_filter=None):
        """List active GCP projects with optional filtering."""
        if not self.crm_service:
            return []
            
        projects = []
        try:
            request = self.crm_service.projects().list()
            while request is not None:
                response = request.execute()
                for proj in response.get("projects", []):
                    if proj["lifecycleState"] != "ACTIVE":
                        continue
                        
                    p_id = proj["projectId"]
                    if project_filter and p_id not in project_filter:
                        continue
    
                    if org_id:
                        parent = proj.get("parent", {})
                        if parent.get("type") == "organization" and parent.get("id") == org_id:
                            projects.append(p_id)
                    else:
                        projects.append(p_id)
                request = self.crm_service.projects().list_next(request, response)
            return projects
        except Exception as e:
            console.log(f"[red]Error listing projects: {e}[/red]")
            return []

    def get_organizations(self):
        """Analyze project structures to find parent organizations."""
        if not self.crm_service:
            return []
        
        orgs = {}
        try:
            request = self.crm_service.projects().list()
            while request is not None:
                response = request.execute()
                for proj in response.get("projects", []):
                    parent = proj.get("parent", {})
                    if parent.get("type") == "organization":
                        o_id = parent.get("id")
                        if o_id not in orgs:
                            orgs[o_id] = {"id": o_id, "projects": [], "displayName": f"Organization {o_id}"}
                        orgs[o_id]["projects"].append(proj["projectId"])
                request = self.crm_service.projects().list_next(request, response)
            return list(orgs.values())
        except Exception as e:
            console.log(f"[yellow]Cannot fetch organizations: {e}[/yellow]")
            return []

    def fetch_firewall_rules(self, project_id):
        """Fetch and filter firewall rules for a project."""
        if not self.compute_service:
            return []

        def _fetch():
            req = self.compute_service.firewalls().list(project=project_id)
            rules = []
            while req is not None:
                res = req.execute()
                rules.extend(res.get("items", []))
                req = self.compute_service.firewalls().list_next(req, res)
            return rules
    
        try:
            result = self._retry_api_call(_fetch)
            return result if result is not None else []
        except HttpError as e:
            if e.resp.status == 403:
                console.log(f"[dim yellow] Skipping {project_id}: Compute API not enabled[/dim yellow]")
            else:
                console.log(f"[red] Error fetching firewalls for {project_id}: {e}[/red]")
            return []
        except (TimeoutError, OSError) as e:
            console.log(f"[yellow] Skipping {project_id}: GCP API timed out ({e})[/yellow]")
            return []

    def list_assets(self, project_id):
        """Fetch public assets using the GCP engine."""
        assets = []
        if not self.gcp_helper:
            return assets

        try:
            raw_ips = self.gcp_helper.get_project_ips(project_id)
            
            mapping = {
                'static_ip': ('Static IP', 'Static IP'),
                'vm_external': ('VM Instance', 'Compute'),
                'load_balancer': ('Forwarding Rule', 'Load Balancer'),
                'cloud_sql': ('SQL Instance', 'Cloud SQL'),
                'vpn_gateway': ('VPN Gateway', 'VPN'),
                'cloud_nat': ('Cloud NAT', 'NAT')
            }

            seen_ips = set()
            for key, (display_name, r_type) in mapping.items():
                ips = raw_ips.get(key, set())
                for ip in ips:
                    if ip not in seen_ips and not self._is_private(ip):
                        assets.append({
                            "project": project_id,
                            "name": f"{display_name}_{ip}",
                            "type": r_type,
                            "ip": str(ip)
                        })
                        seen_ips.add(ip)
        except Exception as e:
            console.log(f"[dim yellow] Warning: Asset discovery error in {project_id}: {e}[/dim yellow]")
            
        return assets

    def _is_private(self, ip_str):
        """Check if an IP is in a private range."""
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False

    # Ports that should never be open to 0.0.0.0/0 — flag at rule level regardless
    # of whether naabu confirms the port is reachable.
    RISKY_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900,
                   6379, 11211, 27017}

    def get_risky_rules(self, fw_rules, project_id: str) -> list:
        """
        Return findings for firewall rules exposing sensitive ports to the internet.
        Raised regardless of whether naabu confirms the port open.
        """
        findings = []
        for rule in fw_rules:
            if rule.get("direction") != "INGRESS" or rule.get("disabled"):
                continue
            sources = rule.get("sourceRanges", [])
            if not any("0.0.0.0/0" in s or "0.0.0.0" in s for s in sources):
                continue

            rule_name = rule.get("name", "unknown")
            for allow in rule.get("allowed", []):
                proto = (allow.get("IPProtocol") or "").lower()
                if proto not in ("tcp", "all"):
                    continue

                ports_field = allow.get("ports", [])
                if not ports_field:
                    findings.append({
                        "project": project_id, "rule": rule_name,
                        "proto": proto, "ports": "ALL", "severity": "critical",
                    })
                    continue

                exposed = set()
                for p_range in ports_field:
                    if "-" in p_range:
                        try:
                            s, e = p_range.split("-", 1)
                            exposed.update(range(int(s), int(e) + 1))
                        except (ValueError, TypeError):
                            pass
                    else:
                        try:
                            exposed.add(int(p_range))
                        except (ValueError, TypeError):
                            pass

                risky = exposed & self.RISKY_PORTS
                if risky:
                    findings.append({
                        "project": project_id, "rule": rule_name, "proto": proto,
                        "ports": ",".join(map(str, sorted(risky))),
                        "severity": "critical" if {3389, 445, 23} & risky else "high",
                    })
        return findings

    def extract_ports(self, fw_rules, max_ports=500):
        """Extract TCP ports allowed from the internet.

        When a rule allows all TCP ports (no ``ports`` field), the full
        1-65535 range is expanded up to *max_ports*.  This is intentional:
        an open-all-ports rule is the most dangerous configuration and must
        not be silently skipped.
        """
        collected = set()
        for rule in fw_rules:
            if rule.get("direction") != "INGRESS" or rule.get("disabled"):
                continue

            sources = rule.get("sourceRanges", [])
            if not any("0.0.0.0/0" in s or "0.0.0.0" in s for s in sources):
                continue

            for allow in rule.get("allowed", []):
                if (allow.get("IPProtocol") or "").lower() != "tcp":
                    continue

                ports = allow.get("ports", [])
                if not ports:
                    for p in range(1, 65536):
                        if len(collected) >= max_ports:
                            break
                        collected.add(p)
                    continue

                for p_range in ports:
                    if "-" in p_range:
                        try:
                            start_str, end_str = p_range.split("-", 1)
                            start, end = int(start_str), int(end_str)
                            for p in range(start, end + 1):
                                if len(collected) < max_ports:
                                    collected.add(p)
                        except (ValueError, TypeError):
                            continue
                    else:
                        try:
                            p = int(p_range)
                            if len(collected) < max_ports:
                                collected.add(p)
                        except (ValueError, TypeError):
                            continue
        return sorted(list(collected))

    def scan_target(self, target, ports, max_workers=200):
        """Scan a list of ports on a specific IP address or hostname."""
        ip = target
        if any(c.isalpha() for c in target):
            try:
                ip = socket.gethostbyname(target)
            except:
                return []

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._check_port, ip, p): p for p in ports}
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    open_ports.append(res)
        return sorted(open_ports)

    def _check_port(self, ip, port):
        """Single socket connection check."""
        try:
            with socket.create_connection((ip, port), timeout=self.TIMEOUT):
                return port
        except:
            return None

    def format_rules(self, rules):
        """Format firewall rules for display/storage."""
        if not rules:
            return "No internet-facing rules found"
            
        formatted = []
        for r in rules:
            if r.get("direction") != "INGRESS" or r.get("disabled"):
                continue
            sources = ",".join(r.get("sourceRanges", []))
            allowed = []
            for a in r.get("allowed", []):
                proto = a.get("IPProtocol", "tcp")
                pts = ",".join(a.get("ports", [])) if a.get("ports") else "ALL"
                allowed.append(f"{proto}:{pts}")
            formatted.append(f"{r['name']} ({sources}) -> ALLOW: {' '.join(allowed)}")
        return "\n".join(formatted)

    def save_to_db(self, results):
        """Save results to MongoDB"""
        if not MongoDB:
            return
        try:
            db = MongoDB()
            col = db.set_collection(self.DB_COLLECTION)
            for r in results:
                query = {"project": r["project"], "instance": r["instance"], "ip": r["ip"]}
                r["last_updated"] = datetime.utcnow()
                col.update_one(query, {"$set": r}, upsert=True)
            console.log(f"[green]Stored {len(results)} results in '{self.DB_COLLECTION}'[/green]")
        except Exception as e:
            console.log(f"[yellow]Warning: Failed to save to MongoDB: {e}[/yellow]")

    def run(self, args):
        """Main execution flow."""
        org_id          = getattr(args, 'org_id', None)
        projects_filter = getattr(args, 'projects', None)
        project_id      = getattr(args, 'project', None)
        max_projects    = getattr(args, 'max_projects', None)
        firewall_ports  = getattr(args, 'firewall_ports', False)
        gke_scan        = getattr(args, 'gke_scan', False)
        max_scan_ports  = getattr(args, 'max_scan_ports', 500)

        projects = self.list_projects(
            org_id=org_id,
            project_filter=projects_filter.split(",") if projects_filter else None,
        )
        if project_id:
            projects = [project_id]
        if max_projects:
            projects = projects[:max_projects]

        console.log(f"[blue]GCP: collecting assets across {len(projects)} project(s)…[/blue]")

        # ── Phase 1: collect all assets via GCP API (sequential — httplib2 not thread-safe) ──
        scan_jobs: list[tuple] = []   # (ip, ports, asset_meta, project_id, fw_display)
        fw_only_results: list[dict] = []
        risky_rules: list[dict] = []  # rule-level findings regardless of naabu

        for p_id in projects:
            if p_id.startswith(("sys-", "gcp-sa-")):
                continue

            fw_rules = self.fetch_firewall_rules(p_id)
            internet_rules = [
                r for r in fw_rules
                if r.get("direction") == "INGRESS"
                and not r.get("disabled")
                and any("0.0.0.0" in s for s in r.get("sourceRanges", []))
            ]
            assets = self.list_assets(p_id)

            if not assets and not internet_rules:
                continue

            risky_rules.extend(self.get_risky_rules(internet_rules, p_id))

            fw_display = self.format_rules(internet_rules)

            # Always extract ports from actual firewall rules + union with SECURITY_PORTS
            # so we never miss a known risky port even if not explicitly in a rule.
            rule_ports = self.extract_ports(internet_rules, max_ports=max_scan_ports)
            if gke_scan:
                ports = sorted(set(rule_ports) | set(self.GKE_PORTS))
            else:
                ports = sorted(set(rule_ports) | set(SECURITY_PORTS))
            if not ports:
                ports = SECURITY_PORTS

            if not assets:
                fw_only_results.append({
                    "project": p_id, "instance": "N/A", "type": "Firewall Only",
                    "ip": "-", "firewall_rules": fw_display,
                    "confirmed_open_ports": [], "source": "GCP",
                })
                continue

            for asset in assets:
                scan_jobs.append((asset["ip"], ports, asset, p_id, fw_display))

        # ── Phase 2: batch naabu grouped by port set (one subprocess per unique port set) ──
        port_groups: dict[tuple, list] = defaultdict(list)
        for ip, ports, asset, p_id, fw_display in scan_jobs:
            port_groups[tuple(sorted(ports))].append((ip, asset, p_id, fw_display))

        all_results = list(fw_only_results)
        total_assets = sum(len(v) for v in port_groups.values())
        console.log(f"[blue]GCP: port scanning {total_assets} asset(s) via naabu…[/blue]")

        for ports_tuple, jobs in port_groups.items():
            ips = [ip for ip, _, _, _ in jobs]
            naabu_res = _naabu_scan_batch(ips, ports=list(ports_tuple))
            for ip, asset, p_id, fw_display in jobs:
                all_results.append({
                    "project":             p_id,
                    "instance":            asset["name"],
                    "type":                asset["type"],
                    "ip":                  ip,
                    "firewall_rules":      fw_display,
                    "confirmed_open_ports": naabu_res.get(ip, []),
                    "source":              "GCP",
                })

        self._display_results(all_results)
        self.save_to_db(all_results)
        self._save_to_files(all_results, args)
        return all_results, risky_rules

    def _display_results(self, results):
        """Render results in a rich table."""
        if not results:
            console.log("[yellow]No results to display[/yellow]")
            return

        table = Table(title="GCP Firewall Security Analysis")
        table.add_column("Project", style="cyan")
        table.add_column("Resource", style="green")
        table.add_column("IP", style="yellow")
        table.add_column("Open Ports", style="red")
        
        for r in results:
            table.add_row(
                r["project"], r["instance"], r["ip"], 
                ", ".join(map(str, r["confirmed_open_ports"])) if r["confirmed_open_ports"] else "-"
            )
        console.print(table)

    def _save_to_files(self, results, args):
        """Export results to CSV and JSON."""
        if not results:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"gcp_firewall_scan_{timestamp}"
        
        try:
            with open(f"{base_name}.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["project", "instance", "type", "ip", "firewall_rules", "confirmed_open_ports"])
                writer.writeheader()
                for r in results:
                    row = r.copy()
                    row["confirmed_open_ports"] = ",".join(map(str, r["confirmed_open_ports"]))
                    row["firewall_rules"] = r["firewall_rules"].replace("\n", " | ")
                    if "last_updated" in row: del row["last_updated"]
                    writer.writerow(row)
        except Exception as e:
            console.log(f"[red]Failed to export CSV: {e}[/red]")
        
        try:
            with open(f"{base_name}.json", "w") as f:
                json.dump(results, f, default=str, indent=2)
        except Exception as e:
            console.log(f"[red]Failed to export JSON: {e}[/red]")
            
        console.log(f"[green]Results exported to {base_name}.csv and {base_name}.json[/green]")

class AWSFirewallScanner:
    """
    Scans AWS public assets by reading Security Group rules (for EC2) and
    Listener ports (for ALBs/NLBs) to determine which ports are actually
    allowed from the internet, then confirms with a live socket scan.

    Supports multi-account via AWS_ACCOUNT_IDS + AWS_ASSUME_ROLE_PATTERN
    (or AWS_ASSUME_ROLE_NAME), and region filtering via AWS_SCAN_REGIONS.
    Falls back to the current caller identity if no account list is given.
    """

    DB_COLLECTION = "Prod Firewall Port"
    TIMEOUT = 3.0  # socket connect timeout (seconds)
    # When a SG rule allows all traffic (-1 protocol), we probe these common ports
    ALL_TRAFFIC_PORTS = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]
    # Cap for port-range expansion in a single SG rule
    MAX_RANGE_EXPAND = 500

    def __init__(self):
        self.assume_role_pattern = os.getenv("AWS_ASSUME_ROLE_PATTERN", "").strip()
        if not self.assume_role_pattern:
            role_name = os.getenv("AWS_ASSUME_ROLE_NAME", "").strip()
            if role_name:
                self.assume_role_pattern = f"arn:aws:iam::{{account_id}}:role/{role_name}"

    # ── AWS CLI helpers ───────────────────────────────────────────────

    def _aws_bin(self):
        path = os.getenv("AWS_CLI_PATH", "").strip()
        return path if path and os.path.isfile(path) else (shutil.which("aws") or "aws")

    def _aws_run(self, cmd_args, env_override=None, timeout=60):
        """Run AWS CLI. Returns (ok, data_or_none)."""
        env = {**os.environ} if env_override is None else {**os.environ, **env_override}
        full_cmd = [self._aws_bin(), "--output", "json", "--no-cli-pager"] + list(cmd_args)
        try:
            r = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout, env=env)
            if r.returncode == 0 and r.stdout.strip():
                return True, json.loads(r.stdout)
            return False, None
        except Exception:
            return False, None

    def _get_account_env(self, account_id):
        """Return env vars for cross-account role assumption, or None for current account."""
        if not self.assume_role_pattern or not account_id:
            return None
        role_arn = self.assume_role_pattern.replace("{account_id}", account_id)
        ok, creds = self._aws_run(
            ["sts", "assume-role", "--role-arn", role_arn,
             "--role-session-name", "appollo-firewall-scan"],
            timeout=20,
        )
        if not ok:
            console.log(f"[yellow]AWS: Could not assume role for {account_id}[/yellow]")
            return None
        c = (creds or {}).get("Credentials", {})
        return {
            "AWS_ACCESS_KEY_ID": c.get("AccessKeyId", ""),
            "AWS_SECRET_ACCESS_KEY": c.get("SecretAccessKey", ""),
            "AWS_SESSION_TOKEN": c.get("SessionToken", ""),
        }

    # ── Account / region discovery ────────────────────────────────────

    def list_accounts(self):
        """Return list of account IDs to scan."""
        ids_raw = os.getenv("AWS_ACCOUNT_IDS", "").strip()
        if ids_raw:
            return [a.strip() for a in ids_raw.split(",") if a.strip()]
        ok, data = self._aws_run(["sts", "get-caller-identity"], timeout=15)
        if ok and data:
            return [data.get("Account", "")]
        return []

    def list_regions(self, account_id=None):
        """Return list of regions to scan for an account."""
        allow = os.getenv("AWS_SCAN_REGIONS", "").strip()
        if allow:
            return [r.strip() for r in allow.split(",") if r.strip()]
        env = self._get_account_env(account_id)
        ok, data = self._aws_run(
            ["ec2", "describe-regions", "--query", "Regions[].RegionName"],
            env_override=env, timeout=20,
        )
        if ok and isinstance(data, list):
            return sorted(data)
        return ["us-east-1", "us-west-2", "eu-west-1"]

    # ── Asset discovery ───────────────────────────────────────────────

    def get_ec2_targets(self, account_id, region):
        """
        Return [{ip, sg_ids, instance_id, name}] for running EC2 instances
        that have a public IP.
        """
        env = self._get_account_env(account_id)
        ok, data = self._aws_run(
            ["ec2", "describe-instances", "--region", region,
             "--filters", "Name=instance-state-name,Values=running",
             "--query",
             "Reservations[].Instances[?PublicIpAddress]"
             ".[PublicIpAddress,SecurityGroups[].GroupId,InstanceId,"
             "Tags[?Key=='Name']|[0].Value]"],
            env_override=env, timeout=90,
        )
        if not ok or not isinstance(data, list):
            return []
        targets = []
        for item in data:
            if not isinstance(item, list) or len(item) < 2:
                continue
            ip = item[0]
            sg_ids = item[1] if isinstance(item[1], list) else []
            inst_id = item[2] if len(item) > 2 else ""
            name = (item[3] if len(item) > 3 and item[3] else None) or inst_id
            if ip and sg_ids:
                targets.append({"ip": ip, "sg_ids": sg_ids, "instance_id": inst_id, "name": name})
        if targets:
            console.log(f"[dim]AWS [{account_id}/{region}] {len(targets)} EC2 instance(s) with public IPs[/dim]")
        return targets

    def get_lb_targets(self, account_id, region):
        """
        Return [{dns, ports, name}] for internet-facing ALBs/NLBs.
        Ports come from the load balancer's listeners (which are definitive —
        the LB terminates the connection so SG rules on the LB itself are
        less meaningful than the listener configuration).
        """
        env = self._get_account_env(account_id)
        ok, lbs = self._aws_run(
            ["elbv2", "describe-load-balancers", "--region", region,
             "--query",
             "LoadBalancers[?Scheme=='internet-facing']"
             ".{Arn:LoadBalancerArn,DNS:DNSName,Name:LoadBalancerName}"],
            env_override=env, timeout=60,
        )
        if not ok or not isinstance(lbs, list):
            return []
        targets = []
        for lb in lbs:
            arn = lb.get("Arn", "")
            dns = lb.get("DNS", "")
            name = lb.get("Name", dns)
            if not dns:
                continue
            ok2, listeners = self._aws_run(
                ["elbv2", "describe-listeners", "--region", region,
                 "--load-balancer-arn", arn,
                 "--query", "Listeners[].Port"],
                env_override=env, timeout=30,
            )
            ports = listeners if ok2 and isinstance(listeners, list) and listeners else [80, 443]
            targets.append({"dns": dns, "ports": sorted(set(ports)), "name": name})
        if targets:
            console.log(f"[dim]AWS [{account_id}/{region}] {len(targets)} internet-facing LB(s)[/dim]")
        return targets

    # ── Security-group port extraction ────────────────────────────────

    def get_sg_allowed_ports(self, sg_ids, account_id, region):
        """
        Return sorted list of TCP ports that the given security groups allow
        inbound from 0.0.0.0/0 or ::/0.

        Port ranges wider than MAX_RANGE_EXPAND are capped to avoid scanning
        thousands of ports per host.
        """
        if not sg_ids:
            return []
        env = self._get_account_env(account_id)
        ok, data = self._aws_run(
            ["ec2", "describe-security-groups", "--region", region,
             "--group-ids"] + list(sg_ids) +
            ["--query", "SecurityGroups[].IpPermissions"],
            env_override=env, timeout=60,
        )
        if not ok or not isinstance(data, list):
            return []

        ports = set()
        for sg_perms in data:
            if not isinstance(sg_perms, list):
                continue
            for rule in sg_perms:
                proto = (rule.get("IpProtocol") or "").lower()
                if proto not in ("tcp", "-1"):
                    continue

                open_to_internet = (
                    any(r.get("CidrIp") in ("0.0.0.0/0",) for r in rule.get("IpRanges", []))
                    or any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
                )
                if not open_to_internet:
                    continue

                if proto == "-1":
                    # All-traffic rule — probe the common set to avoid thousands of ports
                    ports.update(self.ALL_TRAFFIC_PORTS)
                    continue

                from_port = rule.get("FromPort", 0) or 0
                to_port = rule.get("ToPort", 65535) or 65535
                if from_port == to_port:
                    ports.add(from_port)
                else:
                    end = min(to_port + 1, from_port + self.MAX_RANGE_EXPAND)
                    ports.update(range(from_port, end))
                    for p in SECURITY_PORTS:
                        if from_port <= p <= to_port:
                            ports.add(p)

        return sorted(ports)

    RISKY_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900,
                   6379, 11211, 27017}

    def get_risky_sg_rules(self, sg_ids, account_id, region) -> list:
        if not sg_ids:
            return []
        env = self._get_account_env(account_id)
        ok, data = self._aws_run(
            ["ec2", "describe-security-groups", "--region", region,
             "--group-ids"] + list(sg_ids) +
            ["--query", "SecurityGroups[].{Id:GroupId,Name:GroupName,Rules:IpPermissions}"],
            env_override=env, timeout=60,
        )
        if not ok or not isinstance(data, list):
            return []

        findings = []
        for sg in data:
            sg_id   = sg.get("Id", "unknown")
            sg_name = sg.get("Name", sg_id)
            for rule in (sg.get("Rules") or []):
                proto = (rule.get("IpProtocol") or "").lower()
                if proto not in ("tcp", "-1"):
                    continue
                open_to_internet = (
                    any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                    or any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
                )
                if not open_to_internet:
                    continue
                if proto == "-1":
                    findings.append({
                        "account": account_id, "region": region,
                        "sg": sg_name, "ports": "ALL", "severity": "critical",
                    })
                    continue
                from_port = rule.get("FromPort", 0) or 0
                to_port   = rule.get("ToPort", 65535) or 65535
                exposed   = set(range(from_port, min(to_port + 1, from_port + 500)))
                for p in SECURITY_PORTS:
                    if from_port <= p <= to_port:
                        exposed.add(p)
                risky = exposed & self.RISKY_PORTS
                if risky:
                    findings.append({
                        "account": account_id, "region": region,
                        "sg": sg_name,
                        "ports": ",".join(map(str, sorted(risky))),
                        "severity": "critical" if {3389, 445, 23} & risky else "high",
                    })
        return findings

    # ── Port confirmation ─────────────────────────────────────────────

    def _check_port(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=self.TIMEOUT):
                return port
        except Exception:
            return None

    def scan_target(self, target, ports, max_workers=200):
        """Socket-confirm which of *ports* are actually open on *target*."""
        ip = target
        if any(c.isalpha() for c in target):
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                return []
        if not ports:
            return []
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as ex:
            futures = {ex.submit(self._check_port, ip, p): p for p in ports}
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res is not None:
                    open_ports.append(res)
        return sorted(open_ports)

    # ── Persistence ───────────────────────────────────────────────────

    def save_to_db(self, results):
        if not results:
            return
        try:
            db = MongoDB()
            col = db.set_collection(self.DB_COLLECTION)
            for r in results:
                query = {"project": r["project"], "instance": r["instance"], "ip": r["ip"]}
                r["last_updated"] = datetime.utcnow()
                col.update_one(query, {"$set": r}, upsert=True)
            console.log(f"[green]AWS: Stored {len(results)} results in '{self.DB_COLLECTION}'[/green]")
        except Exception as e:
            console.log(f"[yellow]AWS: Failed to save to MongoDB: {e}[/yellow]")

    # ── Main execution ────────────────────────────────────────────────

    def _scan_account_region(self, account_id: str, region: str) -> tuple:
        results = []
        risky_rules = []

        ec2_targets = self.get_ec2_targets(account_id, region)
        if ec2_targets:
            all_ec2_ports: set[int] = set()
            target_map: dict[str, tuple] = {}

            for target in ec2_targets:
                allowed = self.get_sg_allowed_ports(target["sg_ids"], account_id, region)
                risky_rules.extend(self.get_risky_sg_rules(target["sg_ids"], account_id, region))
                if allowed:
                    all_ec2_ports.update(allowed)
                    target_map[target["ip"]] = (target, allowed)

            if target_map and all_ec2_ports:
                naabu_res = _naabu_scan_batch(list(target_map.keys()), ports=sorted(all_ec2_ports))
                for ip, (target, _) in target_map.items():
                    results.append({
                        "project":              account_id,
                        "instance":             target["name"],
                        "type":                 "EC2",
                        "ip":                   ip,
                        "firewall_rules":       f"SecurityGroups: {', '.join(target['sg_ids'])}",
                        "confirmed_open_ports": naabu_res.get(ip, []),
                        "source":               "AWS",
                    })

        lb_targets = self.get_lb_targets(account_id, region)
        if lb_targets:
            all_lb_ports: set[int] = set()
            for lb in lb_targets:
                all_lb_ports.update(lb["ports"])

            naabu_res = _naabu_scan_batch([lb["dns"] for lb in lb_targets], ports=sorted(all_lb_ports))
            for lb in lb_targets:
                results.append({
                    "project":              account_id,
                    "instance":             lb["name"],
                    "type":                 "LoadBalancer",
                    "ip":                   lb["dns"],
                    "firewall_rules":       f"Listeners: {', '.join(map(str, lb['ports']))}",
                    "confirmed_open_ports": naabu_res.get(lb["dns"], []),
                    "source":               "AWS",
                })

        return results, risky_rules

    def run(self):
        accounts = self.list_accounts()
        if not accounts:
            console.log("[yellow]AWS: No accounts found — set AWS_ACCOUNT_IDS or ensure valid AWS credentials.[/yellow]")
            return [], []

        work_items = []
        for account_id in accounts:
            regions = self.list_regions(account_id)
            work_items.extend((account_id, r) for r in regions)

        console.log(f"[blue]AWS: scanning {len(accounts)} account(s) across {len(work_items)} region(s) in parallel[/blue]")

        all_results = []
        all_risky = []
        max_workers = min(len(work_items), 20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {
                ex.submit(self._scan_account_region, aid, reg): (aid, reg)
                for aid, reg in work_items
            }
            for f in concurrent.futures.as_completed(futs):
                aid, reg = futs[f]
                try:
                    res, risky = f.result() or ([], [])
                    all_results.extend(res)
                    all_risky.extend(risky)
                except Exception as e:
                    console.log(f"[yellow]AWS: Error scanning {aid}/{reg}: {e}[/yellow]")

        self.save_to_db(all_results)
        return all_results, all_risky


class InventoryScanner:
    """
    Scan public assets via naabu top-1000.
    Targets are passed in from the caller (already pulled from MongoDB inventory)
    so no redundant asset re-discovery happens here.
    """

    DB_COLLECTION = "Prod Firewall Port"

    def run(self, exclude_ips: set = None, target_override: list = None) -> list:
        exclude = exclude_ips or set()
        targets = [t for t in (target_override or []) if t not in exclude]

        if not targets:
            return []

        console.log(f"[blue]InventoryScanner: naabu top-100 on {len(targets)} target(s)[/blue]")
        naabu_res = _naabu_scan_batch(targets, top_ports=100)

        results = []
        for host, open_ports in naabu_res.items():
            if not open_ports:
                continue
            results.append({
                "project":              "inventory",
                "instance":             host,
                "type":                 "InventoryAsset",
                "ip":                   host,
                "firewall_rules":       "N/A",
                "confirmed_open_ports": open_ports,
                "source":               "Inventory",
            })

        if results:
            try:
                db  = MongoDB()
                col = db.set_collection(self.DB_COLLECTION)
                for r in results:
                    r["last_updated"] = datetime.utcnow()
                    col.update_one(
                        {"project": r["project"], "instance": r["instance"], "ip": r["ip"]},
                        {"$set": r}, upsert=True,
                    )
            except Exception as e:
                console.log(f"[yellow]InventoryScanner: MongoDB save failed: {e}[/yellow]")

        return results


def main():
    parser = argparse.ArgumentParser(description="GCP Firewall & Port Scanner (Modular Production Version)")
    parser.add_argument("--svc", help="Service account JSON file")
    parser.add_argument("--project", help="Single project ID")
    parser.add_argument("--projects", help="Comma-separated project IDs")
    parser.add_argument("--org-id", help="Organization ID filter")
    parser.add_argument("--max-projects", type=int, help="Limit project count")
    parser.add_argument("--workers", type=int, default=20, help="Total workers for scanning")
    parser.add_argument("--gke-scan", action="store_true", help="Scan GKE NodePort ranges")
    parser.add_argument("--firewall-ports", action="store_true", help="Scan only ports found in firewalls")
    parser.add_argument("--max-scan-ports", type=int, default=500, help="Cap for firewall port expansion")
    parser.add_argument("--list-orgs", action="store_true", help="List accessible organizations")
    parser.add_argument("--list-projects", action="store_true", help="List accessible projects")
    args = parser.parse_args()

    scanner = FirewallScanner(svc_account_path=args.svc)
    
    if args.list_orgs:
        orgs = scanner.get_organizations()
        for o in orgs: console.print(f"[green]Org ID: {o['id']}[/green] - {o['displayName']}")
        return

    if args.list_projects:
        projects = scanner.list_projects()
        for p in projects: console.print(f"[cyan]{p}[/cyan]")
        return

    scanner.run(args)

if __name__ == "__main__":
    main()
