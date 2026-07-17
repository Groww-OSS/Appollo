import argparse
import asyncio
import concurrent.futures
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta
import banner  
import pandas as pd
from dotenv import load_dotenv
from rich import print
from modules.aws import run_aws_scan
from modules.cloudflare import Cloudflare
from modules.cloud_storage import run_cloud_storage_scan, run_s3_inventory_scan
from modules.cert_transparency import run_cert_transparency_scan
from modules.dangling_dns import get_dangling_dns_dict, save_dangling_to_csv
from modules.dast import run_dast
from modules.vendor import get_vendor, get_vendor_targets, get_root_domains, update_last_scanned
from modules.email_security import run_email_security
from modules.gcp import GCP
from modules.godaddy import GoDaddy
from modules import endpoints, firewall
from modules.nuclei import run_nuclei, update_nuclei_templates
from modules.portscan import PortScan
from modules.ssl_checker import extract_tls_info, verify_with_crtsh
from modules.subdomain import run_subdomain_enum
from modules.technology import BuiltWithScanner
from modules.wayback import GAU
from system.db import MongoDB
from system import utils as system

logger = logging.getLogger(__name__)

# Constants
PREV_PORT_SCAN_CSV = "/etc/config/previous_port_scan.csv"
PREV_FIREWALL_CSV = "/etc/config/previous_firewall_port_scan.csv"
PREV_EXPOSED_CSV = "/etc/config/previous_exposed_services.csv"
PREV_WAYBACK_CSV = "/etc/config/previous_wayback_results.csv"
PREV_DANGLING_CSV = "/etc/config/previous_dangling_dns.csv"

# naabu flag for non-proxied, non-cloud targets.
# nmap's top-1000 list (statistically ranked by real-world frequency) is far
# more precise than a raw range like 1-9999 and avoids scanning thousands of
# obscure ports that produce noise on restricted networks.
PORT_SCAN_FLAGS = "-top-ports 1000"

DOMAIN_PATTERN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
)


class Appollo:
    def __init__(self, args) -> None:
        load_dotenv(args.env)
        self.args = args
        self.jira = system.get_jira_client()
        self.jira_project = os.getenv("JIRA_PROJECT", "SEC")
        self.db = MongoDB()
        self.label = "periodic-scan"

    # Shared helpers

    def _jira_server(self) -> str:
        return os.environ.get("JIRA_SERVER", "").rstrip("/")

    def _jira_link(self, issue) -> str:
        """Build a Slack-formatted Jira link from an issue object."""
        if not issue or not hasattr(issue, 'key'):
            return ""
        srv = self._jira_server()
        return f"<{srv}/browse/{issue.key}|{issue.key}>" if srv else issue.key

    def _alert_finding(self, summary: str, description: str,
                       label: str, hash_value: str = "",
                       severity: str = "high") -> str:
        """Create Jira ticket + dedup hash, return a Slack-formatted link.

        If *hash_value* is provided the issue is only created when the hash
        is new.  Returns the Jira link string (or empty string on skip).
        After each call, self._last_jira_key and self._last_jira_url are set
        (None if skipped or failed) so callers can store the key in MongoDB.
        """
        self._last_jira_key: str | None = None
        self._last_jira_url: str | None = None
        if hash_value and system.check_if_hash_exists(hash_value):
            return ""
        try:
            issue = system.create_jira_issue(
                self.jira, self.jira_project, summary, description, "Bug", label,
                severity=severity,
            )
            link = self._jira_link(issue)
            key  = getattr(issue, 'key', None)
            if key:
                self._last_jira_key = key
                self._last_jira_url = f"{self._jira_server()}/browse/{key}"
            if hash_value:
                system.add_hash_to_db(hash_value)
            return link
        except Exception as e:
            logger.warning("Failed to create Jira issue for %s: %s", summary, e)
            return ""

    def _get_targets(self, unpack="dns"):
        """Retrieve scan targets from inventory or CLI.

        *unpack* controls which element of get_all_targets() to return:
          - 'ip_domain' -> (ip_domain_dict, domain_list)
          - 'dns'       -> list of dns_targets
          - 'combined'  -> list of combined_targets
        """
        if self.args.complete_scan:
            try:
                ip_dom, dns_t, combined = system.get_all_targets()
            except Exception as e:
                print(f"[bold red][-] Error getting targets: {e}[/bold red]")
                return [] if unpack != "ip_domain" else ({}, [])

            if unpack == "ip_domain":
                return (ip_dom or {}), list(combined) if combined else []
            if unpack == "dns":
                return list(dns_t) if dns_t else []
            return list(combined) if combined else []

        if self.args.target:
            if unpack == "ip_domain":
                ip_dom, doms = {}, []
                targets = self._read_target_list()
                for h in targets:
                    try:
                        ip_dom[h] = socket.gethostbyname(h)
                        doms.append(h)
                    except Exception:
                        pass
                return ip_dom, doms
            return self._read_target_list()

        return [] if unpack != "ip_domain" else ({}, [])

    def _read_target_list(self) -> list:
        """Return a list of targets — either from a file or a single CLI value."""
        t = self.args.target
        if os.path.isfile(t):
            with open(t, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        if t and DOMAIN_PATTERN.match(t):
            return [t]
        return []

    # Scan methods

    def _run_inventory_update(self) -> None:
        self.label = "dns_records"
        start = datetime.now()
        GCP().run(max_workers=50)
        workers = getattr(self.args, "workers", None) or 10
        workers = max(1, min(int(workers), 50))
        try:
            run_aws_scan(max_workers=workers, regions=None, lightweight=True)
        except Exception as e:
            logger.warning("AWS inventory as part of update-inventory failed: %s", e)
            print(
                f"[bold yellow][!] AWS inventory update skipped (Cloudflare/GCP data still refreshed): "
                f"{e}[/bold yellow]"
            )

        try:
            run_s3_inventory_scan()
        except Exception as e:
            logger.warning("S3 inventory scan as part of update-inventory failed: %s", e)
            print(f"[bold yellow][!] S3 bucket check skipped: {e}[/bold yellow]")

        dns_col = self.db.set_collection("Prod DNS Records")
        ip_col = self.db.set_collection("Prod IP Records")
        threshold = start - timedelta(minutes=5)

        new_dns = list(dns_col.find({"timestamp": {"$gt": threshold}, "status": "active"}))
        new_ips = list(ip_col.find({"timestamp": {"$gt": threshold}, "status": "active"}))

        if not new_dns and not new_ips:
            print("[bold yellow][+] No inventory changes[/bold yellow]")
            system.send_slack_alert("Inventory update completed. No changes detected.")
            return

        deltas = self._build_inventory_deltas(new_dns, new_ips)
        if not deltas:
            print("[bold yellow][+] No public inventory changes[/bold yellow]")
            system.send_slack_alert("Inventory update completed. No public asset changes detected.")
            return

        df = pd.DataFrame(deltas)
        mapping = {
            'zone_name': 'Zone Name', 'name': 'Name', 'type': 'Type',
            'content': 'Content', 'resource_type': 'Resource Type', 'source': 'Source',
        }
        jira_data = df.rename(columns=mapping)
        if jira_data.empty:
            system.send_slack_alert("Inventory update completed. No public asset changes detected.")
            return

        csv_path = "dns-records.csv"
        jira_data.to_csv(csv_path, index=False)
        system.upload_file_to_slack(csv_path, f"Inventory Delta: {len(jira_data)} public records")

        j_table = "|| Zone Name || Name || Type || Content || Resource Type || Source ||\n"
        for _, row in jira_data.iterrows():
            j_table += (
                f"| {row['Zone Name']} | {row['Name']} | {row['Type']} "
                f"| {row['Content']} | {row['Resource Type']} | {row['Source']} |\n"
            )

        if len(j_table) > 32000:
            issue = system.create_jira_issue(
                self.jira, self.jira_project, "Inventory Update", "See CSV.", "Bug", self.label,
                severity="medium",
            )
            self.jira.add_attachment(issue=issue.key, attachment=csv_path)
        else:
            issue = system.create_jira_issue(
                self.jira, self.jira_project, "Inventory Update", j_table, "Bug", self.label,
                severity="medium",
            )

        link = self._jira_link(issue)
        msg = f"Inventory Delta detected. {len(jira_data)} public record(s) changed."
        if link:
            msg += f"\nJira: {link}"
        system.send_slack_alert(msg)

    def _build_inventory_deltas(self, new_dns, new_ips) -> list:
        deltas = []
        for r in new_dns:
            rtype = (r.get("type") or "").upper()
            src = r.get("source", "")
            # A/AAAA always included; also include AWS CNAME endpoints (LBs, RDS, EKS, etc.)
            if rtype not in ("A", "AAAA") and not (rtype == "CNAME" and str(src).upper() == "AWS"):
                continue
            content = str(r.get("content", ""))
            if system.is_private_ip(content):
                continue
            deltas.append(r)

        for r in new_ips:
            src = r.get("source")
            if src == "GCP":
                for res, ips in r.get("resource_types", {}).items():
                    for ip in ips:
                        if system.is_private_ip(ip):
                            continue
                        deltas.append({
                            "zone_name": r.get("project_id"), "name": "N/A",
                            "type": "IP", "content": ip,
                            "resource_type": res, "source": src,
                        })
            elif src == "Cloudflare":
                for d in r.get("records", []):
                    for ip_d in d.get("ip", []):
                        ip_val = ip_d.get("ip", "")
                        if system.is_private_ip(ip_val):
                            continue
                        deltas.append({
                            "zone_name": d.get("domain"), "name": ip_d.get("name"),
                            "type": ip_d.get("type"), "content": ip_val,
                            "resource_type": "cloudflare_ip", "source": src,
                        })
            elif src == "AWS":
                aid = r.get("account_id") or ""
                for res, ips in (r.get("resource_types") or {}).items():
                    for ip in ips or []:
                        if system.is_private_ip(ip):
                            continue
                        deltas.append({
                            "zone_name": aid,
                            "name": "N/A",
                            "type": "IP",
                            "content": ip,
                            "resource_type": res,
                            "source": src,
                        })
        return deltas




    def _run_ssl_checker(self) -> None:
        self.label = "ssl_scan"
        targets = self._get_targets(unpack="dns")
        if not targets and not self.args.target:
            return

        # Add every bare public IP in inventory that has no DNS hostname.
        # tlsx only ever probes port 443, so a live reachability check on 443
        # (rather than relying on a possibly-stale Prod Firewall Port record)
        # decides whether it's worth handing to tlsx.
        if not self.args.target:
            try:
                dns_set = set(targets)
                _, _, combined = system.get_all_targets()
                candidate_ips = [t for t in combined if t not in dns_set and not system.is_private_ip(t)]

                def _has_443(ip: str) -> bool:
                    try:
                        socket.create_connection((ip, 443), timeout=5).close()
                        return True
                    except (socket.error, socket.gaierror, socket.timeout, ConnectionRefusedError):
                        return False

                if candidate_ips:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                        futs = {ex.submit(_has_443, ip): ip for ip in candidate_ips}
                        for f in concurrent.futures.as_completed(futs):
                            if f.result():
                                targets.append(futs[f])
            except Exception as e:
                logger.warning("SSL: could not enrich targets with bare IPs: %s", e)

        if not targets:
            return

        ssl_col = self.db.set_collection("Prod SSL Scans")
        print(f"[bold blue][+] Starting SSL check for {len(targets)} domains[/bold blue]")

        tls = extract_tls_info(targets)
        if not tls or not isinstance(tls, list):
            system.send_slack_alert("SSL Checker finished with no results.")
            return

        # Cross-check every result against crt.sh CT logs for double verification.
        # This catches rogue/MITM certs that tlsx alone would miss.
        print(f"[bold blue][+] Cross-checking {len(tls)} certs against crt.sh...[/bold blue]")
        verify_with_crtsh(tls)

        # ssl_checker.py normalises hostnames to bare domain (no :PORT),
        # so this comparison is valid against the targets list.
        responded = {info.get("hostname", "") for info in tls if info and isinstance(info, dict)}
        missed = [t for t in targets if t not in responded]

        print(f"[bold green][+] SSL scan returned {len(tls)}/{len(targets)} results.[/bold green]")
        if missed:
            print(f"[bold yellow][!] {len(missed)} domains did not respond[/bold yellow]")

        t_links = []
        saved = 0

        for idx, info in enumerate(tls, 1):
            if not info or not isinstance(info, dict):
                continue
            try:
                hostname      = info.get("hostname", "")
                expiry        = info.get("not_after", "")
                days          = int(info.get("days_until_expiry", 0) or 0)
                is_expired    = bool(info.get("expired", False))
                ct_verified   = info.get("ct_verified")   # bool or None
                ct_ca_trusted = bool(info.get("ct_ca_trusted", True))
                ct_wildcard   = bool(info.get("ct_wildcard", False))
            except (TypeError, ValueError):
                continue

            if not hostname:
                continue

            if is_expired:
                status_msg = f"EXPIRED {abs(days)} days ago"
            else:
                status_msg = f"expires in {days} days"

            ct_tag = "" if ct_verified is None else (" [CT:✓]" if ct_verified else " [CT:✗]")
            print(f"[dim]  [{idx}/{len(tls)}] {hostname} — {status_msg}{ct_tag}[/dim]")

            ssl_col.update_one(
                {"hostname": hostname},
                {"$set": {
                    "not_before":    info.get("not_before", ""),
                    "not_after":     expiry,
                    "subject_cn":    info.get("subject_cn", ""),
                    "issuer_org":    info.get("issuer_org", ""),
                    "days_until_expiry": days,
                    "expired":       is_expired,
                    "ct_verified":   ct_verified,
                    "ct_ca_trusted": ct_ca_trusted,
                    "ct_wildcard":   ct_wildcard,
                    "last_updated":  datetime.utcnow(),
                }},
                upsert=True,
            )
            saved += 1

            # --- Expiry alerts (same as before) ---
            if days <= 15:
                h = system.calculate_hash(f"{hostname}{expiry}")
                if is_expired:
                    summary = f"[SSL] {hostname} EXPIRED"
                    body = f"{hostname} certificate expired {abs(days)} days ago (expiry: {expiry})."
                else:
                    summary = f"[SSL] {hostname} expiring soon"
                    body = f"{hostname} certificate expires in {days} days (expiry: {expiry})."
                link = self._alert_finding(summary, body, self.label, hash_value=h,
                                           severity="high" if is_expired else "medium")
                if link:
                    t_links.append(link)
                if self._last_jira_key:
                    try:
                        ssl_col.update_one(
                            {"hostname": hostname},
                            {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                        )
                    except Exception:
                        pass


        retired_ssl = 0
        for doc in ssl_col.find({"status": {"$ne": "inactive"}}, {"_id": 1, "hostname": 1}):
            if doc.get("hostname") not in responded:
                ssl_col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"status": "inactive", "remediated_at": datetime.utcnow()}},
                )
                retired_ssl += 1
        if retired_ssl:
            print(f"[bold green][+] SSL: {retired_ssl} stale hostname(s) marked inactive[/bold green]")

        print(f"[bold green][+] Saved {saved}/{len(tls)} SSL results to MongoDB.[/bold green]")
        msg = f"SSL Checker completed ({saved} saved). {'Alerts sent.' if t_links else 'No expiries.'}"
        if t_links:
            msg += f"\nJira: {', '.join(t_links)}"
        system.send_slack_alert(msg)

    def _run_port_scan(self) -> None:
        self.label = "port_scan"
        ip_dom, doms = self._get_targets(unpack="ip_domain")
        if not doms:
            # Called as a supplement (e.g. from firewall scan) — fetch full inventory
            try:
                ip_dom, _, combined = system.get_all_targets()
                doms = [t for t in combined if not system.is_private_ip(t)]
            except Exception as e:
                print(f"[bold red][-] Port scan: failed to fetch inventory targets: {e}[/bold red]")
                system.send_slack_alert(f"Port scan failed: could not fetch inventory targets. {e}")
                return
        if not doms:
            system.send_slack_alert("Port scan completed. No targets found in inventory.")
            return

        # Cloudflare-proxied records resolve to CF's edge IPs, not the origin.
        # Scanning them always shows CF's own open ports → primary false-positive source.
        # This is a cheap pre-filter; the prober confirmation below catches
        # anything this DNS-based check misses (stale/missing proxied flags).
        proxied_names = self._get_proxied_names()
        skipped = [d for d in doms if d in proxied_names]
        scan_targets = [d for d in doms if d not in proxied_names]

        if skipped:
            print(f"[bold yellow][~] Skipping {len(skipped)} Cloudflare-proxied target(s) (CDN edge, not origin)[/bold yellow]")

        port_col = self.db.set_collection("Prod Port Scans")
        raw_results = {}
        with concurrent.futures.ThreadPoolExecutor() as ex:
            futs = {ex.submit(self._scan_ports, d): d for d in scan_targets}
            for f in concurrent.futures.as_completed(futs):
                d = futs[f]
                raw_results[d] = {'ip': ip_dom.get(d, ''), 'ports': f.result() or []}

        results = {d: {'ip': data['ip'], 'ports': data['ports'], 'unconfirmed_ports': []} for d, data in raw_results.items()}

        for d, data in results.items():
            port_col.update_one({"domain": d}, {"$set": data}, upsert=True)

        scanned_domains = set(results.keys())
        retired_ports = 0
        for doc in port_col.find({"status": {"$ne": "inactive"}}, {"_id": 1, "domain": 1}):
            if doc.get("domain") not in scanned_domains:
                port_col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"status": "inactive", "remediated_at": datetime.utcnow()}},
                )
                retired_ports += 1
        if retired_ports:
            print(f"[bold green][+] Port scan: {retired_ports} stale host(s) marked inactive[/bold green]")

        prev = system.read_from_csv(PREV_PORT_SCAN_CSV)
        delta = system.get_delta_ports(results, prev)
        t_links = []

        if delta:
            system.save_port_scan_to_csv(delta, PREV_PORT_SCAN_CSV)
            for d, data in delta.items():
                ip, pts = data['ip'], ",".join(map(str, data['ports']))
                if system.is_private_ip(ip):
                    continue
                h = system.calculate_hash([d, ip, pts])
                link = self._alert_finding(
                    f"[Ports] {d} — new open ports: {pts}",
                    f"*Target:* {d}\n*IP:* {ip}\n*Open Ports:* {pts}\n*Scan type:* Port Scan",
                    self.label, hash_value=h, severity="medium",
                )
                if link:
                    t_links.append(link)
                if self._last_jira_key:
                    try:
                        port_col.update_one(
                            {"domain": d},
                            {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                        )
                    except Exception:
                        pass

        msg = f"Port scan completed. {'New ports.' if delta else 'No new ports.'}"
        if t_links:
            msg += f"\nJira: {', '.join(t_links)}"
        system.send_slack_alert(msg)

    def _get_proxied_names(self) -> set:
        """Return hostnames whose DNS records are Cloudflare-proxied.

        Proxied records point to CF's edge IPs rather than the origin server,
        so port-scanning them reflects Cloudflare's infrastructure, not ours.
        """
        proxied = set()
        try:
            col = self.db.set_collection("Prod DNS Records")
            for doc in col.find({"proxied": True, "status": "active"}, {"name": 1}):
                name = (doc.get("name") or "").rstrip(".")
                if name:
                    proxied.add(name)
        except Exception as e:
            print(f"[bold yellow][~] Could not fetch proxied names: {e}[/bold yellow]")
        return proxied

    def _scan_ports(self, host: str) -> list:
        return PortScan().run(host, PORT_SCAN_FLAGS)

    # Exposed services helpers

    @staticmethod
    def _probe_http(ip: str, port: int, timeout: int = 8) -> dict:
        """HTTP GET probe a single ip:port, following redirects.
        Detects auth walls by checking the final URL and response body
        for login/SSO patterns — a 200 after a redirect to /login is NOT accessible.
        """
        AUTH_URL_PATTERNS = (
            '/login', '/signin', '/sign-in', '/auth/', '/oauth',
            '/sso', '/saml', '/idp', '/adfs', '/oidc', '/cas/',
            '/realms/', '/connect/authorize',
            'accounts.google.com', 'login.microsoftonline.com',
            'okta.com', 'auth0.com', 'onelogin.com', 'pingidentity.com',
        )
        AUTH_BODY_PATTERNS = (
            b'type="password"', b"type='password'",
            b'name="password"', b"name='password'",
            b'<title>sign in', b'<title>log in', b'<title>login',
            b'please sign in', b'please log in',
            b'authentication required', b'access denied',
            b'session expired', b'you are not authorized',
        )

        proto = "https" if port in (443, 8443, 4443, 9443) else "http"
        url   = f"{proto}://{ip}:{port}/"
        if not url.startswith(("https://", "http://")):
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            kwargs: dict = {"timeout": timeout}
            if proto == "https":
                kwargs["context"] = ctx
            resp = urllib.request.urlopen(req, **kwargs)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected
            code      = resp.status
            final_url = resp.url.lower()

            # Auth wall via redirect destination
            auth_redirect = any(p in final_url for p in AUTH_URL_PATTERNS)

            # Auth wall via body content (first 6 KB, lowercased)
            auth_in_body = False
            if not auth_redirect:
                try:
                    body = resp.read(6144).lower()
                    auth_in_body = any(p in body for p in AUTH_BODY_PATTERNS)
                except Exception:
                    pass

            is_auth = auth_redirect or auth_in_body
            accessible = (200 <= code < 400) and not is_auth
            auth_wall  = is_auth or code in (401, 403, 407)

            return {
                "port":        port,
                "proto":       proto,
                "status":      code,
                "final_url":   resp.url if resp.url != url else None,
                "accessible":  accessible,
                "auth_wall":   auth_wall,
            }
        except urllib.error.HTTPError as e:
            auth_wall = e.code in (401, 403, 407)
            return {"port": port, "proto": proto, "status": e.code,
                    "accessible": False, "auth_wall": auth_wall, "final_url": None}
        except Exception:
            return {"port": port, "proto": proto, "status": 0,
                    "accessible": False, "auth_wall": False, "final_url": None}

    @staticmethod
    def _enrich_ip_context(ip: str, db) -> dict:
        """Look up IP in inventory to determine resource type and DNS presence.
        Returns resource_type (e.g. load_balancer, vm_external) and whether
        the IP appears in Cloudflare DNS (= definitely internet-facing)."""
        resource_type = "unknown"
        in_dns        = False
        try:
            ip_rec = db.set_collection("Prod IP Records").find_one(
                {f"resource_types.{k}": ip for k in
                 ["load_balancer", "vm_external", "static_ip", "cloud_run",
                  "cloud_nat", "gke_cluster", "vpn_gateway", "cloud_sql"]},
                {"resource_types": 1},
            )
            # simpler query: any doc that contains the IP in its resource_types values
            ip_rec = db.set_collection("Prod IP Records").find_one(
                {"$or": [{"resource_types.load_balancer": ip},
                         {"resource_types.vm_external":   ip},
                         {"resource_types.static_ip":     ip},
                         {"resource_types.cloud_run":     ip},
                         {"resource_types.gke_cluster":   ip}]},
                {"resource_types": 1},
            )
            if ip_rec:
                rt = ip_rec.get("resource_types", {})
                for rtype, ips in rt.items():
                    if ip in (ips if isinstance(ips, list) else []):
                        resource_type = rtype
                        break
        except Exception:
            pass

        try:
            dns_rec = db.set_collection("Prod DNS Records").find_one(
                {"content": ip, "source": {"$regex": "cloudflare", "$options": "i"}},
                {"_id": 1},
            )
            in_dns = dns_rec is not None
        except Exception:
            pass

        return {"resource_type": resource_type, "in_cloudflare_dns": in_dns}

    def _run_exposed_services_scan(self) -> None:
        """
        Direct naabu top-1000 scan against all public inventory IPs.
        Enriches each result with:
          - HTTP probes on open web ports (status code, accessible flag)
          - IP context from inventory (resource_type, Cloudflare DNS presence)
          - exposure_class: 'public' | 'auth_wall' | 'tcp_only'
        """
        self.label = "exposed_services_scan"

        if self.args.target:
            targets = self._read_target_list()
        else:
            try:
                _, _, combined = system.get_all_targets()
                targets = [t for t in combined if not system.is_private_ip(t)]
            except Exception as e:
                print(f"[bold red][-] Exposed services scan: failed to fetch inventory: {e}[/bold red]")
                system.send_slack_alert(f"Exposed services scan failed: could not fetch inventory. {e}")
                return

        if not targets:
            print("[bold yellow][!] Exposed services scan: no targets.[/bold yellow]")
            system.send_slack_alert("Exposed services scan completed. No targets found in inventory.")
            return

        print(f"[bold blue][*] Exposed services scan: naabu top-1000 on {len(targets)} target(s)[/bold blue]")

        naabu_res = firewall._naabu_scan_batch(targets, top_ports=1000)

        raw = {
            host: ports
            for host, ports in naabu_res.items()
            if ports and not system.is_private_ip(host)
        }

        # HTTP probing
        HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 9090, 4443, 9443, 5000, 7080}
        print(f"[bold blue][*] Exposed services: HTTP probing {len(raw)} host(s)…[/bold blue]")

        results = {}
        db = self.db

        def _enrich_host(item):
            host, ports = item
            web_ports = [p for p in ports if p in HTTP_PORTS]
            probes = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(web_ports), 8)) as ex:
                futures = {ex.submit(self._probe_http, host, p): p for p in web_ports}
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        probes.append(fut.result())
                    except Exception:
                        pass

            publicly_accessible = any(p["accessible"] for p in probes)
            has_auth_wall       = any(p["auth_wall"]   for p in probes) and not publicly_accessible

            if publicly_accessible:
                exposure_class = "public"
            elif has_auth_wall:
                exposure_class = "auth_wall"
            else:
                exposure_class = "tcp_only"

            ctx = self._enrich_ip_context(host, db)

            # load_balancer and cloud_run are always internet-facing by design
            if ctx["resource_type"] in ("load_balancer", "cloud_run") and exposure_class == "tcp_only":
                exposure_class = "auth_wall"  # reachable, just no plain HTTP

            return host, {
                "ip":                 host,
                "ports":              ports,
                "port_count":         len(ports),
                "http_probes":        probes,
                "publicly_accessible": publicly_accessible,
                "has_auth_wall":      has_auth_wall,
                "exposure_class":     exposure_class,
                "resource_type":      ctx["resource_type"],
                "in_cloudflare_dns":  ctx["in_cloudflare_dns"],
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            for host, data in ex.map(_enrich_host, raw.items()):
                results[host] = data

        public_count   = sum(1 for d in results.values() if d["exposure_class"] == "public")
        authwall_count = sum(1 for d in results.values() if d["exposure_class"] == "auth_wall")
        print(f"[bold green][+] Exposed services: {public_count} public, {authwall_count} auth-walled, "
              f"{len(results) - public_count - authwall_count} TCP-only[/bold green]")

        # Persist to DB
        try:
            col = self.db.set_collection("Prod Exposed Services")
            for host, data in results.items():
                col.update_one(
                    {"ip": host},
                    {"$set": {**data, "last_updated": datetime.utcnow()}},
                    upsert=True,
                )
        except Exception as e:
            print(f"[bold yellow][~] DB save failed: {e}[/bold yellow]")

        prev  = system.read_from_csv(PREV_EXPOSED_CSV)
        delta = system.get_delta_ports(
            {h: {"ports": d["ports"]} for h, d in results.items()}, prev
        )
        t_links = []

        if delta:
            system.save_port_scan_to_csv(delta, PREV_EXPOSED_CSV)
            for host, data in delta.items():
                exposure = results.get(host, {}).get("exposure_class", "unknown")
                if exposure not in ("public", "auth_wall"):
                    continue  # skip alerting on TCP-only / internal-only
                pts  = ",".join(map(str, data["ports"]))
                h    = system.calculate_hash([host, pts])
                if system.check_if_hash_exists(h):
                    continue
                link = self._alert_finding(
                    f"[Exposed/{exposure}] {host} open ports",
                    f"Host {host} ({exposure}) has newly detected open ports: {pts}",
                    self.label, hash_value=h, severity="high" if exposure == "public" else "medium",
                )
                if link:
                    t_links.append(link)
                if self._last_jira_key:
                    try:
                        col.update_one(
                            {"ip": host},
                            {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                        )
                    except Exception:
                        pass

        public_new = sum(1 for h in delta if results.get(h, {}).get("exposure_class") == "public")
        msg = (f"Exposed services scan done. "
               f"{public_count} publicly accessible, {authwall_count} auth-walled. "
               f"{f'New: {public_new} public.' if delta else 'No new changes.'}")
        if t_links:
            msg += f"\nJira: {', '.join(t_links)}"
        system.send_slack_alert(msg)

        print("[bold blue][*] Exposed services: running external Lambda probe on public/auth_wall hosts…[/bold blue]")
        try:
            exposure_col = self.db.set_collection("Prod IP Exposure")
            by_host = run_external_probe(col, hosts=list(results.keys()), exposure_col=exposure_col)
            reachable = sum(1 for probes in by_host.values() if any(p.get("reachable") for p in probes))
            print(f"[bold green][+] External probe: {reachable}/{len(by_host)} hosts confirmed internet-reachable[/bold green]")
        except Exception as e:
            print(f"[bold yellow][~] External probe skipped: {e}[/bold yellow]")

    def _run_external_probe_scan(self) -> None:
        """
        Calls the AWS Lambda external prober to confirm true internet reachability
        for services classified as public/auth_wall. Updates Prod Exposed Services
        with external_probe results and externally_reachable flag.
        """
        self.label = "external_probe_scan"
        print("[bold blue][*] External probe scan: confirming internet reachability via Lambda…[/bold blue]")

        hosts = self._read_target_list() if self.args.target else None

        try:
            col     = self.db.set_collection("Prod Exposed Services")
            by_host = run_external_probe(col, hosts=hosts)
        except Exception as e:
            print(f"[bold red][-] External probe scan failed: {e}[/bold red]")
            system.send_slack_alert(f"External probe scan failed: {e}")
            return
        total     = len(by_host)
        reachable = sum(1 for probes in by_host.values() if any(p.get("reachable") for p in probes))
        msg = (
            f"External probe scan done. "
            f"{reachable}/{total} hosts confirmed internet-reachable from outside VPC."
        )
        system.send_slack_alert(msg)

    def _run_probe_all_scan(self) -> None:
        """
        Probes every public-facing host across all collections (Prod Exposed Services,
        Prod Port Scans) via the external Lambda prober and writes results back.
        """
        self.label = "probe_all_scan"
        print("[bold blue][*] Probe-all scan: probing all public hosts via Lambda…[/bold blue]")
        try:
            summary = probe_all(self.db)
        except Exception as e:
            print(f"[bold red][-] Probe-all scan failed: {e}[/bold red]")
            system.send_slack_alert(f"Probe-all scan failed: {e}")
            return
        msg = (
            f"Probe-all scan done. "
            f"{summary['reachable']}/{summary['total']} hosts confirmed internet-reachable. "
            f"{summary['unreachable']} blocked/unreachable, {summary['skipped']} skipped (no ports)."
        )
        system.send_slack_alert(msg)


    def _run_firewall_scan(self) -> None:
        self.label = "firewall_port_scan"

        if self.args.target:
            targets = self._read_target_list()
        else:
            try:
                _, _, combined = system.get_all_targets()
                targets = [t for t in combined if not system.is_private_ip(t)]
            except Exception as e:
                print(f"[bold red][-] Firewall scan: failed to fetch inventory targets: {e}[/bold red]")
                system.send_slack_alert(f"Firewall scan failed: could not fetch inventory targets. {e}")
                return

        if not targets:
            print("[bold yellow][!] Firewall scan: no targets.[/bold yellow]")
            system.send_slack_alert("Firewall scan completed. No targets found in inventory.")
            return

        print(f"[bold blue][*] Firewall scan: {len(targets)} targets[/bold blue]")

        # GCP and AWS run in parallel — independent I/O, no shared state.
        # Each uses cloud APIs for firewall/SG rule context, then confirms
        # with naabu batch port scans.
        gcp_scanner = firewall.FirewallScanner(svc_account_path=os.getenv('SVC_ACCOUNT'))
        aws_scanner = firewall.AWSFirewallScanner()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            gcp_fut = ex.submit(gcp_scanner.run, self.args)
            aws_fut = ex.submit(aws_scanner.run)
            gcp_result = gcp_fut.result()
            gcp_raw, gcp_risky_rules = gcp_result if gcp_result else ([], [])
            aws_result = aws_fut.result()
            aws_raw, aws_risky_rules = aws_result if aws_result else ([], [])

        # Remaining inventory targets not covered by GCP/AWS get top-100 naabu scan.
        covered_ips = {r["ip"] for r in gcp_raw + aws_raw}
        inv_scanner = firewall.InventoryScanner()
        inv_raw = inv_scanner.run(exclude_ips=covered_ips, target_override=targets) or []

        raw = gcp_raw + aws_raw + inv_raw

        fw_col = self.db.set_collection("Prod Firewall Port")
        for r in raw:
            if r.get("instance") != "N/A":
                try:
                    fw_col.update_one(
                        {"project": r["project"], "instance": r["instance"], "ip": r["ip"]},
                        {"$set": {"confirmed_open_ports": r["confirmed_open_ports"]}},
                    )
                except Exception:
                    pass

        res = {
            r["instance"]: {
                "project": r["project"], "ip": r["ip"],
                "ports": r["confirmed_open_ports"],
            }
            for r in raw
            if r.get("instance") != "N/A" and not system.is_private_ip(r.get("ip", ""))
        }

        prev = system.read_from_csv(PREV_FIREWALL_CSV)
        delta = system.get_delta_ports(res, prev)
        t_links = []

        if delta:
            system.save_port_scan_to_csv(delta, PREV_FIREWALL_CSV)
            for d, data in delta.items():
                ip = data['ip']
                if system.is_private_ip(ip):
                    continue

                pts = ",".join(map(str, sorted(data.get('ports', []))))
                if pts:
                    h = system.calculate_hash([d, ip, pts])
                    link = self._alert_finding(
                        f"[Firewall] {d} open ports",
                        f"Instance {d} ({ip}) has open ports: {pts}",
                        self.label, hash_value=h, severity="high",
                    )
                    if link:
                        t_links.append(link)
                    if self._last_jira_key:
                        try:
                            self.db.set_collection("Prod Firewall Port").update_one(
                                {"instance": d, "ip": ip},
                                {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                            )
                        except Exception:
                            pass

        # Alert on risky GCP firewall rules regardless of naabu confirmation.
        for rule_finding in (gcp_risky_rules or []):
            h = system.calculate_hash([rule_finding["project"], rule_finding["rule"], rule_finding["ports"]])
            if system.check_if_hash_exists(h):
                continue
            link = self._alert_finding(
                f"[Firewall Rule] {rule_finding['rule']} exposes {rule_finding['ports']} to internet",
                f"GCP project {rule_finding['project']}: firewall rule '{rule_finding['rule']}' "
                f"allows {rule_finding['proto'].upper()} port(s) {rule_finding['ports']} from 0.0.0.0/0.",
                self.label, hash_value=h, severity="high",
            )
            if link:
                t_links.append(link)

        # Alert on risky AWS security group rules regardless of naabu confirmation.
        for rule_finding in (aws_risky_rules or []):
            h = system.calculate_hash([rule_finding["account"], rule_finding["sg"], rule_finding["ports"]])
            if system.check_if_hash_exists(h):
                continue
            link = self._alert_finding(
                f"[AWS SG] {rule_finding['sg']} exposes {rule_finding['ports']} to internet",
                f"AWS account {rule_finding['account']} / {rule_finding['region']}: "
                f"security group '{rule_finding['sg']}' allows port(s) {rule_finding['ports']} from 0.0.0.0/0.",
                self.label, hash_value=h, severity="high",
            )
            if link:
                t_links.append(link)

        msg = f"Firewall Port Scan completed. {'New ports found.' if delta else 'No new ports.'}"
        if t_links:
            msg += f"\nJira: {', '.join(t_links)}"
        system.send_slack_alert(msg)

        # Port scan supplements the firewall scan — naabu sweep of DNS hostnames
        print("[bold blue][*] Running port scan supplement on DNS targets...[/bold blue]")
        self._run_port_scan()

    def _run_wayback_scan(self) -> None:
        self.label = "wayback_scan"
        doms = set(self._get_targets(unpack="dns"))
        if not doms:
            system.send_slack_alert("Wayback scan completed. No targets found.")
            return

        wayback_res = asyncio.run(GAU().run(doms)) or {}
        prev = system.read_from_csv(PREV_WAYBACK_CSV)
        delta = system.get_delta_links(wayback_res, prev)
        coll = self.db.set_collection("Prod Wayback Results")
        t_links = []

        if delta:
            system.save_wayback_to_csv(delta, PREV_WAYBACK_CSV)
            for d, links in delta.items():
                clean = [l.strip() for l in links if l.strip()]
                if not clean:
                    continue
                coll.update_one(
                    {"domain": d},
                    {"$set": {"urls": clean, "last_updated": datetime.utcnow()}},
                    upsert=True,
                )
                h = system.calculate_hash(f"{d}{sorted(clean)}")
                if system.check_if_hash_exists(h):
                    continue

                url_table = f"New URLs discovered for *{d}* ({len(clean)} total):\n\n|| URL ||\n"
                for u in clean:
                    url_table += f"| {u} |\n"

                if len(url_table) > 32000:
                    csv_file = f"wayback-{d.replace('.', '_')}.csv"
                    pd.DataFrame(clean, columns=["URL"]).to_csv(csv_file, index=False)
                    issue = system.create_jira_issue(
                        self.jira, self.jira_project,
                        f"[Wayback] {d}", f"New URLs for {d} ({len(clean)} URLs). See CSV.",
                        'Bug', self.label,
                    )
                    if issue and hasattr(issue, 'key'):
                        self.jira.add_attachment(issue=issue.key, attachment=csv_file)
                else:
                    issue = system.create_jira_issue(
                        self.jira, self.jira_project,
                        f"[Wayback] {d}", url_table, 'Bug', self.label,
                    )

                link = self._jira_link(issue)
                if link:
                    system.add_hash_to_db(h)
                    t_links.append(link)

        msg = f"Wayback scan completed. {'New URLs found.' if delta else 'No new URLs.'}"
        if t_links:
            msg += f"\nJira: {', '.join(t_links)}"
        system.send_slack_alert(msg)

    def _run_tech_scan(self) -> None:
        self.label = "tech_scan"
        doms = self._get_targets(unpack="dns")
        if not doms:
            return

        scan_result = BuiltWithScanner(doms).scan()
        builtwith = (scan_result[0] if isinstance(scan_result, tuple) else scan_result) or {}
        coll = self.db.set_collection("Prod Technology Scans")
        alerted = False

        for d, techs in builtwith.items():
            coll.update_one(
                {"domain": d},
                {"$set": {"technologies": techs, "source": "BuiltWith"}},
                upsert=True,
            )
            h = system.calculate_hash(techs)
            if not system.check_if_hash_exists(h):
                system.add_hash_to_db(h)
                alerted = True

        system.send_slack_alert(
            f"Technology scan completed. {'New techs.' if alerted else 'No new techs.'}"
        )

    def _run_dir_scan(self) -> None:
        self.label = "dir_scan"
        targets = self._get_targets(unpack="dns")

        # Every public IP in inventory gets dir-scanned too, not just DNS hostnames.
        # check_endpoints() does its own live reachability probe (443/80) before
        # running ffuf, so it's safe to hand it every bare IP unconditionally.
        if not self.args.target:
            try:
                _, _, combined = system.get_all_targets()
                dns_set = set(targets)
                for t in combined:
                    if t not in dns_set and not system.is_private_ip(t):
                        targets.append(t)
            except Exception as e:
                logger.warning("Dir scan: could not enrich targets with inventory IPs: %s", e)

        if not targets:
            system.send_slack_alert("Directory scan completed. No targets found.")
            return

        coll = self.db.set_collection("Prod Exposed Endpoints")
        t_links = []
        scanned_domains: set = set()
        current_endpoints: set = set()

        for t in targets:
            scanned_domains.add(t)
            res = endpoints.check_endpoints(t)
            if not res:
                continue
            base = endpoints.resolve_reachable_url(t) or f"https://{t}"
            found = False
            table_c = ""
            for ep, code in res.items():
                current_endpoints.add((t, ep))
                url = f"{base.rstrip('/')}/{ep.lstrip('/')}"
                coll.update_one(
                    {"domain": t, "endpoint": ep},
                    {"$set": {"full_url": url, "status code": str(code)}},
                    upsert=True,
                )
                h = system.calculate_hash([t, ep, str(code)])
                if not system.check_if_hash_exists(h):
                    system.add_hash_to_db(h)
                    found = True
                    table_c += f"| {t} | {ep} | {url} | {code} |\n"

            if found:
                link = self._alert_finding(f"[Dir] {t} — new endpoints", table_c, self.label,
                                           severity="medium")
                if link:
                    t_links.append(link)
                if self._last_jira_key:
                    try:
                        coll.update_many(
                            {"domain": t},
                            {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                        )
                    except Exception:
                        pass

        retired_eps = 0
        for doc in coll.find({"status": {"$ne": "inactive"}}, {"_id": 1, "domain": 1, "endpoint": 1}):
            if doc.get("domain") not in scanned_domains or (doc.get("domain"), doc.get("endpoint")) not in current_endpoints:
                coll.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"status": "inactive", "remediated_at": datetime.utcnow()}},
                )
                retired_eps += 1
        if retired_eps:
            print(f"[bold green][+] Dir scan: {retired_eps} stale endpoint(s) marked inactive[/bold green]")

        msg = f"Directory scan completed. {'New endpoints.' if t_links else 'No new endpoints.'}"
        if t_links:
            msg += f"\nJira: {', '.join(t_links)}"
        system.send_slack_alert(msg)

    def _run_nuclei_scan(self) -> None:
        self.label = "nuclei_scan"
        tmpl = os.getenv('NUCLEI_TEMPLATE')
        targets = self._get_targets(unpack="combined")
        targets = [t for t in set(targets) if not system.is_private_ip(t)]
        if not targets:
            system.send_slack_alert("Nuclei scan completed. No targets found.")
            return

        update_nuclei_templates()
        res = {}
        with concurrent.futures.ThreadPoolExecutor() as ex:
            futs = {ex.submit(run_nuclei, t, tmpl): t for t in targets}
            for f in concurrent.futures.as_completed(futs):
                res[futs[f]] = f.result() or []

        # Persist each finding to MongoDB
        all_findings = [(target, finding) for target, findings in res.items() for finding in findings]
        if all_findings:
            try:
                col = self.db.set_collection("Prod Nuclei Scans")
                for target, finding in all_findings:
                    info = finding.get("info") or {}
                    doc = {
                        "target":       target,
                        "template_id":  finding.get("template-id", ""),
                        "name":         info.get("name") or finding.get("template-id", ""),
                        "severity":     info.get("severity", "info"),
                        "host":         finding.get("host", target),
                        "matched_at":   finding.get("matched-at", ""),
                        "type":         finding.get("type", ""),
                        "description":  info.get("description", ""),
                        "tags":         info.get("tags") or [],
                        "last_seen":    datetime.utcnow(),
                    }
                    h = system.calculate_hash({"template_id": doc["template_id"], "matched_at": doc["matched_at"]})
                    col.update_one(
                        {"hash": h},
                        {"$set": doc, "$setOnInsert": {"hash": h, "first_seen": datetime.utcnow()}},
                        upsert=True,
                    )
                print(f"[bold green][+] Nuclei: saved {len(all_findings)} finding(s) to DB[/bold green]")
            except Exception as e:
                print(f"[bold yellow][~] Nuclei DB save failed: {e}[/bold yellow]")

        scanned_nuclei_targets = set(targets)
        try:
            col = self.db.set_collection("Prod Nuclei Scans")
            retired_nuclei = 0
            for doc in col.find({"status": {"$ne": "inactive"}}, {"_id": 1, "target": 1}):
                if doc.get("target") not in scanned_nuclei_targets:
                    col.update_one(
                        {"_id": doc["_id"]},
                        {"$set": {"status": "inactive", "remediated_at": datetime.utcnow()}},
                    )
                    retired_nuclei += 1
            if retired_nuclei:
                print(f"[bold green][+] Nuclei: {retired_nuclei} stale finding(s) marked inactive[/bold green]")
        except Exception as e:
            print(f"[bold yellow][~] Nuclei stale retirement failed: {e}[/bold yellow]")

        t_links = []
        sev_counts_n = {"critical": 0, "high": 0, "medium": 0}
        for target, findings in res.items():
            for finding in findings:
                info     = finding.get("info") or {}
                sev      = (info.get("severity") or "info").lower()
                if sev not in ("critical", "high", "medium"):
                    continue
                sev_counts_n[sev] = sev_counts_n.get(sev, 0) + 1
                template_id  = finding.get("template-id", "")
                matched_at   = finding.get("matched-at", target)
                name         = info.get("name") or template_id
                description_text = info.get("description", "")
                tags         = ", ".join(info.get("tags") or [])
                h = system.calculate_hash({"template_id": template_id, "matched_at": matched_at})
                body = (
                    f"*Severity:* {sev.upper()}\n"
                    f"*Target:* {target}\n"
                    f"*Template:* {template_id}\n"
                    f"*Matched At:* {matched_at}\n"
                    f"*Description:* {description_text or 'N/A'}\n"
                    f"*Tags:* {tags or 'N/A'}\n"
                    f"*Scan type:* Nuclei"
                )
                link = self._alert_finding(
                    f"[Nuclei/{sev.upper()}] {name} — {target}",
                    body, self.label, hash_value=h, severity=sev,
                )
                if link:
                    t_links.append(link)
                if self._last_jira_key:
                    try:
                        col = self.db.set_collection("Prod Nuclei Scans")
                        col.update_one(
                            {"hash": h},
                            {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                        )
                    except Exception:
                        pass

        total_n = sum(sev_counts_n.values())
        msg = (
            f"Nuclei scan completed. "
            f"Critical: {sev_counts_n['critical']} | High: {sev_counts_n['high']} | Medium: {sev_counts_n['medium']}"
            if total_n else "Nuclei scan completed. No actionable findings."
        )
        if t_links:
            msg += f"\nJira: {', '.join(t_links[:10])}"
            if len(t_links) > 10:
                msg += f" (+{len(t_links) - 10} more)"
        system.send_slack_alert(msg)

    def _run_aws_scan(self) -> None:
        """Delegate to ``modules.aws.run_aws_scan`` (single AWS integration)."""
        self.label = "aws_scan"
        workers = getattr(self.args, "workers", None) or 10
        workers = max(1, min(int(workers), 50))
        try:
            run_aws_scan(max_workers=workers, regions=None)
            system.send_slack_alert("AWS scan completed.")
        except Exception as e:
            logger.exception("AWS scan failed: %s", e)
            raise

    def _run_godaddy_scan(self) -> None:
        """Run GoDaddy zone-file import: parse BIND zone files and store in MongoDB."""
        self.label = "godaddy_scan"
        txt_dir = getattr(self.args, "godaddy_dir", None)
        try:
            GoDaddy(txt_dir=txt_dir).run()
            system.send_slack_alert("GoDaddy scan completed.")
        except Exception as e:
            logger.exception("GoDaddy scan failed: %s", e)
            raise

    def _run_dast_scan(self) -> None:
        self.label = "dast_scan"

        if self.args.target:
            targets = self._read_target_list()
        else:
            _, dns_targets, combined_targets = system.get_all_targets()
            targets = list(dns_targets)
            # Every public IP in inventory gets DAST'd too, not just DNS hostnames.
            # _is_alive() does its own https->http fallback, so bare HTTP-only
            # IPs are handled without needing a prior firewall/port scan record.
            targets.extend(t for t in combined_targets if t not in dns_targets)

            # Also add cloud function hostnames (Lambda URLs, API GW, Cloud Run) that
            # may not yet be in DNS records if the cloud functions scan ran recently.
            try:
                from urllib.parse import urlparse as _urlparse
                cf_col = self.db.set_collection("Prod Cloud Functions Scans")
                for doc in cf_col.find({}, {"url": 1, "hostname": 1}):
                    host = doc.get("hostname", "") or ""
                    if not host:
                        url = doc.get("url", "") or ""
                        host = _urlparse(url).hostname or "" if url else ""
                    if host and not system.is_private_ip(host):
                        targets.append(host)
            except Exception as e:
                logger.warning("DAST: could not add cloud function targets: %s", e)
        targets = [t for t in set(targets) if not system.is_private_ip(t)]
        if not targets:
            system.send_slack_alert("DAST scan completed. No targets found.")
            return

        tech_map = {}
        try:
            tech_col = self.db.set_collection("Prod Technology Scans")
            for doc in tech_col.find({"domain": {"$in": targets}}, {"domain": 1, "technologies": 1}):
                domain = doc.get("domain", "")
                techs = []
                for cat_items in (doc.get("technologies") or {}).values():
                    for item in (cat_items or []):
                        name = item.get("name") or item.get("tag") or ""
                        if name:
                            techs.append(name)
                if techs:
                    tech_map[domain] = techs
        except Exception as e:
            logger.warning("Could not fetch tech map: %s", e)

        tmpl = os.getenv("NUCLEI_TEMPLATE")
        results = run_dast(targets, tech_map=tech_map, template_path=tmpl)

        dast_col = self.db.set_collection("Prod DAST Scans")
        t_links = []
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for target, findings in results.items():
            for finding in findings:
                sev = finding.get("severity", "info")
                if sev in sev_counts:
                    sev_counts[sev] += 1
                dast_col.update_one(
                    {"target": target, "check": finding["check"]},
                    {"$set": {**finding, "last_updated": datetime.utcnow()}},
                    upsert=True,
                )
                if sev not in ("critical", "high", "medium"):
                    continue
                h = system.calculate_hash(f"{target}{finding['check']}{finding.get('url','')}")
                description = (
                    f"*Severity:* {sev.upper()}\n"
                    f"*Target:* {target}\n"
                    f"*Check:* {finding['check']}\n"
                    f"*URL:* {finding.get('url', 'N/A')}\n"
                    f"*Detail:* {finding['detail']}\n"
                    f"*Evidence:* {finding.get('evidence', 'N/A')}\n"
                    f"*Scan type:* DAST"
                )
                link = self._alert_finding(
                    f"[DAST/{sev.upper()}] {target} — {finding['check']}",
                    description,
                    self.label, hash_value=h, severity=sev,
                )
                if link:
                    t_links.append(link)
                if self._last_jira_key:
                    try:
                        dast_col.update_one(
                            {"target": target, "check": finding["check"]},
                            {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                        )
                    except Exception:
                        pass

        # Retire stale DAST findings:
        # 1. Targets no longer in inventory → mark all their findings inactive
        # 2. Checks no longer triggered on a scanned target → mark those findings inactive
        current_dast_pairs = {
            (t, f["check"]) for t, findings in results.items() for f in findings
        }
        scanned_dast_targets = set(results.keys())
        retired_dast = 0
        for doc in dast_col.find({"status": {"$ne": "inactive"}}, {"_id": 1, "target": 1, "check": 1}):
            t, c = doc.get("target"), doc.get("check")
            if t not in scanned_dast_targets or (t, c) not in current_dast_pairs:
                dast_col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"status": "inactive", "remediated_at": datetime.utcnow()}},
                )
                retired_dast += 1
        if retired_dast:
            print(f"[bold green][+] DAST: {retired_dast} resolved finding(s) marked inactive[/bold green]")

        targets_with_findings = sum(1 for f in results.values() if f)
        msg_lines = [
            f"*DAST Scan Complete* — {len(targets)} targets",
            f"Critical: {sev_counts['critical']} | High: {sev_counts['high']} | Medium: {sev_counts['medium']} | Low: {sev_counts['low']}",
            f"Targets with findings: {targets_with_findings}/{len(targets)}",
        ]
        if t_links:
            msg_lines.append(f"Jira: {', '.join(t_links)}")
        system.send_slack_alert("\n".join(msg_lines))

    def _run_subdomain_scan(self) -> None:
        self.label = "subdomain_scan"

        try:
            dns_col = self.db.set_collection("Prod DNS Records")
            root_domains = set()
            for doc in dns_col.find({"status": "active"}, {"zone_name": 1}):
                zone = (doc.get("zone_name") or "").rstrip(".").strip()
                if zone:
                    root_domains.add(zone)
        except Exception as e:
            print(f"[bold red][-] Subdomain scan: could not fetch root domains: {e}[/bold red]")
            system.send_slack_alert(f"Subdomain scan failed: could not fetch root domains. {e}")
            return

        if not root_domains:
            system.send_slack_alert("Subdomain scan completed. No root domains found in inventory.")
            return
        results = run_subdomain_enum(sorted(root_domains))

        sub_col = self.db.set_collection("Prod Subdomain Scans")
        t_links = []
        new_count = 0

        dns_col = self.db.set_collection("Prod DNS Records")
        for domain, subs in results.items():
            for sub in subs:
                existing = sub_col.find_one({"subdomain": sub})
                if not existing:
                    sub_col.update_one(
                        {"subdomain": sub},
                        {"$set": {"domain": domain, "subdomain": sub,
                                  "discovered_at": datetime.utcnow()}},
                        upsert=True,
                    )
                    # Feed discovered subdomain back into DNS records so subsequent
                    # scans (SSL, DAST, dir, nuclei) pick it up automatically.
                    try:
                        dns_col.update_one(
                            {"name": sub, "source": "subdomain_scan"},
                            {"$set": {
                                "name":      sub,
                                "zone_name": domain,
                                "type":      "CNAME",
                                "content":   sub,
                                "source":    "subdomain_scan",
                                "status":    "active",
                                "updated_at": datetime.utcnow(),
                            }},
                            upsert=True,
                        )
                    except Exception:
                        pass
                    new_count += 1
                    h = system.calculate_hash(f"subdomain:{sub}")
                    if not system.check_if_hash_exists(h):
                        link = self._alert_finding(
                            f"[Subdomain] New: {sub}",
                            f"New subdomain discovered: *{sub}* (root: {domain})",
                            self.label, hash_value=h, severity="low",
                        )
                        if link:
                            t_links.append(link)

        msg = f"Subdomain scan complete — {new_count} new subdomains across {len(results)} domains."
        if t_links:
            msg += f"\nJira: {', '.join(t_links[:10])}"
            if len(t_links) > 10:
                msg += f" (+{len(t_links) - 10} more)"
        system.send_slack_alert(msg)

    def _run_email_security_scan(self) -> None:
        self.label = "email_security_scan"

        try:
            dns_col = self.db.set_collection("Prod DNS Records")
            root_domains = set()
            for doc in dns_col.find({"status": "active"}, {"zone_name": 1}):
                zone = (doc.get("zone_name") or "").rstrip(".").strip()
                if zone:
                    root_domains.add(zone)
        except Exception as e:
            print(f"[bold red][-] Email security scan: could not fetch domains: {e}[/bold red]")
            system.send_slack_alert(f"Email security scan failed: could not fetch domains. {e}")
            return

        if not root_domains:
            system.send_slack_alert("Email security scan completed. No domains found in inventory.")
            return
        results = run_email_security(sorted(root_domains))

        email_col = self.db.set_collection("Prod Email Security Scans")
        t_links = []

        for domain, data in results.items():
            email_col.update_one(
                {"domain": domain},
                {"$set": {**data, "last_updated": datetime.utcnow()}},
                upsert=True,
            )
            sev = data.get("severity", "ok")
            if sev not in ("critical", "high", "medium"):
                continue
            issues = []
            if data.get("spf", {}).get("issue"):
                issues.append(f"SPF: {data['spf']['issue']}")
            if data.get("dmarc", {}).get("issue"):
                issues.append(f"DMARC: {data['dmarc']['issue']}")
            h = system.calculate_hash(f"email_security:{domain}:{sev}")
            link = self._alert_finding(
                f"[Email Security] {domain} — {sev.upper()}",
                "\n".join(issues),
                self.label, hash_value=h, severity=sev,
            )
            if link:
                t_links.append(link)
            if self._last_jira_key:
                try:
                    email_col = self.db.set_collection("Prod Email Security Scans")
                    email_col.update_one(
                        {"domain": domain},
                        {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                    )
                except Exception:
                    pass

        critical = sum(1 for d in results.values() if d.get("severity") == "critical")
        high     = sum(1 for d in results.values() if d.get("severity") == "high")
        medium   = sum(1 for d in results.values() if d.get("severity") == "medium")
        msg = (
            f"Email Security scan complete — {len(results)} domains. "
            f"Critical: {critical} | High: {high} | Medium: {medium}"
        )
        if t_links:
            msg += f"\nJira: {', '.join(t_links)}"
        system.send_slack_alert(msg)

    def _run_cert_transparency_scan(self) -> None:
        self.label = "cert_transparency_scan"
        findings = run_cert_transparency_scan()
        col = self.db.set_collection("Prod Cert Transparency Scans")
        for f in findings:
            h = system.calculate_hash([f.get("cert_id", ""), f.get("san", ""), f.get("domain", "")])
            col.update_one({"cert_id": f.get("cert_id")}, {"$set": {**f, "hash": h}}, upsert=True)
        # Retire CT records that have since expired or belong to domains no longer in inventory.
        # active_roots: root domains still in our target set
        try:
            from datetime import timezone as _tz
            _, dns_targets, _ = system.get_all_targets()
            active_roots = {".".join(h.split(".")[-2:]) for h in dns_targets if "." in h}
            now_utc = datetime.now(_tz.utc)
            retired_ct = 0
            for doc in col.find(
                {"status": {"$nin": ["expired", "archived"]}},
                {"_id": 1, "not_after": 1, "root_domain": 1},
            ):
                not_after = doc.get("not_after", "")
                root = doc.get("root_domain", "")
                reason = None
                if not_after:
                    try:
                        expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=_tz.utc)
                        if expiry < now_utc:
                            reason = "expired"
                    except Exception:
                        pass
                if reason is None and root and root not in active_roots:
                    reason = "archived"
                if reason:
                    col.update_one(
                        {"_id": doc["_id"]},
                        {"$set": {"status": reason, "remediated_at": datetime.utcnow()}},
                    )
                    retired_ct += 1
            if retired_ct:
                print(f"[bold green][+] Cert CT: {retired_ct} stale record(s) marked expired/archived[/bold green]")
        except Exception as e:
            print(f"[bold yellow][~] Cert CT stale retirement failed: {e}[/bold yellow]")

        system.send_slack_alert(f"Cert Transparency scan completed. {len(findings)} cert(s) stored.")

    def _run_cloud_storage_scan(self) -> None:
        self.label = "cloud_storage_scan"
        findings = run_cloud_storage_scan()
        t_links = []
        for f in findings:
            provider    = f["provider"].upper()
            bucket      = f["bucket"]
            access      = ", ".join(f["public_access"])
            url         = f["url"]
            severity    = f["severity"].upper()
            versioning  = f.get("versioning", "unknown")
            encryption  = f.get("encryption", "unknown")
            obj_count   = f.get("object_count", -1)
            reachable   = f.get("reachable", None)
            account     = f.get("account") or f.get("project", "")

            obj_str     = str(obj_count) if obj_count >= 0 else "unknown"
            reach_str   = "Yes" if reachable else ("No" if reachable is False else "unknown")

            perm_note = {
                "critical": "Anonymous callers can WRITE (upload/delete) objects.",
                "high":     "Anonymous callers can LIST all object keys (enumerate bucket contents).",
                "medium":   "Anonymous callers can READ objects by URL but cannot list bucket contents.",
            }.get(f["severity"], "")

            description = (
                f"*Severity:* {severity}\n"
                f"*Provider:* {provider}\n"
                f"*Account/Project:* {account}\n"
                f"*Bucket:* {bucket}\n"
                f"*URL:* {url}\n"
                f"*Anonymous Access:* {access}\n"
                f"*Permission Detail:* {perm_note}\n"
                f"*Publicly Reachable:* {reach_str}\n"
                f"*Versioning:* {versioning}\n"
                f"*Encryption:* {encryption}\n"
                f"*Object Count (est.):* {obj_str}\n"
            )

            h = system.calculate_hash([f["provider"], bucket, severity.lower()])
            link = self._alert_finding(
                f"[{severity}] Public {provider} bucket: {bucket}",
                description,
                self.label, hash_value=h, severity=f["severity"],
            )
            if link:
                t_links.append(link)

        msg = f"Cloud Storage scan completed. {len(findings)} public bucket(s) found."
        if t_links:
            msg += "\n" + "\n".join(t_links)
        system.send_slack_alert(msg)

    def _run_vendor_scan(self) -> None:
        """
        Run a full external posture assessment for a third-party vendor.
        Requires --vendor <slug>.
        Results saved to Prod Vendor Posture + individual scan collections.
        Grade A/B/C based on weighted findings.
        """
        self.label = "vendor_scan"
        from modules.vendor_posture import run_vendor_posture  # lazy import — only load when vendor scan is requested
        slug = getattr(self.args, "vendor", None)
        if not slug:
            print("[bold red][-] --vendor <slug> is required for vendor scan[/bold red]")
            return

        vendor = get_vendor(slug)
        if not vendor:
            print(f"[bold red][-] Vendor not found: {slug}[/bold red]")
            return

        dns_targets, combined = get_vendor_targets(slug)
        root_domains          = get_root_domains(slug)

        if not dns_targets and not combined:
            print(f"[bold yellow][!] Vendor {slug} has no domains or IPs configured[/bold yellow]")
            return

        # Run posture assessment
        posture = run_vendor_posture(
            slug=slug,
            vendor_name=vendor["name"],
            dns_targets=dns_targets,
            combined_targets=combined,
            root_domains=root_domains,
        )

        grade   = posture["grade"]
        score   = posture["score"]
        issues  = posture["issues"]
        details = posture["details"]
        tag     = {"vendor_slug": slug}

        # Persist scan results to MongoDB
        # Subdomains
        sub_col = self.db.set_collection("Prod Subdomain Scans")
        for domain, subs in details["subdomains"].items():
            for sub in subs:
                sub_col.update_one(
                    {"subdomain": sub, "vendor_slug": slug},
                    {"$set": {"domain": domain, "subdomain": sub,
                              "discovered_at": datetime.utcnow(), **tag}},
                    upsert=True,
                )

        # SSL
        ssl_col = self.db.set_collection("Prod SSL Scans")
        for cert in details["ssl"]:
            host = cert.get("host") or cert.get("hostname")
            if host:
                ssl_col.update_one(
                    {"hostname": host, "vendor_slug": slug},
                    {"$set": {**cert, "hostname": host, **tag,
                              "last_updated": datetime.utcnow()}},
                    upsert=True,
                )

        # Email security
        email_col = self.db.set_collection("Prod Email Security Scans")
        for domain, data in details["email"].items():
            email_col.update_one(
                {"domain": domain, "vendor_slug": slug},
                {"$set": {**data, **tag, "last_updated": datetime.utcnow()}},
                upsert=True,
            )

        # Cert transparency
        ct_col = self.db.set_collection("Prod Cert Transparency Scans")
        for f in details["cert_ct"]:
            h = system.calculate_hash([f.get("cert_id", ""), f.get("san", ""), slug])
            if not system.check_if_hash_exists(h):
                ct_col.insert_one({**f, **tag, "hash": h})

        # DAST
        dast_col = self.db.set_collection("Prod DAST Scans")
        for finding in details["dast"]:
            target = finding.get("target") or finding.get("url", "")
            dast_col.update_one(
                {"target": target, "check": finding.get("check", ""), "vendor_slug": slug},
                {"$set": {**finding, **tag, "last_updated": datetime.utcnow()}},
                upsert=True,
            )

        # Ports
        port_col = self.db.set_collection("Prod Vendor Port Scans")
        for host, ports in details["ports"].items():
            port_col.update_one(
                {"host": host, "vendor_slug": slug},
                {"$set": {"host": host, "ports": ports, **tag,
                          "last_updated": datetime.utcnow()}},
                upsert=True,
            )

        # Live hosts (httpx probe results)
        live_col = self.db.set_collection("Prod Vendor Live Hosts")
        for host, info in details.get("live_hosts", {}).items():
            live_col.update_one(
                {"host": host, "vendor_slug": slug},
                {"$set": {"host": host, **info, **tag,
                          "last_updated": datetime.utcnow()}},
                upsert=True,
            )

        # Save posture snapshot
        posture_col = self.db.set_collection("Prod Vendor Posture")
        posture_col.update_one(
            {"vendor_slug": slug},
            {"$set": {
                "vendor_slug": slug,
                "vendor_name": vendor["name"],
                "grade":       grade,
                "score":       score,
                "issues":      issues,
                "scanned_at":  datetime.utcnow(),
            }},
            upsert=True,
        )

        # Alert on high/critical findings
        links = []
        for issue in issues:
            sev = "high" if "[critical]" in issue or "[high]" in issue else None
            if sev:
                h = system.calculate_hash(f"vendor:{slug}:posture:{issue}")
                link = self._alert_finding(
                    f"[Vendor:{vendor['name']}] {issue}",
                    issue, self.label, hash_value=h, severity="high",
                )
                if link:
                    links.append(link)

        update_last_scanned(slug)

        # Severity breakdown from DAST + all findings
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in details.get("dast", []):
            s = (f.get("severity") or "").lower()
            if s in sev_counts:
                sev_counts[s] += 1

        msg_lines = [
            f"*Vendor Scan: {vendor['name']}*",
            f"Critical: {sev_counts['critical']}  |  High: {sev_counts['high']}  |  Medium: {sev_counts['medium']}  |  Low: {sev_counts['low']}",
            f"Subdomains discovered: {sum(len(v) for v in details.get('subdomains', {}).values())}  |  Live hosts: {len(details.get('live_hosts', {}))}  |  Open port hosts: {len(details.get('ports', {}))}",
        ]
        if links:
            msg_lines.append("Tickets: " + "  ".join(links))
        system.send_slack_alert("\n".join(msg_lines))

    def _run_dangling_dns(self) -> None:
        self.label = "dangling_dns"
        res = get_dangling_dns_dict(domains=None, force_update=False) or {}

        # Persist every finding to MongoDB
        if res:
            try:
                col = self.db.set_collection("Prod Dangling DNS")
                for domain, data in res.items():
                    doc = {
                        "domain":          domain,
                        "cloudflare_ips":  data.get("cloudflare_ips", []),
                        "gcp_ips":         data.get("gcp_ips", []),
                        "status":          data.get("status", "dangling"),
                        "record_type":     data.get("type", ""),
                        "last_updated":    datetime.utcnow(),
                    }
                    col.update_one(
                        {"domain": domain},
                        {"$set": doc, "$setOnInsert": {"first_seen": datetime.utcnow()}},
                        upsert=True,
                    )
                print(f"[bold green][+] Dangling DNS: saved {len(res)} finding(s) to DB[/bold green]")
            except Exception as e:
                print(f"[bold yellow][~] Dangling DNS DB save failed: {e}[/bold yellow]")

        prev = system.read_from_csv(PREV_DANGLING_CSV)

        # Compare only on cloudflare_ips + status (type field is not round-tripped through CSV)
        def _sig(d): return (sorted(d.get("cloudflare_ips", [])), d.get("status", ""))
        delta = {
            d: data for d, data in res.items()
            if d not in prev or _sig(data) != _sig(prev[d])
        }

        t_link = ""
        if delta:
            # Use sorted keys so the hash is stable regardless of Cloudflare response order
            stable_key = json.dumps(
                {d: {"ips": sorted(v.get("cloudflare_ips", [])), "status": v.get("status", "")}
                 for d, v in sorted(delta.items())},
                sort_keys=True,
            )
            h = system.calculate_hash(stable_key)

            rows = []
            for d, v in sorted(delta.items())[:20]:
                ips = ", ".join(v.get("cloudflare_ips") or ["unknown"])
                rows.append(f"- *{d}* → {ips}")
            domains_list = "\n".join(rows)

            description = (
                f"*Total new/changed records:* {len(delta)}\n\n"
                f"*Affected domains (first 20):*\n{domains_list}\n\n"
                f"*What to do:* Verify each domain still points to an IP you own. "
                f"If the IP is no longer in any GCP project, remove or update the DNS record immediately."
            )

            t_link = self._alert_finding(
                f"[Dangling DNS] {len(delta)} record(s) detected",
                description,
                self.label, hash_value=h, severity="high",
            )
            if self._last_jira_key and delta:
                try:
                    col = self.db.set_collection("Prod Dangling DNS")
                    col.update_many(
                        {"domain": {"$in": list(delta.keys())}},
                        {"$set": {"jira_key": self._last_jira_key, "jira_url": self._last_jira_url}},
                    )
                except Exception:
                    pass

        # Write back CSV so next run only alerts on genuinely new/changed records
        if res:
            try:
                save_dangling_to_csv(res, PREV_DANGLING_CSV)
            except Exception as e:
                print(f"[bold yellow][~] Dangling DNS CSV write failed: {e}[/bold yellow]")

        msg = f"Dangling DNS scan complete. {len(res)} total dangling record(s)."
        if t_link:
            msg += f" {len(delta)} new/changed. Jira: {t_link}"
        elif res:
            msg += " No new changes since last scan."
        system.send_slack_alert(msg)


    # Main dispatcher

    _SCAN_MAP = {
        'update_inventory':       '_run_inventory_update',
        'ssl_checker':            '_run_ssl_checker',
        'firewall_port_scan':     '_run_firewall_scan',
        'exposed_services_scan':  '_run_exposed_services_scan',
        'wayback_scan':           '_run_wayback_scan',
        'tech_scan':           '_run_tech_scan',
        'dir_scan':            '_run_dir_scan',
        'dast_scan':           '_run_dast_scan',
        'subdomain_scan':      '_run_subdomain_scan',
        'email_security_scan': '_run_email_security_scan',
        'nuclei_scan':         '_run_nuclei_scan',
        'dangling_dns':        '_run_dangling_dns',
        'aws_scan':            '_run_aws_scan',
        'godaddy_scan':        '_run_godaddy_scan',
        'cloud_storage_scan':      '_run_cloud_storage_scan',
        'cert_transparency_scan':  '_run_cert_transparency_scan',
        'vendor_scan':             '_run_vendor_scan',
    }

    def _activate_service_account(self) -> None:
        svc = os.getenv('SVC_ACCOUNT')
        if not svc:
            return
        try:
            subprocess.run(
                ["gcloud", "auth", "activate-service-account", f"--key-file={svc}"],
                check=True, capture_output=True,
            )
            print("[bold green][+] Service Account Activated[/bold green]")
        except Exception as e:
            print(f"[bold red][-] Service Account Error: {e}[/bold red]")

    def run(self):
        self._activate_service_account()
        
        # Validate Slack configuration before starting scans
        system.print_slack_config_status()
        
        # Check if any scans are actually requested
        scans_to_run = [flag for flag in self._SCAN_MAP.keys() if getattr(self.args, flag, False)]
        if not scans_to_run:
            print("[bold yellow][!] No scans specified. Use -h for available options.[/bold yellow]")
            return
            
        print(f"[bold blue]Starting {len(scans_to_run)} scan(s): {', '.join(scans_to_run)}[/bold blue]")

        for flag, method_name in self._SCAN_MAP.items():
            if not getattr(self.args, flag, False):
                continue
            try:
                print(f"[bold green]Starting {flag}...[/bold green]")
                getattr(self, method_name)()
                print(f"[bold green]✓ {flag} completed successfully[/bold green]")
            except Exception as e:
                print(f"[bold red]✗ {flag} failed: {e}[/bold red]")
                system.send_slack_alert(f"Scan '{flag}' failed: {e}")
                logger.exception("Scan %s failed", flag)
                
        print("[bold green]All scans completed![/bold green]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Appollo - Reconnaissance Tool")
    parser.add_argument('-e', "--env", required=True)
    parser.add_argument("-t", "--target")
    parser.add_argument("-U", "--update-inventory", action="store_true")
    parser.add_argument("-sc", "--ssl-checker", action="store_true")
    parser.add_argument("-ws", "--wayback-scan", action="store_true")
    parser.add_argument("-fs", "--firewall-port-scan", action="store_true")
    parser.add_argument("-es", "--exposed-services-scan", action="store_true")
    parser.add_argument("-ts", "--tech-scan", action="store_true")
    parser.add_argument("-ds", "--dir-scan", action="store_true")
    parser.add_argument("-ns", "--nuclei-scan", action="store_true")
    parser.add_argument("-dast", "--dast-scan", action="store_true")
    parser.add_argument("-sub", "--subdomain-scan", action="store_true")
    parser.add_argument("-em", "--email-security-scan", action="store_true")
    parser.add_argument("-dd", "--dangling-dns", action="store_true")
    parser.add_argument("-as", "--aws-scan", action="store_true")
    parser.add_argument("-g", "--godaddy-scan", action="store_true")
    parser.add_argument("-cs", "--cloud-storage-scan", action="store_true")
    parser.add_argument("-ct", "--cert-transparency-scan", action="store_true")
    parser.add_argument("-vs", "--vendor-scan", action="store_true")
    parser.add_argument("-V", "--vendor", help="Vendor slug for --vendor-scan")
    parser.add_argument("-d", "--godaddy-dir", help="Directory containing GoDaddy *.txt zone files")
    parser.add_argument("-A", "--complete-scan", action="store_true")
    parser.add_argument("--org-id")
    parser.add_argument("--projects")
    parser.add_argument("--max-projects", type=int)
    parser.add_argument("--firewall-ports", action="store_true")
    parser.add_argument("--gke-scan", action="store_true")
    parser.add_argument("--workers", type=int, default=20)
    args = parser.parse_args()

    Appollo(args).run()
