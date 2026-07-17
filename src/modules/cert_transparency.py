"""
Certificate Transparency Log Monitor

Polls crt.sh to find all SSL/TLS certificates issued for your domains.
Alerts on:
  - New certificates issued since last scan (could be shadow IT or phishing infra)
  - Certs issued by an unexpected / unknown CA
  - Wildcard certificates (broad coverage — worth knowing about)

Results are saved to MongoDB collection "Prod Cert Transparency Scans".
"""

import concurrent.futures
import os
import time
from datetime import datetime, timezone

import requests
from rich import print
from rich.console import Console

from system.db import MongoDB
from system.utils import calculate_hash, check_if_hash_exists
from system.targets import get_all_targets

console = Console()

_MAX_WORKERS   = int(os.getenv("CERT_CT_WORKERS", "10"))
_REQUEST_TIMEOUT = int(os.getenv("CERT_CT_TIMEOUT", "20"))
_CRTSH_URL     = "https://crt.sh/?q={domain}&output=json"

# CAs you own or fully trust — certs from outside this set will be flagged
# Set TRUSTED_CAS env var as a comma-separated list to override
_DEFAULT_TRUSTED_CAS = {
    "Let's Encrypt",
    "DigiCert",
    "Sectigo",
    "GlobalSign",
    "Comodo",
    "Amazon",
    "Google Trust Services",
    "GTS",
    "Entrust",
    "Thawte",
    "GeoTrust",
    "Symantec",
    "RapidSSL",
    "ZeroSSL",
    "Buypass",
    "SSL.com",
    "Cloudflare",  # Cloudflare issues certs for proxied domains — fully legitimate
    "GoDaddy",
    "Microsoft",
    "cPanel",
    "Trustwave",
    "Network Solutions",
}


def _get_trusted_cas() -> set[str]:
    env = os.getenv("TRUSTED_CAS", "")
    if env:
        return {c.strip() for c in env.split(",") if c.strip()}
    return _DEFAULT_TRUSTED_CAS


def _extract_root_domains(dns_targets: set) -> set[str]:
    """Extract unique root domains from the full target set."""
    roots = set()
    for host in dns_targets:
        parts = host.split(".")
        if len(parts) >= 2:
            roots.add(".".join(parts[-2:]))
    return roots


def _query_crtsh(domain: str) -> list[dict]:
    """Query crt.sh for all certs matching %.domain (includes subdomains)."""
    url = _CRTSH_URL.format(domain=f"%.{domain}")
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=_REQUEST_TIMEOUT)
            if r.status_code == 200 and r.text.strip():
                return r.json()
            if r.status_code == 429:
                time.sleep(5 * (attempt + 1))
        except requests.exceptions.RequestException:
            time.sleep(2)
    return []


def _parse_cert(entry: dict, root_domain: str, trusted_cas: set) -> "dict | None":
    """
    Parse a single crt.sh entry.
    Returns a finding dict if the cert is notable, else None.
    """
    name_value   = entry.get("name_value", "")
    issuer_name  = entry.get("issuer_name", "")
    not_before   = entry.get("not_before", "")
    not_after    = entry.get("not_after", "")
    cert_id      = entry.get("id", "")
    common_name  = entry.get("common_name", name_value)

    if not name_value or not issuer_name:
        return None

    # Skip already-expired certs — no actionable value
    if not_after:
        try:
            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            if expiry < datetime.now(timezone.utc):
                return None
        except Exception:
            pass

    # Extract CA common name from issuer DN (e.g. "CN=Let's Encrypt...")
    ca_name = ""
    for part in issuer_name.split(","):
        part = part.strip()
        if part.startswith("O="):
            ca_name = part[2:].strip().strip('"')
            break
    if not ca_name:
        for part in issuer_name.split(","):
            part = part.strip()
            if part.startswith("CN="):
                ca_name = part[3:].strip()
                break

    is_wildcard     = name_value.startswith("*.")
    is_unknown_ca   = not any(trusted.lower() in ca_name.lower() for trusted in trusted_cas)

    flags = []
    if is_wildcard:
        flags.append("wildcard")
    if is_unknown_ca:
        flags.append("unknown_ca")

    severity = "info"
    if is_unknown_ca:
        severity = "high"   # unexpected CA = potential interception / phishing infra
    elif is_wildcard:
        severity = "medium"

    return {
        "root_domain": root_domain,
        "common_name": common_name,
        "san": name_value,
        "issuer": issuer_name,
        "ca_name": ca_name,
        "not_before": not_before,
        "not_after": not_after,
        "cert_id": cert_id,
        "crtsh_url": f"https://crt.sh/?id={cert_id}",
        "is_wildcard": is_wildcard,
        "is_unknown_ca": is_unknown_ca,
        "flags": flags,
        "severity": severity,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def scan_domain(domain: str, trusted_cas: set) -> list[dict]:
    entries = _query_crtsh(domain)
    if not entries:
        return []

    findings = []
    seen_ids = set()
    for entry in entries:
        cert_id = entry.get("id")
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)

        parsed = _parse_cert(entry, domain, trusted_cas)
        if parsed and parsed["severity"] != "info":
            findings.append(parsed)

    return findings


def run_cert_transparency_scan(domains=None) -> list:
    """
    Poll crt.sh for all root domains in inventory.
    Alerts on certs from unknown CAs and wildcard certs.

    Args:
        domains: override set of root domains. If None, pulls from inventory.

    Returns:
        List of new finding dicts (not previously seen in DB).
    """
    print("[bold blue][*] Certificate Transparency scan starting...[/bold blue]")

    if domains is None:
        _, dns_targets, _ = get_all_targets()
        root_domains = _extract_root_domains(dns_targets)
    else:
        root_domains = domains

    if not root_domains:
        print("[yellow][~] Cert CT: no root domains found in inventory[/yellow]")
        return []

    print(f"[bold blue][*] Cert CT: querying crt.sh for {len(root_domains)} root domain(s)[/bold blue]")
    trusted_cas = _get_trusted_cas()

    all_findings: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        fut_map = {ex.submit(scan_domain, d, trusted_cas): d for d in root_domains}
        for fut in concurrent.futures.as_completed(fut_map):
            domain = fut_map[fut]
            try:
                results = fut.result()
                if results:
                    print(f"[dim]  {domain}: {len(results)} notable cert(s)[/dim]")
                all_findings.extend(results)
            except Exception as e:
                print(f"[yellow][~] Cert CT: error scanning {domain}: {e}[/yellow]")

    if not all_findings:
        print("[bold green][+] Cert CT: no notable certificates found[/bold green]")
        return []

    # Persist for record-keeping — hash dedup is handled by the caller (_alert_finding)
    db  = MongoDB()
    col = db.set_collection("Prod Cert Transparency Scans")
    for f in all_findings:
        h = calculate_hash([f["cert_id"], f["san"]])
        if not check_if_hash_exists(h):
            col.insert_one({**f, "hash": h})

    unknown_ca = [f for f in all_findings if f["is_unknown_ca"]]
    wildcards  = [f for f in all_findings if f["is_wildcard"] and not f["is_unknown_ca"]]

    print(
        f"[bold {'red' if unknown_ca else 'yellow' if wildcards else 'green'}]"
        f"[{'!' if unknown_ca else '~' if wildcards else '+'}] Cert CT: "
        f"{len(all_findings)} cert(s) — "
        f"{len(unknown_ca)} unknown CA, {len(wildcards)} wildcard[/bold "
        f"{'red' if unknown_ca else 'yellow' if wildcards else 'green'}]"
    )
    return all_findings
