import subprocess
import json
import requests
from datetime import datetime, timezone
from rich import print

"""
This module provides functions to extract TLS information from a list of hosts using the tlsx command.
Functions:
    extract_tls_info(hosts): Extracts TLS information for the given list of hosts and returns a list of dictionaries with the extracted data.
    verify_with_crtsh(tls_results): Cross-checks each tlsx result against crt.sh CT logs.
    main(): Main function to read hosts from a file, extract TLS information, and print the results in a formatted table.
Exceptions:
    Exception: Raised when there is an error during the extraction process.
"""

_CRTSH_URL = "https://crt.sh/?q={}&output=json"

# CAs considered trusted — certs issued outside this set are flagged
_TRUSTED_CAS = {
    "Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign", "Comodo",
    "Amazon", "Google Trust Services", "GTS", "Entrust", "Thawte",
    "GeoTrust", "Symantec", "RapidSSL", "ZeroSSL", "Buypass",
    "SSL.com", "Cloudflare", "GoDaddy", "Microsoft", "cPanel",
    "Trustwave", "Network Solutions",
}


def _strip_port(host: str) -> str:
    """Normalize tlsx host output to bare domain (strips :PORT suffix)."""
    if not host or host == "Unknown":
        return host
    if host.startswith("["):
        bracket_end = host.find("]")
        return host[:bracket_end + 1] if bracket_end != -1 else host
    return host.rsplit(":", 1)[0] if ":" in host else host


def _root_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _fetch_crtsh(root_domain: str) -> "list[dict] | None":
    """Query crt.sh for all certs issued under root_domain.

    Returns None when crt.sh is unreachable (so callers can distinguish
    'unavailable' from 'available but no certs found').
    """
    try:
        r = requests.get(_CRTSH_URL.format(f"%.{root_domain}"), timeout=20)
        if r.status_code == 200 and r.text.strip():
            return r.json()
        return []
    except Exception:
        return None


def _build_ct_index(entries: list[dict]) -> dict:
    """Return {name -> set[datetime]} covering both common_name and SAN fields."""
    index: dict[str, set] = {}
    for e in entries:
        raw_date = e.get("not_after", "")
        if not raw_date:
            continue
        try:
            dt = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
            # crt.sh sometimes omits timezone — treat as UTC to avoid
            # "can't subtract offset-naive and offset-aware datetimes"
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        for field in ("common_name", "name_value"):
            for name in (e.get(field) or "").split("\n"):
                name = name.strip()
                if name:
                    index.setdefault(name, set()).add(dt)
    return index


def _is_in_ct(subject_cn: str, hostname: str, not_after: str, index: dict) -> bool:
    if not subject_cn or not not_after or subject_cn == "Unknown":
        return False
    try:
        served = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return False
    candidates = index.get(subject_cn, set()) | index.get(hostname, set())
    # Allow ±2 day tolerance for timezone/rounding differences between sources
    return any(abs((served - ct_dt).days) <= 2 for ct_dt in candidates)


def _ca_trusted(issuer_org: str) -> bool:
    return any(t.lower() in issuer_org.lower() for t in _TRUSTED_CAS)


def verify_with_crtsh(tls_results: list[dict]) -> list[dict]:
    """Cross-check each tlsx result against crt.sh certificate transparency logs.

    Annotates every result dict in-place with:
      ct_verified   : bool | None  — cert found in CT logs (None = crt.sh unreachable)
      ct_ca_trusted : bool         — issuer is in the trusted CA list
      ct_wildcard   : bool         — cert CN is a wildcard (*.example.com)

    Queries crt.sh once per root domain to avoid hammering the API.
    """
    domain_map: dict[str, list[dict]] = {}
    for result in tls_results:
        rd = _root_domain(result.get("hostname", ""))
        domain_map.setdefault(rd, []).append(result)

    for root, results in domain_map.items():
        entries = _fetch_crtsh(root)
        index = _build_ct_index(entries) if entries is not None else None

        for result in results:
            subject_cn = result.get("subject_cn", "")
            hostname   = result.get("hostname", "")
            not_after  = result.get("not_after", "")
            issuer_org = result.get("issuer_org", "")

            result["ct_wildcard"]   = subject_cn.startswith("*.")
            result["ct_ca_trusted"] = _ca_trusted(issuer_org)

            if index is None:
                result["ct_verified"] = None   # crt.sh was unreachable
            else:
                result["ct_verified"] = _is_in_ct(subject_cn, hostname, not_after, index)

    return tls_results


def extract_tls_info(hosts):
    try:
        if not hosts:
            return []

        all_extracted_data = []
        command = ["tlsx", "-json", "-silent"]

        try:
            input_data = "\n".join(hosts)
            process = subprocess.run(
                command,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout scanning batch of {len(hosts)} hosts")
            return []
        except OSError as e:
            if e.errno == 23:
                print(f"[bold red][-] System error: Too many open files. Try reducing concurrency or batching targets.[/bold red]")
            else:
                print(f"[bold red][-] System error: {e}[/bold red]")
            return []

        if process.returncode != 0:
            print(f"Error running tlsx: {process.stderr}")
            return []

        current_date = datetime.now(timezone.utc)

        for line in process.stdout.splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                # tlsx returns "host" as "example.com:443" — normalize to bare domain
                hostname = _strip_port(entry.get("host", "Unknown"))
                not_before = entry.get("not_before", "Unknown")
                not_after = entry.get("not_after", "Unknown")
                subject_cn = entry.get("subject_cn", "Unknown")
                issuer_org = ", ".join(entry.get("issuer_org", ["Unknown"]))

                days_until_expiry = None
                if not_after and not_after != "Unknown":
                    try:
                        not_after_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        days_until_expiry = (not_after_date - current_date).days
                    except Exception:
                        pass

                # Fall back to tlsx's own expired flag only when we cannot parse the date
                if days_until_expiry is None:
                    raw_expired = entry.get("expired")
                    days_until_expiry = -1 if str(raw_expired).lower() == "true" else 0

                is_expired = days_until_expiry < 0

                all_extracted_data.append({
                    "hostname": hostname,
                    "not_before": not_before,
                    "not_after": not_after,
                    "subject_cn": subject_cn,
                    "issuer_org": issuer_org,
                    "days_until_expiry": days_until_expiry,
                    "expired": is_expired,
                })
            except json.JSONDecodeError:
                continue

        return all_extracted_data

    except Exception as e:
        print(f"Error in extract_tls_info: {e}")
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
