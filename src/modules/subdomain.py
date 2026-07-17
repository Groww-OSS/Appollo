"""
Subdomain enumeration module.

Two passive sources combined:
  1. subfinder — fast multi-source passive enumeration (chaos, dnsx, certspotter, etc.)
  2. crt.sh    — certificate transparency log query (no auth required)

Both are read-only / passive — they never touch the target directly.
"""

import json
import subprocess
import concurrent.futures
from datetime import datetime

import requests
import urllib3
from rich import print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_CRT_TIMEOUT = 20
_SUBFINDER_TIMEOUT = 120
_SESSION_HEADERS = {"User-Agent": "ASM-Scanner/1.0"}
_SUBFINDER_WARNED = False  # print missing-binary warning only once


def _crtsh_query(domain: str) -> set:
    """Query crt.sh certificate transparency for subdomains of *domain*."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=_CRT_TIMEOUT,
            headers=_SESSION_HEADERS,
        )
        if r.status_code != 200:
            return set()
        subs = set()
        for entry in r.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and (name.endswith(f".{domain}") or name == domain):
                    subs.add(name)
        return subs
    except Exception:
        return set()


def _subfinder_query(domain: str) -> set:
    """Run subfinder for passive subdomain enumeration."""
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-json"],
            capture_output=True, text=True, timeout=_SUBFINDER_TIMEOUT,
        )
        subs = set()
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                sub = data.get("host", "")
            except json.JSONDecodeError:
                sub = line
            if sub:
                subs.add(sub)
        return subs
    except FileNotFoundError:
        global _SUBFINDER_WARNED
        if not _SUBFINDER_WARNED:
            print("[bold yellow][~] subfinder not in PATH — skipping. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/bold yellow]")
            _SUBFINDER_WARNED = True
        return set()
    except subprocess.TimeoutExpired:
        print(f"[bold yellow][~] subfinder timed out for {domain}[/bold yellow]")
        return set()


def _enumerate_domain(domain: str) -> tuple[str, set]:
    """Run both sources in parallel and return (domain, subdomains)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_sub = ex.submit(_subfinder_query, domain)
        f_crt = ex.submit(_crtsh_query, domain)
        subs = f_sub.result() | f_crt.result()
    return domain, subs


def run_subdomain_enum(root_domains: list, max_workers: int = 5) -> dict:
    """
    Enumerate subdomains for a list of root domains.

    Args:
        root_domains: list of apex domains (e.g. ["example.com"])
        max_workers:  parallel domain enumeration concurrency

    Returns:
        {domain: sorted([subdomain, ...])}
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_enumerate_domain, d): d for d in root_domains}
        for f in concurrent.futures.as_completed(futs):
            domain = futs[f]
            try:
                _, subs = f.result()
                if subs:
                    results[domain] = sorted(subs)
                    print(
                        f"[bold green][+] {domain}: {len(subs)} subdomains[/bold green]"
                    )
                else:
                    print(f"[dim][~] {domain}: no new subdomains[/dim]")
            except Exception as e:
                print(f"[bold red][-] Subdomain enum failed for {domain}: {e}[/bold red]")
    return results
