"""
Vendor Posture Scanner
======================
Full external attack surface assessment for a third-party vendor.
No cloud credentials required — everything is from the attacker's perspective.

Scans included:
  1. Subdomain enumeration    (subfinder + crt.sh)
  2. Live HTTP probe          (httpx — filters to live services, grabs tech stack)
  3. DNS takeover detection   (CNAME → unclaimed cloud service fingerprinting)
  4. SSL/TLS check            (tlsx on original + discovered live hosts)
  5. Email security           (SPF / DMARC / DKIM — DNS only)
  6. Cert transparency        (crt.sh — unauthorized cert issuance)
  7. DAST + Nuclei            (headers, CORS, exposed files, open redirect, CVEs)
       - Nuclei auto-scan uses tech stack from httpx for better template coverage
  8. Port scan top-100        (naabu on IPs + live host IPs)

Grading (A / B / C):
  Score starts at 100.
  Takeover opportunity  : -25 (critical)
  Critical DAST finding : -25 each
  High finding          : -15 each
  Medium finding        : -5  each
  Missing SPF / DMARC   : -10 each
  SSL expired           : -25  |  expiring <14d: -15  |  <30d: -5
  Self-signed cert      : -15
  Unexpected open ports : up to -15 per host
  A: 70-100  |  B: 40-69  |  C: <40
"""
from __future__ import annotations  # allow X | Y union syntax on Python 3.9

import concurrent.futures
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone

import requests
import urllib3
from rich import print

from modules.subdomain import run_subdomain_enum
from modules.ssl_checker import extract_tls_info
from modules.email_security import run_email_security
from modules.cert_transparency import run_cert_transparency_scan
from modules.dast import run_dast

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_EXPECTED_PORTS = {80, 443, 8080, 8443}
_TOP_100_FLAGS  = "-top-ports 100 -rate 1000 -timeout 3"

# Max live subdomains to pass to DAST (nuclei is expensive)
_MAX_DAST_TARGETS = 50


# ── Grading ────────────────────────────────────────────────────────────────────

def _grade(score: int) -> str:
    if score >= 70: return "A"
    if score >= 40: return "B"
    return "C"

def _grade_color(grade: str) -> str:
    return {"A": "green", "B": "yellow", "C": "red"}.get(grade, "white")


# ── 1. Subdomain enumeration ──────────────────────────────────────────────────

def _run_subdomain(root_domains: set) -> dict:
    """Returns {domain: [subdomains]}."""
    if not root_domains:
        return {}
    try:
        return run_subdomain_enum(sorted(root_domains)) or {}
    except Exception as e:
        print(f"[dim][VendorPosture] Subdomain enum error: {e}[/dim]")
        return {}


# ── 2. Live HTTP probe (httpx) ────────────────────────────────────────────────

def _run_httpx(targets: set) -> dict:
    """
    Probe all targets with httpx to find live HTTP services.
    Also captures tech stack for better nuclei template selection.

    Returns:
        {hostname: {"url": str, "status": int, "title": str, "tech": [str]}}
    """
    if not targets:
        return {}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for t in sorted(targets):
            f.write(t + "\n")
        targets_file = f.name

    results: dict = {}
    try:
        cmd = [
            "httpx", "-nc", "-j", "-silent",
            "-list",    targets_file,
            "-title",                   # grab page title
            "-sc",                      # status code
            "-td",                      # tech detection
            "-timeout", "5",
            "-rl",      "150",
            "-threads", "50",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r    = json.loads(line)
                host = (r.get("input") or r.get("host") or "").split(":")[0].strip()
                if not host:
                    continue
                tech_raw   = r.get("tech") or r.get("technologies") or []
                tech_names = []
                for t in tech_raw:
                    name = t.get("name", "") if isinstance(t, dict) else (t if isinstance(t, str) else "")
                    if name:
                        tech_names.append(name)
                results[host] = {
                    "url":    r.get("url", f"https://{host}"),
                    "status": r.get("status-code", 0),
                    "title":  r.get("title", ""),
                    "tech":   tech_names,
                }
            except (json.JSONDecodeError, KeyError):
                continue

        live_count = len(results)
        print(f"[bold blue][*] httpx probe: {live_count}/{len(targets)} targets are live[/bold blue]")

    except FileNotFoundError:
        print("[dim][VendorPosture] httpx not found — skipping live probe (all targets treated as live)[/dim]")
    except subprocess.TimeoutExpired:
        print("[dim][VendorPosture] httpx probe timed out[/dim]")
    except Exception as e:
        print(f"[dim][VendorPosture] httpx error: {e}[/dim]")
    finally:
        try:
            os.unlink(targets_file)
        except Exception:
            pass

    return results


# ── 3. DNS takeover detection ─────────────────────────────────────────────────

# (cname_fragment, error_fingerprint_bytes, service_name)
_TAKEOVER_SIGS: list[tuple[str, bytes, str]] = [
    ("github.io",           b"There isn't a GitHub Pages site here",         "GitHub Pages"),
    ("githubusercontent",   b"Invalid Site",                                  "GitHub Pages"),
    ("heroku",              b"No such app",                                   "Heroku"),
    ("netlify.app",         b"Not Found",                                     "Netlify"),
    ("s3.amazonaws.com",    b"NoSuchBucket",                                  "AWS S3"),
    ("s3-website",          b"NoSuchBucket",                                  "AWS S3"),
    ("cloudfront.net",      b"Bad request.",                                  "AWS CloudFront"),
    ("azurewebsites.net",   b"404 Web Site not found",                        "Azure Web Apps"),
    ("shopify.com",         b"Sorry, this shop is currently unavailable",     "Shopify"),
    ("statuspage.io",       b"You are being redirected",                      "Statuspage.io"),
    ("zendesk.com",         b"Help Center Closed",                            "Zendesk"),
    ("readme.io",           b"Project doesnt exist",                          "ReadMe"),
    ("surge.sh",            b"project not found",                             "Surge.sh"),
    ("fastly.net",          b"Fastly error: unknown domain",                  "Fastly"),
    ("pantheonsite.io",     b"The gods are wise",                             "Pantheon"),
    ("ghost.io",            b"The thing you were looking for",                "Ghost"),
    ("webflow.io",          b"The page you are looking for",                  "Webflow"),
    ("vercel.app",          b"The deployment you are looking for",            "Vercel"),
    ("fly.dev",             b"404 Not Found",                                 "Fly.io"),
    ("tumblr.com",          b"There\xe2\x80\x99s nothing here.",              "Tumblr"),
    ("wordpress.com",       b"Do you want to register",                       "WordPress.com"),
    ("squarespace.com",     b"No Such Account",                               "Squarespace"),
    ("helpscoutdocs.com",   b"No settings were found",                        "HelpScout"),
    ("launchrock.com",      b"It looks like you may have taken a wrong turn", "Launchrock"),
    ("unbounce.com",        b"The requested URL was not found",               "Unbounce"),
    ("wix.com",             b"Error ConnectYourDomain",                       "Wix"),
    ("smugmug.com",         b"Page Not Found",                                "SmugMug"),
    ("strikingly.com",      b"page not found",                                "Strikingly"),
    ("bigcartel.com",       b"Product Not Found",                             "Big Cartel"),
    ("airbyte.io",          b"page not found",                                "Airbyte"),
]


def _resolve_cname(hostname: str) -> str | None:
    """Resolve CNAME using dig. Returns first CNAME target or None."""
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", hostname],
            capture_output=True, text=True, timeout=5,
        )
        out = result.stdout.strip()
        if out and not out.startswith(";") and "." in out:
            return out.rstrip(".")
        return None
    except Exception:
        return None


def _check_dns_takeover(subdomains: set) -> list:
    """
    For each subdomain, resolve its CNAME. If the CNAME points to a known
    cloud/SaaS service, fetch the page and check for unclaimed-resource
    error fingerprints. Returns a list of critical finding dicts.
    """
    if not subdomains:
        return []

    findings = []
    session  = requests.Session()
    session.verify  = False
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})

    print(f"[bold blue][*] DNS takeover: checking {len(subdomains)} subdomain(s)[/bold blue]")

    for sub in sorted(subdomains):
        try:
            cname = _resolve_cname(sub)
            if not cname:
                continue

            cname_lower = cname.lower()

            for svc_suffix, fingerprint, service_name in _TAKEOVER_SIGS:
                if svc_suffix not in cname_lower:
                    continue

                # CNAME matched — fetch the page and verify fingerprint
                body = b""
                fetched_url = ""
                for scheme in ("https", "http"):
                    try:
                        r = session.get(f"{scheme}://{sub}", timeout=7, allow_redirects=True)
                        body        = r.content[:4096]
                        fetched_url = r.url
                        break
                    except Exception:
                        continue

                if fingerprint and fingerprint.lower() in body.lower():
                    findings.append({
                        "check":     "dns_takeover",
                        "severity":  "critical",
                        "target":    sub,
                        "url":       fetched_url or f"https://{sub}",
                        "detail":    (
                            f"Subdomain takeover risk: {sub} CNAME → {cname} "
                            f"({service_name}) — unclaimed resource fingerprint detected"
                        ),
                        "evidence":  f"CNAME: {cname}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source":    "takeover",
                    })
                    print(f"[bold red][!] Takeover: {sub} → {cname} ({service_name})[/bold red]")

                break  # only one service can match per subdomain

        except Exception:
            continue

    if findings:
        print(f"[bold red][!] DNS takeover: {len(findings)} potential takeover(s) found[/bold red]")
    else:
        print("[bold green][+] DNS takeover: no vulnerabilities found[/bold green]")

    return findings


# ── 4. SSL check ───────────────────────────────────────────────────────────────

def _run_ssl(dns_targets: set) -> list:
    if not dns_targets:
        return []
    try:
        return extract_tls_info(sorted(dns_targets)) or []
    except Exception as e:
        print(f"[dim][VendorPosture] SSL check error: {e}[/dim]")
        return []


# ── 5. Email security ─────────────────────────────────────────────────────────

def _run_email(root_domains: set) -> dict:
    if not root_domains:
        return {}
    try:
        return run_email_security(sorted(root_domains)) or {}
    except Exception as e:
        print(f"[dim][VendorPosture] Email security error: {e}[/dim]")
        return {}


# ── 6. Cert transparency ──────────────────────────────────────────────────────

def _run_ct(root_domains: set) -> list:
    if not root_domains:
        return []
    try:
        return run_cert_transparency_scan(domains=root_domains) or []
    except Exception as e:
        print(f"[dim][VendorPosture] Cert transparency error: {e}[/dim]")
        return []


# ── 7. DAST + nuclei (on live targets only, with tech map) ───────────────────

def _run_dast(live_targets: set, tech_map: dict = None) -> list:
    """
    Run DAST + nuclei on live targets only.
    tech_map: {hostname: [tech_name, ...]} from httpx probe — feeds nuclei template selection.
    Returns flat list of finding dicts.
    """
    if not live_targets:
        return []
    # Cap targets to avoid runaway nuclei scan on huge inventories
    targets_list = sorted(live_targets)[:_MAX_DAST_TARGETS]
    try:
        result = run_dast(targets_list, tech_map=tech_map or {}) or {}
        if isinstance(result, dict):
            return [f for findings in result.values() for f in findings]
        return result
    except Exception as e:
        print(f"[dim][VendorPosture] DAST error: {e}[/dim]")
        return []


# ── 8. Port scan ──────────────────────────────────────────────────────────────

def _run_ports(combined_targets: set) -> dict:
    """Returns {host: [open_ports]}."""
    from modules.portscan import PortScan
    results = {}
    scanner = PortScan()
    for host in combined_targets:
        try:
            ports = scanner.run(host, _TOP_100_FLAGS)
            if ports:
                results[host] = ports
        except Exception as e:
            print(f"[dim][VendorPosture] Port scan error for {host}: {e}[/dim]")
    return results


# ── Score calculation ──────────────────────────────────────────────────────────

def _calculate_score(
    ssl_results:   list,
    email_results: dict,
    ct_findings:   list,
    dast_findings: list,
    port_results:  dict,
) -> tuple[int, list]:
    """
    Returns (score, issues) where issues is a list of human-readable strings.
    takeover findings land in dast_findings with severity="critical".
    """
    score  = 100
    issues = []

    sev_weight = {"critical": 25, "high": 15, "medium": 5, "low": 0, "info": 0}

    # ── DAST + takeover ────────────────────────────────────────────────────────
    for f in dast_findings:
        sev = (f.get("severity") or "info").lower()
        w   = sev_weight.get(sev, 0)
        if w:
            score -= w
            check = f.get("check", f.get("type", "finding"))
            if check == "dns_takeover":
                issues.append(f"Takeover [critical]: {f.get('target', '?')} — {f.get('detail', '')[:80]}")
            else:
                issues.append(f"DAST [{sev}]: {check} on {f.get('target', f.get('url', '?'))}")

    # ── Cert transparency ──────────────────────────────────────────────────────
    for f in ct_findings:
        sev = (f.get("severity") or "info").lower()
        w   = sev_weight.get(sev, 0)
        if w:
            score -= w
            flags = ", ".join(f.get("flags") or [])
            issues.append(f"Cert CT [{sev}]: {f.get('san', f.get('domain', '?'))} ({flags})")

    # ── SSL ────────────────────────────────────────────────────────────────────
    for cert in ssl_results:
        days = cert.get("days_until_expiry")
        if days is not None and days < 0:
            score -= 25
            issues.append(f"SSL [critical]: Expired cert on {cert.get('host', '?')}")
        elif days is not None and days < 14:
            score -= 15
            issues.append(f"SSL [high]: Cert expiring in {days}d on {cert.get('host', '?')}")
        elif days is not None and days < 30:
            score -= 5
            issues.append(f"SSL [medium]: Cert expiring in {days}d on {cert.get('host', '?')}")
        if cert.get("self_signed"):
            score -= 15
            issues.append(f"SSL [high]: Self-signed cert on {cert.get('host', '?')}")

    # ── Email security ─────────────────────────────────────────────────────────
    for domain, result in email_results.items():
        spf   = result.get("spf",   {})
        dmarc = result.get("dmarc", {})
        if spf.get("status") not in ("ok",):
            score -= 10
            issues.append(f"Email [high]: Missing or invalid SPF on {domain} ({spf.get('status', '?')})")
        if dmarc.get("status") not in ("ok",):
            score -= 10
            issues.append(f"Email [high]: Missing or invalid DMARC on {domain} ({dmarc.get('status', '?')})")
        if dmarc.get("policy") == "none":
            score -= 5
            issues.append(f"Email [medium]: DMARC policy=none (monitoring only) on {domain}")

    # ── Unexpected open ports ──────────────────────────────────────────────────
    for host, ports in port_results.items():
        unexpected = [p for p in ports if p not in _EXPECTED_PORTS]
        if unexpected:
            score -= min(15, len(unexpected) * 5)
            issues.append(f"Ports [high]: Unexpected open ports on {host}: {sorted(unexpected)}")

    return max(0, score), issues


# ── Main entry point ───────────────────────────────────────────────────────────

def run_vendor_posture(
    slug:             str,
    vendor_name:      str,
    dns_targets:      set,
    combined_targets: set,
    root_domains:     set,
) -> dict:
    """
    Run a full external attack surface assessment for a vendor.

    Flow:
      1. Subdomain enum (parallel)
      2. Email security + cert transparency (parallel with step 1)
      3. httpx probe on original targets + discovered subdomains → live host list + tech stack
      4. DNS takeover check on all discovered subdomains
      5. SSL check on all live hosts (original + discovered)
      6. DAST + nuclei on live HTTP targets (tech-aware via httpx results)
      7. Port scan on combined_targets

    Returns:
        {
            "grade":    "A" | "B" | "C",
            "score":    int (0-100),
            "issues":   [str, ...],
            "details":  {
                "subdomains":   {domain: [sub, ...]},
                "live_hosts":   {hostname: {url, status, title, tech}},
                "ssl":          [...],
                "email":        {...},
                "cert_ct":      [...],
                "dast":         [...],   # includes takeover findings
                "ports":        {host: [port, ...]},
            },
            "scanned_at": str (ISO),
        }
    """
    print(f"[bold blue][*] Vendor Posture: starting assessment for {vendor_name}[/bold blue]")
    print(f"[dim]    Domains: {len(dns_targets)}  IPs: {len(combined_targets - dns_targets)}  Root domains: {len(root_domains)}[/dim]")

    # ── Phase 1: parallel passive recon ────────────────────────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        f_sub   = ex.submit(_run_subdomain, root_domains)
        f_email = ex.submit(_run_email,     root_domains)
        f_ct    = ex.submit(_run_ct,        root_domains)

        subdomain_results = f_sub.result()
        email_results     = f_email.result()
        ct_findings       = f_ct.result()

    # ── Phase 2: collect all discovered hostnames → httpx probe ────────────────
    all_discovered: set[str] = set()
    for subs in subdomain_results.values():
        all_discovered.update(subs)

    all_http_targets = dns_targets | all_discovered
    print(f"[dim]    Total HTTP targets after subdomain enum: {len(all_http_targets)}[/dim]")

    live_hosts = _run_httpx(all_http_targets)

    # Determine DAST targets: prefer live hosts from httpx, fall back to original targets
    live_set = set(live_hosts.keys()) if live_hosts else dns_targets

    # Build tech_map for nuclei template selection
    tech_map: dict[str, list[str]] = {
        host: info.get("tech", []) for host, info in live_hosts.items()
    }

    # ── Phase 3: active scans (sequential — resource-intensive) ────────────────
    # DNS takeover on all discovered subdomains
    takeover_findings = _check_dns_takeover(all_discovered)

    # SSL on all live + original targets
    ssl_targets = live_set | dns_targets
    ssl_results = _run_ssl(ssl_targets)

    # DAST + nuclei on live targets (tech-aware)
    dast_findings = _run_dast(live_set, tech_map=tech_map)

    # Merge takeover into dast findings (same schema → same DAST tab on dashboard)
    dast_findings = takeover_findings + dast_findings

    # Port scan on IPs + discovered live hosts (resolve IPs separately)
    port_results = _run_ports(combined_targets)

    # ── Score ───────────────────────────────────────────────────────────────────
    score, issues = _calculate_score(
        ssl_results, email_results, ct_findings, dast_findings, port_results
    )
    grade = _grade(score)
    color = _grade_color(grade)

    print(f"[bold {color}][{'!' if grade == 'C' else '*'}] Vendor Posture: {vendor_name} — Grade {grade} (score {score}/100)[/bold {color}]")
    if issues:
        for issue in issues[:10]:
            print(f"[dim]  • {issue}[/dim]")
        if len(issues) > 10:
            print(f"[dim]  … and {len(issues) - 10} more[/dim]")

    return {
        "grade":      grade,
        "score":      score,
        "issues":     issues,
        "details": {
            "subdomains": subdomain_results,
            "live_hosts": live_hosts,
            "ssl":        ssl_results,
            "email":      email_results,
            "cert_ct":    ct_findings,
            "dast":       dast_findings,
            "ports":      port_results,
        },
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
