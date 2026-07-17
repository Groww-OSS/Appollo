"""
Email security checks: SPF, DMARC, and DKIM (common selectors).

All checks are passive DNS-only queries — no SMTP connections made.
Findings are severity-rated:
  critical — no SPF + no DMARC (fully open to spoofing)
  high     — SPF missing or "+all" (anyone can send), DMARC missing
  medium   — SPF "~all" (softfail), DMARC p=none (no enforcement)
  low      — minor misconfigs (no rua/ruf reporting)
"""

import re
import concurrent.futures
from datetime import datetime

import dns.resolver
from rich import print

_DKIM_SELECTORS = [
    "default", "google", "k1", "k2", "mail", "dkim",
    "selector1", "selector2", "s1", "s2", "smtp", "email",
]

_DNS_TIMEOUT = 5  # seconds per query


def _txt_records(name: str) -> list[str]:
    """Return all TXT record strings for *name*, empty list on failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNS_TIMEOUT
        answers = resolver.resolve(name, "TXT")
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def check_spf(domain: str) -> dict:
    """
    Returns:
        status: ok | weak | missing | misconfigured
        value:  the SPF record string or None
        issue:  human-readable description of the problem
    """
    records = [t for t in _txt_records(domain) if t.startswith("v=spf1")]
    if not records:
        return {"status": "missing", "value": None,
                "issue": "No SPF record — anyone can spoof sender from this domain."}

    spf = records[0]
    if "+all" in spf:
        return {"status": "misconfigured", "value": spf,
                "issue": "+all allows any host to send mail — effective no-op protection."}
    if "?all" in spf:
        return {"status": "weak", "value": spf,
                "issue": "?all (neutral) gives no protection against spoofing."}
    if "~all" in spf:
        return {"status": "weak", "value": spf,
                "issue": "~all (softfail) — messages pass most spam filters, use -all instead."}
    if "-all" in spf:
        return {"status": "ok", "value": spf, "issue": ""}

    return {"status": "weak", "value": spf, "issue": "No explicit 'all' mechanism — effectiveness unclear."}


def check_dmarc(domain: str) -> dict:
    """
    Returns:
        status: ok | weak | missing
        value:  the DMARC record string or None
        policy: none | quarantine | reject | (missing)
        issue:  human-readable description
    """
    records = [t for t in _txt_records(f"_dmarc.{domain}") if "v=DMARC1" in t]
    if not records:
        return {"status": "missing", "value": None, "policy": "missing",
                "issue": "No DMARC record — phishing/spoofing not mitigated at receiver."}

    dmarc = records[0]
    m = re.search(r"\bp=(\w+)", dmarc)
    policy = m.group(1).lower() if m else "none"

    if policy == "none":
        return {"status": "weak", "value": dmarc, "policy": policy,
                "issue": "p=none — monitor only, emails are NOT rejected/quarantined."}
    if policy == "quarantine":
        return {"status": "ok", "value": dmarc, "policy": policy,
                "issue": "p=quarantine — consider upgrading to p=reject for full enforcement."}
    if policy == "reject":
        return {"status": "ok", "value": dmarc, "policy": policy, "issue": ""}

    return {"status": "weak", "value": dmarc, "policy": policy,
            "issue": f"Unknown DMARC policy: {policy}"}


def check_dkim(domain: str) -> dict:
    """
    Probe common DKIM selectors. Returns the first one found.
    DKIM is selector-specific so a miss doesn't mean it's absent —
    we flag it as 'unknown' rather than 'missing'.
    """
    for sel in _DKIM_SELECTORS:
        records = _txt_records(f"{sel}._domainkey.{domain}")
        for r in records:
            if "v=DKIM1" in r or "k=rsa" in r or "p=" in r:
                return {"status": "ok", "selector": sel, "value": r[:200]}
    return {"status": "unknown",
            "issue": "No DKIM record found for common selectors — may use non-standard selector."}


def _severity_for(spf: dict, dmarc: dict) -> str:
    spf_bad   = spf["status"] in ("missing", "misconfigured")
    dmarc_bad = dmarc["status"] == "missing"
    if spf_bad and dmarc_bad:
        return "critical"
    if spf_bad or dmarc_bad:
        return "high"
    if spf["status"] == "weak" or dmarc["status"] == "weak":
        return "medium"
    return "ok"


def check_domain(domain: str) -> dict:
    """Run all email security checks for a single domain."""
    spf   = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim  = check_dkim(domain)
    return {
        "domain":   domain,
        "spf":      spf,
        "dmarc":    dmarc,
        "dkim":     dkim,
        "severity": _severity_for(spf, dmarc),
        "checked_at": datetime.utcnow().isoformat(),
    }


def run_email_security(domains: list, max_workers: int = 20) -> dict:
    """
    Check SPF, DMARC, DKIM for a list of domains concurrently.

    Returns:
        {domain: {spf, dmarc, dkim, severity, checked_at}}
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(check_domain, d): d for d in domains}
        for f in concurrent.futures.as_completed(futs):
            d = futs[f]
            try:
                results[d] = f.result()
            except Exception as e:
                print(f"[bold red][-] Email security check failed for {d}: {e}[/bold red]")
    return results
