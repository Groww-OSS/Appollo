"""
Vendor management module.

Stores third-party vendor records in MongoDB (Vendors collection).
Each vendor has domains, IPs, and metadata. Scan results across all
existing collections are tagged with vendor_slug for filtering.
"""

import re
import os
from datetime import datetime, timezone

from rich import print
from system.db import MongoDB


def _slugify(name: str) -> str:
    """Convert vendor name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


def _db():
    return MongoDB()


# ── CRUD ─────────────────────────────────────────────────────────────────────

def add_vendor(name: str, domains: list, ips: list = None, description: str = "") -> dict:
    """
    Create or update a vendor. Returns the vendor document.
    Slug is derived from name and used as the unique key.
    """
    slug = _slugify(name)
    db   = _db()
    col  = db.set_collection("Vendors")

    now = datetime.now(timezone.utc)
    doc = {
        "name":           name,
        "slug":           slug,
        "domains":        [d.strip().lower() for d in (domains or []) if d.strip()],
        "ips":            [ip.strip() for ip in (ips or []) if ip.strip()],
        "description":    description,
        "updated_at":     now,
    }

    existing = col.find_one({"slug": slug})
    if existing:
        col.update_one({"slug": slug}, {"$set": doc})
        print(f"[green][+] Vendor updated: {name} ({slug})[/green]")
    else:
        doc["created_at"]     = now
        doc["last_scanned_at"] = None
        col.insert_one(doc)
        print(f"[green][+] Vendor created: {name} ({slug})[/green]")

    return col.find_one({"slug": slug}, {"_id": 0})


def get_vendor(slug: str) -> dict:
    """Fetch a vendor by slug. Returns None if not found."""
    col = _db().set_collection("Vendors")
    return col.find_one({"slug": slug}, {"_id": 0})


def list_vendors() -> list:
    """Return all vendors sorted by name."""
    col = _db().set_collection("Vendors")
    return list(col.find({}, {"_id": 0}).sort("name", 1))


def delete_vendor(slug: str) -> bool:
    col    = _db().set_collection("Vendors")
    result = col.delete_one({"slug": slug})
    return result.deleted_count > 0


def update_last_scanned(slug: str):
    col = _db().set_collection("Vendors")
    col.update_one({"slug": slug}, {"$set": {"last_scanned_at": datetime.now(timezone.utc)}})


# ── Target helpers ────────────────────────────────────────────────────────────

def get_vendor_targets(slug: str) -> tuple:
    """
    Returns (dns_targets, combined_targets) for a vendor.
      dns_targets   — set of hostnames (for HTTP-based scans)
      combined      — set of IPs + hostnames (for network scans)
    """
    vendor = get_vendor(slug)
    if not vendor:
        print(f"[bold red][-] Vendor not found: {slug}[/bold red]")
        return set(), set()

    domains = set(vendor.get("domains") or [])
    ips     = set(vendor.get("ips") or [])

    dns_targets = domains           # hostnames only for DAST/SSL/etc.
    combined    = domains | ips     # IPs + hostnames for port scans

    return dns_targets, combined


def get_root_domains(slug: str) -> set:
    """Return root domains only (for subdomain enum, email security, cert CT)."""
    vendor = get_vendor(slug)
    if not vendor:
        return set()
    roots = set()
    for domain in (vendor.get("domains") or []):
        parts = domain.split(".")
        if len(parts) >= 2:
            roots.add(".".join(parts[-2:]))
    return roots
