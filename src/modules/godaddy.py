import argparse
import glob
import ipaddress
import logging
import os
import re
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich import print

from system.db import MongoDB
from system.hashing import calculate_hash

logger = logging.getLogger(__name__)


class GoDaddy:
    """Parse GoDaddy-exported BIND zone files and store records in MongoDB.

    Mirrors the Cloudflare module: writes to the same three collections
    (Prod DNS, Prod DNS Records, Prod IP Records) so the rest of the
    pipeline (targets.py, scan modules) sees GoDaddy domains transparently.

    The .txt files are standard BIND / RFC-1035 zone exports produced by
    GoDaddy's "Export Zone File" feature.  One file per domain.
    """

    SOURCE = "GoDaddy"

    # name  ttl  IN  type  data
    _RECORD_RE = re.compile(
        r'^(\S+)\s+(\d+)\s+IN\s+(\w+)\s+(.+)$',
        re.IGNORECASE,
    )

    def __init__(self, txt_dir: str = None):
        """
        Args:
            txt_dir: Directory that contains the *.txt zone files.
                     Defaults to the GODADDY_ZONE_DIR env var, then cwd.
        """
        self.txt_dir = txt_dir or os.getenv("GODADDY_ZONE_DIR") or os.getcwd()

    # ── Zone-file parsing ─────────────────────────────────────────────

    def _find_zone_files(self) -> list:
        return sorted(glob.glob(os.path.join(self.txt_dir, "*.txt")))

    def _expand_name(self, name: str, origin: str) -> str:
        """Resolve a zone-file name to a fully-qualified hostname string."""
        if name == "@":
            return origin
        if name.endswith("."):
            return name.rstrip(".")
        return f"{name}.{origin}"

    def _parse_content(self, rtype: str, data: str) -> str:
        """Normalise record content for storage."""
        data = data.strip()
        if rtype in ("A", "AAAA"):
            return data
        if rtype in ("CNAME", "NS", "PTR"):
            return data.rstrip(".")
        if rtype == "MX":
            # data = "priority target."  →  return just the target
            parts = data.split(None, 1)
            return parts[1].rstrip(".") if len(parts) > 1 else data.rstrip(".")
        if rtype == "TXT":
            # Strip wrapping double-quotes and trim leading/trailing whitespace
            return data.strip('"').strip()
        return data

    def parse_zone_file(self, filepath: str):
        """Parse a single BIND zone file exported by GoDaddy.

        Returns:
            (zone_name, list_of_record_dicts)
        """
        with open(filepath) as f:
            content = f.read()

        # Determine origin (apex domain)
        m = re.search(r'^\$ORIGIN\s+(\S+)', content, re.MULTILINE)
        origin = m.group(1).rstrip(".") if m else Path(filepath).stem

        # Collapse SOA multi-line parenthesised block so the lines inside
        # don't get mis-parsed as regular records.
        content = re.sub(r'\([\s\S]*?\)', '', content)

        records = []
        for line in content.splitlines():
            line = line.strip()

            # Skip blank lines, comment lines, and BIND directives
            if not line or line.startswith(";") or line.startswith("$"):
                continue

            m = self._RECORD_RE.match(line)
            if not m:
                continue

            name_raw = m.group(1)
            ttl = int(m.group(2))
            rtype = m.group(3).upper()
            data = m.group(4).strip()

            # SOA records are informational; skip them
            if rtype == "SOA":
                continue

            name = self._expand_name(name_raw, origin)
            content_val = self._parse_content(rtype, data)

            records.append({
                "name": name,
                "ttl": ttl,
                "type": rtype,
                "content": content_val,
                "zone_name": origin,
            })

        return origin, records

    def load_all_zones(self) -> dict:
        """Parse every *.txt zone file in txt_dir.

        Returns a dict keyed by zone name:
            { "finity.in": {"domain": "finity.in", "records": [...], "file": "..."}, ... }
        """
        zone_files = self._find_zone_files()
        if not zone_files:
            print(f"[bold yellow][!] No .txt zone files found in: {self.txt_dir}[/bold yellow]")
            return {}

        print(f"[bold blue][+] Loading {len(zone_files)} GoDaddy zone file(s) from {self.txt_dir}[/bold blue]")
        zones = {}
        for fp in zone_files:
            try:
                zone_name, records = self.parse_zone_file(fp)
                zones[zone_name] = {
                    "domain": zone_name,
                    "records": records,
                    "file": fp,
                }
                print(f"[dim]    - {zone_name}: {len(records)} records[/dim]")
            except Exception as e:
                print(f"[bold red][-] Failed to parse {fp}: {e}[/bold red]")

        return zones

    # ── MongoDB writers (mirror Cloudflare pattern) ───────────────────

    def process_records(self, zones: dict, collection) -> None:
        """Upsert each zone as a single bulk document in 'Prod DNS'."""
        if not zones:
            return

        stored = 0
        for zone_name, zone_data in zones.items():
            record_data = {
                "source": self.SOURCE,
                "domain": zone_data["domain"],
                "records": zone_data["records"],
                "status": "active",
            }
            data_hash = calculate_hash(record_data)
            now = datetime.now()

            try:
                collection.update_one(
                    {"domain": zone_name, "source": self.SOURCE},
                    {
                        "$set": {**record_data, "data_hash": data_hash},
                        "$setOnInsert": {"timestamp": now},
                    },
                    upsert=True,
                )
                stored += 1
            except Exception as e:
                print(f"[bold red][!] Error storing bulk record for {zone_name}: {e}[/bold red]")

        if stored:
            print(f"[green]✓ {self.SOURCE} Bulk DNS: {stored} zones stored in 'Prod DNS'[/green]")

    def process_ip(self, zones: dict, collection) -> None:
        """Upsert A/AAAA IPs per zone into 'Prod IP Records'."""
        if not zones:
            return

        stored = 0
        for zone_name, zone_data in zones.items():
            ips = []
            seen = set()
            for record in zone_data["records"]:
                if record["type"] not in ("A", "AAAA"):
                    continue
                ip = record["content"]
                if not ip or ip in seen:
                    continue
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                seen.add(ip)
                ips.append({
                    "ip": ip,
                    "name": record["name"],
                    "resource_type": "godaddy_ip",
                    "type": record["type"],
                    "proxied": False,
                    "ttl": record["ttl"],
                    "zone_name": zone_name,
                })

            if not ips:
                continue

            data_hash = calculate_hash({
                "source": self.SOURCE,
                "domain": zone_name,
                "records": [{"domain": zone_name, "ip": ips}],
                "status": "active",
            })
            now = datetime.now()

            try:
                collection.update_one(
                    {"domain": zone_name, "source": self.SOURCE},
                    {
                        "$set": {
                            "source": self.SOURCE,
                            "domain": zone_name,
                            "records": [{"domain": zone_name, "ip": ips}],
                            "status": "active",
                            "data_hash": data_hash,
                        },
                        "$setOnInsert": {"timestamp": now},
                    },
                    upsert=True,
                )
                stored += 1
            except Exception as e:
                print(f"[bold red][!] Error storing IP record for {zone_name}: {e}[/bold red]")

        if stored:
            print(f"[green]✓ {self.SOURCE} IP Records: {stored} zones stored in 'Prod IP Records'[/green]")

    def process_individual_dns_records(self, zones: dict, collection) -> None:
        """Upsert individual flattened records into 'Prod DNS Records'.

        Follows the same hash-keyed upsert pattern as Cloudflare so that
        targets.py can query the collection uniformly.
        """
        if not zones:
            return

        individual_records = []
        for zone_name, zone_data in zones.items():
            for record in zone_data["records"]:
                rec = {
                    "zone_name": zone_name,
                    "name": record["name"],
                    "type": record["type"],
                    "content": record["content"],
                    "proxied": False,
                    "resource_type": "godaddy_dns",
                    "source": self.SOURCE,
                    "zone": zone_name,
                }
                rec_hash = calculate_hash(rec)
                individual_records.append({
                    **rec,
                    "hash": rec_hash,
                    "status": "active",
                    "ttl": record["ttl"],
                    "timestamp": datetime.now(),
                })

        if not individual_records:
            print(f"[bold yellow][+] No {self.SOURCE} individual DNS records to store[/bold yellow]")
            return

        stored = skipped = 0
        for record in individual_records:
            try:
                ts = record.pop("timestamp", datetime.now())
                result = collection.update_one(
                    {"hash": record["hash"]},
                    {
                        "$set": record,
                        "$setOnInsert": {"timestamp": ts},
                    },
                    upsert=True,
                )
                if result.upserted_id or result.modified_count > 0:
                    stored += 1
                else:
                    skipped += 1
            except Exception as e:
                print(f"[bold yellow][!] Error upserting {self.SOURCE} record: {e}[/bold yellow]")
                skipped += 1

        if stored:
            print(f"[green]✓ {self.SOURCE} Individual DNS Records: {stored} stored/updated[/green]")
        if skipped:
            print(f"[yellow]  {self.SOURCE} Individual DNS Records: {skipped} unchanged/skipped[/yellow]")

    # ── Entry point ───────────────────────────────────────────────────

    def run(self) -> None:
        zones = self.load_all_zones()
        if not zones:
            return

        mongo = MongoDB()
        dns_col = mongo.set_collection("Prod DNS")
        ip_col = mongo.set_collection("Prod IP Records")
        dns_records_col = mongo.set_collection("Prod DNS Records")

        self.process_records(zones, dns_col)
        self.process_ip(zones, ip_col)
        self.process_individual_dns_records(zones, dns_records_col)

        total_dns = sum(len(z["records"]) for z in zones.values())
        total_ips = sum(
            len([r for r in z["records"] if r["type"] in ("A", "AAAA")])
            for z in zones.values()
        )

        print(f"\n[bold blue]📊 {self.SOURCE} Inventory Statistics:[/bold blue]")
        print(f"[dim] - Total Zones Scanned:       {len(zones)}[/dim]")
        print(f"[dim] - Total DNS Records:          {total_dns}[/dim]")
        print(f"[dim] - Total IP Records (A/AAAA):  {total_ips}[/dim]")
        print(f"[bold green]  {self.SOURCE} inventory scan completed![/bold green]\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GoDaddy zone-file importer")
    parser.add_argument("-e", "--env", required=True, help="Path to .env file")
    parser.add_argument("-d", "--dir", default=None, help="Directory containing *.txt zone files (default: cwd)")
    args = parser.parse_args()

    load_dotenv(args.env)
    GoDaddy(txt_dir=args.dir).run()
