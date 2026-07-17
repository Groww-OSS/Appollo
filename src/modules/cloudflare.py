import os
import logging
import warnings
from urllib.parse import urlencode

import ipaddress
import requests
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from rich import print

from system.db import MongoDB
from system.utils import calculate_hash, check_if_hash_exists, add_hash_to_db

"""
    This class is used to fetch the DNS records from Cloudflare and store them in MongoDB.
    It has the following methods:
    1. __init__: Initializes the Cloudflare class with the configuration settings.
    2. fetch_domains: Fetches the domains from Cloudflare.
    3. get_dns_records: Fetches the DNS records from Cloudflare.
    4. process_records: Processes the DNS records and stores them in MongoDB.
    5. process_ip: Extracts the IPs from the DNS records and stores them in MongoDB.
    6. run: The main method that runs the class.
    
"""

class Cloudflare:
    SOURCE = "Cloudflare"

    @staticmethod
    def _normalize_tags(record: dict) -> list:
        """Return sorted tag list for stable storage and hashing."""
        raw = record.get("tags")
        if not raw:
            return []
        if isinstance(raw, list):
            return sorted(str(t) for t in raw)
        if isinstance(raw, str):
            return sorted(x.strip() for x in raw.split(",") if x.strip())
        return []

    @staticmethod
    def _normalize_comment(record: dict) -> str:
        c = record.get("comment")
        return c.strip() if isinstance(c, str) else ""

    @staticmethod
    def _normalize_zone_tags(tags: object) -> dict:
        """Normalize zone-level tag map (API: string key -> string value)."""
        if not isinstance(tags, dict) or not tags:
            return {}
        out = {}
        for k, v in tags.items():
            if k is None:
                continue
            key = str(k).strip()
            if not key:
                continue
            out[key] = "" if v is None else str(v)
        return dict(sorted(out.items()))

    def _fetch_zone_tags(self, zone_id: str) -> dict:
        """Fetch Cloudflare resource tags for the zone object (resource_type=zone)."""
        if not zone_id:
            return {}
        try:
            q = urlencode({"resource_id": zone_id, "resource_type": "zone"})
            url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/tags?{q}"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return {}
            payload = response.json()
            if not payload.get("success"):
                return {}
            result = payload.get("result") or {}
            return self._normalize_zone_tags(result.get("tags"))
        except Exception as e:
            self.logger.debug("Zone tags unavailable for zone: %s", e)
            return {}

    def __init__(self):
        self.api_key = os.getenv("CLOUDFLARE_API_KEY")
        if not self.api_key:
            raise RuntimeError("CRITICAL: CLOUDFLARE_API_KEY environment variable is not set.")

        self.logger = logging.getLogger("cloudflare_collector")
        self.timeout = 60
        self.verify = True

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        })

        cf_ca = os.environ.get("CLOUDFLARE_CA_BUNDLE")
        if cf_ca:
            self.verify = cf_ca

        self.session.verify = self.verify

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def fetch_domains(self):
        all_zones = []
        page = 1
        per_page = 50  
        try:
            print(f"[bold blue][+] Fetching domains from Cloudflare[/bold blue]")
            while True:
                url = f"https://api.cloudflare.com/client/v4/zones?page={page}&per_page={per_page}"
                response = self.session.get(url, timeout=self.timeout)
                print(f"[dim]    - Page {page}: Status {response.status_code}[/dim]")
                
                if response.status_code != 200:
                    print(f"[bold red][-] Error fetching domains: HTTP {response.status_code}[/bold red]")
                    print(f"[dim]    Response: {response.text}[/dim]")
                    break
                
                data = response.json()
                zones = data.get("result", [])
                print(f"[dim]    - Found {len(zones)} zones on this page[/dim]")
                all_zones.extend(zones)
                
                result_info = data.get("result_info", {})
                total_pages = result_info.get("total_pages", 1)
                
                if page >= total_pages:
                    break
                page += 1
                
            print(f"[bold green][+] Total domains found: {len(all_zones)}[/bold green]")
            return all_zones
        except requests.exceptions.SSLError as e:
            print(f"[red][-] Cloudflare TLS verification failed: {e}. Configure CLOUDFLARE_CA_BUNDLE or set CLOUDFLARE_VERIFY=false (testing only).[/red]")
            return []
        except Exception as e:
            print(f"[red]Error fetching domains from Cloudflare: {e}[/red]")
            return []
    
    def _fetch_zone_records(self, domain):
        """Helper to fetch all DNS records for a single zone with pagination."""
        try:
            all_zone_records = []
            page = 1
            per_page = 100
            
            while True:
                request_url = f"https://api.cloudflare.com/client/v4/zones/{domain['id']}/dns_records?page={page}&per_page={per_page}"
                response = self.session.get(request_url, timeout=self.timeout)
                
                if response.status_code != 200:
                    print(f"[-] Error fetching DNS records for {domain.get('name')}: HTTP {response.status_code}")
                    return domain['id'], None
                
                data = response.json()
                records = data.get("result", [])
                
                for record in records:
                    # Drop provider meta only; keep comment + tags from the API for inventory.
                    record.pop("meta", None)

                all_zone_records.extend(records)
                
                result_info = data.get("result_info", {})
                total_pages = result_info.get("total_pages", 1)
                
                if page >= total_pages:
                    break
                page += 1

            zid = domain["id"]
            zone_tags = self._fetch_zone_tags(zid)
            return zid, {
                "domain": domain["name"],
                "records": all_zone_records,
                "zone_tags": zone_tags,
            }
            
        except requests.exceptions.SSLError as e:
            print(f"[red][-] Cloudflare TLS verification failed for zone {domain.get('name')}: {e}[/red]")
            return domain['id'], None
        except Exception as e:
            print(f"[yellow] Warning: error fetching records for {domain.get('name')}: {e}[/yellow]")
            return domain['id'], None
    
    def get_dns_records(self, domains):
        """Fetch DNS records for all domains in parallel."""
        try:
            dnsRecords = {}
            if not domains:
                return dnsRecords
            
            print(f"[bold blue][+] Fetching DNS records for {len(domains)} domains in parallel...[/bold blue]")
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self._fetch_zone_records, domain) for domain in domains]
                
                for future in as_completed(futures):
                    zone_id, result = future.result()
                    if result:
                        dnsRecords[zone_id] = result
                        
            return dnsRecords
            
        except Exception as e:
            print(f"[red]Error building DNS records: {e}[/red]")
            return {}
    
    def cleanup_stale_data(self, active_zones):
        """Archive records for zones that no longer exist in Cloudflare."""
        if not active_zones:
            return
        try:
            mongo = MongoDB()
            archive_data = {"$set": {"status": "archived", "archived_at": datetime.now()}}
            active_ids = [z['id'] for z in active_zones]
            active_names = [z['name'] for z in active_zones]

            dns_col = mongo.set_collection("Prod DNS")
            res_dns = dns_col.update_many({
                "source": self.SOURCE,
                "_id": {"$nin": active_ids},
                "status": {"$ne": "archived"}
            }, archive_data)

            ip_col = mongo.set_collection("Prod IP Records")
            res_ip = ip_col.update_many({
                "source": self.SOURCE,
                "records.domain": {"$nin": active_names},
                "status": {"$ne": "archived"}
            }, archive_data)


            dns_rec_col = mongo.set_collection("Prod DNS Records")
            res_rec = dns_rec_col.update_many({
                "source": self.SOURCE,
                "zone_name": {"$nin": active_names},
                "status": {"$ne": "archived"}
            }, archive_data)

            if res_dns.modified_count > 0 or res_ip.modified_count > 0 or res_rec.modified_count > 0:
                print(f"[bold yellow]  Archiving stale {self.SOURCE} data...[/bold yellow]")
                if res_dns.modified_count > 0: print(f"[dim] - Archived {res_dns.modified_count} stale zones in 'Prod DNS'[/dim]")
                if res_ip.modified_count > 0: print(f"[dim] - Archived {res_ip.modified_count} stale domains in 'Prod IP Records'[/dim]")
                if res_rec.modified_count > 0: print(f"[dim] - Archived {res_rec.modified_count} stale records in 'Prod DNS Records'[/dim]")

        except Exception as e:
            print(f"[bold red][-] Error during {self.SOURCE} stale data cleanup: {e}[/bold red]")
    
    def process_records(self, dnsRecords, collection):
        """Store each zone as an individual document in the bulk DNS collection."""
        if not dnsRecords:
            return

        stored_count = 0
        for zone_id, value in dnsRecords.items():
            record_data = {
                "source": self.SOURCE,
                "domain": value["domain"],
                "records": value["records"],
                "zone_tags": value.get("zone_tags") or {},
                "status": "active"
            }
            data_hash = calculate_hash(record_data)
            timestamp = datetime.now()

            try:
                collection.update_one(
                    {"_id": zone_id},
                    {
                        "$set": {
                            "source": self.SOURCE,
                            "domain": value["domain"],
                            "records": value["records"],
                            "zone_tags": value.get("zone_tags") or {},
                            "status": "active",
                            "data_hash": data_hash
                        },
                        "$setOnInsert": {"timestamp": timestamp}
                    },
                    upsert=True
                )
                stored_count += 1
            except Exception as e:
                print(f"[bold red][!] Error storing bulk record for {value['domain']}: {e}[/bold red]")

        if stored_count > 0:
            print(f"[green]✓ {self.SOURCE} Bulk DNS: {stored_count} zones processed in 'Prod DNS'[/green]")

    def process_ip(self, dnsRecords, collection):
        """Store each domain's IPs as an individual document in the IP Records collection."""
        if not dnsRecords:
            return

        stored_count = 0
        for zone_id, values in dnsRecords.items():
            domain_name = values["domain"]
            ips = []
            ip_set = set()
            for record in values["records"]:
                if record.get("type") in ["A", "AAAA"]:
                    ip = record.get("content", "")
                    if not ip:
                        continue
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue

                    if ip not in ip_set:
                        ips.append({
                            "ip": ip,
                            "name": record.get("name", ""),
                            "resource_type": "cloudflare_ip",
                            "type": record["type"],
                            "proxied": record.get("proxied", False),
                            "ttl": record.get("ttl", 1),
                            "zone_name": record.get("zone_name", ""),
                            "comment": self._normalize_comment(record),
                            "tags": self._normalize_tags(record),
                        })
                        ip_set.add(ip)

            if ips:
                zt = values.get("zone_tags") or {}
                data_hash = calculate_hash({
                    "source": self.SOURCE,
                    "domain": domain_name,
                    "zone_tags": zt,
                    "records": [{"domain": domain_name, "ip": ips}],
                    "status": "active"
                })
                timestamp = datetime.now()

                try:
                    collection.update_one(
                        {"zone_id": zone_id, "source": self.SOURCE},
                        {
                            "$set": {
                                "source": self.SOURCE,
                                "domain": domain_name,
                                "zone_tags": values.get("zone_tags") or {},
                                "records": [{"domain": domain_name, "ip": ips}],
                                "status": "active",
                                "data_hash": data_hash
                            },
                            "$setOnInsert": {"timestamp": timestamp}
                        },
                        upsert=True
                    )
                    stored_count += 1
                except Exception as e:
                    print(f"[bold red][!] Error storing IP record for {domain_name}: {e}[/bold red]")

        if stored_count > 0:
            print(f"[green]✓ {self.SOURCE} IP Records: {stored_count} domains processed in 'Prod IP Records'[/green]")

    def process_individual_dns_records(self, dnsRecords, dns_records_collection):
        """Process and store individual DNS records in the DNS Records collection.
        
        Mirrors the GCP pattern: build a list of complete record dicts (including
        hash, status, timestamp), then upsert each one by hash. This ensures every
        record in 'Prod DNS Records' has all required fields for downstream queries.
        """
        if not dnsRecords:
            print(f"[yellow]No individual DNS records to process for {self.SOURCE}[/yellow]")
            return


        individual_dns_records = []
        for zone_id, zone_data in dnsRecords.items():
            domain_name = zone_data["domain"]
            zone_tags = zone_data.get("zone_tags") or {}
            for record in zone_data.get("records", []):
                # Hash identity only so comment/tag updates merge into the same document.
                record_identity = {
                    'zone_name': domain_name,
                    'name': record.get('name', ''),
                    'type': record.get('type', ''),
                    'content': record.get('content', ''),
                    'proxied': record.get('proxied', False),
                    'resource_type': 'cloudflare_dns',
                    'source': self.SOURCE,
                    'zone': domain_name
                }
                record_hash = calculate_hash(record_identity)

                individual_record = {
                    **record_identity,
                    'comment': self._normalize_comment(record),
                    'tags': self._normalize_tags(record),
                    'zone_tags': zone_tags,
                }
                individual_record['hash'] = record_hash
                individual_record['status'] = 'active'
                individual_record['timestamp'] = datetime.now()
                individual_record['ttl'] = record.get('ttl', 1)

                individual_dns_records.append(individual_record)

        if not individual_dns_records:
            print(f"[bold yellow][+] No {self.SOURCE} DNS records found to store in 'DNS Records' collection[/bold yellow]")
            return

        stored_count = 0
        skipped_count = 0

        for record in individual_dns_records:
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
                print(f"[bold yellow][!] Error upserting {self.SOURCE} DNS record: {e}[/bold yellow]")
                skipped_count += 1

        if stored_count > 0:
            print(f"[green]✓ {self.SOURCE} Individual DNS Records: {stored_count} stored/updated[/green]")
        if skipped_count > 0:
            print(f"[yellow]  {self.SOURCE} Individual DNS Records: {skipped_count} unchanged/skipped[/yellow]")

    def run(self):
        domains = self.fetch_domains() or []
        dnsRecords = self.get_dns_records(domains) or {}
        
        mongo = MongoDB()
        ip_collection = mongo.set_collection("Prod IP Records")
        dns_collection = mongo.set_collection("Prod DNS")
        dns_records_collection = mongo.set_collection("Prod DNS Records")
        
        self.process_records(dnsRecords, dns_collection)
        self.process_ip(dnsRecords, ip_collection)
        self.process_individual_dns_records(dnsRecords, dns_records_collection)

        self.cleanup_stale_data(domains)

        total_ips = sum(len([r for r in z.get('records', []) if r.get('type') in ['A', 'AAAA']]) for z in dnsRecords.values())
        total_dns = sum(len(z.get('records', [])) for z in dnsRecords.values())

        print(f"\n[bold blue]📊 {self.SOURCE} Inventory Statistics:[/bold blue]")
        print(f"[dim] - Total Zones Scanned:  {len(domains)}[/dim]")
        print(f"[dim] - Total DNS Records:    {total_dns}[/dim]")
        print(f"[dim] - Total IP Records (A/AAAA): {total_ips}[/dim]")
        print(f"[bold green]  {self.SOURCE} inventory scan completed![/bold green]\n")