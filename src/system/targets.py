import logging

from rich import print

from system.db import MongoDB
from system.hashing import calculate_hash
from system.network import is_private_ip

logger = logging.getLogger(__name__)

KNOWN_SOURCES = ["Cloudflare", "GCP", "cloudflare", "gcp", "GoDaddy", "godaddy", "AWS", "aws",
                 "subdomain_scan"]


def get_delta_records_from_mongo(current_records, collection_name,
                                 source_field="source", source_value=None):
    """Compare current records with existing MongoDB records to find new/changed ones.

    Returns only those records whose content hash is not yet in the collection.
    Falls back to returning all records if comparison fails.
    """
    try:
        mongo = MongoDB()
        collection = mongo.set_collection(collection_name)

        query = {source_field: source_value} if source_value else {}
        existing_records = list(collection.find(query))

        exclude_keys = {'_id', 'timestamp', 'lastUpdated', 'data_hash'}
        existing_hashes = set()
        for record in existing_records:
            comparable = {k: v for k, v in record.items() if k not in exclude_keys}
            existing_hashes.add(calculate_hash(comparable))

        delta_records = []
        for record in current_records:
            comparable = {k: v for k, v in record.items() if k not in exclude_keys}
            if calculate_hash(comparable) not in existing_hashes:
                delta_records.append(record)

        return delta_records

    except Exception as e:
        print(f"[bold yellow]Warning: Could not compare with existing records: {e}[/bold yellow]")
        return current_records


def get_delta_dns_records(current_dns_data, source="Cloudflare"):
    """Get new/changed DNS records by comparing with existing MongoDB data."""
    try:
        mongo = MongoDB()
        collection = mongo.set_collection("Prod DNS Records")

        query_source = source
        if source.lower() == "cloudflare":
            query_source = "Cloudflare"
        elif source.lower() == "gcp":
            query_source = "GCP"
        elif source.lower() == "godaddy":
            query_source = "GoDaddy"

        if source == "All":
            existing_records = list(collection.find({}))
        else:
            existing_records = list(collection.find({"source": query_source}))

        existing_signatures = set()
        for record in existing_records:
            sig = (
                f"{record.get('zone_name', '')}|{record.get('name', '')}|"
                f"{record.get('type', '')}|{record.get('content', '')}|"
                f"{record.get('proxied', '')}|{record.get('resource_type', '')}"
            )
            existing_signatures.add(sig)

        new_records = []
        for record in current_dns_data:
            sig = (
                f"{record.get('zone_name', '')}|{record.get('name', '')}|"
                f"{record.get('type', '')}|{record.get('content', '')}|"
                f"{record.get('proxied', '')}|{record.get('resource_type', '')}"
            )
            if sig not in existing_signatures:
                new_records.append(record)

        print(f"[bold blue]Delta Analysis: {len(new_records)} new records "
              f"out of {len(current_dns_data)} total records[/bold blue]")
        return new_records

    except Exception as e:
        print(f"[bold yellow]Warning: Could not get delta DNS records: {e}[/bold yellow]")
        return current_dns_data


def get_all_targets():
    """Fetch all unique public targets from MongoDB.

    Sources:
      1. Prod DNS Records  - flattened A/AAAA records
      2. Prod IP Records   - direct asset IPs

    Returns:
        ip_domain        - dict  {hostname: ip}
        dns_targets      - set   of public hostnames
        combined_targets - set   of all public IPs + hostnames
    """
    ip_domain = {}
    dns_targets = set()
    combined_targets = set()

    stats = {
        "total": 0, "active": 0,
        "type_a_aaaa": 0, "type_cname": 0, "type_other": 0,
        "private_ip": 0, "public_ip": 0, "missing_content": 0,
        "cf_inventory_ips": 0, "gcp_inventory_ips": 0, "godaddy_inventory_ips": 0, "aws_inventory_ips": 0,
        "dns_cloudflare": 0, "dns_gcp": 0, "dns_godaddy": 0,
        "gcp_inventory_public": 0, "gcp_inventory_private": 0,
        "cf_inventory_public": 0, "cf_inventory_private": 0,
        "godaddy_inventory_public": 0, "godaddy_inventory_private": 0,
        "aws_inventory_public": 0, "aws_inventory_private": 0,
    }

    try:
        db = MongoDB()
        dns_records_col = db.set_collection("Prod DNS Records")
        bulk_dns_col = db.set_collection("Prod DNS")
        ip_col = db.set_collection("Prod IP Records")

        seen_records = set()

        def _process_dns_record(source_name, dtype, name, content):
            sig = f"{source_name}|{name}|{dtype}|{content}"
            if sig in seen_records:
                return
            seen_records.add(sig)

            stats["total"] += 1
            stats["active"] += 1
            src = source_name.lower()
            if src == "cloudflare":
                stats["dns_cloudflare"] += 1
            elif src == "gcp":
                stats["dns_gcp"] += 1
            elif src == "godaddy":
                stats["dns_godaddy"] += 1

            if not name or not content:
                if dtype in ("A", "AAAA", "CNAME"):
                    stats["missing_content"] += 1
                return

            if dtype in ("A", "AAAA"):
                stats["type_a_aaaa"] += 1
                contents = content if isinstance(content, list) else [content]
                has_public = False
                for val in contents:
                    if val and isinstance(val, str):
                        if is_private_ip(val):
                            stats["private_ip"] += 1
                        else:
                            stats["public_ip"] += 1
                            has_public = True
                            ip_domain[name] = val
                            combined_targets.add(val)
                if has_public:
                    dns_targets.add(name)
            elif dtype == "CNAME":
                stats["type_cname"] += 1
                # AWS endpoint hostnames (LBs, RDS, EKS, CloudFront, API GW, Lambda)
                # and subdomain-scan discoveries are stored as CNAME records.
                # Add the hostname as a scannable target.
                if src in ("aws", "subdomain_scan") and name and not is_private_ip(name):
                    dns_targets.add(name)
                    combined_targets.add(name)
            else:
                stats["type_other"] += 1

        # 1a. Flattened DNS records
        for doc in dns_records_col.find({"source": {"$in": KNOWN_SOURCES}, "status": "active"}):
            _process_dns_record(
                doc.get("source", ""),
                (doc.get("type") or "").upper(),
                (doc.get("name") or "").rstrip("."),
                doc.get("content") or "",
            )

        # 1b. Bulk DNS records
        for doc in bulk_dns_col.find({"source": {"$in": KNOWN_SOURCES}, "status": "active"}):
            source_name = doc.get("source", "")
            for record in doc.get("records", []):
                _process_dns_record(
                    source_name,
                    (record.get("type") or "").upper(),
                    (record.get("name") or "").rstrip("."),
                    record.get("content") or record.get("data") or "",
                )

        # 2. IP records
        inventory_ips = set()
        for doc in ip_col.find({"status": "active"}):
            source = doc.get("source")

            if source in ("GCP", "gcp"):
                for ips in doc.get("resource_types", {}).values():
                    if not isinstance(ips, list):
                        continue
                    for ip in ips:
                        if ip and isinstance(ip, str):
                            if is_private_ip(ip):
                                stats["gcp_inventory_private"] += 1
                            else:
                                inventory_ips.add(ip)
                                stats["gcp_inventory_ips"] += 1
                                stats["gcp_inventory_public"] += 1

            elif source in ("Cloudflare", "cloudflare"):
                for entry in doc.get("records", []):
                    ip_list = entry.get("ip", [])
                    if isinstance(ip_list, list):
                        for ip_item in ip_list:
                            ip_val = ip_item.get("ip", "") if isinstance(ip_item, dict) else (ip_item if isinstance(ip_item, str) else "")
                            if ip_val:
                                if is_private_ip(ip_val):
                                    stats["cf_inventory_private"] += 1
                                else:
                                    inventory_ips.add(ip_val)
                                    stats["cf_inventory_ips"] += 1
                                    stats["cf_inventory_public"] += 1
                    elif isinstance(ip_list, str) and ip_list:
                        if is_private_ip(ip_list):
                            stats["cf_inventory_private"] += 1
                        else:
                            inventory_ips.add(ip_list)
                            stats["cf_inventory_ips"] += 1
                            stats["cf_inventory_public"] += 1

            elif source in ("GoDaddy", "godaddy"):
                for entry in doc.get("records", []):
                    ip_list = entry.get("ip", [])
                    if isinstance(ip_list, list):
                        for ip_item in ip_list:
                            ip_val = ip_item.get("ip", "") if isinstance(ip_item, dict) else (ip_item if isinstance(ip_item, str) else "")
                            if ip_val:
                                if is_private_ip(ip_val):
                                    stats["godaddy_inventory_private"] += 1
                                else:
                                    inventory_ips.add(ip_val)
                                    stats["godaddy_inventory_ips"] += 1
                                    stats["godaddy_inventory_public"] += 1

            elif source in ("AWS", "aws"):
                # resource_types is {rtype: [ip_or_hostname, ...]}
                # Values can be IPs (EC2, EIP, NAT) or DNS hostnames (LBs, RDS).
                # is_private_ip returns False for hostnames, so they pass through.
                for entries in doc.get("resource_types", {}).values():
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        if not entry or not isinstance(entry, str):
                            continue
                        if is_private_ip(entry):
                            stats["aws_inventory_private"] += 1
                        else:
                            inventory_ips.add(entry)
                            stats["aws_inventory_ips"] += 1
                            stats["aws_inventory_public"] += 1

        combined_targets.update(inventory_ips)
        combined_targets.update(dns_targets)

        _print_inventory_summary(stats, inventory_ips, combined_targets)

    except Exception as e:
        print(f"[bold red][-] Error fetching targets from inventory: {e}[/bold red]")
        return {}, set(), set()

    return ip_domain, dns_targets, combined_targets


def _print_inventory_summary(stats: dict, inventory_ips: set, combined_targets: set) -> None:
    total_inv_public = (
        stats["gcp_inventory_public"] + stats["cf_inventory_public"]
        + stats["godaddy_inventory_public"] + stats["aws_inventory_public"]
    )
    total_inv_private = (
        stats["gcp_inventory_private"] + stats["cf_inventory_private"]
        + stats["godaddy_inventory_private"] + stats["aws_inventory_private"]
    )

    print(f"[bold blue]Inventory Summary:[/bold blue]")
    print()
    print(f"[bold]DNS Records ({stats['active']})[/bold]")
    print(f"[dim]   ├─ Cloudflare:   {stats['dns_cloudflare']}[/dim]")
    print(f"[dim]   ├─ GCP:          {stats['dns_gcp']}[/dim]")
    print(f"[dim]   ├─ GoDaddy:      {stats['dns_godaddy']}[/dim]")
    print(f"[dim]   ├─ A/AAAA:       {stats['type_a_aaaa']}  |  CNAME: {stats['type_cname']}  |  Other: {stats['type_other']}[/dim]")
    print(f"[dim]   └─ Skipped:      {stats['missing_content']} (missing content)[/dim]")
    print()
    print(f"[bold]DNS IPs ({stats['public_ip'] + stats['private_ip']})[/bold]")
    print(f"[dim]   ├─ Public:       {stats['public_ip']}[/dim]")
    print(f"[dim]   └─ Private:      {stats['private_ip']} (filtered)[/dim]")
    print()
    print(f"[bold]Asset IPs ({total_inv_public + total_inv_private})[/bold]")
    print(f"[dim]   ├─ GCP:          {stats['gcp_inventory_public']} public / {stats['gcp_inventory_private']} private[/dim]")
    print(f"[dim]   ├─ Cloudflare:   {stats['cf_inventory_public']} public / {stats['cf_inventory_private']} private[/dim]")
    print(f"[dim]   ├─ GoDaddy:      {stats['godaddy_inventory_public']} public / {stats['godaddy_inventory_private']} private[/dim]")
    print(f"[dim]   ├─ AWS:          {stats['aws_inventory_public']} public / {stats['aws_inventory_private']} private[/dim]")
    print(f"[dim]   └─ Unique Public: {len(inventory_ips)}[/dim]")
    print()
    print(f"[bold green]Scanning Targets: {len(combined_targets)} unique (IPs + hostnames)[/bold green]")
