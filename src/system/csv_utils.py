import ast
import csv
import json
import os

import pandas as pd


def save_wayback_to_csv(new_data: dict, file_path: str) -> None:
    """Append new wayback URL data to an existing CSV (or create one)."""
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        df_existing = pd.read_csv(file_path)
    else:
        df_existing = pd.DataFrame(columns=["Domain", "URL"])

    rows = []
    for domain, links in new_data.items():
        for link in links:
            rows.append([domain, link])

    df_new = pd.DataFrame(rows, columns=["Domain", "URL"])
    df_combined = pd.concat([df_existing, df_new], ignore_index=True).drop_duplicates()
    df_combined.to_csv(file_path, index=False)


def save_port_scan_to_csv(new_data: dict, file_path: str) -> None:
    """Append new port scan data to an existing CSV (or create one)."""
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        df_existing = pd.read_csv(file_path)
    else:
        df_existing = pd.DataFrame(columns=["Domain", "IP", "Port"])

    rows = []
    for domain, info in new_data.items():
        ip = info['ip']
        for port in info['ports']:
            rows.append([domain, ip, port])

    df_new = pd.DataFrame(rows, columns=["Domain", "IP", "Port"])
    df_combined = pd.concat([df_existing, df_new], ignore_index=True).drop_duplicates()
    df_combined.to_csv(file_path, index=False)


def read_from_csv(file_path: str) -> dict:
    """Read results from a CSV file, auto-detecting format by column names.

    Returns:
        Port scan CSVs     -> {domain: [port1, port2, ...]}
        Wayback CSVs       -> {domain: [url1, url2, ...]}
        Dangling DNS CSVs  -> {domain: {cloudflare_ips: [...], gcp_ips: [...], status: ...}}
    """
    if not (os.path.exists(file_path) and os.path.getsize(file_path) > 0):
        return {}

    try:
        df = pd.read_csv(file_path)
    except Exception:
        return {}

    if df.empty:
        return {}

    if 'Port' in df.columns:
        return df.groupby('Domain')['Port'].apply(list).to_dict()

    if 'cloudflare_ips' in df.columns and 'gcp_ips' in df.columns:
        result = {}
        for _, row in df.iterrows():
            domain = row['Domain']
            try:
                cf_ips = ast.literal_eval(row['cloudflare_ips']) if pd.notna(row['cloudflare_ips']) else []
            except (ValueError, SyntaxError):
                cf_ips = []
            try:
                gcp_ips = ast.literal_eval(row['gcp_ips']) if pd.notna(row['gcp_ips']) else []
            except (ValueError, SyntaxError):
                gcp_ips = []
            result[domain] = {
                'cloudflare_ips': cf_ips,
                'gcp_ips': gcp_ips,
                'status': row.get('status', 'unknown'),
            }
        return result

    if 'IP' in df.columns:
        return df.groupby('Domain')['IP'].apply(list).to_dict()

    if 'URL' in df.columns:
        return df.groupby('Domain')['URL'].apply(list).to_dict()

    return {}


def convert_to_csv(data: dict, output_file: str) -> None:
    """Write nuclei-style results to CSV."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['URL', 'Name', 'Vulnerability', 'Exploit URL', 'Description', 'Request'])
        for url, details in data.items():
            for item in details:
                writer.writerow([url] + item)


def get_delta_links(current_results: dict, previous_results: dict) -> dict:
    """Find new URLs by comparing current results with previous ones."""
    new_links = {}
    for domain, links in current_results.items():
        prev_links = previous_results.get(domain, [])
        new_for_domain = list(set(links) - set(prev_links))
        if new_for_domain:
            new_links[domain] = new_for_domain
    return new_links


def get_delta_ports(current_results: dict, previous_results: dict) -> dict:
    """Find new ports by comparing current results with previous ones."""
    new_ports = {}
    for domain, data in current_results.items():
        current_ports = data['ports']
        prev_ports = previous_results.get(domain, [])
        delta_ports = sorted(set(current_ports) - set(prev_ports))
        if delta_ports:
            new_ports[domain] = {
                'ip': data['ip'],
                'ports': delta_ports,
            }
    return new_ports


def write_file(file_path: str, content: str) -> None:
    with open(file_path, "w") as f:
        f.write(content)


def read_file(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def file_exists(file_path: str) -> bool:
    return os.path.exists(file_path)
