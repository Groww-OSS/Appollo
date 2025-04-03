import argparse
from banner import banner
import os
import argparse
import asyncio
from dotenv import load_dotenv
from modules.cloudflare import Cloudflare
from system.db import *
from modules.gcp import GCP
from modules import endpoints
from modules.portscan import PortScan
from modules.wayback import GAU
from modules.nuclei import *
from modules.ssl_checker import extract_tls_info
from rich.table import Table
from rich.console import Console
from rich.text import Text
from rich import print
from datetime import datetime
import time
import concurrent.futures
from system import utils as system
from rich_tools import *
import csv
import pandas as pd
from modules.technology import BuiltWithScanner


"""
Appollo 
This script provides a comprehensive reconnaissance tool that performs various scans and updates for DNS records, port scanning, wayback URLs, directory scanning, and nuclei scans for CVEs. The results are processed and can be sent to Slack, saved to CSV files, and Jira issues can be created for new findings.
Classes:
    Appollo: Main class that handles the scanning and updating logic.
Functions:
    convert_to_csv(data, output_file): Converts scan results to a CSV file.
Usage:
    Run the script with appropriate arguments to perform different types of scans and updates.
Arguments:
    -t, --target: Target domain, IP, CIDR, or any asset which is supported by Appollo.
    -U, --update-inventory: Update Inventory Records.
    -ps, --port-scan: Run port scan logic.
    -ws, --wayback-scan: Run wayback scan logic.
    -ds, --dir-scan: Run directory scan logic.
    -A, --complete-scan: Run Complete scan for all known assets in inventory.
    -ns, --nuclei-scan: Run nuclei scans for CVEs.
"""



class Appollo:
    def __init__(self, args) -> None:
        load_dotenv(args.env)
        self.jira = system.get_jira_client()
        self.label = "appollo-scan"
        self.args = args

    def scan_ports(self, ip):
        ports = PortScan().run(ip, "-p 0-3000")
        open_ports = []
        cloudflare_ports = [ 8080, 8880, 2052, 2082, 2086, 2095,2053, 2083, 2087, 2096, 8443, 2053, 2082, 2083, 2087, 2096, 844]
        open_ports = [port for port in ports if port not in cloudflare_ports]
        return open_ports
        
    def table_to_df(self, table: Table) -> pd.DataFrame:
        table_data = {
            x.header: [Text.from_markup(y).plain for y in x.cells] for x in table.columns
        }
        return pd.DataFrame(table_data)
    
 
    def run(self):
        cloud_command = f"gcloud auth activate-service-account --key-file={os.getenv('SVC_ACCOUNT')}"
        os.system(f"{cloud_command} > /dev/null 2>&1")
        print("[bold green][+] Service Account Activated[/bold green]")

        if self.args.update_inventory:
            print("[bold blue][+] Updating Cloudflare IP/DNS Records[/bold blue]")
            Cloudflare().run()
            print("[bold blue][+] Updating GCP IP/DNS Records[/bold blue]") 
            GCP().run()


            table = Table(title="DNS Records")
            table.add_column("Zone Name", style="yellow")
            table.add_column("Name", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Content", style="blue")
            table.add_column("Proxied", style="blue")
            table.add_column("Source", style="red")

            collection = MongoDB().set_collection("DNS")
            cloudflare_records = collection.find({"source": "cloudflare"})
            gcp_records = collection.find({"source": "GCP"})

            for record in cloudflare_records:
                for r in record.get('records', []):
                    for dns in r.get('records', []):
                        table.add_row(
                        dns.get('zone_name', ''),
                        dns.get('name', ''),
                        dns.get('type', ''),
                        dns.get('content', ''),
                        str(dns.get('proxied', '')),
                        record.get('source', '')
                        )

            for record in gcp_records:
                for r in record.get('records',[]):
                    ip_list = r.get('RRDATA',[])
                    if(ip_list):
                        for ip in ip_list:
                            table.add_row(
                                '',
                                r.get('NAME', ''),
                                r.get('TYPE', ''),
                                ip,
                                '',
                                record.get('source','')
                            )
            print(table)

            data = self.table_to_df(table)
            new_data = pd.DataFrame(columns=['Zone Name', 'Name', 'Type', 'Content', 'Proxied', 'Source'])
            dns_file_path_ = "dns-records.csv"
        
            for _, row in data.iterrows():
                lrow = list(row.to_numpy())
                hash = system.calculate_hash(lrow)
                is_alert_sent = system.check_if_hash_exists(hash)

                if not is_alert_sent:
                    new_data = pd.concat([new_data, pd.DataFrame([row])], ignore_index=True)
                    system.add_hash_to_db(hash)
                    
            table_content = "|| Zone Name || Name || Type || Content || Proxied || Source ||\n"
            for _, row in new_data.iterrows():
                table_content += f"| {row['Zone Name']} | {row['Name']} | {row['Type']} | {row['Content']} | {row['Proxied']} | {row['Source']} |\n"

            new_data.to_csv(dns_file_path_, index=False)

            if(new_data.empty):
                system.send_slack_alert("No new DNS record found")
            else: 
                system.upload_file_to_slack(dns_file_path_,"DNS Records")
                jira_issue = system.create_jira_issue(
                                self.jira,
                                "APOC",
                                f"[DNS Records] New records added",
                                f"New DNS records\n\n{table_content}",
                                "Bug",
                                self.label
                            )
                issue_id = jira_issue.key
                self.jira.add_attachment(issue=issue_id, attachment=dns_file_path_)
                print(f"[bold green][+] Jira ticket created successfully for new DNS records[/bold green]")

#****************************** SSL Checker ********************
        if self.args.ssl_checker:
            target = []
            ssl_collection = MongoDB().set_collection("SSL Certificates")
            if self.args.complete_scan:
                print("[bold blue][+] Running SSL checker on all domains[/bold blue]")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_dns = dns_collection.find({'source': 'GCP'})

                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            ip = r.get('content', '')
                            if r.get('type') == 'A' and not ip.startswith(('10.', '192.168', '127.')):
                                target.append(r.get('name'))
                        target.append(record.get('domain'))

                for records in gcp_dns:
                    for record in records.get('records', []):
                        ip = record.get('RRDATA', [''])[0]
                        if record.get('TYPE') == 'A' and not ip.startswith(('10.', '192.168', '127.')):
                            target.append(record.get('NAME'))
            else:
                if self.args.target:
                    target.append(self.args.target)
                    print(f"[bold blue][+] Starting SSL scan on {self.args.target}[/bold blue]")
                else:
                    print("[bold red][+] No target provided [/bold red]")

            tls_info = extract_tls_info(target)
            if tls_info:
                new_tls_hash = system.calculate_hash(''.join(f"{info['hostname']}{info['not_after']}" for info in tls_info))
                is_alert_sent = system.check_if_hash_exists(new_tls_hash)

                if not is_alert_sent:
                    table = Table(title="SSL Certificate Information")
                    table.add_column("Hostname", style="yellow")
                    table.add_column("Not Before", style="green")
                    table.add_column("Not After", style="blue")
                    table.add_column("Subject CN", style="magenta")
                    table.add_column("Issuer Org", style="cyan")
                    table.add_column("Days Until Expiry", style="red")
                    table.add_column("Certificate Expired", style="purple")

                    for info in tls_info:
                        table.add_row(info['hostname'], info['not_before'], info['not_after'], info['subject_cn'], info['issuer_org'], str(info['days_until_expiry']), str(info['expired']))
                        ssl_collection.update_one({"hostname": info['hostname']}, {"$set": info}, upsert=True)

                        expiry_date = datetime.strptime(info['not_after'], '%Y-%m-%dT%H:%M:%SZ')
                        days_left = (expiry_date - datetime.utcnow()).days
                        if days_left <= 15:
                            system.create_jira_issue(
                                self.jira,
                                "APOC",
                                f"[SSL Certificate Expiry] {info['hostname']} has SSL Certificate Expiry",
                                f"{info['hostname']} has {info['days_until_expiry']} days until expiry.",
                                "Bug",
                                self.label
                            )
                            print(f"[bold green][+] Jira ticket created for {info['hostname']} with expiry in {info['days_until_expiry']} days")

                    system.send_slack_alert("SSL checker completed successfully ")
                    print(table)
                else:
                    print(f"[bold green][+] Jira ticket already created For {domain}[/bold green]")
            else:
                print("[bold red][-] No SSL information found[/bold red]")

#************************** PORT SCAN **************************

        if self.args.port_scan:
            domains = []
            ip_domain = {}
            results = {}
            csv_file_path = "port_scan.csv"
            port_collection = MongoDB().set_collection("Port Scans")
            previous_csv_file_path = "/etc/config/previous_port_scan.csv"

            for file_path in [previous_csv_file_path, csv_file_path]:
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write("Domain,IP,Port\n")

            if self.args.complete_scan:
                print("[bold blue][+] Running Complete Port Scan [/bold blue]")
                dns_collection = MongoDB().set_collection("IP Records")
                ip_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_records = dns_collection.find({'source':'GCP'})
                gcp_ip = ip_collection.find({'source':'GCP'})

            
                for record in cloudflare_records:
                    for sub_record in record.get('records', []):
                        for r in sub_record['ip']:
                            print(system.is_private_ip(r['ip']))
                            if not system.is_private_ip(r['ip']):
                                ip_domain[r['name']]=r['ip']
                                domains.append(r['name'])

                for record in gcp_records:
                    for sub_record in record.get('records', []):
                        for r in sub_record.get('RRDATA',[]):
                            print(system.is_private_ip(r))
                            if not system.is_private_ip(r):
                                ip_domain[sub_record['NAME']]=r
                                domains.append(sub_record['NAME'])
   
            else:
                if not self.args.target:
                    print("[bold red][-] No target provided[/bold red]")
                    return
                try:
                    ip = socket.gethostbyname(self.args.target)
                    ip_domain[self.args.target] = ip
                    domains.append(self.args.target)
                    print(f"[bold blue][+] Running Port scan on {self.args.target}[/bold blue]")
                except socket.gaierror:
                    print(f"[bold red][-] Unable to resolve {self.args.target}[/bold red]")
                    return
            table = Table(title="Port Scans")
            table.add_column("Domain", style="green")
            table.add_column("IP", style="yellow")
            table.add_column("Open Ports", style="blue")

            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {executor.submit(self.scan_ports, domain): domain for domain in domains}
                for future in concurrent.futures.as_completed(futures):
                    domain = futures[future]
                    try:
                        result = future.result()
                        ip = ip_domain.get(domain, '')
                        results[domain] = {'ip': ip, 'ports': result or []}
                    except Exception as e:
                        print(f"[bold red][-] Error scanning {domain}: {e}[/bold red]")

            previous_results = system.read_from_csv(previous_csv_file_path)
            delta_ports = system.get_delta_ports(results, previous_results)

            for domain, data in results.items():
                query = {"domain": domain}
                update = {"$set": {"ip": data['ip'], "domain": domain,"ports": data['ports']}}
                port_collection.update_one(query, update, upsert=True)
                table.add_row(domain, data['ip'], ",".join(map(str, data['ports'])))
            print(table)

            if delta_ports:
                system.save_port_scan_to_csv(delta_ports, previous_csv_file_path)
                for domain, ports in delta_ports.items():
                    ip = ports.get("ip", "")
                    open_ports = ",".join(map(str, ports.get("ports", [])))
                    table_content = f"|| Domain || IP || Open Ports ||\n| {domain} | {ip} | {open_ports} |\n"

                    if not system.check_if_hash_exists(system.calculate_hash([domain, ip, open_ports])):
                        jira_issue = system.create_jira_issue(
                            self.jira,
                            "APOC",
                            f"[Open Ports] {domain} has critical open ports",
                            f"The following ports are open for {domain}:\n\n{table_content}",
                            "Bug",
                            self.label
                        )
                        print(f"[bold green][+] Jira ticket created successfully for {domain} with open ports[/bold green]")
                    else:
                        print(f"[bold yellow][+] Jira ticket already exists for {domain}[/bold yellow]")

                system.send_slack_alert(f"Port scan completed successfully at {datetime.now()}")
            else:
                print("[bold red][-] No new open ports found.[/bold red]")

#********************* WAYBACK SCAN ************************
        if self.args.wayback_scan:
            domains = set()
            csv_file_path = "wayback_urls.csv"
            previous_csv_file_path = "/etc/config/previous_wayback_results.csv"

            for file_path in [csv_file_path, previous_csv_file_path]:
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write("Domain,Links\n")

            table = Table(title="Wayback Scans")
            table.add_column("Domain", style="green")
            table.add_column("Links", style="blue")

            if self.args.complete_scan:
                print("[bold blue][+] Running complete Wayback scan for all assets[/bold blue]")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_dns = dns_collection.find({'source': 'GCP'})

                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            ip = r.get('content', '')
                            if r.get('type') == 'A' and not ip.startswith(('10.', '192.168', '127.')):
                                domains.add(r.get('name'))
                        domains.add(record.get('domain'))

                for records in gcp_dns:
                    for record in records.get('records', []):
                        ip = record.get('RRDATA', [''])[0]
                        if record.get('TYPE') == 'A' and not ip.startswith(('10.', '192.168', '127.')):
                            domains.add(record.get('NAME'))

            else:
                if self.args.target:
                    print(f"[bold blue][+] Running Wayback scan for {self.args.target} [/bold blue]")
                    domains.add(self.args.target)
                else:
                    print("[bold red][-] No target provided[/bold red]")
                    return

            wayback_results = asyncio.run(GAU().run(domains))

            for domain, links in wayback_results.items():
                for link in links:
                    table.add_row(domain, link)

            previous_wayback_results = system.read_from_csv(previous_csv_file_path)
            new_links = system.get_delta_links(wayback_results, previous_wayback_results)
            new_links_hash = system.calculate_hash(str(new_links))
            is_alert_sent = system.check_if_hash_exists(new_links_hash)
            wayback_collection = MongoDB().set_collection("Wayback Results")

            if new_links and not is_alert_sent:
                system.save_wayback_to_csv(new_links, previous_csv_file_path)

                for domain, links in new_links.items():
                    query = {"domain": domain}
                    update = {"$set": {"domain": domain, "urls": links}}
                    wayback_collection.update_one(query, update, upsert=True)

                    table_content = "|| Domain || Links ||\n"
                    table_content += "".join([f"| {domain} | {link} |\n" for link in links])
                    if table_content and len(table_content) < 32767 and len(links) > 1:
                        system.create_jira_issue(
                            self.jira, 'APOC', f'[Wayback URLs] {domain} has new Wayback URLs',
                            f"{domain} has {len(links)} new URLs indexed.\n\n{table_content}", "Bug", self.label
                        )
                        print(f"[bold green][+] Jira Ticket Created Successfully for {domain}[/bold green]")
                    elif table_content and len(table_content) > 32767:
                        jira_issue = system.create_jira_issue(
                            self.jira, 'APOC', f'[Wayback URLs] {domain} has new Wayback URLs',
                            f"{domain} has {len(links)} new URLs indexed.", 'Bug', self.label
                        )
                        issue_id = jira_issue.key
                        self.jira.add_attachment(issue=issue_id, attachment=csv_file_path)
                        print(f"[bold green][+] Jira ticket created successfully for {domain}[/bold green]")
                    else:
                        print(f"[bold red][-] No new wayback links found for {domain} to create Jira Ticket[/bold red]")

                system.send_slack_alert(f"Wayback scan completed successfully at {datetime.now()}")
            else:
                print("[bold green][+] No new wayback links found[/bold green]")

            print(table)

#*********************** TECHNOLOGY SCAN ************************
        if self.args.tech_scan:
            csv_file_path = "tech-scan.csv"
            domains = []

            if(not(os.path.exists(csv_file_path))):
                with open(csv_file_path, 'w') as f:
                    f.write("Domain,Technology,Type,Content\n")

            if self.args.complete_scan:
                print("[bold green][+] Running complete Technology scan[/bold green]")
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_records = dns_collection.find({'source': 'GCP'})

                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            if(r.get('type')=='A'):
                                if r.get('content')[:3] != '10.' and r.get('content')[:8] != '192.168' and r.get('content')[:4] != '127.':
                                    domains.append(r.get('name'))
                        domains.append(record.get('domain'))

                for records in gcp_records:
                    for record in records.get('records', []):
                        if record.get('TYPE') == 'A':
                            if record.get('RRDATA')[0][:3] != '10.' and record.get('RRDATA')[0][:8] != '192.168' and record.get('RRDATA')[0][:4] != '127.':
                                domains.append(record.get('NAME'))
            else:
                
                if self.args.target:
                    domains.append(self.args.target)
                else:
                    print("[bold red][-] No target provided[/bold red]")
                    return
            
            print(f"[bold blue][+] Running Technology scan on {', '.join(domains)}[/bold blue]")
            
            builtwith = BuiltWithScanner(domains).scan()

            table = Table(title="Technology Scans")
            table.add_column("Domain", style="yellow")
            table.add_column("Technology", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Content", style="magenta")

            
            for domain, techs in builtwith.items():
                query = {"domain": domain}
                update = {"$set": {"domain": domain, "technologies": techs, "source": "BuiltWith"}}
                collection = MongoDB().set_collection("Technology Scans")
                collection.update_one(query, update, upsert=True)

                for _, tech_list in techs.items():
                    for tech in tech_list:
                        table.add_row(
                            domain,
                            tech.get("name", ""),
                            tech.get("tag", ""),
                            tech.get("description", "")
                        )
                
            new_data = self.table_to_df(table)
            new_data.to_csv(csv_file_path, index=False)
            print(table)

            alert_sent = False   

            for _, row in new_data.iterrows():
                lrow = list(row.to_numpy())
                hash = system.calculate_hash(lrow)
                is_alert_sent = system.check_if_hash_exists(hash)

                if not is_alert_sent:
                    system.add_hash_to_db(hash)
                    alert_sent = True   

            if not alert_sent: 
                system.send_slack_alert(f"Technology scan completed successfully at {datetime.now()}")
            else:
                system.send_slack_alert(f"Technology scan completed successfully at {datetime.now()}")

#*********************** DIRECTORY SCAN ************************     
        targets = []
        results = {}
        dir_collection = MongoDB().set_collection("Exposed Endpoints")

        if self.args.dir_scan:
            if self.args.complete_scan:
                dns_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_records = dns_collection.find({'source': 'GCP'})

                for records in cloudflare_records:
                    for record in records.get('records', []):
                        for r in record.get('records', []):
                            if r.get('type') == 'A' and not r.get('content').startswith(('10.', '192.168', '127.')):
                                targets.append(r.get('name'))
                        targets.append(record.get('domain'))

                for records in gcp_records:
                    for record in records.get('records', []):
                        if record.get('TYPE') == 'A' and not record.get('RRDATA')[0].startswith(('10.', '192.168', '127.')):
                            targets.append(record.get('NAME'))
            else:
                if self.args.target:
                    targets.append(self.args.target)
                else:
                    print("[bold red][-] No target provided[/bold red]")
                    return

        is_alert_sent = False

        with concurrent.futures.ThreadPoolExecutor() as executor:
            tasks = []
            for target in targets:
                print(f"[bold blue][+] Starting Directory scan for {target}[/bold blue]")
                task = executor.submit(endpoints.check_endpoints, target)
                tasks.append((task, target))
                time.sleep(10)

            table = Table(title="Directory Scans")
            table.add_column("Domain", style="white")
            table.add_column("Endpoint", style="green")
            table.add_column("Status code", style="blue")

            for future, target in tasks:
                result = future.result()
                if result:
                    print(f"[bold green][+] Found {len(result)} exposed endpoints for domain: {target} [/bold green]")
                    results[target] = result

                    table_content = "|| Domain || Endpoint || Status Code ||\n"
                    for endpoint, status_code in result.items():
                        table.add_row(target, endpoint, str(status_code))

                        if endpoint:
                            query = {"domain": target, "endpoint": endpoint}
                            update = {"$set": {"domain": target, "endpoint": endpoint, "status code": str(status_code)}}
                            dir_collection.update_one(query, update, upsert=True)

                            row = pd.DataFrame({
                                'Domain': [target],
                                'Endpoint': [endpoint],
                                'Status code': [str(status_code)]
                            })

                            hash_value = system.calculate_hash(row.values.tolist())
                            if not system.check_if_hash_exists(hash_value):
                                system.add_hash_to_db(hash_value)
                                is_alert_sent = True
                                table_content += f"| {target} | {endpoint} | {status_code} |\n"

                else:
                    print(f"[bold red][-] No exposed endpoints found for {target} [/bold red]")
                    table.add_row(target, "N/A", "N/A")

            if is_alert_sent:
                jira_issue = system.create_jira_issue(
                    self.jira,
                    'APOC',
                    f'[Exposed Endpoints] {target} has exposed directories',
                    table_content,
                    issue_type="Bug",
                    label=self.label
                )
                print(f"[bold blue][+] JIRA ticket created successfully for {target} with exposed endpoints")
                system.send_slack_alert(f"Exposed Endpoints Found for {target}. Visit JIRA {jira_issue.key}")
            else:
                print(f"[bold red][-] Jira ticket already exists for {target} with exposed endpoints[/bold red]")

        print(table)


#*********************** NUCLEI SCAN ************************  
        if self.args.nuclei_scan:
            nuclei_template = os.getenv('NUCLEI_TEMPLATE')
            targets = []
            ip_domain = {}
            results = {}

            if self.args.complete_scan:
                print(f"[bold green][+] Running complete Nuclei scan [/bold green]")
                dns_collection = MongoDB().set_collection("IP Records")
                ip_collection = MongoDB().set_collection("DNS")
                cloudflare_records = dns_collection.find({'source': 'cloudflare'})
                gcp_records = dns_collection.find({'source': 'GCP'})

                for record in cloudflare_records:
                    for sub_record in record.get('records', []):
                        for r in sub_record['ip']:
                            if not (r['ip'].startswith(('10.', '192.168', '127.'))):
                                ip_domain[r['name']] = r['ip']
                                targets.append(r['name'])

                for record in gcp_records:
                    for sub_record in record.get('records', []):
                        for r in sub_record.get('RRDATA', []):
                            if not (r.startswith(('10.', '192.168', '127.'))):
                                ip_domain[sub_record['NAME']] = r
                                targets.append(sub_record['NAME'])
            else:
                if self.args.target:
                    targets.append(self.args.target)
                else:
                    print(f"[bold red][-] No target provided[/bold red]")
                    return

            targets = list(set(targets))
            print(f"[bold green][+] Running Nuclei scan for {self.args.target}[/bold green]")

            table = Table(title="Nuclei Scan Results")
            table.add_column("URL", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Vulnerability", style="magenta")
            table.add_column("Exploit URL", style="yellow")
            table.add_column("Description", style="blue")
            table.add_column("Request", style="white")


            with concurrent.futures.ThreadPoolExecutor() as executor:

                tasks = {executor.submit(run_nuclei, target, nuclei_template): target for target in targets}

                for future in concurrent.futures.as_completed(tasks):
                    target = tasks[future]
                    try:
                        result = future.result()
                        results[target] = result if result else []
                    except Exception as e:
                        print(f"[bold red][-] Error processing target {target}: {str(e)}[/bold red]")
                if any(results.values()):
                    csv_file_path = "nuclei.csv"
                    system.convert_to_csv(results, csv_file_path)
                    hash = system.calculate_hash(results)
                    is_alert_sent = system.check_if_hash_exists(hash)
                    text = "Nuclei Scans!"

                    table_content = ""
                    for target, vulnerabilities in results.items():
                        for vuln in vulnerabilities:
                            table.add_row(target, vuln[0], vuln[1], str(vuln[2]), vuln[3], vuln[4])
                            table_content += f"| {target} | {vuln[0]} | {vuln[1]} | {str(vuln[2])} | {vuln[3]} | {vuln[4]} |\n"
                    print(table)
                    if not is_alert_sent:
                        system.upload_file_to_slack(csv_file_path, text)
                        system.add_hash_to_db(hash)
                        
                        jira_issue = system.create_jira_issue(
                            self.jira,
                            'APOC',
                            f'[Nuclei Scan] {self.args.target} has vulnerabilities',
                            table_content,
                            issue_type="Bug",
                            label=self.label
                        )
                        print(f"[bold green][+] Jira ticket created for {target} [/bold green]")
                    else:
                        print(f"[bold red][-] Jira ticket already exists for {target}[/bold red]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Appollo - Reconnaissance Tool")
    parser.add_argument('-e',"--env", action="store", required=True, help="Path to the .env file")
    parser.add_argument("-t","--target", action="store", help="Target domain, IP, CIDR, or any asset which is supported by Appollo")
    parser.add_argument("-U","--update-inventory", action="store_true", help="Update Inventory Records")
    parser.add_argument("-sc","--ssl-checker", action="store_true", help="Run SSL Checker")
    parser.add_argument("-ps","--port-scan", action="store_true", help="Run port scan logic")
    parser.add_argument("-ws","--wayback-scan", action="store_true", help="Run wayback scan logic")
    parser.add_argument("-ts","--tech-scan", action="store_true", help="Run Technology scan")
    parser.add_argument("-ds","--dir-scan", action="store_true", help="Run directory scan logic")
    parser.add_argument("-ns","--nuclei-scan", action="store_true", help="Run nuclei scans for CVE's")
    parser.add_argument("-A","--complete-scan", action="store_true", help="Run Complete scan for all known assets in inventory")

    args = parser.parse_args()

    appollo = Appollo(args)
    appollo.run()
   

