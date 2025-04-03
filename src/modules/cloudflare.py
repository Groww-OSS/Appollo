import os
import re
import requests
from rich import print
from datetime import datetime
from system.db import MongoDB

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
    def __init__(self):
        self.headers = {
            "Authorization": "Bearer " + os.environ["CLOUDFLARE_API_KEY"],
            "Content-Type": "application/json"
        }

    def fetch_domains(self):
        try:
            url = "https://api.cloudflare.com/client/v4/zones"
            response = requests.get(url, headers=self.headers)
            if response.status_code != 200:
                raise Exception("[-] Error fetching domains from Cloudflare: " + str(response.status_code))
            return response.json()["result"]
        except Exception as e:
            print(e)
    
    def get_dns_records(self, domains):
        try:
            dnsRecords = {}
            for domain in domains:
                request_url = f"https://api.cloudflare.com/client/v4/zones/{domain['id']}/dns_records?per_page=2000"
                response = requests.get(request_url, headers=self.headers)
                if response.status_code != 200:
                    raise Exception("[-] Error fetching DNS records from Cloudflare: " + str(response.status_code))
                records = response.json()["result"]
                for record in records:
                    record.pop("meta", None)
                    record.pop("tags", None)
                dnsRecords[domain["id"]] = {"domain": domain["name"], "records": records}
            return dnsRecords
        except Exception as e:
            print(e)
    
    def process_records(self, dnsRecords, collection):
        dns_records = []
        for key,value in dnsRecords.items():
            dns_records.append({"_id": key, "source": "cloudflare", "domain": value["domain"], "records": value["records"]})
        try:
            collection.update_one(
                {"source": "cloudflare"},
                {
                    "$set": {
                    "source": "cloudflare",
                    "records": dns_records,
                    "lastUpdated": datetime.now()
                }
                },
                upsert=True
            ) 
        except Exception as e:
            print("[bold red] Error inserting data into MongoDB:,{e}")
     


    def process_ip(self, dnsRecords, collection):
        domains = []
        ip_set = set()   
        for values in dnsRecords.values():
            domain_name = values["domain"]
            ips = []
            for record in values["records"]:
                if record["type"] == "A" or record["type"] == "AAAA":
                    if "@" in record["name"] or not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", record["content"]):
                        continue
                    ip = record["content"]
                    if ip not in ip_set:   
                        ips.append({"ip": ip, "name": record["name"]})
                        ip_set.add(ip)
            if ips:  
                domains.append({"domain": domain_name, "ip": ips})
        try:
            query = {"source": "cloudflare"}
            update = {"$set": { "source": "cloudflare","records": domains, "lastUpdated": datetime.now()}}
            collection.update_one(query, update, upsert=True)
        except Exception as e:
            print(f"[bold red ] Error inserting data into MongoDB: {e}")

    def run(self):
        domains = self.fetch_domains()
        dnsRecords = self.get_dns_records(domains)
        ip_collection = MongoDB().set_collection("IP Records")
        dns_collection = MongoDB().set_collection("DNS")
        self.process_records(dnsRecords, dns_collection)
        self.process_ip(dnsRecords, ip_collection)

