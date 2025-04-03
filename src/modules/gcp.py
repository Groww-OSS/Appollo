import concurrent.futures
import subprocess
import json
from rich import print
from system.db import MongoDB
from datetime import datetime


"""
This module provides functionality to interact with Google Cloud Platform (GCP) services, including listing projects, zones, and fetching various records such as compute instances, forwarding rules, compute addresses, SQL instances, VPN tunnels, and DNS records.

Classes:
    GCP: A class to encapsulate methods for interacting with GCP services.

Functions:
    list_projects(self): Lists all GCP projects.
    list_zones(self, project_id): Lists all DNS managed zones for a given project.
    extract_compute_instance_fields(self, entry): Extracts relevant fields from a compute instance entry.
    extract_forwarding_rule_fields(self, entry): Extracts relevant fields from a forwarding rule entry.
    extract_compute_address_fields(self, entry): Extracts relevant fields from a compute address entry.
    extract_sql_instance_fields(self, entry): Extracts relevant fields from a SQL instance entry.
    extract_vpn_tunnel_fields(self, entry): Extracts relevant fields from a VPN tunnel entry.
    run_gcloud_command(self, command, project_id, extract_fields=None): Runs a gcloud command and processes the output.
    fetch_ip_records(self, project_id): Fetches IP-related records for a given project.
    fetch_dns_records(self, project_id, zone): Fetches DNS records for a given project and zone.
    fetch_project_dns_records(self, project_id): Fetches DNS records for all zones in a given project.
    run(self): Main method to fetch and store IP and DNS records for all projects in MongoDB.

Exceptions:
    subprocess.CalledProcessError: Raised when there is an error during the execution of a subprocess command.
    json.decoder.JSONDecodeError: Raised when there is an error decoding JSON output.
"""

class GCP:
    def list_projects(self):
        command = "gcloud projects list --format='value(projectId)'"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            print("Error retrieving projects:", result.stderr)
            return []
        
    def list_zones(self, project_id):
        command = f"gcloud dns managed-zones list --project {project_id} --format='value(name)' --quiet"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            print(f"Error retrieving zones for Project ID {project_id}")
            return []
        
    def extract_compute_instance_fields(self,entry):
            return {
            "Name": entry.get("name"),
            "Zone": entry.get("zone", "").split("/")[-1],
            "Machine_Type": entry.get("machineType", "").split("/")[-1],
            "Preemptible": entry.get("scheduling", {}).get("preemptible"),
            "Internal_Ip": entry.get("networkInterfaces", [{}])[0].get("networkIP"),
            "External_Ip": entry.get("networkInterfaces", [{}])[0].get("accessConfigs", [{}])[0].get("natIP"),
            "Status": entry.get("status")
        }
    
    def extract_forwarding_rule_fields(self,entry):
            return {
            "Name": entry.get("name"),
            "Region": entry.get("region", "").split("/")[-1],
            "Ip": entry.get("IPAddress"),
            "Ip_Protocol": entry.get("IPProtocol"),
            "Target": entry.get("target")
        }
    
    def extract_compute_address_fields(self,entry):
            return {
            "Name": entry.get("name"),
            "Ip": entry.get("address"),
            "Type": entry.get("addressType"),
            "Purpose": entry.get("purpose"),
            "Network": entry.get("network"),
            "Region": entry.get("region", "").split("/")[-1],
            "Subnet": entry.get("subnetwork", "").split("/")[-1],
            "Status": entry.get("status")
        }
    
    def extract_sql_instance_fields(self,entry):
        ip_addresses = entry.get("ipAddresses", [])
        return {
            "Name": entry.get("name"),
            "Database_Version": entry.get("databaseVersion"),
            "Location": entry.get("region"),
            "Tier": entry.get("tier"),
            "External_Ip": ip_addresses[0] if ip_addresses else None,
            "Internal_Ip": ip_addresses[1] if len(ip_addresses) > 1 else None,
            "STATUS": entry.get("state")
        }
    
    def extract_vpn_tunnel_fields(self,entry):
            return {
            "NAME": entry.get("name"),
            "REGION": entry.get("region", "").split("/")[-1],
            "GATEWAY": entry.get("targetVpnGateway", "").split("/")[-1],
            "Ip": entry.get("peerIp")
        }
    
    def run_gcloud_command(self,command, project_id, extract_fields=None):
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=30)
            if not output.strip():
                return {"Project_ID": project_id, "Data": []}
            entries = json.loads(output.strip())
            if not isinstance(entries, list):
                raise json.decoder.JSONDecodeError("Expecting list as JSON root", output, 0)
            data = [extract_fields(entry) for entry in entries]
            return {"Project_ID": project_id, "Data": data}
        except subprocess.CalledProcessError as e:
            return {"Project_ID": project_id, "Data": []}
        except json.decoder.JSONDecodeError as e:
            return {"Project_ID": project_id, "Data": []}
        
    def fetch_ip_records(self, project_id):
        try:
            compute_instances_data = self.run_gcloud_command(
                ["gcloud", "compute", "instances", "list", "--project", project_id, "--format=json","--quiet",],
                project_id,
                extract_fields=self.extract_compute_instance_fields
            )
            forwarding_rules_data = self.run_gcloud_command(
                ["gcloud", "compute", "forwarding-rules", "list", "--project", project_id, "--format=json","--quiet"],
                project_id,
                extract_fields=self.extract_forwarding_rule_fields
            )
            compute_addresses_data = self.run_gcloud_command(
                ["gcloud", "compute", "addresses", "list", "--project", project_id, "--format=json","--quiet"],
                project_id,
                extract_fields=self.extract_compute_address_fields
            )
            sql_instances_data = self.run_gcloud_command(
                ["gcloud", "sql", "instances", "list", "--project", project_id, "--format=json","--quiet"],
                project_id,
                extract_fields=self.extract_sql_instance_fields
            )
            vpn_tunnels_data = self.run_gcloud_command(
                ["gcloud", "compute", "vpn-tunnels", "list", "--project", project_id, "--format=json","--quiet"],
                project_id,
                extract_fields=self.extract_vpn_tunnel_fields
            )
            return compute_instances_data, forwarding_rules_data, compute_addresses_data, sql_instances_data, vpn_tunnels_data
        except Exception as e:
            return {}, {}, {}, {}, {}
        
    def fetch_dns_records(self, project_id, zone):
        command = ["gcloud", "dns", "record-sets", "list", "--project", project_id, "--zone", zone, "--format=json","--quiet"]
        try:
            output = subprocess.check_output(command, text=True)
            records = json.loads(output)
            return [
                {
                    "Name": record.get("name"),
                    "Type": record.get("type"),
                    "Ttl": record.get("ttl"),
                    "Ip": record.get("rrdatas"),
                    "Kind": record.get("kind"),
                    "Project_Id": project_id
                } for record in records
            ]
        except subprocess.CalledProcessError as e:
            return []
        
    def fetch_project_dns_records(self, project_id):
        zones = self.list_zones(project_id)
        dns_records = []
        for zone in zones:
            dns_records.extend(self.fetch_dns_records(project_id, zone))
        return dns_records
    
    def run(self):
        mongo = MongoDB()
        dns_collection = mongo.set_collection("DNS")
        ip_collection = mongo.set_collection("IP Records")
        combined_ip_records = []
        projects = self.list_projects()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            ip_futures = {executor.submit(self.fetch_ip_records, project_id): project_id for project_id in projects}
            dns_futures = {executor.submit(self.fetch_project_dns_records, project_id): project_id for project_id in projects}

        for future in concurrent.futures.as_completed(ip_futures):
            project_id = ip_futures[future]
            ip_records = future.result()
            if ip_records:
                for record in ip_records:
                    if "Data" in record:
                        combined_ip_records.extend(record["Data"])
            ip_collection.update_one(
                {"source": "GCP"},
                {
                    "$addToSet": {
                        "records": {
                            "$each": combined_ip_records
                        }
                    },
                    "$set": {
                        "lastUpdated": datetime.now()
                    }
                },
                upsert=True
            )
        for future in concurrent.futures.as_completed(dns_futures):
            project_id = dns_futures[future]
            dns_records = future.result()
            dns_collection.update_one(
                {"source": "GCP"},
                {
                    "$addToSet": {
                        "records": {
                            "$each": dns_records
                        }
                    },
                    "$set": {
                        "lastUpdated": datetime.now()
                    }
                },
                upsert=True
            )