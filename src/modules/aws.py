"""
Triton Cast — AWS (single module for all AWS integration).

Uses the AWS CLI only. Application entry point: ``run_aws_scan``.

Env: credentials (keys/profile/role), optional ``AWS_ACCOUNT_IDS`` +
``AWS_ASSUME_ROLE_PATTERN``, optional ``AWS_CREDENTIALS_SECRET`` (GCP Secret Manager).

Writes to MongoDB: Prod IP Records, Prod DNS, Prod DNS Records, Prod Security Groups,
Prod AWS Assets.
"""
import sys
from pathlib import Path

# When run as script (e.g. python3 src/modules/aws.py), ensure src/ is on path for system.*
_src = Path(__file__).resolve().parent.parent
if _src.name == "src" and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import json
import logging
import os
import shutil
import socket
import subprocess
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich import print
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from system.db import MongoDB
from system.utils import calculate_hash

# Default regions if describe-regions fails — broad fallback covering all major geo zones
DEFAULT_REGIONS = [
    # US
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    # Asia Pacific
    "ap-south-1",      # Mumbai
    "ap-south-2",      # Hyderabad
    "ap-southeast-1",  # Singapore
    "ap-southeast-2",  # Sydney
    "ap-southeast-3",  # Jakarta
    "ap-northeast-1",  # Tokyo
    "ap-northeast-2",  # Seoul
    "ap-northeast-3",  # Osaka
    "ap-east-1",       # Hong Kong
    # Europe
    "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-central-1", "eu-central-2",
    "eu-north-1", "eu-south-1", "eu-south-2",
    # Canada / SA / Middle East / Africa
    "ca-central-1", "ca-west-1",
    "sa-east-1",
    "me-south-1", "me-central-1",
    "af-south-1",
]

# Resource types from get_account_ips() that produce real IP addresses.
# Only these go into Prod IP Records.
_IP_RESOURCE_TYPES = {
    "ec2_instances", "elastic_ips", "nat_gateways", "ec2_ipv6",
    "lightsail_instances", "ecs_tasks", "workspaces", "global_accelerator", "dms",
}

# Resource types that produce DNS hostnames / URLs.
# These go into Prod DNS Records (as CNAME) so they appear in the DNS view
# and are picked up as scan targets by get_all_targets().
_ENDPOINT_RESOURCE_TYPES = {
    "load_balancers":            "aws_load_balancer",
    "rds_instances":             "aws_rds_instance",
    "eks_clusters":              "aws_eks_cluster",
    "cloudfront_distributions":  "aws_cloudfront",
    "api_gateway_endpoints":     "aws_api_gateway",
    "lambda_function_urls":      "aws_lambda_url",
    "lightsail_containers":      "aws_lightsail_container",
    "lightsail_databases":       "aws_lightsail_database",
    "lightsail_load_balancers":  "aws_lightsail_lb",
    "elastic_beanstalk":         "aws_elastic_beanstalk",
    "api_gateway_v2":            "aws_api_gateway_v2",
    "appsync":                   "aws_appsync",
    "s3_websites":               "aws_s3_website",
    "documentdb":                "aws_documentdb",
    "neptune":                   "aws_neptune",
    "redshift":                  "aws_redshift",
    "mq":                        "aws_mq",
    "msk":                       "aws_msk",
    "elasticache":               "aws_elasticache",
    "sagemaker":                 "aws_sagemaker",
    "emr":                       "aws_emr",
}

# Route53 list-resource-record-sets: safety cap per zone (avoids runaway pagination)
_ROUTE53_MAX_PAGES = max(1, min(5000, int(os.getenv("AWS_ROUTE53_MAX_PAGES", "250") or "250")))
# Per-region Lambda functions to probe for function URLs (full scan); parallelized below
_LAMBDA_URL_MAX = max(50, min(5000, int(os.getenv("AWS_LAMBDA_URL_MAX_CHECKS", "400") or "400")))
_LAMBDA_URL_WORKERS = max(1, min(24, int(os.getenv("AWS_LAMBDA_URL_WORKERS", "12") or "12")))


def _aws_binary():
    """Resolve aws CLI path: AWS_CLI_PATH env, or 'aws' from PATH."""
    path = os.getenv("AWS_CLI_PATH", "").strip()
    if path and os.path.isfile(path):
        return path
    return shutil.which("aws") or "aws"


def _aws_cli_exec(cmd_args, env_override=None, timeout=120):
    """Run aws CLI. Returns (ok, data_or_none, err_snippet_or_none)."""
    env = {**os.environ} if env_override is None else {**os.environ, **env_override}
    # Suppress pager via env var — compatible with both AWS CLI v1 and v2
    env["AWS_PAGER"] = ""
    aws_cmd = _aws_binary()
    full_cmd = [aws_cmd, "--output", "json"] + list(cmd_args)
    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, env=env, timeout=timeout,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()[:400]
            return False, None, err or "aws cli failed"
        out = result.stdout.strip()
        if not out:
            return True, None, None
        try:
            return True, json.loads(out), None
        except json.JSONDecodeError:
            return False, None, "invalid JSON from aws cli"
    except subprocess.TimeoutExpired:
        return False, None, "timeout"
    except FileNotFoundError:
        logging.getLogger("aws_collector").warning(
            "AWS CLI not found. Set AWS_CLI_PATH or install aws CLI."
        )
        return False, None, "aws binary not found"
    except Exception as e:
        return False, None, str(e)[:200]


def _run_aws(cmd_args, env_override=None, timeout=120):
    """Run aws CLI; return (success, parsed_json or None)."""
    ok, data, _ = _aws_cli_exec(cmd_args, env_override, timeout)
    return ok, data


def _paginate(cmd_prefix, list_key, next_token_key="NextToken", env_override=None):
    """Run paginated aws command; yield accumulated items from list_key."""
    next_token = None
    while True:
        args = list(cmd_prefix) + (["--starting-token", next_token] if next_token else [])
        ok, data = _run_aws(args, env_override=env_override)
        if not ok or data is None:
            break
        items = data.get(list_key, [])
        if isinstance(items, dict):
            items = list(items.values()) if list_key == "Items" else []
        for item in items:
            yield item
        next_token = data.get(next_token_key)
        if not next_token:
            break


class AWS:
    SOURCE = "AWS"

    def __init__(self, regions=None):
        self.regions = regions or []
        self.logger = logging.getLogger("aws_collector")
        self._account_env_cache = {}
        self.auth_ok = self._setup_credentials()

    def _get_account_env(self, account_id):
        """Return env dict with credentials for account (assumed role), or None for default."""
        if not account_id or not getattr(self, "assume_role_pattern", None):
            return None
        if account_id in self._account_env_cache:
            return self._account_env_cache[account_id]
        role_arn = self.assume_role_pattern.format(account_id=account_id)
        ok, data = _run_aws(
            ["sts", "assume-role", "--role-arn", role_arn, "--role-session-name", f"appollo-{account_id}"],
            timeout=30,
        )
        if not ok or not data or "Credentials" not in data:
            self.logger.warning(
                "AssumeRole failed for account %s (role %s). Ensure the role exists and trusts this identity.",
                account_id,
                role_arn,
            )
            return None
        creds = data["Credentials"]
        env = {
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
        }
        self._account_env_cache[account_id] = env
        return env

    def _load_base_credentials_from_gcp_secret(self):
        """When running on GCP: optionally load base AWS creds from Secret Manager (no long-lived keys in env)."""
        if os.getenv("AWS_ACCESS_KEY_ID"):
            return
        secret_name = os.getenv("AWS_CREDENTIALS_SECRET", "").strip()
        if not secret_name:
            return
        try:
            try:
                from google.cloud import secretmanager
            except ImportError:
                return  # optional: pip install google-cloud-secret-manager
            client = secretmanager.SecretManagerServiceClient()
            # secret_name can be full resource name or projects/PROJECT_ID/secrets/NAME/versions/LATEST
            if not secret_name.startswith("projects/"):
                project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT", "")
                if not project:
                    return
                secret_name = f"projects/{project}/secrets/{secret_name.split('/')[-1]}/versions/latest"
            if "/versions/" not in secret_name:
                secret_name = secret_name.rstrip("/") + "/versions/latest"
            response = client.access_secret_version(request={"name": secret_name})
            payload = response.payload.data.decode("utf-8")
            data = json.loads(payload)
            for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
                if data.get(key):
                    os.environ[key] = str(data[key])
            if data.get("AWS_SESSION_TOKEN"):
                os.environ["AWS_SESSION_TOKEN"] = str(data["AWS_SESSION_TOKEN"])
            self.logger.info("Loaded base AWS credentials from GCP Secret Manager")
        except Exception as e:
            self.logger.warning("Failed to load AWS credentials from GCP Secret Manager: %s", e)

    def _setup_credentials(self):
        """Load base creds (e.g. from GCP Secret Manager) then verify AWS CLI is configured."""
        self._load_base_credentials_from_gcp_secret()
        ok, data = _run_aws(["sts", "get-caller-identity"], timeout=15)
        if not ok or not data:
            print("[bold red]CRITICAL: AWS CLI not configured or not found. Install the AWS CLI, run `aws configure` (or set AWS_* env), or set AWS_CLI_PATH to the full path of the 'aws' binary.[/bold red]")
            return False
        print(f"[green][+] AWS CLI auth OK: {data.get('Arn', '')}[/green]")
        assume = os.getenv("AWS_ASSUME_ROLE_PATTERN", "").strip()
        if not assume:
            role_name = os.getenv("AWS_ASSUME_ROLE_NAME", "").strip()
            if role_name:
                assume = f"arn:aws:iam::{{account_id}}:role/{role_name}"
        if assume:
            self.assume_role_pattern = assume
            print(f"[blue][+] Cross-account assume-role pattern set[/blue]")
        return True

    def list_accounts(self):
        """List accounts: from AWS_ACCOUNT_IDS (GCP/assume-role flow), Organizations, or current identity."""
        # Explicit list when running from GCP / automation (assume-role into each account)
        account_ids_raw = os.getenv("AWS_ACCOUNT_IDS", "").strip()
        if account_ids_raw:
            ids = [a.strip() for a in account_ids_raw.split(",") if a.strip()]
            if ids:
                if not getattr(self, "assume_role_pattern", None):
                    assume = os.getenv("AWS_ASSUME_ROLE_PATTERN", "").strip()
                    if assume:
                        self.assume_role_pattern = assume
                    else:
                        print("[bold yellow][!] AWS_ACCOUNT_IDS set but AWS_ASSUME_ROLE_PATTERN required for assume-role[/bold yellow]")
                        return []
                accounts = [{"id": aid, "name": f"Account-{aid}", "email": ""} for aid in ids]
                print(f"[green][+] Using {len(accounts)} account(s) from AWS_ACCOUNT_IDS (assume-role)[/green]")
                return accounts
        env = None
        ok, data = _run_aws(["organizations", "list-accounts"], env_override=env, timeout=30)
        if ok and data:
            accounts = []
            for a in data.get("Accounts", []):
                if a.get("Status") == "ACTIVE":
                    accounts.append({"id": a["Id"], "name": a["Name"], "email": a.get("Email", "")})
            if accounts:
                print(f"[green][+] Found {len(accounts)} accounts via Organizations[/green]")
                return accounts
        ok, data = _run_aws(["sts", "get-caller-identity"], timeout=15)
        if ok and data:
            aid = data.get("Account", "")
            return [{"id": aid, "name": f"Account-{aid}", "email": "unknown"}]
        return []

    def list_regions(self, account_id=None):
        """Return explicit regions or discover via CLI."""
        if self.regions:
            return self._slice_regions(self.regions)
        allow = os.getenv("AWS_SCAN_REGIONS", "").strip()
        if allow:
            return self._slice_regions([r.strip() for r in allow.split(",") if r.strip()])
        env = self._get_account_env(account_id)
        ok, data = _run_aws(["ec2", "describe-regions", "--region", "us-east-1", "--query", "Regions[].RegionName", "--output", "json"], env_override=env, timeout=15)
        if ok and isinstance(data, list) and data:
            return self._slice_regions(sorted(data))
        return self._slice_regions(list(DEFAULT_REGIONS))

    def _slice_regions(self, regions):
        """Apply AWS_MAX_SCAN_REGIONS (optional) to avoid huge multi-region runs."""
        if not regions:
            return list(DEFAULT_REGIONS)
        cap = os.getenv("AWS_MAX_SCAN_REGIONS", "").strip()
        if cap.isdigit():
            n = int(cap)
            if 0 < n < len(regions):
                print(f"[dim][!] Scanning {n} of {len(regions)} regions (AWS_MAX_SCAN_REGIONS)[/dim]")
                return regions[:n]
        return regions

    def _handle_api_error(self, account_id, service_name, msg):
        if not msg or any(x in msg for x in ("AccessDenied", "UnauthorizedOperation", "InvalidUserID")):
            return
        print(f"[yellow]    ⚠️  [{account_id}] {service_name}: {msg[:80]}[/yellow]")

    @staticmethod
    def _is_public_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def get_account_ips(self, account_id, region):
        """Collect public IPs / hostnames for one account+region using AWS CLI."""
        ip_details = {
            "ec2_instances": set(),
            "ec2_ipv6": set(),
            "elastic_ips": set(),
            "load_balancers": set(),
            "rds_instances": set(),
            "nat_gateways": set(),
            "eks_clusters": set(),
            "cloudfront_distributions": set(),
            "api_gateway_endpoints": set(),
            "lambda_function_urls": set(),
            "lightsail_instances": set(),
            "lightsail_containers": set(),
            "lightsail_databases": set(),
            "lightsail_load_balancers": set(),
            "ecs_tasks": set(),
            "elastic_beanstalk": set(),
            "api_gateway_v2": set(),
            "appsync": set(),
            "s3_websites": set(),
            "documentdb": set(),
            "neptune": set(),
            "redshift": set(),
            "mq": set(),
            "msk": set(),
            "elasticache": set(),
            "global_accelerator": set(),
            "sagemaker": set(),
            "workspaces": set(),
            "emr": set(),
            "dms": set(),
        }
        env = self._get_account_env(account_id)
        base = ["ec2", "--region", region] if isinstance(region, str) else ["ec2", "--region", str(region)]

        # EC2 instances — check all (state is irrelevant; stopped instances have no public IP anyway)
        ok, data = _run_aws(base + ["describe-instances", "--query", "Reservations[].Instances[]"], env_override=env, timeout=90)
        if ok and isinstance(data, list):
            for inst in data:
                if not isinstance(inst, dict):
                    continue
                # Primary public IPv4
                pip = inst.get("PublicIpAddress")
                if pip:
                    ip_details["ec2_instances"].add(pip)
                # Secondary ENI public IPs + IPv6 addresses
                for eni in (inst.get("NetworkInterfaces") or []):
                    assoc = (eni.get("Association") or {})
                    pub = assoc.get("PublicIp")
                    if pub and pub != pip:
                        ip_details["ec2_instances"].add(pub)
                    for ipv6_entry in (eni.get("Ipv6Addresses") or []):
                        addr = ipv6_entry.get("Ipv6Address")
                        if addr:
                            ip_details["ec2_ipv6"].add(addr)
            v6_count = len(ip_details["ec2_ipv6"])
            print(f"[dim]    - [{account_id}] EC2 IPs in {region}: {len(ip_details['ec2_instances'])} IPv4, {v6_count} IPv6[/dim]")
        else:
            print(f"[dim]    - [{account_id}] EC2 describe-instances failed/empty in {region}[/dim]")

        # Elastic IPs
        ok, data = _run_aws(base + ["describe-addresses", "--query", "Addresses[].PublicIp"], env_override=env, timeout=30)
        if ok and isinstance(data, list):
            for ip in data:
                if ip:
                    ip_details["elastic_ips"].add(ip)
            print(f"[dim]    - [{account_id}] EIPs in {region}: {len(ip_details['elastic_ips'])}[/dim]")
        else:
            print(f"[dim]    - [{account_id}] EIP describe-addresses failed/empty in {region}[/dim]")

        # ALB/NLB
        ok, data = _run_aws(
            ["elbv2", "describe-load-balancers", "--region", region, "--query", "LoadBalancers[?Scheme==`internet-facing`].DNSName"],
            env_override=env,
            timeout=60,
        )
        if ok and isinstance(data, list):
            for dns in data:
                if dns:
                    ip_details["load_balancers"].add(dns)
        ok, data = _run_aws(
            ["elb", "describe-load-balancers", "--region", region, "--query", "LoadBalancerDescriptions[?Scheme==`internet-facing`].DNSName"],
            env_override=env,
            timeout=30,
        )
        if ok and isinstance(data, list):
            for dns in data:
                if dns:
                    ip_details["load_balancers"].add(dns)
        if ip_details["load_balancers"]:
            print(f"[dim]    - [{account_id}] ✓ {len(ip_details['load_balancers'])} LBs in {region}[/dim]")

        # RDS public
        ok, data = _run_aws(
            ["rds", "describe-db-instances", "--region", region, "--query", "DBInstances[?PubliclyAccessible==true && DBInstanceStatus==`available`].Endpoint.Address"],
            env_override=env,
            timeout=60,
        )
        if ok and isinstance(data, list):
            for addr in data:
                if addr:
                    ip_details["rds_instances"].add(addr)
            if ip_details["rds_instances"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['rds_instances'])} RDS in {region}[/dim]")

        # NAT Gateways
        ok, data = _run_aws(
            base + ["describe-nat-gateways", "--query", "NatGateways[?State==`available`].NatGatewayAddresses[].PublicIp"],
            env_override=env,
            timeout=30,
        )
        if ok and isinstance(data, list):
            for ip in data:
                if ip:
                    ip_details["nat_gateways"].add(ip)
            if ip_details["nat_gateways"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['nat_gateways'])} NAT in {region}[/dim]")

        # EKS
        ok, data = _run_aws(["eks", "list-clusters", "--region", region, "--query", "clusters[]"], env_override=env, timeout=30)
        if ok and isinstance(data, list) and data:
            for name in data:
                ok2, cluster = _run_aws(["eks", "describe-cluster", "--name", name, "--region", region, "--query", "cluster.endpoint"], env_override=env, timeout=20)
                if ok2 and cluster:
                    host = urlparse(cluster).hostname if isinstance(cluster, str) else None
                    if host:
                        ip_details["eks_clusters"].add(host)
            if ip_details["eks_clusters"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['eks_clusters'])} EKS in {region}[/dim]")

        # CloudFront (global) — only in us-east-1 to avoid duplicate
        if region == "us-east-1":
            ok_cf, data_cf = _run_aws(
                ["cloudfront", "list-distributions", "--query", "DistributionList.Items[].DomainName"],
                env_override=env,
                timeout=60,
            )
            if ok_cf and isinstance(data_cf, list):
                for d in data_cf:
                    if d:
                        ip_details["cloudfront_distributions"].add(d)
                if ip_details["cloudfront_distributions"]:
                    print(f"[dim]    - [{account_id}] ✓ CloudFront distributions[/dim]")

        # API Gateway (REST APIs) — per region
        ok, data = _run_aws(
            ["apigateway", "get-rest-apis", "--region", region, "--query", "items[].id"],
            env_override=env,
            timeout=30,
        )
        if ok and isinstance(data, list):
            for api_id in data:
                if api_id:
                    url = f"https://{api_id}.execute-api.{region}.amazonaws.com"
                    ip_details["api_gateway_endpoints"].add(url)
            if ip_details["api_gateway_endpoints"]:
                print(f"[dim]    - [{account_id}] ✓ API Gateway in {region}[/dim]")

        # Lightsail Instances
        ok, data = _run_aws(
            ["lightsail", "get-instances", "--region", region, "--query", "instances[?publicIpAddress]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for inst in data:
                pip = inst.get("publicIpAddress")
                if pip:
                    ip_details["lightsail_instances"].add(pip)
            if ip_details["lightsail_instances"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['lightsail_instances'])} Lightsail instances in {region}[/dim]")

        # Lightsail Containers
        ok, data = _run_aws(
            ["lightsail", "get-container-services", "--region", region, "--query", "containerServices[]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for svc in data:
                url = svc.get("url", "")
                if url:
                    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
                    ip_details["lightsail_containers"].add(hostname)
            if ip_details["lightsail_containers"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['lightsail_containers'])} Lightsail containers in {region}[/dim]")

        # Lightsail Databases
        ok, data = _run_aws(
            ["lightsail", "get-relational-databases", "--region", region,
             "--query", "relationalDatabases[?publiclyAccessible]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for db in data:
                endpoint = db.get("masterEndpoint", {}).get("address", "")
                if endpoint:
                    ip_details["lightsail_databases"].add(endpoint)
            if ip_details["lightsail_databases"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['lightsail_databases'])} Lightsail DBs in {region}[/dim]")

        # Lightsail Load Balancers
        ok, data = _run_aws(
            ["lightsail", "get-load-balancers", "--region", region, "--query", "loadBalancers[]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for lb in data:
                dns = lb.get("dnsName", "")
                if dns:
                    ip_details["lightsail_load_balancers"].add(dns)
            if ip_details["lightsail_load_balancers"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['lightsail_load_balancers'])} Lightsail LBs in {region}[/dim]")

        # ECS/Fargate Tasks with public IPs
        ok, data = _run_aws(
            ["ecs", "list-clusters", "--region", region, "--query", "clusterArns[]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for cluster_arn in data:
                ok2, tasks = _run_aws(
                    ["ecs", "list-tasks", "--cluster", cluster_arn, "--region", region,
                     "--query", "taskArns[]"],
                    env_override=env, timeout=30
                )
                if ok2 and tasks:
                    ok3, task_details = _run_aws(
                        ["ecs", "describe-tasks", "--cluster", cluster_arn, "--tasks"] + tasks[:100],
                        env_override=env, timeout=60
                    )
                    if ok3 and isinstance(task_details, dict):
                        for task in task_details.get("tasks", []):
                            for attachment in task.get("attachments", []):
                                if attachment.get("type") == "eni":
                                    for detail in attachment.get("details", []):
                                        if detail.get("name") == "networkInterfaceId":
                                            eni_id = detail.get("value")
                                            ok4, eni = _run_aws(
                                                ["ec2", "describe-network-interfaces",
                                                 "--network-interface-ids", eni_id, "--region", region,
                                                 "--query", "NetworkInterfaces[0].Association.PublicIp"],
                                                env_override=env, timeout=15
                                            )
                                            if ok4 and eni:
                                                ip_details["ecs_tasks"].add(eni)
            if ip_details["ecs_tasks"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['ecs_tasks'])} ECS/Fargate tasks in {region}[/dim]")

        # Elastic Beanstalk
        ok, data = _run_aws(
            ["elasticbeanstalk", "describe-environments", "--region", region,
             "--query", "Environments[?Status==`Ready`]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for env_eb in data:
                cname = env_eb.get("CNAME", "")
                if cname:
                    ip_details["elastic_beanstalk"].add(cname)
                endpoint = env_eb.get("EndpointURL", "")
                if endpoint:
                    hostname = endpoint.replace("https://", "").replace("http://", "").split("/")[0]
                    ip_details["elastic_beanstalk"].add(hostname)
            if ip_details["elastic_beanstalk"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['elastic_beanstalk'])} Elastic Beanstalk in {region}[/dim]")

        # API Gateway V2 (HTTP APIs & WebSocket APIs)
        ok, data = _run_aws(
            ["apigatewayv2", "get-apis", "--region", region, "--query", "Items[]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for api in data:
                endpoint = api.get("ApiEndpoint", "")
                if endpoint:
                    ip_details["api_gateway_v2"].add(endpoint)
            if ip_details["api_gateway_v2"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['api_gateway_v2'])} API Gateway V2 in {region}[/dim]")

        # AppSync GraphQL APIs
        ok, data = _run_aws(
            ["appsync", "list-graphql-apis", "--region", region,
             "--query", "graphqlApis[?authenticationType!=`PRIVATE`]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for api in data:
                uris = api.get("uris", {})
                for uri_type, uri in uris.items():
                    if uri:
                        ip_details["appsync"].add(uri)
            if ip_details["appsync"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['appsync'])} AppSync APIs in {region}[/dim]")

        # S3 Website Endpoints
        ok, data = _run_aws(
            ["s3", "list-buckets", "--query", "Buckets[].Name"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for bucket in data:
                ok2, website = _run_aws(
                    ["s3api", "get-bucket-website", "--bucket", bucket],
                    env_override=env, timeout=10
                )
                if ok2:
                    website_endpoint = f"{bucket}.s3-website-{region}.amazonaws.com"
                    ip_details["s3_websites"].add(website_endpoint)
            if ip_details["s3_websites"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['s3_websites'])} S3 websites in {region}[/dim]")

        # DocumentDB
        ok, data = _run_aws(
            ["docdb", "describe-db-clusters", "--region", region,
             "--query", "DBClusters[?PubliclyAccessible]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for cluster in data:
                endpoint = cluster.get("Endpoint", "")
                if endpoint:
                    ip_details["documentdb"].add(endpoint)
                reader = cluster.get("ReaderEndpoint", "")
                if reader:
                    ip_details["documentdb"].add(reader)
            if ip_details["documentdb"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['documentdb'])} DocumentDB in {region}[/dim]")

        # Neptune
        ok, data = _run_aws(
            ["neptune", "describe-db-clusters", "--region", region,
             "--query", "DBClusters[?PubliclyAccessible]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for cluster in data:
                endpoint = cluster.get("Endpoint", "")
                if endpoint:
                    ip_details["neptune"].add(endpoint)
            if ip_details["neptune"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['neptune'])} Neptune in {region}[/dim]")

        # Redshift
        ok, data = _run_aws(
            ["redshift", "describe-clusters", "--region", region,
             "--query", "Clusters[?PubliclyAccessible]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for cluster in data:
                endpoint = cluster.get("Endpoint", {}).get("Address", "")
                if endpoint:
                    ip_details["redshift"].add(endpoint)
            if ip_details["redshift"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['redshift'])} Redshift in {region}[/dim]")

        # Redshift Serverless
        ok, data = _run_aws(
            ["redshift-serverless", "list-workgroups", "--region", region,
             "--query", "workgroups[?publiclyAccessible]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for wg in data:
                endpoint = wg.get("endpoint", {}).get("address", "")
                if endpoint:
                    ip_details["redshift"].add(endpoint)

        # Amazon MQ
        ok, data = _run_aws(
            ["mq", "list-brokers", "--region", region,
             "--query", "BrokerSummaries[?BrokerState==`RUNNING`]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for broker in data:
                broker_id = broker.get("BrokerId")
                if broker_id:
                    ok2, detail = _run_aws(
                        ["mq", "describe-broker", "--broker-id", broker_id, "--region", region],
                        env_override=env, timeout=30
                    )
                    if ok2 and isinstance(detail, dict):
                        for inst in detail.get("BrokerInstances", []):
                            for ep in inst.get("Endpoints", []):
                                if ep:
                                    ip_details["mq"].add(ep)
            if ip_details["mq"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['mq'])} MQ brokers in {region}[/dim]")

        # MSK (Managed Kafka)
        ok, data = _run_aws(
            ["kafka", "list-clusters-v2", "--region", region,
             "--query", "ClusterInfoList[?State==`ACTIVE`]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for cluster in data:
                cluster_arn = cluster.get("ClusterArn")
                if cluster_arn:
                    ok2, brokers = _run_aws(
                        ["kafka", "get-bootstrap-brokers", "--cluster-arn", cluster_arn, "--region", region],
                        env_override=env, timeout=30
                    )
                    if ok2 and isinstance(brokers, dict):
                        for key, val in brokers.items():
                            if isinstance(val, str):
                                ip_details["msk"].add(val)
            if ip_details["msk"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['msk'])} MSK clusters in {region}[/dim]")

        # ElastiCache
        ok, data = _run_aws(
            ["elasticache", "describe-replication-groups", "--region", region,
             "--query", "ReplicationGroups[]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for rg in data:
                for ng in rg.get("NodeGroups", []):
                    primary = ng.get("PrimaryEndpoint", {}).get("Address", "")
                    if primary:
                        ip_details["elasticache"].add(primary)
                    reader = ng.get("ReaderEndpoint", {}).get("Address", "")
                    if reader:
                        ip_details["elasticache"].add(reader)
            if ip_details["elasticache"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['elasticache'])} ElastiCache in {region}[/dim]")

        # Global Accelerator (only in us-west-2)
        if region == "us-west-2":
            ok, data = _run_aws(
                ["globalaccelerator", "list-accelerators", "--region", "us-west-2",
                 "--query", "Accelerators[?Enabled]"],
                env_override=env, timeout=30
            )
            if ok and isinstance(data, list):
                for acc in data:
                    for ip_set in acc.get("IpSets", []):
                        for ip in ip_set.get("IpAddresses", []):
                            ip_details["global_accelerator"].add(ip)
                if ip_details["global_accelerator"]:
                    print(f"[dim]    - [{account_id}] ✓ {len(ip_details['global_accelerator'])} Global Accelerator IPs[/dim]")

        # SageMaker Notebook Instances
        ok, data = _run_aws(
            ["sagemaker", "list-notebook-instances", "--region", region,
             "--query", "NotebookInstances[?NotebookInstanceStatus==`InService`]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for nb in data:
                name = nb.get("NotebookInstanceName")
                if name:
                    ok2, detail = _run_aws(
                        ["sagemaker", "describe-notebook-instance",
                         "--notebook-instance-name", name, "--region", region],
                        env_override=env, timeout=15
                    )
                    if ok2 and isinstance(detail, dict):
                        url = detail.get("Url", "")
                        if url:
                            ip_details["sagemaker"].add(url)
            if ip_details["sagemaker"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['sagemaker'])} SageMaker in {region}[/dim]")

        # SageMaker Endpoints
        ok, data = _run_aws(
            ["sagemaker", "list-endpoints", "--region", region,
             "--query", "Endpoints[?EndpointStatus==`InService`]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for ep in data:
                name = ep.get("EndpointName")
                if name:
                    endpoint_url = f"https://runtime.sagemaker.{region}.amazonaws.com/endpoints/{name}/invocations"
                    ip_details["sagemaker"].add(endpoint_url)

        # WorkSpaces
        ok, data = _run_aws(
            ["workspaces", "describe-workspaces", "--region", region,
             "--query", "Workspaces[?State==`AVAILABLE`]"],
            env_override=env, timeout=60
        )
        if ok and isinstance(data, list):
            for ws in data:
                ip = ws.get("IpAddress")
                if ip:
                    ip_details["workspaces"].add(ip)
            if ip_details["workspaces"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['workspaces'])} WorkSpaces in {region}[/dim]")

        # EMR Clusters
        ok, data = _run_aws(
            ["emr", "list-clusters", "--region", region,
             "--cluster-states", "RUNNING", "WAITING",
             "--query", "Clusters[]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for cluster in data:
                cluster_id = cluster.get("Id")
                if cluster_id:
                    ok2, detail = _run_aws(
                        ["emr", "describe-cluster", "--cluster-id", cluster_id, "--region", region],
                        env_override=env, timeout=15
                    )
                    if ok2 and isinstance(detail, dict):
                        master_dns = detail.get("Cluster", {}).get("MasterPublicDnsName", "")
                        if master_dns:
                            ip_details["emr"].add(master_dns)
            if ip_details["emr"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['emr'])} EMR clusters in {region}[/dim]")

        # DMS Replication Instances
        ok, data = _run_aws(
            ["dms", "describe-replication-instances", "--region", region,
             "--query", "ReplicationInstances[?PubliclyAccessible]"],
            env_override=env, timeout=30
        )
        if ok and isinstance(data, list):
            for ri in data:
                for ip in ri.get("ReplicationInstancePublicIpAddresses", []):
                    if ip:
                        ip_details["dms"].add(ip)
            if ip_details["dms"]:
                print(f"[dim]    - [{account_id}] ✓ {len(ip_details['dms'])} DMS instances in {region}[/dim]")

        return ip_details

    @staticmethod
    def _rdns(ip: str) -> str:
        """Reverse DNS lookup for a single IP. Returns hostname or empty string."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def get_ec2_instances_detail(self, account_id, region) -> list[dict]:
        """Return per-instance detail: IDs, types, state, tags, IPs (v4 + v6)."""
        env = self._get_account_env(account_id)
        ok, data = _run_aws(
            ["ec2", "--region", region, "describe-instances", "--query", "Reservations[].Instances[]"],
            env_override=env, timeout=90,
        )
        if not ok or not isinstance(data, list):
            return []
        instances = []
        for inst in data:
            if not isinstance(inst, dict):
                continue
            tags = {t["Key"]: t["Value"] for t in (inst.get("Tags") or []) if t.get("Key")}
            ipv6_addrs = []
            secondary_public_ips = []
            primary_pip = inst.get("PublicIpAddress", "")
            for eni in (inst.get("NetworkInterfaces") or []):
                assoc = (eni.get("Association") or {})
                pub = assoc.get("PublicIp")
                if pub and pub != primary_pip:
                    secondary_public_ips.append(pub)
                for ipv6_entry in (eni.get("Ipv6Addresses") or []):
                    addr = ipv6_entry.get("Ipv6Address")
                    if addr:
                        ipv6_addrs.append(addr)
            instances.append({
                "instance_id": inst.get("InstanceId", ""),
                "instance_type": inst.get("InstanceType", ""),
                "state": (inst.get("State") or {}).get("Name", ""),
                "public_ip": primary_pip,
                "secondary_public_ips": secondary_public_ips,
                "private_ip": inst.get("PrivateIpAddress", ""),
                "ipv6_addresses": ipv6_addrs,
                "region": region,
                "name": tags.get("Name", ""),
                "tags": tags,
                "launch_time": str(inst.get("LaunchTime", "")),
                "platform": inst.get("Platform", "linux"),
                "vpc_id": inst.get("VpcId", ""),
                "subnet_id": inst.get("SubnetId", ""),
                "security_group_ids": [sg.get("GroupId", "") for sg in (inst.get("SecurityGroups") or [])],
            })
        return instances

    def get_elb_assets(self, account_id, region):
        """Return ELB/ALB/NLB assets with name, dns, type, scheme."""
        env = self._get_account_env(account_id)
        assets = []
        ok, data = _run_aws(
            ["elbv2", "describe-load-balancers", "--region", region, "--query", "LoadBalancers[]"],
            env_override=env,
            timeout=60,
        )
        if ok and isinstance(data, list):
            for lb in data:
                if isinstance(lb, dict):
                    assets.append({
                        "type": lb.get("Type", "application"),
                        "name": lb.get("LoadBalancerName", ""),
                        "dns": lb.get("DNSName", ""),
                        "arn": lb.get("LoadBalancerArn", ""),
                        "scheme": lb.get("Scheme", ""),
                        "region": region,
                    })
        ok, data = _run_aws(
            ["elb", "describe-load-balancers", "--region", region, "--query", "LoadBalancerDescriptions[]"],
            env_override=env,
            timeout=30,
        )
        if ok and isinstance(data, list):
            for lb in data:
                if isinstance(lb, dict):
                    assets.append({
                        "type": "classic",
                        "name": lb.get("LoadBalancerName", ""),
                        "dns": lb.get("DNSName", ""),
                        "arn": "",
                        "scheme": lb.get("Scheme", ""),
                        "region": region,
                    })
        return assets

    def get_rds_assets(self, account_id, region):
        """Return RDS instances with identifier, endpoint, public."""
        env = self._get_account_env(account_id)
        assets = []
        ok, data = _run_aws(
            ["rds", "describe-db-instances", "--region", region, "--query", "DBInstances[]"],
            env_override=env,
            timeout=60,
        )
        if ok and isinstance(data, list):
            for db in data:
                if isinstance(db, dict):
                    ep = db.get("Endpoint") or {}
                    assets.append({
                        "identifier": db.get("DBInstanceIdentifier", ""),
                        "engine": db.get("Engine", ""),
                        "endpoint": ep.get("Address", ""),
                        "port": ep.get("Port"),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "region": region,
                    })
        return assets

    def get_eks_assets(self, account_id, region):
        """Return EKS clusters with name and endpoint."""
        env = self._get_account_env(account_id)
        assets = []
        ok, data = _run_aws(["eks", "list-clusters", "--region", region, "--query", "clusters[]"], env_override=env, timeout=30)
        if ok and isinstance(data, list):
            for name in data:
                if not name:
                    continue
                ok2, cluster = _run_aws(
                    ["eks", "describe-cluster", "--name", name, "--region", region, "--query", "cluster"],
                    env_override=env,
                    timeout=20,
                )
                if ok2 and isinstance(cluster, dict):
                    endpoint = (cluster.get("endpoint") or "").strip()
                    assets.append({"name": name, "endpoint": endpoint, "region": region})
        return assets

    def get_cloudfront_assets(self, account_id):
        """Return CloudFront distributions (global)."""
        env = self._get_account_env(account_id)
        assets = []
        ok, data = _run_aws(
            ["cloudfront", "list-distributions", "--query", "DistributionList.Items[]"],
            env_override=env,
            timeout=60,
        )
        if ok and data:
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = (data.get("DistributionList") or {}).get("Items") or []
            else:
                items = []
            for d in items:
                if isinstance(d, dict):
                    aliases = d.get("Aliases", {}).get("Items") or []
                    assets.append({
                        "id": d.get("Id", ""),
                        "domainName": d.get("DomainName", ""),
                        "aliases": aliases,
                        "enabled": d.get("Enabled", False),
                    })
        return assets

    def get_api_gateway_assets(self, account_id, region):
        """Return API Gateway REST APIs with id, name, endpoint."""
        env = self._get_account_env(account_id)
        assets = []
        ok, data = _run_aws(
            ["apigateway", "get-rest-apis", "--region", region, "--query", "items[]"],
            env_override=env,
            timeout=30,
        )
        if ok and isinstance(data, list):
            for api in data:
                if isinstance(api, dict) and api.get("id"):
                    assets.append({
                        "id": api["id"],
                        "name": api.get("name", ""),
                        "endpoint": f"https://{api['id']}.execute-api.{region}.amazonaws.com",
                        "region": region,
                    })
        return assets

    def get_lambda_url_assets(self, account_id, region):
        """Return Lambda functions with function URL (via list-function-url-configs per function)."""
        env = self._get_account_env(account_id)
        assets = []
        ok, data = _run_aws(
            ["lambda", "list-functions", "--region", region, "--query", "Functions[].FunctionName"],
            env_override=env,
            timeout=120,
        )
        if not ok or not isinstance(data, list):
            return assets
        names = [n for n in data if n]
        total = len(names)
        if total > _LAMBDA_URL_MAX:
            print(
                f"[dim]    - [{account_id}] Lambda URL probe: { _LAMBDA_URL_MAX }/{total} in {region} "
                f"(raise AWS_LAMBDA_URL_MAX_CHECKS)[/dim]"
            )
            names = names[:_LAMBDA_URL_MAX]

        def _urls_for_one(fname):
            out = []
            ok2, configs = _run_aws(
                [
                    "lambda",
                    "list-function-url-configs",
                    "--function-name",
                    fname,
                    "--region",
                    region,
                    "--query",
                    "FunctionUrlConfigs[]",
                ],
                env_override=env,
                timeout=20,
            )
            if ok2 and isinstance(configs, list):
                for c in configs:
                    if isinstance(c, dict) and c.get("FunctionUrl"):
                        out.append({"name": fname, "url": c["FunctionUrl"], "region": region})
            return out

        w = min(_LAMBDA_URL_WORKERS, max(1, len(names)))
        with ThreadPoolExecutor(max_workers=w) as pool:
            for chunk in pool.map(_urls_for_one, names):
                assets.extend(chunk)
        return assets

    def get_security_groups(self, account_id, region):
        """Collect and analyze security groups via CLI."""
        env = self._get_account_env(account_id)
        ok, data = _run_aws(
            ["ec2", "describe-security-groups", "--region", region, "--query", "SecurityGroups[]"],
            env_override=env,
            timeout=60,
        )
        if not ok or not isinstance(data, list):
            return [], []
        security_groups = []
        risky_rules = []
        for sg in data:
            if not isinstance(sg, dict):
                continue
            sg_analysis = {
                "GroupId": sg.get("GroupId", ""),
                "GroupName": sg.get("GroupName", ""),
                "Description": sg.get("Description", ""),
                "VpcId": sg.get("VpcId"),
                "Region": region,
                "InboundRules": [],
                "OutboundRules": [],
                "RiskLevel": "Low",
                "SecurityIssues": [],
            }
            for rule in sg.get("IpPermissions", []):
                rule_analysis = self._analyze_sg_rule(rule, "inbound", sg.get("GroupId", ""))
                sg_analysis["InboundRules"].append(rule_analysis)
                if rule_analysis.get("Risk") in ("High", "Critical"):
                    sg_analysis["RiskLevel"] = rule_analysis["Risk"]
                    sg_analysis["SecurityIssues"].append(rule_analysis.get("Issue", ""))
                    risky_rules.append({
                        "account_id": account_id,
                        "region": region,
                        "security_group": sg.get("GroupId"),
                        "rule": rule_analysis,
                        "severity": rule_analysis.get("Risk"),
                    })
            for rule in sg.get("IpPermissionsEgress", []):
                rule_analysis = self._analyze_sg_rule(rule, "outbound", sg.get("GroupId", ""))
                sg_analysis["OutboundRules"].append(rule_analysis)
            security_groups.append(sg_analysis)
        if security_groups:
            risky_count = len([s for s in security_groups if s.get("RiskLevel") in ("High", "Critical")])
            print(f"[dim]    - [{account_id}] ✓ {len(security_groups)} SGs in {region} ({risky_count} risky)[/dim]")
        return security_groups, risky_rules

    def _analyze_sg_rule(self, rule, direction, sg_id):
        from_port = rule.get("FromPort") or 0
        to_port = rule.get("ToPort") or 65535
        protocol = rule.get("IpProtocol", "tcp")
        rule_data = {
            "Protocol": protocol,
            "FromPort": from_port,
            "ToPort": to_port,
            "Direction": direction,
            "Sources": [],
            "Risk": "Low",
            "Issue": None,
        }
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            rule_data["Sources"].append({"Type": "CIDR", "Value": cidr})
            if cidr == "0.0.0.0/0" and direction == "inbound":
                dangerous = [22, 3389, 1433, 3306, 5432, 6379, 27017]
                if from_port in dangerous or (from_port <= 22 <= to_port):
                    rule_data["Risk"] = "Critical"
                    rule_data["Issue"] = f"Port {from_port}-{to_port} open to 0.0.0.0/0"
                elif from_port in (80, 443):
                    rule_data["Risk"] = "Medium"
                    rule_data["Issue"] = "HTTP/HTTPS open to internet"
                else:
                    rule_data["Risk"] = "High"
                    rule_data["Issue"] = f"Port {from_port}-{to_port} open to internet"
        for sg_ref in rule.get("UserIdGroupPairs", []):
            rule_data["Sources"].append({"Type": "SecurityGroup", "Value": sg_ref.get("GroupId", "")})
        return rule_data

    def fetch_route53_records(self, account_id):
        """Return list of Route 53 public zone records via CLI."""
        env = self._get_account_env(account_id)
        ok, data = _run_aws(["route53", "list-hosted-zones", "--query", "HostedZones[]"], env_override=env, timeout=30)
        if not ok or not data:
            return []
        zones = []
        for z in (data if isinstance(data, list) else data.get("HostedZones", []) if isinstance(data, dict) else []):
            if not isinstance(z, dict):
                continue
            if z.get("Config", {}).get("PrivateZone") is True:
                continue
            zone_id = (z.get("Id") or "").replace("/hostedzone/", "")
            name = (z.get("Name") or "").rstrip(".")
            if zone_id and name:
                zones.append({"id": zone_id, "name": name})
        if not zones:
            return []
        print(f"[dim]    - [{account_id}] ✓ {len(zones)} public Route 53 zones[/dim]")
        records = []
        for zone in zones:
            zone_id = zone["id"]
            next_token = None
            page = 0
            while page < _ROUTE53_MAX_PAGES:
                args = ["route53", "list-resource-record-sets", "--hosted-zone-id", zone_id]
                if next_token:
                    args += ["--starting-token", next_token]
                ok, data = _run_aws(args, env_override=env, timeout=90)
                if not ok or not data:
                    break
                page += 1
                for rs in data.get("ResourceRecordSets", []):
                    rtype = rs.get("Type", "")
                    name = (rs.get("Name") or "").rstrip(".")
                    ttl = rs.get("TTL", 300)
                    values = []
                    if "ResourceRecords" in rs:
                        values = [rr.get("Value", "") for rr in rs["ResourceRecords"]]
                    elif "AliasTarget" in rs:
                        values = [(rs["AliasTarget"].get("DNSName") or "").rstrip(".")]
                    for v in values:
                        if v:
                            records.append({"name": name, "type": rtype, "ttl": ttl, "data": v, "zone": zone["name"]})
                next_token = data.get("NextToken")
                if not next_token:
                    break
            if page >= _ROUTE53_MAX_PAGES and next_token:
                print(f"[yellow]    ⚠️  [{account_id}] Route53 zone {zone_id}: truncated at {_ROUTE53_MAX_PAGES} pages[/yellow]")
        if records:
            print(f"[dim]    - [{account_id}] ✓ {len(records)} Route 53 records[/dim]")
        return records

    def cleanup_stale_data(self, active_accounts):
        if not active_accounts:
            return
        try:
            mongo = MongoDB()
            active_ids = [a["id"] for a in active_accounts]
            archive_update = {"$set": {"status": "archived", "archived_at": datetime.now()}}
            stale_filter = {"source": self.SOURCE, "account_id": {"$nin": active_ids}, "status": {"$ne": "archived"}}
            for col_name in ("Prod IP Records", "Prod DNS", "Prod DNS Records", "Prod Security Groups", "Prod AWS Assets"):
                col = mongo.set_collection(col_name)
                res = col.update_many(stale_filter, archive_update)
                if res.modified_count:
                    print(f"[dim] - Archived {res.modified_count} stale {self.SOURCE} in '{col_name}'[/dim]")
        except Exception as e:
            print(f"[bold red][-] Stale-data cleanup error: {e}[/bold red]")

    def run(self, max_workers=None, lightweight=False):
        if max_workers is None:
            max_workers = 10
        if not self.auth_ok:
            print("[bold red][-] Skipping AWS scan — auth failed[/bold red]")
            return None, None
        console = Console()
        mode = " (lightweight: IPs, DNS, SGs only)" if lightweight else ""
        print(f"[bold blue][+] Starting {self.SOURCE} inventory scan (CLI){mode}...[/bold blue]")
        if lightweight:
            print(
                "[dim]Skipping ELB/RDS/EKS/CloudFront/API GW/Lambda asset crawl — run standalone aws-scan for full assets.[/dim]"
            )
        accounts = self.list_accounts()
        if not accounts:
            print("[bold yellow][!] No active accounts[/bold yellow]")
            return None, None
        print(f"[bold blue][+] Found {len(accounts)} accounts[/bold blue]")
        all_account_ips = {}
        all_account_dns = {}
        all_security_groups = {}
        all_risky_rules = {}
        all_assets = {}
        all_ec2_detail = {}

        def fetch_region_data(args_tuple):
            aid, region = args_tuple[0], args_tuple[1]
            try:
                region_ips = self.get_account_ips(aid, region)
                region_ec2 = self.get_ec2_instances_detail(aid, region)
                security_groups, risky_rules = self.get_security_groups(aid, region)
                return region, region_ips, region_ec2, security_groups, risky_rules
            except Exception as e:
                print(f"[red]    ❌ {region}/{aid}: {e}[/red]")
                return region, {}, [], [], []

        def fetch_account_ips_and_sg(account):
            aid = account["id"]
            try:
                print(f"[blue][+] {account.get('name', aid)} ({aid}) — IPs & SGs[/blue]")
                regions = self.list_regions(aid)
                if not regions:
                    return aid, {}, [], [], []
                merged_ips = {}
                all_ec2_detail = []
                all_sgs, all_risky = [], []
                # Cap parallel regions to avoid thread/process storms across many accounts
                region_workers = min(max_workers, len(regions), 12)
                with ThreadPoolExecutor(max_workers=region_workers) as ex:
                    for _r, region_ips, region_ec2, sgs, risky in ex.map(fetch_region_data, [(aid, r) for r in regions]):
                        for rtype, ip_set in region_ips.items():
                            if ip_set:
                                merged_ips.setdefault(rtype, set()).update(ip_set)
                        all_ec2_detail.extend(region_ec2)
                        all_sgs.extend(sgs)
                        all_risky.extend(risky)
                return aid, merged_ips, all_ec2_detail, all_sgs, all_risky
            except Exception as e:
                print(f"[red]    ❌ Account {aid}: {e}[/red]")
                return aid, {}, [], [], []

        def fetch_account_dns(account):
            aid = account["id"]
            try:
                print(f"[blue][+] {account.get('name', aid)} ({aid}) — DNS[/blue]")
                return aid, self.fetch_route53_records(aid)
            except Exception as e:
                print(f"[red]    ❌ Account {aid} DNS: {e}[/red]")
                return aid, []

        def fetch_account_assets(account):
            aid = account["id"]
            try:
                print(f"[blue][+] {account.get('name', aid)} ({aid}) — Assets (ELB, RDS, EKS, CloudFront, API GW, Lambda)[/blue]")
                regions = self.list_regions(aid)
                elb, rds, eks, api_gateway, lambda_urls = [], [], [], [], []

                def _fetch_region_assets(region):
                    return (
                        self.get_elb_assets(aid, region),
                        self.get_rds_assets(aid, region),
                        self.get_eks_assets(aid, region),
                        self.get_api_gateway_assets(aid, region),
                        self.get_lambda_url_assets(aid, region),
                    )

                region_workers = min(max_workers, len(regions), 8)
                with ThreadPoolExecutor(max_workers=region_workers) as rpool:
                    for _elb, _rds, _eks, _agw, _lmb in rpool.map(_fetch_region_assets, regions):
                        elb.extend(_elb)
                        rds.extend(_rds)
                        eks.extend(_eks)
                        api_gateway.extend(_agw)
                        lambda_urls.extend(_lmb)

                cloudfront = self.get_cloudfront_assets(aid)
                return aid, {
                    "elb": elb,
                    "rds": rds,
                    "eks": eks,
                    "cloudfront": cloudfront,
                    "api_gateway": api_gateway,
                    "lambda_urls": lambda_urls,
                }
            except Exception as e:
                print(f"[red]    ❌ Account {aid} assets: {e}[/red]")
                return aid, {}

        phases = 2 if lightweight else 3
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Fetching AWS resources...", total=len(accounts) * phases)
            # Fewer concurrent accounts reduces nested thread pools (regions × accounts)
            account_pool = max(1, min(max_workers, 6, len(accounts)))
            with ThreadPoolExecutor(max_workers=account_pool) as executor:
                ip_futures = {executor.submit(fetch_account_ips_and_sg, a): a for a in accounts}
                dns_futures = {executor.submit(fetch_account_dns, a): a for a in accounts}
                asset_futures = (
                    {}
                    if lightweight
                    else {executor.submit(fetch_account_assets, a): a for a in accounts}
                )
                for future in as_completed(ip_futures):
                    aid, ips, ec2_detail, sgs, risky = future.result()
                    if ips:
                        all_account_ips[aid] = ips
                    if ec2_detail:
                        all_ec2_detail[aid] = ec2_detail
                    if sgs:
                        all_security_groups[aid] = sgs
                    if risky:
                        all_risky_rules[aid] = risky
                    progress.advance(task)
                for future in as_completed(dns_futures):
                    aid, dns = future.result()
                    if dns:
                        all_account_dns[aid] = dns
                    progress.advance(task)
                for future in as_completed(asset_futures):
                    aid, assets = future.result()
                    if assets:
                        all_assets[aid] = assets
                    progress.advance(task)

        print(f"[bold blue][+] Storing {self.SOURCE} data...[/bold blue]")
        self._store_ip_records(all_account_ips)
        self._store_endpoint_dns(all_account_ips)
        self._store_bulk_dns(all_account_dns)
        self._store_security_groups(all_security_groups, all_risky_rules)
        self._store_individual_dns(all_account_dns)
        self._store_ec2_detail(all_ec2_detail)
        if not lightweight:
            self._store_aws_assets(all_assets)
        self._print_stats(accounts, all_account_ips, all_account_dns, all_security_groups)
        self.cleanup_stale_data(accounts)
        return all_account_ips, all_account_dns

    def _store_ip_records(self, all_account_ips):
        if not all_account_ips:
            return
        mongo = MongoDB()
        col = mongo.set_collection("Prod IP Records")
        for account_id, ip_details in all_account_ips.items():
            resource_types = {}
            total_count = 0
            all_public_ips = []
            for rtype, ip_set in ip_details.items():
                if rtype not in _IP_RESOURCE_TYPES:
                    continue  # DNS hostnames go to _store_endpoint_dns, not here
                if ip_set:
                    resource_types[rtype] = list(ip_set)
                    total_count += len(ip_set)
                    # Collect IPv4 only for reverse DNS (skip IPv6 and hostnames)
                    for ip in ip_set:
                        try:
                            addr = ipaddress.ip_address(ip)
                            if addr.version == 4 and addr.is_global:
                                all_public_ips.append(ip)
                        except ValueError:
                            pass
            if total_count == 0:
                continue
            # Resolve reverse DNS for all discovered public IPv4s (parallel, best-effort)
            rdns_map = {}
            if all_public_ips:
                with ThreadPoolExecutor(max_workers=20) as rdns_pool:
                    results = rdns_pool.map(self._rdns, all_public_ips)
                rdns_map = {ip: rdns for ip, rdns in zip(all_public_ips, results) if rdns}

            record = {
                "account_id": account_id,
                "source": self.SOURCE,
                "resource_types": resource_types,
                "total_count": total_count,
                "rdns": rdns_map,
                "status": "active",
            }
            try:
                col.update_one(
                    {"account_id": account_id, "source": self.SOURCE},
                    {"$set": record, "$setOnInsert": {"timestamp": datetime.now()}},
                    upsert=True,
                )
            except Exception as e:
                print(f"[yellow] [{account_id}] IP store error: {e}[/yellow]")
        print(f"[green]✓ {self.SOURCE} IP Records stored (EC2, EIP, NAT, Lightsail, ECS, WorkSpaces, Global Accelerator, DMS, rDNS)[/green]")

    def _store_endpoint_dns(self, all_account_ips):
        """Store DNS-based endpoints (LBs, RDS, EKS, CloudFront, API GW, Lambda)
        into Prod DNS Records as CNAME entries so they appear in the DNS view
        and are picked up as scan targets by get_all_targets()."""
        if not all_account_ips:
            return
        mongo = MongoDB()
        col = mongo.set_collection("Prod DNS Records")
        stored = 0
        for account_id, ip_details in all_account_ips.items():
            for rtype, resource_type_label in _ENDPOINT_RESOURCE_TYPES.items():
                for endpoint in ip_details.get(rtype, set()):
                    if not endpoint:
                        continue
                    # Strip URL scheme so API GW / Lambda URLs become scannable hostnames
                    hostname = endpoint.replace("https://", "").replace("http://", "").split("/")[0]
                    if not hostname:
                        continue
                    record_data = {
                        "zone_name": account_id,
                        "name": hostname,
                        "type": "CNAME",
                        "content": hostname,
                        "proxied": "",
                        "resource_type": resource_type_label,
                        "source": self.SOURCE,
                        "account_id": account_id,
                        "status": "active",
                    }
                    record_hash = calculate_hash(record_data)
                    doc = {**record_data, "hash": record_hash}
                    try:
                        col.update_one(
                            {"hash": record_hash},
                            {"$set": doc, "$setOnInsert": {"timestamp": datetime.now()}},
                            upsert=True,
                        )
                        stored += 1
                    except Exception:
                        pass
        if stored:
            print(f"[green]✓ {self.SOURCE} Endpoint DNS stored ({stored} records: LBs, RDS, EKS, CloudFront, API GW, Lambda, Lightsail, Beanstalk, DocumentDB, Neptune, Redshift, MQ, MSK, ElastiCache, SageMaker, EMR, AppSync, S3 Websites)[/green]")

    def _store_bulk_dns(self, all_account_dns):
        if not all_account_dns:
            return
        mongo = MongoDB()
        col = mongo.set_collection("Prod DNS")
        for account_id, dns_records in all_account_dns.items():
            if not dns_records:
                continue
            record = {"account_id": account_id, "source": self.SOURCE, "records": dns_records, "count": len(dns_records), "status": "active"}
            try:
                col.update_one(
                    {"account_id": account_id, "source": self.SOURCE},
                    {"$set": record, "$setOnInsert": {"timestamp": datetime.now()}},
                    upsert=True,
                )
            except Exception as e:
                print(f"[yellow] [{account_id}] DNS store error: {e}[/yellow]")
        print(f"[green]✓ {self.SOURCE} DNS stored[/green]")

    def _store_security_groups(self, all_security_groups, all_risky_rules):
        if not all_security_groups:
            return
        mongo = MongoDB()
        col = mongo.set_collection("Prod Security Groups")
        for account_id, security_groups in all_security_groups.items():
            risky_rules = all_risky_rules.get(account_id, [])
            total = len(security_groups)
            high_risk = len([s for s in security_groups if s.get("RiskLevel") in ("High", "Critical")])
            critical = len([r for r in risky_rules if r.get("severity") == "Critical"])
            record = {
                "account_id": account_id,
                "source": self.SOURCE,
                "security_groups": security_groups,
                "risky_rules": risky_rules,
                "metrics": {
                    "total_security_groups": total,
                    "high_risk_groups": high_risk,
                    "critical_rules": critical,
                    "security_score": max(0, 100 - high_risk * 10 - critical * 20),
                },
                "status": "active",
            }
            try:
                col.update_one(
                    {"account_id": account_id, "source": self.SOURCE},
                    {"$set": record, "$setOnInsert": {"timestamp": datetime.now()}},
                    upsert=True,
                )
            except Exception as e:
                print(f"[yellow] [{account_id}] SG store error: {e}[/yellow]")
        print(f"[green]✓ {self.SOURCE} Security Groups stored[/green]")

    def _store_individual_dns(self, all_account_dns):
        if not all_account_dns:
            return
        mongo = MongoDB()
        col = mongo.set_collection("Prod DNS Records")
        for account_id, dns_records in all_account_dns.items():
            for rec in dns_records or []:
                record_data = {
                    "zone_name": rec.get("zone", ""),
                    "name": rec.get("name", ""),
                    "type": rec.get("type", ""),
                    "content": rec.get("data", ""),
                    "proxied": "",
                    "resource_type": "route53_dns",
                    "source": self.SOURCE,
                    "zone": rec.get("zone", ""),
                    "account_id": account_id,
                }
                record_hash = calculate_hash(record_data)
                doc = {**record_data, "hash": record_hash, "status": "active", "ttl": rec.get("ttl", 300)}
                try:
                    col.update_one({"hash": record_hash}, {"$set": doc, "$setOnInsert": {"timestamp": datetime.now()}}, upsert=True)
                except Exception:
                    pass
        print(f"[green]✓ {self.SOURCE} DNS Records stored[/green]")

    def _store_ec2_detail(self, all_ec2_detail: dict):
        """Store per-EC2-instance detail into Prod AWS Assets under ec2_instances key."""
        if not all_ec2_detail:
            return
        mongo = MongoDB()
        col = mongo.set_collection("Prod AWS Assets")
        for account_id, instances in all_ec2_detail.items():
            if not instances:
                continue
            record = {
                "account_id": account_id,
                "source": self.SOURCE,
                "asset_type": "ec2_instances",
                "instances": instances,
                "count": len(instances),
                "public_count": sum(1 for i in instances if i.get("public_ip")),
                "ipv6_count": sum(len(i.get("ipv6_addresses", [])) for i in instances),
                "status": "active",
            }
            try:
                col.update_one(
                    {"account_id": account_id, "source": self.SOURCE, "asset_type": "ec2_instances"},
                    {"$set": record, "$setOnInsert": {"timestamp": datetime.now()}},
                    upsert=True,
                )
            except Exception as e:
                print(f"[yellow] [{account_id}] EC2 detail store error: {e}[/yellow]")
        total = sum(len(v) for v in all_ec2_detail.values())
        print(f"[green]✓ {self.SOURCE} EC2 detail stored ({total} instances with IPs, IPv6, tags)[/green]")

    def _store_aws_assets(self, all_assets):
        """Store ELB, RDS, EKS, CloudFront, API Gateway, Lambda URL assets per account."""
        if not all_assets:
            return
        mongo = MongoDB()
        col = mongo.set_collection("Prod AWS Assets")
        for account_id, assets in all_assets.items():
            if not assets:
                continue
            record = {
                "account_id": account_id,
                "source": self.SOURCE,
                "asset_type": "aws_assets",
                "assets": assets,
                "status": "active",
            }
            try:
                col.update_one(
                    {"account_id": account_id, "source": self.SOURCE, "asset_type": "aws_assets"},
                    {"$set": record, "$setOnInsert": {"timestamp": datetime.now()}},
                    upsert=True,
                )
            except Exception as e:
                print(f"[yellow] [{account_id}] AWS Assets store error: {e}[/yellow]")
        print(f"[green]✓ {self.SOURCE} AWS Assets stored (ELB, RDS, EKS, CloudFront, API GW, Lambda)[/green]")

    def _print_stats(self, accounts, all_account_ips, all_account_dns, all_security_groups):
        all_ips = set()
        category_counts = {}
        for ip_details in all_account_ips.values():
            for rtype, ip_set in ip_details.items():
                if ip_set:
                    category_counts[rtype] = category_counts.get(rtype, 0) + len(ip_set)
                    all_ips.update(ip_set)
        total_dns = sum(len(r) for r in all_account_dns.values())
        total_sg = sum(len(s) for s in (all_security_groups or {}).values())
        print(f"\n[bold blue]📊 {self.SOURCE} stats[/bold blue]")
        print(f"[dim] Accounts: {len(accounts)} | Unique IPs/hostnames: {len(all_ips)} | DNS records: {total_dns} | Security groups: {total_sg}[/dim]")
        for rtype, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            if count > 0:
                print(f"[dim]   └─ {rtype}: {count}[/dim]")
        print(f"[bold green]  {self.SOURCE} scan completed (CLI)[/bold green]")


# ---------------------------------------------------------------------------
# Public API (Appollo and automation)
# ---------------------------------------------------------------------------


def run_aws_scan(max_workers: int = 10, regions=None, lightweight: bool = False) -> None:
    """
    Run the AWS attack-surface / inventory scan.

    *lightweight=True* (used by update-inventory): IPs, Route53 DNS, security groups
    only — skips the slow ELB/RDS/EKS/CloudFront/Lambda asset crawl.

    Call this from ``appollo.py`` (or jobs). Raises ``RuntimeError`` if the AWS
    CLI is not authenticated.
    """
    collector = AWS(regions=regions)
    if not collector.auth_ok:
        raise RuntimeError("AWS CLI authentication failed")
    collector.run(
        max_workers=max(1, min(int(max_workers or 10), 50)),
        lightweight=lightweight,
    )


def run_aws_connectivity_check() -> int:
    """
    Verify AWS CLI, base credentials, and optionally assume-role into listed accounts.
    Used by ``test_aws_assume_role.py`` from repo root.
    """
    aws_bin = _aws_binary()
    if not shutil.which(aws_bin) and not (os.path.isfile(aws_bin)):
        print("[FAIL] AWS CLI not found. Install it or set AWS_CLI_PATH.")
        return 1
    print(f"[OK] AWS CLI: {aws_bin}")

    ok, data, err = _aws_cli_exec(["sts", "get-caller-identity"], timeout=15)
    if not ok or not data:
        print("[FAIL] Base AWS auth failed.")
        if err:
            print(f"      {err[:200]}")
        return 1
    print(f"[OK] Base identity: {data.get('Arn', '')}")
    print(f"     Account: {data.get('Account', '')}\n")

    assume_pattern = os.getenv("AWS_ASSUME_ROLE_PATTERN", "").strip()
    account_ids_raw = os.getenv("AWS_ACCOUNT_IDS", "").strip()
    account_ids = [a.strip() for a in account_ids_raw.split(",") if a.strip()] if account_ids_raw else []

    if assume_pattern and account_ids:
        role_arn = assume_pattern.format(account_id=account_ids[0])
        ok, data, err = _aws_cli_exec(
            [
                "sts", "assume-role",
                "--role-arn", role_arn,
                "--role-session-name", f"appollo-test-{account_ids[0]}",
            ],
            timeout=30,
        )
        if not ok or not data or "Credentials" not in data:
            print(f"[FAIL] Assume-role failed for {account_ids[0]}.")
            if err:
                print(f"      {err[:300]}")
            return 1
        creds = data["Credentials"]
        env_assumed = {
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
        }
        print(f"[OK] Assumed role: {role_arn}")
        ok2, data2, err2 = _aws_cli_exec(
            ["sts", "get-caller-identity"], env_override=env_assumed, timeout=15,
        )
        if not ok2 or not data2:
            print("[FAIL] get-caller-identity with assumed creds failed.")
            if err2:
                print(f"      {err2[:200]}")
            return 1
        print(f"[OK] Identity after assume: {data2.get('Arn', '')}\n")
        print("Accounts from AWS_ACCOUNT_IDS:")
        for i, aid in enumerate(account_ids, 1):
            print(f"  {i}. {aid}")
        print(f"\n[OK] {len(account_ids)} account(s). Assume-role succeeded.\n")
        return 0

    ok, data, _ = _aws_cli_exec(["organizations", "list-accounts"], timeout=30)
    if ok and data:
        accounts = [a for a in data.get("Accounts", []) if a.get("Status") == "ACTIVE"]
        if accounts:
            print("Accounts from Organizations:")
            for i, a in enumerate(accounts[:20], 1):
                print(f"  {i}. {a.get('Id')}  {a.get('Name', '')}")
            if len(accounts) > 20:
                print(f"  ... and {len(accounts) - 20} more")
            print(f"\n[OK] {len(accounts)} account(s).\n")
            return 0
    ok, data, _ = _aws_cli_exec(["sts", "get-caller-identity"], timeout=15)
    if ok and data:
        print("Organizations unavailable; current account only:")
        print(f"  1. {data.get('Account')} (current)\n")
        return 0
    print("[FAIL] Could not list accounts.")
    return 1


# ── Optional library helpers (posture / graph extensions) ─────────────────

def analyze_ec2_security_posture(ec2_instances):
    findings = []
    for instance in ec2_instances or []:
        if isinstance(instance, dict) and instance.get("PublicIpAddress"):
            findings.append({"resource": instance.get("InstanceId", ""), "issue": "EC2_PUBLIC_INSTANCE", "severity": "Medium", "description": "EC2 has public IP", "remediation": "Review if needed"})
        if isinstance(instance, dict) and "SecurityGroups" in instance:
            for sg in instance.get("SecurityGroups", []):
                if "ssh-open-to-world" in (sg or {}).get("GroupName", ""):
                    findings.append({"resource": instance.get("InstanceId", ""), "issue": "SSH_OPEN_TO_WORLD", "severity": "High", "description": "SSH may be open to 0.0.0.0/0"})
    return findings


def analyze_s3_security_posture(buckets):
    findings = []
    for bucket in buckets or []:
        b = bucket if isinstance(bucket, dict) else {}
        if b.get("public_read"):
            findings.append({"resource": b.get("name", ""), "issue": "S3_PUBLIC_READ", "severity": "High", "description": "S3 public read"})
        if b.get("public_write"):
            findings.append({"resource": b.get("name", ""), "issue": "S3_PUBLIC_WRITE", "severity": "Critical", "description": "S3 public write"})
    return findings


def analyze_infrastructure_graph(aws_resources):
    graph = {"nodes": [], "edges": [], "critical_paths": []}
    for ec2 in (aws_resources or {}).get("ec2_instances", []):
        if not isinstance(ec2, dict):
            continue
        graph["nodes"].append({"id": ec2.get("InstanceId", ""), "type": "EC2", "public": bool(ec2.get("PublicIpAddress")), "critical": bool(ec2.get("PublicIpAddress"))})
        for sg in ec2.get("SecurityGroups", []):
            if isinstance(sg, dict):
                graph["edges"].append({"from": ec2.get("InstanceId", ""), "to": sg.get("GroupId", ""), "type": "uses"})
    return graph


def calculate_attack_surface_score(resources):
    resources = resources or {}
    score = len(resources.get("public_ips", [])) * 10 + len(resources.get("load_balancers", [])) * 5 + len(resources.get("public_databases", [])) * 20
    return {"total_score": score, "risk_level": "High" if score > 50 else "Medium" if score > 20 else "Low", "recommendations": _generate_recommendations(resources)}


def _generate_recommendations(resources):
    recs = []
    if len((resources or {}).get("public_ips", [])) > 5:
        recs.append("Consider ALB/NLB to reduce public IP exposure")
    if (resources or {}).get("public_databases"):
        recs.append("Review RDS public accessibility")
    return recs


def main():
    import argparse
    # Load project .env so AWS_* are available when run as script (cwd or repo root)
    try:
        from dotenv import load_dotenv
        load_dotenv(Path.cwd() / ".env")
        _root = Path(__file__).resolve().parent.parent.parent
        if _root != Path.cwd():
            load_dotenv(_root / ".env")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="AWS Attack Surface Discovery (CLI only)")
    parser.add_argument("--regions", nargs="+", help="Regions to scan")
    parser.add_argument("--max-workers", type=int, default=10)
    parser.add_argument("--test", action="store_true", help="Connectivity / assume-role check (exit 0/1)")
    args = parser.parse_args()
    if args.test:
        raise SystemExit(run_aws_connectivity_check())
    try:
        run_aws_scan(max_workers=args.max_workers, regions=args.regions)
    except RuntimeError:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
