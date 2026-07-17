"""
Cloud Storage Exposure Scanner

Checks whether S3 buckets (AWS) and GCS buckets (GCP) are publicly accessible
to anonymous internet users.

AWS  — checks bucket ACL + public access block settings; distinguishes LIST vs READ
GCP  — tests actual anonymous permissions via GCS testIamPermissions REST API

Severity tiers:
  critical — anonymous WRITE (create / delete objects)
  high     — anonymous LIST  (can enumerate all object keys)
  medium   — anonymous READ only (objects readable by URL, not enumerable)

Parallelism:
  - AWS scan and GCS scan run concurrently
  - All AWS accounts scanned concurrently
  - All GCP projects scanned concurrently
  - Per S3 bucket: ACL + policy fetched in parallel; metadata fetched in parallel
  - Per GCS bucket: object count + reachability checked in parallel

Results are saved to MongoDB collection "Prod Cloud Storage Scans".
"""

import concurrent.futures
import json
import os
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime

from rich import print
from rich.console import Console

from system.db import MongoDB

console = Console()

_MAX_WORKERS = int(os.getenv("CLOUD_STORAGE_WORKERS", "20"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list, env_override: dict = None, timeout: int = 30):
    env = {**os.environ, **(env_override or {})}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
        if r.returncode != 0:
            return None
        return json.loads(r.stdout) if r.stdout.strip() else None
    except Exception:
        return None


# ── AWS S3 ────────────────────────────────────────────────────────────────────

def _assume_role_env(account_id: str, pattern: str) -> dict:
    """Assume role for account_id and return env dict with temp creds."""
    role_arn = pattern.format(account_id=account_id)
    data = _run(
        ["aws", "sts", "assume-role", "--role-arn", role_arn,
         "--role-session-name", f"appollo-storage-{account_id}"],
        timeout=30,
    )
    if not data or "Credentials" not in data:
        print(f"[yellow][~] Cloud Storage: AssumeRole failed for {account_id} ({role_arn})[/yellow]")
        return {}
    creds = data["Credentials"]
    return {
        "AWS_ACCESS_KEY_ID":     creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN":     creds["SessionToken"],
    }


def _get_aws_accounts() -> list[dict]:
    """
    Returns list of {id, env} dicts to scan.
    Supports three modes (same as aws.py):
      1. AWS_ACCOUNT_IDS + AWS_ASSUME_ROLE_PATTERN/NAME — assume role into each
      2. Organizations ListAccounts — with current credentials
      3. Current identity only
    """
    assume_pattern = os.getenv("AWS_ASSUME_ROLE_PATTERN", "").strip()
    if not assume_pattern:
        role_name = os.getenv("AWS_ASSUME_ROLE_NAME", "").strip()
        if role_name:
            assume_pattern = f"arn:aws:iam::{{account_id}}:role/{role_name}"

    account_ids_raw = os.getenv("AWS_ACCOUNT_IDS", "").strip()
    if account_ids_raw and assume_pattern:
        ids = [a.strip() for a in account_ids_raw.split(",") if a.strip()]
        accounts = []
        for aid in ids:
            env = _assume_role_env(aid, assume_pattern)
            if env:
                accounts.append({"id": aid, "env": env})
        return accounts

    ok_data = _run(["aws", "organizations", "list-accounts"], timeout=30)
    if ok_data:
        accounts = []
        for a in (ok_data.get("Accounts") or []):
            if a.get("Status") == "ACTIVE":
                aid = a["Id"]
                env = _assume_role_env(aid, assume_pattern) if assume_pattern else {}
                accounts.append({"id": aid, "env": env})
        if accounts:
            return accounts

    data = _run(["aws", "sts", "get-caller-identity"], timeout=15)
    if data:
        return [{"id": data.get("Account", "default"), "env": {}}]
    return []


def _s3_list_buckets(env: dict) -> list[dict]:
    data = _run(["aws", "s3api", "list-buckets", "--query", "Buckets[]"],
                env_override=env, timeout=60)
    return data or []


def _s3_is_public(bucket_name: str, env: dict) -> "dict | None":
    """
    Returns {read, list, write} indicating what anonymous callers can do.

    Fast path: get-public-access-block first (single call). If all 4 flags are
    set the bucket is fully private — skip ACL and policy entirely.
    Otherwise fetch ACL and policy in parallel, then apply the block-flag gates.
    """
    block = _run(["aws", "s3api", "get-public-access-block", "--bucket", bucket_name],
                 env_override=env, timeout=15)
    cfg = block.get("PublicAccessBlockConfiguration", {}) if block else {}

    # All four flags → guaranteed private; skip further API calls
    if all([cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]):
        return None

    # Fetch ACL and policy in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_acl    = ex.submit(_run,
                             ["aws", "s3api", "get-bucket-acl",    "--bucket", bucket_name],
                             env, 15)
        f_policy = ex.submit(_run,
                             ["aws", "s3api", "get-bucket-policy", "--bucket", bucket_name],
                             env, 15)
        acl        = f_acl.result()
        policy_raw = f_policy.result()

    public_read  = False
    public_list  = False
    public_write = False

    # Bucket ACL — READ on a bucket = s3:ListBucket; ignored when IgnorePublicAcls is set
    if acl and not cfg.get("IgnorePublicAcls"):
        for grant in acl.get("Grants", []):
            uri  = grant.get("Grantee", {}).get("URI", "")
            perm = grant.get("Permission", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                if perm == "FULL_CONTROL":
                    public_read = public_list = public_write = True
                elif perm == "READ":
                    public_list = True   # bucket-level READ = ListBucket
                elif perm == "WRITE":
                    public_write = True

    # Bucket policy — ignored when RestrictPublicBuckets is set
    if policy_raw and not cfg.get("RestrictPublicBuckets"):
        try:
            policy = json.loads(policy_raw.get("Policy", "{}"))
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect    = stmt.get("Effect", "")
                actions   = stmt.get("Action", [])
                condition = stmt.get("Condition", {})
                if isinstance(actions, str):
                    actions = [actions]

                if effect != "Allow":
                    continue
                if principal not in ("*", {"AWS": "*"}):
                    continue
                # Conditioned policies aren't truly open to anyone
                if condition:
                    continue

                for action in actions:
                    a = action.lower()
                    if a in ("*", "s3:*"):
                        public_read = public_list = public_write = True
                    elif "s3:listbucket" in a:
                        public_list = True
                    elif "s3:getobject" in a:
                        public_read = True
                    elif any(w in a for w in ("s3:putobject", "s3:deleteobject",
                                               "s3:put*", "s3:delete*")):
                        public_write = True
        except Exception:
            pass

    if not public_read and not public_list and not public_write:
        return None
    return {"read": public_read, "list": public_list, "write": public_write}


def _get_bucket_region(bucket_name: str, env: dict) -> str:
    data = _run(["aws", "s3api", "get-bucket-location", "--bucket", bucket_name],
                env_override=env, timeout=15)
    if not data:
        return "unknown"
    return data.get("LocationConstraint") or "us-east-1"


def _s3_get_versioning(bucket_name: str, env: dict) -> str:
    data = _run(["aws", "s3api", "get-bucket-versioning", "--bucket", bucket_name],
                env_override=env, timeout=15)
    if not data:
        return "Disabled"
    return data.get("Status", "Disabled") or "Disabled"


def _s3_get_encryption(bucket_name: str, env: dict) -> str:
    data = _run(["aws", "s3api", "get-bucket-encryption", "--bucket", bucket_name],
                env_override=env, timeout=15)
    if not data:
        return "none"
    rules = (data.get("ServerSideEncryptionConfiguration") or {}).get("Rules", [])
    if not rules:
        return "none"
    return (rules[0].get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm", "none")


def _s3_object_count(bucket_name: str, env: dict) -> int:
    """Estimate object count (capped at 1000 to keep it fast)."""
    data = _run(
        ["aws", "s3api", "list-objects-v2", "--bucket", bucket_name,
         "--max-items", "1000", "--query", "length(Contents[])"],
        env_override=env, timeout=30,
    )
    if isinstance(data, int):
        return data
    return -1


def _check_reachable(url: str) -> bool:
    """Confirm actual HTTP/S reachability from the internet (HEAD request)."""
    if not url.startswith(("https://", "http://")):
        return False
    try:
        req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
        resp = urllib.request.urlopen(req, timeout=10)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected
        return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def _check_s3(b: dict, env: dict, account_id: str) -> "dict | None":
    """Check one S3 bucket. Called from a thread pool."""
    name = b.get("Name", "")
    if not name:
        return None

    result = _s3_is_public(name, env)
    if result is None:
        return None

    if result["write"]:
        severity = "critical"
    elif result["list"]:
        severity = "high"
    else:
        severity = "medium"

    access = []
    if result["list"]:  access.append("LIST")
    if result["read"]:  access.append("READ")
    if result["write"]: access.append("WRITE")

    bucket_url = f"https://{name}.s3.amazonaws.com"

    # All metadata calls are independent — run them in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_region    = ex.submit(_get_bucket_region,  name, env)
        f_versioning = ex.submit(_s3_get_versioning, name, env)
        f_encryption = ex.submit(_s3_get_encryption, name, env)
        f_obj_count  = ex.submit(_s3_object_count,   name, env)
        f_reachable  = ex.submit(_check_reachable,   bucket_url)
        region     = f_region.result()
        versioning = f_versioning.result()
        encryption = f_encryption.result()
        obj_count  = f_obj_count.result()
        reachable  = f_reachable.result()

    return {
        "provider":      "aws",
        "account":       account_id,
        "bucket":        name,
        "region":        region,
        "url":           bucket_url,
        "public_access": access,
        "severity":      severity,
        "versioning":    versioning,
        "encryption":    encryption,
        "object_count":  obj_count,
        "reachable":     reachable,
    }


def scan_aws_buckets() -> list[dict]:
    """Scan all S3 buckets across all configured AWS accounts — accounts run concurrently."""
    accounts = _get_aws_accounts()
    if not accounts:
        print("[dim][Cloud Storage] AWS: no accounts found or no access[/dim]")
        return []

    def _scan_account(account: dict) -> list[dict]:
        account_id = account["id"]
        env        = account["env"]
        buckets    = _s3_list_buckets(env)
        if not buckets:
            print(f"[dim][Cloud Storage] AWS {account_id}: no buckets found[/dim]")
            return []
        print(f"[bold blue][*] Cloud Storage: AWS {account_id} — checking {len(buckets)} S3 bucket(s)[/bold blue]")
        with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
            return [r for r in ex.map(lambda b: _check_s3(b, env, account_id), buckets) if r]

    findings: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(accounts), _MAX_WORKERS)) as ex:
        for acct_results in ex.map(_scan_account, accounts):
            findings.extend(acct_results)
    return findings


# ── GCP GCS ───────────────────────────────────────────────────────────────────

def _gcs_list_projects() -> list[str]:
    """Return project IDs from GCP_PROJECTS env or gcloud."""
    env_projects = os.getenv("GCP_PROJECTS", "")
    if env_projects:
        return [p.strip() for p in env_projects.split(",") if p.strip()]
    data = _run(["gcloud", "projects", "list", "--format=json"], timeout=60)
    if not data:
        return []
    return [p.get("projectId", "") for p in data if p.get("projectId")]


def _gcs_list_buckets(project_id: str) -> list[str]:
    data = _run(
        ["gcloud", "storage", "buckets", "list", f"--project={project_id}", "--format=json"],
        timeout=60,
    )
    if not data:
        return []
    return [b.get("name", "").lstrip("gs://") for b in data if b.get("name")]


def _gcs_anon_permissions(bucket_name: str) -> "dict | None":
    """
    Test what permissions an anonymous caller actually has on this GCS bucket
    using the GCS testIamPermissions REST API (no credentials required).

    Returns {get, list, write} if any anonymous access exists, else None.
    """
    perms = [
        "storage.objects.get",
        "storage.objects.list",
        "storage.objects.create",
        "storage.objects.delete",
    ]
    qs  = "&".join(f"permissions={urllib.parse.quote(p)}" for p in perms)
    url = (
        "https://storage.googleapis.com/storage/v1/b/"
        + urllib.parse.quote(bucket_name, safe="")
        + "/iam/testPermissions?" + qs
    )
    granted: set = set()
    try:
        if not url.startswith("https://"):
            return None
        req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=10)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected
        data = json.loads(resp.read())
        granted = set(data.get("permissions", []))
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read())
            granted = set(data.get("permissions", []))
        except Exception:
            pass
    except Exception:
        pass

    if not granted:
        return None
    return {
        "get":   "storage.objects.get"    in granted,
        "list":  "storage.objects.list"   in granted,
        "write": bool(granted & {"storage.objects.create", "storage.objects.delete"}),
    }


def _gcs_object_count(bucket_name: str) -> int:
    """Estimate GCS object count (capped at 1000)."""
    data = _run(
        ["gcloud", "storage", "objects", "list", f"gs://{bucket_name}",
         "--format=json", "--limit=1000"],
        timeout=30,
    )
    if isinstance(data, list):
        return len(data)
    return -1


def _check_gcs(name: str, project_id: str) -> "dict | None":
    """Check one GCS bucket. Called from a thread pool."""
    result = _gcs_anon_permissions(name)
    if result is None:
        return None

    if result["write"]:
        severity = "critical"
    elif result["list"]:
        severity = "high"
    else:
        severity = "medium"

    access = []
    if result["list"]:  access.append("LIST")
    if result["get"]:   access.append("READ")
    if result["write"]: access.append("WRITE")

    if not access:
        return None

    bucket_url = f"https://storage.googleapis.com/{name}"

    # object_count (gcloud subprocess) and reachability check run in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_count     = ex.submit(_gcs_object_count, name)
        f_reachable = ex.submit(_check_reachable, bucket_url)
        obj_count = f_count.result()
        reachable = f_reachable.result()

    return {
        "provider":      "gcp",
        "account":       project_id,
        "project":       project_id,
        "bucket":        name,
        "url":           bucket_url,
        "public_access": access,
        "severity":      severity,
        "object_count":  obj_count,
        "reachable":     reachable,
    }


def scan_gcs_buckets() -> list[dict]:
    """Scan all GCS buckets across all configured GCP projects — projects run concurrently."""
    projects = _gcs_list_projects()
    if not projects:
        print("[dim][Cloud Storage] GCP: no projects found or no access[/dim]")
        return []

    def _scan_project(project_id: str) -> list[dict]:
        buckets = _gcs_list_buckets(project_id)
        if not buckets:
            return []
        print(f"[bold blue][*] Cloud Storage: GCP {project_id} — checking {len(buckets)} GCS bucket(s)[/bold blue]")
        with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
            return [r for r in ex.map(lambda n: _check_gcs(n, project_id), buckets) if r]

    findings: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(projects), _MAX_WORKERS)) as ex:
        for proj_results in ex.map(_scan_project, projects):
            findings.extend(proj_results)
    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def _retire_remediated(col, current_buckets: set, provider_filter: str = None):
    """Mark buckets no longer found as public → set status=inactive in DB."""
    query = {"status": {"$ne": "inactive"}}
    if provider_filter:
        query["provider"] = provider_filter
    active = list(col.find(query, {"_id": 1, "bucket": 1}))
    retired = 0
    for doc in active:
        if doc.get("bucket") not in current_buckets:
            col.update_one(
                {"_id": doc["_id"]},
                {"$set": {"status": "inactive", "remediated_at": datetime.now()}},
            )
            retired += 1
    if retired:
        print(f"[bold green][+] Cloud Storage: {retired} bucket(s) marked inactive (no longer public)[/bold green]")


def run_cloud_storage_scan() -> list[dict]:
    """
    Run S3 + GCS public bucket checks concurrently.
    Returns list of finding dicts (already upserted to DB).
    """
    print("[bold blue][*] Cloud Storage Exposure Scan starting...[/bold blue]")

    # AWS and GCS scans run at the same time
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        aws_fut = ex.submit(scan_aws_buckets)
        gcs_fut = ex.submit(scan_gcs_buckets)
        aws_findings = aws_fut.result()
        gcs_findings = gcs_fut.result()

    all_findings = aws_findings + gcs_findings

    db  = MongoDB()
    col = db.set_collection("Prod Cloud Storage Scans")

    for f in all_findings:
        col.update_one(
            {"provider": f["provider"], "bucket": f["bucket"]},
            {"$set": {**f, "status": "active", "last_updated": datetime.now()}},
            upsert=True,
        )

    current_buckets = {f["bucket"] for f in all_findings}
    _retire_remediated(col, current_buckets)

    count = len(all_findings)
    color = "red" if count else "green"
    icon  = "!" if count else "+"
    print(f"[bold {color}][{icon}] Cloud Storage: {count} public bucket(s) found[/bold {color}]")
    return all_findings


def run_s3_inventory_scan() -> list[dict]:
    """
    Lightweight S3-only scan for use inside update_inventory.
    Checks public access on all S3 buckets, upserts findings, and retires
    buckets that are no longer public.
    Returns list of active public bucket findings.
    """
    print("[bold blue][*] Cloud Storage: S3 inventory check starting...[/bold blue]")

    findings = scan_aws_buckets()

    db  = MongoDB()
    col = db.set_collection("Prod Cloud Storage Scans")

    for f in findings:
        col.update_one(
            {"provider": f["provider"], "bucket": f["bucket"]},
            {"$set": {**f, "status": "active", "last_updated": datetime.now()}},
            upsert=True,
        )

    current_buckets = {f["bucket"] for f in findings}
    _retire_remediated(col, current_buckets, provider_filter="aws")

    count = len(findings)
    print(f"[bold {'red' if count else 'green'}][{'!' if count else '+'}] Cloud Storage: {count} public S3 bucket(s)[/bold {'red' if count else 'green'}]")
    return findings
