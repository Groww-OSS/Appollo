import json
import os
import re
import subprocess
import tempfile
import concurrent.futures
from datetime import datetime
from typing import Optional

import requests
import urllib3
from rich import print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 10

_SESSION_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
}

# (path, content_verifier) — verifier takes bytes, returns bool
# Verifying content (not just status code) is the core FP-reduction mechanism.
SENSITIVE_FILES = [
    (".git/HEAD",         lambda b: b.startswith(b"ref: refs/")),
    (".git/config",       lambda b: b"[core]" in b),
    (".env",              lambda b: (
                              b"DB_PASSWORD" in b or b"SECRET_KEY" in b or b"API_KEY" in b
                              or len(re.findall(rb"^[A-Z][A-Z0-9_]+=", b, re.MULTILINE)) >= 3
                          )),
    (".htpasswd",         lambda b: bool(re.search(rb"[^:\s]+:\$(?:apr1|2y|1)\$", b))),
    (".DS_Store",         lambda b: len(b) > 8 and b[4:8] == b"Bud1"),
    ("wp-config.php.bak", lambda b: b"DB_NAME" in b or b"DB_PASSWORD" in b),
    ("config.php.bak",    lambda b: b"DB_" in b or b"password" in b.lower()),
    ("phpinfo.php",       lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("server-status",     lambda b: b"Apache Status" in b or b"Apache Server Status" in b),
    ("backup.sql",        lambda b: b"INSERT INTO" in b or b"CREATE TABLE" in b),
    ("dump.sql",          lambda b: b"INSERT INTO" in b or b"CREATE TABLE" in b),
    ("actuator/env",      lambda b: b"propertySources" in b or b"activeProfiles" in b),
    ("actuator/health",   lambda b: b'"status"' in b and (b'"UP"' in b or b'"DOWN"' in b)),
]

_FILE_SEVERITY = {
    ".git/HEAD": "critical", ".git/config": "critical",
    ".env": "critical", ".htpasswd": "critical",
    "wp-config.php.bak": "critical", "backup.sql": "critical", "dump.sql": "critical",
    "config.php.bak": "high", "phpinfo.php": "high", "actuator/env": "high",
    "server-status": "info", ".DS_Store": "info", "actuator/health": "info",
}

OPEN_REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "goto",
    "dest", "destination", "redirect_uri", "redirect_url", "continue", "target",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login", "/admin/dashboard",
    "/manager/html", "/console", "/panel", "/backend", "/wp-admin",
    "/wp-login.php", "/_admin", "/management", "/controlpanel",
    "/phpmyadmin", "/pma",
]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/query", "/gql", "/v1/graphql"]
_GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'

_DEBUG_PATHS = [
    ("/debug/vars",            "high",     lambda b: b"cmdline" in b or b"memstats" in b),
    ("/debug/pprof/",          "high",     lambda b: b"goroutine" in b or b"profile" in b),
    ("/actuator/beans",        "high",     lambda b: b"beans" in b and b"scope" in b),
    ("/actuator/mappings",     "high",     lambda b: b"mappings" in b or b"requestMappings" in b),
    ("/actuator/httptrace",    "high",     lambda b: b"traces" in b or b"timeTaken" in b),
    ("/actuator/loggers",      "medium",   lambda b: b"loggers" in b or b"configuredLevel" in b),
    ("/metrics",               "medium",   lambda b: b"# HELP" in b or b"# TYPE" in b),
    ("/actuator/prometheus",   "medium",   lambda b: b"# HELP" in b or b"# TYPE" in b),
    ("/api/v1/namespaces",     "critical", lambda b: b"namespaces" in b and b"items" in b),
    # Version/info disclosure — Kubernetes API server, Spring Boot, Go services, etc.
    ("/version",               "high",     lambda b: (b"gitVersion" in b or b"major" in b or b"buildDate" in b
                                                       or b'"version"' in b) and b"{" in b),
    ("/api/version",           "high",     lambda b: b'"version"' in b and b"{" in b),
    ("/actuator/info",         "medium",   lambda b: b'"' in b and b"{" in b and len(b) > 10),
    ("/info",                  "medium",   lambda b: b'"version"' in b or b'"build"' in b or b'"git"' in b),
    ("/api/v1",                "high",     lambda b: b"APIVersions" in b or (b'"versions"' in b and b"items" in b)),
    ("/swagger.json",          "medium",   lambda b: b'"swagger"' in b or b'"openapi"' in b),
    ("/openapi.json",          "medium",   lambda b: b'"openapi"' in b),
    ("/swagger-ui.html",       "medium",   lambda b: b"swagger" in b.lower()),
    ("/api-docs",              "medium",   lambda b: b'"swagger"' in b or b'"openapi"' in b),
]

_CORS_PROBE_ORIGIN  = "https://dast-probe.invalid"
_REDIRECT_PROBE_URL = "https://dast-redirect-probe.invalid"

# ── Nuclei integration ───────────────────────────────────────────────────────

# Always-on: high-signal, low-FP base tags regardless of tech stack
NUCLEI_BASE_TAGS = [
    "exposure", "config", "panel", "default-login", "misconfig",
]

# Tags to always exclude — primary sources of noise / FPs
NUCLEI_EXCLUDE_TAGS = "dos,fuzz,intrusive,fuzzing,brute-force"

# Normalised tech name → nuclei tag(s).
# Nuclei templates fingerprint their own target before running, so adding a tag
# for a tech that isn't present on a host won't produce false positives.
TECH_TAG_MAP: dict[str, list[str]] = {
    "wordpress":   ["wordpress"],
    "drupal":      ["drupal"],
    "joomla":      ["joomla"],
    "nginx":       ["nginx"],
    "apache":      ["apache"],
    "iis":         ["iis"],
    "tomcat":      ["tomcat"],
    "jenkins":     ["jenkins"],
    "gitlab":      ["gitlab"],
    "grafana":     ["grafana"],
    "confluence":  ["confluence", "atlassian"],
    "jira":        ["jira", "atlassian"],
    "kubernetes":  ["kubernetes", "k8s"],
    "spring":      ["spring"],
    "springboot":  ["spring"],
    "laravel":     ["laravel"],
    "php":         ["php"],
    "elastic":     ["elasticsearch", "elastic"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "mongodb":     ["mongodb"],
    "redis":       ["redis"],
    "graphql":     ["graphql"],
    "swagger":     ["swagger"],
    "openapi":     ["swagger"],
    "struts":      ["struts"],
    "coldfusion":  ["coldfusion"],
    "sharepoint":  ["sharepoint"],
    "zimbra":      ["zimbra"],
    "nextcloud":   ["nextcloud"],
    "moodle":      ["moodle"],
    "magento":     ["magento"],
    "shopify":     ["shopify"],
}

NUCLEI_BATCH_TIMEOUT = 1800  # 30 min for a full inventory batch


def _normalize_tech(name: str) -> str:
    """Lowercase, strip spaces/dashes/dots for TECH_TAG_MAP lookup."""
    return re.sub(r"[\s\-\.]", "", name.lower())


def _collect_nuclei_tags(tech_map: dict) -> list[str]:
    """Build the deduplicated tag list from all detected techs across all targets."""
    tags = set(NUCLEI_BASE_TAGS)
    for tech_names in tech_map.values():
        for name in (tech_names or []):
            norm = _normalize_tech(name)
            for key, extra_tags in TECH_TAG_MAP.items():
                if key in norm or norm in key:
                    tags.update(extra_tags)
    return sorted(tags)


def _extract_hostname(host: str) -> str:
    """Strip scheme and path from nuclei's host field to get bare hostname."""
    for scheme in ("https://", "http://"):
        if host.startswith(scheme):
            host = host[len(scheme):]
    return host.split("/")[0].split(":")[0]


def _nuclei_result_to_finding(r: dict, target: str) -> dict:
    info        = r.get("info", {})
    severity    = info.get("severity", "info").lower()
    name        = info.get("name", "unknown")
    template_id = r.get("template-id", "unknown")
    matched_at  = r.get("matched-at", f"https://{target}")

    evidence_parts = []
    if r.get("matcher-name"):
        evidence_parts.append(f"matcher: {r['matcher-name']}")
    extracted = r.get("extracted-results") or []
    if extracted:
        evidence_parts.append(f"extracted: {', '.join(str(e) for e in extracted[:3])}")
    curl = r.get("curl-command", "")
    if curl:
        evidence_parts.append(f"curl: {curl[:200]}")

    return {
        "check":     f"nuclei:{template_id}",
        "severity":  severity,
        "target":    target,
        "url":       matched_at,
        "detail":    name,
        "evidence":  " | ".join(evidence_parts)[:500],
        "timestamp": datetime.utcnow().isoformat(),
        "source":    "nuclei",
    }


def _run_nuclei_batch(targets: list, template_path: str = None) -> dict:
    """
    Run nuclei once across all targets using a targets list file.
    Uses -as (automatic scan) so nuclei fingerprints each target and selects
    relevant templates itself — same behaviour as the per-target nuclei.py but
    batched into a single subprocess for the whole inventory.
    Returns {hostname: [raw_nuclei_results]}.
    """
    if not targets:
        return {}

    targets_set = set(targets)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for t in targets:
            f.write((t if t.startswith("http") else f"https://{t}") + "\n")
        targets_file = f.name

    cmd = [
        "nuclei", "-nc", "-j",
        "-list",    targets_file,
        "-as",                        # automatic scan: nuclei detects tech and picks templates
        "-nm",                        # no metadata noise in output
        "-etags",   NUCLEI_EXCLUDE_TAGS,
        "-rl",      "150",
        "-c",       "25",
        "-retries", "2",
        "-timeout", "5",
        "-s",       "critical,high,medium,low",
    ]
    if template_path:
        cmd += ["-t", template_path]

    results: dict[str, list] = {}
    try:
        print(f"[bold blue][+] Nuclei batch: {len(targets)} targets[/bold blue]")
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=NUCLEI_BATCH_TIMEOUT,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                host = _extract_hostname(r.get("host", ""))
                if host in targets_set:
                    results.setdefault(host, []).append(r)
            except json.JSONDecodeError:
                continue

        total = sum(len(v) for v in results.values())
        print(f"[bold green][+] Nuclei batch done — {total} findings across {len(results)} targets[/bold green]")

    except subprocess.TimeoutExpired:
        print(f"[bold red][-] Nuclei batch timed out after {NUCLEI_BATCH_TIMEOUT}s[/bold red]")
    except FileNotFoundError:
        print("[bold red][-] nuclei not found in PATH — skipping nuclei checks[/bold red]")
    except Exception as e:
        print(f"[bold red][-] Nuclei batch error: {e}[/bold red]")
    finally:
        try:
            os.unlink(targets_file)
        except Exception:
            pass

    return results


# ── Native DAST scanner ─────────────────────────────────────────────────────

def _base_url(target: str) -> str:
    target = target.strip().rstrip("/")
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(_SESSION_HEADERS)
    s.verify = False  # nosemgrep: python.requests.security.disabled-cert-validation — intentional: DAST probes arbitrary targets for TLS misconfiguration
    return s


class DastScanner:
    def __init__(self, target: str):
        self.target   = target
        self.base_url = _base_url(target)
        self.session  = _make_session()

    def _finding(self, check: str, severity: str, detail: str,
                 url: str, evidence: str = "") -> dict:
        return {
            "check":     check,
            "severity":  severity,
            "target":    self.target,
            "url":       url,
            "detail":    detail,
            "evidence":  evidence[:500] if evidence else "",
            "timestamp": datetime.utcnow().isoformat(),
            "source":    "dast",
        }

    def _get(self, path: str = "", allow_redirects: bool = True,
             extra_headers: dict = None) -> Optional[requests.Response]:
        url = f"{self.base_url}/{path.lstrip('/')}" if path else self.base_url
        try:
            return self.session.get(
                url, timeout=REQUEST_TIMEOUT,
                allow_redirects=allow_redirects,
                headers=extra_headers or {},
            )
        except Exception:
            return None

    def _is_alive(self) -> bool:
        if self._get() is not None:
            return True
        # base_url defaults to https:// — many bare IPs discovered via port
        # scan only serve plain HTTP, so fall back before declaring dead.
        if self.base_url.startswith("https://"):
            self.base_url = "http://" + self.base_url[len("https://"):]
            return self._get() is not None
        return False

    # ── Checks ──────────────────────────────────────────────────────

    def check_security_headers(self) -> list:
        findings = []
        r = self._get()
        if not r:
            return findings

        h        = {k.lower(): v for k, v in r.headers.items()}
        url      = r.url
        is_https = url.startswith("https://")

        # Header checks are hardening gaps, not directly exploitable — all "info".
        # They will be stored but won't surface in the vulnerabilities dashboard
        # (which only shows medium+) and won't create Jira tickets.
        checks = [
            (
                "strict-transport-security", "missing_hsts", "info",
                "Strict-Transport-Security header missing."
                if is_https else None,
            ),
            (
                "x-frame-options", "missing_x_frame_options", "info",
                "X-Frame-Options header missing.",
            ),
            (
                "x-content-type-options", "missing_x_content_type_options", "info",
                "X-Content-Type-Options header missing.",
            ),
            (
                "referrer-policy", "missing_referrer_policy", "info",
                "Referrer-Policy header missing.",
            ),
        ]

        for header, check_id, severity, message in checks:
            if message is None:
                continue
            if header not in h:
                findings.append(self._finding(check_id, severity, message, url))

        # CSP can live in HTTP header OR <meta http-equiv="Content-Security-Policy">
        if "content-security-policy" not in h:
            has_meta_csp = bool(re.search(
                r'<meta[^>]+http-equiv=["\']content-security-policy["\']',
                r.text.lower(),
            ))
            if not has_meta_csp:
                findings.append(self._finding(
                    "missing_csp", "info",
                    "Content-Security-Policy not set via header or meta tag.",
                    url,
                ))

        return findings

    def check_exposed_files(self) -> list:
        findings = []
        for path, verify_fn in SENSITIVE_FILES:
            url = f"{self.base_url}/{path}"
            try:
                r = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                if r.status_code == 200 and verify_fn(r.content):
                    findings.append(self._finding(
                        "exposed_file",
                        _FILE_SEVERITY.get(path, "high"),
                        f"Sensitive file accessible: /{path}",
                        url,
                        r.text[:300],
                    ))
            except Exception:
                continue
        return findings

    def check_cors(self) -> list:
        findings = []
        try:
            r = self.session.get(
                self.base_url, timeout=REQUEST_TIMEOUT,
                headers={"Origin": _CORS_PROBE_ORIGIN},
                allow_redirects=True,
            )
        except Exception:
            return findings

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if acao == _CORS_PROBE_ORIGIN:
            severity = "high" if acac == "true" else "medium"
            findings.append(self._finding(
                "cors_arbitrary_origin_reflected", severity,
                f"CORS: arbitrary Origin reflected{' with credentials' if acac == 'true' else ''}.",
                self.base_url,
                f"ACAO: {acao} | ACAC: {acac}",
            ))
        return findings

    def check_info_disclosure(self) -> list:
        findings = []
        r = self._get()
        if not r:
            return findings

        server = r.headers.get("Server", "")
        if re.search(r"\d+\.\d+", server):
            findings.append(self._finding(
                "server_version_disclosure", "info",
                f"Server header discloses version: {server}", r.url, server,
            ))

        powered_by = r.headers.get("X-Powered-By", "")
        if powered_by:
            findings.append(self._finding(
                "x_powered_by_disclosure", "info",
                f"X-Powered-By present: {powered_by}", r.url, powered_by,
            ))

        for hdr in ("X-AspNet-Version", "X-AspNetMvc-Version"):
            val = r.headers.get(hdr, "")
            if val:
                findings.append(self._finding(
                    "aspnet_version_disclosure", "info",
                    f"{hdr} discloses version: {val}", r.url, val,
                ))

        error_r = self._get("/dast-probe-nonexistent-path-8472")
        if error_r and error_r.status_code in (404, 500):
            body = error_r.text.lower()
            for signal in [
                "traceback (most recent call last)", "stack trace:",
                "at java.", "exception in thread", "syntaxerror:",
                "fatal error:", "parse error:",
            ]:
                if signal in body:
                    findings.append(self._finding(
                        "error_page_stack_trace", "medium",
                        "Error page leaks stack trace or framework internals.",
                        error_r.url, error_r.text[:400],
                    ))
                    break

        return findings

    def check_open_redirect(self) -> list:
        findings = []
        for param in OPEN_REDIRECT_PARAMS:
            url = f"{self.base_url}/?{param}={_REDIRECT_PROBE_URL}"
            try:
                r = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location", "")
                    if _REDIRECT_PROBE_URL in location:
                        findings.append(self._finding(
                            "open_redirect", "medium",
                            f"Open redirect via ?{param}= parameter.",
                            url, f"Location: {location}",
                        ))
                        break
            except Exception:
                continue
        return findings

    def check_http_redirect(self) -> list:
        findings = []
        http_url = self.base_url.replace("https://", "http://", 1)
        if http_url == self.base_url:
            return findings
        try:
            r = self.session.get(http_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if r.status_code not in (301, 302, 307, 308):
                findings.append(self._finding(
                    "no_https_redirect", "info",
                    "HTTP does not redirect to HTTPS.",
                    http_url, f"HTTP status: {r.status_code}",
                ))
            else:
                location = r.headers.get("Location", "")
                if not location.startswith("https://"):
                    findings.append(self._finding(
                        "http_redirect_not_https", "info",
                        f"HTTP redirect target is not HTTPS: {location}",
                        http_url, f"Location: {location}",
                    ))
        except Exception:
            pass
        return findings

    def check_admin_panels(self) -> list:
        findings = []
        for path in ADMIN_PATHS:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                if r.status_code == 200:
                    body = r.text.lower()
                    if any(sig in body for sig in [
                        "admin", "dashboard", "management", "control panel",
                        "sign in", "login", "username", "password", "logout",
                    ]):
                        findings.append(self._finding(
                            "exposed_admin_panel", "high",
                            f"Admin panel reachable without authentication: {path}",
                            url, f"HTTP 200, {len(r.text)} bytes",
                        ))
                        break
            except Exception:
                continue
        return findings

    def check_graphql(self) -> list:
        findings = []
        for path in GRAPHQL_PATHS:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.post(
                    url, data=_GRAPHQL_INTROSPECTION,
                    headers={"Content-Type": "application/json"},
                    timeout=REQUEST_TIMEOUT, allow_redirects=False,
                )
                if r.status_code == 200:
                    try:
                        data = r.json()
                        schema = data.get("data", {}).get("__schema", {})
                        if schema and "types" in schema:
                            type_count = len(schema["types"])
                            findings.append(self._finding(
                                "graphql_introspection_enabled", "medium",
                                "GraphQL introspection publicly enabled — full schema exposed.",
                                url, f"{type_count} types in schema",
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                continue
        return findings

    def check_debug_endpoints(self) -> list:
        findings = []
        for path, severity, verify_fn in _DEBUG_PATHS:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                if r.status_code == 200 and verify_fn(r.content):
                    findings.append(self._finding(
                        "exposed_debug_endpoint", severity,
                        f"Unauthenticated debug/metrics endpoint exposed: {path}",
                        url, r.text[:300],
                    ))
            except Exception:
                continue
        return findings

    def scan(self) -> list:
        if not self._is_alive():
            print(f"[bold yellow][~] DAST: {self.target} unreachable, skipping[/bold yellow]")
            return []

        print(f"[bold blue][+] DAST scanning {self.target}[/bold blue]")

        findings = []
        for check_fn in [
            self.check_security_headers,
            self.check_exposed_files,
            self.check_cors,
            self.check_info_disclosure,
            self.check_open_redirect,
            self.check_http_redirect,
            self.check_admin_panels,
            self.check_graphql,
            self.check_debug_endpoints,
        ]:
            try:
                findings.extend(check_fn())
            except Exception as e:
                print(f"[bold red][-] DAST {check_fn.__name__} failed for {self.target}: {e}[/bold red]")

        actionable = [f for f in findings if f["severity"] in ("critical", "high", "medium")]
        print(
            f"[bold green][+] DAST {self.target}: {len(findings)} findings "
            f"({len(actionable)} actionable)[/bold green]"
        )
        return findings


# ── Orchestrator ────────────────────────────────────────────────────────────

def run_dast(targets: list, tech_map: dict = None,
             template_path: str = None, max_workers: int = 10) -> dict:
    """
    Run native DAST checks + nuclei batch across all targets.

    Args:
        targets:       list of hostnames to scan
        tech_map:      {hostname: [tech_name, ...]} from MongoDB tech scan
        template_path: optional nuclei -t override (uses tags if None)
        max_workers:   concurrency for native checks

    Returns:
        {hostname: [finding_dict, ...]}
    """
    tech_map = tech_map or {}

    # 1. Native DAST checks — run concurrently per target
    native_results: dict[str, list] = {}
    alive_targets: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(DastScanner(t).scan): t for t in targets}
        for f in concurrent.futures.as_completed(futs):
            t = futs[f]
            try:
                findings = f.result() or []
                native_results[t] = findings
                if findings is not None:   # target responded (even if 0 findings)
                    alive_targets.append(t)
            except Exception as e:
                print(f"[bold red][-] DAST native checks failed for {t}: {e}[/bold red]")
                native_results[t] = []

    # 2. Nuclei batch — one subprocess for all live targets
    nuclei_raw = _run_nuclei_batch(alive_targets, template_path)

    # 3. Merge: convert nuclei raw results and append to per-target findings
    results: dict[str, list] = {}
    for t in targets:
        findings = list(native_results.get(t, []))
        for raw in nuclei_raw.get(t, []):
            findings.append(_nuclei_result_to_finding(raw, t))
        results[t] = findings

    return results
