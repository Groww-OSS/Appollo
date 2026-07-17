import os
import warnings
from typing import Optional

import urllib3
from urllib3.exceptions import InsecureRequestWarning
from jira import JIRA
from rich import print


class _NoopIssue:
    """Placeholder returned when Jira is disabled or unavailable."""
    def __init__(self, key: str = "DISABLED") -> None:
        self.key = key


class _SafeJira:
    """Thin wrapper that silently degrades when the real Jira client is absent."""

    def __init__(self, client=None, reason: Optional[str] = None) -> None:
        self._client = client
        self._reason = reason
        self._printed = False
        self._silent = (
            isinstance(os.environ.get("JIRA_SILENT"), str)
            and os.environ.get("JIRA_SILENT").lower() in ("true", "1", "yes")
        )

    def create_issue(self, fields):
        if self._client is not None:
            return self._client.create_issue(fields=fields)
        if not self._silent and not self._printed:
            print(f"[JIRA disabled] create_issue skipped ({self._reason or 'unavailable'})")
            self._printed = True
        return _NoopIssue()

    def add_attachment(self, issue, attachment):
        if self._client is not None:
            return self._client.add_attachment(issue=issue, attachment=attachment)
        if not self._silent and not self._printed:
            print(f"[JIRA disabled] add_attachment skipped ({self._reason or 'unavailable'})")
            self._printed = True
        return None


def _suppress_insecure_warnings() -> None:
    urllib3.disable_warnings(InsecureRequestWarning)


def _apply_session_settings(client) -> None:
    """Apply proxy and timeout settings to a JIRA client session."""
    http_proxy = os.environ.get("JIRA_HTTP_PROXY") or os.environ.get("HTTP_PROXY")
    https_proxy = os.environ.get("JIRA_HTTPS_PROXY") or os.environ.get("HTTPS_PROXY")
    proxies = {}
    if http_proxy:
        proxies['http'] = http_proxy
    if https_proxy:
        proxies['https'] = https_proxy
    if proxies:
        try:
            client._session.proxies.update(proxies)
        except Exception:
            pass
    try:
        connect_timeout = float(os.environ.get("JIRA_CONNECT_TIMEOUT", "30"))
        read_timeout = float(os.environ.get("JIRA_READ_TIMEOUT", "120"))
        client._session.timeout = (connect_timeout, read_timeout)
    except Exception:
        pass


def get_jira_client() -> _SafeJira:
    """Return a Jira client with corporate TLS support and safe fallbacks.

    Environment variables:
    - JIRA_SERVER: base URL
    - JIRA_USER / JIRA_API_TOKEN: credentials
    - JIRA_CA_BUNDLE: path to PEM CA bundle
    - JIRA_VERIFY: 'false' to disable TLS verification (testing only)
    - JIRA_ENABLED: 'false' to disable Jira entirely
    """
    jira_enabled = os.environ.get("JIRA_ENABLED")
    if isinstance(jira_enabled, str) and jira_enabled.lower() in ("false", "0", "no"):
        class _DisabledJira:
            def create_issue(self, fields):
                return _NoopIssue()
            def add_attachment(self, issue, attachment):
                return None
        return _DisabledJira()

    server = os.environ.get("JIRA_SERVER")
    options = {'server': server}

    ca_bundle = os.environ.get("JIRA_CA_BUNDLE")
    verify_env = os.environ.get("JIRA_VERIFY")
    if ca_bundle:
        options['verify'] = ca_bundle
    elif isinstance(verify_env, str) and verify_env.lower() in ("false", "0", "no"):
        options['verify'] = False
        _suppress_insecure_warnings()

    basic_auth = (os.environ.get("JIRA_USER"), os.environ.get("JIRA_API_TOKEN"))

    try:
        client = JIRA(options, basic_auth=basic_auth)
        _apply_session_settings(client)
        return _SafeJira(client)
    except Exception as e:
        if 'CERTIFICATE_VERIFY_FAILED' in str(e) and 'verify' not in options:
            try:
                options['verify'] = False
                _suppress_insecure_warnings()
                client = JIRA(options, basic_auth=basic_auth)
                _apply_session_settings(client)
                return _SafeJira(client)
            except Exception as e2:
                return _SafeJira(None, reason=str(e2))
        return _SafeJira(None, reason=str(e))


_SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Low",
}


def create_jira_issue(jira_client, project_key: str, summary: str,
                      description: str, issue_type: str = "Bug",
                      label: str = "periodic-scan", severity: str = "high"):
    """Create a Jira issue with severity-mapped priority and severity label."""
    priority = _SEVERITY_TO_PRIORITY.get(severity.lower(), "High")
    labels = [label, f"severity-{severity.lower()}"]
    issue_dict = {
        'project':     {'key': project_key},
        'summary':     summary,
        'description': description,
        'issuetype':   {'name': issue_type},
        'priority':    {'name': priority},
        'labels':      labels,
    }
    return jira_client.create_issue(fields=issue_dict)
