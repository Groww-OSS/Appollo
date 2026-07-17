import os
import warnings

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from rich import print


def _get_slack_verify():
    """Determine the SSL verify setting for Slack API calls.

    Checks (in order):
    1. SLACK_CA_BUNDLE  - path to a custom CA PEM bundle
    2. REQUESTS_CA_BUNDLE - global requests CA bundle
    3. SLACK_VERIFY=false - disable verification (corporate proxy workaround)
    4. Default: True (normal verification)
    """
    ca_bundle = os.environ.get("SLACK_CA_BUNDLE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle:
        return ca_bundle
    verify_env = os.environ.get("SLACK_VERIFY", "")
    if verify_env.lower() in ("false", "0", "no"):
        urllib3.disable_warnings(InsecureRequestWarning)
        return False
    return True


def validate_slack_config() -> dict:
    """Validate Slack configuration and return status.
    
    Returns:
        dict: Contains validation results with keys:
            - webhook_ok: bool - WEBHOOK_URL is configured
            - file_upload_ok: bool - SLACK_API_KEY and CHANNEL_ID are configured  
            - errors: list - Any configuration errors found
            - warnings: list - Any configuration warnings
    """
    errors = []
    warnings = []
    
    webhook_url = os.environ.get("WEBHOOK_URL")
    slack_api_key = os.environ.get("SLACK_API_KEY") 
    channel_id = os.environ.get("CHANNEL_ID")
    
    webhook_ok = bool(webhook_url)
    if not webhook_ok:
        warnings.append("WEBHOOK_URL not configured - Slack alerts will be disabled")
        
    file_upload_ok = bool(slack_api_key and channel_id)
    if not file_upload_ok:
        if not slack_api_key:
            warnings.append("SLACK_API_KEY not configured - File uploads to Slack will be disabled")
        if not channel_id:
            warnings.append("CHANNEL_ID not configured - File uploads to Slack will be disabled")
    
    # Additional validation
    if webhook_url and not webhook_url.startswith(('http://', 'https://')):
        errors.append("WEBHOOK_URL must start with http:// or https://")
        
    if slack_api_key and not slack_api_key.startswith('xoxb-'):
        warnings.append("SLACK_API_KEY should start with 'xoxb-' for bot tokens")
    
    return {
        'webhook_ok': webhook_ok,
        'file_upload_ok': file_upload_ok,
        'errors': errors,
        'warnings': warnings,
        'fully_configured': webhook_ok and file_upload_ok and not errors
    }


def print_slack_config_status():
    """Print the current Slack configuration status with colored output."""
    config = validate_slack_config()
    
    print("\n[bold blue]Slack Configuration Status:[/bold blue]")
    print("=" * 40)
    
    # Webhook status
    if config['webhook_ok']:
        print("[bold green]✓[/bold green] Slack Alerts: [green]Enabled[/green]")
    else:
        print("[bold red]✗[/bold red] Slack Alerts: [red]Disabled[/red]")
        
    # File upload status  
    if config['file_upload_ok']:
        print("[bold green]✓[/bold green] File Uploads: [green]Enabled[/green]")
    else:
        print("[bold red]✗[/bold red] File Uploads: [red]Disabled[/red]")
    
    # Print errors
    for error in config['errors']:
        print(f"[bold red]ERROR:[/bold red] {error}")
    
    # Print warnings
    for warning in config['warnings']:
        print(f"[bold yellow]WARNING:[/bold yellow] {warning}")
        
    if config['fully_configured']:
        print("\n[bold green]✓ Slack integration is fully configured and ready![/bold green]")
    else:
        print("\n[bold yellow]⚠  Slack integration is partially configured. See warnings above.[/bold yellow]")
    
    print("=" * 40)


def send_slack_alert(msg: str) -> bool:
    """Post a message to the configured Slack webhook.
    
    Returns:
        bool: True if alert was sent successfully, False otherwise
    """
    url = os.environ.get("WEBHOOK_URL")
    if not url:
        print("[bold red][-] WEBHOOK_URL not set in environment. Skipping Slack alert.[/bold red]")
        print("[bold yellow][!] Set WEBHOOK_URL in your .env file to enable Slack notifications.[/bold yellow]")
        return False

    try:
        verify = _get_slack_verify()
        data = {"text": msg}
        response = requests.post(url, json=data, timeout=10, verify=verify)
        if response.status_code == 200:
            print("[bold green][+] Slack alert sent successfully.[/bold green]")
            return True
        else:
            print(f"[bold red][-] Slack API returned error {response.status_code}: {response.text}[/bold red]")
            return False
    except Exception as e:
        print(f"[bold red][-] Failed to send Slack alert: {e}[/bold red]")
        print("[bold yellow][!] Check your WEBHOOK_URL and network connectivity.[/bold yellow]")
        return False


def upload_file_to_slack(file_path: str, initial_comment: str) -> bool:
    """Upload a file to Slack using the v2 API flow.
    
    Returns:
        bool: True if file was uploaded successfully, False otherwise
    """
    try:
        api_key = os.environ.get("SLACK_API_KEY")
        channel_id = os.environ.get("CHANNEL_ID")

        if not api_key or not channel_id:
            print("[bold red][-] SLACK_API_KEY or CHANNEL_ID not set in environment[/bold red]")
            print("[bold yellow][!] Set SLACK_API_KEY and CHANNEL_ID in your .env file to enable file uploads.[/bold yellow]")
            return False

        if not os.path.exists(file_path):
            print(f"[bold red][-] File not found: {file_path}[/bold red]")
            return False

        verify = _get_slack_verify()
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        header = {"Authorization": f"Bearer {api_key}"}

        # Step 1: Get upload URL
        response = requests.post(
            "https://slack.com/api/files.getUploadURLExternal",
            headers=header,
            data={"filename": file_name, "length": file_size},
            verify=verify,
            timeout=30,
        )
        res_json = response.json()

        if not res_json.get("ok"):
            error_msg = res_json.get("error", "Unknown error")
            print(f"[bold red][-] Slack Step 1 Error: {error_msg}[/bold red]")
            if error_msg == "invalid_auth":
                print("[bold yellow][!] Check your SLACK_API_KEY - it may be invalid or expired.[/bold yellow]")
            return False

        upload_url = res_json.get("upload_url")
        file_id = res_json.get("file_id")

        # Step 2: Upload file
        with open(file_path, 'rb') as f:
            upload_res = requests.post(upload_url, files={'file': f}, verify=verify, timeout=60)
            if upload_res.status_code != 200:
                print(f"[bold red][-] Slack Step 2 Error: Upload failed with status {upload_res.status_code}[/bold red]")
                return False

        # Step 3: Complete upload and share to channel
        complete_data = {
            "files": [{"id": file_id, "title": file_name}],
            "channel_id": channel_id,
            "initial_comment": initial_comment,
        }
        complete_res = requests.post(
            "https://slack.com/api/files.completeUploadExternal",
            headers=header, json=complete_data, verify=verify, timeout=30,
        )
        final_json = complete_res.json()

        if final_json.get("ok"):
            print(f"[bold green]✓ File uploaded and shared to Slack successfully: {file_name}[/bold green]")
            return True
        else:
            error_msg = final_json.get("error", "Unknown error")
            print(f"[bold red][-] Slack Step 3 Error: {error_msg}[/bold red]")
            if error_msg == "channel_not_found":
                print("[bold yellow][!] Check your CHANNEL_ID - the channel may not exist or the bot is not a member.[/bold yellow]")
            return False

    except Exception as e:
        print(f"[bold red][-] Exception during Slack file upload: {e}[/bold red]")
        print("[bold yellow][!] Check your network connectivity and Slack configuration.[/bold yellow]")
        return False
