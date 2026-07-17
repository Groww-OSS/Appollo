"""Backward-compatible facade.

All functionality has been split into focused modules under ``system/``.
This file re-exports every public symbol so that existing imports like
``from system.utils import calculate_hash`` continue to work unchanged.
"""

# ── Hashing / dedup ──────────────────────────────────────────────────
from system.hashing import (          # noqa: F401
    calculate_hash,
    check_if_hash_exists,
    add_hash_to_db,
    clear_hash_database,
    get_hash_database_info,
)

# ── Jira ─────────────────────────────────────────────────────────────
from system.jira_client import (      # noqa: F401
    get_jira_client,
    create_jira_issue,
)

# ── Slack ────────────────────────────────────────────────────────────
from system.slack import (            # noqa: F401
    send_slack_alert,
    upload_file_to_slack,
    validate_slack_config,
    print_slack_config_status,
)

# ── CSV / file helpers ───────────────────────────────────────────────
from system.csv_utils import (        # noqa: F401
    save_wayback_to_csv,
    save_port_scan_to_csv,
    read_from_csv,
    convert_to_csv,
    get_delta_links,
    get_delta_ports,
    write_file,
    read_file,
    file_exists,
)

# ── Network ──────────────────────────────────────────────────────────
from system.network import (          # noqa: F401
    is_private_ip,
)

# ── Targets / delta ──────────────────────────────────────────────────
from system.targets import (          # noqa: F401
    get_all_targets,
    get_delta_records_from_mongo,
    get_delta_dns_records,
)

# Backward compat alias
is_file_exists = file_exists
