"""Utility functions for Lambda Security Scanner."""

import logging
import os
from datetime import datetime
from typing import Any, Dict


def setup_logging(
    output_dir: str,
    log_level: int = logging.INFO,
) -> logging.Logger:
    """Setup logging with console and file handlers."""
    logger = logging.getLogger("lambda_security_scanner")
    logger.setLevel(log_level)
    logger.propagate = False

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    log_file = os.path.join(
        output_dir,
        f'lambda_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


def calculate_security_score(checks: Dict[str, Any]) -> int:
    """Calculate security score from check results.

    Starts at 100 and applies deductions based on findings.
    Mutual-exclusion groups take only the highest penalty.
    """
    score = 100

    def get(check_name, key, default=False):
        check = checks.get(check_name, {})
        if isinstance(check, dict) and "error" not in check:
            return check.get(key, default)
        return default

    # MUTUAL EXCLUSION: A.1 runtime (highest penalty only)
    status = get("runtime", "status", "supported")
    if status == "blocked":
        score -= 15
    elif status == "deprecated":
        score -= 10
    elif status == "near_eol":
        score -= 3

    # MUTUAL EXCLUSION: A.3 secrets
    if get("environment_secrets", "has_secrets"):
        if not get("environment_secrets", "has_kms_key"):
            score -= 20  # CRITICAL: secrets + no KMS
        else:
            score -= 10  # HIGH: secrets + has KMS

    # MUTUAL EXCLUSION: E.1 code signing
    # Skip entirely when not applicable (container image functions —
    # AWS Lambda Code Signing only applies to Zip packages).
    if get("code_signing", "applicable", default=True):
        if not get("code_signing", "configured"):
            score -= 5
        elif not get("code_signing", "is_enforced"):
            score -= 3

    # B.1: Public resource policy
    if get("resource_policy", "is_public"):
        score -= 25

    # B.2: Public function URL
    if get("function_url", "is_public"):
        score -= 25

    # B.4: Execution role overprivilege
    if get("execution_role", "has_full_admin"):
        score -= 20  # CRITICAL: admin-equivalent ("*", Admin/PowerUser)
    elif get("execution_role", "has_wildcard_actions"):
        score -= 10  # HIGH: single-service wildcard (e.g. s3:*)
    elif get("execution_role", "has_privilege_escalation"):
        score -= 10

    # B.3: Function URL CORS allow all origins
    if get("function_url_cors", "allow_all_origins"):
        score -= 10

    # B.5: Shared role
    if get("shared_role", "is_shared"):
        score -= 10

    # A.6: Tracing not enabled (observability hygiene, LOW)
    if not get("tracing", "enabled"):
        score -= 2

    # A.7: Dead letter config not configured (resilience, LOW)
    if not get("dead_letter_config", "configured"):
        score -= 2

    # C.2: Multi-AZ
    if get("multi_az", "applicable") and not get(
        "multi_az", "is_multi_az"
    ):
        score -= 5

    # C.3: Unrestricted egress
    if get("security_groups", "applicable") and get(
        "security_groups", "unrestricted_egress"
    ):
        score -= 5

    # D.1: Log group (max -5 total)
    if not get("log_group", "exists") or not get(
        "log_group", "has_retention"
    ):
        score -= 5

    # D.2: Reserved concurrency (availability hygiene, LOW; the public +
    # no-concurrency combination is penalized separately as CRITICAL)
    if not get("reserved_concurrency", "configured"):
        score -= 2

    # E.2: Event source mappings missing failure destinations
    if get(
        "event_source_mappings", "has_mappings"
    ) and get(
        "event_source_mappings",
        "missing_failure_dest_count",
        0,
    ) > 0:
        score -= 5

    # A.5: External layers
    if get("layers", "has_external_layers"):
        score -= 3

    # C.1: Not in VPC
    if not get("vpc_config", "in_vpc"):
        score -= 3

    # A.2: Max timeout
    if get("timeout", "is_max_timeout"):
        score -= 2

    # A.4: Large ephemeral storage
    if get("ephemeral_storage", "is_large"):
        score -= 2

    return max(0, score)


def get_severity_color(severity: str) -> str:
    """Return Rich color string for a severity level."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
        "ERROR": "magenta",
    }
    return colors.get(severity, "white")


def format_datetime(dt) -> str:
    """Format a datetime object or ISO string to readable UTC."""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(
                dt.replace("Z", "+00:00")
            )
        except ValueError:
            return dt
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(dt)
