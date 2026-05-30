"""Function configuration security checks (A.1-A.7).

Checks runtime status, timeout, environment variable secrets,
ephemeral storage, external layers, X-Ray tracing, and
dead letter queue configuration.
"""

import logging
import re
from typing import Dict, List

from .base import BaseChecker


logger = logging.getLogger("lambda_security_scanner")

# A.1 — Runtime classification lists.
# Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
# Classification rule: block-function-update date has already passed.
# Verified 2026-05-30 against the live AWS runtimes page. AWS has extended
# the "block function update" date to 2027-03-03 for the modern legacy
# runtimes (nodejs14-20, python3.7-3.9, dotnet6, java8, go1.x, provided,
# ruby2.7, ruby3.2), so those are DEPRECATED (still updatable), not blocked.
# Only runtimes whose block-update date has actually passed are BLOCKED.
# This boundary is AWS-policy dependent and shifts over time; re-verify
# against the runtimes page each release. test_function_config locks the
# current mapping so any change is deliberate.
BLOCKED_RUNTIMES = {
    "nodejs",           # Block update: Oct 31, 2016
    "nodejs4.3",        # Block update: Mar 5, 2020
    "nodejs4.3-edge",   # Block update: Apr 30, 2019
    "nodejs6.10",       # Block update: Aug 12, 2019
    "nodejs8.10",       # Block update: Mar 6, 2020
    "nodejs10.x",       # Block update: Feb 14, 2022
    "nodejs12.x",       # Block update: Apr 30, 2023
    "python2.7",        # Block update: May 30, 2022
    "python3.6",        # Block update: Aug 29, 2022
    "dotnetcore1.0",    # Block update: Jul 30, 2019
    "dotnetcore2.0",    # Block update: May 30, 2019
    "dotnetcore2.1",    # Block update: Apr 13, 2022
    "dotnetcore3.1",    # Block update: May 3, 2023
    "dotnet5.0",        # Container only, deprecated May 10, 2022
    "dotnet7",          # Container only, deprecated May 14, 2024
    "ruby2.5",          # Block update: Mar 31, 2022
}

# Deprecated runtimes: past deprecation date, but block-function-update
# has NOT yet been enforced (AWS extended block-update to 2027-03-03
# for most legacy runtimes). Function still updatable today.
DEPRECATED_RUNTIMES = {
    "nodejs14.x",       # Deprecated: Dec 4, 2023 (block update: Mar 3, 2027)
    "nodejs16.x",       # Deprecated: Jun 12, 2024
    "nodejs18.x",       # Deprecated: Sep 1, 2025
    "nodejs20.x",       # Deprecated: Apr 30, 2026
    "python3.7",        # Deprecated: Dec 4, 2023
    "python3.8",        # Deprecated: Oct 14, 2024
    "python3.9",        # Deprecated: Dec 15, 2025
    "dotnet6",          # Deprecated: Dec 20, 2024
    "java8",            # AL1; deprecated: Jan 8, 2024
    "go1.x",            # Deprecated: Jan 8, 2024
    "provided",         # Deprecated: Jan 8, 2024
    "ruby2.7",          # Deprecated: Dec 7, 2023
    "ruby3.2",          # Deprecated: Mar 31, 2026
}

# Near-EOL runtimes (supported today, deprecate within ~12 months).
# Values are official AWS deprecation dates.
NEAR_EOL_RUNTIMES = {
    "provided.al2": "2026-07-31",
    "python3.10": "2026-10-31",
    "dotnet8": "2026-11-10",
    "ruby3.3": "2027-03-31",
    "nodejs22.x": "2027-04-30",
}

# A.3 — Secret detection patterns
SECRET_NAME_PATTERNS = [
    re.compile(r"(?i)password"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)api_?key"),
    re.compile(r"(?i)auth_?token"),
    re.compile(r"(?i)access_?key"),
    re.compile(r"(?i)private_?key"),
    re.compile(r"(?i)database_?url"),
    re.compile(r"(?i)connection_?string"),
    re.compile(r"(?i)credentials"),
    re.compile(r"(?i)token"),
]

SECRET_VALUE_PATTERNS = [
    (
        "AWS_ACCESS_KEY",
        re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ),
    (
        "GITHUB_TOKEN",
        re.compile(r"ghp_[a-zA-Z0-9]{36,}"),
    ),
    (
        "GITHUB_PAT",
        re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
    ),
    (
        "GITLAB_TOKEN",
        re.compile(r"glpat-[a-zA-Z0-9\-]{20,}"),
    ),
    (
        "STRIPE_KEY",
        re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
    ),
    (
        "STRIPE_RESTRICTED_KEY",
        re.compile(r"rk_live_[a-zA-Z0-9]{24,}"),
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"xox[bpors]-[a-zA-Z0-9\-]+"),
    ),
    (
        "SLACK_APP_TOKEN",
        re.compile(r"xapp-[0-9]-[a-zA-Z0-9]+"),
    ),
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+"
            r"|OPENSSH\s+)?PRIVATE\s+KEY-----"
        ),
    ),
    (
        "CONNECTION_STRING",
        re.compile(
            r"(?:mongodb|postgres|mysql|redis|amqp|mssql)"
            r"(?:\+\w+)?://[^:]+:[^@]+@",
            re.IGNORECASE,
        ),
    ),
    (
        "ANTHROPIC_KEY",
        re.compile(r"sk-ant-[a-zA-Z0-9\-]{40,}"),
    ),
    (
        "OPENAI_KEY_PROJECT",
        re.compile(r"sk-proj-[a-zA-Z0-9_\-]{48,}"),
    ),
    (
        "OPENAI_KEY_SVCACCT",
        re.compile(r"sk-svcacct-[a-zA-Z0-9_\-]{48,}"),
    ),
    (
        "OPENAI_KEY",
        re.compile(r"sk-[a-zA-Z0-9]{48,}"),
    ),
    (
        "SENDGRID_KEY",
        re.compile(
            r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"
        ),
    ),
    (
        "NPM_TOKEN",
        re.compile(r"npm_[a-zA-Z0-9]{36,}"),
    ),
]

# Values that mean the env var holds a *reference* to a secret store
# (the AWS-recommended pattern), not a plaintext secret. A secret-looking
# variable NAME pointing at one of these must NOT be flagged.
SAFE_REFERENCE_PATTERNS = [
    re.compile(r"^arn:aws[\w\-]*:secretsmanager:", re.IGNORECASE),
    re.compile(r"^arn:aws[\w\-]*:ssm:", re.IGNORECASE),
    re.compile(r"^arn:aws[\w\-]*:kms:", re.IGNORECASE),
    # CloudFormation dynamic reference
    re.compile(r"^\{\{resolve:(?:secretsmanager|ssm)", re.IGNORECASE),
    # SSM Parameter Store style path, e.g. /myapp/db/password
    re.compile(r"^/[\w./\-]+$"),
]

# Obviously non-secret values: config flags, environment names, ports.
_NON_SECRET_LITERALS = {
    "true", "false", "yes", "no", "none", "null", "enabled", "disabled",
    "prod", "production", "dev", "development", "staging", "test", "local",
}


def _is_safe_reference(value: str) -> bool:
    """True if the value references a managed secret store, not a secret."""
    return any(p.search(value) for p in SAFE_REFERENCE_PATTERNS)


def _is_trivial_value(value: str) -> bool:
    """True if the value is too simple to be a real secret (flag, port...)."""
    v = value.strip()
    if len(v) <= 4:
        return True
    if v.lower() in _NON_SECRET_LITERALS:
        return True
    try:
        float(v)  # ports, TTLs, sizes
        return True
    except ValueError:
        return False


class FunctionConfigChecker(BaseChecker):
    """Security checks for Lambda function configuration.

    Implements checks A.1 through A.7 from the Lambda
    scanner design specification. All checks operate on the
    function configuration dict returned by list_functions;
    no additional API calls are needed.
    """

    def check_runtime(
        self,
        function_config: Dict,
        account_id: str = None,
    ) -> Dict:
        """A.1 — Check for deprecated or end-of-life runtime.

        Args:
            function_config: Lambda function configuration dict
            account_id: AWS account ID (unused, reserved)

        Returns:
            Dict with runtime, package_type, status, eol_date
        """
        package_type = function_config.get(
            "PackageType", "Zip"
        )
        runtime = function_config.get("Runtime", "")

        if package_type == "Image":
            return {
                "runtime": None,
                "package_type": package_type,
                "status": "supported",
                "eol_date": None,
            }

        if runtime in BLOCKED_RUNTIMES:
            status = "blocked"
            eol_date = None
        elif runtime in DEPRECATED_RUNTIMES:
            status = "deprecated"
            eol_date = None
        elif runtime in NEAR_EOL_RUNTIMES:
            status = "near_eol"
            eol_date = NEAR_EOL_RUNTIMES[runtime]
        else:
            status = "supported"
            eol_date = None

        return {
            "runtime": runtime,
            "package_type": package_type,
            "status": status,
            "eol_date": eol_date,
        }

    def check_timeout(self, function_config: Dict) -> Dict:
        """A.2 — Check for maximum timeout setting.

        Args:
            function_config: Lambda function configuration dict

        Returns:
            Dict with timeout_seconds, is_max_timeout
        """
        timeout = function_config.get("Timeout", 3)
        return {
            "timeout_seconds": timeout,
            "is_max_timeout": timeout >= 900,
        }

    def check_environment_secrets(
        self, function_config: Dict
    ) -> Dict:
        """A.3 — Scan environment variables for secrets.

        Checks both variable names (against known secret
        patterns) and values (against known credential
        formats).

        Args:
            function_config: Lambda function configuration dict

        Returns:
            Dict with has_env_vars, env_var_count,
            has_secrets, secret_names, secret_values,
            kms_key_arn, has_kms_key
        """
        env = function_config.get("Environment", {})
        variables = env.get("Variables", {})
        kms_key_arn = function_config.get(
            "KMSKeyArn", None
        )

        secret_names: List[str] = []
        secret_values: List[Dict] = []

        for name, value in variables.items():
            value_str = str(value)

            # 1. A value matching a known credential format is a definitive
            #    plaintext secret regardless of the variable name.
            matched_value = None
            for label, pattern in SECRET_VALUE_PATTERNS:
                if pattern.search(value_str):
                    matched_value = label
                    break
            if matched_value:
                secret_values.append(
                    {"name": name, "type": matched_value}
                )
                if name not in secret_names:
                    secret_names.append(name)
                continue

            # 2. A secret-looking variable NAME is only a finding when the
            #    value is not a managed-secret reference (Secrets Manager /
            #    SSM / KMS) and not a trivial config value. This avoids
            #    flagging the AWS-recommended pattern of storing an ARN or
            #    parameter path in an env var.
            if any(p.search(name) for p in SECRET_NAME_PATTERNS):
                if _is_safe_reference(value_str) or _is_trivial_value(
                    value_str
                ):
                    continue
                if name not in secret_names:
                    secret_names.append(name)

        return {
            "has_env_vars": len(variables) > 0,
            "env_var_count": len(variables),
            "has_secrets": len(secret_names) > 0,
            "secret_names": secret_names,
            "secret_values": secret_values,
            "kms_key_arn": kms_key_arn,
            "has_kms_key": kms_key_arn is not None,
        }

    def check_ephemeral_storage(
        self, function_config: Dict
    ) -> Dict:
        """A.4 — Check for large ephemeral storage.

        Args:
            function_config: Lambda function configuration dict

        Returns:
            Dict with size_mb, is_large
        """
        ephemeral = function_config.get(
            "EphemeralStorage", {}
        )
        size_mb = ephemeral.get("Size", 512)
        return {
            "size_mb": size_mb,
            "is_large": size_mb > 512,
        }

    def check_layers(
        self, function_config: Dict, account_id: str
    ) -> Dict:
        """A.5 — Check for external Lambda layers.

        Flags layers whose account ID differs from the
        scanning account and that are not AWS-managed
        layers (arn:aws:lambda:::awslayer:).

        Args:
            function_config: Lambda function configuration dict
            account_id: AWS account ID of the scanner

        Returns:
            Dict with layer_count, layers,
            has_external_layers, external_layers
        """
        raw_layers = function_config.get("Layers", [])
        layer_arns = [
            layer.get("Arn", "") for layer in raw_layers
        ]
        external_layers: List[str] = []

        for arn in layer_arns:
            # Skip AWS-managed layers
            if ":lambda:::awslayer:" in arn:
                continue

            # Parse account ID from layer ARN
            # Format: arn:aws:lambda:region:account-id:layer:name:version
            parts = arn.split(":")
            if len(parts) >= 5:
                layer_account = parts[4]
                if (
                    layer_account
                    and layer_account != account_id
                ):
                    external_layers.append(arn)

        return {
            "layer_count": len(layer_arns),
            "layers": layer_arns,
            "has_external_layers": len(external_layers) > 0,
            "external_layers": external_layers,
        }

    def check_tracing(self, function_config: Dict) -> Dict:
        """A.6 — Check X-Ray tracing configuration.

        Args:
            function_config: Lambda function configuration dict

        Returns:
            Dict with mode, enabled
        """
        tracing = function_config.get(
            "TracingConfig", {}
        )
        mode = tracing.get("Mode", "PassThrough")
        return {
            "mode": mode,
            "enabled": mode == "Active",
        }

    def check_dead_letter_config(
        self, function_config: Dict
    ) -> Dict:
        """A.7 — Check dead letter queue configuration.

        Args:
            function_config: Lambda function configuration dict

        Returns:
            Dict with configured, target_arn, target_type
        """
        dlc = function_config.get(
            "DeadLetterConfig", {}
        )
        target_arn = dlc.get("TargetArn", None) or None

        target_type = None
        if target_arn:
            if ":sqs:" in target_arn:
                target_type = "SQS"
            elif ":sns:" in target_arn:
                target_type = "SNS"

        return {
            "configured": target_arn is not None,
            "target_arn": target_arn,
            "target_type": target_type,
        }
