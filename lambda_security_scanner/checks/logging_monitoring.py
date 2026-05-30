"""Logging and monitoring checks for Lambda functions (D.1-D.2)."""

import logging
from typing import Dict

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("lambda_security_scanner")


class LoggingMonitoringChecker(BaseChecker):
    """Check logging and monitoring configuration.

    Implements checks D.1 (log group/retention) and
    D.2 (reserved concurrency).
    """

    def check_log_group(
        self,
        function_name: str,
        region: str,
        function_config: Dict = None,
    ) -> Dict:
        """D.1 - Check CloudWatch log group and retention.

        Respects Lambda Advanced Logging Controls
        (LoggingConfig.LogGroup) when set; otherwise falls back to
        the default ``/aws/lambda/{function_name}`` log group.

        Args:
            function_name: Lambda function name.
            region: AWS region name.
            function_config: Optional Lambda function config dict
                from list_functions / get_function_configuration.
                If it contains ``LoggingConfig.LogGroup`` (advanced
                logging GA Nov 2023), that custom group is checked
                instead of the default.

        Returns:
            Dict with exists, retention_days,
            has_retention, kms_encrypted, log_group_name.
        """
        custom = (
            (function_config or {})
            .get("LoggingConfig", {})
            .get("LogGroup")
        )
        log_group_name = (
            custom or f"/aws/lambda/{function_name}"
        )

        try:
            logs = self.get_client("logs", region)
            paginator = logs.get_paginator(
                "describe_log_groups"
            )
            pages = paginator.paginate(
                logGroupNamePrefix=log_group_name
            )
        except ClientError as e:
            return self.handle_client_error(
                e,
                {
                    "exists": False,
                    "retention_days": None,
                    "has_retention": False,
                    "kms_encrypted": False,
                    "log_group_name": log_group_name,
                },
            )

        # Find exact match (not just prefix match)
        all_groups = []
        try:
            for page in pages:
                all_groups.extend(
                    page.get("logGroups", [])
                )
        except ClientError as e:
            return self.handle_client_error(
                e,
                {
                    "exists": False,
                    "retention_days": None,
                    "has_retention": False,
                    "kms_encrypted": False,
                    "log_group_name": log_group_name,
                },
            )
        for group in all_groups:
            if group.get("logGroupName") == log_group_name:
                retention = group.get("retentionInDays")
                kms_key = group.get("kmsKeyId")
                return {
                    "exists": True,
                    "retention_days": retention,
                    "has_retention": retention is not None,
                    "kms_encrypted": bool(kms_key),
                    "log_group_name": log_group_name,
                }

        return {
            "exists": False,
            "retention_days": None,
            "has_retention": False,
            "kms_encrypted": False,
            "log_group_name": log_group_name,
        }

    def check_reserved_concurrency(
        self, function_name: str, region: str
    ) -> Dict:
        """D.2 - Check reserved concurrency configuration.

        ResourceNotFoundException means no concurrency config.
        ReservedConcurrentExecutions == 0 means disabled.

        Args:
            function_name: Lambda function name.
            region: AWS region name.

        Returns:
            Dict with configured, reserved_executions,
            is_disabled.
        """
        try:
            lambda_client = self.get_client(
                "lambda", region
            )
            response = (
                lambda_client.get_function_concurrency(
                    FunctionName=function_name
                )
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get(
                "Code", ""
            )
            if error_code == "ResourceNotFoundException":
                logger.debug(
                    "No concurrency config for %s",
                    function_name,
                )
                return {
                    "configured": False,
                    "reserved_executions": None,
                    "is_disabled": False,
                }
            return self.handle_client_error(
                e,
                {
                    "configured": False,
                    "reserved_executions": None,
                    "is_disabled": False,
                },
            )

        reserved = response.get(
            "ReservedConcurrentExecutions"
        )

        if reserved is not None:
            return {
                "configured": True,
                "reserved_executions": reserved,
                "is_disabled": reserved == 0,
            }

        return {
            "configured": False,
            "reserved_executions": None,
            "is_disabled": False,
        }
