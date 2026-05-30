"""Tests for logging and monitoring checks (D.1-D.2)."""

from unittest import TestCase
from unittest.mock import Mock

from botocore.exceptions import ClientError

from lambda_security_scanner.checks.logging_monitoring import (
    LoggingMonitoringChecker,
)


def _resource_not_found(operation="GetFunctionConcurrency"):
    return ClientError(
        {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "Not found",
            }
        },
        operation,
    )


def _access_denied(operation="Operation"):
    return ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        operation,
    )


class TestCheckLogGroup(TestCase):
    """D.1 - CloudWatch log group checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = LoggingMonitoringChecker(
            lambda: mock_session
        )

    def _setup_paginator(self, pages):
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = iter(pages)
        self.mock_client.get_paginator.return_value = (
            mock_paginator
        )

    def test_log_group_with_retention(self):
        self._setup_paginator([
            {
                "logGroups": [
                    {
                        "logGroupName": (
                            "/aws/lambda/my-func"
                        ),
                        "retentionInDays": 90,
                        "kmsKeyId": None,
                    }
                ]
            }
        ])
        result = self.checker.check_log_group(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["exists"])
        self.assertEqual(result["retention_days"], 90)
        self.assertTrue(result["has_retention"])

    def test_log_group_without_retention(self):
        self._setup_paginator([
            {
                "logGroups": [
                    {
                        "logGroupName": (
                            "/aws/lambda/my-func"
                        ),
                    }
                ]
            }
        ])
        result = self.checker.check_log_group(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["exists"])
        self.assertIsNone(result["retention_days"])
        self.assertFalse(result["has_retention"])

    def test_missing_log_group(self):
        self._setup_paginator([{"logGroups": []}])
        result = self.checker.check_log_group(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["exists"])
        self.assertFalse(result["has_retention"])

    def test_access_denied_log_group(self):
        self.mock_client.get_paginator.side_effect = (
            _access_denied("DescribeLogGroups")
        )
        result = self.checker.check_log_group(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["exists"])
        self.assertFalse(result["has_retention"])
        self.assertIn("error", result)


class TestCheckReservedConcurrency(TestCase):
    """D.2 - Reserved concurrency checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = LoggingMonitoringChecker(
            lambda: mock_session
        )

    def test_with_reserved_concurrency(self):
        self.mock_client.get_function_concurrency \
            .return_value = {
                "ReservedConcurrentExecutions": 100
            }
        result = self.checker.check_reserved_concurrency(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["configured"])
        self.assertEqual(
            result["reserved_executions"], 100
        )
        self.assertFalse(result["is_disabled"])

    def test_without_concurrency(self):
        self.mock_client.get_function_concurrency \
            .side_effect = _resource_not_found()
        result = self.checker.check_reserved_concurrency(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["configured"])
        self.assertIsNone(result["reserved_executions"])
        self.assertFalse(result["is_disabled"])

    def test_disabled_concurrency(self):
        self.mock_client.get_function_concurrency \
            .return_value = {
                "ReservedConcurrentExecutions": 0
            }
        result = self.checker.check_reserved_concurrency(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["configured"])
        self.assertEqual(
            result["reserved_executions"], 0
        )
        self.assertTrue(result["is_disabled"])

    def test_access_denied_reserved_concurrency(self):
        self.mock_client.get_function_concurrency \
            .side_effect = _access_denied(
                "GetFunctionConcurrency"
            )
        result = self.checker.check_reserved_concurrency(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["configured"])
        self.assertIn("error", result)
