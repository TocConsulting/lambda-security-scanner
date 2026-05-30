"""Tests for code security checks (E.1-E.2)."""

from unittest import TestCase
from unittest.mock import Mock, MagicMock

from botocore.exceptions import ClientError

from lambda_security_scanner.checks.code_security import (
    CodeSecurityChecker,
)


def _resource_not_found(operation="Operation"):
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


class TestCheckCodeSigning(TestCase):
    """E.1 - Code signing configuration checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = CodeSecurityChecker(
            lambda: mock_session
        )

    def test_no_code_signing(self):
        self.mock_client \
            .get_function_code_signing_config \
            .side_effect = _resource_not_found()
        result = self.checker.check_code_signing(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["configured"])
        self.assertFalse(result["is_enforced"])
        self.assertIsNone(result["policy"])

    def test_code_signing_enforce(self):
        self.mock_client \
            .get_function_code_signing_config \
            .return_value = {
                "CodeSigningConfigArn": (
                    "arn:aws:lambda:us-east-1:123:"
                    "code-signing-config:csc-123"
                )
            }
        self.mock_client.get_code_signing_config \
            .return_value = {
                "CodeSigningConfig": {
                    "CodeSigningPolicies": {
                        "UntrustedArtifactOnDeployment":
                            "Enforce"
                    }
                }
            }
        result = self.checker.check_code_signing(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["configured"])
        self.assertTrue(result["is_enforced"])
        self.assertEqual(result["policy"], "Enforce")

    def test_code_signing_warn(self):
        self.mock_client \
            .get_function_code_signing_config \
            .return_value = {
                "CodeSigningConfigArn": (
                    "arn:aws:lambda:us-east-1:123:"
                    "code-signing-config:csc-123"
                )
            }
        self.mock_client.get_code_signing_config \
            .return_value = {
                "CodeSigningConfig": {
                    "CodeSigningPolicies": {
                        "UntrustedArtifactOnDeployment":
                            "Warn"
                    }
                }
            }
        result = self.checker.check_code_signing(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["configured"])
        self.assertFalse(result["is_enforced"])
        self.assertEqual(result["policy"], "Warn")

    def test_container_image_not_applicable(self):
        # AWS Lambda Code Signing is not supported for container
        # image functions; the check returns applicable=False so the
        # scorer/issue-analyzer skip E.1 instead of falsely passing.
        result = self.checker.check_code_signing(
            "my-func", "us-east-1", package_type="Image"
        )
        self.assertFalse(result["applicable"])
        self.assertFalse(result["configured"])
        self.assertFalse(result["is_enforced"])
        self.assertIsNone(result["policy"])

    def test_access_denied_code_signing(self):
        self.mock_client \
            .get_function_code_signing_config \
            .side_effect = _access_denied(
                "GetFunctionCodeSigningConfig"
            )
        result = self.checker.check_code_signing(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["configured"])
        self.assertIn("error", result)


class TestCheckEventSourceMappings(TestCase):
    """E.2 - Event source mapping failure dest checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = CodeSecurityChecker(
            lambda: mock_session
        )

    def _setup_paginator(self, mappings):
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"EventSourceMappings": mappings}
        ]
        self.mock_client.get_paginator.return_value = (
            mock_paginator
        )

    def test_no_esms(self):
        self._setup_paginator([])
        result = self.checker.check_event_source_mappings(
            "my-func", "us-east-1"
        )
        self.assertEqual(result["mapping_count"], 0)
        self.assertFalse(result["has_mappings"])

    def test_esm_with_failure_dest(self):
        self._setup_paginator([
            {
                "EventSourceArn": (
                    "arn:aws:sqs:us-east-1:123:my-queue"
                ),
                "UUID": "uuid-1",
                "DestinationConfig": {
                    "OnFailure": {
                        "Destination": (
                            "arn:aws:sqs:us-east-1:"
                            "123:dlq"
                        )
                    }
                },
            }
        ])
        result = self.checker.check_event_source_mappings(
            "my-func", "us-east-1"
        )
        self.assertEqual(result["mapping_count"], 1)
        self.assertTrue(result["has_mappings"])
        self.assertEqual(
            result["missing_failure_dest_count"], 0
        )

    def test_esm_without_failure_dest(self):
        self._setup_paginator([
            {
                "EventSourceArn": (
                    "arn:aws:sqs:us-east-1:123:my-queue"
                ),
                "UUID": "uuid-1",
                "DestinationConfig": {},
            }
        ])
        result = self.checker.check_event_source_mappings(
            "my-func", "us-east-1"
        )
        self.assertEqual(result["mapping_count"], 1)
        self.assertTrue(result["has_mappings"])
        self.assertEqual(
            result["missing_failure_dest_count"], 1
        )
        self.assertIn(
            "uuid-1",
            result["missing_failure_destinations"],
        )
