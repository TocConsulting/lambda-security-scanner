"""Tests for access control checks (B.1-B.5)."""

import json
from unittest import TestCase
from unittest.mock import Mock, MagicMock

from botocore.exceptions import ClientError

from lambda_security_scanner.checks.access_control import (
    AccessControlChecker,
)


def _resource_not_found(operation="GetPolicy"):
    return ClientError(
        {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "Not found",
            }
        },
        operation,
    )


class TestCheckResourcePolicy(TestCase):
    """B.1 - Resource-based policy checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = AccessControlChecker(
            lambda: mock_session
        )

    def test_no_policy(self):
        self.mock_client.get_policy.side_effect = (
            _resource_not_found()
        )
        result = self.checker.check_resource_policy(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["has_policy"])
        self.assertFalse(result["is_public"])
        self.assertEqual(result["statement_count"], 0)

    def test_public_policy_wildcard_principal(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "lambda:InvokeFunction",
                }
            ]
        }
        self.mock_client.get_policy.return_value = {
            "Policy": json.dumps(policy)
        }
        result = self.checker.check_resource_policy(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["has_policy"])
        self.assertTrue(result["is_public"])
        self.assertEqual(result["public_statement_count"], 1)

    def test_non_public_policy(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": (
                            "arn:aws:iam::123456789012:root"
                        )
                    },
                    "Action": "lambda:InvokeFunction",
                }
            ]
        }
        self.mock_client.get_policy.return_value = {
            "Policy": json.dumps(policy)
        }
        result = self.checker.check_resource_policy(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["has_policy"])
        self.assertFalse(result["is_public"])

    def test_confused_deputy_no_condition(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "events.amazonaws.com"
                    },
                    "Action": "lambda:InvokeFunction",
                }
            ]
        }
        self.mock_client.get_policy.return_value = {
            "Policy": json.dumps(policy)
        }
        result = self.checker.check_resource_policy(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["is_public"])

    def test_public_policy_dict_aws_wildcard(self):
        """Principal: {"AWS": "*"} dict form is public."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "lambda:InvokeFunction",
                }
            ]
        }
        self.mock_client.get_policy.return_value = {
            "Policy": json.dumps(policy)
        }
        result = self.checker.check_resource_policy(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["has_policy"])
        self.assertTrue(result["is_public"])
        self.assertEqual(
            result["public_statement_count"], 1
        )

    def test_public_policy_list_aws_wildcard(self):
        """Principal: {"AWS": ["*"]} list form is public."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["*"]},
                    "Action": "lambda:InvokeFunction",
                }
            ]
        }
        self.mock_client.get_policy.return_value = {
            "Policy": json.dumps(policy)
        }
        result = self.checker.check_resource_policy(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["has_policy"])
        self.assertTrue(result["is_public"])
        self.assertEqual(
            result["public_statement_count"], 1
        )

    def test_access_denied_resource_policy(self):
        from botocore.exceptions import ClientError
        self.mock_client.get_policy.side_effect = (
            ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "Access denied",
                    }
                },
                "GetPolicy",
            )
        )
        result = self.checker.check_resource_policy(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["has_policy"])
        self.assertFalse(result["is_public"])
        self.assertIn("error", result)


class TestCheckFunctionUrl(TestCase):
    """B.2 - Function URL auth checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = AccessControlChecker(
            lambda: mock_session
        )

    def test_no_url(self):
        self.mock_client.get_function_url_config \
            .side_effect = _resource_not_found(
                "GetFunctionUrlConfig"
            )
        result = self.checker.check_function_url(
            "my-func", "us-east-1"
        )
        self.assertFalse(result["has_url"])
        self.assertFalse(result["is_public"])

    def test_public_url(self):
        self.mock_client.get_function_url_config \
            .return_value = {
                "AuthType": "NONE",
                "FunctionUrl": "https://x.lambda-url.com/",
                "Cors": {},
            }
        result = self.checker.check_function_url(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["has_url"])
        self.assertTrue(result["is_public"])
        self.assertEqual(result["auth_type"], "NONE")

    def test_authenticated_url(self):
        self.mock_client.get_function_url_config \
            .return_value = {
                "AuthType": "AWS_IAM",
                "FunctionUrl": "https://x.lambda-url.com/",
                "Cors": {},
            }
        result = self.checker.check_function_url(
            "my-func", "us-east-1"
        )
        self.assertTrue(result["has_url"])
        self.assertFalse(result["is_public"])
        self.assertEqual(result["auth_type"], "AWS_IAM")


class TestCheckFunctionUrlCors(TestCase):
    """B.3 - CORS configuration checks."""

    def setUp(self):
        self.checker = AccessControlChecker()

    def test_no_cors(self):
        url_result = {"cors": {}}
        result = self.checker.check_function_url_cors(
            url_result
        )
        self.assertFalse(result["has_cors"])
        self.assertFalse(result["allow_all_origins"])

    def test_wildcard_cors(self):
        url_result = {
            "cors": {
                "AllowOrigins": ["*"],
                "AllowCredentials": True,
            }
        }
        result = self.checker.check_function_url_cors(
            url_result
        )
        self.assertTrue(result["has_cors"])
        self.assertTrue(result["allow_all_origins"])
        self.assertTrue(result["allow_credentials"])

    def test_specific_cors_origins(self):
        url_result = {
            "cors": {
                "AllowOrigins": ["https://example.com"],
                "AllowCredentials": False,
            }
        }
        result = self.checker.check_function_url_cors(
            url_result
        )
        self.assertTrue(result["has_cors"])
        self.assertFalse(result["allow_all_origins"])
        self.assertEqual(
            result["allow_origins"],
            ["https://example.com"],
        )


class TestCheckExecutionRole(TestCase):
    """B.4 - Execution role permission checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = AccessControlChecker(
            lambda: mock_session
        )

    def _setup_paginators(
        self, managed_policies=None, inline_names=None
    ):
        managed_policies = managed_policies or []
        inline_names = inline_names or []

        managed_pag = MagicMock()
        managed_pag.paginate.return_value = [
            {"AttachedPolicies": managed_policies}
        ]

        inline_pag = MagicMock()
        inline_pag.paginate.return_value = [
            {"PolicyNames": inline_names}
        ]

        def get_paginator(name):
            if name == "list_attached_role_policies":
                return managed_pag
            elif name == "list_role_policies":
                return inline_pag
            raise ValueError(f"Unknown paginator: {name}")

        self.mock_client.get_paginator.side_effect = (
            get_paginator
        )

    def test_admin_role(self):
        self._setup_paginators(
            managed_policies=[
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": (
                        "arn:aws:iam::aws:policy/"
                        "AdministratorAccess"
                    ),
                }
            ]
        )
        result = self.checker.check_execution_role(
            "arn:aws:iam::123:role/admin-role",
            "us-east-1",
        )
        self.assertTrue(result["has_admin_access"])
        self.assertIn(
            "AdministratorAccess",
            result["dangerous_permissions"],
        )

    def test_wildcard_actions(self):
        self._setup_paginators(
            managed_policies=[
                {
                    "PolicyName": "custom-policy",
                    "PolicyArn": (
                        "arn:aws:iam::123:policy/custom"
                    ),
                }
            ]
        )
        self.mock_client.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        self.mock_client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }
        result = self.checker.check_execution_role(
            "arn:aws:iam::123:role/wild-role",
            "us-east-1",
        )
        self.assertTrue(result["has_wildcard_actions"])

    def test_privilege_escalation(self):
        self._setup_paginators(
            inline_names=["inline-policy"]
        )
        self.mock_client.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:CreatePolicyVersion",
                        "Resource": "*",
                    }
                ]
            }
        }
        result = self.checker.check_execution_role(
            "arn:aws:iam::123:role/priv-role",
            "us-east-1",
        )
        self.assertTrue(result["has_privilege_escalation"])
        self.assertFalse(result["has_admin_access"])

    def test_clean_role(self):
        self._setup_paginators()
        result = self.checker.check_execution_role(
            "arn:aws:iam::123:role/clean-role",
            "us-east-1",
        )
        self.assertFalse(result["has_admin_access"])
        self.assertFalse(result["has_wildcard_actions"])
        self.assertFalse(result["has_privilege_escalation"])
        self.assertEqual(
            result["dangerous_permissions"], []
        )


class TestCheckSharedRole(TestCase):
    """B.5 - Shared role detection."""

    def setUp(self):
        self.checker = AccessControlChecker()

    def test_unique_role(self):
        role = "arn:aws:iam::123:role/my-role"
        all_roles = [role, "arn:aws:iam::123:role/other"]
        result = self.checker.check_shared_role(
            role, all_roles
        )
        self.assertFalse(result["is_shared"])
        self.assertEqual(result["shared_count"], 1)

    def test_shared_role(self):
        role = "arn:aws:iam::123:role/shared-role"
        all_roles = [role, role, "arn:aws:iam::123:role/x"]
        result = self.checker.check_shared_role(
            role, all_roles
        )
        self.assertTrue(result["is_shared"])
        self.assertEqual(result["shared_count"], 2)
