"""Tests for main scanner orchestrator."""

import json
import os
import tempfile
from unittest import TestCase
from unittest.mock import Mock, MagicMock, patch


class TestGetAllFunctions(TestCase):
    """Test function enumeration with pagination."""

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_pagination(self, mock_init):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )

        scanner = LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )
        scanner.logger = Mock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Functions": [
                    {"FunctionName": "func-1"},
                    {"FunctionName": "func-2"},
                ]
            },
            {
                "Functions": [
                    {"FunctionName": "func-3"},
                ]
            },
        ]
        scanner.lambda_client = Mock()
        scanner.lambda_client.get_paginator.return_value = (
            mock_paginator
        )
        scanner.account_id = "123456789012"

        functions = scanner.get_all_functions()
        self.assertEqual(len(functions), 3)
        self.assertEqual(
            functions[0]["FunctionName"], "func-1"
        )
        self.assertEqual(
            functions[2]["FunctionName"], "func-3"
        )


class TestScanFunction(TestCase):
    """Test scan_function returns expected structure."""

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_scan_function_structure(self, mock_init):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )

        scanner = LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )
        scanner.logger = Mock()
        scanner.region = "us-east-1"
        scanner.account_id = "123456789012"

        # Mock all checkers
        scanner.config_checker = Mock()
        scanner.access_checker = Mock()
        scanner.network_checker = Mock()
        scanner.logging_checker = Mock()
        scanner.code_checker = Mock()
        scanner.compliance_checker = Mock()

        # Setup return values
        scanner.config_checker.check_runtime.return_value = {
            "status": "supported",
            "runtime": "python3.12",
            "package_type": "Zip",
            "eol_date": None,
        }
        scanner.config_checker.check_timeout.return_value = {
            "timeout_seconds": 30,
            "is_max_timeout": False,
        }
        scanner.config_checker \
            .check_environment_secrets.return_value = {
                "has_env_vars": False,
                "env_var_count": 0,
                "has_secrets": False,
                "secret_names": [],
                "secret_values": [],
                "kms_key_arn": None,
                "has_kms_key": False,
            }
        scanner.config_checker \
            .check_ephemeral_storage.return_value = {
                "size_mb": 512,
                "is_large": False,
            }
        scanner.config_checker \
            .check_layers.return_value = {
                "layer_count": 0,
                "layers": [],
                "has_external_layers": False,
                "external_layers": [],
            }
        scanner.config_checker \
            .check_tracing.return_value = {
                "mode": "Active",
                "enabled": True,
            }
        scanner.config_checker \
            .check_dead_letter_config.return_value = {
                "configured": True,
                "target_arn": (
                    "arn:aws:sqs:us-east-1:123:dlq"
                ),
                "target_type": "SQS",
            }
        scanner.access_checker \
            .check_resource_policy.return_value = {
                "has_policy": False,
                "is_public": False,
                "statement_count": 0,
                "public_statement_count": 0,
            }
        scanner.access_checker \
            .check_function_url.return_value = {
                "has_url": False,
                "auth_type": None,
                "is_public": False,
                "function_url": None,
                "cors": {},
            }
        scanner.access_checker \
            .check_function_url_cors.return_value = {
                "has_cors": False,
                "allow_all_origins": False,
                "allow_origins": [],
                "allow_credentials": False,
            }
        scanner.access_checker \
            .check_execution_role.return_value = {
                "role_name": "my-role",
                "has_admin_access": False,
                "has_wildcard_actions": False,
                "has_privilege_escalation": False,
                "dangerous_permissions": [],
                "attached_policy_count": 0,
            }
        scanner.access_checker \
            .check_shared_role.return_value = {
                "is_shared": False,
                "shared_count": 1,
                "role_arn": (
                    "arn:aws:iam::123:role/my-role"
                ),
            }
        scanner.network_checker \
            .check_vpc_config.return_value = {
                "in_vpc": False,
                "vpc_id": None,
                "subnet_count": 0,
                "subnet_ids": [],
                "security_group_count": 0,
                "security_group_ids": [],
            }
        scanner.network_checker \
            .check_multi_az.return_value = {
                "applicable": False,
                "is_multi_az": False,
                "az_count": 0,
                "availability_zones": [],
            }
        scanner.network_checker \
            .check_security_groups.return_value = {
                "applicable": False,
                "unrestricted_egress": False,
                "security_groups": [],
            }
        scanner.logging_checker \
            .check_log_group.return_value = {
                "exists": True,
                "retention_days": 90,
                "has_retention": True,
                "kms_encrypted": False,
            }
        scanner.logging_checker \
            .check_reserved_concurrency.return_value = {
                "configured": True,
                "reserved_executions": 100,
                "is_disabled": False,
            }
        scanner.code_checker \
            .check_code_signing.return_value = {
                "configured": True,
                "policy": "Enforce",
                "config_arn": "arn:...",
                "is_enforced": True,
            }
        scanner.code_checker \
            .check_event_source_mappings.return_value = {
                "mapping_count": 0,
                "mappings": [],
                "missing_failure_dest_count": 0,
                "missing_failure_destinations": [],
                "has_mappings": False,
            }
        scanner.compliance_checker \
            .check_function_compliance.return_value = {}

        func_config = {
            "FunctionName": "test-func",
            "FunctionArn": (
                "arn:aws:lambda:us-east-1:123:"
                "function:test-func"
            ),
            "Role": "arn:aws:iam::123:role/my-role",
            "PackageType": "Zip",
        }
        result = scanner.scan_function(
            func_config, ["arn:aws:iam::123:role/my-role"]
        )

        self.assertEqual(
            result["function_name"], "test-func"
        )
        self.assertIn("security_score", result)
        self.assertIn("issues", result)
        self.assertIn("compliance_status", result)
        self.assertFalse(result["is_public"])


class TestErrorResult(TestCase):
    """Test _error_result structure."""

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_error_result_structure(self, mock_init):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )

        scanner = LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )
        result = scanner._error_result(
            "my-func", "some error"
        )
        self.assertEqual(
            result["function_name"], "my-func"
        )
        self.assertTrue(result["scan_error"])
        self.assertEqual(result["issue_count"], 1)
        self.assertIsNone(result["security_score"])
        self.assertEqual(result["compliance_status"], {})
        self.assertEqual(
            result["issues"][0]["severity"], "ERROR"
        )


class TestAnalyzeIssues(TestCase):
    """Test _analyze_issues generates correct issues."""

    def _get_scanner(self):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )
        return LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )

    def _clean_checks(self):
        """Checks dict that produces zero issues."""
        return {
            "runtime": {
                "status": "supported",
                "runtime": "python3.12",
            },
            "timeout": {"is_max_timeout": False},
            "environment_secrets": {
                "has_secrets": False,
                "has_kms_key": False,
            },
            "ephemeral_storage": {"is_large": False},
            "layers": {"has_external_layers": False},
            "tracing": {"enabled": True},
            "dead_letter_config": {"configured": True},
            "resource_policy": {"is_public": False},
            "function_url": {"is_public": False},
            "function_url_cors": {
                "allow_all_origins": False,
            },
            "execution_role": {
                "has_admin_access": False,
                "has_wildcard_actions": False,
                "has_privilege_escalation": False,
            },
            "shared_role": {"is_shared": False},
            "vpc_config": {"in_vpc": True},
            "multi_az": {
                "applicable": True,
                "is_multi_az": True,
            },
            "security_groups": {
                "applicable": False,
                "unrestricted_egress": False,
            },
            "log_group": {
                "exists": True,
                "has_retention": True,
            },
            "reserved_concurrency": {
                "configured": True,
                "is_disabled": False,
            },
            "code_signing": {
                "configured": True,
                "is_enforced": True,
            },
            "event_source_mappings": {
                "has_mappings": False,
                "missing_failure_dest_count": 0,
            },
        }

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_blocked_runtime_generates_issue(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["runtime"] = {
            "status": "blocked",
            "runtime": "python2.7",
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("blocked_runtime", types)
        blocked = [
            i for i in issues
            if i["issue_type"] == "blocked_runtime"
        ][0]
        self.assertEqual(blocked["severity"], "CRITICAL")

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_clean_checks_yield_no_issues(self, mock_init):
        scanner = self._get_scanner()
        issues = scanner._analyze_issues(
            self._clean_checks()
        )
        self.assertEqual(issues, [])

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_deprecated_runtime_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["runtime"] = {
            "status": "deprecated",
            "runtime": "ruby3.2",
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("deprecated_runtime", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_near_eol_runtime_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["runtime"] = {
            "status": "near_eol",
            "runtime": "nodejs20.x",
            "eol_date": "2026-04-30",
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("near_eol_runtime", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_max_timeout_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["timeout"] = {"is_max_timeout": True}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("max_timeout", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_env_secrets_no_kms_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["environment_secrets"] = {
            "has_secrets": True,
            "has_kms_key": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("env_secrets_no_kms", types)
        issue = next(
            i for i in issues
            if i["issue_type"] == "env_secrets_no_kms"
        )
        self.assertEqual(issue["severity"], "CRITICAL")

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_env_secrets_with_kms_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["environment_secrets"] = {
            "has_secrets": True,
            "has_kms_key": True,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("env_secrets_with_kms", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_large_ephemeral_storage_issue(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["ephemeral_storage"] = {"is_large": True}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("large_ephemeral_storage", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_external_layers_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["layers"] = {"has_external_layers": True}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("external_layers", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_tracing_disabled_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["tracing"] = {"enabled": False}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("tracing_disabled", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_no_dlq_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["dead_letter_config"] = {
            "configured": False
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("no_dlq", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_public_resource_policy_issue(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["resource_policy"] = {"is_public": True}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("public_resource_policy", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_public_function_url_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["function_url"] = {"is_public": True}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("public_function_url", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_cors_wildcard_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["function_url_cors"] = {
            "allow_all_origins": True
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("cors_wildcard", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_admin_execution_role_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["execution_role"] = {
            "has_admin_access": True,
            "has_full_admin": True,
            "has_wildcard_actions": True,
            "has_privilege_escalation": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("admin_execution_role", types)
        issue = next(
            i for i in issues
            if i["issue_type"] == "admin_execution_role"
        )
        self.assertEqual(issue["severity"], "CRITICAL")

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_wildcard_execution_role_issue(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["execution_role"] = {
            "has_admin_access": False,
            "has_full_admin": False,
            "has_wildcard_actions": True,
            "has_privilege_escalation": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("service_wildcard_execution_role", types)
        issue = next(
            i for i in issues
            if i["issue_type"] == "service_wildcard_execution_role"
        )
        self.assertEqual(issue["severity"], "HIGH")

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_check_error_surfaced_as_finding(self, mock_init):
        """A check that errored (AccessDenied) must be surfaced as an
        ERROR finding, not silently treated as clean."""
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["execution_role"] = {
            "error": "AccessDeniedException: not authorized iam:GetРolicy"
        }
        issues = scanner._analyze_issues(checks)
        errs = [
            i for i in issues
            if i["severity"] == "ERROR"
            and i["issue_type"] == "check_failed"
        ]
        self.assertEqual(len(errs), 1)
        self.assertIn("execution_role", errs[0]["description"])

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_privilege_escalation_role_issue(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["execution_role"] = {
            "has_admin_access": False,
            "has_wildcard_actions": False,
            "has_privilege_escalation": True,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("privilege_escalation_role", types)
        issue = next(
            i for i in issues
            if i["issue_type"] == "privilege_escalation_role"
        )
        self.assertEqual(issue["severity"], "HIGH")

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_shared_role_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["shared_role"] = {"is_shared": True}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("shared_role", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_no_vpc_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["vpc_config"] = {"in_vpc": False}
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("no_vpc", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_single_az_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["multi_az"] = {
            "applicable": True,
            "is_multi_az": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("single_az", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_unrestricted_egress_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["security_groups"] = {
            "applicable": True,
            "unrestricted_egress": True,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("unrestricted_egress", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_missing_log_group_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["log_group"] = {
            "exists": False,
            "has_retention": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("missing_log_group", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_no_log_retention_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["log_group"] = {
            "exists": True,
            "has_retention": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("no_log_retention", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_no_reserved_concurrency_issue(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["reserved_concurrency"] = {
            "configured": False,
            "is_disabled": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("no_reserved_concurrency", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_disabled_function_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["reserved_concurrency"] = {
            "configured": True,
            "is_disabled": True,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("disabled_function", types)
        issue = next(
            i for i in issues
            if i["issue_type"] == "disabled_function"
        )
        self.assertEqual(issue["severity"], "INFO")

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_no_code_signing_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["code_signing"] = {
            "configured": False,
            "is_enforced": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("no_code_signing", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_code_signing_warn_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["code_signing"] = {
            "configured": True,
            "is_enforced": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("code_signing_warn", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_esm_no_failure_dest_issue(self, mock_init):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["event_source_mappings"] = {
            "has_mappings": True,
            "missing_failure_dest_count": 2,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("esm_no_failure_dest", types)

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_public_no_concurrency_composite(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["resource_policy"] = {"is_public": True}
        checks["reserved_concurrency"] = {
            "configured": False,
            "is_disabled": False,
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("public_no_concurrency", types)
        issue = next(
            i for i in issues
            if i["issue_type"] == "public_no_concurrency"
        )
        self.assertEqual(issue["severity"], "CRITICAL")

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_public_url_cors_wildcard_composite(
        self, mock_init
    ):
        scanner = self._get_scanner()
        checks = self._clean_checks()
        checks["function_url"] = {"is_public": True}
        checks["function_url_cors"] = {
            "allow_all_origins": True
        }
        issues = scanner._analyze_issues(checks)
        types = [i["issue_type"] for i in issues]
        self.assertIn("public_url_cors_wildcard", types)
        issue = next(
            i for i in issues
            if i["issue_type"] == "public_url_cors_wildcard"
        )
        self.assertEqual(issue["severity"], "CRITICAL")


class TestScanAllFunctions(TestCase):
    """Test scan_all_functions orchestration."""

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_empty_functions_returns_empty(
        self, mock_init
    ):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )
        scanner = LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )
        scanner.logger = Mock()
        results = scanner.scan_all_functions([])
        self.assertEqual(results, [])

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_results_sorted_by_score_ascending(
        self, mock_init
    ):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )
        from unittest.mock import patch as _patch
        from rich.console import Console

        scanner = LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )
        scanner.logger = Mock()
        scanner.max_workers = 2
        scanner.quiet = True
        scanner.console = Console(quiet=True)

        scores = [90, 40, 70]
        idx = [0]

        def fake_scan(func, all_roles, progress=None,
                      task=None):
            score = scores[idx[0] % len(scores)]
            idx[0] += 1
            return {
                "function_name": func["FunctionName"],
                "security_score": score,
                "scan_error": False,
            }

        functions = [
            {
                "FunctionName": f"func-{i}",
                "Role": "arn:aws:iam::123:role/r",
            }
            for i in range(3)
        ]
        with _patch.object(
            scanner,
            "scan_function",
            side_effect=fake_scan,
        ):
            results = scanner.scan_all_functions(functions)

        result_scores = [
            r["security_score"] for r in results
        ]
        self.assertEqual(
            result_scores, sorted(result_scores)
        )


class TestBuildSummary(TestCase):
    """Test _build_summary aggregation."""

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_build_summary_counts(self, mock_init):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )
        scanner = LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )
        scanner.account_id = "123456789012"
        scanner.region = "us-east-1"

        results = [
            {
                "function_name": "f1",
                "security_score": 80,
                "scan_error": False,
                "is_public": True,
                "environment_secrets": {
                    "has_secrets": True
                },
                "runtime": {"status": "blocked"},
            },
            {
                "function_name": "f2",
                "security_score": 60,
                "scan_error": False,
                "is_public": False,
                "environment_secrets": {
                    "has_secrets": False
                },
                "runtime": {"status": "supported"},
            },
            {
                "function_name": "f3",
                "scan_error": True,
            },
        ]

        summary = scanner._build_summary(results)

        self.assertEqual(summary["total_functions"], 3)
        self.assertEqual(summary["scanned_functions"], 2)
        self.assertEqual(summary["error_functions"], 1)
        self.assertEqual(
            summary["average_security_score"], 70.0
        )
        self.assertEqual(summary["public_functions"], 1)
        self.assertEqual(
            summary["functions_with_secrets"], 1
        )
        self.assertEqual(
            summary["functions_with_deprecated_runtime"],
            1,
        )

    @patch(
        "lambda_security_scanner.scanner"
        ".LambdaSecurityScanner.__init__",
        return_value=None,
    )
    def test_build_summary_empty(self, mock_init):
        from lambda_security_scanner.scanner import (
            LambdaSecurityScanner,
        )
        scanner = LambdaSecurityScanner.__new__(
            LambdaSecurityScanner
        )
        scanner.account_id = "123456789012"
        scanner.region = "us-east-1"

        summary = scanner._build_summary([])
        self.assertEqual(summary["total_functions"], 0)
        self.assertEqual(
            summary["average_security_score"], 0
        )


class TestExportMethods(TestCase):
    """Test report export methods."""

    def _make_scanner(self):
        with patch(
            "lambda_security_scanner.scanner"
            ".LambdaSecurityScanner.__init__",
            return_value=None,
        ):
            from lambda_security_scanner.scanner import (
                LambdaSecurityScanner,
            )
            scanner = LambdaSecurityScanner.__new__(
                LambdaSecurityScanner
            )
        scanner.account_id = "123456789012"
        scanner.region = "us-east-1"
        scanner.logger = Mock()
        scanner.html_reporter = Mock()
        scanner.html_reporter.generate_report \
            .return_value = None
        return scanner

    def _sample_results(self):
        return [
            {
                "function_name": "func-1",
                "function_arn": (
                    "arn:aws:lambda:us-east-1:123:"
                    "function:func-1"
                ),
                "region": "us-east-1",
                "security_score": 75,
                "issue_count": 2,
                "is_public": False,
                "scan_error": False,
                "runtime": {"runtime": "python3.12"},
                "compliance_status": {
                    "AWS-FSBP": {
                        "is_compliant": True,
                        "compliance_percentage": 100.0,
                    }
                },
                "environment_secrets": {
                    "has_secrets": False
                },
            }
        ]

    def test_export_json_creates_file(self):
        scanner = self._make_scanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner.output_dir = tmpdir
            results = self._sample_results()
            filepath = scanner._export_json(
                results, "20260101_000000"
            )
            self.assertTrue(os.path.exists(filepath))
            self.assertIn(
                "lambda_scan_us-east-1", filepath
            )
            with open(filepath) as f:
                data = json.load(f)
            # Documented schema: {"summary": {...}, "results": [...]}
            self.assertIn("summary", data)
            self.assertIn("results", data)
            self.assertEqual(len(data["results"]), 1)
            self.assertEqual(
                data["results"][0]["function_name"], "func-1"
            )
            self.assertIn("total_functions", data["summary"])

    def test_export_csv_creates_file_with_headers(self):
        import csv as _csv
        scanner = self._make_scanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner.output_dir = tmpdir
            results = self._sample_results()
            filepath = scanner._export_csv(
                results, "20260101_000000"
            )
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, newline="") as f:
                reader = _csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertIn("function_name", rows[0])
            self.assertIn("security_score", rows[0])

    def test_export_html_calls_reporter(self):
        scanner = self._make_scanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner.output_dir = tmpdir
            results = self._sample_results()
            filepath = scanner._export_html(
                results, "20260101_000000"
            )
            self.assertTrue(
                scanner.html_reporter.generate_report.called
            )
            self.assertIn(
                "lambda_scan_us-east-1", filepath
            )

    def test_export_compliance_creates_file(self):
        scanner = self._make_scanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner.output_dir = tmpdir
            results = self._sample_results()
            filepath = scanner._export_compliance(
                results, "20260101_000000"
            )
            self.assertTrue(os.path.exists(filepath))
            with open(filepath) as f:
                data = json.load(f)
            self.assertEqual(
                data["account_id"], "123456789012"
            )
            self.assertIn("frameworks", data)
            self.assertIn("AWS-FSBP", data["frameworks"])

    def test_generate_reports_all_format(self):
        scanner = self._make_scanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner.output_dir = tmpdir
            results = self._sample_results()
            report_files = scanner.generate_reports(
                results, "all"
            )
            self.assertIn("json", report_files)
            self.assertIn("csv", report_files)
            self.assertIn("html", report_files)
            self.assertIn("compliance", report_files)
            for fmt, path in report_files.items():
                if fmt != "html":
                    self.assertTrue(
                        os.path.exists(path),
                        f"{fmt} file not found",
                    )

    def test_generate_reports_json_only(self):
        scanner = self._make_scanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner.output_dir = tmpdir
            results = self._sample_results()
            report_files = scanner.generate_reports(
                results, "json"
            )
            self.assertIn("json", report_files)
            self.assertIn("compliance", report_files)
            self.assertNotIn("csv", report_files)
            self.assertNotIn("html", report_files)
