"""Tests for security scoring logic."""

from unittest import TestCase

from lambda_security_scanner.utils import (
    calculate_security_score,
)


class TestSecurityScore(TestCase):
    """Test calculate_security_score deductions."""

    def _base_checks(self):
        """Checks dict that yields a perfect 100."""
        return {
            "runtime": {"status": "supported"},
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
                "applicable": True,
                "unrestricted_egress": False,
            },
            "log_group": {
                "exists": True,
                "has_retention": True,
            },
            "reserved_concurrency": {"configured": True},
            "code_signing": {
                "configured": True,
                "is_enforced": True,
            },
            "event_source_mappings": {
                "has_mappings": False,
                "missing_failure_dest_count": 0,
            },
        }

    def test_perfect_score(self):
        checks = self._base_checks()
        score = calculate_security_score(checks)
        self.assertEqual(score, 100)

    def test_floor_at_zero(self):
        checks = {
            "runtime": {"status": "blocked"},
            "timeout": {"is_max_timeout": True},
            "environment_secrets": {
                "has_secrets": True,
                "has_kms_key": False,
            },
            "ephemeral_storage": {"is_large": True},
            "layers": {"has_external_layers": True},
            "tracing": {"enabled": False},
            "dead_letter_config": {"configured": False},
            "resource_policy": {"is_public": True},
            "function_url": {"is_public": True},
            "function_url_cors": {
                "allow_all_origins": True,
            },
            "execution_role": {
                "has_admin_access": True,
                "has_wildcard_actions": True,
                "has_privilege_escalation": True,
            },
            "shared_role": {"is_shared": True},
            "vpc_config": {"in_vpc": False},
            "multi_az": {
                "applicable": True,
                "is_multi_az": False,
            },
            "security_groups": {
                "applicable": True,
                "unrestricted_egress": True,
            },
            "log_group": {
                "exists": False,
                "has_retention": False,
            },
            "reserved_concurrency": {
                "configured": False,
            },
            "code_signing": {
                "configured": False,
                "is_enforced": False,
            },
            "event_source_mappings": {
                "has_mappings": True,
                "missing_failure_dest_count": 2,
            },
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 0)

    def test_runtime_blocked_deduction(self):
        checks = self._base_checks()
        checks["runtime"] = {"status": "blocked"}
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 15)

    def test_runtime_deprecated_deduction(self):
        checks = self._base_checks()
        checks["runtime"] = {"status": "deprecated"}
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 10)

    def test_runtime_near_eol_deduction(self):
        checks = self._base_checks()
        checks["runtime"] = {"status": "near_eol"}
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 3)

    def test_secrets_no_kms_deduction(self):
        checks = self._base_checks()
        checks["environment_secrets"] = {
            "has_secrets": True,
            "has_kms_key": False,
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 20)

    def test_secrets_with_kms_deduction(self):
        checks = self._base_checks()
        checks["environment_secrets"] = {
            "has_secrets": True,
            "has_kms_key": True,
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 10)

    def test_code_signing_no_config_deduction(self):
        checks = self._base_checks()
        checks["code_signing"] = {
            "configured": False,
            "is_enforced": False,
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 5)

    def test_code_signing_warn_deduction(self):
        checks = self._base_checks()
        checks["code_signing"] = {
            "configured": True,
            "is_enforced": False,
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 3)

    def test_public_resource_policy_deduction(self):
        checks = self._base_checks()
        checks["resource_policy"] = {"is_public": True}
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 25)

    def test_public_url_deduction(self):
        checks = self._base_checks()
        checks["function_url"] = {"is_public": True}
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 25)

    def test_b4_admin_only_deduction(self):
        # Admin-equivalent access is CRITICAL (-20)
        checks = self._base_checks()
        checks["execution_role"] = {
            "has_admin_access": True,
            "has_full_admin": True,
            "has_wildcard_actions": True,
            "has_privilege_escalation": False,
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 20)

    def test_b4_wildcard_only_deduction(self):
        # A single-service wildcard (e.g. s3:*) is HIGH (-10), not CRITICAL
        checks = self._base_checks()
        checks["execution_role"] = {
            "has_admin_access": False,
            "has_full_admin": False,
            "has_wildcard_actions": True,
            "has_privilege_escalation": False,
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 10)

    def test_b4_admin_and_wildcard_no_double_penalty(self):
        checks = self._base_checks()
        checks["execution_role"] = {
            "has_admin_access": True,
            "has_full_admin": True,
            "has_wildcard_actions": True,
            "has_privilege_escalation": False,
        }
        score = calculate_security_score(checks)
        # full_admin path applies a single -20 deduction
        self.assertEqual(score, 100 - 20)

    def test_b4_privilege_escalation_only(self):
        checks = self._base_checks()
        checks["execution_role"] = {
            "has_admin_access": False,
            "has_wildcard_actions": False,
            "has_privilege_escalation": True,
        }
        score = calculate_security_score(checks)
        self.assertEqual(score, 100 - 10)
