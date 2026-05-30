"""Tests for compliance engine."""

from unittest import TestCase

from lambda_security_scanner.compliance import (
    ComplianceChecker,
)


class TestComplianceFrameworks(TestCase):
    """Verify all 10 frameworks exist with correct counts."""

    def setUp(self):
        self.checker = ComplianceChecker()

    def test_all_10_frameworks_exist(self):
        expected = [
            "AWS-FSBP",
            "CIS",
            "PCI-DSS-v4.0.1",
            "HIPAA",
            "SOC2",
            "ISO27001",
            "ISO27017",
            "ISO27018",
            "GDPR",
            "NIST-800-53",
        ]
        for fw in expected:
            self.assertIn(fw, self.checker.frameworks)

    def test_aws_fsbp_control_count(self):
        fw = self.checker.frameworks["AWS-FSBP"]
        self.assertEqual(len(fw["controls"]), 5)

    def test_cis_control_count(self):
        fw = self.checker.frameworks["CIS"]
        self.assertEqual(len(fw["controls"]), 8)

    def test_pci_control_count(self):
        fw = self.checker.frameworks["PCI-DSS-v4.0.1"]
        # Code-signing dropped from PCI: there is no clean PCI-DSS
        # clause for artefact integrity. Code signing is still
        # tracked under CIS, SOC2, ISO27001, HIPAA, and NIST.
        self.assertEqual(len(fw["controls"]), 8)

    def test_hipaa_control_count(self):
        fw = self.checker.frameworks["HIPAA"]
        self.assertEqual(len(fw["controls"]), 9)

    def test_soc2_control_count(self):
        fw = self.checker.frameworks["SOC2"]
        self.assertEqual(len(fw["controls"]), 11)

    def test_iso27001_control_count(self):
        fw = self.checker.frameworks["ISO27001"]
        # ISO27001 absorbed A.5.21 (supply chain) and A.8.2
        # (privileged access) — controls that ISO 27017 had under
        # mismatched CLD numbers (now dropped).
        self.assertEqual(len(fw["controls"]), 11)

    def test_iso27017_control_count(self):
        fw = self.checker.frameworks["ISO27017"]
        # CLD.6.3.1 and CLD.8.1.5 were dropped — the original
        # mappings to "shared role" and "external layer
        # verification" did not match the real ISO 27017 clauses.
        # Detection coverage is preserved via ISO27001 A.8.2/A.5.21.
        self.assertEqual(len(fw["controls"]), 4)

    def test_iso27018_control_count(self):
        fw = self.checker.frameworks["ISO27018"]
        self.assertEqual(len(fw["controls"]), 5)

    def test_gdpr_control_count(self):
        fw = self.checker.frameworks["GDPR"]
        self.assertEqual(len(fw["controls"]), 8)

    def test_nist_control_count(self):
        fw = self.checker.frameworks["NIST-800-53"]
        self.assertEqual(len(fw["controls"]), 12)


class TestComplianceEvaluation(TestCase):
    """Compliance evaluation against check results."""

    def setUp(self):
        self.checker = ComplianceChecker()

    def _compliant_checks(self):
        """Build a fully compliant checks dict."""
        return {
            "runtime": {
                "status": "supported",
                "runtime": "python3.12",
            },
            "resource_policy": {
                "is_public": False,
                "has_policy": True,
            },
            "function_url": {
                "is_public": False,
                "has_url": False,
            },
            "execution_role": {
                "has_admin_access": False,
                "has_wildcard_actions": False,
                "has_privilege_escalation": False,
            },
            "shared_role": {"is_shared": False},
            "environment_secrets": {
                "has_secrets": False,
                "has_env_vars": False,
                "has_kms_key": False,
            },
            "tracing": {"enabled": True},
            "dead_letter_config": {"configured": True},
            "vpc_config": {"in_vpc": True},
            "multi_az": {
                "is_multi_az": True,
                "applicable": True,
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
                "has_mappings": True,
                "missing_failure_dest_count": 0,
            },
            "layers": {"has_external_layers": False},
        }

    def test_perfectly_compliant(self):
        checks = self._compliant_checks()
        results = self.checker.check_function_compliance(
            checks
        )
        self.assertEqual(len(results), 10)
        for fw_key, fw_result in results.items():
            self.assertTrue(
                fw_result["is_compliant"],
                f"{fw_key} should be compliant",
            )
            self.assertEqual(
                fw_result["failed_controls"],
                0,
                f"{fw_key} should have 0 failures",
            )

    def test_public_access_fails_controls(self):
        checks = self._compliant_checks()
        checks["resource_policy"] = {"is_public": True}
        checks["function_url"] = {"is_public": True}
        results = self.checker.check_function_compliance(
            checks
        )
        # AWS-FSBP Lambda.1 should fail
        fsbp = results["AWS-FSBP"]
        self.assertFalse(fsbp["is_compliant"])
        failed_ids = [
            c["control_id"] for c in fsbp["failed"]
        ]
        self.assertIn("Lambda.1", failed_ids)

        # CIS Lambda.2 should fail
        cis = results["CIS"]
        failed_ids = [
            c["control_id"] for c in cis["failed"]
        ]
        self.assertIn("CIS-Lambda.2", failed_ids)

        # HIPAA access controls should fail
        hipaa = results["HIPAA"]
        self.assertFalse(hipaa["is_compliant"])
        failed_ids = [
            c["control_id"] for c in hipaa["failed"]
        ]
        self.assertIn("164.312(a)(1)-ACCESS", failed_ids)
        self.assertIn("164.312(a)(1)-URL", failed_ids)

        # ISO27001 A.5.15 should fail
        iso27001 = results["ISO27001"]
        self.assertFalse(iso27001["is_compliant"])
        failed_ids = [
            c["control_id"] for c in iso27001["failed"]
        ]
        self.assertIn("A.5.15", failed_ids)

        # ISO27018 access controls should fail
        iso27018 = results["ISO27018"]
        self.assertFalse(iso27018["is_compliant"])
        failed_ids = [
            c["control_id"] for c in iso27018["failed"]
        ]
        self.assertIn("ISO27018-ACCESS", failed_ids)
        self.assertIn("ISO27018-AUTH", failed_ids)

        # GDPR Art32b should fail
        gdpr = results["GDPR"]
        self.assertFalse(gdpr["is_compliant"])
        failed_ids = [
            c["control_id"] for c in gdpr["failed"]
        ]
        self.assertIn("GDPR-Art32-1b-ACCESS", failed_ids)

        # NIST-800-53 AC-3 and AC-17 should fail
        nist = results["NIST-800-53"]
        self.assertFalse(nist["is_compliant"])
        failed_ids = [
            c["control_id"] for c in nist["failed"]
        ]
        self.assertIn("AC-3", failed_ids)
        self.assertIn("AC-17", failed_ids)

        # PCI-DSS-v4.0.1 public access controls should fail
        pci = results["PCI-DSS-v4.0.1"]
        self.assertFalse(pci["is_compliant"])
        failed_ids = [
            c["control_id"] for c in pci["failed"]
        ]
        self.assertIn("PCI-Lambda.1.4.1", failed_ids)
        self.assertIn("PCI-Lambda.8.3.1", failed_ids)

        # SOC2 access controls should fail
        soc2 = results["SOC2"]
        self.assertFalse(soc2["is_compliant"])
        failed_ids = [
            c["control_id"] for c in soc2["failed"]
        ]
        self.assertIn("SOC2-CC6.1-ACCESS", failed_ids)
        self.assertIn("SOC2-CC6.1-URL", failed_ids)
