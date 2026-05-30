"""Compliance Engine - 10 frameworks, 81 Lambda-mapped controls.

Evaluates function check results against compliance framework controls.
Each control is a lambda that reads from the checks dict built during
scan_function(). The checks dict key names are the contract between
checkers and compliance.

Frameworks: AWS-FSBP, CIS, PCI-DSS-v4.0.1, HIPAA, SOC2,
            ISO27001, ISO27017, ISO27018, GDPR, NIST-800-53
"""

from typing import Any, Dict


class ComplianceChecker:
    """Evaluate function security checks against 10 frameworks."""

    def __init__(self):
        """Initialize compliance checker with all frameworks."""
        self.frameworks = {}
        self._define_frameworks()

    def _define_frameworks(self):
        """Define all 10 compliance frameworks."""
        self.frameworks = {
            "AWS-FSBP": {
                "name": "AWS Foundational Security Best Practices",
                "controls": {
                    "Lambda.1": {"description": "Function policies should prohibit public access", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "Lambda.2": {"description": "Functions should use supported runtimes", "severity": "MEDIUM", "check": lambda r: r.get("runtime", {}).get("status", "blocked") == "supported"},
                    "Lambda.3": {"description": "Functions should be in a VPC", "severity": "LOW", "check": lambda r: r.get("vpc_config", {}).get("in_vpc", False)},
                    "Lambda.5": {"description": "VPC Lambda functions should operate in multiple AZs", "severity": "MEDIUM", "check": lambda r: r.get("multi_az", {}).get("is_multi_az", False) if r.get("vpc_config", {}).get("in_vpc", False) else True},
                    "Lambda.7": {"description": "Functions should have X-Ray active tracing enabled", "severity": "LOW", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                },
            },
            "CIS": {
                "name": "CIS AWS Compute Services Benchmark",
                "controls": {
                    "CIS-Lambda.1": {"description": "Functions should use supported runtimes", "severity": "HIGH", "check": lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")},
                    "CIS-Lambda.2": {"description": "Functions should not be publicly accessible", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True) and not r.get("function_url", {}).get("is_public", True)},
                    "CIS-Lambda.3": {"description": "Execution roles should follow least privilege", "severity": "HIGH", "check": lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)},
                    "CIS-Lambda.4": {"description": "Functions should have dead-letter queues", "severity": "MEDIUM", "check": lambda r: r.get("dead_letter_config", {}).get("configured", False)},
                    "CIS-Lambda.5": {"description": "Functions should be deployed in a VPC", "severity": "LOW", "check": lambda r: r.get("vpc_config", {}).get("in_vpc", False)},
                    "CIS-Lambda.6": {"description": "Functions should have X-Ray tracing enabled", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "CIS-Lambda.7": {"description": "Env vars should not contain sensitive data", "severity": "CRITICAL", "check": lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)},
                    "CIS-Lambda.8": {"description": "Functions should have code signing enabled (N/A for container images)", "severity": "MEDIUM", "check": lambda r: True if not r.get("code_signing", {}).get("applicable", True) else r.get("code_signing", {}).get("configured", False)},
                },
            },
            "PCI-DSS-v4.0.1": {
                "name": "PCI DSS v4.0.1",
                "controls": {
                    "PCI-Lambda.6.3.3": {"description": "Security patches/updates installed (supported runtimes)", "severity": "HIGH", "check": lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")},
                    "PCI-Lambda.8.6.2": {"description": "Application/system account secrets not hard-coded in config (no plaintext secrets in env vars)", "severity": "CRITICAL", "check": lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)},
                    "PCI-Lambda.7.2.1": {"description": "Access roles defined with least privilege", "severity": "HIGH", "check": lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)},
                    "PCI-Lambda.1.4.1": {"description": "NSC implemented between trusted and untrusted networks (no public resource policy)", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "PCI-Lambda.8.3.1": {"description": "User access to system components is authenticated (function URL auth required)", "severity": "CRITICAL", "check": lambda r: not r.get("function_url", {}).get("is_public", True)},
                    "PCI-Lambda.1.3.2": {"description": "Outbound traffic from the CDE is restricted (VPC SG egress)", "severity": "MEDIUM", "check": lambda r: not r.get("security_groups", {}).get("unrestricted_egress", True) if r.get("security_groups", {}).get("applicable", False) else True},
                    "PCI-Lambda.10.2.1": {"description": "Audit logging enabled (tracing)", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "PCI-Lambda.10.5.1": {"description": "Audit log history retained for at least 12 months (retention set)", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                },
            },
            "HIPAA": {
                "name": "HIPAA Security Rule",
                "controls": {
                    "164.312(a)(1)-ACCESS": {"description": "Access control - prohibit public access to ePHI", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "164.312(a)(1)-URL": {"description": "Access control - function URL authentication", "severity": "CRITICAL", "check": lambda r: not r.get("function_url", {}).get("is_public", True)},
                    "164.312(a)(1)-SECRETS": {"description": "No PHI/secrets in env vars", "severity": "CRITICAL", "check": lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)},
                    "164.312(a)(1)-IAM": {"description": "Access control - least privilege execution roles", "severity": "HIGH", "check": lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)},
                    "164.312(b)-TRACING": {"description": "Audit controls - tracing enabled", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "164.312(b)-LOGGING": {"description": "Audit controls - log retention", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                    "164.308(a)(7)-DLQ": {"description": "Contingency plan - dead letter queue for failure capture", "severity": "MEDIUM", "check": lambda r: r.get("dead_letter_config", {}).get("configured", False)},
                    "164.312(c)(1)-SIGNING": {"description": "Integrity - code signing prevents improper alteration (N/A for container images)", "severity": "MEDIUM", "check": lambda r: True if not r.get("code_signing", {}).get("applicable", True) else r.get("code_signing", {}).get("configured", False)},
                    "164.308(a)(5)(ii)(B)-RUNTIME": {"description": "Protection from malicious software - use supported/patched runtimes", "severity": "HIGH", "check": lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")},
                },
            },
            "SOC2": {
                "name": "SOC 2 Type II",
                "controls": {
                    "SOC2-CC6.1-ACCESS": {"description": "Restrict public access to functions", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "SOC2-CC6.1-URL": {"description": "Function URL authentication required", "severity": "CRITICAL", "check": lambda r: not r.get("function_url", {}).get("is_public", True)},
                    "SOC2-CC6.1-IAM": {"description": "Least privilege execution roles", "severity": "HIGH", "check": lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)},
                    "SOC2-CC6.1-ROLE": {"description": "Unique execution roles per function", "severity": "HIGH", "check": lambda r: not r.get("shared_role", {}).get("is_shared", True)},
                    "SOC2-CC6.8-SIGNING": {"description": "Code signing for software integrity (N/A for container images)", "severity": "MEDIUM", "check": lambda r: True if not r.get("code_signing", {}).get("applicable", True) else r.get("code_signing", {}).get("configured", False)},
                    "SOC2-CC6.8-RUNTIME": {"description": "Use current supported runtimes", "severity": "HIGH", "check": lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")},
                    "SOC2-CC7.1-LOGGING": {"description": "CloudWatch log retention configured", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                    "SOC2-CC7.2-TRACING": {"description": "X-Ray tracing for anomaly detection", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "SOC2-CC7.3-DLQ": {"description": "Dead letter queue for failure capture", "severity": "MEDIUM", "check": lambda r: r.get("dead_letter_config", {}).get("configured", False)},
                    "SOC2-CC7.3-ESM": {"description": "ESM failure destinations configured", "severity": "MEDIUM", "check": lambda r: r.get("event_source_mappings", {}).get("missing_failure_dest_count", 1) == 0 if r.get("event_source_mappings", {}).get("has_mappings", False) else True},
                    "SOC2-A1.1-CONCUR": {"description": "Reserved concurrency for availability", "severity": "MEDIUM", "check": lambda r: r.get("reserved_concurrency", {}).get("configured", False)},
                },
            },
            "ISO27001": {
                "name": "ISO 27001:2022",
                "controls": {
                    "A.5.15": {"description": "Access control - restrict public access", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "A.5.21": {"description": "Information security in the ICT supply chain - external layer verification", "severity": "MEDIUM", "check": lambda r: not r.get("layers", {}).get("has_external_layers", True)},
                    "A.8.2": {"description": "Privileged access rights - unique execution role per function", "severity": "HIGH", "check": lambda r: not r.get("shared_role", {}).get("is_shared", True)},
                    "A.8.3": {"description": "Information access restriction - least privilege", "severity": "HIGH", "check": lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)},
                    "A.8.5": {"description": "Secure authentication - function URL auth", "severity": "CRITICAL", "check": lambda r: not r.get("function_url", {}).get("is_public", True)},
                    "A.8.7": {"description": "Protection against malware - code signing (N/A for container images)", "severity": "MEDIUM", "check": lambda r: True if not r.get("code_signing", {}).get("applicable", True) else r.get("code_signing", {}).get("configured", False)},
                    "A.8.12": {"description": "Data leakage prevention - no secrets in env vars", "severity": "CRITICAL", "check": lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)},
                    "A.8.15-T": {"description": "Logging - tracing enabled", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "A.8.15-L": {"description": "Logging - log group retention configured", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                    "A.8.20": {"description": "Network security - VPC configuration", "severity": "LOW", "check": lambda r: r.get("vpc_config", {}).get("in_vpc", False)},
                    "A.8.24": {"description": "Use of cryptography - KMS on env vars", "severity": "MEDIUM", "check": lambda r: r.get("environment_secrets", {}).get("has_kms_key", False) if r.get("environment_secrets", {}).get("has_env_vars", False) else True},
                },
            },
            "ISO27017": {
                "name": "ISO 27017 Cloud Security",
                "controls": {
                    "CLD.9.5.1": {"description": "Segregation in virtual environments - VPC", "severity": "LOW", "check": lambda r: r.get("vpc_config", {}).get("in_vpc", False)},
                    "CLD.9.5.2": {"description": "Virtual machine hardening - runtime security", "severity": "HIGH", "check": lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")},
                    "CLD.12.1.5": {"description": "Administrator operational security - logging", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                    "CLD.12.4.5": {"description": "Monitoring of cloud services - tracing", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                },
            },
            "ISO27018": {
                "name": "ISO 27018 PII Protection",
                "controls": {
                    "ISO27018-ENC": {"description": "Encryption of PII - KMS on env vars", "severity": "CRITICAL", "check": lambda r: r.get("environment_secrets", {}).get("has_kms_key", False) if r.get("environment_secrets", {}).get("has_env_vars", False) else True},
                    "ISO27018-ACCESS": {"description": "Access to data - restrict public function access", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "ISO27018-AUTH": {"description": "Secure transmission - function URL authentication", "severity": "CRITICAL", "check": lambda r: not r.get("function_url", {}).get("is_public", True)},
                    "ISO27018-TRACE": {"description": "Audit logging - tracing enabled", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "ISO27018-LOG": {"description": "Audit logging - log retention configured", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                },
            },
            "GDPR": {
                "name": "General Data Protection Regulation",
                "controls": {
                    "GDPR-Art5": {"description": "Data integrity and confidentiality - no secrets in env vars", "severity": "CRITICAL", "check": lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)},
                    "GDPR-Art25": {"description": "Data protection by design - least privilege execution role", "severity": "HIGH", "check": lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)},
                    "GDPR-Art32-1a-KMS": {"description": "Art 32(1)(a) - encryption of personal data (KMS on env vars)", "severity": "HIGH", "check": lambda r: r.get("environment_secrets", {}).get("has_kms_key", False) if r.get("environment_secrets", {}).get("has_env_vars", False) else True},
                    "GDPR-Art32-1b-ACCESS": {"description": "Art 32(1)(b) - confidentiality (restrict public access)", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "GDPR-Art32-1b-CONCUR": {"description": "Art 32(1)(b) - resilience (reserved concurrency)", "severity": "MEDIUM", "check": lambda r: r.get("reserved_concurrency", {}).get("configured", False)},
                    "GDPR-Art32-1b-ESM": {"description": "Art 32(1)(b) - resilience (ESM failure destinations)", "severity": "MEDIUM", "check": lambda r: r.get("event_source_mappings", {}).get("missing_failure_dest_count", 1) == 0 if r.get("event_source_mappings", {}).get("has_mappings", False) else True},
                    "GDPR-Art32-1b-TRACE": {"description": "Art 32(1)(b) - integrity signal (X-Ray tracing)", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "GDPR-Art32-1b-LOG": {"description": "Art 32(1)(b) - availability/integrity (CloudWatch log retention for forensic analysis)", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                },
            },
            "NIST-800-53": {
                "name": "NIST 800-53 Rev5",
                "controls": {
                    "AC-3": {"description": "Access enforcement - no public access", "severity": "CRITICAL", "check": lambda r: not r.get("resource_policy", {}).get("is_public", True)},
                    "AC-6": {"description": "Least privilege - execution role", "severity": "HIGH", "check": lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)},
                    "AC-17": {"description": "Remote access - function URL auth", "severity": "CRITICAL", "check": lambda r: not r.get("function_url", {}).get("is_public", True)},
                    "AU-2": {"description": "Event logging - tracing enabled", "severity": "MEDIUM", "check": lambda r: r.get("tracing", {}).get("enabled", False)},
                    "AU-9": {"description": "Protection of audit info - log retention", "severity": "MEDIUM", "check": lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)},
                    "CM-7": {"description": "Least functionality - no deprecated runtimes", "severity": "HIGH", "check": lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")},
                    "IA-5": {"description": "Authenticator management - no secrets in env vars", "severity": "CRITICAL", "check": lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)},
                    "SC-5": {"description": "DoS protection - reserved concurrency", "severity": "MEDIUM", "check": lambda r: r.get("reserved_concurrency", {}).get("configured", False)},
                    "SC-7": {"description": "Boundary protection - VPC configuration", "severity": "LOW", "check": lambda r: r.get("vpc_config", {}).get("in_vpc", False)},
                    "SC-7(5)": {"description": "Boundary protection - deny by default / allow by exception (SG egress controls)", "severity": "MEDIUM", "check": lambda r: not r.get("security_groups", {}).get("unrestricted_egress", True) if r.get("security_groups", {}).get("applicable", False) else True},
                    "SI-7": {"description": "Software integrity - code signing (N/A for container images)", "severity": "MEDIUM", "check": lambda r: True if not r.get("code_signing", {}).get("applicable", True) else r.get("code_signing", {}).get("configured", False)},
                    "SR-3": {"description": "Supply chain protection - layer verification", "severity": "MEDIUM", "check": lambda r: not r.get("layers", {}).get("has_external_layers", True)},
                },
            },
        }

    def check_function_compliance(
        self, checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate all frameworks against function checks."""
        results = {}
        for fw_key, framework in self.frameworks.items():
            results[fw_key] = self._check_framework(
                checks, framework
            )
        return results

    def _check_framework(
        self, checks: Dict[str, Any], framework: Dict
    ) -> Dict[str, Any]:
        """Evaluate a single framework against check results."""
        passed = []
        failed = []
        for ctrl_id, ctrl in framework["controls"].items():
            try:
                result = ctrl["check"](checks)
            except Exception:
                result = False  # fail-closed
            entry = {
                "control_id": ctrl_id,
                "description": ctrl["description"],
                "severity": ctrl["severity"],
            }
            if result:
                passed.append(entry)
            else:
                failed.append(entry)
        total = len(passed) + len(failed)
        return {
            "is_compliant": len(failed) == 0,
            "passed_controls": len(passed),
            "failed_controls": len(failed),
            "total_controls": total,
            "compliance_percentage": round(
                len(passed) / total * 100, 1
            )
            if total > 0
            else 0,
            "passed": passed,
            "failed": failed,
        }
