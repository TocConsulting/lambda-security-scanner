#!/usr/bin/env python3
"""Lambda Security Scanner - Main orchestrator with multi-threading
and compliance mapping."""

import csv
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Any

import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .compliance import ComplianceChecker
from .html_reporter import HTMLReporter
from .utils import (
    setup_logging,
    calculate_security_score,
    get_severity_color,
)

from .checks.function_config import FunctionConfigChecker
from .checks.access_control import AccessControlChecker
from .checks.network_security import NetworkSecurityChecker
from .checks.logging_monitoring import LoggingMonitoringChecker
from .checks.code_security import CodeSecurityChecker


class LambdaSecurityScanner:
    """Lambda Security Scanner driving all security checks.

    Facade pattern: orchestrates scanning across 5 checker modules,
    manages thread pool, progress display, and report generation.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        output_dir: str = "./output",
        max_workers: int = 5,
        quiet: bool = False,
    ):
        self.region = region
        self.profile = profile
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.quiet = quiet
        self.console = Console(quiet=quiet)

        os.makedirs(output_dir, exist_ok=True)
        # Preserve any log level already set by caller
        # (e.g. --debug in cli.py sets DEBUG before __init__)
        import logging as _logging
        _existing = _logging.getLogger(
            "lambda_security_scanner"
        ).level
        _level = (
            _existing
            if _existing != _logging.NOTSET
            else _logging.INFO
        )
        self.logger = setup_logging(output_dir, _level)

        # Thread safety
        self._thread_local = threading.local()

        # Main thread session
        try:
            self._session = self._create_session()
            self.lambda_client = self._session.client(
                "lambda", region_name=region
            )
            self.account_id = self._get_account_id()
        except NoCredentialsError:
            self.logger.error(
                "No AWS credentials found. "
                "Please configure your credentials."
            )
            raise

        # 5 checker modules with session factory
        self.config_checker = FunctionConfigChecker(
            self._get_thread_session
        )
        self.access_checker = AccessControlChecker(
            self._get_thread_session
        )
        self.network_checker = NetworkSecurityChecker(
            self._get_thread_session
        )
        self.logging_checker = LoggingMonitoringChecker(
            self._get_thread_session
        )
        self.code_checker = CodeSecurityChecker(
            self._get_thread_session
        )

        # Compliance & reporting
        self.compliance_checker = ComplianceChecker()
        self.html_reporter = HTMLReporter()

    def _create_session(self) -> boto3.Session:
        if self.profile:
            return boto3.Session(
                profile_name=self.profile,
                region_name=self.region,
            )
        return boto3.Session(region_name=self.region)

    def _get_thread_session(self) -> boto3.Session:
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = (
                self._create_session()
            )
        return self._thread_local.session

    def _get_account_id(self) -> str:
        try:
            sts = self._session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as e:
            self.logger.debug(
                f"Could not determine account ID: {e}"
            )
            return "unknown"

    # ============================================================
    # Function Enumeration
    # ============================================================

    def get_all_functions(self) -> List[Dict[str, Any]]:
        """Retrieve all Lambda functions using pagination."""
        try:
            paginator = self.lambda_client.get_paginator(
                "list_functions"
            )
            functions = []
            for page in paginator.paginate():
                functions.extend(
                    page.get("Functions", [])
                )
            self.logger.info(
                f"Found {len(functions)} Lambda functions "
                f"in account {self.account_id}"
            )
            return functions
        except Exception as e:
            self.logger.error(
                f"Error retrieving Lambda functions: {e}"
            )
            return []

    # ============================================================
    # Per-Function Scanning
    # ============================================================

    def scan_function(
        self,
        func_config: Dict,
        all_role_arns: List[str],
        progress=None,
        task=None,
    ) -> Dict[str, Any]:
        """Run all 19 checks for a single function."""
        func_name = func_config.get(
            "FunctionName", "unknown"
        )
        func_arn = func_config.get("FunctionArn", "")
        role_arn = func_config.get("Role", "")
        package_type = func_config.get(
            "PackageType", "Zip"
        )

        try:
            # Build checks dict
            checks = {}

            # A. Function Configuration (A.1-A.7)
            checks["runtime"] = (
                self.config_checker.check_runtime(
                    func_config
                )
            )
            checks["timeout"] = (
                self.config_checker.check_timeout(
                    func_config
                )
            )
            checks["environment_secrets"] = (
                self.config_checker.check_environment_secrets(
                    func_config
                )
            )
            checks["ephemeral_storage"] = (
                self.config_checker.check_ephemeral_storage(
                    func_config
                )
            )
            checks["layers"] = (
                self.config_checker.check_layers(
                    func_config, self.account_id
                )
            )
            checks["tracing"] = (
                self.config_checker.check_tracing(
                    func_config
                )
            )
            checks["dead_letter_config"] = (
                self.config_checker.check_dead_letter_config(
                    func_config
                )
            )

            # B. Access Control (B.1-B.5)
            checks["resource_policy"] = (
                self.access_checker.check_resource_policy(
                    func_name, self.region
                )
            )
            checks["function_url"] = (
                self.access_checker.check_function_url(
                    func_name, self.region
                )
            )
            checks["function_url_cors"] = (
                self.access_checker.check_function_url_cors(
                    checks["function_url"]
                )
            )
            checks["execution_role"] = (
                self.access_checker.check_execution_role(
                    role_arn, self.region
                )
            )
            checks["shared_role"] = (
                self.access_checker.check_shared_role(
                    role_arn, all_role_arns
                )
            )

            # C. Network Security (C.1-C.3)
            checks["vpc_config"] = (
                self.network_checker.check_vpc_config(
                    func_config
                )
            )
            checks["multi_az"] = (
                self.network_checker.check_multi_az(
                    checks["vpc_config"], self.region
                )
            )
            checks["security_groups"] = (
                self.network_checker.check_security_groups(
                    checks["vpc_config"], self.region
                )
            )

            # D. Logging & Monitoring (D.1-D.2)
            checks["log_group"] = (
                self.logging_checker.check_log_group(
                    func_name, self.region, func_config
                )
            )
            checks["reserved_concurrency"] = (
                self.logging_checker.check_reserved_concurrency(
                    func_name, self.region
                )
            )

            # E. Code & Supply Chain (E.1-E.2)
            checks["code_signing"] = (
                self.code_checker.check_code_signing(
                    func_name, self.region, package_type
                )
            )
            checks["event_source_mappings"] = (
                self.code_checker.check_event_source_mappings(
                    func_name, self.region
                )
            )

            # Analyze issues
            issues = self._analyze_issues(checks)

            # Calculate score
            security_score = calculate_security_score(
                checks
            )

            # Compliance
            compliance_status = (
                self.compliance_checker
                .check_function_compliance(checks)
            )

            # Determine public status
            is_public = (
                checks.get("resource_policy", {}).get(
                    "is_public", False
                )
                or checks.get("function_url", {}).get(
                    "is_public", False
                )
            )

            result = {
                "function_name": func_name,
                "function_arn": func_arn,
                "region": self.region,
                "account_id": self.account_id,
                **checks,
                "is_public": is_public,
                "issues": issues,
                "issue_count": len(issues),
                "has_critical_issues": any(
                    i["severity"] == "CRITICAL"
                    for i in issues
                ),
                "has_high_issues": any(
                    i["severity"] == "HIGH"
                    for i in issues
                ),
                "security_score": security_score,
                "compliance_status": compliance_status,
            }

            if progress and task:
                progress.advance(task)

            return result

        except Exception as e:
            self.logger.error(
                f"Error scanning function {func_name}: {e}"
            )
            if progress and task:
                progress.advance(task)
            return self._error_result(
                func_name, str(e)
            )

    def _analyze_issues(
        self, checks: Dict
    ) -> List[Dict[str, Any]]:
        """Generate issue list from checks dict."""
        issues = []

        def add(severity, issue_type, desc, rec):
            issues.append({
                "severity": severity,
                "issue_type": issue_type,
                "description": desc,
                "recommendation": rec,
            })

        # A.1 Runtime
        rt = checks.get("runtime", {})
        status = rt.get("status", "supported")
        if status == "blocked":
            add(
                "CRITICAL", "blocked_runtime",
                f"Runtime {rt.get('runtime')} is blocked",
                "Migrate to a supported runtime "
                "immediately",
            )
        elif status == "deprecated":
            add(
                "HIGH", "deprecated_runtime",
                f"Runtime {rt.get('runtime')} is "
                "deprecated",
                "Migrate to a supported runtime",
            )
        elif status == "near_eol":
            add(
                "LOW", "near_eol_runtime",
                f"Runtime {rt.get('runtime')} approaching "
                f"EOL ({rt.get('eol_date')})",
                "Plan migration to a newer runtime",
            )

        # A.2 Timeout
        if checks.get("timeout", {}).get(
            "is_max_timeout"
        ):
            add(
                "LOW", "max_timeout",
                "Function has maximum timeout (900s)",
                "Review and set an appropriate timeout",
            )

        # A.3 Secrets
        env = checks.get("environment_secrets", {})
        if env.get("has_secrets"):
            if not env.get("has_kms_key"):
                add(
                    "CRITICAL", "env_secrets_no_kms",
                    "Secrets found in environment "
                    "variables without KMS encryption",
                    "Move secrets to Secrets Manager or "
                    "SSM Parameter Store",
                )
            else:
                add(
                    "HIGH", "env_secrets_with_kms",
                    "Secrets found in environment "
                    "variables (KMS encrypted)",
                    "Move secrets to Secrets Manager or "
                    "SSM Parameter Store",
                )

        # A.4 Ephemeral storage
        if checks.get("ephemeral_storage", {}).get(
            "is_large"
        ):
            add(
                "LOW", "large_ephemeral_storage",
                "Ephemeral storage exceeds 512 MB",
                "Ensure sensitive data in /tmp is "
                "cleaned",
            )

        # A.5 External layers
        if checks.get("layers", {}).get(
            "has_external_layers"
        ):
            add(
                "MEDIUM", "external_layers",
                "Function uses external Lambda layers",
                "Verify external layers are from "
                "trusted sources",
            )

        # A.6 Tracing (observability hygiene, not a direct security gap)
        if not checks.get("tracing", {}).get("enabled"):
            add(
                "LOW", "tracing_disabled",
                "X-Ray tracing is disabled",
                "Enable Active tracing for distributed "
                "tracing",
            )

        # A.7 DLQ (resilience for async invokes, not a direct security gap)
        if not checks.get("dead_letter_config", {}).get(
            "configured"
        ):
            add(
                "LOW", "no_dlq",
                "No dead letter queue configured",
                "Configure an SQS or SNS dead letter queue "
                "for async invocations",
            )

        # B.1 Resource policy
        if checks.get("resource_policy", {}).get(
            "is_public"
        ):
            add(
                "CRITICAL", "public_resource_policy",
                "Resource policy allows public access",
                "Restrict the resource policy Principal",
            )

        # B.2 Function URL
        if checks.get("function_url", {}).get(
            "is_public"
        ):
            add(
                "CRITICAL", "public_function_url",
                "Function URL has no authentication "
                "(AuthType: NONE)",
                "Set AuthType to AWS_IAM or remove "
                "the URL",
            )

        # B.3 CORS
        if checks.get("function_url_cors", {}).get(
            "allow_all_origins"
        ):
            add(
                "HIGH", "cors_wildcard",
                "Function URL CORS allows all origins",
                "Restrict AllowOrigins to specific "
                "domains",
            )

        # B.4 Execution role
        role = checks.get("execution_role", {})
        if role.get("has_full_admin"):
            add(
                "CRITICAL", "admin_execution_role",
                "Execution role has admin-equivalent access "
                "(AdministratorAccess/PowerUserAccess or '*')",
                "Apply least privilege to the role",
            )
        elif role.get("has_wildcard_actions"):
            add(
                "HIGH", "service_wildcard_execution_role",
                "Execution role grants service-level wildcard "
                "actions (e.g. s3:*)",
                "Restrict actions to the specific APIs the "
                "function needs",
            )
        elif role.get("has_privilege_escalation"):
            add(
                "HIGH", "privilege_escalation_role",
                "Execution role has privilege escalation "
                "permissions",
                "Remove dangerous IAM permissions",
            )

        # B.5 Shared role
        if checks.get("shared_role", {}).get("is_shared"):
            add(
                "HIGH", "shared_role",
                "Execution role is shared across "
                "functions",
                "Create unique roles per function",
            )

        # C.1 VPC
        if not checks.get("vpc_config", {}).get("in_vpc"):
            add(
                "LOW", "no_vpc",
                "Function is not deployed in a VPC",
                "Consider VPC deployment for sensitive "
                "workloads",
            )

        # C.2 Multi-AZ
        ma = checks.get("multi_az", {})
        if ma.get("applicable") and not ma.get(
            "is_multi_az"
        ):
            add(
                "MEDIUM", "single_az",
                "VPC function deployed in single AZ",
                "Deploy across at least 2 AZs",
            )

        # C.3 SG egress
        sg = checks.get("security_groups", {})
        if sg.get("applicable") and sg.get(
            "unrestricted_egress"
        ):
            add(
                "MEDIUM", "unrestricted_egress",
                "Security group allows unrestricted "
                "egress",
                "Restrict outbound rules to required "
                "destinations",
            )

        # D.1 Log group
        lg = checks.get("log_group", {})
        if not lg.get("exists"):
            add(
                "MEDIUM", "missing_log_group",
                "CloudWatch log group does not exist",
                "Invoke function or create log group "
                "manually",
            )
        elif not lg.get("has_retention"):
            add(
                "MEDIUM", "no_log_retention",
                "Log group has no retention policy",
                "Set a log retention period",
            )

        # D.2 Reserved concurrency
        rc = checks.get("reserved_concurrency", {})
        if not rc.get("configured"):
            add(
                "LOW", "no_reserved_concurrency",
                "No reserved concurrency configured",
                "Set reserved concurrency to prevent "
                "account-wide throttling (especially for "
                "public functions)",
            )
        elif rc.get("is_disabled"):
            add(
                "INFO", "disabled_function",
                "Function is disabled "
                "(reserved concurrency = 0)",
                "Remove or increase reserved concurrency "
                "if the function should be active",
            )

        # E.1 Code signing — only applies to Zip-packaged functions.
        # Container image functions get applicable=False from the
        # checker and are skipped here (signing is N/A for images).
        cs = checks.get("code_signing", {})
        if cs.get("applicable", True):
            if not cs.get("configured"):
                add(
                    "MEDIUM", "no_code_signing",
                    "No code signing configuration",
                    "Enable code signing for deployment "
                    "integrity",
                )
            elif not cs.get("is_enforced"):
                add(
                    "LOW", "code_signing_warn",
                    "Code signing uses Warn policy instead "
                    "of Enforce",
                    "Set UntrustedArtifactOnDeployment to "
                    "Enforce",
                )

        # E.2 ESM
        esm = checks.get("event_source_mappings", {})
        if (
            esm.get("has_mappings")
            and esm.get(
                "missing_failure_dest_count", 0
            ) > 0
        ):
            add(
                "MEDIUM", "esm_no_failure_dest",
                f"{esm['missing_failure_dest_count']} "
                "event source mapping(s) without "
                "failure destination",
                "Configure OnFailure destination for "
                "each ESM",
            )

        # Composite: Public + No concurrency
        is_public = (
            checks.get("resource_policy", {}).get(
                "is_public"
            )
            or checks.get("function_url", {}).get(
                "is_public"
            )
        )
        if is_public and not rc.get("configured"):
            add(
                "CRITICAL", "public_no_concurrency",
                "Public function without reserved "
                "concurrency - financial exhaustion risk",
                "Set reserved concurrency and review "
                "public access",
            )

        # Composite: Public URL + CORS wildcard
        if (
            checks.get("function_url", {}).get(
                "is_public"
            )
            and checks.get(
                "function_url_cors", {}
            ).get("allow_all_origins")
        ):
            add(
                "CRITICAL", "public_url_cors_wildcard",
                "Public function URL with wildcard "
                "CORS - maximally exposed",
                "Restrict CORS origins and add "
                "authentication",
            )

        # Surface checks that errored (e.g. AccessDenied) so the user
        # knows the corresponding finding is "could not evaluate" rather
        # than "confirmed clean". Without this, an under-permissioned
        # scanning role yields an artificially clean report.
        for check_name, check_val in checks.items():
            if isinstance(check_val, dict) and check_val.get("error"):
                add(
                    "ERROR", "check_failed",
                    f"Check '{check_name}' could not run: "
                    f"{check_val['error']}",
                    "Grant the scanning role the missing permission, "
                    "or scope the scan to functions you can audit.",
                )

        return issues

    def _error_result(
        self, func_name: str, error_msg: str
    ) -> Dict[str, Any]:
        """Create safe error result dict."""
        return {
            "function_name": func_name,
            "function_arn": "",
            "error": error_msg,
            "scan_error": True,
            "issues": [{
                "severity": "ERROR",
                "issue_type": "scan_error",
                "description": (
                    f"Scan failed: {error_msg}"
                ),
                "recommendation": (
                    "Check permissions and retry"
                ),
            }],
            "issue_count": 1,
            "security_score": None,
            "compliance_status": {},
        }

    # ============================================================
    # Parallel Scanning
    # ============================================================

    def scan_all_functions(
        self, functions: List[Dict] = None
    ) -> List[Dict[str, Any]]:
        """Scan all functions in parallel."""
        if functions is None:
            functions = self.get_all_functions()

        if not functions:
            return []

        # Collect all role ARNs for B.5 shared role check
        all_role_arns = [
            f.get("Role", "") for f in functions
        ]

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn(
                "[progress.description]"
                "{task.description}"
            ),
            TextColumn(
                "[cyan]{task.completed}/{task.total}"
            ),
            console=self.console,
            disable=self.quiet,
        ) as progress:
            task = progress.add_task(
                "Scanning Lambda functions...",
                total=len(functions),
            )

            with ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as executor:
                future_to_func = {
                    executor.submit(
                        self.scan_function,
                        func,
                        all_role_arns,
                        progress,
                        task,
                    ): func
                    for func in functions
                }

                for future in as_completed(
                    future_to_func
                ):
                    func = future_to_func[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        func_name = func.get(
                            "FunctionName", "unknown"
                        )
                        self.logger.error(
                            "Scan failed for "
                            f"{func_name}: {e}"
                        )
                        results.append(
                            self._error_result(
                                func_name, str(e)
                            )
                        )

        # Sort by score ascending (worst first)
        results.sort(
            key=lambda r: (
                r.get("security_score") is not None,
                r.get("security_score", 0) or 0,
            )
        )

        return results

    # ============================================================
    # Report Generation
    # ============================================================

    def generate_reports(
        self,
        results: List[Dict],
        output_format: str = "all",
    ) -> Dict[str, str]:
        """Generate reports in specified format."""
        report_files = {}
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        if output_format in ("json", "all"):
            report_files["json"] = self._export_json(
                results, timestamp
            )
        if output_format in ("csv", "all"):
            report_files["csv"] = self._export_csv(
                results, timestamp
            )
        if output_format in ("html", "all"):
            report_files["html"] = self._export_html(
                results, timestamp
            )
        # Always export compliance
        report_files["compliance"] = (
            self._export_compliance(results, timestamp)
        )

        return report_files

    def _export_json(
        self, results: List[Dict], timestamp: str
    ) -> str:
        filepath = os.path.join(
            self.output_dir,
            f"lambda_scan_{self.region}_{timestamp}.json",
        )
        # Match the documented schema and the s3/ec2 scanner family:
        # a top-level object with a summary and the per-function results.
        payload = {
            "summary": {
                "scan_time": datetime.now().isoformat(),
                **self._build_summary(results),
            },
            "results": results,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                payload, f, indent=2, default=str
            )
        return filepath

    def _export_csv(
        self, results: List[Dict], timestamp: str
    ) -> str:
        filepath = os.path.join(
            self.output_dir,
            f"lambda_scan_{self.region}_{timestamp}.csv",
        )
        frameworks = [
            "AWS-FSBP", "CIS", "PCI-DSS-v4.0.1",
            "HIPAA", "SOC2", "ISO27001", "ISO27017",
            "ISO27018", "GDPR", "NIST-800-53",
        ]
        fieldnames = [
            "function_name", "function_arn", "region",
            "runtime", "security_score", "issue_count",
            "is_public",
        ] + [f"{fw}_compliant" for fw in frameworks]

        with open(
            filepath, "w", newline="",
            encoding="utf-8",
        ) as f:
            writer = csv.DictWriter(
                f, fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()
            for r in results:
                row = {
                    "function_name": r.get(
                        "function_name"
                    ),
                    "function_arn": r.get(
                        "function_arn"
                    ),
                    "region": r.get("region"),
                    "runtime": r.get(
                        "runtime", {}
                    ).get("runtime", "N/A"),
                    "security_score": r.get(
                        "security_score"
                    ),
                    "issue_count": r.get(
                        "issue_count", 0
                    ),
                    "is_public": r.get(
                        "is_public", False
                    ),
                }
                cs = r.get("compliance_status", {})
                for fw in frameworks:
                    row[f"{fw}_compliant"] = cs.get(
                        fw, {}
                    ).get("is_compliant", False)
                writer.writerow(row)
        return filepath

    def _export_html(
        self, results: List[Dict], timestamp: str
    ) -> str:
        filepath = os.path.join(
            self.output_dir,
            f"lambda_scan_{self.region}_{timestamp}.html",
        )
        summary = self._build_summary(results)
        self.html_reporter.generate_report(
            results, summary, filepath
        )
        return filepath

    def _export_compliance(
        self, results: List[Dict], timestamp: str
    ) -> str:
        filepath = os.path.join(
            self.output_dir,
            "lambda_compliance_"
            f"{self.region}_{timestamp}.json",
        )
        valid = [
            r for r in results
            if not r.get("scan_error", False)
        ]
        compliance_data = {
            "account_id": self.account_id,
            "region": self.region,
            "scan_timestamp": timestamp,
            "total_functions": len(results),
            "scanned_functions": len(valid),
            "frameworks": {},
        }
        frameworks = [
            "AWS-FSBP", "CIS", "PCI-DSS-v4.0.1",
            "HIPAA", "SOC2", "ISO27001", "ISO27017",
            "ISO27018", "GDPR", "NIST-800-53",
        ]
        for fw in frameworks:
            compliant = 0
            total = 0
            for r in valid:
                fw_status = r.get(
                    "compliance_status", {}
                ).get(fw, {})
                if fw_status:
                    total += 1
                    if fw_status.get("is_compliant"):
                        compliant += 1
            compliance_data["frameworks"][fw] = {
                "compliant_functions": compliant,
                "total_functions": total,
                "compliance_percentage": round(
                    compliant / total * 100, 1
                ) if total > 0 else 0,
            }

        with open(
            filepath, "w", encoding="utf-8"
        ) as f:
            json.dump(compliance_data, f, indent=2)
        return filepath

    def _build_summary(
        self, results: List[Dict]
    ) -> Dict[str, Any]:
        valid = [
            r for r in results
            if not r.get("scan_error", False)
        ]
        scores = [
            r.get("security_score", 0)
            for r in valid
            if r.get("security_score") is not None
        ]
        return {
            "account_id": self.account_id,
            "region": self.region,
            "total_functions": len(results),
            "scanned_functions": len(valid),
            "error_functions": (
                len(results) - len(valid)
            ),
            "average_security_score": round(
                sum(scores) / len(scores), 1
            ) if scores else 0,
            "public_functions": sum(
                1 for r in valid
                if r.get("is_public", False)
            ),
            "functions_with_secrets": sum(
                1 for r in valid
                if r.get(
                    "environment_secrets", {}
                ).get("has_secrets", False)
            ),
            "functions_with_deprecated_runtime": sum(
                1 for r in valid
                if r.get("runtime", {}).get(
                    "status"
                ) in ("deprecated", "blocked")
            ),
        }

    # ============================================================
    # Console Summary
    # ============================================================

    def print_summary(
        self, results: List[Dict]
    ) -> None:
        """Print Rich formatted console summary."""
        summary = self._build_summary(results)

        # Overall Metrics
        table = Table(title="Overall Metrics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        table.add_row(
            "Total Functions",
            str(summary["total_functions"]),
        )
        table.add_row(
            "Scanned",
            str(summary["scanned_functions"]),
        )
        table.add_row(
            "Errors",
            str(summary["error_functions"]),
        )
        table.add_row(
            "Average Score",
            f"{summary['average_security_score']:.1f}",
        )
        table.add_row(
            "Public Functions",
            str(summary["public_functions"]),
        )
        table.add_row(
            "Functions with Secrets",
            str(summary["functions_with_secrets"]),
        )
        table.add_row(
            "Deprecated Runtimes",
            str(
                summary[
                    "functions_with_deprecated_runtime"
                ]
            ),
        )
        self.console.print(table)

        # Lowest Scoring Functions (top 5)
        valid = [
            r for r in results
            if not r.get("scan_error", False)
        ]
        if valid:
            worst = sorted(
                valid,
                key=lambda r: (
                    r.get("security_score", 0) or 0
                ),
            )[:5]

            table2 = Table(
                title="Lowest Scoring Functions"
            )
            table2.add_column(
                "Function", style="cyan"
            )
            table2.add_column(
                "Score", justify="right"
            )
            table2.add_column(
                "Issues", justify="right"
            )
            table2.add_column("Runtime")

            for r in worst:
                score = (
                    r.get("security_score", 0) or 0
                )
                color = (
                    "red" if score < 50
                    else "yellow" if score < 70
                    else "green"
                )
                table2.add_row(
                    r.get("function_name", ""),
                    f"[{color}]{score}[/{color}]",
                    str(r.get("issue_count", 0)),
                    r.get("runtime", {}).get(
                        "runtime", "N/A"
                    ),
                )
            self.console.print(table2)

        # Compliance Summary
        frameworks = [
            "AWS-FSBP", "CIS", "PCI-DSS-v4.0.1",
            "HIPAA", "SOC2", "ISO27001", "ISO27017",
            "ISO27018", "GDPR", "NIST-800-53",
        ]
        table3 = Table(title="Compliance Summary")
        table3.add_column("Framework", style="cyan")
        table3.add_column(
            "Compliant", justify="right"
        )
        table3.add_column(
            "Non-Compliant", justify="right"
        )
        table3.add_column(
            "Avg %", justify="right"
        )

        for fw in frameworks:
            pcts = []
            compliant = 0
            total = 0
            for r in valid:
                fw_status = r.get(
                    "compliance_status", {}
                ).get(fw, {})
                if fw_status:
                    total += 1
                    if fw_status.get("is_compliant"):
                        compliant += 1
                    pcts.append(
                        fw_status.get(
                            "compliance_percentage",
                            0,
                        )
                    )
            avg_pct = (
                round(sum(pcts) / len(pcts), 1)
                if pcts else 0
            )
            color = (
                "red" if avg_pct < 50
                else "yellow" if avg_pct < 70
                else "green"
            )
            table3.add_row(
                fw,
                str(compliant),
                str(total - compliant),
                f"[{color}]{avg_pct}%[/{color}]",
            )

        self.console.print(table3)
