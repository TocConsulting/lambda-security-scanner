"""HTML report generator for Lambda Security Scanner."""

import os
from datetime import datetime
from typing import Any, Dict, List

from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from .utils import format_datetime, get_severity_color


class HTMLReporter:
    """Generate HTML dashboard reports."""

    def __init__(self, template_dir: str = None):
        if template_dir is None:
            template_dir = os.path.join(
                os.path.dirname(__file__), "templates"
            )
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(
                ["html", "xml"]
            ),
        )
        self.env.filters["format_datetime"] = (
            format_datetime
        )
        self.env.filters["get_severity_color"] = (
            get_severity_color
        )

    def _calculate_chart_data(
        self, results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        valid = [
            r
            for r in results
            if not r.get("scan_error", False)
        ]
        if not valid:
            return {
                "security_score_distribution": [
                    0, 0, 0, 0, 0,
                ],
                "compliance_labels": [],
                "compliance_percentages": [],
                "severity_counts": [0, 0, 0, 0, 0],
            }

        score_ranges = [0, 0, 0, 0, 0]
        for r in valid:
            score = r.get("security_score", 0) or 0
            if score <= 20:
                score_ranges[0] += 1
            elif score <= 40:
                score_ranges[1] += 1
            elif score <= 60:
                score_ranges[2] += 1
            elif score <= 80:
                score_ranges[3] += 1
            else:
                score_ranges[4] += 1

        frameworks = [
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
        compliance_labels = []
        compliance_percentages = []
        for fw in frameworks:
            pcts = []
            for r in valid:
                fw_status = r.get(
                    "compliance_status", {}
                ).get(fw, {})
                if fw_status:
                    pcts.append(
                        fw_status.get(
                            "compliance_percentage", 0
                        )
                    )
            if pcts:
                compliance_labels.append(fw)
                compliance_percentages.append(
                    round(sum(pcts) / len(pcts), 1)
                )

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for r in valid:
            for issue in r.get("issues", []):
                sev = issue.get("severity", "INFO")
                if sev in severity_counts:
                    severity_counts[sev] += 1

        return {
            "security_score_distribution": score_ranges,
            "compliance_labels": compliance_labels,
            "compliance_percentages": (
                compliance_percentages
            ),
            "severity_counts": [
                severity_counts["CRITICAL"],
                severity_counts["HIGH"],
                severity_counts["MEDIUM"],
                severity_counts["LOW"],
                severity_counts["INFO"],
            ],
        }

    def _calculate_compliance_summary(
        self, results: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        if not results:
            return {}
        frameworks = [
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
        summary = {}
        for fw in frameworks:
            compliant = 0
            total = 0
            pcts = []
            for r in results:
                fw_status = r.get(
                    "compliance_status", {}
                ).get(fw, {})
                if fw_status:
                    total += 1
                    if fw_status.get(
                        "is_compliant", False
                    ):
                        compliant += 1
                    pcts.append(
                        fw_status.get(
                            "compliance_percentage", 0
                        )
                    )
            if total > 0:
                summary[fw] = {
                    "compliant_functions": compliant,
                    "total_functions": total,
                    "non_compliant_functions": (
                        total - compliant
                    ),
                    "compliance_percentage": round(
                        compliant / total * 100, 1
                    ),
                    "average_compliance_percentage": (
                        round(sum(pcts) / len(pcts), 1)
                        if pcts
                        else 0
                    ),
                }
        return summary

    def generate_report(
        self,
        results: List[Dict[str, Any]],
        summary: Dict[str, Any],
        output_file: str,
    ) -> str:
        template = self.env.get_template("report.html")
        valid_results = [
            r
            for r in results
            if not r.get("scan_error", False)
        ]
        chart_data = self._calculate_chart_data(
            valid_results
        )
        compliance_summary = (
            self._calculate_compliance_summary(
                valid_results
            )
        )
        html_content = template.render(
            summary=summary,
            results=valid_results,
            compliance_summary=compliance_summary,
            **chart_data,
        )
        with open(
            output_file, "w", encoding="utf-8"
        ) as f:
            f.write(html_content)
        return output_file
