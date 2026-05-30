"""Lambda Security Scanner - Comprehensive AWS Lambda security
auditing tool with multi-framework compliance mapping."""

__version__ = "1.0.0"
__author__ = "Toc Consulting"
__email__ = "tarek@tocconsulting.fr"

from .scanner import LambdaSecurityScanner
from .compliance import ComplianceChecker

__all__ = ["LambdaSecurityScanner", "ComplianceChecker"]
