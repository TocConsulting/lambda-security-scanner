"""Base class for all security checkers."""

import logging

import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any


logger = logging.getLogger("lambda_security_scanner")


class BaseChecker:
    """Base class for all security checkers.

    Provides thread-safe AWS client creation via session_factory
    and standardized error handling.
    """

    def __init__(self, session_factory=None):
        """Initialize the checker with optional session factory.

        Args:
            session_factory: Callable that returns a boto3 session
                (for thread safety) or a boto3 session object
                (for backward compatibility).
        """
        self.session_factory = session_factory

    def get_client(self, service_name: str, region_name: str = None):
        """Get AWS client for the specified service.

        Uses the thread-safe session factory to create clients,
        ensuring each thread gets its own session.

        Args:
            service_name: AWS service name (e.g., 'lambda', 'iam')
            region_name: AWS region name (optional)

        Returns:
            boto3 client for the service
        """
        if self.session_factory:
            session = (
                self.session_factory()
                if callable(self.session_factory)
                else self.session_factory
            )
            kwargs = (
                {"region_name": region_name} if region_name else {}
            )
            return session.client(service_name, **kwargs)
        else:
            kwargs = (
                {"region_name": region_name} if region_name else {}
            )
            return boto3.client(service_name, **kwargs)

    def handle_client_error(
        self, e: ClientError, default_response: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Handle ClientError exceptions consistently.

        Logs the error and returns a safe default response dict.
        Special handling for AccessDeniedException and
        ResourceNotFoundException.

        Args:
            e: ClientError exception
            default_response: Default response dict to return

        Returns:
            Error response dict with 'error' key
        """
        error_code = e.response.get("Error", {}).get(
            "Code", "Unknown"
        )
        error_msg = str(e)

        if error_code in (
            "AccessDeniedException",
            "AccessDenied",
            "UnauthorizedOperation",
            "AuthFailure",
        ):
            logger.warning(
                f"Access denied ({error_code}): {error_msg} - "
                "scan will continue with limited results"
            )
        elif error_code == "ResourceNotFoundException":
            logger.debug(
                f"Resource not found (expected): {error_msg}"
            )
        else:
            logger.warning(f"AWS API error: {error_msg}")

        if default_response is None:
            default_response = {
                "error": error_msg,
            }
        else:
            default_response["error"] = error_msg

        return default_response
