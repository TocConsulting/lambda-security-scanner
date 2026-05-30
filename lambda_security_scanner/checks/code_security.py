"""Code security checks for Lambda functions (E.1-E.2)."""

import logging
from typing import Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("lambda_security_scanner")


class CodeSecurityChecker(BaseChecker):
    """Check code security configuration for Lambda functions.

    Implements checks E.1 (code signing) and
    E.2 (event source mapping failure destinations).
    """

    def check_code_signing(
        self,
        function_name: str,
        region: str,
        package_type: str = "Zip",
    ) -> Dict:
        """E.1 - Check code signing configuration.

        Skips container image functions (package_type=Image).

        Args:
            function_name: Lambda function name.
            region: AWS region name.
            package_type: "Zip" or "Image".

        Returns:
            Dict with configured, policy, config_arn,
            is_enforced.
        """
        if package_type == "Image":
            # AWS Lambda Code Signing is not supported for container
            # image functions (only Zip packages). Returning
            # applicable=False so scoring/issues skip the check
            # rather than falsely reporting "enforced".
            return {
                "configured": False,
                "policy": None,
                "config_arn": None,
                "is_enforced": False,
                "applicable": False,
            }

        lambda_client = self.get_client("lambda", region)

        try:
            response = (
                lambda_client
                .get_function_code_signing_config(
                    FunctionName=function_name
                )
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get(
                "Code", ""
            )
            if error_code == "ResourceNotFoundException":
                logger.debug(
                    "No code signing config for %s",
                    function_name,
                )
                return {
                    "configured": False,
                    "policy": None,
                    "config_arn": None,
                    "is_enforced": False,
                }
            return self.handle_client_error(
                e,
                {
                    "configured": False,
                    "policy": None,
                    "config_arn": None,
                    "is_enforced": False,
                },
            )

        config_arn = response.get("CodeSigningConfigArn")
        if not config_arn:
            return {
                "configured": False,
                "policy": None,
                "config_arn": None,
                "is_enforced": False,
            }

        try:
            csc_response = (
                lambda_client.get_code_signing_config(
                    CodeSigningConfigArn=config_arn
                )
            )
        except ClientError as e:
            return self.handle_client_error(
                e,
                {
                    "configured": True,
                    "policy": None,
                    "config_arn": config_arn,
                    "is_enforced": False,
                },
            )

        csc = csc_response.get("CodeSigningConfig", {})
        policies = csc.get("CodeSigningPolicies", {})
        policy = policies.get(
            "UntrustedArtifactOnDeployment"
        )

        return {
            "configured": True,
            "policy": policy,
            "config_arn": config_arn,
            "is_enforced": policy == "Enforce",
        }

    def check_event_source_mappings(
        self, function_name: str, region: str
    ) -> Dict:
        """E.2 - Check event source mappings for failure dest.

        Uses paginator to list all event source mappings.

        Args:
            function_name: Lambda function name.
            region: AWS region name.

        Returns:
            Dict with mapping_count, mappings,
            missing_failure_dest_count,
            missing_failure_destinations, has_mappings.
        """
        try:
            lambda_client = self.get_client(
                "lambda", region
            )
            paginator = lambda_client.get_paginator(
                "list_event_source_mappings"
            )
            page_iterator = paginator.paginate(
                FunctionName=function_name
            )
        except ClientError as e:
            return self.handle_client_error(
                e,
                {
                    "mapping_count": 0,
                    "mappings": [],
                    "missing_failure_dest_count": 0,
                    "missing_failure_destinations": [],
                    "has_mappings": False,
                },
            )

        mappings = []
        missing_failure_destinations = []

        try:
            for page in page_iterator:
                for esm in page.get(
                    "EventSourceMappings", []
                ):
                    esm_info = {
                        "EventSourceArn": esm.get(
                            "EventSourceArn"
                        ),
                        "UUID": esm.get("UUID"),
                    }
                    mappings.append(esm_info)

                    dest = (
                        esm.get(
                            "DestinationConfig", {}
                        )
                        .get("OnFailure", {})
                        .get("Destination")
                    )
                    if not dest:
                        missing_failure_destinations.append(
                            esm.get("UUID")
                        )
        except ClientError as e:
            return self.handle_client_error(
                e,
                {
                    "mapping_count": 0,
                    "mappings": [],
                    "missing_failure_dest_count": 0,
                    "missing_failure_destinations": [],
                    "has_mappings": False,
                },
            )

        return {
            "mapping_count": len(mappings),
            "mappings": mappings,
            "missing_failure_dest_count": len(
                missing_failure_destinations
            ),
            "missing_failure_destinations": (
                missing_failure_destinations
            ),
            "has_mappings": len(mappings) > 0,
        }
