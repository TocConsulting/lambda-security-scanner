"""Access control security checks (B.1 through B.5).

Checks resource-based policies, function URLs, CORS
configuration, execution role permissions, and shared roles.
"""

import json
import logging
import urllib.parse
from typing import Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("lambda_security_scanner")

PRIVILEGE_ESCALATION_ACTIONS = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:CreateAccessKey",
    "iam:PassRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
]

DANGEROUS_MANAGED_POLICIES = [
    "AdministratorAccess",
    "PowerUserAccess",
    "IAMFullAccess",
]


class AccessControlChecker(BaseChecker):
    """Checks for access control misconfigurations.

    Covers B.1 (resource policy), B.2 (function URL auth),
    B.3 (CORS), B.4 (execution role), B.5 (shared role).
    """

    def check_resource_policy(
        self, function_name: str, region: str
    ) -> Dict:
        """B.1: Check if resource-based policy allows public access.

        Args:
            function_name: Lambda function name or ARN.
            region: AWS region name.

        Returns:
            Dict with has_policy, is_public, statement_count,
            and public_statement_count.
        """
        client = self.get_client("lambda", region)
        try:
            response = client.get_policy(
                FunctionName=function_name
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get(
                "Code", "Unknown"
            )
            if error_code == "ResourceNotFoundException":
                return {
                    "has_policy": False,
                    "is_public": False,
                    "statement_count": 0,
                    "public_statement_count": 0,
                }
            return self.handle_client_error(
                e,
                {
                    "has_policy": False,
                    "is_public": False,
                    "statement_count": 0,
                    "public_statement_count": 0,
                },
            )

        policy = json.loads(response["Policy"])
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        public_count = 0
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            if self._is_public_statement(stmt):
                public_count += 1

        return {
            "has_policy": True,
            "is_public": public_count > 0,
            "statement_count": len(statements),
            "public_statement_count": public_count,
        }

    def _is_public_statement(self, stmt: Dict) -> bool:
        """Check if a policy statement grants public access.

        Matches AWS Security Hub Lambda.1 semantics: a statement is
        public when its principal includes a wildcard (or NotPrincipal
        is used with Effect: Allow) UNLESS the Condition contains a
        fixed-value source restriction (no wildcards, no policy
        variables).

        Wildcard principals detected:
          - "Principal": "*"
          - "Principal": {"AWS": "*"}  or  {"AWS": [..., "*", ...]}
          - "Principal": {"Service": "*"} or list variant
          - "Principal": {"Federated": "*"} or list variant
          - "Principal": {"CanonicalUser": "*"} or list variant
          - "NotPrincipal" present (broad-by-default with Allow)

        Args:
            stmt: A single policy statement dict.

        Returns:
            True if the statement is publicly accessible.
        """
        # NotPrincipal with Effect: Allow is broad-by-default
        if "NotPrincipal" in stmt:
            return True

        principal = stmt.get("Principal", {})
        condition = stmt.get("Condition") or {}

        is_wildcard = False
        if principal == "*":
            is_wildcard = True
        elif isinstance(principal, dict):
            for key in (
                "AWS",
                "Service",
                "Federated",
                "CanonicalUser",
            ):
                val = principal.get(key)
                if val == "*":
                    is_wildcard = True
                    break
                if (
                    isinstance(val, list)
                    and "*" in val
                ):
                    is_wildcard = True
                    break

        if is_wildcard:
            if not condition:
                return True
            return not self._has_fixed_source_restriction(
                condition
            )

        # Confused-deputy: a named service principal (e.g.
        # s3.amazonaws.com, events.amazonaws.com) with no source
        # restriction is flagged by AWS Security Hub Lambda.1 as
        # public — any S3 bucket / EventBridge rule across the
        # internet can invoke the function.
        if (
            isinstance(principal, dict)
            and principal.get("Service")
        ):
            if not condition:
                return True
            if not self._has_fixed_source_restriction(
                condition
            ):
                return True

        return False

    @staticmethod
    def _has_fixed_source_restriction(
        condition: Dict,
    ) -> bool:
        """Return True only if a fixed-value source key is set.

        FSBP Lambda.1 rule: a condition restricts public access only
        when the operator is a fixed-value comparison
        (StringEquals/ArnEquals) and the value contains no wildcards
        (``*``) or policy variables (``${...}``). StringLike/ArnLike
        with literal values also count as fixed. Anything with
        wildcards or policy variables does NOT restrict.

        Source keys recognized: aws:SourceArn, aws:SourceAccount,
        aws:SourceOwner, aws:PrincipalAccount, aws:PrincipalOrgID.
        """
        FIXED_OPS = (
            "StringEquals",
            "ArnEquals",
            "StringEqualsIfExists",
            "ArnEqualsIfExists",
        )
        LIKE_OPS = (
            "StringLike",
            "ArnLike",
            "StringLikeIfExists",
            "ArnLikeIfExists",
        )
        SOURCE_KEYS = (
            "aws:sourcearn",
            "aws:sourceaccount",
            "aws:sourceowner",
            "aws:principalaccount",
            "aws:principalorgid",
        )

        for op, block in condition.items():
            if not isinstance(block, dict):
                continue
            for cond_key, cond_val in block.items():
                if cond_key.lower() not in SOURCE_KEYS:
                    continue
                values = (
                    cond_val
                    if isinstance(cond_val, list)
                    else [cond_val]
                )
                if op in FIXED_OPS or op in LIKE_OPS:
                    if all(
                        "*" not in str(v)
                        and "${" not in str(v)
                        for v in values
                    ):
                        return True
        return False

    def check_function_url(
        self, function_name: str, region: str
    ) -> Dict:
        """B.2: Check if function URL has no authentication.

        Args:
            function_name: Lambda function name or ARN.
            region: AWS region name.

        Returns:
            Dict with has_url, auth_type, is_public,
            function_url, and cors.
        """
        client = self.get_client("lambda", region)
        try:
            response = client.get_function_url_config(
                FunctionName=function_name
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get(
                "Code", "Unknown"
            )
            if error_code == "ResourceNotFoundException":
                return {
                    "has_url": False,
                    "auth_type": None,
                    "is_public": False,
                    "function_url": None,
                    "cors": {},
                }
            return self.handle_client_error(
                e,
                {
                    "has_url": False,
                    "auth_type": None,
                    "is_public": False,
                    "function_url": None,
                    "cors": {},
                },
            )

        auth_type = response.get("AuthType", "NONE")
        return {
            "has_url": True,
            "auth_type": auth_type,
            "is_public": auth_type == "NONE",
            "function_url": response.get("FunctionUrl"),
            "cors": response.get("Cors", {}),
        }

    def check_function_url_cors(
        self, url_result: Dict
    ) -> Dict:
        """B.3: Check if function URL CORS allows all origins.

        Derived from B.2 result; no API call needed.

        Args:
            url_result: Result dict from check_function_url.

        Returns:
            Dict with has_cors, allow_all_origins,
            allow_origins, and allow_credentials.
        """
        cors = url_result.get("cors", {})
        if not cors:
            return {
                "has_cors": False,
                "allow_all_origins": False,
                "allow_origins": [],
                "allow_credentials": False,
            }

        allow_origins = cors.get("AllowOrigins", [])
        allow_credentials = cors.get(
            "AllowCredentials", False
        )

        return {
            "has_cors": True,
            "allow_all_origins": "*" in allow_origins,
            "allow_origins": allow_origins,
            "allow_credentials": allow_credentials,
        }

    def check_execution_role(
        self, role_arn: str, region: str
    ) -> Dict:
        """B.4: Check for overly permissive execution role.

        Inspects managed and inline policies for admin access,
        wildcard actions, and privilege escalation permissions.

        Args:
            role_arn: IAM role ARN.
            region: AWS region name.

        Returns:
            Dict with role_name, has_admin_access,
            has_wildcard_actions, has_privilege_escalation,
            dangerous_permissions, and attached_policy_count.
        """
        role_name = role_arn.split("/")[-1]
        iam_client = self.get_client("iam", region)

        safe_defaults = {
            "role_name": role_name,
            "has_admin_access": False,
            "has_full_admin": False,
            "has_wildcard_actions": False,
            "has_privilege_escalation": False,
            "dangerous_permissions": [],
            "attached_policy_count": 0,
        }

        try:
            result = self._analyze_role(
                iam_client, role_name, safe_defaults
            )
        except ClientError as e:
            return self.handle_client_error(
                e, dict(safe_defaults)
            )

        return result

    def _analyze_role(
        self,
        iam_client,
        role_name: str,
        result: Dict,
    ) -> Dict:
        """Analyze all policies attached to a role.

        Args:
            iam_client: IAM boto3 client.
            role_name: IAM role name.
            result: Result dict to populate.

        Returns:
            Populated result dict.
        """
        result = dict(result)
        dangerous_permissions = []

        # Check managed policies
        managed_count = self._check_managed_policies(
            iam_client, role_name, dangerous_permissions
        )
        result["attached_policy_count"] = managed_count

        # Check inline policies
        self._check_inline_policies(
            iam_client, role_name, dangerous_permissions
        )

        result["dangerous_permissions"] = dangerous_permissions
        result["has_admin_access"] = any(
            p in dangerous_permissions
            for p in DANGEROUS_MANAGED_POLICIES
        )
        result["has_wildcard_actions"] = any(
            p.endswith(":*") or p == "*"
            for p in dangerous_permissions
        )
        # has_full_admin distinguishes admin-equivalent access
        # (AdministratorAccess/PowerUserAccess/IAMFullAccess managed
        # policies, or a literal "*" action) from a single-service
        # wildcard such as "s3:*". Only the former is scored CRITICAL.
        result["has_full_admin"] = result["has_admin_access"] or any(
            p in ("*", "*:*") for p in dangerous_permissions
        )
        result["has_privilege_escalation"] = any(
            p.lower() in [a.lower() for a in
                          PRIVILEGE_ESCALATION_ACTIONS]
            for p in dangerous_permissions
            if ":" in p
            and p not in DANGEROUS_MANAGED_POLICIES
        )

        return result

    def _check_managed_policies(
        self,
        iam_client,
        role_name: str,
        dangerous_permissions: List[str],
    ) -> int:
        """Check managed policies for dangerous permissions.

        Args:
            iam_client: IAM boto3 client.
            role_name: IAM role name.
            dangerous_permissions: List to append findings.

        Returns:
            Count of attached managed policies.
        """
        paginator = iam_client.get_paginator(
            "list_attached_role_policies"
        )
        attached_policies = []
        for page in paginator.paginate(RoleName=role_name):
            attached_policies.extend(
                page.get("AttachedPolicies", [])
            )

        for policy in attached_policies:
            policy_name = policy["PolicyName"]
            if policy_name in DANGEROUS_MANAGED_POLICIES:
                dangerous_permissions.append(policy_name)
                continue

            # Get policy document for detailed analysis
            policy_arn = policy["PolicyArn"]
            try:
                self._analyze_managed_policy(
                    iam_client,
                    policy_arn,
                    dangerous_permissions,
                )
            except ClientError:
                logger.debug(
                    "Could not analyze policy %s",
                    policy_arn,
                )

        return len(attached_policies)

    def _analyze_managed_policy(
        self,
        iam_client,
        policy_arn: str,
        dangerous_permissions: List[str],
    ) -> None:
        """Analyze a single managed policy document.

        Args:
            iam_client: IAM boto3 client.
            policy_arn: Policy ARN.
            dangerous_permissions: List to append findings.
        """
        policy_meta = iam_client.get_policy(
            PolicyArn=policy_arn
        )
        version_id = policy_meta["Policy"][
            "DefaultVersionId"
        ]
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id,
        )
        doc = version["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            try:
                doc = json.loads(
                    urllib.parse.unquote(doc)
                )
            except (json.JSONDecodeError, ValueError):
                logger.warning(
                    "Could not parse policy document "
                    "for %s",
                    policy_arn,
                )
                return
        self._analyze_policy_document(
            doc, dangerous_permissions
        )

    def _check_inline_policies(
        self,
        iam_client,
        role_name: str,
        dangerous_permissions: List[str],
    ) -> None:
        """Check inline policies for dangerous permissions.

        Args:
            iam_client: IAM boto3 client.
            role_name: IAM role name.
            dangerous_permissions: List to append findings.
        """
        paginator = iam_client.get_paginator(
            "list_role_policies"
        )
        policy_names = []
        for page in paginator.paginate(RoleName=role_name):
            policy_names.extend(
                page.get("PolicyNames", [])
            )

        for policy_name in policy_names:
            try:
                response = iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name,
                )
                doc = response["PolicyDocument"]
                if isinstance(doc, str):
                    try:
                        doc = json.loads(
                            urllib.parse.unquote(doc)
                        )
                    except (json.JSONDecodeError, ValueError):
                        logger.warning(
                            "Could not parse inline "
                            "policy %s",
                            policy_name,
                        )
                        continue
                self._analyze_policy_document(
                    doc, dangerous_permissions
                )
            except ClientError:
                logger.debug(
                    "Could not analyze inline policy %s",
                    policy_name,
                )

    def _analyze_policy_document(
        self,
        document: Dict,
        dangerous_permissions: List[str],
    ) -> None:
        """Analyze a policy document for dangerous perms.

        Checks for wildcard actions and privilege escalation
        permissions with wildcard resources.

        Args:
            document: Parsed IAM policy document.
            dangerous_permissions: List to append findings.
        """
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            has_wildcard_resource = "*" in resources

            for action in actions:
                # Check for wildcard actions
                if action == "*" or action.endswith(":*"):
                    if action not in dangerous_permissions:
                        dangerous_permissions.append(action)

                # Check for privilege escalation actions
                # with wildcard resource
                if has_wildcard_resource:
                    for priv_action in (
                        PRIVILEGE_ESCALATION_ACTIONS
                    ):
                        if (
                            action.lower()
                            == priv_action.lower()
                            and action
                            not in dangerous_permissions
                        ):
                            dangerous_permissions.append(
                                action
                            )

    def check_shared_role(
        self, role_arn: str, all_role_arns: List[str]
    ) -> Dict:
        """B.5: Check if execution role is shared.

        Compares role_arn against the list of all function
        role ARNs. Flags if more than one function uses the
        same role.

        Args:
            role_arn: IAM role ARN to check.
            all_role_arns: List of all function role ARNs.

        Returns:
            Dict with is_shared, shared_count, and role_arn.
        """
        count = all_role_arns.count(role_arn)
        return {
            "is_shared": count > 1,
            "shared_count": count,
            "role_arn": role_arn,
        }
