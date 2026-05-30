"""Network security checks for Lambda functions (C.1-C.3)."""

import logging
from typing import Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("lambda_security_scanner")


class NetworkSecurityChecker(BaseChecker):
    """Check network security configuration for Lambda functions.

    Implements checks C.1 (VPC config), C.2 (multi-AZ),
    and C.3 (security group egress).
    """

    def check_vpc_config(
        self, function_config: Dict
    ) -> Dict:
        """C.1 - Check if function has VPC configuration.

        Extracts VPC configuration from the function config dict.
        No API call required.

        Args:
            function_config: Lambda function configuration dict.

        Returns:
            Dict with in_vpc, vpc_id, subnet_count,
            subnet_ids, security_group_count,
            security_group_ids.
        """
        vpc_config = function_config.get("VpcConfig", {})
        subnet_ids = vpc_config.get("SubnetIds", [])
        security_group_ids = vpc_config.get(
            "SecurityGroupIds", []
        )
        vpc_id = vpc_config.get("VpcId")

        in_vpc = bool(subnet_ids and security_group_ids)

        return {
            "in_vpc": in_vpc,
            "vpc_id": vpc_id if in_vpc else None,
            "subnet_count": len(subnet_ids),
            "subnet_ids": subnet_ids,
            "security_group_count": len(security_group_ids),
            "security_group_ids": security_group_ids,
        }

    def check_multi_az(
        self, vpc_result: Dict, region: str
    ) -> Dict:
        """C.2 - Check if VPC Lambda uses multiple AZs.

        Only applicable if the function is in a VPC.

        Args:
            vpc_result: Result from check_vpc_config.
            region: AWS region name.

        Returns:
            Dict with applicable, is_multi_az, az_count,
            availability_zones.
        """
        if not vpc_result.get("in_vpc"):
            return {
                "applicable": False,
                "is_multi_az": False,
                "az_count": 0,
                "availability_zones": [],
            }

        subnet_ids = vpc_result.get("subnet_ids", [])
        if not subnet_ids:
            return {
                "applicable": True,
                "is_multi_az": False,
                "az_count": 0,
                "availability_zones": [],
            }

        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_subnets(
                SubnetIds=subnet_ids
            )
            azs = list(
                {
                    s["AvailabilityZone"]
                    for s in response.get("Subnets", [])
                }
            )
            return {
                "applicable": True,
                "is_multi_az": len(azs) > 1,
                "az_count": len(azs),
                "availability_zones": sorted(azs),
            }
        except ClientError as e:
            return self.handle_client_error(
                e,
                {
                    "applicable": True,
                    "is_multi_az": False,
                    "az_count": 0,
                    "availability_zones": [],
                },
            )

    def check_security_groups(
        self, vpc_result: Dict, region: str
    ) -> Dict:
        """C.3 - Check for unrestricted security group egress.

        Only applicable if the function is in a VPC.
        Flags rules with IpProtocol="-1" and
        CidrIp="0.0.0.0/0" or CidrIpv6="::/0".

        Args:
            vpc_result: Result from check_vpc_config.
            region: AWS region name.

        Returns:
            Dict with applicable, unrestricted_egress,
            security_groups.
        """
        if not vpc_result.get("in_vpc"):
            return {
                "applicable": False,
                "unrestricted_egress": False,
                "security_groups": [],
            }

        sg_ids = vpc_result.get("security_group_ids", [])
        if not sg_ids:
            return {
                "applicable": True,
                "unrestricted_egress": False,
                "security_groups": [],
            }

        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_security_groups(
                GroupIds=sg_ids
            )
        except ClientError as e:
            return self.handle_client_error(
                e,
                {
                    "applicable": True,
                    "unrestricted_egress": False,
                    "security_groups": [],
                },
            )

        security_groups = []
        unrestricted_egress = False

        for sg in response.get("SecurityGroups", []):
            sg_info = {
                "group_id": sg.get("GroupId"),
                "group_name": sg.get("GroupName"),
                "unrestricted_egress_rules": [],
            }

            for rule in sg.get("IpPermissionsEgress", []):
                if rule.get("IpProtocol") != "-1":
                    continue

                for ip_range in rule.get(
                    "IpRanges", []
                ):
                    if (
                        ip_range.get("CidrIp")
                        == "0.0.0.0/0"
                    ):
                        sg_info[
                            "unrestricted_egress_rules"
                        ].append(rule)
                        unrestricted_egress = True
                        break

                for ip_range in rule.get(
                    "Ipv6Ranges", []
                ):
                    if (
                        ip_range.get("CidrIpv6")
                        == "::/0"
                    ):
                        sg_info[
                            "unrestricted_egress_rules"
                        ].append(rule)
                        unrestricted_egress = True
                        break

            security_groups.append(sg_info)

        return {
            "applicable": True,
            "unrestricted_egress": unrestricted_egress,
            "security_groups": security_groups,
        }
