"""Tests for network security checks (C.1-C.3)."""

from unittest import TestCase
from unittest.mock import Mock

from botocore.exceptions import ClientError

from lambda_security_scanner.checks.network_security import (
    NetworkSecurityChecker,
)


def _access_denied(operation="Operation"):
    return ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        operation,
    )


class TestCheckVpcConfig(TestCase):
    """C.1 - VPC configuration detection."""

    def setUp(self):
        self.checker = NetworkSecurityChecker()

    def test_no_vpc(self):
        cfg = {}
        result = self.checker.check_vpc_config(cfg)
        self.assertFalse(result["in_vpc"])
        self.assertIsNone(result["vpc_id"])
        self.assertEqual(result["subnet_count"], 0)

    def test_with_vpc(self):
        cfg = {
            "VpcConfig": {
                "SubnetIds": ["subnet-1", "subnet-2"],
                "SecurityGroupIds": ["sg-1"],
                "VpcId": "vpc-123",
            }
        }
        result = self.checker.check_vpc_config(cfg)
        self.assertTrue(result["in_vpc"])
        self.assertEqual(result["vpc_id"], "vpc-123")
        self.assertEqual(result["subnet_count"], 2)
        self.assertEqual(
            result["security_group_count"], 1
        )


class TestCheckMultiAz(TestCase):
    """C.2 - Multi-AZ deployment checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = NetworkSecurityChecker(
            lambda: mock_session
        )

    def test_not_applicable(self):
        vpc_result = {"in_vpc": False}
        result = self.checker.check_multi_az(
            vpc_result, "us-east-1"
        )
        self.assertFalse(result["applicable"])
        self.assertFalse(result["is_multi_az"])

    def test_single_az(self):
        vpc_result = {
            "in_vpc": True,
            "subnet_ids": ["subnet-1"],
        }
        self.mock_client.describe_subnets.return_value = {
            "Subnets": [
                {
                    "SubnetId": "subnet-1",
                    "AvailabilityZone": "us-east-1a",
                }
            ]
        }
        result = self.checker.check_multi_az(
            vpc_result, "us-east-1"
        )
        self.assertTrue(result["applicable"])
        self.assertFalse(result["is_multi_az"])
        self.assertEqual(result["az_count"], 1)

    def test_multi_az(self):
        vpc_result = {
            "in_vpc": True,
            "subnet_ids": ["subnet-1", "subnet-2"],
        }
        self.mock_client.describe_subnets.return_value = {
            "Subnets": [
                {
                    "SubnetId": "subnet-1",
                    "AvailabilityZone": "us-east-1a",
                },
                {
                    "SubnetId": "subnet-2",
                    "AvailabilityZone": "us-east-1b",
                },
            ]
        }
        result = self.checker.check_multi_az(
            vpc_result, "us-east-1"
        )
        self.assertTrue(result["applicable"])
        self.assertTrue(result["is_multi_az"])
        self.assertEqual(result["az_count"], 2)

    def test_access_denied_multi_az(self):
        vpc_result = {
            "in_vpc": True,
            "subnet_ids": ["subnet-1"],
        }
        self.mock_client.describe_subnets.side_effect = (
            _access_denied("DescribeSubnets")
        )
        result = self.checker.check_multi_az(
            vpc_result, "us-east-1"
        )
        self.assertTrue(result["applicable"])
        self.assertFalse(result["is_multi_az"])
        self.assertIn("error", result)


class TestCheckSecurityGroups(TestCase):
    """C.3 - Security group egress checks."""

    def setUp(self):
        self.mock_client = Mock()
        mock_session = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = NetworkSecurityChecker(
            lambda: mock_session
        )

    def test_not_applicable(self):
        vpc_result = {"in_vpc": False}
        result = self.checker.check_security_groups(
            vpc_result, "us-east-1"
        )
        self.assertFalse(result["applicable"])
        self.assertFalse(result["unrestricted_egress"])

    def test_unrestricted_egress(self):
        vpc_result = {
            "in_vpc": True,
            "security_group_ids": ["sg-1"],
        }
        self.mock_client.describe_security_groups \
            .return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-1",
                        "GroupName": "default",
                        "IpPermissionsEgress": [
                            {
                                "IpProtocol": "-1",
                                "IpRanges": [
                                    {
                                        "CidrIp":
                                            "0.0.0.0/0"
                                    }
                                ],
                                "Ipv6Ranges": [],
                            }
                        ],
                    }
                ]
            }
        result = self.checker.check_security_groups(
            vpc_result, "us-east-1"
        )
        self.assertTrue(result["applicable"])
        self.assertTrue(result["unrestricted_egress"])

    def test_restricted_egress(self):
        vpc_result = {
            "in_vpc": True,
            "security_group_ids": ["sg-1"],
        }
        self.mock_client.describe_security_groups \
            .return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-1",
                        "GroupName": "restricted",
                        "IpPermissionsEgress": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [
                                    {
                                        "CidrIp":
                                            "10.0.0.0/8"
                                    }
                                ],
                                "Ipv6Ranges": [],
                            }
                        ],
                    }
                ]
            }
        result = self.checker.check_security_groups(
            vpc_result, "us-east-1"
        )
        self.assertTrue(result["applicable"])
        self.assertFalse(result["unrestricted_egress"])

    def test_unrestricted_ipv6_egress(self):
        """Security group with ::/0 IPv6 egress is flagged."""
        vpc_result = {
            "in_vpc": True,
            "security_group_ids": ["sg-2"],
        }
        self.mock_client.describe_security_groups \
            .return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-2",
                        "GroupName": "ipv6-open",
                        "IpPermissionsEgress": [
                            {
                                "IpProtocol": "-1",
                                "IpRanges": [],
                                "Ipv6Ranges": [
                                    {"CidrIpv6": "::/0"}
                                ],
                            }
                        ],
                    }
                ]
            }
        result = self.checker.check_security_groups(
            vpc_result, "us-east-1"
        )
        self.assertTrue(result["applicable"])
        self.assertTrue(result["unrestricted_egress"])

    def test_access_denied_security_groups(self):
        vpc_result = {
            "in_vpc": True,
            "security_group_ids": ["sg-1"],
        }
        self.mock_client.describe_security_groups \
            .side_effect = _access_denied(
                "DescribeSecurityGroups"
            )
        result = self.checker.check_security_groups(
            vpc_result, "us-east-1"
        )
        self.assertTrue(result["applicable"])
        self.assertFalse(result["unrestricted_egress"])
        self.assertIn("error", result)
