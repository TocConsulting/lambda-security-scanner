"""Tests for function configuration checks (A.1-A.7)."""

from unittest import TestCase
from unittest.mock import Mock

from lambda_security_scanner.checks.function_config import (
    FunctionConfigChecker,
    NEAR_EOL_RUNTIMES,
    BLOCKED_RUNTIMES,
    DEPRECATED_RUNTIMES,
)


class TestCheckRuntime(TestCase):
    """A.1 - Runtime status detection."""

    def setUp(self):
        self.checker = FunctionConfigChecker()

    def test_blocked_runtime(self):
        cfg = {"Runtime": "python2.7", "PackageType": "Zip"}
        result = self.checker.check_runtime(cfg)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["runtime"], "python2.7")
        self.assertIsNone(result["eol_date"])

    def test_deprecated_runtime(self):
        cfg = {"Runtime": "ruby3.2", "PackageType": "Zip"}
        result = self.checker.check_runtime(cfg)
        self.assertEqual(result["status"], "deprecated")
        self.assertEqual(result["runtime"], "ruby3.2")
        self.assertIsNone(result["eol_date"])

    def test_near_eol_runtime(self):
        # Use the NEAR_EOL_RUNTIMES dict directly so this
        # test never breaks when a specific runtime graduates
        # to blocked/deprecated.
        runtime_name, expected_eol = next(
            iter(NEAR_EOL_RUNTIMES.items())
        )
        cfg = {
            "Runtime": runtime_name,
            "PackageType": "Zip",
        }
        result = self.checker.check_runtime(cfg)
        self.assertEqual(result["status"], "near_eol")
        self.assertEqual(result["runtime"], runtime_name)
        self.assertEqual(result["eol_date"], expected_eol)

    def test_all_near_eol_runtimes_have_dates(self):
        for runtime_name, eol_date in (
            NEAR_EOL_RUNTIMES.items()
        ):
            cfg = {
                "Runtime": runtime_name,
                "PackageType": "Zip",
            }
            result = self.checker.check_runtime(cfg)
            self.assertEqual(
                result["status"],
                "near_eol",
                f"{runtime_name} should be near_eol",
            )
            self.assertEqual(
                result["eol_date"],
                eol_date,
                f"{runtime_name} eol_date mismatch",
            )

    def test_supported_runtime(self):
        cfg = {"Runtime": "python3.12", "PackageType": "Zip"}
        result = self.checker.check_runtime(cfg)
        self.assertEqual(result["status"], "supported")
        self.assertEqual(result["runtime"], "python3.12")
        self.assertIsNone(result["eol_date"])

    def test_container_image(self):
        cfg = {"PackageType": "Image"}
        result = self.checker.check_runtime(cfg)
        self.assertEqual(result["status"], "supported")
        self.assertIsNone(result["runtime"])
        self.assertEqual(result["package_type"], "Image")
        self.assertIsNone(result["eol_date"])

    def test_runtime_set_sizes_locked(self):
        """Lock the runtime-list sizes so any reclassification (a runtime
        moving from deprecated to blocked, etc.) is a deliberate change
        with a date verification, not an accidental drift. Verified
        2026-05-30."""
        self.assertEqual(len(BLOCKED_RUNTIMES), 16)
        self.assertEqual(len(DEPRECATED_RUNTIMES), 13)
        self.assertEqual(len(NEAR_EOL_RUNTIMES), 5)
        # No runtime may appear in more than one bucket.
        self.assertEqual(
            BLOCKED_RUNTIMES & DEPRECATED_RUNTIMES, set()
        )
        self.assertEqual(
            BLOCKED_RUNTIMES & set(NEAR_EOL_RUNTIMES), set()
        )
        self.assertEqual(
            DEPRECATED_RUNTIMES & set(NEAR_EOL_RUNTIMES), set()
        )

    def test_current_runtimes_supported(self):
        for rt in ("python3.12", "python3.13", "nodejs22.x", "java21"):
            cfg = {"Runtime": rt, "PackageType": "Zip"}
            # nodejs22.x is near_eol, others supported; both are non-blocked
            status = self.checker.check_runtime(cfg)["status"]
            self.assertIn(status, ("supported", "near_eol"))


class TestCheckTimeout(TestCase):
    """A.2 - Timeout check."""

    def setUp(self):
        self.checker = FunctionConfigChecker()

    def test_max_timeout(self):
        cfg = {"Timeout": 900}
        result = self.checker.check_timeout(cfg)
        self.assertEqual(result["timeout_seconds"], 900)
        self.assertTrue(result["is_max_timeout"])

    def test_normal_timeout(self):
        cfg = {"Timeout": 30}
        result = self.checker.check_timeout(cfg)
        self.assertEqual(result["timeout_seconds"], 30)
        self.assertFalse(result["is_max_timeout"])


class TestCheckEnvironmentSecrets(TestCase):
    """A.3 - Environment variable secret detection."""

    def setUp(self):
        self.checker = FunctionConfigChecker()

    def test_no_env_vars(self):
        cfg = {}
        result = self.checker.check_environment_secrets(cfg)
        self.assertFalse(result["has_env_vars"])
        self.assertEqual(result["env_var_count"], 0)
        self.assertFalse(result["has_secrets"])

    def test_env_vars_without_secrets(self):
        cfg = {
            "Environment": {
                "Variables": {"APP_NAME": "myapp"}
            }
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertTrue(result["has_env_vars"])
        self.assertEqual(result["env_var_count"], 1)
        self.assertFalse(result["has_secrets"])

    def test_secrets_found_without_kms(self):
        cfg = {
            "Environment": {
                "Variables": {
                    "DB_PASSWORD": "super-secret"
                }
            }
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertTrue(result["has_secrets"])
        self.assertIn("DB_PASSWORD", result["secret_names"])
        self.assertFalse(result["has_kms_key"])
        self.assertIsNone(result["kms_key_arn"])

    def test_secrets_found_with_kms(self):
        cfg = {
            "Environment": {
                "Variables": {
                    "DB_PASSWORD": "super-secret"
                }
            },
            "KMSKeyArn": "arn:aws:kms:us-east-1:123:key/x",
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertTrue(result["has_secrets"])
        self.assertTrue(result["has_kms_key"])
        self.assertIsNotNone(result["kms_key_arn"])

    def test_value_pattern_detection_akia(self):
        cfg = {
            "Environment": {
                "Variables": {
                    "MY_KEY": "AKIA1234567890ABCDEF"
                }
            }
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertTrue(result["has_secrets"])
        self.assertEqual(len(result["secret_values"]), 1)
        self.assertEqual(
            result["secret_values"][0]["type"],
            "AWS_ACCESS_KEY",
        )

    def test_secrets_manager_arn_reference_not_flagged(self):
        """The AWS-recommended pattern (env var holds a Secrets Manager
        ARN) must NOT be flagged even though the name looks secret-like."""
        cfg = {
            "Environment": {
                "Variables": {
                    "DB_SECRET_ARN": "arn:aws:secretsmanager:"
                    "us-east-1:123456789012:secret:db-AbCdEf"
                }
            }
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertFalse(result["has_secrets"])
        self.assertEqual(result["secret_names"], [])

    def test_ssm_parameter_path_reference_not_flagged(self):
        cfg = {
            "Environment": {
                "Variables": {
                    "API_KEY_PARAM": "/myapp/prod/api-key"
                }
            }
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertFalse(result["has_secrets"])

    def test_trivial_value_with_secret_name_not_flagged(self):
        cfg = {
            "Environment": {
                "Variables": {
                    "FEATURE_SECRET_ENABLED": "true",
                    "TOKEN_TTL": "3600",
                }
            }
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertFalse(result["has_secrets"])

    def test_opaque_value_with_secret_name_still_flagged(self):
        cfg = {
            "Environment": {
                "Variables": {
                    "DB_PASSWORD": "Sup3rS3cretP@ssw0rdValue"
                }
            }
        }
        result = self.checker.check_environment_secrets(cfg)
        self.assertTrue(result["has_secrets"])
        self.assertIn("DB_PASSWORD", result["secret_names"])


class TestSecretValuePatterns(TestCase):
    """A.3 - Exhaustive SECRET_VALUE_PATTERNS coverage."""

    def setUp(self):
        self.checker = FunctionConfigChecker()

    def _detect(self, value):
        cfg = {
            "Environment": {
                "Variables": {"MY_VAR": value}
            }
        }
        return self.checker.check_environment_secrets(cfg)

    def _assert_type(self, value, expected_type):
        result = self._detect(value)
        self.assertTrue(
            result["has_secrets"],
            f"Expected {expected_type} to be detected",
        )
        types = [
            v["type"] for v in result["secret_values"]
        ]
        self.assertIn(expected_type, types)

    def test_asia_prefix_aws_key(self):
        self._assert_type(
            "ASIA1234567890ABCDEF", "AWS_ACCESS_KEY"
        )

    def test_github_token(self):
        self._assert_type(
            "ghp_" + "a" * 36, "GITHUB_TOKEN"
        )

    def test_github_pat(self):
        self._assert_type(
            "github_pat_" + "a" * 82, "GITHUB_PAT"
        )

    def test_gitlab_token(self):
        self._assert_type(
            "glpat-" + "a" * 20, "GITLAB_TOKEN"
        )

    def test_stripe_live_key(self):
        self._assert_type(
            "sk_live_" + "a" * 24, "STRIPE_KEY"
        )

    def test_stripe_restricted_key(self):
        self._assert_type(
            "rk_live_" + "a" * 24, "STRIPE_RESTRICTED_KEY"
        )

    def test_slack_token(self):
        self._assert_type(
            "xoxb-abc123-def456", "SLACK_TOKEN"
        )

    def test_slack_app_token(self):
        self._assert_type(
            "xapp-1-abc123def456", "SLACK_APP_TOKEN"
        )

    def test_private_key_header(self):
        self._assert_type(
            "-----BEGIN RSA PRIVATE KEY-----",
            "PRIVATE_KEY",
        )

    def test_connection_string_postgres(self):
        self._assert_type(
            "postgres://user:pass@db.example.com/mydb",
            "CONNECTION_STRING",
        )

    def test_anthropic_key(self):
        self._assert_type(
            "sk-ant-" + "a" * 40, "ANTHROPIC_KEY"
        )

    def test_openai_key_project(self):
        self._assert_type(
            "sk-proj-" + "a" * 48, "OPENAI_KEY_PROJECT"
        )

    def test_openai_key_svcacct(self):
        self._assert_type(
            "sk-svcacct-" + "a" * 48, "OPENAI_KEY_SVCACCT"
        )

    def test_openai_key_legacy(self):
        # Plain sk- not matching proj/svcacct prefixes
        self._assert_type("sk-" + "a" * 48, "OPENAI_KEY")

    def test_sendgrid_key(self):
        self._assert_type(
            "SG." + "a" * 22 + "." + "b" * 43,
            "SENDGRID_KEY",
        )

    def test_npm_token(self):
        self._assert_type(
            "npm_" + "a" * 36, "NPM_TOKEN"
        )

    def test_no_false_positive_plain_value(self):
        result = self._detect("hello_world_12345")
        self.assertFalse(result["has_secrets"])
        self.assertEqual(result["secret_values"], [])


class TestCheckEphemeralStorage(TestCase):
    """A.4 - Ephemeral storage check."""

    def setUp(self):
        self.checker = FunctionConfigChecker()

    def test_default_storage(self):
        cfg = {"EphemeralStorage": {"Size": 512}}
        result = self.checker.check_ephemeral_storage(cfg)
        self.assertEqual(result["size_mb"], 512)
        self.assertFalse(result["is_large"])

    def test_large_storage(self):
        cfg = {"EphemeralStorage": {"Size": 1024}}
        result = self.checker.check_ephemeral_storage(cfg)
        self.assertEqual(result["size_mb"], 1024)
        self.assertTrue(result["is_large"])


class TestCheckLayers(TestCase):
    """A.5 - External layer detection."""

    def setUp(self):
        self.checker = FunctionConfigChecker()
        self.account_id = "123456789012"

    def test_no_layers(self):
        cfg = {}
        result = self.checker.check_layers(
            cfg, self.account_id
        )
        self.assertEqual(result["layer_count"], 0)
        self.assertFalse(result["has_external_layers"])

    def test_same_account_layers(self):
        cfg = {
            "Layers": [
                {
                    "Arn": (
                        "arn:aws:lambda:us-east-1:"
                        "123456789012:layer:my-layer:1"
                    )
                }
            ]
        }
        result = self.checker.check_layers(
            cfg, self.account_id
        )
        self.assertEqual(result["layer_count"], 1)
        self.assertFalse(result["has_external_layers"])

    def test_external_layers(self):
        cfg = {
            "Layers": [
                {
                    "Arn": (
                        "arn:aws:lambda:us-east-1:"
                        "999999999999:layer:ext-layer:1"
                    )
                }
            ]
        }
        result = self.checker.check_layers(
            cfg, self.account_id
        )
        self.assertEqual(result["layer_count"], 1)
        self.assertTrue(result["has_external_layers"])
        self.assertEqual(len(result["external_layers"]), 1)

    def test_aws_managed_layers(self):
        cfg = {
            "Layers": [
                {
                    "Arn": (
                        "arn:aws:lambda:::awslayer:"
                        "AWSLambdaPowertoolsPython"
                    )
                }
            ]
        }
        result = self.checker.check_layers(
            cfg, self.account_id
        )
        self.assertEqual(result["layer_count"], 1)
        self.assertFalse(result["has_external_layers"])


class TestCheckTracing(TestCase):
    """A.6 - X-Ray tracing check."""

    def setUp(self):
        self.checker = FunctionConfigChecker()

    def test_active_tracing(self):
        cfg = {"TracingConfig": {"Mode": "Active"}}
        result = self.checker.check_tracing(cfg)
        self.assertEqual(result["mode"], "Active")
        self.assertTrue(result["enabled"])

    def test_passthrough_tracing(self):
        cfg = {"TracingConfig": {"Mode": "PassThrough"}}
        result = self.checker.check_tracing(cfg)
        self.assertEqual(result["mode"], "PassThrough")
        self.assertFalse(result["enabled"])


class TestCheckDeadLetterConfig(TestCase):
    """A.7 - Dead letter queue configuration."""

    def setUp(self):
        self.checker = FunctionConfigChecker()

    def test_with_sqs_dlq(self):
        cfg = {
            "DeadLetterConfig": {
                "TargetArn": (
                    "arn:aws:sqs:us-east-1:123:my-dlq"
                )
            }
        }
        result = self.checker.check_dead_letter_config(cfg)
        self.assertTrue(result["configured"])
        self.assertEqual(result["target_type"], "SQS")

    def test_with_sns_dlq(self):
        cfg = {
            "DeadLetterConfig": {
                "TargetArn": (
                    "arn:aws:sns:us-east-1:123:my-topic"
                )
            }
        }
        result = self.checker.check_dead_letter_config(cfg)
        self.assertTrue(result["configured"])
        self.assertEqual(result["target_type"], "SNS")

    def test_without_dlq(self):
        cfg = {}
        result = self.checker.check_dead_letter_config(cfg)
        self.assertFalse(result["configured"])
        self.assertIsNone(result["target_arn"])
        self.assertIsNone(result["target_type"])
