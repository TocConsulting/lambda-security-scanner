"""Tests for CLI interface."""

import os
import tempfile
from unittest import TestCase
from unittest.mock import patch, Mock

from click.testing import CliRunner

from lambda_security_scanner.cli import cli


class TestCliHelp(TestCase):
    """Test CLI help and version output."""

    def setUp(self):
        self.runner = CliRunner()

    def test_help_output(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Lambda Security Scanner", result.output
        )

    def test_version_option(self):
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Lambda Security Scanner", result.output
        )

    def test_security_command_help(self):
        result = self.runner.invoke(
            cli, ["security", "--help"]
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("security", result.output.lower())


class TestSecurityCommand(TestCase):
    """Integration tests for the 'security' CLI command."""

    def setUp(self):
        self.runner = CliRunner()

    def _mock_scanner(self, tmpdir):
        """Create a mock LambdaSecurityScanner."""
        mock = Mock()
        mock.get_all_functions.return_value = [
            {
                "FunctionName": "test-func",
                "Role": "arn:aws:iam::123:role/r",
            }
        ]
        mock.scan_all_functions.return_value = [
            {
                "function_name": "test-func",
                "security_score": 80,
                "scan_error": False,
                "is_public": False,
                "issues": [],
                "issue_count": 0,
                "compliance_status": {},
            }
        ]
        mock.generate_reports.return_value = {
            "json": os.path.join(tmpdir, "report.json"),
            "compliance": os.path.join(
                tmpdir, "compliance.json"
            ),
        }
        mock.output_dir = tmpdir
        return mock

    @patch(
        "lambda_security_scanner.cli.LambdaSecurityScanner"
    )
    def test_security_command_success(
        self, mock_scanner_cls
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_instance = self._mock_scanner(tmpdir)
            mock_scanner_cls.return_value = mock_instance

            result = self.runner.invoke(
                cli,
                [
                    "security",
                    "--region", "us-east-1",
                    "--output-dir", tmpdir,
                    "--quiet",
                ],
            )
            self.assertEqual(
                result.exit_code,
                0,
                result.output,
            )
            mock_instance.get_all_functions.assert_called_once()
            mock_instance.scan_all_functions.assert_called_once()
            mock_instance.generate_reports.assert_called_once()

    @patch(
        "lambda_security_scanner.cli.LambdaSecurityScanner"
    )
    def test_security_command_no_functions_exits_1(
        self, mock_scanner_cls
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_instance = Mock()
            mock_instance.get_all_functions \
                .return_value = []
            mock_instance.output_dir = tmpdir
            mock_scanner_cls.return_value = mock_instance

            result = self.runner.invoke(
                cli,
                [
                    "security",
                    "--region", "us-east-1",
                    "--output-dir", tmpdir,
                ],
            )
            self.assertEqual(result.exit_code, 1)

    @patch(
        "lambda_security_scanner.cli.LambdaSecurityScanner"
    )
    def test_security_region_from_env(
        self, mock_scanner_cls
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_instance = self._mock_scanner(tmpdir)
            mock_scanner_cls.return_value = mock_instance

            result = self.runner.invoke(
                cli,
                [
                    "security",
                    "--output-dir", tmpdir,
                    "--quiet",
                ],
                env={
                    "AWS_DEFAULT_REGION": "eu-west-1"
                },
            )
            self.assertEqual(
                result.exit_code, 0, result.output
            )
            call_kwargs = mock_scanner_cls.call_args[1]
            self.assertEqual(
                call_kwargs["region"], "eu-west-1"
            )
