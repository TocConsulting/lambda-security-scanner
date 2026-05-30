#!/usr/bin/env python3
"""Command-line interface for Lambda Security Scanner."""

import logging
import sys
import traceback

import click
from rich.console import Console

from .scanner import LambdaSecurityScanner
from . import __version__

console = Console()

BANNER = """[bold red]╔══════════════════════════════════════════════════════════╗
║           Lambda Security Scanner                        ║
║      Comprehensive Lambda Security Auditing              ║
╚══════════════════════════════════════════════════════════╝[/bold red]"""


def print_banner():
    console.print(BANNER)
    console.print(
        f"[dim]  Version {__version__} | "
        "https://github.com/TocConsulting/"
        "lambda-security-scanner[/dim]\n"
    )


# Shared options decorators (same pattern as EC2)
def shared_aws_options(f):
    f = click.option(
        "-r",
        "--region",
        default=None,
        help=(
            "AWS region "
            "(default: AWS_DEFAULT_REGION or us-east-1)"
        ),
    )(f)
    f = click.option(
        "-p",
        "--profile",
        default=None,
        help="AWS profile name",
    )(f)
    return f


def shared_output_options(f):
    f = click.option(
        "-o",
        "--output-dir",
        default="./output",
        help="Directory for output files (default: ./output)",
    )(f)
    f = click.option(
        "-f",
        "--output-format",
        type=click.Choice(
            ["json", "csv", "html", "all"],
            case_sensitive=False,
        ),
        default="all",
        help="Report format (default: all)",
    )(f)
    return f


def shared_performance_options(f):
    f = click.option(
        "-w",
        "--max-workers",
        default=5,
        type=int,
        help="Worker threads (default: 5)",
    )(f)
    f = click.option(
        "-q",
        "--quiet",
        is_flag=True,
        help="Suppress console output except errors",
    )(f)
    f = click.option(
        "-d",
        "--debug",
        is_flag=True,
        help="Enable debug logging",
    )(f)
    return f


def shared_options(f):
    f = shared_aws_options(f)
    f = shared_output_options(f)
    f = shared_performance_options(f)
    return f


class CustomGroup(click.Group):
    def format_help(self, ctx, formatter):
        print_banner()
        super().format_help(ctx, formatter)


@click.group(
    cls=CustomGroup,
    context_settings=dict(
        help_option_names=["-h", "--help"]
    ),
)
@click.version_option(
    version=__version__,
    prog_name="Lambda Security Scanner",
)
def cli():
    """
    Comprehensive AWS Lambda security scanner for
    vulnerability detection and multi-framework compliance
    auditing.

    \b
    FRAMEWORKS
    ═══════════════════════════════════════════════════════
      AWS-FSBP, CIS, PCI DSS v4.0.1, HIPAA, SOC 2,
      ISO 27001:2022, ISO 27017, ISO 27018, GDPR,
      NIST 800-53

    \b
    QUICK START
    ═══════════════════════════════════════════════════════
      Scan all functions:
        lambda-security-scanner security
      Use AWS profile:
        lambda-security-scanner security -p prod
      Specific region:
        lambda-security-scanner security -r eu-west-1
      Specific functions:
        lambda-security-scanner security -n my-func

    \b
    MORE INFO
    ═══════════════════════════════════════════════════════
      Run COMMAND --help for detailed options
      Docs: https://github.com/TocConsulting/
            lambda-security-scanner
    """
    pass


@cli.command()
@click.option(
    "--function-name",
    "-n",
    multiple=True,
    help="Specific function name(s) to scan",
)
@click.option(
    "--exclude-function",
    multiple=True,
    help="Function name(s) to exclude from scanning",
)
@click.option(
    "--compliance-only",
    is_flag=True,
    help="Generate compliance report only",
)
@shared_options
def security(
    function_name,
    exclude_function,
    compliance_only,
    region,
    profile,
    output_dir,
    output_format,
    max_workers,
    quiet,
    debug,
):
    """
    Scan Lambda functions for security vulnerabilities
    and compliance issues.

    \b
    Runs 19 security checks across 5 categories and
    evaluates compliance against 10 frameworks with
    81 controls.

    \b
    EXAMPLES:
      lambda-security-scanner security
      lambda-security-scanner security -p prod -r us-west-2
      lambda-security-scanner security -n my-func -n other
      lambda-security-scanner security --compliance-only
      lambda-security-scanner security -f html -o ./reports
    """
    import os as _os
    if region is None:
        region = _os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1"
        )

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger(
            "lambda_security_scanner"
        ).setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    if not quiet:
        print_banner()
        console.print(
            "[bold cyan]Starting Lambda security "
            "analysis...[/bold cyan]\n"
        )

    try:
        scanner = LambdaSecurityScanner(
            region=region,
            profile=profile,
            output_dir=output_dir,
            max_workers=max_workers,
            quiet=quiet,
        )

        # Get functions
        all_functions = scanner.get_all_functions()

        # Apply name filter
        if function_name:
            all_functions = [
                f
                for f in all_functions
                if f["FunctionName"] in function_name
            ]
            if not all_functions:
                console.print(
                    "[red]None of the specified "
                    "functions were found[/red]"
                )
                sys.exit(1)

        # Apply exclusions
        if exclude_function:
            original = len(all_functions)
            all_functions = [
                f
                for f in all_functions
                if f["FunctionName"]
                not in exclude_function
            ]
            excluded = original - len(all_functions)
            if not quiet and excluded > 0:
                console.print(
                    f"[yellow]Excluded {excluded} "
                    f"function(s)[/yellow]"
                )

        if not all_functions:
            console.print(
                "[red]No functions found to scan[/red]"
            )
            sys.exit(1)

        if not quiet:
            console.print(
                f"[green]Scanning {len(all_functions)} "
                f"function(s)...[/green]\n"
            )

        results = scanner.scan_all_functions(all_functions)

        if not results:
            console.print(
                "[red]No results generated[/red]"
            )
            sys.exit(1)

        report_files = scanner.generate_reports(
            results, output_format
        )

        if not quiet:
            scanner.print_summary(results)

            console.print(
                "\n[bold green]Reports "
                "Generated:[/bold green]"
            )
            for report_type, file_path in (
                report_files.items()
            ):
                console.print(
                    f"  {report_type.upper()}: "
                    f"{file_path}"
                )

            if compliance_only:
                _print_compliance_detail(results)

        console.print(
            "\n[bold green]Security scan completed "
            "successfully![/bold green]"
        )
        console.print(
            f"[dim]Reports saved to: {output_dir}[/dim]"
        )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Scan interrupted by user[/yellow]"
        )
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        if debug:
            console.print(
                f"[red]{traceback.format_exc()}[/red]"
            )
        sys.exit(1)


def _print_compliance_detail(results):
    from rich.table import Table

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
    valid = [
        r
        for r in results
        if not r.get("scan_error", False)
    ]
    for fw in frameworks:
        all_failed = {}
        for r in valid:
            fw_status = r.get(
                "compliance_status", {}
            ).get(fw, {})
            for ctrl in fw_status.get("failed", []):
                ctrl_id = ctrl["control_id"]
                if ctrl_id not in all_failed:
                    all_failed[ctrl_id] = {
                        "description": ctrl[
                            "description"
                        ],
                        "severity": ctrl.get(
                            "severity", "MEDIUM"
                        ),
                        "functions": [],
                    }
                all_failed[ctrl_id]["functions"].append(
                    r.get("function_name", "")
                )
        if all_failed:
            table = Table(
                title=f"{fw} - Failed Controls"
            )
            table.add_column(
                "Control", style="cyan", width=20
            )
            table.add_column("Description", width=40)
            table.add_column("Severity", width=10)
            table.add_column(
                "Affected", justify="right", width=10
            )
            for ctrl_id, info in sorted(
                all_failed.items()
            ):
                table.add_row(
                    ctrl_id,
                    info["description"],
                    info["severity"],
                    str(len(info["functions"])),
                )
            console.print(table)


main = cli

if __name__ == "__main__":
    cli()
