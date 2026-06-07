<p align="center">
  <img src="https://raw.githubusercontent.com/TocConsulting/lambda-security-scanner/main/assets/lambda-security-scanner-logo.png" alt="Lambda Security Scanner" style="max-width: 100%; height: auto;">
</p>

<p align="center">
  <a href="https://pypi.org/project/lambda-security-scanner/"><img src="https://img.shields.io/pypi/v/lambda-security-scanner.svg" alt="PyPI version"></a>
  <a href="https://pepy.tech/project/lambda-security-scanner"><img src="https://static.pepy.tech/badge/lambda-security-scanner" alt="Downloads"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/lambda-security-scanner"><img src="https://img.shields.io/docker/v/tarekcheikh/lambda-security-scanner?label=docker&logo=docker" alt="Docker"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/lambda-security-scanner"><img src="https://img.shields.io/docker/pulls/tarekcheikh/lambda-security-scanner" alt="Docker Pulls"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-brightgreen.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python"></a>
  <a href="https://aws.amazon.com/lambda/"><img src="https://img.shields.io/badge/AWS-Lambda-orange.svg" alt="AWS"></a>
</p>

A comprehensive AWS Lambda security scanner with 21 security checks across 5 categories and compliance mapping for 10 frameworks (81 controls). Features multi-threaded scanning, secret detection in environment variables, and interactive HTML dashboards.

<p align="center">
  <img src="https://raw.githubusercontent.com/TocConsulting/lambda-security-scanner/main/assets/demo.gif" alt="Lambda Security Scanner demo: secrets, public URLs, IAM, and multi-framework compliance" width="100%">
</p>

## Key Features

### **Comprehensive Security Analysis**
- **Function Configuration**: Deprecated runtime detection, timeout tuning, environment variable secret scanning, ephemeral storage, external layers, X-Ray tracing, dead letter queues
- **Access Control**: Resource policy public access, function URL authentication, CORS wildcard origins, overly permissive execution roles, shared role detection, cross-account async-invoke destinations, alias traffic shadowing
- **Network Security**: VPC configuration, multi-AZ deployment, unrestricted security group egress
- **Logging & Monitoring**: CloudWatch log group validation, log retention policies, reserved concurrency
- **Code & Supply Chain**: Code signing configuration, event source mapping failure destinations

### **Compliance Frameworks**
- **AWS Foundational Security Best Practices (FSBP)**: 5 Lambda-specific controls
- **CIS AWS Compute Services Benchmark**: 8 controls (scanner-defined IDs mapped to the benchmark's Lambda guidance; see note below)
- **PCI DSS v4.0.1**: 8 controls
- **HIPAA Security Rule**: 9 controls
- **SOC 2**: 11 controls
- **ISO 27001:2022**: 11 controls
- **ISO 27017:2015**: 4 cloud security controls
- **ISO 27018:2019**: 5 PII protection controls
- **GDPR (EU) 2016/679**: 8 controls
- **NIST SP 800-53 Rev5**: 12 controls

### **Performance & Usability**
- **Multi-threaded Scanning**: Parallel function analysis with ThreadPoolExecutor
- **Rich Console Output**: Progress bars, colored output, and formatted tables
- **Multiple Report Formats**: JSON, CSV, HTML, and compliance-specific reports
- **Beautiful HTML Reports**: Interactive dashboard with Chart.js visualizations
- **Flexible Targeting**: Scan all functions, specific names, or exclude by name

### **Production Ready**
- **Modular Architecture**: Facade pattern with 5 dedicated checker modules
- **Thread-safe Sessions**: Thread-local boto3 session management
- **Graceful Degradation**: AccessDenied errors don't crash scans
- **Mutual Exclusion Scoring**: Overlapping check variants use highest deduction only

## Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/TocConsulting/lambda-security-scanner.git
cd lambda-security-scanner
pip install .
```

### Docker Installation

```bash
# Build from source
docker build -t lambda-security-scanner .
```

### Basic Usage

```bash
# Scan all Lambda functions
lambda-security-scanner security

# Scan with specific AWS profile
lambda-security-scanner security --profile production

# Scan specific functions only
lambda-security-scanner security -n my-function -n other-function

# Exclude specific functions
lambda-security-scanner security --exclude-function test-func

# Compliance report only
lambda-security-scanner security --compliance-only

# JSON report only, quiet mode (for CI/CD)
lambda-security-scanner security -f json -q
```

## Commands

### Security Command

Scan Lambda functions for security vulnerabilities and compliance issues.

```bash
lambda-security-scanner security [OPTIONS]

Options:
  -n, --function-name TEXT       Specific function name(s) to scan (multiple)
  --exclude-function TEXT        Function name(s) to exclude
  --compliance-only              Generate compliance report only
  -r, --region TEXT              AWS region (default: us-east-1)
  -p, --profile TEXT             AWS profile name
  -o, --output-dir TEXT          Output directory (default: ./output)
  -f, --output-format TEXT       Report format: json, csv, html, all (default: all)
  -w, --max-workers INTEGER      Worker threads (default: 5)
  -q, --quiet                    Suppress console output except errors
  -d, --debug                    Enable debug logging
  -h, --help                     Show help

# Top-level options (before the 'security' command):
#   lambda-security-scanner --version
#   lambda-security-scanner --help
```

**Examples:**
```bash
# Scan all functions with default settings
lambda-security-scanner security

# Scan specific functions in a different region
lambda-security-scanner security -n my-api -n my-worker -r eu-west-1

# Fast compliance-only scan with HTML output
lambda-security-scanner security --compliance-only -f html -p production

# High-performance scan with more threads
lambda-security-scanner security -w 20 -r eu-west-1

# JSON report only, quiet mode (for CI/CD)
lambda-security-scanner security -f json -q
```

## Security Checks

### 21 Checks Across 5 Categories

| ID  | Check                                    | Severity          | Category              |
|-----|------------------------------------------|-------------------|-----------------------|
| A.1 | Deprecated/EOL runtime                   | HIGH/CRITICAL/LOW | Function Config       |
| A.2 | Maximum timeout (900s)                   | LOW               | Function Config       |
| A.3 | Environment variable secrets             | CRITICAL/HIGH     | Function Config       |
| A.4 | Large ephemeral storage                  | LOW               | Function Config       |
| A.5 | External Lambda layers                   | MEDIUM            | Function Config       |
| A.6 | X-Ray tracing disabled                   | LOW               | Function Config       |
| A.7 | No dead letter queue                     | LOW               | Function Config       |
| B.1 | Resource policy public access            | CRITICAL          | Access Control        |
| B.2 | Function URL no authentication           | CRITICAL          | Access Control        |
| B.3 | Function URL CORS allows all origins     | HIGH              | Access Control        |
| B.4 | Overly permissive execution role         | CRITICAL/HIGH     | Access Control        |
| B.5 | Shared execution role                    | HIGH              | Access Control        |
| B.6 | Async-invoke destination to external account | CRITICAL      | Access Control        |
| B.7 | Alias traffic shadowing (weighted alias) | MEDIUM            | Access Control        |
| C.1 | No VPC configuration                     | LOW               | Network Security      |
| C.2 | VPC single AZ                            | MEDIUM            | Network Security      |
| C.3 | Unrestricted SG egress                   | MEDIUM            | Network Security      |
| D.1 | Log group missing/no retention           | MEDIUM            | Logging & Monitoring  |
| D.2 | No reserved concurrency                  | LOW               | Logging & Monitoring  |
| E.1 | No code signing                          | MEDIUM/LOW        | Code & Supply Chain   |
| E.2 | ESM without failure destination          | MEDIUM            | Code & Supply Chain   |

### Secret Detection in Environment Variables (A.3)

The scanner decodes and scans Lambda environment variables for exposed secrets:

| Pattern | Examples |
|---------|----------|
| AWS Access Keys | `AKIA...`, `ASIA...` |
| AWS Secret Keys | `aws_secret_access_key=...` |
| Passwords | `PASSWORD=`, `DB_PASSWORD=`, `SECRET_KEY=` |
| Private Keys | `-----BEGIN PRIVATE KEY-----` |
| GitHub Tokens | `ghp_...`, `gho_...`, `ghs_...` |
| API Keys | `api_key=`, `api_token=`, `AUTH_TOKEN=` |
| Connection Strings | `postgres://user:pass@host/db` |
| SaaS Tokens | Slack, Stripe (`sk_live_`), Twilio, SendGrid |

**Safe references are not flagged.** A secret-named variable whose value is a managed-secret reference (a Secrets Manager / SSM / KMS ARN, an SSM parameter path like `/app/db/pwd`, or a CloudFormation `{{resolve:...}}` dynamic reference) is the AWS-recommended pattern and is treated as clean, not as a leaked secret. Trivial config values (booleans, ports, environment names) are likewise ignored.

## Compliance Frameworks

| Framework | Controls | Focus |
|-----------|----------|-------|
| AWS-FSBP | 5 | Lambda-specific Security Hub controls |
| CIS | 8 | Compute Services Benchmark |
| PCI DSS v4.0.1 | 8 | Payment card data protection |
| HIPAA | 9 | Healthcare data security |
| SOC 2 | 11 | Service organization controls |
| ISO 27001:2022 | 11 | Information security management |
| ISO 27017:2015 | 4 | Cloud security controls |
| ISO 27018:2019 | 5 | PII protection in cloud |
| GDPR | 8 | EU data protection regulation |
| NIST 800-53 Rev5 | 12 | Federal security controls |

> **Note on control IDs:** Most frameworks use their official citations (e.g. HIPAA `164.312(a)(1)`, ISO 27001 `A.5.15`, SOC 2 `CC6.1`, NIST `AC-3`). The **CIS** entries map to the real **CIS AWS Compute Services Benchmark** Lambda guidance, but the `CIS-Lambda.N` identifiers are this scanner's own labels, not the benchmark's official recommendation numbers (which are section `5.x`). They are an alignment aid, not verbatim CIS control numbers.

## Docker Usage

### Basic Docker Commands

```bash
# Show help
docker run --rm lambda-security-scanner --help

# Show security command help
docker run --rm lambda-security-scanner security --help
```

### Security Scanning with Docker

```bash
# Scan using mounted AWS credentials
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  lambda-security-scanner security

# Scan with specific AWS profile
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  lambda-security-scanner security --profile production

# Scan specific functions
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  lambda-security-scanner security -n my-function
```

### Using Environment Variables for AWS Credentials

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  lambda-security-scanner security

# With session token (for temporary credentials/assumed roles)
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  lambda-security-scanner security
```

### Docker Volume Mounts

| Mount | Purpose |
|-------|---------|
| `-v ~/.aws:/root/.aws:ro` | Mount AWS credentials (read-only) |
| `-v $(pwd)/output:/app/output` | Save reports to local directory |

## Prerequisites

### Python Requirements
- Python 3.10 or higher
- Required packages (installed automatically):
  - `boto3>=1.26.0`
  - `botocore>=1.29.0`
  - `rich>=13.0.0`
  - `click>=8.1.0`
  - `jinja2>=3.1.0`

### AWS Requirements
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- Required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "lambda:ListFunctions",
            "lambda:GetFunctionConfiguration",
            "lambda:GetPolicy",
            "lambda:GetFunctionUrlConfig",
            "lambda:GetFunctionCodeSigningConfig",
            "lambda:GetCodeSigningConfig",
            "lambda:GetFunctionConcurrency",
            "lambda:ListEventSourceMappings",
            "lambda:GetFunctionEventInvokeConfig",
            "lambda:ListAliases",
            "iam:ListAttachedRolePolicies",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
            "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups",
            "logs:DescribeLogGroups",
            "sts:GetCallerIdentity"
        ],
        "Resource": "*"
    }]
}
```

## Security Scoring

Each function receives a security score (0-100) starting at **100 points**:

| Check | Condition | Deduction | Severity |
|-------|-----------|-----------|----------|
| B.1 | Resource policy allows public access | -25 | CRITICAL |
| B.2 | Function URL AuthType NONE | -25 | CRITICAL |
| A.3 | Env var secrets, no KMS (mutually excl.) | -20 | CRITICAL |
| B.4 | Admin-equivalent access (Administrator/PowerUser/IAMFull or `*`) | -20 | CRITICAL |
| A.1 | Runtime blocked | -15 | HIGH |
| A.1 | Runtime deprecated | -10 | HIGH |
| B.3 | CORS allows all origins | -10 | HIGH |
| B.4 | Service-level wildcard actions (e.g. `s3:*`) | -10 | HIGH |
| B.4 | Privilege escalation permissions | -10 | HIGH |
| B.5 | Shared execution role | -10 | HIGH |
| A.3 | Env var secrets, has KMS (mutually excl.) | -10 | HIGH |
| C.2 | VPC single AZ | -5 | MEDIUM |
| C.3 | Unrestricted SG egress | -5 | MEDIUM |
| D.1 | Log group missing or no retention | -5 | MEDIUM |
| A.6 | X-Ray tracing disabled | -2 | LOW |
| A.7 | No dead letter queue | -2 | LOW |
| D.2 | No reserved concurrency | -2 | LOW |
| E.1 | No code signing config | -5 | MEDIUM |
| E.2 | ESM without failure destination | -5 | MEDIUM |
| A.5 | External Lambda layers | -3 | MEDIUM |
| C.1 | No VPC configuration | -3 | LOW |
| A.1 | Runtime near EOL | -3 | LOW |
| E.1 | Code signing policy Warn (not Enforce) | -3 | LOW |
| A.2 | Maximum timeout (900s) | -2 | LOW |
| A.4 | Large ephemeral storage | -2 | LOW |

**Mutual exclusion rules:**
- A.1: Only the highest-severity runtime deduction applies (blocked > deprecated > near_eol)
- A.3: Only one of the two variants applies (no KMS > has KMS)
- E.1: Only one of the two variants applies (no config > Warn policy)

**Formula**: `Score = max(0, 100 - total_deductions)`

### Score Interpretation

| Score Range | Level | Action |
|-------------|-------|--------|
| 90-100 | Excellent | Maintain current posture |
| 70-89 | Good | Address minor gaps |
| 50-69 | Needs Improvement | Fix medium-priority issues |
| 0-49 | Poor | Immediate action required |

## Output Files

The scanner generates reports in the specified output directory:

### JSON Report (`lambda_scan_region_timestamp.json`)
```json
{
  "summary": {
    "scan_time": "2026-03-11T10:30:45",
    "region": "us-east-1",
    "account_id": "123456789012",
    "total_functions": 25,
    "average_security_score": 82.3
  },
  "results": [...]
}
```

### CSV Report (`lambda_scan_region_timestamp.csv`)
Spreadsheet-friendly format with all key metrics and compliance status.

### HTML Report (`lambda_scan_region_timestamp.html`)
Interactive dashboard with:
- **Executive Summary**: Key metrics and risk indicators
- **Score Distribution**: Bar chart of function security scores
- **Compliance Overview**: Bar chart across all 10 frameworks
- **Severity Breakdown**: Doughnut chart of findings by severity
- **Function Details**: Sortable table with score bars
- **Critical Findings**: Table of high/critical severity issues

### Compliance Report (`lambda_compliance_region_timestamp.json`)
Per-function compliance evaluation across all 10 frameworks with passed/failed control details.

## Modular Architecture

```
lambda_security_scanner/
├── scanner.py                  # Main scanner orchestration (facade pattern)
├── cli.py                      # Click CLI interface
├── compliance.py               # 81 controls across 10 frameworks
├── html_reporter.py            # Jinja2 HTML report generation
├── utils.py                    # Logging, scoring, formatting
├── checks/                     # Security check modules
│   ├── base.py                 # BaseChecker (session factory, error handling)
│   ├── function_config.py      # A.1-A.7: Runtime, secrets, layers, tracing
│   ├── access_control.py       # B.1-B.7: Policies, URLs, roles, destinations, aliases
│   ├── network_security.py     # C.1-C.3: VPC, AZ, security groups
│   ├── logging_monitoring.py   # D.1-D.2: Log groups, concurrency
│   └── code_security.py        # E.1-E.2: Code signing, ESM
└── templates/
    └── report.html             # Interactive HTML dashboard
```

## Development

### Setting Up Development Environment

```bash
git clone https://github.com/TocConsulting/lambda-security-scanner.git
cd lambda-security-scanner

python -m venv venv
source venv/bin/activate

pip install -e ".[dev]"
```

## Testing

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_compliance.py -v

# Run with coverage
python -m pytest tests/ --cov=lambda_security_scanner --cov-report=html

# Code formatting
black lambda_security_scanner/ tests/
```

## Support & Contributing

### Getting Help
- **Documentation**: Check this README and inline help (`--help`)
- **Issues**: Report bugs via [GitHub Issues](https://github.com/TocConsulting/lambda-security-scanner/issues)

### Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **AWS Security Best Practices**: Based on official AWS security recommendations
- **CIS Benchmarks**: Maps findings to the CIS AWS Compute Services Benchmark Lambda guidance (scanner-defined control identifiers)
- **[ec2-security-scanner](https://github.com/TocConsulting/ec2-security-scanner)**: Architecture and design patterns

---

**Security Notice**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before scanning AWS resources. The tool requires read-only permissions and does not modify any AWS resources.

**Performance Note**: The scanner uses parallel function analysis with ThreadPoolExecutor to minimize scan time. Use `-w` to adjust parallelism based on your API rate limits.
