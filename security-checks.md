# Lambda Security Scanner — Security Checks Design

Comprehensive security checks for AWS Lambda functions, layers,
event source mappings, and account-level serverless settings.

---

## Category A: Function Configuration (7 checks)

### A.1 — Deprecated or End-of-Life Runtime
- **ID:** `A.1`
- **Severity:** HIGH (deprecated) / CRITICAL (blocked) / LOW (near-EOL)
- **Description:** Lambda functions using deprecated or end-of-life runtimes
  no longer receive security patches, leaving known vulnerabilities unpatched.
- **boto3 APIs:** `lambda:get_function_configuration` → `Runtime`
- **Logic:** Check runtime against known deprecated/blocked/near-EOL list.
  Container image functions (`PackageType: Image`) are N/A — skip.
- **Result dict key:** `runtime`
- **Result dict fields:**
  - `runtime`: str — runtime identifier (e.g., `python3.8`)
  - `package_type`: str — `Zip` or `Image`
  - `status`: str — `"blocked"`, `"deprecated"`, `"near_eol"`, or `"supported"`
  - `eol_date`: str|None — EOL date for near-EOL runtimes
- **Runtime lists (as of 2026-03-11):**
  - **BLOCKED:** nodejs, nodejs4.3, nodejs4.3-edge, nodejs6.10, nodejs8.10,
    nodejs10.x, python2.7, dotnetcore1.0, dotnetcore2.0, dotnetcore2.1,
    ruby2.5
  - **DEPRECATED:** nodejs12.x, nodejs14.x, nodejs16.x, nodejs18.x,
    python3.6, python3.7, python3.8, python3.9, dotnetcore3.1, dotnet5.0,
    dotnet6, dotnet7, ruby2.7, java8, go1.x, provided
  - **NEAR-EOL:** nodejs20.x (2026-04-30), ruby3.2 (2026-03-31),
    provided.al2 (2026-07-31), python3.10 (2026-10-31)
  - **SUPPORTED:** nodejs22.x, python3.11, python3.12, python3.13,
    java8.al2, java11, java17, java21, dotnet8, ruby3.3,
    provided.al2, provided.al2023
- **Note:** The runtime lists should be maintained externally and updated as
  AWS deprecates runtimes. The implementation must NOT hardcode a static list
  without a clear update path.

### A.2 — Maximum Timeout Configuration
- **ID:** `A.2`
- **Severity:** LOW
- **Description:** Functions with the maximum timeout (900s) may indicate
  missing timeout tuning, increasing cost and DoS exposure.
- **boto3 APIs:** `lambda:get_function_configuration` → `Timeout`
- **Logic:** Flag functions where `Timeout >= 900`.
- **Result dict key:** `timeout`
- **Result dict fields:**
  - `timeout_seconds`: int
  - `is_max_timeout`: bool

### A.3 — Environment Variable Secrets Exposure
- **ID:** `A.3`
- **Severity:** CRITICAL (secrets found, no KMS) / HIGH (secrets found, has KMS)
- **Description:** Environment variables containing secrets (passwords, API keys,
  tokens, private keys) are visible to anyone with
  `lambda:GetFunctionConfiguration` permission. Secrets should be stored in
  AWS Secrets Manager or SSM Parameter Store.
- **boto3 APIs:** `lambda:get_function_configuration` → `Environment.Variables`,
  `KMSKeyArn`
- **Logic:**
  1. Handle absent `Environment` key (some functions have none)
  2. Scan env var **names** against secret patterns (PASSWORD, SECRET_KEY,
     API_KEY, AUTH_TOKEN, PRIVATE_KEY, DATABASE_URL, etc.)
  3. Scan env var **values** against known secret formats (AKIA*, ghp_*,
     sk_live_*, xox[bpors]-, -----BEGIN PRIVATE KEY-----, connection strings)
  4. Check if `KMSKeyArn` is set (customer-managed KMS key)
- **Scoring note:** The two severity variants are **mutually exclusive** — apply
  the higher deduction only. If secrets found AND no KMS → CRITICAL (-20).
  If secrets found AND has KMS → HIGH (-10). Never both.
- **Result dict key:** `environment_secrets`
- **Result dict fields:**
  - `has_env_vars`: bool — whether function has any env vars
  - `env_var_count`: int
  - `has_secrets`: bool — whether secret patterns were detected
  - `secret_names`: List[str] — env var names matching secret patterns
  - `secret_values`: List[dict] — env var values matching secret formats
  - `kms_key_arn`: str|None
  - `has_kms_key`: bool — whether customer-managed KMS key is set

### A.4 — Large Ephemeral Storage
- **ID:** `A.4`
- **Severity:** LOW
- **Description:** Functions with ephemeral storage larger than the default
  512 MB may persist sensitive data in `/tmp` across warm-start invocations.
- **boto3 APIs:** `lambda:get_function_configuration` → `EphemeralStorage.Size`
- **Logic:** Flag if `Size > 512`.
- **Result dict key:** `ephemeral_storage`
- **Result dict fields:**
  - `size_mb`: int
  - `is_large`: bool

### A.5 — Third-Party or External Lambda Layers
- **ID:** `A.5`
- **Severity:** MEDIUM
- **Description:** Lambda layers from external accounts may contain malicious
  or vulnerable code. Only layers from trusted sources should be used.
- **boto3 APIs:** `lambda:get_function_configuration` → `Layers`
- **Logic:** Parse layer ARNs; flag layers whose account ID differs from the
  scanning account and that are not AWS-managed layers
  (`arn:aws:lambda:::awslayer:`).
- **Result dict key:** `layers`
- **Result dict fields:**
  - `layer_count`: int
  - `layers`: List[str] — layer ARNs
  - `has_external_layers`: bool
  - `external_layers`: List[str]

### A.6 — X-Ray Tracing Disabled
- **ID:** `A.6`
- **Severity:** MEDIUM
- **Description:** X-Ray tracing provides distributed tracing for incident
  investigation, performance monitoring, and compliance audit trails.
  Default mode is `PassThrough` (disabled). `Active` mode causes Lambda
  to actively sample and send traces.
- **boto3 APIs:** `lambda:get_function_configuration` → `TracingConfig.Mode`
- **Logic:** Flag if `Mode != "Active"`.
- **Result dict key:** `tracing`
- **Result dict fields:**
  - `mode`: str — `"Active"` or `"PassThrough"`
  - `enabled`: bool — `True` if mode is `Active`

### A.7 — No Dead Letter Queue Configured
- **ID:** `A.7`
- **Severity:** MEDIUM
- **Description:** Asynchronous invocations without a dead letter queue (SQS/SNS)
  silently discard failed events after retries, losing audit trail and data.
  Note: DLQ is only relevant for async invocations (S3, SNS, EventBridge, etc.),
  not synchronous ones (API Gateway, ALB). This check flags all functions
  unconditionally because any function can be invoked asynchronously.
- **boto3 APIs:** `lambda:get_function_configuration` → `DeadLetterConfig.TargetArn`
- **Logic:** Flag if `TargetArn` is empty/missing.
- **Result dict key:** `dead_letter_config`
- **Result dict fields:**
  - `configured`: bool
  - `target_arn`: str|None
  - `target_type`: str|None — `"SQS"`, `"SNS"`, or `None`

---

## Category B: Access Control (5 checks)

### B.1 — Resource-Based Policy Allows Public Access
- **ID:** `B.1`
- **Severity:** CRITICAL
- **Description:** A resource-based policy with Principal `*` and no Condition
  allows anyone on the internet to invoke the function. Also checks for
  `Principal.Service` grants without `aws:SourceArn` or `aws:SourceAccount`
  conditions (confused deputy risk).
- **boto3 APIs:** `lambda:get_policy`
- **Logic:** Parse policy JSON. Flag if any statement has:
  - `Effect: Allow` + `Principal: *` (or `Principal.AWS: *`) + no `Condition`, OR
  - `Effect: Allow` + `Principal.Service: *` (any service) + no `aws:SourceArn`
    and no `aws:SourceAccount` in `Condition`
  `ResourceNotFoundException` means no policy exists (GOOD — no external access).
- **Note:** This check only evaluates the `$LATEST` version policy. Alias-specific
  policies are not checked (documented limitation).
- **Result dict key:** `resource_policy`
- **Result dict fields:**
  - `has_policy`: bool
  - `is_public`: bool
  - `statement_count`: int
  - `public_statement_count`: int

### B.2 — Function URL with No Authentication
- **ID:** `B.2`
- **Severity:** CRITICAL
- **Description:** Function URLs with `AuthType: NONE` are publicly accessible
  without any authentication. Anyone who discovers the URL can invoke the
  function, risking data exposure and financial exhaustion.
- **boto3 APIs:** `lambda:get_function_url_config`
- **Logic:** Flag if `AuthType == "NONE"`.
  `ResourceNotFoundException` means no URL configured (not applicable).
- **Result dict key:** `function_url`
- **Result dict fields:**
  - `has_url`: bool
  - `auth_type`: str|None — `"NONE"` or `"AWS_IAM"`
  - `is_public`: bool
  - `function_url`: str|None
  - `cors`: dict

### B.3 — Function URL CORS Allows All Origins
- **ID:** `B.3`
- **Severity:** HIGH
- **Description:** A function URL with CORS `AllowOrigins: ["*"]` permits
  any website to make cross-origin requests to the function. Most severe
  when combined with B.2 (AuthType NONE).
- **boto3 APIs:** `lambda:get_function_url_config` → `Cors`
- **Logic:** Flag if `AllowOrigins` contains `*`. Derived from B.2 result.
- **Result dict key:** `function_url_cors`
- **Result dict fields:**
  - `has_cors`: bool
  - `allow_all_origins`: bool
  - `allow_origins`: List[str]
  - `allow_credentials`: bool

### B.4 — Overly Permissive Execution Role
- **ID:** `B.4`
- **Severity:** CRITICAL (admin/wildcard) / HIGH (privilege escalation perms)
- **Description:** Execution roles with AdministratorAccess, wildcard actions
  (`iam:*`, `s3:*`, `*`), or privilege escalation permissions
  (`iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PassRole` with
  resource `*`) violate least privilege and create escalation paths.
- **boto3 APIs:** `lambda:get_function_configuration` → `Role`,
  `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`,
  `iam:ListRolePolicies`, `iam:GetRolePolicy`
- **Logic:** Uses pagination for `ListAttachedRolePolicies` and `ListRolePolicies`.
  1. Check for `AdministratorAccess` / `PowerUserAccess` managed policies
  2. Parse all policy documents for wildcard actions and critical IAM perms
  3. Check for `iam:PassRole` with `Resource: *`
- **Limitation:** Does not account for IAM permission boundaries, which may
  constrain an otherwise overly-permissive role. May produce false positives
  on boundary-constrained roles.
- **Result dict key:** `execution_role`
- **Result dict fields:**
  - `role_name`: str
  - `has_admin_access`: bool
  - `has_wildcard_actions`: bool
  - `has_privilege_escalation`: bool
  - `dangerous_permissions`: List[str]
  - `attached_policy_count`: int

### B.5 — Shared Execution Role Across Functions
- **ID:** `B.5`
- **Severity:** HIGH
- **Description:** Multiple Lambda functions sharing the same execution role
  violates least privilege. If one function is compromised, the attacker
  gains the permissions of all functions using that role.
- **boto3 APIs:** `lambda:ListFunctions` → `Role` (cross-function comparison,
  **must use pagination** — max 50 per page)
- **Logic:** Count how many scanned functions share the same role ARN.
  Flag if count > 1.
- **Result dict key:** `shared_role`
- **Result dict fields:**
  - `is_shared`: bool
  - `shared_count`: int
  - `role_arn`: str

---

## Category C: Network Security (3 checks)

### C.1 — No VPC Configuration
- **ID:** `C.1`
- **Severity:** LOW
- **Description:** Functions not deployed in a VPC lack network-level isolation
  and cannot use security groups or VPC flow logs for monitoring. Functions
  processing sensitive data should be VPC-attached.
- **boto3 APIs:** `lambda:get_function_configuration` → `VpcConfig.VpcId`
- **Logic:** Flag if `VpcId` is empty.
- **Result dict key:** `vpc_config`
- **Result dict fields:**
  - `in_vpc`: bool
  - `vpc_id`: str|None
  - `subnet_count`: int
  - `subnet_ids`: List[str]
  - `security_group_count`: int
  - `security_group_ids`: List[str]

### C.2 — VPC Lambda in Single Availability Zone
- **ID:** `C.2`
- **Severity:** MEDIUM
- **Description:** VPC Lambda functions deployed in subnets from a single AZ
  have reduced availability. Best practice is at least 2 AZs.
- **boto3 APIs:** `lambda:get_function_configuration` → `VpcConfig.SubnetIds`,
  `ec2:DescribeSubnets` → `AvailabilityZone`
- **Logic:** Resolve subnet IDs to AZs; flag if distinct AZ count < 2.
  Only applicable to VPC-attached functions.
- **Result dict key:** `multi_az`
- **Result dict fields:**
  - `applicable`: bool — only True when function is in a VPC
  - `is_multi_az`: bool
  - `az_count`: int
  - `availability_zones`: List[str]

### C.3 — Unrestricted Security Group Egress
- **ID:** `C.3`
- **Severity:** MEDIUM
- **Description:** VPC Lambda functions with security groups allowing
  unrestricted outbound traffic (0.0.0.0/0 all ports) can exfiltrate data
  to any internet destination.
- **boto3 APIs:** `lambda:get_function_configuration` → `VpcConfig.SecurityGroupIds`,
  `ec2:DescribeSecurityGroups`
- **Logic:** Check egress rules for 0.0.0.0/0 with protocol -1 or ports 0-65535.
  Only applicable to VPC-attached functions.
- **Result dict key:** `security_groups`
- **Result dict fields:**
  - `applicable`: bool
  - `unrestricted_egress`: bool
  - `security_groups`: List[dict]

---

## Category D: Logging & Monitoring (2 checks)

### D.1 — CloudWatch Log Group Missing or No Retention
- **ID:** `D.1`
- **Severity:** MEDIUM
- **Description:** Missing log groups indicate the function has never executed
  or logs were deleted. No retention policy means logs are kept indefinitely
  (cost/compliance risk) or may be set too short for regulatory requirements.
- **boto3 APIs:** `logs:DescribeLogGroups` (prefix: `/aws/lambda/{name}`)
- **Logic:** Check exact-match log group exists; check `retentionInDays` is set.
- **Scoring note:** Two sub-findings (missing log group vs. no retention) share
  a single -5 deduction. They are NOT additive — a function can only get -5
  from D.1 total.
- **Result dict key:** `log_group`
- **Result dict fields:**
  - `exists`: bool
  - `retention_days`: int|None
  - `has_retention`: bool
  - `kms_encrypted`: bool

### D.2 — No Reserved Concurrency Configured
- **ID:** `D.2`
- **Severity:** MEDIUM
- **Description:** Without reserved concurrency, a single function can consume
  the entire account concurrency limit, causing account-wide throttling (DoS).
  Combined with public access, this becomes a financial exhaustion vector.
- **boto3 APIs:** `lambda:GetFunctionConcurrency`
- **Logic:** Flag if `ReservedConcurrentExecutions` is not set.
  `ResourceNotFoundException` means no concurrency config (flag it).
  Note: `ReservedConcurrentExecutions: 0` means the function is **completely
  throttled** (disabled), which is a distinct case — flag as INFO, not MEDIUM.
- **Result dict key:** `reserved_concurrency`
- **Result dict fields:**
  - `configured`: bool
  - `reserved_executions`: int|None
  - `is_disabled`: bool — True when reserved == 0

---

## Category E: Code & Supply Chain Security (2 checks)

### E.1 — No Code Signing Configuration
- **ID:** `E.1`
- **Severity:** MEDIUM (no config) / LOW (Warn policy instead of Enforce)
- **Description:** Code signing ensures only trusted, signed code runs in
  production. Without it, tampered or unauthorized code can be deployed.
  Only applicable to `PackageType: Zip` functions — container image functions
  cannot use code signing.
- **boto3 APIs:** `lambda:GetFunctionCodeSigningConfig`,
  `lambda:GetCodeSigningConfig`
- **Logic:** Flag if no `CodeSigningConfigArn`. If present, check if
  `UntrustedArtifactOnDeployment` policy is `Enforce` (best) or `Warn`.
  `ResourceNotFoundException` means no config (flag it).
  Skip check entirely for `PackageType: Image` functions.
- **Result dict key:** `code_signing`
- **Result dict fields:**
  - `configured`: bool
  - `policy`: str|None — `"Enforce"` or `"Warn"`
  - `config_arn`: str|None
  - `is_enforced`: bool — True only when policy is `Enforce`

### E.2 — Event Source Mapping Without Failure Destination
- **ID:** `E.2`
- **Severity:** MEDIUM
- **Description:** Event source mappings (SQS, Kinesis, DynamoDB Streams)
  without an OnFailure destination silently drop failed records, losing
  audit trail and data.
- **boto3 APIs:** `lambda:ListEventSourceMappings` (**must use pagination**)
- **Logic:** For each ESM, safely traverse
  `DestinationConfig` → `OnFailure` → `Destination` using nested `.get()`.
  Flag ESMs with no failure destination. `DestinationConfig` itself may be
  absent (not just `OnFailure.Destination`).
- **Result dict key:** `event_source_mappings`
- **Result dict fields:**
  - `mapping_count`: int
  - `mappings`: List[dict]
  - `missing_failure_dest_count`: int
  - `missing_failure_destinations`: List[str]
  - `has_mappings`: bool

---

## Composite / Cross-Check Findings

### Public Access + No Reserved Concurrency
- **Severity:** CRITICAL
- **Description:** A function that is publicly accessible (via resource policy
  or function URL) AND has no reserved concurrency is vulnerable to both
  financial exhaustion and account-wide DoS.
- **Logic:** Computed in `_analyze_issues()` by combining B.1/B.2 with D.2.
- **Scoring:** No additional deduction beyond B.1/B.2 (-25) and D.2 (-5).
  The composite finding is severity-only — it appears in the issues list
  for visibility but does not add extra points.

### Public Function URL + CORS Wildcard
- **Severity:** CRITICAL
- **Description:** A function URL with AuthType NONE and CORS AllowOrigins `*`
  is maximally exposed — any website can invoke it cross-origin.
- **Logic:** Computed in `_analyze_issues()` by combining B.2 with B.3.
- **Scoring:** No additional deduction beyond B.2 (-25) and B.3 (-10).

---

## Implementation Notes

### Pagination Requirements
All paginated APIs **MUST** use `get_paginator()`. Never call without pagination:
- `lambda:ListFunctions` — max 50 per page
- `lambda:ListEventSourceMappings` — max 100 per page
- `iam:ListAttachedRolePolicies` — max 100 per page
- `iam:ListRolePolicies` — max 100 per page

### Rate Limiting
All Lambda APIs can raise `TooManyRequestsException`. The scanner must handle
throttling with exponential backoff, especially when scanning 100+ functions.

### Region Scope
`ListFunctions` is region-scoped. The scanner operates on a single region
per invocation. Multi-region scanning requires running the scanner once per region.

### Alias/Version Limitation
`GetPolicy`, `GetFunctionUrlConfig`, and `GetFunctionCodeSigningConfig` accept
a `Qualifier` parameter for aliases/versions. This scanner only checks the
`$LATEST` version. Alias-specific policies are NOT checked. This is a
documented limitation.

---

## Summary Table

| ID  | Check                                    | Severity          | Category              |
|-----|------------------------------------------|-------------------|-----------------------|
| A.1 | Deprecated/EOL runtime                   | HIGH/CRITICAL/LOW | Function Config       |
| A.2 | Maximum timeout (900s)                   | LOW               | Function Config       |
| A.3 | Environment variable secrets             | CRITICAL/HIGH     | Function Config       |
| A.4 | Large ephemeral storage                  | LOW               | Function Config       |
| A.5 | External Lambda layers                   | MEDIUM            | Function Config       |
| A.6 | X-Ray tracing disabled                   | MEDIUM            | Function Config       |
| A.7 | No dead letter queue                     | MEDIUM            | Function Config       |
| B.1 | Resource policy public access            | CRITICAL          | Access Control        |
| B.2 | Function URL no authentication           | CRITICAL          | Access Control        |
| B.3 | Function URL CORS allows all origins     | HIGH              | Access Control        |
| B.4 | Overly permissive execution role         | CRITICAL/HIGH     | Access Control        |
| B.5 | Shared execution role                    | HIGH              | Access Control        |
| C.1 | No VPC configuration                     | LOW               | Network Security      |
| C.2 | VPC single AZ                            | MEDIUM            | Network Security      |
| C.3 | Unrestricted SG egress                   | MEDIUM            | Network Security      |
| D.1 | Log group missing/no retention           | MEDIUM            | Logging & Monitoring  |
| D.2 | No reserved concurrency                  | MEDIUM            | Logging & Monitoring  |
| E.1 | No code signing                          | MEDIUM/LOW        | Code & Supply Chain   |
| E.2 | ESM without failure destination          | MEDIUM            | Code & Supply Chain   |

**Total: 19 checks across 5 categories**

---

## Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
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
        }
    ]
}
```

---

## Scoring Design

Start at 100 points. Deductions:

| Check | Condition                                        | Deduction |
|-------|--------------------------------------------------|-----------|
| B.1   | Resource policy allows public access             | -25       |
| B.2   | Function URL AuthType NONE                       | -25       |
| A.3   | Env var secrets found, no KMS (mutually excl.)   | -20       |
| B.4   | Admin access or wildcard actions                 | -20       |
| A.1   | Runtime status = `blocked`                       | -15       |
| A.1   | Runtime status = `deprecated`                    | -10       |
| B.3   | CORS allows all origins                          | -10       |
| B.4   | Privilege escalation permissions (no admin/wild) | -10       |
| B.5   | Shared execution role                            | -10       |
| A.3   | Env var secrets found, has KMS (mutually excl.)  | -10       |
| A.6   | X-Ray tracing disabled                           | -5        |
| A.7   | No dead letter queue                             | -5        |
| C.2   | VPC single AZ                                    | -5        |
| C.3   | Unrestricted SG egress                           | -5        |
| D.1   | Log group missing OR no retention (max -5 total) | -5        |
| D.2   | No reserved concurrency                          | -5        |
| E.1   | No code signing config                           | -5        |
| E.2   | ESM without failure destination                  | -5        |
| A.5   | External Lambda layers                           | -3        |
| C.1   | No VPC configuration                             | -3        |
| A.1   | Runtime status = `near_eol`                      | -3        |
| E.1   | Code signing policy = Warn (not Enforce)         | -3        |
| A.2   | Maximum timeout (900s)                           | -2        |
| A.4   | Large ephemeral storage                          | -2        |

**Mutual exclusion rules:**
- A.1: Only the highest-severity runtime deduction applies (blocked > deprecated > near_eol)
- A.3: Only one of the two variants applies (no KMS > has KMS)
- E.1: Only one of the two variants applies (no config > Warn policy)

Floor: max(0, score)

Score bands:
- 90-100: Excellent
- 70-89: Good
- 50-69: Needs Improvement
- 0-49: Poor
