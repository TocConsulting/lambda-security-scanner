# Lambda Security Scanner - Comprehensive Remediation Guide

This guide provides step-by-step remediation instructions for all security vulnerabilities detected by the Lambda Security Scanner. Each vulnerability includes remediation steps using AWS Console, AWS CLI, and Python boto3 methods. Check IDs (A.1, B.2, ...) match [security-checks.md](security-checks.md); framework mappings are in [compliance.md](compliance.md).

> **Principle**: keep functions least-privileged, private by default, and free of plaintext secrets. Prefer Secrets Manager / SSM Parameter Store, supported runtimes, and per-function execution roles.

> **Note on compliance tokens**: the `Compliance:` line on each finding lists indicative framework references for orientation. The authoritative, per-check control mappings are maintained in [compliance.md](compliance.md).

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|------------------|
| Lambda Security | [Security in Lambda](https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html) |
| Lambda Runtimes | [Lambda Runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) |
| Environment Variables & Secrets | [Securing Environment Variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html) |
| Resource-Based Policies | [Lambda Resource Access](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html) |
| Function URLs | [Lambda Function URLs](https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html) |
| Execution Role | [Lambda Execution Role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html) |
| VPC Configuration | [Lambda in a VPC](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html) |
| Code Signing | [Code Signing for Lambda](https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html) |
| AWS CLI Lambda Commands | [AWS CLI Lambda Reference](https://docs.aws.amazon.com/cli/latest/reference/lambda/) |
| Boto3 Lambda Documentation | [Boto3 Lambda Service](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lambda.html) |

## Table of Contents

1. [Function Configuration](#function-configuration)
2. [Access Control](#access-control)
3. [Network Security](#network-security)
4. [Logging & Monitoring](#logging--monitoring)
5. [Code & Supply Chain Security](#code--supply-chain-security)
6. [Quick Reference Commands](#quick-reference-commands)
7. [Additional Notes](#additional-notes)

---

## Function Configuration

### 1. Upgrade Deprecated or End-of-Life Runtimes

**Issue**: Function uses a deprecated, blocked, or near-EOL runtime (check A.1)
**Severity**: CRITICAL (blocked), HIGH (deprecated), LOW (near-EOL)
**Compliance**: AWS-FSBP Lambda.2, PCI-DSS 6.3.3, NIST SI-2, RA-5, ISO 27001 A.8.8

EOL runtimes stop receiving security patches. Move to a supported runtime (for example `python3.13`, `nodejs22.x`, `java21`, `dotnet8`, `ruby3.3`), testing the function on the new runtime first.

#### AWS Console
1. **Lambda Console** -> select the function -> **Code** tab -> **Runtime settings** -> **Edit**
2. Choose a supported runtime version
3. Test, then **Save**

#### AWS CLI
```bash
aws lambda update-function-configuration \
  --function-name myfunc \
  --runtime python3.13

# Verify
aws lambda get-function-configuration --function-name myfunc \
  --query 'Runtime'
```

#### Python boto3
```python
import boto3

# Illustrative subset only. Check A.1 is three-valued (blocked=CRITICAL,
# deprecated=HIGH, near-EOL=LOW); maintain the full lists externally and update
# them as AWS deprecates runtimes (do not rely on this hardcoded set).
DEPRECATED = {'python3.8', 'python3.9', 'nodejs16.x', 'nodejs18.x',
              'java8', 'go1.x', 'ruby2.7', 'dotnetcore3.1'}

def find_deprecated_runtimes():
    lam = boto3.client('lambda')
    flagged = []
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            rt = fn.get('Runtime')  # absent for container images
            if rt and rt in DEPRECATED:
                flagged.append((fn['FunctionName'], rt))
    for name, rt in flagged:
        print(f"{name}: deprecated runtime {rt} -> upgrade")
    return flagged

# Usage
find_deprecated_runtimes()
```

---

### 2. Tune the Function Timeout

**Issue**: Function is configured with the maximum timeout (900s) (check A.2)
**Severity**: LOW
**Compliance**: Best-practice (no direct FSBP control), NIST SC-5, SC-6, ISO 27001 A.8.6

A 900s timeout often signals untuned configuration and widens cost/DoS exposure. Set the timeout to a realistic value just above the function's p99 duration.

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **General configuration** -> **Edit**
2. Set **Timeout** to a value matched to the workload (for example 30s)
3. **Save**

#### AWS CLI
```bash
aws lambda update-function-configuration \
  --function-name myfunc \
  --timeout 30
```

#### Python boto3
```python
import boto3

def right_size_timeout(function_name, seconds=30):
    lam = boto3.client('lambda')
    lam.update_function_configuration(FunctionName=function_name,
                                      Timeout=seconds)
    print(f"{function_name} timeout set to {seconds}s.")

# Usage
# right_size_timeout('myfunc', 30)
```

---

### 3. Move Environment-Variable Secrets to Secrets Manager

**Issue**: Plaintext secrets in environment variables (check A.3)
**Severity**: CRITICAL (no KMS), HIGH (has customer KMS key)
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 8.3.x, HIPAA 164.312(a)(2)(i), GDPR Art.32, NIST IA-5, SC-12, ISO 27001 A.8.12, A.8.24

Env vars are readable by anyone with `lambda:GetFunctionConfiguration`. Store secrets in Secrets Manager or SSM Parameter Store and fetch them at runtime; at minimum, encrypt env vars with a customer-managed KMS key.

#### AWS Console
1. Store the secret in **Secrets Manager** (or SSM Parameter Store as a SecureString)
2. **Lambda Console** -> function -> **Configuration** -> **Environment variables** -> remove the plaintext secret
3. Grant the execution role `secretsmanager:GetSecretValue` (or `ssm:GetParameter`) and fetch at runtime
4. Under **Encryption configuration**, set a customer-managed **KMS key** for any remaining env vars

#### AWS CLI
```bash
# Store the secret
aws secretsmanager create-secret --name myfunc/db-password \
  --secret-string 'S3cr3t!'

# WARNING: --environment REPLACES the entire variable map (it is not a merge).
# First read the current vars, then re-supply EVERY non-secret key you want to keep:
#   aws lambda get-function-configuration --function-name myfunc \
#     --query 'Environment.Variables'
aws lambda update-function-configuration --function-name myfunc \
  --environment 'Variables={LOG_LEVEL=info}' \
  --kms-key-arn arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID
```

#### Python boto3
```python
import boto3

SECRET_HINTS = ('PASSWORD', 'SECRET', 'TOKEN', 'API_KEY', 'PRIVATE_KEY',
                'DATABASE_URL', 'CONNECTION_STRING', 'CREDENTIALS')

def find_env_secrets():
    lam = boto3.client('lambda')
    flagged = []
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            env = fn.get('Environment', {}).get('Variables', {})
            has_kms = bool(fn.get('KMSKeyArn'))
            for key in env:
                if any(h in key.upper() for h in SECRET_HINTS):
                    sev = 'HIGH' if has_kms else 'CRITICAL'
                    flagged.append((fn['FunctionName'], key, sev))
    for name, key, sev in flagged:
        print(f"{sev}: {name} env var {key} -> move to Secrets Manager")
    return flagged

# Usage
find_env_secrets()
```

---

### 4. Reduce or Justify Large Ephemeral Storage

**Issue**: Ephemeral storage (`/tmp`) larger than the 512 MB default (check A.4)
**Severity**: LOW
**Compliance**: Best-practice (no direct FSBP control), NIST SC-28, MP-6, ISO 27001 A.8.10

Large `/tmp` can persist sensitive data across warm-start invocations. Reduce it to the default unless the workload needs more, and clear sensitive temp files before returning.

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **General configuration** -> **Edit**
2. Set **Ephemeral storage** back to **512 MB** (or the minimum needed)
3. **Save**

#### AWS CLI
```bash
aws lambda update-function-configuration \
  --function-name myfunc \
  --ephemeral-storage Size=512
```

#### Python boto3
```python
import boto3

def reset_ephemeral_storage(function_name, size_mb=512):
    lam = boto3.client('lambda')
    lam.update_function_configuration(FunctionName=function_name,
                                      EphemeralStorage={'Size': size_mb})
    print(f"{function_name} ephemeral storage set to {size_mb} MB.")

# Usage
# reset_ephemeral_storage('myfunc', 512)
```

---

### 5. Vet External Lambda Layers

**Issue**: Function uses layers from an external (untrusted) account (check A.5)
**Severity**: MEDIUM
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 6.3.x, NIST SR-3, ISO 27001 A.5.21

External layers can carry malicious or vulnerable code. Replace third-party layers with ones you publish from a trusted account, or vendor and review the code.

#### AWS Console
1. **Lambda Console** -> function -> **Code** -> **Layers** -> review each layer's source account
2. Replace external layers with copies you publish in your own account
3. **Save**

#### AWS CLI
```bash
# Inspect attached layers
aws lambda get-function-configuration --function-name myfunc \
  --query 'Layers[].Arn'

# Re-point to a trusted, in-account layer version
aws lambda update-function-configuration --function-name myfunc \
  --layers arn:aws:lambda:REGION:ACCOUNT_ID:layer:trusted-layer:3
```

#### Python boto3
```python
import boto3

def find_external_layers(my_account_id):
    # AWS-managed layers use the arn:aws:lambda:::awslayer: namespace (empty
    # account field) and are excluded by the acct.isdigit() guard below.
    lam = boto3.client('lambda')
    flagged = []
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            for layer in fn.get('Layers', []):
                arn = layer['Arn']
                # arn:aws:lambda:region:ACCOUNT:layer:name:version
                acct = arn.split(':')[4]
                if acct and acct != my_account_id and acct.isdigit():
                    flagged.append((fn['FunctionName'], arn))
    for name, arn in flagged:
        print(f"MEDIUM: {name} uses external layer {arn}")
    return flagged

# Usage
# find_external_layers('123456789012')
```

---

### 6. Enable X-Ray Active Tracing

**Issue**: X-Ray tracing is not in `Active` mode (check A.6)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP Lambda.7, PCI-DSS 10.2.1, NIST AU-2, AU-6, SI-4, ISO 27001 A.8.15

Active tracing gives distributed traces for incident investigation and audit trails. The execution role needs X-Ray write permissions.

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **Monitoring and operations tools** -> **Edit**
2. Enable **Active tracing**
3. **Save** (Lambda adds the needed X-Ray permissions if you allow it)

#### AWS CLI
```bash
aws lambda update-function-configuration \
  --function-name myfunc \
  --tracing-config Mode=Active
```

#### Python boto3
```python
import boto3

def enable_active_tracing(function_name):
    lam = boto3.client('lambda')
    lam.update_function_configuration(FunctionName=function_name,
                                      TracingConfig={'Mode': 'Active'})
    print(f"X-Ray active tracing enabled on {function_name}.")

# Usage
# enable_active_tracing('myfunc')
```

---

### 7. Configure a Dead Letter Queue

**Issue**: No dead letter queue for failed asynchronous invocations (check A.7)
**Severity**: MEDIUM
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 10.2.x, NIST AU-2, CP-9, SI-4, ISO 27001 A.8.15

Without a DLQ (SQS or SNS), failed async events are silently discarded after retries, losing data and audit trail. (Lambda destinations are an alternative for the same goal.)

#### AWS Console
1. Create an **SQS queue** (or SNS topic) for failed events
2. **Lambda Console** -> function -> **Configuration** -> **Asynchronous invocation** -> **Edit** -> set the **DLQ** (or an `OnFailure` destination)
3. Grant the execution role `sqs:SendMessage` (or `sns:Publish`) to that target
4. **Save**

#### AWS CLI
```bash
aws lambda update-function-configuration \
  --function-name myfunc \
  --dead-letter-config TargetArn=arn:aws:sqs:REGION:ACCOUNT_ID:myfunc-dlq
```

#### Python boto3
```python
import boto3

def set_dead_letter_queue(function_name, target_arn):
    lam = boto3.client('lambda')
    lam.update_function_configuration(
        FunctionName=function_name,
        DeadLetterConfig={'TargetArn': target_arn})
    print(f"DLQ set on {function_name} -> {target_arn}.")

# Usage
# set_dead_letter_queue('myfunc', 'arn:aws:sqs:us-east-1:123456789012:myfunc-dlq')
```

---

## Access Control

### 8. Remove Public Access From the Resource-Based Policy

**Issue**: Resource-based policy allows public access (Principal `*` with no condition, or a service principal without `aws:SourceArn`/`aws:SourceAccount`) (check B.1)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP Lambda.1, PCI-DSS 1.3.1, 7.2.x, NIST AC-3, AC-6, ISO 27001 A.8.2

A wildcard-principal permission lets anyone invoke the function. Remove the public statement; for service principals, add `aws:SourceArn`/`aws:SourceAccount` conditions (confused-deputy fix).

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **Permissions** -> **Resource-based policy statements**
2. Delete any statement with **Principal** `*` and no condition
3. For service-principal grants, **Edit** to add the source ARN/account condition

#### AWS CLI
```bash
# Inspect the policy and remove the offending statement by Sid
aws lambda get-policy --function-name myfunc --query 'Policy' --output text
aws lambda remove-permission --function-name myfunc --statement-id PUBLIC_SID

# Re-add a scoped service permission (example: S3 with source conditions)
aws lambda add-permission --function-name myfunc \
  --statement-id s3invoke --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::my-bucket \
  --source-account ACCOUNT_ID
```

#### Python boto3
```python
import json
import boto3

def find_public_resource_policies():
    lam = boto3.client('lambda')
    flagged = []
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            name = fn['FunctionName']
            try:
                policy = json.loads(lam.get_policy(FunctionName=name)['Policy'])
            except lam.exceptions.ResourceNotFoundException:
                continue  # no policy = no external access
            for stmt in policy.get('Statement', []):
                if stmt.get('Effect') != 'Allow':
                    continue
                p = stmt.get('Principal', {})
                cond = stmt.get('Condition', {})
                cond_flat = str(cond).lower()
                # (a) wildcard AWS principal (scalar OR list form) with no condition
                aws_p = p.get('AWS') if isinstance(p, dict) else None
                aws_list = aws_p if isinstance(aws_p, list) else [aws_p]
                wild = p == '*' or '*' in aws_list
                if wild and not cond:
                    flagged.append((name, stmt.get('Sid'), 'public-principal'))
                # (b) service principal without aws:SourceArn / aws:SourceAccount
                #     (confused-deputy), per check B.1
                svc = p.get('Service') if isinstance(p, dict) else None
                if svc and 'sourcearn' not in cond_flat \
                        and 'sourceaccount' not in cond_flat:
                    flagged.append((name, stmt.get('Sid'), 'confused-deputy'))
    for name, sid, kind in flagged:
        print(f"CRITICAL: {name} public statement {sid} ({kind})")
    return flagged

# Usage
find_public_resource_policies()
```

---

### 9. Require Authentication on Function URLs

**Issue**: Function URL has `AuthType: NONE` (check B.2)
**Severity**: CRITICAL
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 1.3.1, 8.3.x, NIST AC-3, IA-2, ISO 27001 A.8.5

`AuthType NONE` lets anyone who finds the URL invoke the function. Switch to `AWS_IAM` (or front the function with API Gateway that enforces auth).

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **Function URL** -> **Edit**
2. Set **Auth type** to **AWS_IAM**
3. **Save** and grant intended callers `lambda:InvokeFunctionUrl`

#### AWS CLI
```bash
aws lambda update-function-url-config \
  --function-name myfunc \
  --auth-type AWS_IAM
# Note: update-function-url-config edits an EXISTING URL. If the URL was deleted,
# recreate it with create-function-url-config (do not leave an unauthenticated
# URL live in the meantime).
```

#### Python boto3
```python
import boto3

def require_url_auth():
    lam = boto3.client('lambda')
    flagged = []
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            name = fn['FunctionName']
            try:
                cfg = lam.get_function_url_config(FunctionName=name)
            except lam.exceptions.ResourceNotFoundException:
                continue  # no URL configured
            if cfg.get('AuthType') == 'NONE':
                print(f"CRITICAL: {name} function URL has AuthType NONE")
                flagged.append(name)
    return flagged

# Usage
require_url_auth()
```

---

### 10. Restrict Function URL CORS Origins

**Issue**: Function URL CORS allows all origins (`AllowOrigins: ["*"]`) (check B.3)
**Severity**: HIGH
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 1.3.x, NIST AC-4, SC-7, ISO 27001 A.8.20

Wildcard CORS lets any website call the function cross-origin. Restrict `AllowOrigins` to specific domains (especially important when combined with B.2).

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **Function URL** -> **Edit** -> **Configure CORS**
2. Replace `*` in **Allow origins** with explicit domains (for example `https://app.example.com`)
3. **Save**

#### AWS CLI
```bash
aws lambda update-function-url-config \
  --function-name myfunc \
  --cors 'AllowOrigins=[https://app.example.com],AllowMethods=[GET,POST]'
```

#### Python boto3
```python
import boto3

def restrict_url_cors(function_name, origins):
    lam = boto3.client('lambda')
    lam.update_function_url_config(
        FunctionName=function_name,
        Cors={'AllowOrigins': origins, 'AllowMethods': ['GET', 'POST']})
    print(f"{function_name} CORS restricted to {origins}.")

# Usage
# restrict_url_cors('myfunc', ['https://app.example.com'])
```

---

### 11. Scope Down the Execution Role

**Issue**: Execution role has admin/wildcard permissions or privilege-escalation actions (check B.4)
**Severity**: CRITICAL (admin/wildcard), HIGH (privilege escalation)
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 7.2.x, NIST AC-6(1), ISO 27001 A.8.3

A function's code runs with its execution role. Remove `AdministratorAccess`/`PowerUserAccess`, replace `*:*` and `service:*` with explicit actions/resources, and restrict `iam:PassRole`.

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **Permissions** -> open the **Execution role**
2. In IAM, remove admin managed policies and rewrite inline policies to least privilege
3. Save the policy changes

#### AWS CLI
```bash
# Detach an admin managed policy
aws iam detach-role-policy --role-name myfunc-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Replace an inline policy with a scoped document
aws iam put-role-policy --role-name myfunc-role --policy-name app \
  --policy-document file://least-privilege.json
```

#### Python boto3
```python
import boto3

ADMIN_ARNS = {'arn:aws:iam::aws:policy/AdministratorAccess',
              'arn:aws:iam::aws:policy/PowerUserAccess'}

def audit_execution_roles():
    # Detects the CRITICAL admin/wildcard variant via attached managed policies.
    # The HIGH privilege-escalation variant additionally requires parsing inline
    # and customer-managed policy documents (GetPolicyVersion / GetRolePolicy) for
    # '*:*', 'service:*', and iam:PassRole on Resource '*' - extend as needed.
    lam = boto3.client('lambda')
    iam = boto3.client('iam')
    flagged = []
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            role = fn['Role'].split('/')[-1]
            for page2 in iam.get_paginator('list_attached_role_policies'
                                           ).paginate(RoleName=role):
                for p in page2['AttachedPolicies']:
                    if p['PolicyArn'] in ADMIN_ARNS:
                        flagged.append((fn['FunctionName'], p['PolicyArn']))
    for name, arn in flagged:
        print(f"CRITICAL: {name} execution role has {arn}")
    return flagged

# Usage
audit_execution_roles()
```

---

### 12. Use Per-Function Execution Roles

**Issue**: Multiple functions share the same execution role (check B.5)
**Severity**: HIGH
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 7.2.x, NIST AC-6, AC-5, ISO 27001 A.8.2

A shared role means compromising one function yields the permissions of all functions using it. Give each function its own least-privilege role.

#### AWS Console
1. Create a dedicated IAM role (trusting `lambda.amazonaws.com`) per function
2. **Lambda Console** -> function -> **Configuration** -> **Permissions** -> **Edit** -> set the dedicated role
3. **Save**

#### AWS CLI
```bash
# Create a per-function role and attach the basic execution policy
cat > lambda-trust.json << 'EOF'
{ "Version": "2012-10-17", "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole" }] }
EOF
aws iam create-role --role-name myfunc-role \
  --assume-role-policy-document file://lambda-trust.json
aws iam attach-role-policy --role-name myfunc-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws lambda update-function-configuration --function-name myfunc \
  --role arn:aws:iam::ACCOUNT_ID:role/myfunc-role
```

#### Python boto3
```python
import boto3
from collections import defaultdict

def find_shared_roles():
    lam = boto3.client('lambda')
    by_role = defaultdict(list)
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            by_role[fn['Role']].append(fn['FunctionName'])
    for role, fns in by_role.items():
        if len(fns) > 1:
            print(f"HIGH: role {role.split('/')[-1]} shared by {fns}")
    return {r: f for r, f in by_role.items() if len(f) > 1}

# Usage
find_shared_roles()
```

---

## Network Security

### 13. Attach Sensitive Functions to a VPC

**Issue**: Function is not deployed in a VPC (check C.1)
**Severity**: LOW
**Compliance**: AWS-FSBP Lambda.3, PCI-DSS 1.3.x, NIST SC-7, AC-4, ISO 27001 A.8.20

Functions handling sensitive data should run in a VPC so they can use security groups and reach private resources without traversing the public internet.

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **VPC** -> **Edit**
2. Select a **VPC**, **private subnets** (2+ AZs), and a least-privilege **security group**
3. Ensure the execution role has the VPC ENI permissions (`AWSLambdaVPCAccessExecutionRole`)
4. **Save**

#### AWS CLI
```bash
aws lambda update-function-configuration \
  --function-name myfunc \
  --vpc-config 'SubnetIds=[subnet-a,subnet-b],SecurityGroupIds=[sg-app]'
```

#### Python boto3
```python
import boto3

def attach_to_vpc(function_name, subnet_ids, security_group_ids):
    lam = boto3.client('lambda')
    lam.update_function_configuration(
        FunctionName=function_name,
        VpcConfig={'SubnetIds': subnet_ids,
                   'SecurityGroupIds': security_group_ids})
    print(f"{function_name} attached to VPC ({len(subnet_ids)} subnets).")

# Usage
# attach_to_vpc('myfunc', ['subnet-a', 'subnet-b'], ['sg-app'])
```

---

### 14. Span Multiple Availability Zones

**Issue**: VPC function uses subnets in a single AZ (check C.2)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP Lambda.5, NIST CP-10, SC-6, ISO 27001 A.8.14

A single-AZ VPC function loses availability if that AZ degrades. Use subnets in at least two AZs.

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **VPC** -> **Edit**
2. Add **private subnets from at least two AZs**
3. **Save**

#### AWS CLI
```bash
# Include subnets from 2+ AZs
aws lambda update-function-configuration \
  --function-name myfunc \
  --vpc-config 'SubnetIds=[subnet-az1,subnet-az2],SecurityGroupIds=[sg-app]'
```

#### Python boto3
```python
import boto3

def check_multi_az(function_name):
    lam = boto3.client('lambda')
    ec2 = boto3.client('ec2')
    cfg = lam.get_function_configuration(FunctionName=function_name)
    subnet_ids = cfg.get('VpcConfig', {}).get('SubnetIds', [])
    if not subnet_ids:
        print(f"{function_name} not in a VPC (C.2 not applicable).")
        return
    azs = {s['AvailabilityZone'] for s in ec2.describe_subnets(
        SubnetIds=subnet_ids)['Subnets']}
    if len(azs) < 2:
        print(f"MEDIUM: {function_name} spans a single AZ {azs}")
    return azs

# Usage
# check_multi_az('myfunc')
```

---

### 15. Restrict Security Group Egress

**Issue**: VPC function security group allows unrestricted egress (`0.0.0.0/0`, all ports) (check C.3)
**Severity**: MEDIUM
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 1.3.2, NIST AC-4, SC-7, ISO 27001 A.8.20

Unrestricted egress lets a compromised function exfiltrate data anywhere. Restrict outbound to the specific destinations/ports the function needs (or VPC endpoints).

#### AWS Console
1. **VPC Console** -> **Security groups** -> the function's SG -> **Outbound rules** -> **Edit**
2. Remove the `0.0.0.0/0` all-traffic rule; add specific destinations/ports
3. **Save rules**

#### AWS CLI
```bash
# Revoke the default all-egress rule
aws ec2 revoke-security-group-egress \
  --group-id sg-app \
  --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'

# Allow only HTTPS to a specific prefix list / CIDR
aws ec2 authorize-security-group-egress \
  --group-id sg-app \
  --ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=10.0.0.0/16}]'
```

#### Python boto3
```python
import boto3

def find_unrestricted_egress(security_group_ids):
    ec2 = boto3.client('ec2')
    flagged = []
    for sg in ec2.describe_security_groups(
            GroupIds=security_group_ids)['SecurityGroups']:
        for rule in sg.get('IpPermissionsEgress', []):
            wide = rule.get('IpProtocol') == '-1'
            anywhere = any(r.get('CidrIp') == '0.0.0.0/0'
                           for r in rule.get('IpRanges', []))
            if wide and anywhere:
                flagged.append(sg['GroupId'])
    for gid in flagged:
        print(f"MEDIUM: {gid} allows unrestricted egress")
    return flagged

# Usage
# find_unrestricted_egress(['sg-app'])
```

---

## Logging & Monitoring

### 16. Configure the Log Group and Retention

**Issue**: CloudWatch log group missing, or has no retention policy (check D.1)
**Severity**: MEDIUM
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 10.5.1, HIPAA 164.312(b), NIST AU-2, AU-11, ISO 27001 A.8.15

Create the `/aws/lambda/<name>` log group and set a retention period (logs default to never-expire). Optionally encrypt logs with KMS.

#### AWS Console
1. **CloudWatch Console** -> **Log groups** -> open `/aws/lambda/<function>` (or create it)
2. **Actions** -> **Edit retention setting** -> choose a retention (for example 90 days)
3. Optionally set a **KMS key** for the log group

#### AWS CLI
```bash
aws logs create-log-group --log-group-name /aws/lambda/myfunc 2>/dev/null
aws logs put-retention-policy \
  --log-group-name /aws/lambda/myfunc \
  --retention-in-days 90
```

#### Python boto3
```python
import boto3

def set_log_retention(function_name, days=90):
    logs = boto3.client('logs')
    group = f"/aws/lambda/{function_name}"
    try:
        logs.create_log_group(logGroupName=group)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    logs.put_retention_policy(logGroupName=group, retentionInDays=days)
    print(f"{group} retention set to {days} days.")

# Usage
# set_log_retention('myfunc', 90)
```

---

### 17. Set Reserved Concurrency

**Issue**: No reserved concurrency configured (check D.2)
**Severity**: MEDIUM
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 6.x, NIST SC-5, SC-6, ISO 27001 A.8.6

Without reserved concurrency, one function can consume the account-wide concurrency limit (account-wide throttling / DoS), and a public function becomes a financial-exhaustion vector. Set a sensible reserved limit (a value of 0 disables the function entirely).

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **Concurrency** -> **Edit**
2. Set **Reserve concurrency** to a value matched to expected load
3. **Save**

#### AWS CLI
```bash
aws lambda put-function-concurrency \
  --function-name myfunc \
  --reserved-concurrent-executions 50
```

#### Python boto3
```python
import boto3

def set_reserved_concurrency(function_name, reserved=50):
    lam = boto3.client('lambda')
    lam.put_function_concurrency(FunctionName=function_name,
                                 ReservedConcurrentExecutions=reserved)
    print(f"{function_name} reserved concurrency set to {reserved}.")

# Usage
# set_reserved_concurrency('myfunc', 50)
```

---

## Code & Supply Chain Security

### 18. Enable Code Signing (Enforce)

**Issue**: No code signing configuration, or policy is `Warn` instead of `Enforce` (check E.1)
**Severity**: MEDIUM (no config), LOW (Warn policy)
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 6.3.x, NIST SI-7, ISO 27001 A.8.7

Code signing ensures only trusted, signed artifacts deploy. Create a signing profile and a code-signing config with `UntrustedArtifactOnDeployment = Enforce` (Zip functions only; container images cannot use code signing).

#### AWS Console
1. **AWS Signer** -> create a **signing profile** (platform: AWS Lambda)
2. **Lambda Console** -> **Code signing configurations** -> create one referencing the profile, action **Enforce**
3. Attach it to the function under **Code** -> **Code signing**

#### AWS CLI
```bash
# Create a code signing config (Enforce) and attach it
aws lambda create-code-signing-config \
  --allowed-publishers SigningProfileVersionArns=[arn:aws:signer:REGION:ACCOUNT_ID:/signing-profiles/myprofile] \
  --code-signing-policies UntrustedArtifactOnDeployment=Enforce

aws lambda update-function-code-signing-config \
  --function-name myfunc \
  --code-signing-config-arn arn:aws:lambda:REGION:ACCOUNT_ID:code-signing-config:csc-XXXX
```

#### Python boto3
```python
import boto3

def check_code_signing():
    # Detects the MEDIUM no-config variant. To distinguish the LOW 'Warn' variant,
    # follow the CodeSigningConfigArn into get_code_signing_config and check
    # CodeSigningPolicies.UntrustedArtifactOnDeployment == 'Warn'.
    lam = boto3.client('lambda')
    flagged = []
    for page in lam.get_paginator('list_functions').paginate():
        for fn in page['Functions']:
            if fn.get('PackageType') == 'Image':
                continue  # not applicable to container images
            name = fn['FunctionName']
            try:
                # GetFunctionCodeSigningConfig returns 200 with an EMPTY
                # CodeSigningConfigArn when none is attached (it does not raise);
                # inspect the value rather than relying on an exception.
                resp = lam.get_function_code_signing_config(FunctionName=name)
            except lam.exceptions.ResourceNotFoundException:
                continue  # function no longer exists - skip
            if not resp.get('CodeSigningConfigArn'):
                print(f"MEDIUM: {name} has no code signing config")
                flagged.append(name)
    return flagged

# Usage
check_code_signing()
```

---

### 19. Add Failure Destinations to Event Source Mappings

**Issue**: An event source mapping (SQS, Kinesis, DynamoDB Streams) has no `OnFailure` destination (check E.2)
**Severity**: MEDIUM
**Compliance**: Best-practice (no direct FSBP control), PCI-DSS 10.2.x, NIST AU-2, CP-9, SI-4, ISO 27001 A.8.15

Without a failure destination, failed records are silently dropped. Configure an `OnFailure` destination (SQS/SNS) so failed batches are captured.

#### AWS Console
1. **Lambda Console** -> function -> **Configuration** -> **Triggers** -> select the event source mapping -> **Edit**
2. Under **On-failure destination**, set an SQS queue or SNS topic
3. **Save**

#### AWS CLI
```bash
# Find the mapping UUID, then add an on-failure destination
aws lambda list-event-source-mappings --function-name myfunc \
  --query 'EventSourceMappings[].UUID'

aws lambda update-event-source-mapping \
  --uuid ESM_UUID \
  --destination-config 'OnFailure={Destination=arn:aws:sqs:REGION:ACCOUNT_ID:esm-dlq}'
```

#### Python boto3
```python
import boto3

def find_esm_without_failure_dest():
    lam = boto3.client('lambda')
    flagged = []
    for page in lam.get_paginator('list_event_source_mappings').paginate():
        for esm in page['EventSourceMappings']:
            dest = esm.get('DestinationConfig', {}).get('OnFailure', {}).get(
                'Destination')
            if not dest:
                flagged.append(esm['UUID'])
    for uuid in flagged:
        print(f"MEDIUM: event source mapping {uuid} has no failure destination")
    return flagged

# Usage
find_esm_without_failure_dest()
```

---

## Quick Reference Commands

### Read-Only Audit Script

```bash
#!/bin/bash
# lambda-quick-audit.sh - read-only checks that mirror common findings
REGION=${1:-us-east-1}

echo "== Functions on deprecated runtimes (A.1) =="
aws lambda list-functions --region "$REGION" \
  --query "Functions[?Runtime!=null && (Runtime=='python3.8' || Runtime=='python3.9' || Runtime=='nodejs16.x' || Runtime=='go1.x')].[FunctionName,Runtime]" \
  --output text

echo "== Function URLs with AuthType NONE (B.2) =="
for f in $(aws lambda list-functions --region "$REGION" --query 'Functions[].FunctionName' --output text); do
  at=$(aws lambda get-function-url-config --region "$REGION" --function-name "$f" \
    --query 'AuthType' --output text 2>/dev/null)
  [ "$at" = "NONE" ] && echo "  $f (AuthType NONE)"
done

echo "== Functions without reserved concurrency (D.2) =="
for f in $(aws lambda list-functions --region "$REGION" --query 'Functions[].FunctionName' --output text); do
  rc=$(aws lambda get-function-concurrency --region "$REGION" --function-name "$f" \
    --query 'ReservedConcurrentExecutions' --output text 2>/dev/null)
  [ "$rc" = "None" ] && echo "  $f"
done
```

### Python Bulk Hardening Function

```python
import boto3


def harden_function(function_name, dlq_arn, retention_days=90, reserved=50):
    """Apply the in-place Lambda hardening controls to a single function."""
    lam = boto3.client('lambda')
    logs = boto3.client('logs')

    lam.update_function_configuration(
        FunctionName=function_name,
        TracingConfig={'Mode': 'Active'},
        DeadLetterConfig={'TargetArn': dlq_arn},
    )
    lam.put_function_concurrency(
        FunctionName=function_name,
        ReservedConcurrentExecutions=reserved)

    group = f"/aws/lambda/{function_name}"
    try:
        logs.create_log_group(logGroupName=group)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    logs.put_retention_policy(logGroupName=group, retentionInDays=retention_days)

    print(f"In-place hardening applied to {function_name}. "
          f"Runtime, secrets, and IAM findings need per-function remediation.")


# Usage
# harden_function('myfunc', 'arn:aws:sqs:us-east-1:123456789012:myfunc-dlq')
```

---

## Additional Notes

### AWS IAM Permissions Required

Remediation requires write access to Lambda (and IAM/Logs/EC2/Secrets Manager for related steps):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:UpdateFunctionConfiguration",
                "lambda:UpdateFunctionUrlConfig",
                "lambda:RemovePermission",
                "lambda:AddPermission",
                "lambda:PutFunctionConcurrency",
                "lambda:UpdateEventSourceMapping",
                "lambda:UpdateFunctionCodeSigningConfig",
                "lambda:CreateCodeSigningConfig",
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:PutRolePolicy",
                "iam:PassRole",
                "logs:CreateLogGroup",
                "logs:PutRetentionPolicy",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupEgress",
                "secretsmanager:CreateSecret"
            ],
            "Resource": "*"
        }
    ]
}
```

> The **scanner itself** only needs read-only permissions (see the README IAM policy). Apply remediation changes from a separate, tightly-controlled administrative principal.

### Validation Commands

After applying remediations, verify with:

```bash
# Re-run the Lambda Security Scanner
lambda-security-scanner security --compliance-only

# Spot-check specific controls
aws lambda get-function-configuration --function-name myfunc \
  --query '{Runtime:Runtime,Tracing:TracingConfig.Mode,DLQ:DeadLetterConfig.TargetArn,KMS:KMSKeyArn}'
aws lambda get-function-url-config --function-name myfunc --query 'AuthType'
```

### Emergency Response

For a publicly exposed function:

```bash
# 1. Require IAM auth on the function URL immediately
# (applies only if a function URL exists; if exposure is via the resource policy,
#  this errors with ResourceNotFoundException - skip straight to step 2)
aws lambda update-function-url-config --function-name myfunc --auth-type AWS_IAM

# 2. Remove any public resource-based policy statement
aws lambda remove-permission --function-name myfunc --statement-id PUBLIC_SID

# 3. Cap blast radius with reserved concurrency (0 fully disables it)
aws lambda put-function-concurrency --function-name myfunc \
  --reserved-concurrent-executions 0

# 4. Rotate any secret exposed via env vars and review CloudWatch/CloudTrail logs.
```

This comprehensive remediation guide provides solutions for all security vulnerabilities detected by the Lambda Security Scanner. Each remediation includes multiple implementation methods to accommodate different operational preferences and automation requirements.
