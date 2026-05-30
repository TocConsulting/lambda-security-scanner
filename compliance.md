# Lambda Security Scanner — Compliance Framework Mapping

Maps 19 security checks to 10 compliance frameworks with lambda-based controls.

> **Key convention:** All compliance lambdas use **fail-closed defaults**:
> `.get("bad_thing", True)` and `.get("good_thing", False)`.
> When data is missing, assume the worst.

---

## 1. AWS Foundational Security Best Practices (AWS-FSBP)

> **Reference:** https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html

**Coverage: 5 controls**

| Control ID | Description                                          | Severity | Check |
|------------|------------------------------------------------------|----------|-------|
| Lambda.1   | Function policies should prohibit public access      | CRITICAL | B.1   |
| Lambda.2   | Functions should use supported runtimes              | MEDIUM   | A.1   |
| Lambda.3   | Functions should be in a VPC                         | LOW      | C.1   |
| Lambda.5   | VPC Lambda functions should operate in multiple AZs  | MEDIUM   | C.2   |
| Lambda.7   | Functions should have X-Ray active tracing enabled   | LOW      | A.6   |

> **Lambda.6 (tagging)** is intentionally out of scope: this scanner does
> not evaluate function tags. If tag-based compliance is required, pair
> this tool with AWS Config or Security Hub directly.

### Control Implementation Details

- **Lambda.1** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **Lambda.2** — `lambda r: r.get("runtime", {}).get("status", "blocked") == "supported"`
- **Lambda.3** — `lambda r: r.get("vpc_config", {}).get("in_vpc", False)`
- **Lambda.5** — `lambda r: r.get("multi_az", {}).get("is_multi_az", False) if r.get("vpc_config", {}).get("in_vpc", False) else True`
- **Lambda.7** — `lambda r: r.get("tracing", {}).get("enabled", False)`

---

## 2. CIS AWS Compute Services Benchmark (CIS)

> **Reference:** https://www.cisecurity.org/benchmark/amazon_web_services
> **Note:** Lambda-specific controls are from the CIS AWS Compute Services
> Benchmark, not the CIS AWS Foundations Benchmark. Control IDs below are
> scanner-defined mappings to CIS guidance areas.

**Coverage: 8 controls**

| Control ID    | Description                                          | Severity | Check    |
|---------------|------------------------------------------------------|----------|----------|
| CIS-Lambda.1  | Functions should use supported runtimes              | HIGH     | A.1      |
| CIS-Lambda.2  | Functions should not be publicly accessible          | CRITICAL | B.1, B.2 |
| CIS-Lambda.3  | Execution roles should follow least privilege        | HIGH     | B.4      |
| CIS-Lambda.4  | Functions should have dead-letter queues             | MEDIUM   | A.7      |
| CIS-Lambda.5  | Functions should be deployed in a VPC                | LOW      | C.1      |
| CIS-Lambda.6  | Functions should have X-Ray tracing enabled          | MEDIUM   | A.6      |
| CIS-Lambda.7  | Env vars should not contain sensitive data           | CRITICAL | A.3      |
| CIS-Lambda.8  | Functions should have code signing enabled           | MEDIUM   | E.1      |

### Control Implementation Details

- **CIS-Lambda.1** — `lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")`
- **CIS-Lambda.2** — `lambda r: not r.get("resource_policy", {}).get("is_public", True) and not r.get("function_url", {}).get("is_public", True)`
- **CIS-Lambda.3** — `lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)`
- **CIS-Lambda.4** — `lambda r: r.get("dead_letter_config", {}).get("configured", False)`
- **CIS-Lambda.5** — `lambda r: r.get("vpc_config", {}).get("in_vpc", False)`
- **CIS-Lambda.6** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **CIS-Lambda.7** — `lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)`
- **CIS-Lambda.8** — `lambda r: r.get("code_signing", {}).get("configured", False)`

---

## 3. PCI DSS v4.0.1 (PCI-DSS-v4.0.1)

> **Reference:** https://www.pcisecuritystandards.org/document_library/
> **Note:** Control IDs use PCI-DSS v4.0.1 requirement numbers. The
> "Lambda" prefix is a scanner convention to namespace Lambda-specific
> mappings.

**Coverage: 8 controls**

| Control ID           | Description                                      | Severity | Check |
|----------------------|--------------------------------------------------|----------|-------|
| PCI-Lambda.1.4.1    | NSC implemented between trusted/untrusted networks | CRITICAL | B.1   |
| PCI-Lambda.1.3.2    | Outbound traffic from the CDE is restricted      | MEDIUM   | C.3   |
| PCI-Lambda.6.3.3    | Security patches/updates installed               | HIGH     | A.1   |
| PCI-Lambda.7.2.1    | Access roles defined with least privilege        | HIGH     | B.4   |
| PCI-Lambda.8.3.1    | User access authenticated via at least one factor | CRITICAL | B.2   |
| PCI-Lambda.8.6.2    | Application/system account secrets not hard-coded | CRITICAL | A.3   |
| PCI-Lambda.10.2.1   | Audit logs capture security events               | MEDIUM   | A.6   |
| PCI-Lambda.10.5.1   | Audit log history retained ≥ 12 months           | MEDIUM   | D.1   |

> **Code signing is not mapped to PCI DSS** — PCI v4.0.1 has no clean
> Lambda-applicable clause for artefact integrity attestation. Code
> signing is still tracked under CIS, SOC2, ISO27001, HIPAA, and NIST.

### Control Implementation Details

- **PCI-Lambda.1.4.1** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **PCI-Lambda.1.3.2** — `lambda r: not r.get("security_groups", {}).get("unrestricted_egress", True) if r.get("security_groups", {}).get("applicable", False) else True`
- **PCI-Lambda.6.3.3** — `lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")`
- **PCI-Lambda.7.2.1** — `lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)`
- **PCI-Lambda.8.3.1** — `lambda r: not r.get("function_url", {}).get("is_public", True)`
- **PCI-Lambda.8.6.2** — `lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)`
- **PCI-Lambda.10.2.1** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **PCI-Lambda.10.5.1** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`

---

## 4. HIPAA (HIPAA)

> **Reference:** https://www.hhs.gov/hipaa/for-professionals/security/
> **Note:** Control IDs reference HIPAA Security Rule CFR sections.

**Coverage: 9 controls**

| Control ID                       | Description                                       | Severity | Check |
|----------------------------------|---------------------------------------------------|----------|-------|
| 164.312(a)(1)-ACCESS             | Access control — prohibit public access to ePHI    | CRITICAL | B.1   |
| 164.312(a)(1)-URL                | Access control — function URL authentication       | CRITICAL | B.2   |
| 164.312(a)(1)-SECRETS            | No PHI/secrets in env vars                         | CRITICAL | A.3   |
| 164.312(a)(1)-IAM                | Access control — least privilege execution roles   | HIGH     | B.4   |
| 164.312(b)-TRACING               | Audit controls — tracing enabled                   | MEDIUM   | A.6   |
| 164.312(b)-LOGGING               | Audit controls — log retention                     | MEDIUM   | D.1   |
| 164.308(a)(7)-DLQ                | Contingency plan — dead letter queue               | MEDIUM   | A.7   |
| 164.312(c)(1)-SIGNING            | Integrity — code signing                           | MEDIUM   | E.1   |
| 164.308(a)(5)(ii)(B)-RUNTIME     | Protection from malicious software — supported runtimes | HIGH | A.1   |

### Control Implementation Details

- **164.312(a)(1)-ACCESS** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **164.312(a)(1)-URL** — `lambda r: not r.get("function_url", {}).get("is_public", True)`
- **164.312(a)(1)-SECRETS** — `lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)`
- **164.312(a)(1)-IAM** — `lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)`
- **164.312(b)-TRACING** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **164.312(b)-LOGGING** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`
- **164.308(a)(7)-DLQ** — `lambda r: r.get("dead_letter_config", {}).get("configured", False)`
- **164.312(c)(1)-SIGNING** — `lambda r: r.get("code_signing", {}).get("configured", False)`
- **164.308(a)(5)(ii)(B)-RUNTIME** — `lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")`

---

## 5. SOC 2 (SOC2)

> **Reference:** https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome

**Coverage: 11 controls**

| Control ID           | Description                                      | Severity | Check |
|----------------------|--------------------------------------------------|----------|-------|
| SOC2-CC6.1-ACCESS    | Restrict public access to functions              | CRITICAL | B.1   |
| SOC2-CC6.1-URL      | Function URL authentication required             | CRITICAL | B.2   |
| SOC2-CC6.1-IAM      | Least privilege execution roles                  | HIGH     | B.4   |
| SOC2-CC6.1-ROLE     | Unique execution roles per function              | HIGH     | B.5   |
| SOC2-CC6.8-SIGNING  | Code signing for software integrity              | MEDIUM   | E.1   |
| SOC2-CC6.8-RUNTIME  | Use current supported runtimes                   | HIGH     | A.1   |
| SOC2-CC7.1-LOGGING  | CloudWatch log retention configured              | MEDIUM   | D.1   |
| SOC2-CC7.2-TRACING  | X-Ray tracing for anomaly detection              | MEDIUM   | A.6   |
| SOC2-CC7.3-DLQ      | Dead letter queue for failure capture            | MEDIUM   | A.7   |
| SOC2-CC7.3-ESM      | ESM failure destinations configured              | MEDIUM   | E.2   |
| SOC2-A1.1-CONCUR    | Reserved concurrency for availability            | MEDIUM   | D.2   |

### Control Implementation Details

- **SOC2-CC6.1-ACCESS** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **SOC2-CC6.1-URL** — `lambda r: not r.get("function_url", {}).get("is_public", True)`
- **SOC2-CC6.1-IAM** — `lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)`
- **SOC2-CC6.1-ROLE** — `lambda r: not r.get("shared_role", {}).get("is_shared", True)`
- **SOC2-CC6.8-SIGNING** — `lambda r: r.get("code_signing", {}).get("configured", False)`
- **SOC2-CC6.8-RUNTIME** — `lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")`
- **SOC2-CC7.1-LOGGING** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`
- **SOC2-CC7.2-TRACING** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **SOC2-CC7.3-DLQ** — `lambda r: r.get("dead_letter_config", {}).get("configured", False)`
- **SOC2-CC7.3-ESM** — `lambda r: r.get("event_source_mappings", {}).get("missing_failure_dest_count", 1) == 0 if r.get("event_source_mappings", {}).get("has_mappings", False) else True`
- **SOC2-A1.1-CONCUR** — `lambda r: r.get("reserved_concurrency", {}).get("configured", False)`

---

## 6. ISO 27001:2022 (ISO27001)

> **Reference:** https://www.iso.org/standard/27001

**Coverage: 11 controls**

| Control ID | Description                                          | Severity | Check |
|------------|------------------------------------------------------|----------|-------|
| A.5.15     | Access control — restrict public access              | CRITICAL | B.1   |
| A.5.21     | Information security in the ICT supply chain — layer verification | MEDIUM | A.5 |
| A.8.2      | Privileged access rights — unique execution role     | HIGH     | B.5   |
| A.8.3      | Information access restriction — least privilege     | HIGH     | B.4   |
| A.8.5      | Secure authentication — function URL auth            | CRITICAL | B.2   |
| A.8.7      | Protection against malware — code signing            | MEDIUM   | E.1   |
| A.8.12     | Data leakage prevention — no secrets in env vars     | CRITICAL | A.3   |
| A.8.15-T   | Logging — tracing enabled                            | MEDIUM   | A.6   |
| A.8.15-L   | Logging — log group retention configured             | MEDIUM   | D.1   |
| A.8.20     | Network security — VPC configuration                 | LOW      | C.1   |
| A.8.24     | Use of cryptography — KMS on env vars                | MEDIUM   | A.3   |

### Control Implementation Details

- **A.5.15** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **A.5.21** — `lambda r: not r.get("layers", {}).get("has_external_layers", True)`
- **A.8.2** — `lambda r: not r.get("shared_role", {}).get("is_shared", True)`
- **A.8.3** — `lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)`
- **A.8.5** — `lambda r: not r.get("function_url", {}).get("is_public", True)`
- **A.8.7** — `lambda r: r.get("code_signing", {}).get("configured", False)`
- **A.8.12** — `lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)`
- **A.8.15-T** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **A.8.15-L** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`
- **A.8.20** — `lambda r: r.get("vpc_config", {}).get("in_vpc", False)`
- **A.8.24** — `lambda r: r.get("environment_secrets", {}).get("has_kms_key", False) if r.get("environment_secrets", {}).get("has_env_vars", False) else True`

---

## 7. ISO 27017 (ISO27017)

> **Reference:** https://www.iso.org/standard/43757.html
> **Note:** ISO 27017 provides cloud-specific guidance extending ISO 27002.
> Control IDs below use the `CLD` prefix as the verbatim ISO/IEC
> 27017:2015 clause numbers.

**Coverage: 4 controls**

| Control ID   | Description                                       | Severity | Check |
|--------------|---------------------------------------------------|----------|-------|
| CLD.9.5.1   | Segregation in virtual environments — VPC          | LOW      | C.1   |
| CLD.9.5.2   | Virtual machine hardening — runtime security       | HIGH     | A.1   |
| CLD.12.1.5  | Administrator operational security — logging       | MEDIUM   | D.1   |
| CLD.12.4.5  | Monitoring of cloud services — tracing             | MEDIUM   | A.6   |

### Control Implementation Details

- **CLD.9.5.1** — `lambda r: r.get("vpc_config", {}).get("in_vpc", False)`
- **CLD.9.5.2** — `lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")`
- **CLD.12.1.5** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`
- **CLD.12.4.5** — `lambda r: r.get("tracing", {}).get("enabled", False)`

> **Shared role isolation** (was `CLD.6.3.1`) and **external layer
> verification** (was `CLD.8.1.5`) are now mapped to ISO 27001:2022
> **A.8.2** and **A.5.21** respectively — those clauses match the
> control intent. The original CLD numbers in ISO 27017:2015 refer to
> different topics (CSP/customer responsibility split and customer
> asset removal at contract end).

---

## 8. ISO 27018 (ISO27018)

> **Reference:** https://www.iso.org/standard/76559.html
> **Note:** ISO 27018 provides PII protection guidance for cloud services.
> Control IDs below are scanner-defined mappings to ISO 27018 guidance areas.

**Coverage: 5 controls**

| Control ID      | Description                                       | Severity | Check |
|-----------------|---------------------------------------------------|----------|-------|
| ISO27018-ENC    | Encryption of PII — KMS on env vars               | CRITICAL | A.3   |
| ISO27018-ACCESS | Access to data — restrict public function access   | CRITICAL | B.1   |
| ISO27018-AUTH   | Secure transmission — function URL authentication  | CRITICAL | B.2   |
| ISO27018-TRACE  | Audit logging — tracing enabled                    | MEDIUM   | A.6   |
| ISO27018-LOG    | Audit logging — log retention configured           | MEDIUM   | D.1   |

### Control Implementation Details

- **ISO27018-ENC** — `lambda r: r.get("environment_secrets", {}).get("has_kms_key", False) if r.get("environment_secrets", {}).get("has_env_vars", False) else True`
- **ISO27018-ACCESS** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **ISO27018-AUTH** — `lambda r: not r.get("function_url", {}).get("is_public", True)`
- **ISO27018-TRACE** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **ISO27018-LOG** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`

---

## 9. GDPR (GDPR)

> **Reference:** https://gdpr-info.eu/

**Coverage: 8 controls**

| Control ID              | Description                                          | Severity | Check |
|-------------------------|------------------------------------------------------|----------|-------|
| GDPR-Art5               | Data integrity and confidentiality — no secrets      | CRITICAL | A.3   |
| GDPR-Art25              | Data protection by design — least privilege          | HIGH     | B.4   |
| GDPR-Art32-1a-KMS       | Art 32(1)(a) — encryption of personal data           | HIGH     | A.3   |
| GDPR-Art32-1b-ACCESS    | Art 32(1)(b) — confidentiality (no public access)    | CRITICAL | B.1   |
| GDPR-Art32-1b-CONCUR    | Art 32(1)(b) — resilience (reserved concurrency)     | MEDIUM   | D.2   |
| GDPR-Art32-1b-ESM       | Art 32(1)(b) — resilience (ESM failure destinations) | MEDIUM   | E.2   |
| GDPR-Art32-1b-TRACE     | Art 32(1)(b) — integrity signal (X-Ray tracing)      | MEDIUM   | A.6   |
| GDPR-Art32-1b-LOG       | Art 32(1)(b) — availability/integrity (log retention) | MEDIUM   | D.1   |

### Control Implementation Details

- **GDPR-Art5** — `lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)`
- **GDPR-Art25** — `lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)`
- **GDPR-Art32-1a-KMS** — `lambda r: r.get("environment_secrets", {}).get("has_kms_key", False) if r.get("environment_secrets", {}).get("has_env_vars", False) else True`
- **GDPR-Art32-1b-ACCESS** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **GDPR-Art32-1b-CONCUR** — `lambda r: r.get("reserved_concurrency", {}).get("configured", False)`
- **GDPR-Art32-1b-ESM** — `lambda r: r.get("event_source_mappings", {}).get("missing_failure_dest_count", 1) == 0 if r.get("event_source_mappings", {}).get("has_mappings", False) else True`
- **GDPR-Art32-1b-TRACE** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **GDPR-Art32-1b-LOG** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`

---

## 10. NIST 800-53 Rev5 (NIST-800-53)

> **Reference:** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

**Coverage: 12 controls**

| Control ID | Description                                          | Severity | Check |
|------------|------------------------------------------------------|----------|-------|
| AC-3       | Access enforcement — no public access                | CRITICAL | B.1   |
| AC-6       | Least privilege — execution role                     | HIGH     | B.4   |
| AC-17      | Remote access — function URL auth                    | CRITICAL | B.2   |
| AU-2       | Event logging — tracing enabled                      | MEDIUM   | A.6   |
| AU-9       | Protection of audit info — log retention             | MEDIUM   | D.1   |
| CM-7       | Least functionality — no deprecated runtimes         | HIGH     | A.1   |
| IA-5       | Authenticator management — no secrets in env vars    | CRITICAL | A.3   |
| SC-5       | DoS protection — reserved concurrency                | MEDIUM   | D.2   |
| SC-7       | Boundary protection — VPC configuration              | LOW      | C.1   |
| SC-7(5)    | Boundary protection — deny by default (SG egress)    | MEDIUM   | C.3   |
| SI-7       | Software integrity — code signing                    | MEDIUM   | E.1   |
| SR-3       | Supply chain controls and processes — layer verification | MEDIUM | A.5 |

### Control Implementation Details

- **AC-3** — `lambda r: not r.get("resource_policy", {}).get("is_public", True)`
- **AC-6** — `lambda r: not r.get("execution_role", {}).get("has_admin_access", True) and not r.get("execution_role", {}).get("has_wildcard_actions", True)`
- **AC-17** — `lambda r: not r.get("function_url", {}).get("is_public", True)`
- **AU-2** — `lambda r: r.get("tracing", {}).get("enabled", False)`
- **AU-9** — `lambda r: r.get("log_group", {}).get("exists", False) and r.get("log_group", {}).get("has_retention", False)`
- **CM-7** — `lambda r: r.get("runtime", {}).get("status", "blocked") in ("supported", "near_eol")`
- **IA-5** — `lambda r: not r.get("environment_secrets", {}).get("has_secrets", True)`
- **SC-5** — `lambda r: r.get("reserved_concurrency", {}).get("configured", False)`
- **SC-7** — `lambda r: r.get("vpc_config", {}).get("in_vpc", False)`
- **SC-7(5)** — `lambda r: not r.get("security_groups", {}).get("unrestricted_egress", True) if r.get("security_groups", {}).get("applicable", False) else True`
- **SI-7** — `lambda r: r.get("code_signing", {}).get("configured", False)`
- **SR-3** — `lambda r: not r.get("layers", {}).get("has_external_layers", True)`

---

## Check-to-Framework Coverage Matrix

| Check | FSBP | CIS | PCI | HIPAA | SOC2 | ISO27001 | ISO27017 | ISO27018 | GDPR | NIST |
|-------|------|-----|-----|-------|------|----------|----------|----------|------|------|
| A.1   | ✓    | ✓   | ✓   | ✓     | ✓    |          | ✓        |          |      | ✓    |
| A.2   |      |     |     |       |      |          |          |          |      |      |
| A.3   |      | ✓   | ✓   | ✓     |      | ✓✓       |          | ✓        | ✓✓   | ✓    |
| A.4   |      |     |     |       |      |          |          |          |      |      |
| A.5   |      |     |     |       |      | ✓        |          |          |      | ✓    |
| A.6   |      | ✓   | ✓   | ✓     | ✓    | ✓        | ✓        | ✓        | ✓    | ✓    |
| A.7   |      | ✓   |     | ✓     | ✓    |          |          |          |      |      |
| B.1   | ✓    | ✓   | ✓   | ✓     | ✓    | ✓        |          | ✓        | ✓    | ✓    |
| B.2   |      | ✓   | ✓   | ✓     | ✓    | ✓        |          | ✓        |      | ✓    |
| B.3   |      |     |     |       |      |          |          |          |      |      |
| B.4   |      | ✓   | ✓   | ✓     | ✓    | ✓        |          |          | ✓    | ✓    |
| B.5   |      |     |     |       | ✓    | ✓        |          |          |      |      |
| C.1   | ✓    | ✓   |     |       |      | ✓        | ✓        |          |      | ✓    |
| C.2   | ✓    |     |     |       |      |          |          |          |      |      |
| C.3   |      |     | ✓   |       |      |          |          |          |      | ✓    |
| D.1   |      |     | ✓   | ✓     | ✓    | ✓        | ✓        | ✓        | ✓    | ✓    |
| D.2   |      |     |     |       | ✓    |          |          |          | ✓    | ✓    |
| E.1   |      | ✓   |     | ✓     | ✓    | ✓        |          |          |      | ✓    |
| E.2   |      |     |     |       | ✓    |          |          |          | ✓    |      |

**Notes:**
- A.2 (max timeout), A.4 (ephemeral storage), B.3 (CORS wildcard) have no
  direct compliance mapping — they are best-practice checks only.
- ✓✓ indicates two controls from same framework map to the check (e.g.,
  ISO27001 maps A.3 to both A.8.12 secrets and A.8.24 KMS).

---

## Framework Summary

| Framework      | Controls | Key Focus Areas                                    |
|----------------|----------|----------------------------------------------------|
| AWS-FSBP       | 5        | Public access, runtimes, VPC, multi-AZ, tracing    |
| CIS            | 8        | Runtimes, access, IAM, DLQ, VPC, tracing, secrets  |
| PCI-DSS-v4.0.1 | 8        | Auth, secrets, runtimes, IAM, egress, logging       |
| HIPAA          | 9        | Access, secrets, IAM, audit, integrity, runtimes    |
| SOC2           | 11       | Access, IAM, signing, runtime, logging, DLQ, ESM    |
| ISO27001       | 11       | Access, IAM, auth, signing, secrets, logging, VPC, supply chain |
| ISO27017       | 4        | VPC, runtimes, logging, monitoring                  |
| ISO27018       | 5        | PII encryption, access, auth, logging               |
| GDPR           | 8        | Secrets, IAM, encryption, access, availability, ESM |
| NIST-800-53    | 12       | Access, IAM, auth, logging, runtimes, DoS, VPC, SG  |

**Total: 81 controls across 10 frameworks**
