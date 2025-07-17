# AWS Account 238233324971 – Compromised AKID Investigation (2025‑03‑04)

## 🆘 Incident Overview

On **2025-03-04 at 22:05:27 UTC**, the billing alarm for AWS account `238233324971` was triggered due to an unexpected spike in charges. A **CloudWatch alarm** had also triggered slightly earlier at **22:02:15 UTC**, suggesting possible malicious activity. The Access Key ID (AKID) tied to a commonly used IAM user for integration testing was suspected to be **compromised** and has since been **deleted**.

---
## 🪜 Investigation Approach

The following investigation methodology was used:

1. **Isolate All Activity by the Compromised AKID**
2. **Identify All Resource Creation and Modification**
3. **Trace Any Lateral Movement or Privilege Escalation**
4. **Identify Persistence Mechanisms (e.g., new users, access keys, roles)**
5. **Provide Supporting Evidence for Suspicious Behavior**


## Detailed Timeline (UTC)

| Time            | Actor                 | Event Description                                      | Evidence ID | MITRE Tactic         | MITRE Technique(s)                                  |
|-----------------|-----------------------|--------------------------------------------------------|-------------|-----------------------|-----------------------------------------------------|
| 22:01:36        | testing_only          | IAM & S3 enumeration                                   | CT‑1        | Reconnaissance        | T1580, T1589.001, T1526                             |
| 22:01:40        | testing_only          | AssumeRole (Admin Role)                               | CT‑2        | Privilege Escalation  | T1078.004                                            |
| 22:02:44        | STS session           | Create IAM user (system-admin)                        | CT‑3        | Persistence           | T1136.003                                            |
| 22:02:49        | STS session           | Attach policy, create access key                      | CT‑4        | Credential Access     | T1552.001, T1098.003                                 |
| 22:02:58–03:48  | new user              | GetBucketPolicy, Describe* (resource mapping)         | CT‑5        | Discovery             | T1526, T1580                                        |
| 22:04:56        | new user              | Create Lambda execution role                          | CT‑6        | Defense Evasion       | T1098.003, T1484.001 (secondary)                   |
| 22:05:07        | new user              | Deploy backdoor Lambda function                       | CT‑7        | Persistence / Execution | T1053.005, T1505.003                              |
| 22:05:08–09     | new user              | Create VPC, Subnet, Security Group                    | CT‑8        | Resource Development   | T1583.006, T1578.002 (inferred)                    |
| 22:05:10–11     | new user              | Launch EC2 instances (billing spike)                  | CT‑9        | Impact                 | T1496                                               |


> **CT‑x** identifiers correspond to rows in the *Suspicious CloudTrail Events* table generated from the CSV.

---

## Resources Created / Modified

| Resource Type | Identifier(s) | Action to Take |
|---------------|---------------|----------------|
| **IAM user** | `system‑admin‑1741125702` | Delete user & keys |
| **IAM policy** | `CustomAdminPolicy` | Delete policy |
| **IAM role** | `lambda‑role‑1741125895` | Delete role |
| **Lambda function** | `data‑processor‑1741125906` | Review code ➔ delete |
| **Networking** | New VPC, subnet, security group in `us‑east‑1` | Remove after forensics |
| **EC2 instances** | `i‑03bd14040…`, `i‑0a2c7f5e…` | Snapshot & terminate |

---

## Indicators of Compromise (IoCs)

| Category | Value |
|----------|-------|
| Source IP | **76.147.57.220** |
| Compromised user | `testing_only` |
| Back‑door users | `system‑admin‑1741125702` (plus earlier `system‑admin‑1741070561/2200/8596`) |
| Back‑door keys | AccessKey created 22:02:49 UTC |


---

## Findings
1. **Resource Creation:** Rogue IAM principal, Lambda, VPC, SG, EC2 built within four minutes.
2. **Privilege Escalation:** `testing_only` ➔ `AssumeRole` ➔ admin STS ➔ permanent admin user.
3. **Persistence:** Durable access key, custom admin policy, independent Lambda execution role.
4. **Single Actor:** All malicious API calls originate from IP 76.147.57.220.
5. **No Cross‑Account Spread** detected; activity remained in account 238233324971.

---

## Recommended Remediation (Immediate)
1. **Revoke & delete** all artefacts listed above (users, keys, policies, role, Lambda, VPC, EC2).
2. **Rotate credentials** for `testing_only` and migrate integration testing to short‑lived roles with MFA.
3. **Block IP 76.147.57.220** at perimeter while analyzing logs.
4. **Review S3 access logs** for `GetObject` events by the IoC IP to confirm/no data theft.
5. **Enable GuardDuty, AWS Config rules, and tighter CloudWatch anomaly alarms** for IAM/network changes.
6. **Post‑incident hardening:** enforce least‑privilege, remove long‑lived keys, and set lower‑threshold cost alerts.

---


