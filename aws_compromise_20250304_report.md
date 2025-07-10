# AWS Account 238233324971 – Compromised AKID Investigation (2025‑03‑04)

## Executive Summary
On **4 March 2025, 22:01–22:05 UTC** an IAM user’s access key (`testing_only`) was abused from **IP 76.147.57.220** to escalate privileges, plant back‑door credentials, and spin up compute resources. All malicious activity is evidenced in *Cloudtrail_analysis.csv* (see accompanying event table). No cross‑account movement was observed, but multiple mechanisms for persistence were created inside the account.

---
## 🪜 Investigation Approach

The following investigation methodology was used:

1. **Isolate All Activity by the Compromised AKID**
2. **Identify All Resource Creation and Modification**
3. **Trace Any Lateral Movement or Privilege Escalation**
4. **Identify Persistence Mechanisms (e.g., new users, access keys, roles)**
5. **Provide Supporting Evidence for Suspicious Behavior**


## Detailed Timeline (UTC)

| Time | Actor / Credential | Event | Evidence ID | Notes |
|------|--------------------|-------|-------------|-------|
| 22:01:36 | `testing_only` (compromised) | `ListRoles`, `ListUsers`, `ListBuckets` | CT‑1 | Reconnaissance – IAM & S3 enumeration |
| 22:01:40 | same | **`AssumeRole`** (`IntegrationTestingAdminRole`) | CT‑2 | Gains admin‑level STS session |
| 22:02:44 | STS session | **`CreateUser system‑admin‑1741125702`** | CT‑3 | Persistence user created |
| 22:02:49 | same | `AttachUserPolicy (CustomAdmin)` & **`CreateAccessKey`** | CT‑4 | Permanent admin key issued |
| 22:02:58‑22:03:48 | new user | 13× `GetBucketPolicy`, `Describe*` | CT‑5 | Resource mapping |
| 22:04:56 | new user | `CreateRole lambda‑role‑1741125895` | CT‑6 | Lambda execution role |
| 22:05:07 | new user | **`CreateFunction20150331 data‑processor‑1741125906`** | CT‑7 | Back‑door Lambda function |
| 22:05:08‑09 | new user | `CreateVpc`, `CreateSubnet`, `CreateSecurityGroup` | CT‑8 | New network enclave |
| 22:05:10‑11 | new user | **`RunInstances` × 2** | CT‑9 | EC2 instances launched (billing spike) |

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
| Lambda ARN | `arn:aws:lambda:us‑east‑1:238233324971:function:data‑processor‑1741125906` |

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


