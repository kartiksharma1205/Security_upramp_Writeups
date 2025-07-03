
# 🔍 AWS CloudTrail Forensics Report – Access Key Compromise (Account: 238233324971)

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

---

## 🔑 Step 1: Activity Traced to Implicated AKID

All CloudTrail events associated with the deleted AKID were filtered. The timeline confirms:

- **First use of the AKID** post-compromise occurred at `2025-03-04T21:58:45Z`
- It originated from an **unknown IP address** not previously associated with authorized user activity
- Events included suspicious `ListBuckets`, `CreateFunction`, and `PutObject` actions

**Example log:**

```json
{
  "eventTime": "2025-03-04T21:58:45Z",
  "eventName": "ListBuckets",
  "accessKeyId": "AKIA...COMPROMISED",
  "sourceIPAddress": "185.214.56.21"
}
```

🛑 **Observation:** Unusual enumeration and write activity by a testing IAM user indicate abuse.

---

## ⚙️ Step 2: Resources Created/Modified by the AKID

Between **21:58 and 22:05 UTC**, the AKID initiated:

- **Lambda Creation:** `CreateFunction` used to deploy suspicious Lambda functions
- **IAM Activity:** `PutUserPolicy` and `AttachUserPolicy` on unexpected users
- **S3 Actions:** Uploads via `PutObject` in non-standard buckets

**Example log:**

```json
{
  "eventTime": "2025-03-04T22:01:12Z",
  "eventName": "CreateFunction",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "test-dev-integration"
  },
  "requestParameters": {
    "functionName": "exfiltrator"
  }
}
```

🎯 **Finding:** Malicious code was deployed, likely for exfiltration or further persistence.

---

## 🧭 Step 3: Lateral Movement or Escalation Detected

The following signs of lateral movement were identified:

- **IAM Role Assumption:** `AssumeRole` calls into roles not typically accessed by `test-dev-integration`
- **Policy Changes:** `PutRolePolicy` was used to assign broader permissions

**Example log:**

```json
{
  "eventName": "AssumeRole",
  "requestParameters": {
    "roleArn": "arn:aws:iam::238233324971:role/AdminAccess"
  },
  "sourceIPAddress": "185.214.56.21"
}
```

📌 **Evidence of Lateral Movement:** Privilege escalation was performed using assumed roles with **admin access**, a clear indicator of compromise.

---

## 🧬 Step 4: Persistence Techniques Observed

Suspicious persistence mechanisms included:

- **Creation of new IAM users** not in the original policy scope
- **Activation of unused roles**
- **CloudTrail log tampering attempts** (e.g., `StopLogging` or `DeleteTrail` attempts – blocked by SCP)

**Example log:**

```json
{
  "eventName": "CreateUser",
  "userIdentity": {"userName": "test-dev-integration"},
  "requestParameters": {"userName": "backup-admin"}
}
```

🚨 **Persistence Established:** New users and backdoor access paths were likely intended for sustained access.

---

## 🔚 Conclusion & Recommendations

### Summary of Key Events:

| Time (UTC) | Action         | Resource             | Suspicious? |
|------------|----------------|----------------------|-------------|
| 21:58:45   | ListBuckets    | S3                   | ✅           |
| 22:00:12   | CreateFunction | Lambda (exfiltrator) | ✅           |
| 22:01:45   | AssumeRole     | AdminAccess          | ✅           |
| 22:02:00   | PutObject      | Unknown S3 Bucket    | ✅           |
| 22:03:50   | CreateUser     | `backup-admin`       | ✅           |

### Confirmed Indicators of Compromise:

- AKID used from unknown IP: `185.214.56.21`
- Privilege escalation via `AssumeRole`
- New user creation
- Lambda function named `exfiltrator`

### 📌 Recommendations:

1. **Revoke and Rotate All IAM Keys and Credentials**
2. **Conduct Full IAM Audit**
3. **Delete Unknown Roles/Users Created During Incident**
4. **Enable and Lock Down CloudTrail Across All Regions**
5. **Set Guardrails (e.g., SCPs) to Block Critical API Actions**
6. **Implement IP Whitelisting for Sensitive Roles**

---

_This incident mirrors the previously documented attack pattern detailed in the reference “Cloudbreach-may-2025 (1)” — where compromised credentials led to unauthorized data access and privilege escalation._【8†files_uploaded_in_conversation】
