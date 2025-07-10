# 🔍 CloudBreach Incident Summary

## 🔍 Summary: What Really Happened?
An attacker took advantage of a public AWS S3 bucket, snatched login credentials from it, escalated their privileges to admin level, and then helped themselves to sensitive data from another protected area. The entire sequence is backed up by log data and points consistently to the same IP address: **45.67.89.123**.

---

## 🪣 Step 1: They Found an Open S3 Bucket
The attacker didn’t even have to log in. They accessed the bucket `cloudbreach-s3` anonymously and listed its contents. That’s a red flag—an open, public-facing storage bucket without proper permissions.

### 🧾 Log Clue:
```json
"userIdentity": {"type": "Anonymous"},
"bucketName": "cloudbreach-s3",
"sourceIPAddress": "45.67.89.123"
```

✅ ** takeaway**: This was like leaving the front door unlocked. Anyone on the internet could walk in and peek around.

---

## 🔐 Step 2: They Stole AWS Keys
Next, they downloaded a file named `config.txt`—and unfortunately, it contained AWS access keys. Again, this was accessed anonymously from the same IP.

### 🧾 Log Clue:
```json
"eventName": "GetObject",
"key": "config.txt",
"sourceIPAddress": "45.67.89.123"
```

✅ ** takeaway**: The attacker found the digital equivalent of keys to the house sitting on the coffee table.

---

## 🧑‍💼 Step 3: They Assumed Admin Role
With the stolen keys in hand, they accessed AWS using the identity of `breached-user` and assumed an admin-level IAM role. That’s privilege escalation, giving them full access.

### 🧾 Log Clue:
```json
"eventName": "AssumeRole",
"roleArn": "arn:aws:iam::123456789012:role/admin-role",
"sourceIPAddress": "45.67.89.123"
```

✅ **Takeaway**: They used the keys to impersonate an admin and unlock all the doors in the house.

---

## 📁 Step 4: They Copied Private Files
Finally, they accessed the restricted bucket `finance-data` and downloaded a confidential file named `confidential.docx`. Now acting as an admin, they were essentially invisible and unrestricted.

### 🧾 Log Clue:
```json
"bucketName": "finance-data",
"key": "confidential.docx",
"sourceIPAddress": "45.67.89.123"
```

✅ **Takeaway**: They got into the company’s safe and walked away with sensitive documents.

---

## ✅ Final Wrap-up
The attack path is **crystal clear** and all events trace back to the **same IP address (45.67.89.123)**.

**Logs confirm the full chain:**
`Public bucket → Keys stolen → Admin role assumed → Private data stolen`
