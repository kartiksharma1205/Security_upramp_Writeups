```markdown
# CloudBreach  log analysis Report  
 

## What Happened?  
An attacker broke into an AWS account by:  
1. Finding an **open S3 bucket** (like an unlocked storage box)  
2. Stealing **login keys** (IAM credentials) from a file inside it  
3. Using those keys to get **admin access**  
4. Copying **private files** from another restricted bucket  

We know how the attack happened from the [original write-up](https://github.com/kartiksharma1205/Security_upramp_Writeups/blob/main/cloudbreach-lab.md). Now let's **prove it using logs**.

---

## Step 1: Attacker Found the Open S3 Bucket  
**Log Proof (AWS CloudTrail):**  
```json
{
    "eventTime": "2023-11-05T14:22:10Z",
    "eventName": "ListBucket",
    "userIdentity": {"type": "Anonymous"},  // No login = public access!
    "requestParameters": {"bucketName": "cloudbreach-s3"},
    "sourceIPAddress": "45.67.89.123"  // Attacker's IP
}
```

**What This Means:**  
- Someone from **IP 45.67.89.123** listed files in `cloudbreach-s3` **without logging in**  
- **Proof the bucket was open to the public**  

---

## Step 2: Attacker Stole AWS Keys  
**Log Proof (S3 Access Log):**  
```json
{
    "eventTime": "2023-11-05T14:25:30Z",
    "eventName": "GetObject",
    "userIdentity": {"type": "Anonymous"},  
    "requestParameters": {"key": "config.txt"},  // File with AWS keys
    "sourceIPAddress": "45.67.89.123"  // Same IP!
}
```

**What This Means:**  
- The attacker downloaded `config.txt` which had **AWS access keys** inside  
- **Proof they stole credentials**  

---

## Step 3: Attacker Used Stolen Keys to Get Admin Power  
**Log Proof (AWS CloudTrail - AssumeRole):**  
```json
{
    "eventTime": "2023-11-05T14:30:15Z",
    "eventName": "AssumeRole",
    "userIdentity": {"userName": "breached-user"},  
    "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/admin-role"},
    "sourceIPAddress": "45.67.89.123"  // Same IP!
}
```

**What This Means:**  
- The attacker used the stolen keys to **become an admin** (`admin-role`)  
- **Proof of privilege escalation**  

---

## Step 4: Attacker Copied Private Files  
**Log Proof (S3 Access Log):**  
```json
{
    "eventTime": "2023-11-05T14:35:45Z",
    "eventName": "ListBucket",
    "userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/admin-role/evil-session"},
    "requestParameters": {"bucketName": "finance-data"},  // Private bucket!
    "sourceIPAddress": "45.67.89.123"  
}
```

```json
{
    "eventTime": "2023-11-05T14:36:20Z",
    "eventName": "GetObject",
    "requestParameters": {"key": "confidential.docx"},  // Stolen file!
    "sourceIPAddress": "45.67.89.123"  
}
```

**What This Means:**  
- The attacker (now as `admin-role`) **opened `finance-data`** and took `confidential.docx`  
- **Proof of data theft**  

---

## Conclusion: We Proved the Attack!  
✅ **Same IP (`45.67.89.123`) did all steps**  
✅ **Logs show: open bucket → stolen keys → admin access → data copied**  


---
* 
``` 
