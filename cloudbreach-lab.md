
# Breach in the Cloud - PwnedLabs Writeup

## Overview
This lab focuses on analyzing **AWS CloudTrail logs** to detect suspicious activity and identify how an attacker breached an AWS account. The goal is to simulate a real-world scenario where an attacker exploits misconfigured permissions to access sensitive data stored in an S3 bucket. As a beginner, this lab helped me understand the importance of monitoring and securing cloud environments.

---

## Lab Objectives
1. Analyze CloudTrail logs to identify suspicious activity.
2. Understand how attackers exploit misconfigured IAM roles and permissions.
3. Simulate an attacker's actions to validate the breach path.
4. Retrieve sensitive data from an S3 bucket.

---

## Tools Used
- **AWS CLI**: To interact with AWS services.
- **jq**: A command-line tool to prettify and parse JSON files.
- **grep**: To search through log files.
- **curl**: To check IP address information.

---

## Step-by-Step Walkthrough

### 1. Setting Up the Lab
The lab provided a zip file (`INCIDENT-3252.zip`) containing CloudTrail logs. These logs record all API calls made in an AWS account, which is useful for detecting suspicious activity.

#### Downloading and Extracting the Logs
1. I downloaded the `INCIDENT-3252.zip` file from the Pwned Labs Discord channel.
2. I unzipped the file using the following command:
   ```bash
   unzip INCIDENT-3252.zip -d INCIDENT-3252
   cd INCIDENT-3252
2. Prettifying the JSON Logs
The CloudTrail logs were in JSON format but weren't easy to read. I used jq to prettify the JSON files for better analysis.

Installing jq
If not already installed, I installed jq using:

bash
Copy
sudo apt install jq
Prettifying the Logs
I ran the following command to prettify all JSON files in the directory:

bash
Copy
for file in *.json; do jq . "$file" > "$file.tmp" && mv "$file.tmp" "$file"; done
Now, the logs were much easier to read and analyze.

3. Identifying Suspicious Activity
I started by searching for all userName entries in the logs to identify any unusual accounts.

Searching for Usernames
bash
Copy
grep -r userName | sort -u
This revealed a suspicious username: temp-user. This account didn't match the company's naming convention, so I decided to investigate further.

4. Analyzing the temp-user Account
I focused on the earliest log file (107513503799_CloudTrail_us-east-1_20230826T2035Z_PjmwM7E4hZ6897Aq.json) to see what actions temp-user performed.

Searching for temp-user Activity
bash
Copy
grep -h -A 10 temp-user 107513503799_CloudTrail_us-east-1_20230826T2035Z_PjmwM7E4hZ6897Aq.json
The logs showed that temp-user executed the GetCallerIdentity command, which is similar to the whoami command in Linux. This command is often used by attackers to check the permissions of compromised credentials.

Key Findings:
IP Address: The request came from 84.32.71.19 (Turkey), which is not a location where the company operates.

Access Key ID: AKIARSCCN4A3WD4RO4P4

5. Investigating the IP Address
I used curl to check the IP address information:

bash
Copy
curl ipinfo.io/84.32.71.19
The IP was located in Turkey, confirming that the activity was suspicious.

6. Enumerating Permissions
Next, I analyzed the logs to see what actions temp-user attempted. I found that the account tried to list the contents of an S3 bucket named emergency-data-recovery.

Searching for S3 Activity
bash
Copy
grep eventName 107513503799_CloudTrail_us-east-1_20230826T2120Z_UCUhsJa0zoFY3ZO0.json
The logs showed that temp-user successfully downloaded a file named emergency.txt from the bucket.

7. Simulating the Attacker's Actions
To validate the breach path, I simulated the attacker's actions using the AWS CLI.

Configuring AWS CLI
I set up the AWS CLI with the compromised credentials:

bash
Copy
aws configure
Checking Execution Context
I verified the execution context using:

bash
Copy
aws sts get-caller-identity
Assuming the Admin Role
The logs revealed that temp-user assumed an IAM role named AdminRole. I simulated this action:

bash
Copy
aws sts assume-role --role-arn arn:aws:iam::107513503799:role/AdminRole --role-session-name MySession
After assuming the role, I verified the new execution context:

bash
Copy
aws sts get-caller-identity
8. Accessing the S3 Bucket
With the elevated permissions, I listed the contents of the emergency-data-recovery bucket:

bash
Copy
aws s3 ls s3://emergency-data-recovery
I then downloaded the sensitive files:

bash
Copy
aws s3 cp s3://emergency-data-recovery/emergency.txt .
aws s3 cp s3://emergency-data-recovery/message.txt .
The file emergency.txt contained the flag, confirming the breach.

Key Takeaways
Monitor CloudTrail Logs: Regularly review CloudTrail logs to detect suspicious activity.

Secure IAM Roles: Avoid granting excessive permissions to IAM users and roles.

Restrict S3 Bucket Access: Ensure S3 buckets are not publicly accessible unless necessary.

Use Strong Credentials: Protect access keys and rotate them regularly.

Conclusion
This lab was an excellent introduction to cloud security. It taught me how attackers exploit misconfigured permissions and the importance of monitoring AWS activity. As a beginner, I now understand the critical role of securing cloud environments to prevent breaches.
