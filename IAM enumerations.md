# My IAM Journey: From Basic Concepts to Real Security Skills  

## Intro to AWS IAM Enumeration - Pwned Labs  

### Overview  
This lab is all about learning how to check AWS IAM settings and find out what permissions different users and roles have. By doing this, we can see if there are any security issues that might let someone gain extra permissions.  

### Goals  
- Learn the basics of AWS IAM enumeration.  
- Use AWS CLI commands to check IAM users, roles, and policies.  
- Understand how some settings can lead to privilege escalation.  
- Get hands-on experience with AWS security.  



### What You Need  
- An AWS account.  
- AWS CLI installed on your computer.  
- IAM credentials (Access Key ID & Secret Access Key).  
- AWS CLI configured properly.  

### Configuring AWS CLI  
Run this command to set up AWS CLI:  
```sh
aws configure
```  
Enter your AWS Access Key, Secret Access Key, region, and output format.  

## Enumeration Steps  

### 1. Finding IAM Users  
To see all IAM users in the AWS account, use:  
```sh
aws iam list-users
```  

### 2. Checking IAM Roles  
To find out what roles exist in the account, run:  
```sh
aws iam list-roles
```  

### 3. Viewing IAM Policies  
To see policies attached to the account:  
```sh
aws iam list-policies --scope Local
```  

### 4. Checking What Permissions a User Has  
To see what policies are attached to a specific user:  
```sh
aws iam list-attached-user-policies --user-name <USERNAME>
```  
To check inline policies for a user:  
```sh
aws iam list-user-policies --user-name <USERNAME>
```  

### 5. Finding Security Risks  
To check if a user has administrator permissions:  
```sh
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::<ACCOUNT-ID>:user/<USERNAME> --action-names "*"
```  
To look for permissions that can lead to privilege escalation, such as `iam:PassRole` or `iam:CreatePolicyVersion`:  
```sh
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```  

## How Someone Could Exploit Weak IAM Settings  

### 1. Using iam:PassRole to Gain More Access  
If a user has the `iam:PassRole` permission, they can attach an admin role to a service and get higher permissions.  
```sh
aws iam pass-role --role-name <ROLE_NAME>
```  

### 2. Creating a New Policy Version with More Access  
If a user has `iam:CreatePolicyVersion`, they can create a new version of a policy that gives them more power.  
```sh
aws iam create-policy-version --policy-arn <POLICY_ARN> --policy-document file://malicious_policy.json --set-as-default
```  

## How to Stay Secure  
- Follow the principle of least privilege (only give users the permissions they need).  
- Regularly review IAM policies and permissions.  
- Turn on AWS CloudTrail to log IAM activities.  
- Use AWS IAM Access Analyzer to find risky permissions.  

## Conclusion  
This lab helps beginners learn how to check IAM settings and understand how security issues can arise. By knowing these basic checks, you can help keep AWS environments more secure!

