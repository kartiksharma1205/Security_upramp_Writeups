
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
   ```
     unzip INCIDENT-3252.zip -d INCIDENT-3252
     cd INCIDENT-3252 
2. Prettifying the JSON Logs
The CloudTrail logs were in JSON format but weren't easy to read. I used jq to prettify the JSON files for better analysis.


Prettifying the Logs
I ran the following command to prettify all JSON files in the directory:

```for file in *.json; do jq . "$file" > "$file.tmp" && mv "$file.tmp" "$file"; done```

Now, the logs were much easier to read and analyze.

3. Identifying Suspicious Activity
I started by searching for all userName entries in the logs to identify any unusual accounts.

Searching for Usernames

```grep -r userName | sort -u```

``` sharkark@b0be8352ef4d INCIDENT-3252 % grep -r userName | sort -u ````
./107513503799_CloudTrail_us-east-1_20230826T2035Z_PjmwM7E4hZ6897Aq.json.save:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2035Z_PjmwM7E4hZ6897Aq.json:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2040Z_UkDeakooXR09uCBm.json.save:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2040Z_UkDeakooXR09uCBm.json:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2050Z_iUtQqYPskB20yZqT.json:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2055Z_W0F5uypAbGttUgSn.json:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2100Z_APB7fBUnHmiWjHtg.json:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json:            "userName": "AdminRole"
./107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json:        "userName": "_devansh"
./107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json:        "userName": "ian"
./107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json:        "userName": "policyuser"
./107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json:        "userName": "temp-user"
./107513503799_CloudTrail_us-east-1_20230826T2120Z_UCUhsJa0zoFY3ZO0.json:            "userName": "AdminRole" ```
This revealed a suspicious username: temp-user. This account didn't match the company's naming convention, so I decided to investigate further.

4. Analyzing  all the Account

Searching for temp user Activity

```
grep -h -A 30 temp-user 107513503799_CloudTrail_us-east-1_20230826T2035Z_PjmwM7E4hZ6897Aq.json
grep -h -A 30 temp-user 107513503799_CloudTrail_us-east-1_20230826T2035Z_PjmwM7E4hZ6897Aq.json`
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:29:37Z",
      "eventSource": "sts.amazonaws.com",
      "eventName": "GetCallerIdentity",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.19",
      "userAgent": "aws-cli/1.27.74 Python/3.10.6 Linux/5.15.90.1-microsoft-standard-WSL2 botocore/1.29.74",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "3db296ab-c531-4b4a-a468-e1b05ec83246",
      "eventID": "ea6ae4b8-aae8-4fca-a495-2df427bdce46",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "sts.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A34LC6MFWG", 
```


The logs showed that temp-user executed the GetCallerIdentity command, which is similar to the whoami command in Linux. This command is often used by attackers to check the permissions of compromised credentials.


Access Key ID: AKIARSCCN4A3WD4RO4P4

5. Investigating the IP Address
I checked the ip address on https://iplocation.io/ip/84.32.71.19

```
Decimal:1411401491

Hostname:84.32.71.19

ASN:204770

ISP:UAB Nacionalinis Telekomunikaciju Tinklas

Services:Datacenter

Country:United States

State/Region:Illinois

City:Chicago

Latitude:41.8758 (41° 52′ 32.78″ N)

Longitude:-87.6206 (87° 37′ 14.18″ W)
```
Checking another json for temp user activity

```
grep -h -A 30 temp-user 107513503799_CloudTrail_us-east-1_20230826T2050Z_iUtQqYPskB20yZqT.json
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:10Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListAccountAliases",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.5",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: iam:ListAccountAliases on resource: * because no identity-based policy allows the iam:ListAccountAliases action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "b9a8da9b-186f-43a9-8f8f-af06b88a04ba",
      "eventID": "e85acf53-e122-4355-ae85-25fc6d019e46",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "iam.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:10Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListInstanceProfiles",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.49",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: iam:ListInstanceProfiles on resource: arn:aws:iam::107513503799:instance-profile/ because no identity-based policy allows the iam:ListInstanceProfiles action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "2fde5739-be1f-4747-88c6-9636b75b00aa",
      "eventID": "dc16a1e4-cda2-4c05-8364-e48729b343dd",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "iam.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:10Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListSigningCertificates",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.35",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: iam:ListSigningCertificates on resource: user temp-user because no identity-based policy allows the iam:ListSigningCertificates action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "3165d62b-f370-4764-815e-827d0fc3d487",
      "eventID": "a015eca1-d37b-4a91-9819-fa821c1cc027",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "iam.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:10Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListUsers",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.5",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: iam:ListUsers on resource: arn:aws:iam::107513503799:user/ because no identity-based policy allows the iam:ListUsers action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "984a45f3-362f-4594-856f-87f9fd09c019",
      "eventID": "ba8030e3-a7b9-4492-a400-6103e5b35860",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "iam.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:46:55Z",
      "eventSource": "datapipeline.amazonaws.com",
      "eventName": "ListPipelines",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.18",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: datapipeline:ListPipelines on resource: arn:aws:datapipeline:us-east-1:107513503799:pipeline/* because no identity-based policy allows the datapipeline:ListPipelines action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "a3ffdf71-6c36-4edc-b23e-dfe50a73967e",
      "eventID": "dd9dfc2d-e6f1-469a-9451-2d516527e3ca",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "datapipeline.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:46:55Z",
      "eventSource": "comprehend.amazonaws.com",
      "eventName": "ListEntityRecognizers",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.32",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: comprehend:ListEntityRecognizers because no identity-based policy allows the comprehend:ListEntityRecognizers action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "8e05b9f8-94e7-4cef-916f-ebf8e85ffe9d",
      "eventID": "9714c9d8-b866-416d-8677-08d5be989f3e",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "comprehend.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:46:58Z",
      "eventSource": "dax.amazonaws.com",
      "eventName": "DescribeDefaultParameters",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.21",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: dax:DescribeDefaultParameters because no identity-based policy allows the dax:DescribeDefaultParameters action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "2e3427b8-7daf-49af-ab99-37275d554b16",
      "eventID": "2180f786-4e0e-476a-af83-d32618b32788",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "dax.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:22Z",
      "eventSource": "organizations.amazonaws.com",
      "eventName": "ListAccounts",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.47",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: organizations:ListAccounts on resource: * because no resource-based policy allows the organizations:ListAccounts action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "d7185d46-3aba-4ca7-9deb-7ba1df4d0ede",
      "eventID": "bd0a64b2-7e00-4069-80ce-f58e52940b31",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:28Z",
      "eventSource": "route53.amazonaws.com",
      "eventName": "ListHealthChecks",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.243",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: route53:ListHealthChecks because no identity-based policy allows the route53:ListHealthChecks action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "3f394d4f-b24e-4f6d-b606-c643da52f535",
      "eventID": "1f4d7d34-da3f-4f62-89ce-ca287c20b40c",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "route53.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:09Z",
      "eventSource": "iot.amazonaws.com",
      "eventName": "ListAuthorizers",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.29",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: iot:ListAuthorizers on resource: * because no identity-based policy allows the iot:ListAuthorizers action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "1f9c63ca-0bcb-4d7e-b4df-851a080e74fb",
      "eventID": "a8e2f4a6-ef73-4622-acc8-9651c5747f36",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "iot.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:19Z",
      "eventSource": "mediaconvert.amazonaws.com",
      "eventName": "ListPresets",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.28",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "9a537c8d-49fe-4c85-beff-07060dd07ef3",
      "eventID": "54979edf-5edb-470a-9e3a-ce3666ddf831",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:30Z",
      "eventSource": "route53resolver.amazonaws.com",
      "eventName": "ListResolverRules",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.29",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: route53resolver:ListResolverRules because no identity-based policy allows the route53resolver:ListResolverRules action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "4ad4a144-ebc4-409b-9ce3-efaaf006bfb5",
      "eventID": "c2724f94-b320-44ec-a4db-5df1e049ad18",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "route53resolver.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:37Z",
      "eventSource": "ssm.amazonaws.com",
      "eventName": "ListComplianceItems",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.50",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: ssm:ListComplianceItems on resource: arn:aws:ssm:us-east-1:107513503799:* because no identity-based policy allows the ssm:ListComplianceItems action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "e38f6d50-d003-4392-b16f-c65056598cd0",
      "eventID": "258ce2ae-9de2-4933-af26-fc9cf5f5c7a6",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "ssm.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:40Z",
      "eventSource": "waf.amazonaws.com",
      "eventName": "ListGeoMatchSets",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.20",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: waf:ListGeoMatchSets on resource: arn:aws:waf::107513503799:geomatchset/* because no identity-based policy allows the waf:ListGeoMatchSets action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "d3f2c8d4-b3cd-4794-88a2-4bfbaae91856",
      "eventID": "2f9fcdf2-53a1-4f83-b936-2d66ebf9c830",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "waf.amazonaws.com"
      }
    }
  ]
}
sharkark@b0be8352ef4d INCIDENT-3252 % >....
      "requestParameters": null,
      "responseElements": null,
      "requestID": "e38f6d50-d003-4392-b16f-c65056598cd0",
      "eventID": "258ce2ae-9de2-4933-af26-fc9cf5f5c7a6",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "ssm.us-east-1.amazonaws.com"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARSCCN4A3X2YWZ37ZI",
        "arn": "arn:aws:iam::107513503799:user/temp-user",
        "accountId": "107513503799",
        "accessKeyId": "AKIARSCCN4A3WD4RO4P4",
        "userName": "temp-user"
      },
      "eventTime": "2023-08-26T20:47:40Z",
      "eventSource": "waf.amazonaws.com",
      "eventName": "ListGeoMatchSets",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.20",
      "userAgent": "aws-sdk-go-v2/1.3.2",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:iam::107513503799:user/temp-user is not authorized to perform: waf:ListGeoMatchSets on resource: arn:aws:waf::107513503799:geomatchset/* because no identity-based policy allows the waf:ListGeoMatchSets action",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "d3f2c8d4-b3cd-4794-88a2-4bfbaae91856",
      "eventID": "2f9fcdf2-53a1-4f83-b936-2d66ebf9c830",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "waf.amazonaws.com"
      }
    }
  ]
}
```
The temp-user attempted to enumerate resources across multiple AWS services but was consistently denied access due to a lack of permissions.

Analyzing next JSON for temp user

```
grep -h -A 20 temp-user 107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json
        "userName": "temp-user"
      },
      "responseElements": null,
      "requestID": "db7e3483-7876-4fc5-b043-b55464e8d6e0",
      "eventID": "674c1fc2-c61a-4f11-b35e-3e67b1909852",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
--
        "userName": "temp-user"
      },
      "responseElements": null,
      "requestID": "6cc85b17-109e-4143-88cd-896b59cd70cd",
      "eventID": "7fee19b4-aa4c-4297-b0b9-f70749c21198",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
--
        "userName": "temp-user"
      },
      "responseElements": null,
      "requestID": "dca5544d-9e90-4a77-af5e-4322963e0df6",
      "eventID": "c45745cd-d6aa-4cf6-b1fc-514a801cb239",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
--
        "userName": "temp-user"
      },
      "responseElements": null,
      "requestID": "d69635cb-67a4-4112-95d4-8bb4cfd7ccde",
      "eventID": "d7a06b60-0bd7-4af2-b9ce-2d0197185bda",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
--
        "userName": "temp-user"
      },
      "responseElements": null,
      "requestID": "177e6cdd-992a-4a3e-825d-3c0cd3e00581",
      "eventID": "118e0170-d435-4bee-bbb9-7b1633dae5af",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A3ULZJKHRZ",
        "sessionContext": {
          "sessionIssuer": {},
```




Checking for Devansh user

``` 
sharkark@b0be8352ef4d INCIDENT-3252 % grep -h -A 30 _devansh 107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json
        "userName": "_devansh"
      },
      "responseElements": null,
      "requestID": "db7e3483-7876-4fc5-b043-b55464e8d6e0",
      "eventID": "90dd3cc8-6264-459a-b3a2-40a6c6652a36",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:45Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "GetLoginProfile",
--
        "userName": "_devansh"
      },
      "responseElements": null,
      "requestID": "6cc85b17-109e-4143-88cd-896b59cd70cd",
      "eventID": "76faf471-a489-4e10-a65e-e9b23d06c37e",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:46Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListSigningCertificates",
--
        "userName": "_devansh"
      },
      "responseElements": null,
      "requestID": "dca5544d-9e90-4a77-af5e-4322963e0df6",
      "eventID": "e7d21ecb-d2fe-44fb-9170-7e1f673bce49",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:47Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListMFADevices",
--
        "userName": "_devansh"
      },
      "responseElements": null,
      "requestID": "d69635cb-67a4-4112-95d4-8bb4cfd7ccde",
      "eventID": "ffb0d076-53a0-4ce8-8502-72b80c58c511",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:48Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListAccessKeys",
--
        "userName": "_devansh"
      },
      "responseElements": null,
      "requestID": "177e6cdd-992a-4a3e-825d-3c0cd3e00581",
      "eventID": "351fa992-77fc-481a-b4e1-4c912fe99ae4",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:48Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListGroupsForUser", 
```
Actions Performed on IAM User _devansh:

GetLoginProfile: Retrieves login profile information for the IAM user.

ListSigningCertificates: Lists signing certificates associated with the IAM user.

ListMFADevices: Lists MFA devices associated with the IAM user.

ListAccessKeys: Lists access keys for the IAM user.

ListGroupsForUser: Lists groups the IAM user belongs to.


Checking for PolicyUser

```
sharkark@b0be8352ef4d INCIDENT-3252 %  grep -h -A 30 policyuser 107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json
        "userName": "policyuser"
      },
      "responseElements": null,
      "requestID": "db7e3483-7876-4fc5-b043-b55464e8d6e0",
      "eventID": "ea797e00-83e4-4d2e-9962-4ba98db9f724",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:45Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "GetLoginProfile",
--
        "userName": "policyuser"
      },
      "responseElements": null,
      "requestID": "6cc85b17-109e-4143-88cd-896b59cd70cd",
      "eventID": "1a9fdf91-f17a-4819-bc46-f0a6daae1646",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:46Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListSigningCertificates",
--
        "userName": "policyuser"
      },
      "responseElements": null,
      "requestID": "dca5544d-9e90-4a77-af5e-4322963e0df6",
      "eventID": "3aec6c23-54db-4e40-9f68-7d19cf3a97d3",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:47Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListMFADevices",
--
        "userName": "policyuser"
      },
      "responseElements": null,
      "requestID": "d69635cb-67a4-4112-95d4-8bb4cfd7ccde",
      "eventID": "ab25dd0b-54af-4b24-bdfe-b07de547e761",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:48Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListAccessKeys",
--
        "userName": "policyuser"
      },
      "responseElements": null,
      "requestID": "177e6cdd-992a-4a3e-825d-3c0cd3e00581",
      "eventID": "7418242d-d2b7-4fed-9f28-722f53c45db7",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:48Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListGroupsForUser",
```
Actions performed by Policy user-

GetLoginProfile: Retrieves the login profile for the IAM user.

ListSigningCertificates: Lists signing certificates associated with the IAM user.

ListMFADevices: Lists MFA devices associated with the IAM user.

ListAccessKeys: Lists access keys for the IAM user.

ListGroupsForUser: Lists groups the IAM user belongs to.

Checking for Ian
```
 grep -h -A 30 ian 107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json
        "userName": "ian"
      },
      "responseElements": null,
      "requestID": "db7e3483-7876-4fc5-b043-b55464e8d6e0",
      "eventID": "7e549918-3c67-4cb6-b9a9-2ab6b611e03e",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:45Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "GetLoginProfile",
--
        "userName": "ian"
      },
      "responseElements": null,
      "requestID": "6cc85b17-109e-4143-88cd-896b59cd70cd",
      "eventID": "1980cc10-07c0-4424-9aeb-aff291afe169",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:46Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListSigningCertificates",
--
        "userName": "ian"
      },
      "responseElements": null,
      "requestID": "dca5544d-9e90-4a77-af5e-4322963e0df6",
      "eventID": "81d2b391-7ab7-4abf-bf21-384433449f3f",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:47Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListMFADevices",
--
        "userName": "ian"
      },
      "responseElements": null,
      "requestID": "d69635cb-67a4-4112-95d4-8bb4cfd7ccde",
      "eventID": "01e37391-70b3-447a-8398-83d6502671ab",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:48Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListAccessKeys",
--
        "userName": "ian"
      },
      "responseElements": null,
      "requestID": "177e6cdd-992a-4a3e-825d-3c0cd3e00581",
      "eventID": "e10e866d-42b9-4903-aec1-f02953279418",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management"
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "Root",
        "principalId": "107513503799",
        "arn": "arn:aws:iam::107513503799:root",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A32TCSFA53",
        "sessionContext": {
          "sessionIssuer": {},
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T18:45:20Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:58:48Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListGroupsForUser",
```
Action performed by Ian

GetLoginProfile: Retrieves the login profile for the IAM user.

ListSigningCertificates: Lists signing certificates associated with the IAM user.

ListMFADevices: Lists MFA devices associated with the IAM user.

ListAccessKeys: Lists access keys for the IAM user.

ListGroupsForUser: Lists groups the IAM user belongs to.

Checking for AdminRole
```
 grep -h -A 30 AdminRole 107513503799_CloudTrail_us-east-1_20230826T2105Z_fpp78PgremAcrW5c.json
        "arn": "arn:aws:sts::107513503799:assumed-role/AdminRole/MySession",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A3QPI4OFEH",
        "sessionContext": {
          "sessionIssuer": {
            "type": "Role",
            "principalId": "AROARSCCN4A34V23XHK6I",
            "arn": "arn:aws:iam::107513503799:role/AdminRole",
            "accountId": "107513503799",
            "userName": "AdminRole"
          },
          "webIdFederationData": {},
          "attributes": {
            "creationDate": "2023-08-26T20:54:28Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T20:59:54Z",
      "eventSource": "sts.amazonaws.com",
      "eventName": "GetCallerIdentity",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "84.32.71.36",
      "userAgent": "aws-cli/1.27.74 Python/3.10.6 Linux/5.15.90.1-microsoft-standard-WSL2 botocore/1.29.74",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "4afc1ae7-cac8-4a12-bf61-5d2b08c5aa46",
      "eventID": "010387ea-2bc8-45fb-8c5a-8ba865492209",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "managementEvent": true,
      "recipientAccountId": "107513503799",
      "eventCategory": "Management",
      "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "sts.amazonaws.com"
      }
    },
```
Action performed by Admin role

The log entry shows that the AdminRole was assumed

The action performed here is likely AssumeRole, which is the API call used to create a session for an IAM role.


Another JSON for AdminRole

```

sharkark@b0be8352ef4d INCIDENT-3252 % grep -h -A 10 AdminRole 107513503799_CloudTrail_us-east-1_20230826T2120Z_UCUhsJa0zoFY3ZO0.json
        "arn": "arn:aws:sts::107513503799:assumed-role/AdminRole/MySession",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A3QPI4OFEH",
        "sessionContext": {
          "sessionIssuer": {
            "type": "Role",
            "principalId": "AROARSCCN4A34V23XHK6I",
            "arn": "arn:aws:iam::107513503799:role/AdminRole",
            "accountId": "107513503799",
            "userName": "AdminRole"
          },
          "attributes": {
            "creationDate": "2023-08-26T20:54:28Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T21:17:10Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "ListObjects",
--
        "arn": "arn:aws:sts::107513503799:assumed-role/AdminRole/MySession",
        "accountId": "107513503799",
        "accessKeyId": "ASIARSCCN4A3QPI4OFEH",
        "sessionContext": {
          "sessionIssuer": {
            "type": "Role",
            "principalId": "AROARSCCN4A34V23XHK6I",
            "arn": "arn:aws:iam::107513503799:role/AdminRole",
            "accountId": "107513503799",
            "userName": "AdminRole"
          },
          "attributes": {
            "creationDate": "2023-08-26T20:54:28Z",
            "mfaAuthenticated": "false"
          }
        }
      },
      "eventTime": "2023-08-26T21:17:16Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "GetObject",
sharkark@b0be8352ef4d INCIDENT-3252 %

```
Actions Performed by AdminRole:

ListObjects: Attempted to list objects in an S3 bucket.

GetObject: Attempted to retrieve an object from an S3 bucket.


6. Enumerating Permissions
Next, I analyzed the logs to see what actions temp-user attempted. I found that the account tried to list the contents of an S3 bucket named emergency-data-recovery.

Searching for S3 Activity


```grep eventName 107513503799_CloudTrail_us-east-1_20230826T2120Z_UCUhsJa0zoFY3ZO0.json```


The logs showed that temp-user successfully downloaded a file named emergency.txt from the bucket.

7. Simulating the Attacker's Actions
To validate the breach path, I simulated the attacker's actions using the AWS CLI.

Configuring AWS CLI
I set up the AWS CLI with the compromised credentials:

```aws configure```

Checking Execution Context
I verified the execution context using:

```aws sts get-caller-identity```

Assuming the Admin Role
The logs revealed that temp-user assumed an IAM role named AdminRole. I simulated this action:

```aws sts assume-role --role-arn arn:aws:iam::107513503799:role/AdminRole --role-session-name MySession```

After assuming the role, I verified the new execution context:

```aws sts get-caller-identity```

8. Accessing the S3 Bucket
With the elevated permissions, I listed the contents of the emergency-data-recovery bucket:

```aws s3 ls s3://emergency-data-recovery```

I then downloaded the sensitive files:

```aws s3 cp s3://emergency-data-recovery/emergency.txt .```
```aws s3 cp s3://emergency-data-recovery/message.txt .```

The file emergency.txt contained the flag, confirming the breach.

Key Takeaways
Monitor CloudTrail Logs: Regularly review CloudTrail logs to detect suspicious activity.

Secure IAM Roles: Avoid granting excessive permissions to IAM users and roles.

Restrict S3 Bucket Access: Ensure S3 buckets are not publicly accessible unless necessary.

Use Strong Credentials: Protect access keys and rotate them regularly.

Conclusion
This lab was an excellent introduction to cloud security. It taught me how attackers exploit misconfigured permissions and the importance of monitoring AWS activity. As a beginner, I now understand the critical role of securing cloud environments to prevent breaches.
