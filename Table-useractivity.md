### Concise Table: User Activity Summary

| **User**      | **Event Time**       | **Event Source**       | **Event Name**            | **Source IP**   | **Error Code** | **Suspicious Activity** |
|---------------|----------------------|------------------------|---------------------------|-----------------|----------------|--------------------------|
| temp-user     | 2023-08-26T20:29:37Z | sts.amazonaws.com      | GetCallerIdentity         | 84.32.71.19     | -              | No                       |
| temp-user     | 2023-08-26T20:47:10Z | iam.amazonaws.com      | ListAccountAliases        | 84.32.71.5      | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:10Z | iam.amazonaws.com      | ListInstanceProfiles      | 84.32.71.49     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:10Z | iam.amazonaws.com      | ListSigningCertificates   | 84.32.71.35     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:10Z | iam.amazonaws.com      | ListUsers                 | 84.32.71.5      | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:46:55Z | datapipeline.amazonaws.com | ListPipelines         | 84.32.71.18     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:46:55Z | comprehend.amazonaws.com | ListEntityRecognizers  | 84.32.71.32     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:46:58Z | dax.amazonaws.com      | DescribeDefaultParameters | 84.32.71.21     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:22Z | organizations.amazonaws.com | ListAccounts       | 84.32.71.47     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:28Z | route53.amazonaws.com  | ListHealthChecks         | 84.32.71.243    | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:09Z | iot.amazonaws.com      | ListAuthorizers          | 84.32.71.29     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:19Z | mediaconvert.amazonaws.com | ListPresets         | 84.32.71.28     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:30Z | route53resolver.amazonaws.com | ListResolverRules | 84.32.71.29     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:37Z | ssm.amazonaws.com      | ListComplianceItems      | 84.32.71.50     | AccessDenied   | Yes                      |
| temp-user     | 2023-08-26T20:47:40Z | waf.amazonaws.com      | ListGeoMatchSets         | 84.32.71.20     | AccessDenied   | Yes                      |
| _devansh      | 2023-08-26T20:58:45Z | iam.amazonaws.com      | GetLoginProfile          | -               | -              | No                       |
| policyuser    | 2023-08-26T20:58:45Z | iam.amazonaws.com      | GetLoginProfile          | -               | -              | No                       |
| ian           | 2023-08-26T20:58:45Z | iam.amazonaws.com      | GetLoginProfile          | -               | -              | No                       |
| AdminRole     | 2023-08-26T20:59:54Z | sts.amazonaws.com      | GetCallerIdentity        | 84.32.71.36     | -              | No                       |
| AdminRole     | 2023-08-26T21:17:10Z | s3.amazonaws.com       | ListObjects              | -               | -              | No                       |

---

### Key Observations:
- **Suspicious Activity**: 
  - `temp-user` has multiple `AccessDenied` errors across various AWS services, indicating potential permission enumeration or probing.
  - Source IPs (`84.32.71.x`) are from Lithuania, which may be unusual if not expected.

- **Normal Activity**:
  - Users like `_devansh`, `policyuser`, and `ian` show routine IAM activities with no errors.
  - `AdminRole` has standard administrative tasks with no suspicious behavior.
