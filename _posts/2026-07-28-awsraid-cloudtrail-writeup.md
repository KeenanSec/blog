---
title: "AWSRaid: Reconstructing a Cloud Account Compromise from CloudTrail"
date: 2026-07-28 12:00:00 -0500
categories: [Blue Team, DFIR]
tags: [aws, cloudtrail, splunk, dfir, mitre, incident-response]
image:
  path: /assets/img/aws-raid/02-s3-getobject.png
  alt: CloudTrail S3 GetObject events surfaced in Splunk
---

## Overview

An external actor brute-forced the `helpdesk.luke` IAM user, then used those valid credentials to pull 8 objects from 7 S3 buckets in under two minutes, including a secrets vault dump, customer data backups, and proprietary CAD designs. They disabled S3 Block Public Access on a critical bucket, created a backdoor IAM user, and escalated it into the `Admins` group. The full kill chain, initial access through privilege escalation, completed in roughly four minutes. All evidence came from AWS CloudTrail logs queried in Splunk.

| Field | Value |
| ----- | ----- |
| Compromised account | `helpdesk.luke` |
| Attacker ARN | `arn:aws:iam::141573590337:user/helpdesk.luke` |
| AWS account ID | `141573590337` |
| Backdoor account | `marketing.mark` (added to `Admins`) |
| Source IP | Not captured in dataset (lab) |
| Activity window | 2023-11-02, 09:55–09:59 UTC |
| Key file stolen | `Product2_CAD_Designs.dwg` |

## Attack timeline

| Time (UTC) | Action | Detail |
| ---------- | ------ | ------ |
| pre-09:55 | Brute force | 10 failed console logins against `helpdesk.luke` |
| 09:55:53 | Collection begins | First `GetObject`: `prototype.obj` |
| 09:55–09:57 | Bulk data access | 8 objects pulled across 7 buckets |
| 09:58:01 | Weaken controls | `PutBucketPublicAccessBlock` on `backup-and-restore98825501` |
| 09:59:33 | Persistence | `CreateUser` `marketing.mark` |
| 09:59:38 | Persistence | `CreateLoginProfile` for `marketing.mark` |
| 09:59:38 | Privilege escalation | `AddUserToGroup`: `marketing.mark` to `Admins` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
| ------ | --------- | -- | -------- |
| Credential Access | Brute Force | T1110 | 10 failed console logins for `helpdesk.luke` |
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | Successful auth after brute force |
| Collection | Data from Cloud Storage | T1530 | 8 `GetObject` calls across 7 buckets |
| Defense Evasion | Impair Defenses: Disable/Modify Cloud Firewall | T1562.007 | `PutBucketPublicAccessBlock` (closest cloud fit for disabling S3 Block Public Access) |
| Persistence | Create Account: Cloud Account | T1136.003 | `CreateUser` `marketing.mark` |
| Persistence | Account Manipulation | T1098 | `CreateLoginProfile` for `marketing.mark` |
| Privilege Escalation | Account Manipulation | T1098 | `AddUserToGroup` to `Admins` |

## Indicators & affected assets

**Identities**

- Compromised: `helpdesk.luke` (`arn:aws:iam::141573590337:user/helpdesk.luke`)
- Attacker-created backdoor: `marketing.mark` (member of `Admins`)

**Buckets accessed** (all via `helpdesk.luke`)

| Bucket | Object | Sensitivity |
| ------ | ------ | ----------- |
| `research-project-files23411723` | `prototype.obj` | R&D |
| `backup-and-restore98825501` | `secrets_vault_dump.bak`, `Configuration_Backup_Server2.zip` | Critical (public access later disabled) |
| `product-designs-repository31183937` | `Product2_CAD_Designs.dwg` | Proprietary IP |
| `contracts-data67988444` | `Contract_Termination_Letter_Client.pdf` | Legal |
| `customer-data-backup57893984` | `CustomerData_Backup_2023-11-01.zip` | Customer PII |
| `legal-docs45020393` | `Contract_Agreement.pdf` | Legal |
| `marketing-assets-vault27512203` | `logo.png` | Low |

## Investigation

### Q1 — Compromised user account

> **Answer:** `helpdesk.luke` — *T1110, Credential Access*
{: .prompt-info }

Counted failed console authentications per user from CloudTrail sign-in events, sorted descending.

```
index="aws_cloudtrail" eventSource="signin.amazonaws.com" errorMessage="Failed authentication" | stats count by userIdentity.userName | sort -count
```

`helpdesk.luke` had 10 failed attempts, well above the next user (`devops.ethan`, 3), consistent with a targeted brute force that eventually succeeded.

![Failed auth counts per user in Splunk, helpdesk.luke highest at 10](/assets/img/aws-raid/01-failed-logins.png)
_Failed-auth counts per user, sorted descending._

### Q2 — First S3 object access

> **Answer:** `2023-11-02 09:55:53` — *T1530, Collection*
{: .prompt-info }

Listed every S3 object touched by `helpdesk.luke`, with time, action, bucket, and key.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" | table _time, eventName, requestParameters.bucketName, requestParameters.key
```

The earliest `GetObject` was `prototype.obj` at 09:55:53. In total 8 objects were pulled from 7 buckets within 78 seconds, indicating scripted bulk collection rather than manual browsing.

![Splunk table of 8 GetObject events across multiple S3 buckets](/assets/img/aws-raid/02-s3-getobject.png)
_8 objects across 7 buckets in 78 seconds._

### Q3 — Bucket containing the DWG file

> **Answer:** `product-designs-repository31183937` — *T1530, Collection*
{: .prompt-info }

Same query as Q2, filtered to `.dwg` (AutoCAD drawing format).

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" "*.dwg" | table _time, requestParameters.bucketName, requestParameters.key
```

One hit: `Product2_CAD_Designs.dwg` in `product-designs-repository31183937` at 09:56:07. Proprietary engineering IP, with no legitimate reason for a helpdesk account to read it.

![Splunk table showing the single dwg file in the product-designs-repository bucket](/assets/img/aws-raid/03-dwg-file.png)
_The only .dwg accessed, the CAD design file._

### Q4 — Bucket configured for public access

> **Answer:** `backup-and-restore98825501` — *T1562.007, Defense Evasion*
{: .prompt-info }

Searched for public-access-block changes, including the full ARN to confirm identity.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventName="PutBucketPublicAccessBlock" | table _time, requestParameters.bucketName, userIdentity.arn
```

At 09:58:01, `helpdesk.luke` modified Block Public Access on `backup-and-restore98825501`. The attacker had **already** pulled `secrets_vault_dump.bak` and `Configuration_Backup_Server2.zip` from this bucket at 09:57 using valid credentials, so disabling the block was not required for their own access. It reads as broad public exposure or staging for a second party rather than a step in Luke's own exfil.

![Splunk table showing PutBucketPublicAccessBlock with the confirming ARN](/assets/img/aws-raid/04-public-access-block.png)
_The block change and the confirming ARN._

### Q5 — Attacker-created account

> **Answer:** `marketing.mark` — *T1136.003, Persistence*
{: .prompt-info }

Looked for IAM user creation and console login setup by `helpdesk.luke`. `CreateUser` alone yields a user with no password, so `CreateLoginProfile` is what enables interactive console sign-in.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventCategory="Management" | search eventName="CreateUser" OR eventName="CreateLoginProfile" | table _time, eventName, requestParameters.userName
```

`marketing.mark` was created at 09:59:33 and given a console login profile at 09:59:38. The login profile signals intent for hands-on-keyboard access, not just API keys.

![Splunk table showing CreateUser and CreateLoginProfile for marketing.mark](/assets/img/aws-raid/05-create-user.png)
_Backdoor account created, then given console access._

### Q6 — Group the account was added to

> **Answer:** `Admins` — *T1098, Privilege Escalation*
{: .prompt-info }

Queried all `AddUserToGroup` events account-wide, deliberately not scoped to Luke, since escalation could target any identity.

```
index="aws_cloudtrail" eventName="AddUserToGroup" | table _time, requestParameters.groupName, requestParameters.userName
```

Single result: `marketing.mark` added to `Admins` at 09:59:38. This is the escalation that turns the backdoor account from powerless into full administrator. The wide query returned only this one event, confirming the blast radius is a single created account.

![Splunk table showing marketing.mark added to the Admins group](/assets/img/aws-raid/06-add-to-group.png)
_The escalation to full admin._

## Lessons learned

Each item maps to a control gap the attacker exploited in this incident.

| Gap | Impact in this incident | Recommendation |
| --- | --- | --- |
| No evidence of MFA on console logins | Password brute force alone granted full access | Enforce MFA on all IAM users via SCP |
| No alerting on failed-auth volume | 10 failed logins went unnoticed before the breach | GuardDuty / CloudWatch alarm on repeated `ConsoleLogin` failures per user |
| Over-permissioned helpdesk account | One account read 7 buckets of secrets, PII, contracts, and CAD IP | Scope IAM policies to least privilege |
| Unmonitored IAM changes | Backdoor admin created and escalated in seconds | Alert on `CreateUser`, `CreateLoginProfile`, `AddUserToGroup`; SCP-gate `Admins` membership |
| Mutable public-access controls | Critical bucket exposed by a non-admin user | SCP denying `PutBucketPublicAccessBlock` except a break-glass role |

> This was a lab environment, so MFA enforcement could not be confirmed from the available logs. The failed-then-successful login pattern is consistent with weak or absent MFA, but this is an inference, not a confirmed finding.
{: .prompt-warning }

## Gaps & recommendations

**Investigation gaps**

- No attacker source IP or user agent was collected. Pull `sourceIPAddress` and `userAgent` on the sign-in and API events to attribute geo, check for impossible travel, and confirm whether all actions came from one host.
- Confirm the direction of the public-access-block change by inspecting `requestParameters.PublicAccessBlockConfiguration` in the raw event (all four flags `false` = block disabled).
- Verify whether `marketing.mark` also received access keys (`CreateAccessKey`) for programmatic persistence alongside the console login.

**Containment / remediation**

- Disable `helpdesk.luke`, force password rotation, revoke active sessions.
- Delete `marketing.mark` and remove it from `Admins`.
- Re-enable Block Public Access on `backup-and-restore98825501` and audit whether the bucket was reached publicly during the exposure window.
- Treat `secrets_vault_dump.bak`, customer data, and CAD IP as confirmed exfiltrated; rotate any credentials in the secrets dump.
