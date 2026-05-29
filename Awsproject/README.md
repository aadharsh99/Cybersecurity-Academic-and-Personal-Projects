# 🔐 AWS Misconfiguration Checker

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![AWS](https://img.shields.io/badge/AWS-boto3-orange?logo=amazon-aws)
![License](https://img.shields.io/badge/License-MIT-green)

> Audits your AWS account for security misconfigurations and compliance risks.

## Overview
Scans an AWS account for common security misconfigurations across S3 buckets, IAM policies, CloudTrail, and security groups. Generates a color-coded terminal report and JSON output with findings at a glance.

## Features
- **S3 Audits** – Detects public ACLs, missing public access blocks, and unversioned buckets
- **IAM Security** – Checks for disabled MFA on root/users, admin-level policies, and stale access keys (90+ days)
- **CloudTrail Monitoring** – Verifies audit logging is enabled, multi-region enabled, and log validation active
- **Security Group Analysis** – Flags risky ports (SSH, RDP, MySQL, PostgreSQL, MongoDB) open to `0.0.0.0/0` and IPv6
- **JSON Reports** – Saves detailed findings to timestamped report files for compliance documentation

## Prerequisites
- Python 3.10+
- AWS account with IAM permissions to read S3, IAM, CloudTrail, EC2
- AWS CLI configured with valid credentials

## Installation
```bash
git clone https://github.com/aadharsh99/Projects.git
cd Awsproject
pip install -r requirements.txt
```

## Configuration
Set up AWS credentials using one of these methods:

**Option 1: AWS CLI**
```bash
aws configure
```

**Option 2: Environment variables**
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

**Option 3: IAM credentials file**
Create `~/.aws/credentials` with your profile credentials.

## Usage
```bash
python main.py
```

### Example Output
```
═══════════════════════════════════════════════════════
  AWS Misconfiguration Checker
  Started: 2024-01-15 14:32:01
═══════════════════════════════════════════════════════

[INFO] Account ID : 123456789012
[INFO] ARN        : arn:aws:iam::123456789012:user/auditor

───────────────────────────────────────────────────────
 S3 Bucket Checks
───────────────────────────────────────────────────────
  [FAIL] s3://my-bucket — Public ACL detected (READ)
  [ OK ] s3://secure-bucket — ACL is not public
  [WARN] s3://logs-bucket — Versioning is Disabled

───────────────────────────────────────────────────────
 IAM Checks
───────────────────────────────────────────────────────
  [ OK ] Root account MFA is enabled
  [WARN] IAM user 'dev-user' — No MFA device attached
  [FAIL] IAM user 'admin-user' — Access key is 145 days old

───────────────────────────────────────────────────────
 CloudTrail Checks
───────────────────────────────────────────────────────
  [ OK ] Trail 'organization-trail' — Logging is active
  [ OK ] Trail 'organization-trail' — Multi-region enabled

───────────────────────────────────────────────────────
 Scan Summary
───────────────────────────────────────────────────────
  Total checks : 26
  Passed       : 18
  Warnings     : 5
  Failures     : 3

  Report saved: aws_misconfig_report_20240115_143201.json
```

## Report Output
The tool generates a timestamped JSON report with findings:

```json
{
  "scan_time": "20240115_143201",
  "summary": {
    "pass": 18,
    "warn": 5,
    "fail": 3
  },
  "findings": [
    {
      "level": "fail",
      "check": "S3 Public ACL",
      "detail": "my-bucket grants public READ"
    },
    {
      "level": "warn",
      "check": "IAM User MFA",
      "detail": "dev-user: no MFA"
    }
  ]
}
```

## Technologies
| Library | Purpose |
|---------|---------|
| boto3 | AWS SDK for Python |
| botocore | AWS error handling |
| json | Report generation |
| datetime | Timestamp tracking |

## Author
Aadharsh Anbuchezhian