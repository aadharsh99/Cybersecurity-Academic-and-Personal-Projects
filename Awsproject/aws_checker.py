#!/usr/bin/env python3
"""
AWS Misconfiguration Checker
-----------------------------
Audits an AWS account for common security misconfigurations across:
- S3 Buckets
- IAM Users & Policies
- CloudTrail
- Security Groups
- Root Account Usage

Author: Aadharsh Anbuchezhian
"""

import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


# ─── Colour output ────────────────────────────────────────────────────────────
class Colour:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def fail(msg):  print(f"  {Colour.RED}[FAIL]{Colour.RESET} {msg}")
def warn(msg):  print(f"  {Colour.YELLOW}[WARN]{Colour.RESET} {msg}")
def ok(msg):    print(f"  {Colour.GREEN}[ OK ]{Colour.RESET} {msg}")
def info(msg):  print(f"  {Colour.BLUE}[INFO]{Colour.RESET} {msg}")
def header(msg):print(f"\n{Colour.BOLD}{'─'*55}\n {msg}\n{'─'*55}{Colour.RESET}")


# ─── Results tracker ──────────────────────────────────────────────────────────
results = {"pass": 0, "warn": 0, "fail": 0, "findings": []}

def record(level, check, detail):
    results[level] += 1
    results["findings"].append({"level": level, "check": check, "detail": detail})


# ─── S3 Checks ────────────────────────────────────────────────────────────────
def check_s3():
    header("S3 Bucket Checks")
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            info("No S3 buckets found.")
            return

        for bucket in buckets:
            name = bucket["Name"]

            # Public ACL check
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "") in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    ]:
                        fail(f"s3://{name} — Public ACL detected ({grant['Permission']})")
                        record("fail", "S3 Public ACL", f"{name} grants public {grant['Permission']}")
                        break
                else:
                    ok(f"s3://{name} — ACL is not public")
                    record("pass", "S3 Public ACL", name)
            except ClientError as e:
                warn(f"s3://{name} — Could not read ACL: {e.response['Error']['Code']}")

            # Public access block check
            try:
                block = s3.get_public_access_block(Bucket=name)
                config = block["PublicAccessBlockConfiguration"]
                all_blocked = all([
                    config.get("BlockPublicAcls"),
                    config.get("IgnorePublicAcls"),
                    config.get("BlockPublicPolicy"),
                    config.get("RestrictPublicBuckets"),
                ])
                if all_blocked:
                    ok(f"s3://{name} — Public access block enabled")
                    record("pass", "S3 Public Access Block", name)
                else:
                    warn(f"s3://{name} — Public access block partially or not enabled")
                    record("warn", "S3 Public Access Block", f"{name}: {config}")
            except ClientError:
                warn(f"s3://{name} — No public access block configuration found")
                record("warn", "S3 Public Access Block", f"{name}: no block config")

            # Versioning check
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                status = ver.get("Status", "Disabled")
                if status == "Enabled":
                    ok(f"s3://{name} — Versioning enabled")
                    record("pass", "S3 Versioning", name)
                else:
                    warn(f"s3://{name} — Versioning is {status}")
                    record("warn", "S3 Versioning", f"{name}: {status}")
            except ClientError as e:
                warn(f"s3://{name} — Could not check versioning: {e}")

    except ClientError as e:
        fail(f"Could not list S3 buckets: {e}")


# ─── IAM Checks ───────────────────────────────────────────────────────────────
def check_iam():
    header("IAM Checks")
    iam = boto3.client("iam")

    # MFA on root
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 1:
            ok("Root account MFA is enabled")
            record("pass", "Root MFA", "Enabled")
        else:
            fail("Root account MFA is NOT enabled")
            record("fail", "Root MFA", "Disabled — high risk")
    except ClientError as e:
        warn(f"Could not check root MFA: {e}")

    # Users without MFA
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if mfa_devices:
                ok(f"IAM user '{username}' — MFA enabled")
                record("pass", "IAM User MFA", username)
            else:
                warn(f"IAM user '{username}' — No MFA device attached")
                record("warn", "IAM User MFA", f"{username}: no MFA")
    except ClientError as e:
        warn(f"Could not list IAM users: {e}")

    # Users with admin-level inline/attached policies
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for policy in attached:
                if "AdministratorAccess" in policy["PolicyName"]:
                    warn(f"IAM user '{username}' — Has AdministratorAccess policy attached")
                    record("warn", "IAM Admin Policy", f"{username}: AdministratorAccess attached")
    except ClientError as e:
        warn(f"Could not check user policies: {e}")

    # Access keys older than 90 days
    try:
        users = iam.list_users()["Users"]
        now = datetime.now(timezone.utc)
        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                age_days = (now - key["CreateDate"]).days
                if age_days > 90:
                    fail(f"IAM user '{username}' — Access key {key['AccessKeyId']} is {age_days} days old")
                    record("fail", "IAM Stale Access Key", f"{username}: key age {age_days}d")
                else:
                    ok(f"IAM user '{username}' — Access key is {age_days} days old")
                    record("pass", "IAM Access Key Age", username)
    except ClientError as e:
        warn(f"Could not check access keys: {e}")


# ─── CloudTrail Checks ────────────────────────────────────────────────────────
def check_cloudtrail():
    header("CloudTrail Checks")
    ct = boto3.client("cloudtrail")

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            fail("No CloudTrail trails found — audit logging is disabled")
            record("fail", "CloudTrail Enabled", "No trails configured")
            return

        for trail in trails:
            name = trail["Name"]

            # Is logging active?
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging"):
                ok(f"Trail '{name}' — Logging is active")
                record("pass", "CloudTrail Logging", name)
            else:
                fail(f"Trail '{name}' — Logging is INACTIVE")
                record("fail", "CloudTrail Logging", f"{name}: not logging")

            # Multi-region
            if trail.get("IsMultiRegionTrail"):
                ok(f"Trail '{name}' — Multi-region enabled")
                record("pass", "CloudTrail Multi-Region", name)
            else:
                warn(f"Trail '{name}' — Single region only")
                record("warn", "CloudTrail Multi-Region", f"{name}: single region")

            # Log file validation
            if trail.get("LogFileValidationEnabled"):
                ok(f"Trail '{name}' — Log file validation enabled")
                record("pass", "CloudTrail Log Validation", name)
            else:
                warn(f"Trail '{name}' — Log file validation disabled")
                record("warn", "CloudTrail Log Validation", f"{name}: validation off")

    except ClientError as e:
        fail(f"Could not check CloudTrail: {e}")


# ─── Security Group Checks ────────────────────────────────────────────────────
def check_security_groups():
    header("EC2 Security Group Checks")
    ec2 = boto3.client("ec2")

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        risky_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}

        for sg in sgs:
            sg_id   = sg["GroupId"]
            sg_name = sg.get("GroupName", "unknown")

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort", 65535)

                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        for port, service in risky_ports.items():
                            if from_port <= port <= to_port:
                                fail(f"SG '{sg_name}' ({sg_id}) — Port {port} ({service}) open to 0.0.0.0/0")
                                record("fail", f"SG Open {service}", f"{sg_name}: {port} open to world")

                for ipv6_range in rule.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        for port, service in risky_ports.items():
                            if from_port <= port <= to_port:
                                warn(f"SG '{sg_name}' ({sg_id}) — Port {port} ({service}) open to ::/0 (IPv6)")
                                record("warn", f"SG Open {service} IPv6", f"{sg_name}: {port} open to IPv6 world")

        ok("Security group scan complete")

    except ClientError as e:
        fail(f"Could not check security groups: {e}")


# ─── Summary & JSON Report ────────────────────────────────────────────────────
def print_summary():
    header("Scan Summary")
    total = results["pass"] + results["warn"] + results["fail"]
    print(f"  Total checks : {total}")
    print(f"  {Colour.GREEN}Passed{Colour.RESET}       : {results['pass']}")
    print(f"  {Colour.YELLOW}Warnings{Colour.RESET}     : {results['warn']}")
    print(f"  {Colour.RED}Failures{Colour.RESET}     : {results['fail']}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"aws_misconfig_report_{timestamp}.json"
    with open(report_path, "w") as f:
        json.dump({
            "scan_time": timestamp,
            "summary": {
                "pass": results["pass"],
                "warn": results["warn"],
                "fail": results["fail"]
            },
            "findings": results["findings"]
        }, f, indent=2)

    print(f"\n  {Colour.BLUE}Report saved:{Colour.RESET} {report_path}\n")


# ─── Entry point ──────────────────────────────────────────────────────────────
def main():
    print(f"\n{Colour.BOLD}{'═'*55}")
    print("  AWS Misconfiguration Checker")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*55}{Colour.RESET}")

    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        info(f"Account ID : {identity['Account']}")
        info(f"ARN        : {identity['Arn']}")
    except NoCredentialsError:
        print(f"\n{Colour.RED}[ERROR] No AWS credentials found.")
        print("Configure with: aws configure  OR  set environment variables")
        print(f"AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY{Colour.RESET}\n")
        return

    check_s3()
    check_iam()
    check_cloudtrail()
    check_security_groups()
    print_summary()


if __name__ == "__main__":
    main()
