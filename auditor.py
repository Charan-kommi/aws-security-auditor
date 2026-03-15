#!/usr/bin/env python3
"""
AWS Security Auditor
====================
Scans AWS environments for common security misconfigurations across:
  - IAM users (MFA, stale access keys, admin policies)
  - S3 buckets (public access, encryption, versioning)
  - EC2 Security Groups (dangerous inbound rules)

Author : Sai Charan Kommi
GitHub : https://github.com/Charan-kommi
"""

import json
import datetime
import argparse
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_COLOR = {
    CRITICAL : "#dc2626",
    HIGH     : "#ea580c",
    MEDIUM   : "#d97706",
    LOW      : "#65a30d",
    INFO     : "#2563eb",
}


class Finding:
    def __init__(self, service, resource, title, description, severity, recommendation):
        self.service        = service
        self.resource       = resource
        self.title          = title
        self.description    = description
        self.severity       = severity
        self.recommendation = recommendation

    def to_dict(self):
        return {
            "service"        : self.service,
            "resource"       : self.resource,
            "title"          : self.title,
            "description"    : self.description,
            "severity"       : self.severity,
            "recommendation" : self.recommendation,
        }


def audit_iam(session):
    findings = []
    iam = session.client("iam")
    print("[*] Auditing IAM...")

    try:
        users = iam.list_users()["Users"]
    except ClientError as e:
        print(f"  [!] IAM access denied: {e}")
        return findings

    for user in users:
        uname = user["UserName"]

        mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
        if not mfa_devices:
            findings.append(Finding(
                service="IAM", resource=f"User: {uname}",
                title="MFA Not Enabled",
                description=f"IAM user '{uname}' has no MFA device attached.",
                severity=HIGH,
                recommendation="Enable MFA for all IAM users with console access.",
            ))

        keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                age_days = (datetime.datetime.now(datetime.timezone.utc) - key["CreateDate"]).days
                if age_days > 90:
                    findings.append(Finding(
                        service="IAM", resource=f"User: {uname} / Key: {key['AccessKeyId']}",
                        title="Stale Access Key (>90 days)",
                        description=f"Access key for '{uname}' is {age_days} days old.",
                        severity=MEDIUM,
                        recommendation="Rotate access keys every 90 days. Use IAM roles instead.",
                    ))

        attached = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
        for policy in attached:
            if "AdministratorAccess" in policy["PolicyName"]:
                findings.append(Finding(
                    service="IAM", resource=f"User: {uname}",
                    title="AdministratorAccess Policy Attached Directly",
                    description=f"'{uname}' has AdministratorAccess, violating least-privilege.",
                    severity=CRITICAL,
                    recommendation="Remove AdministratorAccess. Use groups and scoped roles.",
                ))

    print(f"  [+] IAM: {len(findings)} findings")
    return findings


def audit_s3(session):
    findings = []
    s3 = session.client("s3")
    print("[*] Auditing S3...")

    try:
        buckets = s3.list_buckets()["Buckets"]
    except ClientError as e:
        print(f"  [!] S3 access denied: {e}")
        return findings

    for bucket in buckets:
        name = bucket["Name"]

        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(pab.values()):
                findings.append(Finding(
                    service="S3", resource=f"Bucket: {name}",
                    title="Public Access Block Not Fully Enabled",
                    description=f"Bucket '{name}' has partial public-access-block settings.",
                    severity=HIGH,
                    recommendation="Enable all four PublicAccessBlock settings.",
                ))
        except ClientError:
            findings.append(Finding(
                service="S3", resource=f"Bucket: {name}",
                title="Public Access Block Configuration Missing",
                description=f"Could not retrieve public access block config for '{name}'.",
                severity=HIGH,
                recommendation="Configure public access block settings explicitly.",
            ))

        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(Finding(
                    service="S3", resource=f"Bucket: {name}",
                    title="Server-Side Encryption Not Enabled",
                    description=f"Bucket '{name}' has no default SSE configuration.",
                    severity=MEDIUM,
                    recommendation="Enable SSE-S3 or SSE-KMS as default encryption.",
                ))

        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                findings.append(Finding(
                    service="S3", resource=f"Bucket: {name}",
                    title="Versioning Not Enabled",
                    description=f"Bucket '{name}' does not have versioning enabled.",
                    severity=LOW,
                    recommendation="Enable versioning to protect against accidental deletion.",
                ))
        except ClientError:
            pass

    print(f"  [+] S3: {len(findings)} findings")
    return findings


DANGEROUS_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 445: "SMB", 23: "Telnet",
}

def audit_security_groups(session):
    findings = []
    ec2 = session.client("ec2")
    print("[*] Auditing Security Groups...")

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        print(f"  [!] EC2 access denied: {e}")
        return findings

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port   = rule.get("ToPort", 65535)
            protocol  = rule.get("IpProtocol", "-1")
            open_to_world = any(
                r.get("CidrIp") in ("0.0.0.0/0", "::/0")
                for r in rule.get("IpRanges", []) + rule.get("Ipv6Ranges", [])
            )
            if not open_to_world:
                continue
            if protocol == "-1":
                findings.append(Finding(
                    service="EC2", resource=f"Security Group: {sg_name} ({sg_id})",
                    title="All Traffic Open to World",
                    description=f"Security group '{sg_name}' allows ALL traffic from 0.0.0.0/0.",
                    severity=CRITICAL,
                    recommendation="Restrict inbound rules to specific IP ranges and ports.",
                ))
                continue
            for port, service_name in DANGEROUS_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append(Finding(
                        service="EC2", resource=f"Security Group: {sg_name} ({sg_id})",
                        title=f"Port {port} ({service_name}) Open to World",
                        description=f"Security group '{sg_name}' allows {service_name} from 0.0.0.0/0.",
                        severity=HIGH if port in (22, 3389) else MEDIUM,
                        recommendation=f"Restrict port {port} to trusted IP ranges only.",
                    ))

    print(f"  [+] Security Groups: {len(findings)} findings")
    return findings


def generate_html_report(findings, output_path="report.html"):
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    rows = ""
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "#6b7280")
        rows += f"<tr><td>{f.service}</td><td>{f.resource}</td><td>{f.title}</td><td><span style='background:{color};padding:2px 8px;border-radius:999px;color:#fff;font-size:.75rem'>{f.severity}</span></td><td>{f.description}</td><td>{f.recommendation}</td></tr>"

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><title>AWS Security Audit</title>
<style>body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}}
h1{{color:#38bdf8}}table{{width:100%;border-collapse:collapse;background:#1e293b}}
th{{background:#0ea5e9;color:#fff;padding:10px;text-align:left}}td{{padding:10px;border-bottom:1px solid #334155;font-size:.85rem}}</style>
</head><body><h1>🔐 AWS Security Audit Report</h1>
<p>Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | CRITICAL:{counts[CRITICAL]} HIGH:{counts[HIGH]} MEDIUM:{counts[MEDIUM]} LOW:{counts[LOW]}</p>
<table><thead><tr><th>Service</th><th>Resource</th><th>Finding</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[+] HTML report saved → {output_path}")


def generate_json_report(findings, output_path="report.json"):
    data = {"generated_at": datetime.datetime.utcnow().isoformat()+"Z","total":len(findings),"findings":[f.to_dict() for f in findings]}
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] JSON report saved → {output_path}")


def main():
    parser = argparse.ArgumentParser(description="AWS Security Auditor")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region",  default="us-east-1")
    parser.add_argument("--output",  default="html", choices=["html","json","both"])
    parser.add_argument("--checks",  nargs="+", choices=["iam","s3","sg","all"], default=["all"])
    args = parser.parse_args()

    if not BOTO3_AVAILABLE:
        print("[!] boto3 not installed. Run: pip install boto3")
        return

    print("="*55)
    print("   AWS Security Auditor — by Sai Charan Kommi")
    print("="*55)

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        session.client("sts").get_caller_identity()
        print("[+] AWS credentials validated\n")
    except NoCredentialsError:
        print("[!] No AWS credentials found. Run 'aws configure'.")
        return
    except ClientError as e:
        print(f"[!] Credential error: {e}")
        return

    run_all  = "all" in args.checks
    findings = []
    if run_all or "iam" in args.checks: findings += audit_iam(session)
    if run_all or "s3"  in args.checks: findings += audit_s3(session)
    if run_all or "sg"  in args.checks: findings += audit_security_groups(session)

    print(f"\n[=] Total findings: {len(findings)}")
    if args.output in ("html","both"): generate_html_report(findings)
    if args.output in ("json","both"): generate_json_report(findings)


if __name__ == "__main__":
    main()
