# 🔐 AWS Security Auditor

> Automated misconfiguration scanner for AWS IAM, S3, and EC2 Security Groups — with HTML & JSON reporting.

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-boto3-FF9900?style=flat-square&logo=amazon-aws&logoColor=white)](https://aws.amazon.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![Security](https://img.shields.io/badge/Domain-Cloud%20Security-blue?style=flat-square)]()

---

## 📋 Overview

**AWS Security Auditor** is a Python tool that programmatically scans your AWS environment for common security misconfigurations — the same checks that attackers look for first. It helps cloud engineers and security teams get a quick, actionable snapshot of their AWS security posture.

**Why this matters:** Misconfigured IAM policies, public S3 buckets, and overly permissive security groups are consistently in the OWASP Top 10 cloud risks and appear in the majority of real-world AWS breaches (Capital One, Twitch, etc.).

---

## ✨ Features

- ✅ **IAM Audit** — detects missing MFA, stale access keys (>90 days), and direct AdministratorAccess grants
- ✅ **S3 Audit** — checks public access block settings, server-side encryption, and versioning
- ✅ **Security Group Audit** — flags ports exposed to `0.0.0.0/0` (SSH, RDP, MySQL, Redis, MongoDB, etc.)
- ✅ **Severity Rating** — CRITICAL / HIGH / MEDIUM / LOW with color-coded HTML reports
- ✅ **Flexible Output** — HTML dashboard or JSON (for SIEM/pipeline integration)
- ✅ **Multi-profile support** — works with any named AWS CLI profile

---

## 🚀 Getting Started

```bash
git clone https://github.com/Charan-kommi/aws-security-auditor.git
cd aws-security-auditor
pip install -r requirements.txt
```

## 💻 Usage

```bash
# Run all checks (default: HTML report)
python auditor.py

# Use a named AWS profile
python auditor.py --profile my-profile --region us-west-2

# Run only IAM + S3 checks
python auditor.py --checks iam s3

# Output both HTML and JSON
python auditor.py --output both
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| AWS SDK | boto3 / botocore |
| Services Covered | IAM, S3, EC2 |
| Report Formats | HTML, JSON |

---

## 🔒 Security Note

> ⚠️ **For authorized use only.** Never commit AWS credentials. The `.gitignore` is pre-configured to exclude credentials and reports.

---

## 🗺️ Roadmap

- [x] IAM, S3, Security Group auditing
- [x] HTML + JSON reporting
- [ ] CloudTrail logging checks
- [ ] KMS key rotation checks
- [ ] Slack/email alert integration
- [ ] Docker containerization

---

## 👤 Author

**Sai Charan Kommi**
[![LinkedIn](https://img.shields.io/badge/LinkedIn-charankommi-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/charankommi)
[![GitHub](https://img.shields.io/badge/GitHub-Charan--kommi-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/Charan-kommi)

> MS Cybersecurity @ GWU | CompTIA Security+ | AWS Cloud Security Builder
