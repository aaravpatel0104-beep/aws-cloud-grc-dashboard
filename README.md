# Automated AWS Cloud Security & GRC Posture Dashboard

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Boto3%20%7C%20IAM%20%7C%20EC2%20%7C%20S3-FF9900?logo=amazon-aws&logoColor=white)
![Framework](https://img.shields.io/badge/Compliance-NIST%20CSF%202.0%20%7C%20CIS%20v3.0-0A85EA)
![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-FF4B4B?logo=streamlit&logoColor=white)

An automated cloud posture assessment tool that audits live AWS infrastructure against **NIST CSF 2.0** and the **CIS AWS Foundations Benchmark v3.0**, rendering executive posture metrics and generating downloadable audit artifacts (.CSV & .PDF).

---

## 📌 Business Problem & Engineering Objective
Manual security assessments in cloud environments are slow, inconsistent, and often disconnected from enterprise compliance frameworks. Organizations struggle to correlate raw infrastructure states (unencrypted storage, non-MFA privileged accounts, permissive network access) into actionable control mappings required by internal risk managers and external auditors.

This tool solves this by querying the AWS API programmatically using least-privilege `SecurityAudit` permissions, correlating live resource telemetry directly against NIST CSF and CIS controls, and generating executive audit reports in real time.

---

## 🏗️ Architecture & Control Mapping

- **CIS 1.1 / NIST CSF PR.AC-01:** Verifies hardware/virtual MFA enforcement on the AWS Root user.
- **CIS 1.8 / NIST CSF PR.AC-01:** Audits the presence of an account-wide password complexity policy.
- **CIS 2.1.4 / NIST CSF PR.DS-01:** Evaluates S3 buckets for centralized 'Block Public Access' configurations.
- **CIS 2.2.1 / NIST CSF PR.DS-02:** Validates default account-level EBS volume encryption via AWS KMS.
- **CIS 5.2 / NIST CSF PR.AC-05:** Detects unshielded public ingress rules (`0.0.0.0/0`) on management ports (SSH 22 / RDP 3389).

---

## 📸 Interface Preview

![Dashboard Preview][(https://github.com/user-attachments/files/33419030/Dashboard.pdf)]


*A sample generated audit artifact is available at `reports/sample_audit_output.pdf`.*

---

## ⚙️ Setup & Local Execution

### Prerequisites
- Python 3.11+
- An AWS Account with an IAM user/role assigned the `SecurityAudit` managed policy

### Installation
```bash
git clone [https://github.com/aaravpatel0104-beep/aws-cloud-grc-dashboard.git](https://github.com/aaravpatel0104-beep/aws-cloud-grc-dashboard.git)
cd aws-cloud-grc-dashboard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
