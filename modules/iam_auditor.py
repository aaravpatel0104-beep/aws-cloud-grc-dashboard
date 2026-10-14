import boto3
from botocore.exceptions import ClientError

def check_iam_security():
    iam = boto3.client('iam')
    findings = []
    
    # 1. Root Account MFA
    try:
        summary = iam.get_account_summary()['SummaryMap']
        root_mfa_enabled = summary.get('AccountMFAEnabled', 0) == 1
        findings.append({
            "Control_ID": "CIS-1.1",
            "Framework": "NIST CSF 2.0 PR.AC-01",
            "Resource": "AWS Account Root",
            "Status": "PASS" if root_mfa_enabled else "FAIL",
            "Severity": "Critical",
            "Remediation": "Enable hardware or virtual MFA on the root user immediately."
        })
    except ClientError as e:
        findings.append({"Control_ID": "CIS-1.1", "Status": "ERROR", "Details": str(e)})

    # 2. Account Password Policy
    try:
        iam.get_account_password_policy()
        findings.append({
            "Control_ID": "CIS-1.8",
            "Framework": "NIST CSF 2.0 PR.AC-01",
            "Resource": "IAM Password Policy",
            "Status": "PASS",
            "Severity": "Medium",
            "Remediation": "Password policy adheres to complexity requirements."
        })
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append({
                "Control_ID": "CIS-1.8",
                "Framework": "NIST CSF 2.0 PR.AC-01",
                "Resource": "IAM Password Policy",
                "Status": "FAIL",
                "Severity": "Medium",
                "Remediation": "Configure an account-level password complexity policy."
            })

    return findings
