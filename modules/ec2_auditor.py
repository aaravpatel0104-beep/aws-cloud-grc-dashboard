import boto3
from botocore.exceptions import ClientError

def check_ec2_security():
    ec2 = boto3.client('ec2')
    findings = []

    # 1. Audit EBS Default Encryption
    try:
        encryption_status = ec2.get_ebs_encryption_by_default()
        is_encrypted = encryption_status.get('EbsEncryptionByDefault', False)
        findings.append({
            "Control_ID": "CIS-2.2.1",
            "Framework": "NIST CSF 2.0 PR.DS-02",
            "Resource": "EC2 EBS Default Encryption",
            "Status": "PASS" if is_encrypted else "FAIL",
            "Severity": "High",
            "Remediation": "Enable account-level EBS default encryption using AWS KMS."
        })
    except ClientError as e:
        findings.append({"Control_ID": "CIS-2.2.1", "Status": "ERROR", "Details": str(e)})

    # 2. Audit Security Groups for Open Ingress (0.0.0.0/0 on SSH port 22 or RDP port 3389)
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'Unnamed')
            has_open_mgmt_port = False

            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_ranges = [ip.get('CidrIp') for ip in rule.get('IpRanges', [])]

                if '0.0.0.0/0' in ip_ranges:
                    if from_port is not None and to_port is not None:
                        if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                            has_open_mgmt_port = True
                            break

            findings.append({
                "Control_ID": "CIS-5.2",
                "Framework": "NIST CSF 2.0 PR.AC-05",
                "Resource": f"Security Group: {sg_name} ({sg_id})",
                "Status": "FAIL" if has_open_mgmt_port else "PASS",
                "Severity": "Critical" if has_open_mgmt_port else "Low",
                "Remediation": "Restrict SSH (port 22) and RDP (port 3389) ingress to trusted CIDR blocks only."
            })
    except ClientError as e:
        findings.append({"Control_ID": "CIS-5.2", "Status": "ERROR", "Details": str(e)})

    return findings
