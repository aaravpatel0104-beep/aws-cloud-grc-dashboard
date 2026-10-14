import boto3
from botocore.exceptions import ClientError

def check_s3_security():
    s3 = boto3.client('s3')
    findings = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            b_name = bucket['Name']
            
            # Check Public Access Block
            try:
                pab = s3.get_public_access_block(Bucket=b_name)
                conf = pab['PublicAccessBlockConfiguration']
                is_secure = all([
                    conf.get('BlockPublicAcls', False),
                    conf.get('IgnorePublicAcls', False),
                    conf.get('BlockPublicPolicy', False),
                    conf.get('RestrictPublicBuckets', False)
                ])
                status = "PASS" if is_secure else "FAIL"
            except ClientError:
                status = "FAIL"

            findings.append({
                "Control_ID": "CIS-2.1.4",
                "Framework": "NIST CSF 2.0 PR.DS-01",
                "Resource": f"S3 Bucket: {b_name}",
                "Status": status,
                "Severity": "High",
                "Remediation": "Enable 'Block All Public Access' on the S3 bucket."
            })
            
    except ClientError as e:
        findings.append({"Control_ID": "S3-List", "Status": "ERROR", "Details": str(e)})

    return findings
