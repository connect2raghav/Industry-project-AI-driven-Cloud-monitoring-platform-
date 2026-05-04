"""
LocalStack AWS Engine
Connects to LocalStack (fake AWS on localhost:4566) for real boto3 CSPM/CIEM scans.
Falls back to simulator if LocalStack is not running.

Setup:
  pip install localstack awscli-local
  localstack start
  awslocal s3 mb s3://test-public-bucket
  awslocal iam create-user --user-name alice
"""
import os
import uuid

LOCALSTACK_ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
USE_LOCALSTACK = os.environ.get("USE_LOCALSTACK", "false").lower() == "true"

def _client(service: str):
    import boto3
    return boto3.client(
        service,
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )


def is_localstack_running() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen(f"{LOCALSTACK_ENDPOINT}/_localstack/health", timeout=2)
        return True
    except Exception:
        return False


def run_cspm_scan_localstack() -> list:
    results = []
    try:
        s3 = _client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all(block.values()):
                    results.append({
                        "scan_id": str(uuid.uuid4())[:8],
                        "vulnerability_id": "CSPM-S3-001",
                        "title": "S3 Bucket Publicly Accessible",
                        "description": f"Bucket '{name}' has public access enabled.",
                        "severity": "critical",
                        "resource": f"arn:aws:s3:::{name}",
                        "remediation": "Enable all PublicAccessBlock settings.",
                        "status": "open"
                    })
            except Exception:
                results.append({
                    "scan_id": str(uuid.uuid4())[:8],
                    "vulnerability_id": "CSPM-S3-001",
                    "title": "S3 Bucket — No Public Access Block",
                    "description": f"Bucket '{name}' has no PublicAccessBlock configuration.",
                    "severity": "critical",
                    "resource": f"arn:aws:s3:::{name}",
                    "remediation": "Add PublicAccessBlock configuration.",
                    "status": "open"
                })
    except Exception as e:
        print(f"[LocalStack CSPM S3] {e}")

    try:
        ec2 = _client("ec2")
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0" and rule.get("FromPort") in [22, 3389]:
                        results.append({
                            "scan_id": str(uuid.uuid4())[:8],
                            "vulnerability_id": "CSPM-EC2-002",
                            "title": f"Port {rule['FromPort']} Open to Internet",
                            "description": f"SG {sg['GroupId']} allows port {rule['FromPort']} from 0.0.0.0/0",
                            "severity": "high",
                            "resource": sg["GroupId"],
                            "remediation": "Restrict to corporate CIDR.",
                            "status": "open"
                        })
    except Exception as e:
        print(f"[LocalStack CSPM EC2] {e}")

    return results


def run_ciem_scan_localstack() -> list:
    results = []
    try:
        iam = _client("iam")

        for user in iam.list_users().get("Users", []):
            username = user["UserName"]
            try:
                policies = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                for p in policies:
                    if p["PolicyName"] == "AdministratorAccess":
                        results.append({
                            "scan_id": str(uuid.uuid4())[:8],
                            "risk_id": "CIEM-001",
                            "title": "Over-privileged User",
                            "entity_name": username,
                            "entity_type": "human",
                            "risk_level": "critical",
                            "description": f"User '{username}' has AdministratorAccess.",
                            "remediation": "Apply least-privilege policy."
                        })
            except Exception:
                pass

        for role in iam.list_roles().get("Roles", []):
            role_name = role["RoleName"]
            try:
                for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                    doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Action") == "*" or stmt.get("Resource") == "*":
                            results.append({
                                "scan_id": str(uuid.uuid4())[:8],
                                "risk_id": "CIEM-004",
                                "title": "Wildcard Permissions in Role",
                                "entity_name": role_name,
                                "entity_type": "role",
                                "risk_level": "high",
                                "description": f"Role '{role_name}' has wildcard Action/Resource.",
                                "remediation": "Scope down to specific ARNs."
                            })
            except Exception:
                pass

    except Exception as e:
        print(f"[LocalStack CIEM] {e}")

    return results


def get_localstack_status() -> dict:
    running = is_localstack_running()
    return {
        "available": running,
        "endpoint": LOCALSTACK_ENDPOINT,
        "mode": "localstack" if running else "simulated",
        "message": f"Connected to LocalStack at {LOCALSTACK_ENDPOINT}" if running else "LocalStack not running — using simulator"
    }
