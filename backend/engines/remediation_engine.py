"""
Automation & Remediation Engine
Provides automated remediation playbooks, configuration correction,
and access revocation for risky entities.

This engine simulates what would happen in a real cloud environment:
- Playbooks define step-by-step remediation actions
- Config correction applies fixes to CSPM findings
- Access revocation disables risky IAM entities from CIEM findings
"""
import uuid
import random
from datetime import datetime, timezone
from typing import List, Dict, Optional
from engines.alert_engine import alert_soc, alert_remediation


# ── Remediation Playbook Definitions ──────────────────────────────────────
PLAYBOOKS = {
    "brute_force": {
        "playbook_id": "PB-BF-001",
        "name": "Brute Force Response",
        "description": "Automated response to detected brute force attacks",
        "severity_trigger": "high",
        "steps": [
            {"order": 1, "action": "block_ip", "description": "Block source IP at WAF/Security Group level", "automated": True},
            {"order": 2, "action": "lock_account", "description": "Temporarily lock targeted user account (30 min)", "automated": True},
            {"order": 3, "action": "force_mfa", "description": "Enforce MFA re-verification on next login", "automated": True},
            {"order": 4, "action": "alert_soc", "description": "Send alert to SOC team via Slack/PagerDuty", "automated": True},
            {"order": 5, "action": "audit_log", "description": "Generate detailed forensic audit trail", "automated": True},
        ],
        "estimated_time_seconds": 45,
        "rollback_available": True
    },
    "privilege_escalation": {
        "playbook_id": "PB-PE-002",
        "name": "Privilege Escalation Response",
        "description": "Automated response to unauthorized privilege escalation",
        "severity_trigger": "critical",
        "steps": [
            {"order": 1, "action": "revert_policy", "description": "Revert IAM policy changes to last known-good state", "automated": True},
            {"order": 2, "action": "revoke_sessions", "description": "Revoke all active sessions for the entity", "automated": True},
            {"order": 3, "action": "quarantine_entity", "description": "Move entity to quarantine OU with read-only access", "automated": True},
            {"order": 4, "action": "snapshot_evidence", "description": "Capture CloudTrail evidence snapshot", "automated": True},
            {"order": 5, "action": "notify_admin", "description": "Escalate to cloud security admin", "automated": True},
        ],
        "estimated_time_seconds": 30,
        "rollback_available": True
    },
    "data_exfiltration": {
        "playbook_id": "PB-DE-003",
        "name": "Data Exfiltration Response",
        "description": "Automated response to possible data exfiltration events",
        "severity_trigger": "critical",
        "steps": [
            {"order": 1, "action": "block_egress", "description": "Block outbound traffic to destination IP via NACL", "automated": True},
            {"order": 2, "action": "revoke_s3_access", "description": "Revoke S3 access for the involved identity", "automated": True},
            {"order": 3, "action": "enable_logging", "description": "Enable enhanced S3 access logging on affected buckets", "automated": True},
            {"order": 4, "action": "isolate_instance", "description": "Isolate source EC2 instance with restrictive SG", "automated": True},
            {"order": 5, "action": "incident_ticket", "description": "Create P1 incident ticket in ITSM system", "automated": True},
            {"order": 6, "action": "preserve_evidence", "description": "Snapshot EBS volumes and preserve CloudTrail logs", "automated": True},
        ],
        "estimated_time_seconds": 60,
        "rollback_available": False
    },
    "lateral_movement": {
        "playbook_id": "PB-LM-004",
        "name": "Lateral Movement Response",
        "description": "Automated response to detected lateral movement within cloud infrastructure",
        "severity_trigger": "high",
        "steps": [
            {"order": 1, "action": "restrict_assume_role", "description": "Deny sts:AssumeRole for the source identity", "automated": True},
            {"order": 2, "action": "isolate_network", "description": "Apply micro-segmentation rules to contain spread", "automated": True},
            {"order": 3, "action": "revoke_temp_creds", "description": "Revoke all temporary security credentials (STS tokens)", "automated": True},
            {"order": 4, "action": "alert_soc", "description": "Alert SOC with kill-chain analysis", "automated": True},
        ],
        "estimated_time_seconds": 35,
        "rollback_available": True
    },
    "misconfiguration": {
        "playbook_id": "PB-MC-005",
        "name": "Misconfiguration Auto-Fix",
        "description": "Automated correction of cloud misconfigurations detected by CSPM",
        "severity_trigger": "medium",
        "steps": [
            {"order": 1, "action": "validate_finding", "description": "Re-validate finding against current resource state", "automated": True},
            {"order": 2, "action": "apply_fix", "description": "Apply predefined Terraform/CloudFormation remediation", "automated": True},
            {"order": 3, "action": "verify_fix", "description": "Verify remediation was successful", "automated": True},
            {"order": 4, "action": "update_baseline", "description": "Update security baseline configuration", "automated": True},
        ],
        "estimated_time_seconds": 90,
        "rollback_available": True
    },
    "crypto_mining": {
        "playbook_id": "PB-CM-006",
        "name": "Crypto Mining Response",
        "description": "Automated response to detected cryptocurrency mining activity",
        "severity_trigger": "high",
        "steps": [
            {"order": 1, "action": "terminate_instance", "description": "Terminate suspicious EC2 instances immediately", "automated": True},
            {"order": 2, "action": "revoke_keys", "description": "Rotate and revoke compromised access keys", "automated": True},
            {"order": 3, "action": "scan_account", "description": "Full account scan for additional compromised resources", "automated": True},
            {"order": 4, "action": "cost_alert", "description": "Trigger billing alert and set spend limit", "automated": True},
        ],
        "estimated_time_seconds": 25,
        "rollback_available": False
    },
    "credential_stuffing": {
        "playbook_id": "PB-CS-007",
        "name": "Credential Stuffing Response",
        "description": "Automated response to credential stuffing attacks using leaked credential lists",
        "severity_trigger": "high",
        "steps": [
            {"order": 1, "action": "rate_limit_logins", "description": "Apply aggressive rate limiting on login endpoints", "automated": True},
            {"order": 2, "action": "block_ip_range", "description": "Block IP ranges associated with credential stuffing botnet", "automated": True},
            {"order": 3, "action": "force_password_reset", "description": "Force password reset for all affected accounts", "automated": True},
            {"order": 4, "action": "enable_captcha", "description": "Enable CAPTCHA challenge on login page", "automated": True},
            {"order": 5, "action": "alert_soc", "description": "Notify SOC with list of targeted accounts", "automated": True},
        ],
        "estimated_time_seconds": 40,
        "rollback_available": True
    },
    "ransomware_precursor": {
        "playbook_id": "PB-RP-008",
        "name": "Ransomware Precursor Response",
        "description": "Early-stage ransomware activity detected — contain before encryption begins",
        "severity_trigger": "critical",
        "steps": [
            {"order": 1, "action": "isolate_host", "description": "Immediately isolate affected host from network", "automated": True},
            {"order": 2, "action": "snapshot_volumes", "description": "Take EBS snapshots of all attached volumes for recovery", "automated": True},
            {"order": 3, "action": "revoke_all_access", "description": "Revoke all IAM credentials associated with the host", "automated": True},
            {"order": 4, "action": "block_c2_ips", "description": "Block known C2 server IPs at network perimeter", "automated": True},
            {"order": 5, "action": "preserve_forensics", "description": "Preserve memory dump and disk image for forensic analysis", "automated": True},
            {"order": 6, "action": "alert_soc", "description": "P0 escalation to SOC and incident response team", "automated": True},
        ],
        "estimated_time_seconds": 20,
        "rollback_available": False
    }
}

# ── CSPM Config Correction Mappings ──────────────────────────────────────────
CONFIG_CORRECTIONS = {
    "CSPM-S3-001": {
        "fix_id": "FIX-S3-001",
        "action": "update_bucket_policy",
        "description": "Remove public access and apply restrictive bucket policy",
        "config_before": {"PublicAccessBlock": {"BlockPublicAcls": False, "BlockPublicPolicy": False}},
        "config_after": {"PublicAccessBlock": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}},
        "terraform_snippet": 'resource "aws_s3_bucket_public_access_block" "fix" {\n  bucket = aws_s3_bucket.target.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}',
        "risk_removed": "Public data exposure"
    },
    "CSPM-EC2-002": {
        "fix_id": "FIX-EC2-002",
        "action": "update_security_group",
        "description": "Remove 0.0.0.0/0 from RDP inbound rule and restrict to corporate CIDR",
        "config_before": {"IpPermissions": [{"FromPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        "config_after": {"IpPermissions": [{"FromPort": 3389, "IpRanges": [{"CidrIp": "10.0.0.0/8"}, {"CidrIp": "172.16.0.0/12"}]}]},
        "terraform_snippet": 'resource "aws_security_group_rule" "rdp_fix" {\n  type = "ingress"\n  from_port = 3389\n  to_port = 3389\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]\n  security_group_id = aws_security_group.target.id\n}',
        "risk_removed": "Remote code execution via exposed RDP"
    },
    "CSPM-IAM-003": {
        "fix_id": "FIX-IAM-003",
        "action": "enable_root_mfa",
        "description": "Enable virtual MFA device for root account",
        "config_before": {"MFADevices": []},
        "config_after": {"MFADevices": [{"SerialNumber": "arn:aws:iam::mfa/root-account-mfa-device", "EnableDate": "auto"}]},
        "terraform_snippet": "# Root MFA must be enabled manually via AWS Console\n# This playbook sends an automated reminder to the account owner",
        "risk_removed": "Account takeover via root credential compromise"
    },
    "CSPM-RDS-004": {
        "fix_id": "FIX-RDS-004",
        "action": "enable_rds_encryption",
        "description": "Create encrypted copy from snapshot and replace unencrypted instance",
        "config_before": {"StorageEncrypted": False},
        "config_after": {"StorageEncrypted": True, "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/auto-generated"},
        "terraform_snippet": 'resource "aws_db_instance" "encrypted" {\n  storage_encrypted = true\n  kms_key_id = aws_kms_key.rds.arn\n  # ... other config from snapshot\n}',
        "risk_removed": "Data-at-rest exposure"
    },
    "CSPM-KMS-005": {
        "fix_id": "FIX-KMS-005",
        "action": "enable_key_rotation",
        "description": "Enable automatic annual key rotation for customer managed KMS key",
        "config_before": {"KeyRotationEnabled": False},
        "config_after": {"KeyRotationEnabled": True},
        "terraform_snippet": 'resource "aws_kms_key" "fix" {\n  enable_key_rotation = true\n}',
        "risk_removed": "Cryptographic key compromise due to stale keys"
    }
}


def execute_playbook(attack_type: str, event: Optional[Dict] = None) -> Dict:
    """
    Execute a remediation playbook for a given attack type.
    Simulates step-by-step execution with status tracking.
    """
    playbook = PLAYBOOKS.get(attack_type, PLAYBOOKS.get("misconfiguration"))
    
    execution_id = f"EXEC-{str(uuid.uuid4())[:8].upper()}"
    now = datetime.now(timezone.utc)
    
    executed_steps = []
    all_success = True
    
    for step in playbook["steps"]:
        # Simulate ~95% success rate per step
        success = random.random() < 0.95
        if not success:
            all_success = False
        
        executed_steps.append({
            "order": step["order"],
            "action": step["action"],
            "description": step["description"],
            "status": "completed" if success else "failed",
            "automated": step["automated"],
            "duration_ms": random.randint(200, 5000)
        })

        # Send real email alert for alert_soc steps
        if step["action"] == "alert_soc" and success and event:
            alert_soc(attack_type, event)
    
    return {
        "execution_id": execution_id,
        "playbook_id": playbook["playbook_id"],
        "playbook_name": playbook["name"],
        "description": playbook["description"],
        "trigger_type": attack_type,
        "triggered_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall_status": "completed" if all_success else "partial_failure",
        "steps_executed": len(executed_steps),
        "steps_succeeded": sum(1 for s in executed_steps if s["status"] == "completed"),
        "steps_failed": sum(1 for s in executed_steps if s["status"] == "failed"),
        "total_duration_ms": sum(s["duration_ms"] for s in executed_steps),
        "steps": executed_steps,
        "rollback_available": playbook["rollback_available"],
        "target_event": event.get("id") if event else None
    }


def correct_configuration(vulnerability_id: str) -> Dict:
    """
    Apply automated configuration correction for a CSPM finding.
    Returns the before/after config diff and remediation details.
    """
    correction = CONFIG_CORRECTIONS.get(vulnerability_id)
    
    if not correction:
        return {
            "fix_id": f"FIX-UNKNOWN-{str(uuid.uuid4())[:6]}",
            "vulnerability_id": vulnerability_id,
            "status": "no_fix_available",
            "message": f"No automated fix available for {vulnerability_id}. Manual remediation required."
        }
    
    # Simulate ~90% success rate
    success = random.random() < 0.90
    
    return {
        "fix_id": correction["fix_id"],
        "vulnerability_id": vulnerability_id,
        "action": correction["action"],
        "description": correction["description"],
        "status": "applied" if success else "failed",
        "applied_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config_before": correction["config_before"],
        "config_after": correction["config_after"],
        "terraform_snippet": correction["terraform_snippet"],
        "risk_removed": correction["risk_removed"],
        "verification": "passed" if success else "pending_manual_review"
    }


def revoke_entity_access(entity_name: str, entity_type: str, risk_level: str) -> Dict:
    """
    Revoke or restrict access for a risky IAM entity identified by CIEM.
    Actions vary based on entity type and risk level.
    """
    revocation_id = f"REV-{str(uuid.uuid4())[:8].upper()}"
    now = datetime.now(timezone.utc)
    
    # Determine actions based on entity type and risk
    actions_taken = []
    
    if risk_level in ["critical", "high"]:
        if entity_type == "human":
            actions_taken = [
                {"action": "disable_console_access", "status": "completed", "description": f"Disabled AWS Console access for user '{entity_name}'"},
                {"action": "deactivate_access_keys", "status": "completed", "description": f"Deactivated all access keys for '{entity_name}'"},
                {"action": "revoke_active_sessions", "status": "completed", "description": f"Revoked all active sessions via inline deny policy"},
                {"action": "remove_inline_policies", "status": "completed", "description": f"Removed all inline policies from '{entity_name}'"},
                {"action": "notify_manager", "status": "completed", "description": f"Sent notification to {entity_name}'s manager for review"},
            ]
        elif entity_type == "machine":
            actions_taken = [
                {"action": "detach_all_policies", "status": "completed", "description": f"Detached all managed policies from service account '{entity_name}'"},
                {"action": "apply_deny_all", "status": "completed", "description": f"Applied explicit Deny-All inline policy"},
                {"action": "rotate_credentials", "status": "completed", "description": f"Rotated all credentials and secrets for '{entity_name}'"},
                {"action": "quarantine", "status": "completed", "description": f"Moved to quarantine organizational unit"},
            ]
        elif entity_type == "role":
            actions_taken = [
                {"action": "update_trust_policy", "status": "completed", "description": f"Updated trust policy to deny all assume-role requests"},
                {"action": "remove_permissions", "status": "completed", "description": f"Removed all permission boundaries from role '{entity_name}'"},
                {"action": "tag_for_review", "status": "completed", "description": f"Tagged role with 'security-review-required'"},
            ]
    else:
        # Medium/Low risk — restrict rather than revoke
        actions_taken = [
            {"action": "apply_permission_boundary", "status": "completed", "description": f"Applied restrictive permission boundary to '{entity_name}'"},
            {"action": "enable_monitoring", "status": "completed", "description": f"Enabled enhanced CloudTrail monitoring for '{entity_name}'"},
            {"action": "schedule_review", "status": "completed", "description": f"Scheduled access review within 7 days"},
        ]
    
    # Simulate occasional failures
    if random.random() < 0.05:
        actions_taken[-1]["status"] = "failed"
    
    return {
        "revocation_id": revocation_id,
        "entity_name": entity_name,
        "entity_type": entity_type,
        "risk_level": risk_level,
        "executed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actions_taken": actions_taken,
        "total_actions": len(actions_taken),
        "successful_actions": sum(1 for a in actions_taken if a["status"] == "completed"),
        "overall_status": "completed" if all(a["status"] == "completed" for a in actions_taken) else "partial_failure",
        "restore_instructions": f"To restore access for '{entity_name}', submit a re-enablement request through the IAM governance portal."
    }


def get_all_playbooks() -> List[Dict]:
    """Return all available remediation playbooks with their metadata."""
    result = []
    for attack_type, pb in PLAYBOOKS.items():
        result.append({
            "attack_type": attack_type,
            "playbook_id": pb["playbook_id"],
            "name": pb["name"],
            "description": pb["description"],
            "severity_trigger": pb["severity_trigger"],
            "num_steps": len(pb["steps"]),
            "estimated_time_seconds": pb["estimated_time_seconds"],
            "rollback_available": pb["rollback_available"],
            "steps_preview": [s["description"] for s in pb["steps"]]
        })
    return result


def auto_remediate_threats(analyzed_events: List[Dict]) -> Dict:
    """
    Given ML-analyzed events, automatically trigger remediation playbooks
    for events classified as anomalies with high/critical severity.
    Returns a summary of all remediation actions taken.
    """
    remediation_results = []
    skipped = 0
    
    for event in analyzed_events:
        if event.get("is_anomaly") and event.get("ml_severity") in ["Critical", "High"]:
            attack_type = event.get("attack_type", "misconfiguration")
            if attack_type and attack_type in PLAYBOOKS:
                result = execute_playbook(attack_type, event)
                remediation_results.append(result)
            else:
                skipped += 1
        else:
            skipped += 1
    
    return {
        "total_events_analyzed": len(analyzed_events),
        "remediations_triggered": len(remediation_results),
        "events_skipped": skipped,
        "remediations": remediation_results,
        "summary": {
            "fully_completed": sum(1 for r in remediation_results if r["overall_status"] == "completed"),
            "partial_failures": sum(1 for r in remediation_results if r["overall_status"] == "partial_failure"),
        }
    }


if __name__ == "__main__":
    import json
    
    print("=== Available Playbooks ===")
    print(json.dumps(get_all_playbooks(), indent=2))
    
    print("\n=== Execute Brute Force Playbook ===")
    result = execute_playbook("brute_force", {"id": "TEST-001"})
    print(json.dumps(result, indent=2))
    
    print("\n=== Correct S3 Config ===")
    fix = correct_configuration("CSPM-S3-001")
    print(json.dumps(fix, indent=2))
    
    print("\n=== Revoke Entity Access ===")
    rev = revoke_entity_access("svc-data-sync", "machine", "critical")
    print(json.dumps(rev, indent=2))
