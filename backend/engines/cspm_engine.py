"""
Cloud Security Posture Management (CSPM) Engine
Derives real misconfigurations by analysing Wazuh log events.
If no Wazuh logs are available it falls back to the LocalStack boto3 scan.

Logic:
  - Reads parsed Wazuh events (already enriched by wazuh_reader / wazuh_simulator)
  - Maps specific rule IDs and attack patterns to known cloud misconfigurations
  - Every finding returned is backed by at least one real log event
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict

# ── Vulnerability catalogue (static metadata only, no random selection) ───────
VULN_CATALOGUE = {
    "CSPM-S3-001": {
        "title": "S3 Bucket Publicly Accessible",
        "description": "Wazuh detected a large-volume data transfer to an external IP, "
                       "indicating a publicly accessible S3 bucket was exploited.",
        "severity": "critical",
        "resource": "arn:aws:s3:::detected-via-log",
        "remediation": "Enable S3 Block Public Access on all buckets. "
                       "Review bucket policies and ACLs.",
    },
    "CSPM-EC2-002": {
        "title": "RDP/SSH Port Open to Internet",
        "description": "Wazuh detected a brute-force or port-scan attack against a "
                       "login service, indicating an internet-exposed management port.",
        "severity": "high",
        "resource": "security-group:detected-via-log",
        "remediation": "Remove 0.0.0.0/0 from inbound rules on ports 22 and 3389. "
                       "Restrict to corporate CIDR only.",
    },
    "CSPM-IAM-003": {
        "title": "Root / Admin Account Missing MFA",
        "description": "Wazuh detected a successful login after multiple failures on an "
                       "admin account, suggesting MFA is not enforced.",
        "severity": "critical",
        "resource": "iam:root-or-admin-account",
        "remediation": "Enable MFA on all privileged accounts immediately.",
    },
    "CSPM-PRIV-004": {
        "title": "Privilege Escalation Path Detected",
        "description": "Wazuh logged an IAM policy attachment or AssumeRole chain that "
                       "grants elevated privileges to a non-admin identity.",
        "severity": "high",
        "resource": "iam:policy-attachment-detected",
        "remediation": "Revert IAM policy changes. Apply least-privilege and enable "
                       "CloudTrail alerts on AttachUserPolicy / AssumeRole.",
    },
    "CSPM-LATERAL-005": {
        "title": "Lateral Movement via AssumeRole",
        "description": "Wazuh detected an unusual AssumeRole chain across accounts or "
                       "services, indicating lateral movement.",
        "severity": "high",
        "resource": "iam:assumerole-chain-detected",
        "remediation": "Restrict sts:AssumeRole in trust policies. "
                       "Enable SCP guardrails at the AWS Organization level.",
    },
    "CSPM-CRYPTO-006": {
        "title": "Compute Resource Hijacked for Crypto Mining",
        "description": "Wazuh detected crypto-mining process signatures on a compute "
                       "resource, indicating a compromised or misconfigured instance.",
        "severity": "critical",
        "resource": "ec2:instance-detected-via-log",
        "remediation": "Terminate the instance, rotate all credentials, and enable "
                       "GuardDuty CryptoCurrency findings.",
    },
    "CSPM-RANSOM-007": {
        "title": "Ransomware Precursor Activity",
        "description": "Wazuh detected early-stage ransomware behaviour: mass file "
                       "enumeration or shadow-copy deletion patterns.",
        "severity": "critical",
        "resource": "ec2:host-detected-via-log",
        "remediation": "Isolate the host immediately. Snapshot EBS volumes. "
                       "Block C2 IPs at the network perimeter.",
    },
    "CSPM-CRED-008": {
        "title": "Credential Stuffing Attack Surface",
        "description": "Wazuh detected a credential-stuffing pattern against a login "
                       "endpoint, indicating the endpoint is publicly reachable without "
                       "rate-limiting or CAPTCHA.",
        "severity": "high",
        "resource": "alb:login-endpoint-detected",
        "remediation": "Enable WAF rate-limiting rules. Add CAPTCHA. "
                       "Force password reset for targeted accounts.",
    },
}

# ── Rule-ID → vulnerability mapping ──────────────────────────────────────────
RULE_TO_VULN = {
    # Data exfiltration → public S3
    31100: "CSPM-S3-001", 31101: "CSPM-S3-001", 31102: "CSPM-S3-001",
    # Brute force / port scan → open port
    5710: "CSPM-EC2-002", 5712: "CSPM-EC2-002",
    40101: "CSPM-EC2-002", 40102: "CSPM-EC2-002", 40103: "CSPM-EC2-002",
    # Brute force success on admin → missing MFA
    5715: "CSPM-IAM-003",
    # Privilege escalation
    5402: "CSPM-PRIV-004", 5403: "CSPM-PRIV-004",
    8502: "CSPM-PRIV-004", 8504: "CSPM-PRIV-004",
    # Lateral movement
    5510: "CSPM-LATERAL-005", 5511: "CSPM-LATERAL-005", 18100: "CSPM-LATERAL-005",
    # Crypto mining
    87100: "CSPM-CRYPTO-006", 87101: "CSPM-CRYPTO-006",
    # Ransomware
    60100: "CSPM-RANSOM-007", 60101: "CSPM-RANSOM-007",
    # Credential stuffing
    5716: "CSPM-CRED-008", 5717: "CSPM-CRED-008",
}

# Attack-type string → vulnerability (fallback when rule_id not in map)
ATTACK_TO_VULN = {
    "data_exfiltration":    "CSPM-S3-001",
    "brute_force":          "CSPM-EC2-002",
    "privilege_escalation": "CSPM-PRIV-004",
    "lateral_movement":     "CSPM-LATERAL-005",
    "crypto_mining":        "CSPM-CRYPTO-006",
    "ransomware_precursor": "CSPM-RANSOM-007",
    "credential_stuffing":  "CSPM-CRED-008",
    "port_scan":            "CSPM-EC2-002",
}


def run_cspm_scan(events: List[Dict] = None) -> List[Dict]:
    """
    Derive CSPM findings from Wazuh log events.

    Parameters
    ----------
    events : list of parsed Wazuh events (already enriched dicts).
             If None or empty the function returns an empty list —
             the caller (main.py _get_cspm) is responsible for
             passing real or simulated events.

    Returns
    -------
    List of unique CSPM findings, one per vulnerability type detected.
    Each finding references the triggering event's timestamp and source IP.
    """
    if not events:
        return []

    seen_vulns: Dict[str, Dict] = {}   # vuln_id → finding (deduplicated)

    for event in events:
        rule_id   = int(event.get("rule_id", 0))
        attack    = event.get("attack_type") or ""
        src_ip    = event.get("src_ip", "unknown")
        user      = event.get("user", "unknown")
        timestamp = event.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

        # Resolve which vulnerability this event maps to
        vuln_id = RULE_TO_VULN.get(rule_id) or ATTACK_TO_VULN.get(attack)
        if not vuln_id:
            continue

        # First occurrence wins; subsequent events for the same vuln are ignored
        if vuln_id in seen_vulns:
            continue

        meta = VULN_CATALOGUE[vuln_id]
        seen_vulns[vuln_id] = {
            "scan_id":          str(uuid.uuid4())[:8],
            "vulnerability_id": vuln_id,
            "title":            meta["title"],
            "description":      meta["description"],
            "severity":         meta["severity"],
            "resource":         meta["resource"],
            "remediation":      meta["remediation"],
            "status":           "open",
            "detected_at":      timestamp,
            "triggered_by":     {
                "rule_id":  rule_id,
                "src_ip":   src_ip,
                "user":     user,
                "event_id": event.get("id", ""),
            },
        }

    return list(seen_vulns.values())


if __name__ == "__main__":
    import json, sys, os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from simulator.wazuh_simulator import simulate_session
    events = simulate_session(n_normal=80, n_attacks=20)
    print(json.dumps(run_cspm_scan(events), indent=2))
