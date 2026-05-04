"""
Wazuh-style Attack Log Simulator
Generates realistic cloud security events including:
- Normal login/API activity
- Brute force attacks
- Privilege escalation
- Data exfiltration
- Misconfiguration events
- IAM anomalies
"""

import random
import json
import datetime
import uuid
from typing import List, Dict

# ── Config ─────────────────────────────────────────────────────────────────
USERS = ["alice", "bob", "charlie", "dave", "eve", "frank", "svc-account-01", "svc-backup", "admin"]
IPS = {
    "internal": ["10.0.0.{0}".format(i) for i in range(1, 50)],
    "external": ["185.220.101.{0}".format(i) for i in range(1, 30)]
    + ["192.42.116.{0}".format(i) for i in range(1, 20)]
    + ["198.96.155.{0}".format(i) for i in range(1, 10)],
}
SERVICES = ["s3", "ec2", "iam", "rds", "lambda", "cloudtrail", "kms", "sts", "secretsmanager"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
ATTACK_TYPES = [
    "brute_force", "privilege_escalation", "data_exfiltration",
    "lateral_movement", "credential_stuffing", "port_scan",
    "ransomware_precursor", "crypto_mining"
]

WAZUH_RULE_IDS = {
    "normal": [1001, 1002, 1003, 5500, 5501, 5715],
    "brute_force": [5710, 5712, 40111, 40112],
    "privilege_escalation": [5402, 5403, 8502, 8504],
    "data_exfiltration": [31100, 31101, 31102],
    "lateral_movement": [5510, 5511, 18100],
    "port_scan": [40101, 40102, 40103],
    "crypto_mining": [87100, 87101],
    "ransomware_precursor": [60100, 60101],
}


def _ts(minutes_ago: int = 0) -> str:
    t = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity(level: int) -> str:
    if level <= 3:
        return "low"
    if level <= 7:
        return "medium"
    if level <= 11:
        return "high"
    return "critical"


def generate_normal_event(minutes_ago: int = 0) -> Dict:
    user = random.choice(USERS[:-2])  # avoid admin in normals
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _ts(minutes_ago),
        "source": "wazuh",
        "rule_id": random.choice(WAZUH_RULE_IDS["normal"]),
        "level": random.randint(1, 3),
        "severity": "low",
        "event_type": "normal",
        "attack_type": None,
        "user": user,
        "src_ip": random.choice(IPS["internal"]),
        "dst_ip": random.choice(IPS["internal"]),
        "service": random.choice(SERVICES),
        "region": random.choice(REGIONS),
        "action": random.choice(["GetObject", "ListBuckets", "DescribeInstances", "GetSecretValue"]),
        "status": "success",
        "bytes_transferred": random.randint(100, 5000),
        "failed_attempts": 0,
        "description": "Normal cloud API activity",
        "anomaly_score": round(random.uniform(0.0, 0.3), 4),
    }


def generate_attack_event(attack_type: str, minutes_ago: int = 0) -> Dict:
    if attack_type == "brute_force":
        return {
            "id": str(uuid.uuid4()),
            "timestamp": _ts(minutes_ago),
            "source": "wazuh",
            "rule_id": random.choice(WAZUH_RULE_IDS["brute_force"]),
            "level": random.randint(8, 12),
            "severity": _severity(random.randint(8, 12)),
            "event_type": "attack",
            "attack_type": "brute_force",
            "user": random.choice(USERS),
            "src_ip": random.choice(IPS["external"]),
            "dst_ip": random.choice(IPS["internal"]),
            "service": "iam",
            "region": random.choice(REGIONS),
            "action": "ConsoleLogin",
            "status": "failure",
            "bytes_transferred": 0,
            "failed_attempts": random.randint(10, 200),
            "description": "Multiple failed login attempts detected — possible brute force",
            "anomaly_score": round(random.uniform(0.7, 1.0), 4),
        }
    elif attack_type == "privilege_escalation":
        return {
            "id": str(uuid.uuid4()),
            "timestamp": _ts(minutes_ago),
            "source": "wazuh",
            "rule_id": random.choice(WAZUH_RULE_IDS["privilege_escalation"]),
            "level": random.randint(9, 14),
            "severity": _severity(random.randint(9, 14)),
            "event_type": "attack",
            "attack_type": "privilege_escalation",
            "user": random.choice(["svc-account-01", "bob", "eve"]),
            "src_ip": random.choice(IPS["internal"]),
            "dst_ip": random.choice(IPS["internal"]),
            "service": "iam",
            "region": random.choice(REGIONS),
            "action": "AttachUserPolicy",
            "status": "success",
            "bytes_transferred": 0,
            "failed_attempts": 0,
            "description": "User attached AdministratorAccess policy to themselves",
            "anomaly_score": round(random.uniform(0.8, 1.0), 4),
        }
    elif attack_type == "data_exfiltration":
        return {
            "id": str(uuid.uuid4()),
            "timestamp": _ts(minutes_ago),
            "source": "wazuh",
            "rule_id": random.choice(WAZUH_RULE_IDS["data_exfiltration"]),
            "level": random.randint(10, 15),
            "severity": _severity(random.randint(10, 15)),
            "event_type": "attack",
            "attack_type": "data_exfiltration",
            "user": random.choice(USERS),
            "src_ip": random.choice(IPS["internal"]),
            "dst_ip": random.choice(IPS["external"]),
            "service": "s3",
            "region": random.choice(REGIONS),
            "action": "GetObject",
            "status": "success",
            "bytes_transferred": random.randint(500_000_000, 5_000_000_000),
            "failed_attempts": 0,
            "description": "Large volume data transfer to external IP — possible exfiltration",
            "anomaly_score": round(random.uniform(0.85, 1.0), 4),
        }
    elif attack_type == "lateral_movement":
        return {
            "id": str(uuid.uuid4()),
            "timestamp": _ts(minutes_ago),
            "source": "wazuh",
            "rule_id": random.choice(WAZUH_RULE_IDS["lateral_movement"]),
            "level": random.randint(7, 11),
            "severity": _severity(random.randint(7, 11)),
            "event_type": "attack",
            "attack_type": "lateral_movement",
            "user": random.choice(USERS),
            "src_ip": random.choice(IPS["internal"]),
            "dst_ip": random.choice(IPS["internal"]),
            "service": random.choice(["ec2", "lambda", "sts"]),
            "region": random.choice(REGIONS),
            "action": "AssumeRole",
            "status": "success",
            "bytes_transferred": random.randint(0, 1000),
            "failed_attempts": 0,
            "description": "Unusual AssumeRole chain — possible lateral movement",
            "anomaly_score": round(random.uniform(0.6, 0.9), 4),
        }
    elif attack_type == "port_scan":
        return {
            "id": str(uuid.uuid4()),
            "timestamp": _ts(minutes_ago),
            "source": "wazuh",
            "rule_id": random.choice(WAZUH_RULE_IDS["port_scan"]),
            "level": random.randint(6, 9),
            "severity": _severity(random.randint(6, 9)),
            "event_type": "attack",
            "attack_type": "port_scan",
            "user": "anonymous",
            "src_ip": random.choice(IPS["external"]),
            "dst_ip": random.choice(IPS["internal"]),
            "service": "ec2",
            "region": random.choice(REGIONS),
            "action": "NetworkScan",
            "status": "blocked",
            "bytes_transferred": 0,
            "failed_attempts": random.randint(50, 1000),
            "description": "Port scan detected from external IP",
            "anomaly_score": round(random.uniform(0.6, 0.85), 4),
        }
    else:
        # generic attack
        return {
            "id": str(uuid.uuid4()),
            "timestamp": _ts(minutes_ago),
            "source": "wazuh",
            "rule_id": random.choice(WAZUH_RULE_IDS.get(attack_type, [99999])),
            "level": random.randint(8, 15),
            "severity": _severity(random.randint(8, 15)),
            "event_type": "attack",
            "attack_type": attack_type,
            "user": random.choice(USERS),
            "src_ip": random.choice(IPS["external"]),
            "dst_ip": random.choice(IPS["internal"]),
            "service": random.choice(SERVICES),
            "region": random.choice(REGIONS),
            "action": "SuspiciousAPICall",
            "status": "detected",
            "bytes_transferred": random.randint(0, 100_000),
            "failed_attempts": random.randint(0, 50),
            "description": f"Suspicious activity: {attack_type.replace('_', ' ')}",
            "anomaly_score": round(random.uniform(0.7, 1.0), 4),
        }


def simulate_session(
    n_normal: int = 80,
    n_attacks: int = 20,
    time_window_hours: int = 24
) -> List[Dict]:
    """Generate a mixed session of normal + attack events."""
    events = []
    total_minutes = time_window_hours * 60

    # Normal events
    for _ in range(n_normal):
        events.append(generate_normal_event(random.randint(0, total_minutes)))

    # Attack events
    chosen_attacks = random.choices(ATTACK_TYPES, k=n_attacks)
    for at in chosen_attacks:
        events.append(generate_attack_event(at, random.randint(0, total_minutes)))

    # Sort by timestamp desc
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events


if __name__ == "__main__":
    events = simulate_session(n_normal=100, n_attacks=25)
    print(json.dumps(events[:5], indent=2))
    print(f"\nTotal events: {len(events)}")
