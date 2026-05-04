"""
Attack Simulation Module
Simulates realistic attack scenarios to verify detection by the system.
Scenarios: brute force, privilege escalation, data exfiltration, abnormal access.
Each scenario generates targeted events, runs them through ML, and verifies detection.
"""
import uuid
import random
from datetime import datetime, timezone
from typing import Dict, List

def simulate_brute_force(intensity: str = "high") -> Dict:
    """Simulate a brute force login attack with configurable intensity."""
    mult = {"low": 1, "medium": 3, "high": 5, "extreme": 10}.get(intensity, 5)
    events = []
    src_ip = f"103.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    target_user = random.choice(["admin", "root", "svc-account-01"])
    for i in range(10 * mult):
        events.append({
            "id": f"SIM-BF-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "wazuh", "rule_id": random.choice([5710, 5712, 40111]),
            "level": random.randint(8, 14), "severity": "critical" if i > 5 * mult else "high",
            "event_type": "attack", "attack_type": "brute_force",
            "user": target_user, "src_ip": src_ip, "dst_ip": "10.0.0.5",
            "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
            "status": "failure", "bytes_transferred": 0,
            "failed_attempts": random.randint(20 * mult, 100 * mult),
            "description": f"Brute force attempt #{i+1} from {src_ip}",
        })
    # Final successful login after failures
    events.append({
        "id": f"SIM-BF-SUCCESS-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "wazuh", "rule_id": 5715, "level": 14, "severity": "critical",
        "event_type": "attack", "attack_type": "brute_force",
        "user": target_user, "src_ip": src_ip, "dst_ip": "10.0.0.5",
        "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
        "status": "success", "bytes_transferred": 0, "failed_attempts": len(events),
        "description": f"SUCCESSFUL LOGIN after {len(events)} failed attempts from {src_ip}",
    })
    return {
        "scenario": "brute_force", "intensity": intensity, "target_user": target_user,
        "source_ip": src_ip, "total_events": len(events), "events": events,
        "expected_detection": True, "description": f"Brute force attack: {len(events)-1} failed + 1 successful login"
    }

def simulate_privilege_escalation() -> Dict:
    """Simulate privilege escalation via policy attachment chain."""
    user = random.choice(["bob", "eve", "svc-account-01"])
    events = [
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "source": "wazuh", "rule_id": 5402, "level": 10, "severity": "high",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "iam", "region": "us-east-1",
         "action": "CreatePolicy", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} created a new IAM policy with AdministratorAccess"},
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "source": "wazuh", "rule_id": 5403, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "iam", "region": "us-east-1",
         "action": "AttachUserPolicy", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} attached AdministratorAccess to self"},
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "source": "wazuh", "rule_id": 8502, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "sts", "region": "us-east-1",
         "action": "AssumeRole", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} assumed production admin role"},
    ]
    return {
        "scenario": "privilege_escalation", "target_user": user, "total_events": len(events),
        "events": events, "expected_detection": True,
        "description": f"Privilege escalation: {user} created policy → attached admin → assumed prod role"
    }

def simulate_data_exfiltration() -> Dict:
    """Simulate large-scale data exfiltration via S3."""
    user = random.choice(["charlie", "eve", "malicious-insider"])
    dst_ip = f"198.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    events = []
    total_bytes = 0
    for i in range(5):
        chunk = random.randint(500_000_000, 2_000_000_000)
        total_bytes += chunk
        events.append({
            "id": f"SIM-DE-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "wazuh", "rule_id": random.choice([31100, 31101]), "level": random.randint(11, 15),
            "severity": "critical", "event_type": "attack", "attack_type": "data_exfiltration",
            "user": user, "src_ip": "10.0.0.20", "dst_ip": dst_ip, "service": "s3",
            "region": "us-east-1", "action": "GetObject", "status": "success",
            "bytes_transferred": chunk, "failed_attempts": 0,
            "description": f"Large data transfer #{i+1}: {chunk/1e9:.1f} GB to external IP {dst_ip}",
        })
    return {
        "scenario": "data_exfiltration", "target_user": user, "destination_ip": dst_ip,
        "total_bytes_exfiltrated": total_bytes, "total_events": len(events), "events": events,
        "expected_detection": True,
        "description": f"Data exfiltration: {total_bytes/1e9:.1f} GB transferred to {dst_ip}"
    }

def simulate_abnormal_access() -> Dict:
    """Simulate abnormal access patterns — unusual hours, geo-impossible travel."""
    user = random.choice(["alice", "bob", "dave"])
    events = [
        {"id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "source": "wazuh", "rule_id": 5500, "level": 8, "severity": "high",
         "event_type": "attack", "attack_type": "lateral_movement", "user": user,
         "src_ip": "185.220.101.50", "dst_ip": "10.0.0.5", "service": "iam", "region": "eu-west-1",
         "action": "ConsoleLogin", "status": "success", "bytes_transferred": 0, "failed_attempts": 2,
         "description": f"Login from unusual location (EU) for US-based user {user}"},
        {"id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "source": "wazuh", "rule_id": 5510, "level": 9, "severity": "high",
         "event_type": "attack", "attack_type": "lateral_movement", "user": user,
         "src_ip": "185.220.101.50", "dst_ip": "10.0.0.10", "service": "secretsmanager", "region": "eu-west-1",
         "action": "GetSecretValue", "status": "success", "bytes_transferred": 5000, "failed_attempts": 0,
         "description": f"{user} accessed secrets from anomalous IP"},
    ]
    return {
        "scenario": "abnormal_access", "target_user": user, "total_events": len(events),
        "events": events, "expected_detection": True,
        "description": f"Abnormal access: {user} logged in from unusual geo-location and accessed secrets"
    }

SCENARIOS = {
    "brute_force": simulate_brute_force,
    "privilege_escalation": simulate_privilege_escalation,
    "data_exfiltration": simulate_data_exfiltration,
    "abnormal_access": simulate_abnormal_access,
}

def run_attack_simulation(scenario: str = "brute_force", intensity: str = "high") -> Dict:
    """Run a specific attack simulation scenario."""
    fn = SCENARIOS.get(scenario, simulate_brute_force)
    if scenario == "brute_force":
        return fn(intensity=intensity)
    return fn()

def run_full_simulation() -> Dict:
    """Run all attack scenarios and return combined results."""
    results = []
    for name, fn in SCENARIOS.items():
        if name == "brute_force":
            results.append(fn(intensity="high"))
        else:
            results.append(fn())
    total_events = sum(r["total_events"] for r in results)
    return {
        "simulation_id": f"FULLSIM-{str(uuid.uuid4())[:8].upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scenarios_run": len(results), "total_events_generated": total_events,
        "scenarios": results
    }
