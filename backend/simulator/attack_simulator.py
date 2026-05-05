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

INTENSITY_PROFILES = {
    "low": {"scale": 0.7, "byte_scale": 0.6, "extra_steps": 0},
    "medium": {"scale": 1.0, "byte_scale": 1.0, "extra_steps": 1},
    "high": {"scale": 1.4, "byte_scale": 1.35, "extra_steps": 2},
    "extreme": {"scale": 2.0, "byte_scale": 1.9, "extra_steps": 3},
}

SCENARIO_METADATA = {
    "brute_force": {
        "title": "Brute Force",
        "description": "Multiple failed login attempts followed by a successful breach.",
        "icon": "hammer",
        "supports_intensity": True,
        "default_intensity": "high",
    },
    "privilege_escalation": {
        "title": "Privilege Escalation",
        "description": "A user escalates privileges through IAM policy manipulation.",
        "icon": "arrow-up",
        "supports_intensity": True,
        "default_intensity": "high",
    },
    "data_exfiltration": {
        "title": "Data Exfiltration",
        "description": "Large outbound transfers to an external destination.",
        "icon": "upload",
        "supports_intensity": True,
        "default_intensity": "high",
    },
    "abnormal_access": {
        "title": "Abnormal Access",
        "description": "Unusual geo-location access followed by suspicious cloud activity.",
        "icon": "globe",
        "supports_intensity": True,
        "default_intensity": "high",
    },
}

def _profile(intensity: str) -> Dict:
    return INTENSITY_PROFILES.get(intensity, INTENSITY_PROFILES["high"])

def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _simulation_meta(prefix: str) -> Dict:
    return {
        "simulation_id": f"{prefix}-{str(uuid.uuid4())[:8].upper()}",
        "generated_at": _timestamp(),
    }

def simulate_brute_force(intensity: str = "high") -> Dict:
    """Simulate a brute force login attack with configurable intensity."""
    profile = _profile(intensity)
    events = []
    src_ip = f"103.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    target_user = random.choice(["admin", "root", "svc-account-01"])
    attempt_count = max(8, int(round(random.randint(10, 18) * profile["scale"])))
    for i in range(attempt_count):
        events.append({
            "id": f"SIM-BF-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([5710, 5712, 40111]),
            "level": random.randint(8, 14), "severity": "critical" if i > attempt_count // 2 else "high",
            "event_type": "attack", "attack_type": "brute_force",
            "user": target_user, "src_ip": src_ip, "dst_ip": "10.0.0.5",
            "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
            "status": "failure", "bytes_transferred": 0,
            "failed_attempts": random.randint(max(5, attempt_count // 2), attempt_count * 8),
            "description": f"Brute force attempt #{i+1} from {src_ip}",
        })
    # Final successful login after failures
    events.append({
        "id": f"SIM-BF-SUCCESS-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
        "source": "wazuh", "rule_id": 5715, "level": 14, "severity": "critical",
        "event_type": "attack", "attack_type": "brute_force",
        "user": target_user, "src_ip": src_ip, "dst_ip": "10.0.0.5",
        "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
        "status": "success", "bytes_transferred": 0, "failed_attempts": len(events),
        "description": f"SUCCESSFUL LOGIN after {len(events)} failed attempts from {src_ip}",
    })
    return {
        **_simulation_meta("SIM-BF"),
        "scenario": "brute_force", "intensity": intensity, "target_user": target_user,
        "source_ip": src_ip, "total_events": len(events), "events": events,
        "expected_detection": True, "description": f"Brute force attack: {len(events)-1} failed + 1 successful login"
    }

def simulate_privilege_escalation(intensity: str = "high") -> Dict:
    """Simulate privilege escalation via policy attachment chain."""
    profile = _profile(intensity)
    user = random.choice(["bob", "eve", "svc-account-01"])
    events = [
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5402, "level": 10, "severity": "high",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "iam", "region": "us-east-1",
         "action": "CreatePolicy", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} created a new IAM policy with AdministratorAccess"},
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5403, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "iam", "region": "us-east-1",
         "action": "AttachUserPolicy", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} attached AdministratorAccess to self"},
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 8502, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "sts", "region": "us-east-1",
         "action": "AssumeRole", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} assumed production admin role"},
    ]
    extra_actions = [
        ("iam", "CreateAccessKey", 11, "Created a new access key after elevation"),
        ("cloudtrail", "StopLogging", 13, "Attempted to disable audit logging"),
        ("kms", "ScheduleKeyDeletion", 12, "Scheduled a sensitive KMS key for deletion"),
    ]
    for idx in range(random.randint(0, profile["extra_steps"])):
        service, action, level, desc = extra_actions[idx]
        events.append({
            "id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([5403, 8502, 8504]), "level": level, "severity": "critical",
            "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
            "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": service, "region": "us-east-1",
            "action": action, "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
            "description": f"{user} {desc.lower()}",
        })
    return {
        **_simulation_meta("SIM-PE"),
        "scenario": "privilege_escalation", "intensity": intensity, "target_user": user, "total_events": len(events),
        "events": events, "expected_detection": True,
        "description": f"Privilege escalation: {user} created policy → attached admin → assumed prod role"
    }

def simulate_data_exfiltration(intensity: str = "high") -> Dict:
    """Simulate large-scale data exfiltration via S3."""
    profile = _profile(intensity)
    user = random.choice(["charlie", "eve", "malicious-insider"])
    dst_ip = f"198.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    events = []
    total_bytes = 0
    chunk_count = max(3, int(round(random.randint(3, 5) * profile["scale"])))
    for i in range(chunk_count):
        chunk = int(random.randint(500_000_000, 2_000_000_000) * profile["byte_scale"])
        total_bytes += chunk
        events.append({
            "id": f"SIM-DE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([31100, 31101]), "level": random.randint(11, 15),
            "severity": "critical", "event_type": "attack", "attack_type": "data_exfiltration",
            "user": user, "src_ip": "10.0.0.20", "dst_ip": dst_ip, "service": "s3",
            "region": "us-east-1", "action": "GetObject", "status": "success",
            "bytes_transferred": chunk, "failed_attempts": 0,
            "description": f"Large data transfer #{i+1}: {chunk/1e9:.1f} GB to external IP {dst_ip}",
        })
    return {
        **_simulation_meta("SIM-DE"),
        "scenario": "data_exfiltration", "intensity": intensity, "target_user": user, "destination_ip": dst_ip,
        "total_bytes_exfiltrated": total_bytes, "total_events": len(events), "events": events,
        "expected_detection": True,
        "description": f"Data exfiltration: {total_bytes/1e9:.1f} GB transferred to {dst_ip}"
    }

def simulate_abnormal_access(intensity: str = "high") -> Dict:
    """Simulate abnormal access patterns — unusual hours, geo-impossible travel."""
    profile = _profile(intensity)
    user = random.choice(["alice", "bob", "dave"])
    events = [
        {"id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5500, "level": 8, "severity": "high",
         "event_type": "attack", "attack_type": "lateral_movement", "user": user,
         "src_ip": "185.220.101.50", "dst_ip": "10.0.0.5", "service": "iam", "region": "eu-west-1",
         "action": "ConsoleLogin", "status": "success", "bytes_transferred": 0, "failed_attempts": 2,
         "description": f"Login from unusual location (EU) for US-based user {user}"},
        {"id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5510, "level": 9, "severity": "high",
         "event_type": "attack", "attack_type": "lateral_movement", "user": user,
         "src_ip": "185.220.101.50", "dst_ip": "10.0.0.10", "service": "secretsmanager", "region": "eu-west-1",
         "action": "GetSecretValue", "status": "success", "bytes_transferred": 5000, "failed_attempts": 0,
         "description": f"{user} accessed secrets from anomalous IP"},
    ]
    extra_steps = [
        ("sts", "AssumeRole", 10, "assumed an unfamiliar role from the anomalous session"),
        ("kms", "Decrypt", 11, "attempted decryption activity from the anomalous session"),
        ("iam", "ListUsers", 9, "enumerated IAM users from the anomalous session"),
    ]
    for idx in range(random.randint(0, profile["extra_steps"])):
        service, action, level, desc = extra_steps[idx]
        events.append({
            "id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([5510, 5511, 18100]), "level": level, "severity": "high",
            "event_type": "attack", "attack_type": "lateral_movement", "user": user,
            "src_ip": "185.220.101.50", "dst_ip": f"10.0.0.{random.randint(6, 25)}", "service": service, "region": "eu-west-1",
            "action": action, "status": "success", "bytes_transferred": random.randint(0, 12000), "failed_attempts": 0,
            "description": f"{user} {desc}",
        })
    return {
        **_simulation_meta("SIM-AA"),
        "scenario": "abnormal_access", "intensity": intensity, "target_user": user, "total_events": len(events),
        "events": events, "expected_detection": True,
        "description": f"Abnormal access: {user} logged in from unusual geo-location and accessed secrets"
    }

SCENARIOS = {
    "brute_force": simulate_brute_force,
    "privilege_escalation": simulate_privilege_escalation,
    "data_exfiltration": simulate_data_exfiltration,
    "abnormal_access": simulate_abnormal_access,
}

def get_scenario_catalog() -> List[Dict]:
    """Return scenario metadata for frontend rendering."""
    catalog = []
    for scenario_id in SCENARIOS:
        meta = SCENARIO_METADATA.get(scenario_id, {})
        catalog.append({
            "id": scenario_id,
            "title": meta.get("title", scenario_id.replace("_", " ").title()),
            "description": meta.get("description", "Attack simulation"),
            "icon": meta.get("icon", "zap"),
            "supports_intensity": meta.get("supports_intensity", False),
            "default_intensity": meta.get("default_intensity"),
        })
    return catalog

def run_attack_simulation(scenario: str = "brute_force", intensity: str = "high") -> Dict:
    """Run a specific attack simulation scenario."""
    fn = SCENARIOS.get(scenario, simulate_brute_force)
    return fn(intensity=intensity)

def run_full_simulation(intensity: str = "high") -> Dict:
    """Run all attack scenarios and return combined results."""
    results = []
    for name, fn in SCENARIOS.items():
        results.append(fn(intensity=intensity))
    total_events = sum(r["total_events"] for r in results)
    return {
        "simulation_id": f"FULLSIM-{str(uuid.uuid4())[:8].upper()}",
        "timestamp": _timestamp(),
        "intensity": intensity,
        "scenarios_run": len(results), "total_events_generated": total_events,
        "scenarios": results
    }
