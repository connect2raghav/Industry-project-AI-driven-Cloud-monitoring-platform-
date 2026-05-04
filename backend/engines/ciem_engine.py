"""
Cloud Infrastructure Entitlement Management (CIEM) Engine
Derives real IAM risks by analysing Wazuh log events.

Logic:
  - Reads parsed Wazuh events
  - Identifies risky identities (users / service accounts / roles) that appear
    in attack-type events
  - Maps each identity + attack pattern to a specific IAM risk category
  - Every finding is backed by a real log event — no random selection
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict

# ── Risk catalogue ────────────────────────────────────────────────────────────
RISK_CATALOGUE = {
    "CIEM-001": {
        "title": "Over-privileged Identity",
        "description": "Identity performed actions far beyond its expected scope, "
                       "indicating excessive permissions (AdministratorAccess or wildcard policy).",
        "remediation": "Generate a least-privilege policy using IAM Access Analyzer. "
                       "Remove unused permissions.",
    },
    "CIEM-002": {
        "title": "Inactive High-Privilege Account",
        "description": "Identity has not performed normal activity but was observed in "
                       "an attack event, suggesting a dormant account was compromised.",
        "remediation": "Deactivate the account. Remove associated policies. "
                       "Rotate all credentials.",
    },
    "CIEM-003": {
        "title": "Cross-Account / Cross-Service Privilege Escalation",
        "description": "Identity used AssumeRole or policy attachment to gain higher "
                       "privileges than originally assigned.",
        "remediation": "Remove sts:AssumeRole for the target role. "
                       "Apply SCP guardrails at the organisation level.",
    },
    "CIEM-004": {
        "title": "Wildcard / Unrestricted Permissions",
        "description": "Identity executed actions matching a wildcard policy pattern "
                       "(Action:* or Resource:*), confirmed by log evidence.",
        "remediation": "Scope down to specific ARNs and actions. "
                       "Enable IAM Access Analyzer findings.",
    },
    "CIEM-005": {
        "title": "Compromised Service Account",
        "description": "A machine identity (service account) was observed in an attack "
                       "event, indicating credential theft or misconfiguration.",
        "remediation": "Rotate all credentials for the service account. "
                       "Apply a Deny-All inline policy until reviewed.",
    },
    "CIEM-006": {
        "title": "Brute-Force Targeted Account",
        "description": "This identity was the target of a brute-force or credential-stuffing "
                       "attack, indicating it is reachable and potentially weak.",
        "remediation": "Enforce MFA. Apply account lockout policy. "
                       "Reset password and rotate access keys.",
    },
}

# ── Attack type → risk ID + entity type ──────────────────────────────────────
ATTACK_RISK_MAP = {
    "privilege_escalation": ("CIEM-003", "human"),
    "lateral_movement":     ("CIEM-003", "role"),
    "data_exfiltration":    ("CIEM-001", "human"),
    "brute_force":          ("CIEM-006", "human"),
    "credential_stuffing":  ("CIEM-006", "human"),
    "crypto_mining":        ("CIEM-005", "machine"),
    "ransomware_precursor": ("CIEM-005", "machine"),
    "port_scan":            ("CIEM-004", "role"),
}

# Service accounts heuristic — if username contains these strings → machine
MACHINE_KEYWORDS = ("svc", "service", "bot", "daemon", "agent", "worker", "lambda", "func")

# Risk level derived from attack severity
SEVERITY_RISK_LEVEL = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
}


def _entity_type(username: str, default: str) -> str:
    lower = username.lower()
    if any(k in lower for k in MACHINE_KEYWORDS):
        return "machine"
    if lower in ("anonymous", "unknown", ""):
        return "role"
    return default


def run_ciem_scan(events: List[Dict] = None) -> List[Dict]:
    """
    Derive CIEM findings from Wazuh log events.

    Parameters
    ----------
    events : list of parsed Wazuh events.
             If None or empty returns an empty list.

    Returns
    -------
    List of unique CIEM findings keyed by (entity_name, risk_id).
    Each finding references the triggering event.
    """
    if not events:
        return []

    seen: Dict[str, Dict] = {}   # key = "entity_name::risk_id"

    for event in events:
        attack    = event.get("attack_type") or ""
        if not attack:
            continue

        risk_id, default_entity_type = ATTACK_RISK_MAP.get(attack, (None, "human"))
        if not risk_id:
            continue

        user      = event.get("user", "unknown")
        src_ip    = event.get("src_ip", "unknown")
        severity  = event.get("severity", "medium").lower()
        timestamp = event.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        entity_type = _entity_type(user, default_entity_type)

        key = f"{user}::{risk_id}"
        if key in seen:
            continue

        meta = RISK_CATALOGUE[risk_id]
        seen[key] = {
            "scan_id":     str(uuid.uuid4())[:8],
            "risk_id":     risk_id,
            "title":       meta["title"],
            "entity_name": user,
            "entity_type": entity_type,
            "risk_level":  SEVERITY_RISK_LEVEL.get(severity, "medium"),
            "description": meta["description"],
            "remediation": meta["remediation"],
            "detected_at": timestamp,
            "triggered_by": {
                "attack_type": attack,
                "src_ip":      src_ip,
                "event_id":    event.get("id", ""),
            },
        }

    return list(seen.values())


if __name__ == "__main__":
    import json, sys, os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from simulator.wazuh_simulator import simulate_session
    events = simulate_session(n_normal=80, n_attacks=20)
    print(json.dumps(run_ciem_scan(events), indent=2))
