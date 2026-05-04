"""
Live Wazuh Log Generator
========================
Simulates a real server being monitored by Wazuh.
Writes one batch of events every 60 seconds to data/alerts.json
in exact Wazuh JSON format — one alert per line.

The platform's wazuh_reader.py reads this file automatically.

Simulates realistic server behaviour:
  - Business hours (9am-6pm): mostly normal traffic, rare attacks
  - Night hours (10pm-6am):   more attack attempts
  - Random attack campaigns:  sustained attack bursts every ~15 minutes
  - Normal services:          SSH, HTTP, S3, IAM, RDS, EC2 API calls

Run in a separate terminal:
  cd backend
  python simulator/log_generator.py

Then set env var and start the backend:
  set WAZUH_LOG_PATH=data/alerts.json
  python main.py

The dashboard will show source: real and update every 60 seconds.
"""

import json
import os
import random
import time
import uuid
from datetime import datetime, timezone

# ── Output path ───────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH  = os.path.join(BASE_DIR, "data", "alerts.json")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# ── Server identity ───────────────────────────────────────────────────────────
AGENTS = [
    {"id": "001", "name": "web-server-01",   "ip": "10.0.0.10"},
    {"id": "002", "name": "db-server-01",    "ip": "10.0.0.20"},
    {"id": "003", "name": "app-server-01",   "ip": "10.0.0.30"},
    {"id": "004", "name": "bastion-host",    "ip": "10.0.0.5"},
    {"id": "005", "name": "worker-node-01",  "ip": "10.0.0.40"},
]

INTERNAL_IPS = [f"10.0.{i}.{j}" for i in range(0, 3) for j in range(1, 20)]
EXTERNAL_IPS = (
    [f"185.220.101.{i}" for i in range(1, 50)] +   # Tor exit nodes
    [f"103.21.{i}.{j}"  for i in range(1, 10) for j in range(1, 10)] +  # Asia
    [f"198.51.100.{i}"  for i in range(1, 30)] +   # Known bad IPs
    [f"91.108.{i}.{j}"  for i in range(1, 5)  for j in range(1, 10)]    # Eastern Europe
)

USERS = ["alice", "bob", "charlie", "dave", "eve", "frank",
         "svc-backup", "svc-data-sync", "svc-worker", "admin", "root"]

# ── Wazuh rule definitions ────────────────────────────────────────────────────
# Each rule: (rule_id, level, description, category)
RULES = {
    # ── Normal activity ───────────────────────────────────────────────────────
    "normal_ssh_login": {
        "rule": {"id": "5501", "level": 3,
                 "description": "SSH login success"},
        "category": "normal",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "dstuser": random.choice(USERS[:6]),
            "program_name": "sshd",
            "failed_attempts": "0",
        }
    },
    "normal_api_call": {
        "rule": {"id": "1002", "level": 2,
                 "description": "Normal cloud API activity"},
        "category": "normal",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(USERS[:6]),
            "program_name": random.choice(["s3", "ec2", "iam", "rds"]),
            "size": str(random.randint(100, 8000)),
            "failed_attempts": "0",
        }
    },
    "normal_web_request": {
        "rule": {"id": "31100", "level": 2,
                 "description": "Web server request"},
        "category": "normal",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(USERS[:6]),
            "program_name": "apache2",
            "size": str(random.randint(200, 5000)),
            "failed_attempts": "0",
        }
    },
    "normal_db_query": {
        "rule": {"id": "1003", "level": 2,
                 "description": "Database query executed"},
        "category": "normal",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(["svc-backup", "svc-data-sync", "alice"]),
            "program_name": "postgres",
            "size": str(random.randint(50, 2000)),
            "failed_attempts": "0",
        }
    },
    "normal_cron": {
        "rule": {"id": "5500", "level": 1,
                 "description": "Scheduled task executed"},
        "category": "normal",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": "svc-backup",
            "program_name": "cron",
            "size": "0",
            "failed_attempts": "0",
        }
    },

    # ── Brute force ───────────────────────────────────────────────────────────
    "brute_force_ssh": {
        "rule": {"id": "5710", "level": 8,
                 "description": "Multiple failed SSH login attempts — possible brute force"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(EXTERNAL_IPS),
            "dstuser": random.choice(["admin", "root", "ubuntu"]),
            "program_name": "sshd",
            "failed_attempts": str(random.randint(10, 80)),
            "size": "0",
        }
    },
    "brute_force_heavy": {
        "rule": {"id": "5712", "level": 12,
                 "description": "Brute force attack detected — high frequency"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(EXTERNAL_IPS),
            "dstuser": random.choice(["admin", "root"]),
            "program_name": "sshd",
            "failed_attempts": str(random.randint(100, 500)),
            "size": "0",
        }
    },

    # ── Privilege escalation ──────────────────────────────────────────────────
    "priv_esc_policy": {
        "rule": {"id": "5403", "level": 13,
                 "description": "User attached AdministratorAccess policy to self"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(["bob", "eve", "svc-worker"]),
            "dstuser": random.choice(["bob", "eve", "svc-worker"]),
            "program_name": "iam",
            "failed_attempts": "0",
            "size": "0",
        }
    },
    "priv_esc_sudo": {
        "rule": {"id": "5402", "level": 10,
                 "description": "Privilege escalation via sudo detected"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(["charlie", "dave"]),
            "program_name": "sudo",
            "failed_attempts": "0",
            "size": "0",
        }
    },

    # ── Data exfiltration ─────────────────────────────────────────────────────
    "data_exfil_s3": {
        "rule": {"id": "31101", "level": 14,
                 "description": "Large data transfer to external IP — possible S3 exfiltration"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "dstip": random.choice(EXTERNAL_IPS),
            "srcuser": random.choice(USERS),
            "program_name": "s3",
            "size": str(random.randint(500_000_000, 5_000_000_000)),
            "failed_attempts": "0",
        }
    },

    # ── Lateral movement ──────────────────────────────────────────────────────
    "lateral_assumerole": {
        "rule": {"id": "5510", "level": 9,
                 "description": "Unusual AssumeRole chain — possible lateral movement"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(["svc-backup", "svc-worker", "charlie"]),
            "program_name": "sts",
            "failed_attempts": "0",
            "size": str(random.randint(0, 1000)),
        }
    },

    # ── Port scan ─────────────────────────────────────────────────────────────
    "port_scan": {
        "rule": {"id": "40101", "level": 8,
                 "description": "Port scan detected from external IP"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(EXTERNAL_IPS),
            "dstip": random.choice(INTERNAL_IPS),
            "program_name": "firewall",
            "failed_attempts": str(random.randint(50, 1000)),
            "size": "0",
        }
    },

    # ── Crypto mining ─────────────────────────────────────────────────────────
    "crypto_mining": {
        "rule": {"id": "87100", "level": 12,
                 "description": "Crypto mining process detected on compute instance"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(["svc-worker", "svc-backup"]),
            "program_name": "xmrig",
            "failed_attempts": "0",
            "size": str(random.randint(10_000, 100_000)),
        }
    },

    # ── Ransomware precursor ──────────────────────────────────────────────────
    "ransomware": {
        "rule": {"id": "60100", "level": 15,
                 "description": "Ransomware precursor — mass file enumeration detected"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(INTERNAL_IPS),
            "srcuser": random.choice(USERS),
            "program_name": "kernel",
            "failed_attempts": "0",
            "size": str(random.randint(1_000_000, 10_000_000)),
        }
    },

    # ── Credential stuffing ───────────────────────────────────────────────────
    "credential_stuffing": {
        "rule": {"id": "5716", "level": 11,
                 "description": "Credential stuffing pattern detected on login endpoint"},
        "category": "attack",
        "data_fn": lambda: {
            "srcip": random.choice(EXTERNAL_IPS),
            "dstuser": random.choice(USERS),
            "program_name": "nginx",
            "failed_attempts": str(random.randint(30, 300)),
            "size": "0",
        }
    },
}

# ── Time-based attack probability ────────────────────────────────────────────
# Returns (n_normal, n_attacks) per minute based on current hour
def _batch_size() -> tuple:
    hour = datetime.now().hour
    if 9 <= hour <= 18:
        # Business hours: heavy normal traffic, rare attacks
        return random.randint(8, 15), random.randint(0, 2)
    elif 19 <= hour <= 22:
        # Evening: moderate traffic, some attacks
        return random.randint(4, 8), random.randint(1, 3)
    else:
        # Night: low normal traffic, more attacks
        return random.randint(2, 5), random.randint(2, 6)


# ── Attack campaign state ─────────────────────────────────────────────────────
# Every ~15 minutes a sustained attack campaign starts
_campaign_active    = False
_campaign_type      = None
_campaign_remaining = 0

ATTACK_RULES = [k for k, v in RULES.items() if v["category"] == "attack"]
NORMAL_RULES = [k for k, v in RULES.items() if v["category"] == "normal"]


def _maybe_start_campaign():
    global _campaign_active, _campaign_type, _campaign_remaining
    # 7% chance per minute of starting a campaign (~1 per 15 min)
    if not _campaign_active and random.random() < 0.07:
        _campaign_active    = True
        _campaign_type      = random.choice(ATTACK_RULES)
        _campaign_remaining = random.randint(3, 8)  # lasts 3–8 minutes
        print(f"[LogGen] Attack campaign started: {_campaign_type} "
              f"({_campaign_remaining} min)")


def _build_alert(rule_key: str) -> dict:
    """Build one Wazuh-format alert JSON object."""
    rule_def = RULES[rule_key]
    agent    = random.choice(AGENTS)
    data     = rule_def["data_fn"]()

    return {
        "id":        str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rule":      rule_def["rule"],
        "agent":     agent,
        "data":      data,
        "location":  data.get("srcip", agent["ip"]),
        "manager":   {"name": "wazuh-manager"},
    }


def generate_batch() -> list:
    """
    Generate one minute's worth of alerts.
    Mix of normal + attack events based on time of day and campaign state.
    """
    global _campaign_active, _campaign_remaining

    _maybe_start_campaign()

    n_normal, n_attacks = _batch_size()

    alerts = []

    # Normal events
    for _ in range(n_normal):
        alerts.append(_build_alert(random.choice(NORMAL_RULES)))

    # Attack events
    if _campaign_active:
        # During a campaign: all attacks are the same type (sustained)
        for _ in range(n_attacks + random.randint(2, 5)):
            alerts.append(_build_alert(_campaign_type))
        _campaign_remaining -= 1
        if _campaign_remaining <= 0:
            print(f"[LogGen] Campaign ended: {_campaign_type}")
            _campaign_active = False
    else:
        # Random scattered attacks
        for _ in range(n_attacks):
            alerts.append(_build_alert(random.choice(ATTACK_RULES)))

    return alerts


def append_to_log(alerts: list):
    """Append new alerts to the log file — one JSON object per line."""
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")


def rotate_log(max_lines: int = 5000):
    """
    Keep the log file from growing forever.
    Keeps only the last max_lines lines.
    """
    if not os.path.exists(LOG_PATH):
        return
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if len(lines) > max_lines:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines[-max_lines:])


def run(interval_seconds: int = 60):
    """
    Main loop — generates and appends logs every interval_seconds.
    Runs forever until Ctrl+C.
    """
    print(f"\n=== Ram Antivirus — Live Log Generator ===")
    print(f"Writing to: {LOG_PATH}")
    print(f"Interval  : every {interval_seconds} seconds")
    print(f"Press Ctrl+C to stop\n")
    print(f"Set this env var before starting the backend:")
    print(f"  set WAZUH_LOG_PATH={LOG_PATH}\n")

    total = 0
    try:
        while True:
            batch   = generate_batch()
            append_to_log(batch)
            rotate_log(max_lines=5000)
            total  += len(batch)

            now     = datetime.now().strftime("%H:%M:%S")
            attacks = sum(1 for a in batch if a["rule"]["level"] >= 8)
            normal  = len(batch) - attacks

            print(f"[{now}] +{len(batch):3d} alerts  "
                  f"(normal={normal}  attacks={attacks})  "
                  f"total={total}  "
                  f"{'[CAMPAIGN: ' + _campaign_type + ']' if _campaign_active else ''}")

            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print(f"\n[LogGen] Stopped. Total alerts written: {total}")
        print(f"[LogGen] Log file: {LOG_PATH}")


if __name__ == "__main__":
    import sys
    interval = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    run(interval)
