from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from fastapi.responses import JSONResponse
from fastapi.websockets import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import uvicorn
from typing import Optional
import asyncio
import json
import csv
import io
import sys
import os
import traceback

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.wazuh_simulator import simulate_session
from simulator.wazuh_reader import read_wazuh_logs, get_wazuh_status, is_wazuh_available
from simulator.attack_simulator import run_attack_simulation, run_full_simulation, SCENARIOS, get_scenario_catalog
from engines.cspm_engine import run_cspm_scan
from engines.ciem_engine import run_ciem_scan
from engines.ml_engine import analyze_events, compare_models, get_model_info
from engines.remediation_engine import (
    execute_playbook, correct_configuration, revoke_entity_access,
    get_all_playbooks, auto_remediate_threats
)
from engines.compliance_engine import (
    map_findings_to_compliance, get_compliance_dashboard,
    generate_compliance_report, COMPLIANCE_FRAMEWORKS
)
from engines.auth_engine import (
    register_user, login_user, verify_token, check_permission,
    get_all_users, deactivate_user, reactivate_user, get_role_info, ROLE_PERMISSIONS
)
from engines.risk_engine import calculate_unified_risk, get_risk_trend
from engines.localstack_engine import (
    run_cspm_scan_localstack, run_ciem_scan_localstack,
    get_localstack_status, is_localstack_running
)
from engines.db import (
    save_risk_score, get_cspm_history, get_ciem_history,
    save_cspm_scan, save_ciem_scan, get_alert_log,
    save_compliance_score, get_compliance_trend_db
)
from engines.alert_engine import send_alert_email

app = FastAPI(title="Advanced Cloud Security API")

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Return JSON for unexpected backend failures so the frontend sees the real error."""
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "detail": str(exc) or exc.__class__.__name__,
            "path": str(request.url.path),
        },
    )


# ── Pydantic Models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str
    role: str = "viewer"
    full_name: str = ""

class LoginRequest(BaseModel):
    username: str
    password: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_current_user(authorization: Optional[str] = None):
    if not authorization:
        return None
    try:
        token = authorization.replace("Bearer ", "")
        result = verify_token(token)
        if result["valid"]:
            return result["payload"]
    except Exception:
        pass
    return None

def _require_permission(authorization: Optional[str], permission: str):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    token = authorization.replace("Bearer ", "")
    result = check_permission(token, permission)
    if not result["authorized"]:
        raise HTTPException(status_code=403, detail=result.get("error", "Forbidden"))
    return result["user"]

def _get_events(normal: int = 80, attacks: int = 15):
    if is_wazuh_available():
        events = read_wazuh_logs(max_events=normal + attacks)
        if events:
            return events
    return simulate_session(n_normal=normal, n_attacks=attacks)

def _get_cspm(events: list = None):
    """Derive CSPM findings from log events. Falls back to LocalStack if running."""
    if is_localstack_running():
        results = run_cspm_scan_localstack()
        if results:
            save_cspm_scan(results)
            return results
    results = run_cspm_scan(events or [])
    save_cspm_scan(results)
    return results

def _get_ciem(events: list = None):
    """Derive CIEM findings from log events. Falls back to LocalStack if running."""
    if is_localstack_running():
        results = run_ciem_scan_localstack()
        if results:
            save_ciem_scan(results)
            return results
    results = run_ciem_scan(events or [])
    save_ciem_scan(results)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# 1 — AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
def api_register(req: RegisterRequest):
    result = register_user(req.username, req.password, req.email, req.role, req.full_name)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"status": "success", "data": result}

@app.post("/api/auth/login")
def api_login(req: LoginRequest):
    result = login_user(req.username, req.password)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["error"])
    return {"status": "success", "data": result}

@app.get("/api/auth/me")
def api_get_me(authorization: Optional[str] = Header(None)):
    user = _get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    return {"status": "success", "data": user}

@app.get("/api/auth/roles")
def api_get_roles():
    return {"status": "success", "data": get_role_info()}

@app.get("/api/auth/users")
def api_list_users(authorization: Optional[str] = Header(None)):
    _require_permission(authorization, "users:read")
    return {"status": "success", "data": get_all_users()}

@app.post("/api/auth/users/{username}/deactivate")
def api_deactivate_user(username: str, authorization: Optional[str] = Header(None)):
    _require_permission(authorization, "users:manage")
    result = deactivate_user(username)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"status": "success", "data": result}

@app.post("/api/auth/users/{username}/reactivate")
def api_reactivate_user(username: str, authorization: Optional[str] = Header(None)):
    _require_permission(authorization, "users:manage")
    result = reactivate_user(username)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"status": "success", "data": result}


# ══════════════════════════════════════════════════════════════════════════════
# 2 — EVENTS & SCANS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/simulate/events")
def get_simulated_events(hours: int = 24, normal: int = 150, attacks: int = 25):
    raw_events = _get_events(normal, attacks)
    analyzed_events = analyze_events(raw_events)
    return {"status": "success", "count": len(analyzed_events), "data": analyzed_events,
            "source": get_wazuh_status()["mode"]}

@app.get("/api/cspm/scan")
def get_cspm_results():
    events = _get_events(80, 20)
    results = _get_cspm(events)
    return {"status": "success", "count": len(results), "data": results,
            "source": get_localstack_status()["mode"]}

@app.get("/api/ciem/scan")
def get_ciem_results():
    events = _get_events(80, 20)
    results = _get_ciem(events)
    return {"status": "success", "count": len(results), "data": results,
            "source": get_localstack_status()["mode"]}

@app.get("/api/dashboard/summary")
def get_dashboard_summary():
    events = _get_events(100, 15)
    analyzed = analyze_events(events)
    cspm_issues = _get_cspm(events)
    ciem_issues = _get_ciem(events)
    return {
        "status": "success",
        "data": {
            "threats": {
                "critical": sum(1 for e in analyzed if e["ml_severity"] == "Critical"),
                "high": sum(1 for e in analyzed if e["ml_severity"] == "High"),
                "total_analyzed": len(analyzed)
            },
            "posture": {"cspm_open_issues": len(cspm_issues), "ciem_open_risks": len(ciem_issues)},
            "recent_critical_alerts": [e for e in analyzed if e["ml_severity"] == "Critical"][:5]
        }
    }

@app.get("/api/simulate/attack")
def trigger_targeted_attack(type: str = "brute_force"):
    noise = simulate_session(n_normal=50, n_attacks=0, time_window_hours=1)
    if type == "data_exfiltration":
        attack = {
            "id": "TARGETED-ATTACK-001", "timestamp": noise[0]["timestamp"], "source": "wazuh",
            "rule_id": 31101, "level": 15, "severity": "critical", "event_type": "attack",
            "attack_type": "data_exfiltration", "user": "malicious-actor", "src_ip": "1.2.3.4",
            "dst_ip": "99.88.77.66", "service": "s3", "region": "us-east-1", "action": "ExfiltrateData",
            "status": "success", "bytes_transferred": 10_000_000_000, "failed_attempts": 0,
            "description": "TARGETED TEST: Massive data transfer detected"
        }
    else:
        attack = {
            "id": "TARGETED-ATTACK-002", "timestamp": noise[0]["timestamp"], "source": "wazuh",
            "rule_id": 5712, "level": 12, "severity": "critical", "event_type": "attack",
            "attack_type": "brute_force", "user": "admin", "src_ip": "103.21.244.1",
            "dst_ip": "10.0.0.5", "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
            "status": "failure", "bytes_transferred": 0, "failed_attempts": 500,
            "description": "TARGETED TEST: Massive brute force detected"
        }
    events = [attack] + noise
    analyzed = analyze_events(events)
    target_result = next(e for e in analyzed if e["id"].startswith("TARGETED-ATTACK"))
    return {
        "status": "success",
        "pyod_analysis": {"score": target_result["ml_anomaly_score"], "is_anomaly": target_result["is_anomaly"], "severity": target_result["ml_severity"]},
        "all_data": analyzed
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3 — ML
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ml/compare")
def ml_model_comparison(normal: int = 100, attacks: int = 20):
    events = simulate_session(n_normal=normal, n_attacks=attacks)
    return {"status": "success", "data": compare_models(events)}

@app.get("/api/ml/model-info")
def ml_model_info():
    """Return metadata about the loaded pre-trained models."""
    return {"status": "success", "data": get_model_info()}


# ══════════════════════════════════════════════════════════════════════════════
# 4 — REMEDIATION
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/remediation/playbooks")
def list_playbooks():
    return {"status": "success", "count": len(get_all_playbooks()), "data": get_all_playbooks()}

@app.post("/api/remediation/execute/{attack_type}")
def execute_remediation(attack_type: str):
    result = execute_playbook(attack_type)
    return {"status": "success", "data": result}

@app.post("/api/remediation/auto")
def auto_remediate():
    events = _get_events(100, 20)
    analyzed = analyze_events(events)
    return {"status": "success", "data": auto_remediate_threats(analyzed)}

@app.post("/api/remediation/config-fix/{vulnerability_id}")
def fix_configuration(vulnerability_id: str):
    return {"status": "success", "data": correct_configuration(vulnerability_id)}

@app.post("/api/remediation/revoke-access")
def revoke_access(entity_name: str, entity_type: str = "human", risk_level: str = "high"):
    return {"status": "success", "data": revoke_entity_access(entity_name, entity_type, risk_level)}

@app.get("/api/remediation/full-pipeline")
def full_remediation_pipeline():
    events = _get_events(80, 20)
    analyzed = analyze_events(events)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    return {
        "status": "success",
        "data": {
            "ml_analysis": {"total_events": len(analyzed), "anomalies_detected": sum(1 for e in analyzed if e["is_anomaly"])},
            "threat_remediation": auto_remediate_threats(analyzed),
            "config_fixes": [correct_configuration(f["vulnerability_id"]) for f in cspm_findings],
            "access_revocations": [revoke_entity_access(f["entity_name"], f["entity_type"], f["risk_level"]) for f in ciem_findings],
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# 5 — COMPLIANCE
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/compliance/frameworks")
def list_frameworks():
    return {"status": "success", "data": COMPLIANCE_FRAMEWORKS}

@app.get("/api/compliance/dashboard")
def compliance_dashboard():
    events = _get_events(80, 15)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    dashboard = get_compliance_dashboard(cspm_findings, ciem_findings)
    # Replace hardcoded trend with DB trend
    dashboard["trend"] = get_compliance_trend_db(dashboard["overall_score"])
    save_compliance_score(dashboard["overall_score"])
    return {"status": "success", "data": dashboard}

@app.get("/api/compliance/map")
def compliance_mapping(framework: str = None):
    events = _get_events(80, 15)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    return {"status": "success", "data": map_findings_to_compliance(cspm_findings, ciem_findings, framework)}

@app.get("/api/compliance/report")
def get_compliance_report(format: str = "json"):
    events = _get_events(80, 15)
    analyzed = analyze_events(events)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    remediation = auto_remediate_threats(analyzed)
    report = generate_compliance_report(cspm_findings, ciem_findings, analyzed, remediation_results=remediation, format=format)
    if format == "csv":
        return PlainTextResponse(content=report["csv_data"], media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=compliance_report_{report['report_id']}.csv"})
    return {"status": "success", "data": report}

@app.get("/api/compliance/report/executive")
def executive_summary():
    events = _get_events(80, 15)
    analyzed = analyze_events(events)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    remediation = auto_remediate_threats(analyzed)
    report = generate_compliance_report(cspm_findings, ciem_findings, analyzed, remediation_results=remediation)
    dashboard = get_compliance_dashboard(cspm_findings, ciem_findings)
    return {
        "status": "success",
        "data": {
            "executive_summary": report["executive_summary"],
            "compliance_scores": {fw: {"score": data["score"], "status": data["status"]} for fw, data in dashboard["frameworks"].items()},
            "overall_score": dashboard["overall_score"], "trend": dashboard["trend"], "generated_at": report["generated_at"]
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# 6 — RISK SCORE
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/risk/score")
def get_risk_score():
    events = _get_events(80, 15)
    analyzed = analyze_events(events)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    risk = calculate_unified_risk(analyzed, cspm_findings, ciem_findings)
    # Save to DB for real trend history
    save_risk_score(
        risk["unified_risk_score"],
        risk["components"]["ml_anomaly_detection"]["score"],
        risk["components"]["cspm_posture"]["score"],
        risk["components"]["ciem_identity"]["score"],
        risk["unified_risk_level"]
    )
    risk["trend"] = get_risk_trend(risk["unified_risk_score"])
    return {"status": "success", "data": risk}


# ══════════════════════════════════════════════════════════════════════════════
# 7 — ATTACK SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/simulation/scenarios")
def list_scenarios():
    return {"status": "success", "data": get_scenario_catalog()}

@app.post("/api/simulation/run/{scenario}")
def run_simulation(scenario: str, intensity: str = "high"):
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{scenario}'. Valid: {list(SCENARIOS.keys())}")
    sim = run_attack_simulation(scenario, intensity)
    noise = simulate_session(n_normal=50, n_attacks=0)
    all_events = sim["events"] + noise
    analyzed = analyze_events(all_events)
    sim_ids = {e["id"] for e in sim["events"]}
    detected = [e for e in analyzed if e["id"] in sim_ids and e["is_anomaly"]]
    detection_rate = len(detected) / len(sim["events"]) * 100 if sim["events"] else 0
    return {
        "status": "success",
        "data": {
            "simulation": {k: v for k, v in sim.items() if k != "events"},
            "detection": {"total_sim_events": len(sim["events"]), "detected_as_anomaly": len(detected),
                          "detection_rate": round(detection_rate, 1), "detection_success": detection_rate > 50},
            "sample_sim_events": sim["events"][:5],
            "all_analyzed_events": analyzed
        }
    }

@app.post("/api/simulation/full")
def run_full_attack_simulation(intensity: str = "high"):
    full_sim = run_full_simulation(intensity)
    all_sim_events = [e for s in full_sim["scenarios"] for e in s["events"]]
    noise = simulate_session(n_normal=80, n_attacks=0)
    all_events = all_sim_events + noise
    analyzed = analyze_events(all_events)
    sim_ids = {e["id"] for e in all_sim_events}
    detected = [e for e in analyzed if e["id"] in sim_ids and e["is_anomaly"]]
    detection_rate = len(detected) / len(all_sim_events) * 100 if all_sim_events else 0
    cspm = _get_cspm(all_events)
    ciem = _get_ciem(all_events)
    risk = calculate_unified_risk(analyzed, cspm, ciem)
    remediation = auto_remediate_threats(analyzed)
    return {
        "status": "success",
        "data": {
            "simulation_summary": {
                "simulation_id": full_sim["simulation_id"],
                "generated_at": full_sim["timestamp"],
                "intensity": full_sim["intensity"],
                "scenarios_run": full_sim["scenarios_run"],
                "total_attack_events": len(all_sim_events),
                "total_with_noise": len(all_events)
            },
            "detection": {"detected_as_anomaly": len(detected), "detection_rate": round(detection_rate, 1), "detection_success": detection_rate > 50},
            "risk_score": {"unified": risk["unified_risk_score"], "level": risk["unified_risk_level"], "components": {k: v["score"] for k, v in risk["components"].items()}},
            "auto_remediation": {"triggered": remediation["remediations_triggered"], "completed": remediation["summary"]["fully_completed"]},
            "scenarios": [{k: v for k, v in s.items() if k != "events"} for s in full_sim["scenarios"]]
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# 8 — HISTORY & EXPORT
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/history/cspm")
def cspm_history():
    return {"status": "success", "data": get_cspm_history()}

@app.get("/api/history/ciem")
def ciem_history():
    return {"status": "success", "data": get_ciem_history()}

@app.get("/api/history/alerts")
def alert_history():
    return {"status": "success", "data": get_alert_log()}

@app.get("/api/export/events")
def export_events():
    events = _get_events(100, 20)
    analyzed = analyze_events(events)
    output = io.StringIO()
    if analyzed:
        writer = csv.DictWriter(output, fieldnames=["id", "timestamp", "event_type", "attack_type", "user", "src_ip", "service", "level", "severity", "ml_anomaly_score", "is_anomaly", "ml_severity", "description"])
        writer.writeheader()
        for e in analyzed:
            writer.writerow({k: e.get(k, "") for k in writer.fieldnames})
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events_export.csv"})

@app.get("/api/export/cspm")
def export_cspm():
    events = _get_events(80, 20)
    findings = _get_cspm(events)
    output = io.StringIO()
    if findings:
        writer = csv.DictWriter(output, fieldnames=["scan_id", "vulnerability_id", "title", "severity", "resource", "description", "remediation", "status"])
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in writer.fieldnames})
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cspm_export.csv"})

@app.get("/api/export/ciem")
def export_ciem():
    events = _get_events(80, 20)
    findings = _get_ciem(events)
    output = io.StringIO()
    if findings:
        writer = csv.DictWriter(output, fieldnames=["scan_id", "risk_id", "title", "entity_name", "entity_type", "risk_level", "description", "remediation"])
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in writer.fieldnames})
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ciem_export.csv"})


# ══════════════════════════════════════════════════════════════════════════════
# 9 — SYSTEM STATUS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/status")
def system_status():
    return {
        "status": "success",
        "data": {
            "wazuh": get_wazuh_status(),
            "localstack": get_localstack_status(),
            "database": "connected",
        }
    }

@app.post("/api/alerts/test")
def test_alert(authorization: Optional[str] = Header(None)):
    _require_permission(authorization, "users:manage")
    result = send_alert_email("Test Alert", "This is a test alert from Ram Antivirus Cloud Security Platform.")
    return {"status": "success", "data": result}


# ══════════════════════════════════════════════════════════════════════════════
# 10 — WEBSOCKET (real-time auto-poll)
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    WebSocket endpoint — pushes new analyzed events every 10 seconds.
    Frontend connects once and receives live updates automatically.
    """
    await websocket.accept()
    try:
        while True:
            events = _get_events(30, 5)
            analyzed = analyze_events(events)
            anomalies = [e for e in analyzed if e["is_anomaly"]]
            await websocket.send_text(json.dumps({
                "type": "events_update",
                "total": len(analyzed),
                "anomalies": len(anomalies),
                "critical": sum(1 for e in analyzed if e["ml_severity"] == "Critical"),
                "latest_events": analyzed[:10]
            }))
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        pass


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
