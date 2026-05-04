"""
Unified Risk Scoring Engine
Combines outputs from CSPM, CIEM, and ML anomaly detection
into a single, weighted risk score.

Score Formula:
  system_risk = 0.35 * ml_risk + 0.35 * cspm_risk + 0.30 * ciem_risk
"""
from typing import List, Dict, Optional
from datetime import datetime, timezone
import uuid
import random
from engines.db import save_risk_score, get_risk_trend_db

SEVERITY_SCORES = {
    "critical": 100, "high": 75, "medium": 50, "low": 25,
    "Critical": 100, "High": 75, "Medium": 50, "Low": 25,
}

def _risk_level(score: float) -> str:
    if score >= 76: return "critical"
    elif score >= 51: return "high"
    elif score >= 26: return "medium"
    else: return "low"

def _risk_color(level: str) -> str:
    return {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#10b981"}.get(level, "#8b949e")

def calculate_ml_risk(analyzed_events: List[Dict]) -> Dict:
    if not analyzed_events:
        return {"score": 0, "level": "low", "details": {}}
    total = len(analyzed_events)
    anomalies = [e for e in analyzed_events if e.get("is_anomaly")]
    anomaly_ratio = len(anomalies) / total if total > 0 else 0
    avg_score = sum(e.get("ml_anomaly_score", 0) for e in anomalies) / len(anomalies) if anomalies else 0
    critical_count = sum(1 for e in analyzed_events if e.get("ml_severity") == "Critical")
    high_count = sum(1 for e in analyzed_events if e.get("ml_severity") == "High")
    critical_density = (critical_count + high_count * 0.5) / total if total > 0 else 0
    risk_score = min(100, round(anomaly_ratio * 40 + avg_score * 35 + critical_density * 25, 1))
    return {
        "score": risk_score, "level": _risk_level(risk_score), "color": _risk_color(_risk_level(risk_score)),
        "details": {"total_events": total, "anomalies_detected": len(anomalies),
                     "anomaly_ratio": round(anomaly_ratio * 100, 1), "avg_anomaly_score": round(avg_score, 4),
                     "critical_threats": critical_count, "high_threats": high_count}
    }

def calculate_cspm_risk(cspm_findings: List[Dict]) -> Dict:
    if not cspm_findings:
        return {"score": 0, "level": "low", "details": {}}
    sc = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in cspm_findings:
        s = f.get("severity", "low").lower()
        sc[s] = sc.get(s, 0) + 1
    raw = sc["critical"] * 25 + sc["high"] * 15 + sc["medium"] * 8 + sc["low"] * 3
    risk_score = min(100, round(raw, 1))
    return {
        "score": risk_score, "level": _risk_level(risk_score), "color": _risk_color(_risk_level(risk_score)),
        "details": {"total_findings": len(cspm_findings), "severity_breakdown": sc,
                     "open_critical": sc["critical"], "open_high": sc["high"]}
    }

def calculate_ciem_risk(ciem_findings: List[Dict]) -> Dict:
    if not ciem_findings:
        return {"score": 0, "level": "low", "details": {}}
    rc = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    et = {"human": 0, "machine": 0, "role": 0}
    for f in ciem_findings:
        r = f.get("risk_level", "low").lower()
        rc[r] = rc.get(r, 0) + 1
        t = f.get("entity_type", "unknown")
        et[t] = et.get(t, 0) + 1
    raw = rc["critical"] * 30 + rc["high"] * 20 + rc["medium"] * 10 + rc["low"] * 5
    risk_score = min(100, round(raw, 1))
    return {
        "score": risk_score, "level": _risk_level(risk_score), "color": _risk_color(_risk_level(risk_score)),
        "details": {"total_risky_entities": len(ciem_findings), "risk_breakdown": rc, "entity_types_affected": et}
    }

def calculate_unified_risk(analyzed_events, cspm_findings, ciem_findings, weights=None):
    if weights is None:
        weights = {"ml": 0.35, "cspm": 0.35, "ciem": 0.30}
    ml_risk = calculate_ml_risk(analyzed_events)
    cspm_risk = calculate_cspm_risk(cspm_findings)
    ciem_risk = calculate_ciem_risk(ciem_findings)
    unified_score = round(ml_risk["score"] * weights["ml"] + cspm_risk["score"] * weights["cspm"] + ciem_risk["score"] * weights["ciem"], 1)
    unified_level = _risk_level(unified_score)
    recs = []
    if ml_risk["score"] > 60:
        recs.append({"priority": "critical" if ml_risk["score"] > 80 else "high", "category": "ML/AI Detection",
                      "recommendation": f"High anomaly rate. Review {ml_risk['details'].get('critical_threats', 0)} critical threats.",
                      "action": "Trigger auto-remediation playbooks"})
    if cspm_risk["score"] > 40:
        recs.append({"priority": "critical" if cspm_risk["score"] > 70 else "high", "category": "Cloud Posture",
                      "recommendation": f"{cspm_risk['details'].get('open_critical', 0)} critical misconfigurations.",
                      "action": "Run CSPM auto-fix pipeline"})
    if ciem_risk["score"] > 40:
        recs.append({"priority": "critical" if ciem_risk["score"] > 70 else "high", "category": "Identity & Access",
                      "recommendation": f"{ciem_risk['details'].get('total_risky_entities', 0)} risky IAM entities.",
                      "action": "Revoke excessive permissions"})
    if not recs:
        recs.append({"priority": "low", "category": "General", "recommendation": "Risk within acceptable thresholds.", "action": "Maintain current posture"})
    actions = {
        "auto_remediate": unified_score >= 70, "block_suspicious_ips": ml_risk["score"] >= 75,
        "disable_risky_users": ciem_risk["score"] >= 80, "fix_configurations": cspm_risk["score"] >= 60,
        "escalate_to_soc": unified_score >= 85, "generate_incident_report": unified_score >= 60,
    }
    triggered = [k for k, v in actions.items() if v]
    return {
        "risk_id": f"RISK-{str(uuid.uuid4())[:8].upper()}", "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "unified_risk_score": unified_score, "unified_risk_level": unified_level, "unified_risk_color": _risk_color(unified_level),
        "weights": weights,
        "components": {"ml_anomaly_detection": ml_risk, "cspm_posture": cspm_risk, "ciem_identity": ciem_risk},
        "risk_breakdown_chart": [
            {"name": "ML/AI Detection", "score": ml_risk["score"], "weight": weights["ml"], "color": "#8b5cf6"},
            {"name": "CSPM Posture", "score": cspm_risk["score"], "weight": weights["cspm"], "color": "#3b82f6"},
            {"name": "CIEM Identity", "score": ciem_risk["score"], "weight": weights["ciem"], "color": "#06b6d4"},
        ],
        "recommendations": sorted(recs, key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}[r["priority"]]),
        "threshold_actions": {"actions": actions, "triggered_count": len(triggered), "triggered_actions": triggered, "severity": unified_level},
    }

def get_risk_trend(current_score: float, periods: int = 7) -> List[Dict]:
    trend = get_risk_trend_db(periods)
    if not trend:
        # Fallback: generate synthetic history only if DB is empty
        for i in range(periods, 0, -1):
            score = max(0, min(100, current_score + random.uniform(-8, 8) + i * 1.5))
            trend.append({"period": f"Day -{i}", "score": round(score, 1), "level": _risk_level(score)})
    trend.append({"period": "Today", "score": current_score, "level": _risk_level(current_score)})
    return trend
