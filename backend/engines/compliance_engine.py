"""
Compliance & Reporting Engine
Maps security findings to compliance frameworks (ISO 27001, SOC2, GDPR),
provides real-time compliance scoring, and generates exportable reports.
"""
import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
from io import StringIO
import csv


# ── Compliance Framework Definitions ─────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = {
    "ISO27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "Information Security Management Systems (ISMS)",
        "total_controls": 93,
        "categories": {
            "A.5": "Organizational Controls",
            "A.6": "People Controls",
            "A.7": "Physical Controls",
            "A.8": "Technological Controls"
        }
    },
    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "Trust Services Criteria (AICPA)",
        "total_controls": 64,
        "categories": {
            "CC1": "Control Environment",
            "CC2": "Communication and Information",
            "CC3": "Risk Assessment",
            "CC5": "Control Activities",
            "CC6": "Logical and Physical Access Controls",
            "CC7": "System Operations",
            "CC8": "Change Management",
            "CC9": "Risk Mitigation"
        }
    },
    "GDPR": {
        "name": "General Data Protection Regulation",
        "description": "EU Data Protection and Privacy Regulation",
        "total_controls": 44,
        "categories": {
            "Art.5": "Principles of Processing",
            "Art.25": "Data Protection by Design",
            "Art.30": "Records of Processing",
            "Art.32": "Security of Processing",
            "Art.33": "Breach Notification",
            "Art.35": "Impact Assessment"
        }
    }
}

# ── Control Mapping: Security Finding → Compliance Control ──────────────────

CSPM_COMPLIANCE_MAP = {
    "CSPM-S3-001": {
        "ISO27001": [
            {"control": "A.8.3", "name": "Access Restriction", "status": "fail", "description": "S3 bucket public access violates access restriction controls"},
            {"control": "A.8.10", "name": "Information Deletion", "status": "fail", "description": "Public bucket exposes data to unauthorized deletion"}
        ],
        "SOC2": [
            {"control": "CC6.1", "name": "Logical Access Security", "status": "fail", "description": "Public S3 bucket violates logical access controls"},
            {"control": "CC6.3", "name": "Role-Based Access", "status": "fail", "description": "S3 access not restricted to authorized roles"}
        ],
        "GDPR": [
            {"control": "Art.32", "name": "Security of Processing", "status": "fail", "description": "Public data storage violates security requirements"},
            {"control": "Art.25", "name": "Data Protection by Design", "status": "fail", "description": "Bucket design lacks default privacy controls"}
        ]
    },
    "CSPM-EC2-002": {
        "ISO27001": [
            {"control": "A.8.20", "name": "Network Security", "status": "fail", "description": "Open RDP port violates network segmentation controls"},
            {"control": "A.8.21", "name": "Web Service Security", "status": "fail", "description": "Unrestricted inbound port exposes services"}
        ],
        "SOC2": [
            {"control": "CC6.6", "name": "System Boundaries", "status": "fail", "description": "Open port violates system boundary controls"},
            {"control": "CC7.1", "name": "Infrastructure Monitoring", "status": "fail", "description": "Unmonitored open port detected"}
        ],
        "GDPR": [
            {"control": "Art.32", "name": "Security of Processing", "status": "fail", "description": "Open RDP creates unauthorized access risk to data"}
        ]
    },
    "CSPM-IAM-003": {
        "ISO27001": [
            {"control": "A.8.5", "name": "Secure Authentication", "status": "fail", "description": "Root account without MFA violates authentication controls"},
            {"control": "A.5.15", "name": "Access Control", "status": "fail", "description": "Root access lacks defense-in-depth"}
        ],
        "SOC2": [
            {"control": "CC6.1", "name": "Logical Access Security", "status": "fail", "description": "Missing MFA on root violates access security"},
            {"control": "CC6.2", "name": "User Authentication", "status": "fail", "description": "Single-factor auth insufficient for privileged access"}
        ],
        "GDPR": [
            {"control": "Art.32", "name": "Security of Processing", "status": "fail", "description": "Weak root authentication creates data breach risk"}
        ]
    },
    "CSPM-RDS-004": {
        "ISO27001": [
            {"control": "A.8.24", "name": "Cryptography Usage", "status": "fail", "description": "Unencrypted database violates encryption-at-rest requirements"}
        ],
        "SOC2": [
            {"control": "CC6.7", "name": "Data at Rest", "status": "fail", "description": "Database encryption not enabled for data at rest"}
        ],
        "GDPR": [
            {"control": "Art.32", "name": "Security of Processing", "status": "fail", "description": "Unencrypted personal data storage"},
            {"control": "Art.25", "name": "Data Protection by Design", "status": "fail", "description": "Database not designed with encryption by default"}
        ]
    },
    "CSPM-KMS-005": {
        "ISO27001": [
            {"control": "A.8.24", "name": "Cryptography Usage", "status": "fail", "description": "KMS key rotation disabled undermines cryptographic controls"}
        ],
        "SOC2": [
            {"control": "CC6.7", "name": "Data at Rest", "status": "fail", "description": "Stale encryption keys increase compromise risk"}
        ],
        "GDPR": [
            {"control": "Art.32", "name": "Security of Processing", "status": "fail", "description": "Non-rotating keys weaken encryption posture"}
        ]
    }
}

CIEM_COMPLIANCE_MAP = {
    "CIEM-001": {
        "ISO27001": [
            {"control": "A.5.18", "name": "Access Rights", "status": "fail", "description": "Over-privileged machine identity violates least-privilege"},
            {"control": "A.8.2", "name": "Privileged Access", "status": "fail", "description": "Service account has excessive admin rights"}
        ],
        "SOC2": [
            {"control": "CC6.3", "name": "Role-Based Access", "status": "fail", "description": "Machine identity exceeds required permissions"},
            {"control": "CC6.1", "name": "Logical Access Security", "status": "fail", "description": "Overly permissive service account"}
        ],
        "GDPR": [
            {"control": "Art.25", "name": "Data Protection by Design", "status": "fail", "description": "Over-privileged access to personal data"}
        ]
    },
    "CIEM-002": {
        "ISO27001": [
            {"control": "A.5.18", "name": "Access Rights", "status": "fail", "description": "Inactive user retains high privileges — stale access"},
            {"control": "A.5.16", "name": "Identity Management", "status": "fail", "description": "User identity not reviewed for 90+ days"}
        ],
        "SOC2": [
            {"control": "CC6.2", "name": "User Authentication", "status": "fail", "description": "Dormant privileged account not deactivated"},
            {"control": "CC6.5", "name": "Account Management", "status": "fail", "description": "No periodic access review performed"}
        ],
        "GDPR": [
            {"control": "Art.5", "name": "Principles of Processing", "status": "fail", "description": "Storage limitation — access retained beyond necessity"}
        ]
    },
    "CIEM-003": {
        "ISO27001": [
            {"control": "A.8.2", "name": "Privileged Access", "status": "fail", "description": "Cross-account privilege escalation path exists"}
        ],
        "SOC2": [
            {"control": "CC6.1", "name": "Logical Access Security", "status": "fail", "description": "Cross-account role chain enables privilege escalation"}
        ],
        "GDPR": [
            {"control": "Art.32", "name": "Security of Processing", "status": "fail", "description": "Escalation path could expose personal data in prod"}
        ]
    },
    "CIEM-004": {
        "ISO27001": [
            {"control": "A.5.15", "name": "Access Control", "status": "fail", "description": "Wildcard permissions grant unrestricted access"},
            {"control": "A.5.18", "name": "Access Rights", "status": "fail", "description": "Resource: * violates least-privilege principle"}
        ],
        "SOC2": [
            {"control": "CC6.3", "name": "Role-Based Access", "status": "fail", "description": "Wildcard permissions not scoped to specific resources"},
            {"control": "CC6.1", "name": "Logical Access Security", "status": "fail", "description": "Action: * grants all API permissions"}
        ],
        "GDPR": [
            {"control": "Art.25", "name": "Data Protection by Design", "status": "fail", "description": "Unrestricted access violates data minimization"}
        ]
    }
}

# ── Baseline passing controls (controls not affected by findings) ────────────

BASELINE_CONTROLS = {
    "ISO27001": [
        {"control": "A.5.1", "name": "Information Security Policies", "status": "pass", "description": "Organizational security policy documented and maintained"},
        {"control": "A.5.2", "name": "Information Security Roles", "status": "pass", "description": "Security roles and responsibilities assigned"},
        {"control": "A.5.10", "name": "Acceptable Use", "status": "pass", "description": "Asset use policies established"},
        {"control": "A.5.23", "name": "Cloud Services Security", "status": "pass", "description": "Cloud security processes defined and monitored"},
        {"control": "A.5.24", "name": "Incident Management Planning", "status": "pass", "description": "Incident response procedures established"},
        {"control": "A.5.29", "name": "Business Continuity", "status": "pass", "description": "BC/DR plans documented and tested"},
        {"control": "A.6.1", "name": "Staff Screening", "status": "pass", "description": "Background verification processes in place"},
        {"control": "A.6.3", "name": "Security Awareness", "status": "pass", "description": "Security training programs active"},
        {"control": "A.7.1", "name": "Physical Security Perimeter", "status": "pass", "description": "Physical boundaries defined (cloud provider responsibility)"},
        {"control": "A.8.1", "name": "User Endpoint Devices", "status": "pass", "description": "Endpoint protection deployed"},
        {"control": "A.8.7", "name": "Malware Protection", "status": "pass", "description": "Anti-malware (Wazuh) active and monitoring"},
        {"control": "A.8.8", "name": "Vulnerability Management", "status": "pass", "description": "CSPM scanning active for configuration vulnerabilities"},
        {"control": "A.8.9", "name": "Configuration Management", "status": "pass", "description": "Configuration baselines defined"},
        {"control": "A.8.15", "name": "Logging", "status": "pass", "description": "Comprehensive logging via Wazuh + CloudTrail"},
        {"control": "A.8.16", "name": "Monitoring Activities", "status": "pass", "description": "Real-time ML anomaly detection active (PyOD)"},
    ],
    "SOC2": [
        {"control": "CC1.1", "name": "Organizational Structure", "status": "pass", "description": "Security governance structure established"},
        {"control": "CC2.1", "name": "Internal Communication", "status": "pass", "description": "Security communications processes active"},
        {"control": "CC3.1", "name": "Risk Identification", "status": "pass", "description": "Automated risk identification via CSPM/CIEM"},
        {"control": "CC3.2", "name": "Risk Analysis", "status": "pass", "description": "ML-based risk scoring operational"},
        {"control": "CC5.1", "name": "Control Selection", "status": "pass", "description": "Technical controls selected and implemented"},
        {"control": "CC7.2", "name": "Activity Monitoring", "status": "pass", "description": "Real-time anomaly detection via PyOD Isolation Forest"},
        {"control": "CC7.3", "name": "Incident Detection", "status": "pass", "description": "Automated incident detection pipelines active"},
        {"control": "CC8.1", "name": "Change Control", "status": "pass", "description": "Infrastructure change management process defined"},
        {"control": "CC9.1", "name": "Risk Mitigation", "status": "pass", "description": "Automated remediation playbooks available"},
    ],
    "GDPR": [
        {"control": "Art.5.1a", "name": "Lawfulness", "status": "pass", "description": "Processing activities have documented legal basis"},
        {"control": "Art.5.1b", "name": "Purpose Limitation", "status": "pass", "description": "Data collected for specified purposes only"},
        {"control": "Art.5.1c", "name": "Data Minimization", "status": "pass", "description": "Only necessary data collected"},
        {"control": "Art.30", "name": "Records of Processing", "status": "pass", "description": "Processing activity records maintained"},
        {"control": "Art.33", "name": "Breach Notification", "status": "pass", "description": "72-hour breach notification process established"},
        {"control": "Art.35", "name": "Impact Assessment", "status": "pass", "description": "DPIA conducted for high-risk processing"},
        {"control": "Art.37", "name": "Data Protection Officer", "status": "pass", "description": "DPO designated and contactable"},
    ]
}


def map_findings_to_compliance(
    cspm_findings: List[Dict],
    ciem_findings: List[Dict],
    framework: Optional[str] = None
) -> Dict:
    """
    Map CSPM and CIEM findings to compliance framework controls.
    Returns per-framework compliance status and scoring.
    """
    frameworks_to_check = [framework] if framework else ["ISO27001", "SOC2", "GDPR"]
    
    result = {}
    
    for fw in frameworks_to_check:
        fw_info = COMPLIANCE_FRAMEWORKS.get(fw, {})
        
        # Start with baseline passing controls
        all_controls = list(BASELINE_CONTROLS.get(fw, []))
        failed_control_ids = set()
        
        # Map CSPM findings to controls
        for finding in cspm_findings:
            vuln_id = finding.get("vulnerability_id", "")
            mapping = CSPM_COMPLIANCE_MAP.get(vuln_id, {}).get(fw, [])
            for control in mapping:
                failed_control_ids.add(control["control"])
                all_controls.append({
                    **control,
                    "source": "CSPM",
                    "finding_id": vuln_id,
                    "finding_title": finding.get("title", "")
                })
        
        # Map CIEM findings to controls
        for finding in ciem_findings:
            risk_id = finding.get("risk_id", "")
            mapping = CIEM_COMPLIANCE_MAP.get(risk_id, {}).get(fw, [])
            for control in mapping:
                failed_control_ids.add(control["control"])
                all_controls.append({
                    **control,
                    "source": "CIEM",
                    "finding_id": risk_id,
                    "finding_title": finding.get("title", "")
                })
        
        # Calculate compliance score
        passing = sum(1 for c in all_controls if c["status"] == "pass")
        failing = sum(1 for c in all_controls if c["status"] == "fail")
        total_evaluated = passing + failing
        score = round((passing / total_evaluated * 100), 1) if total_evaluated > 0 else 100.0
        
        result[fw] = {
            "framework": fw_info.get("name", fw),
            "description": fw_info.get("description", ""),
            "compliance_score": score,
            "controls_evaluated": total_evaluated,
            "controls_passing": passing,
            "controls_failing": failing,
            "status": "compliant" if score >= 90 else ("at_risk" if score >= 70 else "non_compliant"),
            "failed_controls": [c for c in all_controls if c["status"] == "fail"],
            "passing_controls": [c for c in all_controls if c["status"] == "pass"],
        }
    
    return result


def get_compliance_dashboard(cspm_findings: List[Dict], ciem_findings: List[Dict]) -> Dict:
    """
    Generate real-time compliance dashboard data with scores across all frameworks.
    """
    compliance_map = map_findings_to_compliance(cspm_findings, ciem_findings)
    
    summary = {
        "overall_score": round(
            sum(fw["compliance_score"] for fw in compliance_map.values()) / len(compliance_map), 1
        ),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "frameworks": {}
    }
    
    for fw_key, fw_data in compliance_map.items():
        summary["frameworks"][fw_key] = {
            "name": fw_data["framework"],
            "score": fw_data["compliance_score"],
            "status": fw_data["status"],
            "passing": fw_data["controls_passing"],
            "failing": fw_data["controls_failing"],
            "total": fw_data["controls_evaluated"],
            "critical_gaps": [
                {
                    "control": c["control"],
                    "name": c["name"],
                    "source": c.get("source", "baseline"),
                    "finding": c.get("finding_title", "")
                }
                for c in fw_data["failed_controls"]
            ]
        }
    
    # Calculate risk trend (simulated — in production, you'd store historical data)
    summary["trend"] = {
        "direction": "improving" if summary["overall_score"] > 75 else "declining",
        "change_7d": round(summary["overall_score"] - 72.5, 1),  # Simulated comparison
    }
    
    return summary


def generate_compliance_report(
    cspm_findings: List[Dict],
    ciem_findings: List[Dict],
    ml_analysis: List[Dict],
    remediation_results: Optional[Dict] = None,
    format: str = "json"
) -> Dict:
    """
    Generate exportable compliance report in JSON or CSV format.
    Comprehensive report covering all findings, mappings, and remediation status.
    """
    report_id = f"RPT-{str(uuid.uuid4())[:8].upper()}"
    now = datetime.now(timezone.utc)
    
    compliance_map = map_findings_to_compliance(cspm_findings, ciem_findings)
    
    # Build comprehensive report
    report = {
        "report_id": report_id,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_type": "Cloud Security Compliance Assessment",
        "organization": "Ram Antivirus — Cloud Security Division",
        "period": {
            "from": now.strftime("%Y-%m-01T00:00:00Z"),
            "to": now.strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        
        # Executive Summary
        "executive_summary": {
            "overall_compliance_score": round(
                sum(fw["compliance_score"] for fw in compliance_map.values()) / len(compliance_map), 1
            ),
            "total_findings": len(cspm_findings) + len(ciem_findings),
            "critical_findings": sum(
                1 for f in cspm_findings if f.get("severity") == "critical"
            ) + sum(
                1 for f in ciem_findings if f.get("risk_level") == "critical"
            ),
            "ml_anomalies_detected": sum(1 for e in ml_analysis if e.get("is_anomaly")),
            "remediations_executed": remediation_results.get("remediations_triggered", 0) if remediation_results else 0,
        },
        
        # Framework compliance details
        "compliance_by_framework": {},
        
        # Detailed findings
        "cspm_findings": cspm_findings,
        "ciem_findings": ciem_findings,
        
        # ML Analysis Summary
        "ml_analysis_summary": {
            "total_events_analyzed": len(ml_analysis),
            "anomalies_detected": sum(1 for e in ml_analysis if e.get("is_anomaly")),
            "severity_distribution": {
                "critical": sum(1 for e in ml_analysis if e.get("ml_severity") == "Critical"),
                "high": sum(1 for e in ml_analysis if e.get("ml_severity") == "High"),
                "medium": sum(1 for e in ml_analysis if e.get("ml_severity") == "Medium"),
                "low": sum(1 for e in ml_analysis if e.get("ml_severity") == "Low"),
            },
            "model_info": {
                "algorithm": "Isolation Forest (PyOD)",
                "contamination": 0.15,
                "n_estimators": 100,
                "features": ["level", "bytes_transferred", "failed_attempts"]
            }
        },
        
        # Remediation status
        "remediation_summary": remediation_results if remediation_results else {"status": "not_executed"}
    }
    
    # Add framework details
    for fw_key, fw_data in compliance_map.items():
        report["compliance_by_framework"][fw_key] = {
            "framework_name": fw_data["framework"],
            "score": fw_data["compliance_score"],
            "status": fw_data["status"],
            "controls_passing": fw_data["controls_passing"],
            "controls_failing": fw_data["controls_failing"],
            "failed_controls_detail": fw_data["failed_controls"],
            "passing_controls_detail": fw_data["passing_controls"],
        }
    
    if format == "csv":
        return _report_to_csv(report)
    
    return report


def _report_to_csv(report: Dict) -> Dict:
    """Convert the compliance report to CSV format for export."""
    rows = []
    
    # Framework summary rows
    for fw_key, fw_data in report["compliance_by_framework"].items():
        for control in fw_data.get("failed_controls_detail", []):
            rows.append({
                "Report ID": report["report_id"],
                "Generated At": report["generated_at"],
                "Framework": fw_key,
                "Control ID": control.get("control", ""),
                "Control Name": control.get("name", ""),
                "Status": control.get("status", ""),
                "Source": control.get("source", ""),
                "Finding ID": control.get("finding_id", ""),
                "Finding Title": control.get("finding_title", ""),
                "Description": control.get("description", "")
            })
        for control in fw_data.get("passing_controls_detail", []):
            rows.append({
                "Report ID": report["report_id"],
                "Generated At": report["generated_at"],
                "Framework": fw_key,
                "Control ID": control.get("control", ""),
                "Control Name": control.get("name", ""),
                "Status": control.get("status", ""),
                "Source": "baseline",
                "Finding ID": "",
                "Finding Title": "",
                "Description": control.get("description", "")
            })
    
    # Convert to CSV string
    output = StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    
    return {
        "report_id": report["report_id"],
        "format": "csv",
        "generated_at": report["generated_at"],
        "csv_data": output.getvalue(),
        "row_count": len(rows)
    }


if __name__ == "__main__":
    from cspm_engine import run_cspm_scan
    from ciem_engine import run_ciem_scan
    
    cspm = run_cspm_scan()
    ciem = run_ciem_scan()
    
    print("=== Compliance Dashboard ===")
    dashboard = get_compliance_dashboard(cspm, ciem)
    print(json.dumps(dashboard, indent=2))
    
    print("\n=== Compliance Report (JSON) ===")
    report = generate_compliance_report(cspm, ciem, [], format="json")
    print(json.dumps(report["executive_summary"], indent=2))
