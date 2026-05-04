"""
Email Alert Engine
Sends real email alerts via SMTP (Gmail/Outlook) or falls back to console log.
Configure via environment variables:
  ALERT_EMAIL_FROM    = sender email
  ALERT_EMAIL_PASS    = app password (Gmail: 16-char app password)
  ALERT_EMAIL_TO      = SOC/admin recipient email
  SMTP_HOST           = smtp.gmail.com (default)
  SMTP_PORT           = 587 (default)
"""
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from engines.db import log_alert

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", "")
EMAIL_PASS = os.environ.get("ALERT_EMAIL_PASS", "")
EMAIL_TO   = os.environ.get("ALERT_EMAIL_TO", "")


def send_alert_email(subject: str, body: str, recipient: str = "") -> dict:
    """
    Send a security alert email. Falls back to console log if SMTP not configured.
    Returns status dict.
    """
    to_addr = recipient or EMAIL_TO

    # Log to DB regardless
    log_alert(
        alert_type="email_alert",
        severity="high",
        message=f"{subject} | {body[:200]}",
        email_sent=bool(EMAIL_FROM and EMAIL_PASS and to_addr),
        recipient=to_addr
    )

    if not (EMAIL_FROM and EMAIL_PASS and to_addr):
        print(f"[ALERT — no SMTP configured] {subject}: {body}")
        return {"sent": False, "reason": "SMTP not configured — alert logged to DB only", "subject": subject}

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[RAM ANTIVIRUS ALERT] {subject}"
        msg["From"] = EMAIL_FROM
        msg["To"] = to_addr

        html = f"""
        <html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#f0f6fc;padding:20px;">
        <div style="max-width:600px;margin:auto;background:#161b22;border-radius:12px;padding:24px;border:1px solid #30363d;">
          <h2 style="color:#ef4444;">🚨 Ram Antivirus — Security Alert</h2>
          <h3 style="color:#f0f6fc;">{subject}</h3>
          <p style="color:#8b949e;">{body}</p>
          <hr style="border-color:#30363d;"/>
          <p style="color:#8b949e;font-size:12px;">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div></body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASS)
            server.sendmail(EMAIL_FROM, to_addr, msg.as_string())

        return {"sent": True, "recipient": to_addr, "subject": subject}

    except Exception as e:
        print(f"[ALERT EMAIL FAILED] {e}")
        return {"sent": False, "reason": str(e), "subject": subject}


def alert_soc(attack_type: str, event: dict) -> dict:
    """Send SOC alert for a detected attack event."""
    subject = f"CRITICAL: {attack_type.replace('_', ' ').title()} Detected"
    body = (
        f"Attack Type: {attack_type}\n"
        f"User: {event.get('user', 'unknown')}\n"
        f"Source IP: {event.get('src_ip', 'unknown')}\n"
        f"Service: {event.get('service', 'unknown')}\n"
        f"ML Score: {event.get('ml_anomaly_score', 'N/A')}\n"
        f"Description: {event.get('description', '')}"
    )
    return send_alert_email(subject, body)


def alert_remediation(playbook_name: str, status: str, steps_failed: int) -> dict:
    """Send alert when a remediation playbook completes or partially fails."""
    subject = f"Remediation {'Completed' if steps_failed == 0 else 'Partial Failure'}: {playbook_name}"
    body = f"Playbook: {playbook_name}\nStatus: {status}\nFailed Steps: {steps_failed}"
    return send_alert_email(subject, body)
