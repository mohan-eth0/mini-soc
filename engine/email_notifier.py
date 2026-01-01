import json
import smtplib
import time
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# =========================
# Configuration
# =========================

CONFIG_PATH = Path("config/email.json")

SUPPRESSION_FILE = "state/email_suppression.json"
SUPPRESSION_WINDOW = 15 * 60  # 15 minutes


# =========================
# Helpers
# =========================

def load_email_config():
    if not CONFIG_PATH.exists():
        return None

    with open(CONFIG_PATH) as f:
        return json.load(f)


def is_suppressed(incident):
    """
    Suppress duplicate email alerts for same IP + rule
    within the suppression window.
    """
    key = f"{incident['source_ip']}:{incident['signals'][0]['rule']}"
    now = int(time.time())

    if not os.path.exists(SUPPRESSION_FILE):
        return False

    try:
        with open(SUPPRESSION_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        return False

    last_sent = data.get(key, 0)
    return (now - last_sent) < SUPPRESSION_WINDOW


def mark_email_sent(incident):
    """
    Record timestamp of sent email for suppression.
    """
    key = f"{incident['source_ip']}:{incident['signals'][0]['rule']}"
    now = int(time.time())

    data = {}
    if os.path.exists(SUPPRESSION_FILE):
        try:
            with open(SUPPRESSION_FILE, "r") as f:
                data = json.load(f)
        except Exception:
            data = {}

    data[key] = now

    with open(SUPPRESSION_FILE, "w") as f:
        json.dump(data, f)


# =========================
# Main Email Function
# =========================

def send_incident_email(incident):
    """
    Send SOC incident email with suppression to prevent duplicates.
    """

    # 1. Suppression check (MOST IMPORTANT)
    if is_suppressed(incident):
        print(f"[INFO] Email suppressed for {incident['source_ip']}")
        return

    # 2. Load config
    cfg = load_email_config()
    if not cfg or not cfg.get("enabled"):
        return

    # 3. Build email
    subject = f"[Mini-SOC] {incident['severity']} incident from {incident['source_ip']}"

    body = f"""
Incident ID : {incident['incident_id']}
Time        : {incident['alert_time']}
Source IP  : {incident['source_ip']}
Severity   : {incident['severity']}
Confidence : {incident.get('confidence', 'unknown')}

Signals:
"""

    for sig in incident["signals"]:
        body += f"- {sig['rule']} (count={sig['count']}) [{sig.get('mitre', 'N/A')}]\n"

    msg = MIMEMultipart()
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    # 4. Send email
    try:
        server = smtplib.SMTP(cfg["host"], cfg["port"])
        server.starttls()
        server.login(cfg["user"], cfg["password"])
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print("[WARN] Email send failed:", e)
        return

    # 5. Mark email sent (update suppression state)
    mark_email_sent(incident)

