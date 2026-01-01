#!/usr/bin/env python3
"""
Incident Presentation & Notification Engine
-------------------------------------------
Displays SOC-style incidents and triggers notifications.
"""

import datetime
import json
import os

EMAIL_CFG = None

# Optional email config loader
cfg_path = os.path.join("config", "email.json")
if os.path.exists(cfg_path):
    try:
        with open(cfg_path) as f:
            EMAIL_CFG = json.load(f)
    except Exception:
        EMAIL_CFG = None


def present_incident(incident):
    ts = datetime.datetime.fromtimestamp(
        incident.get("alert_time", 0)
    ).strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 70)
    print(f"[INCIDENT] {incident.get('incident_id', 'N/A')}")
    print(f" Time      : {ts}")
    print(f" Source IP : {incident.get('source_ip', 'unknown')}")
    print(f" Severity  : {incident.get('severity', 'unknown')}")
    print(f" Confidence: {incident.get('confidence', 'unknown')}")
    print(" Signals   :")

    for sig in incident.get("signals", []):
        print(
            f"   - {sig.get('rule', 'unknown')} "
            f"(count={sig.get('count', 0)}) "
            f"[{sig.get('mitre', 'N/A')}]"
        )

    print("=" * 70)


def notify_incident(incident):
    """
    Trigger external notifications (email, webhook, etc.)
    """
    if not EMAIL_CFG:
        return

    if not EMAIL_CFG.get("enabled"):
        return

    # Only notify on high severity
    if incident.get("severity") not in ("HIGH", "CRITICAL"):
        return

    try:
        from engine.email_alert import send_email
        send_email(incident, EMAIL_CFG)
    except Exception as e:
        print(f"[WARN] Email notification failed: {e}")


def send(incident):
    """
    Entry point used by main.py
    """
    present_incident(incident)
    notify_incident(incident)

