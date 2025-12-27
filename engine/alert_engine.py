#!/usr/bin/env python3
"""
Incident Presentation Engine
----------------------------
Displays SOC-style incidents (not raw alerts).
"""

import datetime


def present_incident(incident):
    ts = datetime.datetime.fromtimestamp(
        incident["alert_time"]
    ).strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 70)
    print(f"[INCIDENT] {incident['incident_id']}")
    print(f" Time      : {ts}")
    print(f" Source IP : {incident['source_ip']}")
    print(f" Severity  : {incident['severity']}")
    print(f" Confidence: {incident['confidence']}")
    print(" Signals   :")

    for sig in incident["signals"]:
        print(
            f"   - {sig['rule']} "
            f"(count={sig['count']}) "
            f"[{sig['mitre']}]"
        )

    print("=" * 70)


def send(incident):
    """
    Entry point used by main.py
    """
    present_incident(incident)

