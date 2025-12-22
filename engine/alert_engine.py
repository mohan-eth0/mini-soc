#!/usr/bin/env python3
"""
Alert Engine
Responsible only for presenting detections to the analyst.
"""

from datetime import datetime


def send(detection: dict):
    """
    Print a SOC-style alert to stdout.
    """

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rule = detection.get("rule", "UNKNOWN")
    severity = detection.get("severity", "LOW")
    ip = detection.get("ip", "N/A")

    print("=" * 70)
    print(f"[ALERT] {rule}")
    print(f" Time      : {ts}")
    print(f" Severity  : {severity}")
    print(f" Source IP: {ip}")

    # Print remaining context
    for k, v in detection.items():
        if k not in ("rule", "severity", "ip"):
            print(f" {k}: {v}")

    print("=" * 70)
