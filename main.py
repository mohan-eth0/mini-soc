#!/usr/bin/env python3

from collectors import ssh_journal, ssh_authlog, ssh_advanced
from engine import rule_engine, alert_engine
from engine.email_notifier import send_incident_email

import subprocess
import time
import uuid
import json
from pathlib import Path
from collections import defaultdict

ENABLE_RESPONSE = False  # keep disabled for safety

LAST_RUN_FILE = Path("state/last_run.json")


# =========================
# State helpers
# =========================

def get_last_run_time():
    if not LAST_RUN_FILE.exists():
        return 0
    try:
        with open(LAST_RUN_FILE) as f:
            return json.load(f).get("last_run", 0)
    except Exception:
        return 0


def update_last_run_time(ts):
    with open(LAST_RUN_FILE, "w") as f:
        json.dump({"last_run": ts}, f)


# =========================
# Collection
# =========================

def collect_events():
    events = []
    events += ssh_journal.collect()
    events += ssh_authlog.collect()
    events += ssh_advanced.collect()
    return events


# =========================
# Aggregation
# =========================

def aggregate_incidents(incidents):
    """
    Aggregate incidents by (ip, rule) to reduce alert noise.
    """
    agg = defaultdict(lambda: {
        "count": 0,
        "severity": "LOW"
    })

    for inc in incidents:
        ip = inc.get("ip")
        rule = inc.get("rule")
        key = (ip, rule)

        agg[key]["count"] += inc.get("count", 1)

        if inc.get("severity") == "HIGH":
            agg[key]["severity"] = "HIGH"

    aggregated = []
    for (ip, rule), data in agg.items():
        aggregated.append({
            "ip": ip,
            "rule": rule,
            "count": data["count"],
            "severity": data["severity"],
        })

    return aggregated


# =========================
# Normalization
# =========================

def normalize_incident(incident):
    """
    Convert aggregated incident into SOC-style incident.
    """
    return {
        "incident_id": f"INC-{uuid.uuid4().hex[:8]}",
        "alert_time": int(time.time()),
        "source_ip": incident.get("ip", "unknown"),
        "severity": incident.get("severity", "UNKNOWN"),
        "confidence": "unknown",
        "signals": [
            {
                "rule": incident.get("rule", "UNKNOWN"),
                "count": incident.get("count", 1),
                "mitre": "N/A"
            }
        ]
    }


# =========================
# Main
# =========================

def main():
    print("[*] Mini-SOC starting")

    last_run = get_last_run_time()

    # 1. Collect logs
    events = collect_events()
    print(f"[*] Collected {len(events)} events")

    # 2. Detect
    raw_incidents = rule_engine.evaluate(events)
    print(f"[*] Raw detections: {len(raw_incidents)}")

    # 3. Aggregate
    aggregated = aggregate_incidents(raw_incidents)
    print(f"[*] Aggregated incidents: {len(aggregated)}")

    # 4. Normalize + NEW-only alerting
    for incident in aggregated:
        soc_incident = normalize_incident(incident)

        # 🔒 ONLY NEW INCIDENTS
        if soc_incident["alert_time"] <= last_run:
            continue

        alert_engine.send(soc_incident)

        # Email escalation
        if soc_incident["severity"] in ("HIGH", "CRITICAL"):
            send_incident_email(soc_incident)

        # Optional response
        if ENABLE_RESPONSE and soc_incident["severity"] in ("HIGH", "CRITICAL"):
            subprocess.call(
                ["sudo", "./response/self_heal.sh", soc_incident["source_ip"]]
            )

    # 5. Update run state (VERY IMPORTANT)
    update_last_run_time(int(time.time()))

    print("[*] Mini-SOC run complete")


if __name__ == "__main__":
    main()

