#!/usr/bin/env python3

from collectors import ssh_journal, ssh_authlog, ssh_advanced
from engine import rule_engine, alert_engine
import subprocess
import time
import uuid
from collections import defaultdict

ENABLE_RESPONSE = False  # keep disabled for safety


def collect_events():
    events = []
    events += ssh_journal.collect()
    events += ssh_authlog.collect()
    events += ssh_advanced.collect()
    return events


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

        # Keep highest severity
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


def normalize_incident(incident):
    """
    Convert aggregated incident into SOC-style incident
    expected by alert_engine.
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


def main():
    print("[*] Mini-SOC starting")

    # 1. Collect logs
    events = collect_events()
    print(f"[*] Collected {len(events)} events")

    # 2. Detect + correlate (rule engine)
    raw_incidents = rule_engine.evaluate(events)
    print(f"[*] Raw detections: {len(raw_incidents)}")

    # 3. Aggregate (noise reduction)
    aggregated = aggregate_incidents(raw_incidents)
    print(f"[*] Aggregated incidents: {len(aggregated)}")

    # 4. Normalize + present
    for incident in aggregated:
        soc_incident = normalize_incident(incident)
        alert_engine.send(soc_incident)

        # Optional auto-response (disabled by default)
        if ENABLE_RESPONSE and soc_incident["severity"] in ("HIGH", "CRITICAL"):
            subprocess.call(
                ["sudo", "./response/self_heal.sh", soc_incident["source_ip"]]
            )

    print("[*] Mini-SOC run complete")


if __name__ == "__main__":
    main()

