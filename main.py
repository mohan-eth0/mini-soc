#!/usr/bin/env python3

from collectors import ssh_journal, ssh_authlog, ssh_advanced
from engine import rule_engine, alert_engine
from datetime import datetime
import subprocess

ENABLE_RESPONSE = False  # keep disabled for safety


def collect_events():
    events = []
    events += ssh_journal.collect()
    events += ssh_authlog.collect()
    events += ssh_advanced.collect()
    return events


def main():
    print("[*] Mini-SOC starting")

    # 1. Collect logs
    events = collect_events()
    print(f"[*] Collected {len(events)} events")

    # 2. Detect + correlate incidents
    incidents = rule_engine.evaluate(events)
    print(f"[*] Detections: {len(incidents)}")

    # 3. Present incidents
    for incident in incidents:
        alert_engine.send(incident)

        # Optional auto-response (incident-level)
        if ENABLE_RESPONSE and incident["severity"] in ("HIGH", "CRITICAL"):
            subprocess.call(
                ["sudo", "./response/self_heal.sh", incident["source_ip"]]
            )

    print("[*] Mini-SOC run complete")


if __name__ == "__main__":
    main()

