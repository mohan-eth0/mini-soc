#!/usr/bin/env python3

from collectors import ssh_journal, ssh_authlog, ssh_advanced
from engine import rule_engine, alert_engine
import subprocess

ENABLE_RESPONSE = False  # keep false for now


def collect_events():
    events = []

    events += ssh_journal.collect()
    events += ssh_authlog.collect()
    events += ssh_advanced.collect()

    return events


def main():
    print("[*] Mini-SOC starting")

    events = collect_events()
    print(f"[*] Collected {len(events)} events")

    detections = rule_engine.evaluate(events)
    print(f"[*] Detections: {len(detections)}")

    for d in detections:
        alert_engine.send(d)

        if ENABLE_RESPONSE and d.get("severity") == "HIGH":
            subprocess.call(
                ["sudo", "./response/self_heal.sh", d["ip"]]
            )

    print("[*] Mini-SOC run complete")


if __name__ == "__main__":
    main()
