#!/usr/bin/env python3
"""
Rule Engine
-----------
SOC-grade incident correlation engine.

Key features:
- Sliding window detections
- Dynamic severity scoring
- Confidence scoring
- MITRE-aware signals
- Incident-level correlation (SIEM/SOAR model)
"""

import time
import sqlite3
import os
from collections import defaultdict, deque

# =========================
# Database configuration
# =========================
DB_PATH = os.path.expanduser("~/security-projects/mini-soc/incidents.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER,
            incident_id TEXT,
            source_ip TEXT,
            severity TEXT,
            confidence REAL,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()


def persist_incident(incident):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO incidents (ts, incident_id, source_ip, severity, confidence, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            int(time.time()),
            incident["incident_id"],
            incident["source_ip"],
            incident["severity"],
            incident["confidence"],
            str(incident["signals"])
        )
    )
    conn.commit()
    conn.close()


init_db()

# =========================
# Sliding window memory
# =========================
SSH_FAILS = defaultdict(deque)
SSH_LAST_FAIL = {}
PORT_HITS = defaultdict(deque)
SUDO_FAILS = defaultdict(deque)

# =========================
# Thresholds
# =========================
SSH_FAIL_THRESHOLD = 5
SSH_FAIL_WINDOW = 300

SUDO_FAIL_THRESHOLD = 5
SUDO_FAIL_WINDOW = 300

PORT_SCAN_THRESHOLD = 10
SSH_SUCCESS_WINDOW = 600

# =========================
# Incident store
# =========================
INCIDENTS = {}

# =========================
# Utility helpers
# =========================
def _cleanup(dq, window, now):
    while dq and dq[0] < now - window:
        dq.popleft()


def severity_rank(sev):
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }.get(sev, 0)


def calculate_severity(count):
    if count > 20:
        return "CRITICAL"
    elif count > 10:
        return "HIGH"
    else:
        return "MEDIUM"


def calculate_confidence(count, max_attempts=20):
    return round(min(1.0, count / max_attempts), 2)


# =========================
# Incident helpers
# =========================
def generate_incident_id():
    date = time.strftime("%Y%m%d")
    seq = len(INCIDENTS) + 1
    return f"INC-{date}-{seq:03d}"


def get_incident(ip, ts):
    if ip not in INCIDENTS:
        INCIDENTS[ip] = {
            "incident_id": generate_incident_id(),
            "source_ip": ip,
            "severity": "LOW",
            "confidence": 0.0,
            "first_seen": ts,
            "last_seen": ts,
            "alert_time": ts,
            "signals": []
        }
    return INCIDENTS[ip]


def add_signal(incident, rule, count, severity, confidence, mitre_id):
    incident["last_seen"] = int(time.time())

    # Escalate severity
    if severity_rank(severity) > severity_rank(incident["severity"]):
        incident["severity"] = severity
        incident["alert_time"] = incident["last_seen"]

    # Max confidence wins
    incident["confidence"] = round(
        max(incident["confidence"], confidence), 2
    )

    # Merge signal
    for s in incident["signals"]:
        if s["rule"] == rule:
            s["count"] += count
            return

    incident["signals"].append({
        "rule": rule,
        "count": count,
        "mitre": mitre_id
    })


# =========================
# MAIN ENGINE
# =========================
def evaluate(events):
    PORT_HITS.clear()

    for event in events:
        etype = event.get("type")
        ip = event.get("ip")
        ts = int(event.get("timestamp", time.time()))

        if not ip:
            continue

        # -------------------------
        # SSH brute-force
        # -------------------------
        if etype == "ssh_failed":
            dq = SSH_FAILS[ip]
            dq.append(ts)
            _cleanup(dq, SSH_FAIL_WINDOW, ts)

            if len(dq) >= SSH_FAIL_THRESHOLD:
                count = len(dq)
                severity = calculate_severity(count)
                confidence = calculate_confidence(count)

                incident = get_incident(ip, ts)
                add_signal(
                    incident,
                    rule="SSH_BRUTE_FORCE",
                    count=count,
                    severity=severity,
                    confidence=confidence,
                    mitre_id="T1110"
                )

                dq.clear()

            SSH_LAST_FAIL[ip] = ts

        # -------------------------
        # SSH success after failure
        # -------------------------
        elif etype == "ssh_success":
            last_fail = SSH_LAST_FAIL.get(ip)
            if last_fail and (ts - last_fail) <= SSH_SUCCESS_WINDOW:
                incident = get_incident(ip, ts)
                add_signal(
                    incident,
                    rule="SSH_SUCCESS_AFTER_FAIL",
                    count=1,
                    severity="HIGH",
                    confidence=0.9,
                    mitre_id="T1078"
                )

                SSH_LAST_FAIL.pop(ip, None)

        # -------------------------
        # Port hits
        # -------------------------
        elif etype == "port_hit":
            port = event.get("port")
            if port is not None:
                PORT_HITS[ip].append((ts, port))

        # -------------------------
        # Sudo brute-force
        # -------------------------
        elif etype == "sudo_failed":
            dq = SUDO_FAILS[ip]
            dq.append(ts)
            _cleanup(dq, SUDO_FAIL_WINDOW, ts)

            if len(dq) >= SUDO_FAIL_THRESHOLD:
                count = len(dq)
                severity = calculate_severity(count)
                confidence = calculate_confidence(count)

                incident = get_incident(ip, ts)
                add_signal(
                    incident,
                    rule="SUDO_BRUTE_FORCE",
                    count=count,
                    severity=severity,
                    confidence=confidence,
                    mitre_id="T1548"
                )

                dq.clear()

    # -------------------------
    # Batch PORT SCAN
    # -------------------------
    for ip, dq in PORT_HITS.items():
        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            count = len(unique_ports)
            severity = calculate_severity(count)
            confidence = calculate_confidence(count, max_attempts=50)

            incident = get_incident(ip, int(time.time()))
            add_signal(
                incident,
                rule="PORT_SCAN",
                count=count,
                severity=severity,
                confidence=confidence,
                mitre_id="T1046"
            )

    # -------------------------
    # Finalize incidents
    # -------------------------
    final_incidents = []

    for incident in INCIDENTS.values():
        persist_incident(incident)
        final_incidents.append(incident)

    return final_incidents


# =========================
# Dashboard helper
# =========================
def get_recent_incidents(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT ts, incident_id, source_ip, severity, confidence, details
        FROM incidents
        ORDER BY ts DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

