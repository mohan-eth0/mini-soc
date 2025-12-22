#!/usr/bin/env python3
"""
Rule Engine
-----------
Transforms normalized security events into high-signal incidents.
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
            rule TEXT,
            source_ip TEXT,
            details TEXT,
            severity TEXT
        )
    """)
    conn.commit()
    conn.close()


def create_incident(rule, ip, details, severity):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO incidents (ts, rule, source_ip, details, severity)
        VALUES (?, ?, ?, ?, ?)
        """,
        (int(time.time()), rule, ip, details, severity)
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
# Detection thresholds
# =========================
SSH_FAIL_THRESHOLD = 5
SSH_FAIL_WINDOW = 300

PORT_SCAN_THRESHOLD = 10

SUDO_FAIL_THRESHOLD = 5
SUDO_FAIL_WINDOW = 300

SSH_SUCCESS_WINDOW = 600

# =========================
# Utility
# =========================
def _cleanup(dq, window, now):
    while dq and dq[0] < now - window:
        dq.popleft()


# =========================
# MAIN RULE ENGINE
# =========================
def evaluate(events):
    detections = []

    # Reset batch-only PORT_SCAN state
    PORT_HITS.clear()

    for event in events:
        etype = event.get("type")
        ip = event.get("ip")
        ts = event.get("timestamp", time.time())
        now = ts

        # SSH brute-force
        if etype == "ssh_failed" and ip:
            dq = SSH_FAILS[ip]
            dq.append(ts)
            _cleanup(dq, SSH_FAIL_WINDOW, now)

            if len(dq) >= SSH_FAIL_THRESHOLD:
                detections.append({
                    "rule": "SSH_BRUTE_FORCE",
                    "ip": ip,
                    "severity": "HIGH"
                })
                create_incident(
                    "SSH_BRUTE_FORCE",
                    ip,
                    f"{len(dq)} SSH failures",
                    "HIGH"
                )
                dq.clear()
            SSH_LAST_FAIL[ip] = ts

        # SSH success after failure
        elif etype == "ssh_success" and ip:
            last_fail = SSH_LAST_FAIL.get(ip)
            if last_fail and (now - last_fail) <= SSH_SUCCESS_WINDOW:
                detections.append({
                    "rule": "SSH_SUCCESS_AFTER_FAIL",
                    "ip": ip,
                    "severity": "MEDIUM"
                })
                create_incident(
                    "SSH_SUCCESS_AFTER_FAIL",
                    ip,
                    "Successful SSH login after failures",
                    "MEDIUM"
                )
                SSH_LAST_FAIL.pop(ip, None)

        # Collect port hits (batch)
        elif etype == "port_hit" and ip:
            port = event.get("port")
            if port is not None:
                PORT_HITS[ip].append((ts, port))

        # Sudo brute-force
        elif etype == "sudo_failed" and ip:
            dq = SUDO_FAILS[ip]
            dq.append(ts)
            _cleanup(dq, SUDO_FAIL_WINDOW, now)

            if len(dq) >= SUDO_FAIL_THRESHOLD:
                detections.append({
                    "rule": "SUDO_BRUTE_FORCE",
                    "ip": ip,
                    "severity": "HIGH"
                })
                create_incident(
                    "SUDO_BRUTE_FORCE",
                    ip,
                    "Multiple sudo authentication failures",
                    "HIGH"
                )
                dq.clear()

        # New user creation
        elif etype == "new_user":
            user = event.get("user", "unknown")
            detections.append({
                "rule": "NEW_USER_CREATED",
                "user": user,
                "severity": "MEDIUM"
            })
            create_incident(
                "NEW_USER_CREATED",
                None,
                f"New system user created: {user}",
                "MEDIUM"
            )

    # =========================
    # Batch PORT SCAN detection
    # =========================
    for ip, dq in PORT_HITS.items():
        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            detections.append({
                "rule": "PORT_SCAN",
                "ip": ip,
                "ports": sorted(unique_ports),
                "severity": "HIGH"
            })
            create_incident(
                "PORT_SCAN",
                ip,
                f"Port scan on ports: {sorted(unique_ports)}",
                "HIGH"
            )

    return detections


# =========================
# Dashboard helper
# =========================
def get_recent_incidents(limit=100):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT ts, rule, source_ip, details, severity
        FROM incidents
        ORDER BY ts DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

