#!/usr/bin/env python3
import time
import sqlite3
import os
from collections import defaultdict, deque

# =========================
# Database
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
            severity TEXT,
            confidence REAL,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()


def persist_incident(rule, ip, severity, confidence, details):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO incidents (ts, rule, source_ip, severity, confidence, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        int(time.time()),
        rule,
        ip,
        severity,
        confidence,
        str(details)
    ))
    conn.commit()
    conn.close()


init_db()

# =========================
# State
# =========================
SSH_FAILS = defaultdict(deque)
SSH_LAST_FAIL = {}
PORT_HITS = defaultdict(set)
SUDO_FAILS = defaultdict(deque)

# =========================
# Thresholds
# =========================
SSH_FAIL_THRESHOLD = 5
SUDO_FAIL_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10
SSH_SUCCESS_WINDOW = 600

# =========================
# Rule Engine
# =========================
def evaluate(events):
    detections = []
    port_scan_alerted = set()   # 🔒 prevents duplicate port-scan alerts per run

    for event in events:
        etype = event.get("type")
        ip = event.get("ip")
        ts = int(event.get("timestamp", time.time()))

        # ---------------- SSH brute force ----------------
        if etype == "ssh_failed" and ip:
            SSH_FAILS[ip].append(ts)

            if len(SSH_FAILS[ip]) >= SSH_FAIL_THRESHOLD:
                detections.append({
                    "rule": "SSH_BRUTE_FORCE",
                    "ip": ip,
                    "severity": "HIGH",
                    "count": len(SSH_FAILS[ip])
                })
                persist_incident(
                    "SSH_BRUTE_FORCE", ip, "HIGH", 0.9, SSH_FAILS[ip]
                )
                SSH_FAILS[ip].clear()

            SSH_LAST_FAIL[ip] = ts

        # ---------------- SSH success after fail ----------------
        elif etype == "ssh_success" and ip:
            last_fail = SSH_LAST_FAIL.get(ip)
            if last_fail and ts - last_fail <= SSH_SUCCESS_WINDOW:
                detections.append({
                    "rule": "SSH_SUCCESS_AFTER_FAIL",
                    "ip": ip,
                    "severity": "HIGH",
                    "count": 1
                })
                persist_incident(
                    "SSH_SUCCESS_AFTER_FAIL", ip, "HIGH", 0.9, {}
                )
                SSH_LAST_FAIL.pop(ip, None)

        # ---------------- Port scan ----------------
        elif etype == "port_hit" and ip:
            if ip in port_scan_alerted:
                continue

            PORT_HITS[ip].add(event.get("port"))

            if len(PORT_HITS[ip]) >= PORT_SCAN_THRESHOLD:
                detections.append({
                    "rule": "PORT_SCAN",
                    "ip": ip,
                    "severity": "HIGH",
                    "count": len(PORT_HITS[ip])
                })
                persist_incident(
                    "PORT_SCAN", ip, "HIGH", 0.9, list(PORT_HITS[ip])
                )
                port_scan_alerted.add(ip)

        # ---------------- Sudo brute force ----------------
        elif etype == "sudo_failed" and ip:
            SUDO_FAILS[ip].append(ts)

            if len(SUDO_FAILS[ip]) >= SUDO_FAIL_THRESHOLD:
                detections.append({
                    "rule": "SUDO_BRUTE_FORCE",
                    "ip": ip,
                    "severity": "HIGH",
                    "count": len(SUDO_FAILS[ip])
                })
                persist_incident(
                    "SUDO_BRUTE_FORCE", ip, "HIGH", 0.9, SUDO_FAILS[ip]
                )
                SUDO_FAILS[ip].clear()

        # ---------------- New user ----------------
        elif etype == "new_user":
            detections.append({
                "rule": "NEW_USER_CREATED",
                "ip": "localhost",
                "severity": "MEDIUM",
                "count": 1
            })
            persist_incident(
                "NEW_USER_CREATED", "localhost", "MEDIUM", 0.8, event
            )

    return detections


# =========================
# Query helper
# =========================
def get_recent_incidents(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT ts, rule, source_ip, severity, confidence, details
        FROM incidents
        ORDER BY ts DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

