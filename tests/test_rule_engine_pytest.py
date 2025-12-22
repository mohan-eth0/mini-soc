import time
import os
import sqlite3
import pytest

from engine.rule_engine import evaluate, get_recent_incidents, DB_PATH


# =========================
# Helper: clean database
# =========================
def clear_db():
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM incidents")
        conn.commit()
        conn.close()


# =========================
# Auto-reset before tests
# =========================
@pytest.fixture(autouse=True)
def reset_environment():
    clear_db()
    yield
    clear_db()


# =========================
# Tests
# =========================
def test_ssh_brute_force_detection():
    now = time.time()
    events = [
        {"type": "ssh_failed", "ip": "10.1.1.75", "timestamp": now - i}
        for i in range(5)
    ]

    detections = evaluate(events)

    assert len(detections) == 1
    assert detections[0]["rule"] == "SSH_BRUTE_FORCE"
    assert detections[0]["severity"] == "HIGH"


def test_ssh_success_after_fail():
    now = time.time()

    evaluate([
        {"type": "ssh_failed", "ip": "10.1.1.80", "timestamp": now - i}
        for i in range(5)
    ])

    detections = evaluate([
        {"type": "ssh_success", "ip": "10.1.1.80", "timestamp": now}
    ])

    assert len(detections) == 1
    assert detections[0]["rule"] == "SSH_SUCCESS_AFTER_FAIL"


def test_port_scan_detection():
    now = time.time()

    events = [
        {"type": "port_hit", "ip": "10.1.1.99", "port": p, "timestamp": now}
        for p in range(20, 35)
    ]

    detections = evaluate(events)

    assert len(detections) == 1
    assert detections[0]["rule"] == "PORT_SCAN"


def test_sudo_brute_force():
    now = time.time()

    events = [
        {"type": "sudo_failed", "ip": "10.1.1.55", "timestamp": now - i}
        for i in range(5)
    ]

    detections = evaluate(events)

    assert len(detections) == 1
    assert detections[0]["rule"] == "SUDO_BRUTE_FORCE"


def test_new_user_creation():
    detections = evaluate([
        {"type": "new_user", "user": "eviluser", "timestamp": time.time()}
    ])

    assert len(detections) == 1
    assert detections[0]["rule"] == "NEW_USER_CREATED"


def test_no_false_positive():
    detections = evaluate([
        {"type": "ssh_failed", "ip": "10.1.1.10", "timestamp": time.time()}
    ])

    assert detections == []


def test_incident_written_to_db():
    now = time.time()

    evaluate([
        {"type": "ssh_failed", "ip": "10.1.1.200", "timestamp": now - i}
        for i in range(5)
    ])

    incidents = get_recent_incidents(5)

    assert len(incidents) >= 1
    assert incidents[0][1] == "SSH_BRUTE_FORCE"
