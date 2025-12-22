#!/usr/bin/env python3
import time
from engine.rule_engine import evaluate, get_recent_incidents

now = time.time()

print("\n=== TEST 1: SSH brute-force ===")
events = [
    {"type": "ssh_failed", "ip": "10.1.1.75", "user": "root", "timestamp": now - 10},
    {"type": "ssh_failed", "ip": "10.1.1.75", "user": "root", "timestamp": now - 9},
    {"type": "ssh_failed", "ip": "10.1.1.75", "user": "root", "timestamp": now - 8},
    {"type": "ssh_failed", "ip": "10.1.1.75", "user": "root", "timestamp": now - 7},
    {"type": "ssh_failed", "ip": "10.1.1.75", "user": "root", "timestamp": now - 6},
]

detections = evaluate(events)
print("Detections:", detections)


print("\n=== TEST 2: SSH success after failures ===")
events = [
    {"type": "ssh_success", "ip": "10.1.1.75", "user": "root", "timestamp": now}
]

detections = evaluate(events)
print("Detections:", detections)


print("\n=== TEST 3: Port scan ===")
events = [
    {"type": "port_hit", "ip": "10.1.1.99", "port": p, "timestamp": now - 5}
    for p in range(20, 35)
]

detections = evaluate(events)
print("Detections:", detections)


print("\n=== TEST 4: Sudo brute-force ===")
events = [
    {"type": "sudo_failed", "ip": "10.1.1.55", "user": "admin", "timestamp": now - i}
    for i in range(6)
]

detections = evaluate(events)
print("Detections:", detections)


print("\n=== TEST 5: New user creation ===")
events = [
    {"type": "new_user", "user": "eviluser", "timestamp": now}
]

detections = evaluate(events)
print("Detections:", detections)


print("\n=== Recent Incidents in DB ===")
for row in get_recent_incidents(10):
    print(row)
