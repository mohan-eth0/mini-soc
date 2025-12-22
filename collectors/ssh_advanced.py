#!/usr/bin/env python3 
def collect():
    """
    Advanced collector placeholder.
    Will be implemented later.
    """
    return []

import subprocess
import re
from collections import defaultdict
import time
import os

THRESHOLD = 5

def get_failed_logins():
    """Parse SSH failed logins from journalctl"""
    CMD = ["journalctl", "-u", "ssh", "--since", "today"]
    logs = subprocess.check_output(CMD, text=True, errors='ignore')

    pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")

    failed_attempts = defaultdict(int)

    for line in logs.splitlines():
        m = pattern.search(line)
        if m:
            failed_attempts[m.group(1)] += 1

    return failed_attempts


def get_active_ssh_connections():
    """Show active SSH sessions (real-time)"""
    who_output = subprocess.check_output(["who"], text=True)
    active = []

    for line in who_output.splitlines():
        if "pts" in line or "ssh" in line:
            active.append(line)

    return active


def get_last_success_logins():
    """Show successful SSH login IPs"""
    logs = subprocess.check_output(
        ["journalctl", "-u", "ssh", "--since", "today"],
        text=True, errors="ignore"
    )
    pattern = re.compile(r"Accepted password.*from (\d+\.\d+\.\d+\.\d+)")
    
    success_ips = set()
    for line in logs.splitlines():
        m = pattern.search(line)
        if m:
            success_ips.add(m.group(1))

    return success_ips


def get_current_user_commands():
    """Show commands executed by users (basic approximation)"""
    cmds = subprocess.check_output(
        ["ps", "-eo", "user,pid,cmd", "--sort=pid"],
        text=True, errors="ignore"
    ).splitlines()

    tracked = []
    for line in cmds:
        if "pts" in line or "ssh" in line:
            tracked.append(line)

    return tracked


def monitor():
    failed = get_failed_logins()
    success_ips = get_last_success_logins()
    active_ssh = get_active_ssh_connections()
    user_cmds = get_current_user_commands()

    print("\n============ SSH SECURITY MONITOR ============")

    # --- Failed Attempts ---
    print("\n--- Failed SSH Login Attempts ---")
    for ip, count in failed.items():
        print(f"{ip}: {count} attempts")

    # --- Suspicious Alerts ---
    print("\n--- Suspicious IPs (Exceeded Threshold) ---")
    for ip, count in failed.items():
        if count >= THRESHOLD:
            print(f"[ALERT] {ip} exceeded {THRESHOLD} failed attempts!")
            if ip in success_ips:
                print(f"⚠️  [CRITICAL] {ip} also successfully logged in!")

    # --- Successful Logins ---
    print("\n--- Successful Logins Today ---")
    for ip in success_ips:
        print(f"Logged in: {ip}")

    # --- Active Live SSH Sessions ---
    print("\n--- LIVE SSH Sessions ---")
    if active_ssh:
        for session in active_ssh:
            print(session)
    else:
        print("No active SSH sessions.")

    # --- What They Are Doing ---
    print("\n--- Commands Executed By SSH Users (live) ---")
    for c in user_cmds:
        print(c)

    print("\n==============================================\n")


if __name__ == "__main__":
    monitor()

