#!/usr/bin/env python3

import subprocess
import re
import time

# -------- Regex patterns --------
RE_FAILED = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

RE_ACCEPT = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

RE_PAM_FAIL = re.compile(
    r"authentication failure;.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+).*user=(?P<user>\S+)"
)


def collect():
    """
    Debian 12 SSH collector (journald-based, normalized events)
    """
    events = []

    try:
        output = subprocess.check_output(
            [
                "journalctl",
                "_COMM=sshd",
                "-n", "300",
                "--no-pager"
            ],
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception:
        return events

    now = time.time()

    for line in output.splitlines():

        # PAM authentication failure
        m = RE_PAM_FAIL.search(line)
        if m:
            events.append({
                "source": "ssh",
                "type": "ssh_failed",
                "ip": m.group("ip"),
                "user": m.group("user"),
                "timestamp": now,
                "raw": line
            })
            continue

        # SSH failed password
        m = RE_FAILED.search(line)
        if m:
            events.append({
                "source": "ssh",
                "type": "ssh_failed",
                "ip": m.group("ip"),
                "user": m.group("user"),
                "timestamp": now,
                "raw": line
            })
            continue

        # SSH success
        m = RE_ACCEPT.search(line)
        if m:
            events.append({
                "source": "ssh",
                "type": "ssh_success",
                "ip": m.group("ip"),
                "user": m.group("user"),
                "timestamp": now,
                "raw": line
            })

    return events


if __name__ == "__main__":
    for e in collect():
        print(e)

