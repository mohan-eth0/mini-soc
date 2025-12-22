#!/usr/bin/env python3
def collect():
    """
    Stub collector.
    auth.log is not used on Debian 12.
    """
    return []
"""
PRO-Level SSH Monitor
Features:
 - Show live SSH connections (ss -tp)
 - Show what remote users are doing (who + ps by TTY + journalctl -u ssh --since)
 - Detect suspicious behaviour:
     * too many commands (heuristic based on processes spawned under user's shell)
     * sudo failures (journalctl SYSLOG_IDENTIFIER=sudo)
     * editing sensitive files (editor processes with sensitive paths)
     * port scan tools run by logged-in users (nmap/masscan/etc)

Run as root (recommended) for full visibility. Tested on Linux with systemd.

Usage:
  sudo python3 pro_ssh_monitor.py --since "1 hour ago" --cmd-threshold 50

"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from collections import defaultdict, Counter
from datetime import datetime

SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/sudoers",
]
SCANNER_SIGNS = ["nmap", "masscan", "zmap", "unicornscan", "fping"]
EDITORS = ["vi", "vim", "nano", "emacs", "sed"]

# Helpers

def run(cmd, capture=True, text=True):
    try:
        if capture:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
            return out.decode('utf-8', errors='ignore')
        else:
            subprocess.check_call(cmd, shell=True)
            return ""
    except subprocess.CalledProcessError:
        return ""


def parse_ss_for_sshd():
    """Return list of dicts: [{pid, local, remote, user, state, process_desc}]"""
    out = run("ss -tp")
    lines = out.splitlines()
    results = []
    for line in lines:
        if 'sshd' in line:
            # Example line: ESTAB 0 0 192.168.1.2:55846 192.168.1.10:22 users:(("sshd",pid=1234,fd=3))
            parts = line.split()
            state = parts[0]
            try:
                local = parts[3]
                remote = parts[4]
            except Exception:
                # fallback
                local = parts[-2] if len(parts) >= 2 else ''
                remote = parts[-1] if len(parts) >= 1 else ''
            m = re.search(r'users:\(\("(?P<proc>[^\"]+)",pid=(?P<pid>\d+)', line)
            pid = None
            proc = None
            if m:
                proc = m.group('proc')
                pid = int(m.group('pid'))
            results.append({
                'state': state,
                'local': local,
                'remote': remote,
                'pid': pid,
                'process': proc,
                'raw': line.strip(),
            })
    return results


def journal_lines_for_ssh(since):
    # Use json output for parsing
    cmd = f"journalctl -u ssh -o json --since {shlex.quote(since)}"
    out = run(cmd)
    items = []
    for raw in out.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            j = json.loads(raw)
            items.append(j)
        except Exception:
            # fallback: keep raw message
            items.append({'MESSAGE': raw})
    return items


def journal_for_sudo(since):
    cmd = f"journalctl SYSLOG_IDENTIFIER=sudo -o json --since {shlex.quote(since)}"
    out = run(cmd)
    items = []
    for raw in out.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            items.append(json.loads(raw))
        except Exception:
            items.append({'MESSAGE': raw})
    return items


def parse_who():
    out = run('who')
    entries = []
    for line in out.splitlines():
        # username pts/0 2025-11-29 13:20 (192.168.1.100)
        parts = line.split()
        if len(parts) >= 2:
            user = parts[0]
            tty = parts[1]
            host = parts[4].strip('()') if len(parts) >= 5 else None
            entries.append({'user': user, 'tty': tty, 'host': host, 'raw': line})
    return entries


def ps_by_tty(tty):
    out = run(f"ps -t {shlex.quote(tty)} -o pid,ppid,cmd --no-headers")
    procs = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid_ppid, cmd = line.split(None, 2)[0:2], ' '.join(line.split(None, 2)[2:]) if len(line.split(None,2))>2 else ''
            # fallback parse
            sp = line.split(None, 2)
            pid = int(sp[0])
            ppid = int(sp[1]) if len(sp) > 1 else None
            cmd = sp[2] if len(sp) > 2 else ''
            procs.append({'pid': pid, 'ppid': ppid, 'cmd': cmd, 'raw': line})
        except Exception:
            continue
    return procs


def detect_editing_sensitive(procs):
    alerts = []
    for p in procs:
        cmd = p.get('cmd','')
        for ed in EDITORS:
            if re.search(r'\b' + re.escape(ed) + r'\b', cmd):
                for sp in SENSITIVE_PATHS:
                    if sp in cmd:
                        alerts.append((p, ed, sp))
    return alerts


def detect_scanner_processes(procs):
    alerts = []
    for p in procs:
        cmd = p.get('cmd','').lower()
        for sig in SCANNER_SIGNS:
            if sig in cmd:
                alerts.append((p, sig))
    return alerts


def detect_too_many_commands(shell_pid, threshold=100):
    # heuristic: count number of child processes of shell pid
    out = run(f"pgrep -P {shell_pid} -l")
    lines = out.splitlines()
    cnt = len(lines)
    return cnt, cnt > threshold


def analyze(since, cmd_threshold):
    print("\n[+] Live SSH connections (ss -tp):\n")
    live = parse_ss_for_sshd()
    if not live:
        print("No active sshd connections found via ss -tp\n")
    else:
        for c in live:
            print(f"{c['raw']}")
    
    print("\n[+] Recent journal (ssh) entries since {}:\n".format(since))
    j = journal_lines_for_ssh(since)
    if not j:
        print("No journal ssh entries found.\n")
    else:
        # show compact summary: timestamp, message
        for it in j[-50:]:
            ts = it.get('__REALTIME_TIMESTAMP') or it.get('__MONOTONIC_TIMESTAMP') or it.get('_SOURCE_REALTIME_TIMESTAMP')
            msg = it.get('MESSAGE') if isinstance(it, dict) else str(it)
            if isinstance(msg, str) and len(msg) > 250:
                msg = msg[:247] + '...'
            print(msg)

    print("\n[+] What remote users are doing (who + ps by tty):\n")
    who = parse_who()
    if not who:
        print("No interactive logged-in users found (who).\n")
    else:
        for ent in who:
            print(f"User: {ent['user']} tty={ent['tty']} host={ent.get('host')}")
            procs = ps_by_tty(ent['tty'])
            if not procs:
                print("  (no processes visible on this tty)\n")
                continue
            for p in procs:
                print(f"  {p['pid']} PPID={p.get('ppid')} CMD={p.get('cmd')}")
            # heuristic: shell pid is the smallest ppid? try to detect: shell is often a parent with cmd 'bash' or 'sh'
            shell_pid = None
            for p in procs:
                if re.search(r'\b(bash|sh|zsh|ksh)\b', p.get('cmd','')):
                    shell_pid = p['pid']
                    break
            if shell_pid:
                cnt, too_many = detect_too_many_commands(shell_pid, threshold=cmd_threshold)
                print(f"  -> child processes count under shell {shell_pid}: {cnt} {'(too many)' if too_many else ''}")
            # detect editing sensitive files
            edits = detect_editing_sensitive(procs)
            for p, ed, sp in edits:
                print(f"  !! Editor {ed} editing sensitive file {sp} (pid {p['pid']})")
            # detect scanners
            scans = detect_scanner_processes(procs)
            for p, sig in scans:
                print(f"  !! Scanner process detected: {sig} in {p['cmd']} (pid {p['pid']})")
            print("")

    print("\n[+] Sudo journal entries (since {}):\n".format(since))
    sud = journal_for_sudo(since)
    if not sud:
        print("No sudo events found.\n")
    else:
        fail_count = 0
        total = 0
        for it in sud:
            total += 1
            msg = it.get('MESSAGE', '')
            print(msg)
            if re.search(r'authentication failure|incorrect password|sudo: .*: authentication failure', msg, re.I):
                fail_count += 1
        if fail_count:
            print(f"\n  => Found {fail_count} sudo authentication failures out of {total} sudo events\n")

    # Additional: scan overall process list for scanners or editors editing sensitive files (system-wide)
    print("\n[+] System-wide suspicious processes check:\n")
    ps_all = run("ps aux --no-heading")
    suspicious = []
    for line in ps_all.splitlines():
        low = line.lower()
        for sig in SCANNER_SIGNS:
            if sig in low and 'grep' not in low:
                suspicious.append(line)
        for ed in EDITORS:
            if re.search(r'\b' + re.escape(ed) + r'\b', low):
                for sp in SENSITIVE_PATHS:
                    if sp in low:
                        suspicious.append(line)
    if suspicious:
        for s in suspicious:
            print("  "+s)
    else:
        print("  No obvious scanner/editor processes found system-wide.\n")


def main():
    parser = argparse.ArgumentParser(description='PRO SSH Monitor')
    parser.add_argument('--since', default='1 hour ago', help='journalctl since (quoted)')
    parser.add_argument('--cmd-threshold', type=int, default=50, help='threshold for "too many commands" heuristic')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Warning: some information may be missing when not run as root. Consider running with sudo.")

    analyze(args.since, args.cmd_threshold)

if __name__ == '__main__':
    main()
