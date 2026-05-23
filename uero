import re
from collections import defaultdict
from datetime import datetime

# ── UERO v0.1 — Automated Log Threat Analyzer ──
# Detects: brute force, impossible travel, privilege escalation

LOG_FILE = "/home/zlats/security/labs/auth.log"
BRUTE_THRESHOLD = 5  # failed attempts before flagging

def parse_log(filepath):
    events = []
    with open(filepath, "r") as f:
        for line in f:
            events.append(line.strip())
    return events

def detect_brute_force(events):
    failures = defaultdict(int)
    findings = []
    for event in events:
        if "Failed password" in event:
            ip = re.search(r'from (\S+) port', event)
            user = re.search(r'for (\S+) from', event)
            if ip and user:
                key = (ip.group(1), user.group(1))
                failures[key] += 1
    for (ip, user), count in failures.items():
        if count >= BRUTE_THRESHOLD:
            findings.append({
                "type": "BRUTE FORCE",
                "ip": ip,
                "target_user": user,
                "attempts": count,
                "severity": "HIGH"
            })
    return findings

def detect_successful_after_brute(events):
    failed_ips = set()
    findings = []
    for event in events:
        if "Failed password" in event:
            ip = re.search(r'from (\S+) port', event)
            if ip:
                failed_ips.add(ip.group(1))
        if "Accepted password" in event:
            ip = re.search(r'from (\S+) port', event)
            user = re.search(r'for (\S+) from', event)
            if ip and user and ip.group(1) in failed_ips:
                findings.append({
                    "type": "BRUTE FORCE SUCCESS",
                    "ip": ip.group(1),
                    "compromised_user": user.group(1),
                    "severity": "CRITICAL"
                })
    return findings

def detect_impossible_travel(events):
    user_logins = defaultdict(list)
    findings = []
    for event in events:
        if "Accepted password" in event:
            ip = re.search(r'from (\S+) port', event)
            user = re.search(r'for (\S+) from', event)
            if ip and user:
                user_logins[user.group(1)].append(ip.group(1))
    for user, ips in user_logins.items():
        unique_ips = list(set(ips))
        if len(unique_ips) > 1:
            internal = [i for i in unique_ips if i.startswith("192.168") or i.startswith("10.")]
            external = [i for i in unique_ips if not i.startswith("192.168") and not i.startswith("10.")]
            if internal and external:
                findings.append({
                    "type": "IMPOSSIBLE TRAVEL",
                    "user": user,
                    "internal_ip": internal,
                    "external_ip": external,
                    "severity": "HIGH"
                })
    return findings

def detect_privilege_escalation(events):
    findings = []
    dangerous_commands = ["/etc/shadow", "/etc/passwd", "nc -e", "/bin/bash"]
    for event in events:
        if "sudo" in event:
            for cmd in dangerous_commands:
                if cmd in event:
                    findings.append({
                        "type": "PRIVILEGE ESCALATION",
                        "event": event,
                        "severity": "CRITICAL"
                    })
    return findings

def generate_report(all_findings):
    print("\n" + "="*60)
    print("  UERO v0.1 — THREAT ANALYSIS REPORT")
    print("  Analyst: Chris Beauvoir")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    if not all_findings:
        print("\n  No threats detected.")
        return

    critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    high = [f for f in all_findings if f.get("severity") == "HIGH"]

    print(f"\n  SUMMARY: {len(critical)} CRITICAL  |  {len(high)} HIGH\n")
    print("-"*60)

    for finding in all_findings:
        print(f"\n  [{finding['severity']}] {finding['type']}")
        for key, value in finding.items():
            if key not in ["type", "severity"]:
                print(f"    {key.upper()}: {value}")

    print("\n" + "="*60)
    print("  INDICATORS OF COMPROMISE (IOCs)")
    print("="*60)
    ips = set()
    users = set()
    for f in all_findings:
        if "ip" in f:
            ips.add(f["ip"])
        if "external_ip" in f:
            for ip in f["external_ip"]:
                ips.add(ip)
        if "compromised_user" in f:
            users.add(f["compromised_user"])
        if "user" in f:
            users.add(f["user"])
    print(f"\n  Malicious IPs:        {', '.join(ips) if ips else 'None'}")
    print(f"  Compromised Users:    {', '.join(users) if users else 'None'}")
    print("\n" + "="*60 + "\n")

# ── MAIN ──
events = parse_log(LOG_FILE)
all_findings = []
all_findings += detect_brute_force(events)
all_findings += detect_successful_after_brute(events)
all_findings += detect_impossible_travel(events)
all_findings += detect_privilege_escalation(events)
generate_report(all_findings)