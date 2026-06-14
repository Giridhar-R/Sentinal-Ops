"""
SentinelOps — Demo Scenario Definition
Pre-built credential-stuffing + lateral movement attack scenario using BOTS v3 data.
"""

from __future__ import annotations

DEMO_ALERT = {
    "alert_id": "ALERT-2025-0847",
    "alert_name": "Multiple Failed Logins Followed by Successful Authentication — Possible Credential Stuffing",
    "alert_severity": "high",
    "alert_raw": {
        "search_name": "Credential Stuffing Detection",
        "trigger_time": "2025-08-20T14:32:00Z",
        "source_ip": "40.80.148.42",
        "failed_count": 47,
        "success_count": 3,
        "targeted_accounts": ["svc_admin", "j.smith", "m.johnson"],
        "index": "botsv3",
        "sourcetype": "WinEventLog:Security",
        "notable_event_id": "NE-2025-08-20-001",
        "urgency": "high",
    },
}

DEMO_IOCS = {
    "attacker_ips": [
        {"ip": "40.80.148.42", "context": "Primary attack source, credential stuffing origin"},
        {"ip": "23.129.64.210", "context": "Secondary C2 callback IP observed in DNS queries"},
    ],
    "compromised_accounts": [
        {"username": "svc_admin", "context": "Service account — successful login after 47 failures"},
        {"username": "j.smith", "context": "Domain user — successful RDP login from attacker IP"},
    ],
    "affected_hosts": [
        {"hostname": "we8105desk", "role": "Workstation", "risk": "compromised"},
        {"hostname": "we9041srv", "role": "File Server", "risk": "compromised"},
        {"hostname": "venus", "role": "Domain Controller", "risk": "potentially_affected"},
        {"hostname": "wrk-aturing", "role": "Workstation", "risk": "potentially_affected"},
    ],
    "malicious_domains": [
        {"domain": "hildegardsfarm.com", "context": "C2 domain — DNS exfiltration observed"},
        {"domain": "cerberhhyed5frqa.xmfir0.win", "context": "Ransomware callback domain"},
    ],
    "malicious_hashes": [
        {
            "hash": "c99131e0169171b6f566e650f4d7c0b7",
            "type": "MD5",
            "filename": "svchost_update.exe",
            "context": "Dropped by PsExec on we9041srv"
        },
    ],
}

DEMO_ATTACK_TIMELINE = [
    {
        "time": "2025-08-20T14:15:00Z",
        "event": "Credential Stuffing Begins",
        "detail": "47 failed login attempts against multiple accounts from 40.80.148.42",
        "host": "venus",
        "mitre": "T1110.004",
    },
    {
        "time": "2025-08-20T14:28:00Z",
        "event": "Successful Authentication",
        "detail": "svc_admin account compromised — successful login from attacker IP",
        "host": "venus",
        "mitre": "T1078",
    },
    {
        "time": "2025-08-20T14:32:00Z",
        "event": "Alert Fires",
        "detail": "Splunk ES notable event triggered: credential stuffing detection rule",
        "host": "venus",
        "mitre": "N/A",
    },
    {
        "time": "2025-08-20T14:35:00Z",
        "event": "Lateral Movement — PsExec",
        "detail": "PsExec executed from venus targeting we8105desk using svc_admin credentials",
        "host": "we8105desk",
        "mitre": "T1570",
    },
    {
        "time": "2025-08-20T14:38:00Z",
        "event": "Malware Dropped",
        "detail": "svchost_update.exe dropped on we8105desk (MD5: c99131e0169171b6f566e650f4d7c0b7)",
        "host": "we8105desk",
        "mitre": "T1105",
    },
    {
        "time": "2025-08-20T14:42:00Z",
        "event": "Privilege Escalation",
        "detail": "j.smith added to Domain Admins group on venus",
        "host": "venus",
        "mitre": "T1078.002",
    },
    {
        "time": "2025-08-20T14:45:00Z",
        "event": "Lateral Movement — RDP",
        "detail": "RDP session initiated from we8105desk to we9041srv using j.smith credentials",
        "host": "we9041srv",
        "mitre": "T1021.001",
    },
    {
        "time": "2025-08-20T14:50:00Z",
        "event": "C2 Communication",
        "detail": "DNS queries to hildegardsfarm.com detected from we9041srv",
        "host": "we9041srv",
        "mitre": "T1071.004",
    },
    {
        "time": "2025-08-20T14:55:00Z",
        "event": "Data Staging",
        "detail": "Large file archive created on we9041srv: sensitive_data.7z (842MB)",
        "host": "we9041srv",
        "mitre": "T1074.001",
    },
    {
        "time": "2025-08-20T15:02:00Z",
        "event": "Scheduled Task Persistence",
        "detail": "Scheduled task 'WindowsUpdate' created for persistence on we8105desk",
        "host": "we8105desk",
        "mitre": "T1053.005",
    },
]

DEMO_MITRE_TECHNIQUES = [
    {"id": "T1110.004", "name": "Credential Stuffing", "tactic": "Credential Access"},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    {"id": "T1078.002", "name": "Domain Accounts", "tactic": "Privilege Escalation"},
    {"id": "T1071.004", "name": "DNS", "tactic": "Command and Control"},
    {"id": "T1074.001", "name": "Local Data Staging", "tactic": "Collection"},
    {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
]
