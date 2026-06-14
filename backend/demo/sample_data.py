"""
SentinelOps — Demo Sample Data
Pre-baked SPL query results that mirror realistic Splunk data for demo mode.
Maps saia_generate_spl output patterns to realistic result sets.
"""

from __future__ import annotations

# Maps SPL query substrings to pre-baked result sets
# These match the SPL that saia_generate_spl returns in demo mode
_DEMO_RESULTS: dict[str, list[dict]] = {

    # ===== THREAT HUNTER QUERIES =====

    # TH-001: Failed authentication
    "Failed password": [
        {"src_ip": "40.80.148.42", "user": "svc_admin", "count": "23"},
        {"src_ip": "40.80.148.42", "user": "j.smith", "count": "15"},
        {"src_ip": "40.80.148.42", "user": "m.johnson", "count": "9"},
        {"src_ip": "10.0.2.15", "user": "admin_local", "count": "2"},
    ],

    # TH-002: Suspicious processes
    "wget OR curl": [
        {"host": "we8105desk", "user": "svc_admin", "process": "wget", "count": "3"},
        {"host": "we9041srv", "user": "j.smith", "process": "curl", "count": "2"},
        {"host": "we8105desk", "user": "svc_admin", "process": "chmod +x", "count": "1"},
    ],

    # TH-003: Successful login after failures
    "Accepted": [
        {"src_ip": "40.80.148.42", "user": "svc_admin", "count": "3"},
        {"src_ip": "10.0.2.101", "user": "j.smith", "count": "5"},
    ],

    # TH-004: Outbound connections
    "dest_ip!=10": [
        {"src_ip": "we8105desk", "dest_ip": "23.129.64.210", "dest_port": "443", "count": "89"},
        {"src_ip": "we9041srv", "dest_ip": "40.80.148.42", "dest_port": "8443", "count": "12"},
    ],

    # TH-005: Privilege escalation
    "sudo": [
        {"user": "svc_admin", "host": "we8105desk", "count": "8"},
        {"user": "j.smith", "host": "venus", "count": "4"},
    ],

    # TH-006: Lateral movement
    "dc(host)": [
        {"user": "svc_admin", "hosts": "3"},
        {"user": "j.smith", "hosts": "2"},
    ],

    # ===== RCA QUERIES =====

    # Saved search results
    "saved_search:": [
        {"src_ip": "40.80.148.42", "count": "47", "first_seen": "2025-08-20T14:15:00Z"},
        {"host": "we8105desk", "user": "svc_admin", "count": "3"},
    ],

    # Timeline correlation
    "correlate": [
        {"_time": "2025-08-20T14:15:00Z", "event": "Failed Login", "host": "venus", "user": "svc_admin"},
        {"_time": "2025-08-20T14:28:00Z", "event": "Successful Login", "host": "venus", "user": "svc_admin"},
        {"_time": "2025-08-20T14:35:00Z", "event": "PsExec Execution", "host": "we8105desk", "user": "svc_admin"},
        {"_time": "2025-08-20T14:42:00Z", "event": "Privilege Escalation", "host": "venus", "user": "j.smith"},
        {"_time": "2025-08-20T14:45:00Z", "event": "RDP Session", "host": "we9041srv", "user": "j.smith"},
    ],

    # ===== BLAST RADIUS QUERIES =====

    # Hosts connected to attacker
    "203.0.113.42": [
        {"host": "web-prod-01", "count": "156"},
        {"host": "app-srv-02", "count": "23"},
        {"host": "db-srv-01", "count": "4"},
    ],

    "40.80.148.42": [
        {"host": "venus", "count": "52"},
        {"host": "we8105desk", "count": "24"},
        {"host": "we9041srv", "count": "18"},
    ],

    # User authentication from compromised hosts
    "authenticated": [
        {"user": "svc_admin", "host": "we8105desk", "count": "24"},
        {"user": "j.smith", "host": "we9041srv", "count": "18"},
    ],

    # ===== REMEDIATION QUERIES =====

    # Verification queries
    "active sessions": [
        {"src_ip": "40.80.148.42", "active_sessions": "0", "last_seen": "2025-08-20T15:40:00Z"},
    ],

    # ===== FALLBACK QUERIES =====

    # Generic stats
    "stats count by sourcetype": [
        {"sourcetype": "linux_secure", "host": "venus", "count": "18234"},
        {"sourcetype": "syslog", "host": "we8105desk", "count": "12450"},
        {"sourcetype": "access_combined", "host": "web-prod-01", "count": "89234"},
    ],

    # Error rate
    "status>=500": [
        {"_time": "2025-08-20T14:30:00Z", "count": "12"},
        {"_time": "2025-08-20T14:31:00Z", "count": "28"},
        {"_time": "2025-08-20T14:32:00Z", "count": "45"},
    ],

    # DNS queries
    "query": [
        {"query": "hildegardsfarm.com", "count": "142"},
        {"query": "cerberhhyed5frqa.xmfir0.win", "count": "37"},
    ],

    # Legacy BOTS queries
    "EventCode=4625 OR EventCode=4624": [
        {"src_ip": "40.80.148.42", "failed_count": "47", "success_count": "3",
         "targeted_accounts": "svc_admin, j.smith, m.johnson"},
    ],
    "psexec": [
        {"Computer": "we8105desk", "User": "FROTHLY\\svc_admin",
         "Image": "C:\\Windows\\System32\\psexec.exe", "count": "3"},
    ],
}


def get_demo_results(spl_query: str) -> list[dict]:
    """
    Match an SPL query to pre-baked demo results.
    Uses substring matching against known query patterns.
    Falls back to a generic result for unmatched queries.
    """
    spl_lower = spl_query.lower()

    for pattern, results in _DEMO_RESULTS.items():
        if pattern.lower() in spl_lower:
            return results

    # Fallback: return generic results (so result_count > 0 and hunts produce findings)
    return [
        {"src_ip": "40.80.148.42", "user": "svc_admin", "host": "we8105desk", "count": "5"},
        {"src_ip": "10.0.2.101", "user": "j.smith", "host": "we9041srv", "count": "3"},
    ]
