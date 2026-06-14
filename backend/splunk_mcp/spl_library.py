"""
SentinelOps — SPL Query Library
Pre-built, parameterized SPL queries organized by MITRE ATT&CK tactic.
Designed for the BOTS v3 dataset.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class SPLQuery:
    """A parameterized SPL query with MITRE ATT&CK metadata."""

    name: str
    description: str
    mitre_tactic: str
    mitre_technique: str
    spl_template: str
    parameters: list[str]

    def render(self, **kwargs) -> str:
        """Render the SPL template with provided parameters."""
        spl = self.spl_template
        for key, value in kwargs.items():
            spl = spl.replace(f"{{{{{key}}}}}", str(value))
        return spl


# ============================================================
# Credential Access (TA0006)
# ============================================================

CREDENTIAL_STUFFING_DETECTION = SPLQuery(
    name="Credential Stuffing Detection",
    description="Detect credential stuffing by correlating multiple failed logins followed by a success from the same source IP",
    mitre_tactic="TA0006 - Credential Access",
    mitre_technique="T1110.004 - Credential Stuffing",
    spl_template="""index={{index}} sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| eval login_status=if(EventCode=4625, "failure", "success")
| stats count(eval(login_status="failure")) as failed_count
        count(eval(login_status="success")) as success_count
        values(Account_Name) as targeted_accounts
        earliest(_time) as first_attempt
        latest(_time) as last_attempt
        by src_ip
| where failed_count > {{threshold}} AND success_count > 0
| eval attack_duration=last_attempt - first_attempt
| sort - failed_count
| head {{max_results}}""",
    parameters=["index", "threshold", "max_results"],
)

BRUTE_FORCE_SINGLE_ACCOUNT = SPLQuery(
    name="Brute Force Against Single Account",
    description="Detect brute force attacks targeting a specific user account",
    mitre_tactic="TA0006 - Credential Access",
    mitre_technique="T1110.001 - Password Guessing",
    spl_template="""index={{index}} sourcetype="WinEventLog:Security" EventCode=4625
    Account_Name="{{target_user}}"
| stats count as attempt_count dc(src_ip) as unique_sources values(src_ip) as source_ips
        earliest(_time) as first_attempt latest(_time) as last_attempt
        by Account_Name
| where attempt_count > 5""",
    parameters=["index", "target_user"],
)

# ============================================================
# Lateral Movement (TA0008)
# ============================================================

LATERAL_MOVEMENT_PSEXEC = SPLQuery(
    name="PsExec Lateral Movement",
    description="Detect PsExec usage for lateral movement",
    mitre_tactic="TA0008 - Lateral Movement",
    mitre_technique="T1570 - Lateral Tool Transfer",
    spl_template="""index={{index}} (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
    (EventCode=1 OR EventCode=4688)
    (Image="*\\\\psexec*" OR CommandLine="*psexec*" OR ParentImage="*\\\\psexe*")
| stats count by Computer, User, Image, CommandLine, ParentImage
| sort - count""",
    parameters=["index"],
)

LATERAL_MOVEMENT_RDP = SPLQuery(
    name="RDP Lateral Movement",
    description="Detect suspicious RDP connections indicating lateral movement",
    mitre_tactic="TA0008 - Lateral Movement",
    mitre_technique="T1021.001 - Remote Desktop Protocol",
    spl_template="""index={{index}} sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count dc(Computer) as unique_targets values(Computer) as targets
        earliest(_time) as first_login latest(_time) as last_login
        by Account_Name, src_ip
| where unique_targets > 1
| sort - unique_targets""",
    parameters=["index"],
)

LATERAL_MOVEMENT_WMI = SPLQuery(
    name="WMI Lateral Movement",
    description="Detect WMI-based remote execution for lateral movement",
    mitre_tactic="TA0008 - Lateral Movement",
    mitre_technique="T1047 - Windows Management Instrumentation",
    spl_template="""index={{index}} (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
    (EventCode=1 OR EventCode=4688)
    (Image="*\\\\wmic*" OR CommandLine="*wmic*process*call*create*")
| stats count by Computer, User, CommandLine, ParentImage
| sort - count""",
    parameters=["index"],
)

# ============================================================
# Privilege Escalation (TA0004)
# ============================================================

PRIVILEGE_ESCALATION_ADMIN = SPLQuery(
    name="Admin Group Modification",
    description="Detect additions to privileged groups",
    mitre_tactic="TA0004 - Privilege Escalation",
    mitre_technique="T1078.002 - Domain Accounts",
    spl_template="""index={{index}} sourcetype="WinEventLog:Security"
    (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| stats count by Group_Name, MemberName, SubjectUserName, Computer
| sort - count""",
    parameters=["index"],
)

# ============================================================
# Persistence (TA0003)
# ============================================================

PERSISTENCE_SCHEDULED_TASK = SPLQuery(
    name="Scheduled Task Creation",
    description="Detect creation of scheduled tasks for persistence",
    mitre_tactic="TA0003 - Persistence",
    mitre_technique="T1053.005 - Scheduled Task",
    spl_template="""index={{index}} sourcetype="WinEventLog:Security" EventCode=4698
| stats count by TaskName, SubjectUserName, Computer
| sort - count""",
    parameters=["index"],
)

# ============================================================
# Network Analysis
# ============================================================

SUSPICIOUS_DNS_QUERIES = SPLQuery(
    name="Suspicious DNS Queries",
    description="Identify unusual or potentially malicious DNS queries",
    mitre_tactic="TA0011 - Command and Control",
    mitre_technique="T1071.004 - DNS",
    spl_template="""index={{index}} sourcetype="stream:dns"
| stats count dc(src_ip) as unique_sources by query
| where count > {{threshold}} OR len(query) > 50
| sort - count
| head {{max_results}}""",
    parameters=["index", "threshold", "max_results"],
)

NETWORK_CONNECTIONS_BY_HOST = SPLQuery(
    name="Network Connections by Host",
    description="Map outbound network connections for a specific host",
    mitre_tactic="TA0011 - Command and Control",
    mitre_technique="T1071 - Application Layer Protocol",
    spl_template="""index={{index}} sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=3 Computer="{{hostname}}"
| stats count by DestinationIp, DestinationPort, Image
| sort - count
| head {{max_results}}""",
    parameters=["index", "hostname", "max_results"],
)

# ============================================================
# Impact Assessment
# ============================================================

AFFECTED_HOSTS_BY_USER = SPLQuery(
    name="Hosts Accessed by Compromised User",
    description="Identify all hosts a compromised user account has accessed",
    mitre_tactic="Impact Assessment",
    mitre_technique="N/A",
    spl_template="""index={{index}} sourcetype="WinEventLog:Security" EventCode=4624
    Account_Name="{{username}}"
| stats count earliest(_time) as first_access latest(_time) as last_access
        values(Logon_Type) as logon_types
        by Computer
| sort - count""",
    parameters=["index", "username"],
)

AFFECTED_USERS_BY_IP = SPLQuery(
    name="Users Authenticated from Suspicious IP",
    description="Find all user accounts that authenticated from a suspicious source IP",
    mitre_tactic="Impact Assessment",
    mitre_technique="N/A",
    spl_template="""index={{index}} sourcetype="WinEventLog:Security" EventCode=4624
    src_ip="{{src_ip}}"
| stats count earliest(_time) as first_login latest(_time) as last_login
        dc(Computer) as unique_hosts values(Computer) as hosts
        by Account_Name
| sort - count""",
    parameters=["index", "src_ip"],
)

TIMELINE_EVENTS = SPLQuery(
    name="Incident Timeline Events",
    description="Build a chronological timeline of key security events",
    mitre_tactic="Investigation",
    mitre_technique="N/A",
    spl_template="""index={{index}} (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
    (EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR EventCode=4688 OR EventCode=1 OR EventCode=3)
    (src_ip="{{ioc_ip}}" OR Account_Name="{{ioc_user}}")
| eval event_type=case(
    EventCode=4624, "Successful Login",
    EventCode=4625, "Failed Login",
    EventCode=4648, "Explicit Credential Use",
    EventCode=4688, "Process Created",
    EventCode=1, "Sysmon Process Create",
    EventCode=3, "Network Connection",
    true(), "Other"
  )
| table _time, event_type, EventCode, Computer, Account_Name, src_ip, Image, CommandLine
| sort _time
| head {{max_results}}""",
    parameters=["index", "ioc_ip", "ioc_user", "max_results"],
)


# ============================================================
# Query Registry — for dynamic agent access
# ============================================================

QUERY_REGISTRY: dict[str, SPLQuery] = {
    "credential_stuffing": CREDENTIAL_STUFFING_DETECTION,
    "brute_force_single": BRUTE_FORCE_SINGLE_ACCOUNT,
    "lateral_psexec": LATERAL_MOVEMENT_PSEXEC,
    "lateral_rdp": LATERAL_MOVEMENT_RDP,
    "lateral_wmi": LATERAL_MOVEMENT_WMI,
    "privesc_admin_group": PRIVILEGE_ESCALATION_ADMIN,
    "persistence_schtask": PERSISTENCE_SCHEDULED_TASK,
    "suspicious_dns": SUSPICIOUS_DNS_QUERIES,
    "network_by_host": NETWORK_CONNECTIONS_BY_HOST,
    "hosts_by_user": AFFECTED_HOSTS_BY_USER,
    "users_by_ip": AFFECTED_USERS_BY_IP,
    "timeline_events": TIMELINE_EVENTS,
}


def get_queries_for_tactic(tactic: str) -> list[SPLQuery]:
    """Return all queries matching a MITRE ATT&CK tactic."""
    return [q for q in QUERY_REGISTRY.values() if tactic.lower() in q.mitre_tactic.lower()]


def get_query(name: str) -> SPLQuery | None:
    """Retrieve a query by its registry key."""
    return QUERY_REGISTRY.get(name)
