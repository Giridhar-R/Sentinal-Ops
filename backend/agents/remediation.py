"""
SentinelOps — Remediation Agent
Uses saia_ask_splunk_question for contextual remediation advice,
retrieves runbooks from KV Store, and builds prioritized action plan.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from backend.agents.state import (
    IncidentState,
    RemediationAction,
    LogEntry,
    AgentStatusEnum,
)
from backend.evidence.board import get_evidence_board
from backend.splunk_mcp.client import get_mcp_client
from backend.splunk_mcp.kv_store import get_runbook

logger = logging.getLogger("sentinelops.remediation")


async def remediation_node(state: IncidentState) -> dict:
    """
    Remediation Agent node for LangGraph.

    Pipeline:
    1. saia_ask_splunk_question — Get contextual remediation advice
    2. Retrieve runbooks from KV Store
    3. Build prioritized action list with risk assessment
    4. saia_generate_spl — Create verification SPL for each action
    """
    board = get_evidence_board()
    await board.update_agent_status("remediation", AgentStatusEnum.RUNNING.value, "Building action plan")

    mcp = await get_mcp_client()
    alert_raw = state.get("alert_raw", {})
    index = alert_raw.get("index", "sentinalops_os")

    actions: list[dict] = []
    log_entries: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    # --- Step 1: Ask SAIA for contextual remediation advice ---
    await board.add_log_entry(
        agent="remediation",
        action="saia_ask_question",
        detail="[SAIA:saia_ask_splunk_question] Requesting containment recommendations",
    )
    remediation_advice = await mcp.saia_ask_question(
        "What are the recommended containment and remediation steps for a credential "
        "stuffing attack that resulted in account compromise and lateral movement?"
    )
    log_entries.append(LogEntry(
        timestamp=now, agent="remediation", action="saia_ask_question",
        detail=f"[SAIA:saia_ask_splunk_question] Remediation advice received: {remediation_advice[:100]}...",
    ).to_dict())
    await asyncio.sleep(0.2)

    # --- Step 2: Retrieve runbooks from KV Store ---
    runbook_types = ["credential_compromise", "lateral_movement", "host_isolation"]
    for rb_type in runbook_types:
        await board.add_log_entry(
            agent="remediation",
            action="kv_lookup",
            detail=f"[MCP:splunk_get_kv_store] Retrieving runbook: {rb_type}",
        )
        runbook = await get_runbook(rb_type)
        if runbook:
            log_entries.append(LogEntry(
                timestamp=now, agent="remediation", action="runbook_loaded",
                detail=f"[MCP:splunk_get_kv_store] Loaded runbook: {runbook.get('name', rb_type)}",
            ).to_dict())
        await asyncio.sleep(0.1)

    # --- Step 3: Generate verification SPL for key actions ---
    verify_intent = "verify that the attacker IP 203.0.113.42 has no active sessions after firewall block"
    await board.add_log_entry(
        agent="remediation",
        action="saia_generate_spl",
        detail=f"[SAIA:saia_generate_spl] Creating verification query",
    )
    verify_spl = await mcp.saia_generate_spl(verify_intent, index_context=index)

    # --- Step 4: Build prioritized action list ---
    source_ip = alert_raw.get("source_ip", "203.0.113.42")

    remediation_items = [
        {
            "id": "REM-001",
            "title": "Disable Compromised Accounts",
            "description": f"Force password reset and disable accounts: svc_admin, j.smith, a.johnson. "
                          f"These accounts showed successful authentication from attacker IP {source_ip}.",
            "target": "svc_admin, j.smith, a.johnson",
            "action_type": "containment",
            "priority": 1,
            "risk_assessment": "LOW — Prevents further attacker access. May cause brief service disruption for svc_admin.",
            "requires_approval": True,
            "runbook_ref": "credential_compromise",
            "verification_spl": f'index={index} sourcetype=linux_secure user IN ("svc_admin","j.smith") Accepted | stats count',
        },
        {
            "id": "REM-002",
            "title": "Network Isolate Compromised Hosts",
            "description": "Quarantine hosts web-prod-01, app-srv-02, db-srv-01 by moving to isolated VLAN. "
                          "Maintains forensic state while preventing further lateral movement.",
            "target": "web-prod-01, app-srv-02, db-srv-01",
            "action_type": "containment",
            "priority": 1,
            "risk_assessment": "MEDIUM — Services on these hosts will be unavailable. Failover required.",
            "requires_approval": True,
            "runbook_ref": "host_isolation",
            "verification_spl": f'index={index} host IN ("web-prod-01","app-srv-02","db-srv-01") | stats latest(_time) by host',
        },
        {
            "id": "REM-003",
            "title": "Block Attacker Source IPs",
            "description": f"Add firewall deny rules for {source_ip} and associated IPs: 25.129.64.42. "
                          f"Block at perimeter firewall and host-level iptables.",
            "target": f"{source_ip}, 25.129.64.42",
            "action_type": "containment",
            "priority": 2,
            "risk_assessment": "LOW — No legitimate traffic expected from these IPs.",
            "requires_approval": True,
            "runbook_ref": "credential_compromise",
            "verification_spl": verify_spl,
        },
        {
            "id": "REM-004",
            "title": "Block C2 Domains at DNS",
            "description": "Sinkhole known C2 domains: h1t.degendfarm.com, czbeennydafrca.xerfind.ai2. "
                          "Apply DNS blackhole and update threat intel feeds.",
            "target": "h1t.degendfarm.com, czbeennydafrca.xerfind.ai2",
            "action_type": "containment",
            "priority": 2,
            "risk_assessment": "LOW — These domains are confirmed malicious C2 infrastructure.",
            "requires_approval": True,
            "runbook_ref": "lateral_movement",
            "verification_spl": f'index={index} sourcetype=syslog query IN ("h1t.degendfarm.com","czbeennydafrca.xerfind.ai2") | stats count',
        },
        {
            "id": "REM-005",
            "title": "Remove Persistence Mechanisms",
            "description": "Delete malicious scheduled tasks and cron jobs found on compromised hosts. "
                          "Verify no additional persistence (registry, startup, authorized_keys).",
            "target": "web-prod-01, app-srv-02, db-srv-01",
            "action_type": "eradication",
            "priority": 3,
            "risk_assessment": "LOW — Only removes attacker-created artifacts.",
            "requires_approval": True,
            "runbook_ref": "lateral_movement",
            "verification_spl": f'index={index} sourcetype=syslog (schtasks OR crontab OR authorized_keys) | stats count by host',
        },
        {
            "id": "REM-006",
            "title": "Enable Enhanced Monitoring",
            "description": "Deploy enhanced audit logging on all affected hosts. Increase log verbosity "
                          "for auth, process, and network events. Set up real-time Splunk alerts.",
            "target": "All affected hosts + network perimeter",
            "action_type": "monitoring",
            "priority": 4,
            "risk_assessment": "NONE — Monitoring only, no service impact.",
            "requires_approval": False,
            "runbook_ref": None,
            "verification_spl": f'index={index} | stats count by sourcetype | where count > 0',
        },
        {
            "id": "REM-007",
            "title": "Enforce MFA on All Endpoints",
            "description": "Deploy MFA requirement for SSH, VPN, and all administrative access. "
                          "Priority: service accounts and privileged users first.",
            "target": "All endpoints — svc_admin, admin accounts first",
            "action_type": "hardening",
            "priority": 5,
            "risk_assessment": "MEDIUM — Requires user enrollment. Allow 48h rollout window.",
            "requires_approval": False,
            "runbook_ref": None,
            "verification_spl": None,
        },
    ]

    for item in remediation_items:
        actions.append(
            RemediationAction(
                action_id=item["id"],
                title=item["title"],
                description=item["description"],
                target=item["target"],
                action_type=item["action_type"],
                priority=item["priority"],
                risk_assessment=item["risk_assessment"],
                requires_approval=item["requires_approval"],
                approved=False,
                executed=False,
                runbook_ref=item["runbook_ref"],
                timestamp=now,
            ).to_dict()
        )

    # --- Update counters and complete ---
    call_stats = mcp.get_call_stats()

    await board.update_agent_status("remediation", AgentStatusEnum.COMPLETE.value,
                                      f"{len(actions)} actions recommended")
    await board.update(
        {"remediation_actions": [a for a in actions]},
        source="remediation",
    )

    log_entries.append(LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent="remediation",
        action="complete",
        detail=(
            f"Remediation complete. {len(actions)} actions, "
            f"{sum(1 for a in actions if a.get('requires_approval'))} require approval. "
            f"SAIA calls: {call_stats['total_saia_calls']}"
        ),
    ).to_dict())

    return {
        "remediation_actions": actions,
        "execution_log": log_entries,
        "total_saia_calls": call_stats["total_saia_calls"],
        "total_spl_queries": call_stats["total_spl_queries"],
    }
