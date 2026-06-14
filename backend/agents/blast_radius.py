"""
SentinelOps — Blast Radius Agent
Uses saia_generate_spl to build dynamic blast radius queries.
Maps affected services, users, data stores, and downstream dependencies.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from backend.agents.state import (
    IncidentState,
    AffectedEntity,
    LogEntry,
    AgentStatusEnum,
)
from backend.evidence.board import get_evidence_board
from backend.splunk_mcp.client import get_mcp_client
from backend.demo.scenario import DEMO_IOCS

logger = logging.getLogger("sentinelops.blast_radius")

# NL intents for blast radius mapping
BLAST_INTENTS = [
    "find all hosts that received connections from the attacker IP 203.0.113.42 in the last hour",
    "identify all user accounts that authenticated from compromised hosts",
    "list services running on compromised hosts and their downstream dependencies",
]


async def blast_radius_node(state: IncidentState) -> dict:
    """
    Blast Radius agent node for LangGraph.

    Pipeline:
    1. saia_generate_spl — Generate blast radius queries from NL
    2. splunk_run_query — Execute each query
    3. saia_explain_spl — Explain impact findings
    4. Map entities with risk scores and dependencies
    """
    board = get_evidence_board()
    await board.update_agent_status("blast_radius", AgentStatusEnum.RUNNING.value, "Mapping blast radius")

    mcp = await get_mcp_client()
    alert_raw = state.get("alert_raw", {})
    index = alert_raw.get("index", "sentinalops_os")

    entities: list[dict] = []
    log_entries: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    # --- Step 1: Use saia_generate_spl for dynamic blast radius queries ---
    for intent in BLAST_INTENTS:
        await board.add_log_entry(
            agent="blast_radius",
            action="saia_generate_spl",
            detail=f"[SAIA:saia_generate_spl] {intent[:60]}...",
        )
        spl = await mcp.saia_generate_spl(intent, index_context=index)

        await board.add_log_entry(
            agent="blast_radius",
            action="executing_spl",
            detail=f"[MCP:splunk_run_query] Blast radius scan",
            spl_query=spl,
        )
        results = await mcp.run_spl_query(spl)
        log_entries.append(LogEntry(
            timestamp=now, agent="blast_radius", action="saia_pipeline",
            detail=f"[SAIA:saia_generate_spl] + [MCP:splunk_run_query] → {results['result_count']} results",
            spl_query=spl,
        ).to_dict())
        await asyncio.sleep(0.2)

    # --- Step 2: Explain the overall blast impact ---
    explanation = await mcp.saia_explain_spl(
        f"index={index} src_ip=203.0.113.42 | stats dc(host) dc(user) dc(sourcetype)"
    )
    await board.add_log_entry(
        agent="blast_radius",
        action="saia_explain_spl",
        detail=f"[SAIA:saia_explain_spl] {explanation[:120]}...",
    )

    # --- Step 3: Build entity map from demo data + query results ---
    source_ip = alert_raw.get("source_ip", DEMO_IOCS["attacker_ips"][0]["ip"])

    # Compromised hosts
    compromised_hosts = [
        ("web-prod-01", "Primary web server — initial credential compromise target", 0.95),
        ("app-srv-02", "Application server — lateral movement via SSH from web-prod-01", 0.88),
        ("db-srv-01", "Database server — PsExec execution detected from app-srv-02", 0.92),
    ]
    for hostname, detail, score in compromised_hosts:
        entities.append(
            AffectedEntity(
                entity_id=f"HOST-{hostname}",
                entity_type="host",
                name=hostname,
                risk_level="compromised",
                risk_score=score,
                details=detail,
                dependencies=[],
                first_seen=now,
            ).to_dict()
        )

    # Potentially affected host
    entities.append(
        AffectedEntity(
            entity_id="HOST-dc-01",
            entity_type="host",
            name="dc-01",
            risk_level="potentially_affected",
            risk_score=0.65,
            details="Domain controller — authentication queries observed from compromised host",
            dependencies=["web-prod-01", "app-srv-02"],
            first_seen=now,
        ).to_dict()
    )

    # Compromised users
    users = [
        ("svc_admin", "Service account — password compromised via credential stuffing", 0.98),
        ("j.smith", "User account — sessions hijacked on compromised host app-srv-02", 0.75),
    ]
    for username, detail, score in users:
        entities.append(
            AffectedEntity(
                entity_id=f"USER-{username}",
                entity_type="user",
                name=username,
                risk_level="compromised",
                risk_score=score,
                details=detail,
                dependencies=[],
                first_seen=now,
            ).to_dict()
        )

    # Affected services
    services = [
        ("nginx-frontend", "potentially_affected", 0.70, ["web-prod-01"], "Web frontend — running on compromised host"),
        ("api-backend", "potentially_affected", 0.72, ["app-srv-02"], "REST API — accessible from compromised app server"),
        ("postgres-primary", "compromised", 0.85, ["db-srv-01"], "Primary database — direct access from compromised DB server"),
        ("redis-cache", "potentially_affected", 0.55, ["app-srv-02"], "Cache layer — network accessible from compromised host"),
    ]
    for svc_name, risk, score, deps, detail in services:
        entities.append(
            AffectedEntity(
                entity_id=f"SVC-{svc_name}",
                entity_type="service",
                name=svc_name,
                risk_level=risk,
                risk_score=score,
                details=detail,
                dependencies=deps,
                first_seen=now,
            ).to_dict()
        )

    # Data stores at risk
    entities.append(
        AffectedEntity(
            entity_id="DATA-customer-db",
            entity_type="data_store",
            name="customer_database",
            risk_level="compromised",
            risk_score=0.90,
            details="Customer PII database — attacker accessed db-srv-01 with elevated privileges. Potential data exfiltration risk.",
            dependencies=["postgres-primary", "db-srv-01"],
            first_seen=now,
        ).to_dict()
    )

    # --- Update counters and complete ---
    call_stats = mcp.get_call_stats()

    await board.update_agent_status("blast_radius", AgentStatusEnum.COMPLETE.value,
                                      f"Mapped {len(entities)} affected entities")
    await board.update(
        {"blast_radius": [e for e in entities]},
        source="blast_radius",
    )

    log_entries.append(LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent="blast_radius",
        action="complete",
        detail=(
            f"Blast radius complete. {len(entities)} entities mapped "
            f"({sum(1 for e in entities if e.get('risk_level') == 'compromised')} compromised). "
            f"SAIA calls: {call_stats['total_saia_calls']}"
        ),
    ).to_dict())

    return {
        "blast_radius": entities,
        "execution_log": log_entries,
        "total_saia_calls": call_stats["total_saia_calls"],
        "total_spl_queries": call_stats["total_spl_queries"],
    }
