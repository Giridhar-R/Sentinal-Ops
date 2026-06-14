"""
SentinelOps — Threat Hunter Agent
Uses the mandated SAIA → MCP pipeline:
  saia_generate_spl → saia_optimize_spl → splunk_run_query → saia_explain_spl
Searches for IOCs, lateral movement, and maps findings to MITRE ATT&CK.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from backend.agents.state import (
    IncidentState,
    ThreatFinding,
    LogEntry,
    AgentStatusEnum,
)
from backend.evidence.board import get_evidence_board
from backend.splunk_mcp.client import get_mcp_client
from backend.splunk_mcp.spl_library import QUERY_REGISTRY

logger = logging.getLogger("sentinelops.threat_hunter")

# Natural-language hunting intents — converted to SPL via saia_generate_spl
HUNTING_INTENTS = [
    {
        "id": "TH-001",
        "intent": "find failed authentication attempts with high frequency from a single source in the last 15 minutes",
        "title": "Credential Stuffing Attack Detected",
        "severity": "high",
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1110.004",
        "finding_type": "technique",
    },
    {
        "id": "TH-002",
        "intent": "detect suspicious process executions including wget curl bash with unusual parent processes",
        "title": "Suspicious Process Execution — Post-Exploitation Activity",
        "severity": "critical",
        "mitre_tactic": "TA0002 - Execution",
        "mitre_technique": "T1059.004",
        "finding_type": "technique",
    },
    {
        "id": "TH-003",
        "intent": "identify accounts with successful login after many consecutive failures in last 30 minutes",
        "title": "Credential Compromise — Successful Auth After Brute Force",
        "severity": "critical",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1078",
        "finding_type": "technique",
    },
    {
        "id": "TH-004",
        "intent": "find outbound connections to unusual external IPs from internal hosts in last hour",
        "title": "Suspicious Outbound Connections — Possible C2 Communication",
        "severity": "high",
        "mitre_tactic": "TA0011 - Command and Control",
        "mitre_technique": "T1071.004",
        "finding_type": "ioc",
    },
    {
        "id": "TH-005",
        "intent": "detect privilege escalation including sudo usage and admin group modifications",
        "title": "Privilege Escalation — Unauthorized Elevation",
        "severity": "critical",
        "mitre_tactic": "TA0004 - Privilege Escalation",
        "mitre_technique": "T1078.002",
        "finding_type": "technique",
    },
    {
        "id": "TH-006",
        "intent": "identify lateral movement by users authenticating to multiple distinct hosts",
        "title": "Lateral Movement — Multi-Host Authentication",
        "severity": "high",
        "mitre_tactic": "TA0008 - Lateral Movement",
        "mitre_technique": "T1021.001",
        "finding_type": "technique",
    },
]


async def threat_hunter_node(state: IncidentState) -> dict:
    """
    Threat Hunter agent node for LangGraph.

    Pipeline per hunt:
    1. saia_generate_spl — Convert NL intent to SPL
    2. saia_optimize_spl — Optimize the generated SPL
    3. splunk_run_query  — Execute against live data
    4. saia_explain_spl  — Explain results to operators
    5. Map findings to MITRE ATT&CK with confidence scores
    """
    board = get_evidence_board()
    await board.update_agent_status("threat_hunter", AgentStatusEnum.RUNNING.value, "Starting threat hunt")

    mcp = await get_mcp_client()
    alert_raw = state.get("alert_raw", {})
    index = alert_raw.get("index", "sentinalops_os")

    findings: list[dict] = []
    log_entries: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    for hunt in HUNTING_INTENTS:
        hunt_id = hunt["id"]
        intent = hunt["intent"]

        # --- Step 1: saia_generate_spl — NL → SPL ---
        await board.add_log_entry(
            agent="threat_hunter",
            action="saia_generate_spl",
            detail=f"[SAIA:saia_generate_spl] Intent: '{intent[:60]}...'",
        )
        raw_spl = await mcp.saia_generate_spl(intent, index_context=index)
        log_entries.append(LogEntry(
            timestamp=now, agent="threat_hunter", action="saia_generate_spl",
            detail=f"[SAIA:saia_generate_spl] → SPL generated for {hunt_id}",
            spl_query=raw_spl,
        ).to_dict())

        # --- Step 2: saia_optimize_spl — Optimize before execution ---
        await board.add_log_entry(
            agent="threat_hunter",
            action="saia_optimize_spl",
            detail=f"[SAIA:saia_optimize_spl] Optimizing SPL for {hunt_id}",
        )
        optimized_spl = await mcp.saia_optimize_spl(raw_spl)

        # --- Step 3: splunk_run_query — Execute the SPL ---
        await board.add_log_entry(
            agent="threat_hunter",
            action="executing_spl",
            detail=f"[MCP:splunk_run_query] Executing hunt {hunt_id}",
            spl_query=optimized_spl,
        )
        results = await mcp.run_spl_query(optimized_spl)
        await asyncio.sleep(0.2)  # Natural pacing

        if results["result_count"] > 0:
            # --- Step 4: saia_explain_spl — Explain results ---
            explanation = await mcp.saia_explain_spl(optimized_spl)
            await board.add_log_entry(
                agent="threat_hunter",
                action="saia_explain_spl",
                detail=f"[SAIA:saia_explain_spl] {explanation[:120]}...",
            )

            # Extract IOCs from results
            iocs = _extract_iocs(results["results"])

            findings.append(
                ThreatFinding(
                    finding_id=hunt_id,
                    finding_type=hunt["finding_type"],
                    title=hunt["title"],
                    description=(
                        f"{explanation} "
                        f"Detected {results['result_count']} matching event(s) "
                        f"across the monitored environment."
                    ),
                    severity=hunt["severity"],
                    confidence=0.88 + (0.07 if results["result_count"] > 5 else 0),
                    mitre_tactic=hunt["mitre_tactic"],
                    mitre_technique=hunt["mitre_technique"],
                    iocs=iocs,
                    evidence_spl=optimized_spl,
                    raw_results=results["results"][:10],
                    timestamp=now,
                ).to_dict()
            )

            log_entries.append(LogEntry(
                timestamp=now, agent="threat_hunter", action="finding",
                detail=f"[MCP:splunk_run_query] {hunt['title']}: {results['result_count']} events",
                spl_query=optimized_spl,
            ).to_dict())

    # --- Update SAIA counters ---
    call_stats = mcp.get_call_stats()

    # --- Complete ---
    await board.update_agent_status("threat_hunter", AgentStatusEnum.COMPLETE.value,
                                      f"Found {len(findings)} threat indicators")
    await board.update(
        {"threat_findings": [f for f in findings]},
        source="threat_hunter",
    )

    log_entries.append(LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent="threat_hunter",
        action="complete",
        detail=(
            f"Threat hunt complete. {len(findings)} findings across {len(HUNTING_INTENTS)} hunts. "
            f"SAIA calls: {call_stats['total_saia_calls']}, SPL queries: {call_stats['total_spl_queries']}"
        ),
    ).to_dict())

    return {
        "threat_findings": findings,
        "execution_log": log_entries,
        "total_saia_calls": call_stats["total_saia_calls"],
        "total_spl_queries": call_stats["total_spl_queries"],
    }


def _extract_iocs(results: list[dict]) -> list[dict]:
    """Extract IOCs from query results."""
    iocs = []
    seen = set()
    for r in results:
        for field in ["src_ip", "source_ip", "src"]:
            ip = r.get(field, "")
            if ip and ip not in seen:
                iocs.append({"type": "ip", "value": ip, "context": f"{r.get('count', '?')} events"})
                seen.add(ip)

        for field in ["user", "Account_Name", "username"]:
            user = r.get(field, "")
            if user and user not in seen:
                iocs.append({"type": "username", "value": user, "context": "Targeted account"})
                seen.add(user)

        for field in ["host", "Computer", "dest"]:
            host = r.get(field, "")
            if host and host not in seen:
                iocs.append({"type": "hostname", "value": host, "context": "Affected host"})
                seen.add(host)

        for field in ["query", "domain"]:
            domain = r.get(field, "")
            if domain and domain not in seen and not any(safe in domain for safe in ["microsoft.com", "windows.com"]):
                iocs.append({"type": "domain", "value": domain, "context": f"{r.get('count', '?')} queries"})
                seen.add(domain)

    return iocs[:20]  # Cap at 20 IOCs
