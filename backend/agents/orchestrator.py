"""
SentinelOps — Orchestrator Agent
Master coordinator that decomposes incidents, delegates to sub-agents, and synthesizes findings.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from backend.agents.state import (
    IncidentState,
    LogEntry,
    AgentStatusEnum,
)
from backend.evidence.board import get_evidence_board
from backend.splunk_mcp.client import get_mcp_client

logger = logging.getLogger("sentinelops.orchestrator")


async def orchestrator_decompose(state: IncidentState) -> dict:
    """
    First orchestrator pass: discover available Splunk data, analyze the
    incoming alert, and prepare context for specialist agents.

    Uses: splunk_get_indexes, splunk_get_metadata (MCP tools)
    """
    board = get_evidence_board()
    await board.update_agent_status("orchestrator", AgentStatusEnum.RUNNING.value, "Decomposing incident")

    alert_name = state.get("alert_name", "Unknown Alert")
    alert_severity = state.get("alert_severity", "medium")
    alert_raw = state.get("alert_raw", {})

    # --- STEP 1: Dynamic Index Discovery via MCP ---
    mcp = await get_mcp_client()

    await board.add_log_entry(
        agent="orchestrator",
        action="index_discovery",
        detail="[MCP:splunk_get_indexes] Discovering available Splunk data indexes",
    )

    indexes = await mcp.get_indexes()
    available_indexes = [ix["name"] if isinstance(ix, dict) else ix
                         for ix in indexes
                         if not (ix.get("name", ix) if isinstance(ix, dict) else ix).startswith("_")
                         or (ix.get("name", ix) if isinstance(ix, dict) else ix) == "_internal"]

    await board.add_log_entry(
        agent="orchestrator",
        action="index_discovery",
        detail=f"[MCP:splunk_get_indexes] Discovered {len(available_indexes)} indexes: {available_indexes[:5]}",
    )

    # --- STEP 2: Get sourcetypes for each index (splunk_get_metadata) ---
    data_context = {}
    for idx_name in available_indexes[:5]:
        name = idx_name.get("name", idx_name) if isinstance(idx_name, dict) else idx_name
        sourcetypes = await mcp.get_metadata(name, "sourcetypes")
        st_names = [s.get("value", s) if isinstance(s, dict) else s for s in sourcetypes[:10]]
        data_context[name] = st_names

    await board.add_log_entry(
        agent="orchestrator",
        action="metadata_discovery",
        detail=f"[MCP:splunk_get_metadata] Data context mapped: {json.dumps({k: v[:3] for k, v in data_context.items()})}",
    )

    # Update SAIA/MCP counters
    call_stats = mcp.get_call_stats()
    await board.update({
        "total_saia_calls": call_stats["total_saia_calls"],
        "total_spl_queries": call_stats["total_spl_queries"],
        "total_saved_searches": call_stats["total_saved_searches"],
        "data_context": data_context,
    }, source="orchestrator")

    # --- STEP 3: Classify incident and build summary ---
    incident_type = _classify_incident(alert_name, alert_raw)

    source_ip = alert_raw.get("source_ip", "unknown")
    failed_count = alert_raw.get("failed_count", 0)
    accounts = alert_raw.get("targeted_accounts", [])

    summary = (
        f"INCIDENT DECOMPOSITION\n"
        f"Alert: {alert_name}\n"
        f"Severity: {alert_severity.upper()}\n"
        f"Type Classification: {incident_type}\n"
        f"Source IP: {source_ip}\n"
        f"Failed Attempts: {failed_count}\n"
        f"Targeted Accounts: {', '.join(accounts) if isinstance(accounts, list) else accounts}\n"
        f"Available Indexes: {', '.join(str(i) for i in available_indexes[:5])}\n\n"
        f"WORKSTREAM ASSIGNMENTS:\n"
        f"1. Threat Hunter → Search for IOCs, lateral movement, MITRE ATT&CK mapping\n"
        f"2. RCA Agent → Correlate logs to build causal chain\n"
        f"3. Blast Radius → Map affected services, users, hosts\n"
        f"4. Remediation → Retrieve runbooks, draft action plan"
    )

    await board.add_log_entry(
        agent="orchestrator",
        action="decomposition_complete",
        detail=f"Incident classified as '{incident_type}'. Dispatching 4 sub-agents in parallel.",
    )
    await board.update_agent_status("orchestrator", AgentStatusEnum.WAITING.value, "Waiting for sub-agents")

    return {
        "incident_summary": summary,
        "data_context": data_context,
        "total_saia_calls": call_stats["total_saia_calls"],
        "total_spl_queries": call_stats["total_spl_queries"],
        "total_saved_searches": call_stats["total_saved_searches"],
        "execution_log": [
            LogEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent="orchestrator",
                action="decompose",
                detail=f"[MCP:splunk_get_indexes] + [MCP:splunk_get_metadata] → Classified as {incident_type}. Dispatching sub-agents.",
            ).to_dict()
        ],
    }


async def orchestrator_synthesize(state: IncidentState) -> dict:
    """
    Second orchestrator pass: synthesize all sub-agent findings into
    a coherent incident narrative and severity assessment.

    This node runs AFTER all sub-agents complete.
    """
    board = get_evidence_board()
    await board.update_agent_status("orchestrator", AgentStatusEnum.RUNNING.value, "Synthesizing findings")

    threat_findings = state.get("threat_findings", [])
    rca_findings = state.get("rca_findings", [])
    blast_entities = state.get("blast_radius", [])
    remediation = state.get("remediation_actions", [])

    await board.add_log_entry(
        agent="orchestrator",
        action="synthesis_start",
        detail=(
            f"Synthesizing: {len(threat_findings)} threats, "
            f"{len(rca_findings)} RCA findings, "
            f"{len(blast_entities)} affected entities, "
            f"{len(remediation)} remediation actions"
        ),
    )

    # Extract MITRE techniques from threat findings
    mitre_techniques = []
    for finding in threat_findings:
        f = finding if isinstance(finding, dict) else finding.to_dict() if hasattr(finding, 'to_dict') else {}
        tech = f.get("mitre_technique", "")
        if tech and tech not in mitre_techniques:
            mitre_techniques.append(tech)

    # Build severity assessment
    critical_count = sum(
        1 for f in threat_findings
        if (f if isinstance(f, dict) else f.to_dict() if hasattr(f, 'to_dict') else {}).get("severity") == "critical"
    )
    high_count = sum(
        1 for f in threat_findings
        if (f if isinstance(f, dict) else f.to_dict() if hasattr(f, 'to_dict') else {}).get("severity") == "high"
    )
    compromised_hosts = sum(
        1 for e in blast_entities
        if (e if isinstance(e, dict) else e.to_dict() if hasattr(e, 'to_dict') else {}).get("risk_level") == "compromised"
    )

    if critical_count > 0 or compromised_hosts >= 3:
        severity = "CRITICAL"
    elif high_count > 0 or compromised_hosts >= 1:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    # Build narrative
    narrative_parts = [
        f"## Incident Narrative — {state.get('alert_name', 'Unknown')}",
        f"**Severity Assessment: {severity}**",
        f"**Triggered:** {state.get('triggered_at', 'Unknown')}",
        "",
        "### Attack Summary",
    ]

    # Summarize RCA
    if rca_findings:
        f = rca_findings[0] if isinstance(rca_findings[0], dict) else rca_findings[0].to_dict()
        narrative_parts.append(f"**Root Cause:** {f.get('root_cause', 'Under investigation')}")
        narrative_parts.append("")

    # Summarize threats
    if threat_findings:
        narrative_parts.append("### Key Findings")
        for finding in threat_findings[:5]:
            f = finding if isinstance(finding, dict) else finding.to_dict() if hasattr(finding, 'to_dict') else {}
            narrative_parts.append(
                f"- **[{f.get('severity', 'unknown').upper()}]** {f.get('title', 'Unknown')} "
                f"(MITRE: {f.get('mitre_technique', 'N/A')}, Confidence: {f.get('confidence', 0):.0%})"
            )
        narrative_parts.append("")

    # Summarize blast radius
    if blast_entities:
        narrative_parts.append("### Blast Radius")
        narrative_parts.append(f"- **{compromised_hosts}** confirmed compromised entities")
        narrative_parts.append(f"- **{len(blast_entities) - compromised_hosts}** potentially affected")
        narrative_parts.append("")

    # Summarize MITRE
    if mitre_techniques:
        narrative_parts.append("### MITRE ATT&CK Coverage")
        narrative_parts.append(f"Techniques identified: {', '.join(mitre_techniques)}")
        narrative_parts.append("")

    # Summarize remediation
    if remediation:
        narrative_parts.append("### Recommended Actions")
        for action in sorted(
            remediation,
            key=lambda a: (a if isinstance(a, dict) else a.to_dict() if hasattr(a, 'to_dict') else {}).get("priority", 99)
        )[:3]:
            a = action if isinstance(action, dict) else action.to_dict() if hasattr(action, 'to_dict') else {}
            narrative_parts.append(
                f"- **[P{a.get('priority', '?')}]** {a.get('title', 'Unknown')} → {a.get('target', 'N/A')}"
            )

    narrative = "\n".join(narrative_parts)

    await board.add_log_entry(
        agent="orchestrator",
        action="synthesis_complete",
        detail=f"Severity: {severity}. {len(mitre_techniques)} MITRE techniques. Awaiting human approval.",
    )
    await board.update(
        {"incident_narrative": narrative, "severity_assessment": severity},
        source="orchestrator",
    )
    await board.update_agent_status("orchestrator", AgentStatusEnum.COMPLETE.value, "Synthesis complete")

    return {
        "incident_narrative": narrative,
        "severity_assessment": severity,
        "mitre_techniques": mitre_techniques,
        "execution_log": [
            LogEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent="orchestrator",
                action="synthesize",
                detail=f"Synthesis complete. Severity: {severity}",
            ).to_dict()
        ],
    }


def _classify_incident(alert_name: str, alert_raw: dict) -> str:
    """Classify the incident type from alert metadata."""
    name_lower = alert_name.lower()

    if any(kw in name_lower for kw in ["credential", "brute force", "login", "authentication"]):
        return "credential_compromise"
    elif any(kw in name_lower for kw in ["malware", "virus", "ransomware"]):
        return "malware_infection"
    elif any(kw in name_lower for kw in ["lateral", "movement", "psexec", "rdp"]):
        return "lateral_movement"
    elif any(kw in name_lower for kw in ["exfiltration", "data loss"]):
        return "data_exfiltration"
    elif any(kw in name_lower for kw in ["dos", "denial", "ddos"]):
        return "denial_of_service"
    else:
        return "unknown_security_event"
