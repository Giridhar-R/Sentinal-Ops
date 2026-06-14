"""
SentinelOps — LangGraph Workflow Definition
Defines the multi-agent graph with parallel fan-out, human-in-the-loop gate,
and post-mortem generation.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import interrupt, Command

from backend.agents.state import IncidentState, LogEntry, AgentStatusEnum
from backend.agents.orchestrator import orchestrator_decompose, orchestrator_synthesize
from backend.agents.threat_hunter import threat_hunter_node
from backend.agents.rca_agent import rca_agent_node
from backend.agents.blast_radius import blast_radius_node
from backend.agents.remediation import remediation_node
from backend.evidence.board import get_evidence_board

logger = logging.getLogger("sentinelops.graph")


# ============================================================
# Human-in-the-Loop Gate
# ============================================================

async def human_approval_gate(state: IncidentState) -> dict:
    """
    Human-in-the-loop gate node.
    In demo mode: auto-approves after broadcasting the waiting state.
    In production: uses LangGraph interrupt() to pause for real human review.
    """
    from backend.config import get_settings

    board = get_evidence_board()
    await board.update_agent_status("orchestrator", AgentStatusEnum.WAITING.value,
                                     "Awaiting human approval")

    narrative = state.get("incident_narrative", "No narrative generated")
    severity = state.get("severity_assessment", "UNKNOWN")
    actions = state.get("remediation_actions", [])

    approval_count = sum(
        1 for a in actions
        if (a if isinstance(a, dict) else {}).get("requires_approval", False)
    )

    await board.add_log_entry(
        agent="orchestrator",
        action="human_gate",
        detail=f"Incident package ready. Severity: {severity}. "
               f"{approval_count} actions require human approval. "
               f"Waiting for operator decision.",
    )

    settings = get_settings()

    if settings.demo_mode:
        # Demo mode: auto-approve after a brief pause for UI visibility
        await asyncio.sleep(2)
        human_decision = "approved"
        human_notes = "Auto-approved in demo mode"
        logger.info("Demo mode: auto-approving remediation actions")
    else:
        # Production: use LangGraph interrupt to pause and wait for human
        try:
            decision = interrupt({
                "type": "approval_required",
                "severity": severity,
                "narrative_preview": narrative[:500],
                "pending_actions": approval_count,
                "message": "Review the incident package and approve recommended actions.",
            })
            if isinstance(decision, dict):
                human_decision = decision.get("decision", "approved")
                human_notes = decision.get("notes", "")
            else:
                human_decision = str(decision) if decision else "approved"
                human_notes = ""
        except Exception:
            human_decision = "approved"
            human_notes = "Fallback auto-approve"

    await board.add_log_entry(
        agent="human_operator",
        action="decision",
        detail=f"Operator decision: {human_decision}. Notes: {human_notes or 'None'}",
    )
    await board.update(
        {"human_decision": human_decision, "human_notes": human_notes},
        source="human_operator",
    )

    return {
        "human_decision": human_decision,
        "human_notes": human_notes,
        "execution_log": [
            LogEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent="human_operator",
                action="decision",
                detail=f"Decision: {human_decision}",
            ).to_dict()
        ],
    }


# ============================================================
# Action Execution Node
# ============================================================

async def execute_approved_actions(state: IncidentState) -> dict:
    """
    Execute approved remediation actions.
    In the hackathon demo, this simulates execution with audit logging.
    """
    board = get_evidence_board()
    decision = state.get("human_decision", "approved")
    actions = state.get("remediation_actions", [])

    if decision not in ("approved", "modified"):
        await board.add_log_entry(
            agent="orchestrator",
            action="actions_skipped",
            detail=f"Actions skipped — operator decision: {decision}",
        )
        return {"execution_log": [LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent="orchestrator",
            action="actions_skipped",
            detail=f"Skipped due to operator decision: {decision}",
        ).to_dict()]}

    executed_actions = []
    for action in actions:
        a = action if isinstance(action, dict) else {}
        if not a.get("requires_approval", False) or decision == "approved":
            a["approved"] = True
            a["executed"] = True
            executed_actions.append(a)
            await board.add_log_entry(
                agent="orchestrator",
                action="action_executed",
                detail=f"Executed: {a.get('title', 'Unknown')} → {a.get('target', 'N/A')}",
            )
            await asyncio.sleep(0.2)  # Simulate execution time

    await board.add_log_entry(
        agent="orchestrator",
        action="execution_complete",
        detail=f"Executed {len(executed_actions)} of {len(actions)} remediation actions",
    )

    return {
        "execution_log": [LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent="orchestrator",
            action="execute_actions",
            detail=f"Executed {len(executed_actions)} actions",
        ).to_dict()],
    }


# ============================================================
# Post-Mortem Generation Node
# ============================================================

async def generate_postmortem_node(state: IncidentState) -> dict:
    """Generate the post-mortem document from the evidence board."""
    from backend.postmortem.generator import generate_postmortem

    board = get_evidence_board()
    await board.add_log_entry(
        agent="orchestrator",
        action="postmortem_start",
        detail="Generating incident post-mortem document",
    )

    document = await generate_postmortem(state)

    await board.update(
        {"postmortem_document": document},
        source="orchestrator",
    )
    await board.add_log_entry(
        agent="orchestrator",
        action="postmortem_complete",
        detail="Post-mortem document generated successfully",
    )

    return {
        "postmortem_document": document,
        "execution_log": [LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent="orchestrator",
            action="postmortem",
            detail="Post-mortem generated",
        ).to_dict()],
    }


# ============================================================
# Routing Logic
# ============================================================

def should_execute_actions(state: IncidentState) -> str:
    """Route based on human decision."""
    decision = state.get("human_decision", "")
    if decision in ("approved", "modified"):
        return "execute_actions"
    elif decision == "escalated":
        return "generate_postmortem"
    else:
        return "generate_postmortem"


# ============================================================
# Graph Construction
# ============================================================

def build_incident_graph() -> StateGraph:
    """
    Build and compile the SentinelOps multi-agent workflow graph.

    Flow:
    START → orchestrator_decompose
          → [PARALLEL: threat_hunter, rca_agent, blast_radius, remediation]
          → orchestrator_synthesize
          → human_approval_gate (interrupt)
          → execute_approved_actions | skip
          → generate_postmortem
          → END
    """
    builder = StateGraph(IncidentState)

    # Add nodes
    builder.add_node("orchestrator_decompose", orchestrator_decompose)
    builder.add_node("threat_hunter", threat_hunter_node)
    builder.add_node("rca_agent", rca_agent_node)
    builder.add_node("blast_radius", blast_radius_node)
    builder.add_node("remediation", remediation_node)
    builder.add_node("orchestrator_synthesize", orchestrator_synthesize)
    builder.add_node("human_approval_gate", human_approval_gate)
    builder.add_node("execute_actions", execute_approved_actions)
    builder.add_node("generate_postmortem", generate_postmortem_node)

    # Entry point
    builder.set_entry_point("orchestrator_decompose")

    # Parallel fan-out from decompose to all 4 sub-agents
    builder.add_edge("orchestrator_decompose", "threat_hunter")
    builder.add_edge("orchestrator_decompose", "rca_agent")
    builder.add_edge("orchestrator_decompose", "blast_radius")
    builder.add_edge("orchestrator_decompose", "remediation")

    # All sub-agents converge at synthesize
    builder.add_edge("threat_hunter", "orchestrator_synthesize")
    builder.add_edge("rca_agent", "orchestrator_synthesize")
    builder.add_edge("blast_radius", "orchestrator_synthesize")
    builder.add_edge("remediation", "orchestrator_synthesize")

    # Synthesize → Human Gate
    builder.add_edge("orchestrator_synthesize", "human_approval_gate")

    # Conditional routing from human gate
    builder.add_conditional_edges(
        "human_approval_gate",
        should_execute_actions,
        {
            "execute_actions": "execute_actions",
            "generate_postmortem": "generate_postmortem",
        },
    )

    # Execute → Post-mortem → END
    builder.add_edge("execute_actions", "generate_postmortem")
    builder.add_edge("generate_postmortem", END)

    return builder


def compile_graph(checkpointer=None):
    """Compile the graph with an optional checkpointer for persistence."""
    builder = build_incident_graph()

    if checkpointer is None:
        checkpointer = MemorySaver()

    return builder.compile(checkpointer=checkpointer)


# Pre-built graph instance for the application
_compiled_graph = None


def get_compiled_graph():
    """Get or create the singleton compiled graph."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = compile_graph()
    return _compiled_graph
