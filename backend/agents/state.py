"""
SentinelOps — Agent State Schema
Defines the shared Evidence Board state that all agents read from and write to.
This is the canonical LangGraph state used across the entire workflow.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, TypedDict


# ============================================================
# Enums
# ============================================================

class AgentStatusEnum(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"
    WAITING = "waiting_approval"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    IOC = "ioc"
    TECHNIQUE = "technique"
    TIMELINE_EVENT = "timeline_event"
    AFFECTED_ENTITY = "affected_entity"
    ROOT_CAUSE = "root_cause"
    REMEDIATION = "remediation"


# ============================================================
# Data Classes — Agent Findings
# ============================================================

@dataclass
class LogEntry:
    """A single entry in the execution trace."""
    timestamp: str
    agent: str
    action: str
    detail: str
    spl_query: str | None = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "agent": self.agent,
            "action": self.action,
            "detail": self.detail,
            "spl_query": self.spl_query,
        }


@dataclass
class ThreatFinding:
    """A finding from the Threat Hunter agent."""
    finding_id: str
    finding_type: str  # "ioc", "technique", "behavior"
    title: str
    description: str
    severity: str
    confidence: float  # 0.0 - 1.0
    mitre_tactic: str
    mitre_technique: str
    iocs: list[dict] = field(default_factory=list)  # [{type, value, context}]
    evidence_spl: str = ""
    raw_results: list[dict] = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "iocs": self.iocs,
            "evidence_spl": self.evidence_spl,
            "raw_results": self.raw_results[:5],  # Limit for serialization
            "timestamp": self.timestamp,
        }


@dataclass
class RCAFinding:
    """A finding from the Root Cause Analysis agent."""
    root_cause: str
    confidence: float
    contributing_factors: list[str] = field(default_factory=list)
    causal_chain: list[dict] = field(default_factory=list)
    finding_id: str = ""
    title: str = "Root Cause Analysis"
    description: str = ""
    evidence_spl: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "causal_chain": self.causal_chain,
            "root_cause": self.root_cause,
            "confidence": self.confidence,
            "contributing_factors": self.contributing_factors,
            "evidence_spl": self.evidence_spl,
            "timestamp": self.timestamp,
        }


@dataclass
class AffectedEntity:
    """An entity identified by the Blast Radius agent."""
    entity_id: str
    entity_type: str  # "host", "user", "service", "data_store"
    name: str
    risk_level: str  # "compromised", "potentially_affected", "safe"
    risk_score: float  # 0.0 - 1.0
    details: str = ""
    dependencies: list[str] = field(default_factory=list)
    first_seen: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "name": self.name,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "details": self.details,
            "dependencies": self.dependencies,
            "first_seen": self.first_seen,
            "timestamp": self.timestamp,
        }


@dataclass
class RemediationAction:
    """A remediation action proposed by the Remediation agent."""
    action_id: str
    title: str
    description: str
    priority: int  # 1 = highest
    action_type: str  # "isolate", "block", "reset", "patch", "scan"
    target: str  # What entity this acts on
    requires_approval: bool = True
    approved: bool = False
    executed: bool = False
    runbook_ref: str = ""
    risk_assessment: str = ""
    estimated_time_minutes: int = 0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "action_type": self.action_type,
            "target": self.target,
            "requires_approval": self.requires_approval,
            "approved": self.approved,
            "executed": self.executed,
            "runbook_ref": self.runbook_ref,
            "risk_assessment": self.risk_assessment,
            "estimated_time_minutes": self.estimated_time_minutes,
            "timestamp": self.timestamp,
        }


# ============================================================
# LangGraph State — the Evidence Board
# ============================================================

class IncidentState(TypedDict):
    """
    The shared state object (Evidence Board) that flows through the LangGraph workflow.
    All agents read from and write to this state.
    """

    # --- Alert Trigger ---
    alert_id: str
    alert_name: str
    alert_severity: str
    alert_raw: dict
    triggered_at: str

    # --- Agent Findings (append-only via operator.add) ---
    threat_findings: Annotated[list, operator.add]
    rca_findings: Annotated[list, operator.add]
    blast_radius: Annotated[list, operator.add]
    remediation_actions: Annotated[list, operator.add]

    # --- Agent Status ---
    agent_status: dict

    # --- Orchestrator Synthesis ---
    incident_summary: str
    incident_narrative: str
    severity_assessment: str
    mitre_techniques: list

    # --- Human-in-the-Loop ---
    human_decision: str
    human_notes: str

    # --- Post-Mortem ---
    postmortem_document: str

    # --- Splunk AI Tool Counters ---
    total_saia_calls: Annotated[int, operator.add]
    total_spl_queries: Annotated[int, operator.add]
    total_saved_searches: Annotated[int, operator.add]
    data_context: dict  # {index_name: [sourcetypes]}

    # --- Execution Trace ---
    execution_log: Annotated[list, operator.add]


def create_initial_state(
    alert_id: str,
    alert_name: str,
    alert_severity: str,
    alert_raw: dict | None = None,
) -> IncidentState:
    """Create the initial state for a new incident."""
    now = datetime.now(timezone.utc).isoformat()
    return IncidentState(
        alert_id=alert_id,
        alert_name=alert_name,
        alert_severity=alert_severity,
        alert_raw=alert_raw or {},
        triggered_at=now,
        threat_findings=[],
        rca_findings=[],
        blast_radius=[],
        remediation_actions=[],
        agent_status={
            "orchestrator": AgentStatusEnum.IDLE.value,
            "threat_hunter": AgentStatusEnum.IDLE.value,
            "rca_agent": AgentStatusEnum.IDLE.value,
            "blast_radius": AgentStatusEnum.IDLE.value,
            "remediation": AgentStatusEnum.IDLE.value,
        },
        incident_summary="",
        incident_narrative="",
        severity_assessment="",
        mitre_techniques=[],
        human_decision="",
        human_notes="",
        postmortem_document="",
        total_saia_calls=0,
        total_spl_queries=0,
        total_saved_searches=0,
        data_context={},
        execution_log=[],
    )
