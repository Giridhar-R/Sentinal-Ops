"""
SentinelOps — FastAPI Backend Server
Main application server with REST API, WebSocket streaming, and static file serving.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import get_settings
from backend.agents.state import create_initial_state
from backend.agents.graph import get_compiled_graph
from backend.evidence.board import get_evidence_board
from backend.splunk_mcp.client import get_mcp_client
from backend.splunk_mcp.kv_store import get_kv_manager
from backend.demo.scenario import DEMO_ALERT

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-30s | %(levelname)-7s | %(message)s",
)
logger = logging.getLogger("sentinelops.server")


# ============================================================
# Application Lifespan
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    settings = get_settings()
    logger.info("=" * 60)
    logger.info("  SentinelOps — Autonomous Incident Command")
    logger.info(f"  Demo Mode: {settings.demo_mode}")
    logger.info(f"  Splunk: {settings.splunk.base_url}")
    logger.info(f"  LLM: {settings.llm.provider}/{settings.llm.model}")
    logger.info("=" * 60)

    # Initialize Splunk MCP client
    mcp = await get_mcp_client(settings)
    logger.info(f"Splunk MCP client initialized (demo_mode={mcp.demo_mode})")

    # Initialize KV Store manager
    get_kv_manager(mcp_client=mcp, demo_mode=settings.demo_mode)

    yield

    # Shutdown
    if mcp:
        await mcp.disconnect()
    logger.info("SentinelOps server shut down")


# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(
    title="SentinelOps",
    description="Autonomous Incident Command for Splunk — Multi-Agent AI System",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
FRONTEND_DIR = PROJECT_ROOT / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ============================================================
# Global State
# ============================================================

# Track active incidents
active_incidents: dict[str, dict] = {}
incident_tasks: dict[str, asyncio.Task] = {}


# ============================================================
# Request / Response Models
# ============================================================

class AlertWebhook(BaseModel):
    alert_id: str = ""
    alert_name: str = "Unknown Alert"
    alert_severity: str = "medium"
    alert_raw: dict = {}


class ApprovalRequest(BaseModel):
    decision: str = "approved"  # approved | modified | escalated | overridden
    notes: str = ""


class ChatMessage(BaseModel):
    message: str
    incident_id: str = ""


# ============================================================
# Routes — Dashboard
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the War Room Dashboard."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SentinelOps — Frontend not found</h1>", status_code=404)


# ============================================================
# Routes — Incident Management
# ============================================================

@app.post("/api/webhook/alert")
async def receive_alert_webhook(alert: AlertWebhook):
    """
    Receive an alert webhook from Splunk ES and trigger the agent workflow.
    """
    incident_id = alert.alert_id or f"INC-{uuid.uuid4().hex[:8].upper()}"
    logger.info(f"Alert webhook received: {alert.alert_name} (ID: {incident_id})")

    # Create initial state
    initial_state = create_initial_state(
        alert_id=incident_id,
        alert_name=alert.alert_name,
        alert_severity=alert.alert_severity,
        alert_raw=alert.alert_raw,
    )

    # Initialize evidence board
    board = get_evidence_board()
    await board.initialize(initial_state)

    # Run the agent graph in background
    task = asyncio.create_task(_run_incident_graph(incident_id, initial_state))
    incident_tasks[incident_id] = task
    active_incidents[incident_id] = {
        "id": incident_id,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "alert_name": alert.alert_name,
        "severity": alert.alert_severity,
    }

    return JSONResponse({
        "status": "accepted",
        "incident_id": incident_id,
        "message": f"Incident workflow started for alert: {alert.alert_name}",
    })


@app.post("/api/incident/trigger-demo")
async def trigger_demo_incident():
    """Trigger the demo scenario using pre-built BOTS v3 data."""
    alert = DEMO_ALERT
    incident_id = alert["alert_id"]
    logger.info(f"Demo incident triggered: {alert['alert_name']}")

    initial_state = create_initial_state(
        alert_id=incident_id,
        alert_name=alert["alert_name"],
        alert_severity=alert["alert_severity"],
        alert_raw=alert["alert_raw"],
    )

    board = get_evidence_board()
    await board.initialize(initial_state)

    task = asyncio.create_task(_run_incident_graph(incident_id, initial_state))
    incident_tasks[incident_id] = task
    active_incidents[incident_id] = {
        "id": incident_id,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "alert_name": alert["alert_name"],
        "severity": alert["alert_severity"],
    }

    return JSONResponse({
        "status": "accepted",
        "incident_id": incident_id,
        "message": "Demo incident triggered — agents are now working",
    })


@app.get("/api/incident/{incident_id}/status")
async def get_incident_status(incident_id: str):
    """Get the current status of an incident."""
    board = get_evidence_board()
    state = board.get_state()

    if not state:
        raise HTTPException(status_code=404, detail="Incident not found")

    return JSONResponse({
        "incident_id": incident_id,
        "state": state,
        "meta": active_incidents.get(incident_id, {}),
    })


@app.post("/api/incident/{incident_id}/approve")
async def approve_incident(incident_id: str, req: ApprovalRequest):
    """Submit human approval decision for an incident."""
    board = get_evidence_board()

    await board.update(
        {"human_decision": req.decision, "human_notes": req.notes},
        source="human_operator",
    )
    await board.add_log_entry(
        agent="human_operator",
        action="decision",
        detail=f"Decision: {req.decision}. Notes: {req.notes or 'None'}",
    )

    # Resume the graph if it was interrupted
    graph = get_compiled_graph()
    config = {"configurable": {"thread_id": incident_id}}

    try:
        from langgraph.types import Command
        result = await graph.ainvoke(
            Command(resume={"decision": req.decision, "notes": req.notes}),
            config,
        )
        logger.info(f"Graph resumed for incident {incident_id} with decision: {req.decision}")
    except Exception as e:
        logger.warning(f"Could not resume graph (may already be complete): {e}")

    return JSONResponse({
        "status": "accepted",
        "incident_id": incident_id,
        "decision": req.decision,
    })


@app.post("/api/incident/{incident_id}/chat")
async def chat_with_agents(incident_id: str, msg: ChatMessage):
    """Natural language query to the agent system."""
    board = get_evidence_board()
    state = board.get_state()

    if not state:
        raise HTTPException(status_code=404, detail="Incident not found")

    await board.add_log_entry(
        agent="human_operator",
        action="chat_message",
        detail=f"Operator: {msg.message}",
    )

    # Generate a contextual response based on the evidence board
    response = _generate_chat_response(msg.message, state)

    await board.add_log_entry(
        agent="orchestrator",
        action="chat_response",
        detail=f"Agent: {response}",
    )

    return JSONResponse({
        "incident_id": incident_id,
        "query": msg.message,
        "response": response,
    })


@app.post("/api/chat")
async def global_chat(msg: ChatMessage):
    """
    Global chat endpoint — uses saia_generate_spl for SPL questions
    and saia_ask_splunk_question for general Splunk questions.
    """
    board = get_evidence_board()
    state = board.get_state()
    mcp = await get_mcp_client()

    message = msg.message
    msg_lower = message.lower()

    await board.add_log_entry(
        agent="human_operator",
        action="chat_message",
        detail=f"Operator: {message}",
    )

    # Determine if this is a SPL generation or general question
    spl_keywords = ["search", "find", "show me", "query", "how many", "count", "list", "detect"]
    is_spl_request = any(kw in msg_lower for kw in spl_keywords)

    if is_spl_request:
        # Use saia_generate_spl
        spl = await mcp.saia_generate_spl(message)
        explanation = await mcp.saia_explain_spl(spl)
        await board.add_log_entry(
            agent="orchestrator",
            action="saia_generate_spl",
            detail=f"[SAIA:saia_generate_spl] Chat SPL: {spl[:80]}...",
            spl_query=spl,
        )

        # Update SAIA counters
        call_stats = mcp.get_call_stats()
        await board.update({
            "total_saia_calls": call_stats["total_saia_calls"],
            "total_spl_queries": call_stats["total_spl_queries"],
        }, source="chat")

        return JSONResponse({
            "answer": explanation,
            "spl": spl,
            "tool_used": "saia_generate_spl + saia_explain_spl",
        })
    else:
        # Use evidence board context first, then SAIA
        if state:
            response = _generate_chat_response(message, state)
        else:
            response = await mcp.saia_ask_question(message)

        await board.add_log_entry(
            agent="orchestrator",
            action="chat_response",
            detail=f"[SAIA:saia_ask_splunk_question] {response[:80]}...",
        )

        # Update SAIA counters
        call_stats = mcp.get_call_stats()
        await board.update({
            "total_saia_calls": call_stats["total_saia_calls"],
        }, source="chat")

        return JSONResponse({
            "answer": response,
            "tool_used": "saia_ask_splunk_question",
        })


@app.get("/api/incident/{incident_id}/postmortem")
async def get_postmortem(incident_id: str):
    """Get the generated post-mortem document."""
    board = get_evidence_board()
    state = board.get_state()

    doc = state.get("postmortem_document", "")
    if not doc:
        raise HTTPException(status_code=404, detail="Post-mortem not yet generated")

    return JSONResponse({
        "incident_id": incident_id,
        "postmortem": doc,
    })


@app.get("/api/health")
async def health_check():
    """System health check."""
    mcp = await get_mcp_client()
    splunk_ok = await mcp.health_check()
    return JSONResponse({
        "status": "healthy",
        "splunk_connected": splunk_ok,
        "demo_mode": mcp.demo_mode,
        "active_incidents": len(active_incidents),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ============================================================
# WebSocket — Real-time Event Streaming
# ============================================================

@app.websocket("/ws/incident/{incident_id}")
async def websocket_incident_stream(websocket: WebSocket, incident_id: str):
    """WebSocket endpoint for real-time incident event streaming."""
    await _handle_ws_connection(websocket)


@app.websocket("/ws")
async def websocket_global_stream(websocket: WebSocket):
    """Global WebSocket endpoint (no incident ID required)."""
    await _handle_ws_connection(websocket)


async def _handle_ws_connection(websocket: WebSocket):
    """Shared WebSocket handler for both global and incident-scoped connections."""
    await websocket.accept()
    logger.info("WebSocket client connected")

    board = get_evidence_board()
    queue = board.subscribe()

    # Send initial state
    try:
        await websocket.send_json({
            "type": "initial_state",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "state": board.get_state(),
        })
    except Exception as e:
        logger.error(f"Failed to send initial state: {e}")
        board.unsubscribe(queue)
        return

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json({
                    "type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            except WebSocketDisconnect:
                break
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        board.unsubscribe(queue)
        logger.info("WebSocket client disconnected")


# ============================================================
# Internal Helpers
# ============================================================

async def _run_incident_graph(incident_id: str, initial_state: dict):
    """Run the LangGraph incident workflow."""
    try:
        graph = get_compiled_graph()
        config = {"configurable": {"thread_id": incident_id}}

        logger.info(f"Starting agent graph for incident {incident_id}")

        # Run the graph asynchronously
        result = await graph.ainvoke(initial_state, config)

        # Update SAIA counters from MCP client
        mcp = await get_mcp_client()
        call_stats = mcp.get_call_stats()

        board = get_evidence_board()
        await board.update({
            "total_saia_calls": call_stats["total_saia_calls"],
            "total_spl_queries": call_stats["total_spl_queries"],
            "total_saved_searches": call_stats["total_saved_searches"],
        }, source="orchestrator")

        # Generate post-mortem
        from backend.postmortem.generator import generate_postmortem
        final_state = board.get_state()
        postmortem = await generate_postmortem(final_state)
        await board.update({"postmortem_document": postmortem}, source="postmortem")

        logger.info(f"Post-mortem generated ({len(postmortem)} chars)")

        active_incidents[incident_id]["status"] = "complete"
        logger.info(f"Agent graph complete for incident {incident_id}")

    except Exception as e:
        logger.error(f"Agent graph error for incident {incident_id}: {e}")
        import traceback
        traceback.print_exc()
        active_incidents[incident_id]["status"] = "error"
        active_incidents[incident_id]["error"] = str(e)

        board = get_evidence_board()
        await board.add_log_entry(
            agent="orchestrator",
            action="error",
            detail=f"Graph execution error: {str(e)[:200]}",
        )


def _generate_chat_response(message: str, state: dict) -> str:
    """Generate a contextual chat response from the evidence board state."""
    msg_lower = message.lower()

    # Simple pattern matching for common questions
    if any(w in msg_lower for w in ["ioc", "indicator", "iocs"]):
        findings = state.get("threat_findings", [])
        iocs = []
        for f in findings:
            f = f if isinstance(f, dict) else {}
            for ioc in f.get("iocs", []):
                iocs.append(f"  • [{ioc.get('type', '')}] {ioc.get('value', '')} — {ioc.get('context', '')}")
        if iocs:
            return "Here are the IOCs identified in this incident:\n" + "\n".join(iocs)
        return "No IOCs have been identified yet."

    elif any(w in msg_lower for w in ["timeline", "events", "what happened"]):
        findings = state.get("rca_findings", [])
        if findings:
            f = findings[0] if isinstance(findings[0], dict) else {}
            chain = f.get("causal_chain", [])
            events = [f"  • [{e.get('time', '')[-8:]}] {e.get('event', '')} on {e.get('host', '')}"
                      for e in chain[:8]]
            return "Incident Timeline:\n" + "\n".join(events)
        return "Timeline is still being constructed."

    elif any(w in msg_lower for w in ["blast", "affected", "impact", "radius"]):
        entities = state.get("blast_radius", [])
        if entities:
            compromised = [e for e in entities
                           if (e if isinstance(e, dict) else {}).get("risk_level") == "compromised"]
            names = [f"  • {(e if isinstance(e, dict) else {}).get('name', '?')} ({(e if isinstance(e, dict) else {}).get('entity_type', '?')})"
                     for e in compromised]
            return f"Compromised entities ({len(compromised)}):\n" + "\n".join(names)
        return "Blast radius analysis is still in progress."

    elif any(w in msg_lower for w in ["remediat", "action", "fix", "contain"]):
        actions = state.get("remediation_actions", [])
        if actions:
            items = [f"  • [P{(a if isinstance(a, dict) else {}).get('priority', '?')}] "
                     f"{(a if isinstance(a, dict) else {}).get('title', '?')}"
                     for a in sorted(actions, key=lambda x: (x if isinstance(x, dict) else {}).get("priority", 99))[:5]]
            return "Top recommended remediation actions:\n" + "\n".join(items)
        return "Remediation plan is still being generated."

    elif any(w in msg_lower for w in ["severity", "how bad", "critical"]):
        severity = state.get("severity_assessment", "Under assessment")
        return f"Current severity assessment: **{severity}**"

    elif any(w in msg_lower for w in ["mitre", "attack", "technique"]):
        techniques = state.get("mitre_techniques", [])
        if techniques:
            return f"MITRE ATT&CK techniques identified: {', '.join(techniques)}"
        return "MITRE ATT&CK mapping is still in progress."

    elif any(w in msg_lower for w in ["status", "progress", "agents"]):
        statuses = state.get("agent_status", {})
        lines = [f"  • {agent}: {status}" for agent, status in statuses.items()]
        return "Agent Status:\n" + "\n".join(lines)

    else:
        return (
            "I can answer questions about this incident. Try asking about:\n"
            "  • IOCs and indicators\n"
            "  • Timeline of events\n"
            "  • Blast radius and affected entities\n"
            "  • Remediation actions\n"
            "  • MITRE ATT&CK techniques\n"
            "  • Agent status and progress"
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level=settings.log_level.lower(),
    )
