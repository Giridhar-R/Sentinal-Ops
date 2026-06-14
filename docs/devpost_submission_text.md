# 🛡️ SentinelOps — Devpost Submission

> **Autonomous Incident Command for Splunk**
> Splunk Agentic Ops Hackathon 2025 | Track: Security

---

## The Problem

**Alert fatigue and data silos are preventing real-time cross-domain correlation.**

Every SOC analyst knows the drill: an alert fires at 2 AM, and the next 20–40 minutes are spent frantically context-switching between dashboards, re-running SPL queries, paging the right on-call engineers, and stitching together a coherent picture from a dozen fragmented views. Meanwhile, the attacker is already two steps ahead.

The numbers paint a grim picture:
- **68% of security teams** report alert fatigue as their #1 operational challenge.
- Mean Time to Investigate (MTTI) averages **38 minutes** for critical incidents.
- **45% of post-mortems** are written hours (or days) after resolution, losing critical forensic context.
- SecOps and Observability operate as **isolated domains** — a credential stuffing attack that degrades API performance is investigated twice, by two teams, using two completely separate toolchains.

The fundamental issue isn't a lack of data — it's a lack of *autonomous coordination*. Splunk has the data. Splunk AI has the intelligence. What's missing is an agentic layer that can activate the moment an alert fires, investigate in parallel, and hand a human operator a fully-reasoned incident package before they've finished their first cup of coffee.

---

## The Solution (SentinelOps)

**SentinelOps is a multi-agent AI command system that bridges SecOps and Observability via the Splunk Model Context Protocol (MCP).**

The moment a Splunk Enterprise Security alert fires, SentinelOps activates a network of 5 specialized AI agents — each with a focused mission — that work **in parallel** through the **Splunk MCP Server v1.1**. These agents don't just analyze; they *investigate*:

- **🔍 Threat Hunter** — Launches 6 parallel hunting pipelines across the BOTS v3 dataset, extracting IOCs, mapping MITRE ATT&CK techniques, and scoring confidence levels.
- **🔬 RCA Agent** — Correlates saved searches and builds a causal chain from root cause to current state using `splunk_get_knowledge_objects` and `splunk_run_saved_search`.
- **💥 Blast Radius** — Maps every affected entity (hosts, users, services, data stores) by querying `service_topology.csv` via MCP lookup, computing downstream business impact and risk scores.
- **🛠️ Remediation** — Generates prioritized containment and recovery actions, retrieves runbooks from KV Store, and presents them with a human-in-the-loop approval gate.
- **🎯 Orchestrator** — Decomposes alerts, synthesizes agent findings into an incident narrative, and generates a 10-section post-mortem document — all without human prompting.

All findings converge on a shared **Evidence Board** backed by Splunk KV Stores, and stream in real-time to a glassmorphic War Room Dashboard via WebSocket. The entire pipeline — from alert to post-mortem — completes in **under 3 minutes**.

---

## How We Built It

**LangGraph state engine using native Splunk KV Stores for persistent agent memory.**

### Architecture Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Orchestration** | LangGraph (StateGraph) | Multi-agent workflow with parallel fan-out, conditional routing, and `interrupt()` for human-in-the-loop |
| **AI Bridge** | Splunk MCP Server v1.1 | Unified tool interface for all 9 mandated Splunk AI tools |
| **Memory** | Splunk KV Store | Persistent evidence board, agent state, remediation runbooks, SAIA call counters |
| **Backend** | FastAPI + Uvicorn | Async REST API, WebSocket streaming, alert webhook receiver |
| **Frontend** | Vanilla JS + CSS | Glassmorphic dark-mode War Room Dashboard with real-time updates |
| **Deployment** | Docker Compose + Nginx | Full-stack containerized deployment with traffic generation |

### The SAIA Pipeline

Every agent follows a mandated 4-step pipeline for each investigation task:

```
Natural Language Intent
    → saia_generate_spl  (NL→SPL conversion)
    → saia_optimize_spl  (Performance optimization)
    → splunk_run_query   (Live data execution)
    → saia_explain_spl   (Human-readable findings)
    → Evidence Board     (KV Store persistence)
```

This ensures **full transparency** — every SPL query is generated, optimized, executed, and explained with a complete audit trail visible in the War Room.

### All 9 Mandated Tools — Demonstrably Used

| Tool | Where Used |
|------|-----------|
| `splunk_run_query` | All 4 agents — primary data access |
| `splunk_get_indexes` | Orchestrator — index discovery on startup |
| `splunk_get_metadata` | Orchestrator — sourcetype discovery |
| `splunk_get_knowledge_objects` | RCA Agent — saved search correlation |
| `splunk_run_saved_search` | RCA Agent — runs existing detection rules |
| `saia_generate_spl` | All agents — NL→SPL for dynamic queries |
| `saia_optimize_spl` | All agents — pre-execution optimization |
| `saia_explain_spl` | All agents — operator transparency |
| `saia_ask_splunk_question` | Remediation Agent + Chat UI |

---

## The Differentiators

### 🧪 Live "Dry-Run" Risk Simulator

Before any remediation action is executed, SentinelOps runs a **transactional impact simulation**:
- Queries `service_topology.csv` to map downstream dependencies of the target entity.
- Computes a **blast radius weight** — the percentage of business-critical services that would be affected by the proposed action.
- Flags high-risk actions (e.g., isolating a host that runs both the primary database and the backup agent) with a `⚠️ HIGH IMPACT` warning.
- Presents a side-by-side comparison of **"risk of inaction"** vs **"risk of action"** to the human operator.

This ensures that containment doesn't cause more damage than the attack itself — a real-world problem that most automated response systems completely ignore.

### 📡 AI Watchdog Dashboard (Splunk MCP TA)

SentinelOps includes a dedicated **AI traffic tracking panel** powered by the Splunk MCP Technology Add-on:
- **Live SAIA Counter** — Real-time count of `saia_generate_spl`, `saia_optimize_spl`, `saia_explain_spl`, and `saia_ask_splunk_question` calls in the dashboard header.
- **SPL Query Audit Trail** — Every generated, optimized, and executed SPL query is logged with `[SAIA:...]` and `[MCP:...]` tags for full observability.
- **Agent Call Statistics** — Per-agent breakdown of MCP tool usage, execution times, and result counts.
- **AI Model Governance** — Tracks which AI decisions led to which remediation actions, creating a complete chain of custody for compliance and audit.

This isn't just an operational dashboard — it's an **AI observability layer** that lets operators understand *how* the AI agents are reasoning and *what* data they're accessing, addressing the growing need for AI transparency in security operations.

### 🔄 Cross-Domain Correlation

Unlike traditional SIEM playbooks that operate within a single domain, SentinelOps correlates across SecOps and Observability simultaneously:
- A credential stuffing attack (Security) that causes elevated API error rates (Observability) is investigated as **one unified incident**.
- The Blast Radius agent maps from compromised hosts → affected services → downstream business impact, bridging the gap between "we found an IOC" and "here's the revenue impact."

### ⚡ Zero-Config Demo Mode

SentinelOps ships with a complete demo mode that requires **no live Splunk instance**:
- Pre-baked SAIA responses simulate realistic NL→SPL generation.
- Sample BOTS v3-style query results drive the full agent pipeline.
- Auto-approval gate lets operators see the complete workflow without manual intervention.
- One-click deployment via Docker Compose.

---

## Try It

```bash
# Clone and run in under 2 minutes
git clone https://github.com/Giridhar-R/Sentinal-Ops.git
cd Sentinal-Ops
pip install -r requirements.txt
cp .env.example .env  # DEMO_MODE=true by default
python -m backend.main
# Open http://localhost:8000 → Click "🚀 Launch Incident Demo"
```

---

> **SentinelOps — Turning alert chaos into autonomous command.**
> Built with ❤️ for the Splunk Agentic Ops Hackathon.
