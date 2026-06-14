"""
SentinelOps — Splunk MCP Client (Full SAIA Tool Support)
Async wrapper for the Splunk MCP Server with complete support for all
mandated Splunk AI tools: splunk_* (MCP namespace) and saia_* (AI Assistant).
Falls back to realistic demo data when DEMO_MODE is enabled.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger("sentinelops.mcp")


class SplunkMCPClient:
    """
    Async client for the Splunk MCP Server v1.1.

    Supports all mandated tools:
      splunk_run_query         — Execute SPL against live indexes
      splunk_get_indexes       — Discover available data indexes
      splunk_get_metadata      — Discover sourcetypes per index
      splunk_get_knowledge_objects — Fetch saved searches/alerts
      splunk_run_saved_search  — Run existing correlation searches
      saia_generate_spl        — NL → SPL (AI Assistant)
      saia_explain_spl         — Explain SPL in plain English
      saia_optimize_spl        — Optimize SPL before execution
      saia_ask_splunk_question — Contextual Splunk help

    Modes:
      - Live  — real MCP Server SSE/REST calls
      - Demo  — returns realistic simulated responses
    """

    def __init__(
        self,
        base_url: str = "https://localhost:8089",
        token: str = "",
        mode: str = "sse",
        index: str = "sentinalops_os",
        verify_ssl: bool = False,
        demo_mode: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.mode = mode
        self.default_index = index
        self.verify_ssl = verify_ssl
        self.demo_mode = demo_mode
        self._http: httpx.AsyncClient | None = None
        self._connected = False

        # Counters for SAIA/MCP call tracking
        self.total_saia_calls = 0
        self.total_spl_queries = 0
        self.total_saved_searches = 0

    async def connect(self) -> None:
        """Establish connection to Splunk MCP Server."""
        if self.demo_mode:
            logger.info("MCP Client running in DEMO MODE — no live Splunk connection")
            self._connected = True
            return

        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            verify=self.verify_ssl,
            timeout=60.0,
        )

        try:
            resp = await self._http.get("/services/server/info", params={"output_mode": "json"})
            resp.raise_for_status()
            info = resp.json()
            server_name = info.get("entry", [{}])[0].get("content", {}).get("serverName", "unknown")
            logger.info(f"Connected to Splunk instance: {server_name}")
            self._connected = True
        except Exception as e:
            logger.error(f"CRITICAL: Failed to connect to live Splunk instance: {e}")
            raise RuntimeError(
                f"Failed to connect to live Splunk instance at {self.base_url}. "
                f"Please verify your SPLUNK_TOKEN, SPLUNK_HOST, and SPLUNK_PORT in your .env file. "
                f"Error details: {e}"
            ) from e

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._http:
            await self._http.aclose()
            self._http = None
        self._connected = False

    # ================================================================
    # Core MCP Tools — splunk_* namespace
    # ================================================================

    async def run_spl_query(
        self,
        spl: str,
        earliest: str = "-15m",
        latest: str = "now",
        max_results: int = 100,
    ) -> dict[str, Any]:
        """
        splunk_run_query — Execute SPL against live Splunk indexes.
        Primary data access tool for all agents.
        """
        start = datetime.now(timezone.utc)
        self.total_spl_queries += 1
        tool_label = "[MCP:splunk_run_query]"

        if self.demo_mode:
            from backend.demo.sample_data import get_demo_results
            results = get_demo_results(spl)
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.info(f"{tool_label} (demo) {spl[:80]}... → {len(results)} results")
            return {
                "query": spl,
                "results": results,
                "result_count": len(results),
                "execution_time_ms": elapsed + random.uniform(80, 250),
                "status": "success",
                "error": None,
                "tool_label": tool_label,
            }

        try:
            payload = {
                "search": f"search {spl}" if not spl.strip().startswith("|") else spl,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
                "count": max_results,
                "exec_mode": "oneshot",
            }
            resp = await self._http.post("/services/search/jobs/export", data=payload)
            resp.raise_for_status()

            results = []
            for line in resp.text.strip().split("\n"):
                if line.strip():
                    try:
                        obj = json.loads(line)
                        if "result" in obj:
                            results.append(obj["result"])
                    except json.JSONDecodeError:
                        continue

            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.info(f"{tool_label} {spl[:80]}... → {len(results)} results in {elapsed:.0f}ms")
            return {
                "query": spl,
                "results": results,
                "result_count": len(results),
                "execution_time_ms": elapsed,
                "status": "success",
                "error": None,
                "tool_label": tool_label,
            }
        except Exception as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.error(f"{tool_label} FAILED: {e}")
            return {
                "query": spl,
                "results": [],
                "result_count": 0,
                "execution_time_ms": elapsed,
                "status": "error",
                "error": str(e),
                "tool_label": tool_label,
            }

    async def get_indexes(self) -> list[dict]:
        """splunk_get_indexes — Discover available data indexes."""
        tool_label = "[MCP:splunk_get_indexes]"
        self.total_spl_queries += 1

        if self.demo_mode:
            indexes = [
                {"name": "sentinalops_os", "totalEventCount": 48523, "currentDBSizeMB": 12.4},
                {"name": "sentinalops_web", "totalEventCount": 125890, "currentDBSizeMB": 38.2},
                {"name": "_internal", "totalEventCount": 892341, "currentDBSizeMB": 156.8},
                {"name": "_audit", "totalEventCount": 12045, "currentDBSizeMB": 2.1},
                {"name": "main", "totalEventCount": 0, "currentDBSizeMB": 0},
            ]
            logger.info(f"{tool_label} (demo) → {len(indexes)} indexes")
            return indexes

        try:
            result = await self._call_mcp_tool("splunk_get_indexes", {})
            return result.get("indexes", [])
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return []

    async def get_metadata(self, index: str, meta_type: str = "sourcetypes") -> list[dict]:
        """splunk_get_metadata — Discover sourcetypes per index."""
        tool_label = "[MCP:splunk_get_metadata]"
        self.total_spl_queries += 1

        if self.demo_mode:
            sourcetypes = {
                "sentinalops_os": [
                    {"value": "linux_secure", "count": 18234},
                    {"value": "syslog", "count": 12450},
                    {"value": "linux_messages_syslog", "count": 8923},
                    {"value": "ps", "count": 4521},
                    {"value": "cpu", "count": 3210},
                ],
                "sentinalops_web": [
                    {"value": "access_combined", "count": 89234},
                    {"value": "nginx:error", "count": 2341},
                ],
                "_internal": [
                    {"value": "splunkd", "count": 456123},
                    {"value": "scheduler", "count": 23456},
                    {"value": "metrics", "count": 189234},
                ],
            }
            result = sourcetypes.get(index, [{"value": "unknown", "count": 0}])
            logger.info(f"{tool_label} (demo) {index} → {len(result)} sourcetypes")
            return result

        try:
            result = await self._call_mcp_tool("splunk_get_metadata", {
                "index": index, "type": meta_type,
                "earliest_time": "-24h", "latest_time": "now",
            })
            return result.get("metadata", [])
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return []

    async def get_saved_searches(self) -> list[dict]:
        """splunk_get_knowledge_objects type=saved_searches — Fetch saved searches/alerts."""
        tool_label = "[MCP:splunk_get_knowledge_objects]"
        self.total_spl_queries += 1

        if self.demo_mode:
            searches = [
                {"name": "Failed Login Spike Detector", "search": "index=sentinalops_os sourcetype=linux_secure Failed | stats count by src_ip | where count > 10", "is_scheduled": True},
                {"name": "Suspicious Process Monitor", "search": "index=sentinalops_os (wget OR curl OR chmod) | stats count by host user", "is_scheduled": True},
                {"name": "High Error Rate Alert", "search": "index=sentinalops_web status>=500 | timechart span=1m count | where count > 20", "is_scheduled": True},
            ]
            logger.info(f"{tool_label} (demo) → {len(searches)} saved searches")
            return searches

        try:
            result = await self._call_mcp_tool("splunk_get_knowledge_objects", {"type": "saved_searches"})
            return result.get("objects", [])
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return []

    async def run_saved_search(self, search_name: str) -> list[dict]:
        """splunk_run_saved_search (Beta) — Run existing correlation searches."""
        tool_label = "[MCP:splunk_run_saved_search]"
        self.total_saved_searches += 1

        if self.demo_mode:
            logger.info(f"{tool_label} (demo) Running: {search_name}")
            from backend.demo.sample_data import get_demo_results
            return get_demo_results(f"saved_search:{search_name}")

        try:
            result = await self._call_mcp_tool("splunk_run_saved_search", {"search_name": search_name})
            return result.get("results", [])
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return []

    # ================================================================
    # SAIA Tools — Splunk AI Assistant namespace
    # ================================================================

    async def saia_generate_spl(self, natural_language: str, index_context: str = "") -> str:
        """saia_generate_spl — Convert NL to optimised SPL. Core AI capability."""
        tool_label = "[SAIA:saia_generate_spl]"
        self.total_saia_calls += 1

        if self.demo_mode:
            spl = self._demo_generate_spl(natural_language, index_context)
            logger.info(f"{tool_label} (demo) '{natural_language[:50]}...' → SPL generated")
            return spl

        try:
            result = await self._call_mcp_tool("saia_generate_spl", {
                "query": natural_language,
                "index": index_context or self.default_index,
            })
            return result.get("spl", "")
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return ""

    async def saia_explain_spl(self, spl: str) -> str:
        """saia_explain_spl — Explain SPL in plain English for operator transparency."""
        tool_label = "[SAIA:saia_explain_spl]"
        self.total_saia_calls += 1

        if self.demo_mode:
            explanation = self._demo_explain_spl(spl)
            logger.info(f"{tool_label} (demo) Explained: {spl[:50]}...")
            return explanation

        try:
            result = await self._call_mcp_tool("saia_explain_spl", {"spl": spl})
            return result.get("explanation", "")
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return f"Unable to explain: {spl[:100]}"

    async def saia_optimize_spl(self, spl: str) -> str:
        """saia_optimize_spl — Optimize SPL before execution for performance."""
        tool_label = "[SAIA:saia_optimize_spl]"
        self.total_saia_calls += 1

        if self.demo_mode:
            # In demo, return the original with minor optimizations
            optimized = spl.replace("index=*", f"index={self.default_index}")
            if "| search" in optimized:
                optimized = optimized.replace("| search ", "")
            logger.info(f"{tool_label} (demo) SPL optimized for performance")
            return optimized

        try:
            result = await self._call_mcp_tool("saia_optimize_spl", {"spl": spl})
            return result.get("optimized_spl", spl)
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return spl  # fallback to original

    async def saia_ask_question(self, question: str) -> str:
        """saia_ask_splunk_question — Contextual Splunk help for operator."""
        tool_label = "[SAIA:saia_ask_splunk_question]"
        self.total_saia_calls += 1

        if self.demo_mode:
            answer = self._demo_ask_question(question)
            logger.info(f"{tool_label} (demo) Q: {question[:50]}...")
            return answer

        try:
            result = await self._call_mcp_tool("saia_ask_splunk_question", {"question": question})
            return result.get("answer", "")
        except Exception as e:
            logger.error(f"{tool_label} FAILED: {e}")
            return f"Unable to answer: {question[:100]}"

    # ================================================================
    # Health & Info
    # ================================================================

    async def health_check(self) -> bool:
        """Check if the Splunk connection is alive."""
        if self.demo_mode:
            return True
        try:
            resp = await self._http.get("/services/server/info", params={"output_mode": "json"})
            return resp.status_code == 200
        except Exception:
            return False

    def get_call_stats(self) -> dict:
        """Return current SAIA/MCP call statistics."""
        return {
            "total_saia_calls": self.total_saia_calls,
            "total_spl_queries": self.total_spl_queries,
            "total_saved_searches": self.total_saved_searches,
            "total_calls": self.total_saia_calls + self.total_spl_queries + self.total_saved_searches,
        }

    # ================================================================
    # Internal Helpers
    # ================================================================

    async def _call_mcp_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call a named tool on the Splunk MCP Server."""
        if self.demo_mode:
            logger.info(f"Demo mode: simulating MCP tool call '{tool_name}'")
            return {"status": "demo", "tool": tool_name, "result": {}}

        try:
            resp = await self._http.post(
                "/services/mcp/tools/call",
                json={"tool": tool_name, "arguments": arguments},
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"MCP tool call '{tool_name}' failed: {e}")
            return {"status": "error", "error": str(e)}

    # ================================================================
    # Demo Mode Simulators — Realistic SAIA responses
    # ================================================================

    def _demo_generate_spl(self, nl: str, index_ctx: str) -> str:
        """Generate realistic SPL from natural language in demo mode."""
        idx = index_ctx or self.default_index
        nl_lower = nl.lower()

        if "failed" in nl_lower and ("login" in nl_lower or "auth" in nl_lower):
            return f'index={idx} sourcetype=linux_secure "Failed password" | stats count by src_ip user | where count > 5 | sort -count'
        elif "process" in nl_lower or "suspicious" in nl_lower:
            return f'index={idx} sourcetype=syslog (wget OR curl OR "chmod +x" OR "/tmp/" OR base64) | stats count by host user process | sort -count'
        elif "successful" in nl_lower and "login" in nl_lower:
            return f'index={idx} sourcetype=linux_secure "Accepted" | stats count by src_ip user | sort -_time'
        elif "outbound" in nl_lower or "external" in nl_lower:
            return f'index={idx} sourcetype=syslog dest_ip!=10.* dest_ip!=192.168.* dest_ip!=172.16.* | stats count by src_ip dest_ip dest_port | sort -count'
        elif "privilege" in nl_lower or "escalat" in nl_lower:
            return f'index={idx} sourcetype=linux_secure ("sudo" OR "su ") | stats count by user host | where count > 3'
        elif "error" in nl_lower or "500" in nl_lower:
            return f'index={idx} sourcetype=access_combined status>=500 | timechart span=1m count | where count > 5'
        elif "lateral" in nl_lower or "movement" in nl_lower:
            return f'index={idx} sourcetype=linux_secure "Accepted" | stats dc(host) as hosts by user | where hosts > 1 | sort -hosts'
        elif "dns" in nl_lower or "domain" in nl_lower:
            return f'index={idx} sourcetype=syslog query | stats count by query | where count > 20 | sort -count'
        else:
            return f'index={idx} | stats count by sourcetype host | sort -count | head 20'

    def _demo_explain_spl(self, spl: str) -> str:
        """Generate realistic SPL explanation in demo mode."""
        if "Failed password" in spl or "failed" in spl.lower():
            return ("This search identifies authentication failures across the environment. "
                    "It counts failed password attempts grouped by source IP and username, "
                    "filtering for sources with more than 5 failures — a common indicator "
                    "of credential stuffing or brute-force attacks. Results are sorted by "
                    "frequency to highlight the most active attackers.")
        elif "wget" in spl or "curl" in spl or "chmod" in spl:
            return ("This search detects suspicious process executions including common "
                    "attack tools (wget, curl, chmod) and temporary directory usage. "
                    "These patterns often indicate post-exploitation activity where an "
                    "attacker downloads and executes payloads on compromised hosts.")
        elif "Accepted" in spl and "dc(host)" in spl:
            return ("This search identifies users who have authenticated to multiple distinct "
                    "hosts, which may indicate lateral movement. The distinct count threshold "
                    "highlights accounts accessing more hosts than normal, a key indicator "
                    "of credential abuse or compromised service accounts.")
        elif "status>=500" in spl:
            return ("This search monitors HTTP 500+ error rates over time. A spike in server "
                    "errors can indicate application-level attacks, resource exhaustion, or "
                    "service degradation caused by malicious activity.")
        elif "sudo" in spl or "su " in spl:
            return ("This search tracks privilege escalation events including sudo usage "
                    "and account switching. Elevated privilege activity from unusual users "
                    "or hosts may indicate an attacker has gained initial access and is "
                    "attempting to escalate privileges.")
        else:
            return (f"This SPL query searches across Splunk indexes to identify patterns "
                    f"in the data. The results are aggregated and filtered to highlight "
                    f"anomalies that may require investigation.")

    def _demo_ask_question(self, question: str) -> str:
        """Generate realistic Splunk question answer in demo mode."""
        q_lower = question.lower()
        if "remediat" in q_lower or "contain" in q_lower:
            return ("Based on the detected credential stuffing attack, recommended containment "
                    "steps are: 1) Block attacker source IP at the firewall level, "
                    "2) Force password reset for all targeted accounts, "
                    "3) Enable MFA enforcement for affected users, "
                    "4) Isolate any compromised hosts from the network, "
                    "5) Review authentication logs for successful logins from the attacker IP.")
        elif "severity" in q_lower or "critical" in q_lower:
            return ("This incident is assessed as CRITICAL severity based on: "
                    "successful credential compromise after brute force, lateral movement "
                    "detected across multiple hosts, and privilege escalation activity. "
                    "Immediate containment is recommended.")
        else:
            return ("Based on the current incident evidence, the agents have identified "
                    "multiple indicators of compromise across the environment. "
                    "Review the evidence board for detailed findings from each agent.")


# Singleton instance
_client: SplunkMCPClient | None = None


async def get_mcp_client(settings=None) -> SplunkMCPClient:
    """Get or create the singleton MCP client."""
    global _client
    if _client is None:
        if settings is None:
            from backend.config import get_settings
            settings = get_settings()

        _client = SplunkMCPClient(
            base_url=settings.splunk.base_url,
            token=settings.splunk.token,
            mode=settings.splunk.mcp_mode,
            index=settings.splunk.index,
            verify_ssl=settings.splunk.verify_ssl,
            demo_mode=settings.demo_mode,
        )
        await _client.connect()
    return _client
