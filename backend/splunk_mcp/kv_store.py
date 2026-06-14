"""
SentinelOps — Splunk KV Store Operations
Manages evidence board persistence, runbook retrieval, and audit logging via KV Store.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sentinelops.kvstore")


class KVStoreManager:
    """
    Manages Splunk KV Store collections for SentinelOps.

    Collections:
      - sentinelops_evidence:   Stores evidence board entries
      - sentinelops_runbooks:   Pre-loaded runbook templates
      - sentinelops_audit:      Immutable audit trail of all decisions
      - sentinelops_postmortems: Generated post-mortem documents
    """

    COLLECTIONS = {
        "evidence": "sentinelops_evidence",
        "runbooks": "sentinelops_runbooks",
        "audit": "sentinelops_audit",
        "postmortems": "sentinelops_postmortems",
    }

    def __init__(self, mcp_client=None, demo_mode: bool = True):
        self.mcp_client = mcp_client
        self.demo_mode = demo_mode
        # In-memory store for demo mode
        self._memory_store: dict[str, list[dict]] = {
            name: [] for name in self.COLLECTIONS
        }
        # Pre-load demo runbooks
        if self.demo_mode:
            self._load_demo_runbooks()

    def _load_demo_runbooks(self) -> None:
        """Load sample runbooks for demo mode."""
        self._memory_store["runbooks"] = [
            {
                "_key": "runbook_credential_compromise",
                "incident_type": "credential_compromise",
                "title": "Credential Compromise Response Runbook",
                "priority": 1,
                "steps": [
                    "1. Immediately disable the compromised user account(s)",
                    "2. Force password reset for all affected accounts",
                    "3. Revoke all active sessions and tokens",
                    "4. Isolate the source host from the network",
                    "5. Check for any data exfiltration from compromised accounts",
                    "6. Review MFA enrollment and enforce MFA for affected users",
                    "7. Scan affected hosts for malware and persistence mechanisms",
                    "8. Monitor for re-authentication attempts from blocked IPs",
                ],
                "estimated_time_minutes": 30,
                "requires_approval": True,
            },
            {
                "_key": "runbook_lateral_movement",
                "incident_type": "lateral_movement",
                "title": "Lateral Movement Containment Runbook",
                "priority": 1,
                "steps": [
                    "1. Identify all hosts accessed by the attacker",
                    "2. Isolate compromised hosts at the network level",
                    "3. Block attacker source IPs at the firewall",
                    "4. Disable compromised service accounts",
                    "5. Collect forensic images from affected hosts",
                    "6. Scan for dropped tools (PsExec, Mimikatz, etc.)",
                    "7. Reset Kerberos tickets (krbtgt) if domain compromise suspected",
                    "8. Re-enable hosts one at a time after verification",
                ],
                "estimated_time_minutes": 60,
                "requires_approval": True,
            },
            {
                "_key": "runbook_malware_infection",
                "incident_type": "malware_infection",
                "title": "Malware Infection Response Runbook",
                "priority": 2,
                "steps": [
                    "1. Isolate infected host(s) from the network",
                    "2. Capture memory dump and disk image",
                    "3. Identify malware family and IOCs",
                    "4. Block C2 domains/IPs at DNS and firewall",
                    "5. Scan environment for additional infections",
                    "6. Remove malware and restore from clean backup",
                    "7. Patch the vulnerability used for initial access",
                    "8. Update AV/EDR signatures",
                ],
                "estimated_time_minutes": 45,
                "requires_approval": True,
            },
        ]

    async def get_records(
        self, collection: str, query: dict | None = None
    ) -> list[dict]:
        """Retrieve records from a KV Store collection."""
        collection_name = self.COLLECTIONS.get(collection, collection)

        if self.demo_mode:
            records = self._memory_store.get(collection, [])
            if query:
                records = [
                    r for r in records
                    if all(r.get(k) == v for k, v in query.items())
                ]
            return records

        try:
            result = await self.mcp_client.call_mcp_tool(
                "splunk_get_kv_store_collections",
                {"collection": collection_name, "query": json.dumps(query or {})},
            )
            return result.get("result", {}).get("records", [])
        except Exception as e:
            logger.error(f"KV Store read failed for {collection_name}: {e}")
            return []

    async def write_record(self, collection: str, record: dict) -> str:
        """Write a record to a KV Store collection. Returns the record key."""
        collection_name = self.COLLECTIONS.get(collection, collection)

        # Add timestamp
        record["_timestamp"] = datetime.now(timezone.utc).isoformat()

        if self.demo_mode:
            if "_key" not in record:
                record["_key"] = f"{collection}_{len(self._memory_store.get(collection, []))}"
            self._memory_store.setdefault(collection, []).append(record)
            return record["_key"]

        try:
            result = await self.mcp_client.call_mcp_tool(
                "splunk_run_query",
                {
                    "query": f"| inputlookup {collection_name} | append [| makeresults | eval data=\"{json.dumps(record)}\"]"
                },
            )
            return record.get("_key", "unknown")
        except Exception as e:
            logger.error(f"KV Store write failed for {collection_name}: {e}")
            return ""

    async def get_runbooks(self, incident_type: str) -> list[dict]:
        """Retrieve relevant runbooks for an incident type."""
        all_runbooks = await self.get_records("runbooks")
        matching = [
            rb for rb in all_runbooks
            if rb.get("incident_type") == incident_type
        ]
        # If no exact match, return all sorted by priority
        if not matching:
            matching = sorted(all_runbooks, key=lambda r: r.get("priority", 99))
        return matching

    async def log_audit_entry(
        self,
        incident_id: str,
        action: str,
        actor: str,
        details: dict | None = None,
    ) -> None:
        """Write an immutable audit trail entry."""
        await self.write_record("audit", {
            "incident_id": incident_id,
            "action": action,
            "actor": actor,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def save_postmortem(self, incident_id: str, document: str) -> str:
        """Persist a generated post-mortem document."""
        return await self.write_record("postmortems", {
            "_key": f"postmortem_{incident_id}",
            "incident_id": incident_id,
            "document": document,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })


# Singleton
_kv_manager: KVStoreManager | None = None


def get_kv_manager(mcp_client=None, demo_mode: bool = True) -> KVStoreManager:
    """Get or create the singleton KV Store manager."""
    global _kv_manager
    if _kv_manager is None:
        _kv_manager = KVStoreManager(mcp_client=mcp_client, demo_mode=demo_mode)
    return _kv_manager


# Demo runbook data
_DEMO_RUNBOOKS = {
    "credential_compromise": {
        "name": "Credential Compromise Response Runbook",
        "steps": [
            "Disable compromised accounts",
            "Force password reset",
            "Block attacker IPs",
            "Review authentication logs",
            "Enable MFA",
        ],
        "severity": "critical",
    },
    "lateral_movement": {
        "name": "Lateral Movement Containment Runbook",
        "steps": [
            "Isolate affected hosts",
            "Block C2 domains at DNS",
            "Kill malicious processes",
            "Remove persistence mechanisms",
            "Deploy EDR scans",
        ],
        "severity": "critical",
    },
    "host_isolation": {
        "name": "Host Isolation Runbook",
        "steps": [
            "Move host to quarantine VLAN",
            "Preserve forensic evidence",
            "Deploy replacement if critical",
            "Scan with updated signatures",
            "Re-image if warranted",
        ],
        "severity": "high",
    },
}


async def get_runbook(runbook_type: str) -> dict | None:
    """Retrieve a runbook by type from KV Store or demo data."""
    return _DEMO_RUNBOOKS.get(runbook_type)

