"""
SentinelOps — Evidence Board Manager
Thread-safe evidence board with WebSocket event broadcasting.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger("sentinelops.evidence")


class EvidenceBoard:
    """
    Central evidence board that manages incident state and broadcasts
    updates to all connected WebSocket clients in real time.
    """

    def __init__(self):
        self._state: dict[str, Any] = {}
        self._subscribers: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        self._event_history: list[dict] = []

    async def initialize(self, initial_state: dict) -> None:
        """Initialize the board with the starting incident state."""
        async with self._lock:
            self._state = dict(initial_state)
            self._event_history = []
        await self._broadcast({
            "type": "board_initialized",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "state": self._serialize_state(),
        })

    async def update(self, updates: dict, source: str = "system") -> None:
        """
        Apply partial updates to the board state and broadcast the change.

        Args:
            updates: Dict of field -> new value. For list fields, items are appended.
            source: The agent or system component that made the update.
        """
        async with self._lock:
            changes = {}
            for key, value in updates.items():
                if key in self._state:
                    old = self._state[key]
                    if isinstance(old, list) and isinstance(value, list):
                        self._state[key] = old + value
                    elif isinstance(old, dict) and isinstance(value, dict):
                        self._state[key] = {**old, **value}
                    else:
                        self._state[key] = value
                    changes[key] = self._serialize_value(self._state[key])
                else:
                    self._state[key] = value
                    changes[key] = self._serialize_value(value)

        event = {
            "type": "board_updated",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "changes": changes,
        }
        self._event_history.append(event)
        await self._broadcast(event)

    async def update_agent_status(self, agent: str, status: str, detail: str = "") -> None:
        """Update a specific agent's status and broadcast."""
        async with self._lock:
            if "agent_status" not in self._state:
                self._state["agent_status"] = {}
            self._state["agent_status"][agent] = status

        event = {
            "type": "agent_status_changed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "status": status,
            "detail": detail,
        }
        self._event_history.append(event)
        await self._broadcast(event)

    async def add_log_entry(self, agent: str, action: str, detail: str, spl_query: str = None) -> None:
        """Add an execution log entry and broadcast."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "action": action,
            "detail": detail,
            "spl_query": spl_query,
        }
        async with self._lock:
            if "execution_log" not in self._state:
                self._state["execution_log"] = []
            self._state["execution_log"].append(entry)

        event = {
            "type": "log_entry",
            "timestamp": entry["timestamp"],
            "entry": entry,
        }
        self._event_history.append(event)
        await self._broadcast(event)

    def get_state(self) -> dict:
        """Return a snapshot of the current board state."""
        return self._serialize_state()

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to board events. Returns a queue that receives events."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Remove a subscriber."""
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def _broadcast(self, event: dict) -> None:
        """Send an event to all subscribers."""
        dead_queues = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                dead_queues.append(queue)
                logger.warning("Subscriber queue full, dropping")

        for q in dead_queues:
            self._subscribers.remove(q)

    def _serialize_state(self) -> dict:
        """Serialize the entire state for JSON transmission."""
        return self._serialize_value(self._state)

    def _serialize_value(self, value: Any) -> Any:
        """Recursively serialize a value for JSON."""
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if isinstance(value, list):
            return [self._serialize_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}
        if isinstance(value, datetime):
            return value.isoformat()
        return value


# Singleton
_board: EvidenceBoard | None = None


def get_evidence_board() -> EvidenceBoard:
    """Get or create the singleton evidence board."""
    global _board
    if _board is None:
        _board = EvidenceBoard()
    return _board
