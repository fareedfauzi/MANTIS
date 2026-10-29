"""Structured event logging for autonomous agent runs."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field


@dataclass
class AgentEvent:
    """One bounded, serializable event from an agent run."""

    kind: str
    payload: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        data = asdict(self)
        data["timestamp_iso"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
        )
        return data


class AgentEventLog:
    """Append-only in-memory event log with optional durable persistence."""

    def __init__(self, max_events=2000, goal_store=None, goal_id=""):
        self.max_events = max(1, int(max_events))
        self.events = []
        self.goal_store = goal_store
        self.goal_id = str(goal_id or "")

    def attach_goal(self, goal_store, goal_id):
        self.goal_store = goal_store
        self.goal_id = str(goal_id or "")

    def append(self, kind, **payload):
        event = AgentEvent(str(kind), dict(payload or {}))
        self.events.append(event)
        del self.events[:-self.max_events]
        self._persist(event)
        return event

    def clear(self):
        self.events = []

    def to_list(self):
        return [event.to_dict() for event in self.events]

    def export_json(self):
        return json.dumps(self.to_list(), ensure_ascii=False, indent=2)

    def _persist(self, event):
        if not self.goal_store or not self.goal_id:
            return
        try:
            self.goal_store.add_event(
                self.goal_id, event.kind, event.payload, event.timestamp,
            )
            if event.kind == "tool_result":
                self.goal_store.add_step(
                    self.goal_id,
                    "tool:%s" % event.payload.get("tool", ""),
                    status=event.payload.get("status", "unknown"),
                    result=event.payload.get("result_preview", ""),
                )
        except Exception:
            pass
