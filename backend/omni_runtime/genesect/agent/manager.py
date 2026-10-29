"""Convenience accessors for durable agent state outside an active run."""

from __future__ import annotations

import json

from .goals import GoalStore
from .memory import MemoryStore


class AgentStateManager:
    """Read-only facade over durable goals and memory."""

    def __init__(self, goal_store=None, memory_store=None):
        self.goal_store = goal_store or GoalStore()
        self.memory_store = memory_store or MemoryStore()

    def snapshot(self, project_id=None, query="", goal_limit=20, memory_limit=20):
        goals = []
        memory = []
        try:
            goals = self.goal_store.list_goals(project_id=project_id, limit=goal_limit)
        except Exception as exc:
            goals = [{"error": "could not read goals", "details": str(exc)}]
        try:
            memory = self.memory_store.search(
                query,
                project_id=project_id,
                limit=memory_limit,
                include_cross_project=True,
            )
        except Exception as exc:
            memory = [{"error": "could not read memory", "details": str(exc)}]
        return {
            "project_id": project_id or "",
            "query": query or "",
            "goals": goals,
            "memory": memory,
        }

    def export_json(self, project_id=None, query=""):
        return json.dumps(
            self.snapshot(project_id=project_id, query=query),
            ensure_ascii=False,
            indent=2,
        )
