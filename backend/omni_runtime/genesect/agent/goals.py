"""Durable SQLite goal management for autonomous agent runs."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path


SCHEMA_VERSION = 1


def default_goal_db_path():
    root = Path.home() / ".genesect" / "agent_memory"
    return root / "goals.sqlite3"


class GoalStore:
    """Small SQLite store for goals, run events, steps, and findings."""

    def __init__(self, path=None):
        self.path = Path(path or default_goal_db_path())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def connect(self):
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with closing(self.connect()) as conn, conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS goals (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    binary_hash TEXT NOT NULL DEFAULT '',
                    root_ea TEXT NOT NULL DEFAULT '',
                    function_name TEXT NOT NULL DEFAULT '',
                    objective TEXT NOT NULL,
                    status TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    completed_at REAL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS goal_steps (
                    id TEXT PRIMARY KEY,
                    goal_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY(goal_id) REFERENCES goals(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_events (
                    id TEXT PRIMARY KEY,
                    goal_id TEXT,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    timestamp REAL NOT NULL,
                    FOREIGN KEY(goal_id) REFERENCES goals(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    goal_id TEXT NOT NULL,
                    claim TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'low',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    created_at REAL NOT NULL,
                    FOREIGN KEY(goal_id) REFERENCES goals(id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_goals_project ON goals(project_id, updated_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_goal_steps_goal ON goal_steps(goal_id, updated_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_events_goal ON agent_events(goal_id, timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_goal ON findings(goal_id, created_at)")
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def create_goal(
        self,
        objective,
        project_id,
        binary_hash="",
        root_ea="",
        function_name="",
        mode="",
        metadata=None,
    ):
        now = time.time()
        goal_id = uuid.uuid4().hex
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO goals(
                    id, project_id, binary_hash, root_ea, function_name,
                    objective, status, mode, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    goal_id,
                    str(project_id or "default"),
                    str(binary_hash or ""),
                    str(root_ea or ""),
                    str(function_name or ""),
                    str(objective or ""),
                    "active",
                    str(mode or ""),
                    now,
                    now,
                    json.dumps(metadata or {}, ensure_ascii=False),
                ),
            )
        return goal_id

    def update_goal(self, goal_id, status=None, metadata=None):
        if not goal_id:
            return
        now = time.time()
        assignments = ["updated_at = ?"]
        values = [now]
        if status:
            assignments.append("status = ?")
            values.append(str(status))
            if status in {"complete", "blocked", "stopped"}:
                assignments.append("completed_at = ?")
                values.append(now)
        if metadata is not None:
            assignments.append("metadata_json = ?")
            values.append(json.dumps(metadata, ensure_ascii=False))
        values.append(str(goal_id))
        with closing(self.connect()) as conn, conn:
            conn.execute(
                "UPDATE goals SET " + ", ".join(assignments) + " WHERE id = ?",
                values,
            )

    def add_step(self, goal_id, action, status="pending", result=""):
        if not goal_id:
            return ""
        now = time.time()
        step_id = uuid.uuid4().hex
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO goal_steps(id, goal_id, status, action, result, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (step_id, str(goal_id), str(status), str(action or ""), str(result or ""), now, now),
            )
            conn.execute("UPDATE goals SET updated_at = ? WHERE id = ?", (now, str(goal_id)))
        return step_id

    def add_event(self, goal_id, kind, payload=None, timestamp=None):
        now = float(timestamp or time.time())
        event_id = uuid.uuid4().hex
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO agent_events(id, goal_id, kind, payload_json, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    str(goal_id) if goal_id else None,
                    str(kind or ""),
                    json.dumps(payload or {}, ensure_ascii=False, default=str),
                    now,
                ),
            )
            if goal_id:
                conn.execute("UPDATE goals SET updated_at = ? WHERE id = ?", (now, str(goal_id)))
        return event_id

    def add_finding(self, goal_id, finding):
        if not goal_id or not finding:
            return ""
        finding_id = getattr(finding, "finding_id", "") or uuid.uuid4().hex
        now = time.time()
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings(
                    id, goal_id, claim, confidence, evidence_json, tags_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(finding_id),
                    str(goal_id),
                    str(getattr(finding, "claim", "")),
                    str(getattr(finding, "confidence", "low")),
                    json.dumps(getattr(finding, "evidence", []) or [], ensure_ascii=False),
                    json.dumps(getattr(finding, "tags", []) or [], ensure_ascii=False),
                    now,
                ),
            )
            conn.execute("UPDATE goals SET updated_at = ? WHERE id = ?", (now, str(goal_id)))
        return str(finding_id)

    def get_goal(self, goal_id):
        with closing(self.connect()) as conn, conn:
            row = conn.execute("SELECT * FROM goals WHERE id = ?", (str(goal_id),)).fetchone()
        return dict(row) if row else None

    def list_goals(self, project_id=None, limit=50):
        sql = "SELECT * FROM goals"
        values = []
        if project_id:
            sql += " WHERE project_id = ?"
            values.append(str(project_id))
        sql += " ORDER BY updated_at DESC LIMIT ?"
        values.append(max(1, int(limit)))
        with closing(self.connect()) as conn, conn:
            return [dict(row) for row in conn.execute(sql, values).fetchall()]

    def goal_events(self, goal_id, limit=200):
        with closing(self.connect()) as conn, conn:
            rows = conn.execute(
                """
                SELECT * FROM agent_events WHERE goal_id = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (str(goal_id), max(1, int(limit))),
            ).fetchall()
        return [dict(row) for row in rows]


def project_id_from_context(binary_hash="", idb_path=""):
    material = str(binary_hash or "").strip() or os.path.abspath(str(idb_path or "") or "default")
    return material or "default"
