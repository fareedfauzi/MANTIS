"""Durable cross-project memory for autonomous agent evidence."""

from __future__ import annotations

import json
import hashlib
import math
import re
import sqlite3
import time
from collections import Counter
from contextlib import closing
from pathlib import Path


SCHEMA_VERSION = 1
TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]{2,}|[0-9]{3,}")


def default_memory_db_path():
    root = Path.home() / ".genesect" / "agent_memory"
    return root / "memory.sqlite3"


def _tokens(text):
    terms = []
    for match in TOKEN_RE.finditer(str(text or "").lower()):
        token = match.group(0).strip("_")
        if len(token) >= 3:
            terms.append(token[:80])
    return terms


def _term_vector(*parts):
    return dict(Counter(_tokens("\n".join(str(part or "") for part in parts))))


def _cosine(left, right):
    if not left or not right:
        return 0.0
    overlap = set(left) & set(right)
    numerator = sum(float(left[key]) * float(right[key]) for key in overlap)
    left_norm = math.sqrt(sum(float(value) * float(value) for value in left.values()))
    right_norm = math.sqrt(sum(float(value) * float(value) for value in right.values()))
    if not left_norm or not right_norm:
        return 0.0
    return numerator / (left_norm * right_norm)


class MemoryStore:
    """SQLite-backed memory with deterministic lexical-vector retrieval."""

    def __init__(self, path=None):
        self.path = Path(path or default_memory_db_path())
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
                CREATE TABLE IF NOT EXISTS memory_records (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    binary_hash TEXT NOT NULL DEFAULT '',
                    scope TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    text TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    source_goal_id TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    terms_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_project ON memory_records(project_id, updated_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_kind ON memory_records(kind, updated_at)"
            )
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def upsert_record(
        self,
        record_id,
        project_id,
        kind,
        title,
        text,
        binary_hash="",
        scope="",
        evidence=None,
        tags=None,
        source_goal_id="",
        metadata=None,
    ):
        now = time.time()
        terms = _term_vector(title, text, " ".join(evidence or []), " ".join(tags or []))
        payload = (
            str(record_id),
            str(project_id or "default"),
            str(binary_hash or ""),
            str(scope or ""),
            str(kind or "note"),
            str(title or "")[:500],
            str(text or "")[:20000],
            json.dumps(evidence or [], ensure_ascii=False),
            json.dumps(tags or [], ensure_ascii=False),
            str(source_goal_id or ""),
            json.dumps(metadata or {}, ensure_ascii=False, default=str),
            json.dumps(terms, ensure_ascii=False),
            now,
            now,
        )
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO memory_records(
                    id, project_id, binary_hash, scope, kind, title, text,
                    evidence_json, tags_json, source_goal_id, metadata_json,
                    terms_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    project_id = excluded.project_id,
                    binary_hash = excluded.binary_hash,
                    scope = excluded.scope,
                    kind = excluded.kind,
                    title = excluded.title,
                    text = excluded.text,
                    evidence_json = excluded.evidence_json,
                    tags_json = excluded.tags_json,
                    source_goal_id = excluded.source_goal_id,
                    metadata_json = excluded.metadata_json,
                    terms_json = excluded.terms_json,
                    updated_at = excluded.updated_at
                """,
                payload,
            )
        return str(record_id)

    def record_finding(
        self,
        finding,
        project_id,
        binary_hash="",
        source_goal_id="",
        metadata=None,
    ):
        if not finding:
            return ""
        finding_id = getattr(finding, "finding_id", "") or hashlib.sha256(
            (
                str(getattr(finding, "claim", ""))
                + "\0"
                + "\0".join(str(item) for item in (getattr(finding, "evidence", []) or []))
            ).encode("utf-8")
        ).hexdigest()[:16]
        record_id = "finding:" + str(finding_id)
        return self.upsert_record(
            record_id=record_id,
            project_id=project_id,
            binary_hash=binary_hash,
            scope="global",
            kind="finding",
            title=str(getattr(finding, "claim", ""))[:500],
            text=str(getattr(finding, "claim", "")),
            evidence=getattr(finding, "evidence", []) or [],
            tags=getattr(finding, "tags", []) or [],
            source_goal_id=source_goal_id,
            metadata=metadata,
        )

    def record_function_summary(
        self,
        ea,
        record,
        project_id,
        binary_hash="",
        source_goal_id="",
    ):
        if not record:
            return ""
        canonical = str(ea or record.get("ea") or "").upper()
        title = "%s %s" % (canonical, record.get("current_name") or record.get("suggested_name") or "")
        text = "%s\n%s" % (record.get("summary", ""), record.get("last_error", ""))
        tags = ["function", str(record.get("state", "")), str(record.get("name_validation", ""))]
        return self.upsert_record(
            record_id="function:%s:%s" % (str(project_id or "default"), canonical),
            project_id=project_id,
            binary_hash=binary_hash,
            scope=canonical,
            kind="function_summary",
            title=title.strip(),
            text=text.strip(),
            evidence=record.get("evidence", []) or [],
            tags=[tag for tag in tags if tag],
            source_goal_id=source_goal_id,
            metadata=record,
        )

    def search(self, query, project_id=None, limit=10, include_cross_project=True):
        query = str(query or "").strip()
        query_vector = _term_vector(query)
        limit = max(1, min(int(limit or 10), 50))
        with closing(self.connect()) as conn:
            rows = conn.execute(
                """
                SELECT * FROM memory_records
                ORDER BY updated_at DESC
                LIMIT 2000
                """
            ).fetchall()
        scored = []
        lowered_query = query.lower()
        for row in rows:
            item = dict(row)
            same_project = project_id and item.get("project_id") == str(project_id)
            if project_id and not include_cross_project and not same_project:
                continue
            try:
                terms = json.loads(item.get("terms_json") or "{}")
            except Exception:
                terms = {}
            haystack = "\n".join([item.get("title", ""), item.get("text", "")]).lower()
            score = _cosine(query_vector, terms)
            if lowered_query and lowered_query in haystack:
                score += 0.35
            if same_project:
                score += 0.2
            if not query:
                score = 0.2 + (0.2 if same_project else 0.0)
            if score <= 0:
                continue
            item["score"] = round(float(score), 4)
            item["same_project"] = bool(same_project)
            scored.append(item)
        scored.sort(key=lambda item: (item["score"], item["updated_at"]), reverse=True)
        return [self._decode(row) for row in scored[:limit]]

    def list_records(self, project_id=None, limit=200):
        limit = max(1, min(int(limit or 200), 2000))
        sql = "SELECT * FROM memory_records"
        values = []
        if project_id:
            sql += " WHERE project_id = ?"
            values.append(str(project_id))
        sql += " ORDER BY updated_at DESC LIMIT ?"
        values.append(limit)
        with closing(self.connect()) as conn:
            rows = conn.execute(sql, values).fetchall()
        return [self._decode(row) for row in rows]

    def delete_record(self, record_id):
        with closing(self.connect()) as conn, conn:
            cur = conn.execute("DELETE FROM memory_records WHERE id = ?", (str(record_id),))
            return cur.rowcount > 0

    def export_records_json(self, project_id=None, limit=2000):
        return json.dumps(
            self.list_records(project_id=project_id, limit=limit),
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    def _decode(self, row):
        item = dict(row)
        for key in ("evidence_json", "tags_json"):
            try:
                item[key[:-5]] = json.loads(item.get(key) or "[]")
            except Exception:
                item[key[:-5]] = []
        try:
            item["metadata"] = json.loads(item.get("metadata_json") or "{}")
        except Exception:
            item["metadata"] = {}
        return item

    def format_results(self, results):
        if not results:
            return "No durable memory matched your query."
        lines = ["Durable memory matches:"]
        for item in results:
            scope = item.get("scope") or "global"
            project_hint = "same project" if item.get("same_project") else "cross-project"
            lines.append(
                "- [%s/%s score %.2f] %s: %s"
                % (
                    item.get("kind", "memory"),
                    project_hint,
                    float(item.get("score", 0.0)),
                    scope,
                    item.get("title") or item.get("text", "")[:120],
                )
            )
            text = str(item.get("text", "")).strip()
            if text:
                lines.append("  " + text[:500])
            evidence = item.get("evidence", []) or []
            if evidence:
                lines.append("  evidence: " + "; ".join(str(value) for value in evidence[:5]))
        return "\n".join(lines)
