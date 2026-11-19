"""
MANTIS AI Threat Hunting Database Layer
Provides persistent SQLite storage for:
- Investigations (metadata, source documents, URLs, raw & normalized content)
- Extracted Intelligence Findings & Attacker Behaviors
- Threat Hunting Hypotheses
- Platform-Specific Hunting / Detection Queries
- Query Version History & Diff Tracking
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.environ.get("MANTIS_THREAT_HUNTING_DB") or os.path.join(DATA_DIR, "threat_hunting.db")


def _get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Initializes tables for threat hunting investigations."""
    with _get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS th_investigations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                source_type TEXT NOT NULL, -- 'file', 'url', 'text', 'multi'
                source_metadata TEXT DEFAULT '{}',
                raw_content TEXT DEFAULT '',
                normalized_content TEXT DEFAULT '',
                ai_provider TEXT DEFAULT '',
                ai_model TEXT DEFAULT '',
                summary TEXT DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS th_findings (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                category TEXT DEFAULT 'execution', -- Tactic or artifact category
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                attack_tactic TEXT DEFAULT '',
                attack_technique TEXT DEFAULT '',
                attack_id TEXT DEFAULT '',
                artifacts TEXT DEFAULT '[]', -- JSON array of IOCs, commands, paths, keys
                evidence_quote TEXT DEFAULT '',
                confidence TEXT DEFAULT 'confirmed', -- 'confirmed' or 'inferred'
                created_at REAL NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES th_investigations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS th_hypotheses (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                finding_id TEXT DEFAULT '',
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                supporting_evidence TEXT DEFAULT '',
                mitre_attack TEXT DEFAULT '',
                telemetry_required TEXT DEFAULT '',
                event_ids TEXT DEFAULT '',
                recommended_sources TEXT DEFAULT '',
                hunting_strategy TEXT DEFAULT '',
                expected_observations TEXT DEFAULT '',
                potential_false_positives TEXT DEFAULT '',
                investigation_pivots TEXT DEFAULT '',
                status TEXT DEFAULT 'proposed', -- 'proposed', 'approved', 'excluded'
                created_at REAL NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES th_investigations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS th_queries (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                hypothesis_id TEXT DEFAULT '',
                platform TEXT NOT NULL, -- e.g. 'splunk', 'sentinel', 'elastic_eql'
                query_language TEXT NOT NULL, -- e.g. 'SPL', 'KQL', 'EQL'
                mode TEXT DEFAULT 'hunting', -- 'hunting' or 'detection'
                title TEXT NOT NULL,
                query_text TEXT NOT NULL,
                telemetry_schema TEXT DEFAULT '{}',
                validation_status TEXT DEFAULT 'Not Verified', -- 'Validated', 'Warning', 'Failed', 'Not Verified'
                validation_details TEXT DEFAULT '{}',
                explanation TEXT DEFAULT '',
                tuning_guidance TEXT DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES th_investigations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS th_query_versions (
                id TEXT PRIMARY KEY,
                query_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                query_text TEXT NOT NULL,
                action TEXT DEFAULT 'generate', -- 'generate', 'optimize', 'reduce_fp', 'expand_coverage', 'fix_syntax', 'convert', 'manual_edit'
                diff TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at REAL NOT NULL,
                FOREIGN KEY (query_id) REFERENCES th_queries(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_th_findings_inv ON th_findings(investigation_id);
            CREATE INDEX IF NOT EXISTS idx_th_hypo_inv ON th_hypotheses(investigation_id);
            CREATE INDEX IF NOT EXISTS idx_th_queries_inv ON th_queries(investigation_id);
            CREATE INDEX IF NOT EXISTS idx_th_qversions_query ON th_query_versions(query_id);
        """)


init_db()


# ---------------------------------------------------------------------------
# Investigation CRUD
# ---------------------------------------------------------------------------

def create_investigation(
    title: str,
    source_type: str,
    raw_content: str,
    normalized_content: str = "",
    description: str = "",
    source_metadata: Optional[Dict[str, Any]] = None,
    ai_provider: str = "",
    ai_model: str = "",
    investigation_id: Optional[str] = None
) -> Dict[str, Any]:
    inv_id = investigation_id or f"th-inv-{uuid.uuid4().hex[:12]}"
    now = time.time()
    meta_json = json.dumps(source_metadata or {})

    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO th_investigations (
                id, title, description, source_type, source_metadata,
                raw_content, normalized_content, ai_provider, ai_model,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inv_id, title, description, source_type, meta_json,
                raw_content, normalized_content or raw_content, ai_provider, ai_model,
                now, now
            )
        )
    return get_investigation(inv_id)  # type: ignore


def append_investigation_content(
    investigation_id: str,
    text: str,
    source_type: str = "text",
    source_meta: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Append a newly ingested source to an investigation.

    An investigation holds one evidence blob (`raw_content`); uploading a second
    report must extend it rather than replace it. Every append is recorded in
    `source_metadata["sources"]`, and `source_type` becomes "multi" once more
    than one source has been ingested.
    """
    text = text or ""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT raw_content, source_type, source_metadata FROM th_investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if not row:
            return None
        existing = (row["raw_content"] or "").strip()
        try:
            meta = json.loads(row["source_metadata"] or "{}")
        except Exception:
            meta = {}
        sources = meta.get("sources")
        if not isinstance(sources, list):
            sources = []
        entry = dict(source_meta or {})
        entry.setdefault("source_type", source_type)
        entry["chars"] = len(text)
        entry["added_at"] = time.time()
        sources.append(entry)
        meta["sources"] = sources

        merged = f"{existing}\n\n{text.strip()}" if existing else text.strip()
        conn.execute(
            """
            UPDATE th_investigations
               SET raw_content = ?, normalized_content = ?, source_type = ?,
                   source_metadata = ?, updated_at = ?
             WHERE id = ?
            """,
            (
                merged,
                merged,
                "multi" if existing else source_type,
                json.dumps(meta),
                time.time(),
                investigation_id,
            ),
        )
    return get_investigation(investigation_id)


def update_investigation_summary(investigation_id: str, summary: str, title: Optional[str] = None) -> None:
    now = time.time()
    with _get_connection() as conn:
        if title:
            conn.execute(
                "UPDATE th_investigations SET summary = ?, title = ?, updated_at = ? WHERE id = ?",
                (summary, title, now, investigation_id)
            )
        else:
            conn.execute(
                "UPDATE th_investigations SET summary = ?, updated_at = ? WHERE id = ?",
                (summary, now, investigation_id)
            )


def list_investigations(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT i.id, i.title, i.description, i.source_type, i.source_metadata,
                   i.ai_provider, i.ai_model, i.summary, i.created_at, i.updated_at,
                   (SELECT COUNT(*) FROM th_findings WHERE investigation_id = i.id) as findings_count,
                   (SELECT COUNT(*) FROM th_hypotheses WHERE investigation_id = i.id) as hypotheses_count,
                   (SELECT COUNT(*) FROM th_queries WHERE investigation_id = i.id) as queries_count
            FROM th_investigations i
            ORDER BY i.updated_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset)
        ).fetchall()

        out = []
        for r in rows:
            d = dict(r)
            try:
                d["source_metadata"] = json.loads(d["source_metadata"])
            except Exception:
                d["source_metadata"] = {}
            out.append(d)
        return out


def get_investigation(investigation_id: str) -> Optional[Dict[str, Any]]:
    with _get_connection() as conn:
        row = conn.execute("SELECT * FROM th_investigations WHERE id = ?", (investigation_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["source_metadata"] = json.loads(d["source_metadata"])
        except Exception:
            d["source_metadata"] = {}

        # Fetch findings
        findings_rows = conn.execute(
            "SELECT * FROM th_findings WHERE investigation_id = ? ORDER BY created_at ASC",
            (investigation_id,)
        ).fetchall()
        d["findings"] = []
        for fr in findings_rows:
            f_dict = dict(fr)
            try:
                f_dict["artifacts"] = json.loads(f_dict["artifacts"])
            except Exception:
                f_dict["artifacts"] = []
            d["findings"].append(f_dict)

        # Fetch hypotheses
        hypo_rows = conn.execute(
            "SELECT * FROM th_hypotheses WHERE investigation_id = ? ORDER BY created_at ASC",
            (investigation_id,)
        ).fetchall()
        d["hypotheses"] = [dict(hr) for hr in hypo_rows]

        # Fetch queries
        query_rows = conn.execute(
            "SELECT * FROM th_queries WHERE investigation_id = ? ORDER BY created_at DESC",
            (investigation_id,)
        ).fetchall()
        d["queries"] = []
        for qr in query_rows:
            q_dict = dict(qr)
            try:
                q_dict["telemetry_schema"] = json.loads(q_dict["telemetry_schema"])
            except Exception:
                q_dict["telemetry_schema"] = {}
            try:
                q_dict["validation_details"] = json.loads(q_dict["validation_details"])
            except Exception:
                q_dict["validation_details"] = {}
            d["queries"].append(q_dict)

        return d


def delete_investigation(investigation_id: str) -> bool:
    with _get_connection() as conn:
        res = conn.execute("DELETE FROM th_investigations WHERE id = ?", (investigation_id,))
        return res.rowcount > 0


# ---------------------------------------------------------------------------
# Findings CRUD
# ---------------------------------------------------------------------------

def save_findings(investigation_id: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now = time.time()
    saved: List[Dict[str, Any]] = []

    with _get_connection() as conn:
        # Clear existing findings if refreshing
        conn.execute("DELETE FROM th_findings WHERE investigation_id = ?", (investigation_id,))

        for f in findings:
            fid = f.get("id") or f"th-fnd-{uuid.uuid4().hex[:10]}"
            artifacts_json = json.dumps(f.get("artifacts") or [])
            conn.execute(
                """
                INSERT INTO th_findings (
                    id, investigation_id, category, title, description,
                    attack_tactic, attack_technique, attack_id, artifacts,
                    evidence_quote, confidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fid,
                    investigation_id,
                    f.get("category", "execution"),
                    f.get("title", "Technical Finding"),
                    f.get("description", ""),
                    f.get("attack_tactic", ""),
                    f.get("attack_technique", ""),
                    f.get("attack_id", ""),
                    artifacts_json,
                    f.get("evidence_quote", ""),
                    f.get("confidence", "confirmed"),
                    now
                )
            )
            saved.append({**f, "id": fid, "investigation_id": investigation_id, "created_at": now})

        conn.execute("UPDATE th_investigations SET updated_at = ? WHERE id = ?", (now, investigation_id))
    return saved


# ---------------------------------------------------------------------------
# Hypotheses CRUD
# ---------------------------------------------------------------------------

def save_hypotheses(investigation_id: str, hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now = time.time()
    saved: List[Dict[str, Any]] = []

    with _get_connection() as conn:
        for h in hypotheses:
            hid = h.get("id") or f"th-hypo-{uuid.uuid4().hex[:10]}"
            conn.execute(
                """
                INSERT OR REPLACE INTO th_hypotheses (
                    id, investigation_id, finding_id, title, description,
                    supporting_evidence, mitre_attack, telemetry_required,
                    event_ids, recommended_sources, hunting_strategy,
                    expected_observations, potential_false_positives,
                    investigation_pivots, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hid,
                    investigation_id,
                    h.get("finding_id", ""),
                    h.get("title", "Threat Hunting Hypothesis"),
                    h.get("description", ""),
                    h.get("supporting_evidence", ""),
                    h.get("mitre_attack", ""),
                    h.get("telemetry_required", ""),
                    h.get("event_ids", ""),
                    h.get("recommended_sources", ""),
                    h.get("hunting_strategy", ""),
                    h.get("expected_observations", ""),
                    h.get("potential_false_positives", ""),
                    h.get("investigation_pivots", ""),
                    h.get("status", "proposed"),
                    now
                )
            )
            saved.append({**h, "id": hid, "investigation_id": investigation_id, "created_at": now})

        conn.execute("UPDATE th_investigations SET updated_at = ? WHERE id = ?", (now, investigation_id))
    return saved


def update_hypothesis_status(hypothesis_id: str, status: str) -> bool:
    with _get_connection() as conn:
        res = conn.execute("UPDATE th_hypotheses SET status = ? WHERE id = ?", (status, hypothesis_id))
        return res.rowcount > 0


# ---------------------------------------------------------------------------
# Queries & Versioning CRUD
# ---------------------------------------------------------------------------

def save_query(
    investigation_id: str,
    platform: str,
    query_language: str,
    title: str,
    query_text: str,
    hypothesis_id: str = "",
    mode: str = "hunting",
    telemetry_schema: Optional[Dict[str, Any]] = None,
    validation_status: str = "Not Verified",
    validation_details: Optional[Dict[str, Any]] = None,
    explanation: str = "",
    tuning_guidance: str = "",
    query_id: Optional[str] = None
) -> Dict[str, Any]:
    qid = query_id or f"th-qry-{uuid.uuid4().hex[:10]}"
    now = time.time()
    schema_json = json.dumps(telemetry_schema or {})
    val_json = json.dumps(validation_details or {})

    with _get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO th_queries (
                id, investigation_id, hypothesis_id, platform, query_language,
                mode, title, query_text, telemetry_schema, validation_status,
                validation_details, explanation, tuning_guidance,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                qid, investigation_id, hypothesis_id, platform, query_language,
                mode, title, query_text, schema_json, validation_status,
                val_json, explanation, tuning_guidance,
                now, now
            )
        )

        # Record initial version
        vid = f"th-ver-{uuid.uuid4().hex[:10]}"
        conn.execute(
            """
            INSERT INTO th_query_versions (
                id, query_id, version_number, query_text, action, diff, notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (vid, qid, 1, query_text, "generate", "", "Initial query generation", now)
        )

        conn.execute("UPDATE th_investigations SET updated_at = ? WHERE id = ?", (now, investigation_id))

    return get_query(qid)  # type: ignore


def record_query_version(
    query_id: str,
    query_text: str,
    action: str,
    diff: str = "",
    notes: str = "",
    validation_status: Optional[str] = None,
    validation_details: Optional[Dict[str, Any]] = None,
    explanation: Optional[str] = None
) -> Dict[str, Any]:
    now = time.time()
    with _get_connection() as conn:
        # Determine next version number
        last_ver = conn.execute(
            "SELECT MAX(version_number) as v FROM th_query_versions WHERE query_id = ?",
            (query_id,)
        ).fetchone()
        next_v = (last_ver["v"] or 0) + 1

        vid = f"th-ver-{uuid.uuid4().hex[:10]}"
        conn.execute(
            """
            INSERT INTO th_query_versions (
                id, query_id, version_number, query_text, action, diff, notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (vid, query_id, next_v, query_text, action, diff, notes, now)
        )

        # Update current query row
        updates = ["query_text = ?", "updated_at = ?"]
        params: List[Any] = [query_text, now]

        if validation_status:
            updates.append("validation_status = ?")
            params.append(validation_status)
        if validation_details is not None:
            updates.append("validation_details = ?")
            params.append(json.dumps(validation_details))
        if explanation is not None:
            updates.append("explanation = ?")
            params.append(explanation)

        params.append(query_id)
        conn.execute(f"UPDATE th_queries SET {', '.join(updates)} WHERE id = ?", tuple(params))

    return get_query(query_id)  # type: ignore


def get_query(query_id: str) -> Optional[Dict[str, Any]]:
    with _get_connection() as conn:
        row = conn.execute("SELECT * FROM th_queries WHERE id = ?", (query_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["telemetry_schema"] = json.loads(d["telemetry_schema"])
        except Exception:
            d["telemetry_schema"] = {}
        try:
            d["validation_details"] = json.loads(d["validation_details"])
        except Exception:
            d["validation_details"] = {}

        # Fetch versions
        versions = conn.execute(
            "SELECT * FROM th_query_versions WHERE query_id = ? ORDER BY version_number ASC",
            (query_id,)
        ).fetchall()
        d["versions"] = [dict(v) for v in versions]
        return d
