"""MANTIS Custom Ransom Notes Database
Local SQLite database with FTS5 full-text search for analyst-curated ransom notes,
leak site contacts, crypto wallets, and attribution metadata.
"""

import json
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("mantis.ransom_notes_db")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "custom_ransom_notes.db")

os.makedirs(DATA_DIR, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """Initialize SQLite tables, triggers, and FTS5 search index."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_ransom_notes (
                id TEXT PRIMARY KEY,
                group_name TEXT NOT NULL,
                family TEXT,
                filename TEXT NOT NULL,
                extension TEXT,
                note_content TEXT NOT NULL,
                snippet TEXT,
                contact_email TEXT,
                contact_onion TEXT,
                contact_matrix TEXT,
                ransom_amount TEXT,
                crypto_wallet TEXT,
                analyst_notes TEXT,
                tags TEXT,
                author TEXT NOT NULL DEFAULT 'local_analyst',
                discovered_at TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_crn_created ON custom_ransom_notes(created_at DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_crn_group ON custom_ransom_notes(group_name);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_crn_discovered ON custom_ransom_notes(discovered_at DESC);")

        # FTS5 virtual table
        fts_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='custom_ransom_notes_fts';"
        ).fetchone()

        if not fts_exists:
            try:
                conn.execute("""
                    CREATE VIRTUAL TABLE custom_ransom_notes_fts USING fts5(
                        id UNINDEXED,
                        group_name,
                        family,
                        filename,
                        note_content,
                        contact_onion,
                        contact_email,
                        crypto_wallet,
                        tags,
                        analyst_notes,
                        tokenize='trigram'
                    );
                """)
                logger.info("Created custom_ransom_notes_fts with trigram tokenizer.")
            except sqlite3.OperationalError as e:
                logger.warning(f"Falling back to default tokenizer for custom_ransom_notes_fts: {e}")
                conn.execute("""
                    CREATE VIRTUAL TABLE IF NOT EXISTS custom_ransom_notes_fts USING fts5(
                        id UNINDEXED,
                        group_name,
                        family,
                        filename,
                        note_content,
                        contact_onion,
                        contact_email,
                        crypto_wallet,
                        tags,
                        analyst_notes
                    );
                """)

            # Create Triggers to keep FTS index synchronized
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS crn_after_insert AFTER INSERT ON custom_ransom_notes
                BEGIN
                    INSERT INTO custom_ransom_notes_fts(
                        id, group_name, family, filename, note_content,
                        contact_onion, contact_email, crypto_wallet, tags, analyst_notes
                    ) VALUES (
                        new.id, new.group_name, new.family, new.filename, new.note_content,
                        new.contact_onion, new.contact_email, new.crypto_wallet, new.tags, new.analyst_notes
                    );
                END;
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS crn_after_update AFTER UPDATE ON custom_ransom_notes
                BEGIN
                    DELETE FROM custom_ransom_notes_fts WHERE id = old.id;
                    INSERT INTO custom_ransom_notes_fts(
                        id, group_name, family, filename, note_content,
                        contact_onion, contact_email, crypto_wallet, tags, analyst_notes
                    ) VALUES (
                        new.id, new.group_name, new.family, new.filename, new.note_content,
                        new.contact_onion, new.contact_email, new.crypto_wallet, new.tags, new.analyst_notes
                    );
                END;
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS crn_after_delete AFTER DELETE ON custom_ransom_notes
                BEGIN
                    DELETE FROM custom_ransom_notes_fts WHERE id = old.id;
                END;
            """)

        conn.commit()

    # Seed 2 realistic custom notes if DB is empty
    seed_sample_notes_if_empty()


def _sanitize_tags(raw_tags: Any) -> str:
    if isinstance(raw_tags, list):
        tags = [str(t).strip().lower() for t in raw_tags if str(t).strip()]
        return json.dumps(list(dict.fromkeys(tags)))
    elif isinstance(raw_tags, str):
        parts = [p.strip().lower() for p in re.split(r"[,;\s]+", raw_tags) if p.strip()]
        return json.dumps(list(dict.fromkeys(parts)))
    return "[]"


def _parse_tags(tags_str: Optional[str]) -> List[str]:
    if not tags_str:
        return []
    try:
        data = json.loads(tags_str)
        if isinstance(data, list):
            return [str(x) for x in data]
    except Exception:
        pass
    return [p.strip() for p in tags_str.split(",") if p.strip()]


def _derive_snippet(content: str, max_len: int = 160) -> str:
    cleaned = re.sub(r"\s+", " ", content or "").strip()
    return cleaned[:max_len]


def create_custom_note(payload: Dict[str, Any], author: str = "local_analyst") -> Dict[str, Any]:
    """Create a new custom ransom note record."""
    group_name = str(payload.get("group_name") or payload.get("group") or "").strip()
    if not group_name:
        raise ValueError("Ransomware group name is required.")

    filename = str(payload.get("filename") or "").strip()
    if not filename:
        filename = f"{group_name.lower().replace(' ', '_')}_readme.txt"

    note_content = str(payload.get("note_content") or payload.get("note") or "").strip()
    if not note_content:
        raise ValueError("Ransom note content is required.")

    extension = str(payload.get("extension") or "").strip()
    if not extension and "." in filename:
        extension = "." + filename.rsplit(".", 1)[1].lower()
    elif not extension:
        extension = ".txt"

    family = str(payload.get("family") or group_name).strip()
    snippet = str(payload.get("snippet") or "").strip() or _derive_snippet(note_content)
    contact_email = str(payload.get("contact_email") or "").strip()
    contact_onion = str(payload.get("contact_onion") or "").strip()
    contact_matrix = str(payload.get("contact_matrix") or "").strip()
    ransom_amount = str(payload.get("ransom_amount") or "").strip()
    crypto_wallet = str(payload.get("crypto_wallet") or "").strip()
    analyst_notes = str(payload.get("analyst_notes") or "").strip()
    tags_json = _sanitize_tags(payload.get("tags"))
    
    discovered_at = str(payload.get("discovered_at") or "").strip()
    now_ts = int(time.time())
    if not discovered_at:
        discovered_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    note_id = str(payload.get("id") or "").strip()
    if not note_id:
        note_id = str(uuid.uuid4())

    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO custom_ransom_notes (
                id, group_name, family, filename, extension, note_content, snippet,
                contact_email, contact_onion, contact_matrix, ransom_amount,
                crypto_wallet, analyst_notes, tags, author, discovered_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            note_id, group_name, family, filename, extension, note_content, snippet,
            contact_email, contact_onion, contact_matrix, ransom_amount,
            crypto_wallet, analyst_notes, tags_json, author, discovered_at,
            now_ts, now_ts
        ))
        conn.commit()

    return get_custom_note(note_id) or {}


def get_custom_note(note_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single custom ransom note by ID."""
    clean_id = note_id.replace("custom:", "").strip()
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM custom_ransom_notes WHERE id = ?;", (clean_id,)).fetchone()
        if not row:
            return None
        res = dict(row)
        res["tags"] = _parse_tags(res.get("tags"))
        return res


def update_custom_note(note_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update an existing custom ransom note."""
    clean_id = note_id.replace("custom:", "").strip()
    existing = get_custom_note(clean_id)
    if not existing:
        return None

    group_name = str(payload.get("group_name") or payload.get("group") or existing["group_name"]).strip()
    family = str(payload.get("family") if "family" in payload else existing["family"]).strip()
    filename = str(payload.get("filename") or existing["filename"]).strip()
    
    note_content = str(payload.get("note_content") if "note_content" in payload else (payload.get("note") or existing["note_content"])).strip()
    if not note_content:
        note_content = existing["note_content"]

    extension = str(payload.get("extension") if "extension" in payload else existing["extension"]).strip()
    if not extension and "." in filename:
        extension = "." + filename.rsplit(".", 1)[1].lower()

    snippet = str(payload.get("snippet") if "snippet" in payload else existing["snippet"]).strip()
    if not snippet:
        snippet = _derive_snippet(note_content)

    contact_email = str(payload.get("contact_email") if "contact_email" in payload else existing.get("contact_email") or "").strip()
    contact_onion = str(payload.get("contact_onion") if "contact_onion" in payload else existing.get("contact_onion") or "").strip()
    contact_matrix = str(payload.get("contact_matrix") if "contact_matrix" in payload else existing.get("contact_matrix") or "").strip()
    ransom_amount = str(payload.get("ransom_amount") if "ransom_amount" in payload else existing.get("ransom_amount") or "").strip()
    crypto_wallet = str(payload.get("crypto_wallet") if "crypto_wallet" in payload else existing.get("crypto_wallet") or "").strip()
    analyst_notes = str(payload.get("analyst_notes") if "analyst_notes" in payload else existing.get("analyst_notes") or "").strip()

    tags_json = _sanitize_tags(payload.get("tags")) if "tags" in payload else json.dumps(existing.get("tags", []))
    discovered_at = str(payload.get("discovered_at") if "discovered_at" in payload else existing.get("discovered_at") or "").strip()
    now_ts = int(time.time())

    with get_db_connection() as conn:
        conn.execute("""
            UPDATE custom_ransom_notes SET
                group_name = ?,
                family = ?,
                filename = ?,
                extension = ?,
                note_content = ?,
                snippet = ?,
                contact_email = ?,
                contact_onion = ?,
                contact_matrix = ?,
                ransom_amount = ?,
                crypto_wallet = ?,
                analyst_notes = ?,
                tags = ?,
                discovered_at = ?,
                updated_at = ?
            WHERE id = ?;
        """, (
            group_name, family, filename, extension, note_content, snippet,
            contact_email, contact_onion, contact_matrix, ransom_amount,
            crypto_wallet, analyst_notes, tags_json, discovered_at, now_ts,
            clean_id
        ))
        conn.commit()

    return get_custom_note(clean_id)


def delete_custom_note(note_id: str) -> bool:
    """Delete a custom ransom note."""
    clean_id = note_id.replace("custom:", "").strip()
    with get_db_connection() as conn:
        cur = conn.execute("DELETE FROM custom_ransom_notes WHERE id = ?;", (clean_id,))
        conn.commit()
        return cur.rowcount > 0


def list_custom_notes(
    q: str = "",
    group: str = "",
    page: int = 1,
    page_size: int = 50
) -> Dict[str, Any]:
    """Search and paginate custom ransom notes."""
    q = (q or "").strip()
    group = (group or "").strip()
    page = max(1, int(page or 1))
    page_size = max(1, min(100, int(page_size or 50)))
    offset = (page - 1) * page_size

    with get_db_connection() as conn:
        if q:
            # Query with FTS5 or LIKE
            try:
                # Trigram search or match
                safe_q = f'"{q}"' if " " in q else f"*{q}*"
                count_row = conn.execute("""
                    SELECT COUNT(*) as c FROM custom_ransom_notes_fts f
                    JOIN custom_ransom_notes n ON f.id = n.id
                    WHERE custom_ransom_notes_fts MATCH ?
                    AND (? = '' OR LOWER(n.group_name) LIKE LOWER(?));
                """, (safe_q, group, f"%{group}%")).fetchone()
                total = count_row["c"] if count_row else 0

                rows = conn.execute("""
                    SELECT n.* FROM custom_ransom_notes_fts f
                    JOIN custom_ransom_notes n ON f.id = n.id
                    WHERE custom_ransom_notes_fts MATCH ?
                    AND (? = '' OR LOWER(n.group_name) LIKE LOWER(?))
                    ORDER BY n.created_at DESC
                    LIMIT ? OFFSET ?;
                """, (safe_q, group, f"%{group}%", page_size, offset)).fetchall()
            except sqlite3.OperationalError:
                # Fallback to standard LIKE
                like_str = f"%{q}%"
                count_row = conn.execute("""
                    SELECT COUNT(*) as c FROM custom_ransom_notes
                    WHERE (group_name LIKE ? OR family LIKE ? OR filename LIKE ? OR note_content LIKE ? OR analyst_notes LIKE ?)
                    AND (? = '' OR LOWER(group_name) LIKE LOWER(?));
                """, (like_str, like_str, like_str, like_str, like_str, group, f"%{group}%")).fetchone()
                total = count_row["c"] if count_row else 0

                rows = conn.execute("""
                    SELECT * FROM custom_ransom_notes
                    WHERE (group_name LIKE ? OR family LIKE ? OR filename LIKE ? OR note_content LIKE ? OR analyst_notes LIKE ?)
                    AND (? = '' OR LOWER(group_name) LIKE LOWER(?))
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?;
                """, (like_str, like_str, like_str, like_str, like_str, group, f"%{group}%", page_size, offset)).fetchall()
        else:
            count_row = conn.execute("""
                SELECT COUNT(*) as c FROM custom_ransom_notes
                WHERE (? = '' OR LOWER(group_name) LIKE LOWER(?));
            """, (group, f"%{group}%")).fetchone()
            total = count_row["c"] if count_row else 0

            rows = conn.execute("""
                SELECT * FROM custom_ransom_notes
                WHERE (? = '' OR LOWER(group_name) LIKE LOWER(?))
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?;
            """, (group, f"%{group}%", page_size, offset)).fetchall()

        items = []
        for r in rows:
            d = dict(r)
            d["tags"] = _parse_tags(d.get("tags"))
            items.append(d)

        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "notes": items
        }


def get_all_custom_notes_for_monitor(q: str = "", group: str = "") -> List[Dict[str, Any]]:
    """Retrieve all matching custom ransom notes formatted for Ransomware Monitor."""
    init_db()
    data = list_custom_notes(q=q, group=group, page=1, page_size=1000)
    out = []
    for item in data.get("notes", []):
        cid = item["id"]
        note_text = item.get("note_content") or ""
        out.append({
            "id": f"custom:{cid}",
            "custom_id": cid,
            "group": item.get("group_name") or "",
            "family": item.get("family") or item.get("group_name") or "",
            "filename": item.get("filename") or "README.txt",
            "extension": item.get("extension") or ".txt",
            "note": note_text,
            "snippet": item.get("snippet") or _derive_snippet(note_text),
            "contact_email": item.get("contact_email") or "",
            "contact_onion": item.get("contact_onion") or "",
            "contact_matrix": item.get("contact_matrix") or "",
            "ransom_amount": item.get("ransom_amount") or "",
            "crypto_wallet": item.get("crypto_wallet") or "",
            "analyst_notes": item.get("analyst_notes") or "",
            "tags": item.get("tags") or [],
            "author": item.get("author") or "local_analyst",
            "discovered_at": item.get("discovered_at") or datetime.fromtimestamp(item.get("created_at") or time.time(), tz=timezone.utc).strftime("%Y-%m-%d"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "source": "Custom DB",
            "sources": ["Custom DB"],
            "is_custom": True,
            "size": len(note_text.encode("utf-8")),
            "raw": item,
        })
    return out


def seed_sample_notes_if_empty() -> None:
    """Pre-populate 2 high-fidelity custom notes if the table is freshly created."""
    with get_db_connection() as conn:
        c = conn.execute("SELECT COUNT(*) as cnt FROM custom_ransom_notes;").fetchone()["cnt"]
        if c > 0:
            return

        sample1 = {
            "id": "crn-sample-lockbit3",
            "group_name": "LockBit 3.0",
            "family": "LockBit Black",
            "filename": "README_LOCKBIT3_CUSTOM.txt",
            "extension": ".txt",
            "note_content": """====================== LockBit 3.0 Ransomware Notice ======================
Your data has been stolen and encrypted using strong military-grade algorithms.
To recover your files and prevent leaked customer records, contact our support portal:

1) Download Tor Browser from https://www.torproject.org/
2) Open our negotiation portal: http://lockbit77vvxcuvdqut2kh556df536y6cq2e5g5x6d5h3w6nklqyid.onion
3) Enter your Decryption ID: 9F8A-43B2-8821-EAA0

Ransom Demand: $750,000 USD (payable in BTC or XMR)
Primary Wallet: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
Emergency Tox ID: 41B3E0A08C99D542AA91E1390497529481DF9C75A18C7E61

DO NOT rename files. DO NOT use third-party decryptors or your data will be permanently destroyed.""",
            "snippet": "LockBit 3.0 Ransomware Notice - Your data has been stolen and encrypted using strong military-grade algorithms...",
            "contact_onion": "http://lockbit77vvxcuvdqut2kh556df536y6cq2e5g5x6d5h3w6nklqyid.onion",
            "contact_email": "lockbit_support@tutanota.com",
            "contact_matrix": "41B3E0A08C99D542AA91E1390497529481DF9C75A18C7E61",
            "ransom_amount": "$750,000 USD",
            "crypto_wallet": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "analyst_notes": "Recovered from IR engagement 2026-Q1. Sample includes Tox failover and dual Tor onion endpoints.",
            "tags": ["lockbit", "double-extortion", "ir-case-2026", "lockbit-black"],
            "author": "lead_incident_responder",
            "discovered_at": "2026-11-15",
        }

        sample2 = {
            "id": "crn-sample-akira",
            "group_name": "Akira",
            "family": "Akira Linux/ESXi",
            "filename": "akira_readme.txt",
            "extension": ".txt",
            "note_content": """Hi Friends,
Whatever who you are and what your goals are, your network was compromised and sensitive virtual disks (.vmdk, .vmx) are encrypted.
We also dumped confidential financial data, NDAs, and source code archives.

To initiate negotiations and purchase decryptor:
1. Visit: https://akiralkzxzq2dsrhfd4q69.onion
2. Your Organization Code: AK-991284
3. Telegram: @akira_support_bot

We are not interested in destroying your business, only in receiving our fee.""",
            "snippet": "Akira Ransomware - Your network was compromised and sensitive virtual disks (.vmdk, .vmx) are encrypted...",
            "contact_onion": "https://akiralkzxzq2dsrhfd4q69.onion",
            "contact_email": "",
            "contact_matrix": "@akira_support_bot",
            "ransom_amount": "$350,000 USD",
            "crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "analyst_notes": "Observed in VMware ESXi hypervisor attack targeting staging clusters.",
            "tags": ["akira", "esxi", "linux-variant", "vm-encryption"],
            "author": "dfir_analyst",
            "discovered_at": "2026-11-18",
        }

        for s in (sample1, sample2):
            now_ts = int(time.time())
            conn.execute("""
                INSERT INTO custom_ransom_notes (
                    id, group_name, family, filename, extension, note_content, snippet,
                    contact_email, contact_onion, contact_matrix, ransom_amount,
                    crypto_wallet, analyst_notes, tags, author, discovered_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                s["id"], s["group_name"], s["family"], s["filename"], s["extension"],
                s["note_content"], s["snippet"], s["contact_email"], s["contact_onion"],
                s["contact_matrix"], s["ransom_amount"], s["crypto_wallet"],
                s["analyst_notes"], json.dumps(s["tags"]), s["author"], s["discovered_at"],
                now_ts, now_ts
            ))
        conn.commit()
        logger.info("Seeded initial custom ransom notes.")


# Auto-initialize on module load
try:
    init_db()
except Exception as e:
    logger.error(f"Failed to auto-init custom ransom notes DB: {e}")
