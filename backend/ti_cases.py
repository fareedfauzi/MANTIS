"""Shared TI cases and canonical IOC registry for the current MANTIS installation."""
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DATA = Path(__file__).resolve().parent / "data"
DB = DATA / "ti_cases.db"
UPLOADS = DATA / "malware_db" / "samples"
DATA.mkdir(exist_ok=True)


@contextmanager
def connect():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    try:
        with db:
            yield db
    finally:
        db.close()


def init():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Open', notes TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '[]', ttps TEXT NOT NULL DEFAULT '[]',
            references_json TEXT NOT NULL DEFAULT '[]',
            created_by TEXT NOT NULL, updated_by TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY, value TEXT NOT NULL, normalized TEXT NOT NULL,
            type TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            assessment TEXT NOT NULL DEFAULT 'Unknown', confidence TEXT NOT NULL DEFAULT 'Low',
            first_seen TEXT, last_seen TEXT, tags TEXT NOT NULL DEFAULT '[]',
            references_json TEXT NOT NULL DEFAULT '[]',
            added_by TEXT NOT NULL, updated_by TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            UNIQUE(type, normalized)
        );
        CREATE TABLE IF NOT EXISTS case_iocs (
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
            note TEXT NOT NULL DEFAULT '', PRIMARY KEY(case_id, ioc_id)
        );
        CREATE TABLE IF NOT EXISTS case_samples (
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            sha256 TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'local',
            filename TEXT NOT NULL DEFAULT '', md5 TEXT NOT NULL DEFAULT '',
            sha1 TEXT NOT NULL DEFAULT '', size INTEGER NOT NULL DEFAULT 0,
            metadata TEXT NOT NULL DEFAULT '{}', added_by TEXT NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY(case_id, sha256, source)
        );
        CREATE TABLE IF NOT EXISTS case_relations (
            left_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            right_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            reason TEXT NOT NULL DEFAULT '', PRIMARY KEY(left_id, right_id),
            CHECK(left_id < right_id)
        );
        CREATE TABLE IF NOT EXISTS case_activity (
            id INTEGER PRIMARY KEY, case_id INTEGER, actor TEXT NOT NULL,
            action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cases_updated ON cases(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_iocs_updated ON iocs(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_case_iocs_ioc ON case_iocs(ioc_id);
        """)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def items(value, maximum=100):
    if isinstance(value, str):
        value = re.split(r"[,\n]", value)
    if not isinstance(value, list):
        raise ValueError("Expected a list")
    return list(dict.fromkeys(str(v).strip()[:500] for v in value[:maximum] if str(v).strip()))


def normalize(value, kind=None):
    value = str(value or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("IOC must be between 1 and 2048 characters")
    value = re.sub(r"(?i)^hxxps://", "https://", value)
    value = re.sub(r"(?i)^hxxp://", "http://", value).replace("[.]", ".")
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
        detected, normalized = "ip", ip.compressed
    except ValueError:
        if re.fullmatch(r"[a-fA-F0-9]{32}", value):
            detected, normalized = "md5", value.lower()
        elif re.fullmatch(r"[a-fA-F0-9]{40}", value):
            detected, normalized = "sha1", value.lower()
        elif re.fullmatch(r"[a-fA-F0-9]{64}", value):
            detected, normalized = "sha256", value.lower()
        elif re.match(r"(?i)^https?://", value):
            url = urlsplit(value)
            if not url.hostname or url.username or url.password:
                raise ValueError("Invalid URL")
            host = url.hostname.lower().rstrip(".")
            port = f":{url.port}" if url.port else ""
            normalized = urlunsplit((url.scheme.lower(), host + port, url.path or "/", url.query, ""))
            detected = "url"
        elif re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            detected, normalized = "email", value.lower()
        elif re.fullmatch(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,63}", value):
            detected, normalized = "domain", value.lower().rstrip(".")
        else:
            detected, normalized = "other", value.casefold()
    kind = (kind or "auto").lower().replace("-", "")
    if kind in ("auto", "hash"):
        kind = detected
    elif kind not in ("ip", "domain", "url", "md5", "sha1", "sha256", "email",
                      "filename", "mutex", "registry", "other"):
        raise ValueError("Unsupported IOC type")
    elif kind in ("ip", "domain", "url", "md5", "sha1", "sha256", "email") and kind != detected:
        raise ValueError(f"IOC is a {detected}, not a {kind}")
    elif detected != "other" and kind not in ("filename", "mutex", "registry", "other") and kind != detected:
        raise ValueError(f"IOC is a {detected}, not a {kind}")
    return value, kind, normalized


def activity(db, case_id, actor, action, details=""):
    db.execute("INSERT INTO case_activity(case_id,actor,action,details,created_at) VALUES (?,?,?,?,?)",
               (case_id, actor, action, details[:500], now()))


def case_exists(db, case_id):
    if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise KeyError("Case not found")


def row_json(row, fields=("tags", "ttps", "references_json", "metadata")):
    out = dict(row)
    for field in fields:
        if field in out:
            out[field] = json.loads(out[field])
    if "references_json" in out:
        out["references"] = out.pop("references_json")
    return out


def case_detail(case_id):
    with connect() as db:
        row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise KeyError("Case not found")
        result = row_json(row)
        result["case_id"] = f"TI-{case_id:06d}"
        result["iocs"] = [row_json(r) for r in db.execute(
            "SELECT i.*, ci.note FROM iocs i JOIN case_iocs ci ON ci.ioc_id=i.id WHERE ci.case_id=? ORDER BY i.updated_at DESC", (case_id,))]
        result["samples"] = [row_json(r) for r in db.execute(
            "SELECT * FROM case_samples WHERE case_id=? ORDER BY created_at DESC", (case_id,))]
        result["related_cases"] = [dict(r) for r in db.execute(
            """SELECT c.id,c.name,r.reason FROM case_relations r JOIN cases c
               ON c.id=CASE WHEN r.left_id=? THEN r.right_id ELSE r.left_id END
               WHERE r.left_id=? OR r.right_id=?""", (case_id, case_id, case_id))]
        result["activity"] = [dict(r) for r in db.execute(
            "SELECT actor,action,details,created_at FROM case_activity WHERE case_id=? ORDER BY id DESC LIMIT 100", (case_id,))]
        return result


def list_cases(q="", status="", tag="", limit=50, offset=0):
    clauses, params = [], []
    if q:
        clauses.append("(c.name LIKE ? OR c.description LIKE ? OR EXISTS (SELECT 1 FROM case_iocs ci JOIN iocs i ON i.id=ci.ioc_id WHERE ci.case_id=c.id AND i.value LIKE ?) OR c.id=?)")
        match = re.fullmatch(r"TI-(\d{1,12})", q.strip(), re.IGNORECASE)
        params.extend([f"%{q}%"] * 3 + [int(match.group(1)) if match else -1])
    if status:
        clauses.append("c.status=?"); params.append(status)
    if tag:
        clauses.append("c.tags LIKE ?"); params.append(f'%"{tag}"%')
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as db:
        count = db.execute(f"SELECT count(*) FROM cases c {where}", params).fetchone()[0]
        rows = db.execute(f"""SELECT c.*, (SELECT count(*) FROM case_iocs WHERE case_id=c.id) ioc_count
            FROM cases c {where} ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""", [*params, limit, offset])
        return {"total": count, "items": [dict(row_json(r), case_id=f"TI-{r['id']:06d}") for r in rows]}


def save_case(data, actor, case_id=None):
    name = str(data.get("name") or "").strip()[:200]
    if not name:
        raise ValueError("Case name required")
    status = data.get("status", "Open")
    if status not in ("Open", "Investigating", "Closed"):
        raise ValueError("Invalid case status")
    fields = (name, str(data.get("description") or "")[:10000], status,
              str(data.get("notes") or "")[:100000],
              json.dumps(items(data.get("tags", []))),
              json.dumps(items(data.get("ttps", []))),
              json.dumps(items(data.get("references", []))))
    with connect() as db:
        if case_id:
            case_exists(db, case_id)
            db.execute("""UPDATE cases SET name=?,description=?,status=?,notes=?,tags=?,ttps=?,
                references_json=?,updated_by=?,updated_at=? WHERE id=?""",
                (*fields, actor, now(), case_id))
            activity(db, case_id, actor, "updated")
        else:
            cur = db.execute("""INSERT INTO cases(name,description,status,notes,tags,ttps,references_json,
                created_by,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (*fields, actor, actor, now(), now()))
            case_id = cur.lastrowid
            activity(db, case_id, actor, "created")
    return case_detail(case_id)


def delete_case(case_id, actor):
    with connect() as db:
        case_exists(db, case_id)
        activity(db, case_id, actor, "deleted")
        db.execute("DELETE FROM cases WHERE id=?", (case_id,))


def ioc_detail(ioc_id):
    with connect() as db:
        row = db.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row:
            raise KeyError("IOC not found")
        result = row_json(row)
        result["related_cases"] = [dict(r) for r in db.execute(
            "SELECT c.id,c.name,ci.note FROM cases c JOIN case_iocs ci ON ci.case_id=c.id WHERE ci.ioc_id=? ORDER BY c.updated_at DESC", (ioc_id,))]
        return result


def save_ioc(data, actor, ioc_id=None):
    value, kind, normalized = normalize(data.get("value"), data.get("type"))
    assessment = data.get("assessment", "Unknown")
    confidence = data.get("confidence", "Low")
    if assessment not in ("Malicious", "Suspicious", "Benign", "Unknown") or confidence not in ("Low", "Medium", "High"):
        raise ValueError("Invalid assessment or confidence")
    first, last = data.get("first_seen") or None, data.get("last_seen") or None
    for date in (first, last):
        if date:
            datetime.fromisoformat(str(date).replace("Z", "+00:00"))
    fields = (value, normalized, kind, str(data.get("description") or "")[:10000],
              assessment, confidence, first, last, json.dumps(items(data.get("tags", []))),
              json.dumps(items(data.get("references", []))))
    with connect() as db:
        if ioc_id:
            if not db.execute("SELECT 1 FROM iocs WHERE id=?", (ioc_id,)).fetchone():
                raise KeyError("IOC not found")
            db.execute("""UPDATE iocs SET value=?,normalized=?,type=?,description=?,assessment=?,
                confidence=?,first_seen=?,last_seen=?,tags=?,references_json=?,updated_by=?,
                updated_at=? WHERE id=?""", (*fields, actor, now(), ioc_id))
        else:
            cur = db.execute("""INSERT OR IGNORE INTO iocs(value,normalized,type,description,assessment,confidence,
                first_seen,last_seen,tags,references_json,added_by,updated_by,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*fields, actor, actor, now(), now()))
            ioc_id = db.execute("SELECT id FROM iocs WHERE type=? AND normalized=?", (kind, normalized)).fetchone()[0]
            if not cur.rowcount and data.get("references"):
                existing = db.execute("SELECT references_json FROM iocs WHERE id=?", (ioc_id,)).fetchone()
                merged = items(json.loads(existing[0]) + items(data["references"]))
                db.execute("UPDATE iocs SET references_json=?,updated_by=?,updated_at=? WHERE id=?",
                           (json.dumps(merged), actor, now(), ioc_id))
    return ioc_detail(ioc_id)


def list_iocs(q="", kind="", assessment="", tag="", limit=50, offset=0):
    clauses, params = [], []
    if q:
        clauses.append("(i.value LIKE ? OR i.description LIKE ?)"); params += [f"%{q}%"] * 2
    if kind:
        clauses.append("i.type=?"); params.append(kind)
    if assessment:
        clauses.append("i.assessment=?"); params.append(assessment)
    if tag:
        clauses.append("i.tags LIKE ?"); params.append(f'%"{tag}"%')
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as db:
        count = db.execute(f"SELECT count(*) FROM iocs i {where}", params).fetchone()[0]
        rows = db.execute(f"""SELECT i.*, (SELECT count(*) FROM case_iocs WHERE ioc_id=i.id) case_count
            FROM iocs i {where} ORDER BY i.updated_at DESC LIMIT ? OFFSET ?""", [*params, limit, offset])
        return {"total": count, "items": [row_json(r) for r in rows]}


def lookup(value, kind=None):
    try:
        _, kind, normalized = normalize(value, kind)
    except ValueError:
        return None
    with connect() as db:
        row = db.execute("SELECT id FROM iocs WHERE type=? AND normalized=?", (kind, normalized)).fetchone()
    return ioc_detail(row["id"]) if row else None


def link_ioc(case_id, ioc_id, actor, note=""):
    with connect() as db:
        case_exists(db, case_id)
        if not db.execute("SELECT 1 FROM iocs WHERE id=?", (ioc_id,)).fetchone():
            raise KeyError("IOC not found")
        db.execute("INSERT INTO case_iocs(case_id,ioc_id,note) VALUES (?,?,?) ON CONFLICT(case_id,ioc_id) DO UPDATE SET note=CASE WHEN excluded.note != '' THEN excluded.note ELSE case_iocs.note END",
                   (case_id, ioc_id, note[:5000]))
        db.execute("UPDATE cases SET updated_at=?,updated_by=? WHERE id=?", (now(), actor, case_id))
        activity(db, case_id, actor, "linked IOC", str(ioc_id))


def unlink_ioc(case_id, ioc_id, actor):
    with connect() as db:
        case_exists(db, case_id)
        db.execute("DELETE FROM case_iocs WHERE case_id=? AND ioc_id=?", (case_id, ioc_id))
        activity(db, case_id, actor, "unlinked IOC", str(ioc_id))


def update_case_ioc_note(case_id, ioc_id, note, actor):
    with connect() as db:
        case_exists(db, case_id)
        changed = db.execute("UPDATE case_iocs SET note=? WHERE case_id=? AND ioc_id=?",
                             (str(note)[:5000], case_id, ioc_id))
        if not changed.rowcount:
            raise KeyError("IOC is not linked to this case")
        db.execute("UPDATE cases SET updated_at=?, updated_by=? WHERE id=?", (now(), actor, case_id))
        activity(db, case_id, actor, "updated IOC note", str(ioc_id))


def relation(case_id, related_id, reason, actor, remove=False):
    a, b = sorted((case_id, related_id))
    if a == b:
        raise ValueError("Cannot link a case to itself")
    with connect() as db:
        case_exists(db, a); case_exists(db, b)
        if remove:
            db.execute("DELETE FROM case_relations WHERE left_id=? AND right_id=?", (a, b))
        else:
            db.execute("INSERT INTO case_relations VALUES (?,?,?) ON CONFLICT(left_id,right_id) DO UPDATE SET reason=excluded.reason",
                       (a, b, reason[:500]))
        activity(db, case_id, actor, "unlinked case" if remove else "linked case", str(related_id))


def link_sample(case_id, sample, actor, source="local"):
    with connect() as db:
        case_exists(db, case_id)
        db.execute("""INSERT OR IGNORE INTO case_samples
            (case_id,sha256,source,filename,md5,sha1,size,metadata,added_by,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (case_id, sample["sha256"], source, str(sample.get("original_filename") or sample.get("filename") or "")[:255],
             sample.get("md5", ""), sample.get("sha1", ""), sample.get("file_size", sample.get("size", 0)),
             json.dumps(sample.get("metadata", {})), actor, now()))
        activity(db, case_id, actor, "linked sample", sample["sha256"])


def unlink_sample(case_id, sha256, source, actor):
    with connect() as db:
        case_exists(db, case_id)
        db.execute("DELETE FROM case_samples WHERE case_id=? AND sha256=? AND source=?", (case_id, sha256, source))
        activity(db, case_id, actor, "unlinked sample", sha256)


init()
