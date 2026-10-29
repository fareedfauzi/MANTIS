"""Telegram Intelligence: artifact parser + discovery + investigations.

MANTIS-native implementation of Telegram-malware investigation techniques
(Bot API getMe/getUpdates/forwardMessage, multi-bot collection, artifact
recovery from intel sources).

PASSIVE (never touches Telegram): artifact parsing, ThreatFox / URLScan /
MalwareBazaar / CTI-Articles discovery, stream aggregation.
ACTIVE (explicit analyst initiation only): token validation (getMe),
Full/Live collection (getUpdates + forwardMessage into the analyst
destination chat). Discovery NEVER triggers active operations.

Safety: no deleteWebhook/setWebhook/sendMessage/send-poll calls anywhere;
read-only getChat/getWebhookInfo diagnostics only. Tokens are stored locally
(required for collection jobs), identified by fingerprint, masked in every
response, and never written to logs.
"""
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid

import requests

logger = logging.getLogger("mantis.tg")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TG_DB_PATH = os.path.join(DATA_DIR, "telegram_intel.db")

TG_API_BASE = "https://api.telegram.org"
TG_TIMEOUT = 25
TG_UA = "Mozilla/5.0 (compatible; MANTIS-TG/1.0; passive research client)"

# Strict raw bot-token shape: <bot-id>:<35-char secret>.
TOKEN_RE = re.compile(r"\b(\d{6,12}):([A-Za-z0-9_-]{35})\b")
# Bot API URLs carrying a token.
BOT_URL_RE = re.compile(
    r"https?://api\.telegram\.org/bot(\d{6,12}:[A-Za-z0-9_-]{35})(/[A-Za-z0-9_./?=&%+-]*)?",
    re.IGNORECASE)
# Explicit chat-id assignments only — never nearby bare numbers.
CHAT_ID_RE = re.compile(
    r"(?:chat[_-]?id|chatId|chatID|CHAT_ID)\s*[:=]\s*(-?\d{5,15})")
BOT_USERNAME_RE = re.compile(r"@([A-Za-z0-9_]{5,32}[Bb][Oo][Tt])\b")

CTI_SIGNALS = ("api.telegram.org", "telegram bot api", "bot token",
               "chat_id", "sendmessage", "senddocument", "sendphoto")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tg_bots (
    id TEXT PRIMARY KEY,
    bot_id TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    token_fp TEXT NOT NULL DEFAULT '',
    token TEXT NOT NULL DEFAULT '',
    token_state TEXT NOT NULL DEFAULT 'not-validated',
    chat_id TEXT NOT NULL DEFAULT '',
    dest_chat_id TEXT NOT NULL DEFAULT '',
    transport TEXT NOT NULL DEFAULT 'native',
    mode TEXT NOT NULL DEFAULT 'full',
    state TEXT NOT NULL DEFAULT 'idle',
    last_update_id INTEGER NOT NULL DEFAULT 0,
    first_message_at TEXT DEFAULT '',
    latest_message_at TEXT DEFAULT '',
    total_messages INTEGER NOT NULL DEFAULT 0,
    failed_ids TEXT NOT NULL DEFAULT '[]',
    last_error TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tg_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id TEXT NOT NULL,
    message_id INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT DEFAULT '',
    chat_id TEXT DEFAULT '',
    sender TEXT DEFAULT '',
    msg_type TEXT DEFAULT 'text',
    text TEXT DEFAULT '',
    file_name TEXT DEFAULT '',
    file_size INTEGER DEFAULT 0,
    mime_type TEXT DEFAULT '',
    caption TEXT DEFAULT '',
    reply_to INTEGER DEFAULT 0,
    forwarded INTEGER DEFAULT 0,
    raw TEXT DEFAULT '',
    UNIQUE(bot_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_tg_messages_bot ON tg_messages(bot_id);
CREATE INDEX IF NOT EXISTS idx_tg_messages_time ON tg_messages(timestamp);
CREATE TABLE IF NOT EXISTS tg_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT '',
    value TEXT NOT NULL DEFAULT '',
    observed_value TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    malware_family TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    first_seen TEXT DEFAULT '',
    last_seen TEXT DEFAULT '',
    validation TEXT NOT NULL DEFAULT 'not-validated',
    UNIQUE(kind, value, source)
);
"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def connect(path: str = "") -> sqlite3.Connection:
    db_path = path or TG_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=120000")
    except sqlite3.Error:
        pass
    return conn


def init_db(path: str = "") -> str:
    db_path = path or TG_DB_PATH
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()
    return db_path


def _migrate(conn: sqlite3.Connection):
    """Additive columns for newer capabilities (safe on existing DBs)."""
    try:
        msg_cols = {r[1] for r in conn.execute("PRAGMA table_info(tg_messages)").fetchall()}
        if "copied" not in msg_cols:
            conn.execute("ALTER TABLE tg_messages ADD COLUMN copied INTEGER DEFAULT 0")
        bot_cols = {r[1] for r in conn.execute("PRAGMA table_info(tg_bots)").fetchall()}
        if "dump_done" not in bot_cols:
            conn.execute("ALTER TABLE tg_bots ADD COLUMN dump_done INTEGER DEFAULT 0")
        if "dump_total" not in bot_cols:
            conn.execute("ALTER TABLE tg_bots ADD COLUMN dump_total INTEGER DEFAULT 0")
        if "transport" not in bot_cols:
            conn.execute("ALTER TABLE tg_bots ADD COLUMN transport TEXT NOT NULL DEFAULT 'native'")
        art_cols = {r[1] for r in conn.execute("PRAGMA table_info(tg_artifacts)").fetchall()}
        if "link" not in art_cols:
            conn.execute("ALTER TABLE tg_artifacts ADD COLUMN link TEXT DEFAULT ''")
    except sqlite3.Error:
        pass


def token_fingerprint(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()[:16]


def mask_token(token: str) -> str:
    """12345678:ABC**************XYZ — safe for UI display."""
    token = (token or "").strip()
    if ":" in token:
        head, _, secret = token.partition(":")
        if len(secret) >= 8:
            return f"{head}:{secret[:3]}**************{secret[-3:]}"
        return f"{head}:***"
    if len(token) >= 8:
        return f"{token[:3]}**************{token[-3:]}"
    return "***"


def _redact(obj):
    """Deep-copy with token-shaped values scrubbed for logs/errors."""
    if isinstance(obj, dict):
        return {k: "***" if k in ("token", "bot_token") else _redact(v)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, str):
        return TOKEN_RE.sub(lambda m: f"{m.group(1)}:***", obj)
    return obj


# ---------------------------------------------------------------------------
# Minimal Bot API client (ACTIVE surface; called only from explicit actions)
# ---------------------------------------------------------------------------
def _bot_call(token: str, method: str, params: dict = None,
              timeout: int = TG_TIMEOUT, retries: int = 3) -> dict:
    """Bot API call with exponential-backoff retry on network errors only.

    API-level errors (bad token, blocked, unknown chat) are returned
    immediately — retrying those is pointless and noisy.
    """
    url = f"{TG_API_BASE}/bot{token}/{method}"
    delay = 1.0
    for attempt in range(max(1, retries)):
        try:
            resp = requests.post(url, json=params or {}, timeout=timeout,
                                 headers={"User-Agent": TG_UA})
            break
        except requests.exceptions.RequestException as e:
            if attempt == max(1, retries) - 1:
                return {"ok": False, "error": f"network: {type(e).__name__}"}
            time.sleep(delay)
            delay *= 2
    try:
        data = resp.json()
    except ValueError:
        return {"ok": False, "error": f"HTTP {resp.status_code}: non-JSON"}
    if not isinstance(data, dict) or not data.get("ok"):
        desc = ""
        try:
            desc = str(data.get("description", ""))[:200]
        except Exception:
            pass
        return {"ok": False, "error": desc or f"HTTP {resp.status_code}"}
    return {"ok": True, "result": data.get("result")}


def bot_validate(token: str) -> dict:
    """getMe only: safe read-only validation, explicit analyst action."""
    token = (token or "").strip()
    if not TOKEN_RE.fullmatch(token):
        m = TOKEN_RE.search(token)
        if not m:
            return {"ok": False, "error": "Not a valid bot-token shape"}
        token = m.group(0)
    out = _bot_call(token, "getMe", timeout=15)
    if not out.get("ok"):
        return {"ok": False, "error": out.get("error", "validation failed")}
    res = out["result"] if isinstance(out.get("result"), dict) else {}
    return {"ok": True, "bot_id": str(res.get("id", "")),
            "username": res.get("username", "") or "",
            "display_name": res.get("first_name", "") or "",
            "token_fp": token_fingerprint(token)}


def bot_info(token: str) -> dict:
    """Return read-only getMe metadata without exposing the token in a URL response."""
    token = (token or "").strip()
    if not TOKEN_RE.fullmatch(token):
        return {"ok": False, "error": "Not a valid bot-token shape"}
    out = _bot_call(token, "getMe", timeout=15)
    if not out.get("ok"):
        return {"ok": False, "error": out.get("error", "Unable to fetch bot information")}
    result = out.get("result")
    if not isinstance(result, dict):
        return {"ok": False, "error": "Telegram returned an invalid bot-information response"}
    return {"ok": True, "result": result}


def bot_diagnostics(token: str) -> dict:
    """Read-only diagnostics: webhook state + bot identity. No changes."""
    info = {"webhook": {}, "me": {}}
    wh = _bot_call(token, "getWebhookInfo", timeout=15)
    if wh.get("ok") and isinstance(wh.get("result"), dict):
        r = wh["result"]
        info["webhook"] = {"url_set": bool(r.get("url")),
                           "pending_updates": r.get("pending_update_count", 0),
                           "last_error": (r.get("last_error_message") or "")[:200]}
    me = bot_validate(token)
    if me.get("ok"):
        info["me"] = {k: me[k] for k in ("bot_id", "username", "display_name") if k in me}
    return info


# ---------------------------------------------------------------------------
# Artifact parser (PASSIVE)
# ---------------------------------------------------------------------------
def _window(text: str, start: int, end: int, size: int = 120) -> str:
    s = max(0, start - size)
    e = min(len(text), end + size)
    return text[s:e].strip()[:600]


def parse_telegram_artifacts(text: str, source: str = "",
                             malware_family: str = "", tags=None,
                             link: str = "", title: str = "",
                             date: str = "") -> list:
    """Extract bot URLs / tokens / chat ids / usernames with evidence.

    Chat IDs only from explicit assignments; tokens only in strict shape.
    Returns [{kind, value, observed_value, ...}] (normalized + observed).
    link/title/date ride along for grouped display (never stored).
    """
    text = text or ""
    tags = tags or []
    tag_str = ",".join(str(t) for t in tags if t)[:300]
    found: dict = {}

    def add(kind, value, observed, start, end):
        if not kind or not value:
            return
        key = (kind, value, source)
        if key in found:
            return
        found[key] = {
            "kind": kind, "value": value,
            "observed_value": (observed or value)[:500],
            "source": source or "", "malware_family": malware_family or "",
            "tags": tag_str, "evidence": _window(text, start, end),
            "link": (link or "")[:500], "title": (title or "")[:200],
            "date": (date or "")[:40],
        }

    for m in BOT_URL_RE.finditer(text):
        token = m.group(1)
        add("bot_token", token, m.group(0), m.start(), m.end())
        add("api_url", "https://api.telegram.org/bot" + token,
            m.group(0), m.start(), m.end())
    for m in TOKEN_RE.finditer(text):
        token = m.group(0)
        add("bot_token", token, token, m.start(), m.end())
    for m in CHAT_ID_RE.finditer(text):
        add("chat_id", m.group(1), m.group(0), m.start(), m.end())
    for m in BOT_USERNAME_RE.finditer(text):
        add("bot_username", "@" + m.group(1), m.group(0), m.start(), m.end())
    return list(found.values())


def dedupe_key(kind: str, value: str) -> str:
    return hashlib.sha1(f"{kind}|{value}".encode()).hexdigest()[:16]


def _blob_text(obj) -> str:
    try:
        return json.dumps(obj, default=str)[:20000]
    except Exception:
        return str(obj)[:20000]


def _tf_items(payload) -> list:
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return payload["data"]
    return []


def _fam_of(item: dict) -> str:
    for k in ("malware", "malware_printable", "family"):
        v = item.get(k)
        if isinstance(v, str) and v:
            return v[:120]
    return ""


def _tags_of(item: dict) -> list:
    tags = item.get("tags")
    if isinstance(tags, list):
        return [str(t) for t in tags if t][:12]
    if isinstance(tags, str) and tags:
        return [tags[:120]]
    return []


# ---------------------------------------------------------------------------
# Artifact Discovery (PASSIVE — existing MANTIS clients only)
# ---------------------------------------------------------------------------
def discover_threatfox(api_key: str = "", query: str = "api.telegram.org",
                       size: int = 100, with_tag: bool = True) -> dict:
    """ThreatFox IOCs mentioning a term (existing client).

    Default query mirrors the reference discovery; with_tag adds a
    best-effort tag sweep for the default query only.
    """
    from intel_query import query_threatfox, query_tf_keyword
    artifacts = []
    try:
        res = query_threatfox((query or "api.telegram.org").strip() or "api.telegram.org",
                              api_key or "")
        items = _tf_items(res)[:max(1, size)]
        for item in items:
            if not isinstance(item, dict):
                continue
            ioc = str(item.get("ioc", ""))
            link = ioc if ioc.lower().startswith(("http://", "https://")) else ""
            artifacts.extend(parse_telegram_artifacts(
                _blob_text(item), source="ThreatFox",
                malware_family=_fam_of(item), tags=_tags_of(item),
                link=link, title=_fam_of(item),
                date=str(item.get("first_seen", "") or "")))
    except Exception as e:
        return {"error": str(e)[:300], "artifacts": []}
    if with_tag and (query or "").strip() in ("", "api.telegram.org"):
        try:
            tag_res = query_tf_keyword("telegram", "taginfo", api_key or "")
            for item in _tf_items(tag_res)[:max(1, size)]:
                if not isinstance(item, dict):
                    continue
                artifacts.extend(parse_telegram_artifacts(
                    _blob_text(item), source="ThreatFox",
                    malware_family=_fam_of(item), tags=_tags_of(item),
                    date=str(item.get("first_seen", "") or "")))
        except Exception:
            pass
    return {"total": len(artifacts), "artifacts": _merge_artifacts(artifacts)}


def discover_urlscan(api_key: str = "") -> dict:
    """urlscan.io scans referencing api.telegram.org (existing client)."""
    return discover_urlscan_query(api_key, "api.telegram.org")


def discover_urlscan_query(api_key: str = "", domain: str = "api.telegram.org",
                           size: int = 50) -> dict:
    """Per-domain urlscan search (existing domain query client)."""
    from intel_query import query_urlscan
    domain = (domain or "").strip() or "api.telegram.org"
    try:
        res = query_urlscan(domain, "domain", api_key or "",
                            size=max(1, min(int(size or 50), 100)))
    except Exception as e:
        return {"error": str(e)[:300], "artifacts": []}
    if isinstance(res, dict) and res.get("error"):
        return {"error": str(res["error"])[:300], "artifacts": []}
    artifacts = []
    scans = []
    if isinstance(res, dict):
        scans = res.get("results", []) or []
    for item in scans if isinstance(scans, list) else []:
        if not isinstance(item, dict):
            continue
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        page = item.get("page") if isinstance(item.get("page"), dict) else {}
        fam = ""
        for k in ("malware_family", "family"):
            v = item.get(k)
            if isinstance(v, str) and v:
                fam = v[:120]
                break
        link = page.get("url") or task.get("url") or ""
        title = page.get("title") or ""
        date = task.get("time") or ""
        artifacts.extend(parse_telegram_artifacts(
            _blob_text(item), source="URLScan", malware_family=fam,
            tags=task.get("tags") if isinstance(task.get("tags"), list) else [],
            link=link, title=title, date=date))
    return {"total": len(artifacts), "artifacts": _merge_artifacts(artifacts)}


def discover_malwarebazaar(api_key: str = "") -> dict:
    """Recent telegram_bot_api YARA matches, metadata only (existing client)."""
    from intel_query import query_mb_keyword
    try:
        res = query_mb_keyword("telegram_bot_api", "get_yarainfo", api_key or "")
    except Exception as e:
        return {"error": str(e)[:300], "artifacts": [], "samples": []}
    data = res.get("data", []) if isinstance(res, dict) else []
    samples = []
    artifacts = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        samples.append({
            "sha256": item.get("sha256", "") or "",
            "sha1": item.get("sha1", "") or "",
            "md5": item.get("md5", "") or "",
            "file_name": item.get("file_name", "") or "",
            "file_type": item.get("file_type", "") or "",
            "file_size": item.get("file_size", "") or "",
            "signature": item.get("signature", "") or "",
            "tags": item.get("tags", []) if isinstance(item.get("tags"), list) else [],
            "first_seen": item.get("first_seen", "") or "",
            "reporter": item.get("reporter", "") or "",
            "yara": "telegram_bot_api",
        })
        artifacts.extend(parse_telegram_artifacts(
            _blob_text(item), source="MalwareBazaar",
            malware_family=item.get("signature", "") or "",
            tags=item.get("tags", []) if isinstance(item.get("tags"), list) else []))
    samples = [s for s in samples if s["sha256"]]
    # Recent-first, last 14 days like the reference feed (matkap parity).
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 14 * 86400))
    recent = [s for s in samples if (s.get("first_seen") or "") >= cutoff]
    recent.sort(key=lambda s: s.get("first_seen", ""), reverse=True)
    samples = recent[:100]
    return {"total": len(artifacts), "artifacts": _merge_artifacts(artifacts),
            "samples_total": len(samples), "samples": samples}


def discover_cti_articles(limit: int = 50) -> dict:
    """Local CTI repository: articles with Telegram-malware signals."""
    try:
        import cti_db as cti_db_mod
    except Exception as e:
        return {"error": f"CTI repository unavailable: {e}", "reports": []}
    conn = cti_db_mod.connect()
    try:
        seen = {}
        for sig in CTI_SIGNALS:
            try:
                rows = conn.execute(
                    "SELECT article_id, bm25(articles_fts) AS r FROM articles_fts"
                    " WHERE articles_fts MATCH ? ORDER BY r LIMIT 40",
                    (f'"{sig}"',)).fetchall()
            except Exception:
                continue
            for r in rows:
                aid = r["article_id"]
                seen.setdefault(aid, []).append(sig)
        out = []
        for aid, sigs in list(seen.items())[:max(1, limit)]:
            row = conn.execute(
                "SELECT a.*, s.name AS source_name FROM articles a"
                " LEFT JOIN sources s ON s.id = a.source_id WHERE a.id = ?",
                (aid,)).fetchone()
            if not row:
                continue
            d = dict(row)
            out.append({"article_id": d["id"], "title": d.get("title", ""),
                        "source": d.get("source_name", ""),
                        "published": d.get("published_at", "") or d.get("fetched_at", ""),
                        "url": d.get("url", ""),
                        "excerpt": (d.get("excerpt", "") or "")[:300],
                        "matched_signal": sigs[0], "signals": sigs})
        out.sort(key=lambda r: r["published"], reverse=True)
        return {"total": len(out), "reports": out}
    finally:
        conn.close()


def _merge_artifacts(artifacts: list) -> list:
    merged: dict = {}
    for a in artifacts:
        key = (a["kind"], a["value"], a["source"])
        if key not in merged:
            merged[key] = dict(a)
            merged[key]["count"] = 1
        else:
            merged[key]["count"] += 1
            fams = {merged[key]["malware_family"], a["malware_family"]} - {""}
            merged[key]["malware_family"] = sorted(fams)[0] if fams else ""
    return list(merged.values())


def _host_of(link: str, fallback: str = "") -> str:
    try:
        from urllib.parse import urlsplit
        return (urlsplit(link or "").hostname or fallback or "").lower()
    except ValueError:
        return fallback or ""


def group_discovery(artifacts: list) -> dict:
    """Normalize discovery hits into source-result groups.

    One card per (source, evidence page): {source, source_url, title, host,
    observed_at, artifacts:[{type, observed_value, normalized_value}]}.
    Bot tokens seen in several groups keep every provenance in `seen_in`.
    """
    groups: dict = {}
    for a in artifacts or []:
        if not isinstance(a, dict) or not a.get("value"):
            continue
        link = (a.get("link") or "").strip()
        title = (a.get("title") or "").strip()
        key = (a.get("source") or "unknown", link or title or a.get("value", ""))
        g = groups.get(key)
        if g is None:
            g = {"source": a.get("source") or "unknown",
                 "source_url": link, "title": title,
                 "host": _host_of(link, a.get("source") or ""),
                 "observed_at": (a.get("date") or "")[:40],
                 "malware_family": a.get("malware_family") or "",
                 "artifacts": []}
            groups[key] = g
        if title and not g["title"]:
            g["title"] = title
        if not g["observed_at"] and a.get("date"):
            g["observed_at"] = (a.get("date") or "")[:40]
        if not g["malware_family"] and a.get("malware_family"):
            g["malware_family"] = a["malware_family"]
        g["artifacts"].append({
            "type": a.get("kind", ""),
            "observed_value": a.get("observed_value") or a.get("value", ""),
            "normalized_value": a.get("value", ""),
        })
    # Cross-source provenance: same bot token in several groups.
    token_sources: dict = {}
    for g in groups.values():
        for art in g["artifacts"]:
            if art["type"] == "bot_token":
                token_sources.setdefault(art["normalized_value"], set()).add(g["source"])
    grouped = []
    for g in groups.values():
        for art in g["artifacts"]:
            if art["type"] == "bot_token":
                others = sorted(token_sources.get(art["normalized_value"], set())
                                - {g["source"]})
                if others:
                    art["seen_in"] = others
        grouped.append(g)
    grouped.sort(key=lambda g: (g["source"], g["host"]))
    hosts = {g["host"] for g in grouped if g["host"]}
    sources = sorted({g["source"] for g in grouped})
    total = sum(len(g["artifacts"]) for g in grouped)
    return {"groups": grouped, "total": total,
            "hosts": len(hosts), "sources": sources}


def store_artifacts(artifacts: list, conn=None) -> dict:
    """Persist discovery artifacts locally (validation stays not-validated)."""
    init_db()
    own = conn is None
    if own:
        conn = connect()
    try:
        stored = 0
        for a in artifacts or []:
            if not a.get("kind") or not a.get("value"):
                continue
            ts = now_iso()
            cur = conn.execute(
                "INSERT INTO tg_artifacts (kind, value, observed_value, source,"
                " malware_family, tags, evidence, first_seen, last_seen, validation, link)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'not-validated', ?)"
                " ON CONFLICT(kind, value, source) DO UPDATE SET"
                " last_seen=excluded.last_seen,"
                " link=CASE WHEN excluded.link != '' THEN excluded.link"
                " ELSE tg_artifacts.link END,"
                " evidence=CASE WHEN length(excluded.evidence)>length(tg_artifacts.evidence)"
                " THEN excluded.evidence ELSE tg_artifacts.evidence END",
                (a["kind"], a["value"], (a.get("observed_value") or "")[:500],
                 (a.get("source") or "")[:120], (a.get("malware_family") or "")[:120],
                 (a.get("tags") or "")[:300], (a.get("evidence") or "")[:600],
                 ts, ts, (a.get("link") or "")[:500]))
            if cur.rowcount:
                stored += 1
        if own:
            conn.commit()
        return {"stored": stored}
    finally:
        if own:
            conn.close()


def list_artifacts(kind: str = "", source: str = "", limit: int = 100,
                   offset: int = 0) -> dict:
    init_db()
    conn = connect()
    try:
        clauses, params = [], []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if source:
            clauses.append("source = ?")
            params.append(source)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(
            f"SELECT * FROM tg_artifacts {where} ORDER BY last_seen DESC"
            " LIMIT ? OFFSET ?", (*params, max(1, limit), max(0, offset))).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM tg_artifacts {where}",
                             params).fetchone()[0]
        return {"total": total, "artifacts": [dict(r) for r in rows]}
    finally:
        conn.close()


def validate_artifact(artifact_id: int) -> dict:
    """ACTIVE, manual analyst action: getMe on a discovered token."""
    init_db()
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM tg_artifacts WHERE id = ?",
                           (artifact_id,)).fetchone()
        if not row:
            return {"error": "Artifact not found"}
        a = dict(row)
        if a["kind"] != "bot_token":
            return {"error": "Only bot-token artifacts can be validated"}
        res = bot_validate(a["value"])
        state = "live" if res.get("ok") else "dead"
        detail = ""
        if res.get("ok"):
            detail = "@" + res.get("username", "") if res.get("username") else "valid"
            conn.execute("UPDATE tg_artifacts SET validation = ?, tags = ? WHERE id = ?",
                         (state, (a.get("tags") or "")[:300], artifact_id))
        else:
            detail = res.get("error", "validation failed")[:200]
            conn.execute("UPDATE tg_artifacts SET validation = ? WHERE id = ?",
                         (state, artifact_id))
        conn.commit()
        return {"id": artifact_id, "validation": state, "detail": detail,
                "username": res.get("username", "") if res.get("ok") else ""}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Investigations + collection jobs (ACTIVE surface below is explicit-only)
# ---------------------------------------------------------------------------
_jobs: dict = {}
_jobs_lock = threading.Lock()
_auth_attempts: dict = {}
_auth_lock = threading.Lock()


def _env_path() -> str:
    return os.path.join(os.path.dirname(BASE_DIR), ".env")


def _load_env() -> None:
    try:
        import dotenv
        dotenv.load_dotenv(_env_path(), override=False)
    except Exception:
        pass


def _update_env(values: dict) -> None:
    path = _env_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []
    pending = dict(values)
    output = []
    for line in lines:
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        key = match.group(1) if match else ""
        if key not in pending:
            output.append(line)
            continue
        value = pending.pop(key)
        if value is not None:
            output.append(f"{key}={value}")
    for key, value in pending.items():
        if value is not None:
            output.append(f"{key}={value}")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(output).rstrip() + "\n")
    for key, value in values.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = str(value)


def auth_status() -> dict:
    _load_env()
    configured = all((os.environ.get(key) or "").strip() for key in (
        "TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TELEGRAM_STRING_SESSION"
    ))
    return {"authenticated": configured, "configured": configured}


def auth_send_code(api_id: int, api_hash: str, phone: str) -> dict:
    api_hash = (api_hash or "").strip()
    phone = (phone or "").strip()
    if not api_id or not api_hash or not phone:
        return {"error": "API ID, API hash, and phone are required"}

    async def _send():
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        client = TelegramClient(StringSession(), int(api_id), api_hash)
        await client.connect()
        try:
            sent = await client.send_code_request(phone)
            return client.session.save(), sent.phone_code_hash
        finally:
            await client.disconnect()

    import asyncio
    try:
        session, phone_code_hash = asyncio.run(_send())
    except Exception as exc:
        return {"error": f"Telegram login code request failed: {type(exc).__name__}"}
    attempt_id = uuid.uuid4().hex
    with _auth_lock:
        cutoff = time.time() - 900
        for key in [key for key, value in _auth_attempts.items() if value.get("created", 0) < cutoff]:
            _auth_attempts.pop(key, None)
        _auth_attempts[attempt_id] = {
            "api_id": int(api_id), "api_hash": api_hash, "phone": phone,
            "phone_code_hash": phone_code_hash, "session": session, "created": time.time(),
        }
    return {"ok": True, "attempt_id": attempt_id}


def auth_login(attempt_id: str, code: str, password: str = "") -> dict:
    attempt_id = (attempt_id or "").strip()
    with _auth_lock:
        attempt = dict(_auth_attempts.get(attempt_id) or {})
    if not attempt or time.time() - attempt.get("created", 0) > 900:
        return {"error": "Login attempt expired; request a new code"}
    code = (code or "").strip()
    password = password or ""
    if not code and not attempt.get("password_required"):
        return {"error": "Login code is required"}

    async def _login():
        from telethon import TelegramClient
        from telethon.errors import SessionPasswordNeededError
        from telethon.sessions import StringSession
        client = TelegramClient(StringSession(attempt["session"]), attempt["api_id"], attempt["api_hash"])
        await client.connect()
        try:
            if attempt.get("password_required"):
                if not password:
                    return {"password_required": True, "session": client.session.save()}
                await client.sign_in(password=password)
            else:
                try:
                    await client.sign_in(
                        phone=attempt["phone"], code=code,
                        phone_code_hash=attempt["phone_code_hash"],
                    )
                except SessionPasswordNeededError:
                    if not password:
                        return {"password_required": True, "session": client.session.save()}
                    await client.sign_in(password=password)
            me = await client.get_me()
            return {
                "session": client.session.save(),
                "name": " ".join(value for value in (getattr(me, "first_name", ""), getattr(me, "last_name", "")) if value),
                "username": getattr(me, "username", "") or "",
            }
        finally:
            await client.disconnect()

    import asyncio
    try:
        result = asyncio.run(_login())
    except Exception as exc:
        return {"error": f"Telegram login failed: {type(exc).__name__}"}
    if result.get("password_required"):
        with _auth_lock:
            stored = _auth_attempts.get(attempt_id)
            if stored:
                stored["password_required"] = True
                stored["session"] = result.get("session") or stored["session"]
        return {"password_required": True}
    _update_env({
        "TELEGRAM_API_ID": str(attempt["api_id"]),
        "TELEGRAM_API_HASH": attempt["api_hash"],
        "TELEGRAM_PHONE": attempt["phone"],
        "TELEGRAM_STRING_SESSION": result["session"],
    })
    with _auth_lock:
        _auth_attempts.pop(attempt_id, None)
    return {"ok": True, "name": result.get("name", ""), "username": result.get("username", "")}


def auth_verify() -> dict:
    _load_env()
    api_id = (os.environ.get("TELEGRAM_API_ID") or "").strip()
    api_hash = (os.environ.get("TELEGRAM_API_HASH") or "").strip()
    session = (os.environ.get("TELEGRAM_STRING_SESSION") or "").strip()
    if not api_id or not api_hash or not session:
        return {"error": "Telegram authentication is not configured"}

    async def _verify():
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        client = TelegramClient(StringSession(session), int(api_id), api_hash)
        await client.connect()
        try:
            if not await client.is_user_authorized():
                return {"error": "Telegram session is not authorized"}
            me = await client.get_me()
            return {
                "ok": True,
                "name": " ".join(value for value in (getattr(me, "first_name", ""), getattr(me, "last_name", "")) if value),
                "username": getattr(me, "username", "") or "",
            }
        finally:
            await client.disconnect()

    import asyncio
    try:
        return asyncio.run(_verify())
    except Exception as exc:
        return {"error": f"Telegram verification failed: {type(exc).__name__}"}


def auth_logout() -> dict:
    _update_env({"TELEGRAM_STRING_SESSION": None, "TELEGRAM_PHONE": None})
    with _auth_lock:
        _auth_attempts.clear()
    return {"ok": True}


def _new_id(prefix: str) -> str:
    import uuid
    return f"{prefix}_{uuid.uuid4().hex[:12]}"




def list_bots() -> dict:
    init_db()
    conn = connect()
    try:
        rows = conn.execute("SELECT * FROM tg_bots ORDER BY created_at DESC").fetchall()
        bots = [_public_bot(dict(b)) for b in rows]
        return {"total": len(bots), "bots": bots}
    finally:
        conn.close()


def _public_bot(b: dict) -> dict:
    """Bot summary safe for UI/API."""
    b = dict(b)
    token = b.pop("token", "")
    b["token_masked"] = mask_token(token)
    b["token_fp"] = b.get("token_fp", "") or token_fingerprint(token)
    try:
        b["failed_ids"] = json.loads(b.get("failed_ids") or "[]")
    except ValueError:
        b["failed_ids"] = []
    with _jobs_lock:
        b["job_running"] = b["id"] in _jobs
    return b


def _get_bot(bot_id: str, conn=None):
    own = conn is None
    if own:
        conn = connect()
    try:
        row = conn.execute("SELECT * FROM tg_bots WHERE id = ?", (bot_id,)).fetchone()
        return dict(row) if row else None
    finally:
        if own:
            conn.close()


def add_bot(token: str, chat_id: str = "", dest_chat_id: str = "", mode: str = "full",
            transport: str = "native") -> dict:
    """Register a bot (passive: shape-checked only, no Telegram contact)."""
    init_db()
    token = (token or "").strip()
    m = TOKEN_RE.search(token)
    if not m:
        return {"error": "Not a valid bot-token shape (<bot-id>:<35-char secret>)"}
    token = m.group(0)
    mode = "live" if (mode or "").strip().lower().startswith("live") else "full"
    transport = "manual" if (transport or "").strip().lower() == "manual" else "native"
    chat_id = (chat_id or "").strip()
    dest_chat_id = (dest_chat_id or "").strip()
    if transport == "manual" and (not chat_id or not dest_chat_id):
        return {"error": "Manual transport requires operator and destination chat IDs"}
    conn = connect()
    try:
        fp = token_fingerprint(token)
        dup = conn.execute("SELECT id FROM tg_bots WHERE token_fp = ?", (fp,)).fetchone()
        if dup:
            return {"error": "This bot is already added"}
        bid = _new_id("bot")
        conn.execute(
            "INSERT INTO tg_bots (id, token_fp, token,"
            " token_state, chat_id, dest_chat_id, transport, mode, state, created_at)"
            " VALUES (?, ?, ?, 'not-validated', ?, ?, ?, ?, 'idle', ?)",
            (bid, fp, token, chat_id, dest_chat_id, transport, mode, now_iso()))
        conn.commit()
        bot = _get_bot(bid, conn=conn)
    finally:
        conn.close()
    out = _public_bot(bot)
    return out


def _job_token(bot_id: str) -> str:
    """Full token for a running collection job. Internal use only."""
    conn = connect()
    try:
        row = conn.execute("SELECT token FROM tg_bots WHERE id = ?",
                           (bot_id,)).fetchone()
        return row["token"] if row else ""
    finally:
        conn.close()


def start_bot(bot_id: str) -> dict:
    """ACTIVE: begin Full/Live collection for one bot (explicit initiation)."""
    bot = _get_bot(bot_id)
    if not bot:
        return {"error": "Bot not found"}
    _load_env()
    if bot.get("transport", "native") == "native":
        missing = [name for name in ("TELEGRAM_STRING_SESSION", "TELEGRAM_API_ID", "TELEGRAM_API_HASH")
                   if not (os.environ.get(name) or "").strip()]
        if missing:
            return {"error": "Native transport requires completed Telegram Auth Settings"}
        if not (bot.get("username") or "").strip():
            return {"error": "Validate the bot before starting native collection"}
    with _jobs_lock:
        if bot_id in _jobs:
            return {"error": "Collection already running for this bot",
                    "bot": _public_bot(bot)}
        stop_ev = threading.Event()
        th = threading.Thread(target=_collection_loop, args=(bot_id, stop_ev),
                              name=f"mantis-tg-{bot_id[:8]}", daemon=True)
        _jobs[bot_id] = {"stop": stop_ev, "thread": th,
                         "investigation_id": bot["investigation_id"]}
        th.start()
    conn = connect()
    try:
        conn.execute("UPDATE tg_bots SET state = 'running', last_error = ''"
                     " WHERE id = ?", (bot_id,))
        conn.commit()
    finally:
        conn.close()
    return {"started": True, "bot": _public_bot(_get_bot(bot_id))}


def stop_bot(bot_id: str, paused: bool = False) -> dict:
    with _jobs_lock:
        job = _jobs.pop(bot_id, None)
    if job:
        job["stop"].set()
    conn = connect()
    try:
        conn.execute("UPDATE tg_bots SET state = ? WHERE id = ?",
                     ("paused" if paused else "stopped", bot_id))
        conn.commit()
    finally:
        conn.close()
    bot = _get_bot(bot_id)
    return {"stopped": True, "bot": _public_bot(bot) if bot else None}


def prune_old_messages(days: int = 90) -> int:
    """Hard-delete messages older than N days to prevent database bloating."""
    conn = connect()
    try:
        cutoff_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - (days * 86400)))
        cur = conn.execute("DELETE FROM tg_messages WHERE timestamp != '' AND timestamp < ?", (cutoff_iso,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def delete_bot(bot_id: str) -> dict:
    """Stop any running job and permanently remove the bot and its messages."""
    stop_bot(bot_id, paused=False)
    conn = connect()
    try:
        conn.execute("DELETE FROM tg_messages WHERE bot_id = ?", (bot_id,))
        conn.execute("DELETE FROM tg_bots WHERE id = ?", (bot_id,))
        conn.commit()
    finally:
        conn.close()
    return {"deleted": True, "bot_id": bot_id}


def _set_bot_fields(bot_id: str, **fields):
    if not fields:
        return
    conn = connect()
    try:
        conn.execute("UPDATE tg_bots SET {} WHERE id = ?".format(
            ", ".join(f"{k} = ?" for k in fields)),
            (*fields.values(), bot_id))
        conn.commit()
    finally:
        conn.close()


def _norm_message(update: dict) -> dict:
    """Update -> normalized message record (None when not a message)."""
    msg = update.get("message") or update.get("channel_post") or {}
    if not isinstance(msg, dict) or not msg.get("message_id"):
        edited = update.get("edited_message") or update.get("edited_channel_post") or {}
        if isinstance(edited, dict) and edited.get("message_id"):
            msg = edited
        else:
            return None
    chat = msg.get("chat", {}) if isinstance(msg.get("chat"), dict) else {}
    frm = msg.get("from", {}) if isinstance(msg.get("from"), dict) else {}
    sender = (frm.get("username") or
              " ".join(x for x in (frm.get("first_name"), frm.get("last_name")) if x) or
              str(frm.get("id", "")))[:200]
    text = (msg.get("text") or "")[:8000]
    caption = (msg.get("caption") or "")[:2000]
    msg_type, file_name, file_size, mime = "text", "", 0, ""
    doc = msg.get("document")
    if isinstance(doc, dict):
        msg_type, file_name = "document", (doc.get("file_name") or "")[:300]
        file_size, mime = int(doc.get("file_size") or 0), (doc.get("mime_type") or "")[:120]
    elif isinstance(msg.get("photo"), list) and msg["photo"]:
        msg_type = "photo"
    elif isinstance(msg.get("video"), dict):
        msg_type, file_size = "video", int(msg["video"].get("file_size") or 0)
        mime = (msg["video"].get("mime_type") or "")[:120]
    elif isinstance(msg.get("audio"), dict):
        msg_type = "audio"
    elif isinstance(msg.get("voice"), dict):
        msg_type = "voice"
    elif isinstance(msg.get("sticker"), dict):
        msg_type = "sticker"
    try:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S",
                           time.gmtime(int(msg.get("date", 0))))
    except (ValueError, TypeError, OSError):
        ts = ""
    reply = msg.get("reply_to_message", {})
    return {
        "message_id": int(msg.get("message_id", 0)),
        "timestamp": ts,
        "chat_id": str(chat.get("id", "")),
        "sender": sender,
        "msg_type": msg_type,
        "text": text or caption,
        "file_name": file_name, "file_size": file_size, "mime_type": mime,
        "caption": caption if text else "",
        "reply_to": int(reply.get("message_id", 0)) if isinstance(reply, dict) else 0,
        "raw": json.dumps(update)[:8000],
    }


def _store_message(bot_id: str, rec: dict, conn) -> bool:
    cur = conn.execute(
        "INSERT OR IGNORE INTO tg_messages (bot_id, message_id, timestamp,"
        " chat_id, sender, msg_type, text, file_name, file_size, mime_type,"
        " caption, reply_to, forwarded, raw)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
        (bot_id, rec["message_id"], rec["timestamp"], rec["chat_id"],
         rec["sender"], rec["msg_type"], rec["text"], rec["file_name"],
         rec["file_size"], rec["mime_type"], rec["caption"], rec["reply_to"],
         rec["raw"]))
    return cur.rowcount > 0


DUMP_PROBE_TEXT = "Here is our latest message :)"
DUMP_BATCH_SIZE = 50
DUMP_BATCH_DELAY = 0.4


def _store_copied(bot_id: str, operator_mid: int, operator_chat: str,
                   item: dict, conn) -> bool:
    """Store one copied message under its OPERATOR message id."""
    if not isinstance(item, dict):
        return False
    rec = _norm_message({"message": item})
    if not rec:
        return False
    rec["message_id"] = operator_mid
    rec["chat_id"] = operator_chat
    cur = conn.execute(
        "INSERT OR IGNORE INTO tg_messages (bot_id, message_id, timestamp,"
        " chat_id, sender, msg_type, text, file_name, file_size, mime_type,"
        " caption, reply_to, forwarded, copied, raw)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?)",
        (bot_id, rec["message_id"], rec["timestamp"], rec["chat_id"],
         rec["sender"], rec["msg_type"], rec["text"], rec["file_name"],
         rec["file_size"], rec["mime_type"], rec["caption"], rec["reply_to"],
         rec["raw"]))
    return cur.rowcount > 0


def _copy_single(token: str, operator_chat: str, dest_chat: str,
                 operator_mid: int):
    """copyMessage for one id. Returns (ok, item-or-error)."""
    res = _bot_call(token, "copyMessage",
                    {"chat_id": dest_chat, "from_chat_id": operator_chat,
                     "message_id": operator_mid}, timeout=20, retries=2)
    if res.get("ok"):
        return True, res.get("result")
    return False, res.get("error", "copy failed")


def _dump_history(bot_id: str, token: str, operator_chat: str, dest_chat: str,
                  stop_ev: threading.Event, conn):
    """Dump history by batch-copying from operator_chat to dest_chat until exhaustion.
    This bypasses getUpdates 409 conflicts for historical messages.
    """
    _set_bot_fields(bot_id, dump_done=0, dump_total=-1)
    
    start = 1
    empty_batches = 0
    total_copied = 0
    
    while not stop_ev.is_set():
        batch = list(range(start, start + 50))
        res = _bot_call(token, "copyMessages",
                        {"chat_id": dest_chat, "from_chat_id": operator_chat, "message_ids": batch})
        
        if not res.get("ok"):
            err = str(res.get("error", ""))
            if "too many requests" in err.lower() or "retry" in err.lower():
                if stop_ev.wait(5):
                    break
                continue
            return {"error": err}
            
        copied = res.get("result", [])
        if not copied:
            empty_batches += 1
            if empty_batches >= 4:  # 200 consecutive missing messages = likely end of chat
                break
        else:
            empty_batches = 0
            total_copied += len(copied)
            
        start += 50
        _set_bot_fields(bot_id, dump_done=total_copied)
        if stop_ev.wait(0.5):
            break

    _set_bot_fields(bot_id, dump_total=total_copied)
    return {"ok": True, "copied": total_copied}



def _run_telethon_sync(bot_id: str, stop_ev: threading.Event):
    import asyncio
    _load_env()

    session_str = os.environ.get("TELEGRAM_STRING_SESSION")
    api_id = os.environ.get("TELEGRAM_API_ID")
    api_hash = os.environ.get("TELEGRAM_API_HASH")
    if not session_str or not api_id or not api_hash:
        _set_bot_fields(bot_id, last_error="MTProto: missing session/api_id/api_hash in .env")
        return

    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        _set_bot_fields(bot_id, last_error="MTProto: telethon not installed")
        return

    async def _sync():
        client = TelegramClient(StringSession(session_str), int(api_id), api_hash)
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            _set_bot_fields(bot_id, last_error="MTProto: session not authorized — re-login")
            return

        conn = connect()
        try:
            bot = _get_bot(bot_id, conn)
            if not bot or not bot.get("username"):
                _set_bot_fields(bot_id, last_error="MTProto: bot username not set — validate first")
                return

            try:
                bot_entity = await client.get_entity(bot["username"])
            except Exception as e:
                _set_bot_fields(bot_id, last_error=f"MTProto: could not find entity @{bot['username']}: {e}"[:300])
                return

            mode = bot.get("mode", "full")

            # ── Phase 1: Full history dump ──────────────────────────────────
            # iter_messages with no min_id fetches from newest → oldest (reverse=False)
            # We store each batch and track the highest id seen.
            _set_bot_fields(bot_id, last_error="")
            last_id = 0
            batch_count = 0
            logger.info("[MTProto] Starting history dump for bot %s (@%s)", bot_id, bot.get("username"))
            try:
                async for msg in client.iter_messages(bot_entity, reverse=False, limit=None if mode == "full" else 1):
                    if stop_ev.is_set():
                        break
                    if msg.id > last_id:
                        last_id = msg.id
                    if mode != "full":
                        break
                    text = msg.text or ""
                    sender = "operator" if msg.out else "bot"
                    ts = msg.date.strftime("%Y-%m-%dT%H:%M:%S") if msg.date else ""
                    msg_type = "text"
                    file_name, file_size, mime_type = "", 0, ""
                    if msg.media:
                        msg_type = "document"
                        if hasattr(msg.media, "document"):
                            doc = msg.media.document
                            file_size = getattr(doc, "size", 0)
                            mime_type = getattr(doc, "mime_type", "")
                            for attr in getattr(doc, "attributes", []):
                                if hasattr(attr, "file_name"):
                                    file_name = attr.file_name
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO tg_messages "
                            "(bot_id, message_id, timestamp, chat_id, sender, msg_type, text, file_name, file_size, mime_type, copied) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                            (bot_id, msg.id, ts, str(bot_entity.id), sender, msg_type, text, file_name, file_size, mime_type)
                        )
                        batch_count += 1
                        if batch_count % 50 == 0:
                            conn.commit()
                            conn.execute(
                                "UPDATE tg_bots SET total_messages=(SELECT COUNT(*) FROM tg_messages WHERE bot_id=?),"
                                " dump_done=?, last_error='' WHERE id=?",
                                (bot_id, batch_count, bot_id)
                            )
                            conn.commit()
                    except Exception:
                        pass
            except Exception as e:
                logger.warning("[MTProto] History dump error: %s", e)

            # Final commit after history dump
            conn.commit()
            conn.execute(
                "UPDATE tg_bots SET total_messages=(SELECT COUNT(*) FROM tg_messages WHERE bot_id=?),"
                " first_message_at=COALESCE((SELECT MIN(NULLIF(timestamp, '')) FROM tg_messages WHERE bot_id=?), ''),"
                " latest_message_at=COALESCE((SELECT MAX(NULLIF(timestamp, '')) FROM tg_messages WHERE bot_id=?), ''),"
                " dump_done=?, dump_total=?, last_error='' WHERE id=?",
                (bot_id, bot_id, bot_id, batch_count, batch_count, bot_id)
            )
            conn.commit()
            logger.info("[MTProto] History dump complete: %d messages for bot %s", batch_count, bot_id)

            # ── Phase 2: Live polling for new messages ──────────────────────
            while not stop_ev.is_set():
                try:
                    new_count = 0
                    async for msg in client.iter_messages(bot_entity, min_id=last_id, reverse=True):
                        if stop_ev.is_set():
                            break
                        if msg.id > last_id:
                            last_id = msg.id
                        text = msg.text or ""
                        sender = "operator" if msg.out else "bot"
                        ts = msg.date.strftime("%Y-%m-%dT%H:%M:%S") if msg.date else ""
                        msg_type = "text"
                        file_name, file_size, mime_type = "", 0, ""
                        if msg.media:
                            msg_type = "document"
                            if hasattr(msg.media, "document"):
                                doc = msg.media.document
                                file_size = getattr(doc, "size", 0)
                                mime_type = getattr(doc, "mime_type", "")
                                for attr in getattr(doc, "attributes", []):
                                    if hasattr(attr, "file_name"):
                                        file_name = attr.file_name
                        try:
                            conn.execute(
                                "INSERT OR IGNORE INTO tg_messages "
                                "(bot_id, message_id, timestamp, chat_id, sender, msg_type, text, file_name, file_size, mime_type, copied) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                                (bot_id, msg.id, ts, str(bot_entity.id), sender, msg_type, text, file_name, file_size, mime_type)
                            )
                            new_count += 1
                        except Exception:
                            pass
                    if new_count:
                        conn.commit()
                        conn.execute(
                            "UPDATE tg_bots SET total_messages=(SELECT COUNT(*) FROM tg_messages WHERE bot_id=?),"
                            " first_message_at=COALESCE((SELECT MIN(NULLIF(timestamp, '')) FROM tg_messages WHERE bot_id=?), ''),"
                            " latest_message_at=COALESCE((SELECT MAX(NULLIF(timestamp, '')) FROM tg_messages WHERE bot_id=?), '')"
                            " WHERE id=?",
                            (bot_id, bot_id, bot_id, bot_id)
                        )
                        conn.commit()
                except Exception as e:
                    logger.warning("[MTProto] Live poll error: %s", e)
                await asyncio.sleep(5)
        finally:
            conn.close()
            await client.disconnect()

    try:
        asyncio.run(_sync())
    except Exception as e:
        logger.warning("[MTProto] asyncio.run error: %s", e)


def _collection_loop(bot_id: str, stop_ev: threading.Event):
    """Full = probe + brute-force copy dump, then live tail.
    Live = skip backlog, then tail. New operator messages are copied
    (not forwarded) into the analyst destination chat.
    """
    token = _job_token(bot_id)
    if not token:
        _set_bot_fields(bot_id, state="error", last_error="Missing token")
        with _jobs_lock:
            _jobs.pop(bot_id, None)
        return

    conn = connect()
    try:
        bot = _get_bot(bot_id, conn=conn)
        if not bot:
            return
        mode = bot.get("mode", "full")
        operator_chat = (bot.get("chat_id") or "").strip()
        dest_chat = (bot.get("dest_chat_id") or "").strip()

        _load_env()

        if bot.get("transport", "native") == "native":
            conn.close()
            _run_telethon_sync(bot_id, stop_ev)
            return

        webhook = _bot_call(token, "getWebhookInfo", timeout=15)
        webhook_data = webhook.get("result") if webhook.get("ok") and isinstance(webhook.get("result"), dict) else {}
        if webhook_data.get("url"):
            _set_bot_fields(
                bot_id,
                state="error",
                last_error="Manual collection cannot use getUpdates while a webhook is configured; remove it outside MANTIS first",
            )
            return

        # Step 1: Dump history
        if mode == "full" and operator_chat and dest_chat:
            dump = _dump_history(bot_id, token, operator_chat, dest_chat, stop_ev, conn)
            if dump.get("error"):
                _set_bot_fields(bot_id, last_error=f"dump: {dump['error']}"[:300])

        # Step 2: Live polling via getUpdates
        offset = int(bot.get("last_update_id") or 0) + 1
        if mode == "live" and offset <= 1:
            first = _bot_call(token, "getUpdates", {"offset": 0, "limit": 100, "timeout": 0})
            if first.get("ok") and isinstance(first.get("result"), list):
                ids = [u.get("update_id", 0) for u in first["result"] if isinstance(u, dict)]
                if ids:
                    offset = max(ids) + 1
                    _set_bot_fields(bot_id, last_update_id=offset - 1)

        failed = []
        try:
            failed = json.loads(bot.get("failed_ids") or "[]")
        except ValueError:
            failed = []

        while not stop_ev.is_set():
            res = _bot_call(token, "getUpdates",
                            {"offset": offset, "limit": 100, "timeout": 8},
                            timeout=15)
            if not res.get("ok"):
                err = str(res.get("error", ""))
                _set_bot_fields(bot_id, last_error=err[:300])
                if "conflict" in err.lower() or "409" in err:
                    logger.warning("[TG] 409 Conflict for bot %s — backing off 15 s", bot_id)
                    if stop_ev.wait(15):
                        break
                else:
                    if stop_ev.wait(5):
                        break
                continue

            updates = res.get("result") if isinstance(res.get("result"), list) else []
            if not updates:
                continue
            for update in updates:
                if not isinstance(update, dict):
                    continue
                uid = int(update.get("update_id", 0) or 0)
                if uid:
                    offset = max(offset, uid + 1)
                rec = _norm_message(update)
                if not rec:
                    continue
                _store_message(bot_id, rec, conn)
                
                # Forward to analyst chat if applicable
                if operator_chat and rec["chat_id"] == operator_chat and dest_chat:
                    ok, _item = _copy_single(token, operator_chat, dest_chat, rec["message_id"])
                    if ok:
                        conn.execute("UPDATE tg_messages SET copied = 1 WHERE bot_id = ? AND message_id = ?",
                                     (bot_id, rec["message_id"]))
                    elif rec["message_id"] not in failed:
                        failed.append(rec["message_id"])
                
                conn.execute(
                    "UPDATE tg_bots SET last_update_id = ?, latest_message_at = ?,"
                    " total_messages = (SELECT COUNT(*) FROM tg_messages WHERE bot_id = ?),"
                    " first_message_at = CASE WHEN first_message_at = '' THEN ? ELSE first_message_at END,"
                    " failed_ids = ?, last_error = '' WHERE id = ?",
                    (offset - 1, rec["timestamp"] or now_iso(), bot_id,
                     rec["timestamp"] or now_iso(), json.dumps(failed[-50:]), bot_id))
                conn.commit()
                
                if stop_ev.is_set():
                    break
    except Exception as e:
        logger.warning("TG collection loop failed: %s", type(e).__name__)
        try:
            _set_bot_fields(bot_id, state="error", last_error=str(e)[:300])
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            current = _get_bot(bot_id)
            if current and current.get("state") == "running":
                _set_bot_fields(
                    bot_id,
                    state="error" if current.get("last_error") else "stopped",
                )
        except Exception:
            pass
        with _jobs_lock:
            _jobs.pop(bot_id, None)


def query_messages(bot_id: str = "", text: str = "", msg_type: str = "",
                   date_from: str = "", date_to: str = "",
                   limit: int = 200, offset: int = 0) -> dict:
    """Chronological message explorer with text/type/date/bot filters."""
    init_db()
    conn = connect()
    try:
        clauses, params = [], []
        if bot_id:
            clauses.append("m.bot_id = ?")
            params.append(bot_id)
        if text:
            escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("m.text LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")
        if msg_type:
            clauses.append("m.msg_type = ?")
            params.append(msg_type)
        if date_from:
            clauses.append("m.timestamp >= ?")
            params.append(f"{date_from}T00:00:00" if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_from) else date_from)
        if date_to:
            clauses.append("m.timestamp <= ?")
            params.append(f"{date_to}T23:59:59" if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_to) else date_to)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(
            f"SELECT m.*, b.username AS bot_username FROM tg_messages m"
            f" LEFT JOIN tg_bots b ON b.id = m.bot_id"
            f" {where} ORDER BY m.timestamp DESC, m.message_id DESC"
            f" LIMIT ? OFFSET ?", (*params, max(1, limit), max(0, offset))).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM tg_messages m {where}",
                             params).fetchone()[0]
        return {"total": total, "limit": limit, "offset": offset,
                "messages": [dict(r) for r in rows]}
    finally:
        conn.close()


def bot_messages_summary(bot_id: str) -> dict:
    bot = _get_bot(bot_id)
    if not bot:
        return {"error": "Bot not found"}
    out = _public_bot(bot)
    out["diagnostics_note"] = ("Read-only diagnostics (getMe/getWebhookInfo);"
                               " no state-changing Telegram calls.")
    return out


def aggregate_stream(abusech_key: str = "", urlscan_key: str = "",
                     limit: int = 30) -> dict:
    """Intelligence Stream: Telegram-focused intel from MANTIS sources.

    Reports = local CTI articles with Telegram signals; artifacts = stored
    discovery results; malware = recent telegram_bot_api samples (needs key).
    All passive.
    """
    reports = []
    try:
        cti = discover_cti_articles(limit=limit)
        reports = cti.get("reports", [])
    except Exception as e:
        reports = [{"error": str(e)[:200]}]
    artifacts = []
    try:
        arts = list_artifacts(limit=limit)
        artifacts = arts.get("artifacts", [])
    except Exception:
        pass
    malware = []
    if abusech_key:
        try:
            mb = discover_malwarebazaar(abusech_key)
            malware = mb.get("samples", [])[:max(1, limit)]
        except Exception:
            pass
    return {"reports_total": len(reports), "reports": reports,
            "artifacts_total": len(artifacts), "artifacts": artifacts,
            "malware_total": len(malware), "malware": malware}
