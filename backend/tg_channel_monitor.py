"""Telegram Channel Monitoring & Threat Intelligence utilities.

Features:
- On-demand Telethon MTProto history sync for accessible channels and groups.
- Multi-category channel monitoring: threat_actor_public, hacktivism, ransomware_leaks,
  stealer_logs, malware_distribution, cti_research.
- Modular Log Parser Engine: extracts URL:User:Pass, combo lists, JSON logs, CTI IOCs.
- Ephemeral File Extraction: downloads attached archives (.zip, .rar, .7z, .txt), parses
  in temporary scope, and IMMEDIATELY deletes original archive and temp files (0MB disk leak).
- Asset Exposure Matcher: flags target domains/emails against extracted leak credentials.
"""
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import zipfile
from typing import List, Dict, Any, Optional

logger = logging.getLogger("mantis.tg.monitor")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TG_DB_PATH = os.path.join(DATA_DIR, "telegram_intel.db")
TEMP_DOWNLOAD_DIR = os.path.join(DATA_DIR, "temp_tg_downloads")
CHANNEL_CATEGORIES = {
    "threat_actor_public", "hacktivism", "ransomware_leaks",
    "stealer_logs", "malware_distribution", "cti_research",
}
TARGET_TYPES = {"domain", "email_domain", "keyword"}

# ---------------------------------------------------------------------------
# Strict Regex Extraction Patterns
# ---------------------------------------------------------------------------
BOT_TOKEN_RE = re.compile(r"\b(\d{6,12}):([A-Za-z0-9_-]{35})\b")
URL_RE = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CRYPTO_BTC_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[qz257edm4k08424d382sc24628v6884x009e8f][a-zA-Z0-9]{25,39}\b")
CRYPTO_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Credential log patterns: URL:User:Pass or Domain|User|Pass or User:Pass
CRED_PATTERN_1 = re.compile(r"(?:URL|Host|Site|Url):\s*(https?://[^\s\n]+|\S+)\s*\n(?:User|Login|Username|Email):\s*([^\s\n]+)\s*\n(?:Pass|Password):\s*([^\s\n]+)", re.IGNORECASE)
CRED_PATTERN_2 = re.compile(r"\b(https?://[^\s:|]+|[\w.-]+\.[a-zA-Z]{2,})[:|]([^\s:|]+[:|][^\s:\n]+)")
COMBO_LINE_RE = re.compile(r"^(https?://[^\s:|]+|[\w.-]+\.[a-zA-Z]{2,})[|\t:]([^:\s|\t]+)[|\t:]([^\r\n\s]+)$")

SCHEMA_ADDITIONS = """
CREATE TABLE IF NOT EXISTS tg_monitored_channels (
    id TEXT PRIMARY KEY,
    telegram_id INTEGER UNIQUE,
    username TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'threat_actor_public',
    access_hash INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    auto_download_files INTEGER DEFAULT 1,
    file_max_mb INTEGER DEFAULT 50,
    total_messages INTEGER DEFAULT 0,
    last_message_id INTEGER DEFAULT 0,
    last_fetched_at TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tg_channel_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    sender TEXT DEFAULT '',
    text TEXT DEFAULT '',
    has_media INTEGER DEFAULT 0,
    media_type TEXT DEFAULT '',
    file_name TEXT DEFAULT '',
    file_size INTEGER DEFAULT 0,
    extracted_iocs TEXT DEFAULT '[]',
    raw TEXT DEFAULT '{}',
    UNIQUE(channel_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_tg_chan_msg_chan ON tg_channel_messages(channel_id);
CREATE INDEX IF NOT EXISTS idx_tg_chan_msg_time ON tg_channel_messages(timestamp);

CREATE TABLE IF NOT EXISTS tg_stealer_exposures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    channel_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    url TEXT DEFAULT '',
    username TEXT DEFAULT '',
    password_masked TEXT DEFAULT '',
    password_hash TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    stealer_family TEXT DEFAULT 'unknown',
    matched_asset TEXT DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tg_exp_domain ON tg_stealer_exposures(domain);
CREATE INDEX IF NOT EXISTS idx_tg_exp_family ON tg_stealer_exposures(stealer_family);

CREATE TABLE IF NOT EXISTS tg_target_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL DEFAULT 'domain',
    value TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    alert_enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);
"""

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

def connect_db() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(TG_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=120000")
    except sqlite3.Error:
        pass
    return conn

def init_monitor_db():
    conn = connect_db()
    try:
        conn.executescript(SCHEMA_ADDITIONS)
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(tg_stealer_exposures)").fetchall()}
        if "idx_tg_exp_unique" not in indexes:
            conn.execute(
                "DELETE FROM tg_stealer_exposures WHERE id NOT IN ("
                "SELECT MIN(id) FROM tg_stealer_exposures "
                "GROUP BY channel_id, message_id, domain, username, password_hash)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX idx_tg_exp_unique ON tg_stealer_exposures "
                "(channel_id, message_id, domain, username, password_hash)"
            )
        conn.commit()
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Modular Multi-Format Parser Engine
# ---------------------------------------------------------------------------
def mask_password(password: str) -> str:
    pwd = (password or "").strip()
    if not pwd:
        return ""
    if len(pwd) <= 3:
        return "***"
    return f"{pwd[0]}***{pwd[-1]}"

def hash_password(password: str) -> str:
    return hashlib.sha256((password or "").encode("utf-8", errors="ignore")).hexdigest()

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    text = text or ""
    iocs = {
        "bot_tokens": list(set(BOT_TOKEN_RE.findall(text))),
        "urls": list(set(URL_RE.findall(text)))[:20],
        "domains": list(set(DOMAIN_RE.findall(text)))[:20],
        "emails": list(set(EMAIL_RE.findall(text)))[:20],
        "ipv4": list(set(IPV4_RE.findall(text)))[:20],
        "cves": list(set(CVE_RE.findall(text))),
        "crypto_btc": list(set(CRYPTO_BTC_RE.findall(text))),
        "crypto_eth": list(set(CRYPTO_ETH_RE.findall(text)))
    }
    # Flatten bot tokens if tuple
    tokens = []
    for t in iocs["bot_tokens"]:
        if isinstance(t, tuple):
            tokens.append(f"{t[0]}:{t[1]}")
        else:
            tokens.append(str(t))
    iocs["bot_tokens"] = list(set(tokens))
    return iocs

def parse_credential_lines(text: str, stealer_family: str = "unknown") -> List[Dict[str, Any]]:
    """Extremely resilient multi-format credential parser."""
    text = text or ""
    results = []
    seen = set()

    # Format 1: Multi-line key-value pairs (URL: ... User: ... Pass: ...)
    for m in CRED_PATTERN_1.finditer(text):
        url, user, pwd = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        domain = extract_domain(url)
        key = (domain, user, hash_password(pwd))
        if key not in seen and domain:
            seen.add(key)
            results.append({
                "domain": domain,
                "url": url,
                "username": user,
                "password_masked": mask_password(pwd),
                "password_hash": hash_password(pwd),
                "stealer_family": stealer_family
            })

    # Format 2: Line by line Delimited (URL|USER|PASS or URL:USER:PASS)
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or len(line) > 500:
            continue
        m = COMBO_LINE_RE.match(line)
        if m:
            url_or_dom, user, pwd = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
            domain = extract_domain(url_or_dom)
            key = (domain, user, hash_password(pwd))
            if key not in seen and domain and user and pwd:
                seen.add(key)
                results.append({
                    "domain": domain,
                    "url": url_or_dom if url_or_dom.startswith("http") else f"https://{url_or_dom}",
                    "username": user,
                    "password_masked": mask_password(pwd),
                    "password_hash": hash_password(pwd),
                    "stealer_family": stealer_family
                })

    return results

def extract_domain(url_or_domain: str) -> str:
    url_or_domain = (url_or_domain or "").strip()
    if not url_or_domain:
        return ""
    if url_or_domain.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse
            return (urlparse(url_or_domain).netloc or "").split(":")[0].lower()
        except Exception:
            pass
    m = DOMAIN_RE.search(url_or_domain)
    return m.group(0).lower() if m else ""

def get_target_assets(conn=None) -> List[Dict[str, Any]]:
    own = conn is None
    if own:
        conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM tg_target_assets WHERE alert_enabled = 1").fetchall()
        return [dict(r) for r in rows]
    finally:
        if own:
            conn.close()

def match_target_assets(domain: str, username: str, targets: List[Dict[str, Any]]) -> str:
    domain_lower = (domain or "").lower()
    user_lower = (username or "").lower()
    for t in targets:
        val = t["value"].lower().strip()
        if not val:
            continue
        if t["target_type"] == "domain" and (domain_lower == val or domain_lower.endswith("." + val)):
            return val
        if t["target_type"] == "email_domain" and user_lower.endswith(val):
            return val
        if t["target_type"] == "keyword" and (val in domain_lower or val in user_lower):
            return val
    return ""

# ---------------------------------------------------------------------------
# Strict Ephemeral Archive & File Ingestion Pipeline
# ---------------------------------------------------------------------------
def process_and_cleanup_archive(file_path: str, max_files: int = 200, max_size_mb: int = 50) -> Dict[str, Any]:
    """Downloads archive, extracts text in memory/temp folder, parses logs,

    and IMMEDIATELY deletes both the original file and temp extraction dir.
    """
    exposures = []
    iocs = {
        "bot_tokens": [], "urls": [], "domains": [], "emails": [],
        "ipv4": [], "cves": [], "crypto_btc": [], "crypto_eth": []
    }
    extracted_temp_dir = None

    try:
        if not os.path.exists(file_path):
            return {"exposures": exposures, "iocs": iocs}

        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if file_size_mb > max_size_mb:
            logger.warning(f"File {file_path} size {file_size_mb:.1f}MB exceeds limit {max_size_mb}MB. Skipping.")
            return {"exposures": exposures, "iocs": iocs}

        extracted_temp_dir = tempfile.mkdtemp(prefix="tg_ext_")

        # Handle Zip archive
        if file_path.lower().endswith(".zip") and zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as zf:
                count = 0
                processed_bytes = 0
                max_bytes = max_size_mb * 1024 * 1024
                for info in zf.infolist():
                    if count >= max_files:
                        break
                    # Skip non-text/large files
                    if info.file_size > 5 * 1024 * 1024:
                        continue
                    fname = info.filename.lower()
                    if fname.endswith((".txt", ".log", ".json", ".csv", ".dat")):
                        if processed_bytes + info.file_size > max_bytes:
                            break
                        try:
                            content = zf.read(info.filename).decode("utf-8", errors="ignore")
                            processed_bytes += info.file_size
                            fam = detect_stealer_family(info.filename, content)
                            exposures.extend(parse_credential_lines(content, stealer_family=fam))
                            file_iocs = extract_iocs_from_text(content)
                            merge_iocs(iocs, file_iocs)
                            count += 1
                        except Exception:
                            pass
        elif file_path.lower().endswith((".txt", ".log", ".json", ".csv")):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(5 * 1024 * 1024)
                fam = detect_stealer_family(os.path.basename(file_path), content)
                exposures.extend(parse_credential_lines(content, stealer_family=fam))
                merge_iocs(iocs, extract_iocs_from_text(content))
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Error processing archive {file_path}: {e}")
    finally:
        # STRICT EPHEMERAL DISK HYGIENE: Unlink original download & temp files
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
                logger.info(f"Unlinked original file: {file_path}")
        except Exception as e:
            logger.error(f"Failed to delete download file {file_path}: {e}")
        try:
            if extracted_temp_dir and os.path.exists(extracted_temp_dir):
                shutil.rmtree(extracted_temp_dir, ignore_errors=True)
        except Exception:
            pass

    return {"exposures": exposures, "iocs": iocs}

def detect_stealer_family(filename: str, content: str) -> str:
    fn = filename.lower()
    c = content[:2000].lower()
    if "redline" in fn or "redline" in c:
        return "RedLine"
    if "lumma" in fn or "lumma" in c:
        return "LummaStealc"
    if "vidar" in fn or "vidar" in c:
        return "Vidar"
    if "stealc" in fn or "stealc" in c:
        return "Stealc"
    if "raccoon" in fn or "raccoon" in c:
        return "Raccoon"
    if "metastealer" in fn or "metastealer" in c:
        return "MetaStealer"
    if "taurus" in fn or "taurus" in c:
        return "Taurus"
    return "Generic Combo"

def merge_iocs(target: Dict[str, List[str]], source: Dict[str, List[str]]):
    for k, v in source.items():
        if k in target:
            target[k] = list(set(target[k] + v))[:50]

# ---------------------------------------------------------------------------
# Database CRUD Operations for Channel Monitoring
# ---------------------------------------------------------------------------
def list_monitored_channels() -> List[Dict[str, Any]]:
    init_monitor_db()
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM tg_monitored_channels ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def add_monitored_channel(username_or_link: str, category: str = "threat_actor_public",
                          auto_download: bool = True) -> Dict[str, Any]:
    init_monitor_db()
    clean_name = (username_or_link or "").strip()
    if not clean_name:
        return {"error": "Channel username or invite link is required"}
    category = (category or "").strip()
    if category not in CHANNEL_CATEGORIES:
        return {"error": "Unsupported channel category"}
    link_match = re.search(r"(?:https?://)?t\.me/(.+)", clean_name, re.IGNORECASE)
    if link_match:
        path = link_match.group(1).split("?", 1)[0].strip("/")
        if path.startswith("+") or path.startswith("joinchat/"):
            clean_name = f"https://t.me/{path}"
        else:
            clean_name = "@" + path.split("/", 1)[0].lstrip("@").lower()
    elif not clean_name.startswith("@"):
        clean_name = "@" + clean_name.lstrip("/").lower()
    else:
        clean_name = "@" + clean_name.lstrip("@").lower()
    if clean_name.startswith("@") and not re.fullmatch(r"@[A-Za-z0-9_]{5,32}", clean_name):
        return {"error": "Telegram channel usernames must be 5-32 letters, numbers, or underscores"}

    conn = connect_db()
    try:
        dup = conn.execute("SELECT * FROM tg_monitored_channels WHERE username = ?", (clean_name,)).fetchone()
        if dup:
            return {"error": "Channel already monitored", "channel": dict(dup)}

        import uuid
        cid = f"chan_{uuid.uuid4().hex[:12]}"
        ts = now_iso()
        conn.execute(
            "INSERT INTO tg_monitored_channels (id, username, title, category, status, auto_download_files, created_at)"
            " VALUES (?, ?, ?, ?, 'active', ?, ?)",
            (cid, clean_name, clean_name, category, 1 if auto_download else 0, ts)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tg_monitored_channels WHERE id = ?", (cid,)).fetchone()
        return {"ok": True, "channel": dict(row)}
    finally:
        conn.close()

def delete_monitored_channel(channel_id: str) -> Dict[str, Any]:
    init_monitor_db()
    conn = connect_db()
    try:
        exists = conn.execute("SELECT 1 FROM tg_monitored_channels WHERE id = ?", (channel_id,)).fetchone()
        if not exists:
            return {"error": "Monitored channel not found"}
        conn.execute("DELETE FROM tg_stealer_exposures WHERE channel_id = ?", (channel_id,))
        conn.execute("DELETE FROM tg_channel_messages WHERE channel_id = ?", (channel_id,))
        conn.execute("DELETE FROM tg_monitored_channels WHERE id = ?", (channel_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()

def get_live_messages(page: int = 1, page_size: int = 20, limit: Optional[int] = None, category: str = "") -> Dict[str, Any]:
    init_monitor_db()
    conn = connect_db()
    try:
        clauses, params = [], []
        if category:
            clauses.append("c.category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        if limit is not None:
            page_size = max(1, min(limit, 200))
        
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        offset = (page - 1) * page_size

        count_sql = f"SELECT COUNT(*) FROM tg_channel_messages m JOIN tg_monitored_channels c ON c.id = m.channel_id {where}"
        total = conn.execute(count_sql, params).fetchone()[0]

        sql = f"""
            SELECT m.*, c.username as channel_username, c.title as channel_title, c.category as channel_category
            FROM tg_channel_messages m
            JOIN tg_monitored_channels c ON c.id = m.channel_id
            {where}
            ORDER BY m.id DESC LIMIT ? OFFSET ?
        """
        query_params = list(params) + [page_size, offset]
        rows = conn.execute(sql, query_params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["extracted_iocs"] = json.loads(d.get("extracted_iocs") or "{}")
            except Exception:
                d["extracted_iocs"] = {}
            out.append(d)

        pages = (total + page_size - 1) // page_size if total > 0 else 1
        return {
            "messages": out,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": pages
            }
        }
    finally:
        conn.close()

def get_stealer_exposures(domain: str = "", limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    init_monitor_db()
    conn = connect_db()
    try:
        clauses, params = [], []
        if domain:
            escaped = domain.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("e.domain LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT e.id, e.message_id, e.channel_id, e.domain, e.url, e.username,
                   e.password_masked, e.ip_address, e.stealer_family, e.matched_asset,
                   e.observed_at, c.username as channel_username, c.title as channel_title
            FROM tg_stealer_exposures e
            JOIN tg_monitored_channels c ON c.id = e.channel_id
            {where}
            ORDER BY e.id DESC LIMIT ? OFFSET ?
        """
        count_sql = f"SELECT COUNT(*) FROM tg_stealer_exposures e {where}"
        total = conn.execute(count_sql, params).fetchone()[0]
        params.extend([max(1, min(int(limit or 100), 500)), max(0, int(offset or 0))])
        rows = conn.execute(sql, params).fetchall()
        return {"total": total, "exposures": [dict(r) for r in rows]}
    finally:
        conn.close()

def add_target_asset(value: str, target_type: str = "domain", description: str = "") -> Dict[str, Any]:
    init_monitor_db()
    conn = connect_db()
    try:
        val = (value or "").strip().lower()
        target_type = (target_type or "").strip().lower()
        if not val:
            return {"error": "Target asset value is required"}
        if target_type not in TARGET_TYPES:
            return {"error": "Unsupported target asset type"}
        if target_type == "domain" and extract_domain(val) != val:
            return {"error": "Enter a valid domain such as company.com"}
        if target_type == "email_domain" and not re.fullmatch(r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", val):
            return {"error": "Enter an email domain such as @company.com"}
        conn.execute(
            "INSERT INTO tg_target_assets (target_type, value, description, created_at)"
            " VALUES (?, ?, ?, ?)",
            (target_type, val, description, now_iso())
        )
        conn.commit()
        return {"ok": True, "value": val}
    except sqlite3.IntegrityError:
        return {"error": "Target asset already exists"}
    finally:
        conn.close()

def list_target_assets() -> List[Dict[str, Any]]:
    init_monitor_db()
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM tg_target_assets ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def delete_target_asset(target_id: int) -> Dict[str, Any]:
    init_monitor_db()
    conn = connect_db()
    try:
        cursor = conn.execute("DELETE FROM tg_target_assets WHERE id = ?", (target_id,))
        if cursor.rowcount == 0:
            return {"error": "Target asset not found"}
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()

def get_monitor_stats() -> Dict[str, Any]:
    init_monitor_db()
    conn = connect_db()
    try:
        chans = conn.execute("SELECT COUNT(*) FROM tg_monitored_channels").fetchone()[0]
        msgs = conn.execute("SELECT COUNT(*) FROM tg_channel_messages").fetchone()[0]
        exps = conn.execute("SELECT COUNT(*) FROM tg_stealer_exposures").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM tg_stealer_exposures WHERE matched_asset != ''").fetchone()[0]
        targets = conn.execute("SELECT COUNT(*) FROM tg_target_assets").fetchone()[0]
        return {
            "monitored_channels": chans,
            "total_messages": msgs,
            "total_exposures": exps,
            "alert_matches": alerts,
            "target_assets": targets
        }
    finally:
        conn.close()
