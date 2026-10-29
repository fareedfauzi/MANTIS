"""X Monitor: local watchlist, normalized post storage, and optional collection.

The monitor is intentionally split from the X/Twitter provider. The UI reads
local SQLite state; collection can be swapped later without changing the view.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

from intel_query import query_twitter_user_tweets

logger = logging.getLogger("mantis.x_monitor")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.environ.get("MANTIS_X_MONITOR_DB") or os.path.join(DATA_DIR, "x_monitor.db")
SEED_PATH = os.path.join(DATA_DIR, "x_monitor_accounts_seed.txt")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,15}$")
COLLECTION_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS x_accounts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    profile_url TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    interval_minutes INTEGER NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    last_checked_at TEXT NOT NULL DEFAULT '',
    last_successful_check_at TEXT NOT NULL DEFAULT '',
    last_seen_post_id TEXT NOT NULL DEFAULT '',
    last_seen_published_at TEXT NOT NULL DEFAULT '',
    last_result_count INTEGER NOT NULL DEFAULT 0,
    collection_status TEXT NOT NULL DEFAULT 'pending',
    collection_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_x_accounts_enabled ON x_accounts(enabled);
CREATE TABLE IF NOT EXISTS x_account_deletions (
    username TEXT PRIMARY KEY,
    deleted_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS x_posts (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'x',
    source_post_id TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    author_username TEXT NOT NULL DEFAULT '',
    author_display_name TEXT NOT NULL DEFAULT '',
    author_avatar TEXT NOT NULL DEFAULT '',
    published_at TEXT NOT NULL DEFAULT '',
    collected_at TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL DEFAULT '',
    urls TEXT NOT NULL DEFAULT '[]',
    hashtags TEXT NOT NULL DEFAULT '[]',
    mentions TEXT NOT NULL DEFAULT '[]',
    media TEXT NOT NULL DEFAULT '[]',
    post_url TEXT NOT NULL DEFAULT '',
    is_reply INTEGER NOT NULL DEFAULT 0,
    is_repost INTEGER NOT NULL DEFAULT 0,
    is_quote INTEGER NOT NULL DEFAULT 0,
    reply_to TEXT NOT NULL DEFAULT '',
    quoted_post_id TEXT NOT NULL DEFAULT '',
    raw_metadata TEXT NOT NULL DEFAULT '{}',
    categories TEXT NOT NULL DEFAULT '[]',
    UNIQUE(source, source_post_id)
);
CREATE INDEX IF NOT EXISTS idx_x_posts_author ON x_posts(author_username);
CREATE INDEX IF NOT EXISTS idx_x_posts_account ON x_posts(account_id);
CREATE INDEX IF NOT EXISTS idx_x_posts_published ON x_posts(published_at);
CREATE VIRTUAL TABLE IF NOT EXISTS x_posts_fts USING fts5(
    post_id UNINDEXED, author_username, author_display_name, text, urls, hashtags,
    tokenize='porter unicode61 remove_diacritics 2');
CREATE TABLE IF NOT EXISTS x_post_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT '',
    value TEXT NOT NULL DEFAULT '',
    observed_value TEXT NOT NULL DEFAULT '',
    UNIQUE(post_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_x_entities_kind_value ON x_post_entities(kind, value);
CREATE INDEX IF NOT EXISTS idx_x_entities_post ON x_post_entities(post_id);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def connect(path: str = "") -> sqlite3.Connection:
    db_path = path or DB_PATH
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
    db_path = path or DB_PATH
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        migrate_schema(conn)
        purge_tweetfeed_observations(conn)
        normalize_transient_collection_statuses(conn)
        normalize_stale_collecting_statuses(conn)
        conn.commit()
        seed_accounts(conn)
        conn.commit()
    finally:
        conn.close()
    return db_path


def migrate_schema(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(x_accounts)").fetchall()}
    migrations = {
        "last_seen_published_at": "ALTER TABLE x_accounts ADD COLUMN last_seen_published_at TEXT NOT NULL DEFAULT ''",
        "last_result_count": "ALTER TABLE x_accounts ADD COLUMN last_result_count INTEGER NOT NULL DEFAULT 0",
    }
    for name, sql in migrations.items():
        if name not in columns:
            conn.execute(sql)


def normalize_username(value: str) -> str:
    raw = (value or "").strip().lstrip("@")
    if not USERNAME_RE.fullmatch(raw):
        raise ValueError("Invalid X username. Use 1-15 letters, numbers, or underscore.")
    return raw.lower()


def _account_id(username: str) -> str:
    return hashlib.sha256(f"x:{username.lower()}".encode("utf-8")).hexdigest()[:18]


def _json(value: Any, fallback: Any = None) -> str:
    return json.dumps(value if value is not None else (fallback if fallback is not None else []), ensure_ascii=False)


def _loads(value: Any, fallback: Any = None) -> Any:
    if fallback is None:
        fallback = []
    try:
        return json.loads(value) if value else fallback
    except Exception:
        return fallback


def _row_account(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "handle": f"@{row['username']}",
        "display_name": row["display_name"] or row["username"],
        "profile_url": row["profile_url"] or f"https://x.com/{row['username']}",
        "notes": row["notes"] or "",
        "tags": _loads(row["tags"], []),
        "enabled": bool(row["enabled"]),
        "interval_minutes": int(row["interval_minutes"] or 60),
        "created_at": row["created_at"] or "",
        "updated_at": row["updated_at"] or "",
        "last_checked_at": row["last_checked_at"] or "",
        "last_successful_check_at": row["last_successful_check_at"] or "",
        "last_seen_post_id": row["last_seen_post_id"] or "",
        "last_seen_published_at": row["last_seen_published_at"] or "",
        "last_result_count": int(row["last_result_count"] or 0),
        "collection_status": row["collection_status"] or "pending",
        "collection_error": row["collection_error"] or "",
    }


def seed_accounts(conn: sqlite3.Connection | None = None) -> int:
    owns_conn = conn is None
    conn = conn or connect()
    added = 0
    try:
        path = os.environ.get("MANTIS_X_MONITOR_SEED") or SEED_PATH
        if not os.path.exists(path):
            return 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            usernames = []
            for line in fh:
                line = line.strip()
                if not line or line.lower().startswith("these are"):
                    continue
                try:
                    usernames.append(normalize_username(line))
                except ValueError:
                    continue
        ts = now_iso()
        deleted = {
            row["username"]
            for row in conn.execute("SELECT username FROM x_account_deletions").fetchall()
        }
        for username in dict.fromkeys(usernames):
            if username in deleted:
                continue
            aid = _account_id(username)
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO x_accounts
                (id, username, display_name, profile_url, tags, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (aid, username, username, f"https://x.com/{username}", "[]", ts, ts),
            )
            added += int(cur.rowcount or 0)
        if owns_conn:
            conn.commit()
        return added
    finally:
        if owns_conn:
            conn.close()


def list_accounts() -> dict:
    init_db()
    conn = connect()
    try:
        rows = conn.execute("SELECT * FROM x_accounts ORDER BY enabled DESC, username ASC").fetchall()
        accounts = [_row_account(r) for r in rows]
        stats = {
            "monitored": len(accounts),
            "active": sum(1 for a in accounts if a["enabled"]),
            "paused": sum(1 for a in accounts if not a["enabled"]),
            "failing": sum(1 for a in accounts if a["collection_status"] in {"provider_error", "unavailable", "private", "renamed"}),
            "last_successful_collection": max([a["last_successful_check_at"] for a in accounts if a["last_successful_check_at"]] or [""]),
        }
        return {"accounts": accounts, "stats": stats}
    finally:
        conn.close()


def add_account(payload: dict) -> dict:
    init_db()
    username = normalize_username(payload.get("username", ""))
    tags = _normalize_tags(payload.get("tags"))
    ts = now_iso()
    account = {
        "id": _account_id(username),
        "username": username,
        "display_name": (payload.get("display_name") or username).strip()[:120],
        "profile_url": f"https://x.com/{username}",
        "notes": (payload.get("notes") or "").strip()[:2000],
        "tags": tags,
        "enabled": bool(payload.get("enabled", True)),
        "interval_minutes": max(15, min(int(payload.get("interval_minutes") or 60), 1440)),
    }
    conn = connect()
    try:
        conn.execute("DELETE FROM x_account_deletions WHERE username = ?", (username,))
        conn.execute(
            """
            INSERT INTO x_accounts
            (id, username, display_name, profile_url, notes, tags, enabled, interval_minutes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account["id"], account["username"], account["display_name"], account["profile_url"],
                account["notes"], _json(tags), 1 if account["enabled"] else 0, account["interval_minutes"], ts, ts,
            ),
        )
        conn.commit()
        return get_account(account["id"])
    except sqlite3.IntegrityError:
        raise ValueError(f"@{username} is already monitored.")
    finally:
        conn.close()


def purge_tweetfeed_observations(conn: sqlite3.Connection | None = None) -> int:
    owns_conn = conn is None
    conn = conn or connect()
    try:
        rows = conn.execute(
            """
            SELECT id FROM x_posts
            WHERE raw_metadata LIKE '%"tweetfeed"%'
               OR text LIKE 'TweetFeed observed %'
            """
        ).fetchall()
        post_ids = [r["id"] for r in rows]
        if not post_ids:
            return 0
        conn.executemany("DELETE FROM x_post_entities WHERE post_id = ?", [(pid,) for pid in post_ids])
        conn.executemany("DELETE FROM x_posts_fts WHERE post_id = ?", [(pid,) for pid in post_ids])
        conn.executemany("DELETE FROM x_posts WHERE id = ?", [(pid,) for pid in post_ids])
        if owns_conn:
            conn.commit()
        return len(post_ids)
    finally:
        if owns_conn:
            conn.close()


def normalize_transient_collection_statuses(conn: sqlite3.Connection | None = None) -> int:
    owns_conn = conn is None
    conn = conn or connect()
    try:
        cur = conn.execute(
            """
            UPDATE x_accounts
            SET collection_status = 'timeout'
            WHERE collection_status = 'error'
              AND LOWER(collection_error) LIKE '%timeout%'
            """
        )
        conn.execute(
            """
            UPDATE x_accounts
            SET collection_error = 'TwitterAPI.io plan or credit limit reached (HTTP 402)'
            WHERE collection_error = 'TwitterAPI.io request failed (HTTP 402)'
            """
        )
        if owns_conn:
            conn.commit()
        return int(cur.rowcount or 0)
    finally:
        if owns_conn:
            conn.close()


def normalize_stale_collecting_statuses(conn: sqlite3.Connection | None = None) -> int:
    owns_conn = conn is None
    conn = conn or connect()
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=20)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        cur = conn.execute(
            """
            UPDATE x_accounts
            SET collection_status = 'timeout',
                collection_error = 'Previous collection was interrupted before completion.'
            WHERE collection_status = 'collecting'
              AND COALESCE(NULLIF(last_checked_at, ''), '1970') < ?
            """,
            (cutoff,),
        )
        if owns_conn:
            conn.commit()
        return int(cur.rowcount or 0)
    finally:
        if owns_conn:
            conn.close()


def get_account(account_id: str) -> dict:
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM x_accounts WHERE id = ?", (account_id,)).fetchone()
        if not row:
            raise KeyError("Account not found.")
        return _row_account(row)
    finally:
        conn.close()


def update_account(account_id: str, payload: dict) -> dict:
    init_db()
    current = get_account(account_id)
    username = normalize_username(payload.get("username") or current["username"])
    tags = _normalize_tags(payload.get("tags", current["tags"]))
    ts = now_iso()
    new_id = _account_id(username)
    conn = connect()
    try:
        conn.execute(
            """
            UPDATE x_accounts
            SET id = ?, username = ?, display_name = ?, profile_url = ?, notes = ?, tags = ?,
                enabled = ?, interval_minutes = ?, updated_at = ?, collection_status = CASE
                    WHEN username != ? THEN 'pending' ELSE collection_status END,
                collection_error = CASE WHEN username != ? THEN '' ELSE collection_error END,
                last_seen_post_id = CASE WHEN username != ? THEN '' ELSE last_seen_post_id END,
                last_seen_published_at = CASE WHEN username != ? THEN '' ELSE last_seen_published_at END,
                last_result_count = CASE WHEN username != ? THEN 0 ELSE last_result_count END
            WHERE id = ?
            """,
            (
                new_id,
                username,
                (payload.get("display_name") or current["display_name"] or username).strip()[:120],
                f"https://x.com/{username}",
                (payload.get("notes") if payload.get("notes") is not None else current["notes"]).strip()[:2000],
                _json(tags),
                1 if bool(payload.get("enabled", current["enabled"])) else 0,
                max(15, min(int(payload.get("interval_minutes") or current["interval_minutes"] or 60), 1440)),
                ts,
                current["username"], current["username"], current["username"], current["username"], current["username"], account_id,
            ),
        )
        conn.commit()
        return get_account(new_id)
    except sqlite3.IntegrityError:
        raise ValueError(f"@{username} is already monitored.")
    finally:
        conn.close()


def delete_account(account_id: str, delete_posts: bool = False) -> dict:
    init_db()
    conn = connect()
    try:
        account = conn.execute("SELECT username FROM x_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            return {"ok": True, "deleted": False}
        if delete_posts:
            post_ids = [r["id"] for r in conn.execute("SELECT id FROM x_posts WHERE account_id = ?", (account_id,)).fetchall()]
            conn.executemany("DELETE FROM x_post_entities WHERE post_id = ?", [(pid,) for pid in post_ids])
            conn.executemany("DELETE FROM x_posts_fts WHERE post_id = ?", [(pid,) for pid in post_ids])
            conn.execute("DELETE FROM x_posts WHERE account_id = ?", (account_id,))
        conn.execute(
            """
            INSERT INTO x_account_deletions (username, deleted_at)
            VALUES (?, ?)
            ON CONFLICT(username) DO UPDATE SET deleted_at = excluded.deleted_at
            """,
            (account["username"], now_iso()),
        )
        conn.execute("DELETE FROM x_accounts WHERE id = ?", (account_id,))
        conn.commit()
        return {"ok": True, "deleted": True, "username": account["username"], "posts_deleted": bool(delete_posts)}
    finally:
        conn.close()


def _normalize_tags(value: Any) -> list[str]:
    if isinstance(value, str):
        raw = re.split(r"[,;\n]", value)
    elif isinstance(value, list):
        raw = value
    else:
        raw = []
    out = []
    for item in raw:
        tag = str(item or "").strip().lower()
        if tag and tag not in out:
            out.append(tag[:40])
    return out[:20]


def _parse_time(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        pass
    for fmt in ("%a %b %d %H:%M:%S %z %Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except Exception:
            continue
    return ""


def _defang_to_plain(text: str) -> str:
    plain = str(text or "")
    replacements = {
        "hxxps://": "https://",
        "hxxp://": "http://",
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[://]": "://",
    }
    for src, dst in replacements.items():
        plain = plain.replace(src, dst).replace(src.upper(), dst)
    return plain


def extract_entities(text: str, urls: list[str] | None = None, hashtags: list[str] | None = None, mentions: list[Any] | None = None) -> dict[str, list[str]]:
    plain = _defang_to_plain(text)
    found = {"urls": [], "domains": [], "ips": [], "hashes": [], "cves": [], "hashtags": [], "mentions": []}
    for url in (urls or []):
        if isinstance(url, str) and url.strip():
            found["urls"].append(url.strip())
    for match in re.finditer(r"https?://[^\s)\"'<>]+", plain, re.IGNORECASE):
        found["urls"].append(match.group(0).rstrip(".,;:!?"))
    for url in found["urls"]:
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
        if host and not host.endswith(("twitter.com", "x.com", "t.co")):
            _add_host_entity(found, host)
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", plain):
        _add_host_entity(found, match.group(0))
    for match in re.finditer(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b", plain, re.IGNORECASE):
        domain = match.group(0).lower().strip(".")
        if not domain.endswith(("twitter.com", "x.com", "t.co")):
            found["domains"].append(domain)
    for match in re.finditer(r"\bCVE-\d{4}-\d{4,7}\b", plain, re.IGNORECASE):
        found["cves"].append(match.group(0).upper())
    for match in re.finditer(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", plain):
        found["hashes"].append(match.group(0).lower())
    for tag in hashtags or []:
        if isinstance(tag, str) and tag.strip():
            found["hashtags"].append(tag.strip() if tag.strip().startswith("#") else f"#{tag.strip()}")
    for match in re.finditer(r"(?<!\w)#([A-Za-z0-9_]{2,80})", plain):
        found["hashtags"].append(f"#{match.group(1)}")
    for mention in mentions or []:
        if isinstance(mention, dict):
            mention = mention.get("username")
        if isinstance(mention, str) and mention.strip():
            found["mentions"].append(mention.strip() if mention.strip().startswith("@") else f"@{mention.strip()}")
    for key in found:
        found[key] = list(dict.fromkeys([x for x in found[key] if x]))[:50]
    return found


def _add_host_entity(found: dict[str, list[str]], host: str) -> None:
    host = (host or "").lower().strip("[]().,;:!?")
    if not host:
        return
    try:
        found["ips"].append(str(ipaddress.ip_address(host)))
    except ValueError:
        if "." in host:
            found["domains"].append(host)


def _classify(text: str, entities: dict[str, list[str]]) -> list[str]:
    low = f" {text.lower()} "
    categories = []
    if any(k in low for k in ("malware", "stealer", "loader", "backdoor", "trojan", "rat ", "botnet", "c2", "lumma", "plugx")):
        categories.append("malware")
    if entities.get("cves") or any(k in low for k in ("cve-", "0day", "zero-day", "vulnerability", "exploit", "rce", "poc")):
        categories.append("vulnerabilities")
    if entities.get("domains") or entities.get("ips") or any(k in low for k in ("infrastructure", "server", "panel", "hosted", "beacon")):
        categories.append("infrastructure")
    if any(k in low for k in ("campaign", "operation", "apt", "cluster", "threat actor", "intrusion set")):
        categories.append("campaigns")
    if any(k in low for k in ("ransomware", "leak site", "victim", "extortion")):
        categories.append("ransomware")
    if categories:
        return categories
    return ["threat-intel"] if any(entities.values()) else ["news"]


def normalize_post(tweet: dict, account: dict | sqlite3.Row | None = None) -> dict:
    author = tweet.get("author") if isinstance(tweet.get("author"), dict) else {}
    username = normalize_username(author.get("username") or (account or {}).get("username") or "")
    published_at = _parse_time(tweet.get("created_at") or tweet.get("createdAt") or tweet.get("published_at") or "")
    if not published_at:
        raise ValueError("Tweet missing a valid published timestamp")
    entities_raw = tweet.get("entities") if isinstance(tweet.get("entities"), dict) else {}
    urls = [str(x) for x in entities_raw.get("urls", []) or [] if x]
    hashtags = [str(x) for x in entities_raw.get("hashtags", []) or [] if x]
    mentions = entities_raw.get("mentions", []) or []
    entities = extract_entities(tweet.get("text") or "", urls, hashtags, mentions)
    source_post_id = str(tweet.get("id") or "")
    if not source_post_id:
        source_post_id = hashlib.sha256(f"{username}:{tweet.get('created_at')}:{tweet.get('text')}".encode("utf-8")).hexdigest()[:24]
    post_url = tweet.get("url") or f"https://x.com/{username}/status/{source_post_id}"
    return {
        "id": hashlib.sha256(f"x:{source_post_id}".encode("utf-8")).hexdigest()[:24],
        "source": "x",
        "source_post_id": source_post_id,
        "account_id": (account or {}).get("id") or _account_id(username),
        "author_username": username,
        "author_display_name": author.get("name") or (account or {}).get("display_name") or username,
        "author_avatar": author.get("profile_picture") or "",
        "published_at": published_at,
        "collected_at": now_iso(),
        "text": str(tweet.get("text") or ""),
        "urls": entities["urls"],
        "hashtags": entities["hashtags"],
        "mentions": entities["mentions"],
        "media": tweet.get("media") if isinstance(tweet.get("media"), list) else [],
        "post_url": post_url,
        "is_reply": bool(tweet.get("reply_to") or tweet.get("reply_to_user")),
        "is_repost": bool(tweet.get("retweeted_tweet")),
        "is_quote": bool(tweet.get("quoted_tweet")),
        "reply_to": str(tweet.get("reply_to") or ""),
        "quoted_post_id": str((tweet.get("quoted_tweet") or {}).get("id") or ""),
        "raw_metadata": tweet,
        "entities": entities,
        "categories": _classify(str(tweet.get("text") or ""), entities),
    }


def store_posts(posts: list[dict], conn: sqlite3.Connection | None = None) -> dict:
    owns_conn = conn is None
    conn = conn or connect()
    inserted = 0
    duplicates = 0
    try:
        for post in posts:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO x_posts
                (id, source, source_post_id, account_id, author_username, author_display_name, author_avatar,
                 published_at, collected_at, text, urls, hashtags, mentions, media, post_url, is_reply,
                 is_repost, is_quote, reply_to, quoted_post_id, raw_metadata, categories)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    post["id"], post["source"], post["source_post_id"], post["account_id"], post["author_username"],
                    post["author_display_name"], post["author_avatar"], post["published_at"], post["collected_at"],
                    post["text"], _json(post["urls"]), _json(post["hashtags"]), _json(post["mentions"]),
                    _json(post["media"]), post["post_url"], 1 if post["is_reply"] else 0,
                    1 if post["is_repost"] else 0, 1 if post["is_quote"] else 0, post["reply_to"],
                    post["quoted_post_id"], _json(post["raw_metadata"], {}), _json(post["categories"]),
                ),
            )
            if cur.rowcount:
                inserted += 1
                conn.execute(
                    "INSERT INTO x_posts_fts (post_id, author_username, author_display_name, text, urls, hashtags) VALUES (?, ?, ?, ?, ?, ?)",
                    (post["id"], post["author_username"], post["author_display_name"], post["text"], " ".join(post["urls"]), " ".join(post["hashtags"])),
                )
                kind_map = {
                    "urls": "url",
                    "domains": "domain",
                    "ips": "ip",
                    "hashes": "hash",
                    "cves": "cve",
                    "hashtags": "hashtag",
                    "mentions": "mention",
                }
                for kind, values in (post.get("entities") or {}).items():
                    for value in values:
                        conn.execute(
                            "INSERT OR IGNORE INTO x_post_entities (post_id, kind, value, observed_value) VALUES (?, ?, ?, ?)",
                            (post["id"], kind_map.get(kind, kind), value.lower() if kind not in {"cves", "hashtags", "mentions"} else value, value),
                        )
            else:
                duplicates += 1
        if owns_conn:
            conn.commit()
        return {"inserted": inserted, "duplicates": duplicates}
    finally:
        if owns_conn:
            conn.close()


def _backfill_page_cap(payload: dict, start: str, end: str) -> int:
    range_name = str(payload.get("range") or "7d").lower()
    if range_name in {"today", "24h", "24hours"}:
        return 2
    if range_name in {"30d", "30days"}:
        return 8
    if range_name == "custom":
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
            days = max(1, (end_dt - start_dt).days + 1)
            return max(2, min(8, (days // 2) + 1))
        except Exception:
            return 5
    return 5


def _post_exists(conn: sqlite3.Connection, source_post_id: str) -> bool:
    if not source_post_id:
        return False
    return bool(conn.execute(
        "SELECT 1 FROM x_posts WHERE source = 'x' AND source_post_id = ? LIMIT 1",
        (source_post_id,),
    ).fetchone())


def _is_original_tweet(tweet: dict) -> bool:
    if tweet.get("retweeted_tweet"):
        return False
    text = str(tweet.get("text") or "").lstrip()
    if text.upper().startswith("RT @"):
        return False
    return True


def _classify_account_status(result: dict) -> str:
    if int(result.get("inserted") or 0) or int(result.get("in_window_posts") or 0):
        return "active"
    if int(result.get("provider_tweets") or 0) == 0:
        return "empty"
    if result.get("stop_reason") == "older_than_window":
        return "inactive"
    return "active"


def _classify_error_status(message: str) -> str:
    low = (message or "").lower()
    if "timeout" in low:
        return "timeout"
    if "private" in low or "protected" in low:
        return "private"
    if "not found" in low or "suspended" in low:
        return "unavailable"
    if "auth" in low or "401" in low or "403" in low or "rate limit" in low or "429" in low:
        return "provider_error"
    return "provider_error"


def _query_timeline_with_retry(username: str, twitter_key: str, cursor: str, max_retries: int, force_refresh: bool) -> dict:
    attempt = 0
    while True:
        data = query_twitter_user_tweets(
            username,
            twitter_key,
            cursor=cursor,
            include_replies=False,
            force_refresh=force_refresh,
        )
        if not (isinstance(data, dict) and data.get("error") and "timeout" in str(data.get("error")).lower()):
            return data
        if attempt >= max_retries:
            return data
        attempt += 1
        time.sleep(min(0.25 * (2 ** (attempt - 1)), 1.0))


def collect_account_timeline(row: sqlite3.Row, twitter_key: str, conn: sqlite3.Connection, start: str, end: str, max_pages: int, mode: str = "monitor") -> dict:
    normalized: list[dict] = []
    cursor = ""
    seen_cursors: set[str] = set()
    pages = 0
    stop_reason = "max_pages"
    account = _row_account(row)
    provider_tweets = 0
    canonical_tweets = 0
    rejected = 0
    api_requests = 0
    newest_timestamp = ""
    oldest_timestamp = ""
    max_retries = 1
    historical = mode == "backfill"
    while pages < max_pages:
        data = _query_timeline_with_retry(row["username"], twitter_key, cursor, max_retries, force_refresh=True)
        api_requests += 1
        if isinstance(data, dict) and data.get("error"):
            if "timeout" in str(data.get("error")).lower():
                stop_reason = "timeout"
            else:
                stop_reason = "provider_error"
            raise RuntimeError(str(data.get("error"))[:240])
        diag = data.get("diagnostics") if isinstance(data, dict) and isinstance(data.get("diagnostics"), dict) else {}
        page_provider_tweets = int(diag.get("provider_tweets") or 0)
        provider_tweets += page_provider_tweets
        raw_tweets = data.get("tweets") if isinstance(data, dict) else []
        tweets = [tweet for tweet in (raw_tweets or []) if _is_original_tweet(tweet)]
        canonical_tweets += len(tweets)
        pages += 1
        if page_provider_tweets == 0 or not tweets:
            stop_reason = "no_tweets"
            break
        page_posts = []
        for tweet in tweets or []:
            try:
                page_posts.append(normalize_post(tweet, account))
            except Exception as exc:
                rejected += 1
                logger.warning("X Monitor rejected @%s tweet during normalization: %s", row["username"], str(exc)[:180])
        if not page_posts:
            stop_reason = "no_tweets"
            break
        page_times = [p["published_at"] for p in page_posts if p.get("published_at")]
        if page_times:
            page_newest = max(page_times)
            page_oldest = min(page_times)
            newest_timestamp = max([newest_timestamp, page_newest]) if newest_timestamp else page_newest
            oldest_timestamp = min([oldest_timestamp, page_oldest]) if oldest_timestamp else page_oldest
            if page_newest < start:
                stop_reason = "older_than_window"
                break
        in_window = [p for p in page_posts if start <= p["published_at"] < end]
        if historical:
            normalized.extend(in_window)
        else:
            for post in in_window:
                known_boundary = (
                    (row["last_seen_post_id"] and post["source_post_id"] == row["last_seen_post_id"])
                    or _post_exists(conn, post["source_post_id"])
                )
                if known_boundary:
                    stop_reason = "incremental_boundary"
                    break
                normalized.append(post)
            if stop_reason == "incremental_boundary":
                break
        pagination = data.get("pagination") if isinstance(data, dict) and isinstance(data.get("pagination"), dict) else {}
        has_next_page = bool(pagination.get("has_next_page"))
        next_cursor = str(pagination.get("next_cursor") or "")
        if not has_next_page:
            stop_reason = "no_next_page"
            break
        if not next_cursor:
            stop_reason = "no_cursor"
            break
        if next_cursor == cursor or next_cursor in seen_cursors:
            stop_reason = "repeated_cursor"
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    result = store_posts(normalized, conn)
    latest = normalized[0]["source_post_id"] if normalized else row["last_seen_post_id"]
    latest_published = normalized[0]["published_at"] if normalized else row["last_seen_published_at"]
    logger.info(
        "X Monitor @%s diagnostics provider=%d canonical=%d rejected=%d in_window=%d newest=%s oldest=%s inserted=%d duplicates=%d pages=%d stop_reason=%s",
        row["username"],
        provider_tweets,
        canonical_tweets,
        rejected,
        len(normalized),
        newest_timestamp or "-",
        oldest_timestamp or "-",
        result["inserted"],
        result["duplicates"],
        pages,
        stop_reason,
    )
    return {
        "collected": len(normalized),
        "latest": latest,
        "latest_published": latest_published,
        "pages": pages,
        "stop_reason": stop_reason,
        "newest_timestamp": newest_timestamp,
        "oldest_timestamp": oldest_timestamp,
        "provider_tweets": provider_tweets,
        "normalized_posts": canonical_tweets,
        "rejected_posts": rejected,
        "in_window_posts": len(normalized),
        "api_requests": api_requests,
        **result,
    }


def collect(payload: dict) -> dict:
    init_db()
    started_at = time.time()
    twitter_key = (payload.get("twitter_key") or "").strip()
    if not twitter_key:
        return {
            "ok": False,
            "reason": "Twitter/X API key is required for X Monitor account timeline collection.",
            "checked": 0,
            "collected": 0,
            "inserted": 0,
            "duplicates": 0,
            "errors": [],
        }
    if not COLLECTION_LOCK.acquire(blocking=False):
        return {"ok": False, "reason": "X Monitor collection is already running.", "collected": 0, "inserted": 0, "duplicates": 0}
    max_accounts = max(1, min(int(payload.get("accounts_per_batch") or payload.get("max_accounts") or 12), 50))
    account_id = (payload.get("account_id") or "").strip()
    start, end = _date_range(payload)
    mode = str(payload.get("mode") or "monitor").lower()
    if mode not in {"monitor", "backfill"}:
        mode = "monitor"
    max_pages = _backfill_page_cap(payload, start, end) if mode == "backfill" else 1
    conn = connect()
    checked = 0
    collected = 0
    inserted = 0
    duplicates = 0
    errors = []
    provider_tweets = 0
    normalized_posts = 0
    rejected_posts = 0
    in_window_posts = 0
    accounts_succeeded = 0
    accounts_timed_out = 0
    accounts_failed = 0
    accounts_empty = 0
    accounts_with_new_posts = 0
    api_requests = 0
    stop_reasons: dict[str, int] = {}
    try:
        if account_id:
            rows = conn.execute("SELECT * FROM x_accounts WHERE id = ? AND enabled = 1", (account_id,)).fetchall()
            total_active_accounts = len(rows)
        else:
            all_rows = conn.execute(
                "SELECT * FROM x_accounts WHERE enabled = 1 ORDER BY COALESCE(NULLIF(last_checked_at,''), '1970') ASC, username ASC"
            ).fetchall()
            total_active_accounts = len(all_rows)
            rows = all_rows[:max_accounts]
        for row in rows:
            checked += 1
            ts = now_iso()
            conn.execute("UPDATE x_accounts SET last_checked_at = ?, collection_status = 'collecting', collection_error = '' WHERE id = ?", (ts, row["id"]))
            conn.commit()
            try:
                result = collect_account_timeline(row, twitter_key, conn, start, end, max_pages, mode=mode)
                collected += int(result.get("collected") or 0)
                provider_tweets += int(result.get("provider_tweets") or 0)
                normalized_posts += int(result.get("normalized_posts") or 0)
                rejected_posts += int(result.get("rejected_posts") or 0)
                in_window_posts += int(result.get("in_window_posts") or 0)
                api_requests += int(result.get("api_requests") or 0)
                stop_reason = str(result.get("stop_reason") or "")
                if stop_reason:
                    stop_reasons[stop_reason] = stop_reasons.get(stop_reason, 0) + 1
                latest = result.get("latest") or row["last_seen_post_id"]
                latest_published = result.get("latest_published") or row["last_seen_published_at"]
                inserted += result["inserted"]
                duplicates += result["duplicates"]
                accounts_succeeded += 1
                if int(result.get("inserted") or 0) > 0:
                    accounts_with_new_posts += 1
                if _classify_account_status(result) == "empty":
                    accounts_empty += 1
                conn.execute(
                    """
                    UPDATE x_accounts
                    SET last_successful_check_at = ?,
                        last_seen_post_id = ?,
                        last_seen_published_at = ?,
                        last_result_count = ?,
                        collection_status = ?,
                        collection_error = ''
                    WHERE id = ?
                    """,
                    (now_iso(), latest, latest_published, int(result.get("in_window_posts") or 0), _classify_account_status(result), row["id"]),
                )
                conn.commit()
                logger.info("X Monitor checked @%s via twitterapi.io: %d in-window, %d new, %d duplicates, %d pages", row["username"], result.get("collected", 0), result["inserted"], result["duplicates"], result.get("pages", 0))
            except Exception as exc:
                msg = str(exc)[:240] or type(exc).__name__
                errors.append({"username": row["username"], "error": msg})
                status = _classify_error_status(msg)
                if status == "timeout":
                    accounts_timed_out += 1
                    stop_reasons["timeout"] = stop_reasons.get("timeout", 0) + 1
                else:
                    accounts_failed += 1
                    stop_reasons["provider_error"] = stop_reasons.get("provider_error", 0) + 1
                conn.execute("UPDATE x_accounts SET collection_status = ?, collection_error = ? WHERE id = ?", (status, msg, row["id"]))
                conn.commit()
        return {
            "ok": accounts_failed == 0,
            "mode": mode,
            "total_active_accounts": total_active_accounts,
            "accounts_requested": len(rows),
            "accounts_selected": len(rows),
            "checked": checked,
            "accounts_checked": checked,
            "accounts_succeeded": accounts_succeeded,
            "accounts_failed": accounts_failed,
            "accounts_timed_out": accounts_timed_out,
            "accounts_timeout": accounts_timed_out,
            "accounts_empty": accounts_empty,
            "accounts_with_new_posts": accounts_with_new_posts,
            "provider_tweets": provider_tweets,
            "provider_posts": provider_tweets,
            "normalized_posts": normalized_posts,
            "canonical_posts": normalized_posts,
            "rejected_posts": rejected_posts,
            "in_window_posts": in_window_posts,
            "collected": collected,
            "inserted": inserted,
            "duplicates": duplicates,
            "errors": errors,
            "api_requests": api_requests,
            "duration_ms": int((time.time() - started_at) * 1000),
            "stop_reasons": stop_reasons,
            "range_start": start,
            "range_end": end,
            "max_pages": max_pages,
        }
    finally:
        conn.close()
        COLLECTION_LOCK.release()


def _date_range(filters: dict) -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    range_name = str(filters.get("range") or "7d").lower()
    if range_name == "today":
        start = now.replace(hour=0, minute=0, second=0)
    elif range_name in {"24h", "24hours"}:
        start = now - timedelta(hours=24)
    elif range_name in {"30d", "30days"}:
        start = now - timedelta(days=30)
    elif range_name == "custom":
        start_raw = str(filters.get("start_date") or "").strip()
        end_raw = str(filters.get("end_date") or "").strip()
        start = datetime.fromisoformat(start_raw).replace(tzinfo=timezone.utc) if start_raw else now - timedelta(days=7)
        end = datetime.fromisoformat(end_raw).replace(tzinfo=timezone.utc) + timedelta(days=1) if end_raw else now + timedelta(seconds=1)
        return start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z")
    else:
        start = now - timedelta(days=7)
    return start.isoformat().replace("+00:00", "Z"), (now + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")


def dashboard(filters: dict | None = None) -> dict:
    init_db()
    filters = filters or {}
    page = max(1, int(filters.get("page") or 1))
    page_size = max(12, min(int(filters.get("page_size") or 36), 100))
    start, end = _date_range(filters)
    where = ["published_at >= ?", "published_at < ?"]
    args: list[Any] = [start, end]
    account = (filters.get("account") or "").strip().lstrip("@").lower()
    if account:
        where.append("author_username = ?")
        args.append(account)
    category = (filters.get("category") or "").strip().lower()
    if category and category != "all":
        where.append("categories LIKE ?")
        args.append(f"%{category}%")
    entity = (filters.get("entity") or "").strip().lower()
    if entity:
        entity_map = {"url": "url", "domain": "domain", "ip": "ip", "hash": "hash", "cve": "cve", "media": "media"}
        if entity == "media":
            where.append("media != '[]'")
        else:
            kind = entity_map.get(entity, entity)
            where.append("id IN (SELECT post_id FROM x_post_entities WHERE kind = ?)")
            args.append(kind)
    q = (filters.get("q") or "").strip()
    if q:
        like = f"%{q.lower()}%"
        where.append("(LOWER(text) LIKE ? OR LOWER(author_username) LIKE ? OR LOWER(urls) LIKE ? OR LOWER(hashtags) LIKE ?)")
        args.extend([like, like, like, like])
    sort = "ASC" if str(filters.get("sort") or "newest").lower() == "oldest" else "DESC"
    where_sql = " AND ".join(where)
    conn = connect()
    try:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM x_posts WHERE {where_sql}", args).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM x_posts WHERE {where_sql} ORDER BY published_at {sort} LIMIT ? OFFSET ?",
            args + [page_size, (page - 1) * page_size],
        ).fetchall()
        accounts = [_row_account(r) for r in conn.execute("SELECT * FROM x_accounts ORDER BY enabled DESC, username ASC").fetchall()]
        stats = _stats(conn, start, end)
        posts = [_row_post(r, conn) for r in rows]
        categories = _category_counts(conn, start, end)
        health = _health(accounts)
        return {
            "filters": {**filters, "range_start": start, "range_end": end},
            "stats": stats,
            "accounts": accounts,
            "categories": categories,
            "posts": posts,
            "pagination": {"page": page, "page_size": page_size, "total": total, "pages": max(1, (int(total) + page_size - 1) // page_size)},
            "health": health,
            "collector": {"mode": "twitterapi.io", "requires_key": True, "api_free_adapter": "not configured"},
        }
    finally:
        conn.close()


def _row_post(row: sqlite3.Row, conn: sqlite3.Connection) -> dict:
    entities: dict[str, list[str]] = {}
    for e in conn.execute("SELECT kind, observed_value FROM x_post_entities WHERE post_id = ? ORDER BY kind, observed_value", (row["id"],)).fetchall():
        entities.setdefault(e["kind"], []).append(e["observed_value"])
    raw_metadata = _loads(row["raw_metadata"], {})
    media = _loads(row["media"], [])
    if not media:
        media = _media_from_raw_metadata(raw_metadata)
    else:
        media = _dedupe_media_items(media)
    return {
        "id": row["id"],
        "source": row["source"],
        "source_post_id": row["source_post_id"],
        "account_id": row["account_id"],
        "author_username": row["author_username"],
        "author_display_name": row["author_display_name"] or row["author_username"],
        "author_avatar": row["author_avatar"],
        "published_at": row["published_at"],
        "collected_at": row["collected_at"],
        "text": row["text"],
        "urls": _loads(row["urls"], []),
        "hashtags": _loads(row["hashtags"], []),
        "mentions": _loads(row["mentions"], []),
        "media": media,
        "post_url": row["post_url"],
        "is_reply": bool(row["is_reply"]),
        "is_repost": bool(row["is_repost"]),
        "is_quote": bool(row["is_quote"]),
        "metrics": raw_metadata.get("metrics") if isinstance(raw_metadata.get("metrics"), dict) else {},
        "categories": _loads(row["categories"], []),
        "entities": entities,
    }


def _media_dedup_key(url: Any) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw
    host = parsed.netloc.lower()
    path = parsed.path or ""
    if host == "pbs.twimg.com" and (path.startswith("/media/") or path.startswith("/card_img/")):
        return f"{host}{path}"
    return urlunparse((
        parsed.scheme.lower(),
        host,
        path.rstrip("/") if path != "/" else path,
        "",
        parsed.query,
        "",
    )) or raw


def _media_dimensions(item: dict) -> tuple[int, int]:
    width = item.get("width") if isinstance(item, dict) else 0
    height = item.get("height") if isinstance(item, dict) else 0
    return (
        int(width or 0) if str(width or "").isdigit() else 0,
        int(height or 0) if str(height or "").isdigit() else 0,
    )


def _dedupe_media_items(media: Any) -> list[dict]:
    if not isinstance(media, list):
        return []
    out: list[dict] = []
    seen: dict[str, int] = {}
    for item in media:
        if not isinstance(item, dict):
            continue
        preview = str(item.get("preview") or item.get("url") or "").strip()
        url = str(item.get("url") or preview or "").strip()
        if preview.startswith(("https://t.co/", "http://t.co/")):
            preview = ""
        if url.startswith(("https://t.co/", "http://t.co/")) and preview:
            url = preview
        if not preview and not url:
            continue
        width, height = _media_dimensions(item)
        normalized = {
            "type": item.get("type") or "photo",
            "url": url,
            "preview": preview,
            "width": width,
            "height": height,
        }
        key = _media_dedup_key(preview or url)
        if key in seen:
            existing = out[seen[key]]
            existing_area = int(existing.get("width") or 0) * int(existing.get("height") or 0)
            new_area = width * height
            if new_area > existing_area:
                out[seen[key]] = normalized
            continue
        seen[key] = len(out)
        out.append(normalized)
    return out[:12]


def _media_from_raw_metadata(raw_metadata: dict) -> list[dict]:
    if not isinstance(raw_metadata, dict):
        return []
    media = raw_metadata.get("media")
    if isinstance(media, list) and media:
        return _dedupe_media_items(media)
    provider = raw_metadata.get("raw_provider_data") if isinstance(raw_metadata.get("raw_provider_data"), dict) else {}
    out: list[dict] = []
    seen: dict[str, int] = {}

    def add(url: str, media_type: str = "photo", width: Any = 0, height: Any = 0) -> None:
        if not url:
            return
        key = _media_dedup_key(url)
        item = {
            "type": media_type,
            "url": str(url),
            "preview": str(url),
            "width": int(width or 0) if str(width or "").isdigit() else 0,
            "height": int(height or 0) if str(height or "").isdigit() else 0,
        }
        if key in seen:
            existing = out[seen[key]]
            existing_area = int(existing.get("width") or 0) * int(existing.get("height") or 0)
            new_area = item["width"] * item["height"]
            if new_area > existing_area:
                out[seen[key]] = item
            return
        seen[key] = len(out)
        out.append(item)

    for item in provider.get("media") or []:
        if not isinstance(item, dict):
            continue
        add(
            item.get("media_url_https") or item.get("mediaUrlHttps") or item.get("url") or item.get("preview_image_url") or item.get("previewImageUrl") or "",
            item.get("type") or item.get("mediaType") or "",
            item.get("width"),
            item.get("height"),
        )
    card = provider.get("card") if isinstance(provider.get("card"), dict) else {}
    for binding in card.get("binding_values") or []:
        value = binding.get("value") if isinstance(binding, dict) else {}
        image = value.get("image_value") if isinstance(value, dict) else {}
        if isinstance(image, dict):
            add(image.get("url") or "", "photo", image.get("width"), image.get("height"))
    return out[:12]


def _stats(conn: sqlite3.Connection, start: str, end: str) -> dict:
    total_accounts = conn.execute("SELECT COUNT(*) AS c FROM x_accounts").fetchone()["c"]
    active_accounts = conn.execute("SELECT COUNT(*) AS c FROM x_accounts WHERE enabled = 1").fetchone()["c"]
    total_posts = conn.execute("SELECT COUNT(*) AS c FROM x_posts").fetchone()["c"]
    posts_range = conn.execute("SELECT COUNT(*) AS c FROM x_posts WHERE published_at >= ? AND published_at < ?", (start, end)).fetchone()["c"]
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")
    posts_today = conn.execute("SELECT COUNT(*) AS c FROM x_posts WHERE published_at >= ?", (today_start,)).fetchone()["c"]
    def count_kind(kind: str) -> int:
        return conn.execute(
            "SELECT COUNT(DISTINCT post_id || ':' || value) AS c FROM x_post_entities WHERE kind = ? AND post_id IN (SELECT id FROM x_posts WHERE published_at >= ? AND published_at < ?)",
            (kind, start, end),
        ).fetchone()["c"]
    return {
        "monitored_accounts": total_accounts,
        "active_accounts": active_accounts,
        "posts_today": posts_today,
        "total_posts": total_posts,
        "range_posts": posts_range,
        "urls": count_kind("url"),
        "domains": count_kind("domain"),
        "ips": count_kind("ip"),
        "hashes": count_kind("hash"),
        "cves": count_kind("cve"),
    }


def _category_counts(conn: sqlite3.Connection, start: str, end: str) -> list[dict]:
    rows = conn.execute("SELECT categories FROM x_posts WHERE published_at >= ? AND published_at < ?", (start, end)).fetchall()
    counts: dict[str, int] = {"all": len(rows)}
    for row in rows:
        for cat in _loads(row["categories"], []):
            counts[cat] = counts.get(cat, 0) + 1
    order = ["all", "threat-intel", "malware", "vulnerabilities", "infrastructure", "campaigns", "ransomware", "news"]
    return [{"id": key, "label": _category_label(key), "count": int(counts.get(key, 0))} for key in order]


def _category_label(key: str) -> str:
    return {
        "all": "All Posts",
        "threat-intel": "Threat Intel",
        "malware": "Malware",
        "vulnerabilities": "Vulnerabilities",
        "infrastructure": "Infrastructure",
        "campaigns": "Campaigns",
        "ransomware": "Ransomware",
        "news": "News",
    }.get(key, key.title())


def _health(accounts: list[dict]) -> list[dict]:
    if not accounts:
        return [{"ok": False, "label": "Watchlist", "status": "empty", "detail": "No monitored X accounts configured."}]
    failing = [a for a in accounts if a["collection_status"] in {"provider_error", "unavailable", "private", "renamed"}]
    provider_failing = [a for a in failing if a["collection_status"] == "provider_error"]
    account_failing = [a for a in failing if a["collection_status"] != "provider_error"]
    timeouts = [a for a in accounts if a["collection_status"] == "timeout"]
    collecting = [a for a in accounts if a["collection_status"] == "collecting"]
    checked = [a for a in accounts if a["last_checked_at"]]
    successful = [a for a in accounts if a["last_successful_check_at"]]
    last_check = max([a["last_checked_at"] for a in checked] or [""])
    recent_results = sum(a.get("last_result_count", 0) for a in accounts if a.get("last_checked_at") == last_check)
    if collecting:
        sync_status = "collecting"
    elif failing or timeouts:
        sync_status = "partial"
    elif successful:
        sync_status = "ready"
    else:
        sync_status = "not tested"
    health = [
        {"ok": True, "label": "Accounts", "status": f"{sum(1 for a in accounts if a['enabled'])} active", "detail": f"{len(accounts)} monitored accounts."},
        {"ok": not failing and not collecting, "label": "Timeline Sync", "status": sync_status, "detail": "Direct X account timeline collection. Key presence alone does not prove provider reachability."},
        {"ok": bool(checked), "label": "Last Check", "status": (last_check or "never")[:16].replace("T", " "), "detail": "Manual refresh collects recent posts when a Twitter/X API key is configured."},
        {"ok": True, "label": "New Posts", "status": str(recent_results), "detail": "In-window posts from the most recent account check timestamp."},
    ]
    if timeouts:
        health.append({
            "ok": True,
            "label": "Timeouts",
            "status": str(len(timeouts)),
            "detail": f"Latest timeout on @{timeouts[0]['username']}: {timeouts[0]['collection_error']}",
        })
    if provider_failing:
        health.append({
            "ok": False,
            "label": "Provider Errors",
            "status": f"{len(provider_failing)} request{'s' if len(provider_failing) != 1 else ''}",
            "detail": provider_failing[0]["collection_error"] or f"Latest provider error while checking @{provider_failing[0]['username']}.",
        })
    if account_failing:
        health.append({
            "ok": False,
            "label": "Account Errors",
            "status": f"{len(account_failing)} account",
            "detail": f"@{account_failing[0]['username']}: {account_failing[0]['collection_error']}",
        })
    return health
