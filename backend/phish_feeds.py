"""Batch 2: OpenPhish Community Feed -> local URL index.

OpenPhish offers no public URL lookup API, so the feed is ingested locally
and all analyst lookups run against this index. Community feed only: no
reporting, no submissions, no scan requests, no investigator uploads.

Reusable shape for future Batch 4 feeds: fetch -> normalize -> upsert ->
exact/domain query + staleness reporting.
"""
import logging
import os
import re
import sqlite3
import time
import urllib.parse

import requests

logger = logging.getLogger("mantis.phish")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
PHISH_DB_PATH = os.path.join(DATA_DIR, "phish_feeds.db")

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_REFRESH_SECONDS = 12 * 3600

SCHEMA = """
CREATE TABLE IF NOT EXISTS openphish_urls (
    normalized_url TEXT PRIMARY KEY,
    original_url TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    first_imported TEXT NOT NULL DEFAULT '',
    last_seen_in_feed TEXT NOT NULL DEFAULT '',
    feed_timestamp TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_openphish_domain ON openphish_urls(domain);
"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def connect(path: str = "") -> sqlite3.Connection:
    db_path = path or PHISH_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error:
        pass
    return conn


def init_db(path: str = "") -> str:
    db_path = path or PHISH_DB_PATH
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    return db_path


def normalize_feed_url(url: str) -> str:
    """Canonical form for exact matching. Keeps path/query/port (meaningful),
    lowercases scheme+host, strips default ports and one trailing slash."""
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https"):
        return ""
    host = (parts.hostname or "").lower()
    if not host or "." not in host:
        return ""
    if re.search(r"\s", host):
        return ""
    port = parts.port
    netloc = host
    if port and not ((parts.scheme == "http" and port == 80) or
                     (parts.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    try:
        path = urllib.parse.unquote(parts.path or "/")
    except Exception:
        path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return urllib.parse.urlunsplit(
        (parts.scheme.lower(), netloc, path, parts.query, ""))


def feed_domain(normalized_url: str) -> str:
    try:
        return (urllib.parse.urlsplit(normalized_url).hostname or "").lower()
    except ValueError:
        return ""


def _feed_state(conn) -> dict:
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n, MAX(last_seen_in_feed) AS ts"
            " FROM openphish_urls").fetchone()
        return {"count": row["n"] if row else 0,
                "feed_timestamp": row["ts"] if row and row["ts"] else ""}
    except sqlite3.Error:
        return {"count": 0, "feed_timestamp": ""}


def feed_status(conn=None) -> dict:
    """Freshness for the Sources/status line."""
    own = conn is None
    if own:
        init_db()
        conn = connect()
    try:
        st = _feed_state(conn)
        ts = st["feed_timestamp"]
        try:
            import calendar
            age = (time.time() - calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%S"))
                   if ts else float("inf"))
        except (ValueError, OverflowError):
            age = float("inf")
        st["stale"] = age > OPENPHISH_REFRESH_SECONDS or not st["count"]
        st["age_s"] = int(age) if age != float("inf") else -1
        return st
    finally:
        if own:
            conn.close()


def refresh_openphish(force: bool = False) -> dict:
    """Download the Community feed and upsert URLs. Passive feed fetch only."""
    init_db()
    conn = connect()
    try:
        state = _feed_state(conn)
        if not force and state["count"]:
            try:
                import calendar
                last = calendar.timegm(time.strptime(state["feed_timestamp"],
                                                     "%Y-%m-%dT%H:%M:%S"))
                if time.time() - last < OPENPHISH_REFRESH_SECONDS:
                    return {"refreshed": False, "reason": "fresh",
                            **feed_status(conn)}
            except (ValueError, OverflowError, TypeError):
                pass
        try:
            resp = requests.get(
                OPENPHISH_FEED_URL, timeout=30,
                headers={"User-Agent": "MANTIS-Threat-Intel/1.0"})
        except requests.exceptions.Timeout:
            return {"refreshed": False, "reason": "feed timed out",
                    **feed_status(conn)}
        except Exception as e:
            return {"refreshed": False,
                    "reason": f"feed failed ({type(e).__name__})",
                    **feed_status(conn)}
        if resp.status_code != 200:
            return {"refreshed": False,
                    "reason": f"feed status {resp.status_code}",
                    **feed_status(conn)}
        ts = now_iso()
        seen, added = 0, 0
        for line in resp.text.splitlines():
            url = (line or "").strip()
            if not url:
                continue
            norm = normalize_feed_url(url)
            if not norm:
                continue
            seen += 1
            cur = conn.execute(
                "SELECT normalized_url FROM openphish_urls WHERE normalized_url = ?",
                (norm,)).fetchone()
            if cur:
                conn.execute(
                    "UPDATE openphish_urls SET last_seen_in_feed = ?,"
                    " feed_timestamp = ?, original_url = ? WHERE normalized_url = ?",
                    (ts, ts, url[:500], norm))
            else:
                conn.execute(
                    "INSERT INTO openphish_urls (normalized_url, original_url, domain,"
                    " first_imported, last_seen_in_feed, feed_timestamp)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (norm, url[:500], feed_domain(norm), ts, ts, ts))
                added += 1
        conn.commit()
        return {"refreshed": True, "seen": seen, "added": added,
                **feed_status(conn)}
    finally:
        conn.close()


def query_openphish_url(url: str, conn=None) -> dict:
    """Exact normalized URL match (highest confidence)."""
    norm = normalize_feed_url(url or "")
    if not norm:
        return {"source": "OpenPhish", "match": "none", "results": []}
    own = conn is None
    if own:
        init_db()
        conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM openphish_urls WHERE normalized_url = ?",
            (norm,)).fetchone()
        if not row:
            return {"source": "OpenPhish", "match": "none", "results": []}
        d = dict(row)
        return {"source": "OpenPhish", "match": "exact",
                "results": [{
                    "url": d["original_url"], "normalized_url": d["normalized_url"],
                    "domain": d["domain"], "first_seen": d["first_imported"],
                    "last_seen": d["last_seen_in_feed"],
                    "feed_timestamp": d["feed_timestamp"]}],
                "note": "Observed in the OpenPhish Community Feed"}
    finally:
        if own:
            conn.close()


def query_openphish_domain(domain: str, limit: int = 50, conn=None) -> dict:
    """Domain-level relationship evidence (NOT an exact-URL verdict)."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"source": "OpenPhish", "match": "none", "results": []}
    own = conn is None
    if own:
        init_db()
        conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM openphish_urls WHERE domain = ?"
            " ORDER BY last_seen_in_feed DESC LIMIT ?",
            (domain, max(1, min(int(limit or 50), 200)))).fetchall()
        results = [{
            "url": r["original_url"], "normalized_url": r["normalized_url"],
            "domain": r["domain"], "first_seen": r["first_imported"],
            "last_seen": r["last_seen_in_feed"],
            "feed_timestamp": r["feed_timestamp"]} for r in rows]
        if not results:
            return {"source": "OpenPhish", "match": "none", "results": []}
        return {"source": "OpenPhish", "match": "domain",
                "results": results,
                "note": "Domain-level evidence only: one phishing URL here"
                        " does not make every URL on the domain phishing"}
    finally:
        if own:
            conn.close()
