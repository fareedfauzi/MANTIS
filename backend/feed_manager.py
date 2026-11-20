import csv
import io
import json
import logging
import sqlite3
import requests
from feed_intel import KASPERSKY_FEEDS, connect, feed_sync_stages, init_db, kaspersky_token

logger = logging.getLogger("mantis.feed_manager")

# Catalog feeds with no usable machine-readable upstream (HTML landing or
# terms pages, rate-limited, or not IP/domain/hash data). Not synced, and
# existing rows are removed on the next catalog sync.
REMOVED_FEED_IDS = {
    "dyn_snort_ip",               # SNORT: terms-of-use HTML page
    "dyn_ellio_ip",               # Ellio: web app HTML page
    "dyn_danielaustinmbcs_ip",    # dan.me.uk: 403, 30-minute rate limit
    "dyn_mthcht_namepipe",        # Named pipe names, not an indicator type
}

CATALOG_URL = "https://raw.githubusercontent.com/Bert-JanP/Open-Source-Threat-Intel-Feeds/refs/heads/main/ThreatIntelFeeds.csv"

def sync_catalog():
    conn = None
    try:
        resp = requests.get(CATALOG_URL, timeout=15)
        if resp.status_code != 200:
            logger.error(f"Failed to fetch feed catalog: {resp.status_code}")
            return {"ok": False, "reason": f"HTTP {resp.status_code}"}
        
        # Parse CSV
        reader = csv.DictReader(io.StringIO(resp.text), delimiter=';')
        
        init_db()
        conn = connect()
        added = 0
        for rid in REMOVED_FEED_IDS:
            conn.execute("DELETE FROM feed_indicators WHERE source = ?", (rid,))
            conn.execute("DELETE FROM feed_networks WHERE source = ?", (rid,))
            conn.execute("DELETE FROM feed_sources WHERE id = ? AND is_dynamic = 1", (rid,))
        for row in reader:
            vendor = (row.get('Vendor') or '').strip()
            desc = (row.get('Description') or '').strip()
            cat = (row.get('Category') or '').strip().lower()
            url = (row.get('Url') or '').strip()
            status = (row.get('FeedStatus') or '').strip().lower()
            
            if not url or status != 'active':
                continue
                
            # determine id
            fid = f"dyn_{vendor.replace(' ', '').lower()}_{cat}"
            name = f"{vendor} ({cat})"
            if fid in REMOVED_FEED_IDS:
                continue
            
            # Map their Category to our indicator_type (exact match: "namepipe" contains "ip")
            itype = {"ip": "ip", "ipv4": "ip", "domain": "domain", "url": "url",
                     "md5": "md5", "sha1": "sha1", "sha256": "sha256"}.get(cat, "")
            
            if not itype:
                continue
                
            try:
                # INSERT OR IGNORE, keeping enabled status if it already exists
                cursor = conn.execute(
                    "INSERT INTO feed_sources (id, name, type, source_url, enabled, is_dynamic, indicator_type, description) "
                    "VALUES (?, ?, 'feed', ?, 1, 1, ?, ?)",
                    (fid, name, url, itype, desc)
                )
                if cursor.rowcount > 0:
                    added += 1
            except sqlite3.IntegrityError:
                pass # Already exists
        conn.commit()
        return {"ok": True, "added": added}
    except Exception as e:
        logger.error(f"Catalog sync failed: {e}")
        return {"ok": False, "reason": str(e)}
    finally:
        if conn is not None:
            conn.close()

def get_feed_list(tip_key: str = ""):
    conn = connect()
    try:
        # Keep status polling read-only after the catalog's first initialization.
        if conn.execute("PRAGMA user_version").fetchone()[0] == 0:
            init_db()
        rows = conn.execute("SELECT id, name, source_url, enabled, status, record_count, is_dynamic, indicator_type, description, last_success, error FROM feed_sources ORDER BY is_dynamic ASC, name ASC").fetchall()
    finally:
        conn.close()
    sources = [dict(row) for row in rows]
    stages = feed_sync_stages()
    for source in sources:
        if source["id"] in KASPERSKY_FEEDS:
            source["requires_tip_key"] = True
            if not kaspersky_token(tip_key):
                source.update(enabled=0, status="not-configured", record_count=0, last_success="", error="")
        if source["enabled"]:
            source["sync_stage"] = stages.get(source["id"], "")
    return sources


def export_feed_csv(feed_ids: list[str]):
    """Stream cached indicator rows, retaining one row per source and indicator."""
    placeholders = ",".join("?" for _ in feed_ids)
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(("indicator", "type", "source", "category", "synced_at_utc"))
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate()
    # StreamingResponse may resume the iterator on a different worker thread.
    conn = connect(check_same_thread=False)
    try:
        rows = conn.execute(f"""
            SELECT i.value, i.indicator_type, s.name, i.category, s.last_success
            FROM feed_indicators i JOIN feed_sources s ON s.id = i.source
            WHERE i.source IN ({placeholders})
            UNION ALL
            SELECT COALESCE(NULLIF(n.cidr, ''), n.asn),
                   CASE WHEN n.cidr <> '' THEN 'cidr' ELSE 'asn' END,
                   s.name, n.category, s.last_success
            FROM feed_networks n JOIN feed_sources s ON s.id = n.source
            WHERE n.source IN ({placeholders})
        """, feed_ids + feed_ids)
        for indicator, kind, source, category, synced_at in rows:
            timestamp = f"{synced_at}Z" if synced_at else ""
            fields = (indicator, kind, source, category or "", timestamp)
            # Feed content is untrusted and the CSV may be opened in Excel.
            writer.writerow([
                "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
                for value in fields
            ])
            if buffer.tell() >= 64 * 1024:
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate()
        if buffer.tell():
            yield buffer.getvalue()
    finally:
        conn.close()


def toggle_feed(fid: str, enabled: bool, tip_key: str = ""):
    if fid in KASPERSKY_FEEDS and enabled and not kaspersky_token(tip_key):
        return {"ok": False, "status": 400, "reason": "Configure a Kaspersky TIP API token to enable this feed."}
    init_db()
    conn = connect()
    try:
        cursor = conn.execute("UPDATE feed_sources SET enabled = ? WHERE id = ?", (1 if enabled else 0, fid))
        conn.commit()
        if cursor.rowcount == 0:
            return {"ok": False, "reason": "Feed source not found"}
        return {"ok": True}
    finally:
        conn.close()
