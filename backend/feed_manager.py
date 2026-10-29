import csv
import io
import json
import logging
import sqlite3
import requests
from feed_intel import connect

logger = logging.getLogger("mantis.feed_manager")

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
        
        conn = connect()
        added = 0
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
            
            # Map their Category to our indicator_type
            itype = ""
            if 'ip' in cat: itype = 'ip'
            elif 'domain' in cat: itype = 'domain'
            elif 'url' in cat: itype = 'url'
            elif 'md5' in cat: itype = 'md5'
            elif 'sha1' in cat: itype = 'sha1'
            elif 'sha256' in cat: itype = 'sha256'
            
            if not itype:
                continue
                
            try:
                # INSERT OR IGNORE, keeping enabled status if it already exists
                cursor = conn.execute(
                    "INSERT INTO feed_sources (id, name, type, source_url, enabled, is_dynamic, indicator_type, description) "
                    "VALUES (?, ?, 'feed', ?, 0, 1, ?, ?)",
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

def get_feed_list():
    conn = connect()
    rows = conn.execute("SELECT id, name, source_url, enabled, status, record_count, is_dynamic, description FROM feed_sources ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def toggle_feed(fid: str, enabled: bool):
    conn = connect()
    try:
        cursor = conn.execute("UPDATE feed_sources SET enabled = ? WHERE id = ?", (1 if enabled else 0, fid))
        conn.commit()
        if cursor.rowcount == 0:
            return {"ok": False, "reason": "Feed source not found"}
        return {"ok": True}
    finally:
        conn.close()
