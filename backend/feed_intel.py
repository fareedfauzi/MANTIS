"""Batch 4: local reputation-feed engine + passive live lookups.

Architecture: External Feed -> fetch -> validate -> parse (memory) ->
atomic single-transaction replace -> local SQLite match. The previous
dataset is never dropped before the new one validates, and suspicious
record-count collapses keep last-known-good data.

Strictly PASSIVE / READ-ONLY. No submissions, reports, scans, probes,
downloads of targets, validation, blocking, or enrichment chains.
A zero result stays zero; failures are isolated per source.
"""
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
from typing import Any, Dict

import requests

logger = logging.getLogger("mantis.feeds")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
FEED_DB_PATH = os.path.join(DATA_DIR, "reputation_feeds.db")

UA = "MANTIS-Threat-Intel/1.0"

SCHEMA = """
CREATE TABLE IF NOT EXISTS feed_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_success TEXT DEFAULT '',
    last_attempt TEXT DEFAULT '',
    next_refresh TEXT DEFAULT '',
    record_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'never-synced',
    error TEXT DEFAULT '',
    is_dynamic INTEGER NOT NULL DEFAULT 0,
    indicator_type TEXT DEFAULT '',
    category_override TEXT DEFAULT '',
    description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS feed_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    category TEXT DEFAULT '',
    confidence TEXT DEFAULT '',
    first_seen TEXT DEFAULT '',
    last_seen TEXT DEFAULT '',
    metadata_json TEXT DEFAULT '{}',
    UNIQUE(source, indicator_type, normalized_value)
);
CREATE INDEX IF NOT EXISTS idx_feed_ind_value ON feed_indicators(indicator_type, normalized_value);
CREATE INDEX IF NOT EXISTS idx_feed_ind_source ON feed_indicators(source);
CREATE TABLE IF NOT EXISTS feed_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    cidr TEXT NOT NULL DEFAULT '',
    prefix_length INTEGER DEFAULT 0,
    asn TEXT DEFAULT '',
    category TEXT DEFAULT '',
    metadata_json TEXT DEFAULT '{}',
    UNIQUE(source, cidr, asn)
);
CREATE INDEX IF NOT EXISTS idx_feed_net_source ON feed_networks(source);
"""

# Refresh intervals (seconds) per spec guidance.
INTERVALS = {
    "et_open": 24 * 3600,
    "spamhaus": 12 * 3600,
    "cins": 12 * 3600,
    "blocklist": 6 * 3600,
    "tor": 3 * 3600,
    "stevenblack": 24 * 3600,
}


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def connect(path: str = "") -> sqlite3.Connection:
    db_path = path or FEED_DB_PATH
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
    db_path = path or FEED_DB_PATH
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    return db_path


_CACHE: dict = {}
_CACHE_TTL = {"hit": 21600, "miss": 1800}


def _feed_feed_key_tag(api_key: str = "") -> str:
    if not (api_key or "").strip():
        return "anon"
    return hashlib.sha256(api_key.strip().encode()).hexdigest()[:12]


def _http_error(label: str, status: int) -> Dict[str, Any]:
    if status == 400:
        return {"error": f"{label}: invalid request (400)"}
    if status in (401, 403):
        return {"error": f"{label}: unauthorized — check the API key ({status})"}
    if status == 404:
        return {"data": [], "note": f"No {label} record"}
    if status == 429:
        return {"error": f"{label}: rate limited (429)", "rate_limited": True}
    if status in (408, 504):
        return {"error": f"{label}: timed out ({status})"}
    if status >= 500:
        return {"error": f"{label}: provider error ({status})"}
    return {"error": f"{label}: unexpected status ({status})"}


def _cache_get(key: str):
    entry = _CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value


def _cache_set(key: str, value, ttl: int):
    try:
        _CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass


def _feed_key_tag(key: str) -> str:
    if not key:
        return ""
    return hashlib.sha256(key.strip().encode()).hexdigest()[:12]


def _get(url: str, timeout: int = 30, headers: dict = None, cap: int = 0):
    """Bounded GET for feed files. Returns (ok, bytes-or-error)."""
    try:
        with requests.get(url, timeout=timeout, stream=True,
                          headers={"User-Agent": UA, **(headers or {})}) as resp:
            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code}"
            chunks, total = [], 0
            limit = cap or 150 * 1024 * 1024
            for chunk in resp.iter_content(1024 * 256):
                if not chunk:
                    continue
                total += len(chunk)
                if total > limit:
                    return False, "oversize (>150MB), refusing"
                chunks.append(chunk)
            return True, b"".join(chunks)
    except requests.exceptions.Timeout:
        return False, "timed out"
    except Exception as e:
        return False, f"{type(e).__name__}"


def _replace_dataset(source_id: str, name: str, source_url: str,
                     indicators: list, networks: list) -> dict:
    """Validate + atomically replace one source's dataset.

    indicators: [(type, value, normalized, category, confidence,
                  first_seen, last_seen, metadata_dict)]
    networks: [(cidr, prefix_length, asn, category, metadata_dict)]
    """
    init_db()
    conn = connect()
    try:
        old_n = conn.execute(
            "SELECT COUNT(*) FROM feed_indicators WHERE source = ?",
            (source_id,)).fetchone()[0]
        old_nets = conn.execute(
            "SELECT COUNT(*) FROM feed_networks WHERE source = ?",
            (source_id,)).fetchone()[0]
        old_total = old_n + old_nets
        new_total = len(indicators) + len(networks)
        if old_total > 100 and new_total < old_total // 10:
            conn.execute(
                "UPDATE feed_sources SET last_attempt = ?, status = ?, error = ?"
                " WHERE id = ?",
                (now_iso(), "validation-failed",
                 f"collapse {old_total}->{new_total}, kept last good", source_id))
            conn.commit()
            return {"ok": False, "reason": "record-count collapse, kept last good",
                    "records": old_total}
        conn.execute("DELETE FROM feed_indicators WHERE source = ?", (source_id,))
        conn.execute("DELETE FROM feed_networks WHERE source = ?", (source_id,))
        for t, v, norm, cat, conf, first, last, meta in indicators:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO feed_indicators (source, indicator_type,"
                    " value, normalized_value, category, confidence, first_seen,"
                    " last_seen, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (source_id, t, v, norm, cat or "", conf or "", first or "",
                     last or "", json.dumps(meta or {})))
            except sqlite3.Error:
                continue
        for cidr, plen, asn, cat, meta in networks:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO feed_networks (source, cidr, prefix_length,"
                    " asn, category, metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (source_id, cidr, plen, asn or "", cat or "",
                     json.dumps(meta or {})))
            except sqlite3.Error:
                continue
        conn.execute(
            "INSERT INTO feed_sources (id, name, type, source_url, enabled,"
            " last_success, last_attempt, record_count, status, error)"
            " VALUES (?, ?, 'feed', ?, 1, ?, ?, ?, 'healthy', '')"
            " ON CONFLICT(id) DO UPDATE SET name=excluded.name,"
            " source_url=excluded.source_url, last_success=excluded.last_success,"
            " last_attempt=excluded.last_attempt, record_count=excluded.record_count,"
            " status='healthy', error=''",
            (source_id, name, source_url, now_iso(), now_iso(), new_total))
        conn.commit()
        return {"ok": True, "records": new_total}
    finally:
        conn.close()


def _mark_failed(source_id: str, name: str, error: str):
    init_db()
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO feed_sources (id, name, type, last_attempt, status, error)"
            " VALUES (?, ?, 'feed', ?, 'error', ?)"
            " ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,"
            " status='error', error=excluded.error",
            (source_id, name, now_iso(), (error or "")[:300]))
        conn.commit()
    finally:
        conn.close()


def _due(source_id: str, interval: int) -> bool:
    init_db()
    conn = connect()
    try:
        row = conn.execute("SELECT last_success FROM feed_sources WHERE id = ?",
                           (source_id,)).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return True
    try:
        last = time.mktime(time.strptime(row[0], "%Y-%m-%dT%H:%M:%S"))
        return (time.time() - last) >= interval
    except (ValueError, OverflowError):
        return True


# ---------------------------------------------------------------------------
# Emerging Threats Open (Suricata ruleset -> conservative IOC extraction)
# ---------------------------------------------------------------------------
ET_OPEN_BASE = "https://rules.emergingthreats.net/open/"
ET_TARBALL_TEMPLATE = "https://rules.emergingthreats.net/open/suricata-%s/emerging.rules.tar.gz"
ET_MAX_TARBALL_BYTES = 150 * 1024 * 1024

_RULE_HEAD_RE = re.compile(
    r"^(alert|drop|reject)\s+(\S+)\s+(\S+)\s+(\S+)\s+([^\s]+)\s+(\S+)\s*\((.*)\)\s*$",
    re.DOTALL)
_OPT_RE = re.compile(r'\b(msg|sid|rev|classtype|reference|content)\s*:\s*(?:"((?:[^"\\]|\\.)*)"|([^;]*))\s*;')
_DNS_BUF_RE = re.compile(r"dns\.query|tls\.sni")
_HTTP_HOST_RE = re.compile(r"http\.host|http\.header")
_IP_LIT_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?\b")
_DOMAIN_LIT_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")


def _et_versions():
    """Discover Suricata version dirs (never hardcode one forever)."""
    ok, body = _get(ET_OPEN_BASE, timeout=20, cap=1024 * 1024)
    versions = []
    if ok:
        for m in re.finditer(rb"suricata-([\d.]+)/", body):
            try:
                versions.append(tuple(int(x) for x in m.group(1).decode().split(".")))
            except ValueError:
                continue
    versions = sorted(set(versions), reverse=True)
    return [".".join(str(x) for x in v) for v in versions] or ["7.0.3"]


def _et_parse_rules(data: bytes):
    """Yields (category, header-dict, options-text) per rule block."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return
    try:
        import tarfile as _tf
        buf = io.BytesIO(data)
        if _tf.is_tarfile(buf):
            buf.seek(0)
            with _tf.open(fileobj=buf, mode="r|gz") as tar:
                for member in tar:
                    if not member.isfile() or not member.name.endswith(".rules"):
                        continue
                    f = tar.extractfile(member)
                    if not f:
                        continue
                    category = member.name.split("/")[-1].replace(".rules", "")
                    yield from _et_parse_text(f.read().decode("utf-8", errors="replace"), category)
            return
    except Exception:
        pass
    yield from _et_parse_text(text, "")


def _et_parse_text(text: str, category: str):
    buf = ""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        buf += (" " if buf else "") + s
        if buf.rstrip().endswith(")"):
            m = _RULE_HEAD_RE.match(buf)
            if m:
                yield category, m, buf
            buf = ""


def _et_rule_meta(options: str) -> dict:
    meta = {"msg": "", "sid": "", "rev": "", "classtype": "", "reference": ""}
    for m in _OPT_RE.finditer(options or ""):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        if key in meta and not meta[key]:
            meta[key] = val.strip()[:300]
    return meta


def _valid_ip_or_cidr(token: str):
    try:
        net = ipaddress.ip_network(token, strict=False)
        if net.is_private or net.is_loopback or net.is_multicast or net.is_reserved:
            return ""
        return str(net) if "/" in token else str(net.network_address)
    except ValueError:
        return ""


def _valid_domain(token: str):
    token = (token or "").lower().strip().strip(".")
    if not token or len(token) > 253 or ".." in token:
        return ""
    if not _DOMAIN_LIT_RE.fullmatch(token):
        return ""
    return token


def _et_extract(category: str, head, options: str):
    """Conservative IOCs: header IP literals + content domains only when the
    rule actually inspects DNS/TLS-SNI/HTTP-host buffers."""
    out = []
    meta = _et_rule_meta(options)
    base_meta = {"sid": meta["sid"], "rev": meta["rev"], "msg": meta["msg"],
                 "classtype": meta["classtype"], "reference": meta["reference"]}
    for field in (head.group(2), head.group(4)):
        for tok in str(field).split(","):
            tok = tok.strip().strip("[]")
            norm = _valid_ip_or_cidr(tok)
            if norm:
                out.append(("ip" if "/" not in tok else "cidr", tok, norm,
                            category, "", "", "", dict(base_meta)))
    wants_domain = bool(_DNS_BUF_RE.search(options) or _HTTP_HOST_RE.search(options))
    if wants_domain:
        for m in re.finditer(r'content\s*:\s*"((?:[^"\\]|\\.)*)"', options):
            for cand in re.split(r"[,\s;|]+", m.group(1)):
                norm = _valid_domain(cand.strip().strip("*").strip("."))
                if norm:
                    out.append(("domain", cand.strip(), norm, category, "",
                                "", "", dict(base_meta)))
    return out


def refresh_et_open(force: bool = False) -> dict:
    """Daily Suricata ruleset ingest (version-discovered, size-capped)."""
    source_id = "et_open"
    if not force and not _due(source_id, INTERVALS["et_open"]):
        return {"ok": True, "reason": "fresh"}
    last_err = ""
    for version in _et_versions()[:3]:
        url = ET_TARBALL_TEMPLATE % version
        ok, data = _get(url, timeout=120)
        if not ok:
            last_err = data if isinstance(data, str) else "download failed"
            continue
        indicators = []
        try:
            for category, head, options in _et_parse_rules(data):
                indicators.extend(_et_extract(category, head, options))
                if len(indicators) > 500000:
                    break
        except Exception as e:
            last_err = f"parse failed ({type(e).__name__})"
            continue
        if len(indicators) < 500:
            last_err = f"only {len(indicators)} indicators (suspicious)"
            continue
        res = _replace_dataset(source_id, "Emerging Threats Open", url,
                               indicators, [])
        if res.get("ok"):
            return {"ok": True, "records": res["records"], "version": version}
        last_err = res.get("reason", "validation failed")
    _mark_failed(source_id, "Emerging Threats Open", last_err or "all versions failed")
    return {"ok": False, "reason": last_err or "all versions failed"}


# ---------------------------------------------------------------------------
# Spamhaus DROP (free JSON datasets only)
# ---------------------------------------------------------------------------
SPAMHAUS_URLS = {
    "drop_v4": "https://www.spamhaus.org/drop/drop_v4.json",
    "drop_v6": "https://www.spamhaus.org/drop/drop_v6.json",
    "asndrop": "https://www.spamhaus.org/drop/asndrop.json",
}


def _spamhaus_ndjson(data: bytes):
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            yield obj


def refresh_spamhaus(force: bool = False) -> dict:
    """DROP v4/v6 networks + ASN-DROP (CIDR containment, never expanded)."""
    source_id = "spamhaus"
    if not force and not _due(source_id, INTERVALS["spamhaus"]):
        return {"ok": True, "reason": "fresh"}
    networks, errors = [], []
    for dataset, url in SPAMHAUS_URLS.items():
        ok, data = _get(url, timeout=60)
        if not ok:
            errors.append(f"{dataset}: {data if isinstance(data, str) else 'failed'}")
            continue
        count = 0
        for obj in _spamhaus_ndjson(data):
            if dataset == "asndrop":
                asn = str(obj.get("asn", "") or "").strip().upper()
                if not asn:
                    continue
                if not asn.startswith("AS"):
                    asn = "AS" + asn
                meta = {"dataset": dataset, "rir": str(obj.get("rir", "") or ""),
                        "domain": str(obj.get("domain", "") or ""),
                        "cc": str(obj.get("cc", "") or ""),
                        "asname": str(obj.get("asname", "") or "")}
                networks.append(("", 0, asn, dataset, meta))
                count += 1
            else:
                cidr = str(obj.get("cidr", "") or "").strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                meta = {"dataset": dataset,
                        "sblid": str(obj.get("sblid", "") or ""),
                        "rir": str(obj.get("rir", "") or "")}
                networks.append((str(net), net.prefixlen, "", dataset, meta))
                count += 1
        if not count:
            errors.append(f"{dataset}: empty")
    if not networks:
        _mark_failed(source_id, "Spamhaus DROP", "; ".join(errors) or "empty")
        return {"ok": False, "reason": "; ".join(errors) or "empty"}
    return _replace_dataset(source_id, "Spamhaus DROP",
                            "https://www.spamhaus.org/drop/", [], networks)


# ---------------------------------------------------------------------------
# CINS Army (operator-supplied feed URL + token; plain-text IP dataset)
# ---------------------------------------------------------------------------
def _cins_env():
    url = (os.environ.get("MANTIS_CINS_FEED_URL", "") or
           os.environ.get("IOCINTEL_CINS_FEED_URL", "")).strip()
    token = (os.environ.get("MANTIS_CINS_TOKEN", "") or
             os.environ.get("IOCINTEL_CINS_TOKEN", "")).strip()
    return url, token


def refresh_cins(url: str = "", token: str = "", force: bool = False) -> dict:
    """Registered CINS feed (text/IP dataset preferred)."""
    source_id = "cins"
    if not url:
        url, token = _cins_env()
    if not url:
        return {"ok": False, "reason": "not configured (feed URL required)"}
    if not force and not _due(source_id, INTERVALS["cins"]):
        return {"ok": True, "reason": "fresh"}
    headers = {}
    if (token or "").strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    ok, data = _get(url, timeout=60, headers=headers)
    if not ok:
        _mark_failed(source_id, "CINS Army",
                     data if isinstance(data, str) else "failed")
        return {"ok": False, "reason": data if isinstance(data, str) else "failed"}
    text = data.decode("utf-8", errors="replace")
    indicators = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        token_ip = re.split(r"[\s,;|]+", line)[0].strip("[]")
        try:
            addr = ipaddress.ip_address(token_ip)
            if addr.is_private or addr.is_loopback or addr.is_multicast:
                continue
            indicators.append(("ip", token_ip, str(addr), "CINS Army", "",
                               "", "", {}))
        except ValueError:
            continue
        if len(indicators) > 500000:
            break
    if len(indicators) < 10:
        _mark_failed(source_id, "CINS Army",
                     f"only {len(indicators)} IPs parsed")
        return {"ok": False, "reason": "unusable feed content"}
    return _replace_dataset(source_id, "CINS Army", url, indicators, [])


# ---------------------------------------------------------------------------
# blocklist.de (bulk lists + read-only live lookup; never reporting)
# ---------------------------------------------------------------------------
BLOCKLIST_BASE = "https://lists.blocklist.de/"
BLOCKLIST_PREFERRED = ["all.txt", "ssh.txt", "mail.txt", "apache.txt",
                       "imap.txt", "ftp.txt", "sip.txt", "bots.txt"]
BLOCKLIST_PORT_SERVICE = {"21": "ftp", "22": "ssh", "25": "mail", "80": "http",
                          "143": "imap", "443": "https", "993": "imaps"}


def _blocklist_index():
    ok, body = _get(BLOCKLIST_BASE, timeout=20, cap=1024 * 1024)
    if not ok:
        return []
    names = re.findall(rb'href="([A-Za-z0-9._-]+\.txt)"', body)
    return sorted({n.decode() for n in names})


def refresh_blocklist(force: bool = False) -> dict:
    """Bulk lists for offline matching (service label = filename/port)."""
    source_id = "blocklist"
    if not force and not _due(source_id, INTERVALS["blocklist"]):
        return {"ok": True, "reason": "fresh"}
    available = _blocklist_index()
    wanted = [f for f in BLOCKLIST_PREFERRED if f in available]
    for num, svc in BLOCKLIST_PORT_SERVICE.items():
        f = f"{num}.txt"
        if f in available and f not in wanted:
            wanted.append(f)
    if not wanted:
        _mark_failed(source_id, "blocklist.de", "no usable lists indexed")
        return {"ok": False, "reason": "no usable lists indexed"}
    indicators = []
    for fname in wanted[:12]:
        stem = fname[:-4]
        service = BLOCKLIST_PORT_SERVICE.get(stem, stem)
        ok, data = _get(BLOCKLIST_BASE + fname, timeout=60)
        if not ok:
            continue
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            token_ip = re.split(r"[\s,;|]+", line)[0].strip("[]")
            try:
                addr = ipaddress.ip_address(token_ip)
                if addr.is_private or addr.is_loopback or addr.is_multicast:
                    continue
                indicators.append(("ip", token_ip, str(addr), service, "",
                                   "", "", {"list": fname}))
            except ValueError:
                continue
            if len(indicators) > 500000:
                break
        if len(indicators) > 500000:
            break
    if len(indicators) < 10:
        _mark_failed(source_id, "blocklist.de", "no IPs parsed")
        return {"ok": False, "reason": "no IPs parsed"}
    return _replace_dataset(source_id, "blocklist.de", BLOCKLIST_BASE,
                            indicators, [])


def query_blocklist_api(ip: str) -> Dict[str, Any]:
    """Read-only live lookup (no reporting parameters ever sent)."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for blocklist.de lookup"}
    cache_key = f"bl:api:{ip}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        resp = requests.get("https://api.blocklist.de/api.php",
                            params={"ip": ip}, timeout=20,
                            headers={"User-Agent": UA, "Accept": "text/plain"})
    except requests.exceptions.Timeout:
        out = {"error": "blocklist.de: timed out"}
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    except Exception as e:
        out = {"error": f"blocklist.de: request failed ({type(e).__name__})"}
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    if resp.status_code != 200:
        out = _http_error("blocklist.de", resp.status_code)
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    attacks, reports = "", ""
    for line in resp.text.splitlines():
        low = line.strip().lower()
        if low.startswith("attacks:"):
            attacks = line.split(":", 1)[1].strip()
        elif low.startswith("reports:"):
            reports = line.split(":", 1)[1].strip()
    out = {"source": "blocklist.de", "ip": ip, "listed": attacks not in ("", "0"),
           "service": "", "attacks": attacks, "reports": reports,
           "first_seen": "", "last_seen": ""}
    _cache_set(cache_key, out, _CACHE_TTL["hit"])
    return out


# ---------------------------------------------------------------------------
# Project Honey Pot http:BL (DNS query to the reputation provider only)
# ---------------------------------------------------------------------------
PHPBL_TYPES = {0: "Search Engine", 1: "Suspicious", 2: "Harvester",
               3: "Suspicious + Harvester", 4: "Comment Spammer",
               5: "Suspicious + Comment Spammer", 6: "Harvester + Comment Spammer",
               7: "Suspicious + Harvester + Comment Spammer"}


def query_phphbl(ip: str, api_key: str) -> Dict[str, Any]:
    """DNSBL lookup against dnsbl.httpbl.org (never the investigated IP)."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for Project Honey Pot lookup"}
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return {"source": "Project Honey Pot", "ip": ip, "listed": False,
                    "note": "http:BL supports IPv4 only"}
    except ValueError:
        return {"error": "Project Honey Pot: invalid IPv4 address"}
    if not (api_key or "").strip():
        return {"error": "Project Honey Pot: access key required (Settings)",
                "not_configured": True}
    cache_key = f"phbl:{ip}:{_feed_key_tag(api_key)}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    import socket
    reversed_ip = ".".join(reversed(ip.split(".")))
    qname = f"{api_key.strip()}.{reversed_ip}.dnsbl.httpbl.org"
    try:
        answer = socket.gethostbyname(qname)
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        out = {"source": "Project Honey Pot", "ip": ip, "listed": False,
               "note": "No http:BL record"}
        _cache_set(cache_key, out, _CACHE_TTL["hit"])
        return out
    except Exception as e:
        out = {"error": f"Project Honey Pot: DNS failed ({type(e).__name__})"}
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    parts = answer.strip().split(".")
    if len(parts) != 4 or parts[0] != "127":
        out = {"source": "Project Honey Pot", "ip": ip, "listed": False,
               "note": "No http:BL record"}
        _cache_set(cache_key, out, _CACHE_TTL["hit"])
        return out
    try:
        days, score, typ = int(parts[1]), int(parts[2]), int(parts[3])
    except ValueError:
        out = {"source": "Project Honey Pot", "ip": ip, "listed": False,
               "note": "No http:BL record"}
        _cache_set(cache_key, out, _CACHE_TTL["hit"])
        return out
    out = {"source": "Project Honey Pot", "ip": ip, "listed": True,
           "days_since_last_activity": days, "threat_score": score,
           "visitor_type": PHPBL_TYPES.get(typ & 7, f"type {typ & 7}"),
           "visitor_type_code": typ & 7}
    _cache_set(cache_key, out, _CACHE_TTL["hit"])
    return out


# ---------------------------------------------------------------------------
# Tor exit nodes (official torbulkexitlist, plain IPs)
# ---------------------------------------------------------------------------
TOR_URL = "https://check.torproject.org/torbulkexitlist"


def refresh_tor(force: bool = False) -> dict:
    """Tor exit relays (official list). Exit != malicious, always."""
    source_id = "tor"
    if not force and not _due(source_id, INTERVALS["tor"]):
        return {"ok": True, "reason": "fresh"}
    ok, data = _get(TOR_URL, timeout=60)
    if not ok:
        _mark_failed(source_id, "Tor Exit Nodes",
                     data if isinstance(data, str) else "failed")
        return {"ok": False, "reason": data if isinstance(data, str) else "failed"}
    indicators = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            addr = ipaddress.ip_address(line.split()[0])
            indicators.append(("ip", str(addr), str(addr), "tor_exit", "",
                               "", "", {}))
        except ValueError:
            continue
        if len(indicators) > 500000:
            break
    if len(indicators) < 100:
        _mark_failed(source_id, "Tor Exit Nodes",
                     f"only {len(indicators)} nodes (suspicious)")
        return {"ok": False, "reason": "suspiciously small list"}
    return _replace_dataset(source_id, "Tor Exit Nodes", TOR_URL, indicators, [])


# ---------------------------------------------------------------------------
# DroneBL RPC2 (lookup ONLY — add/remove/update never implemented)
# ---------------------------------------------------------------------------
DRONEBL_RPC_URL = "https://dronebl.org/rpc2"


def query_dronebl(ip: str, api_key: str) -> Dict[str, Any]:
    """Read-only RPC2 lookup. No mutation method exists in this codebase."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for DroneBL lookup"}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "DroneBL: invalid IP address"}
    if not (api_key or "").strip():
        return {"error": "DroneBL: RPC key required (Settings)",
                "not_configured": True}
    cache_key = f"dronebl:{ip}:{_feed_key_tag(api_key)}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    import xml.etree.ElementTree as _ET
    body = (f"<?xml version=\"1.0\"?><request key=\"{api_key.strip()}\">"
            f"<lookup ip=\"{ip}\" listed=\"1\" /></request>")
    try:
        resp = requests.post(DRONEBL_RPC_URL, data=body.encode(),
                             headers={"Content-Type": "text/xml",
                                      "User-Agent": UA}, timeout=20)
    except requests.exceptions.Timeout:
        out = {"error": "DroneBL: timed out"}
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    except Exception as e:
        out = {"error": f"DroneBL: request failed ({type(e).__name__})"}
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    if resp.status_code != 200:
        out = _http_error("DroneBL", resp.status_code)
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    try:
        root = _ET.fromstring(resp.content)
    except Exception:
        out = {"error": "DroneBL: malformed response"}
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    if root.tag == "response" and root.get("type") == "error":
        code = root.findtext("code") or ""
        msg = root.findtext("message") or ""
        out = {"error": f"DroneBL: {msg or code or 'lookup failed'}"[:300]}
        _cache_set(cache_key, out, _CACHE_TTL["miss"])
        return out
    results = []
    for res in root.iter("result"):
        results.append({
            "ip": res.get("ip", "") or ip,
            "port": res.get("port", "") or "",
            "type": res.get("type", "") or "",
            "listed": res.get("listed", "") or "",
            "timestamp": res.get("timestamp", "") or ""})
        if len(results) >= 50:
            break
    out = {"source": "DroneBL", "ip": ip, "listed": bool(results),
           "results": results}
    _cache_set(cache_key, out, _CACHE_TTL["hit"])
    return out


# ---------------------------------------------------------------------------
# StevenBlack hosts (base adware+malware aggregate only)
# ---------------------------------------------------------------------------
STEVENBLACK_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


def refresh_stevenblack(force: bool = False) -> dict:
    """Base unified hosts file (adware + malware aggregate)."""
    source_id = "stevenblack"
    if not force and not _due(source_id, INTERVALS["stevenblack"]):
        return {"ok": True, "reason": "fresh"}
    ok, data = _get(STEVENBLACK_URL, timeout=120)
    if not ok:
        _mark_failed(source_id, "StevenBlack Hosts",
                     data if isinstance(data, str) else "failed")
        return {"ok": False, "reason": data if isinstance(data, str) else "failed"}
    indicators = []
    seen = set()
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        host = parts[1].lower().rstrip(".")
        if host in ("localhost", "localhost.localdomain", "local"):
            continue
        if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", host):
            continue
        if host not in seen:
            seen.add(host)
            indicators.append(("domain", host, host, "adware/malware aggregate",
                               "", "", "", {}))
        if len(indicators) > 1000000:
            break
    if len(indicators) < 1000:
        _mark_failed(source_id, "StevenBlack Hosts",
                     f"only {len(indicators)} domains (suspicious)")
        return {"ok": False, "reason": "suspiciously small list"}
    return _replace_dataset(source_id, "StevenBlack Hosts", STEVENBLACK_URL,
                            indicators, [])


# ---------------------------------------------------------------------------
# Local matching (exact + CIDR containment, never expanded)
# ---------------------------------------------------------------------------
def _rows_match_ip(conn, ip: str):
    """(exact_rows, network_rows) for an IP across all feed sources."""
    exact = [dict(r) for r in conn.execute(
        "SELECT * FROM feed_indicators WHERE indicator_type = 'ip' AND normalized_value = ?",
        (ip,)).fetchall()]
    nets = []
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return exact, nets
    for r in conn.execute("SELECT * FROM feed_networks"):
        cidr = r["cidr"] or ""
        if not cidr:
            continue
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                nets.append(dict(r))
        except ValueError:
            continue
    return exact, nets


def match_ip(ip: str, conn=None) -> Dict[str, Any]:
    """Local feed matches for an IP (exact + CIDR containment)."""
    ip = (ip or "").strip()
    if not ip:
        return {"matches": []}
    try:
        norm = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"matches": []}
    own = conn is None
    if own:
        init_db()
        conn = connect()
    try:
        exact, nets = _rows_match_ip(conn, norm)
        matches = []
        for r in exact:
            matches.append({
                "source": r["source"], "match": True,
                "indicator_type": r["indicator_type"], "value": r["value"],
                "category": r.get("category", "") or "",
                "confidence": r.get("confidence", "") or "",
                "first_seen": r.get("first_seen", "") or "",
                "last_seen": r.get("last_seen", "") or "",
                "metadata": json.loads(r.get("metadata_json") or "{}")})
        for r in nets:
            matches.append({
                "source": r["source"], "match": True,
                "indicator_type": "network",
                "value": norm, "network": r["cidr"], "asn": r.get("asn", "") or "",
                "category": r.get("category", "") or "",
                "metadata": json.loads(r.get("metadata_json") or "{}")})
        return {"matches": matches}
    finally:
        if own:
            conn.close()


def match_domain(domain: str, conn=None) -> Dict[str, Any]:
    """Local feed matches for a domain (exact, lowercase)."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"matches": []}
    own = conn is None
    if own:
        init_db()
        conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM feed_indicators WHERE indicator_type = 'domain'"
            " AND normalized_value = ?", (domain,)).fetchall()
        return {"matches": [{
            "source": r["source"], "match": True,
            "indicator_type": "domain", "value": r["value"],
            "category": r.get("category", "") or "",
            "confidence": r.get("confidence", "") or "",
            "first_seen": r.get("first_seen", "") or "",
            "last_seen": r.get("last_seen", "") or "",
            "metadata": json.loads(r.get("metadata_json") or "{}")} for r in rows]}
    finally:
        if own:
            conn.close()


def match_asn(asn: str, conn=None) -> Dict[str, Any]:
    """Local feed matches for an ASN (Spamhaus ASN-DROP)."""
    asn = (asn or "").strip().upper()
    if asn and not asn.startswith("AS"):
        asn = "AS" + asn
    if not asn:
        return {"matches": []}
    own = conn is None
    if own:
        init_db()
        conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM feed_networks WHERE asn = ?", (asn,)).fetchall()
        return {"matches": [{
            "source": r["source"], "match": True, "indicator_type": "asn",
            "value": asn, "category": r.get("category", "") or "",
            "metadata": json.loads(r.get("metadata_json") or "{}")} for r in rows]}
    finally:
        if own:
            conn.close()


def feed_status(conn=None) -> Dict[str, Any]:
    """Compact per-source health for Settings (no new page)."""
    own = conn is None
    if own:
        init_db()
        conn = connect()
    try:
        out = []
        for r in conn.execute("SELECT * FROM feed_sources ORDER BY name").fetchall():
            d = dict(r)
            out.append({
                "id": d["id"], "name": d.get("name", "") or d["id"],
                "status": d.get("status", "") or "never-synced",
                "last_success": d.get("last_success", "") or "",
                "record_count": d.get("record_count", 0) or 0,
                "error": d.get("error", "") or ""})
        return {"sources": out}
    finally:
        if own:
            conn.close()



def refresh_destroylist(force: bool = False) -> dict:
    source_id = "destroylist"
    if not force and not _due(source_id, 3600):
        return {"ok": True, "reason": "fresh"}
    ok, data = _get("https://api.destroy.tools/v1/feed/primary")
    if not ok:
        _mark_failed(source_id, "Destroylist", str(data))
        return {"ok": False, "reason": str(data)}
    indicators = []
    lines = data.decode("utf-8", "ignore").splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"): continue
        if _valid_domain(line):
            indicators.append(("domain", line, line.lower(), "phishing", "high", "", "", {}))
    return _replace_dataset(source_id, "Destroylist", "https://api.destroy.tools", indicators, [])

def refresh_c2intel(force: bool = False) -> dict:
    source_id = "c2intel"
    if not force and not _due(source_id, 3600 * 12):
        return {"ok": True, "reason": "fresh"}
    ok1, data1 = _get("https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv")
    ok2, data2 = _get("https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day.csv")
    if not ok1 or not ok2:
        _mark_failed(source_id, "C2IntelFeeds", "Failed to fetch C2 feeds")
        return {"ok": False, "reason": "fetch failed"}
    
    indicators = []
    for line in data1.decode("utf-8", "ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line == "ip": continue
        if _valid_ip_or_cidr(line):
            indicators.append(("ip", line, line, "c2", "high", "", "", {}))
            
    for line in data2.decode("utf-8", "ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line == "domain": continue
        if _valid_domain(line):
            indicators.append(("domain", line, line.lower(), "c2", "high", "", "", {}))
            
    return _replace_dataset(source_id, "C2IntelFeeds", "https://github.com/drb-ra/C2IntelFeeds", indicators, [])

def refresh_generic_feed(source_id: str, name: str, url: str, itype: str, category: str, force: bool = False) -> dict:
    if not force and not _due(source_id, 3600 * 12):
        return {"ok": True, "reason": "fresh"}
    ok, data = _get(url)
    if not ok:
        _mark_failed(source_id, name, str(data))
        return {"ok": False, "reason": str(data)}
    indicators = []
    for line in data.decode("utf-8", "ignore").splitlines():
        # extremely naive CSV/TXT parsing: take first valid column
        parts = line.strip().split(',')
        if not parts: continue
        val = parts[0].strip(' "')
        if not val or val.startswith('#'): continue
        if itype == 'ip' and _valid_ip_or_cidr(val):
            indicators.append(("ip", val, val, category, "medium", "", "", {}))
        elif itype == 'domain' and _valid_domain(val):
            indicators.append(("domain", val, val.lower(), category, "medium", "", "", {}))
        elif itype in ('md5', 'sha1', 'sha256'):
            indicators.append(("hash", val, val.lower(), category, "medium", "", "", {}))
        elif itype == 'url' and val.startswith("http"):
            indicators.append(("url", val, val.lower(), category, "medium", "", "", {}))
    return _replace_dataset(source_id, name, url, indicators, [])

def refresh_due(force: bool = False) -> dict:
    """Refresh every stale feed (background scheduler entry point)."""
    results = {}
    cins_url, cins_token = _cins_env()
    
    # 1. Hardcoded / specialized feeds
    jobs = [
        ("et_open", lambda: refresh_et_open(force=force)),
        ("spamhaus", lambda: refresh_spamhaus(force=force)),
        ("cins", lambda: refresh_cins(cins_url, cins_token, force=force)),
        ("blocklist", lambda: refresh_blocklist(force=force)),
        ("tor", lambda: refresh_tor(force=force)),
        ("stevenblack", lambda: refresh_stevenblack(force=force)),
        ("destroylist", lambda: refresh_destroylist(force=force)),
        ("c2intel", lambda: refresh_c2intel(force=force)),
    ]
    for name, fn in jobs:
        # Check if enabled in DB
        conn = connect()
        row = conn.execute("SELECT enabled FROM feed_sources WHERE id = ?", (name,)).fetchone()
        conn.close()
        # Default to enabled if not in DB, but if it is in DB and enabled=0, skip it
        if row and row['enabled'] == 0:
            results[name] = {"ok": True, "reason": "disabled"}
            continue
        try:
            results[name] = fn()
        except Exception as e:
            results[name] = {"ok": False, "reason": f"{type(e).__name__}"}
            
    # 2. Dynamic feeds from DB
    conn = connect()
    dynamic_feeds = conn.execute("SELECT * FROM feed_sources WHERE is_dynamic = 1 AND enabled = 1").fetchall()
    conn.close()
    
    for df in dynamic_feeds:
        name = df['id']
        try:
            results[name] = refresh_generic_feed(
                source_id=name,
                name=df['name'],
                url=df['source_url'],
                itype=df['indicator_type'],
                category=df['category_override'],
                force=force
            )
        except Exception as e:
            results[name] = {"ok": False, "reason": f"{type(e).__name__}"}
            
    return results
