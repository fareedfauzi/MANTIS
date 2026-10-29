from __future__ import annotations



import hashlib

import ipaddress

import json

import os

import re

import sqlite3

import threading

import base64

import urllib.parse

from collections import defaultdict

from concurrent.futures import ThreadPoolExecutor, as_completed

from contextlib import contextmanager

from datetime import datetime, timedelta, timezone

from pathlib import Path

from typing import Any, Dict, Iterable, List, Tuple





DATA_DIR = Path(__file__).resolve().parent / "data"

DB_PATH = DATA_DIR / "infra_hunts.db"

_DB_LOCK = threading.RLock()



IP_RE = re.compile(r"(?<![\w:])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w:])")

DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")

HASH_PATTERNS = {

    "certificate_sha256": re.compile(r"(?i)^[a-f0-9]{64}$"),

    "jarm": re.compile(r"(?i)^[a-f0-9]{62}$"),

    "ja4x": re.compile(r"(?i)^[a-z0-9]{12}_[a-z0-9]{12}_[a-z0-9]{12}$"),

}



SHARED_INFRA_MARKERS = {

    "cloudflare", "akamai", "fastly", "amazon cloudfront", "google cloud cdn",

    "azure front door", "github pages", "vercel", "netlify", "public resolver",

}



SIGNAL_WEIGHTS = {

    "certificate_sha256": 35,

    "ja4x": 25,

    "http_body_hash": 18,

    "http_headers_hash": 18,

    "favicon_hash": 12,

    "certificate_subject": 12,

    "certificate_issuer": 10,

    "jarm": 7,

    "ja3s": 7,

    "ja4": 9,

    "http_title": 7,

    "http_server": 5,

    "banner": 8,

    "port": 2,

    "asn": 2,

    "registrar": 4,

    "nameserver": 5,

    "tld": 2,

}



EXPANSION_PROVIDERS = {

    "shodan": {"label": "Shodan", "role": "search", "key_required": True},

    "censys": {"label": "Censys", "role": "search", "key_required": True},

    "fofa": {"label": "FOFA", "role": "search", "key_required": True},

    "netlas": {"label": "Netlas", "role": "search", "key_required": True},

    "silentpush": {"label": "Silent Push", "role": "search", "key_required": True},

    "driftnet": {"label": "Driftnet", "role": "search", "key_required": True},

    "validin": {"label": "Validin", "role": "pivot", "key_required": True},

    "etugen": {"label": "Etugen (OpenDir)", "role": "open_dir", "key_required": True, "description": "Exposed open directories & leaked files (Trashpile)"},

    "zoomeye": {"label": "ZoomEye", "role": "search", "key_required": True, "description": "Global cyberspace search engine by Knownsec"},

    "greynoise": {"label": "GreyNoise", "role": "validate", "key_required": False},

}



DEFAULT_EXPANSION_PROVIDERS = list(EXPANSION_PROVIDERS)

DEFAULT_SEED_SOURCES = [

    "virustotal", "silentpush", "driftnet", "shodan", "censys", "fofa", "zoomeye", "validin", "etugen",

    "urlscan", "greynoise", "ripe", "crtsh", "netlas",

]



BUILTIN_SIGNATURES = [

    {

        "slug": "asyncrat-default-tls",

        "name": "AsyncRAT default TLS",

        "family": "AsyncRAT",

        "description": "Default AsyncRAT certificate naming observed across public deployments.",

        "signals": {"certificate_subject": ["AsyncRAT Server"]},

        "minimum_matches": 1,

        "false_positive_notes": "Validate with ports, TLS structure, and independent threat telemetry.",

    },

    {

        "slug": "cobalt-strike-default-cert",

        "name": "Cobalt Strike default certificate",

        "family": "Cobalt Strike",

        "description": "Default certificate metadata associated with unmodified Cobalt Strike profiles.",

        "signals": {"certificate_subject": ["Major Cobalt Strike"], "certificate_issuer": ["Major Cobalt Strike"]},

        "minimum_matches": 1,

        "false_positive_notes": "Default strings are high-signal but can be copied or used by researchers.",

    },

    {

        "slug": "havoc-default-banner",

        "name": "Havoc default service banner",

        "family": "Havoc",

        "description": "Default X-Havoc service marker.",

        "signals": {"banner": ["X-Havoc"]},

        "minimum_matches": 1,

        "false_positive_notes": "Confirm the service profile and exclude scanners or honeypots.",

    },

    {

        "slug": "mythic-default-title",

        "name": "Mythic default web title",

        "family": "Mythic",

        "description": "Default Mythic web interface title.",

        "signals": {"http_title": ["Mythic"]},

        "minimum_matches": 1,

        "false_positive_notes": "A title alone is mutable; require a second signal for blocking decisions.",

    },

    {

        "slug": "purehvnc-http-profile",

        "name": "PureHVNC/PureLogs HTTP profile",

        "family": "PureHVNC",

        "description": "Research-derived HTTP body and header hash combination.",

        "signals": {"http_body_hash": ["1929577144"], "http_headers_hash": ["707481832"]},

        "minimum_matches": 2,

        "false_positive_notes": "Historical profile; validate freshness and malware relations.",

    },

]





def _utcnow() -> str:

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()





def _json(value: Any) -> str:

    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)





def _loads(value: Any, default: Any) -> Any:

    if not value:

        return default

    try:

        return json.loads(value)

    except (TypeError, ValueError):

        return default





@contextmanager

def _connect():

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=20)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("PRAGMA foreign_keys=ON")

    try:

        yield conn

        conn.commit()

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()





def init_db() -> None:

    with _DB_LOCK, _connect() as conn:

        conn.executescript(

            """

            CREATE TABLE IF NOT EXISTS infra_hunts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name TEXT NOT NULL,

                seed TEXT NOT NULL,

                description TEXT NOT NULL DEFAULT '',

                enabled INTEGER NOT NULL DEFAULT 1,

                interval_minutes INTEGER NOT NULL DEFAULT 1440,

                providers_json TEXT NOT NULL DEFAULT '[]',

                source_ids_json TEXT NOT NULL DEFAULT '[]',

                created_at TEXT NOT NULL,

                updated_at TEXT NOT NULL,

                last_run_at TEXT NOT NULL DEFAULT '',

                next_run_at TEXT NOT NULL DEFAULT '',

                last_status TEXT NOT NULL DEFAULT 'never',

                last_error TEXT NOT NULL DEFAULT ''

            );

            CREATE TABLE IF NOT EXISTS infra_hunt_runs (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                hunt_id INTEGER,

                seed TEXT NOT NULL,

                status TEXT NOT NULL,

                started_at TEXT NOT NULL,

                finished_at TEXT NOT NULL DEFAULT '',

                summary_json TEXT NOT NULL DEFAULT '{}',

                result_json TEXT NOT NULL DEFAULT '{}',

                error TEXT NOT NULL DEFAULT '',

                FOREIGN KEY(hunt_id) REFERENCES infra_hunts(id) ON DELETE CASCADE

            );

            CREATE TABLE IF NOT EXISTS infra_hunt_candidates (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                run_id INTEGER NOT NULL,

                value TEXT NOT NULL,

                value_type TEXT NOT NULL,

                score INTEGER NOT NULL,

                confidence TEXT NOT NULL,

                providers_json TEXT NOT NULL,

                evidence_json TEXT NOT NULL,

                first_seen TEXT NOT NULL DEFAULT '',

                last_seen TEXT NOT NULL DEFAULT '',

                raw_json TEXT NOT NULL DEFAULT '{}',

                UNIQUE(run_id, value),

                FOREIGN KEY(run_id) REFERENCES infra_hunt_runs(id) ON DELETE CASCADE

            );

            CREATE TABLE IF NOT EXISTS infra_signature_packs (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                slug TEXT NOT NULL UNIQUE,

                name TEXT NOT NULL,

                family TEXT NOT NULL DEFAULT '',

                description TEXT NOT NULL DEFAULT '',

                signals_json TEXT NOT NULL DEFAULT '{}',

                minimum_matches INTEGER NOT NULL DEFAULT 2,

                false_positive_notes TEXT NOT NULL DEFAULT '',

                enabled INTEGER NOT NULL DEFAULT 1,

                builtin INTEGER NOT NULL DEFAULT 0,

                updated_at TEXT NOT NULL

            );

            CREATE INDEX IF NOT EXISTS idx_infra_hunt_runs_hunt ON infra_hunt_runs(hunt_id, id DESC);

            CREATE INDEX IF NOT EXISTS idx_infra_candidates_run_score ON infra_hunt_candidates(run_id, score DESC);

            """

        )

        for item in BUILTIN_SIGNATURES:

            conn.execute(

                """INSERT INTO infra_signature_packs

                   (slug, name, family, description, signals_json, minimum_matches,

                    false_positive_notes, enabled, builtin, updated_at)

                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?)

                   ON CONFLICT(slug) DO UPDATE SET

                     name=excluded.name, family=excluded.family,

                     description=excluded.description, signals_json=excluded.signals_json,

                     minimum_matches=excluded.minimum_matches,

                     false_positive_notes=excluded.false_positive_notes,

                     builtin=1, updated_at=excluded.updated_at""",

                (

                    item["slug"], item["name"], item["family"], item["description"],

                    _json(item["signals"]), item["minimum_matches"],

                    item["false_positive_notes"], _utcnow(),

                ),

            )





def _walk(value: Any, path: str = "") -> Iterable[Tuple[str, Any]]:

    if isinstance(value, dict):

        for key, child in value.items():

            child_path = f"{path}.{key}" if path else str(key)

            yield from _walk(child, child_path)

    elif isinstance(value, list):

        for index, child in enumerate(value):

            yield from _walk(child, f"{path}[{index}]")

    elif value not in (None, ""):

        yield path.lower(), value





def _add(feature_map: Dict[str, List[Dict[str, Any]]], kind: str, value: Any, path: str, provider: str = "") -> None:

    text = str(value).strip()

    if not text or len(text) > 1000:

        return

    lowered = text.lower()

    if lowered in {"true", "false", "none", "unknown", "n/a"}:

        return

    row = {"value": text, "path": path}

    if provider:

        row["provider"] = provider

    if not any(existing["value"].lower() == lowered for existing in feature_map[kind]):

        feature_map[kind].append(row)





def extract_features(payload: Any) -> Dict[str, Any]:

    features: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for path, value in _walk(payload):

        text = str(value).strip()

        key = path.rsplit(".", 1)[-1]

        provider = path.split(".", 1)[0] if "." in path else ""

        low_path = path.lower()



        if key in {"ip", "ip_str", "ip_address", "address"}:

            try:

                _add(features, "ip", str(ipaddress.ip_address(text)), path, provider)

            except ValueError:

                pass

        if (key in {"domain", "hostname", "host", "name", "dns_name", "fqdn"} or "subject_alternative_name" in low_path or "san" in low_path) and DOMAIN_RE.fullmatch(text):

            _add(features, "domain", text.lower().rstrip("."), path, provider)

        if "port" in key and text.isdigit() and 0 < int(text) <= 65535:

            _add(features, "port", text, path, provider)

        elif "port_info." in low_path:

            m_port = re.search(r"port_info\.(\d+)", low_path)

            if m_port and 0 < int(m_port.group(1)) <= 65535:

                _add(features, "port", m_port.group(1), path, provider)

        if key in {"asn", "as_number"} or low_path.endswith("autonomous_system.asn"):

            match = re.search(r"(?i)(?:AS)?(\d{1,10})", text)

            if match:

                _add(features, "asn", f"AS{match.group(1)}", path, provider)

        if "jarm" in key and HASH_PATTERNS["jarm"].fullmatch(text.replace(":", "")):

            _add(features, "jarm", text.lower(), path, provider)

        if "ja4x" in key and HASH_PATTERNS["ja4x"].fullmatch(text):

            _add(features, "ja4x", text.lower(), path, provider)

        elif "ja4t" in key:

            _add(features, "ja4t", text, path, provider)

        elif "ja4" in key:

            _add(features, "ja4", text, path, provider)

        if "ja3s" in key:

            _add(features, "ja3s", text, path, provider)

        if any(marker in low_path for marker in ("fingerprint_sha256", "fingerprint.sha256", "certificate.sha256", "cert_sha256", "certificates.leaf_fp_sha_256", "thumbprint_sha256", "thumbprint")):

            cleaned = text.replace(":", "").lower()

            if HASH_PATTERNS["certificate_sha256"].fullmatch(cleaned):

                _add(features, "certificate_sha256", cleaned, path, provider)

        if any(marker in low_path for marker in ("subject_dn", "subject.common_name", "ssl_subject", "certificate_subject", "cert.subject", "subject.cn", "subject.o")):

            _add(features, "certificate_subject", text, path, provider)

        if any(marker in low_path for marker in ("issuer_dn", "issuer.common_name", "ssl_issuer", "certificate_issuer", "cert.issuer", "issuer.cn", "issuer.o")):

            _add(features, "certificate_issuer", text, path, provider)

        if any(marker in key for marker in ("favicon", "icon_hash", "favicon_hash", "murmur3")) or "favicon" in low_path:

            _add(features, "favicon_hash", text, path, provider)

        if "scanning_technologies" in low_path and key in {"product", "vendor"}:

            _add(features, "http_server", text, path, provider)

        if key in {"html_hash", "body_hash", "body_sha256", "http_body_hash", "content_sha1"}:

            _add(features, "http_body_hash", text, path, provider)

        if key in {"headers_hash", "header_hash", "http_headers_hash"}:

            _add(features, "http_headers_hash", text, path, provider)

        if key in {"title", "html_title", "http_title"} or low_path.endswith("http.title"):

            _add(features, "http_title", text, path, provider)

        if key in {"server", "http_server"} or low_path.endswith("http.server"):

            _add(features, "http_server", text, path, provider)

        if key in {"banner", "data", "service_banner"}:

            m_srv = re.search(r"(?i)Server:\s*([^\r\n]+)", text)

            if m_srv:

                _add(features, "http_server", m_srv.group(1).strip()[:100], path, provider)

            elif len(text) <= 90 and not text.startswith(("{", "<", "[")):

                _add(features, "banner", text, path, provider)

        if "registrar" in key:

            _add(features, "registrar", text, path, provider)

        if key in {"nameserver", "nameservers", "name_server", "name_servers"}:

            for domain in DOMAIN_RE.findall(text):

                _add(features, "nameserver", domain.lower(), path, provider)



    for row in list(features.get("domain", [])):

        suffix = row["value"].rsplit(".", 1)[-1]

        if suffix and len(suffix) <= 8 and suffix.isalpha():

            _add(features, "tld", suffix, row["path"], row.get("provider", ""))



    ranked = sorted(

        (

            {

                "kind": kind,

                "value": row["value"],

                "path": row.get("path", ""),

                "provider": row.get("provider", ""),

                "weight": SIGNAL_WEIGHTS.get(kind, 1),

            }

            for kind, rows in features.items()

            for row in rows

        ),

        key=lambda item: (-item["weight"], item["kind"], item["value"]),

    )

    categories = {

        "certificates": [item for item in ranked if item["kind"].startswith("certificate_")],

        "web": [item for item in ranked if any(item["kind"].startswith(p) for p in ("jarm", "ja4", "ja3", "http_", "favicon", "banner"))],

        "network": [item for item in ranked if item["kind"] in {"asn", "port", "nameserver", "registrar", "tld"}],

        "hosts": [item for item in ranked if item["kind"] in {"domain", "ip"}],

    }

    return {"by_type": dict(features), "ranked": ranked, "count": len(ranked), "categories": categories}







def _engine_search_url(provider: str, query: str) -> str:
    provider = (provider or "").lower().strip()
    query = (query or "").strip()
    if not query:
        return ""

    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
    is_pure_ip = bool(re.match(r'^(?:net:)?(?:ip:)?\s*"?((?:\d{1,3}\.){3}\d{1,3})"?$', query))
    is_pure_domain = bool(re.match(r'^(?:domain:)?\s*"?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"?$', query)) and not is_pure_ip
    raw_ip = ip_match.group(0) if ip_match else ""

    if provider == "shodan":
        if is_pure_ip and raw_ip:
            return f"https://www.shodan.io/host/{raw_ip}"
        clean_q = re.sub(r'\bip:"?([0-9.]+)"?', r'net:\1', query)
        clean_q = re.sub(r'\basn:"?(?:AS)?(\d+)"?', r'asn:AS\1', clean_q)
        return f"https://www.shodan.io/search?query={urllib.parse.quote(clean_q)}"

    if provider == "censys":
        if is_pure_ip and raw_ip:
            return f"https://search.censys.io/hosts/{raw_ip}"
        clean_q = re.sub(r'\bip\s*:\s*"([0-9.]+)"', r'ip: \1', query)
        return f"https://search.censys.io/search?resource=hosts&q={urllib.parse.quote(clean_q)}"

    if provider == "fofa":
        b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
        return f"https://fofa.info/result?qbase64={b64}"

    if provider == "netlas":
        clean_q = re.sub(r'\bip:"([0-9.]+)"', r'ip:\1', query)
        return f"https://app.netlas.io/responses/?q={urllib.parse.quote(clean_q)}"

    if provider == "urlscan":
        if is_pure_ip and raw_ip:
            return f"https://urlscan.io/ip/{raw_ip}"
        if is_pure_domain:
            dom = re.sub(r'^domain:\s*"?|"?$', '', query)
            return f"https://urlscan.io/domain/{dom}"
        clean_q = re.sub(r'files\.sha256:"?([a-f0-9]{64})"?', r'hash:\1', query, flags=re.IGNORECASE)
        frag = urllib.parse.quote(clean_q, safe=':="/+*')
        return f"https://urlscan.io/search/#{frag}"

    if provider == "greynoise":
        if is_pure_ip and raw_ip:
            return f"https://viz.greynoise.io/ip/{raw_ip}"
        return f"https://viz.greynoise.io/query?gnql={urllib.parse.quote(query)}"

    if provider == "silentpush":
        if raw_ip:
            return f"https://explore.silentpush.com/enrichment/ip/{raw_ip}"
        if is_pure_domain:
            dom = re.sub(r'^domain:\s*"?|"?$', '', query)
            return f"https://explore.silentpush.com/enrichment/domain/{dom}"
        return "https://explore.silentpush.com/"

    if provider == "etugen":
        if is_pure_ip and raw_ip:
            return f"https://app.etugen.io/trashpile/host/{raw_ip}"
        return f"https://app.etugen.io/search?q={urllib.parse.quote(query)}"

    if provider == "zoomeye":
        if is_pure_ip and raw_ip:
            return f"https://www.zoomeye.ai/searchResult?q=ip%3D%22{raw_ip}%22"
        return f"https://www.zoomeye.ai/searchResult?q={urllib.parse.quote(query)}"

    if provider == "validin":
        if raw_ip:
            return f"https://app.validin.com/ip/{raw_ip}"
        if is_pure_domain:
            dom = re.sub(r'^domain:\s*"?|"?$', '', query)
            return f"https://app.validin.com/domain/{dom}"
        return f"https://app.validin.com/search?q={urllib.parse.quote(query)}"

    return ""


def _quote(value: str) -> str:

    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'





def compose_queries(features: Dict[str, Any], max_signals: int = 3) -> List[Dict[str, Any]]:

    selected: List[Dict[str, Any]] = []

    used = set()

    for item in features.get("ranked", []):

        kind = item.get("kind")

        value = item.get("value")

        if kind not in SIGNAL_WEIGHTS or not value or kind in used:

            continue

        if kind in {"port", "asn", "tld"} and len(selected) < 1:

            continue

        selected.append(item)

        used.add(kind)

        if len(selected) >= max(1, min(max_signals, 5)):

            break



    if not selected:

        selected = [item for item in features.get("ranked", []) if item.get("kind") in {"domain", "ip", "asn"}][:2]



    maps = {

        "shodan": {

            "certificate_sha256": "ssl.cert.fingerprint", "certificate_subject": "ssl.cert.subject.cn",

            "certificate_issuer": "ssl.cert.issuer.cn", "jarm": "ssl.jarm", "http_body_hash": "http.html_hash",

            "http_headers_hash": "http.headers_hash", "favicon_hash": "http.favicon.hash",

            "http_title": "http.title", "http_server": "http.server", "port": "port", "asn": "asn", "ip": "ip",

        },

        "censys": {

            "certificate_sha256": "cert.fingerprint_sha256", "certificate_subject": "cert.parsed.subject_dn",

            "certificate_issuer": "cert.parsed.issuer_dn", "jarm": "host.services.jarm.fingerprint",

            "http_title": "host.services.http.response.html_title", "http_server": "host.services.http.response.headers.server",

            "port": "host.services.port", "asn": "host.autonomous_system.asn", "ip": "ip",

        },

        "fofa": {

            "certificate_sha256": "cert", "certificate_subject": "cert.subject", "certificate_issuer": "cert.issuer",

            "jarm": "jarm", "ja3s": "tls.ja3s", "http_body_hash": "body_hash",

            "http_headers_hash": "header_hash", "favicon_hash": "icon_hash", "http_title": "title",

            "http_server": "server", "port": "port", "asn": "asn", "ip": "ip",

        },

        "netlas": {

            "certificate_sha256": "certificate.fingerprint_sha256", "certificate_subject": "certificate.subject_dn",

            "certificate_issuer": "certificate.issuer_dn", "jarm": "jarm", "ja3s": "ja3s",

            "favicon_hash": "http.favicon.hash", "http_title": "http.title", "http_server": "http.headers.server",

            "port": "port", "asn": "whois.asn.number", "ip": "ip",

        },

        "silentpush": {

            "certificate_sha256": "ssl_sha256", "certificate_subject": "ssl_subject",

            "certificate_issuer": "ssl_issuer", "jarm": "jarm", "http_body_hash": "body_sha256",

            "favicon_hash": "favicon_murmur3", "http_title": "htmltitle", "http_server": "server",

            "port": "port", "asn": "asn", "ip": "ip",

        },
        "zoomeye": {
            "certificate_sha256": "ssl.cert.fingerprint", "certificate_subject": "ssl.cert.subject.cn",
            "certificate_issuer": "ssl.cert.issuer.cn", "jarm": "ssl.jarm",
            "favicon_hash": "iconhash", "http_title": "title", "http_server": "app",
            "port": "port", "asn": "asn", "ip": "ip",
        },
    }



    queries = []

    for provider, field_map in maps.items():
        clauses, signals = [], []
        for item in selected:
            field = field_map.get(item["kind"])
            if not field:
                continue
            value = item["value"]
            kind = item["kind"]

            if provider == "shodan":
                if kind == "ip":
                    clauses.append(f"net:{value}")
                elif kind == "asn":
                    clean_asn = re.sub(r"(?i)^AS", "", str(value))
                    clauses.append(f"asn:AS{clean_asn}")
                elif kind == "port":
                    clauses.append(f"port:{value}")
                else:
                    clauses.append(f"{field}:{_quote(value)}")
            elif provider == "censys":
                if kind == "ip":
                    clauses.append(f"ip: {value}")
                elif kind in {"port", "asn"}:
                    clean_val = re.sub(r"(?i)^AS", "", str(value)) if kind == "asn" else value
                    clauses.append(f"{field} = {clean_val}")
                else:
                    clauses.append(f"{field} : {_quote(value)}")
            elif provider == "fofa":
                clean_asn = re.sub(r"(?i)^AS", "", str(value)) if kind == "asn" else value
                clauses.append(f'{field}={_quote(clean_asn)}')
            elif provider == "netlas":
                if kind == "ip":
                    clauses.append(f"ip:{value}")
                elif kind in {"port", "asn"}:
                    clean_val = re.sub(r"(?i)^AS", "", str(value)) if kind == "asn" else value
                    clauses.append(f"{field}:{clean_val}")
                else:
                    clauses.append(f"{field}:{_quote(value)}")
            elif provider == "silentpush":
                clean_val = re.sub(r"(?i)^AS", "", str(value)) if kind == "asn" else value
                clauses.append(f"{field} = {_quote(clean_val) if not str(clean_val).isdigit() else clean_val}")
            elif provider == "zoomeye":
                if kind == "ip":
                    clauses.append(f'ip="{value}"')
                elif kind == "port":
                    clauses.append(f'port="{value}"')
                elif kind == "asn":
                    clean_asn = re.sub(r"(?i)^AS", "", str(value))
                    clauses.append(f'asn="{clean_asn}"')
                else:
                    clauses.append(f'{field}={_quote(value)}')
            else:
                clauses.append(f"{field}:{_quote(value)}")
            signals.append({"kind": item["kind"], "value": item["value"], "weight": item["weight"]})

        if clauses:
            joiner = " && " if provider in {"fofa", "zoomeye"} else " AND " if provider in {"netlas", "silentpush"} else " " if provider == "shodan" else " and "
            query = joiner.join(clauses)
            if provider == "silentpush":
                query += ' AND datasource = "webscan"'
            queries.append({
                "provider": provider,
                "query": query,
                "signals": signals,
                "estimated_strength": sum(item["weight"] for item in signals),
                "mode": "compound_search",
                "external_url": _engine_search_url(provider, query),
            })

    driftnet_fields = {

        "jarm": "jarm", "ja4": "ja4", "ja4t": "ja4t", "favicon_hash": "favicon",

        "certificate_subject": "subject", "certificate_issuer": "issuer", "http_title": "title",

        "http_body_hash": "obj-sha1", "http_server": "protocol", "port": "port-tcp",

    }

    driftnet_signals = [item for item in selected if item["kind"] in driftnet_fields]

    if driftnet_signals:

        clauses = [f'{driftnet_fields[item["kind"]]}:{_quote(item["value"])}' for item in driftnet_signals]

        queries.append({

            "provider": "driftnet", "query": " AND ".join(clauses), "signals": driftnet_signals,

            "estimated_strength": sum(item["weight"] for item in driftnet_signals),

            "mode": "passive_search", "dataset": "protocols",

            "external_url": "",

        })



    validin_kinds = {

        "certificate_sha256": "cert_hash", "jarm": "jarm", "http_headers_hash": "header_hash",

        "favicon_hash": "fingerprint",

    }

    validin_signal = next((item for item in selected if item["kind"] in validin_kinds), None)

    if validin_signal:

        pivot_kind = validin_kinds[validin_signal["kind"]]

        queries.append({

            "provider": "validin", "query": f'{pivot_kind}:{validin_signal["value"]}',

            "signals": [validin_signal], "estimated_strength": validin_signal["weight"],

            "mode": "fingerprint_pivot", "pivot_kind": pivot_kind,

            "external_url": f"https://app.validin.com/search?q={urllib.parse.quote(validin_signal['value'])}",

        })



    # Etugen: Focus on exposed open directory (Trashpile) & leaked files
    ip_signal = next((item for item in selected if item["kind"] == "ip"), None) or next((item for item in features.get("ip", [])), None)
    if ip_signal:
        ip_val = str(ip_signal["value"])
        queries.append({
            "provider": "etugen",
            "query": ip_val,
            "signals": [ip_signal],
            "estimated_strength": 5,
            "mode": "open_dir_host",
            "focus": "open_directory",
            "notes": "Inspect exposed open directory files and leaked artifacts on host (Trashpile)",
            "external_url": f"https://app.etugen.io/trashpile/host/{urllib.parse.quote(ip_val)}",
        })

    port_signal = next((item for item in selected if item["kind"] == "port" and str(item.get("value")) in {"8000", "8080", "8888"}), None)
    title_signal = next((item for item in selected if item["kind"] == "http_title"), None)

    if title_signal:
        t_val = str(title_signal["value"])
        if "phpmyadmin" in t_val.lower():
            queries.append({
                "provider": "etugen",
                "query": "title LIKE %phpMyAdmin%",
                "signals": [title_signal],
                "estimated_strength": 4,
                "mode": "template_search",
                "notes": "Etugen template: phpMyAdmin panels",
                "external_url": "https://app.etugen.io/search?q=" + urllib.parse.quote("title LIKE %phpMyAdmin%"),
            })
        elif "gophish" in t_val.lower():
            queries.append({
                "provider": "etugen",
                "query": "title LIKE %Gophish%",
                "signals": [title_signal],
                "estimated_strength": 5,
                "mode": "template_search",
                "notes": "Etugen template: Gophish phishing consoles",
                "external_url": "https://app.etugen.io/search?q=" + urllib.parse.quote("title LIKE %Gophish%"),
            })
        elif not ip_signal:
            queries.append({
                "provider": "etugen",
                "query": f'title LIKE "%{t_val}%"',
                "signals": [title_signal],
                "estimated_strength": 3,
                "mode": "open_dir_search",
                "focus": "open_directory",
                "notes": f"Search open directories for title '{t_val}'",
                "external_url": f"https://app.etugen.io/search?q={urllib.parse.quote(t_val)}",
            })

    if port_signal and str(port_signal["value"]) == "8000":
        queries.append({
            "provider": "etugen",
            "query": 'title LIKE "Index of%" AND port:8000',
            "signals": [port_signal],
            "estimated_strength": 4,
            "mode": "template_search",
            "focus": "open_directory",
            "notes": "Etugen template: Open directories on port 8000",
            "external_url": "https://app.etugen.io/search?q=" + urllib.parse.quote('title LIKE "Index of%" AND port:8000'),
        })

    if not ip_signal and not title_signal:
        etugen_signal = next((item for item in selected if item["kind"] in {
            "http_server", "banner", "domain", "certificate_subject",
        }), None)
        if etugen_signal:
            sig_val = str(etugen_signal["value"])
            queries.append({
                "provider": "etugen",
                "query": sig_val,
                "signals": [etugen_signal],
                "estimated_strength": etugen_signal.get("weight", 3),
                "mode": "open_dir_search",
                "focus": "open_directory",
                "notes": "Search exposed open directories (Trashpile) for leaked files and paths",
                "external_url": f"https://app.etugen.io/search?q={urllib.parse.quote(sig_val)}",
            })

    return queries





def _nested_candidate_rows(value: Any, limit: int = 1000) -> List[Dict[str, Any]]:

    rows: List[Dict[str, Any]] = []



    def visit(item: Any) -> None:

        if len(rows) >= limit:

            return

        if isinstance(item, dict):

            if _candidate_identity(item)[0]:

                rows.append(item)

            for child in item.values():

                visit(child)

        elif isinstance(item, list):

            for child in item:

                visit(child)



    visit(value)

    return rows





def _candidate_rows(provider: str, result: Any) -> List[Dict[str, Any]]:

    if not isinstance(result, dict):

        return []

    normalized = result.get("normalized") if isinstance(result.get("normalized"), dict) else result

    if provider == "shodan":

        return [row for row in normalized.get("matches", []) if isinstance(row, dict)]

    if provider == "censys":

        rows = []

        for item in normalized.get("hits", []):

            if not isinstance(item, dict):

                continue

            asset = item.get("host") or item.get("web_property") or item.get("certificate") or item

            if isinstance(asset, dict):

                rows.append(asset)

        return rows

    if provider == "fofa":

        return [row for row in normalized.get("records", []) if isinstance(row, dict)]

    if provider == "netlas":

        return [row for row in normalized.get("records", []) if isinstance(row, dict)]

    if provider in {"silentpush", "driftnet", "validin", "etugen", "zoomeye"}:

        return _nested_candidate_rows(normalized)

    return []





def _candidate_identity(row: Dict[str, Any]) -> Tuple[str, str]:

    target_type = str(row.get("target_type") or row.get("type") or "").lower()

    paths = ["ip", "host.ip", "address", "domain", "hostname", "host"]

    if target_type in {"ip", "domain"}:

        paths.insert(0, "target")

    for path in paths:

        value: Any = row

        for part in path.split("."):

            value = value.get(part) if isinstance(value, dict) else None

        if value:

            text = str(value).strip()

            try:

                return str(ipaddress.ip_address(text)), "ip"

            except ValueError:

                if DOMAIN_RE.fullmatch(text):

                    return text.lower(), "domain"

    blob = _json(row)

    ip_match = IP_RE.search(blob)

    if ip_match:

        return ip_match.group(0), "ip"

    domain_match = DOMAIN_RE.search(blob)

    if domain_match:

        return domain_match.group(0).lower(), "domain"

    return "", "unknown"





def _confidence(score: int, signal_count: int, provider_count: int) -> str:

    if score >= 65 and signal_count >= 2 and provider_count >= 2:

        return "high"

    if score >= 40 and signal_count >= 2:

        return "medium"

    if score >= 20:

        return "low"

    return "lead"





def score_candidates(seed: str, expansion_results: Dict[str, Any], query_specs: List[Dict[str, Any]], features: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:

    query_by_provider = {item["provider"]: item for item in query_specs}

    merged: Dict[str, Dict[str, Any]] = {}

    if features:
        host_items = []
        if isinstance(features, dict):
            if "categories" in features and "hosts" in features["categories"]:
                host_items.extend(features["categories"]["hosts"])
            if "by_type" in features:
                host_items.extend(features["by_type"].get("dns", []))
                host_items.extend(features["by_type"].get("domain", []))
        for dom in host_items:
            d_val = str(dom.get("value", "")).lower().strip(".")
            if d_val and d_val != seed.lower() and d_val not in merged:
                is_ip = False
                parts = d_val.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    is_ip = True
                merged[d_val] = {
                    "value": d_val,
                    "value_type": "ip" if is_ip else "domain",
                    "providers": ["seed_enrichment"],
                    "evidence": [{"kind": dom.get("kind", "correlated_host"), "value": d_val, "weight": 35, "matched": True}],
                    "raw": {"seed_enrichment": dom},
                }

    for provider, result in expansion_results.items():

        spec = query_by_provider.get(provider, {})

        for row in _candidate_rows(provider, result):

            value, value_type = _candidate_identity(row)

            if not value or value.lower() == seed.lower():

                continue

            item = merged.setdefault(value, {

                "value": value, "value_type": value_type, "providers": [], "evidence": [], "raw": {},

            })

            if provider not in item["providers"]:

                item["providers"].append(provider)

            item["raw"][provider] = row

            blob = _json(row).lower()

            for signal in spec.get("signals", []):

                evidence = {**signal, "provider": provider, "matched": str(signal["value"]).lower() in blob}

                if not any(e["kind"] == evidence["kind"] and e["value"] == evidence["value"] for e in item["evidence"]):

                    item["evidence"].append(evidence)



    output = []

    for item in merged.values():

        matched = [e for e in item["evidence"] if e.get("matched")]

        inferred = [e for e in item["evidence"] if not e.get("matched")]

        for evidence in inferred:

            evidence["query_inferred"] = True

        unique_signal_weights = {}

        for evidence in matched + inferred:

            kind = str(evidence.get("kind") or "")

            unique_signal_weights[kind] = max(unique_signal_weights.get(kind, 0), int(evidence.get("weight") or 0))

        score = sum(unique_signal_weights.values())

        score += max(0, len(item["providers"]) - 1) * 10

        raw_blob = _json(item["raw"]).lower()

        shared = next((marker for marker in SHARED_INFRA_MARKERS if marker in raw_blob), "")

        if shared:

            score = max(0, score - 20)

            item["evidence"].append({"kind": "shared_infrastructure", "value": shared, "weight": -20, "matched": True})

        signal_count = len({e["kind"] for e in item["evidence"] if e.get("matched") or e.get("query_inferred")})

        item["score"] = min(100, score)

        item["confidence"] = _confidence(item["score"], signal_count, len(item["providers"]))

        item["signal_count"] = signal_count

        output.append(item)

    return sorted(output, key=lambda row: (-row["score"], row["value"]))[:500]





def build_graph(seed: str, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:

    nodes = [{"id": f"seed:{seed}", "label": seed, "type": "seed", "score": 100}]

    edges = []

    signal_nodes = set()

    for candidate in candidates[:200]:

        candidate_id = f"candidate:{candidate['value']}"

        nodes.append({

            "id": candidate_id, "label": candidate["value"], "type": candidate["value_type"],

            "score": candidate["score"], "confidence": candidate["confidence"],

        })

        edges.append({

            "source": f"seed:{seed}", "target": candidate_id, "relation": "candidate_cluster",

            "weight": candidate["score"], "providers": candidate["providers"],

        })

        for evidence in candidate.get("evidence", []):

            if evidence.get("kind") == "shared_infrastructure":

                continue

            signal_key = hashlib.sha1(f"{evidence.get('kind')}:{evidence.get('value')}".encode()).hexdigest()[:16]

            signal_id = f"signal:{signal_key}"

            if signal_id not in signal_nodes:

                signal_nodes.add(signal_id)

                nodes.append({

                    "id": signal_id, "label": str(evidence.get("value")), "type": evidence.get("kind"),

                    "weight": evidence.get("weight", 0),

                })

            edges.append({

                "source": candidate_id, "target": signal_id, "relation": "matches",

                "weight": evidence.get("weight", 0), "provider": evidence.get("provider", ""),

            })

    return {"nodes": nodes, "edges": edges}





def match_signature_packs(features: Dict[str, Any]) -> List[Dict[str, Any]]:

    available = {

        kind: [str(item.get("value", "")).lower() for item in rows]

        for kind, rows in features.get("by_type", {}).items()

    }

    matches = []

    for pack in list_signature_packs(enabled_only=True):

        evidence = []

        for kind, values in pack["signals"].items():

            for expected in values if isinstance(values, list) else [values]:

                expected_low = str(expected).lower()

                if any(expected_low in observed for observed in available.get(kind, [])):

                    evidence.append({"kind": kind, "value": expected})

        if len(evidence) >= pack["minimum_matches"]:

            matches.append({**pack, "matched_evidence": evidence})

    return matches





def _execute_expansion(query_specs: List[Dict[str, Any]], keys: Dict[str, str], providers: List[str]) -> Dict[str, Any]:

    import intel_query



    provider_set = set(providers or DEFAULT_EXPANSION_PROVIDERS)

    calls = {}

    for spec in query_specs:

        provider, query = spec["provider"], spec["query"]

        if provider not in provider_set or not keys.get(f"{provider}_key"):

            continue

        if provider == "shodan":

            calls[provider] = lambda q=query: intel_query.query_shodan_search(q, keys["shodan_key"], query_type="shodan_query")

        elif provider == "censys":

            calls[provider] = lambda q=query: intel_query.query_censys_search(q, keys["censys_key"], query_type="censys_query", page_size=100)

        elif provider == "fofa":

            calls[provider] = lambda q=query: intel_query.query_fofa(q, keys["fofa_key"], query_type="fofa_query", size=100)

        elif provider == "netlas" and hasattr(intel_query, "query_netlas_search"):

            calls[provider] = lambda q=query: intel_query.query_netlas_search(q, keys["netlas_key"], size=100)

        elif provider == "silentpush":

            calls[provider] = lambda q=query: intel_query.query_silent_push_scan_data(q, keys["silentpush_key"], limit=100, query_type="spql")

        elif provider == "driftnet":

            calls[provider] = lambda q=query, s=spec: intel_query.query_driftnet_dataset(

                s.get("dataset", "protocols"), api_key=keys["driftnet_key"], expression=q,

            )

        elif provider == "validin":

            calls[provider] = lambda s=spec: intel_query.query_validin_fingerprint(

                s["signals"][0]["value"], s.get("pivot_kind", "fingerprint"), keys["validin_key"], limit=100,

            )

        elif provider == "etugen":

            calls[provider] = lambda q=query: intel_query.query_etugen_open_dir(q, keys["etugen_key"])
        elif provider == "zoomeye":
            calls[provider] = lambda q=query: intel_query.query_zoomeye_search(q, keys.get("zoomeye_key", ""), pagesize=100)

    results = {}

    with ThreadPoolExecutor(max_workers=min(4, max(1, len(calls)))) as executor:

        futures = {executor.submit(call): provider for provider, call in calls.items()}

        for future in as_completed(futures):

            provider = futures[future]

            try:

                results[provider] = future.result()

            except Exception as exc:

                results[provider] = {"error": str(exc)[:300]}

    return results





def _validate_candidates(candidates: List[Dict[str, Any]], keys: Dict[str, str], providers: List[str]) -> Dict[str, Any]:

    if "greynoise" not in providers:

        return {}

    import intel_query



    targets = [item for item in candidates if item.get("value_type") == "ip"][:50]

    if not targets:

        return {}

    results: Dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as executor:

        futures = {

            executor.submit(intel_query.query_greynoise, item["value"], keys.get("greynoise_key", "")): item

            for item in targets

        }

        for future in as_completed(futures):

            candidate = futures[future]

            try:

                result = future.result()

            except Exception as exc:

                result = {"error": str(exc)[:300]}

            results[candidate["value"]] = result

            if result.get("error"):

                continue

            candidate["raw"]["greynoise"] = result

            if "greynoise" not in candidate["providers"]:

                candidate["providers"].append("greynoise")

            candidate["evidence"].append({

                "kind": "internet_noise", "value": str(bool(result.get("noise"))).lower(),

                "classification": result.get("classification", ""), "provider": "greynoise",

                "weight": 0, "matched": True, "validation_only": True,

            })

    return results





def provider_readiness(keys: Dict[str, str] | None = None, server_only: bool = False) -> Dict[str, Any]:

    active_keys = environment_keys() if server_only else (keys or {})

    providers = []

    for provider, metadata in EXPANSION_PROVIDERS.items():

        configured = bool(active_keys.get(f"{provider}_key"))

        providers.append({"id": provider, **metadata, "configured": configured})

    return {"providers": providers, "server_only": server_only}





def preview_hunt(seed: str, keys: Dict[str, str] | None = None, providers: List[str] | None = None,

                 source_ids: List[str] | None = None, max_signals: int = 3) -> Dict[str, Any]:

    import intel_query



    seed = str(seed or "").strip()

    if not seed:

        raise ValueError("Hunt seed is required")

    keys = keys or {}

    selected_providers = providers or DEFAULT_EXPANSION_PROVIDERS

    seed_results = intel_query.do_infra_intel(

        seed, silentpush_key=keys.get("silentpush_key", ""), driftnet_key=keys.get("driftnet_key", ""),

        shodan_key=keys.get("shodan_key", ""), censys_key=keys.get("censys_key", ""),

        etugen_key=keys.get("etugen_key", ""), pulsedive_key=keys.get("pulsedive_key", ""),

        fofa_key=keys.get("fofa_key", ""), validin_key=keys.get("validin_key", ""),

        ha_key=keys.get("ha_key", ""), abuseipdb_key=keys.get("abuseipdb_key", ""),

        urlscan_key=keys.get("urlscan_key", ""), dnsdumpster_key=keys.get("dnsdumpster_key", ""),

        greynoise_key=keys.get("greynoise_key", ""), netlas_key=keys.get("netlas_key", ""),

        vt_key=keys.get("vt_key", ""),

        sources=source_ids or DEFAULT_SEED_SOURCES,

    )

    features = extract_features(seed_results)

    queries = [item for item in compose_queries(features, max_signals=max_signals) if item["provider"] in selected_providers]

    readiness = provider_readiness(keys)["providers"]

    return {

        "preview": True, "seed": seed, "features": features, "queries": queries,

        "signature_matches": match_signature_packs(features),

        "provider_readiness": readiness,

        "estimated_calls": len([item for item in queries if keys.get(f'{item["provider"]}_key')]) + (1 if "greynoise" in selected_providers else 0),

        "seed_sources": seed_results.get("sources_queried", []),

    }





def run_hunt(seed: str, keys: Dict[str, str] | None = None, providers: List[str] | None = None,

             source_ids: List[str] | None = None, hunt_id: int | None = None,

             max_signals: int = 3) -> Dict[str, Any]:

    import intel_query



    init_db()

    seed = str(seed or "").strip()

    if not seed:

        raise ValueError("Hunt seed is required")

    keys = keys or {}

    providers = providers or DEFAULT_EXPANSION_PROVIDERS

    source_ids = source_ids or DEFAULT_SEED_SOURCES

    started = _utcnow()

    with _DB_LOCK, _connect() as conn:

        cursor = conn.execute(

            "INSERT INTO infra_hunt_runs (hunt_id, seed, status, started_at) VALUES (?, ?, 'running', ?)",

            (hunt_id, seed, started),

        )

        run_id = int(cursor.lastrowid)



    try:

        seed_results = intel_query.do_infra_intel(

            seed,

            silentpush_key=keys.get("silentpush_key", ""),

            driftnet_key=keys.get("driftnet_key", ""),

            shodan_key=keys.get("shodan_key", ""),

            censys_key=keys.get("censys_key", ""),

            etugen_key=keys.get("etugen_key", ""),

            pulsedive_key=keys.get("pulsedive_key", ""),

            fofa_key=keys.get("fofa_key", ""),

            validin_key=keys.get("validin_key", ""),

            ha_key=keys.get("ha_key", ""),

            abuseipdb_key=keys.get("abuseipdb_key", ""),

            urlscan_key=keys.get("urlscan_key", ""),

            dnsdumpster_key=keys.get("dnsdumpster_key", ""),

            greynoise_key=keys.get("greynoise_key", ""),

            netlas_key=keys.get("netlas_key", ""),

            vt_key=keys.get("vt_key", ""),

            sources=source_ids,

        )

        features = extract_features(seed_results)

        query_specs = compose_queries(features, max_signals=max_signals)

        expansions = _execute_expansion(query_specs, keys, providers)

        candidates = score_candidates(seed, expansions, query_specs, features=features)

        validation_results = _validate_candidates(candidates, keys, providers)

        signature_matches = match_signature_packs(features)

        graph = build_graph(seed, candidates)

        previous_values = set()

        if hunt_id:

            with _connect() as conn:

                previous = conn.execute(

                    """SELECT c.value FROM infra_hunt_candidates c

                       JOIN infra_hunt_runs r ON r.id=c.run_id

                       WHERE r.hunt_id=? AND r.id<>? ORDER BY r.id DESC""",

                    (hunt_id, run_id),

                ).fetchall()

                previous_values = {row["value"] for row in previous}

        new_values = [row["value"] for row in candidates if row["value"] not in previous_values]

        summary = {

            "run_id": run_id,

            "seed": seed,

            "feature_count": features["count"],

            "query_count": len(query_specs),

            "candidate_count": len(candidates),

            "high_confidence": sum(1 for row in candidates if row["confidence"] == "high"),

            "medium_confidence": sum(1 for row in candidates if row["confidence"] == "medium"),

            "new_candidate_count": len(new_values),

            "new_candidates": new_values[:100],

            "signature_matches": [item["name"] for item in signature_matches],

            "providers_queried": list(expansions),

        }

        result = {

            "summary": summary,

            "features": features,

            "queries": query_specs,

            "candidates": candidates,

            "graph": graph,

            "signature_matches": signature_matches,

            "provider_results": expansions,

            "validation_results": {"greynoise": validation_results} if validation_results else {},

            "seed_sources": seed_results.get("sources_queried", []),

        }

        finished = _utcnow()

        with _DB_LOCK, _connect() as conn:

            conn.execute(

                "UPDATE infra_hunt_runs SET status='complete', finished_at=?, summary_json=?, result_json=? WHERE id=?",

                (finished, _json(summary), _json(result), run_id),

            )

            for candidate in candidates:

                conn.execute(

                    """INSERT OR REPLACE INTO infra_hunt_candidates

                       (run_id, value, value_type, score, confidence, providers_json, evidence_json, raw_json)

                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",

                    (

                        run_id, candidate["value"], candidate["value_type"], candidate["score"],

                        candidate["confidence"], _json(candidate["providers"]),

                        _json(candidate["evidence"]), _json(candidate["raw"]),

                    ),

                )

            if hunt_id:

                interval = conn.execute("SELECT interval_minutes FROM infra_hunts WHERE id=?", (hunt_id,)).fetchone()

                minutes = max(15, int(interval["interval_minutes"] if interval else 1440))

                next_run = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).replace(microsecond=0).isoformat()

                conn.execute(

                    """UPDATE infra_hunts SET last_run_at=?, next_run_at=?, last_status='complete',

                       last_error='', updated_at=? WHERE id=?""",

                    (finished, next_run, finished, hunt_id),

                )

        return result

    except Exception as exc:

        finished = _utcnow()

        with _DB_LOCK, _connect() as conn:

            conn.execute(

                "UPDATE infra_hunt_runs SET status='failed', finished_at=?, error=? WHERE id=?",

                (finished, str(exc)[:1000], run_id),

            )

            if hunt_id:

                conn.execute(

                    "UPDATE infra_hunts SET last_run_at=?, last_status='failed', last_error=?, updated_at=? WHERE id=?",

                    (finished, str(exc)[:1000], finished, hunt_id),

                )

        raise





def _hunt_row(row: sqlite3.Row) -> Dict[str, Any]:

    item = dict(row)

    item["enabled"] = bool(item["enabled"])

    item["providers"] = _loads(item.pop("providers_json"), [])

    item["source_ids"] = _loads(item.pop("source_ids_json"), [])

    return item





def list_hunts() -> List[Dict[str, Any]]:

    init_db()

    with _connect() as conn:

        rows = conn.execute("SELECT * FROM infra_hunts ORDER BY updated_at DESC, id DESC").fetchall()

        return [_hunt_row(row) for row in rows]





def get_hunt(hunt_id: int) -> Dict[str, Any] | None:

    init_db()

    with _connect() as conn:

        row = conn.execute("SELECT * FROM infra_hunts WHERE id=?", (int(hunt_id),)).fetchone()

        if not row:

            return None

        hunt = _hunt_row(row)

        runs = conn.execute(

            "SELECT id, status, started_at, finished_at, summary_json, error FROM infra_hunt_runs WHERE hunt_id=? ORDER BY id DESC LIMIT 30",

            (int(hunt_id),),

        ).fetchall()

        hunt["runs"] = [

            {**dict(run), "summary": _loads(run["summary_json"], {})}

            for run in runs

        ]

        for run in hunt["runs"]:

            run.pop("summary_json", None)

        return hunt





def save_hunt(payload: Dict[str, Any], hunt_id: int | None = None) -> Dict[str, Any]:

    init_db()

    seed = str(payload.get("seed") or "").strip()

    if not seed:

        raise ValueError("Hunt seed is required")

    now = _utcnow()

    name = str(payload.get("name") or f"Infrastructure hunt: {seed}").strip()[:160]

    description = str(payload.get("description") or "").strip()[:2000]

    enabled = 1 if payload.get("enabled", True) else 0

    interval = max(15, min(int(payload.get("interval_minutes") or 1440), 43200))

    providers = [str(value) for value in payload.get("providers", []) if str(value).strip()]

    sources = [str(value) for value in payload.get("source_ids", []) if str(value).strip()]

    with _DB_LOCK, _connect() as conn:

        if hunt_id:

            conn.execute(

                """UPDATE infra_hunts SET name=?, seed=?, description=?, enabled=?, interval_minutes=?,

                   providers_json=?, source_ids_json=?, updated_at=? WHERE id=?""",

                (name, seed, description, enabled, interval, _json(providers), _json(sources), now, int(hunt_id)),

            )

            saved_id = int(hunt_id)

        else:

            next_run = now if enabled else ""

            cursor = conn.execute(

                """INSERT INTO infra_hunts

                   (name, seed, description, enabled, interval_minutes, providers_json,

                    source_ids_json, created_at, updated_at, next_run_at)

                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",

                (name, seed, description, enabled, interval, _json(providers), _json(sources), now, now, next_run),

            )

            saved_id = int(cursor.lastrowid)

    return get_hunt(saved_id) or {}





def delete_hunt(hunt_id: int) -> Dict[str, Any]:

    init_db()

    with _DB_LOCK, _connect() as conn:

        cursor = conn.execute("DELETE FROM infra_hunts WHERE id=?", (int(hunt_id),))

        return {"deleted": cursor.rowcount > 0, "id": int(hunt_id)}





def get_run(run_id: int) -> Dict[str, Any] | None:

    init_db()

    with _connect() as conn:

        row = conn.execute("SELECT * FROM infra_hunt_runs WHERE id=?", (int(run_id),)).fetchone()

        if not row:

            return None

        item = dict(row)

        item["summary"] = _loads(item.pop("summary_json"), {})

        item["result"] = _loads(item.pop("result_json"), {})

        return item





def list_signature_packs(enabled_only: bool = False) -> List[Dict[str, Any]]:

    init_db()

    query = "SELECT * FROM infra_signature_packs"

    if enabled_only:

        query += " WHERE enabled=1"

    query += " ORDER BY builtin DESC, family, name"

    with _connect() as conn:

        rows = conn.execute(query).fetchall()

        output = []

        for row in rows:

            item = dict(row)

            item["signals"] = _loads(item.pop("signals_json"), {})

            item["enabled"] = bool(item["enabled"])

            item["builtin"] = bool(item["builtin"])

            output.append(item)

        return output





def save_signature_pack(payload: Dict[str, Any], pack_id: int | None = None) -> Dict[str, Any]:

    init_db()

    name = str(payload.get("name") or "").strip()

    if not name:

        raise ValueError("Signature name is required")

    slug = str(payload.get("slug") or re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")).strip()[:120]

    signals = payload.get("signals") if isinstance(payload.get("signals"), dict) else {}

    if not signals:

        raise ValueError("At least one signature signal is required")

    values = (

        slug, name[:160], str(payload.get("family") or "")[:120], str(payload.get("description") or "")[:2000],

        _json(signals), max(1, int(payload.get("minimum_matches") or 2)),

        str(payload.get("false_positive_notes") or "")[:2000], 1 if payload.get("enabled", True) else 0, _utcnow(),

    )

    with _DB_LOCK, _connect() as conn:

        if pack_id:

            conn.execute(

                """UPDATE infra_signature_packs SET slug=?, name=?, family=?, description=?, signals_json=?,

                   minimum_matches=?, false_positive_notes=?, enabled=?, updated_at=? WHERE id=? AND builtin=0""",

                (*values, int(pack_id)),

            )

        else:

            conn.execute(

                """INSERT INTO infra_signature_packs

                   (slug, name, family, description, signals_json, minimum_matches,

                    false_positive_notes, enabled, builtin, updated_at)

                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",

                values,

            )

    return next((item for item in list_signature_packs() if item["slug"] == slug), {})





def delete_signature_pack(pack_id: int) -> Dict[str, Any]:

    init_db()

    with _DB_LOCK, _connect() as conn:

        cursor = conn.execute("DELETE FROM infra_signature_packs WHERE id=? AND builtin=0", (int(pack_id),))

        return {"deleted": cursor.rowcount > 0, "id": int(pack_id)}





def environment_keys() -> Dict[str, str]:

    aliases = {

        "shodan_key": ("SHODAN_API_KEY", "MANTIS_SHODAN_API_KEY"),

        "censys_key": ("CENSYS_PAT", "CENSYS_API_KEY", "MANTIS_CENSYS_PAT"),

        "fofa_key": ("FOFA_API_KEY", "MANTIS_FOFA_API_KEY"),

        "netlas_key": ("NETLAS_API_KEY", "MANTIS_NETLAS_API_KEY"),

        "zoomeye_key": ("ZOOMEYE_API_KEY", "MANTIS_ZOOMEYE_API_KEY", "IOCINTEL_ZOOMEYE_API_KEY"),

        "validin_key": ("VALIDIN_API_KEY", "MANTIS_VALIDIN_API_KEY"),

        "driftnet_key": ("DRIFTNET_API_TOKEN", "DRIFTNET_API_KEY", "MANTIS_DRIFTNET_API_TOKEN", "MANTIS_DRIFTNET_KEY"),

        "silentpush_key": ("SILENT_PUSH_API_KEY", "SILENTPUSH_API_KEY", "MANTIS_SILENTPUSH_API_KEY"),

        "etugen_key": ("ETUGEN_API_KEY", "MANTIS_ETUGEN_API_KEY"),

        "urlscan_key": ("URLSCAN_API_KEY", "MANTIS_URLSCAN_API_KEY"),

        "greynoise_key": ("GREYNOISE_API_KEY", "MANTIS_GREYNOISE_API_KEY"),

    }

    return {name: next((os.getenv(alias, "").strip() for alias in names if os.getenv(alias, "").strip()), "") for name, names in aliases.items()}





def run_due_hunts(keys: Dict[str, str] | None = None, limit: int = 5) -> Dict[str, Any]:

    init_db()

    keys = {**environment_keys(), **(keys or {})}

    now = _utcnow()

    with _connect() as conn:

        rows = conn.execute(

            """SELECT * FROM infra_hunts WHERE enabled=1 AND (next_run_at='' OR next_run_at<=?)

               ORDER BY next_run_at, id LIMIT ?""",

            (now, max(1, min(int(limit), 20))),

        ).fetchall()

    completed, failed = [], []

    for row in rows:

        hunt = _hunt_row(row)

        try:

            result = run_hunt(

                hunt["seed"], keys=keys, providers=hunt["providers"], source_ids=hunt["source_ids"], hunt_id=hunt["id"],

            )

            completed.append(result["summary"])

        except Exception as exc:

            failed.append({"hunt_id": hunt["id"], "seed": hunt["seed"], "error": str(exc)[:500]})

    return {"checked_at": now, "due": len(rows), "completed": completed, "failed": failed}





init_db()

