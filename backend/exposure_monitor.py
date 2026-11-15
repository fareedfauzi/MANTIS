"""Passive, on-demand exposure snapshots from curated infrastructure queries."""

import json
import os
import sqlite3
import ipaddress
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock

import intel_query
from infra_hunt_service import _candidate_rows, _candidate_identity

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "exposure_monitor.db")
_LOCK = Lock()

# Each query is a narrow, reviewable lead. A matching banner is never a C2 verdict.
TOOLS = {
    "cobalt-strike": {
        "name": "Cobalt Strike", "category": "C2 framework",
        "description": "Commercial adversary simulation platform whose teamserver fingerprints can also appear in attacker infrastructure.",
        "queries": {"shodan": 'product:"Cobalt Strike Beacon"',
                    "fofa": 'app="Cobalt Strike"',
                    "censys": 'services.tls.certificates.leaf_data.issuer.common_name="Major Cobalt Strike"'},
    },
    "sliver": {
        "name": "Sliver", "category": "C2 framework",
        "description": "Open source adversary simulation framework. These searches look for distinctive exposed artifacts.",
        "queries": {"shodan": 'http.title:"Index of" http.html:"sliver-c2"',
                    "censys": 'services:(tls.certificates.leaf_data.subject.common_name:multiplayer and tls.certificates.leaf_data.issuer.common_name:operators)',
                    "zoomeye": 'http.body="sliver" && title="Index of /"'},
    },
    "mythic": {
        "name": "Mythic", "category": "C2 framework",
        "description": "Collaborative C2 framework. The selected favicon fingerprint is a lead that needs corroboration.",
        "queries": {"shodan": 'http.favicon.hash:-859291042',
                    "fofa": 'icon_hash="-859291042"',
                    "censys": 'host.services.endpoints.http.html_title = "Mythic"',
                    "validin": 'jarm:1dd40d40d00040d00042d43d000000831b6af40378e2dd35eeac4e9311926e',
                    "zoomeye": 'title="Mythic" && http.body="login"'},
    },
    "havoc": {
        "name": "Havoc", "category": "C2 framework",
        "description": "C2 framework; exposed web content may identify installations, including legitimate labs.",
        "queries": {"zoomeye": 'http.body="Havoc" && title="Index of /"'},
    },
    "metasploit": {
        "name": "Metasploit", "category": "Security tool",
        "description": "Penetration testing framework. An exposed artifact is not evidence of malicious use.",
        "queries": {"shodan": 'ssl.cert.subject.cn:"MetasploitSelfSignedCA"',
                    "fofa": 'cert.subject.cn="MetasploitSelfSignedCA"',
                    "zoomeye": 'title="Index of /" && http.body="metasploit"'},
    },
    "nessus": {
        "name": "Nessus", "category": "Security scanner",
        "description": "Tenable vulnerability scanner. Exposed management services may be authorized deployments.",
        "queries": {"shodan": 'product:"Nessus"', "fofa": 'title="Nessus"'},
    },
    "acunetix": {
        "name": "Acunetix", "category": "Security scanner",
        "description": "Web vulnerability scanner; searches for indexed console titles rather than scanning targets.",
        "queries": {"shodan": 'http.title:"Acunetix"', "fofa": 'title="Acunetix"'},
    },
    "openvas": {
        "name": "Greenbone / OpenVAS", "category": "Security scanner",
        "description": "Vulnerability management console; public exposure may be intentional or misconfigured.",
        "queries": {"shodan": 'http.title:"Greenbone Security Assistant"',
                    "fofa": 'title="Greenbone Security Assistant"'},
    },
    "nexpose": {
        "name": "Rapid7 Nexpose", "category": "Security scanner",
        "description": "Vulnerability management console identified by its indexed page title.",
        "queries": {"shodan": 'http.title:"Nexpose Security Console"',
                    "fofa": 'title="Nexpose Security Console"'},
    },
    "burp-enterprise": {
        "name": "Burp Suite Enterprise", "category": "Security scanner",
        "description": "Enterprise web scanning console; an indexed login page is only an exposure lead.",
        "queries": {"shodan": 'http.title:"Burp Suite Enterprise Edition"',
                    "fofa": 'title="Burp Suite Enterprise Edition"'},
    },
    "covenant": {
        "name": "Covenant", "category": "C2 framework",
        "description": "Open source .NET C2 framework; indexed console favicons and certificate names are investigation leads.",
        "queries": {"shodan": 'http.favicon.hash:-737603591',
                    "fofa": 'icon_hash="-737603591"',
                    "censys": 'services.tls.certificates.leaf_data.subject_dn:"CN=Covenant"'},
    },
    "supershell": {
        "name": "SuperShell", "category": "C2 framework",
        "description": "Web-based remote administration framework; searches identify exposed console artifacts.",
        "queries": {"shodan": 'http.favicon.hash:-1010228102',
                    "fofa": 'icon_hash="-1010228102"',
                    "censys": 'services.http.response.html_title:"Supershell"'},
    },
    "vshell": {
        "name": "VSHELL", "category": "C2 framework",
        "description": "A curated console favicon fingerprint; inspect the page and service before attribution.",
        "queries": {"shodan": 'http.favicon.hash:-2040870717',
                    "fofa": 'icon_hash="-2040870717"',
                    "censys": 'services.http.response.html_title="Vshell - 登录"'},
    },
    "panda-c2": {
        "name": "PandaC2", "category": "C2 framework",
        "description": "A curated web console favicon fingerprint; matching assets may be reused elsewhere.",
        "queries": {"shodan": 'http.favicon.hash:-296385002',
                    "fofa": 'icon_hash="-296385002"'},
    },
    "startkiller-c2": {
        "name": "StartKillerC2", "category": "C2 framework",
        "description": "A curated web console favicon fingerprint; corroborate with other host evidence.",
        "queries": {"shodan": 'http.favicon.hash:1866124853',
                    "fofa": 'icon_hash="1866124853"'},
    },
    "hak5-cloud-c2": {
        "name": "Hak5 Cloud C2", "category": "C2 framework",
        "description": "Administration platform used for Hak5 devices; indexed product and console signals require context.",
        "queries": {"shodan": 'http.favicon.hash:1294130019 product:"Hak5 Cloud C2"',
                    "fofa": 'icon_hash="1294130019"',
                    "censys": 'host.services.software.product:"Hak5 Cloud C2" AND host.services.port:8080'},
    },
    "gophish": {
        "name": "GoPhish", "category": "Phishing framework",
        "description": "Open source phishing simulation platform; a public login console may be a legitimate deployment.",
        "queries": {"shodan": 'http.favicon.hash:803527991 http.title:"Gophish"',
                    "censys": 'host.services.endpoints.http.body:"gophish.css" AND host.services.endpoints.http.html_title:"Gophish"'},
    },
    "evilginx": {
        "name": "Evilginx", "category": "Phishing framework",
        "description": "AiTM phishing framework; indexed product or title artifacts identify exposed instances, while unbranded proxies may be missed.",
        "queries": {"shodan": 'http.title:"evilginx"',
                    "censys": 'host.services.software.product:"Evilginx"'},
    },
    "asyncrat": {
        "name": "AsyncRAT", "category": "Remote access trojan",
        "description": "Remote access trojan with a recognizable server certificate name; certificates can be copied.",
        "queries": {"fofa": 'cert.subject.cn="AsyncRAT Server"',
                    "censys": 'services.tls.certificates.leaf_data.subject_dn="CN=AsyncRAT Server"'},
    },
    "quasar-rat": {
        "name": "Quasar RAT", "category": "Remote access trojan",
        "description": "Remote access trojan; searches for its documented server CA certificate name.",
        "queries": {"shodan": 'ssl.cert.subject.cn:"Quasar Server CA"',
                    "fofa": 'cert.subject.cn="Quasar Server CA"',
                    "censys": 'services.tls.certificates.leaf_data.subject.common_name:"Quasar Server CA"'},
    },
    "laplas-clipper": {
        "name": "Laplas Clipper", "category": "Malware infrastructure",
        "description": "Certificate name associated with Laplas infrastructure; validate the certificate and service before attribution.",
        "queries": {"shodan": 'ssl.cert.subject.cn:"Laplas.app"',
                    "fofa": 'cert.subject.cn="Laplas.app"',
                    "censys": 'services.tls.certificates.leaf_data.subject.common_name:"Laplas.app"'},
    },
    "amadey": {
        "name": "Amadey", "category": "Malware infrastructure",
        "description": "Paired web content and certificate signal from the hunting catalog; a matching host remains a lead.",
        "queries": {"shodan": 'http.html:"Amadey" ssl.cert.subject.cn:"desas.digital"',
                    "fofa": 'cert.subject.cn="desas.digital"'},
    },
    "risepro": {
        "name": "RisePro", "category": "Info stealer",
        "description": "Curated panel favicon paired with a separate RisePro service-content search for review.",
        "queries": {"shodan": 'http.favicon.hash:-1819134017',
                    "censys": 'services.http.response.body:"RisePro" and services.port:8081'},
    },
    "immortal-dropper": {
        "name": "Immortal Dropper", "category": "Malware infrastructure",
        "description": "Searches for a specific named dropper management panel and its indexed content.",
        "queries": {"shodan": 'http.title:"IMMORTAL DROPPER C2 Panel"'},
    },
    "shadow-c2": {
        "name": "Shadow C2", "category": "Info stealer",
        "description": "Specific panel title and implementation string; confirm the page before linking it to a campaign.",
        "queries": {"shodan": 'http.title:"Shadow C2 Panel" http.html:"shadow_secure_key"'},
    },
    "geacon-pro": {
        "name": "Geacon Pro", "category": "C2 framework",
        "description": "Narrow certificate-name fingerprint from the catalog; the certificate may be copied or reused.",
        "queries": {"shodan": 'ssl.cert.subject.cn:"foren.zik"'},
    },
    "locust": {
        "name": "Locust HTTP Flood", "category": "Security tool",
        "description": "Specific exposed Locust test script strings; legitimate load testing is common.",
        "queries": {"shodan": 'http.html:"HTTPFloodUser" http.html:"attack_get"'},
    },
    "pikvm": {
        "name": "PiKVM", "category": "Remote access tool",
        "description": "Internet-indexed remote KVM management interface; verify ownership and access controls.",
        "queries": {"shodan": 'product:"PiKVM"'},
    },
}

# Additional curated searches for profiles with an independent product, page, or certificate signal.
# Favicon-only additions are restricted to named panels with another catalog signal.
EXTRA_QUERIES = {
    "cobalt-strike": [("shodan-default-cert", "shodan", 'ssl.cert.subject.cn:"Major Cobalt Strike"')],
    "mythic": [("shodan-panel", "shodan", 'http.html:"mythic-react"')],
    "panda-c2": [("shodan-product", "shodan", 'product:"Panda C2"')],
    "hak5-cloud-c2": [("shodan-product", "shodan", 'product:"Hak5 Cloud C2"')],
    "gophish": [("shodan-favicon", "shodan", 'http.favicon.hash:803527991'),
                ("shodan-product", "shodan", 'product:"GoPhish"')],
    "evilginx": [("shodan-product", "shodan", 'product:"Evilginx"')],
    "risepro": [("shodan-content", "shodan", 'http.html:"RisePro" port:8081')],
    "amadey": [("shodan-favicon", "shodan", 'http.favicon.hash:177506569')],
    "immortal-dropper": [("shodan-content", "shodan", 'http.html:"IMMORTAL DROPPER"')],
}

# Exposure uses the same reviewed rules as the AI Red Team catalog. CLI-only tools
# without a stable indexed service stay in the catalog's source reference list.
AI_EXPOSURE_PROFILES = {
    "artex": ("ARTEX family", "ARTEX and related consoles; shared icons and title templates may identify a derivative, not a specific fork.",
              ["ai-artex-shodan-title", "ai-artex-censys-console", "ai-artex-fofa-title", "ai-artex-zoomeye-title",
               "ai-artex-shodan-template", "ai-artex-shodan-favicon"]),
    "cyberstrikeai": ("CyberStrikeAI", "AI security operations console; title, default certificate and icon can change in renamed builds.",
                       ["ai-cyberstrike-shodan-title", "ai-cyberstrike-fofa-cert", "ai-cyberstrike-zoomeye-title", "ai-cyberstrike-shodan-cert",
                        "ai-cyberstrike-shodan-favicon"]),
    "pentagi": ("PentAGI", "AI penetration-testing console; the default CA is a stronger pivot than its title alone.",
                ["ai-pentagi-shodan-cert", "ai-pentagi-fofa-cert", "ai-pentagi-zoomeye-title", "ai-pentagi-shodan-title", "ai-pentagi-shodan-favicon"]),
    "strix": ("Strix", "Finds an optional results viewer, not every Strix installation; the icon is shared by some forks.",
              ["ai-strix-shodan-title", "ai-strix-fofa-title", "ai-strix-zoomeye-viewer", "ai-strix-shodan-favicon"]),
    "scopeweaver": ("ScopeWeaver", "ARTEX-derived console with localized branding; shared ARTEX fingerprints can overlap.",
                    ["ai-scopeweaver-shodan-title", "ai-scopeweaver-zoomeye-title", "ai-scopeweaver-shodan-body"]),
    "agent-zero": ("Agent Zero", "Agent console login; a matching page can be an authorized self-hosted deployment.",
                   ["ai-agentzero-shodan-login", "ai-agentzero-fofa-login"]),
    "redamon": ("RedAmon", "Autonomous reconnaissance console; compare title, page text and favicon.",
                ["ai-redamon-shodan-title", "ai-redamon-shodan-body", "ai-redamon-shodan-favicon"]),
    "cairn": ("Cairn", "AI agent console; a distinctive UI class is more useful than its generic page title.",
              ["ai-cairn-shodan-body", "ai-cairn-shodan-favicon"]),
    "xalgorix": ("Xalgorix", "AI offensive platform; correlate its theme string with the console title.",
                 ["ai-xalgorix-shodan-body", "ai-xalgorix-shodan-title"]),
    "decepticon": ("Decepticon", "AI red-team console; the generic platform phrase needs confirmation on the page.",
                   ["ai-decepticon-shodan-body", "ai-decepticon-shodan-title"]),
    "cyberstrike": ("CyberStrike", "Agent harness console with a title and icon asset; separate from CyberStrikeAI.",
                    ["ai-cyberstrike-shodan-panel", "ai-cyberstrike-fofa-panel"]),
    "redcell": ("redcell", "AI agent console with a distinctive theme marker; confirm its page title.",
                ["ai-redcell-shodan-theme", "ai-redcell-shodan-title"]),
}


def _add_ai_exposure_profiles():
    rules_path = os.path.join(os.path.dirname(__file__), "data", "c2_hunting_rules", "ai_red_team_rules.json")
    with open(rules_path, "r", encoding="utf-8") as source:
        rules = {item["id"]: item for item in json.load(source)}
    for profile_id, (name, description, rule_ids) in AI_EXPOSURE_PROFILES.items():
        selected = [rules[rule_id] for rule_id in rule_ids]
        base = {}
        extra = []
        for item in selected:
            if item["engine"] not in base:
                base[item["engine"]] = item["query"]
            else:
                extra.append((item["id"], item["engine"], item["query"]))
        TOOLS[profile_id] = {"name": name, "category": "AI Red Team", "description": description,
                             "queries": base}
        EXTRA_QUERIES[profile_id] = extra


_add_ai_exposure_profiles()
@contextmanager
def _db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("""CREATE TABLE IF NOT EXISTS snapshots (
            tool_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL, result_json TEXT NOT NULL
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS observed_hosts (
            tool_id TEXT NOT NULL, value_type TEXT NOT NULL, value TEXT NOT NULL,
            port INTEGER NOT NULL, first_checked TEXT NOT NULL, last_checked TEXT NOT NULL,
            host_json TEXT NOT NULL,
            PRIMARY KEY (tool_id, value_type, value, port)
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS observed_hosts_lookup ON observed_hosts(value_type, value)")
        connection.execute("""CREATE TABLE IF NOT EXISTS query_edits (
            tool_id TEXT NOT NULL, query_id TEXT NOT NULL, provider TEXT, query TEXT,
            deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (tool_id, query_id)
        )""")
        yield connection
        connection.commit()
    finally:
        connection.close()


def _latest(tool_id):
    with _db() as db:
        row = db.execute("SELECT result_json FROM snapshots WHERE tool_id=?", (tool_id,)).fetchone()
    return json.loads(row[0]) if row else None


def queries_for(tool_id):
    if tool_id not in TOOLS:
        raise ValueError("Unknown exposure tool")
    queries = {provider: {"id": provider, "provider": provider, "query": query, "origin": "curated"}
               for provider, query in TOOLS[tool_id]["queries"].items()}
    for query_id, provider, query in EXTRA_QUERIES.get(tool_id, []):
        queries[query_id] = {"id": query_id, "provider": provider, "query": query, "origin": "curated"}
    with _db() as db:
        edits = db.execute("SELECT query_id, provider, query, deleted FROM query_edits WHERE tool_id=?", (tool_id,)).fetchall()
    for row in edits:
        if row["deleted"]:
            queries.pop(row["query_id"], None)
        else:
            queries[row["query_id"]] = {"id": row["query_id"], "provider": row["provider"],
                                        "query": row["query"], "origin": "custom" if row["query_id"].startswith("user-") else "edited"}
    return list(queries.values())


def save_query(tool_id, provider, query, query_id=None):
    if tool_id not in TOOLS:
        raise ValueError("Unknown exposure tool")
    provider, query = str(provider or "").strip().lower(), str(query or "").strip()
    if provider not in {"shodan", "fofa", "censys", "zoomeye", "validin"} or not query or len(query) > 4000:
        raise ValueError("Select a supported provider and enter a query under 4000 characters")
    if provider == "validin" and (":" not in query or not all(query.split(":", 1))):
        raise ValueError("Validin fingerprint queries need kind:value syntax")
    if query_id and not any(item["id"] == query_id for item in queries_for(tool_id)):
        raise ValueError("Query not found")
    query_id = query_id or "user-" + uuid.uuid4().hex
    with _LOCK, _db() as db:
        db.execute("INSERT OR REPLACE INTO query_edits (tool_id, query_id, provider, query, deleted) VALUES (?, ?, ?, ?, 0)",
                   (tool_id, query_id, provider, query))
    return {"id": query_id, "provider": provider, "query": query}


def delete_query(tool_id, query_id):
    if not any(item["id"] == query_id for item in queries_for(tool_id)):
        raise ValueError("Query not found")
    with _LOCK, _db() as db:
        db.execute("INSERT OR REPLACE INTO query_edits (tool_id, query_id, deleted) VALUES (?, ?, 1)", (tool_id, query_id))
    return {"deleted": query_id}


def catalog():
    output = []
    for tool_id, spec in TOOLS.items():
        saved = _latest(tool_id)
        output.append({"id": tool_id, "name": spec["name"], "category": spec["category"],
                       "description": spec["description"], "providers": sorted({q["provider"] for q in queries_for(tool_id)}),
                       "queries": queries_for(tool_id),
                       "observed_at": saved.get("observed_at") if saved else None,
                       "count": len(saved.get("hosts", [])) if saved else None,
                       "new_count": saved.get("new_count") if saved else None,
                       "countries": sorted({h.get("country", "") for h in saved.get("hosts", []) if h.get("country")}) if saved else [],
                       "provider_status": saved.get("provider_status", {}) if saved else {}})
    return {"tools": output, "method": "passive indexed observations; not a live C2 verdict"}


def detail(tool_id):
    if tool_id not in TOOLS:
        raise ValueError("Unknown exposure tool")
    return _latest(tool_id) or {"tool_id": tool_id, "hosts": [], "observed_at": None,
                                "provider_status": {}, "new_count": 0}


def _canonical_value(value, value_type):
    value = str(value or "").strip()
    if value_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return ""
    if value_type == "domain":
        return value.lower().rstrip(".")
    return ""


def _save_observed_host(db, tool_id, host, checked):
    value_type = host.get("value_type")
    canonical = _canonical_value(host.get("value"), value_type)
    if not canonical:
        return
    db.execute("""INSERT INTO observed_hosts
        (tool_id, value_type, value, port, first_checked, last_checked, host_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tool_id, value_type, value, port) DO UPDATE SET
            last_checked=MAX(observed_hosts.last_checked, excluded.last_checked),
            host_json=CASE WHEN excluded.last_checked >= observed_hosts.last_checked
                THEN excluded.host_json ELSE observed_hosts.host_json END""",
        (tool_id, value_type, canonical, host.get("port") or 0, checked, checked, json.dumps(host)))


def lookup(value, value_type):
    """Exact IOC match against saved observations; never triggers provider searches."""
    canonical = _canonical_value(value, value_type)
    if not canonical:
        return {"matches": [], "note": "No saved C2 exposure observations for this indicator."}
    matches = {}
    with _db() as db:
        rows = db.execute(
            "SELECT tool_id, port, first_checked, last_checked, host_json FROM observed_hosts WHERE value_type=? AND value=?",
            (value_type, canonical),
        ).fetchall()
        snapshots = db.execute("SELECT tool_id, observed_at, result_json FROM snapshots").fetchall()
    for row in rows:
        host = json.loads(row["host_json"])
        matches[(row["tool_id"], row["port"])] = (host, row["last_checked"], row["first_checked"], False)
    for snapshot in snapshots:
        for host in json.loads(snapshot["result_json"]).get("hosts", []):
            if host.get("value_type") != value_type or _canonical_value(host.get("value"), value_type) != canonical:
                continue
            key = (snapshot["tool_id"], host.get("port") or 0)
            first = matches[key][2] if key in matches else snapshot["observed_at"]
            matches[key] = (host, snapshot["observed_at"], first, True)
    output = []
    for (tool_id, port), (host, checked, first, latest) in matches.items():
        spec = TOOLS.get(tool_id, {})
        output.append({"tool_id": tool_id, "name": spec.get("name", tool_id),
                       "category": spec.get("category", "C2 exposure"), "value": canonical,
                       "port": port or None, "country": host.get("country") or "",
                       "service": host.get("service") or "", "title": host.get("title") or "",
                       "confidence": host.get("confidence") or "single source",
                       "providers": sorted({e.get("provider", "") for e in host.get("evidence", []) if e.get("provider")}),
                       "first_checked": first, "last_checked": checked, "in_latest_snapshot": latest})
    output.sort(key=lambda item: (not item["in_latest_snapshot"], item["name"], item["port"] or 0))
    return {"matches": output, "note": "Saved passive search-index leads. A match does not confirm an active or malicious C2 server."}


def _search(provider, query, api_key, shodan_pages=100):
    if provider == "shodan":
        result = intel_query.query_shodan_search(query, api_key, query_type="shodan_query")
        if result.get("error") or shodan_pages <= 1:
            return result
        normalized = result.get("normalized") or {}
        total = normalized.get("total") or 0
        matches = list(normalized.get("matches") or [])
        fetched = 1
        for page in range(2, min(shodan_pages, (total + 99) // 100) + 1):
            time.sleep(1.0)
            next_result = intel_query.query_shodan_search(query, api_key, page=page, query_type="shodan_query")
            if next_result.get("error"):
                result["partial_error"] = str(next_result["error"])[:200]
                break
            rows = (next_result.get("normalized") or {}).get("matches") or []
            if not rows:
                break
            matches.extend(rows)
            fetched = page
        normalized["matches"] = matches
        normalized["pages_fetched"] = fetched
        return result
    if provider == "fofa":
        return intel_query.query_fofa(query, api_key, query_type="fofa_query", size=50)
    if provider == "censys":
        return intel_query.query_censys_search(query, api_key, query_type="censys_query", page_size=50)
    if provider == "zoomeye":
        return intel_query.query_zoomeye_search(query, api_key, pagesize=50)
    if provider == "validin":
        kind, value = query.split(":", 1)
        return intel_query.query_validin_fingerprint(value, kind, api_key, limit=50)
    return {"error": "Unsupported provider"}


def _row_value(row, *keys):
    for key in keys:
        value = row
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value not in (None, "", [], {}):
            return value
    return ""


def _normalize(provider, query, row):
    value, value_type = _candidate_identity(row)
    if not value or value_type not in {"ip", "domain"}:
        return None
    port = _row_value(row, "port", "service.port", "services.port")
    services = row.get("services") if isinstance(row.get("services"), list) else []
    if port == "" and services and isinstance(services[0], dict):
        port = services[0].get("port") or ""
    try:
        port = int(port) if port != "" else None
    except (ValueError, TypeError):
        port = None
    if port is not None and not 1 <= port <= 65535:
        port = None
    observed = _row_value(row, "last_seen", "last_updated", "observed", "timestamp", "update_time")
    service = _row_value(row, "product", "service", "protocol")
    if isinstance(service, dict):
        service = service.get("name") or service.get("product") or ""
    return {"value": value, "value_type": value_type, "port": port,
            "country": str(_row_value(row, "country", "location.country_name", "location.country") or "")[:80],
            "title": str(_row_value(row, "title", "http_title", "http.title", "services.http.response.html_title") or "")[:180],
            "service": str(service or "")[:100],
            "last_seen": str(observed or "")[:50],
            "evidence": {"provider": provider, "query": query,
                         "observed_at": str(observed or "")[:50]}}


def refresh(tool_id, keys):
    if tool_id not in TOOLS:
        raise ValueError("Unknown exposure tool")
    spec = TOOLS[tool_id]
    selected = [(item["provider"], item["query"], str(keys.get(item["provider"] + "_key") or "").strip())
                for item in queries_for(tool_id)]
    configured = [(provider, query, key) for provider, query, key in selected if key]
    shodan_pages = max(1, min(100, int(keys.get("shodan_pages") or 100)))
    if not configured:
        raise ValueError("Configure an API key for at least one supported provider in Settings")
    previous = _latest(tool_id)
    previous_keys = {(h["value"], h.get("port")) for h in previous.get("hosts", [])} if previous else set()
    status = {provider: {"status": "not configured"} for provider, _, key in selected if not key}
    provider_runs = {provider: {"ok": 0, "returned": 0, "errors": []} for provider, _, _ in configured}
    merged = {}
    with ThreadPoolExecutor(max_workers=min(4, len(configured))) as pool:
        tasks = {pool.submit(_search, provider, query, key, shodan_pages): (provider, query)
                 for provider, query, key in configured}
        for future in as_completed(tasks):
            provider, query = tasks[future]
            try:
                result = future.result()
                if not isinstance(result, dict) or result.get("error"):
                    provider_runs[provider]["errors"].append(str(result.get("error") if isinstance(result, dict) else "Unexpected response")[:200])
                    continue
                rows = _candidate_rows(provider, result)
                if provider != "shodan":
                    rows = rows[:100]
                provider_runs[provider]["ok"] += 1
                provider_runs[provider]["returned"] += len(rows)
                if provider == "shodan":
                    provider_runs[provider]["total"] = provider_runs[provider].get("total", 0) + int((result.get("normalized") or {}).get("total") or len(rows))
                    provider_runs[provider]["pages_fetched"] = max(provider_runs[provider].get("pages_fetched", 1), int((result.get("normalized") or {}).get("pages_fetched") or 1))
                if result.get("partial_error"):
                    provider_runs[provider]["errors"].append(result["partial_error"])
                for row in rows:
                    item = _normalize(provider, query, row)
                    if not item:
                        continue
                    identity = (item["value"], item["port"])
                    if identity not in merged:
                        merged[identity] = item
                        merged[identity]["evidence"] = [item["evidence"]]
                    elif not any(e["provider"] == provider and e["query"] == query for e in merged[identity]["evidence"]):
                        merged[identity]["evidence"].append(item["evidence"])
            except Exception as exc:
                provider_runs[provider]["errors"].append(str(exc)[:200])
    for provider, run in provider_runs.items():
        status[provider] = ({"status": "ok", "returned": run["returned"], "queries_succeeded": run["ok"],
                             "queries_failed": len(run["errors"]),
                             **({"total": run.get("total", run["returned"]), "pages_fetched": run.get("pages_fetched", 1), "queries_run": run["ok"]} if provider == "shodan" else {}),
                             **({"message": "; ".join(run["errors"])[:200]} if run["errors"] else {})} if run["ok"] else
                            {"status": "error", "message": "; ".join(run["errors"])[:200]})
    if not any(entry["status"] == "ok" for entry in status.values()):
        raise ValueError("All configured provider queries failed; previous snapshot was kept")
    hosts = sorted(merged.values(), key=lambda h: (-len({e["provider"] for e in h["evidence"]}), h["value"], h["port"] or 0))
    previous_ok = {p for p, item in (previous or {}).get("provider_status", {}).items() if item.get("status") == "ok"}
    current_ok = {p for p, item in status.items() if item.get("status") == "ok"}
    query_set = [list(pair) for pair in sorted((provider, query) for provider, query, _ in configured)]
    comparable = (previous is not None and previous_ok == current_ok
                  and previous.get("query_set") == query_set
                  and previous.get("shodan_pages", 1) == shodan_pages)
    for host in hosts:
        host["new"] = comparable and (host["value"], host["port"]) not in previous_keys
        host["confidence"] = "corroborated" if len({e["provider"] for e in host["evidence"]}) > 1 else "single source"
    snapshot = {"tool_id": tool_id, "name": spec["name"], "category": spec["category"],
                "observed_at": datetime.now(timezone.utc).isoformat(), "hosts": hosts,
                "new_count": sum(h["new"] for h in hosts) if comparable else None, "provider_status": status,
                "comparison_available": comparable, "query_set": query_set, "shodan_pages": shodan_pages,
                "note": f"Shodan: all available pages up to the API's 100-page limit per query; other providers: first page. Search API permissions, credits, or page limits may prevent complete retrieval. Indexed leads are not proof that a host is currently online or malicious."}
    with _LOCK, _db() as db:
        # Keep observations from databases created before the historical index existed.
        if previous:
            for host in previous.get("hosts", []):
                _save_observed_host(db, tool_id, host, previous["observed_at"])
        db.execute("INSERT OR REPLACE INTO snapshots (tool_id, observed_at, result_json) VALUES (?, ?, ?)",
                   (tool_id, snapshot["observed_at"], json.dumps(snapshot)))
        for host in hosts:
            _save_observed_host(db, tool_id, host, snapshot["observed_at"])
    return snapshot
