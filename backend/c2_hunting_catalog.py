"""
C2 & Infrastructure Hunting Playbook Catalog
Ingests and indexes curated hunting queries from:
- Awesome-Malicious-Infra-Hunting-Queries (Shodan, Censys, Netlas)
- 0x4bdo C2-Hunting (URLScan C2 queries, SHA-256 hashes, Favicon MMH3 hashes)
"""

import os
import re
import json
import urllib.parse
from typing import List, Dict, Any, Optional

CATALOG_DIR = os.path.join(os.path.dirname(__file__), "data", "c2_hunting_rules")
CACHE_FILE = os.path.join(CATALOG_DIR, "compiled_catalog.json")

# In-memory store
_CATALOG_CACHE: Optional[List[Dict[str, Any]]] = None
_FAVICON_LOOKUP: Dict[str, str] = {}
_JARM_LOOKUP: Dict[str, str] = {}


def _get_external_url(engine: str, query: str) -> str:
    engine = (engine or "").lower().strip()
    query = (query or "").strip()
    if not query:
        return ""

    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
    is_pure_ip = bool(re.match(r'^(?:net:)?(?:ip:)?\s*"?((?:\d{1,3}\.){3}\d{1,3})"?$', query))
    is_pure_domain = bool(re.match(r'^(?:domain:)?\s*"?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"?$', query)) and not is_pure_ip
    raw_ip = ip_match.group(0) if ip_match else ""

    if engine == "shodan":
        if is_pure_ip and raw_ip:
            return f"https://www.shodan.io/host/{raw_ip}"
        clean_q = re.sub(r'\bip:"?([0-9.]+)"?', r'net:\1', query)
        clean_q = re.sub(r'\basn:"?(?:AS)?(\d+)"?', r'asn:AS\1', clean_q)
        return f"https://www.shodan.io/search?query={urllib.parse.quote(clean_q)}"

    elif engine == "censys":
        if is_pure_ip and raw_ip:
            return f"https://search.censys.io/hosts/{raw_ip}"
        clean_q = re.sub(r'\bip\s*:\s*"([0-9.]+)"', r'ip: \1', query)
        return f"https://search.censys.io/search?resource=hosts&q={urllib.parse.quote(clean_q)}"

    elif engine == "fofa":
        import base64
        b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
        return f"https://fofa.info/result?qbase64={b64}"

    elif engine == "netlas":
        clean_q = re.sub(r'\bip:"([0-9.]+)"', r'ip:\1', query)
        return f"https://app.netlas.io/responses/?q={urllib.parse.quote(clean_q)}"

    elif engine == "urlscan":
        if is_pure_ip and raw_ip:
            return f"https://urlscan.io/ip/{raw_ip}"
        if is_pure_domain:
            dom = re.sub(r'^domain:\s*"?|"?$', '', query)
            return f"https://urlscan.io/domain/{dom}"
        clean_q = re.sub(r'files\.sha256:"?([a-f0-9]{64})"?', r'hash:\1', query, flags=re.IGNORECASE)
        frag = urllib.parse.quote(clean_q, safe=':="/+*')
        return f"https://urlscan.io/search/#{frag}"

    elif engine == "greynoise":
        if is_pure_ip and raw_ip:
            return f"https://viz.greynoise.io/ip/{raw_ip}"
        return f"https://viz.greynoise.io/query?gnql={urllib.parse.quote(query)}"

    elif engine == "etugen":
        if is_pure_ip and raw_ip:
            return f"https://app.etugen.io/trashpile/host/{raw_ip}"
        return f"https://app.etugen.io/search?q={urllib.parse.quote(query)}"

    elif engine == "validin":
        if is_pure_ip and raw_ip:
            return f"https://app.validin.com/ip/{raw_ip}"
        if is_pure_domain:
            dom = re.sub(r'^domain:\s*"?|"?$', '', query)
            return f"https://app.validin.com/domain/{dom}"
        return f"https://app.validin.com/search?q={urllib.parse.quote(query)}"

    elif engine == "zoomeye":
        if is_pure_ip and raw_ip:
            return f"https://www.zoomeye.ai/searchResult?q=ip%3D%22{raw_ip}%22"
        return f"https://www.zoomeye.ai/searchResult?q={urllib.parse.quote(query)}"

    return ""


def _categorize_family(family: str, tech: str) -> str:
    f_lower = (family + " " + tech).lower()
    if any(k in f_lower for k in ["opendir", "open directory", "git exposure", "bash_history", "secrets", "backup", "trashpile"]):
        return "Exposed OpenDir / Secrets"
    if "webshell" in f_lower:
        return "Webshell"
    if any(k in f_lower for k in ["hacktool", "password-cracking", "exploit"]):
        return "Hacktool"
    if "tunnel" in f_lower:
        return "Tunnel / Proxy"
    if "botnet" in f_lower:
        return "Botnet"
    if any(k in f_lower for k in ["phish", "gophish", "evilginx", "modlishka"]):
        return "Phishing Framework"
    if any(k in f_lower for k in ["stealer", "collector", "redline", "vidar", "raccoon", "mars", "stealc", "lumma", "luma", "meduza", "risepro"]):
        return "Info Stealer"
    if any(k in f_lower for k in ["rat", "asyncrat", "quasar", "orcus", "dcrat", "remcos", "njrat", "warzone", "nanocore", "hookbot"]):
        return "RAT"
    if any(k in f_lower for k in ["trojan", "banking", "icedid", "gozi", "bokbot", "qakbot", "trickbot", "dridex"]):
        return "Banking Trojan"
    if any(k in f_lower for k in ["ransom", "lockbit", "blackcat", "alphv", "ransomhub"]):
        return "Ransomware"
    if any(k in f_lower for k in ["apt", "winnti", "barium", "lazarus", "mustang", "sandworm", "turla", "charming"]):
        return "APT Infrastructure"
    if "favicon" in f_lower:
        return "Favicon Fingerprint"
    return "C2 Framework"


def parse_all_rules() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []

    # 1. Favicon Hashes
    fav_file = os.path.join(CATALOG_DIR, "favicon_hashes.md")
    if os.path.isfile(fav_file):
        with open(fav_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[0].isdigit():
                    name = " ".join(parts[1:-1])
                    hash_val = parts[-1]
                    _FAVICON_LOOKUP[hash_val] = name

                    # Generate Shodan query
                    shodan_q = f"http.favicon.hash:{hash_val}"
                    items.append({
                        "id": f"fav-shodan-{hash_val}",
                        "family": name,
                        "category": _categorize_family(name, "Favicon Hash"),
                        "technique": "Murmur3 Favicon Hash",
                        "engine": "shodan",
                        "query": shodan_q,
                        "external_url": _get_external_url("shodan", shodan_q),
                        "notes": f"MMH3 Favicon Hash: {hash_val}",
                        "hash_value": hash_val
                    })

                    # Generate FOFA query
                    fofa_q = f'icon_hash="{hash_val}"'
                    items.append({
                        "id": f"fav-fofa-{hash_val}",
                        "family": name,
                        "category": _categorize_family(name, "Favicon Hash"),
                        "technique": "Favicon Icon Hash",
                        "engine": "fofa",
                        "query": fofa_q,
                        "external_url": _get_external_url("fofa", fofa_q),
                        "notes": f"MMH3 Favicon Hash: {hash_val}",
                        "hash_value": hash_val
                    })

                    # Generate Netlas query
                    netlas_q = f"http.favicon.hash_mmh3:{hash_val}"
                    items.append({
                        "id": f"fav-netlas-{hash_val}",
                        "family": name,
                        "category": _categorize_family(name, "Favicon Hash"),
                        "technique": "Favicon MMH3",
                        "engine": "netlas",
                        "query": netlas_q,
                        "external_url": _get_external_url("netlas", netlas_q),
                        "notes": f"MMH3 Favicon Hash: {hash_val}",
                        "hash_value": hash_val
                    })

    # 2. URLScan SHA256 Hashes
    sha_file = os.path.join(CATALOG_DIR, "urlscan_sha256.md")
    if os.path.isfile(sha_file):
        with open(sha_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 4 and parts[1].isdigit():
                        name = parts[2]
                        sha = parts[3]
                        if len(sha) == 64:
                            q = f'files.sha256:"{sha}"'
                            items.append({
                                "id": f"urlscan-sha-{sha[:12]}",
                                "family": name,
                                "category": _categorize_family(name, "Payload Hash"),
                                "technique": "File SHA-256 Hash",
                                "engine": "urlscan",
                                "query": q,
                                "external_url": _get_external_url("urlscan", q),
                                "notes": f"Associated Payload SHA256: {sha}",
                                "hash_value": sha
                            })

    # 3. URLScan Generic C2 Queries
    urlscan_q_file = os.path.join(CATALOG_DIR, "urlscan_queries.md")
    if os.path.isfile(urlscan_q_file):
        with open(urlscan_q_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or not (line[0].isdigit() and "-" in line[:4]):
                    continue
                q = line.split("-", 1)[1].strip().strip('"').strip("“").strip("”")
                if q:
                    items.append({
                        "id": f"urlscan-dork-{len(items)}",
                        "family": "C2 Threat Feed",
                        "category": "C2 Framework",
                        "technique": "Community Tag / Dork",
                        "engine": "urlscan",
                        "query": q,
                        "external_url": _get_external_url("urlscan", q),
                        "notes": "URLScan hunting query for active threat/c2 scans",
                    })

    # 4. Helper for Shodan, Censys, Netlas MD parsing
    engine_files = [
        ("shodan", os.path.join(CATALOG_DIR, "shodan_queries.md")),
        ("censys", os.path.join(CATALOG_DIR, "censys_queries.md")),
        ("netlas", os.path.join(CATALOG_DIR, "netlas_queries.md")),
    ]

    for engine, fpath in engine_files:
        if not os.path.isfile(fpath):
            continue
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        sections = re.split(r"\n##\s+", text)
        for sec in sections[1:]:
            lines = sec.split("\n")
            sec_title = lines[0].strip()
            if any(k in sec_title for k in ["Table of Contents", "Platform Syntax", "Netlas Featured"]):
                continue

            sub_parts = re.split(r"\n###\s+", sec)
            family = sub_parts[0].split("\n")[0].strip()
            # Clean up icons or extra notes from family
            family = re.sub(r"^[^\w\s]+", "", family).strip()
            if not family:
                family = "Unknown C2"

            for sub in sub_parts[1:]:
                sub_lines = sub.split("\n")
                tech = sub_lines[0].strip()
                tech = re.sub(r"^[^\w\s]+", "", tech).strip()

                queries = re.findall(r"```(?:bash|shodan|censys|sql|netlas|text)?\s*\n([\s\S]*?)\n```", sub)
                for q_block in queries:
                    for q_line in q_block.strip().split("\n"):
                        q_line = q_line.strip()
                        if not q_line or q_line.startswith("#") or q_line.startswith("curl"):
                            continue
                        # If JARM in query, register in lookup
                        jarm_match = re.search(r'jarm[:=" ]+([a-f0-9]{62})', q_line, re.IGNORECASE)
                        if jarm_match:
                            _JARM_LOOKUP[jarm_match.group(1).lower()] = family

                        items.append({
                            "id": f"{engine}-{len(items)}",
                            "family": family,
                            "category": _categorize_family(family, tech),
                            "technique": tech or "Detection Rule",
                            "engine": engine,
                            "query": q_line,
                            "external_url": _get_external_url(engine, q_line),
                            "notes": f"{family} -> {tech}"
                        })

    # 5. OpenHunting.io Censys Threat Rules (PDF: Threat Hunting Malware Infrastructure)
    openhunting_file = os.path.join(CATALOG_DIR, "openhunting_censys.json")
    if os.path.isfile(openhunting_file):
        try:
            with open(openhunting_file, "r", encoding="utf-8") as f:
                oh_items = json.load(f)
                for entry in oh_items:
                    q = entry.get("query", "")
                    items.append({
                        "id": f"openhunting-{len(items)}",
                        "family": entry.get("family", "Unknown"),
                        "category": entry.get("category", "C2 Framework"),
                        "technique": entry.get("technique", "Signature Rule"),
                        "engine": "censys",
                        "query": q,
                        "external_url": _get_external_url("censys", q),
                        "notes": entry.get("notes", "OpenHunting.io threat hunting query")
                    })
        except Exception:
            pass

    # 6. Etugen Threat Rules & Search Templates
    etugen_file = os.path.join(CATALOG_DIR, "etugen_rules.json")
    if os.path.isfile(etugen_file):
        try:
            with open(etugen_file, "r", encoding="utf-8") as f:
                etugen_items = json.load(f)
                for entry in etugen_items:
                    q = entry.get("query", "")
                    entry["external_url"] = _get_external_url("etugen", q)
                    items.append(entry)
        except Exception:
            pass

    # 7. Silent Push Threat Hunting Cheatsheet Rules
    sp_file = os.path.join(CATALOG_DIR, "silentpush_rules.json")
    if os.path.isfile(sp_file):
        try:
            with open(sp_file, "r", encoding="utf-8") as f:
                sp_items = json.load(f)
                for entry in sp_items:
                    q = entry.get("query", "")
                    entry["external_url"] = _get_external_url("silentpush", q)
                    items.append(entry)
        except Exception:
            pass

    # 8. Validin Threat Hunting VQL Rules
    val_file = os.path.join(CATALOG_DIR, "validin_rules.json")
    if os.path.isfile(val_file):
        try:
            with open(val_file, "r", encoding="utf-8") as f:
                val_items = json.load(f)
                for entry in val_items:
                    q = entry.get("query", "")
                    entry["external_url"] = _get_external_url("validin", q)
                    items.append(entry)
        except Exception:
            pass

    # 9. Embee Research Malware Infrastructure Rules
    embee_file = os.path.join(CATALOG_DIR, "embeeresearch_rules.json")
    if os.path.isfile(embee_file):
        try:
            with open(embee_file, "r", encoding="utf-8") as f:
                embee_items = json.load(f)
                for entry in embee_items:
                    eng = entry.get("engine", "censys")
                    q = entry.get("query", "")
                    entry["external_url"] = _get_external_url(eng, q)
                    items.append(entry)
        except Exception:
            pass

    # 10. ZoomEye Cyberspace Search Rules & Staging Templates
    zoomeye_file = os.path.join(CATALOG_DIR, "zoomeye_rules.json")
    if os.path.isfile(zoomeye_file):
        try:
            with open(zoomeye_file, "r", encoding="utf-8") as f:
                zoomeye_items = json.load(f)
                for entry in zoomeye_items:
                    q = entry.get("query", "")
                    entry["external_url"] = _get_external_url("zoomeye", q)
                    items.append(entry)
        except Exception:
            pass

    return items


def get_catalog() -> List[Dict[str, Any]]:
    global _CATALOG_CACHE
    if _CATALOG_CACHE is not None:
        return _CATALOG_CACHE

    if os.path.isfile(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                _CATALOG_CACHE = json.load(f)
                # rebuild lookups
                for item in _CATALOG_CACHE:
                    if "hash_value" in item and item["technique"] == "Murmur3 Favicon Hash":
                        _FAVICON_LOOKUP[str(item["hash_value"])] = item["family"]
                return _CATALOG_CACHE
        except Exception:
            pass

    _CATALOG_CACHE = parse_all_rules()
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_CATALOG_CACHE, f)
    except Exception:
        pass

    return _CATALOG_CACHE


def query_playbooks(q: str = "", engine: str = "", family: str = "", category: str = "", limit: int = 150, offset: int = 0) -> Dict[str, Any]:
    catalog = get_catalog()
    q_norm = (q or "").strip().lower()
    engine_norm = (engine or "").strip().lower()
    family_norm = (family or "").strip().lower()
    cat_norm = (category or "").strip().lower()

    filtered = []
    for item in catalog:
        if engine_norm and engine_norm != "all" and item["engine"].lower() != engine_norm:
            continue
        if cat_norm and cat_norm != "all" and item["category"].lower() != cat_norm:
            continue
        if family_norm and family_norm != "all" and family_norm not in item["family"].lower():
            continue
        if q_norm:
            haystack = (item["family"] + " " + item["technique"] + " " + item["category"] + " " + item["query"] + " " + item.get("notes", "")).lower()
            if q_norm not in haystack:
                continue
        filtered.append(item)

    # Aggregates for filter UI
    engines_count: Dict[str, int] = {}
    categories_count: Dict[str, int] = {}
    for item in catalog:
        eng = item["engine"].lower()
        engines_count[eng] = engines_count.get(eng, 0) + 1
        cat = item["category"]
        categories_count[cat] = categories_count.get(cat, 0) + 1

    total = len(filtered)
    paged = filtered[offset: offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": paged,
        "aggregates": {
            "engines": engines_count,
            "categories": categories_count
        }
    }


def match_seed_c2(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Checks extracted seed features against known C2 profiles (Favicon hashes, JARM, SSL DN).
    """
    catalog = get_catalog()
    matches: List[Dict[str, Any]] = []
    seen_families = set()

    # Extract all feature signals
    ranked = features.get("ranked", []) if isinstance(features, dict) else []
    by_type = features.get("by_type", {}) if isinstance(features, dict) else {}

    signals_by_kind: Dict[str, List[str]] = {}
    for s in ranked:
        k = s.get("kind", "")
        v = str(s.get("value", "")).strip().lower()
        if k and v:
            signals_by_kind.setdefault(k, []).append(v)

    # 1. Match Favicon Hash
    fav_values = signals_by_kind.get("favicon_mmh3", []) + signals_by_kind.get("favicon_md5", [])
    for fav in fav_values:
        for f_hash, f_name in _FAVICON_LOOKUP.items():
            if str(f_hash).lower() == fav or fav in str(f_hash).lower():
                if f_name not in seen_families:
                    seen_families.add(f_name)
                    # Pull queries for this family
                    family_queries = [item for item in catalog if item["family"] == f_name][:5]
                    matches.append({
                        "family": f_name,
                        "category": _categorize_family(f_name, "Favicon Hash"),
                        "matched_by": "favicon_hash",
                        "matched_value": fav,
                        "confidence": "HIGH",
                        "description": f"Observed favicon MMH3 hash {fav} directly matches known {f_name} management/C2 panel.",
                        "recommended_queries": family_queries
                    })

    # 2. Match JARM
    jarm_values = signals_by_kind.get("jarm", [])
    for jarm in jarm_values:
        for j_hash, j_name in _JARM_LOOKUP.items():
            if jarm == j_hash:
                if j_name not in seen_families:
                    seen_families.add(j_name)
                    family_queries = [item for item in catalog if item["family"] == j_name][:5]
                    matches.append({
                        "family": j_name,
                        "category": _categorize_family(j_name, "JARM"),
                        "matched_by": "jarm",
                        "matched_value": jarm,
                        "confidence": "HIGH",
                        "description": f"Observed JARM fingerprint {jarm} matches known {j_name} profile.",
                        "recommended_queries": family_queries
                    })

    return matches
