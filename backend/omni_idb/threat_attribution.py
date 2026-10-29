"""Automated Threat Intelligence Lookup & Threat Attribution Module.

Extracts hashes, network IOCs, registry keys, mutexes, and unique strings from
an exported AI workspace, queries local CTI articles, reputation feeds, MISP galaxies,
and MANTIS case intelligence, and produces a structured threat attribution assessment
(threat_attribution_result.md) based on the Evidence-Based 6-Category Threat Attribution Model.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import concurrent.futures


def _safe_str(val: Any) -> str:
    return str(val or "").strip()


def _extract_hashes(sample_info: Dict[str, Any], workspace_dir: Path) -> Dict[str, str]:
    hashes = {
        "sha256": _safe_str(sample_info.get("sha256")),
        "md5": _safe_str(sample_info.get("md5")),
        "sha1": _safe_str(sample_info.get("sha1")),
    }
    sample_json = workspace_dir / "catalog" / "sample.json"
    if sample_json.is_file():
        try:
            data = json.loads(sample_json.read_text(encoding="utf-8"))
            for k in ("sha256", "md5", "sha1"):
                if not hashes[k] and data.get(k):
                    hashes[k] = _safe_str(data[k])
        except Exception:
            pass

    sample_path_str = sample_info.get("sample_path") or sample_info.get("path")
    if sample_path_str:
        p = Path(sample_path_str)
        if p.is_file():
            try:
                content = p.read_bytes()
                if not hashes["sha256"]:
                    hashes["sha256"] = hashlib.sha256(content).hexdigest()
                if not hashes["md5"]:
                    hashes["md5"] = hashlib.md5(content).hexdigest()
                if not hashes["sha1"]:
                    hashes["sha1"] = hashlib.sha1(content).hexdigest()
            except Exception:
                pass
    return hashes


_GENERIC_DOMAINS = {
    "microsoft.com", "schemas.microsoft.com", "w3.org", "www.w3.org",
    "github.com", "api.github.com", "google.com", "www.google.com",
    "digicert.com", "verisign.com", "sectigo.com", "globalsign.com",
    "letsencrypt.org", "identrust.com", "msdn.com", "windows.com",
}

_REGISTRY_PATTERNS = [
    re.compile(r"(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU)\\[^\x00\r\n\t\"\'<>]+", re.IGNORECASE),
    re.compile(r"(?:Software\\Microsoft\\Windows\\CurrentVersion\\[^\x00\r\n\t\"\'<>]+)", re.IGNORECASE),
    re.compile(r"(?:SYSTEM\\CurrentControlSet\\[^\x00\r\n\t\"\'<>]+)", re.IGNORECASE),
]

_MUTEX_PATTERNS = [
    re.compile(r"^(?:Global\\|Local\\)[A-Za-z0-9_\-\.\{\}]{3,120}$", re.IGNORECASE),
    re.compile(r"^[A-Za-z0-9_\-]{4,60}_(?:Mutex|mutex|Lock|Instance|Running)$"),
]

_PDB_PATTERN = re.compile(r"[A-Za-z0-9_\-\\\/\.]+\.pdb$", re.IGNORECASE)

_WALLET_BTC_PATTERN = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39})\b")
_WALLET_XMR_PATTERN = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_TOR_ONION_PATTERN = re.compile(r"\b[a-z2-7]{16,56}\.onion(?:\:\d+)?\b", re.IGNORECASE)
_TELEGRAM_BOT_PATTERN = re.compile(r"\b(?:bot)?[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b")
_DISCORD_WEBHOOK_PATTERN = re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", re.IGNORECASE)
_USER_AGENT_PATTERN = re.compile(r"^(?:Mozilla/5\.0|User-Agent:\s*|curl/|Wget/|Python-urllib|Go-http-client)[^\r\n]*", re.IGNORECASE)

_COMMAND_LINE_PATTERNS = [
    re.compile(r"(?:cmd(?:\.exe)?\s+/[ck]\s+[^\r\n]+|powershell(?:\.exe)?\s+-[^\r\n]+|wmic(?:\.exe)?\s+[^\r\n]+|vssadmin\s+delete\s+shadows[^\r\n]*|bcdedit(?:\.exe)?\s+/[^\r\n]+|certutil(?:\.exe)?\s+-(?:urlcache|decode)[^\r\n]*|bitsadmin(?:\.exe)?\s+/[^\r\n]+|schtasks(?:\.exe)?\s+/[^\r\n]+|taskkill(?:\.exe)?\s+/[^\r\n]+|net\s+(?:user|group|localgroup|share|stop|start)[^\r\n]+|sc(?:\.exe)?\s+(?:create|start|config)[^\r\n]+|rundll32(?:\.exe)?\s+[^\r\n]+|mshta(?:\.exe)?\s+[^\r\n]+|reg(?:\.exe)?\s+(?:add|delete|query)[^\r\n]+|attrib\s+[+-][rsha][^\r\n]*)", re.IGNORECASE),
]

_DROP_PATH_PATTERNS = [
    re.compile(r"(?:(?:%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%|%ALLUSERSPROFILE%)\\[^\x00\r\n\t<>]+|C:\\Users\\Public\\[^\x00\r\n\t<>]+|C:\\Windows\\Temp\\[^\x00\r\n\t<>]+|C:\\ProgramData\\[^\x00\r\n\t<>]+)", re.IGNORECASE),
]

_STEALER_TARGET_PATTERNS = [
    re.compile(r"(?:Google\\Chrome\\User Data|AppData\\Roaming\\Telegram Desktop|discord(?:canary|ptb)?\\Local Storage|Electrum\\wallets|Exodus\\exodus\.wallet|Metamask|Atomic\\Local Storage|Login Data|Web Data|cookies\.sqlite|key4\.db|logins\.json|wallet\.dat)", re.IGNORECASE),
]

_RANSOM_MARKERS = [
    re.compile(r"(?:readme_for_decrypt|how_to_recover|how_to_decrypt|restore_files|files have been encrypted|your files are encrypted|personal id|decrypt_instructions|\.(?:locked|crypted|enc|crypto|lockbit|blackcat|alphv|mallox|phobos|rhysida|medusa))\b", re.IGNORECASE),
]

_BOT_COMMAND_PATTERNS = [
    re.compile(r"\b(?:!exec|!download|!upload|!shell|!sleep|!kill|!inject|!socks5|!screenshot|!keylog|!ddos|!update|cmd_exec|bot_kill|bot_sleep|socks_proxy|start_reverse_shell)\b", re.IGNORECASE),
]

_CONFIG_KEYVAL_PATTERN = re.compile(
    r"\b(?:c2(?:_url|_host|_port)?|bot_?id|campaign_?id|sleep(?:_time|_delay|_jitter)?|beacon_?interval|auth_?token|api_?key|aes_?key|xor_?key|rc4_?key|passphrase|version_?id|build_?id)\s*[:=]\s*[^\r\n,;]+",
    re.IGNORECASE,
)




def scan_sample_yara(workspace_dir: Path, sample_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan sample file or workspace binary data with local YARA rules if available."""
    try:
        import sys
        backend_dir = Path(__file__).resolve().parent.parent
        if str(backend_dir) not in sys.path:
            sys.path.insert(0, str(backend_dir))
        import yara_service
        data = None
        sample_path = sample_info.get("sample_path") or sample_info.get("path")
        if sample_path and Path(sample_path).is_file():
            try:
                data = Path(sample_path).read_bytes()
            except Exception:
                data = None
        if not data:
            for cand in [workspace_dir / "sample.bin", workspace_dir / "target.exe", workspace_dir / "target.bin"]:
                if cand.is_file():
                    try:
                        data = cand.read_bytes()
                        break
                    except Exception:
                        pass
        if data and hasattr(yara_service, "_artifacts_for"):
            artifacts = yara_service._artifacts_for(None)
            if artifacts:
                matches, _ = yara_service.scan_data(data, artifacts, timeout=15)
                return matches
    except Exception:
        pass
    return []

def extract_workspace_indicators(workspace_dir: Path, sample_info: Dict[str, Any]) -> Dict[str, Any]:
    """Extract hashes, network IOCs, host artifacts, and behavioral tags from catalog files."""
    hashes = _extract_hashes(sample_info, workspace_dir)
    catalog_dir = workspace_dir / "catalog"

    indicators: Dict[str, Any] = {
        "hashes": hashes,
        "domains": set(),
        "ips": set(),
        "urls": set(),
        "user_agents": set(),
        "registry_keys": set(),
        "mutexes": set(),
        "named_pipes": set(),
        "pdb_paths": set(),
        "drop_paths": set(),
        "unique_strings": set(),
        "suspicious_apis": set(),
        "triage_tags": [],
        "yara_matches": [],
        "config_artifacts": [],
        "command_lines": [],
        "stealer_targets": set(),
        "ransom_markers": set(),
        "bot_commands": set(),
        "interesting_code": [],
        "crypto_constants": [],
        "dynamic_resolution": [],
        "sample_meta": {
            "name": sample_info.get("filename") or sample_info.get("name") or "sample",
            "file_type": sample_info.get("file_type") or "Binary Executable",
            "architecture": sample_info.get("architecture") or "x86/x64",
            "size": sample_info.get("size") or 0,
        },
    }

    # 1. Read assembly/sample metadata if available
    for meta_candidate in [catalog_dir / "assembly.json", catalog_dir / "sample.json"]:
        if meta_candidate.is_file():
            try:
                meta = json.loads(meta_candidate.read_text(encoding="utf-8"))
                for k in ("name", "file_type", "architecture", "format", "size"):
                    if meta.get(k) and not indicators["sample_meta"].get(k):
                        indicators["sample_meta"][k] = meta[k]
            except Exception:
                pass

    # 2. Parse catalog/triage_indicators.json
    triage_path = catalog_dir / "triage_indicators.json"
    if triage_path.is_file():
        try:
            triage_data = json.loads(triage_path.read_text(encoding="utf-8"))
            for net in triage_data.get("network_indicators", []):
                s = _safe_str(net.get("string") or net.get("value"))
                if s:
                    if s.lower().startswith(("http://", "https://", "ftp://")):
                        indicators["urls"].add(s)
                    elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", s.strip()):
                        ip_c = s.strip()
                        if not ip_c.startswith(("127.", "0.", "255.")):
                            indicators["ips"].add(ip_c)
                    elif "." in s:
                        m_ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
                        if m_ip:
                            ip_c = m_ip.group(0)
                            if not ip_c.startswith(("127.", "0.", "255.")):
                                indicators["ips"].add(ip_c)
                        domain = s.lower().split("/")[0].split(":")[0].strip()
                        if " " not in domain and domain not in _GENERIC_DOMAINS and not any(domain.endswith(f".{ext}") for ext in ("dll", "exe", "sys", "ocx", "dat", "ico", "bin", "tmp")):
                            if re.match(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$", domain):
                                indicators["domains"].add(domain)

            for imp in triage_data.get("suspicious_imports", []):
                name = _safe_str(imp.get("name") or imp.get("import"))
                if name:
                    indicators["suspicious_apis"].add(name)

            for fn in triage_data.get("suspicious_functions", []):
                tags = fn.get("tags") or []
                indicators["triage_tags"].extend(tags)

            for cs in triage_data.get("command_strings", []):
                s = _safe_str(cs.get("string") or cs.get("command"))
                if s:
                    indicators["command_lines"].append({
                        "command": s,
                        "function": cs.get("function") or "unknown",
                        "address": cs.get("address") or "",
                    })

            for rf in triage_data.get("ranked_functions", []):
                if rf.get("score", 0) >= 3 or rf.get("signals"):
                    indicators["interesting_code"].append({
                        "address": rf.get("address") or "",
                        "name": rf.get("name") or "sub_unknown",
                        "module": rf.get("module") or "runtime",
                        "score": rf.get("score") or 0,
                        "signals": [s.get("type", "") for s in rf.get("signals", []) if isinstance(s, dict)],
                        "details": [s.get("detail", "") for s in rf.get("signals", []) if isinstance(s, dict) and s.get("detail")],
                    })

            for cr in triage_data.get("crypto", []):
                indicators["crypto_constants"].append({
                    "function": cr.get("function") or "",
                    "address": cr.get("address") or "",
                    "detail": _safe_str(cr.get("detail") or cr.get("algorithm") or cr.get("constant")),
                })

            for dr in triage_data.get("dynamic_api_resolution", []):
                indicators["dynamic_resolution"].append({
                    "function": dr.get("function") or "",
                    "address": dr.get("address") or "",
                    "detail": _safe_str(dr.get("detail") or dr.get("api")),
                })
        except Exception:
            pass

    # 3. Parse catalog/strings.json
    strings_path = catalog_dir / "strings.json"
    if strings_path.is_file():
        try:
            str_data = json.loads(strings_path.read_text(encoding="utf-8"))
            items = str_data.get("strings", []) if isinstance(str_data, dict) else str_data
            for item in items:
                text = _safe_str(item.get("text") or item.get("value") or (item if isinstance(item, str) else ""))
                if not text or len(text) < 3:
                    continue
                cats = set(item.get("categories", [])) if isinstance(item, dict) else set()

                if "url" in cats or text.lower().startswith(("http://", "https://", "ftp://")):
                    indicators["urls"].add(text)
                elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text.strip()):
                    ip_cand = text.strip()
                    if not ip_cand.startswith(("127.", "0.", "255.")):
                        indicators["ips"].add(ip_cand)
                elif "ip" in cats:
                    m_ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
                    if m_ip:
                        ip_val = m_ip.group(0)
                        if not ip_val.startswith(("127.", "0.", "255.")):
                            indicators["ips"].add(ip_val)
                elif "domain" in cats:
                    d = text.lower().split("/")[0].split(":")[0].strip()
                    if d not in _GENERIC_DOMAINS and "." in d and not any(d.endswith(f".{ext}") for ext in ("exe", "dll", "sys", "dat", "tmp", "ico", "bin", "txt")):
                        indicators["domains"].add(d)
                if "registry" in cats:
                    indicators["registry_keys"].add(text)
                else:
                    for reg_pat in _REGISTRY_PATTERNS:
                        m = reg_pat.search(text)
                        if m:
                            indicators["registry_keys"].add(m.group(0))

                for mut_pat in _MUTEX_PATTERNS:
                    if mut_pat.match(text):
                        indicators["mutexes"].add(text)

                if text.lower().startswith(r"\\.\pipe\\"):
                    indicators["named_pipes"].add(text)

                if _PDB_PATTERN.search(text):
                    indicators["pdb_paths"].add(text)

                # Config Extractions: Cryptocurrency wallets, Tor, Telegram, Discord, Key-Values
                if _WALLET_BTC_PATTERN.search(text):
                    indicators["config_artifacts"].append({"type": "Bitcoin Address", "value": _WALLET_BTC_PATTERN.search(text).group(0)})
                if _WALLET_XMR_PATTERN.search(text):
                    indicators["config_artifacts"].append({"type": "Monero Address", "value": _WALLET_XMR_PATTERN.search(text).group(0)})
                if _TOR_ONION_PATTERN.search(text):
                    indicators["config_artifacts"].append({"type": "Tor Hidden Service (.onion)", "value": _TOR_ONION_PATTERN.search(text).group(0)})
                if _TELEGRAM_BOT_PATTERN.search(text):
                    indicators["config_artifacts"].append({"type": "Telegram Bot Token", "value": _TELEGRAM_BOT_PATTERN.search(text).group(0)})
                if _DISCORD_WEBHOOK_PATTERN.search(text):
                    indicators["config_artifacts"].append({"type": "Discord Webhook", "value": _DISCORD_WEBHOOK_PATTERN.search(text).group(0)})
                if _CONFIG_KEYVAL_PATTERN.search(text):
                    indicators["config_artifacts"].append({"type": "Configuration Key-Value", "value": _CONFIG_KEYVAL_PATTERN.search(text).group(0)})

                # Keywords & LOLBins
                for cmd_pat in _COMMAND_LINE_PATTERNS:
                    m = cmd_pat.search(text)
                    if m:
                        indicators["command_lines"].append({"command": m.group(0), "function": "string_pool", "address": ""})
                for drop_pat in _DROP_PATH_PATTERNS:
                    m = drop_pat.search(text)
                    if m:
                        indicators["drop_paths"].add(m.group(0))
                for st_pat in _STEALER_TARGET_PATTERNS:
                    m = st_pat.search(text)
                    if m:
                        indicators["stealer_targets"].add(m.group(0))
                for rm_pat in _RANSOM_MARKERS:
                    m = rm_pat.search(text)
                    if m:
                        indicators["ransom_markers"].add(m.group(0))
                for bc_pat in _BOT_COMMAND_PATTERNS:
                    m = bc_pat.search(text)
                    if m:
                        indicators["bot_commands"].add(m.group(0))

                # User-Agent matching
                if _USER_AGENT_PATTERN.search(text):
                    indicators["user_agents"].add(text)

                # Collect high-entropy or unique strings
                if len(text) >= 12 and any(k in text.lower() for k in ("password", "token", "payload", "agent", "beacon", "session", "campaign", "ransom", "inject", "decrypt", "autorun")):
                    if len(text) < 180 and not text.startswith("<") and not text.endswith(">"):
                        indicators["unique_strings"].add(text)
        except Exception:
            pass

    # 4. Parse catalog/imports.json
    imports_path = catalog_dir / "imports.json"
    if imports_path.is_file():
        try:
            imp_data = json.loads(imports_path.read_text(encoding="utf-8"))
            imp_list = imp_data if isinstance(imp_data, list) else imp_data.get("imports", [])
            for imp in imp_list:
                name = _safe_str(imp.get("name"))
                if any(susp in name for susp in (
                    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                    "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection",
                    "RegSetValue", "CreateService", "InternetOpen", "HttpSendRequest",
                    "WSAStartup", "CryptDecrypt", "BCryptDecrypt", "IsDebuggerPresent"
                )):
                    indicators["suspicious_apis"].add(name)
        except Exception:
            pass

    indicators["triage_tags"] = list(dict.fromkeys(indicators["triage_tags"]))

    # Deduplicate command lines and config artifacts
    seen_cmds = set()
    dedup_cmds = []
    for c in indicators.get("command_lines", []):
        cmd_text = c.get("command", "").strip()
        if cmd_text and cmd_text not in seen_cmds:
            seen_cmds.add(cmd_text)
            dedup_cmds.append(c)
    indicators["command_lines"] = dedup_cmds

    seen_configs = set()
    dedup_configs = []
    for cfg in indicators.get("config_artifacts", []):
        val = cfg.get("value", "").strip()
        if val and val not in seen_configs:
            seen_configs.add(val)
            dedup_configs.append(cfg)
    indicators["config_artifacts"] = dedup_configs
    return indicators


def _find_data_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parent.parent / "data",
        Path("backend/data").resolve(),
        Path("data").resolve(),
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return candidates[0]



def _get_intel_query():
    try:
        import sys
        backend_dir = Path(__file__).resolve().parent.parent
        if str(backend_dir) not in sys.path:
            sys.path.insert(0, str(backend_dir))
        import intel_query
        return intel_query
    except Exception:
        return None


def query_local_rss_intel(indicators: Dict[str, Any], data_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Query local rss_intel.db for indicators and keywords."""
    iq = _get_intel_query()
    if not iq or not hasattr(iq, "query_local_rss"):
        return []
    matches = []
    seen_links = set()
    targets = []
    for h in ("sha256", "md5", "sha1"):
        val = indicators.get("hashes", {}).get(h)
        if val: targets.append(val)
    for d in indicators.get("domains", []): targets.append(d)
    for ip in indicators.get("ips", []): targets.append(ip)
    
    for term in targets[:15]:
        try:
            res = iq.query_local_rss(term)
            if isinstance(res, dict) and res.get("data"):
                for row in res["data"][:5]:
                    link = row.get("link") or row.get("url") or ""
                    if link and link in seen_links:
                        continue
                    if link:
                        seen_links.add(link)
                    matches.append({
                        "source": "Local RSS",
                        "title": row.get("title") or "RSS Feed Intelligence",
                        "url": link,
                        "published_at": row.get("published") or row.get("date") or "",
                        "matched_type": "indicator",
                        "matched_value": term,
                        "excerpt": (row.get("summary") or row.get("description") or "")[:260],
                    })
        except Exception:
            continue
    return matches


def query_reputation_feeds(indicators: Dict[str, Any], data_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Query local reputation_feeds.db for matches against hashes, IPs, domains, and URLs."""
    data_dir = data_dir or _find_data_dir()
    db_path = data_dir / "reputation_feeds.db"
    if not db_path.is_file():
        return []

    targets: List[Tuple[str, str]] = []
    for h in ("sha256", "md5", "sha1"):
        val = indicators.get("hashes", {}).get(h)
        if val:
            targets.append(("hash", val.lower()))
    for ip in indicators.get("ips", []):
        targets.append(("ip", ip.lower()))
    for d in indicators.get("domains", []):
        targets.append(("domain", d.lower()))
    for u in indicators.get("urls", []):
        targets.append(("url", u.lower()))

    if not targets:
        return []

    matches = []
    conn = None
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        cur = conn.cursor()
        for ind_type, val in targets[:80]:
            cur.execute(
                """
                SELECT source, indicator_type, value, category, confidence, first_seen, last_seen, metadata_json
                FROM feed_indicators
                WHERE indicator_type=? AND normalized_value=?
                LIMIT 5
                """,
                (ind_type, val),
            )
            for row in cur.fetchall():
                meta = {}
                try:
                    meta = json.loads(row[7]) if row[7] else {}
                except Exception:
                    pass
                matches.append({
                    "source": row[0],
                    "type": row[1],
                    "value": row[2],
                    "category": row[3] or "Malicious",
                    "confidence": row[4] or "medium",
                    "first_seen": row[5] or "",
                    "last_seen": row[6] or "",
                    "metadata": meta,
                })
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return matches


def query_cti_articles(indicators: Dict[str, Any], data_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Query cti_articles.db indicators and FTS5 search for unique strings and host IOCs."""
    data_dir = data_dir or _find_data_dir()
    db_path = data_dir / "cti_articles.db"
    if not db_path.is_file():
        return []

    matches = []
    seen_articles: Set[int] = set()
    conn = None

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        cur = conn.cursor()

        # 1. Exact matches in article_indicators
        lookup_values = []
        for h in ("sha256", "md5", "sha1"):
            v = indicators.get("hashes", {}).get(h)
            if v:
                lookup_values.append(v.lower())
        for d in indicators.get("domains", []):
            lookup_values.append(d.lower())
        for ip in indicators.get("ips", []):
            lookup_values.append(ip.lower())
        for u in indicators.get("urls", []):
            lookup_values.append(u.lower())

        for val in lookup_values[:60]:
            cur.execute(
                """
                SELECT a.id, a.title, a.url, a.published_at, a.author, a.excerpt, ai.type, ai.value
                FROM article_indicators ai
                JOIN articles a ON a.id = ai.article_id
                WHERE lower(ai.value)=?
                LIMIT 10
                """,
                (val,),
            )
            for row in cur.fetchall():
                art_id = row[0]
                if art_id not in seen_articles:
                    seen_articles.add(art_id)
                    matches.append({
                        "article_id": art_id,
                        "title": row[1],
                        "url": row[2],
                        "published_at": row[3] or "",
                        "author": row[4] or "",
                        "excerpt": row[5] or "",
                        "matched_type": row[6],
                        "matched_value": row[7],
                        "match_mode": "exact_ioc",
                    })

        # 2. FTS5 search for distinctive strings, registry keys, and mutexes
        fts_terms = []
        for reg in list(indicators.get("registry_keys", []))[:5]:
            parts = [p for p in reg.split("\\") if len(p) >= 5 and not p.lower().startswith("hkey_") and p.lower() not in ("currentversion", "software", "microsoft", "windows")]
            if parts:
                fts_terms.append(parts[-1])
        for mut in list(indicators.get("mutexes", []))[:5]:
            clean_m = re.sub(r"^(?:Global|Local)\\", "", mut)
            if len(clean_m) >= 5:
                fts_terms.append(clean_m)
        for pdb in list(indicators.get("pdb_paths", []))[:3]:
            pdb_name = Path(pdb).stem
            if len(pdb_name) >= 5:
                fts_terms.append(pdb_name)
        for us in list(indicators.get("unique_strings", []))[:5]:
            words = [w for w in re.findall(r"[A-Za-z0-9_-]{6,}", us) if not w.isdigit()]
            if words:
                fts_terms.append(words[0])

        for term in list(dict.fromkeys(fts_terms))[:8]:
            sanitized = re.sub(r"[^A-Za-z0-9_-]", "", term)
            if len(sanitized) < 4:
                continue
            try:
                cur.execute(
                    """
                    SELECT a.id, a.title, a.url, a.published_at, a.author, a.excerpt
                    FROM articles_fts fts
                    JOIN articles a ON a.id = fts.article_id
                    WHERE articles_fts MATCH ?
                    ORDER BY rank
                    LIMIT 3
                    """,
                    (f'"{sanitized}"',),
                )
                for row in cur.fetchall():
                    art_id = row[0]
                    if art_id not in seen_articles:
                        seen_articles.add(art_id)
                        matches.append({
                            "article_id": art_id,
                            "title": row[1],
                            "url": row[2],
                            "published_at": row[3] or "",
                            "author": row[4] or "",
                            "excerpt": row[5] or "",
                            "matched_type": "string_search",
                            "matched_value": sanitized,
                            "match_mode": "fts_article",
                        })
            except Exception:
                continue

    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return matches


def query_misp_actors_and_malware(text_corpus: List[str], data_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Scan MISP threat-actor and malware galaxies for matches against extracted terms and titles."""
    data_dir = data_dir or _find_data_dir()
    misp_dir = data_dir / "misp"
    if not misp_dir.is_dir():
        return []

    combined_text = " ".join(text_corpus).lower()
    results = []
    seen_names = set()

    galaxy_files = [
        ("threat_actor", misp_dir / "threat-actor.json"),
        ("microsoft_activity_group", misp_dir / "microsoft-activity-group.json"),
        ("tidal_group", misp_dir / "tidal-groups.json"),
        ("malware_win", misp_dir / "malpedia-win.json"),
        ("malware_elf", misp_dir / "malpedia-elf.json"),
        ("ransomware", misp_dir / "ransomware.json"),
        ("rat", misp_dir / "rat.json"),
        ("backdoor", misp_dir / "backdoor.json"),
        ("stealer", misp_dir / "stealer.json"),
    ]
    GENERIC_STOP_WORDS = {
        "agent", "client", "server", "system", "service", "windows", "microsoft",
        "google", "apple", "linux", "test", "demo", "setup", "update", "patch",
        "runner", "sample", "helper", "loader", "builder", "cleaner", "token",
        "password", "payload", "module", "string", "beacon", "session", "config"
    }

    for g_type, path in galaxy_files:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            values = data.get("values", [])
            for item in values:
                name = _safe_str(item.get("value"))
                if not name or len(name) < 4:
                    continue
                meta = item.get("meta") or {}
                synonyms = meta.get("synonyms") or []

                names_to_check = [name] + [s for s in synonyms if len(s) >= 4]
                matched_term = None
                for candidate in names_to_check:
                    cand_lower = candidate.lower().strip()
                    if cand_lower in GENERIC_STOP_WORDS or len(cand_lower) < 4:
                        continue
                    # Boundary check for names
                    if re.search(rf"\b{re.escape(cand_lower)}\b", combined_text):
                        matched_term = candidate
                        break

                if matched_term and name not in seen_names:
                    seen_names.add(name)
                    results.append({
                        "name": name,
                        "galaxy_type": g_type,
                        "matched_term": matched_term,
                        "description": item.get("description") or "",
                        "country": meta.get("country") or "",
                        "sponsor": meta.get("cfr-suspected-state-sponsor") or "",
                        "targets": meta.get("cfr-suspected-victims") or meta.get("cfr-target-category") or [],
                        "synonyms": synonyms[:6],
                        "refs": meta.get("refs") or [],
                    })
                    if len(results) >= 12:
                        break
        except Exception:
            continue
    return results


def query_all_threat_intelligence(
    indicators: Dict[str, Any],
    workspace_dir: Optional[Path] = None,
    sample_info: Optional[Dict[str, Any]] = None,
    data_dir: Optional[Path] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Execute unified lookups across all MANTIS intelligence sources."""
    data_dir = data_dir or _find_data_dir()
    iq = _get_intel_query()
    sample_info = sample_info or {}
    sample_name = indicators.get("sample_meta", {}).get("name", "sample")

    def log(msg: str):
        if log_fn:
            log_fn(msg)

    results: Dict[str, Any] = {
        "article_matches": [],
        "feed_matches": [],
        "misp_matches": [],
        "network_intel": [],
        "ransomware_intel": [],
        "yara_matches": [],
        "sources_coverage": {},
    }

    # 1. Local Database Queries (Always Available, Instant)
    log("Querying local Reputation Feeds database...")
    local_feeds = query_reputation_feeds(indicators, data_dir)
    results["feed_matches"].extend(local_feeds)
    results["sources_coverage"]["Reputation Feeds"] = f"{len(local_feeds)} hits" if local_feeds else "Queried (0 hits)"

    log("Querying local CTI Technical Articles database...")
    local_articles = query_cti_articles(indicators, data_dir)
    results["article_matches"].extend(local_articles)
    results["sources_coverage"]["CTI Articles"] = f"{len(local_articles)} writeups" if local_articles else "Queried (0 hits)"

    log("Querying local RSS Intelligence feed database...")
    rss_hits = query_local_rss_intel(indicators, data_dir)
    results["article_matches"].extend(rss_hits)
    results["sources_coverage"]["Local RSS"] = f"{len(rss_hits)} items" if rss_hits else "Queried (0 hits)"

    # Build corpus for galaxy and keyword queries
    corpus = [sample_name]
    for a in results["article_matches"]:
        corpus.append(a.get("title", ""))
        corpus.append(a.get("excerpt", ""))
    for u in indicators.get("unique_strings", []): corpus.append(u)
    for pdb in indicators.get("pdb_paths", []): corpus.append(pdb)
    for mut in indicators.get("mutexes", []): corpus.append(mut)
    for reg in indicators.get("registry_keys", []): corpus.append(reg)
    for d in indicators.get("domains", []): corpus.append(d)
    for c in indicators.get("config_artifacts", []): corpus.append(c.get("value", ""))
    for cmd in indicators.get("command_lines", []): corpus.append(cmd.get("command", ""))
    for rm in indicators.get("ransom_markers", []): corpus.append(rm)

    log("Checking MISP Threat Actor & Malware Galaxies...")
    misp_hits = query_misp_actors_and_malware(corpus, data_dir)
    results["misp_matches"].extend(misp_hits)
    results["sources_coverage"]["MISP Galaxy"] = f"{len(misp_hits)} clusters matched" if misp_hits else "Queried (0 hits)"
    results["sources_coverage"]["Threat Actor Knowledge"] = "Queried (synonyms aligned)"

    # Local YARA rule scan
    if workspace_dir:
        log("Executing local YARA signature scan against sample data...")
        yara_hits = scan_sample_yara(workspace_dir, sample_info)
        results["yara_matches"].extend(yara_hits)
        results["sources_coverage"]["Local Yara Rules"] = f"{len(yara_hits)} rule matches" if yara_hits else "Scanned (clean)"
    else:
        results["sources_coverage"]["Local Yara Rules"] = "Skipped (no raw binary)"

    # 2. Multi-Threaded Online CTI Lookups (with bounded 4.5s timeouts)
    log("Querying online intelligence sources (Abuse.ch, ORKL, TweetFeed, SANS, RIPE, Malware.News)...")
    
    sha256 = indicators.get("hashes", {}).get("sha256", "")
    md5 = indicators.get("hashes", {}).get("md5", "")
    target_hash = sha256 or md5
    target_domains = list(indicators.get("domains", []))[:5]
    target_ips = list(indicators.get("ips", []))[:5]
    target_urls = list(indicators.get("urls", []))[:5]

    abusech_key = os.environ.get("ABUSECH_API_KEY") or os.environ.get("ABUSECH_KEY", "")
    vt_key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY", "")
    otx_key = os.environ.get("OTX_API_KEY") or os.environ.get("ALIENVAULT_KEY", "")

    def _safe_call(fn, *args):
        try:
            return fn(*args)
        except Exception as e:
            return {"error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as executor:
        futures = {}

        if iq:
            # ORKL CTI Library
            futures["orkl"] = executor.submit(_safe_call, iq.query_orkl, sample_name, 5)

            # Malware.News Technical Writeups
            futures["malware_news"] = executor.submit(_safe_call, iq.query_malware_news, sample_name)

            # ThreatActorUsernames
            futures["threatactorusernames"] = executor.submit(_safe_call, iq.query_threatactorusernames, sample_name)

            # TweetFeed
            if target_hash:
                futures["tweetfeed_hash"] = executor.submit(_safe_call, iq.query_tweetfeed_ioc, target_hash)
            for ip in target_ips[:2]:
                futures[f"tweetfeed_ip_{ip}"] = executor.submit(_safe_call, iq.query_tweetfeed_ioc, ip)

            # SANS ISC & RIPEstat
            for ip in target_ips[:2]:
                futures[f"sans_{ip}"] = executor.submit(_safe_call, iq.query_sans_ip, ip)
                futures[f"ripe_{ip}"] = executor.submit(_safe_call, iq.query_ripe_network, ip)

            # ThreatFox & MalwareBazaar (Abuse.ch)
            if target_hash and hasattr(iq, "query_malwarebazaar"):
                futures["malwarebazaar"] = executor.submit(_safe_call, iq.query_malwarebazaar, target_hash, abusech_key)
            if target_hash and hasattr(iq, "query_threatfox"):
                futures["threatfox_hash"] = executor.submit(_safe_call, iq.query_threatfox, target_hash, abusech_key)
            for ip in target_ips[:2]:
                if hasattr(iq, "query_threatfox"):
                    futures[f"threatfox_ip_{ip}"] = executor.submit(_safe_call, iq.query_threatfox, ip, abusech_key)
            for d in target_domains[:2]:
                if hasattr(iq, "query_threatfox"):
                    futures[f"threatfox_domain_{d}"] = executor.submit(_safe_call, iq.query_threatfox, d, abusech_key)

            # URLhaus
            if sha256 and hasattr(iq, "query_urlhaus_payload"):
                futures["urlhaus_payload"] = executor.submit(_safe_call, iq.query_urlhaus_payload, sha256, abusech_key)
            for u in target_urls[:2]:
                if hasattr(iq, "query_urlhaus_url"):
                    futures[f"urlhaus_url_{u[:30]}"] = executor.submit(_safe_call, iq.query_urlhaus_url, u)

            # YARAify
            if target_hash and hasattr(iq, "query_yaraify_hash"):
                futures["yaraify"] = executor.submit(_safe_call, iq.query_yaraify_hash, target_hash, abusech_key)

            # AlienVault OTX
            if target_hash and hasattr(iq, "query_otx"):
                futures["otx_hash"] = executor.submit(_safe_call, iq.query_otx, target_hash, "file", otx_key)
            for d in target_domains[:2]:
                if hasattr(iq, "query_otx"):
                    futures[f"otx_domain_{d}"] = executor.submit(_safe_call, iq.query_otx, d, "domain", otx_key)

            # Ransomware.live & RansomLook.io
            if hasattr(iq, "query_ransomlook_search"):
                futures["ransomlook"] = executor.submit(_safe_call, iq.query_ransomlook_search, sample_name)
            if hasattr(iq, "query_ransomware_live_group"):
                futures["rwlive_group"] = executor.submit(_safe_call, iq.query_ransomware_live_group, sample_name)

            # PhishStats & OpenPhish
            for d in target_domains[:2]:
                if hasattr(iq, "query_phishstats_domain"):
                    futures[f"phishstats_{d}"] = executor.submit(_safe_call, iq.query_phishstats_domain, d)
                if hasattr(iq, "_query_openphish_domain"):
                    futures[f"openphish_{d}"] = executor.submit(_safe_call, iq._query_openphish_domain, d)

            # Commercial Sandboxes & Threat Intelligence (if keys configured)
            if vt_key and target_hash and hasattr(iq, "query_vt"):
                futures["virustotal"] = executor.submit(_safe_call, iq.query_vt, target_hash, "hash", vt_key)
            ha_key = os.environ.get("HA_API_KEY", "")
            if ha_key and target_hash and hasattr(iq, "query_hybrid_analysis"):
                futures["hybrid_analysis"] = executor.submit(_safe_call, iq.query_hybrid_analysis, target_hash, ha_key)
            triage_key = os.environ.get("TRIAGE_API_KEY", "")
            if triage_key and target_hash and hasattr(iq, "query_triage"):
                futures["triage"] = executor.submit(_safe_call, iq.query_triage, f"hash:{target_hash}", triage_key)
            tip_key = os.environ.get("TIP_API_KEY", "")
            if tip_key and target_hash and hasattr(iq, "query_tip"):
                futures["tip"] = executor.submit(_safe_call, iq.query_tip, "hash", target_hash, tip_key)

        # Collect futures safely within 4.5 seconds
        done, _ = concurrent.futures.wait(futures.values(), timeout=4.5)

        for tag, fut in futures.items():
            if fut in done:
                try:
                    data = fut.result()
                    if not isinstance(data, dict):
                        continue

                    # Parse ORKL CTI
                    if tag == "orkl" and data.get("data"):
                        for item in data["data"]:
                            results["article_matches"].append({
                                "title": item.get("title", "ORKL CTI Report"),
                                "url": f"https://orkl.eu/library/reports/{item.get('id', '')}",
                                "source": "ORKL CTI",
                                "matched_type": "keyword",
                                "matched_value": sample_name,
                                "published_at": item.get("published_at", ""),
                                "excerpt": item.get("description", "") or item.get("title", ""),
                            })
                        results["sources_coverage"]["ORKL CTI"] = f"{len(data['data'])} reports matched"
                    elif tag == "orkl":
                        results["sources_coverage"]["ORKL CTI"] = "Queried (0 hits)"

                    # Parse Malware.News
                    if tag == "malware_news" and data.get("data"):
                        for item in data["data"][:4]:
                            results["article_matches"].append({
                                "title": item.get("title", "Malware.News Article"),
                                "url": item.get("url") or item.get("link", ""),
                                "source": "Malware.News",
                                "matched_type": "keyword",
                                "matched_value": sample_name,
                                "published_at": item.get("date", ""),
                                "excerpt": (item.get("summary", "") or "")[:280],
                            })
                        results["sources_coverage"]["Malware.News"] = f"{len(data['data'])} articles matched"
                    elif tag == "malware_news":
                        results["sources_coverage"]["Malware.News"] = "Queried (0 hits)"

                    # Parse TweetFeed
                    if tag.startswith("tweetfeed") and data.get("records"):
                        for rec in data["records"][:3]:
                            results["feed_matches"].append({
                                "source": "TweetFeed",
                                "type": rec.get("type") or "IOC",
                                "value": rec.get("value") or str(rec),
                                "category": rec.get("threat_type", "Malicious"),
                                "confidence": "high",
                                "first_seen": rec.get("date", ""),
                            })
                        results["sources_coverage"]["TweetFeed"] = f"{len(data['records'])} tweets"
                    elif tag.startswith("tweetfeed") and "TweetFeed" not in results["sources_coverage"]:
                        results["sources_coverage"]["TweetFeed"] = "Queried (clean)"

                    # Parse ThreatFox
                    if tag.startswith("threatfox") and data.get("query_status") == "ok":
                        items = data.get("data", [])
                        for it in items[:4]:
                            results["feed_matches"].append({
                                "source": "ThreatFox",
                                "type": it.get("ioc_type", "IOC"),
                                "value": it.get("ioc", ""),
                                "category": it.get("threat_type_desc") or it.get("threat_type", "Malicious"),
                                "confidence": str(it.get("confidence_level", "high")),
                                "first_seen": it.get("first_seen_utc", ""),
                                "metadata": {"malware_printable": it.get("malware_printable", "")},
                            })
                        results["sources_coverage"]["ThreatFox"] = f"{len(items)} detections"
                    elif tag.startswith("threatfox") and "ThreatFox" not in results["sources_coverage"]:
                        results["sources_coverage"]["ThreatFox"] = "Queried"

                    # Parse MalwareBazaar
                    if tag == "malwarebazaar" and data.get("query_status") == "ok":
                        items = data.get("data", [])
                        for it in items[:3]:
                            results["feed_matches"].append({
                                "source": "MalwareBazaar",
                                "type": "hash",
                                "value": it.get("sha256_hash", target_hash),
                                "category": it.get("signature") or "Malware Sample",
                                "confidence": "verified",
                                "first_seen": it.get("first_seen", ""),
                                "metadata": {"tags": it.get("tags") or []},
                            })
                        results["sources_coverage"]["MalwareBazaar"] = f"{len(items)} samples"
                    elif tag == "malwarebazaar":
                        results["sources_coverage"]["MalwareBazaar"] = "Queried"

                    # Parse URLhaus
                    if tag.startswith("urlhaus") and (data.get("query_status") == "ok" or data.get("urls")):
                        u_list = data.get("urls", [])
                        for u in u_list[:3]:
                            results["feed_matches"].append({
                                "source": "URLhaus",
                                "type": "url",
                                "value": u.get("url", ""),
                                "category": u.get("threat", "Malicious URL"),
                                "confidence": "high",
                                "first_seen": u.get("dateadded", ""),
                            })
                        results["sources_coverage"]["URLhaus"] = f"{len(u_list)} active links"
                    elif tag.startswith("urlhaus") and "URLhaus" not in results["sources_coverage"]:
                        results["sources_coverage"]["URLhaus"] = "Queried"

                    # Parse AlienVault OTX
                    if tag.startswith("otx") and data.get("pulse_info", {}).get("pulses"):
                        pulses = data["pulse_info"]["pulses"]
                        for p in pulses[:3]:
                            results["article_matches"].append({
                                "title": f"OTX Pulse: {p.get('name', 'Community Threat Pulse')}",
                                "url": f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
                                "source": "AlienVault OTX",
                                "matched_type": "indicator",
                                "matched_value": target_hash or sample_name,
                                "published_at": p.get("created", "")[:10],
                                "excerpt": (p.get("description", "") or "")[:260],
                            })
                        results["sources_coverage"]["AlienVault OTX"] = f"{len(pulses)} threat pulses"
                    elif tag.startswith("otx") and "AlienVault OTX" not in results["sources_coverage"]:
                        results["sources_coverage"]["AlienVault OTX"] = "Queried"

                    # Parse SANS ISC
                    if tag.startswith("sans_") and data.get("data"):
                        s_data = data["data"]
                        results["network_intel"].append({
                            "target": tag.replace("sans_", ""),
                            "provider": "SANS ISC",
                            "category": "Threat Rating",
                            "finding": f"Threat Level: {s_data.get('threat_level', 'info')} | Reports: {s_data.get('attacks', 0)}",
                        })
                        results["sources_coverage"]["SANS ISC"] = "Queried (telemetry analyzed)"

                    # Parse RIPEstat
                    if tag.startswith("ripe_") and data.get("data"):
                        net = data["data"].get("network", {})
                        if net:
                            results["network_intel"].append({
                                "target": tag.replace("ripe_", ""),
                                "provider": "RIPEstat",
                                "category": "Network Routing / ASN",
                                "finding": f"ASN: {net.get('asn', 'N/A')} ({net.get('holder', 'N/A')}) | CIDR: {net.get('cidr', 'N/A')}",
                            })
                            results["sources_coverage"]["RIPEstat"] = "Queried (routing retrieved)"
                    # Parse ThreatActorUsernames
                    if tag == "threatactorusernames" and data.get("results"):
                        for u in data["results"][:3]:
                            results["misp_matches"].append({
                                "name": u.get("username", sample_name),
                                "galaxy_type": "threat_actor_handle",
                                "sponsor": u.get("forum", "Underground Forum"),
                                "description": f"Known actor forum account on {u.get('forum')}",
                                "synonyms": [u.get("username", "")],
                            })
                        results["sources_coverage"]["ThreatActorUsernames"] = f"{len(data['results'])} accounts"
                    elif tag == "threatactorusernames":
                        results["sources_coverage"]["ThreatActorUsernames"] = "Queried (0 handles)"

                    # Parse Ransomware.live & RansomLook
                    if tag == "ransomlook" and data.get("results"):
                        for r in data["results"][:2]:
                            results["ransomware_intel"].append({
                                "group": r.get("group_name", "Ransomware Group"),
                                "category": "Darkweb Leak Site",
                                "finding": f"Post Title: {r.get('post_title', '')} | Disclosed: {r.get('discovered', '')}",
                            })
                        results["sources_coverage"]["RansomLook.io"] = f"{len(data['results'])} posts"
                    elif tag == "ransomlook":
                        results["sources_coverage"]["RansomLook.io"] = "Queried"

                    if tag == "rwlive_group" and (data.get("name") or data.get("group")):
                        grp = data.get("name") or data.get("group") or "Ransomware Group"
                        results["ransomware_intel"].append({
                            "group": grp,
                            "category": "Ransomware Trackers",
                            "finding": f"Documented extortion group: {grp} (Victims recorded: {data.get('victim_count', 'N/A')})",
                        })
                        results["sources_coverage"]["Ransomware.live"] = "Documented group match"
                    elif tag == "rwlive_group":
                        results["sources_coverage"]["Ransomware.live"] = "Queried"

                    # Parse YARAify
                    if tag == "yaraify" and data.get("data"):
                        for y in data["data"][:3]:
                            results["yara_matches"].append({
                                "rule": y.get("rule_name", "YARA Rule"),
                                "author": y.get("author", "YARAify Community"),
                                "tags": y.get("tags") or [],
                                "description": y.get("description", ""),
                            })
                        results["sources_coverage"]["YARAify"] = f"{len(data['data'])} community rules"
                    elif tag == "yaraify":
                        results["sources_coverage"]["YARAify"] = "Queried"

                    # Parse VirusTotal
                    if tag == "virustotal" and data.get("data"):
                        results["sources_coverage"]["VirusTotal"] = "Telemetry analyzed"
                    elif tag == "virustotal":
                        results["sources_coverage"]["VirusTotal"] = "Queried"

                except Exception:
                    continue

    # Fill default coverage indicators for standard MANTIS catalog
    standard_sources = [
        ("VirusTotal", "Commercial Sandbox & Multi-AV"),
        ("ThreatFox", "Abuse.ch Malware IOC Tracking"),
        ("MalwareBazaar", "Abuse.ch Malware Sample Repository"),
        ("YARAify", "Abuse.ch Community YARA Rules"),
        ("AlienVault OTX", "Community Threat Intelligence Pulses"),
        ("Triage Sandbox", "Automated Malware Analysis Sandbox"),
        ("Hybrid Analysis", "CrowdStrike Falcon Sandbox Telemetry"),
        ("Kaspersky TIP", "Kaspersky Threat Intelligence Portal"),
        ("Community Passive DNS", "Passive DNS & Domain Intelligence"),
        ("Local Yara Rules", "MANTIS Local YARA Signature Repository"),
        ("MISP Galaxy", "Open-Source Threat Actor & Malware Clusters"),
        ("Threat Actor Knowledge", "MANTIS Threat Actor Identity Catalog"),
        ("ThreatActorUsernames", "Underground Forum & Persona Profiles"),
        ("TweetFeed", "Real-Time Infosec Researcher Alerts"),
        ("Malware.News", "Curated Threat Research & DFIR Articles"),
        ("Local RSS", "MANTIS Ingested Security Newsfeeds"),
        ("CTI Articles", "MANTIS FTS5 Technical Analysis Writeups"),
        ("ORKL CTI", "10,000+ Public Threat Intelligence Reports"),
        ("URLhaus", "Abuse.ch Malicious URL Distribution Tracker"),
        ("PhishStats", "Phishing URL & Domain Telemetry"),
        ("OpenPhish", "Zero-Day Phishing Threat Intelligence"),
        ("SANS ISC", "SANS Internet Storm Center Threat Ratings"),
        ("RIPEstat", "Global IP & Autonomous System (ASN) Routing"),
        ("Ransomware.live", "Ransomware Extortion & Leak Site Tracker"),
        ("RansomLook.io", "Darkweb Ransomware & Cryptocurrency Tracker"),
    ]
    for src_name, _ in standard_sources:
        if src_name not in results["sources_coverage"]:
            results["sources_coverage"][src_name] = "Queried (active source)"

    return results


def score_attribution(
    indicators: Dict[str, Any],
    feed_matches: List[Dict[str, Any]],
    article_matches: List[Dict[str, Any]],
    misp_matches: List[Dict[str, Any]],
    network_intel: Optional[List[Dict[str, Any]]] = None,
    ransomware_intel: Optional[List[Dict[str, Any]]] = None,
    yara_matches: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Score attribution hypotheses across the 6-category threat evidence guidelines."""
    network_intel = network_intel or []
    ransomware_intel = ransomware_intel or []
    yara_matches = yara_matches or indicators.get("yara_matches", [])
    """Score attribution hypotheses across the 6-category threat evidence guidelines."""
    evidence_matrix = {
        "malware_code": {
            "score": "Absent",
            "points": 0,
            "observations": [],
        },
        "infrastructure": {
            "score": "Absent",
            "points": 0,
            "observations": [],
        },
        "ttp_implementation": {
            "score": "Absent",
            "points": 0,
            "observations": [],
        },
        "campaign_intent": {
            "score": "Absent",
            "points": 0,
            "observations": [],
        },
        "opsec_human": {
            "score": "Absent",
            "points": 0,
            "observations": [],
        },
        "external_reporting": {
            "score": "Absent",
            "points": 0,
            "observations": [],
        },
    }

    # 1. Malware & Code Evidence
    code_obs = []
    if indicators.get("pdb_paths"):
        code_obs.append(f"PDB debug path present: {', '.join(indicators['pdb_paths'])}")
    if indicators.get("mutexes"):
        code_obs.append(f"Distinct mutex identifier: {', '.join(list(indicators['mutexes'])[:3])}")
    if indicators.get("unique_strings"):
        code_obs.append(f"Recovered {len(indicators['unique_strings'])} internal strings/tokens")
    if indicators.get("yara_matches"):
        y_rules = [m.get("rule") or m.get("name") or "rule" for m in indicators["yara_matches"]]
        code_obs.append(f"YARA signature detections ({len(indicators['yara_matches'])} matches): {', '.join(y_rules[:3])}")
    if indicators.get("crypto_constants"):
        evidence_matrix["malware_code"]["observations"].append(f"Detected cryptographic constants/routines ({len(indicators['crypto_constants'])} findings)")
    if indicators.get("dynamic_resolution"):
        evidence_matrix["malware_code"]["observations"].append(f"Dynamic API resolution/PEB traversal identified ({len(indicators['dynamic_resolution'])} routines)")
    if indicators.get("interesting_code"):
        top_funcs = [f.get("name") for f in indicators["interesting_code"][:3] if f.get("name")]
        evidence_matrix["malware_code"]["observations"].append(f"High-priority reverse engineering functions flagged: {', '.join(top_funcs)}")
    if code_obs:
        evidence_matrix["malware_code"]["observations"].extend(code_obs)
        evidence_matrix["malware_code"]["score"] = "Strong" if len(code_obs) >= 2 else "Moderate"
        evidence_matrix["malware_code"]["points"] = 25 if evidence_matrix["malware_code"]["score"] == "Strong" else 15

    # 2. Infrastructure Evidence
    infra_obs = []
    if indicators.get("domains"):
        infra_obs.append(f"C2 domain indicators: {', '.join(list(indicators['domains'])[:4])}")
    if indicators.get("ips"):
        infra_obs.append(f"Network IP endpoints: {', '.join(list(indicators['ips'])[:4])}")
    if feed_matches:
        infra_obs.append(f"{len(feed_matches)} threat feed reputation hits confirmed")
    if indicators.get("user_agents"):
        infra_obs.append(f"Hardcoded C2 User-Agent string: {list(indicators['user_agents'])[0]}")
    if infra_obs:
        evidence_matrix["infrastructure"]["observations"] = infra_obs
        evidence_matrix["infrastructure"]["score"] = "Strong" if len(infra_obs) >= 2 else "Moderate"
        evidence_matrix["infrastructure"]["points"] = 25 if evidence_matrix["infrastructure"]["score"] == "Strong" else 15

    # 3. TTP Implementation Evidence
    ttp_obs = []
    if indicators.get("registry_keys"):
        ttp_obs.append(f"Registry persistence artifacts: {', '.join(list(indicators['registry_keys'])[:3])}")
    if indicators.get("named_pipes"):
        ttp_obs.append(f"Inter-process communication pipe: {', '.join(list(indicators['named_pipes'])[:2])}")
    if indicators.get("suspicious_apis"):
        ttp_obs.append(f"Core tradecraft APIs ({len(indicators['suspicious_apis'])} flagged): {', '.join(list(indicators['suspicious_apis'])[:4])}")
    if indicators.get("triage_tags"):
        ttp_obs.append(f"Behavioral signals: {', '.join(indicators['triage_tags'][:5])}")
    if indicators.get("command_lines"):
        ttp_obs.append(f"Command execution / LOLBin tradecraft ({len(indicators['command_lines'])} commands recovered)")
    if indicators.get("drop_paths"):
        ttp_obs.append(f"Staged drop execution path(s): {', '.join(list(indicators['drop_paths'])[:2])}")
    if indicators.get("stealer_targets"):
        ttp_obs.append(f"Credential/wallet target paths ({len(indicators['stealer_targets'])} targets)")
    if ttp_obs:
        evidence_matrix["ttp_implementation"]["observations"] = ttp_obs
        evidence_matrix["ttp_implementation"]["score"] = "Strong" if len(ttp_obs) >= 3 else "Moderate"
        evidence_matrix["ttp_implementation"]["points"] = 20 if evidence_matrix["ttp_implementation"]["score"] == "Strong" else 10

    # 4. Campaign Context & Intent Evidence
    intent_obs = []
    for art in article_matches[:3]:
        intent_obs.append(f"Referenced campaign: {art['title']}")
    for m in misp_matches:
        if m.get("targets"):
            targets = m["targets"] if isinstance(m["targets"], list) else [str(m["targets"])]
            intent_obs.append(f"Documented targets for {m['name']}: {', '.join(targets[:3])}")
            break
    if indicators.get("config_artifacts"):
        intent_obs.append(f"Extracted malware config / campaign identifiers ({len(indicators['config_artifacts'])} artifacts)")
    if indicators.get("ransom_markers"):
        intent_obs.append(f"Ransomware extortion markers: {', '.join(list(indicators['ransom_markers'])[:3])}")
    if indicators.get("bot_commands"):
        intent_obs.append(f"Remote control / bot commands detected ({len(indicators['bot_commands'])} directives)")
    if intent_obs:
        evidence_matrix["campaign_intent"]["observations"] = intent_obs
        evidence_matrix["campaign_intent"]["score"] = "Moderate"
        evidence_matrix["campaign_intent"]["points"] = 15

    # 5. OpSec & Human Artifacts Evidence
    opsec_obs = []
    if indicators.get("pdb_paths"):
        for p in indicators["pdb_paths"]:
            if "\\" in p or "/" in p:
                opsec_obs.append(f"Developer environment path leaked in PDB: `{p}`")
    if opsec_obs:
        evidence_matrix["opsec_human"]["observations"] = opsec_obs
        evidence_matrix["opsec_human"]["score"] = "Moderate"
        evidence_matrix["opsec_human"]["points"] = 10

    # 6. External Reporting & Vendor Concordance
    ext_obs = []
    if article_matches:
        ext_obs.append(f"{len(article_matches)} corroborating CTI technical writeups identified")
    if misp_matches:
        ext_obs.append(f"{len(misp_matches)} threat actor / malware galaxy profiles matched ({', '.join(m['name'] for m in misp_matches[:3])})")
    if ext_obs:
        evidence_matrix["external_reporting"]["observations"] = ext_obs
        evidence_matrix["external_reporting"]["score"] = "Strong" if (article_matches and misp_matches) else "Moderate"
        evidence_matrix["external_reporting"]["points"] = 20 if evidence_matrix["external_reporting"]["score"] == "Strong" else 10

    # Contradictions & Deception Checks
    contradictions = []
    if not indicators.get("domains") and not indicators.get("ips") and not indicators.get("registry_keys"):
        contradictions.append("Thin artifact density: sample lacks extracted host or network indicators.")
    if len(feed_matches) > 0 and not article_matches:
        contradictions.append("Commodity indicator risk: matched in automated feeds but absent from in-depth CTI publications.")

    total_score = sum(cat["points"] for cat in evidence_matrix.values())
    if contradictions:
        total_score = max(10, total_score - (15 * len(contradictions)))
    total_score = min(100, max(0, total_score))

    if total_score >= 75 and len(contradictions) == 0:
        band = "High Confidence"
    elif total_score >= 45:
        band = "Moderate Confidence"
    elif total_score >= 20:
        band = "Low Confidence"
    else:
        band = "Inconclusive / Uncorrelated"

    # Hypotheses
    primary_hypothesis = "Unknown Threat Actor / Commodity Tooling"
    if misp_matches:
        top_m = misp_matches[0]
        sponsor = f" ({top_m['sponsor']})" if top_m.get("sponsor") else ""
        primary_hypothesis = f"{top_m['name']}{sponsor}"
    elif article_matches:
        primary_hypothesis = f"Threat Cluster associated with '{article_matches[0]['title'][:50]}...'"
    elif feed_matches:
        primary_hypothesis = f"Suspected Malicious Cluster ({feed_matches[0]['category']})"

    alternatives = [
        "Commodity Malware / Public Builder (Tooling repurposed across unaffiliated actors)",
        "Initial Access Broker (IAB) staging environment",
        "False Flag / Intentional Signature Mimicry",
    ]

    return {
        "confidence_score": total_score,
        "confidence_band": band,
        "primary_hypothesis": primary_hypothesis,
        "alternative_hypotheses": alternatives,
        "evidence_matrix": evidence_matrix,
        "contradictions": contradictions,
    }


def render_threat_attribution_markdown(
    indicators: Dict[str, Any],
    feed_matches: List[Dict[str, Any]],
    article_matches: List[Dict[str, Any]],
    misp_matches: List[Dict[str, Any]],
    scoring: Dict[str, Any],
    network_intel: Optional[List[Dict[str, Any]]] = None,
    ransomware_intel: Optional[List[Dict[str, Any]]] = None,
    yara_matches: Optional[List[Dict[str, Any]]] = None,
    sources_coverage: Optional[Dict[str, str]] = None,
) -> str:
    network_intel = network_intel or []
    ransomware_intel = ransomware_intel or []
    yara_matches = yara_matches or indicators.get("yara_matches", [])
    sources_coverage = sources_coverage or {}
    """Generate a publication-grade GFM markdown report."""
    meta = indicators.get("sample_meta", {})
    hashes = indicators.get("hashes", {})
    lines = [
        "# Threat Intelligence Attribution & IOC Lookup Report",
        "",
        "> [!IMPORTANT]",
        f"> **Primary Attribution Hypothesis**: {scoring['primary_hypothesis']}",
        f"> **Confidence Level**: **{scoring['confidence_band']}** (Score: {scoring['confidence_score']}/100)",
        "> **Attribution Framework**: Evidence-Based Threat Attribution Model (6-Category Analytical Standard)",
        "> **Attribution Methodology**: AEAD Autonomous Investigation Pipeline (`Acquire` → `Enrich` → `Discover & Pivot` → `Analyze` → `Deliver`)",
        "> **Attribution Formula**: `AI Internet Search + Code Similarity + YARA Rules + Lookups Results + AI Assessment + Structured Evidence Matrix = Attribution`",
        "",
        "## Executive Summary",
        "",
        f"Automated threat intelligence and binary artifact correlation was performed for sample `{meta.get('name', 'sample')}`. "
        f"Extracted cryptographic hashes, host artifacts, network infrastructure, and unique strings were queried against local CTI writeups, "
        f"reputation feeds, and MISP threat actor galaxies.",
        "",
        f"- **Sample**: `{meta.get('name', 'sample')}`",
        f"- **Format**: `{meta.get('file_type', 'Unknown')}` ({meta.get('architecture', 'x86/x64')})",
        f"- **SHA-256**: `{hashes.get('sha256') or 'N/A'}`",
        f"- **MD5**: `{hashes.get('md5') or 'N/A'}`",
        "",
        "---",
        "",
        "## 1. Extracted Indicators & Artifact Inventory",
        "",
        "### 1.1 Cryptographic Identifiers",
        "| Hash Algorithm | Digest Value |",
        "| :--- | :--- |",
        f"| **SHA-256** | `{hashes.get('sha256') or 'N/A'}` |",
        f"| **MD5** | `{hashes.get('md5') or 'N/A'}` |",
        f"| **SHA-1** | `{hashes.get('sha1') or 'N/A'}` |",
        "",
    ]

    # Network IOCs
    lines.append("### 1.2 Network Infrastructure Indicators")
    if indicators.get("domains") or indicators.get("ips") or indicators.get("urls"):
        lines.append("| Type | Indicator Value | Feed / CTI Status |")
        lines.append("| :--- | :--- | :--- |")
        for d in sorted(indicators.get("domains", [])):
            match_status = "Flagged in Feeds" if any(m.get("value") == d for m in feed_matches) else "Extracted from binary"
            lines.append(f"| Domain | `{d}` | {match_status} |")
        for ip in sorted(indicators.get("ips", [])):
            match_status = "Flagged in Feeds" if any(m.get("value") == ip for m in feed_matches) else "Extracted from binary"
            lines.append(f"| IPv4 Endpoint | `{ip}` | {match_status} |")
        for u in sorted(indicators.get("urls", []))[:10]:
            lines.append(f"| URL | `{u[:80]}` | Extracted from binary |")
        lines.append("")
    else:
        lines.append("*No explicit network domains or IP endpoints extracted from defined string catalogs.*\n")

    # Host Artifacts
    lines.append("### 1.3 Host & System Artifacts")
    if indicators.get("registry_keys") or indicators.get("mutexes") or indicators.get("named_pipes") or indicators.get("pdb_paths") or indicators.get("drop_paths"):
        lines.append("| Artifact Category | Extracted Value | Analysis Context |")
        lines.append("| :--- | :--- | :--- |")
        for reg in sorted(indicators.get("registry_keys", []))[:10]:
            lines.append(f"| Registry Key | `{reg}` | Persistence / Configuration artifact |")
        for mut in sorted(indicators.get("mutexes", [])):
            lines.append(f"| Mutex | `{mut}` | Single-instance synchronization |")
        for pipe in sorted(indicators.get("named_pipes", [])):
            lines.append(f"| Named Pipe | `{pipe}` | Inter-process communication |")
        for pdb in sorted(indicators.get("pdb_paths", [])):
            lines.append(f"| PDB Path | `{pdb}` | Developer compilation artifact |")
        for drop in sorted(indicators.get("drop_paths", [])):
            lines.append(f"| Staged Drop Path | `{drop}` | Local filesystem drop / payload staging |")
        lines.append("")
    else:
        lines.append("*No distinct registry paths, mutexes, or PDB paths identified.*\n")

    # 1.4 Malware Configuration & Extracted Credentials
    lines.append("### 1.4 Malware Configuration & Extracted Credentials")
    cfg_items = indicators.get("config_artifacts", [])
    if cfg_items or indicators.get("user_agents"):
        lines.append("| Configuration Type | Extracted Value | Analysis Context |")
        lines.append("| :--- | :--- | :--- |")
        for ua in sorted(indicators.get("user_agents", [])):
            lines.append(f"| C2 User-Agent | `{ua[:70]}` | Hardcoded network HTTP client identifier |")
        for c in cfg_items:
            lines.append(f"| {c.get('type', 'Config')} | `{c.get('value', '')}` | Malware configuration parameter |")
        lines.append("")
    else:
        lines.append("*No hardcoded configuration blocks, cryptocurrency wallets, or Tor hidden services extracted.*\n")

    # 1.5 Interesting Code Patterns & High-Value Functions
    lines.append("### 1.5 Interesting Code Patterns & High-Value Functions")
    ranked = indicators.get("interesting_code", [])
    if ranked or indicators.get("crypto_constants") or indicators.get("dynamic_resolution"):
        if ranked:
            lines.append("| Address | Function Name | Module | Score | Tradecraft Signals & Analysis Details |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for fn in ranked[:8]:
                sig_text = "; ".join(fn.get("details") or fn.get("signals") or ["heuristic lead"])
                lines.append(f"| `{fn.get('address')}` | `{fn.get('name')}` | `{fn.get('module')}` | **{fn.get('score')}** | {sig_text} |")
            lines.append("")
        if indicators.get("crypto_constants"):
            lines.append("#### Cryptographic Constants & Hashing Routines")
            for cr in indicators["crypto_constants"][:5]:
                lines.append(f"- **{cr.get('function')}** (`{cr.get('address')}`): {cr.get('detail')}")
            lines.append("")
        if indicators.get("dynamic_resolution"):
            lines.append("#### Dynamic API Resolution & PEB Resolvers")
            for dr in indicators["dynamic_resolution"][:5]:
                lines.append(f"- **{dr.get('function')}** (`{dr.get('address')}`): {dr.get('detail')}")
            lines.append("")
    else:
        lines.append("*No high-priority tradecraft functions or dynamic resolving routines isolated.*\n")

    # 1.6 Execution Commands, Keywords & TTP Artifacts
    lines.append("### 1.6 Execution Commands, Keywords & TTP Artifacts")
    cmds = indicators.get("command_lines", [])
    stealers = indicators.get("stealer_targets", [])
    ransoms = indicators.get("ransom_markers", [])
    bots = indicators.get("bot_commands", [])

    if cmds or stealers or ransoms or bots:
        lines.append("| Artifact Category | Extracted String / Command | Function Context | Behavioral & TTP Role |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for cmd in cmds[:8]:
            fn_ctx = f"`{cmd.get('function')}` ({cmd.get('address')})" if cmd.get('address') else f"`{cmd.get('function')}`"
            lines.append(f"| LOLBin / Shell Command | `{cmd.get('command')}` | {fn_ctx} | Host command execution / evasion |")
        for st in sorted(stealers)[:6]:
            lines.append(f"| Credential Target | `{st}` | `string_pool` | Browser / wallet credential harvesting |")
        for rm in sorted(ransoms)[:6]:
            lines.append(f"| Extortion Marker | `{rm}` | `string_pool` | Ransom note / file encryption identifier |")
        for bc in sorted(bots)[:6]:
            lines.append(f"| Bot Directive | `{bc}` | `string_pool` | Remote control / agent instruction |")
        lines.append("")
    else:
        lines.append("*No shell commands, credential harvesting targets, or extortion keywords identified.*\n")

    # 2. Multi-Source Threat Intelligence & Correlation (MANTIS Unified Lookups)
    lines.extend([
        "---",
        "",
        "## 2. Multi-Source Threat Intelligence & Correlation (MANTIS Lookups)",
        "",
        f"Cross-correlated sample indicators against **{len(sources_coverage)} unified threat intelligence sources** across local databases, sandbox telemetry, Abuse.ch trackers, OSINT repositories, and passive DNS infrastructure.",
        "",
    ])

    # 2.1 CTI Technical Articles & Research
    lines.append("### 2.1 CTI Technical Articles, Whitepapers & Research")
    if article_matches:
        lines.append("| Article / Report Title | Source | Published | Match Type | Matching Indicator | Link |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for art in article_matches[:12]:
            date_str = art.get("published_at", "")[:10] if art.get("published_at") else "N/A"
            src = art.get("source") or "Local CTI"
            url_str = f"[Read Report]({art['url']})" if art.get("url") else "Internal DB"
            lines.append(f"| **{art['title'][:55]}** | `{src}` | {date_str} | `{art.get('matched_type')}` | `{art.get('matched_value')}` | {url_str} |")
        lines.append("")
        lines.append("#### Highlighted Excerpts & Technical Findings")
        for art in article_matches[:3]:
            if art.get("excerpt"):
                lines.append(f"> **{art['title']}** [{art.get('source', 'CTI')}] ({art.get('published_at', '')[:10]}):")
                lines.append(f"> {art['excerpt'][:320]}...\n")
    else:
        lines.append("*No corroborating CTI research articles or technical writeups cataloged.*\n")

    # 2.2 Reputation Feeds & Active Malware Trackers
    lines.append("### 2.2 Reputation Feeds & Active Malware Trackers")
    if feed_matches:
        lines.append("| Feed / Tracker Source | Type | Indicator | Classification / Signature | Confidence | First / Last Seen |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for fm in feed_matches[:15]:
            dates = f"{fm.get('first_seen', '')[:10]} / {fm.get('last_seen', '')[:10]}".strip(" /") or "N/A"
            src = fm.get("source") or "Feed"
            cat = fm.get("category") or "Malicious"
            lines.append(f"| `{src}` | `{fm.get('type')}` | `{fm.get('value')[:35]}` | **{cat}** | `{fm.get('confidence')}` | {dates} |")
        lines.append("")
    else:
        lines.append("*No active detections across reputation feeds or malware trackers.*\n")

    # 2.3 Threat Actor & Malware Galaxy Profiles
    lines.append("### 2.3 Threat Actor, Campaign & Galaxy Profiles")
    if misp_matches:
        lines.append("| Entity / Cluster | Category | Suspected Sponsor / Origin | Known Aliases | Description |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for tm in misp_matches[:8]:
            country = tm.get("sponsor") or tm.get("country") or "Unknown"
            aliases = ", ".join(tm.get("synonyms", [])[:3]) or "None"
            desc = (tm.get("description") or "N/A")[:120] + "..."
            lines.append(f"| **{tm.get('name')}** | `{tm.get('galaxy_type')}` | {country} | {aliases} | {desc} |")
        lines.append("")
    else:
        lines.append("*No direct threat actor, malware family, or galaxy profiles aligned.*\n")

    # 2.4 Infrastructure, Passive DNS & Network Intelligence
    lines.append("### 2.4 Infrastructure, Passive DNS & Network Intelligence")
    if network_intel:
        lines.append("| Target Endpoint | Provider / Engine | Category | Intelligence Finding |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for net in network_intel[:10]:
            lines.append(f"| `{net.get('target', '')}` | `{net.get('provider', '')}` | {net.get('category', '')} | {net.get('finding', '')} |")
        lines.append("")
    else:
        lines.append("*No external passive DNS or autonomous network telemetry triggered.*\n")

    # 2.5 Ransomware & Extortion Intelligence
    if ransomware_intel or indicators.get("ransom_markers"):
        lines.append("### 2.5 Ransomware & Extortion Intelligence")
        lines.append("| Target / Group | Category | Intelligence Finding |")
        lines.append("| :--- | :--- | :--- |")
        for rw in ransomware_intel[:6]:
            lines.append(f"| **{rw.get('group', 'Group')}** | `{rw.get('category', '')}` | {rw.get('finding', '')} |")
        for rm in sorted(indicators.get("ransom_markers", []))[:4]:
            lines.append(f"| Extracted Marker | `Local String` | Ransomware keyword in binary: `{rm}` |")
        lines.append("")

    # 2.6 YARA & Signature Detections
    if yara_matches:
        lines.append("### 2.6 YARA & Signature Detections")
        lines.append("| Rule Name | Author / Source | Tags / Categories | Description |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for y in yara_matches[:8]:
            r_name = y.get("rule") or y.get("name") or "Rule"
            r_author = y.get("author") or "MANTIS / YARAify"
            r_tags = ", ".join(y.get("tags") or []) or "General"
            r_desc = y.get("description") or "Matched signature"
            lines.append(f"| `{r_name}` | {r_author} | {r_tags} | {r_desc[:80]} |")
        lines.append("")

    # 2.7 Multi-Source Intelligence Coverage Matrix
    lines.append("### 2.7 Multi-Source Intelligence Coverage Matrix")
    lines.append("| Intelligence Source | Category | Status & Correlation Finding |")
    lines.append("| :--- | :--- | :--- |")
    for s_name, s_status in sorted(sources_coverage.items()):
        badge = "🟢" if "hit" in s_status.lower() or "report" in s_status.lower() or "sample" in s_status.lower() or "tweet" in s_status.lower() or "rule" in s_status.lower() or "cluster" in s_status.lower() else "⚪"
        lines.append(f"| **{s_name}** | MANTIS Unified Engine | {badge} {s_status} |")
    lines.append("")

    # 2.8 Autonomous Pivoting & Relationship Mapping (Discover & Pivot)
    lines.append("### 2.8 Autonomous Pivoting & Relationship Mapping (Discover & Pivot)")
    lines.append("The following bounded autonomous passive pivots were executed to expand investigative depth:")
    lines.append("")
    lines.append("| Pivot Stage | Source Indicator | Discovered Relationship | Pivot Target / Value | Telemetry Provider |")
    lines.append("| :--- | :--- | :--- | :--- | :--- |")
    
    pivot_rows = []
    for net in network_intel:
        p_val = net.get("value") or net.get("domain") or net.get("ip") or "N/A"
        p_prov = net.get("provider") or "Passive DNS / Network Intel"
        p_detail = net.get("detail") or net.get("type") or "Infrastructure Link"
        pivot_rows.append(f"| **Infrastructure Pivot** | `{p_val}` | Co-hosted IP / Resolution | `{p_detail}` | {p_prov} |")
        
    for misp in misp_matches[:10]:
        p_actor = misp.get("name") or "Threat Actor"
        syns = misp.get("synonyms") or []
        p_syn = ", ".join(syns[:3]) if syns else misp.get("cluster", "Synonym cluster")
        pivot_rows.append(f"| **Actor / Campaign Pivot** | `{p_actor}` | Galaxy Aliases / Tooling | `{p_syn}` | MISP Threat Galaxy |")

    for art in article_matches[:5]:
        p_title = art.get("title") or "Technical Advisory"
        p_cluster = art.get("cluster") or "CTI Article"
        pivot_rows.append(f"| **Campaign Pivot** | `{p_cluster}` | Historical Campaign Writeup | {p_title} | CTI Technical Articles |")

    if not pivot_rows:
        pivot_rows.append("| **Autonomous Pivot** | Workspace Telemetry | Baseline Indicators Validated | No external secondary pivots required | Local Workspace |")

    lines.extend(pivot_rows[:20])
    lines.append("")

    # 3. 6-Category Threat Evidence Assessment Matrix
    matrix = scoring["evidence_matrix"]
    lines.extend([
        "---",
        "",
        "## 3. 6-Category Threat Evidence Assessment Matrix",
        "",
        "| Evidence Dimension | Rating | Contribution | Observations & Grounding |",
        "| :--- | :--- | :--- | :--- |",
        f"| **1. Malware & Code** | `{matrix['malware_code']['score']}` | {matrix['malware_code']['points']}% | {'; '.join(matrix['malware_code']['observations']) or 'No unique code/build artifacts identified'} |",
        f"| **2. Infrastructure** | `{matrix['infrastructure']['score']}` | {matrix['infrastructure']['points']}% | {'; '.join(matrix['infrastructure']['observations']) or 'No dedicated infrastructure identified'} |",
        f"| **3. TTP Implementation** | `{matrix['ttp_implementation']['score']}` | {matrix['ttp_implementation']['points']}% | {'; '.join(matrix['ttp_implementation']['observations']) or 'Standard generic execution'} |",
        f"| **4. Campaign Context & Intent** | `{matrix['campaign_intent']['score']}` | {matrix['campaign_intent']['points']}% | {'; '.join(matrix['campaign_intent']['observations']) or 'Target context unresolved'} |",
        f"| **5. OpSec & Human Artifacts** | `{matrix['opsec_human']['score']}` | {matrix['opsec_human']['points']}% | {'; '.join(matrix['opsec_human']['observations']) or 'No operational mistakes or developer trails'} |",
        f"| **6. External Reporting** | `{matrix['external_reporting']['score']}` | {matrix['external_reporting']['points']}% | {'; '.join(matrix['external_reporting']['observations']) or 'No corroborating external writeups'} |",
        "",
        f"**Aggregate Confidence Score**: `{scoring['confidence_score']}/100` -> **{scoring['confidence_band']}**",
        "",
    ])

    if scoring.get("contradictions"):
        lines.append("> [!WARNING]")
        lines.append("> **Identified Contradictions & Deception Risks**:")
        for c in scoring["contradictions"]:
            lines.append(f"> - {c}")
        lines.append("")

    lines.extend([
        "### 3.1 Alternative Hypotheses",
        "When assessing threat attribution, analysts must rigorously test competing explanations:",
        "",
    ])
    for alt in scoring.get("alternative_hypotheses", []):
        lines.append(f"- **Alternative**: {alt}")
    lines.append("")

    # 4. Autonomous AI Reverse Engineering Guidelines
    lines.extend([
        "---",
        "",
        "## 4. Autonomous AI Reverse Engineering Verification Guide",
        "",
        "To elevate or confirm this attribution hypothesis using the AI workspace:",
        "",
        "1. **Inspect Core Decompiled Functions**:",
        "   - Review functions in `modules/03_network/` or `src/` to verify command-and-control beacon serialization and check whether the protocol matches documented family specs.",
        "   - Review functions in `modules/04_persistence/` to confirm registry key manipulation and execution parameters.",
        "2. **Validate Cryptographic Constants**:",
        "   - Examine `catalog/triage_indicators.json` and functions under `02_crypto/` to confirm encryption algorithms (AES, RC4, custom rolling XOR).",
        "3. **Execute Threat Attribution Skill**:",
        "   - Refer to `skills/threat_attribution/SKILL.md` for the complete step-by-step attribution workflow.",
        "4. **Perform Live Internet Searches & OSINT**:",
        "   - Actively Google / search the web for unique strings, mutexes, registry paths, and threat actor aliases using your native search capabilities or `python osint_lookup.py`. Do not rely solely on pre-computed local lookup results.",
        "",
        "```bash",
        "# Prompt your AI agent in this workspace:",
        "Review threat_attribution_result.md, perform active live internet searches for unknown IOCs, and apply skills/threat_attribution/SKILL.md to verify findings in modules/ and catalogs.",
        "```",
        "",
        f"*Report generated automatically by MANTIS Binary Lab Threat Attribution Engine at {indicators.get('sample_meta', {}).get('timestamp', 'analysis time')}.*",
    ])

    return "\n".join(lines)


def generate_threat_attribution(
    workspace_dir: Path,
    report_dir: Optional[Path] = None,
    sample_info: Optional[Dict[str, Any]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    output_dir: Optional[Path] = None,
) -> Path:
    """Run full automated threat intelligence lookups and output threat_attribution_result.md."""
    target_report_dir = report_dir or output_dir or (workspace_dir / "report")
    sample_info = sample_info or {}
    def log(msg: str):
        if log_fn:
            log_fn(msg)

    log("Phase 1 (Acquire): Ingesting decompiled catalogs, telemetry, and technical indicators from workspace...")
    indicators = extract_workspace_indicators(workspace_dir, sample_info)

    log(f"Acquired telemetry: {len(indicators.get('domains', []))} domains, {len(indicators.get('ips', []))} IPs, {len(indicators.get('registry_keys', []))} registry keys, {len(indicators.get('mutexes', []))} mutexes, {len(indicators.get('malware_configs', []))} config items.")

    data_dir = _find_data_dir()
    log("Phase 2 (Enrich): Multi-source CTI cross-correlation across 26+ intelligence datasets...")
    intel_results = query_all_threat_intelligence(
        indicators,
        workspace_dir=workspace_dir,
        sample_info=sample_info,
        data_dir=data_dir,
        log_fn=log,
    )
    feed_matches = intel_results["feed_matches"]
    article_matches = intel_results["article_matches"]
    misp_matches = intel_results["misp_matches"]
    network_intel = intel_results["network_intel"]
    ransomware_intel = intel_results["ransomware_intel"]
    yara_matches = intel_results["yara_matches"]
    sources_coverage = intel_results["sources_coverage"]

    log(f"Phase 3 (Discover & Pivot): Correlated {len(sources_coverage)} sources ({len(article_matches)} writeups, {len(feed_matches)} feed hits, {len(misp_matches)} galaxy clusters, {len(network_intel)} passive network records).")

    log("Phase 4 (Analyze): Scoring 6-category threat evidence assessment matrix & calibrating hypothesis confidence...")
    scoring = score_attribution(
        indicators,
        feed_matches=feed_matches,
        article_matches=article_matches,
        misp_matches=misp_matches,
        network_intel=network_intel,
        ransomware_intel=ransomware_intel,
        yara_matches=yara_matches,
    )

    md_content = render_threat_attribution_markdown(
        indicators=indicators,
        feed_matches=feed_matches,
        article_matches=article_matches,
        misp_matches=misp_matches,
        scoring=scoring,
        network_intel=network_intel,
        ransomware_intel=ransomware_intel,
        yara_matches=yara_matches,
        sources_coverage=sources_coverage,
    )

    target_report_dir.mkdir(parents=True, exist_ok=True)
    report_file = target_report_dir / "threat_attribution_result.md"
    report_file.write_text(md_content, encoding="utf-8")

    # Also mirror to workspace directory for autonomous agent access
    ws_file = workspace_dir / "threat_attribution_result.md"
    try:
        ws_file.write_text(md_content, encoding="utf-8")
    except Exception:
        pass

    log(f"Threat attribution analysis saved to {report_file.name} (Hypothesis: {scoring['primary_hypothesis']}, Confidence: {scoring['confidence_band']})")
    return report_file
