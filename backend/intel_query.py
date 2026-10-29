import requests
import json
import os
import urllib3
import re
import base64
import urllib.parse
import ipaddress
import sqlite3
import time
import html
import hashlib
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from collections import Counter
import requests
import json
import os
import urllib3
import re
import base64
import urllib.parse
import ipaddress
import sqlite3
import time
import html
import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from collections import Counter
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor
from misp_query import query_misp_galaxy, query_misp_ioc
import tweetfeed_service

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("mantis.twitterapi")

YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "data", "yara-rules")
LOCAL_YARA_RULE_HEAD_RE = re.compile(
    r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::\s*([^\{\r\n]*))?\s*\{"
)

def query_local_rss(indicator: str) -> Dict[str, Any]:
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rss_intel.db")
    if not os.path.exists(db_path):
        return {"error": "RSS database not found"}
    text = (indicator or "").strip()
    if not text:
        return {"data": []}
    # Exact matching only works for atomic IOCs, but callers also pass full
    # URLs and free-text keywords (which can never equal a stored row): pull
    # any IOC candidates out of the input and fall back to a title substring
    # search for whatever is left.
    candidates = {text.lower()}
    try:
        from rss_manager import extract_iocs
        for val, _typ in extract_iocs(text):
            candidates.add(val.lower())
    except Exception:
        pass

    try:
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in candidates)
            cursor.execute(f'''
                SELECT a.title, a.link, a.published_date, a.source_feed, i.ioc_type
                FROM articles a
                JOIN iocs i ON a.id = i.article_id
                WHERE i.ioc_value IN ({placeholders})
            ''', tuple(candidates))
            results = cursor.fetchall()
            exact_ioc_search = bool(_exact_ioc_search_kind(text))
            if not results and not exact_ioc_search:
                tokens = [t for t in re.split(r"\s+", text.lower()) if len(t) >= 4][:5]
                if tokens:
                    conds = " OR ".join("LOWER(a.title) LIKE ?" for _ in tokens)
                    cursor.execute(f'''
                        SELECT a.title, a.link, a.published_date, a.source_feed, i.ioc_type
                        FROM articles a
                        JOIN iocs i ON a.id = i.article_id
                        WHERE {conds}
                        LIMIT 200
                    ''', tuple(f"%{t}%" for t in tokens))
                    results = cursor.fetchall()
        finally:
            conn.close()

        if not results:
            return {"data": []}

        def rss_date_key(row):
            try:
                return parsedate_to_datetime(row[2]).timestamp() if row[2] else 0
            except Exception:
                return 0

        data = []
        seen_rows = set()
        for row in sorted(set(results), key=rss_date_key, reverse=True)[:50]:
            if row in seen_rows:
                continue
            seen_rows.add(row)
            data.append({
                "title": row[0],
                "link": row[1],
                "published_date": row[2],
                "source_feed": row[3],
                "matched_type": row[4]
            })

        return {"data": data}
    except Exception as e:
        return {"error": str(e)}

def query_local_yara_rules(keyword: str, tip_key: str = "") -> Dict[str, Any]:

    if not os.path.exists(YARA_RULES_DIR):
        return {"error": "Local Yara rules directory not found. Please restart the backend to trigger the updater."}
    
    keyword = (keyword or "").strip().lower()
    if not keyword:
        return {"matches": []}
    matches = []
    
    yara_files = []
    for root, dirs, files in os.walk(YARA_RULES_DIR):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                yara_files.append(os.path.join(root, file))
                
    if not yara_files:
        return {"error": "No .yar or .yara files found in data/yara-rules/"}

    try:
        for yfile in yara_files:
            if len(matches) >= 50:
                break
                
            try:
                with open(yfile, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                continue
                
            rule_heads = list(LOCAL_YARA_RULE_HEAD_RE.finditer(content or ""))
            for idx, head in enumerate(rule_heads):
                full_rule = content[head.start():rule_heads[idx + 1].start() if idx + 1 < len(rule_heads) else len(content)].strip()
                if keyword in full_rule.lower():
                    rule_name = head.group(1)
                    # Determine source based on path
                    source = "Unknown"
                    yfile_lower = yfile.lower()
                    if "kaspersky" in yfile_lower: source = "Kaspersky TIP"
                    elif "elastic" in yfile_lower: source = "Elastic"
                    elif "yaraify" in yfile_lower: source = "Yaraify"
                    elif "yara-forge" in yfile_lower: source = "YARA Forge"
                    
                    matches.append({
                        "rule_name": rule_name,
                        "content": full_rule,
                        "source": source,
                        "file": os.path.relpath(yfile, YARA_RULES_DIR).replace("\\", "/")
                    })
                    if len(matches) >= 50:
                        break
                        
        if not matches:
            return {"matches": []}
        return {"matches": matches}
    except Exception as e:
        return {"error": str(e)}

def _json_request(method: str, url: str, label: str = "request", **kwargs) -> Any:
    try:
        resp = requests.request(method, url, timeout=kwargs.pop("timeout", 15), **kwargs)
        content_type = resp.headers.get("content-type", "")
        if resp.status_code == 204:
            return {"data": []}
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"text": resp.text}
        if resp.status_code == 404:
            return {"error": "Not Found"}
        if "html" in content_type.lower() or resp.text.lstrip().lower().startswith(("<!doctype html", "<html")):
            if resp.status_code in (401, 403):
                return {"error": f"{label} access denied ({resp.status_code}); provider returned an HTML challenge page"}
            return {"error": f"{label} provider returned HTML instead of JSON ({resp.status_code})"}
        detail = re.sub(r"\s+", " ", resp.text or "").strip()
        return {"error": f"{label} status {resp.status_code}" + (f" - {detail[:300]}" if detail else "")}
    except Exception as e:
        return {"error": f"{label} failed", "message": str(e)}

def _keep_success(results: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in results.items() if v is not None and not (isinstance(v, dict) and v.get("error"))}

# Single source-of-truth provider capability registry.
# ALLOWED_SOURCES (backend validation) and GET /api/meta/sources (frontend
# selector) are both derived from this. Keep per-lookup flags in sync with
# what each provider function actually supports.
SOURCE_CAPABILITIES = {
    "virustotal": {"label": "VirusTotal", "key": "vt", "icon": "fa-solid fa-shield-virus", "category": "ioc", "aliases": ["vt"], "hash": True, "domain": True, "ip": True, "url": True, "keyword": False, "infra": True},
    "threatfox": {"label": "ThreatFox", "key": "abusech", "icon": "fa-solid fa-bug", "category": "ioc", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "infra": False},
    "malwarebazaar": {"label": "MalwareBazaar", "key": "abusech", "icon": "fa-solid fa-database", "category": "malware", "hash": True, "domain": False, "ip": False, "url": False, "keyword": True, "infra": False},
    "yaraify": {"label": "YARAify", "key": "abusech", "icon": "fa-solid fa-code", "category": "malware", "hash": True, "domain": False, "ip": False, "url": False, "keyword": True, "infra": False},
    "alienvault": {"label": "AlienVault OTX", "key": "otx", "icon": "fa-solid fa-satellite-dish", "category": "ioc", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "infra": False},
    "triage": {"label": "Triage Sandbox", "key": "triage", "icon": "fa-solid fa-laptop-code", "category": "malware", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "infra": False},
    "hybrid-analysis": {"label": "Hybrid Analysis", "key": "ha", "icon": "fa-solid fa-microchip", "category": "sandbox_intelligence", "aliases": ["hybrid_analysis"], "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": False, "infra": True, "passive_only": True, "submission": False},
    "malshare": {"label": "MalShare", "key": "malshare", "icon": "fa-solid fa-share-nodes", "category": "malware_repository", "hash": True, "domain": False, "ip": False, "url": False, "keyword": True, "threat_actor": False, "infra": False, "passive_only": True, "submission": False, "bulk_hash": True, "file_type_search": True, "recent_samples": True, "sample_download": False},
    "tip": {"label": "Kaspersky TIP", "key": "tip", "icon": "fa-solid fa-shield-halved", "category": "ioc", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "infra": False},
    "cb": {"label": "CyberBriefing", "key": "cb", "icon": "fa-solid fa-briefcase", "category": "cti", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": True, "cve": True, "infra": False},
    "dnsdumpster": {"label": "DNSDumpster", "key": "dnsdumpster", "requires_api_key": False, "optional_api_key": True, "key_required": True, "icon": "fa-solid fa-sitemap", "category": "dns_infrastructure", "hash": False, "domain": True, "ip": False, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False, "domain_lookup": True, "dns_records": True, "banners": True, "cidr_banners": True, "pagination": True, "domain_map": True, "plan_dependent": True},
    "urlscan": {"label": "URLScan.io", "key": "urlscan", "icon": "fa-solid fa-magnifying-glass-chart", "category": "web_intelligence", "hash": False, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": False, "infra": True, "passive_only": True, "submission": False},
    "reputation_feeds": {"label": "Reputation Feeds", "key": None, "icon": "fa-solid fa-satellite-dish", "category": "threat_intelligence", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "infra": False, "passive_only": True},
    "threatbook": {"label": "ThreatBook Community", "key": "threatbook", "icon": "fa-solid fa-book-skull", "category": "ip_intelligence", "community": True, "hash": False, "domain": False, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": False},
    "orkl": {"label": "ORKL CTI", "key": None, "icon": "fa-solid fa-book-journal-whills", "category": "cti_library", "hash": False, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": True, "cve": True, "infra": False},
    "shodan": {"label": "Shodan", "key": "shodan", "requires_api_key": False, "optional_api_key": True, "key_required": True, "icon": "fa-solid fa-globe", "category": "internet_infrastructure", "hash": False, "domain": False, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False, "host_lookup": True, "historical_host": "plan_dependent", "banner_search": True, "facets": True, "dns": "plan_dependent", "vulnerability_context": "plan_dependent"},
    "censys": {"label": "Censys", "key": "censys", "requires_api_key": False, "optional_api_key": True, "key_required": True, "icon": "fa-solid fa-magnifying-glass-location", "category": "internet_infrastructure", "hash": False, "domain": False, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False, "host_lookup": True, "web_property_lookup": True, "certificate_lookup": True, "global_search": "plan_dependent", "aggregate": "plan_dependent", "host_history": "plan_dependent", "adversary_investigation": "plan_dependent", "live_rescan": False},
    "silentpush": {"label": "Silent Push", "key": "silentpush", "requires_api_key": False, "optional_api_key": True, "key_required": True, "icon": "fa-solid fa-eye-slash", "category": "threat_infrastructure", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False, "domain_enrichment": True, "ipv4_enrichment": True, "ipv6_enrichment": True, "padns": True, "reverse_padns": True, "domain_search": True, "spql": "plan_dependent", "existing_scan_data": "plan_dependent", "threat_ranking": "plan_dependent", "iofa": "plan_dependent", "live_scan": False, "live_screenshot": False, "feed_mutation": False},
    "driftnet": {"label": "Driftnet", "key": "driftnet", "requires_api_key": False, "optional_api_key": True, "key_required": True, "icon": "fa-solid fa-network-wired", "category": "internet_infrastructure", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False, "internet_scan": True, "domain_scan": True, "open_ports": True, "passive_dns": True, "reverse_dns": True, "whois": True, "bgp": True, "certificate_transparency": True, "favicon": True, "ja4": True, "ja4t": True, "jarm": True, "http_body_search": True, "prioritization": False, "active_collection": False},
    "netlas": {"label": "Netlas", "key": "netlas", "requires_api_key": False, "optional_api_key": True, "key_required": True, "icon": "fa-solid fa-globe", "category": "internet_infrastructure", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False, "response_search": True, "certificate_search": True, "dns_search": True, "facets": True, "active_scan": False},
    "zoomeye": {"label": "ZoomEye", "key": "zoomeye", "requires_api_key": True, "key_required": True, "icon": "fa-solid fa-magnifying-glass-location", "category": "internet_infrastructure", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False, "host_search": True, "service_search": True, "banner_search": True, "active_scan": False},
    "pulsedive": {"label": "Pulsedive", "key": "pulsedive", "requires_api_key": False, "optional_api_key": True, "icon": "fa-solid fa-water", "category": "threat_intelligence", "hash": False, "domain": True, "ip": True, "url": True, "keyword": True, "infra": True, "threat_actor": True, "passive_only": True, "submission": False, "indicator_lookup": True, "indicator_links": True, "indicator_properties": True, "historical_properties": True, "explore": True, "threats": True, "threat_indicators": True, "feeds": True, "feed_indicators": True, "analyze": False, "scan": False, "probe": False, "submit": False},
    "validin": {"label": "Validin", "key": "validin", "icon": "fa-solid fa-shield-halved", "category": "dns_infrastructure", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "infra": True, "passive_only": True, "submission": False, "dns_history": True, "subdomains": True, "http_observations": True, "certificate_transparency": True, "certificate_search": "plan_dependent", "fingerprint_pivots": True, "threat_intelligence": "plan_dependent", "reputation": "plan_dependent", "registration_history": "plan_dependent", "advanced_search": "plan_dependent", "live_scan": False, "custom_crawling": False, "monitoring_mutation": False},
    "etugen": {"label": "Etugen", "key": "etugen", "icon": "fa-solid fa-crosshairs", "category": "infrastructure", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "infra": True},
    "fofa": {"label": "FOFA", "key": "fofa", "requires_api_key": False, "optional_api_key": True, "key_required": True, "icon": "fa-solid fa-search-location", "category": "internet_infrastructure", "hash": False, "domain": False, "ip": False, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False, "asset_search": True, "ip_search": True, "domain_search": True, "asn_search": True, "certificate_search": "plan_dependent", "jarm_search": True, "ja3s_search": True, "fingerprint_search": "plan_dependent", "product_search": "plan_dependent", "continuous_pagination": "api_supported", "historical_search": "plan_dependent", "asset_refresh": False, "active_scan": False},
    "archive": {"label": "Internet Archive", "key": None, "icon": "fa-solid fa-landmark", "category": "historical_web_intelligence", "hash": False, "domain": True, "ip": False, "url": True, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False, "wayback": True, "snapshot_search": True, "historical_urls": True, "timeline": True, "historical_content": True, "save_page": False},
    "abuseipdb": {"label": "AbuseIPDB", "key": "abuseipdb", "icon": "fa-solid fa-user-ninja", "category": "ip_reputation", "hash": False, "domain": False, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False},
    "yara_forge": {"label": "Local Yara Rules", "key": None, "icon": "fa-solid fa-code", "category": "local_rules", "hash": True, "domain": False, "ip": False, "url": False, "keyword": True, "infra": False},
    "ransomlook": {"label": "RansomLook.io", "key": None, "icon": "fa-solid fa-magnifying-glass-dollar", "category": "ransomware", "hash": False, "domain": False, "ip": False, "url": False, "keyword": True, "threat_actor": True, "ransomware_group": True, "ransomware_victim": True, "infra": False},
    "rwlive": {"label": "Ransomware.live", "key": "rwlive", "icon": "fa-solid fa-heart-pulse", "category": "ransomware", "hash": False, "domain": True, "ip": False, "url": False, "keyword": True, "threat_actor": True, "ransomware_group": True, "ransomware_victim": True, "country": True, "sector": True, "yara": True, "kql": False, "infra": True, "api_pro": True, "victim_details": True, "iocs": True, "ransom_notes": True, "negotiations": True, "statistics": True},
    "misp": {"label": "MISP Intelligence", "key": "misp", "requires_api_key": True, "key_required": True, "icon": "fa-solid fa-diagram-project", "category": "threat_intelligence", "hash": True, "domain": True, "ip": True, "url": True, "keyword": False, "infra": False, "passive_only": True, "read_only": True, "submission": False, "contextual_correlation": True, "events": True, "related_indicators": True, "galaxies": True, "taxonomies": True, "warninglists": True, "sightings": True, "event_reports": True, "enrichment": False, "mutation": False},
    "misp_galaxy": {"label": "MISP Galaxy", "key": None, "icon": "fa-solid fa-meteor", "category": "knowledge_base", "hash": False, "domain": False, "ip": False, "url": False, "keyword": True, "infra": False},
    "threat_actor_knowledge": {"label": "Threat Actor", "key": None, "icon": "fa-solid fa-user-secret", "category": "knowledge_base", "hash": False, "domain": False, "ip": False, "url": False, "keyword": True, "threat_actor": True, "infra": False, "passive_only": True},
    "malware_tools_knowledge": {"label": "Malware & Tools", "key": None, "icon": "fa-solid fa-screwdriver-wrench", "category": "knowledge_base", "hash": False, "domain": False, "ip": False, "url": False, "keyword": True, "infra": False, "passive_only": True},
    "ransom_yara_explorer": {"label": "Ransomware Monitor YARA", "key": "rwlive", "requires_api_key": False, "optional_api_key": True, "icon": "fa-solid fa-code", "category": "ransomware", "hash": False, "domain": False, "ip": False, "url": False, "keyword": True, "ransomware_group": True, "yara": True, "infra": False, "passive_only": True},
    "vulnerability_intel": {"label": "Vulnerability Intelligence", "key": None, "icon": "fa-solid fa-bug-slash", "category": "vulnerability", "hash": False, "domain": False, "ip": False, "url": False, "keyword": True, "cve": True, "infra": False, "passive_only": True},
    "x_monitor": {"label": "X Monitor", "key": None, "icon": "fa-brands fa-twitter", "category": "social_intelligence", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": True, "infra": False, "passive_only": True},
    "threatactorusernames": {"label": "ThreatActorUsernames", "key": None, "icon": "fa-solid fa-user-secret", "category": "cti", "hash": False, "domain": False, "ip": False, "url": False, "keyword": True, "threat_actor": True, "infra": False},
    "github_repos": {"label": "GitHub Threat Intel Repos", "key": "github", "requires_api_key": False, "optional_api_key": True, "icon": "fa-brands fa-github", "category": "code_intelligence", "hash": True, "domain": False, "ip": False, "url": False, "keyword": True, "infra": False, "passive_only": True, "submission": False, "repository_search": True},
    "twitter": {"label": "Twitter/X", "key": "twitter", "icon": "fa-brands fa-twitter", "category": "social_intelligence", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": False, "infra": False, "passive_only": True, "submission": False, "tweet_search": True, "user_search": True, "user_profile": True, "user_network": True, "conversation": True, "lists": False, "communities": False, "trends": False},
    "tweetfeed": {"label": "TweetFeed", "key": None, "icon": "fa-solid fa-rss", "category": "social_ioc_intelligence", "hash": True, "domain": True, "ip": True, "url": True, "keyword": False, "infra": False, "passive_only": True, "submission": False, "exact_ioc_lookup": True, "campaign_context": True, "reporter_context": True},
    "github": {"label": "GitHub", "key": "github", "requires_api_key": False, "optional_api_key": True, "icon": "fa-brands fa-github", "category": "code_intelligence", "hash": True, "domain": False, "ip": False, "url": True, "keyword": True, "threat_actor": False, "infra": False, "passive_only": True, "submission": False, "code_search": True, "repository_search": True, "repository_details": True, "commit_intelligence": True, "user_search": True, "organization_search": True, "issues": True, "releases": True},
    "malware_news": {"label": "Malware.News", "key": None, "icon": "fa-solid fa-newspaper", "category": "cti_content", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "rss_intel": {"label": "Local RSS", "key": None, "icon": "fa-solid fa-rss", "category": "osint", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "infra": False},
    "cti_articles": {"label": "CTI Articles", "key": None, "icon": "fa-solid fa-file-lines", "category": "local_articles", "hash": True, "domain": True, "ip": True, "url": True, "keyword": True, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "threatminer": {"label": "ThreatMiner", "key": None, "icon": "fa-solid fa-magnifying-glass-chart", "category": "ioc", "hash": True, "domain": True, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "urlhaus": {"label": "URLhaus", "key": "abusech", "icon": "fa-solid fa-link-slash", "category": "malware", "hash": True, "domain": False, "ip": False, "url": True, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "greynoise": {"label": "GreyNoise", "key": "greynoise", "requires_api_key": False, "optional_api_key": True, "icon": "fa-solid fa-cloud-bolt", "category": "internet_intelligence", "hash": False, "domain": False, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False},
    "crtsh": {"label": "crt.sh", "key": None, "icon": "fa-solid fa-certificate", "category": "certificate_transparency", "hash": False, "domain": True, "ip": False, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False},
    "ripe": {"label": "RIPEstat", "key": None, "icon": "fa-solid fa-network-wired", "category": "routing", "hash": False, "domain": False, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": True, "passive_only": True, "submission": False},
    "leakix": {"label": "LeakIX", "key": "leakix", "icon": "fa-solid fa-eye", "category": "internet_intelligence", "hash": False, "domain": True, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "phishstats": {"label": "PhishStats", "key": "phishstats", "requires_api_key": False, "optional_api_key": True, "icon": "fa-solid fa-fish", "category": "phishing", "hash": False, "domain": True, "ip": True, "url": True, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "openphish": {"label": "OpenPhish", "key": None, "icon": "fa-solid fa-envelope-open-text", "category": "phishing", "hash": False, "domain": True, "ip": False, "url": True, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "commoncrawl": {"label": "Common Crawl", "key": None, "icon": "fa-solid fa-box-archive", "category": "historical", "hash": False, "domain": True, "ip": False, "url": False, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
    "sans": {"label": "SANS ISC", "key": None, "icon": "fa-solid fa-shield-halved", "category": "internet_intelligence", "hash": False, "domain": False, "ip": True, "url": False, "keyword": False, "threat_actor": False, "infra": False, "passive_only": True, "submission": False},
}

_LOOKUP_TYPES = ("hash", "domain", "ip", "url", "keyword", "infra")

def _build_allowed_sources() -> Dict[str, set]:
    allowed: Dict[str, set] = {t: set() for t in _LOOKUP_TYPES}
    for pid, meta in SOURCE_CAPABILITIES.items():
        names = [pid] + list(meta.get("aliases", []))
        for lookup in _LOOKUP_TYPES:
            if meta.get(lookup):
                allowed[lookup].update(names)
    return allowed

ALLOWED_SOURCES = _build_allowed_sources()

# Frontend key-id -> server-side env vars probed for a configured key.
# Mirrors each provider's own resolution code; used only to report
# `server_key` presence to the UI (never the secret itself).
SERVER_KEY_ENVS = {
    "vt": ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "MANTIS_VT_KEY", "IOCINTEL_VT_KEY"),
    "shodan": ("SHODAN_API_KEY", "MANTIS_SHODAN_KEY", "IOCINTEL_SHODAN_KEY"),
    "censys": ("CENSYS_PAT", "CENSYS_API_KEY", "CENSYS_API_TOKEN",
               "MANTIS_CENSYS_PAT", "MANTIS_CENSYS_KEY",
               "IOCINTEL_CENSYS_PAT", "IOCINTEL_CENSYS_KEY"),
    "silentpush": ("SILENT_PUSH_API_KEY", "SILENTPUSH_API_KEY", "SILENT_PUSH_KEY",
                   "MANTIS_SILENTPUSH_KEY", "MANTIS_SILENT_PUSH_KEY",
                   "IOCINTEL_SILENTPUSH_KEY", "IOCINTEL_SILENT_PUSH_KEY"),
    "driftnet": ("DRIFTNET_API_TOKEN", "DRIFTNET_API_KEY", "DRIFTNET_TOKEN",
                 "MANTIS_DRIFTNET_TOKEN", "MANTIS_DRIFTNET_KEY",
                 "IOCINTEL_DRIFTNET_TOKEN", "IOCINTEL_DRIFTNET_KEY"),
    "pulsedive": ("PULSEDIVE_API_KEY", "PULSEDIVE_KEY",
                  "MANTIS_PULSEDIVE_KEY", "MANTIS_PULSEDIVE_TOKEN",
                  "IOCINTEL_PULSEDIVE_KEY", "IOCINTEL_PULSEDIVE_TOKEN"),
    "fofa": ("FOFA_API_KEY", "MANTIS_FOFA_KEY", "IOCINTEL_FOFA_KEY", "FOFA_KEY"),
    "netlas": ("NETLAS_API_KEY", "MANTIS_NETLAS_API_KEY", "IOCINTEL_NETLAS_API_KEY"),
    "zoomeye": ("ZOOMEYE_API_KEY", "MANTIS_ZOOMEYE_API_KEY", "IOCINTEL_ZOOMEYE_API_KEY"),
    "dnsdumpster": ("DNSDUMPSTER_API_KEY", "MANTIS_DNSDUMPSTER_KEY",
                    "IOCINTEL_DNSDUMPSTER_KEY"),
    "github": ("GITHUB_TOKEN", "GITHUB_API_TOKEN"),
    "rwlive": ("RANSOMWARE_LIVE_API_KEY",),
    "misp": ("MISP_API_KEY", "MISP_AUTH_KEY", "MANTIS_MISP_KEY", "MANTIS_MISP_API_KEY",
             "IOCINTEL_MISP_KEY", "IOCINTEL_MISP_API_KEY"),
}


def has_server_key(key_id: str) -> bool:
    """True when a server-side env key is configured for a provider key-id."""
    if not key_id:
        return False
    return any((os.environ.get(name) or "").strip()
               for name in SERVER_KEY_ENVS.get(key_id, ()))


def get_source_metadata() -> Dict[str, List[Dict[str, Any]]]:
    """Frontend-friendly source registry grouped by lookup type.

    Internal provider IDs are excluded.

    `server_key` reports whether a server-side env key is configured, so the
    UI can leave a pill unlocked even when the browser holds no key.
    `key_required` marks providers that error out when NO key exists anywhere
    (browser or server); keyless-capable ones (Pulsedive, GitHub, …) omit it.
    """
    tabs: Dict[str, List[Dict[str, Any]]] = {}
    for lookup in _LOOKUP_TYPES:
        tabs[lookup] = [
            {
                "id": pid,
                "label": meta.get("label", pid),
                "key": meta.get("key"),
                "icon": meta.get("icon"),
                "category": meta.get("category"),
                "requires_api_key": bool(meta.get("requires_api_key", meta.get("key") is not None)),
                "optional_api_key": bool(meta.get("optional_api_key", False)),
                "key_required": bool(meta.get("key_required", False)),
                "server_key": has_server_key(meta.get("key")),
                "capabilities": {
                    k: v for k, v in meta.items()
                    if k not in {"label", "key", "icon", "category", "internal", "requires_api_key", "optional_api_key", "key_required"}
                },
            }
            for pid, meta in SOURCE_CAPABILITIES.items()
            if meta.get(lookup) and not meta.get("internal")
        ]
    return tabs

SOURCE_EXPANSIONS = {
    "hash": {},
    "domain": {},
    "ip": {},
    "url": {},
    "infra": {},
    "keyword": {},
}

def _allowed_sources(query_type: str, sources: List[str] = None) -> set:
    allowed = ALLOWED_SOURCES.get(query_type, set())
    requested = set(sources or [])
    if not requested:
        requested = set(allowed)
    expanded = set(requested)
    for source in list(requested):
        expanded.update(SOURCE_EXPANSIONS.get(query_type, {}).get(source, set()))
    return expanded & allowed

def is_not_found_error(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    message = str(data.get("error") or data.get("message") or data.get("detail") or "").strip().lower()
    return message in {"not found", "no data", "no results", "404", "http 404"}

def _collect_futures(futures: Dict[str, Any]) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for key, future in futures.items():
        try:
            results[key] = future.result()
        except Exception as e:
            results[key] = {"error": str(e)}
    return results

def _collect_callables(callables: Dict[str, Any], max_workers: int = 8) -> Dict[str, Any]:
    if not callables:
        return {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(callables))) as executor:
        futures = {name: executor.submit(fn) for name, fn in callables.items()}
        return _collect_futures(futures)

def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

VT_RELATION_MAP = {
    "contacted_domains": "communicates_with",
    "contacted_ips": "communicates_with",
    "contacted_urls": "communicates_with",
    "communicating_files": "communicates_with",
    "downloaded_files": "downloads",
    "dropped_files": "drops",
    "embedded_urls": "contains",
    "embedded_ips": "contains",
    "bundled_files": "contains",
    "compressed_parents": "contained_by",
    "execution_parents": "contained_by",
    "referrer_files": "refers_to",
    "similar_files": "similar_to",
    "resolutions": "resolves_to",
    "subdomains": "resolves_to",
    "redirecting_urls": "redirects",
    "redirects_to": "redirects_to",
    "historical_ssl_certificates": "associated_with_certificate",
    "historical_whois": "associated_with_registration",
    "related_threat_actors": "associated_with_actor",
    "related_references": "mentioned_in",
    "collections": "mentioned_in",
    "comments": "mentioned_in",
}

def normalize_vt_relation_items(relation: str, items: List[Any]) -> List[Dict[str, Any]]:
    normalized = []
    relation_type = VT_RELATION_MAP.get(relation, relation)
    for item in items or []:
        if not isinstance(item, dict):
            continue
        attr = item.get("attributes") or {}
        value = attr.get("url") or attr.get("ip_address") or attr.get("host_name") or item.get("id")
        normalized.append({
            "relation": relation_type,
            "provider_relation": relation,
            "source": "virustotal",
            "target_type": item.get("type"),
            "value": value,
            "id": item.get("id"),
        })
    return normalized

# Shared IOC defanging/refanging utilities (usable by Malware.News, GitHub,
# Twitter/X, RSS/article and other text-oriented CTI providers — never by
# structured IOC APIs, which receive canonical values only).
# Small centralized set of common CTI conventions; no Cartesian explosion.
DEFANG_DOT_ALTERNATIVE = r"\[\.\] |\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}".replace(" ", "")
DEFANG_SCHEME_MAP = (("hxxps", "https"), ("hxxp", "http"))


def refang_value(value: str) -> str:
    """Restore a defanged IOC to canonical form (hxxp->http, [.] '(.)' etc)."""
    text = (value or "").strip()
    lowered = text.lower()
    for defanged, canonical in DEFANG_SCHEME_MAP:
        if lowered.startswith(defanged + "://") or lowered.startswith(defanged + "[:]//"):
            text = canonical + text[len(defanged):]
            lowered = text.lower()
            break
    text = re.sub(r"\[:\]//", "://", text)
    text = re.sub(DEFANG_DOT_ALTERNATIVE, ".", text, flags=re.IGNORECASE)
    return text.strip()


def is_defanged(value: str) -> bool:
    text = (value or "").strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered.startswith(("hxxp://", "hxxps://", "hxxp[:]//", "hxxps[:]//")):
        return True
    return bool(re.search(DEFANG_DOT_ALTERNATIVE, text, re.IGNORECASE))


def defang_search_variants(canonical: str, kind: str) -> List[str]:
    """Canonical + a small controlled set of defanged search variants."""
    canonical = (canonical or "").strip()
    if not canonical:
        return []
    kind = (kind or "").strip().lower()
    if kind == "domain":
        host = canonical.lower().rstrip(".")
        return list(dict.fromkeys([host, host.replace(".", "[.]"),
                                   host.replace(".", "(.)"),
                                   host.replace(".", "[dot]")]))
    if kind in {"ip", "ipv4"}:
        return list(dict.fromkeys([canonical, canonical.replace(".", "[.]"),
                                   canonical.replace(".", "(.)"),
                                   canonical.replace(".", "[dot]")]))
    if kind == "url":
        parsed = urllib.parse.urlsplit(canonical if "://" in canonical else f"//{canonical}")
        host = (parsed.hostname or "").rstrip(".")
        if not host:
            return [canonical]
        scheme = (parsed.scheme or "https").lower()
        hx_scheme = "hxxps" if scheme == "https" else "hxxp"
        rest = urllib.parse.urlunsplit(("", parsed.netloc.replace(host, host.replace(".", "[.]")),
                                        parsed.path or "", parsed.query or "", ""))
        variants = [canonical, f"{hx_scheme}:{rest}", f"{hx_scheme}[:]{rest}",
                    f"{scheme}[:]{rest}"]
        return list(dict.fromkeys(variants))[:5]
    return [canonical]


def classify_canonical_ioc(value: str) -> str:
    """Return domain/ip/url/hash/'' for a canonical candidate."""
    value = (value or "").strip()
    if not value:
        return ""
    if is_ip(value):
        return "ip"
    if is_url(value):
        return "url"
    if get_hash_type(value) in {"md5", "sha1", "sha256"}:
        return "hash"
    if is_domain(value):
        return "domain"
    return ""


def _exact_ioc_search_kind(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    canonical = refang_value(raw) if is_defanged(raw) else raw
    kind = classify_canonical_ioc(canonical)
    if kind:
        return kind
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", canonical, re.IGNORECASE):
        return "cve"
    return ""


def _text_contains_exact_ioc(text: str, value: str) -> bool:
    """Exact IOC containment for article providers.

    This intentionally avoids keyword token matching: IP/domain lookups must
    not match partial labels such as "100", "10", or "dns".
    """
    canonical = refang_value(value) if is_defanged(value) else (value or "").strip()
    kind = _exact_ioc_search_kind(canonical)
    if not kind:
        return False
    haystack = refang_value(str(text or "")).lower()
    needle = canonical.lower()
    if kind == "ip":
        pattern = rf"(?<![0-9A-Fa-f:.]){re.escape(needle)}(?![0-9A-Fa-f:.])"
    elif kind == "domain":
        pattern = rf"(?<![A-Za-z0-9_.-]){re.escape(needle.rstrip('.'))}(?![A-Za-z0-9_.-])"
    elif kind == "url":
        pattern = rf"(?<![A-Za-z0-9]){re.escape(needle.rstrip('/'))}(?:/)?(?![A-Za-z0-9/?#&=._:-])"
    elif kind == "hash":
        pattern = rf"(?<![A-Fa-f0-9]){re.escape(needle)}(?![A-Fa-f0-9])"
    elif kind == "cve":
        pattern = rf"(?<![A-Za-z0-9-]){re.escape(needle)}(?![A-Za-z0-9-])"
    else:
        return False
    return bool(re.search(pattern, haystack, re.IGNORECASE))


def _report_contains_exact_ioc(report: Dict[str, Any], value: str) -> bool:
    if not isinstance(report, dict):
        return False
    canonical = refang_value(value) if is_defanged(value) else (value or "").strip()
    kind = _exact_ioc_search_kind(canonical)
    if not kind:
        return False
    iocs = report.get("extracted_iocs") if isinstance(report.get("extracted_iocs"), dict) else {}
    keys = {
        "domain": ("domains",),
        "ip": ("ips", "ipv4", "ipv6"),
        "url": ("urls",),
        "hash": ("hashes", "md5", "sha1", "sha256", "sha3_384", "sha512"),
        "cve": ("cves",),
    }.get(kind, ())
    canonical_cmp = canonical.lower().rstrip(".") if kind == "domain" else canonical.lower().rstrip("/") if kind == "url" else canonical.lower()
    for key in keys:
        vals = iocs.get(key) if isinstance(iocs, dict) else []
        vals = vals if isinstance(vals, list) else ([vals] if vals else [])
        for val in vals:
            normalized = refang_value(str(val or "")).lower()
            if kind == "domain":
                normalized = normalized.rstrip(".")
            elif kind == "url":
                normalized = normalized.rstrip("/")
            if normalized == canonical_cmp:
                return True
    fallback_text = "\n".join(str(report.get(key) or "") for key in ("title", "report_names", "original_urls", "raw"))
    return _text_contains_exact_ioc(fallback_text, canonical)


MALWARE_NEWS_BASE = "https://malware.news"
MALWARE_NEWS_UA = "Mozilla/5.0 (compatible; MANTIS-CTI/1.0; passive research client)"
# Verified live category map (categories.json).
MALWARE_NEWS_CATEGORIES = {8: "Malware News", 10: "Malware Analysis", 11: "Forensics",
                           9: "Mirai Botnet", 1: "Uncategorized"}
_MALWARE_NEWS_CACHE: Dict[str, Any] = {}
_MALWARE_NEWS_CACHE_TTL = {"search": 1800, "topic": 21600}

def _malware_news_cache_get(key: str) -> Any:
    entry = _MALWARE_NEWS_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _MALWARE_NEWS_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _malware_news_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _MALWARE_NEWS_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _malware_news_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _malware_news_get(path: str, params: Dict[str, Any] = None, timeout: int = 20) -> Any:
    """Read-only Discourse GET helper (search.json, topic .json). No
    write/post/reply/like endpoints exist here; only GET is ever issued."""
    try:
        resp = requests.get(f"{MALWARE_NEWS_BASE}{path}", headers={"User-Agent": MALWARE_NEWS_UA,
                            "Accept": "application/json"}, params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"error": "Malware.News returned a malformed response"}
        if resp.status_code in {401, 403}:
            return {"error": "Malware.News access denied (HTTP {})".format(resp.status_code)}
        if resp.status_code == 404:
            return {"error": "Not Found"}
        if resp.status_code == 429:
            return {"error": "Malware.News rate limit exceeded (HTTP 429)"}
        if 500 <= resp.status_code < 600:
            return {"error": f"Malware.News provider error (HTTP {resp.status_code})"}
        return {"error": f"Malware.News request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "Malware.News request timeout"}
    except Exception as e:
        return {"error": f"Malware.News request failed: {e}"}

def _malware_news_strip(text: str) -> str:
    cleaned = html.unescape(re.sub(r"<[^>]+>", " ", str(text or "")))
    return re.sub(r"\s+", " ", cleaned).strip()

def _malware_news_topic_url(topic_id: Any, slug: str = "") -> str:
    try:
        tid = int(topic_id)
    except (TypeError, ValueError):
        return ""
    if slug and re.match(r"^[A-Za-z0-9_\-]+$", slug):
        return f"https://malware.news/t/{slug}/{tid}"
    return f"https://malware.news/t/{tid}"

def extract_malware_news_iocs(text: str) -> Dict[str, Any]:
    """Analyst-triggered pivots only; a mention proves nothing malicious.

    Recognizes canonical and common defanged forms. Returns canonical values
    in the plain lists plus a details list preserving each observed form:
    {type, value, observed_value, defanged}.
    """
    found: Dict[str, Any] = {"domains": [], "ips": [], "urls": [],
                             "hashes": [], "cves": [], "details": []}
    if not isinstance(text, str) or not text:
        return found
    seen_canonical = set()

    def record(ioc_type: str, observed: str, canonical: str) -> None:
        key = (ioc_type, canonical)
        if canonical and key not in seen_canonical:
            seen_canonical.add(key)
            found[{"domain": "domains", "ip": "ips", "url": "urls",
                   "hash": "hashes", "cve": "cves"}[ioc_type]].append(canonical)
            found["details"].append({"type": ioc_type, "value": canonical,
                                     "observed_value": observed,
                                     "defanged": observed != canonical})

    for match in re.finditer(r"\b(?:CVE-\d{4}-\d{4,7})\b", text, re.IGNORECASE):
        record("cve", match.group(0), match.group(0).upper())
    for match in re.finditer(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text):
        record("hash", match.group(0), match.group(0).lower())
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        candidate = match.group(0)
        try:
            if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv4Address):
                record("ip", candidate, candidate)
        except ValueError:
            continue
    # Defanged IPv4: 1[.]2[.]3[.]4, 1(.)2(.)3(.)4, 1[dot]2[dot]3[dot]4 ...
    octet = r"\d{1,3}"
    sep = r"(?:\.|\[\.\] |\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})".replace(" ", "")
    for match in re.finditer(rf"\b{octet}(?:{sep}{octet}){{3}}\b", text, re.IGNORECASE):
        observed = match.group(0)
        if not is_defanged(observed):
            continue
        canonical = refang_value(observed)
        try:
            if isinstance(ipaddress.ip_address(canonical), ipaddress.IPv4Address):
                record("ip", observed, canonical)
        except ValueError:
            continue
    for match in re.finditer(r"(?:https?|hxxps?)[:]?//[^\s)\"'<>`]+", text, re.IGNORECASE):
        observed = match.group(0).rstrip(".,;:!?")
        canonical = refang_value(observed)
        if not is_url(canonical):
            continue
        record("url", observed, canonical)
        host = urllib.parse.urlsplit(canonical).hostname or ""
        host = host.strip().lower()
        if host and not host.endswith("malware.news"):
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
                record("ip", observed, host)
            elif "." in host:
                record("domain", observed, host.lstrip("."))
    for match in re.finditer(r"(?<![A-Za-z0-9@_./:-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![A-Za-z0-9_./:-])", text):
        candidate = match.group(0).strip().lower().rstrip(".")
        if candidate.endswith("malware.news"):
            continue
        if "@" in text[max(0, match.start() - 1):match.end() + 1]:
            continue
        record("domain", match.group(0), candidate)
    # Defanged domains: example[.]com, example(.)com, example[dot]com ...
    for match in re.finditer(r"[A-Za-z0-9_.\-\[\]\(\)\{\}]*?(?:" + DEFANG_DOT_ALTERNATIVE + r")[A-Za-z0-9_.\-\[\]\(\)\{\}]*", text, re.IGNORECASE):
        observed = match.group(0).strip(".,;:!?()[]{} \t")
        if not observed or not is_defanged(observed):
            continue
        canonical = refang_value(observed).lower().rstrip(".")
        if is_domain(canonical) and not canonical.endswith("malware.news"):
            record("domain", observed, canonical)
    for key in ("domains", "ips", "urls", "hashes", "cves"):
        found[key] = found[key][:25]
    found["details"] = found["details"][:60]
    return found

def normalize_malware_news_result(topic: Dict[str, Any], post: Dict[str, Any],
                                  query: str, query_type: str = "all") -> Dict[str, Any]:
    topic = topic if isinstance(topic, dict) else {}
    post = post if isinstance(post, dict) else {}
    topic_id = topic.get("id") if isinstance(topic.get("id"), int) else post.get("topic_id")
    title = topic.get("title") or topic.get("fancy_title") or ""
    excerpt = _malware_news_strip(post.get("blurb") or "")
    category = MALWARE_NEWS_CATEGORIES.get(topic.get("category_id"), "")
    result = {
        "source": "Malware.News",
        "topic_id": topic_id if isinstance(topic_id, int) else None,
        "post_id": post.get("id") if isinstance(post.get("id"), int) else None,
        "post_number": post.get("post_number"),
        "title": title,
        "url": _malware_news_topic_url(topic_id, topic.get("slug") or ""),
        "author": post.get("username") or "",
        "created_at": post.get("created_at") or topic.get("created_at") or "",
        "category": category,
        "excerpt": excerpt[:2000],
        "match": query,
        "metadata": {"like_count": post.get("like_count"),
                     "posts_count": topic.get("posts_count"),
                     "reply_count": topic.get("reply_count"),
                     "last_posted_at": topic.get("last_posted_at") or ""},
    }
    relationships = []
    anchor = result["url"] or title or f"topic:{topic_id}"
    for domain in extract_malware_news_iocs(f"{title}\n{excerpt}")["domains"]:
        relationships.append({"source": anchor, "relation": "mentions", "target": domain, "target_type": "domain"})
    for ip in extract_malware_news_iocs(f"{title}\n{excerpt}")["ips"]:
        relationships.append({"source": anchor, "relation": "mentions", "target": ip, "target_type": "ip"})
    for url in extract_malware_news_iocs(f"{title}\n{excerpt}")["urls"]:
        if "malware.news" not in url:
            relationships.append({"source": anchor, "relation": "mentions", "target": url, "target_type": "url"})
    for file_hash in extract_malware_news_iocs(f"{title}\n{excerpt}")["hashes"]:
        relationships.append({"source": anchor, "relation": "mentions", "target": file_hash, "target_type": "hash"})
    for cve in extract_malware_news_iocs(f"{title}\n{excerpt}")["cves"]:
        relationships.append({"source": anchor, "relation": "references", "target": cve, "target_type": "cve"})
    # Family/actor discussion only when the searched term visibly matches.
    if query_type in {"malware_family", "threat_actor"} and query:
        haystack = f"{title}\n{excerpt}".lower()
        if query.lower() in haystack:
            relation = "discusses" if query_type == "malware_family" else "discusses"
            relationships.append({"source": anchor, "relation": relation, "target": query, "target_type": query_type})
    seen, deduped = set(), []
    for rel in relationships:
        key = (rel["source"], rel["relation"], rel["target"])
        if key not in seen:
            seen.add(key)
            deduped.append(rel)
    result["relationships"] = deduped
    return result

def _malware_news_search_variants(query: str) -> List[str]:
    """Canonical query plus a small controlled set of defanged variants, only
    when the query validates as a domain/IPv4/URL. Plain keywords search once."""
    base = refang_value(query) if is_defanged(query) else (query or "").strip()
    kind = classify_canonical_ioc(base)
    if kind == "domain":
        return defang_search_variants(base.lower().rstrip("."), "domain")
    if kind == "ip":
        return defang_search_variants(base, "ip")
    if kind == "url":
        return defang_search_variants(base, "url")
    return [query]

def query_malware_news(query: str, query_type: str = "all") -> Dict[str, Any]:
    query = (query or "").strip()
    if not query:
        return {"error": "Empty Malware.News query"}
    query_type = (query_type or "all").strip().lower() or "all"
    canonical = refang_value(query) if is_defanged(query) else query
    variants = _malware_news_search_variants(query)
    cache_key = f"malware_news:search:{canonical.lower()}:{query_type}"
    cached = _malware_news_cache_get(cache_key)
    if cached is not None:
        return cached

    raws: Dict[str, Any] = {}
    if len(variants) == 1:
        raws[variants[0]] = _malware_news_get("/search.json", {"q": variants[0]})
    else:
        with ThreadPoolExecutor(max_workers=min(len(variants), 5)) as executor:
            futures = {variant: executor.submit(_malware_news_get, "/search.json", {"q": variant})
                       for variant in variants}
            for variant, future in futures.items():
                try:
                    raws[variant] = future.result()
                except Exception as exc:
                    raws[variant] = {"error": f"Malware.News variant search failed: {exc}"}

    topics: Dict[int, Dict[str, Any]] = {}
    matched: Dict[tuple, str] = {}
    ordered_posts: List[Dict[str, Any]] = []
    first_term = ""
    first_error: Dict[str, Any] = {}
    for variant in variants:
        raw = raws.get(variant)
        if _malware_news_is_error(raw) or not isinstance(raw, dict):
            if not first_error and _malware_news_is_error(raw):
                first_error = raw
            continue
        if not first_term:
            grouped = raw.get("grouped_search_result")
            first_term = grouped.get("term") if isinstance(grouped, dict) else ""
        for topic in raw.get("topics", []):
            if isinstance(topic, dict) and isinstance(topic.get("id"), int):
                topics.setdefault(topic["id"], topic)
        for post in raw.get("posts", []):
            if not isinstance(post, dict):
                continue
            key = (post.get("topic_id"), post.get("id"))
            if key not in matched:
                matched[key] = variant
                ordered_posts.append(post)

    results = []
    if not ordered_posts and first_error:
        return first_error
    exact_ioc_search = bool(_exact_ioc_search_kind(canonical))
    for post in ordered_posts:
        topic_id = post.get("topic_id")
        entry = normalize_malware_news_result(topics.get(topic_id, {}), post, canonical, query_type)
        variant = matched.get((post.get("topic_id"), post.get("id")), canonical)
        if exact_ioc_search and not _text_contains_exact_ioc(f"{entry.get('title', '')}\n{entry.get('excerpt', '')}", canonical):
            continue
        entry["search_value"] = canonical
        entry["matched_variant"] = variant
        entry["match"] = variant
        entry["match_context"] = "canonical" if variant == canonical else "defanged"
        if entry["title"] or entry["excerpt"] or entry["topic_id"] is not None:
            results.append(entry)

    result = {
        "query": first_term or canonical,
        "search_value": canonical,
        "total": len(results),
        "data": results,
        "query_type": query_type,
    }
    # Backward-compatible flat fields used by older cards.
    for entry in result["data"]:
        entry["topic_url"] = entry["url"]
        entry["snippet"] = entry["excerpt"]
        entry["date"] = entry["created_at"]
        entry["username"] = entry["author"]
    _malware_news_cache_set(cache_key, result, _MALWARE_NEWS_CACHE_TTL["search"])
    return result

def query_malware_news_topic(topic_id: int, slug: str = "") -> Dict[str, Any]:
    """Lazy topic enrichment: metadata, content excerpt, original sources,
    related topics. Full article bodies are never bulk-fetched."""
    try:
        tid = int(topic_id)
    except (TypeError, ValueError):
        return {"error": "Invalid Malware.News topic ID"}
    if tid <= 0:
        return {"error": "Invalid Malware.News topic ID"}
    slug = (slug or "").strip()
    if slug and not re.match(r"^[A-Za-z0-9_\-]+$", slug):
        slug = ""
    cache_key = f"malware_news:topic:{tid}"
    cached = _malware_news_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _malware_news_get(f"/t/{slug}/{tid}.json" if slug else f"/t/{tid}.json")
    if _malware_news_is_error(raw):
        return raw
    if not isinstance(raw, dict):
        return {"error": "Malware.News returned a malformed response"}
    posts = ((raw.get("post_stream") or {}) if isinstance(raw.get("post_stream"), dict) else {}).get("posts") or []
    first = next((p for p in posts if isinstance(p, dict)), {})
    cooked_html = first.get("cooked") or ""
    cooked = _malware_news_strip(cooked_html)
    hrefs = [u for u in dict.fromkeys(re.findall(r'href="(https?://[^"]+)"', cooked_html)) if "malware.news" not in u]
    original_sources = []
    for entry in (first.get("link_counts") or []):
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "")
        if url.startswith("http") and "malware.news" not in url and url not in original_sources:
            original_sources.append(url)
    related = []
    for entry in (raw.get("suggested_topics") or []):
        if not isinstance(entry, dict):
            continue
        sid = entry.get("id") if isinstance(entry.get("id"), int) else None
        if sid is None:
            continue
        related.append({"topic_id": sid, "title": entry.get("title") or entry.get("fancy_title") or "",
                        "url": _malware_news_topic_url(sid, entry.get("slug") or "")})
    iocs = extract_malware_news_iocs(f"{raw.get('title') or ''}\n{cooked}\n" + "\n".join(hrefs))
    for href in hrefs:
        if href not in iocs["urls"]:
            iocs["urls"].append(href)
    anchor = _malware_news_topic_url(tid, raw.get("slug") or slug)
    relationships = []
    for kind, relation, target_type in (("domains", "mentions", "domain"), ("ips", "mentions", "ip"),
                                        ("urls", "mentions", "url"), ("hashes", "mentions", "hash"),
                                        ("cves", "references", "cve")):
        for value in iocs[kind]:
            if kind == "urls" and "malware.news" in value:
                continue
            relationships.append({"source": anchor, "relation": relation, "target": value, "target_type": target_type})
    result = {
        "source": "Malware.News",
        "topic_id": tid,
        "title": raw.get("title") or raw.get("fancy_title") or "",
        "url": anchor,
        "author": first.get("username") or "",
        "created_at": first.get("created_at") or raw.get("created_at") or "",
        "category": MALWARE_NEWS_CATEGORIES.get(raw.get("category_id"), ""),
        "tags": raw.get("tags") if isinstance(raw.get("tags"), list) else [],
        "reply_count": raw.get("reply_count"),
        "views": raw.get("views"),
        "excerpt": cooked[:4000],
        "original_sources": original_sources[:10],
        "related": related[:10],
        "iocs": iocs,
        "relationships": relationships,
    }
    _malware_news_cache_set(cache_key, result, _MALWARE_NEWS_CACHE_TTL["topic"])
    return result

MALSHARE_API_BASE = "https://malshare.com/api.php"
# Explicit passive action allowlist (verified against malshare.com/doc.php).
# POST is only ever used for hashlookup (existing-hash database search).
MALSHARE_ALLOWED_ACTIONS = {"details", "hashlookup", "search", "type", "gettypes",
                            "getlist", "getlistraw", "getsources", "getsourcesraw",
                            "getfilenames", "getlimit"}
MALSHARE_POST_ACTIONS = {"hashlookup"}
# Actively prohibited: sample upload, URL download/crawling tasks, and raw
# sample download. No zero-result/error path may fall back to these.
MALSHARE_BLOCKED_ACTIONS = {"upload", "download_url", "download_url_check", "getfile"}
_MALSHARE_CACHE: Dict[str, Any] = {}
_MALSHARE_CACHE_TTL = {"hit": 43200, "miss": 7200, "search": 1800, "types": 86400, "feed": 3600}

def _malshare_cache_get(key: str) -> Any:
    entry = _MALSHARE_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _MALSHARE_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _malshare_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _MALSHARE_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _malshare_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _malshare_call(action: str, api_key: str, params: Dict[str, Any] = None,
                   hashes: List[str] = None, timeout: int = 20) -> Any:
    """Single gateway for MalShare API access. Only allowlisted passive
    actions are reachable; upload/download_url/getfile are denied even if
    requested. The API key travels in request params per official docs and
    is never logged or echoed in errors/results."""
    action = (action or "").strip().lower()
    if action in MALSHARE_BLOCKED_ACTIONS:
        return {"error": f"MalShare action denied (passive-only integration): {action}"}
    if action not in MALSHARE_ALLOWED_ACTIONS:
        return {"error": f"MalShare action not allowlisted (passive-only integration): {action or 'empty'}"}
    if not api_key:
        return {"error": "No MalShare API key"}
    query = {"api_key": api_key, "action": action}
    query.update(params or {})
    try:
        if action in MALSHARE_POST_ACTIONS:
            # Documented bulk hash database search (existing hashes only).
            resp = requests.post(MALSHARE_API_BASE, params=query,
                                 data={"hashes": hashes or []}, timeout=timeout)
        else:
            if hashes:
                return {"error": f"MalShare action does not accept a hash list: {action}"}
            resp = requests.get(MALSHARE_API_BASE, params=query, timeout=timeout)
        if resp.status_code == 200:
            content_type = (resp.headers.get("Content-Type") or "").lower() if hasattr(resp, "headers") else ""
            if "json" in content_type:
                try:
                    return resp.json()
                except ValueError:
                    return {"error": "MalShare returned a malformed response",
                            "raw": (getattr(resp, "text", "") or "")[:500]}
            text = resp.text.strip()
            if not text:
                return {"error": "No existing MalShare sample found"}
            if "ERROR" in text.upper():
                if "invalid" in text.lower() and "key" in text.lower():
                    return {"error": "MalShare authentication failure (invalid API key)"}
                return {"error": f"MalShare provider error: {text[:300]}"}
            try:
                return resp.json()
            except (ValueError, AttributeError):
                return {"text": text}
        if resp.status_code in {401, 403}:
            return {"error": "MalShare authentication failure (HTTP {})".format(resp.status_code)}
        if resp.status_code == 404:
            return {"error": "No existing MalShare sample found"}
        if resp.status_code == 429:
            return {"error": "MalShare rate limit exceeded (HTTP 429)"}
        if 500 <= resp.status_code < 600:
            return {"error": f"MalShare provider error (HTTP {resp.status_code})"}
        return {"error": f"MalShare request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "MalShare request timeout"}
    except Exception as e:
        return {"error": f"MalShare request failed: {e}"}

def _malshare_detail_record(data: Any) -> Dict[str, Any]:
    if isinstance(data, list):
        data = data[0] if data else None
    return data if isinstance(data, dict) else {}

def normalize_malshare_sample(data: Any, query: str = "") -> Dict[str, Any]:
    record = _malshare_detail_record(data)
    normalized: Dict[str, Any] = {
        "source": "MalShare",
        "query": query,
        "sample": {"md5": "", "sha1": "", "sha256": "", "filename": "",
                   "file_type": "", "sample_source": ""},
        "relationships": [],
        "metadata": {"raw": record},
    }
    if not record or "ERROR" in record:
        return normalized
    sample = normalized["sample"]
    sample["md5"] = record.get("MD5") or record.get("md5") or ""
    sample["sha1"] = record.get("SHA1") or record.get("sha1") or ""
    sample["sha256"] = record.get("SHA256") or record.get("sha256") or ""
    sample["filename"] = record.get("FILENAME") or record.get("file_name") or ""
    sample["file_type"] = record.get("F_TYPE") or record.get("file_type") or ""
    sources = record.get("SOURCES") if isinstance(record.get("SOURCES"), list) else []
    sample["sample_source"] = next((str(s) for s in sources if isinstance(s, str) and s.strip()), "")
    anchor = sample["md5"] or sample["sha1"] or sample["sha256"] or query
    rels: List[Dict[str, Any]] = []
    seen = set()

    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen:
            seen.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    for algo in ("md5", "sha1", "sha256"):
        if sample[algo]:
            add_rel(anchor, "has_hash", sample[algo], "hash")
    if sample["filename"]:
        add_rel(anchor, "named_as", sample["filename"], "filename")
    if sample["sample_source"]:
        add_rel(anchor, "observed_from", sample["sample_source"], "source")
    if sample["file_type"]:
        add_rel(anchor, "classified_as_file_type", sample["file_type"], "file_type")
    normalized["relationships"] = rels
    return normalized

def query_malshare_hash(hash_val: str, api_key: str) -> Dict[str, Any]:
    file_hash = (hash_val or "").strip().lower()
    hash_kind = get_hash_type(file_hash)
    if not file_hash:
        return {"error": "Empty hash for MalShare lookup"}
    cache_key = f"malshare:details:{file_hash}"
    cached = _malshare_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _malshare_call("details", api_key, {"hash": file_hash})
    if _malshare_is_error(raw):
        return raw
    record = _malshare_detail_record(raw)
    if not record or "ERROR" in record:
        result = {"error": "No existing MalShare sample found"}
        _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["miss"])
        return result
    if hash_kind and not (record.get(hash_kind.upper()) or record.get(hash_kind)):
        record[hash_kind.upper()] = file_hash
    normalized = normalize_malshare_sample(record, file_hash)
    result = {"data": [{**normalized["sample"], "hash": file_hash,
                        "hash_algorithm": hash_kind or "unknown"}],
              "normalized": normalized}
    _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["hit"])
    return result

def query_malshare_hashlookup(hashes: List[str], api_key: str) -> Dict[str, Any]:
    """Documented bulk hash database search (POST hashes[]). Passive only."""
    cleaned = list(dict.fromkeys([h.strip().lower() for h in (hashes or [])
                                  if isinstance(h, str) and h.strip()]))
    if not cleaned:
        return {"error": "No hashes provided for MalShare bulk lookup"}
    if len(cleaned) > 100:
        return {"error": "MalShare bulk lookup limited to 100 hashes per request"}
    results: List[Dict[str, Any]] = []
    uncached = [h for h in cleaned if _malshare_cache_get(f"malshare:details:{h}") is None]
    if uncached:
        raw = _malshare_call("hashlookup", api_key, hashes=uncached)
        if _malshare_is_error(raw):
            return raw
        records = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
        for record in records:
            if not isinstance(record, dict) or "ERROR" in record:
                continue
            norm = normalize_malshare_sample(record)
            anchor = norm["sample"]["md5"] or norm["sample"]["sha1"] or norm["sample"]["sha256"]
            if anchor:
                _malshare_cache_set(f"malshare:details:{anchor.lower()}", norm, _MALSHARE_CACHE_TTL["hit"])
    for h in cleaned:
        cached = _malshare_cache_get(f"malshare:details:{h}")
        # Two shapes share this key: bulk entries are bare normalized records
        # ({"sample", ...}), single lookups cache {"data", "normalized"}.
        entry = None
        if isinstance(cached, dict):
            sample = cached.get("sample")
            if not (isinstance(sample, dict) and sample.get("md5")):
                norm = cached.get("normalized")
                sample = norm.get("sample") if isinstance(norm, dict) else None
                cached = norm if isinstance(sample, dict) and sample.get("md5") else None
            entry = cached
        if entry is not None:
            results.append(entry)
        else:
            results.append({"source": "MalShare", "query": h, "sample": {"md5": "", "sha1": "",
                            "sha256": "", "filename": "", "file_type": "", "sample_source": ""},
                            "relationships": [], "metadata": {}, "found": False})
    return {"source": "MalShare", "total": len(results),
            "found": sum(1 for r in results if r.get("sample", {}).get("md5")),
            "results": results}

def _malshare_match_reason(line: str, keyword: str) -> str:
    lowered = (line or "").strip().lower()
    if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^[a-f0-9]{128}$", lowered):
        return "hash"
    if keyword and keyword.lower() in lowered:
        return "filename" if re.search(r"\.[a-z0-9]{1,5}$", lowered) or "/" in lowered or "\\" in lowered else "source"
    return "source"

def query_malshare_search(keyword: str, api_key: str) -> Dict[str, Any]:
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty MalShare search"}
    cache_key = f"malshare:search:{keyword.lower()}"
    cached = _malshare_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _malshare_call("search", api_key, {"query": keyword})
    if _malshare_is_error(raw):
        return raw
    text = raw.get("text", "") if isinstance(raw, dict) else ""
    if isinstance(raw, list):
        lines = [str(x).strip() for x in raw if str(x).strip()]
    else:
        lines = [line.strip() for line in text.split("\n") if line.strip()
                 and line.strip() not in {"[]", "{}"} and "ERROR" not in line.upper()]
    if not lines:
        result = {"error": "No existing MalShare sample found"}
        _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["miss"])
        return result
    results = [{"value": line, "match": _malshare_match_reason(line, keyword)} for line in lines[:50]]
    result = {"source": "MalShare", "query": keyword, "total": len(results), "results": results}
    _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["search"])
    # Backward-compatible shape for the existing card renderer.
    result["data"] = [{"md5": (r["value"] if r["match"] == "hash" and len(r["value"]) == 32 else ""),
                       "hash": r["value"], "match": r["match"],
                       "file_type": "Search Result", "first_seen": "N/A"} for r in results]
    return result

def query_malshare_type(file_type: str, api_key: str) -> Dict[str, Any]:
    """Documented type action: hashes of a file type from recent dataset."""
    file_type = (file_type or "").strip()
    if not re.match(r"^[A-Za-z0-9_.\-]{1,40}$", file_type):
        return {"error": "Invalid MalShare file type"}
    cache_key = f"malshare:type:{file_type.lower()}"
    cached = _malshare_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _malshare_call("type", api_key, {"type": file_type})
    if _malshare_is_error(raw):
        return raw
    records = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    results = []
    for record in records[:100]:
        if not isinstance(record, dict):
            continue
        norm = normalize_malshare_sample(record, file_type)
        if norm["sample"]["md5"] or norm["sample"]["sha1"] or norm["sample"]["sha256"]:
            results.append(norm)
    if not results:
        result = {"error": "No existing MalShare sample found"}
        _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["miss"])
        return result
    result = {"source": "MalShare", "file_type": file_type, "total": len(results), "results": results}
    _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["search"])
    return result

def query_malshare_gettypes(api_key: str) -> Dict[str, Any]:
    """Documented gettypes action (cached 24h; avoids hardcoded type lists)."""
    cache_key = "malshare:gettypes"
    cached = _malshare_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _malshare_call("gettypes", api_key)
    if _malshare_is_error(raw):
        return raw
    result = {"source": "MalShare", "types": raw}
    _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["types"])
    return result

def query_malshare_limit(api_key: str) -> Dict[str, Any]:
    """Documented getlimit action for quota awareness. Never cached."""
    if not api_key:
        return {"error": "No MalShare API key"}
    raw = _malshare_call("getlimit", api_key)
    if _malshare_is_error(raw):
        return raw
    text = raw.get("text", "") if isinstance(raw, dict) else ""
    if isinstance(raw, dict) and "text" not in raw:
        return {"source": "MalShare", "quota": raw}
    numbers = re.findall(r"\d+", text)
    return {"source": "MalShare", "quota": {"raw": text,
            "limit": int(numbers[0]) if len(numbers) > 0 else None,
            "remaining": int(numbers[1]) if len(numbers) > 1 else None}}

def query_malshare_feed(feed: str, api_key: str) -> Dict[str, Any]:
    """Backend-ready recent-24h feeds (getlist/getsources/getfilenames).
    Not called during normal lookups; reserved for a future feed feature."""
    feed = (feed or "").strip().lower()
    actions = {"list": "getlist", "sources": "getsources", "filenames": "getfilenames"}
    if feed not in actions:
        return {"error": f"Unknown MalShare feed: {feed or 'empty'} (list/sources/filenames)"}
    cache_key = f"malshare:feed:{feed}"
    cached = _malshare_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _malshare_call(actions[feed], api_key)
    if _malshare_is_error(raw):
        return raw
    if isinstance(raw, dict) and "text" in raw:
        items = [line.strip() for line in raw["text"].split("\n") if line.strip()]
        result = {"source": "MalShare", "feed": feed, "total": len(items), "items": items[:500]}
    else:
        items = raw if isinstance(raw, list) else [raw]
        result = {"source": "MalShare", "feed": feed, "total": len(items), "items": items[:500]}
    _malshare_cache_set(cache_key, result, _MALSHARE_CACHE_TTL["feed"])
    return result

def query_vt(indicator: str, i_type: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"error": "No API Key provided"}

    vt_indicator = vt_url_id(indicator) if i_type == "url" else indicator
        
    endpoints = {
        'domain': f"https://www.virustotal.com/api/v3/domains/{indicator}",
        'ip': f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
        'hash': f"https://www.virustotal.com/api/v3/files/{indicator}",
        'url': f"https://www.virustotal.com/api/v3/urls/{vt_indicator}",
    }
    
    url = endpoints.get(i_type)
    if not url: return {"error": "Invalid indicator type"}

    headers = {'x-apikey': api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            try:
                sub_endpoints = {
                    "comments": f"{url}/comments?limit=10"
                }
                if i_type in ("ip", "domain"):
                    sub_endpoints["historical_ssl_certificates"] = f"{url}/historical_ssl_certificates?limit=10"
                if i_type == "ip":
                    sub_endpoints["scanning_technologies"] = f"{url}/scanning_technologies?limit=25"

                def _fetch_sub(item):
                    rel_name, rel_url = item
                    try:
                        r = requests.get(rel_url, headers=headers, timeout=8)
                        if r.status_code == 200:
                            return rel_name, r.json().get('data', [])
                    except Exception:
                        pass
                    return rel_name, []

                with ThreadPoolExecutor(max_workers=len(sub_endpoints)) as pool:
                    for rel_name, rel_data in pool.map(_fetch_sub, list(sub_endpoints.items())):
                        if rel_data and 'data' in result:
                            result['data'][rel_name] = rel_data
            except Exception:
                pass
            return result
        elif resp.status_code == 404:
            return {"error": "Not Found"}
        else:
            return {"error": f"Status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_vt_relation(indicator: str, i_type: str, relation: str, api_key: str, limit: int = 40) -> Dict[str, Any]:
    if not api_key:
        return {"error": "No API Key provided"}

    vt_indicator = vt_url_id(indicator) if i_type == "url" else indicator
        
    endpoints = {
        'domain': f"https://www.virustotal.com/api/v3/domains/{indicator}/{relation}?limit={limit}",
        'ip': f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}/{relation}?limit={limit}",
        'hash': f"https://www.virustotal.com/api/v3/files/{indicator}/{relation}?limit={limit}",
        'url': f"https://www.virustotal.com/api/v3/urls/{vt_indicator}/{relation}?limit={limit}",
    }
    
    url = endpoints.get(i_type)
    if not url: return {"error": "Invalid indicator type"}

    headers = {'x-apikey': api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), list):
                data["normalized_relations"] = normalize_vt_relation_items(relation, data["data"])
            return data
        elif resp.status_code == 404:
            return {"data": [], "normalized_relations": [], "not_found": True}
        elif resp.status_code == 429:
            return {"error": "Quota Exceeded (HTTP 429). Please wait a minute."}
        else:
            return {"error": f"Status {resp.status_code} - {resp.text}"}
    except Exception as e:
        return {"error": str(e)}

GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
# Explicit read-only allowlist (verified against official GitHub REST docs).
# Only GET retrieval/search is reachable: the helper below never issues
# POST/PUT/PATCH/DELETE, so create/update/delete, push, fork, star, watch,
# follow, workflow/release dispatch and webhook operations are unreachable.
# There is no generic GitHub proxy: unknown paths are denied.
GITHUB_READ_PREFIXES = (
    "/search/repositories", "/search/code", "/search/issues", "/search/users",
    "/search/commits", "/repos/", "/users/", "/orgs/", "/rate_limit",
)
GITHUB_WRITE_MARKERS = (
    "forks", "star", "watch", "follow", "dispatch", "webhook", "gists",
    "collaborator", "invitation", "secret", "deploy-key", "pages/builds",
)
_GITHUB_CACHE: Dict[str, Any] = {}
_GITHUB_CACHE_TTL = {"search": 1800, "repo": 21600, "commits": 3600,
                      "issues": 3600, "releases": 21600, "user": 21600, "org": 21600}

def _github_cache_get(key: str) -> Any:
    entry = _GITHUB_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _GITHUB_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _github_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _GITHUB_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _github_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _github_token(api_key: str = "") -> str:
    return (api_key or os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_TOKEN") or "").strip()

def _github_auth_fingerprint(api_key: str = "") -> str:
    token = _github_token(api_key)
    if not token:
        return "public"
    return hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:10]

def _github_rate_meta(resp: Any) -> Dict[str, Any]:
    try:
        headers = resp.headers
    except Exception:
        return {}
    meta = {}
    for source, dest in (
        ("X-RateLimit-Limit", "limit"),
        ("X-RateLimit-Remaining", "remaining"),
        ("X-RateLimit-Used", "used"),
        ("X-RateLimit-Reset", "reset"),
        ("X-RateLimit-Resource", "resource"),
        ("Retry-After", "retry_after"),
    ):
        value = headers.get(source)
        if value is not None:
            meta[dest] = value
    return meta

def _github_get(path: str, api_key: str, params: Dict[str, Any] = None,
                timeout: int = 20, accept: str = "application/vnd.github+json") -> Any:
    """Single gateway for GitHub REST access. GET-only; only allowlisted
    read paths are reachable. The token travels in the Authorization header
    and is never logged or echoed in errors/results."""
    lowered = (path or "").lower().split("?")[0]
    if not lowered.startswith(GITHUB_READ_PREFIXES):
        return {"error": "GitHub endpoint not allowlisted (passive-only integration)"}
    for marker in GITHUB_WRITE_MARKERS:
        if marker in lowered:
            return {"error": "GitHub write/mutation denied (passive-only integration)"}
    token = _github_token(api_key)
    headers = {"Accept": accept, "X-GitHub-Api-Version": GITHUB_API_VERSION}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(f"{GITHUB_API_BASE}{path}", headers=headers,
                            params=params or {}, timeout=timeout)
        rate_meta = _github_rate_meta(resp)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                return {"error": "GitHub returned a malformed response"}
            if isinstance(data, dict):
                data["_rate_limit"] = rate_meta
                data["_rate_limit_remaining"] = rate_meta.get("remaining")
            return data
        if resp.status_code in {401, 403}:
            detail = ""
            try:
                body = resp.json()
                detail = str(body.get("message") or "")
            except Exception:
                detail = ""
            if resp.status_code == 403 and ("rate limit" in detail.lower() or rate_meta.get("remaining") == "0"):
                reset = f" Reset epoch: {rate_meta.get('reset')}." if rate_meta.get("reset") else ""
                retry = f" Retry after: {rate_meta.get('retry_after')}s." if rate_meta.get("retry_after") else ""
                return {"error": f"GitHub rate limit exceeded: {detail[:200] or 'rate limit'}{reset}{retry}",
                        "rate_limit": rate_meta}
            return {"error": f"GitHub authentication failure (HTTP {resp.status_code}): the saved token is invalid, expired, or lacks access; update it in Settings"}
        if resp.status_code == 404:
            return {"error": "Not Found"}
        if resp.status_code == 422:
            detail = ""
            try:
                detail = str(resp.json().get("message") or "")
            except Exception:
                detail = ""
            return {"error": f"GitHub validation failed: {detail[:200] or 'unprocessable query'}"}
        if resp.status_code == 429:
            retry = f" Retry after: {rate_meta.get('retry_after')}s." if rate_meta.get("retry_after") else ""
            return {"error": f"GitHub rate limit exceeded (HTTP 429).{retry}", "rate_limit": rate_meta}
        if 500 <= resp.status_code < 600:
            return {"error": f"GitHub provider error (HTTP {resp.status_code})"}
        return {"error": f"GitHub request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "GitHub request timeout"}
    except Exception as e:
        return {"error": f"GitHub request failed: {e}"}

def _github_full_name(value: str) -> str:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\s*$", value or "")
    if not match or match.group(1).lower() in {"http:", "https:"}:
        return ""
    return f"{match.group(1)}/{match.group(2)}"

def _github_search_query(indicator: str, query_type: str) -> str:
    value = (indicator or "").strip()
    qtype = (query_type or "code").strip().lower()
    if not value:
        return value
    if qtype == "yara":
        return f"{value} extension:yar"
    if qtype == "sigma":
        return f"{value} extension:yml"
    if qtype == "filename":
        return f"filename:{value}"
    if qtype == "cve":
        return value.upper() if re.match(r"^cve-\d{4}-\d{4,7}$", value, re.I) else value
    if qtype in {"domain", "ip", "url", "hash"}:
        return f'"{value}"'
    return value

def query_github_search(indicator: str, query_type: str, api_key: str,
                        per_page: int = 5, page: int = 1) -> Dict[str, Any]:
    try:
        per_page = max(1, min(int(per_page or 5), 100))
    except (TypeError, ValueError):
        per_page = 5
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1

    qtype = (query_type or "code").strip().lower()
    # Repository discovery is kept separate from code mentions. Keyword/IOC
    # strings go through code search so GitHub stays evidence, not reputation.
    if qtype in {"repository", "repo", "project"}:
        path, result_type = "/search/repositories", "repository"
        accept = "application/vnd.github+json"
    else:
        path, result_type = "/search/code", "code"
        # text-match media type preserves match fragments/snippets.
        accept = "application/vnd.github.text-match+json"

    query = _github_search_query(indicator, qtype)
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:{path}:{qtype}:{query}:{per_page}:{page}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    data = _github_get(path, api_key, params={"q": query, "per_page": per_page, "page": page}, accept=accept)
    result = normalize_github_search(data, result_type, query=indicator)
    if not _github_is_error(result):
        _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["search"])
    return result

def query_github_specific_repos(keyword: str, api_key: str, repos: list = None) -> Dict[str, Any]:
    if not repos:
        repos = [
            "mthcht/ThreatHunting-Keywords",
            "mthcht/ThreatIntel-Reports",
            "alexander-hanel/APTnotes-md",
            "blackorbird/APT_REPORT",
            "ThreatLabz/ransomware_notes"
        ]
    repos = [_github_full_name(r) for r in repos]
    repos = [r for r in repos if r][:10]
    if not repos:
        return {"error": "No valid GitHub repositories configured"}
    repo_query = " ".join([f"repo:{repo}" for repo in repos])
    # The API limit might be an issue for very long queries, but 4 repos is fine.
    # Searching code with multiple repos and keyword
    query_str = f"{keyword} {repo_query}"

    cache_key = f"github:{_github_auth_fingerprint(api_key)}:repos:{query_str}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    data = _github_get("/search/code", api_key, params={"q": query_str, "per_page": 10},
                       accept="application/vnd.github.text-match+json")
    result = normalize_github_search(data, "code", query=keyword)
    if not _github_is_error(result):
        _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["search"])
    return result

def _github_file_context(path: str) -> str:
    name = (path or "").lower()
    if name.endswith((".yar", ".yara")):
        return "Detection Rule"
    if name.endswith((".sigma", ".sigmac", ".yml", ".yaml")) and any(k in name for k in ("sigma", "rule", "detect")):
        return "Detection Rule"
    if name.endswith(".json") and any(k in name for k in ("ioc", "stix", "misp", "threat", "intel", "feed", "indicator")):
        return "IOC List"
    if "stix" in name or "misp" in name:
        return "IOC List"
    if name.endswith((".md", ".rst", ".txt")) and any(k in name for k in ("readme", "report", "research", "apt", "malware", "threat", "analysis")):
        return "Documentation"
    if name.endswith((".md", ".rst", ".txt")):
        return "Research"
    if name.endswith((".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf")):
        return "Configuration"
    if any(k in name for k in ("exploit", "poc", "payload")):
        return "Exploit/PoC"
    if name.endswith((".py", ".ps1", ".sh", ".js", ".go", ".rs", ".c", ".cpp")):
        return "Source Code"
    return ""

def extract_github_iocs(text: str) -> Dict[str, List[str]]:
    """Analyst-triggered pivots only; a mention proves nothing malicious."""
    found: Dict[str, List[str]] = {"domains": [], "ips": [], "urls": [],
                                   "hashes": [], "cves": [], "emails": []}
    if not isinstance(text, str) or not text:
        return found
    for match in re.finditer(r"\b(?:CVE-\d{4}-\d{4,7})\b", text, re.IGNORECASE):
        found["cves"].append(match.group(0).upper())
    for match in re.finditer(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text):
        found["hashes"].append(match.group(0).lower())
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        candidate = match.group(0)
        try:
            if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv4Address):
                found["ips"].append(candidate)
        except ValueError:
            continue
    for match in re.finditer(r"https?://[^\s)\"'<>`]+", text):
        candidate = match.group(0).rstrip(".,;:!?")
        if candidate not in found["urls"]:
            found["urls"].append(candidate)
            host = re.sub(r"^https?://", "", candidate, flags=re.IGNORECASE).split("/")[0].split(":")[0].strip().lower()
            if host and not host.endswith(("github.com", "raw.githubusercontent.com")):
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
                    found["ips"].append(host)
                elif "." in host:
                    found["domains"].append(host.lstrip("."))
    for match in re.finditer(r"(?<!@)\b(?:[A-Za-z0-9-]{1,63}\.)+(?:[A-Za-z]{2,63})\b", text):
        candidate = match.group(0).lower().strip(".")
        suffix = candidate.rsplit(".", 1)[-1]
        file_suffixes = {
            "yar", "yara", "sigma", "json", "yaml", "yml", "toml", "ini", "cfg", "conf",
            "txt", "md", "rst", "py", "ps1", "sh", "js", "ts", "go", "rs", "c", "cpp",
            "h", "hpp", "java", "cs", "rb", "php", "pl", "exe", "dll", "sys", "bin",
        }
        if suffix not in file_suffixes and not candidate.endswith(("github.com", "raw.githubusercontent.com")):
            found["domains"].append(candidate)
    for match in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        found["emails"].append(match.group(0).lower())
    for key in found:
        found[key] = list(dict.fromkeys(found[key]))[:25]
    return found

def normalize_github_search(data: Dict[str, Any], result_type: str, query: str = "") -> Dict[str, Any]:
    if not isinstance(data, dict) or data.get("error"):
        return data

    normalized = []
    for item in data.get("items", []):
        if not isinstance(item, dict):
            continue

        if result_type == "repository":
            owner = item.get("owner") or {}
            normalized.append({
                "type": "repository",
                "title": item.get("full_name") or item.get("name") or "Repository",
                "repository": item.get("full_name") or item.get("name"),
                "owner": owner.get("login"),
                "url": item.get("html_url"),
                "description": item.get("description") or "",
                "language": item.get("language"),
                "stars": item.get("stargazers_count"),
                "forks": item.get("forks_count"),
                "watchers": item.get("watchers_count"),
                "open_issues": item.get("open_issues_count"),
                "topics": item.get("topics") if isinstance(item.get("topics"), list) else [],
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "pushed_at": item.get("pushed_at"),
                "archived": bool(item.get("archived")),
                "fork": bool(item.get("fork")),
                "default_branch": item.get("default_branch") or "",
                "score": item.get("score"),
            })
            continue

        repo = item.get("repository") or {}
        owner = repo.get("owner") or {}
        text_matches = []
        for match in item.get("text_matches", []) or []:
            if isinstance(match, dict) and match.get("fragment"):
                text_matches.append(match.get("fragment"))
        path = item.get("path") or ""
        iocs = extract_github_iocs("\n".join(text_matches + [path, item.get("name") or ""]))

        normalized.append({
            "type": "code",
            "title": item.get("path") or item.get("name") or "Code result",
            "name": item.get("name"),
            "path": path,
            "context": _github_file_context(path),
            "sha": item.get("sha"),
            "short_sha": (item.get("sha") or "")[:12],
            "url": item.get("html_url"),
            "api_url": item.get("url"),
            "repository": repo.get("full_name") or repo.get("name"),
            "repository_url": repo.get("html_url"),
            "repository_description": repo.get("description") or "",
            "owner": owner.get("login"),
            "score": item.get("score"),
            "snippets": text_matches,
            "iocs": iocs,
        })

    rels: List[Dict[str, Any]] = []
    seen = set()

    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen:
            seen.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    for entry in normalized:
        repo_name = entry.get("repository") or ""
        owner = entry.get("owner") or ""
        if repo_name and owner:
            add_rel(repo_name, "owned_by", owner, "user")
        if entry.get("type") == "code" and repo_name and entry.get("path"):
            add_rel(repo_name, "contains", entry["path"], "file")
        for domain in (entry.get("iocs") or {}).get("domains", []) or []:
            add_rel(entry.get("path") or repo_name, "references", domain, "domain")
        for ip in (entry.get("iocs") or {}).get("ips", []) or []:
            add_rel(entry.get("path") or repo_name, "references", ip, "ip")
        for url in (entry.get("iocs") or {}).get("urls", []) or []:
            add_rel(entry.get("path") or repo_name, "references", url, "url")
        for file_hash in (entry.get("iocs") or {}).get("hashes", []) or []:
            add_rel(entry.get("path") or repo_name, "references", file_hash, "hash")
        for cve in (entry.get("iocs") or {}).get("cves", []) or []:
            add_rel(entry.get("path") or repo_name, "references", cve, "cve")

    return {
        "type": result_type,
        "query": query,
        "total_count": data.get("total_count", len(normalized)),
        "incomplete_results": data.get("incomplete_results", False),
        "rate_remaining": data.get("_rate_limit_remaining"),
        "rate_limit": data.get("_rate_limit") or {},
        "items": normalized,
        "relationships": rels,
    }

def normalize_github_repo(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    owner = item.get("owner") or {}
    return {
        "name": item.get("name") or "",
        "full_name": item.get("full_name") or "",
        "owner": owner.get("login") or "",
        "description": item.get("description") or "",
        "topics": item.get("topics") if isinstance(item.get("topics"), list) else [],
        "language": item.get("language") or "",
        "stars": item.get("stargazers_count"),
        "forks": item.get("forks_count"),
        "watchers": item.get("watchers_count") or item.get("subscribers_count"),
        "open_issues": item.get("open_issues_count"),
        "created_at": item.get("created_at") or "",
        "updated_at": item.get("updated_at") or "",
        "pushed_at": item.get("pushed_at") or "",
        "archived": bool(item.get("archived")),
        "fork": bool(item.get("fork")),
        "default_branch": item.get("default_branch") or "",
        "url": item.get("html_url") or "",
    }

def query_github_repo(full_name: str, api_key: str) -> Dict[str, Any]:
    """Lazy repository details: metadata + languages + contributors + tags +
    releases. Never fetches trees/contents automatically."""
    name = _github_full_name(full_name)
    if not name:
        return {"error": "Invalid GitHub repository (expected owner/repo)"}
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:repo:{name.lower()}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_repo = executor.submit(_github_get, f"/repos/{name}", api_key, {})
        future_lang = executor.submit(_github_get, f"/repos/{name}/languages", api_key, {})
        future_contrib = executor.submit(_github_get, f"/repos/{name}/contributors", api_key,
                                         {"per_page": 10})
        future_tags = executor.submit(_github_get, f"/repos/{name}/tags", api_key, {"per_page": 10})
        future_rel = executor.submit(_github_get, f"/repos/{name}/releases", api_key, {"per_page": 5})
        repo, languages, contributors, tags, releases = (
            future_repo.result(), future_lang.result(), future_contrib.result(),
            future_tags.result(), future_rel.result())
    if _github_is_error(repo):
        return repo
    contributors = contributors if isinstance(contributors, list) else []
    tags = tags if isinstance(tags, list) else []
    releases = releases if isinstance(releases, list) else []
    result = {
        "source": "GitHub",
        "repository": normalize_github_repo(repo),
        "languages": languages if isinstance(languages, dict) else {},
        "contributors": [{"login": c.get("login") or "", "contributions": c.get("contributions"),
                          "url": c.get("html_url") or ""} for c in contributors[:10] if isinstance(c, dict)],
        "tags": [{"name": t.get("name") or "", "commit": ((t.get("commit") or {}).get("sha") or "")[:12]}
                 for t in tags[:10] if isinstance(t, dict)],
        "releases": [{"name": r.get("name") or r.get("tag_name") or "", "tag": r.get("tag_name") or "",
                      "published_at": r.get("published_at") or "", "prerelease": bool(r.get("prerelease")),
                      "notes": (r.get("body") or "")[:2000],
                      "assets": [{"name": a.get("name") or "", "size": a.get("size"),
                                  "downloads": a.get("download_count")} for a in (r.get("assets") or [])[:10]
                                 if isinstance(a, dict)]} for r in releases[:5] if isinstance(r, dict)],
        "relationships": ([{"source": name, "relation": "owned_by",
                            "target": (repo.get("owner") or {}).get("login") or "",
                            "target_type": "user"}] if isinstance(repo.get("owner"), dict) and repo["owner"].get("login") else []),
        "raw": {"repo": repo},
    }
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["repo"])
    return result

def query_github_commits(full_name: str, api_key: str, path: str = "", author: str = "",
                         since: str = "", until: str = "", page: int = 1) -> Dict[str, Any]:
    name = _github_full_name(full_name)
    if not name:
        return {"error": "Invalid GitHub repository (expected owner/repo)"}
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1
    params: Dict[str, Any] = {"per_page": 20, "page": page}
    if path and len(path) <= 500 and "\n" not in path and "\r" not in path:
        params["path"] = path
    if author and re.match(r"^[A-Za-z0-9_.-]{1,100}$", author):
        params["author"] = author
    for key, value in (("since", since), ("until", until)):
        if value and re.match(r"^\d{4}-\d{2}-\d{2}", str(value)):
            params[key] = str(value)[:10]
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:commits:{name.lower()}:{sorted((str(k), str(v)) for k, v in params.items())}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _github_get(f"/repos/{name}/commits", api_key, params)
    if _github_is_error(raw):
        return raw
    commits = []
    for entry in (raw if isinstance(raw, list) else []):
        if not isinstance(entry, dict):
            continue
        commit = entry.get("commit") or {}
        author_info = commit.get("author") or {}
        committer_info = commit.get("committer") or {}
        verification = commit.get("verification") or {}
        parents = [str(p.get("sha") or "")[:12] for p in (entry.get("parents") or []) if isinstance(p, dict)]
        commits.append({
            "sha": entry.get("sha") or "",
            "short_sha": (entry.get("sha") or "")[:12],
            "message": (commit.get("message") or "")[:1000],
            "author": author_info.get("name") or "",
            "author_email": author_info.get("email") or "",
            "authored_date": author_info.get("date") or "",
            "committer": committer_info.get("name") or "",
            "committed_date": committer_info.get("date") or "",
            "parents": parents,
            "verified": verification.get("verified") if isinstance(verification.get("verified"), bool) else None,
            "verification_reason": verification.get("reason") or "",
            "url": entry.get("html_url") or "",
        })
    result = {"source": "GitHub", "repository": name, "commits": commits,
              "page": page, "relationships": [
                  {"source": name, "relation": "has_commit", "target": c["short_sha"], "target_type": "commit"}
                  for c in commits if c["short_sha"]] + [
                  {"source": c["short_sha"], "relation": "authored_by", "target": c["author"], "target_type": "user"}
                  for c in commits if c["short_sha"] and c["author"]]}
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["commits"])
    return result

def query_github_commit_detail(full_name: str, sha: str, api_key: str) -> Dict[str, Any]:
    """Lazy read of one documented commit object. Includes changed-file
    metadata only; it does not fetch file blobs or repository contents."""
    name = _github_full_name(full_name)
    sha = (sha or "").strip()
    if not name or not re.match(r"^[A-Fa-f0-9]{7,40}$", sha):
        return {"error": "Invalid GitHub repository or commit SHA"}
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:commit:{name.lower()}:{sha.lower()}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _github_get(f"/repos/{name}/commits/{sha}", api_key, {})
    if _github_is_error(raw):
        return raw
    commit = raw.get("commit") if isinstance(raw, dict) else {}
    commit = commit if isinstance(commit, dict) else {}
    author_info = commit.get("author") or {}
    committer_info = commit.get("committer") or {}
    verification = commit.get("verification") or {}
    files = []
    for entry in (raw.get("files") or []) if isinstance(raw, dict) else []:
        if not isinstance(entry, dict):
            continue
        files.append({
            "filename": entry.get("filename") or "",
            "status": entry.get("status") or "",
            "additions": entry.get("additions"),
            "deletions": entry.get("deletions"),
            "changes": entry.get("changes"),
            "url": entry.get("blob_url") or "",
        })
    parents = [str(p.get("sha") or "")[:12] for p in (raw.get("parents") or []) if isinstance(p, dict)]
    result = {
        "source": "GitHub",
        "repository": name,
        "commit": {
            "sha": raw.get("sha") or sha,
            "short_sha": (raw.get("sha") or sha)[:12],
            "message": commit.get("message") or "",
            "author": author_info.get("name") or "",
            "author_email": author_info.get("email") or "",
            "authored_date": author_info.get("date") or "",
            "committer": committer_info.get("name") or "",
            "committer_email": committer_info.get("email") or "",
            "committed_date": committer_info.get("date") or "",
            "parents": parents,
            "verified": verification.get("verified") if isinstance(verification.get("verified"), bool) else None,
            "verification_reason": verification.get("reason") or "",
            "url": raw.get("html_url") or "",
        },
        "files": files[:100],
        "relationships": [{"source": name, "relation": "has_commit", "target": (raw.get("sha") or sha)[:12],
                           "target_type": "commit"}],
    }
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["commits"])
    return result

def query_github_readme(full_name: str, api_key: str) -> Dict[str, Any]:
    name = _github_full_name(full_name)
    if not name:
        return {"error": "Invalid GitHub repository (expected owner/repo)"}
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:readme:{name.lower()}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _github_get(f"/repos/{name}/readme", api_key, {})
    if _github_is_error(raw):
        return raw
    content = ""
    if isinstance(raw, dict):
        try:
            import base64 as _b64
            if raw.get("encoding") == "base64" and isinstance(raw.get("content"), str):
                content = _b64.b64decode(raw["content"]).decode("utf-8", errors="replace")[:20000]
        except Exception:
            content = ""
    result = {"source": "GitHub", "repository": name,
              "path": raw.get("path") or "", "content": content}
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["repo"])
    return result

def query_github_issues(full_name: str, api_key: str, state: str = "all",
                        page: int = 1) -> Dict[str, Any]:
    """Passive issue retrieval (user content = unverified, never intel)."""
    name = _github_full_name(full_name)
    if not name:
        return {"error": "Invalid GitHub repository (expected owner/repo)"}
    if state not in {"open", "closed", "all"}:
        state = "all"
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:issues:{name.lower()}:{state}:{page}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _github_get(f"/repos/{name}/issues", api_key,
                      {"state": state, "per_page": 20, "page": page})
    if _github_is_error(raw):
        return raw
    issues = []
    for entry in (raw if isinstance(raw, list) else []):
        if not isinstance(entry, dict):
            continue
        user = entry.get("user") or {}
        issues.append({
            "number": entry.get("number"),
            "title": entry.get("title") or "",
            "state": entry.get("state") or "",
            "author": user.get("login") or "",
            "created_at": entry.get("created_at") or "",
            "updated_at": entry.get("updated_at") or "",
            "comments": entry.get("comments"),
            "labels": [label.get("name") for label in (entry.get("labels") or []) if isinstance(label, dict)][:10],
            "body": (entry.get("body") or "")[:3000],
            "url": entry.get("html_url") or "",
            "iocs": extract_github_iocs(entry.get("body") or entry.get("title") or ""),
        })
    result = {"source": "GitHub", "repository": name, "issues": issues, "page": page}
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["issues"])
    return result

def query_github_issue_comments(full_name: str, number: int, api_key: str) -> Dict[str, Any]:
    name = _github_full_name(full_name)
    try:
        number = int(number)
    except (TypeError, ValueError):
        number = 0
    if not name or number <= 0:
        return {"error": "Invalid GitHub repository or issue number"}
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:issue_comments:{name.lower()}:{number}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _github_get(f"/repos/{name}/issues/{number}/comments", api_key, {"per_page": 50})
    if _github_is_error(raw):
        return raw
    comments = []
    for entry in (raw if isinstance(raw, list) else []):
        if not isinstance(entry, dict):
            continue
        user = entry.get("user") or {}
        comments.append({
            "author": user.get("login") or "",
            "created_at": entry.get("created_at") or "",
            "body": (entry.get("body") or "")[:3000],
            "url": entry.get("html_url") or "",
            "iocs": extract_github_iocs(entry.get("body") or ""),
        })
    result = {"source": "GitHub", "repository": name, "issue": number, "comments": comments}
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["issues"])
    return result

def normalize_github_user(user: Any) -> Dict[str, Any]:
    if not isinstance(user, dict):
        return {}
    return {
        "login": user.get("login") or "",
        "name": user.get("name") or "",
        "bio": user.get("bio") or "",
        "company": user.get("company") or "",
        "location": user.get("location") or "",
        "blog": user.get("blog") or "",
        "created_at": user.get("created_at") or "",
        "followers": user.get("followers"),
        "following": user.get("following"),
        "public_repos": user.get("public_repos"),
        "avatar": user.get("avatar_url") or "",
        "url": user.get("html_url") or "",
    }

def query_github_user(username: str, api_key: str) -> Dict[str, Any]:
    login = (username or "").strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9-]{1,39}$", login):
        return {"error": "Invalid GitHub username"}
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:user:{login.lower()}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _github_get(f"/users/{login}", api_key, {})
    if _github_is_error(raw):
        return raw
    result = {"source": "GitHub", "user": normalize_github_user(raw), "raw": raw}
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["user"])
    return result

def query_github_user_repos(username: str, api_key: str, page: int = 1) -> Dict[str, Any]:
    login = (username or "").strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9-]{1,39}$", login):
        return {"error": "Invalid GitHub username"}
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:user_repos:{login.lower()}:{page}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _github_get(f"/users/{login}/repos", api_key,
                      {"per_page": 30, "page": page, "sort": "updated"})
    if _github_is_error(raw):
        return raw
    repos = [normalize_github_repo(x) for x in (raw if isinstance(raw, list) else [])]
    result = {"source": "GitHub", "user": login, "page": page,
              "repositories": [r for r in repos if r.get("full_name")],
              "relationships": [{"source": login, "relation": "owns", "target": r["full_name"], "target_type": "repository"}
                                for r in repos if r.get("full_name")]}
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["user"])
    return result

def query_github_org(org: str, api_key: str) -> Dict[str, Any]:
    login = (org or "").strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9-]{1,39}$", login):
        return {"error": "Invalid GitHub organization"}
    cache_key = f"github:{_github_auth_fingerprint(api_key)}:org:{login.lower()}"
    cached = _github_cache_get(cache_key)
    if cached is not None:
        return cached
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_org = executor.submit(_github_get, f"/orgs/{login}", api_key, {})
        future_repos = executor.submit(_github_get, f"/orgs/{login}/repos", api_key,
                                       {"per_page": 30, "sort": "updated"})
        raw_org, raw_repos = future_org.result(), future_repos.result()
    if _github_is_error(raw_org):
        return raw_org
    repos = [normalize_github_repo(x) for x in (raw_repos if isinstance(raw_repos, list) else [])]
    repos = [r for r in repos if r.get("full_name")]
    result = {"source": "GitHub", "organization": {
        "login": raw_org.get("login") or "", "name": raw_org.get("name") or "",
        "description": raw_org.get("description") or "",
        "public_repos": raw_org.get("public_repos"), "url": raw_org.get("html_url") or ""},
        "repositories": repos,
        "relationships": [{"source": login, "relation": "owns", "target": r["full_name"], "target_type": "repository"}
                          for r in repos]}
    _github_cache_set(cache_key, result, _GITHUB_CACHE_TTL["org"])
    return result

ARCHIVE_AVAILABLE_URL = "https://archive.org/wayback/available"
ARCHIVE_CDX_URL = "https://web.archive.org/cdx/search/cdx"
ARCHIVE_WEB_BASE = "https://web.archive.org/web"
ARCHIVE_USER_AGENT = os.environ.get(
    "MANTIS_ARCHIVE_USER_AGENT",
    os.environ.get(
        "IOCINTEL_ARCHIVE_USER_AGENT",
        "MANTIS/1.0 (passive historical web intelligence)"
    )
)
ARCHIVE_CDX_FIELDS = "urlkey,timestamp,original,mimetype,statuscode,digest,length"
ARCHIVE_WRITE_MARKERS = (
    "save", "savepagenow", "upload", "metadata", "tasks", "derive", "delete",
    "reviews", "review", "relationships", "services", "modify", "submit",
    "create", "rerun", "s3", "bucket"
)
_ARCHIVE_CACHE: Dict[str, Any] = {}

def _archive_cache_get(key: str) -> Any:
    entry = _ARCHIVE_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _ARCHIVE_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _archive_cache_set(key: str, value: Any, ttl: int = 21600) -> None:
    try:
        _ARCHIVE_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _archive_is_allowed_get(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if host == "archive.org" and path == "/wayback/available":
        return True
    if host == "web.archive.org" and path == "/cdx/search/cdx":
        return True
    if host == "web.archive.org" and re.match(r"^/web/\d{14}id_/https?://", parsed.path):
        return True
    if any(marker in path for marker in ARCHIVE_WRITE_MARKERS):
        return False
    return False

def _archive_get(url: str, params: Dict[str, Any] = None, label: str = "Internet Archive", as_text: bool = False) -> Any:
    if not _archive_is_allowed_get(url):
        return {"error": "Internet Archive endpoint is not allowlisted for passive read-only use"}
    cache_key = f"archive:get:{url}:{urllib.parse.urlencode(sorted((params or {}).items()), doseq=True)}:{as_text}"
    cached = _archive_cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        headers = {
            "User-Agent": ARCHIVE_USER_AGENT,
            "Accept": "text/plain" if as_text else "application/json",
        }
        resp = requests.get(url, params=params or {}, headers=headers, timeout=20)
        if resp.status_code == 204:
            result = {"data": []}
        elif resp.status_code == 200:
            if as_text:
                result = {
                    "text": resp.text,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "status_code": resp.status_code,
                    "final_url": resp.url,
                }
            else:
                try:
                    result = resp.json()
                except ValueError:
                    result = {"text": resp.text}
        elif resp.status_code == 404:
            result = {"data": [], "not_found": True}
        elif resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "")
            result = {"error": "Rate limited by Internet Archive", "retry_after": retry_after}
        else:
            result = {"error": f"{label} status {resp.status_code} - {resp.text[:500]}"}
    except requests.exceptions.Timeout:
        result = {"error": f"{label} timed out"}
    except Exception as e:
        result = {"error": f"{label} failed", "message": str(e)}
    cache_ttl = 60 if isinstance(result, dict) and result.get("error") else (86400 if as_text else 21600)
    _archive_cache_set(cache_key, result, cache_ttl)
    return result

def _archive_timestamp_display(timestamp: str) -> str:
    ts = str(timestamp or "")
    if not re.match(r"^\d{14}$", ts):
        return ts
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]} UTC"

def _archive_snapshot_urls(timestamp: str, original: str) -> Dict[str, str]:
    if not timestamp or not original:
        return {"snapshot_url": "", "raw_snapshot_url": ""}
    return {
        "snapshot_url": f"{ARCHIVE_WEB_BASE}/{timestamp}/{original}",
        "raw_snapshot_url": f"{ARCHIVE_WEB_BASE}/{timestamp}id_/{original}",
    }

def _archive_row_to_snapshot(row: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = str(row.get("timestamp") or "")
    original = str(row.get("original") or "")
    urls = _archive_snapshot_urls(timestamp, original)
    return {
        "timestamp": timestamp,
        "timestamp_display": _archive_timestamp_display(timestamp),
        "original_url": original,
        "archived_url": urls["snapshot_url"],
        "raw_archived_url": urls["raw_snapshot_url"],
        "status": str(row.get("statuscode") or ""),
        "mime_type": str(row.get("mimetype") or ""),
        "digest": str(row.get("digest") or ""),
        "length": str(row.get("length") or ""),
        "urlkey": str(row.get("urlkey") or ""),
    }

def _archive_parse_cdx(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict) and raw.get("error"):
        return {"error": raw.get("error"), "retry_after": raw.get("retry_after")}
    if not isinstance(raw, list) or not raw:
        return {"rows": [], "resume_key": ""}
    header = raw[0] if isinstance(raw[0], list) else ARCHIVE_CDX_FIELDS.split(",")
    rows = []
    resume_key = ""
    items = raw[1:] if isinstance(raw[0], list) else raw
    for item in items:
        if item == []:
            continue
        if isinstance(item, list) and len(item) == 1 and not str(item[0]).isdigit():
            resume_key = str(item[0])
            continue
        if isinstance(item, list):
            rows.append({str(header[idx]): value for idx, value in enumerate(item) if idx < len(header)})
        elif isinstance(item, dict):
            rows.append(item)
    return {"rows": [_archive_row_to_snapshot(row) for row in rows], "resume_key": resume_key}

def _archive_availability(target_url: str) -> Dict[str, Any]:
    raw = _archive_get(ARCHIVE_AVAILABLE_URL, {"url": target_url}, "Internet Archive availability")
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    closest = (raw or {}).get("archived_snapshots", {}).get("closest", {}) if isinstance(raw, dict) else {}
    timestamp = str(closest.get("timestamp") or "")
    return {
        "query_url": (raw or {}).get("url", target_url) if isinstance(raw, dict) else target_url,
        "available": bool(closest.get("available")),
        "status": str(closest.get("status") or ""),
        "timestamp": timestamp,
        "timestamp_display": _archive_timestamp_display(timestamp),
        "archived_url": closest.get("url", ""),
    }

def _archive_cdx(params: Dict[str, Any], label: str = "Internet Archive CDX") -> Dict[str, Any]:
    clean = {k: v for k, v in params.items() if v not in (None, "")}
    clean.setdefault("output", "json")
    clean.setdefault("fl", ARCHIVE_CDX_FIELDS)
    raw = _archive_get(ARCHIVE_CDX_URL, clean, label)
    return _archive_parse_cdx(raw)

def _archive_query_target(indicator: str, query_type: str = "") -> Dict[str, str]:
    raw = (indicator or "").strip()
    qtype = (query_type or "").strip().lower()
    if qtype == "url" or (not qtype and is_url(raw)):
        url = normalize_url(raw)
        return {"query_type": "url", "target": url, "availability_url": url, "match_type": "exact"}
    domain = normalize_domain(raw)
    return {"query_type": "domain", "target": domain, "availability_url": f"http://{domain}/", "match_type": "domain"}

def _archive_normalize_result(indicator: str, query_type: str, availability: List[Dict[str, Any]],
                              first_rows: List[Dict[str, Any]], latest_rows: List[Dict[str, Any]],
                              historical_rows: List[Dict[str, Any]], resume_key: str = "") -> Dict[str, Any]:
    combined = [row for row in first_rows + latest_rows + historical_rows if row.get("timestamp") and row.get("original_url")]
    by_url = {}
    for row in historical_rows + latest_rows + first_rows:
        original = row.get("original_url", "")
        if not original or original in by_url:
            continue
        by_url[original] = row
    sorted_rows = sorted(combined, key=lambda r: r.get("timestamp", ""))
    first = sorted_rows[0] if sorted_rows else {}
    last = sorted_rows[-1] if sorted_rows else {}
    historical_urls = list(by_url.values())
    relationships = []
    for row in historical_urls[:50]:
        relationships.append({
            "source": indicator,
            "relation": "historically_exposed",
            "target": row.get("original_url", ""),
            "target_type": "url",
            "timestamp": row.get("timestamp", ""),
        })
    for row in (latest_rows or first_rows)[:25]:
        relationships.append({
            "source": row.get("original_url", indicator),
            "relation": "archived_as",
            "target": row.get("archived_url", ""),
            "target_type": "snapshot",
            "timestamp": row.get("timestamp", ""),
        })
        relationships.append({
            "source": row.get("archived_url", ""),
            "relation": "captured_at",
            "target": row.get("timestamp_display", row.get("timestamp", "")),
            "target_type": "timestamp",
        })
    return {
        "source": "Internet Archive",
        "provider": "Wayback Machine",
        "type": "historical_web_intelligence",
        "query": indicator,
        "query_type": query_type,
        "semantics": {
            "label": "Historical Web Activity",
            "found_does_not_mean_malicious": True,
            "not_found_does_not_mean_benign": True,
            "first_archived_is_not_domain_creation": True,
            "historical_status_is_not_current_status": True,
        },
        "availability": availability,
        "summary": {
            "first_archived": first.get("timestamp", ""),
            "first_archived_display": first.get("timestamp_display", ""),
            "first_url": first.get("original_url", ""),
            "last_archived": last.get("timestamp", ""),
            "last_archived_display": last.get("timestamp_display", ""),
            "last_url": last.get("original_url", ""),
            "available_snapshots_returned": len(combined),
            "historical_urls_returned": len(historical_urls),
            "partial": True,
        },
        "snapshots": latest_rows[:25],
        "historical_urls": historical_urls[:50],
        "timeline": sorted_rows[:80],
        "pagination": {"resume_key": resume_key, "has_more": bool(resume_key)},
        "relationships": [r for r in relationships if r.get("target")],
    }

def query_archive_cdx(indicator: str, query_type: str = "") -> Dict[str, Any]:
    target = _archive_query_target(indicator, query_type)
    if not target["target"]:
        return {"error": "Invalid Internet Archive query"}
    cache_key = f"archive:summary:{target['query_type']}:{target['target']}"
    cached = _archive_cache_get(cache_key)
    if cached is not None:
        return cached

    availability_targets = [target["availability_url"]]
    if target["query_type"] == "domain":
        domain = target["target"]
        alt = domain[4:] if domain.startswith("www.") else f"www.{domain}"
        availability_targets.append(f"http://{alt}/")
    availability = [_archive_availability(url) for url in dict.fromkeys(availability_targets)]

    if target["query_type"] == "url":
        base_params = {"url": target["target"], "matchType": "exact"}
    else:
        base_params = {"url": f"{target['target']}/*", "matchType": "domain"}

    first = _archive_cdx({**base_params, "limit": 1}, "Internet Archive first snapshot")
    latest = _archive_cdx({**base_params, "limit": -10, "fastLatest": "true"}, "Internet Archive latest snapshots")
    historical = _archive_cdx({**base_params, "limit": 25, "collapse": "urlkey", "showResumeKey": "true"},
                              "Internet Archive historical URLs")
    for bucket in (first, latest, historical):
        if bucket.get("error"):
            return {"error": bucket["error"], "retry_after": bucket.get("retry_after")}
    result = _archive_normalize_result(
        target["target"], target["query_type"], availability,
        first.get("rows", []), latest.get("rows", []), historical.get("rows", []),
        historical.get("resume_key", "")
    )
    _archive_cache_set(cache_key, result, 21600)
    return result

def _archive_safe_digits(value: str, min_len: int = 1, max_len: int = 14) -> str:
    value = (value or "").strip()
    if value and not re.match(rf"^\d{{{min_len},{max_len}}}$", value):
        return ""
    return value

def query_archive_historical_urls(indicator: str, query_type: str = "", limit: int = 50,
                                  resume_key: str = "", from_ts: str = "", to_ts: str = "",
                                  status: str = "", mime: str = "", path: str = "",
                                  extension: str = "") -> Dict[str, Any]:
    target = _archive_query_target(indicator, query_type)
    if not target["target"]:
        return {"error": "Invalid Internet Archive query"}
    try:
        limit = max(1, min(int(limit or 50), 200))
    except (TypeError, ValueError):
        limit = 50
    params = {
        "url": target["target"] if target["query_type"] == "url" else f"{target['target']}/*",
        "matchType": "exact" if target["query_type"] == "url" else "domain",
        "limit": limit,
        "collapse": "urlkey",
        "showResumeKey": "true",
    }
    if resume_key and re.match(r"^[A-Za-z0-9%+!(),._~-]{1,500}$", resume_key):
        params["resumeKey"] = resume_key
    if _archive_safe_digits(from_ts):
        params["from"] = from_ts
    if _archive_safe_digits(to_ts):
        params["to"] = to_ts
    filters = []
    if re.match(r"^\d{3}$", status or ""):
        filters.append(f"statuscode:{status}")
    if mime and re.match(r"^[A-Za-z0-9*.+/_-]{1,80}$", mime):
        filters.append(f"mimetype:{mime}")
    if extension and re.match(r"^[A-Za-z0-9]{1,20}$", extension):
        filters.append(rf"original:.*\.{re.escape(extension)}(?:[?#].*)?$")
    if filters:
        params["filter"] = filters
    parsed = _archive_cdx(params, "Internet Archive historical URLs")
    if parsed.get("error"):
        return {"error": parsed["error"], "retry_after": parsed.get("retry_after")}
    rows = parsed.get("rows", [])
    if path:
        needle = path.strip().lower()
        if len(needle) <= 200 and "\n" not in needle and "\r" not in needle:
            rows = [row for row in rows if needle in (row.get("original_url", "").lower())]
    by_url = {}
    for row in rows:
        original = row.get("original_url", "")
        if original and original not in by_url:
            by_url[original] = row
    rows = list(by_url.values())
    return {
        "source": "Internet Archive",
        "provider": "Wayback Machine",
        "type": "historical_urls",
        "query": target["target"],
        "query_type": target["query_type"],
        "historical_urls": rows,
        "snapshots": rows,
        "pagination": {"resume_key": parsed.get("resume_key", ""), "has_more": bool(parsed.get("resume_key")), "limit": limit},
        "filters": {"from": from_ts, "to": to_ts, "status": status, "mime": mime, "path": path, "extension": extension},
    }

def query_archive_timeline(indicator: str, query_type: str = "", limit: int = 80,
                           from_ts: str = "", to_ts: str = "", resume_key: str = "") -> Dict[str, Any]:
    target = _archive_query_target(indicator, query_type)
    if not target["target"]:
        return {"error": "Invalid Internet Archive query"}
    try:
        limit = max(1, min(int(limit or 80), 200))
    except (TypeError, ValueError):
        limit = 80
    params = {
        "url": target["target"] if target["query_type"] == "url" else f"{target['target']}/*",
        "matchType": "exact" if target["query_type"] == "url" else "domain",
        "limit": limit,
        "collapse": "timestamp:8",
        "showResumeKey": "true",
    }
    if _archive_safe_digits(from_ts):
        params["from"] = from_ts
    if _archive_safe_digits(to_ts):
        params["to"] = to_ts
    if resume_key and re.match(r"^[A-Za-z0-9%+!(),._~-]{1,500}$", resume_key):
        params["resumeKey"] = resume_key
    parsed = _archive_cdx(params, "Internet Archive timeline")
    if parsed.get("error"):
        return {"error": parsed["error"], "retry_after": parsed.get("retry_after")}
    rows = sorted(parsed.get("rows", []), key=lambda r: r.get("timestamp", ""))
    return {
        "source": "Internet Archive",
        "provider": "Wayback Machine",
        "type": "timeline",
        "query": target["target"],
        "query_type": target["query_type"],
        "timeline": rows,
        "pagination": {"resume_key": parsed.get("resume_key", ""), "has_more": bool(parsed.get("resume_key")), "limit": limit},
    }

def _archive_extract_iocs(text: str) -> Dict[str, List[str]]:
    iocs = extract_github_iocs(text or "")
    filenames = []
    for match in re.finditer(r"\b[A-Za-z0-9_.-]{1,120}\.(?:exe|dll|sys|ps1|bat|cmd|js|vbs|jar|zip|rar|7z|pdf|docm|xlsm)\b", text or "", re.IGNORECASE):
        filenames.append(match.group(0))
    iocs["files"] = list(dict.fromkeys(filenames))[:25]
    return iocs

def query_archive_snapshot(timestamp: str, original_url: str, max_bytes: int = 200000) -> Dict[str, Any]:
    timestamp = (timestamp or "").strip()
    original_url = normalize_url(original_url)
    if not re.match(r"^\d{14}$", timestamp) or not original_url:
        return {"error": "Invalid Internet Archive snapshot request"}
    try:
        max_bytes = max(1000, min(int(max_bytes or 200000), 500000))
    except (TypeError, ValueError):
        max_bytes = 200000
    raw_url = f"{ARCHIVE_WEB_BASE}/{timestamp}id_/{original_url}"
    raw = _archive_get(raw_url, label="Internet Archive snapshot", as_text=True)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    content_type = raw.get("content_type", "") if isinstance(raw, dict) else ""
    text = raw.get("text", "") if isinstance(raw, dict) else ""
    is_textual = bool(re.search(r"(text/|json|javascript|xml|html|x-www-form-urlencoded)", content_type, re.IGNORECASE))
    if not is_textual:
        text = ""
    if len(text.encode("utf-8", errors="ignore")) > max_bytes:
        text = text[:max_bytes]
    iocs = _archive_extract_iocs(text) if text else {"domains": [], "ips": [], "urls": [], "hashes": [], "cves": [], "emails": [], "files": []}
    relationships = []
    for key, target_type in (("domains", "domain"), ("ips", "ip"), ("urls", "url"), ("hashes", "hash"), ("emails", "email"), ("files", "file")):
        for value in iocs.get(key, [])[:25]:
            relationships.append({"source": raw_url, "relation": "references", "target": value, "target_type": target_type})
    return {
        "source": "Internet Archive",
        "provider": "Wayback Machine",
        "type": "snapshot_content",
        "timestamp": timestamp,
        "timestamp_display": _archive_timestamp_display(timestamp),
        "original_url": original_url,
        "archived_url": f"{ARCHIVE_WEB_BASE}/{timestamp}/{original_url}",
        "raw_archived_url": raw_url,
        "content_type": content_type,
        "text": text,
        "truncated": len(raw.get("text", "")) > len(text) if isinstance(raw, dict) else False,
        "iocs": iocs,
        "relationships": relationships,
    }

TWITTER_API_BASE = "https://api.twitterapi.io"
# Explicit read-only allowlist (verified against official TwitterAPI.io docs).
# Write/account-action families (login_v2, create/reply/delete/like/unlike/
# retweet/bookmark/follow/unfollow, send_dm, upload_media, update_*, community
# create/delete/join/leave, webhook add/update/delete, monitor add/remove) are
# structurally unreachable: no helper accepts an arbitrary endpoint and only
# GET is ever issued. Costly deferred areas (article, spaces, my_info,
# retweeters, full followings, verified followers, follow checks, about,
# lists, communities, trends) stay out of the allowlist for now.
TWITTER_READ_PATHS = (
    "/twitter/tweet/advanced_search",
    "/twitter/tweets",
    "/twitter/tweet/replies",
    "/twitter/tweet/quotes",
    "/twitter/tweet/thread_context",
    "/twitter/user/info",
    "/twitter/user/search",
    "/twitter/user/last_tweets",
    "/twitter/user/followers_ids",
)
TWITTER_WRITE_MARKERS = (
    "login", "create_tweet", "delete_tweet", "like_tweet", "unlike_tweet",
    "retweet_tweet", "bookmark", "follow_user", "unfollow_user", "send_dm",
    "upload_media", "update_avatar", "update_banner", "update_profile",
    "create_community", "delete_community", "join_community", "leave_community",
    "webhook", "monitor",
)
_TWITTER_CACHE: Dict[str, Any] = {}
_TWITTER_CACHE_TTL = {"search": 900, "tweet": 86400, "user": 21600,
                      "tweets": 120, "thread": 21600, "network": 900}

def _twitter_cache_get(key: str) -> Any:
    entry = _TWITTER_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _TWITTER_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _twitter_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _TWITTER_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _twitter_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _twitter_tweet_items(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return []
    if isinstance(raw.get("tweets"), list):
        return [x for x in raw["tweets"] if isinstance(x, dict)]
    data = raw.get("data")
    if isinstance(data, dict) and isinstance(data.get("tweets"), list):
        return [x for x in data["tweets"] if isinstance(x, dict)]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []

def _twitter_response_keys(raw: Any) -> List[str]:
    if not isinstance(raw, dict):
        return []
    keys = list(raw.keys())
    data = raw.get("data")
    if isinstance(data, dict):
        keys.extend([f"data.{key}" for key in data.keys()])
    return keys[:24]

def _twitter_next_cursor(raw: Any) -> str:
    if not isinstance(raw, dict):
        return ""
    pagination = raw.get("pagination") if isinstance(raw.get("pagination"), dict) else {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    return str(
        raw.get("next_cursor")
        or raw.get("nextCursor")
        or pagination.get("next_cursor")
        or pagination.get("nextCursor")
        or data.get("next_cursor")
        or data.get("nextCursor")
        or ""
    )

def _twitter_has_next_page(raw: Any, cursor: str) -> bool:
    if not isinstance(raw, dict):
        return False
    for obj in (raw, raw.get("data") if isinstance(raw.get("data"), dict) else {}, raw.get("pagination") if isinstance(raw.get("pagination"), dict) else {}):
        for key in ("has_next_page", "hasNextPage", "hasNext"):
            if key in obj:
                return bool(obj.get(key)) and bool(cursor)
    return bool(cursor)

def _twitter_get(path: str, api_key: str, params: Dict[str, Any] = None,
                 timeout: int = 20) -> Any:
    """Single gateway for TwitterAPI.io access. Only allowlisted read-only
    GET endpoints are reachable; the key travels in the X-API-Key header and
    is never logged or echoed in errors/results."""
    lowered = (path or "").lower().split("?")[0]
    for marker in TWITTER_WRITE_MARKERS:
        if marker in lowered:
            return {"error": "TwitterAPI.io write/action denied (passive-only integration)"}
    if lowered not in TWITTER_READ_PATHS:
        return {"error": "TwitterAPI.io endpoint not allowlisted (passive-only integration)"}
    if not api_key:
        return {"error": "No Twitter API Key provided"}
    try:
        resp = requests.get(f"{TWITTER_API_BASE}{path}", headers={"X-API-Key": api_key},
                            params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                logger.warning("TwitterAPI.io %s HTTP 200 malformed JSON", path)
                return {"error": "TwitterAPI.io returned a malformed response"}
            if isinstance(data, dict) and data.get("status") == "error":
                logger.warning("TwitterAPI.io %s provider error keys=%s", path, _twitter_response_keys(data))
                return {"error": f"TwitterAPI.io provider error: {data.get('message') or data.get('msg') or data.get('detail') or 'unknown'}"}
            cursor = _twitter_next_cursor(data)
            logger.info(
                "TwitterAPI.io %s HTTP 200 keys=%s tweet_count=%d next_page=%s cursor_present=%s",
                path,
                _twitter_response_keys(data),
                len(_twitter_tweet_items(data)),
                _twitter_has_next_page(data, cursor),
                bool(cursor),
            )
            return data
        if resp.status_code in {401, 403}:
            logger.warning("TwitterAPI.io %s auth failure HTTP %s", path, resp.status_code)
            return {"error": "TwitterAPI.io authentication failure (HTTP {})".format(resp.status_code)}
        if resp.status_code == 400:
            detail = ""
            try:
                body = resp.json()
                detail = str(body.get("message") or body.get("error") or "")
            except Exception:
                detail = ""
            return {"error": f"TwitterAPI.io invalid request: {detail[:300] or 'validation error (HTTP 400)'}"}
        if resp.status_code == 402:
            logger.warning("TwitterAPI.io %s plan/credit limit HTTP 402", path)
            return {"error": "TwitterAPI.io plan or credit limit reached (HTTP 402)"}
        if resp.status_code == 429:
            logger.warning("TwitterAPI.io %s rate limit HTTP 429", path)
            return {"error": "TwitterAPI.io rate limit exceeded (HTTP 429)"}
        if 500 <= resp.status_code < 600:
            logger.warning("TwitterAPI.io %s provider HTTP %s", path, resp.status_code)
            return {"error": f"TwitterAPI.io provider error (HTTP {resp.status_code})"}
        logger.warning("TwitterAPI.io %s failed HTTP %s", path, resp.status_code)
        return {"error": f"TwitterAPI.io request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        logger.warning("TwitterAPI.io %s request timeout", path)
        return {"error": "TwitterAPI.io request timeout"}
    except Exception as e:
        return {"error": f"TwitterAPI.io request failed: {e}"}

def _twitter_int(value: Any) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, number)

def _twitter_media_dedup_key(url: Any) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return raw
    host = parsed.netloc.lower()
    path = parsed.path or ""
    if host == "pbs.twimg.com" and (path.startswith("/media/") or path.startswith("/card_img/")):
        return f"{host}{path}"
    return urllib.parse.urlunparse((
        parsed.scheme.lower(),
        host,
        path.rstrip("/") if path != "/" else path,
        "",
        parsed.query,
        "",
    )) or raw

def normalize_twitter_user(user: Any) -> Dict[str, Any]:
    if not isinstance(user, dict):
        return {}
    return {
        "id": str(user.get("id") or ""),
        "username": user.get("userName") or user.get("username") or user.get("screen_name") or "",
        "name": user.get("name") or "",
        "description": user.get("description") or "",
        "url": user.get("url") or "",
        "profile_picture": user.get("profilePicture") or user.get("profile_picture") or "",
        "location": user.get("location") or "",
        "created_at": user.get("createdAt") or user.get("created_at") or "",
        "followers": _twitter_int(user.get("followers")),
        "following": _twitter_int(user.get("following")),
        "statuses": _twitter_int(user.get("statusesCount") or user.get("statuses_count")),
        "media_count": _twitter_int(user.get("mediaCount")),
        "verified": bool(user.get("isBlueVerified")) or bool(user.get("verifiedType")),
        "verified_type": user.get("verifiedType") or "",
        "automated": bool(user.get("isAutomated")),
        "automated_by": user.get("automatedBy") or "",
        "pinned_tweets": [str(x) for x in (user.get("pinnedTweetIds") or []) if x],
    }

def _twitter_entity_texts(entities: Any, key: str, subkey: str = "text") -> List[str]:
    out: List[str] = []
    if isinstance(entities, dict) and isinstance(entities.get(key), list):
        for entry in entities[key]:
            if isinstance(entry, dict) and isinstance(entry.get(subkey), str) and entry[subkey].strip():
                out.append(entry[subkey].strip())
    return list(dict.fromkeys(out))

def _twitter_media_items(item: Any) -> List[Dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    raw_items = []
    if isinstance((item.get("extendedEntities") or {}).get("media"), list):
        raw_items.extend((item.get("extendedEntities") or {}).get("media") or [])
    if isinstance((item.get("extended_entities") or {}).get("media"), list):
        raw_items.extend((item.get("extended_entities") or {}).get("media") or [])
    if isinstance((item.get("entities") or {}).get("media"), list):
        raw_items.extend((item.get("entities") or {}).get("media") or [])
    if isinstance(item.get("media"), list):
        raw_items.extend(item.get("media") or [])
    out: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}

    def add_media(media_type: Any, click_url: Any, preview_img: Any, width: Any = 0, height: Any = 0) -> None:
        preview = str(preview_img or "").strip()
        click = str(click_url or preview or "").strip()
        if preview.startswith(("https://t.co/", "http://t.co/")):
            preview = ""
        if click.startswith(("https://t.co/", "http://t.co/")) and preview:
            click = preview
        if not preview and not click:
            return
        key = _twitter_media_dedup_key(preview or click)
        entry = {
            "type": media_type or "photo",
            "url": click,
            "preview": preview,
            "width": _twitter_int(width),
            "height": _twitter_int(height),
        }
        if key in seen:
            existing = out[seen[key]]
            existing_area = int(existing.get("width") or 0) * int(existing.get("height") or 0)
            new_area = entry["width"] * entry["height"]
            if new_area > existing_area:
                out[seen[key]] = entry
            return
        seen[key] = len(out)
        out.append(entry)

    for media in raw_items:
        if not isinstance(media, dict):
            continue
        real_img = media.get("media_url_https") or media.get("mediaUrlHttps") or media.get("media_url") or media.get("preview_image_url") or media.get("previewImageUrl") or ""
        if real_img.startswith("https://t.co/") or real_img.startswith("http://t.co/"):
            real_img = ""

        click_url = media.get("expanded_url") or media.get("url") or real_img
        preview_img = real_img or media.get("preview_image_url") or media.get("previewImageUrl") or ""
        add_media(
            media.get("type") or media.get("mediaType") or "photo",
            click_url,
            preview_img,
            media.get("width"),
            media.get("height"),
        )
    card = item.get("card") if isinstance(item.get("card"), dict) else {}
    for binding in card.get("binding_values") or []:
        value = binding.get("value") if isinstance(binding, dict) else {}
        image = value.get("image_value") if isinstance(value, dict) else {}
        url = image.get("url") if isinstance(image, dict) else ""
        add_media(
            "photo",
            url,
            url,
            image.get("width") if isinstance(image, dict) else 0,
            image.get("height") if isinstance(image, dict) else 0,
        )
    return out[:12]

def normalize_twitter_tweet(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    entities = item.get("entities") if isinstance(item.get("entities"), dict) else {}
    urls = _twitter_entity_texts(entities, "urls", "expanded_url") or _twitter_entity_texts(entities, "urls", "url")
    hashtags = _twitter_entity_texts(entities, "hashtags")
    mentions = []
    if isinstance(entities.get("user_mentions"), list):
        for entry in entities["user_mentions"]:
            if isinstance(entry, dict) and isinstance(entry.get("screen_name"), str) and entry["screen_name"].strip():
                mentions.append({"username": entry["screen_name"].strip(),
                                 "name": entry.get("name") or "", "id": str(entry.get("id_str") or "")})
    author = normalize_twitter_user(item.get("author"))
    quoted = normalize_twitter_tweet(item.get("quoted_tweet")) if isinstance(item.get("quoted_tweet"), dict) else None
    retweeted = normalize_twitter_tweet(item.get("retweeted_tweet")) if isinstance(item.get("retweeted_tweet"), dict) else None
    return {
        "id": str(item.get("id") or item.get("tweet_id") or item.get("tweetId") or ""),
        "url": item.get("url") or "",
        "text": item.get("text") or "",
        "created_at": item.get("createdAt") or item.get("created_at") or "",
        "language": item.get("lang") or item.get("language") or "",
        "author": author,
        "metrics": {
            "replies": _twitter_int(item.get("replyCount")),
            "retweets": _twitter_int(item.get("retweetCount")),
            "quotes": _twitter_int(item.get("quoteCount")),
            "likes": _twitter_int(item.get("likeCount")),
            "views": _twitter_int(item.get("viewCount")),
            "bookmarks": _twitter_int(item.get("bookmarkCount")),
        },
        "entities": {"urls": urls, "hashtags": hashtags, "mentions": mentions},
        "media": _twitter_media_items(item),
        "conversation_id": str(item.get("conversationId") or item.get("conversation_id") or ""),
        "reply_to": str(item.get("inReplyToId") or item.get("in_reply_to") or ""),
        "reply_to_user": item.get("inReplyToUsername") or "",
        "quoted_tweet": quoted,
        "retweeted_tweet": retweeted,
        "raw_provider_data": item,
    }

def extract_twitter_iocs(tweet: Dict[str, Any]) -> Dict[str, List[str]]:
    """Analyst-triggered pivots only; mentioning an IOC proves nothing."""
    found: Dict[str, List[str]] = {"domains": [], "ips": [], "urls": [], "hashes": [],
                                   "cves": [], "hashtags": [], "mentions": []}
    if not isinstance(tweet, dict):
        return found
    entities = tweet.get("entities") if isinstance(tweet.get("entities"), dict) else {}
    for url in entities.get("urls", []) or []:
        if url and isinstance(url, str):
            found["urls"].append(url)
            host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0].strip().lower()
            if host and not host.endswith(("twitter.com", "x.com", "t.co")):
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
                    found["ips"].append(host)
                elif "." in host:
                    found["domains"].append(host.lstrip("."))
    for tag in entities.get("hashtags", []) or []:
        if tag and isinstance(tag, str):
            found["hashtags"].append(tag if tag.startswith("#") else f"#{tag}")
    for mention in entities.get("mentions", []) or []:
        username = mention.get("username") if isinstance(mention, dict) else mention
        if username and isinstance(username, str):
            found["mentions"].append(username if username.startswith("@") else f"@{username}")
    text = tweet.get("text") or ""
    for match in re.finditer(r"\b(?:CVE-\d{4}-\d{4,7})\b", text, re.IGNORECASE):
        found["cves"].append(match.group(0).upper())
    for match in re.finditer(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text):
        found["hashes"].append(match.group(0).lower())
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        candidate = match.group(0)
        try:
            if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv4Address):
                found["ips"].append(candidate)
        except ValueError:
            continue
    for match in re.finditer(r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]{2,}\b", text):
        candidate = match.group(0).strip(".:")
        try:
            if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv6Address):
                found["ips"].append(ipaddress.ip_address(candidate).compressed)
        except ValueError:
            continue
    for match in re.finditer(r"https?://[^\s)\"'<>]+", text):
        candidate = match.group(0).rstrip(".,;:!?")
        if candidate not in found["urls"]:
            found["urls"].append(candidate)
    for key in found:
        found[key] = list(dict.fromkeys(found[key]))[:25]
    return found

def _twitter_relationships(tweets: List[Dict[str, Any]], users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rels: List[Dict[str, Any]] = []
    seen = set()

    def add(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen:
            seen.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    for tweet in tweets:
        tid = tweet.get("id") or ""
        author = (tweet.get("author") or {}).get("username") or ""
        if tid and author:
            add(tid, "authored_by", author, "user")
        for mention in (tweet.get("entities") or {}).get("mentions", []) or []:
            username = mention.get("username") if isinstance(mention, dict) else mention
            if tid and username:
                add(tid, "mentions", username.lstrip("@"), "user")
        iocs = extract_twitter_iocs(tweet)
        for url in iocs["urls"]:
            add(tid, "references", url, "url")
        for domain in iocs["domains"]:
            add(tid, "references", domain, "domain")
        for ip in iocs["ips"]:
            add(tid, "references", ip, "ip")
        for file_hash in iocs["hashes"]:
            add(tid, "references", file_hash, "hash")
        for cve in iocs["cves"]:
            add(tid, "references", cve, "cve")
        if tid and tweet.get("reply_to"):
            add(tid, "replies_to", tweet["reply_to"], "tweet")
        if tid and isinstance(tweet.get("quoted_tweet"), dict) and tweet["quoted_tweet"].get("id"):
            add(tid, "quotes", tweet["quoted_tweet"]["id"], "tweet")
        if tid and tweet.get("conversation_id"):
            add(tid, "part_of", tweet["conversation_id"], "conversation")
    for user in users:
        username = user.get("username") or ""
        for follower_id in user.get("_follower_ids", []) or []:
            add(str(follower_id), "follows", username, "user")
    return rels

def build_twitter_query(keyword: str, query_type: str) -> str:
    keyword = (keyword or "").strip()
    if not keyword:
        return ""
    lowered = (query_type or "all").strip().lower()
    if lowered == "hashtag":
        tag = keyword if keyword.startswith("#") else f"#{keyword}"
        return tag
    if lowered == "username":
        user = keyword if keyword.startswith("@") else f"@{keyword}"
        return f"from:{user[1:]} OR {user}"
    if lowered in {"malware_family", "threat_actor", "cve", "campaign"}:
        return f'"{keyword}"'
    return keyword

def query_twitter_search(keyword: str, api_key: str, query_type: str = "all",
                         query_kind: str = "Latest", cursor: str = "",
                         since_time: int = 0, until_time: int = 0) -> Dict[str, Any]:
    query = build_twitter_query(keyword, query_type)
    if not query:
        return {"error": "Empty Twitter search"}
    if query_kind not in {"Latest", "Top"}:
        query_kind = "Latest"
    params: Dict[str, Any] = {"query": query, "queryType": query_kind}
    if cursor:
        params["cursor"] = cursor[:500]
    if since_time:
        try:
            params["since_time"] = int(since_time)
        except (TypeError, ValueError):
            pass
    if until_time:
        try:
            params["until_time"] = int(until_time)
        except (TypeError, ValueError):
            pass
    cache_key = f"twitter:search:{query_kind}:{query.lower()}:{params.get('cursor', '')}:{params.get('since_time', '')}:{params.get('until_time', '')}"
    cached = _twitter_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _twitter_get("/twitter/tweet/advanced_search", api_key, params)
    if _twitter_is_error(raw):
        return raw
    items = _twitter_tweet_items(raw)
    tweets = [normalize_twitter_tweet(x) for x in items]
    tweets = [t for t in tweets if t.get("id")]
    for tweet in tweets:
        tweet["iocs"] = extract_twitter_iocs(tweet)
    result = {"source": "Twitter/X", "query": query, "query_kind": query_kind,
              "query_type": (query_type or "all").strip().lower() or "all",
              "tweets": tweets,
              "pagination": {"has_next_page": bool(raw.get("has_next_page")),
                             "next_cursor": raw.get("next_cursor") or ""},
              "relationships": _twitter_relationships(tweets, []),
              "raw": raw}
    _twitter_cache_set(cache_key, result, _TWITTER_CACHE_TTL["search"])
    return result

def _twitter_tweet_id(value: str) -> str:
    value = (value or "").strip()
    match = re.search(r"(\d{10,25})", value)
    return match.group(1) if match else ""

def _twitter_screen_name(value: str) -> str:
    value = (value or "").strip().lstrip("@")
    if not value:
        return ""
    if "/" in value:
        value = value.rstrip("/").split("/")[-1]
    value = value.split("?")[0].strip()
    if not re.match(r"^[A-Za-z0-9_]{1,15}$", value):
        return ""
    return value

def query_twitter_tweet(tweet_id: str, api_key: str) -> Dict[str, Any]:
    tid = _twitter_tweet_id(tweet_id)
    if not tid:
        return {"error": "Invalid tweet ID"}
    cache_key = f"twitter:tweet:{tid}"
    cached = _twitter_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _twitter_get("/twitter/tweets", api_key, {"tweet_ids": tid})
    if _twitter_is_error(raw):
        return raw
    items = raw.get("tweets") if isinstance(raw, dict) and isinstance(raw.get("tweets"), list) else []
    tweets = [normalize_twitter_tweet(x) for x in items]
    tweets = [t for t in tweets if t.get("id")]
    if not tweets:
        return {"error": "Tweet not found"}
    for tweet in tweets:
        tweet["iocs"] = extract_twitter_iocs(tweet)
    result = {"source": "Twitter/X", "tweets": tweets,
              "relationships": _twitter_relationships(tweets, []), "raw": raw}
    _twitter_cache_set(cache_key, result, _TWITTER_CACHE_TTL["tweet"])
    return result

def _twitter_paged_tweets(path: str, params: Dict[str, Any], api_key: str,
                          cache_key: str, ttl_key: str) -> Dict[str, Any]:
    cached = _twitter_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _twitter_get(path, api_key, params)
    if _twitter_is_error(raw):
        return raw
    key = "replies" if isinstance(raw.get("replies"), list) else "tweets"
    items = raw.get(key) if isinstance(raw.get(key), list) else []
    tweets = [normalize_twitter_tweet(x) for x in items]
    tweets = [t for t in tweets if t.get("id")]
    for tweet in tweets:
        tweet["iocs"] = extract_twitter_iocs(tweet)
    result = {"source": "Twitter/X", "tweets": tweets,
              "pagination": {"has_next_page": bool(raw.get("has_next_page")),
                             "next_cursor": raw.get("next_cursor") or ""},
              "relationships": _twitter_relationships(tweets, []), "raw": raw}
    _twitter_cache_set(cache_key, result, _TWITTER_CACHE_TTL[ttl_key])
    return result

def query_twitter_replies(tweet_id: str, api_key: str, cursor: str = "") -> Dict[str, Any]:
    tid = _twitter_tweet_id(tweet_id)
    if not tid:
        return {"error": "Invalid tweet ID"}
    params: Dict[str, Any] = {"tweetId": tid}
    if cursor:
        params["cursor"] = cursor[:500]
    return _twitter_paged_tweets("/twitter/tweet/replies", params, api_key,
                                 f"twitter:replies:{tid}:{params.get('cursor', '')}", "tweets")

def query_twitter_quotes(tweet_id: str, api_key: str, cursor: str = "") -> Dict[str, Any]:
    tid = _twitter_tweet_id(tweet_id)
    if not tid:
        return {"error": "Invalid tweet ID"}
    params: Dict[str, Any] = {"tweetId": tid}
    if cursor:
        params["cursor"] = cursor[:500]
    return _twitter_paged_tweets("/twitter/tweet/quotes", params, api_key,
                                 f"twitter:quotes:{tid}:{params.get('cursor', '')}", "tweets")

def query_twitter_thread(tweet_id: str, api_key: str, cursor: str = "") -> Dict[str, Any]:
    tid = _twitter_tweet_id(tweet_id)
    if not tid:
        return {"error": "Invalid tweet ID"}
    params: Dict[str, Any] = {"tweetId": tid}
    if cursor:
        params["cursor"] = cursor[:500]
    return _twitter_paged_tweets("/twitter/tweet/thread_context", params, api_key,
                                 f"twitter:thread:{tid}:{params.get('cursor', '')}", "thread")

def query_twitter_user(username: str, api_key: str) -> Dict[str, Any]:
    name = _twitter_screen_name(username)
    if not name:
        return {"error": "Invalid X username (1-15 letters/numbers/underscore)"}
    cache_key = f"twitter:user:{name.lower()}"
    cached = _twitter_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _twitter_get("/twitter/user/info", api_key, {"userName": name})
    if _twitter_is_error(raw):
        return raw
    payload = raw.get("data") if isinstance(raw, dict) and isinstance(raw.get("data"), dict) else {}
    user = normalize_twitter_user(payload)
    if not user.get("id") and not user.get("username"):
        return {"error": "User not found"}
    result = {"source": "Twitter/X", "user": user, "raw": raw}
    _twitter_cache_set(cache_key, result, _TWITTER_CACHE_TTL["user"])
    return result

def query_twitter_user_search(keyword: str, api_key: str, cursor: str = "") -> Dict[str, Any]:
    keyword = (keyword or "").strip().lstrip("@")
    if not keyword:
        return {"error": "Empty user search"}
    params: Dict[str, Any] = {"query": keyword}
    if cursor:
        params["cursor"] = cursor[:500]
    cache_key = f"twitter:user_search:{keyword.lower()}:{params.get('cursor', '')}"
    cached = _twitter_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _twitter_get("/twitter/user/search", api_key, params)
    if _twitter_is_error(raw):
        return raw
    items = raw.get("users") if isinstance(raw, dict) and isinstance(raw.get("users"), list) else []
    users = [normalize_twitter_user(x) for x in items]
    users = [u for u in users if u.get("username") or u.get("id")]
    result = {"source": "Twitter/X", "users": users,
              "pagination": {"has_next_page": bool(raw.get("has_next_page")),
                             "next_cursor": raw.get("next_cursor") or ""},
              "relationships": _twitter_relationships([], users), "raw": raw}
    _twitter_cache_set(cache_key, result, _TWITTER_CACHE_TTL["search"])
    return result

def query_twitter_user_tweets(username: str, api_key: str, cursor: str = "",
                              include_replies: bool = False,
                              force_refresh: bool = False) -> Dict[str, Any]:
    name = _twitter_screen_name(username)
    if not name:
        return {"error": "Invalid X username (1-15 letters/numbers/underscore)"}
    params: Dict[str, Any] = {"userName": name}
    if cursor:
        params["cursor"] = cursor[:500]
    if include_replies:
        params["includeReplies"] = True
    cache_key = f"twitter:user_tweets:{name.lower()}:{params.get('cursor', '')}:{bool(include_replies)}"
    cached = None if force_refresh else _twitter_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _twitter_get("/twitter/user/last_tweets", api_key, params)
    if _twitter_is_error(raw):
        return raw
    items = _twitter_tweet_items(raw)
    tweets = [normalize_twitter_tweet(x) for x in items]
    tweets = [t for t in tweets if t.get("id")]
    for tweet in tweets:
        tweet["iocs"] = extract_twitter_iocs(tweet)
    next_cursor = _twitter_next_cursor(raw)
    has_next_page = _twitter_has_next_page(raw, next_cursor)
    if items and not tweets:
        logger.warning(
            "TwitterAPI.io @%s parser extracted zero canonical tweets from %d raw items keys=%s",
            name,
            len(items),
            _twitter_response_keys(raw),
        )
    logger.info(
        "TwitterAPI.io @%s normalized raw_tweets=%d normalized=%d next_page=%s cursor_present=%s",
        name,
        len(items),
        len(tweets),
        has_next_page,
        bool(next_cursor),
    )
    result = {"source": "Twitter/X", "tweets": tweets,
              "pagination": {"has_next_page": has_next_page,
                             "next_cursor": next_cursor},
              "diagnostics": {
                  "response_keys": _twitter_response_keys(raw),
                  "provider_tweets": len(items),
                  "normalized_tweets": len(tweets),
                  "cursor_present": bool(next_cursor),
                  "has_next_page": has_next_page,
              },
              "relationships": _twitter_relationships(tweets, []), "raw": raw}
    _twitter_cache_set(cache_key, result, _TWITTER_CACHE_TTL["tweets"])
    return result

def query_twitter_follower_ids(username: str, api_key: str, cursor: str = "",
                               count: int = 5000) -> Dict[str, Any]:
    """Cheapest network primitive: IDs only, hydrate selected users lazily."""
    name = _twitter_screen_name(username)
    if not name:
        return {"error": "Invalid X username (1-15 letters/numbers/underscore)"}
    try:
        count = max(50, min(int(count or 5000), 5000))
    except (TypeError, ValueError):
        count = 5000
    params: Dict[str, Any] = {"userName": name, "count": count}
    if cursor:
        params["cursor"] = cursor[:500]
    cache_key = f"twitter:follower_ids:{name.lower()}:{count}:{params.get('cursor', '')}"
    cached = _twitter_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _twitter_get("/twitter/user/followers_ids", api_key, params)
    if _twitter_is_error(raw):
        return raw
    ids = [str(x) for x in (raw.get("ids") or []) if str(x).isdigit()] if isinstance(raw, dict) else []
    result = {"source": "Twitter/X", "username": name, "follower_ids": ids,
              "pagination": {"has_next_page": bool(raw.get("has_next_page")),
                             "next_cursor": raw.get("next_cursor") or ""},
              "relationships": _twitter_relationships([], [{"username": name, "_follower_ids": ids}]),
              "raw": raw}
    _twitter_cache_set(cache_key, result, _TWITTER_CACHE_TTL["network"])
    return result

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"
# Read-only allowlist. Write/report endpoints (report, bulk-report,
# clear-address) are never reachable from MANTIS: passive lookups only.
ABUSEIPDB_READ_ENDPOINTS = ("/check", "/reports", "/check-block")
# Official category names (abuseipdb.com/categories). Unknown IDs preserved.
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}
_ABUSEIPDB_CACHE: Dict[str, Any] = {}
_ABUSEIPDB_CACHE_TTL = {"hit": 43200, "empty": 21600}

def _abuseipdb_cache_get(key: str) -> Any:
    entry = _ABUSEIPDB_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _ABUSEIPDB_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _abuseipdb_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _ABUSEIPDB_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _abuseipdb_get(path: str, api_key: str, params: Dict[str, Any] = None, timeout: int = 20) -> Any:
    """Provider-specific GET helper. Only allowlisted read-only endpoints are
    reachable; report/bulk-report/clear-address are explicitly denied."""
    lowered = (path or "").lower().split("?")[0]
    # Segment match so that "/reports" never trips the "/report" marker.
    segments = [seg for seg in lowered.split("/") if seg]
    if "report" in segments or "bulk-report" in segments or "clear-address" in segments:
        return {"error": "AbuseIPDB write/report operation denied (passive-only integration)"}
    if lowered not in ABUSEIPDB_READ_ENDPOINTS:
        return {"error": "AbuseIPDB endpoint not allowlisted (passive-only integration)"}
    if not api_key:
        return {"error": "Missing AbuseIPDB API Key"}
    # Documented header auth (never query-string; never logged).
    headers = {"Accept": "application/json", "Key": api_key}
    try:
        resp = requests.get(f"{ABUSEIPDB_API_BASE}{path}", headers=headers, params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"error": "AbuseIPDB returned a malformed response"}
        if resp.status_code in {401, 403}:
            return {"error": "AbuseIPDB authentication failure (HTTP {})".format(resp.status_code)}
        if resp.status_code == 402:
            return {"error": "AbuseIPDB request exceeds plan limits (HTTP 402)"}
        if resp.status_code == 422:
            detail = ""
            try:
                errors = resp.json().get("errors") or []
                detail = "; ".join([str(e.get("detail") or "") for e in errors if isinstance(e, dict)])[:300]
            except Exception:
                detail = ""
            return {"error": f"AbuseIPDB invalid request: {detail or 'validation error (HTTP 422)'}"}
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "") if hasattr(resp, "headers") else ""
            return {"error": "AbuseIPDB rate limit exceeded (HTTP 429){}".format(f" — retry after {retry}s" if retry else "")}
        if 500 <= resp.status_code < 600:
            return {"error": f"AbuseIPDB provider error (HTTP {resp.status_code})"}
        return {"error": f"AbuseIPDB request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB request timeout"}
    except Exception as e:
        return {"error": f"AbuseIPDB request failed: {e}"}

def _abuseipdb_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _abuseipdb_valid_ip(ip: str) -> str:
    normalized = normalize_ip(ip or "")
    if not normalized or not is_ip(normalized):
        return ""
    return normalized

def normalize_abuseipdb_category(category_id: Any) -> Dict[str, Any]:
    try:
        cid = int(category_id)
    except (TypeError, ValueError):
        return {"id": category_id, "name": ""}
    return {"id": cid, "name": ABUSEIPDB_CATEGORIES.get(cid, "")}

def normalize_abuseipdb_report(item: Any, ip: str = "") -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    categories = []
    raw_cats = item.get("categories") if isinstance(item.get("categories"), list) else []
    for cat in raw_cats:
        entry = normalize_abuseipdb_category(cat)
        if isinstance(entry.get("id"), int) or entry.get("name"):
            categories.append(entry)
    return {
        "reportedAt": item.get("reportedAt") or "",
        "comment": item.get("comment") or "",
        "categories": categories,
        "reporterId": item.get("reporterId"),
        "reporterCountryCode": item.get("reporterCountryCode") or "",
        "reporterCountryName": item.get("reporterCountryName") or "",
        "ip": ip,
    }

def _abuseipdb_relationships(ip: str, normalized: Dict[str, Any]) -> List[Dict[str, Any]]:
    rels: List[Dict[str, Any]] = []
    seen = set()

    def add(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen:
            seen.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    network = normalized.get("network", {}) if isinstance(normalized, dict) else {}
    if network.get("isp"):
        add(ip, "belongs_to", network["isp"], "isp")
    if network.get("domain"):
        add(ip, "associated_with", network["domain"], "domain")
    for hostname in (normalized.get("hostnames", []) if isinstance(normalized, dict) else []) or []:
        add(ip, "resolves_as", hostname, "hostname")
    if network.get("country"):
        add(ip, "located_in", network["country"], "country")
    return rels

def normalize_abuseipdb_check(payload: Any, max_age: int = 90) -> Dict[str, Any]:
    """AbuseIPDB confidence stays provider-specific. No malicious/benign,
    safe/unsafe inference is generated here."""
    normalized: Dict[str, Any] = {
        "source": "AbuseIPDB",
        "kind": "check",
        "ip": "",
        "max_age_days": max_age,
        "score": 0,
        "whitelist": None,
        "tor": None,
        "is_public": None,
        "total_reports": 0,
        "distinct_users": 0,
        "last_reported": "",
        "network": {"country_code": "", "country": "", "usage_type": "", "isp": "",
                    "domain": "", "ip_version": None},
        "hostnames": [],
        "recent_reports": [],
        "relationships": [],
        "raw": payload if isinstance(payload, dict) else {},
    }
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return normalized
    try:
        score = int(data.get("abuseConfidenceScore", 0) or 0)
    except (TypeError, ValueError):
        score = 0
    try:
        total = int(data.get("totalReports", 0) or 0)
    except (TypeError, ValueError):
        total = 0
    try:
        users = int(data.get("numDistinctUsers", 0) or 0)
    except (TypeError, ValueError):
        users = 0
    try:
        version = int(data.get("ipVersion")) if data.get("ipVersion") is not None else None
    except (TypeError, ValueError):
        version = None
    ip = data.get("ipAddress") or ""
    normalized.update({
        "ip": ip,
        "score": max(0, min(100, score)),
        "whitelist": data.get("isWhitelisted") if isinstance(data.get("isWhitelisted"), bool) else None,
        "tor": data.get("isTor") if isinstance(data.get("isTor"), bool) else None,
        "is_public": data.get("isPublic") if isinstance(data.get("isPublic"), bool) else None,
        "total_reports": total,
        "distinct_users": users,
        "last_reported": data.get("lastReportedAt") or "",
        "network": {
            "country_code": data.get("countryCode") or "",
            "country": data.get("countryName") or "",
            "usage_type": data.get("usageType") or "",
            "isp": data.get("isp") or "",
            "domain": data.get("domain") or "",
            "ip_version": version,
        },
        "hostnames": [h for h in (data.get("hostnames") or []) if isinstance(h, str) and h.strip()],
    })
    recent = []
    reports = data.get("reports") if isinstance(data.get("reports"), list) else []
    for item in reports[:25]:
        entry = normalize_abuseipdb_report(item, ip)
        if entry:
            recent.append(entry)
    normalized["recent_reports"] = recent
    normalized["relationships"] = _abuseipdb_relationships(ip, normalized)
    return normalized

def query_abuseipdb(ip: str, api_key: str, max_age: int = 90) -> Dict[str, Any]:
    valid_ip = _abuseipdb_valid_ip(ip)
    if not valid_ip:
        return {"error": "AbuseIPDB supports IP addresses only (invalid IP, not a domain/URL/hash)."}
    try:
        max_age = max(1, min(int(max_age or 90), 365))
    except (TypeError, ValueError):
        max_age = 90
    cache_key = f"abuseipdb:check:{valid_ip}:{max_age}"
    cached = _abuseipdb_cache_get(cache_key)
    if cached is not None:
        return cached
    # verbose=1 keeps countryName + recent reports in ONE request.
    raw = _abuseipdb_get("/check", api_key, {"ipAddress": valid_ip, "maxAgeInDays": max_age, "verbose": 1})
    if _abuseipdb_is_error(raw):
        return raw
    result: Dict[str, Any] = {"data": (raw.get("data") if isinstance(raw, dict) else None) or raw,
                              "normalized": normalize_abuseipdb_check(raw, max_age)}
    _abuseipdb_cache_set(cache_key, result,
                          _ABUSEIPDB_CACHE_TTL["hit"] if result["normalized"]["total_reports"] else _ABUSEIPDB_CACHE_TTL["empty"])
    return result

def query_abuseipdb_reports(ip: str, api_key: str, max_age: int = 90, page: int = 1, per_page: int = 25) -> Dict[str, Any]:
    """Lazy full report history with documented pagination. Never called
    during the initial lookup."""
    valid_ip = _abuseipdb_valid_ip(ip)
    if not valid_ip:
        return {"error": "AbuseIPDB supports IP addresses only (invalid IP, not a domain/URL/hash)."}
    try:
        max_age = max(1, min(int(max_age or 90), 365))
    except (TypeError, ValueError):
        max_age = 90
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = max(1, min(int(per_page or 25), 100))
    except (TypeError, ValueError):
        per_page = 25
    cache_key = f"abuseipdb:reports:{valid_ip}:{max_age}:{page}:{per_page}"
    cached = _abuseipdb_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _abuseipdb_get("/reports", api_key, {"ipAddress": valid_ip, "maxAgeInDays": max_age, "page": page, "perPage": per_page})
    if _abuseipdb_is_error(raw):
        return raw
    data = raw.get("data") if isinstance(raw, dict) else None
    items = []
    total, last_page = 0, page
    if isinstance(data, dict):
        try:
            total = int(data.get("total", 0) or 0)
        except (TypeError, ValueError):
            total = 0
        try:
            last_page = int(data.get("lastPage", page) or page)
        except (TypeError, ValueError):
            last_page = page
        for item in (data.get("results") if isinstance(data.get("results"), list) else []):
            entry = normalize_abuseipdb_report(item, valid_ip)
            if entry:
                items.append(entry)
    result = {"ip": valid_ip, "reports": items,
              "pagination": {"page": page, "per_page": per_page, "total": total, "last_page": last_page,
                             "next_page": page + 1 if page < last_page else None},
              "relationships": [{"source": valid_ip, "relation": "has_abuse_report",
                                 "target": f"report@{r['reportedAt']}" if r.get("reportedAt") else "report",
                                 "target_type": "report"} for r in items if r.get("reportedAt")]
                             + [{"source": f"report@{r['reportedAt']}", "relation": "categorized_as",
                                 "target": c["name"] or f"category {c['id']}", "target_type": "category"}
                                for r in items if r.get("reportedAt") for c in r.get("categories", [])]}
    _abuseipdb_cache_set(cache_key, result, _ABUSEIPDB_CACHE_TTL["hit"] if items else _ABUSEIPDB_CACHE_TTL["empty"])
    return result

def query_abuseipdb_check_block(cidr: str, api_key: str, max_age: int = 30) -> Dict[str, Any]:
    """Explicit CIDR queries for Infra Search. Per-address rows only; a subnet
    with reports is never labeled malicious as a whole."""
    value = (cidr or "").strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return {"error": "AbuseIPDB check-block requires valid CIDR notation (e.g. 192.0.2.0/24)."}
    if (network.version == 4 and not 16 <= network.prefixlen <= 32) or \
       (network.version == 6 and not 32 <= network.prefixlen <= 128):
        return {"error": "AbuseIPDB check-block supports IPv4 /16–/32 and IPv6 /32–/128 (tighter plan limits enforced server-side)."}
    try:
        max_age = max(1, min(int(max_age or 30), 365))
    except (TypeError, ValueError):
        max_age = 30
    cache_key = f"abuseipdb:block:{str(network)}:{max_age}"
    cached = _abuseipdb_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _abuseipdb_get("/check-block", api_key, {"network": str(network), "maxAgeInDays": max_age})
    if _abuseipdb_is_error(raw):
        return raw
    data = raw.get("data") if isinstance(raw, dict) else {}
    if not isinstance(data, dict):
        data = {}
    addresses = []
    for entry in (data.get("reportedAddress") if isinstance(data.get("reportedAddress"), list) else []):
        if not isinstance(entry, dict) or not entry.get("ipAddress"):
            continue
        try:
            score = int(entry.get("abuseConfidenceScore", 0) or 0)
        except (TypeError, ValueError):
            score = 0
        try:
            count = int(entry.get("numReports", 0) or 0)
        except (TypeError, ValueError):
            count = 0
        addresses.append({"ip": entry["ipAddress"], "score": max(0, min(100, score)),
                          "reports": count, "last_reported": entry.get("mostRecentReport") or "",
                          "country": entry.get("countryCode") or ""})
    result = {"source": "AbuseIPDB", "kind": "check_block", "cidr": str(network),
              "network": {"address": data.get("networkAddress") or "", "netmask": data.get("netmask") or "",
                          "min": data.get("minAddress") or "", "max": data.get("maxAddress") or "",
                          "possible_hosts": data.get("numPossibleHosts"),
                          "description": data.get("addressSpaceDesc") or ""},
              "reported_addresses": addresses,
              "relationships": [{"source": str(network), "relation": "contains_reported",
                                 "target": a["ip"], "target_type": "ip"} for a in addresses]}
    _abuseipdb_cache_set(cache_key, result, _ABUSEIPDB_CACHE_TTL["hit"] if addresses else _ABUSEIPDB_CACHE_TTL["empty"])
    return result

# NOTE (deferred): GET /api/v2/blacklist is not integrated. MANTIS has no
# feed/watchlist feature, blacklist params are partly subscriber-gated, and
# standard-plan daily limits (5/day) make on-demand calls wasteful.

def query_threatfox(indicator: str, api_key: str) -> Dict[str, Any]:
    if not (api_key or "").strip():
        return {"error": "ThreatFox: Auth-Key required in Settings"}
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/json"}
    headers["Auth-Key"] = api_key.strip()

    def tf_post(payload: Dict[str, Any]):
        return _json_request("POST", url, "ThreatFox", headers=headers, json=payload)

    if is_hash(indicator):
        return tf_post({"query": "search_hash", "hash": indicator})

    if is_ip(indicator):
        results = _collect_callables({
            "exact": lambda: tf_post({"query": "search_ioc", "search_term": indicator, "exact_match": True}),
            "associations": lambda: tf_post({"query": "search_ioc", "search_term": indicator, "exact_match": False}),
        }, max_workers=2)
        merged = []
        seen = set()
        for key in ("exact", "associations"):
            data = results.get(key)
            if isinstance(data, dict) and isinstance(data.get("data"), list):
                for item in data["data"]:
                    unique = str(item.get("id") or item.get("ioc") or item)
                    if unique in seen:
                        continue
                    seen.add(unique)
                    merged.append(item)
        if merged:
            return {"query_status": "ok", "data": merged, "exact": results.get("exact"), "associations": results.get("associations")}
        first_error = next((v for v in results.values() if isinstance(v, dict) and v.get("error")), None)
        return first_error or {"query_status": "no_result", "data": []}

    return tf_post({"query": "search_ioc", "search_term": indicator, "exact_match": True})

def query_threatfox_ioc(ioc_id: str, api_key: str) -> Dict[str, Any]:
    if not (api_key or "").strip():
        return {"error": "ThreatFox: Auth-Key required in Settings"}
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/json"}
    headers["Auth-Key"] = api_key.strip()
    return _json_request("POST", url, "ThreatFox IOC detail", headers=headers, json={"query": "ioc", "id": ioc_id})

def query_malwarebazaar(file_hash: str, api_key: str) -> Dict[str, Any]:
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if api_key:
        headers["X-AbuseCh-Key"] = api_key
        
    payload = {
        "query": "get_info",
        "hash": file_hash
    }
    try:
        resp = requests.post(url, data=payload, headers=headers, timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            if isinstance(result, dict) and result.get("query_status") == "ok" and isinstance(result.get("data"), list):
                pivot_calls = {}
                seen = set()

                def add_pivot(name: str, query: str, field: str, value: str):
                    if not value:
                        return
                    key = f"{name}:{value}"
                    if key in seen:
                        return
                    seen.add(key)
                    body = {"query": query, field: value, "limit": 50}
                    pivot_calls[name] = lambda body=body: _json_request("POST", url, "MalwareBazaar pivot", headers=headers, data=body)

                for sample in result.get("data", [])[:3]:
                    if not isinstance(sample, dict):
                        continue
                    add_pivot("signature", "get_siginfo", "signature", sample.get("signature"))
                    add_pivot("imphash", "get_imphash", "imphash", sample.get("imphash"))
                    add_pivot("tlsh", "get_tlsh", "tlsh", sample.get("tlsh"))
                    add_pivot("telfhash", "get_telfhash", "telfhash", sample.get("telfhash"))
                    add_pivot("gimphash", "get_gimphash", "gimphash", sample.get("gimphash"))
                    add_pivot("icon_dhash", "get_dhash_icon", "dhash_icon", sample.get("dhash_icon"))
                    add_pivot("file_type", "get_file_type", "file_type", sample.get("file_type"))
                    code_sign_rows = sample.get("code_sign") if isinstance(sample.get("code_sign"), list) else ([sample.get("code_sign")] if isinstance(sample.get("code_sign"), dict) else [])
                    for cert in code_sign_rows[:3]:
                        add_pivot("cert_subject", "get_subjectinfo", "subject_cn", cert.get("subject_cn"))
                        add_pivot("cert_issuer", "get_issuerinfo", "issuer_cn", cert.get("issuer_cn"))
                        add_pivot("cert_serial", "get_certificate", "serial_number", cert.get("serial_number"))
                    for tag in (sample.get("tags") or [])[:5]:
                        add_pivot(f"tag_{tag}", "get_taginfo", "tag", tag)
                    intelligence_data = sample.get("intelligence") if isinstance(sample.get("intelligence"), dict) else {}
                    for intelligence in (intelligence_data.get("clamav") or [])[:3]:
                        add_pivot(f"clamav_{intelligence}", "get_clamavinfo", "clamav", intelligence)

                pivots = _keep_success(_collect_callables(pivot_calls, max_workers=8))
                if pivots:
                    result["pivots"] = pivots
            return result
        elif resp.status_code == 404:
            return {"error": "Not Found"}
        else:
            return {"error": f"Status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_yaraify_hash(file_hash: str, api_key: str) -> Dict[str, Any]:
    url = "https://yaraify-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/json"}
    if api_key: headers["Auth-Key"] = api_key
    
    payload = {
        "query": "lookup_hash",
        "search_term": file_hash
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            if isinstance(result, dict) and result.get("query_status") == "ok" and isinstance(result.get("data"), list):
                pivot_calls = {}
                seen = set()

                def sample_value(sample: Dict[str, Any], key: str):
                    metadata = sample.get("metadata") if isinstance(sample.get("metadata"), dict) else {}
                    return sample.get(key) or metadata.get(key)

                def add_pivot(name: str, query: str, value: str):
                    if not value:
                        return
                    key = f"{name}:{value}"
                    if key in seen:
                        return
                    seen.add(key)
                    body = {"query": query, "search_term": value, "result_max": 50}
                    pivot_calls[name] = lambda body=body: _json_request("POST", url, "YARAify pivot", headers=headers, json=body)

                for sample in result.get("data", [])[:3]:
                    if not isinstance(sample, dict):
                        continue
                    add_pivot("imphash", "get_imphash", sample_value(sample, "imphash"))
                    add_pivot("tlsh", "get_tlsh", sample_value(sample, "tlsh"))
                    add_pivot("telfhash", "get_telfhash", sample_value(sample, "telfhash"))
                    add_pivot("gimphash", "get_gimphash", sample_value(sample, "gimphash"))
                    add_pivot("icon_dhash", "get_dhash_icon", sample_value(sample, "dhash_icon"))

                pivots = _keep_success(_collect_callables(pivot_calls, max_workers=5))
                if pivots:
                    result["pivots"] = pivots
            return result
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def query_tf_keyword(keyword: str, query_type: str, api_key: str) -> Dict[str, Any]:
    if not (api_key or "").strip():
        return {"error": "ThreatFox: Auth-Key required in Settings"}
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/json", "Auth-Key": api_key.strip()}
    
    # query_type: 'taginfo' or 'malwareinfo'
    payload = {"query": query_type}
    if query_type == "taginfo": payload["tag"] = keyword
    elif query_type == "malwareinfo": payload["malware"] = keyword
    else: return {"error": "Invalid query_type for ThreatFox"}
    
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        if resp.status_code == 200: return resp.json()
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def query_mb_keyword(keyword: str, query_type: str, api_key: str) -> Dict[str, Any]:
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if api_key: headers["X-AbuseCh-Key"] = api_key
    
    # query_type maps to MalwareBazaar's supported malware/sample pivots.
    payload = {"query": query_type}
    if query_type == "get_taginfo": payload["tag"] = keyword
    elif query_type == "get_siginfo": payload["signature"] = keyword
    elif query_type == "get_yarainfo": payload["yara_rule"] = keyword
    elif query_type == "get_clamavinfo": payload["clamav"] = keyword
    elif query_type == "get_imphash": payload["imphash"] = keyword
    elif query_type == "get_tlsh": payload["tlsh"] = keyword
    elif query_type == "get_telfhash": payload["telfhash"] = keyword
    elif query_type == "get_gimphash": payload["gimphash"] = keyword
    elif query_type == "get_dhash_icon": payload["dhash_icon"] = keyword
    elif query_type == "get_file_type": payload["file_type"] = keyword
    elif query_type == "get_subjectinfo": payload["subject_cn"] = keyword
    elif query_type == "get_issuerinfo": payload["issuer_cn"] = keyword
    elif query_type == "get_certificate": payload["serial_number"] = keyword
    else: return {"error": "Invalid query_type for MalwareBazaar"}
    
    try:
        resp = requests.post(url, data=payload, headers=headers, timeout=15)
        if resp.status_code == 200: return resp.json()
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def query_yaraify_keyword(keyword: str, query_type: str, api_key: str) -> Dict[str, Any]:
    url = "https://yaraify-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/json"}
    if api_key: headers["Auth-Key"] = api_key
    
    payload = {}
    if query_type == "yara":
        payload = {"query": "get_yara", "search_term": keyword}
    elif query_type == "clamav":
        payload = {"query": "get_clamav", "search_term": keyword}
    elif query_type in {"imphash", "tlsh", "telfhash", "gimphash", "icon_dhash"}:
        query_name = "get_dhash_icon" if query_type == "icon_dhash" else f"get_{query_type}"
        payload = {"query": query_name, "search_term": keyword, "result_max": 100}
    else: return {"error": "Invalid query_type for YARAify"}
    
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        if resp.status_code == 200: return resp.json()
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

OTX_SECTIONS = {
    "file": ["general", "analysis"],
    "domain": ["general", "geo", "malware", "url_list", "passive_dns"],
    "hostname": ["general", "geo", "malware", "url_list", "passive_dns"],
    "IPv4": ["general", "reputation", "geo", "malware", "url_list", "passive_dns"],
    "IPv6": ["general", "reputation", "geo", "malware", "url_list", "passive_dns"],
    "url": ["general", "url_list"],
}

def _otx_str_list(values: Any) -> List[str]:
    out: List[str] = []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return out
    for v in values:
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
        elif isinstance(v, dict):
            for key in ("username", "display_name", "name", "id", "value", "country", "label"):
                val = v.get(key)
                if isinstance(val, str) and val.strip():
                    out.append(val.strip())
                    break
    # de-dupe preserving order
    seen = set()
    uniq = []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq

def _otx_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        for key in ("username", "display_name", "name", "author_name", "login", "id", "value", "indicator"):
            text = _otx_text(value.get(key))
            if text:
                return text
        return ""
    if isinstance(value, list):
        return ", ".join([text for text in (_otx_text(v) for v in value) if text])
    return str(value).strip()

def _otx_first_nonempty(mapping: Any) -> str:
    if not isinstance(mapping, dict):
        return ""
    for key in sorted(mapping.keys()):
        val = mapping.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""

def normalize_otx_pulse(p: Any) -> Dict[str, Any]:
    if not isinstance(p, dict):
        return {}
    industries = p.get("industries")
    if isinstance(industries, str):
        industries = [industries] if industries.strip() else []
    return {
        "id": _otx_text(p.get("id")),
        "name": _otx_text(p.get("name")),
        "description": _otx_text(p.get("description")),
        "author": _otx_text(p.get("author_name") or p.get("author")),
        "created": p.get("created") or "",
        "modified": p.get("modified") or "",
        "tags": _otx_str_list(p.get("tags")),
        "references": _otx_str_list(p.get("references")),
        "adversary": _otx_text(p.get("adversary")),
        "malware_families": _otx_str_list(p.get("malware_families")),
        "targeted_countries": _otx_str_list(p.get("targeted_countries") or p.get("targeted_countries_list")),
        "industries": _otx_str_list(industries),
        "attack_ids": _otx_str_list(p.get("attack_ids")),
        "indicator_count": p.get("indicator_count", p.get("indicator-count", p.get("indicators_count", 0))) or 0,
    }

def _otx_extract_pulses(general: Any) -> List[Dict[str, Any]]:
    if not isinstance(general, dict):
        return []
    pulse_info = general.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") if isinstance(pulse_info, dict) else None
    if pulses is None:
        pulses = general.get("pulses")
    if not isinstance(pulses, list):
        return []
    return [p for p in pulses if isinstance(p, dict)]

def _otx_extract_pdns(section: Any) -> List[Dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    raw = section.get("passive_dns")
    if raw is None:
        raw = section.get("passive_dns_records") or section.get("results") or section.get("data")
    if isinstance(raw, dict):
        raw = raw.get("records") or raw.get("passive_dns") or []
    if not isinstance(raw, list):
        return []
    out = []
    for r in raw:
        if not isinstance(r, dict):
            continue
        out.append({
            "record_type": r.get("record_type") or r.get("type") or "",
            "hostname": r.get("hostname") or "",
            "address": r.get("address") or r.get("ip") or "",
            "first": r.get("first") or r.get("first_seen") or "",
            "last": r.get("last") or r.get("last_seen") or "",
            "raw": r,
        })
    return out

def _otx_extract_urls(section: Any) -> List[Dict[str, Any]]:
    if section is None:
        return []
    candidates: Any = None
    if isinstance(section, dict):
        inner = section.get("url_list")
        if isinstance(inner, dict) and isinstance(inner.get("url_list"), list):
            candidates = inner["url_list"]
        elif isinstance(inner, list):
            candidates = inner
        elif isinstance(section.get("url_list"), list):
            candidates = section.get("url_list")
        else:
            candidates = section.get("results") or section.get("data") or section.get("urls") or []
    elif isinstance(section, list):
        candidates = section
    if not isinstance(candidates, list):
        return []
    out = []
    for u in candidates:
        if isinstance(u, str):
            out.append({"url": u, "date": "", "result": {}})
            continue
        if not isinstance(u, dict):
            continue
        url_val = u.get("url") or u.get("result", {}).get("urlworker", {}).get("url") if isinstance(u.get("result"), dict) else u.get("url")
        if not url_val and isinstance(u.get("result"), dict):
            url_val = u["result"].get("url")
        out.append({
            "url": url_val or "",
            "date": u.get("date") or u.get("datetime") or u.get("created") or "",
            "httpcode": u.get("httpcode", u.get("status", "")),
            "raw": u,
        })
    return [x for x in out if x.get("url") or x.get("raw")]

def _otx_extract_malware(section: Any) -> List[Dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    raw = section.get("data")
    if raw is None:
        raw = section.get("results") or section.get("malware") or []
    if not isinstance(raw, list):
        return []
    out = []
    for m in raw:
        if not isinstance(m, dict):
            continue
        detections = m.get("detections") if isinstance(m.get("detections"), dict) else {}
        out.append({
            "hash": m.get("hash") or "",
            "detections": detections,
            "detection": _otx_first_nonempty(detections),
            "timestamp": m.get("datetime_int") or m.get("date") or m.get("datetime") or m.get("created") or "",
            "raw": m,
        })
    return out

def normalize_otx_response(raw: Dict[str, Any], indicator: str, i_type: str) -> Dict[str, Any]:
    general = raw.get("general") if isinstance(raw, dict) else None
    raw_pulses = _otx_extract_pulses(general or {})
    pulses = [normalize_otx_pulse(p) for p in raw_pulses]
    pulse_count = 0
    if isinstance(general, dict):
        pi = general.get("pulse_info") or {}
        if isinstance(pi, dict) and isinstance(pi.get("count"), int):
            pulse_count = pi["count"]
        else:
            pulse_count = len(pulses)
    pdns = _otx_extract_pdns(raw.get("passive_dns") if isinstance(raw, dict) else None)
    urls = _otx_extract_urls(raw.get("url_list") if isinstance(raw, dict) else None)
    malware = _otx_extract_malware(raw.get("malware") if isinstance(raw, dict) else None)
    geo = raw.get("geo") if isinstance(raw, dict) and isinstance(raw.get("geo"), dict) else {}
    reputation = raw.get("reputation") if isinstance(raw, dict) and isinstance(raw.get("reputation"), dict) else {}
    analysis = raw.get("analysis") if isinstance(raw, dict) and isinstance(raw.get("analysis"), dict) else {}

    relationships: List[Dict[str, Any]] = []
    for p in pulses:
        pid = p.get("id") or p.get("name")
        if pid:
            relationships.append({"source": indicator, "relation": "mentioned_in", "target": pid, "target_type": "pulse"})
        if p.get("adversary"):
            relationships.append({"source": pid, "relation": "attributed_to", "target": p["adversary"], "target_type": "adversary"})
        for fam in p.get("malware_families", []) or []:
            relationships.append({"source": pid, "relation": "uses", "target": fam, "target_type": "malware_family"})
        for c in p.get("targeted_countries", []) or []:
            relationships.append({"source": pid, "relation": "targets", "target": c, "target_type": "country"})
        for ind in p.get("industries", []) or []:
            relationships.append({"source": pid, "relation": "targets", "target": ind, "target_type": "industry"})
        for aid in p.get("attack_ids", []) or []:
            relationships.append({"source": pid, "relation": "uses_technique", "target": aid, "target_type": "attack_id"})
        relationships.append({"source": pid, "relation": "contains", "target": f"{p.get('indicator_count', 0)} indicators", "target_type": "indicator_count"})
    for r in pdns:
        if i_type in ("domain", "hostname") and r.get("address"):
            relationships.append({"source": indicator, "relation": "resolves_to", "target": r["address"], "target_type": "ip"})
        elif i_type in ("IPv4", "IPv6") and r.get("hostname"):
            relationships.append({"source": indicator, "relation": "resolved_domain", "target": r["hostname"], "target_type": "domain"})
    for u in urls:
        if u.get("url"):
            relationships.append({"source": indicator, "relation": "associated_url", "target": u["url"], "target_type": "url"})
    for m in malware:
        if m.get("hash"):
            relationships.append({"source": indicator, "relation": "associated_malware", "target": m["hash"], "target_type": "hash"})

    return {
        "source": "AlienVault OTX",
        "overview": {"pulse_count": pulse_count, "indicator": indicator, "indicator_type": i_type},
        "pulses": pulses,
        "infrastructure": {"passive_dns": pdns, "urls": urls, "geo": geo or {}},
        "malware": malware,
        "reputation": reputation or {},
        "analysis": analysis or {},
        "relationships": relationships,
    }

def query_otx(indicator: str, i_type: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"error": "No API Key provided"}
    
    headers = {"X-OTX-API-KEY": api_key}
    path_indicator = urllib.parse.quote(indicator, safe='') if i_type == "url" else indicator
    base_url = f"https://otx.alienvault.com/api/v1/indicators/{i_type}/{path_indicator}"
    
    def fetch_section(section: str):
        try:
            resp = requests.get(f"{base_url}/{section}", headers=headers, timeout=30)
            if resp.status_code == 200: return resp.json()
            elif resp.status_code == 404: return None
            else: return {"error": f"Status {resp.status_code}"}
        except Exception as e: return {"error": str(e)}

    res: Dict[str, Any] = {}
    sections = OTX_SECTIONS.get(i_type, ["general"])
    with ThreadPoolExecutor(max_workers=max(1, len(sections))) as executor:
        futures = {s: executor.submit(fetch_section, s) for s in sections}
        for s, f in futures.items():
            res[s] = f.result()

    # Check if general failed
    if not res.get("general") or (isinstance(res.get("general"), dict) and "error" in res["general"]):
        return res.get("general") or {"error": "Not Found"}

    try:
        res["normalized"] = normalize_otx_response(res, indicator, i_type)
    except Exception as e:
        res["normalized"] = {"error": f"Normalization failed: {e}", "source": "AlienVault OTX"}

    return res

def query_otx_pulse(keyword: str, api_key: str) -> Dict[str, Any]:
    if not api_key: return {"error": "No API Key provided"}
    url = "https://otx.alienvault.com/api/v1/search/pulses"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        resp = requests.get(url, headers=headers, params={"q": keyword}, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                try:
                    data["normalized_pulses"] = [normalize_otx_pulse(p) for p in data["results"]]
                except Exception:
                    pass
            return data
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def _otx_indicator_items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("results", "indicators", "data", "items"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _otx_indicator_items(value)
            if nested:
                return nested
    if data.get("indicator") or data.get("value"):
        return [data]
    return []

def query_otx_pulse_indicators(pulse_id: str, api_key: str, limit: int = 100) -> Dict[str, Any]:
    if not api_key:
        return {"error": "No API Key provided"}
    pid = (pulse_id or "").strip()
    if not pid:
        return {"error": "Missing Pulse ID"}
    try:
        limit = max(1, min(int(limit or 100), 1000))
    except (TypeError, ValueError):
        limit = 100
    headers = {"X-OTX-API-KEY": api_key}
    indicators: List[Dict[str, Any]] = []
    encoded_pid = urllib.parse.quote(pid, safe='')
    url = f"https://otx.alienvault.com/api/v1/pulses/{encoded_pid}/indicators"
    params: Dict[str, Any] = {"limit": min(limit, 100), "page": 1}
    try:
        while len(indicators) < limit:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code != 200:
                if not indicators:
                    return {"error": f"Status {resp.status_code}"}
                break
            data = resp.json()
            batch = _otx_indicator_items(data)
            if not isinstance(batch, list):
                break
            indicators.extend([b for b in batch if isinstance(b, dict)])
            nxt = data.get("next") if isinstance(data, dict) else None
            if not nxt or len(indicators) >= limit:
                break
            # OTX returns a full URL (possibly relative) for next page
            if isinstance(nxt, str) and nxt:
                url = nxt if nxt.startswith("http") else urllib.parse.urljoin("https://otx.alienvault.com", nxt)
                params = {}
            else:
                params["page"] = int(params.get("page", 1)) + 1
        if not indicators:
            detail_resp = requests.get(f"https://otx.alienvault.com/api/v1/pulses/{encoded_pid}", headers=headers, timeout=30)
            if detail_resp.status_code == 200:
                indicators = _otx_indicator_items(detail_resp.json())
        indicators = indicators[:limit]
        grouped: Dict[str, List[str]] = {}
        for item in indicators:
            itype = str(item.get("type") or "other").strip() or "other"
            val = _otx_text(item.get("indicator") or item.get("value") or item.get("hostname") or item.get("domain") or item.get("url") or item.get("hash"))
            if val:
                grouped.setdefault(itype, []).append(val)
        return {"pulse_id": pid, "count": len(indicators), "grouped": grouped, "indicators": indicators}
    except Exception as e:
        return {"error": str(e)}



THREATBOOK_API_BASE = "https://api.threatbook.io"
# Quota-aware cache (seconds): successful results 24h, neutral/empty 12h,
# provider errors short/no cache. Keyed by normalized IP (IPv6 normalized).
_THREATBOOK_CACHE: Dict[str, Any] = {}
_THREATBOOK_CACHE_TTL = {"hit": 86400, "empty": 43200}

def _threatbook_cache_get(key: str) -> Any:
    entry = _THREATBOOK_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _THREATBOOK_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _threatbook_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _THREATBOOK_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _threatbook_error(status: int, msg: str) -> Dict[str, Any]:
    text = str(msg or "")
    if status == 400:
        if "Required" in text:
            return {"error": f"ThreatBook invalid request: {text}"}
        return {"error": f"ThreatBook invalid parameter: {text}"}
    if status == 401:
        return {"error": f"ThreatBook authentication/account failure: {text or 'check API key, access IP binding and quotas'}"}
    if status == 405:
        return {"error": "ThreatBook method error: Invalid API method"}
    if status == 429:
        return {"error": f"ThreatBook quota/rate limit exceeded: {text or 'request rate or quota limitation'}"}
    if 500 <= status < 600:
        return {"error": f"ThreatBook provider error (HTTP {status}): {text or 'system error'}"}
    return {"error": f"ThreatBook request failed (HTTP {status}): {text}"}

def normalize_threatbook_ip(payload: Any, ip: str) -> Dict[str, Any]:
    """Community IP Report normalization. Preserves provider semantics:
    whitelist=false is not malicious, empty judgments are not benign,
    timestamps are discovery dates, geo is not attribution."""
    normalized: Dict[str, Any] = {
        "source": "ThreatBook Community",
        "ip": ip,
        "summary": {"judgments": [], "whitelist": None, "first_seen": "", "last_seen": ""},
        "network": {"carrier": "", "country": "", "country_code": "", "province": "",
                    "city": "", "longitude": "", "latitude": ""},
        "asn": {"number": None, "name": "", "rank": None, "metadata": {}},
        "services": [],
        "certificates": [],
        "relationships": [],
        "raw": payload if isinstance(payload, dict) else {},
    }
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return normalized
    rels: List[Dict[str, Any]] = []

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    judgments = [j for j in (summary.get("judgments") or []) if isinstance(j, str) and j.strip()]
    normalized["summary"] = {
        "judgments": judgments,
        "whitelist": summary.get("whitelist") if isinstance(summary.get("whitelist"), bool) else None,
        "first_seen": summary.get("first_seen") or "",
        "last_seen": summary.get("last_seen") or "",
    }

    basic = data.get("basic") if isinstance(data.get("basic"), dict) else {}
    location = basic.get("location") if isinstance(basic.get("location"), dict) else {}
    normalized["network"] = {
        "carrier": basic.get("carrier") or "",
        "country": location.get("country") or "",
        "country_code": location.get("country_code") or "",
        "province": location.get("province") or "",
        "city": location.get("city") or "",
        "longitude": str(location.get("lng") or ""),
        "latitude": str(location.get("lat") or ""),
    }
    if normalized["network"]["country"]:
        rels.append({"source": ip, "relation": "located_in", "target": normalized["network"]["country"], "target_type": "country"})

    asn = data.get("asn") if isinstance(data.get("asn"), dict) else {}
    try:
        asn_number = int(asn.get("number")) if asn.get("number") is not None else None
    except (TypeError, ValueError):
        asn_number = None
    try:
        asn_rank = int(asn.get("rank")) if asn.get("rank") is not None else None
    except (TypeError, ValueError):
        asn_rank = None
    normalized["asn"] = {
        "number": asn_number,
        "name": asn.get("info") or "",
        "rank": asn_rank,
        "metadata": {k: v for k, v in asn.items() if k not in {"number", "info", "rank"}},
    }
    if asn_number is not None:
        rels.append({"source": ip, "relation": "belongs_to", "target": f"AS{asn_number}", "target_type": "asn"})

    services = []
    for entry in (data.get("ports") if isinstance(data.get("ports"), list) else []):
        if not isinstance(entry, dict):
            continue
        try:
            port = int(entry.get("port")) if entry.get("port") is not None else None
        except (TypeError, ValueError):
            port = None
        services.append({
            "port": port,
            "protocol": entry.get("protocol") or entry.get("module") or "",
            "module": entry.get("module") or "",
            "product": entry.get("product") or "",
            "version": entry.get("version") or "",
            "detail": entry.get("detail") or "",
        })
        if port is not None:
            rels.append({"source": ip, "relation": "exposes", "target": f"{ip}:{port}", "target_type": "service"})
    normalized["services"] = services

    certificates = []
    for entry in (data.get("cas") if isinstance(data.get("cas"), list) else []):
        if not isinstance(entry, dict):
            continue
        detail = entry.get("digital_certificate") if isinstance(entry.get("digital_certificate"), dict) else {}
        try:
            cert_port = int(entry.get("port")) if entry.get("port") is not None else None
        except (TypeError, ValueError):
            cert_port = None
        try:
            revoked = detail.get("revoked") if isinstance(detail.get("revoked"), bool) else None
        except Exception:
            revoked = None
        certificates.append({
            "protocol": entry.get("protocol") or "",
            "port": cert_port,
            "subject": detail.get("subject") or "",
            "issuer": detail.get("issuer") or "",
            "serial_number": detail.get("serial_number") or "",
            "fingerprints": {k: v for k, v in detail.items()
                             if k in {"fingerprint", "sha256", "sha1", "md5"} and isinstance(v, str) and v.strip()},
            "signature_algorithm": detail.get("verify") or "",
            "valid_from": detail.get("begin") or detail.get("start") or "",
            "valid_to": detail.get("end") or "",
            "status": detail.get("status") if detail.get("status") is not None else "",
            "status_desc": detail.get("status_desc") or "",
            "revoked": revoked,
            "revoke_time": detail.get("revoke_time") or detail.get("revoked_time") or "",
            "purpose": detail.get("purpose") or "",
        })
        subject = detail.get("subject") or ""
        issuer = detail.get("issuer") or ""
        if subject:
            rels.append({"source": ip, "relation": "presents", "target": subject, "target_type": "certificate"})
            rels.append({"source": subject, "relation": "has_subject", "target": subject, "target_type": "subject"})
        if issuer:
            rels.append({"source": subject or ip, "relation": "issued_by", "target": issuer, "target_type": "issuer"})
        for domain in _threatbook_cert_domains(subject):
            rels.append({"source": subject or ip, "relation": "references", "target": domain, "target_type": "domain"})
    normalized["certificates"] = certificates

    seen = set()
    deduped = []
    for rel in rels:
        key = (rel["source"], rel["relation"], rel["target"])
        if key not in seen:
            seen.add(key)
            deduped.append(rel)
    normalized["relationships"] = deduped
    return normalized

def _threatbook_cert_domains(subject: str) -> List[str]:
    """Extract DNS-like references (CN= / SAN entries) from a certificate
    subject string without asserting anything about them."""
    domains: List[str] = []
    if not isinstance(subject, str) or not subject:
        return domains
    for match in re.finditer(r"CN\s*=\s*([A-Za-z0-9*._-]+)", subject):
        candidate = match.group(1).strip().lstrip("*.")
        if "." in candidate and " " not in candidate:
            domains.append(candidate)
    for token in re.split(r"[,/;]", subject):
        token = token.strip().lstrip("*.")
        if token.startswith("DNS:"):
            token = token[4:].strip()
        if "." in token and " " not in token and "=" not in token and "@" not in token:
            if re.match(r"^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$", token):
                domains.append(token)
    return list(dict.fromkeys(domains))

def query_threatbook_ip(ip: str, api_key: str) -> Dict[str, Any]:
    # Community scope: IP Lookup only. Validate locally before spending quota.
    normalized_ip = normalize_ip(ip or "")
    if not normalized_ip or not is_ip(normalized_ip):
        return {"error": "ThreatBook Community supports IP addresses only (invalid IP, not a domain/URL/hash)."}
    if not api_key:
        return {"error": "No API Key provided"}

    cache_key = f"threatbook:{normalized_ip}"
    cached = _threatbook_cache_get(cache_key)
    if cached is not None:
        return cached

    # Documented Community auth: apikey + resource as query parameters.
    # The full URL (with key) is never logged. Omitting `include` returns
    # all Community sections in ONE request.
    url = f"{THREATBOOK_API_BASE}/v1/community/ip"
    try:
        resp = requests.post(url, params={"apikey": api_key, "resource": normalized_ip}, timeout=20)
        if resp.status_code == 200:
            try:
                payload = resp.json()
            except ValueError:
                return {"error": "ThreatBook returned a malformed response"}
            if not isinstance(payload, dict):
                return {"error": "ThreatBook returned a malformed response"}
            if payload.get("response_code") not in (None, 200) or str(payload.get("msg", "Success")) != "Success":
                return {"error": f"ThreatBook provider error: {payload.get('msg') or payload.get('response_code')}"}
            result: Dict[str, Any] = {"data": payload.get("data", payload),
                                      "normalized": normalize_threatbook_ip(payload, normalized_ip)}
            # Neutral/empty results get a shorter TTL; real errors are not cached.
            has_content = bool(result["normalized"]["summary"]["judgments"]
                               or result["normalized"]["services"]
                               or result["normalized"]["certificates"]
                               or result["normalized"]["network"]["country"]
                               or result["normalized"]["asn"]["number"] is not None)
            _threatbook_cache_set(cache_key, result,
                                  _THREATBOOK_CACHE_TTL["hit"] if has_content else _THREATBOOK_CACHE_TTL["empty"])
            return result
        try:
            detail = resp.json().get("msg")
        except Exception:
            detail = None
        return _threatbook_error(resp.status_code, detail or resp.text[:300])
    except requests.exceptions.Timeout:
        return {"error": "ThreatBook request timeout"}
    except Exception as e:
        return {"error": f"ThreatBook request failed: {e}"}

SILENT_PUSH_API_BASE = "https://api.silentpush.com"
SILENT_PUSH_PASSIVE_PATHS = (
    ("GET", re.compile(r"^/api/v1/merge-api/explore/enrich/(domain|ipv4|ipv6)/[^/]+$", re.I)),
    ("POST", re.compile(r"^/api/v1/merge-api/explore/bulk/summary/domain$", re.I)),
    ("POST", re.compile(r"^/api/v1/merge-api/explore/bulk/ip2asn/(ipv4|ipv6)$", re.I)),
    ("GET", re.compile(r"^/api/v1/merge-api/explore/domain/domaininfo/[^/]+$", re.I)),
    ("GET", re.compile(r"^/api/v1/merge-api/explore/domain/search$", re.I)),
    ("GET", re.compile(r"^/api/v1/merge-api/explore/padns/lookup/query/(a|aaaa|cname|mx|ns|ptr4|ptr6|any|soa|txt)/[^/]+$", re.I)),
    ("GET", re.compile(r"^/api/v1/merge-api/explore/padns/lookup/answer/(a|aaaa|cname|mx|ns|ptr4|ptr6|any|soa|txt|mxhash|nshash|soahash|txthash)/[^/]+$", re.I)),
    ("POST", re.compile(r"^/api/v1/merge-api/explore/scandata/search/raw$", re.I)),
    ("GET", re.compile(r"^/api/v2/iocs/threat-ranking/?$", re.I)),
)
SILENT_PUSH_ACTIVE_MARKERS = (
    "live-scan", "scan-on-demand", "screenshot-on-demand", "scanondemand",
    "screenshotondemand", "/tools/scan", "/tools/screenshot", "/feeds/",
    "/indicators", "/tags", "/monitor", "/monitors", "/submit", "/rescan",
)
SILENT_PUSH_CACHE: Dict[str, Any] = {}
SILENT_PUSH_CACHE_TTL = {"hit": 1800, "empty": 600, "error": 120}
SILENT_PUSH_PADNS_FORWARD_RECORDS = {"A", "AAAA", "CNAME", "MX", "NS", "PTR4", "PTR6", "ANY", "SOA", "TXT"}
SILENT_PUSH_PADNS_REVERSE_RECORDS = SILENT_PUSH_PADNS_FORWARD_RECORDS | {"MXHASH", "NSHASH", "SOAHASH", "TXTHASH"}
SILENT_PUSH_SPQL_SOURCES = "[webscan, torscan, webresources, opendirectory, services, whois]"

def _silent_push_key(_api_key: str = "") -> str:
    return (
        os.environ.get("SILENT_PUSH_API_KEY")
        or os.environ.get("SILENTPUSH_API_KEY")
        or os.environ.get("SILENT_PUSH_KEY")
        or os.environ.get("MANTIS_SILENTPUSH_KEY")
        or os.environ.get("MANTIS_SILENT_PUSH_KEY")
        or os.environ.get("IOCINTEL_SILENTPUSH_KEY")
        or os.environ.get("IOCINTEL_SILENT_PUSH_KEY")
        or (_api_key or "").strip()
        or ""
    ).strip()

def _silent_push_cache_key(method: str, path: str, params: Dict[str, Any] = None, body: Dict[str, Any] = None) -> str:
    blob = repr((method.upper(), path, sorted((params or {}).items()), body or {})).encode("utf-8", "replace")
    return "silentpush:" + hashlib.sha256(blob).hexdigest()

def _silent_push_cache_get(key: str) -> Any:
    entry = SILENT_PUSH_CACHE.get(key)
    if not entry:
        return None
    value, ts, ttl = entry
    if time.time() - ts <= ttl:
        return value
    SILENT_PUSH_CACHE.pop(key, None)
    return None

def _silent_push_cache_set(key: str, value: Any, ttl: int) -> None:
    if len(SILENT_PUSH_CACHE) > 512:
        SILENT_PUSH_CACHE.clear()
    SILENT_PUSH_CACHE[key] = (value, time.time(), ttl)

def _silent_push_sanitize_error(message: str, api_key: str = "") -> str:
    text = str(message or "")
    for secret in {api_key, _silent_push_key(api_key)}:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text[:800]

def _silent_push_allowed_path(method: str, path: str) -> bool:
    clean = urllib.parse.urlsplit(path).path
    method = method.upper()
    if any(method == allowed and pattern.match(clean) for allowed, pattern in SILENT_PUSH_PASSIVE_PATHS):
        return True
    lowered = clean.lower()
    if any(marker in lowered for marker in SILENT_PUSH_ACTIVE_MARKERS):
        return False
    return False

def _query_silent_push(path: str, api_key: str = "", method: str = "GET", params: Dict[str, Any] = None,
                       body: Dict[str, Any] = None, cache_ttl: int = 600) -> Dict[str, Any]:
    method = method.upper()
    if not _silent_push_allowed_path(method, path):
        return {"error": "Silent Push endpoint not allowlisted (passive-only integration)"}
    api_key = _silent_push_key(api_key)
    if not api_key:
        return {"error": "No Silent Push API key configured on server"}

    safe_params = {k: v for k, v in (params or {}).items() if v not in (None, "")}
    cache_key = _silent_push_cache_key(method, path, safe_params, body)
    cached = _silent_push_cache_get(cache_key)
    if cached is not None:
        return cached

    headers = {"X-API-KEY": api_key}
    if method == "POST":
        headers.update({"Content-Type": "application/json", "meta-data": "1"})
    try:
        resp = requests.request(
            method,
            f"{SILENT_PUSH_API_BASE}{path}",
            headers=headers,
            params=safe_params,
            json=body if method == "POST" else None,
            timeout=25,
        )
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text}
        if resp.status_code == 200:
            _silent_push_cache_set(cache_key, payload, cache_ttl)
            return payload
        detail = payload if isinstance(payload, dict) else resp.text
        if resp.status_code in (401, 403):
            result = {"error": f"Silent Push authentication/entitlement failed (HTTP {resp.status_code})",
                      "message": _silent_push_sanitize_error(detail, api_key)}
        elif resp.status_code == 404:
            result = {"error": "Not Found"}
        elif resp.status_code == 429:
            result = {"error": "Silent Push quota or rate limit reached", "message": _silent_push_sanitize_error(detail, api_key)}
        else:
            result = {"error": f"Silent Push status {resp.status_code}", "message": _silent_push_sanitize_error(detail, api_key)}
        _silent_push_cache_set(cache_key, result, SILENT_PUSH_CACHE_TTL["error"])
        return result
    except requests.exceptions.Timeout:
        return {"error": "Silent Push request timeout"}
    except Exception as e:
        return {"error": "Silent Push request failed", "message": _silent_push_sanitize_error(str(e), api_key)}

def _sp_text(value: Any) -> str:
    if value is None or value is False:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""

def _sp_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v not in (None, "")]
    if isinstance(value, tuple):
        return [v for v in value if v not in (None, "")]
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str):
        return [v.strip() for v in re.split(r"[,;\s]+", value) if v.strip()]
    return [value]

def _sp_response(raw: Any) -> Any:
    if isinstance(raw, dict) and "response" in raw:
        return raw.get("response")
    return raw

def _sp_records(raw: Any, *keys: str) -> List[Dict[str, Any]]:
    response = _sp_response(raw)
    if isinstance(response, list):
        return [x for x in response if isinstance(x, dict)]
    if not isinstance(response, dict):
        return []
    for key in keys + ("records", "scandata_raw", "results", "data"):
        value = response.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []

def _sp_first(obj: Any, keys: set, depth: int = 0) -> Any:
    if depth > 6 or obj is None:
        return None
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in keys and value not in (None, "", [], {}):
                return value
        for value in obj.values():
            found = _sp_first(value, keys, depth + 1)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(obj, list):
        for value in obj[:20]:
            found = _sp_first(value, keys, depth + 1)
            if found not in (None, "", [], {}):
                return found
    return None

def _sp_issue(endpoint: str, raw: Any) -> Dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    error = raw.get("error")
    status_code = raw.get("status_code")
    errors = raw.get("errors")
    if str(error).lower() in {"", "none", "null", "false"}:
        error = None
    if error and str(error).lower() in {"not found", "no data", "no results"}:
        return {}
    if not error and isinstance(status_code, int) and 200 <= status_code < 300:
        return {}
    if not error and not errors and (status_code in (None, 200)):
        return {}
    message = raw.get("message") or raw.get("detail") or error or errors or raw
    if isinstance(message, (dict, list)):
        message = str(message)
    return {"endpoint": endpoint, "message": _silent_push_sanitize_error(message)}

def normalize_silent_push_enrichment(raw: Any, indicator: str, query_type: str) -> Dict[str, Any]:
    response = _sp_response(raw)
    candidate = response
    if isinstance(response, dict):
        for key in ("ip2asn", "domaininfo", "records", "summary"):
            records = response.get(key)
            if isinstance(records, list) and records:
                candidate = records[0]
                break
            if isinstance(records, dict):
                candidate = records
                break
    if not isinstance(candidate, dict):
        candidate = {}
    location = _sp_first(candidate, {"ip_location", "location", "geoip"}) or {}
    flags = _sp_first(candidate, {"ip_flags", "flags"}) or {}
    return {
        "indicator": indicator,
        "type": query_type,
        "risk_score": _sp_first(candidate, {"sp_risk_score", "domain_risk_score", "risk_score"}),
        "risk_explanation": _sp_first(candidate, {"sp_risk_score_explain", "domain_risk_score_explain", "risk_score_explain"}),
        "reputation": _sp_first(candidate, {"ip_reputation", "domain_reputation", "reputation"}),
        "reputation_score": _sp_first(candidate, {"ip_reputation_score", "domain_reputation_score", "reputation_score"}),
        "asn": _sp_first(candidate, {"asn", "asnum"}),
        "asname": _sp_first(candidate, {"asname", "asn_name", "as_org"}),
        "country_code": location.get("country_code") if isinstance(location, dict) else _sp_text(_sp_first(candidate, {"country_code"})),
        "country_name": location.get("country_name") if isinstance(location, dict) else _sp_text(_sp_first(candidate, {"country_name"})),
        "location": location if isinstance(location, dict) else {},
        "ip_flags": flags if isinstance(flags, dict) else {},
        "proxy_tags": _sp_list(flags.get("proxy_tags") if isinstance(flags, dict) else _sp_first(candidate, {"proxy_tags"})),
        "first_seen": _sp_first(candidate, {"first_seen", "firstseen", "firstSeen"}),
        "last_seen": _sp_first(candidate, {"last_seen", "lastseen", "lastSeen"}),
        "registrar": _sp_first(candidate, {"registrar"}),
        "nameservers": _sp_list(_sp_first(candidate, {"nameservers", "name_servers", "ns"})),
        "listings": _sp_list(_sp_first(candidate, {"listings", "listed", "feeds"})),
    }

def normalize_silent_push_padns(raw: Any, indicator: str, direction: str, record: str) -> List[Dict[str, Any]]:
    rows = []
    for item in _sp_records(raw):
        rtype = (_sp_text(item.get("type") or item.get("record") or item.get("rrtype") or record) or record).upper()
        query = _sp_text(item.get("query") or item.get("domain") or item.get("host") or item.get("name"))
        value = _sp_text(item.get("value") or item.get("answer") or item.get("rrdata") or item.get("ip") or item.get("target"))
        if not value:
            values = _sp_list(item.get("values") or item.get("answers"))
            value = _sp_text(values[0]) if values else ""
        rows.append({
            "direction": direction,
            "record": rtype,
            "query": query or (indicator if direction == "forward" else ""),
            "value": value or (indicator if direction == "reverse" else ""),
            "first_seen": _sp_text(item.get("first_seen") or item.get("firstseen") or item.get("firstSeen")),
            "last_seen": _sp_text(item.get("last_seen") or item.get("lastseen") or item.get("lastSeen")),
            "count": item.get("count") or item.get("records") or item.get("record_count"),
            "asn": item.get("asn") or item.get("asnum"),
            "asname": _sp_text(item.get("asname") or item.get("asn_name") or item.get("as_org")),
        })
    return [row for row in rows if row["query"] or row["value"]]

def normalize_silent_push_domain_search(raw: Any) -> List[Dict[str, Any]]:
    rows = []
    for item in _sp_records(raw):
        rows.append({
            "domain": _sp_text(item.get("domain") or item.get("host") or item.get("hostname")),
            "asn": item.get("asn") or item.get("asnum"),
            "asname": _sp_text(item.get("asname") or item.get("asn_name")),
            "registrar": _sp_text(item.get("registrar")),
            "first_seen": _sp_text(item.get("first_seen") or item.get("firstseen")),
            "last_seen": _sp_text(item.get("last_seen") or item.get("lastseen")),
            "ip_diversity": item.get("ip_diversity_all") or item.get("ip_diversity"),
            "asn_diversity": item.get("asn_diversity"),
            "timeline": _sp_list(item.get("timeline"))[:10],
        })
    return [row for row in rows if row["domain"] or row["asn"]]

def normalize_silent_push_scan_data(raw: Any) -> List[Dict[str, Any]]:
    rows = []
    for item in _sp_records(raw):
        header = item.get("header") if isinstance(item.get("header"), dict) else {}
        body = item.get("body_analysis") if isinstance(item.get("body_analysis"), dict) else {}
        ssl = item.get("ssl") if isinstance(item.get("ssl"), dict) else {}
        rows.append({
            "datasource": _sp_text(item.get("datasource")),
            "url": _sp_text(item.get("url")),
            "domain": _sp_text(item.get("domain")),
            "subdomain": _sp_text(item.get("subdomain")),
            "ip": _sp_text(item.get("ip")),
            "port": item.get("port"),
            "scheme": _sp_text(item.get("scheme")),
            "response": item.get("response"),
            "scan_date": _sp_text(item.get("scan_date")),
            "title": _sp_text(item.get("htmltitle") or item.get("title")),
            "server": _sp_text(header.get("server") or item.get("server")),
            "favicon_murmur3": _sp_text(item.get("favicon_murmur3") or item.get("favicon2_murmur3")),
            "favicon_md5": _sp_text(item.get("favicon_md5") or item.get("favicon2_md5")),
            "body_sha256": _sp_text(body.get("body_sha256") or body.get("SHV") or item.get("body_sha256")),
            "datahash": _sp_text(item.get("datahash")),
            "ssl_subject": _sp_text(_sp_first(ssl, {"subject", "subject_cn", "organization"})),
            "ssl_issuer": _sp_text(_sp_first(ssl, {"issuer", "issuer_cn"})),
            "ssl_sans": _sp_list(_sp_first(ssl, {"sans", "names"}))[:20],
            "jarm": _sp_text(item.get("jarm") or ssl.get("jarm")),
        })
    return [row for row in rows if any(v not in (None, "", [], {}) for v in row.values())]

def build_silent_push_spql(value: str, query_type: str = "auto") -> str:
    raw = (value or "").strip()
    if not raw or len(raw) > 1000:
        return ""
    lowered = raw.lower()
    if any(marker in lowered for marker in SILENT_PUSH_ACTIVE_MARKERS):
        return ""
    if query_type in {"spql", "silent_push_query"} or (("datasource" in lowered) and re.search(r"\s(=|!=|~=|!~=|>=|<=|>|<)\s", raw)):
        return raw
    escaped = raw.replace("\\", "\\\\").replace('"', '\\"')
    if query_type == "ip" or is_ip(raw):
        return f'ip = "{escaped}" AND datasource = {SILENT_PUSH_SPQL_SOURCES}'
    if query_type == "domain" or is_domain(normalize_domain(raw)):
        domain = normalize_domain(raw)
        return f'domain = "{domain}" AND datasource = {SILENT_PUSH_SPQL_SOURCES}'
    return f'domain = "*{escaped}*" AND datasource = {SILENT_PUSH_SPQL_SOURCES}'

def normalize_silent_push_result(indicator: str, query_type: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {
        "kind": query_type,
        "indicator": indicator,
        "summary": {},
        "enrichment": {},
        "padns_forward": [],
        "padns_reverse": [],
        "domain_search": [],
        "scan_data": [],
        "relationships": [],
    }
    seen_rels = set()

    def add_rel(source: str, relation: str, target: str, target_type: str, evidence: Dict[str, Any] = None) -> None:
        source = _sp_text(source)
        target = _sp_text(target)
        if not source or not target:
            return
        key = (source, relation, target, target_type)
        if key in seen_rels:
            return
        seen_rels.add(key)
        row = {"source": source, "relation": relation, "target": target, "target_type": target_type}
        if evidence:
            row["evidence"] = {k: v for k, v in evidence.items() if v not in (None, "", [], {})}
        normalized["relationships"].append(row)

    if "enrich" in raw_results:
        normalized["enrichment"] = normalize_silent_push_enrichment(raw_results["enrich"], indicator, query_type)
        normalized["summary"] = {k: v for k, v in normalized["enrichment"].items() if v not in (None, "", [], {})}
    if "domaininfo" in raw_results:
        info = _sp_response(raw_results["domaininfo"])
        if isinstance(info, dict):
            normalized["domain_info"] = info
            if not normalized["summary"]:
                normalized["summary"] = normalize_silent_push_enrichment(raw_results["domaininfo"], indicator, query_type)

    for key in ("padns_forward", "padns"):
        if key in raw_results:
            normalized["padns_forward"].extend(normalize_silent_push_padns(raw_results[key], indicator, "forward", "ANY"))
    if "padns_reverse" in raw_results:
        normalized["padns_reverse"].extend(normalize_silent_push_padns(raw_results["padns_reverse"], indicator, "reverse", "A"))
    if "domain_search" in raw_results:
        normalized["domain_search"] = normalize_silent_push_domain_search(raw_results["domain_search"])
    if "scan_data" in raw_results:
        normalized["scan_data"] = normalize_silent_push_scan_data(raw_results["scan_data"])

    for row in normalized["padns_forward"]:
        q, val, rtype = row.get("query"), row.get("value"), row.get("record")
        evidence = {"record": rtype, "first_seen": row.get("first_seen"), "last_seen": row.get("last_seen")}
        if rtype in {"A", "AAAA"}:
            add_rel(q or indicator, "resolves_to", val, "ip", evidence)
        elif rtype == "CNAME":
            add_rel(q or indicator, "aliases_to", val, "domain", evidence)
        elif rtype == "MX":
            add_rel(q or indicator, "uses_mail_server", val, "domain", evidence)
        elif rtype == "NS":
            add_rel(q or indicator, "uses_nameserver", val, "domain", evidence)
    for row in normalized["padns_reverse"]:
        q, val, rtype = row.get("query"), row.get("value"), row.get("record")
        evidence = {"record": rtype, "first_seen": row.get("first_seen"), "last_seen": row.get("last_seen")}
        add_rel(val or indicator, "historically_resolved_by", q or row.get("query"), "domain", evidence)
    for row in normalized["scan_data"]:
        host = row.get("domain") or row.get("url")
        if row.get("ip"):
            add_rel(host, "resolves_to", row["ip"], "ip", {"scan_date": row.get("scan_date"), "datasource": row.get("datasource")})
        if row.get("server"):
            add_rel(host, "observed_with", row["server"], "http_server", {"scan_date": row.get("scan_date")})
        if row.get("favicon_murmur3"):
            add_rel(host, "observed_with", row["favicon_murmur3"], "favicon", {"scan_date": row.get("scan_date")})
        if row.get("ssl_subject"):
            add_rel(host, "presents", row["ssl_subject"], "certificate_subject", {"scan_date": row.get("scan_date")})
    if normalized["summary"].get("asn"):
        asn = str(normalized["summary"]["asn"])
        if not asn.upper().startswith("AS"):
            asn = f"AS{asn}"
        add_rel(indicator, "belongs_to", asn, "asn")

    return normalized

def query_silent_push_padns(indicator: str, api_key: str = "", direction: str = "forward",
                            record: str = "ANY", limit: int = 100) -> Dict[str, Any]:
    direction = (direction or "forward").strip().lower()
    record = (record or "ANY").strip().upper()
    try:
        limit = max(1, min(int(limit or 100), 1000))
    except (TypeError, ValueError):
        limit = 100
    value = (indicator or "").strip()
    if direction == "forward":
        domain = normalize_domain(value)
        if not is_domain(domain) or record not in SILENT_PUSH_PADNS_FORWARD_RECORDS:
            return {"error": "Silent Push forward PADNS requires a valid domain and supported record type"}
        path = f"/api/v1/merge-api/explore/padns/lookup/query/{record.lower()}/{urllib.parse.quote(domain, safe='')}"
        raw = _query_silent_push(path, api_key, "GET", params={"limit": limit}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"])
        issue = _sp_issue("padns_forward", raw)
        if issue:
            return {"error": issue["message"]}
        return {"indicator": domain, "record": record, "direction": direction, "normalized": {"padns": normalize_silent_push_padns(raw, domain, "forward", record)}, "raw": raw}
    normalized_ip = normalize_ip(value)
    if not is_ip(normalized_ip) or record not in SILENT_PUSH_PADNS_REVERSE_RECORDS:
        return {"error": "Silent Push reverse PADNS requires a valid IP/hash value and supported record type"}
    path = f"/api/v1/merge-api/explore/padns/lookup/answer/{record.lower()}/{urllib.parse.quote(normalized_ip, safe='')}"
    raw = _query_silent_push(path, api_key, "GET", params={"limit": limit}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"])
    issue = _sp_issue("padns_reverse", raw)
    if issue:
        return {"error": issue["message"]}
    return {"indicator": normalized_ip, "record": record, "direction": direction, "normalized": {"padns": normalize_silent_push_padns(raw, normalized_ip, "reverse", record)}, "raw": raw}

def query_silent_push_domain_search(pattern: str, api_key: str = "", limit: int = 50) -> Dict[str, Any]:
    value = (pattern or "").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 253:
        return {"error": "Invalid Silent Push domain search pattern"}
    try:
        limit = max(1, min(int(limit or 50), 250))
    except (TypeError, ValueError):
        limit = 50
    raw = _query_silent_push("/api/v1/merge-api/explore/domain/search", api_key, "GET",
                             params={"domain": value, "limit": limit, "timeline": 1, "prefer": "result", "max_wait": 25},
                             cache_ttl=SILENT_PUSH_CACHE_TTL["hit"])
    issue = _sp_issue("domain_search", raw)
    if issue:
        return {"error": issue["message"]}
    return {"query": value, "normalized": {"domain_search": normalize_silent_push_domain_search(raw)}, "raw": raw}

def query_silent_push_scan_data(query: str, api_key: str = "", limit: int = 50, query_type: str = "spql") -> Dict[str, Any]:
    spql = build_silent_push_spql(query, query_type)
    if not spql:
        return {"error": "Invalid or active Silent Push SPQL query"}
    try:
        limit = max(1, min(int(limit or 50), 250))
    except (TypeError, ValueError):
        limit = 50
    raw = _query_silent_push("/api/v1/merge-api/explore/scandata/search/raw", api_key, "POST",
                             params={"limit": limit, "with_metadata": 1}, body={"query": spql},
                             cache_ttl=SILENT_PUSH_CACHE_TTL["hit"])
    issue = _sp_issue("scan_data", raw)
    if issue:
        return {"error": issue["message"]}
    return {"query": spql, "normalized": {"scan_data": normalize_silent_push_scan_data(raw)}, "raw": raw}

def query_silent_push(indicator: str, query_type: str, api_key: str) -> Dict[str, Any]:
    query_type = (query_type or "").strip().lower()
    value = (indicator or "").strip()
    if query_type == "domain":
        value = normalize_domain(value)
        if not is_domain(value):
            return {"error": "Silent Push domain lookup requires a valid domain"}
        encoded = urllib.parse.quote(value, safe="")
        calls = {
            "enrich": lambda: _query_silent_push(f"/api/v1/merge-api/explore/enrich/domain/{encoded}", api_key, "GET", params={"explain": 1}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
            "domaininfo": lambda: _query_silent_push(f"/api/v1/merge-api/explore/domain/domaininfo/{encoded}", api_key, "GET", cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
            "padns_forward": lambda: _query_silent_push(f"/api/v1/merge-api/explore/padns/lookup/query/any/{encoded}", api_key, "GET", params={"limit": 50}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
            "domain_search": lambda: _query_silent_push("/api/v1/merge-api/explore/domain/search", api_key, "GET", params={"domain": f"*.{value}", "limit": 25, "timeline": 1, "prefer": "result", "max_wait": 25}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
            "scan_data": lambda: _query_silent_push("/api/v1/merge-api/explore/scandata/search/raw", api_key, "POST", params={"limit": 25, "with_metadata": 1}, body={"query": build_silent_push_spql(value, "domain")}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
        }
    elif query_type == "ip":
        value = normalize_ip(value)
        if not is_ip(value):
            return {"error": "Silent Push IP lookup requires a valid IPv4 or IPv6 address"}
        ip_family = "ipv6" if get_ip_version(value) == 6 else "ipv4"
        answer_type = "aaaa" if ip_family == "ipv6" else "a"
        encoded = urllib.parse.quote(value, safe="")
        calls = {
            "enrich": lambda: _query_silent_push(f"/api/v1/merge-api/explore/enrich/{ip_family}/{encoded}", api_key, "GET", params={"explain": 1}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
            "padns_reverse": lambda: _query_silent_push(f"/api/v1/merge-api/explore/padns/lookup/answer/{answer_type}/{encoded}", api_key, "GET", params={"limit": 50}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
            "scan_data": lambda: _query_silent_push("/api/v1/merge-api/explore/scandata/search/raw", api_key, "POST", params={"limit": 25, "with_metadata": 1}, body={"query": build_silent_push_spql(value, "ip")}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
        }
    elif query_type in {"keyword", "infra", "spql", "silent_push_query"}:
        if not value or "\n" in value or "\r" in value:
            return {"error": "Invalid Silent Push infrastructure query"}
        pattern = value if "*" in value else f"*{value}*"
        spql = build_silent_push_spql(value, "spql" if query_type in {"spql", "silent_push_query"} else "keyword")
        calls = {
            "domain_search": lambda: _query_silent_push("/api/v1/merge-api/explore/domain/search", api_key, "GET", params={"domain": pattern[:253], "limit": 25, "timeline": 1, "prefer": "result", "max_wait": 25}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
            "scan_data": lambda: _query_silent_push("/api/v1/merge-api/explore/scandata/search/raw", api_key, "POST", params={"limit": 25, "with_metadata": 1}, body={"query": spql}, cache_ttl=SILENT_PUSH_CACHE_TTL["hit"]),
        }
    else:
        return {"error": "Invalid Silent Push query type"}

    raw_results = _collect_callables(calls, max_workers=min(5, len(calls)))
    issues = [issue for name, raw in raw_results.items() for issue in [_sp_issue(name, raw)] if issue]
    normalized = normalize_silent_push_result(value, query_type, raw_results)
    has_findings = any(
        normalized.get(key) for key in ("summary", "padns_forward", "padns_reverse", "domain_search", "scan_data", "relationships")
    )
    return {
        "indicator": value,
        "query_type": query_type,
        "normalized": normalized,
        "provider_errors": issues,
        "data": {name: raw for name, raw in raw_results.items() if not _sp_issue(name, raw)},
        "empty": not has_findings,
    }

# ---------------------------------------------------------------------------
# Validin: passive DNS & infrastructure intelligence.
#
# Every endpoint below was verified against the official OpenAPI reference
# (https://docs.validin.com, Apr-Jun 2026): base https://app.validin.com,
# Bearer auth, GET paths under /api/axon/{domain,ip,string,hash}/... and
# /api/threat/{names,group/...}. Standard params: limit (1-20000),
# annotate={tags,popularity,intel}, time_format={unix,iso}, exclude_nx,
# wildcard, lookback, first_seen/last_seen.
#
# PASSIVE-ONLY: only documented read/search/pivot endpoints over already
# collected data are reachable. Live Scan, domain submissions, projects,
# alerts, YARA, live WHOIS/RDAP and any other active/mutating endpoint are
# intentionally absent. Unknown indicators simply return no data; nothing
# here can trigger collection against a target.
# ---------------------------------------------------------------------------
VALIDIN_BASE = "https://app.validin.com"

# Explicit semantic allowlist: (GET-only) full path patterns MANTIS may call.
# Anything not matching is rejected before any HTTP is issued, so no generic
# proxying is possible even if a caller passes a crafted value.
VALIDIN_ALLOWED_PATHS = [
    r"^/api/axon/domain/reputation/quick/[^/]+$",
    r"^/api/axon/domain/osint/history/[^/]+$",
    r"^/api/axon/domain/dns/history/[^/]+$",
    r"^/api/axon/domain/dns/extra/[^/]+$",
    r"^/api/axon/domain/subdomains/[^/]+$",
    r"^/api/axon/domain/certificates/[^/]+$",
    r"^/api/axon/domain/crawl/history/[^/]+$",
    r"^/api/axon/domain/pivots/[^/]+$",
    r"^/api/axon/domain/pivots/[^/]+/[A-Z_]+$",
    r"^/api/axon/domain/registration/history/[^/]+$",
    r"^/api/axon/ip/reputation/quick/[^/]+$",
    r"^/api/axon/ip/osint/history/[^/]+$",
    r"^/api/axon/ip/dns/history/[^/]+$",
    r"^/api/axon/ip/dns/history/[^/]+/\d{1,3}$",
    r"^/api/axon/ip/dns/hostname/[^/]+$",
    r"^/api/axon/ip/dns/extra/[^/]+$",
    r"^/api/axon/ip/pivots/[^/]+$",
    r"^/api/axon/ip/pivots/[^/]+/[A-Z_0-9]+$",
    r"^/api/axon/ip/pivots/[^/]+/\d{1,3}$",
    r"^/api/axon/ip/crawl/history/[^/]+$",
    r"^/api/axon/hash/pivots/[^/]+$",
    r"^/api/axon/hash/pivots/[^/]+/[A-Z_0-9]+$",
    r"^/api/axon/hash/crawl/history/[^/]+$",
    r"^/api/axon/string/pivots2/[A-Z_]+$",
    r"^/api/axon/advanced/query$",
    r"^/api/threat/names$",
    r"^/api/threat/group/[^/]+/summary$",
    r"^/api/threat/group/[^/]+/indicators$",
]
_VALIDIN_ALLOWED_RE = [re.compile(p) for p in VALIDIN_ALLOWED_PATHS]

# Pivot categories verified in the API reference (category path segments are
# validated against these; unknown categories are rejected).
VALIDIN_DOMAIN_PIVOT_CATEGORIES = {
    "ANCHORS_LINKS", "CERT_DOMAIN", "IFRAMES_LINKS", "JS_LINKS",
    "LINKS_LINKS", "LOCATION_DOMAIN", "META_LINKS",
}
VALIDIN_IP_PIVOT_CATEGORIES = {"LOCATION_IP4"}
VALIDIN_HASH_PIVOT_CATEGORIES = {
    "BANNER_0_HASH", "BODY_SHA1", "CERT_FINGERPRINT", "CERT_FINGERPRINT_SHA256",
    "CLASS_0_HASH", "CLASS_1_HASH", "FAVICON_HASH", "HEADER_HASH",
}
VALIDIN_STRING_PIVOT_CATEGORIES = {
    "BANNER", "CERT_CN", "CERT_DC", "CERT_DNQUALIFIER", "CERT_EMAILADDRESS",
    "CERT_INITIALS", "CERT_ISSUER", "CERT_L", "CERT_NAME", "CERT_NOT_AFTER",
    "CERT_NOT_BEFORE", "CERT_O", "CERT_ORGANIZATIONIDENTIFIER", "CERT_OU",
    "CERT_POSTALCODE", "CERT_SERIALNUMBER", "CERT_SN", "CERT_ST",
    "CERT_STREET", "CERT_SUBJECTALTNAME", "ETAG", "GTAG_ID", "HTTP_DATE",
    "JARM", "LAST_MODIFIED", "LOCATION", "META", "ONION_LOCATION", "PATH",
    "SERVER", "TITLE", "WAYWARD_CERT_DOMAIN",
}
# Infra-search fingerprint kinds (NOT malware file hashes).
VALIDIN_FINGERPRINT_KINDS = {"fingerprint", "cert_hash", "jarm", "header_hash"}
_VALIDIN_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")

# Conservative summary limits (history-heavy retrieval stays lazy).
VALIDIN_SUMMARY_LIMITS = {
    "reputation": 1, "osint": 25, "dns": 100, "extra": 100, "subdomains": 100,
    "certificates": 25, "crawl": 25, "pivots": 50, "hostname": 50,
}
VALIDIN_LAZY_LIMITS = {"default": 1000, "max": 5000}

VALIDIN_CACHE: Dict[str, Any] = {}
VALIDIN_CACHE_TTL = {"hit": 21600, "reputation": 3600, "error": 120}


def _validin_cache_key(path: str, params: Dict[str, Any], api_key: str) -> str:
    # Key fingerprint isolates per-account entitlements on shared deployments.
    fp = hashlib.sha256((api_key or "").encode("utf-8")).hexdigest()[:12]
    normalized = "&".join(f"{k}={params.get(k)}" for k in sorted(params or {}))
    return f"{path}?{normalized}#{fp}"


def _validin_cache_get(key: str) -> Any:
    entry = VALIDIN_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            VALIDIN_CACHE.pop(key, None)
            return None
        return value
    except Exception:
        return None


def _validin_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        VALIDIN_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass


def _validin_path_allowed(path: str) -> bool:
    candidate = (path or "").split("?", 1)[0]
    return any(rx.match(candidate) for rx in _VALIDIN_ALLOWED_RE)


def _looks_like_domain(value: str) -> bool:
    s = str(value or "").strip().lower().rstrip(".")
    return bool(s) and "." in s and " " not in s and "/" not in s \
        and re.fullmatch(r"[a-z0-9_.-]+", s) is not None


def _looks_like_ip(value: str) -> bool:
    s = str(value or "").strip()
    return bool(s) and re.fullmatch(r"[0-9a-fA-F.:]+", s) is not None and ("." in s or ":" in s)


def _validin_issue(status_code: int, body: Any) -> Dict[str, Any]:
    """Classify provider failures (auth / plan / quota / outage)."""
    text = ""
    try:
        if isinstance(body, dict):
            text = str(body.get("message") or body.get("error") or "")[:300]
        elif body is not None:
            text = str(body)[:300]
    except Exception:
        text = ""
    if status_code == 401:
        return {"error": "Invalid Validin API key", "auth_error": True}
    if status_code == 403:
        return {"error": "Validin plan restriction: this endpoint or data is not included in the configured account tier",
                "plan_restricted": True, "detail": text}
    if status_code == 429:
        return {"error": "Validin API quota exceeded for the configured account (plan rate limits apply)",
                "quota_exceeded": True, "detail": text}
    if status_code == 404:
        return {"error": "Not found in Validin"}
    return {"error": f"Validin provider error (HTTP {status_code})", "detail": text}


def _validin_get(path: str, api_key: str, params: Dict[str, Any] = None,
                 cache_ttl: int = None) -> Dict[str, Any]:
    """Single allowlisted Validin GET with caching. Never raises."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    if not _validin_path_allowed(path):
        return {"error": "Blocked: not a passive allowlisted Validin endpoint"}
    params = dict(params or {})
    cache_ttl = VALIDIN_CACHE_TTL["hit"] if cache_ttl is None else cache_ttl
    cache_key = _validin_cache_key(path, params, api_key)
    cached = _validin_cache_get(cache_key)
    if cached is not None:
        return cached
    headers = {"Authorization": f"Bearer {api_key.strip()}"}
    try:
        resp = requests.get(f"{VALIDIN_BASE}{path}", headers=headers,
                            params=params, timeout=20)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                data = {"error": "Validin returned non-JSON data"}
            _validin_cache_set(cache_key, data, cache_ttl)
            return data
        # Failures (auth/plan/quota/outage) are never cached: the next
        # explicit lookup must re-evaluate account state.
        return _validin_issue(resp.status_code, resp.text)
    except Exception as e:
        return {"error": "Validin query failed", "message": str(e)[:300]}


def query_validin(url: str, api_key: str) -> Dict[str, Any]:
    """Legacy entry point, now constrained by the passive allowlist."""
    if not api_key:
        return {"error": "No Validin API Key provided"}
    try:
        parsed = urllib.parse.urlparse(url or "")
        if parsed.netloc.lower() != "app.validin.com":
            return {"error": "Blocked: not a passive allowlisted Validin endpoint"}
        params = dict(urllib.parse.parse_qsl(parsed.query or "", keep_blank_values=True))
        return _validin_get(parsed.path or "/", api_key, params)
    except Exception as e:
        return {"error": "Validin query failed", "message": str(e)[:300]}


def _validin_ts(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value or "")


_VALIDIN_RELATIONSHIP = {
    "A": "resolves_to", "AAAA": "resolves_to",
    "CNAME": "aliases_to", "CNAME_FOR": "aliased_by",
    "NS": "uses_nameserver", "NS_FOR": "nameserver_for",
    "MX": "mail_server", "MX_FOR": "mail_server_for",
    "SOA_MNAME": "soa_nameserver", "SOA_MNAME_FOR": "soa_nameserver_for",
    "SOA_RNAME": "soa_contact", "SOA_RNAME_FOR": "soa_contact_for",
    "SRV": "service_target", "SRV_TARGET_FOR": "service_target_for",
    "HTTPS": "https_record", "TXT": "text_record",
    "CAA": "caa_record", "PTR": "reverse_dns",
    "CERT": "presents", "CERT_DOMAIN": "presents",
    "CERT_FINGERPRINT": "presents", "CERT_FINGERPRINT_SHA256": "presents",
}


def _normalize_validin_records(payload: Any, source: str = "") -> Dict[str, Any]:
    """Tolerant normalization of standard Validin record responses."""
    def iter_entries(value: Any, default_type: str = ""):
        if isinstance(value, dict):
            records = value.get("records", value.get("data", value.get("results", value.get("items", value))))
            if isinstance(records, dict):
                yielded = False
                for rtype, entries in records.items():
                    if isinstance(entries, list):
                        yielded = True
                        for entry in entries:
                            yield str(rtype), entry
                if yielded:
                    return
            if isinstance(records, list):
                for entry in records:
                    yield default_type, entry
                return
            for key in ("subdomains", "domains", "hostnames", "ips", "certificates", "http_observations"):
                if isinstance(value.get(key), list):
                    for entry in value[key]:
                        yield key, entry
        elif isinstance(value, list):
            for entry in value:
                yield default_type, entry

    dns, certificates, http_obs, threat = [], [], [], []
    ips, domains, hostnames = set(), set(), set()
    first_seen_all, last_seen_all = [], []
    for rtype, entry in iter_entries(payload):
        if isinstance(entry, str):
            entry = {"value": entry}
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("key") or entry.get("name") or entry.get("hostname") or entry.get("domain") or entry.get("host") or source or "")
        value = str(
            entry.get("value")
            or entry.get("ip")
            or entry.get("address")
            or entry.get("target")
            or entry.get("domain")
            or entry.get("hostname")
            or entry.get("name")
            or ""
        )
        vtype = str(entry.get("value_type") or entry.get("type") or entry.get("record_type") or "")
        if not rtype:
            rtype = vtype or str(entry.get("record_type") or entry.get("type") or "")
        if not key and value:
            key = source
        if not value and key and key != source:
            value = key
        first = entry.get("first_seen", entry.get("firstSeen", ""))
        last = entry.get("last_seen", entry.get("lastSeen", ""))
        if isinstance(first, int):
            first_seen_all.append(first)
        if isinstance(last, int):
            last_seen_all.append(last)
        row = {"type": str(rtype), "key": key, "value": value,
               "value_type": vtype,
               "first_seen": first, "last_seen": last,
               "first_seen_iso": _validin_ts(first) if isinstance(first, int) else str(first or ""),
               "last_seen_iso": _validin_ts(last) if isinstance(last, int) else str(last or "")}
        upper = str(rtype).upper()
        vtype_lower = vtype.lower()
        if upper in ("A", "AAAA", "IPS") or vtype_lower in ("ip4", "ip6", "ip"):
            if value:
                ips.add(value)
            if _looks_like_domain(key):
                domains.add(key.rstrip(".").lower())
        if vtype_lower == "dom" or upper in ("SUBDOMAINS", "DOMAINS", "HOSTNAMES", "NS", "NS_FOR", "MX", "MX_FOR", "CNAME", "CNAME_FOR",
                                             "SOA_MNAME", "SOA_MNAME_FOR", "SRV_TARGET_FOR",
                                             "CAA_ISSUER_FOR", "CERT_DOMAIN"):
            for candidate in (key, value):
                if candidate and "." in candidate and " " not in candidate:
                    (hostnames if upper in ("SUBDOMAINS", "HOSTNAMES", "NS", "NS_FOR", "MX", "MX_FOR", "SOA_MNAME") else domains).add(candidate.rstrip(".").lower())
        if _looks_like_ip(key):
            ips.add(key)
        if _looks_like_ip(value):
            ips.add(value)
        if upper.startswith("CERT") or "CERT" in upper:
            certificates.append(row)
        elif upper in ("CRAWL", "HTTP", "HOST", "HTTP_OBSERVATIONS", "CRAWL-HISTORY", "CRAWL_HISTORY"):
            http_obs.append(row)
        elif upper in ("THREAT", "INTEL", "REPUTATION"):
            threat.append(row)
        else:
            dns.append(row)
    relationships = []
    for row in dns + certificates + http_obs:
        rel = _VALIDIN_RELATIONSHIP.get(str(row["type"]).upper(), "associated_with")
        relationships.append({"source": row["key"] or source, "relation": rel,
                              "target": row["value"], "target_type": row["value_type"],
                              "first_seen": row["first_seen"], "last_seen": row["last_seen"]})
    def _iso(ts_list, fn):
        try:
            return _validin_ts(fn(ts_list)) if ts_list else ""
        except Exception:
            return ""
    return {
        "summary": {
            "record_types": sorted({str(r["type"]) for r in dns + certificates + http_obs + threat}),
            "dns_records": len(dns),
            "ips": sorted(ips),
            "domains": sorted(domains),
            "hostnames": sorted(hostnames),
            "certificates": len(certificates),
            "http_observations": len(http_obs),
            "first_seen": min(first_seen_all) if first_seen_all else "",
            "last_seen": max(last_seen_all) if last_seen_all else "",
            "first_seen_iso": _iso(first_seen_all, min),
            "last_seen_iso": _iso(last_seen_all, max),
        },
        "dns": dns,
        "relationships": relationships,
        "certificates": certificates,
        "http_observations": http_obs,
        "threat_context": threat,
    }


def _validin_has_error(result: Any) -> bool:
    return isinstance(result, dict) and bool(result.get("error"))


def _validin_plan_restricted(results: Dict[str, Any]) -> bool:
    try:
        return any(isinstance(v, dict) and v.get("plan_restricted") for v in results.values())
    except Exception:
        return False


def _validin_result(indicator: str, kind: str, results: Dict[str, Any],
                    normalized: Dict[str, Any]) -> Dict[str, Any]:
    issues = []
    for name, raw in results.items():
        if _validin_has_error(raw):
            flag = "plan" if raw.get("plan_restricted") else ("quota" if raw.get("quota_exceeded") else "error")
            issues.append({"section": name, "kind": flag,
                           "message": str(raw.get("error", "failed"))[:300]})
    has_findings = bool(normalized.get("dns") or normalized.get("certificates")
                        or normalized.get("http_observations") or normalized.get("threat_context")
                        or (normalized.get("summary") or {}).get("ips")
                        or (normalized.get("summary") or {}).get("domains"))
    return {
        "indicator": indicator,
        "kind": kind,
        "provider": "Validin",
        "passive_only": True,
        "normalized": normalized,
        "provider_errors": issues,
        "plan_restricted": _validin_plan_restricted(results),
        "limited": any(isinstance(v, dict) and v.get("limited") for v in results.values()),
        "data": {name: raw for name, raw in results.items() if not _validin_has_error(raw)},
        "empty": not has_findings and not issues,
        "semantics": ("Found in Validin means observed infrastructure, not malicious. "
                      "Not found means no indexed data, not benign. Historical observations "
                      "describe past state, not current state."),
    }


def _validin_std_params(limit: int, annotate: bool = True) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": max(1, min(int(limit), 20000)),
                              "time_format": "iso"}
    if annotate:
        params["annotate"] = "intel"
    return params


def query_validin_domain(domain: str, api_key: str) -> Dict[str, Any]:
    """Domain summary: reputation + recent DNS/infra. History stays lazy."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    domain = normalize_domain(domain or "")
    if not is_domain(domain):
        return {"error": "Invalid domain for Validin lookup"}
    encoded = urllib.parse.quote(domain, safe="")
    calls = {
        "reputation": lambda: _validin_get(
            f"/api/axon/domain/reputation/quick/{encoded}", api_key, {},
            cache_ttl=VALIDIN_CACHE_TTL["reputation"]),
        "osint_history": lambda: _validin_get(
            f"/api/axon/domain/osint/history/{encoded}", api_key,
            {**_validin_std_params(25), "wildcard": "true"}),
        "dns_history": lambda: _validin_get(
            f"/api/axon/domain/dns/history/{encoded}", api_key,
            {**_validin_std_params(100), "exclude_nx": "true"}),
        "dns_extra": lambda: _validin_get(
            f"/api/axon/domain/dns/extra/{encoded}", api_key, _validin_std_params(100)),
        "subdomains": lambda: _validin_get(
            f"/api/axon/domain/subdomains/{encoded}", api_key, _validin_std_params(100)),
        "certificates": lambda: _validin_get(
            f"/api/axon/domain/certificates/{encoded}", api_key, _validin_std_params(25)),
        "crawl_history": lambda: _validin_get(
            f"/api/axon/domain/crawl/history/{encoded}", api_key, _validin_std_params(25)),
        "pivots": lambda: _validin_get(
            f"/api/axon/domain/pivots/{encoded}", api_key, _validin_std_params(50)),
    }
    results = _collect_callables(calls, max_workers=8)
    normalized: Dict[str, Any] = {"summary": {}, "dns": [], "relationships": [],
                                  "certificates": [], "http_observations": [],
                                  "threat_context": [], "reputation": {}}
    for name in ("dns_history", "dns_extra", "subdomains", "certificates",
                 "crawl_history", "pivots", "osint_history"):
        raw = results.get(name)
        if _validin_has_error(raw):
            continue
        part = _normalize_validin_records(raw, domain)
        for key in ("dns", "relationships", "certificates", "http_observations", "threat_context"):
            normalized[key].extend(part[key])
        merged_summary = dict(part["summary"])
        for key in ("ips", "domains", "hostnames"):
            merged_summary[key] = sorted(set(normalized["summary"].get(key, [])) | set(part["summary"].get(key, [])))
        for key in ("dns_records", "certificates", "http_observations"):
            merged_summary[key] = normalized["summary"].get(key, 0) + part["summary"].get(key, 0)
        for key in ("first_seen", "last_seen", "first_seen_iso", "last_seen_iso", "record_types"):
            if not normalized["summary"].get(key) and part["summary"].get(key):
                merged_summary[key] = part["summary"][key]
        normalized["summary"] = merged_summary
    rep = results.get("reputation")
    if not _validin_has_error(rep):
        normalized["reputation"] = rep if isinstance(rep, dict) else {"result": rep}
    normalized["summary"]["domains"] = sorted(set(normalized["summary"].get("domains", [])) | {domain})
    normalized["lazy_available"] = ["dns-history", "certificates", "pivots",
                                    "crawl-history", "registration-history", "subdomains"]
    return _validin_result(domain, "domain", results, normalized)


def query_validin_ip(ip: str, api_key: str) -> Dict[str, Any]:
    """IP summary: reputation + associated infra. History stays lazy."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    ip = normalize_ip(ip or "")
    if not is_ip(ip):
        return {"error": "Invalid IP address for Validin lookup"}
    encoded = urllib.parse.quote(ip, safe="")
    calls = {
        "reputation": lambda: _validin_get(
            f"/api/axon/ip/reputation/quick/{encoded}", api_key, {},
            cache_ttl=VALIDIN_CACHE_TTL["reputation"]),
        "osint_history": lambda: _validin_get(
            f"/api/axon/ip/osint/history/{encoded}", api_key, _validin_std_params(25)),
        "dns_history": lambda: _validin_get(
            f"/api/axon/ip/dns/history/{encoded}", api_key, _validin_std_params(100)),
        "dns_extra": lambda: _validin_get(
            f"/api/axon/ip/dns/extra/{encoded}", api_key, _validin_std_params(50)),
        "ptr": lambda: _validin_get(
            f"/api/axon/ip/dns/hostname/{encoded}", api_key, _validin_std_params(50)),
        "pivots": lambda: _validin_get(
            f"/api/axon/ip/pivots/{encoded}", api_key, _validin_std_params(50)),
        "crawl_history": lambda: _validin_get(
            f"/api/axon/ip/crawl/history/{encoded}", api_key, _validin_std_params(25)),
    }
    results = _collect_callables(calls, max_workers=7)
    normalized: Dict[str, Any] = {"summary": {}, "dns": [], "relationships": [],
                                  "certificates": [], "http_observations": [],
                                  "threat_context": [], "reputation": {}, "ptr": []}
    for name in ("dns_history", "dns_extra", "ptr", "pivots", "crawl_history", "osint_history"):
        raw = results.get(name)
        if _validin_has_error(raw):
            continue
        part = _normalize_validin_records(raw, ip)
        for key in ("dns", "relationships", "certificates", "http_observations", "threat_context"):
            normalized[key].extend(part[key])
        merged_summary = dict(part["summary"])
        for key in ("ips", "domains", "hostnames"):
            merged_summary[key] = sorted(set(normalized["summary"].get(key, [])) | set(part["summary"].get(key, [])))
        for key in ("dns_records", "certificates", "http_observations"):
            merged_summary[key] = normalized["summary"].get(key, 0) + part["summary"].get(key, 0)
        for key in ("first_seen", "last_seen", "first_seen_iso", "last_seen_iso", "record_types"):
            if not normalized["summary"].get(key) and part["summary"].get(key):
                merged_summary[key] = part["summary"][key]
        normalized["summary"] = merged_summary
        if name == "ptr":
            normalized["ptr"] = [{"hostname": r["value"], "first_seen": r["first_seen"],
                                  "last_seen": r["last_seen"]} for r in part["dns"]]
    rep = results.get("reputation")
    if not _validin_has_error(rep):
        normalized["reputation"] = rep if isinstance(rep, dict) else {"result": rep}
    normalized["summary"]["ips"] = sorted(set(normalized["summary"].get("ips", [])) | {ip})
    normalized["lazy_available"] = ["dns-history", "pivots", "crawl-history",
                                    "dns-extra", "ptr"]
    return _validin_result(ip, "ip", results, normalized)


def _parse_validin_cidr(value: str):
    """Split explicit CIDR notation into (ip, prefix). Rejects bare IPs."""
    raw = (value or "").strip()
    if "/" not in raw:
        return None, "Validin CIDR lookup requires explicit CIDR notation (e.g. 192.0.2.0/24)"
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None, "Invalid CIDR for Validin lookup"
    prefix = net.prefixlen
    if not 8 <= prefix <= 128:
        return None, "Validin CIDR prefix must be between 8 and 128"
    if isinstance(net, ipaddress.IPv4Network) and prefix > 32:
        return None, "Invalid IPv4 CIDR prefix"
    return str(net.network_address), prefix


def query_validin_cidr(cidr: str, api_key: str, limit: int = 100) -> Dict[str, Any]:
    """Passive CIDR enrichment (verified /{ip}/{prefix} template)."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    ip, prefix = _parse_validin_cidr(cidr)
    if ip is None:
        return {"error": prefix}
    try:
        limit = max(1, min(int(limit or 100), 5000))
    except (TypeError, ValueError):
        limit = 100
    base = f"/api/axon/ip/dns/history/{urllib.parse.quote(ip, safe='')}/{prefix}"
    pivot_base = f"/api/axon/ip/pivots/{urllib.parse.quote(ip, safe='')}/{prefix}"
    calls = {
        "dns_history": lambda: _validin_get(base, api_key, _validin_std_params(limit)),
        "pivots": lambda: _validin_get(pivot_base, api_key, _validin_std_params(min(limit, 500))),
    }
    results = _collect_callables(calls, max_workers=2)
    normalized: Dict[str, Any] = {"summary": {}, "dns": [], "relationships": [],
                                  "certificates": [], "http_observations": [],
                                  "threat_context": [], "cidr": f"{ip}/{prefix}"}
    for name in ("dns_history", "pivots"):
        raw = results.get(name)
        if _validin_has_error(raw):
            continue
        part = _normalize_validin_records(raw, f"{ip}/{prefix}")
        for key in ("dns", "relationships", "certificates", "http_observations", "threat_context"):
            normalized[key].extend(part[key])
        merged = dict(part["summary"])
        for key in ("ips", "domains", "hostnames"):
            merged[key] = sorted(set(normalized["summary"].get(key, [])) | set(part["summary"].get(key, [])))
        normalized["summary"] = merged
    return _validin_result(f"{ip}/{prefix}", "cidr", results, normalized)


def _validate_fingerprint(value: str, kind: str):
    """Validate infrastructure fingerprint/hash values (never file hashes)."""
    raw = (value or "").strip().lower()
    if kind == "jarm":
        if re.fullmatch(r"[0-9a-f]{62}", raw):
            return raw, ""
        return "", "Invalid JARM fingerprint (expected 62 hex characters)"
    if kind == "cert_hash":
        if _VALIDIN_HEX_RE.match(raw or "") and len(raw) in (40, 64):
            return raw, ""
        return "", "Invalid certificate hash (expected SHA-1/40 or SHA-256/64 hex)"
    if kind == "header_hash":
        if _VALIDIN_HEX_RE.match(raw or "") and len(raw) in (32, 40, 64):
            return raw, ""
        return "", "Invalid header hash (expected 32/40/64 hex characters)"
    # Generic infrastructure fingerprint: constrained hex lengths only.
    if _VALIDIN_HEX_RE.match(raw or "") and len(raw) in (32, 40, 62, 64):
        return raw, ""
    return "", "Invalid infrastructure fingerprint (expected 32/40/62/64 hex characters)"


def query_validin_fingerprint(value: str, kind: str, api_key: str,
                              limit: int = 100) -> Dict[str, Any]:
    """Infrastructure fingerprint pivots. NEVER used for malware file hashes."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    kind = (kind or "fingerprint").strip().lower()
    if kind not in VALIDIN_FINGERPRINT_KINDS:
        return {"error": f"Unknown Validin fingerprint kind: {kind}"}
    clean, problem = _validate_fingerprint(value, kind)
    if problem:
        return {"error": problem}
    try:
        limit = max(1, min(int(limit or 100), 1000))
    except (TypeError, ValueError):
        limit = 100
    encoded = urllib.parse.quote(clean, safe="")
    if kind == "jarm":
        calls = {"jarm_pivots": lambda: _validin_get(
            "/api/axon/string/pivots2/JARM", api_key,
            {**_validin_std_params(limit), "string": clean})}
    elif kind == "cert_hash":
        category = "CERT_FINGERPRINT_SHA256" if len(clean) == 64 else "CERT_FINGERPRINT"
        calls = {f"pivots_{category.lower()}": (lambda category=category: _validin_get(
            f"/api/axon/hash/pivots/{encoded}/{category}", api_key,
            _validin_std_params(limit)))}
    elif kind == "header_hash":
        calls = {"pivots_header_hash": lambda: _validin_get(
            f"/api/axon/hash/pivots/{encoded}/HEADER_HASH", api_key,
            _validin_std_params(limit))}
    else:
        calls = {"pivots": lambda: _validin_get(
            f"/api/axon/hash/pivots/{encoded}", api_key,
            {**_validin_std_params(limit), "annotate": "intel"})}
    results = _collect_callables(calls, max_workers=len(calls))
    normalized: Dict[str, Any] = {"summary": {}, "dns": [], "relationships": [],
                                  "certificates": [], "http_observations": [],
                                  "threat_context": [], "fingerprint": clean, "kind": kind,
                                  "infrastructure_note": ("Infrastructure fingerprint pivot: shared values are "
                                                          "correlation evidence, not proof of common ownership, "
                                                          "and never a malware verdict.")}
    for name, raw in results.items():
        if _validin_has_error(raw):
            continue
        part = _normalize_validin_records(raw, clean)
        for key in ("dns", "relationships", "certificates", "http_observations", "threat_context"):
            normalized[key].extend(part[key])
    return _validin_result(clean, f"fingerprint:{kind}", results, normalized)


def query_validin_threat(kind: str, value: str, api_key: str) -> Dict[str, Any]:
    """Threat profile lookups (verified /api/threat/* paths only)."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    kind = (kind or "").strip().lower()
    if kind == "names":
        raw = _validin_get("/api/threat/names", api_key, {}, cache_ttl=86400)
        if _validin_has_error(raw):
            return _validin_result("", "threat:names", {"names": raw},
                                   {"summary": {}, "dns": [], "relationships": [],
                                    "certificates": [], "http_observations": [],
                                    "threat_context": [], "threat_names": []})
        names = raw.get("names", raw.get("threats", raw if isinstance(raw, list) else []))
        if not isinstance(names, list):
            names = []
        return _validin_result("", "threat:names", {"names": raw},
                               {"summary": {"threat_names": len(names)}, "dns": [],
                                "relationships": [], "certificates": [],
                                "http_observations": [], "threat_context": [],
                                "threat_names": names[:500]})
    if kind not in ("group", "indicators"):
        return {"error": f"Unknown Validin threat lookup: {kind}"}
    threat_key = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,128}", threat_key):
        return {"error": "Invalid Validin threat key"}
    encoded = urllib.parse.quote(threat_key, safe="")
    if kind == "group":
        raw = _validin_get(f"/api/threat/group/{encoded}/summary", api_key, {})
    else:
        raw = _validin_get(f"/api/threat/group/{encoded}/indicators", api_key,
                           _validin_std_params(500))
    if _validin_has_error(raw):
        return _validin_result(threat_key, f"threat:{kind}", {kind: raw},
                               {"summary": {}, "dns": [], "relationships": [],
                                "certificates": [], "http_observations": [],
                                "threat_context": []})
    return _validin_result(threat_key, f"threat:{kind}", {kind: raw},
                           {"summary": {"threat_key": threat_key}, "dns": [],
                            "relationships": [], "certificates": [],
                            "http_observations": [], "threat_context": [raw],
                            "threat_detail": raw})


def _detect_validin_fingerprint_kind(value: str) -> str:
    """Infer an infrastructure fingerprint kind from analyst-typed hex.

    Only used for Infra Search input (never malware Hash Lookup): 62-hex is
    JARM-shaped, 40/64-hex may be certificate hashes. Returns "" otherwise.
    """
    raw = (value or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{62}", raw or ""):
        return "jarm"
    if _VALIDIN_HEX_RE.match(raw or "") and len(raw) in (32, 40, 64):
        return "fingerprint"
    return ""


def query_validin_infra(value: str, query_type: str, api_key: str) -> Dict[str, Any]:
    """Typed Infra Search dispatcher (explicit types only, no generic proxy)."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    qtype = (query_type or "").strip().lower().removeprefix("validin_")
    raw = (value or "").strip()
    if qtype in ("ip",):
        ip = normalize_ip(raw)
        if not is_ip(ip):
            return {"error": "Invalid IP for Validin Infra Search"}
        return query_validin_ip(ip, api_key)
    if qtype in ("domain",):
        domain = normalize_domain(raw)
        if not is_domain(domain):
            return {"error": "Invalid domain for Validin Infra Search"}
        return query_validin_domain(domain, api_key)
    if qtype in ("cidr",):
        return query_validin_cidr(raw, api_key)
    if qtype in ("wildcard",):
        domain = normalize_domain(raw.lstrip("*."))
        if not is_domain(domain):
            return {"error": "Invalid wildcard domain for Validin Infra Search"}
        encoded = urllib.parse.quote(domain, safe="")
        results = {
            "dns_history": _validin_get(
                f"/api/axon/domain/dns/history/{encoded}", api_key,
                {**_validin_std_params(200), "wildcard": "true", "exclude_nx": "true"}),
            "certificates": _validin_get(
                f"/api/axon/domain/certificates/{encoded}", api_key,
                {**_validin_std_params(100), "wildcard": "true"}),
            "subdomains": _validin_get(
                f"/api/axon/domain/subdomains/{encoded}", api_key,
                _validin_std_params(200)),
        }
        normalized: Dict[str, Any] = {"summary": {}, "dns": [], "relationships": [],
                                      "certificates": [], "http_observations": [],
                                      "threat_context": []}
        for name, r in results.items():
            if _validin_has_error(r):
                continue
            part = _normalize_validin_records(r, domain)
            for key in ("dns", "relationships", "certificates", "http_observations", "threat_context"):
                normalized[key].extend(part[key])
        return _validin_result(domain, "wildcard", results, normalized)
    if qtype in VALIDIN_FINGERPRINT_KINDS:
        return query_validin_fingerprint(raw, qtype, api_key)
    return {"error": f"Unknown Validin Infra Search type: {query_type}"}


def query_validin_lazy(kind: str, indicator: str, api_key: str, value: str = "",
                       limit: int = 1000, query_type: str = "") -> Dict[str, Any]:
    """Explicit lazy retrieval (history-heavy sections only)."""
    if not (api_key or "").strip():
        return {"error": "No Validin API Key provided"}
    kind = (kind or "").strip().lower()
    try:
        limit = max(1, min(int(limit or 1000), 20000))
    except (TypeError, ValueError):
        limit = 1000

    if kind == "advanced":
        # Enterprise-only best effort; plan errors surface cleanly.
        if not (value or "").strip():
            return {"error": "Advanced query text is required"}
        raw = _validin_get("/api/axon/advanced/query", api_key,
                           {"query_string": (value or "").strip()[:500], "limit": min(limit, 100)})
        return _validin_result(value, "advanced", {"advanced": raw},
                               {**_normalize_validin_records(raw, value),
                                } if not _validin_has_error(raw) else
                               {"summary": {}, "dns": [], "relationships": [],
                                "certificates": [], "http_observations": [],
                                "threat_context": []})
    if kind == "registration-history":
        domain = normalize_domain(indicator or "")
        if not is_domain(domain):
            return {"error": "Invalid domain for Validin registration history"}
        raw = _validin_get(f"/api/axon/domain/registration/history/{urllib.parse.quote(domain, safe='')}",
                           api_key, _validin_std_params(min(limit, 1000)))
        out = _validin_result(domain, kind, {"registration": raw},
                              {"summary": {}, "dns": [], "relationships": [],
                               "certificates": [], "http_observations": [],
                               "threat_context": [], "registration": [] if _validin_has_error(raw) else raw})
        return out
    domain = normalize_domain(indicator or "")
    ip = normalize_ip(indicator or "")
    cidr_ip, cidr_prefix = (None, None)
    if "/" in (indicator or ""):
        cidr_ip, _cidr_err = _parse_validin_cidr(indicator)
    is_dom = is_domain(domain)
    is_ipaddr = is_ip(ip)
    base: Dict[str, Any] = {}
    if kind in ("dns-history", "dns-extra", "subdomains", "certificates",
                "pivots", "crawl-history", "osint-history", "ptr"):
        if is_dom:
            encoded = urllib.parse.quote(domain, safe="")
            paths = {
                "dns-history": f"/api/axon/domain/dns/history/{encoded}",
                "dns-extra": f"/api/axon/domain/dns/extra/{encoded}",
                "subdomains": f"/api/axon/domain/subdomains/{encoded}",
                "certificates": f"/api/axon/domain/certificates/{encoded}",
                "pivots": f"/api/axon/domain/pivots/{encoded}",
                "crawl-history": f"/api/axon/domain/crawl/history/{encoded}",
                "osint-history": f"/api/axon/domain/osint/history/{encoded}",
            }
            if kind not in paths:
                return {"error": f"Lazy kind '{kind}' is not available for domain lookups"}
            params = _validin_std_params(limit)
            if kind == "dns-history":
                params["exclude_nx"] = "true"
            raw = _validin_get(paths[kind], api_key, params)
            base = _normalize_validin_records(raw, domain)
            return _validin_result(domain, kind, {kind: raw}, base) if not _validin_has_error(raw) \
                else _validin_result(domain, kind, {kind: raw}, {**base, "error": raw.get("error")})
        if is_ipaddr:
            encoded = urllib.parse.quote(ip, safe="")
            paths = {
                "dns-history": f"/api/axon/ip/dns/history/{encoded}",
                "dns-extra": f"/api/axon/ip/dns/extra/{encoded}",
                "ptr": f"/api/axon/ip/dns/hostname/{encoded}",
                "pivots": f"/api/axon/ip/pivots/{encoded}",
                "crawl-history": f"/api/axon/ip/crawl/history/{encoded}",
                "osint-history": f"/api/axon/ip/osint/history/{encoded}",
            }
            if kind not in paths:
                return {"error": f"Lazy kind '{kind}' is not available for IP lookups"}
            raw = _validin_get(paths[kind], api_key, _validin_std_params(limit))
            base = _normalize_validin_records(raw, ip)
            if kind == "ptr":
                base["ptr"] = [{"hostname": r["value"], "first_seen": r["first_seen"],
                                "last_seen": r["last_seen"]} for r in base["dns"]]
            return _validin_result(ip, kind, {kind: raw}, base) if not _validin_has_error(raw) \
                else _validin_result(ip, kind, {kind: raw}, {**base, "error": raw.get("error")})
        if cidr_ip:
            if kind not in ("dns-history", "pivots"):
                return {"error": f"Lazy kind '{kind}' is not available for CIDR lookups"}
            action = "dns/history" if kind == "dns-history" else "pivots"
            raw = _validin_get(
                f"/api/axon/ip/{action}/{urllib.parse.quote(cidr_ip, safe='')}/{cidr_prefix}",
                api_key, _validin_std_params(limit))
            base = _normalize_validin_records(raw, indicator)
            return _validin_result(indicator, kind, {kind: raw}, base)
        return {"error": "Validin lazy lookup requires a valid domain, IP, or CIDR"}
    return {"error": f"Unknown Validin lazy lookup: {kind}"}


FOFA_API_BASE = "https://fofa.info/api/v1"
FOFA_ALLOWED_PATHS = {"/search/all", "/search/next", "/info/my"}
FOFA_BLOCKED_MARKERS = ("refresh", "scan", "submit", "rescan", "asset/refresh", "asset_refresh")
FOFA_CACHE: Dict[str, Any] = {}
FOFA_CACHE_TTL = {"hit": 1800, "empty": 600, "error": 120}
FOFA_MINIMAL_FIELDS = (
    "host", "ip", "port", "protocol", "domain", "title", "server",
    "country", "region", "city", "as_number", "as_organization", "base_protocol",
)
FOFA_RICH_FIELDS = FOFA_MINIMAL_FIELDS + (
    "os", "product", "product_category", "product_version", "version",
    "status_code", "jarm", "ja3s", "icon_hash", "header_hash", "banner_hash",
    "cname", "lastupdatetime",
)
FOFA_FIELD_ALIASES = {
    "asn": "as_number",
    "org": "as_organization",
    "organization": "as_organization",
    "status": "status_code",
    "http_status": "status_code",
    "observed": "lastupdatetime",
}
FOFA_STRUCTURED_FIELDS = {
    "ip": "ip",
    "cidr": "ip",
    "domain": "domain",
    "host": "host",
    "hostname": "host",
    "asn": "asn",
    "org": "org",
    "organization": "org",
    "port": "port",
    "protocol": "protocol",
    "product": "product",
    "version": "version",
    "os": "os",
    "title": "title",
    "http_title": "title",
    "server": "server",
    "http_server": "server",
    "status": "status_code",
    "http_status": "status_code",
    "status_code": "status_code",
    "cert": "cert",
    "certificate": "cert",
    "cert_subject": "cert.subject",
    "certificate_subject": "cert.subject",
    "cert_issuer": "cert.issuer",
    "certificate_issuer": "cert.issuer",
    "cert_serial": "cert.serial",
    "certificate_serial": "cert.serial",
    "cert_domain": "cert.domain",
    "certificate_domain": "cert.domain",
    "jarm": "jarm",
    "ja3s": "ja3s",
    "icon_hash": "icon_hash",
    "favicon_hash": "icon_hash",
    "header_hash": "header_hash",
    "banner_hash": "banner_hash",
}

def _fofa_key(api_key: str = "") -> str:
    return (
        os.environ.get("FOFA_API_KEY")
        or os.environ.get("MANTIS_FOFA_KEY")
        or os.environ.get("IOCINTEL_FOFA_KEY")
        or os.environ.get("FOFA_KEY")
        or api_key
        or ""
    ).strip()

def _fofa_cache_get(key: str) -> Any:
    entry = FOFA_CACHE.get(key)
    if not entry:
        return None
    value, created, ttl = entry
    if time.time() - created > ttl:
        FOFA_CACHE.pop(key, None)
        return None
    return value

def _fofa_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        if len(FOFA_CACHE) > 512:
            FOFA_CACHE.clear()
        FOFA_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _fofa_sanitize_error(message: str, api_key: str = "") -> str:
    clean = str(message or "")
    for secret in {api_key, _fofa_key(api_key)}:
        if secret:
            clean = clean.replace(secret, "<redacted>")
    clean = re.sub(r"([?&]key=)[^&\s]+", r"\1<redacted>", clean, flags=re.I)
    return clean

def _fofa_has_rows(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("results"))

def _query_fofa(path: str, api_key: str = "", params: Dict[str, Any] = None) -> Dict[str, Any]:
    if path not in FOFA_ALLOWED_PATHS:
        return {"error": f"FOFA endpoint not allowlisted: {path}"}
    lowered_path = path.lower()
    if any(marker in lowered_path for marker in FOFA_BLOCKED_MARKERS):
        return {"error": "FOFA active collection endpoint is not allowed"}
    token = _fofa_key(api_key)
    if not token:
        return {"error": "No API Key provided"}

    safe_params = dict(params or {})
    safe_params["key"] = token
    cache_key = f"fofa:GET:{path}:{urllib.parse.urlencode(sorted((str(k), str(v)) for k, v in safe_params.items() if k != 'key'))}"
    cached = _fofa_cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        resp = requests.get(f"{FOFA_API_BASE}{path}", params=safe_params, timeout=20)
        if resp.status_code == 204:
            result = {"results": [], "size": 0}
            _fofa_cache_set(cache_key, result, FOFA_CACHE_TTL["empty"])
            return result
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text}
        if resp.status_code != 200:
            result = {"error": _fofa_sanitize_error(f"FOFA status {resp.status_code} - {resp.text}", token)}
            _fofa_cache_set(cache_key, result, FOFA_CACHE_TTL["error"])
            return result
        _fofa_cache_set(cache_key, payload, FOFA_CACHE_TTL["hit"] if _fofa_has_rows(payload) else FOFA_CACHE_TTL["empty"])
        return payload
    except Exception as exc:
        result = {"error": "FOFA request failed", "message": _fofa_sanitize_error(str(exc), token)}
        _fofa_cache_set(cache_key, result, FOFA_CACHE_TTL["error"])
        return result

def _fofa_escape_value(value: str, max_len: int = 512) -> str:
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "")).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)[:max_len]
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')

def _fofa_clause(field: str, value: str) -> str:
    return f'{field}="{_fofa_escape_value(value)}"'

def _fofa_is_expert_query(value: str) -> bool:
    raw = str(value or "").strip()
    return bool(re.search(r'\b[a-zA-Z_][\w.]*\s*(=|==|!=|~=|=~)\s*"?[^"]', raw) or "&&" in raw or "||" in raw)

def _fofa_expert_query(value: str) -> str:
    raw = str(value or "").strip()
    if not raw or len(raw) > 4096 or re.search(r"[\r\n;]", raw):
        return ""
    if re.search(r"https?://|/api/|api/v\d|key=", raw, re.I):
        return ""
    return raw

def build_fofa_query(value: str, query_type: str = "auto") -> str:
    raw = str(value or "").strip()
    qtype = (query_type or "auto").strip().lower().replace("-", "_")
    if not raw:
        return ""

    if qtype in {"fofa_query", "expert", "expert_fofa"} or (qtype == "auto" and _fofa_is_expert_query(raw)):
        return _fofa_expert_query(raw)

    prefix_match = re.match(r"^([a-zA-Z_][\w.-]{1,40})\s*[:=]\s*(.+)$", raw)
    if qtype == "auto" and prefix_match:
        possible_type = prefix_match.group(1).strip().lower().replace("-", "_")
        if possible_type in FOFA_STRUCTURED_FIELDS:
            qtype = possible_type
            raw = prefix_match.group(2).strip()

    if qtype == "auto":
        try:
            if "/" in raw:
                return _fofa_clause("ip", str(ipaddress.ip_network(raw, strict=False)))
        except ValueError:
            pass
        ip_value = normalize_ip(raw)
        if is_ip(ip_value):
            return _fofa_clause("ip", ip_value)
        domain_value = normalize_domain(raw)
        if is_domain(domain_value):
            return f'{_fofa_clause("domain", domain_value)} || {_fofa_clause("host", domain_value)}'
        asn_match = re.match(r"^(?:AS)?(\d{1,10})$", raw, re.I)
        if asn_match and not (raw.isdigit() and 0 < int(raw) <= 65535):
            return _fofa_clause("asn", asn_match.group(1))
        if raw.isdigit() and 0 < int(raw) <= 65535:
            return _fofa_clause("port", raw)
        safe = _fofa_escape_value(raw)
        return " || ".join([
            f'title="{safe}"',
            f'server="{safe}"',
            f'product="{safe}"',
            f'org="{safe}"',
            f'host="{safe}"',
        ])

    field = FOFA_STRUCTURED_FIELDS.get(qtype)
    if not field:
        return ""
    if qtype == "asn":
        asn = re.sub(r"^AS", "", raw, flags=re.I)
        if not re.fullmatch(r"\d{1,10}", asn):
            return ""
        raw = asn
    if qtype == "port" and (not raw.isdigit() or not (0 < int(raw) <= 65535)):
        return ""
    if qtype == "cidr":
        try:
            raw = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            return ""
    return _fofa_clause(field, raw)

def _fofa_normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    get = lambda *names: next((record.get(name) for name in names if record.get(name) not in (None, "", [])), "")
    asn = get("as_number", "asn")
    if asn and not str(asn).upper().startswith("AS"):
        asn = f"AS{asn}"
    normalized = {
        "host": get("host"),
        "ip": get("ip"),
        "port": get("port"),
        "protocol": get("protocol", "base_protocol"),
        "base_protocol": get("base_protocol"),
        "domain": get("domain"),
        "asn": asn,
        "organization": get("as_organization", "org", "organization"),
        "country": get("country"),
        "region": get("region"),
        "city": get("city"),
        "os": get("os"),
        "server": get("server"),
        "title": get("title"),
        "http_status": get("status_code", "status"),
        "cname": get("cname"),
        "product": get("product"),
        "product_category": get("product_category"),
        "product_version": get("product_version", "version"),
        "jarm": get("jarm"),
        "ja3s": get("ja3s"),
        "icon_hash": get("icon_hash"),
        "header_hash": get("header_hash"),
        "banner_hash": get("banner_hash"),
        "observed": get("lastupdatetime", "observed"),
    }
    return {key: value for key, value in normalized.items() if value not in (None, "", [])}

def normalize_fofa_response(data: Dict[str, Any], query: str, fields: List[str], page: int, size: int, full: bool) -> Dict[str, Any]:
    rows = data.get("results") if isinstance(data, dict) else []
    records = []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict):
            raw_record = {FOFA_FIELD_ALIASES.get(k, k): v for k, v in row.items()}
        elif isinstance(row, list):
            raw_record = {FOFA_FIELD_ALIASES.get(field, field): row[idx] for idx, field in enumerate(fields) if idx < len(row)}
        else:
            continue
        record = _fofa_normalize_record(raw_record)
        if record:
            records.append(record)
    total = data.get("size") or data.get("total") or len(records)
    return {
        "provider": "fofa",
        "query": query,
        "passive_only": True,
        "records": records,
        "count": len(records),
        "total": total,
        "page": page,
        "page_size": size,
        "has_more": bool(len(records) >= size or data.get("next")),
        "next": data.get("next") or "",
        "full_history": bool(full),
        "fields": fields,
    }

def _fofa_permission_error(data: Dict[str, Any]) -> bool:
    message = str(data.get("errmsg") or data.get("message") or data.get("error") or "")
    return bool(data.get("error") is True and re.search(r"permission|restricted|820001|没有权限|lastupdatetime", message, re.I))

def query_fofa(query_string: str, api_key: str, size: int = 50, page: int = 1, query_type: str = "auto", full: bool = False) -> Dict[str, Any]:
    query = build_fofa_query(query_string, query_type)
    if not query:
        return {"error": "Invalid FOFA query"}

    page = max(1, int(page or 1))
    size = max(1, min(int(size or 50), 100))
    fields = list(FOFA_RICH_FIELDS)
    params = {
        "qbase64": base64.b64encode(query.encode("utf-8")).decode("utf-8"),
        "fields": ",".join(fields),
        "page": page,
        "size": size,
        "full": "true" if full else "false",
    }
    data = _query_fofa("/search/all", api_key, params)
    if isinstance(data, dict) and _fofa_permission_error(data):
        limited_fields = list(FOFA_MINIMAL_FIELDS)
        retry_params = {**params, "fields": ",".join(limited_fields)}
        retry = _query_fofa("/search/all", api_key, retry_params)
        if isinstance(retry, dict) and retry.get("error") is not True and not retry.get("error"):
            retry["fields_limited"] = True
            retry["field_note"] = "FOFA plan restricted one or more enriched fields, so MANTIS retried with the safe infrastructure field set."
            retry["normalized"] = normalize_fofa_response(retry, query, limited_fields, page, size, full)
            retry["query"] = query
            retry["passive_only"] = True
            retry["endpoint"] = "/api/v1/search/all"
            return retry
        message = retry.get("errmsg") or retry.get("message") or retry.get("error") or data.get("errmsg") or data.get("message") or "FOFA API error"
        return {"error": _fofa_sanitize_error(message, api_key), "raw": {"error": True}}
    if isinstance(data, dict) and data.get("error") is True:
        message = data.get("errmsg") or data.get("message") or "FOFA API error"
        return {"error": _fofa_sanitize_error(message, api_key), "raw": {"error": True}}
    if isinstance(data, dict) and data.get("error"):
        return data
    if isinstance(data, dict):
        data.pop("error", None)
        data["normalized"] = normalize_fofa_response(data, query, fields, page, size, full)
        data["query"] = query
        data["passive_only"] = True
        data["endpoint"] = "/api/v1/search/all"
        return data
    return {"error": "Unexpected FOFA response"}

def query_fofa_domain(domain: str, api_key: str) -> Dict[str, Any]:
    return query_fofa(domain, api_key, query_type="domain")

def query_fofa_ip(ip: str, api_key: str) -> Dict[str, Any]:
    return query_fofa(ip, api_key, query_type="ip")

def query_fofa_hash(hash_val: str, api_key: str) -> Dict[str, Any]:
    return {"results": [], "normalized": {"provider": "fofa", "passive_only": True, "records": [], "count": 0, "note": "FOFA fingerprint hashes are infrastructure pivots, not malware file-hash lookup."}}


ZOOMEYE_API_V2 = "https://api.zoomeye.ai/v2/search"
ZOOMEYE_API_V1 = "https://api.zoomeye.org/host/search"


def query_zoomeye_search(query_string: str, api_key: str, page: int = 1, pagesize: int = 20, sub_type: str = "all") -> Dict[str, Any]:
    api_key = (api_key or os.getenv("ZOOMEYE_API_KEY") or os.getenv("MANTIS_ZOOMEYE_API_KEY") or os.getenv("IOCINTEL_ZOOMEYE_API_KEY") or "").strip()
    if not api_key:
        return {"error": "Missing ZoomEye API Key"}
    q = (query_string or "").strip()
    if not q:
        return {"error": "Empty ZoomEye search query"}

    q_b64 = base64.b64encode(q.encode("utf-8")).decode("utf-8")
    headers = {
        "API-KEY": api_key.strip(),
        "Content-Type": "application/json",
        "User-Agent": "MANTIS-CyberIntel/2.0",
    }
    payload = {
        "qbase64": q_b64,
        "fields": "ip,port,domain,service,title,country,city,asn,ssl.jarm,update_time",
        "sub_type": sub_type,
        "page": max(1, int(page or 1)),
        "pagesize": max(1, min(int(pagesize or 20), 100)),
    }

    try:
        resp = requests.post(ZOOMEYE_API_V2, json=payload, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            records = data.get("data", []) or []
            total = data.get("total", len(records))
            return {
                "provider": "zoomeye",
                "query": q,
                "total": total,
                "page": page,
                "pagesize": pagesize,
                "records": records,
                "hits": records,
                "raw": data,
            }
        # Fallback to ZoomEye.org API if v2 returns non-200
        v1_url = f"{ZOOMEYE_API_V1}?query={urllib.parse.quote(q)}&page={page}"
        v1_headers = {"API-KEY": api_key.strip(), "User-Agent": "MANTIS-CyberIntel/2.0"}
        v1_resp = requests.get(v1_url, headers=v1_headers, timeout=15)
        if v1_resp.status_code == 200:
            v1_data = v1_resp.json()
            v1_records = v1_data.get("matches", []) or v1_data.get("data", []) or []
            return {
                "provider": "zoomeye",
                "query": q,
                "total": v1_data.get("total", len(v1_records)),
                "records": v1_records,
                "hits": v1_records,
                "raw": v1_data,
            }
        return {"error": f"ZoomEye API error (HTTP {resp.status_code}): {resp.text[:200]}", "code": resp.status_code}
    except Exception as exc:
        return {"error": f"ZoomEye query failed: {str(exc)[:200]}"}


def query_zoomeye_ip(ip: str, api_key: str) -> Dict[str, Any]:
    return query_zoomeye_search(f'ip="{ip}"', api_key)


def query_zoomeye_domain(domain: str, api_key: str) -> Dict[str, Any]:
    return query_zoomeye_search(f'site="{domain}"', api_key)

PULSEDIVE_API_BASE = "https://pulsedive.com/api"
PULSEDIVE_ALLOWED_PATHS = {"/indicator.php", "/explore.php", "/threat.php", "/feed.php"}
PULSEDIVE_BLOCKED_MARKERS = ("analyze", "probe", "submit", "queue", "qid")
PULSEDIVE_BLOCKED_QUERY_MARKERS = ("analyze.php", "/api/analyze", "probe=", "submit=", "qid=", "queue")
PULSEDIVE_CACHE: Dict[str, Any] = {}
PULSEDIVE_CACHE_TTL = {"hit": 21600, "miss": 3600, "search": 1800, "lazy": 21600, "error": 300}

def _pulsedive_cache_get(key: str) -> Any:
    entry = PULSEDIVE_CACHE.get(key)
    if not entry:
        return None
    value, created, ttl = entry
    if time.time() - created > ttl:
        try:
            PULSEDIVE_CACHE.pop(key, None)
        except Exception:
            pass
        return None
    return value

def _pulsedive_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        PULSEDIVE_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _pulsedive_key(_api_key: str = "") -> str:
    for name in ("PULSEDIVE_API_KEY", "PULSEDIVE_KEY", "MANTIS_PULSEDIVE_KEY", "MANTIS_PULSEDIVE_TOKEN", "IOCINTEL_PULSEDIVE_KEY", "IOCINTEL_PULSEDIVE_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return (_api_key or "").strip()

def _pulsedive_rate_headers(headers: Any) -> Dict[str, str]:
    names = ("X-Requests-Remaining-Second", "X-Requests-Remaining-Day", "X-Requests-Remaining-Month")
    return {name: str(headers.get(name)) for name in names if headers is not None and headers.get(name) is not None}

def _sanitize_pulsedive_response(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sanitize_pulsedive_response(v) for k, v in value.items() if str(k).lower() != "key"}
    if isinstance(value, list):
        return [_sanitize_pulsedive_response(v) for v in value]
    return value

def _pulsedive_request(path: str, params: Dict[str, Any] = None, api_key: str = "", cache_ttl: int = None) -> Dict[str, Any]:
    if path not in PULSEDIVE_ALLOWED_PATHS:
        return {"error": "Unsupported Pulsedive endpoint. MANTIS only allows passive indicator, explore, threat, and feed lookups."}
    params = {k: v for k, v in (params or {}).items() if v not in (None, "")}
    lowered_path = path.lower()
    if any(marker in lowered_path for marker in PULSEDIVE_BLOCKED_MARKERS):
        return {"error": "Blocked Pulsedive active/submission workflow."}
    for key in params:
        if str(key).strip().lower() in {"probe", "submit", "qid", "queue"}:
            return {"error": "Blocked Pulsedive active/submission parameter."}
    server_key = _pulsedive_key(api_key)
    if server_key:
        params["key"] = server_key
    cache_key = f"pulsedive:{path}:{urllib.parse.urlencode(sorted((k, str(v)) for k, v in params.items() if k != 'key'))}"
    cached = _pulsedive_cache_get(cache_key)
    if cached is not None:
        return cached
    url = f"{PULSEDIVE_API_BASE}{path}"
    try:
        resp = requests.request("GET", url, params=params, timeout=20)
        rate_limit = _pulsedive_rate_headers(resp.headers)
        if resp.status_code in {204, 404}:
            result = {"data": [], "message": "No existing Pulsedive intelligence found."}
            if rate_limit:
                result["rate_limit"] = rate_limit
            _pulsedive_cache_set(cache_key, result, PULSEDIVE_CACHE_TTL["miss"])
            return result
        try:
            data = resp.json()
        except ValueError:
            data = {"text": resp.text}
        data = _sanitize_pulsedive_response(data)
        if resp.status_code == 200:
            if isinstance(data, dict) and data.get("error"):
                result = {"data": [], "message": data.get("error") or "No existing Pulsedive intelligence found."} if is_not_found_error(data) else data
            else:
                result = data if isinstance(data, dict) else {"data": data}
            if rate_limit and isinstance(result, dict):
                result["rate_limit"] = rate_limit
            _pulsedive_cache_set(cache_key, result, cache_ttl or PULSEDIVE_CACHE_TTL["hit"])
            return result
        if resp.status_code == 429:
            result = {"error": "Pulsedive rate limit exceeded (HTTP 429)", "message": data.get("error") if isinstance(data, dict) else resp.text}
        elif resp.status_code in {401, 403}:
            result = {"error": f"Pulsedive access restricted (HTTP {resp.status_code})", "message": data.get("error") if isinstance(data, dict) else resp.text}
        else:
            result = {"error": f"Pulsedive HTTP {resp.status_code}", "message": data.get("error") if isinstance(data, dict) else resp.text}
        if rate_limit:
            result["rate_limit"] = rate_limit
        _pulsedive_cache_set(cache_key, result, PULSEDIVE_CACHE_TTL["error"])
        return result
    except Exception as e:
        return {"error": "Pulsedive request failed", "message": str(e)}

def _pd_values(value: Any) -> List[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        out: List[Any] = []
        for item in value:
            out.extend(_pd_values(item))
        return out
    if isinstance(value, tuple):
        out: List[Any] = []
        for item in value:
            out.extend(_pd_values(item))
        return out
    return [value]

def _pd_clean_dict(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in obj.items() if v not in (None, "", [], {})}

def _pd_compact_indicator(row: Dict[str, Any]) -> Dict[str, Any]:
    summary = row.get("summary") if isinstance(row.get("summary"), dict) else {}
    props = summary.get("properties") if isinstance(summary.get("properties"), dict) else row.get("properties")
    return _pd_clean_dict({
        "iid": row.get("iid"),
        "indicator": row.get("indicator") or row.get("ioc") or row.get("value"),
        "type": row.get("type"),
        "risk": row.get("risk"),
        "first_seen": row.get("stamp_added"),
        "last_seen": row.get("stamp_seen") or row.get("stamp_updated"),
        "updated": row.get("stamp_updated"),
        "retired": row.get("retired") or row.get("stamp_retired"),
        "threats": row.get("threats") or summary.get("threats"),
        "feeds": row.get("feeds") or summary.get("feeds"),
        "attributes": row.get("attributes") or summary.get("attributes"),
        "properties": normalize_pulsedive_properties({"properties": props or {}}).get("property_groups", []),
    })

def normalize_pulsedive_properties(raw: Any, indicator: str = "", historical: bool = False) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {"historical": historical, "property_groups": []}
    props = raw.get("properties") if isinstance(raw.get("properties"), dict) else raw
    groups = []
    for name, values in props.items():
        if name in {"rate_limit", "error", "message"}:
            continue
        if not values:
            continue
        if isinstance(values, dict):
            rows = [{"name": str(k).lstrip("+"), "value": _pd_values(v)} for k, v in values.items() if _pd_values(v)]
        elif isinstance(values, list):
            rows = [{"name": name, "value": _pd_values(values)}]
        else:
            rows = [{"name": name, "value": [values]}]
        if rows:
            groups.append({"type": name, "fields": rows})
    return _pd_clean_dict({
        "indicator": indicator,
        "historical": historical,
        "property_groups": groups,
        "dns": props.get("dns") if isinstance(props.get("dns"), dict) else None,
        "whois": props.get("whois") if isinstance(props.get("whois"), dict) else None,
        "http": props.get("http") if isinstance(props.get("http"), dict) else None,
        "ssl": props.get("ssl") if isinstance(props.get("ssl"), dict) else None,
        "geo": props.get("geo") if isinstance(props.get("geo"), dict) else None,
    })

def normalize_pulsedive_links(raw: Any, source_indicator: str = "") -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []
    if not isinstance(raw, dict):
        return {"links": rows, "relationships": relationships}
    for group, values in raw.items():
        if group in {"rate_limit", "error", "message"} or not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            row = _pd_clean_dict({
                "group": group,
                "iid": item.get("iid"),
                "indicator": item.get("indicator"),
                "type": item.get("type"),
                "risk": item.get("risk"),
                "linked_at": item.get("stamp_linked"),
                "summary": item.get("summary"),
            })
            rows.append(row)
            target = row.get("indicator")
            if target:
                rel = "related_to"
                gl = str(group).lower()
                if "active dns" in gl:
                    rel = "resolves_to"
                elif "redirect" in gl:
                    rel = "redirects_to"
                elif "url" in gl:
                    rel = "associated_with_url"
                relationships.append(_pd_clean_dict({
                    "source": source_indicator,
                    "relation": rel,
                    "target": target,
                    "target_type": row.get("type"),
                    "provenance": "Pulsedive indicator links",
                    "group": group,
                    "timestamp": row.get("linked_at"),
                }))
    return {"links": rows, "relationships": relationships}

def _pd_relationships_from_indicator(raw: Dict[str, Any], norm_props: Dict[str, Any]) -> List[Dict[str, Any]]:
    src = raw.get("indicator") or ""
    rels: List[Dict[str, Any]] = []
    for threat in raw.get("threats") or []:
        if isinstance(threat, dict) and (threat.get("name") or threat.get("threat")):
            rels.append(_pd_clean_dict({"source": src, "relation": "associated_with", "target": threat.get("name") or threat.get("threat"), "target_type": "threat", "provenance": "Pulsedive threat link", "timestamp": threat.get("stamp_linked")}))
    for feed in raw.get("feeds") or []:
        if isinstance(feed, dict) and (feed.get("name") or feed.get("feed")):
            name = feed.get("name") or feed.get("feed")
            org = feed.get("organization")
            rels.append(_pd_clean_dict({"source": src, "relation": "sourced_from", "target": f"{org}/{name}" if org else name, "target_type": "feed", "provenance": "Pulsedive feed link", "timestamp": feed.get("stamp_linked")}))
    dns = norm_props.get("dns") or {}
    for key, relation, target_type in (("a", "resolves_to", "ip"), ("aaaa", "resolves_to", "ip"), ("mx", "uses_mail_server", "domain"), ("ns", "uses_nameserver", "domain")):
        for value in _pd_values(dns.get(key)):
            rels.append({"source": src, "relation": relation, "target": value, "target_type": target_type, "provenance": "Pulsedive DNS property"})
    ssl = norm_props.get("ssl") or {}
    for value in _pd_values(ssl.get("domain")):
        rels.append({"source": src, "relation": "associated_with_certificate_domain", "target": value, "target_type": "domain", "provenance": "Pulsedive SSL property"})
    for value in _pd_values(ssl.get("ip")):
        rels.append({"source": src, "relation": "associated_with_certificate_ip", "target": value, "target_type": "ip", "provenance": "Pulsedive SSL property"})
    redirects = raw.get("redirects") if isinstance(raw.get("redirects"), dict) else {}
    for item in _pd_values(redirects.get("to")):
        if isinstance(item, dict) and item.get("indicator"):
            rels.append({"source": src, "relation": "redirects_to", "target": item.get("indicator"), "target_type": "indicator", "provenance": "Pulsedive redirects"})
    for item in _pd_values(redirects.get("from")):
        if isinstance(item, dict) and item.get("indicator"):
            rels.append({"source": item.get("indicator"), "relation": "redirects_to", "target": src, "target_type": "indicator", "provenance": "Pulsedive redirects"})
    return rels

def normalize_pulsedive_indicator(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("data") == []:
        return {"found": False, "message": "No existing Pulsedive intelligence found."}
    props = normalize_pulsedive_properties(raw, raw.get("indicator") or "")
    indicator = _pd_clean_dict({
        "iid": raw.get("iid"),
        "indicator": raw.get("indicator"),
        "type": raw.get("type"),
        "risk": raw.get("risk"),
        "recommended_risk": raw.get("risk_recommended"),
        "manual_risk": raw.get("manualrisk"),
        "classification": raw.get("classification") or raw.get("category"),
        "active": False if raw.get("retired") in {1, True, "1", "true", "retired"} else True,
        "retired": raw.get("retired"),
        "first_seen": raw.get("stamp_added"),
        "last_seen": raw.get("stamp_seen") or raw.get("stamp_updated"),
        "updated": raw.get("stamp_updated"),
        "last_provider_enrichment": raw.get("stamp_probed"),
        "retired_at": raw.get("stamp_retired"),
        "recent": raw.get("recent"),
        "submissions": raw.get("submissions"),
        "umbrella_rank": raw.get("umbrella_rank"),
        "umbrella_domain": raw.get("umbrella_domain"),
    })
    return _pd_clean_dict({
        "found": True,
        "indicator": indicator,
        "risk_factors": raw.get("riskfactors") or [],
        "threats": raw.get("threats") or [],
        "feeds": raw.get("feeds") or [],
        "attributes": raw.get("attributes") or {},
        "properties": props,
        "relationships": _pd_relationships_from_indicator(raw, props),
        "comments": raw.get("comments") or [],
    })

def normalize_pulsedive_explore(raw: Any, mode: str = "indicators") -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {"results": [], "mode": mode}
    results = raw.get("results") if isinstance(raw.get("results"), list) else []
    if mode == "threats":
        norm_results = [normalize_pulsedive_threat(item) for item in results if isinstance(item, dict)]
    else:
        norm_results = [_pd_compact_indicator(item) for item in results if isinstance(item, dict)]
    return _pd_clean_dict({"mode": mode, "query": raw.get("query"), "results": norm_results, "count": len(norm_results)})

def normalize_pulsedive_threat(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("data") == []:
        return {"found": False, "message": "No existing Pulsedive threat intelligence found."}
    return _pd_clean_dict({
        "found": True,
        "tid": raw.get("tid"),
        "name": raw.get("threat") or raw.get("name"),
        "category": raw.get("category") or raw.get("type"),
        "aliases": raw.get("othernames") or raw.get("aliases") or [],
        "risk": raw.get("risk"),
        "description": raw.get("description") or raw.get("wikisummary"),
        "notes": raw.get("notes"),
        "wiki_reference": raw.get("wikireference"),
        "retired": raw.get("retired"),
        "first_seen": raw.get("stamp_added"),
        "last_seen": raw.get("stamp_seen") or raw.get("stamp_updated"),
        "updated": raw.get("stamp_updated"),
        "related": raw.get("related") or [],
        "attributes": raw.get("attributes") or {},
        "ttps": raw.get("ttps") or [],
        "news": raw.get("news") or [],
        "comments": raw.get("comments") or [],
        "summary": raw.get("summary") or {},
        "feeds": (raw.get("summary") or {}).get("feeds") if isinstance(raw.get("summary"), dict) else None,
    })

def normalize_pulsedive_feed(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("data") == []:
        return {"found": False, "message": "No existing Pulsedive feed intelligence found."}
    return _pd_clean_dict({
        "found": True,
        "fid": raw.get("fid"),
        "name": raw.get("feed") or raw.get("name"),
        "organization": raw.get("organization"),
        "category": raw.get("category"),
        "pricing": raw.get("pricing"),
        "website": raw.get("website"),
        "schedule": raw.get("schedule"),
        "description": raw.get("description"),
        "access_link": raw.get("accesslink"),
        "first_seen": raw.get("stamp_added"),
        "last_seen": raw.get("stamp_seen") or raw.get("stamp_updated"),
        "updated": raw.get("stamp_updated"),
        "indicators": raw.get("indicators") or {},
        "summary": raw.get("summary") or {},
    })

def normalize_pulsedive_linked_indicators(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {"results": []}
    results = raw.get("results") if isinstance(raw.get("results"), list) else []
    return _pd_clean_dict({
        "page_current": raw.get("page_current"),
        "page_next": raw.get("page_next"),
        "results": [_pd_compact_indicator(item) for item in results if isinstance(item, dict)],
        "summary": {k: v for k, v in raw.items() if k not in {"results", "page_current", "page_next", "rate_limit"} and v not in (None, "", [], {})},
    })

def _pd_escape_query_value(value: str, wildcard: bool = False) -> str:
    value = str(value or "").strip()
    value = re.sub(r"[\r\n]", " ", value)[:500]
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    if wildcard:
        value = f"*{value.strip('*')}*"
    if re.search(r"\s|[()]", value):
        return f'"{value}"'
    return value

def build_pulsedive_query(value: str, query_type: str = "auto") -> str:
    raw = str(value or "").strip()
    lowered = raw.lower()
    if any(marker in lowered for marker in PULSEDIVE_BLOCKED_QUERY_MARKERS):
        raise ValueError("Pulsedive active/submission workflow is not allowed.")
    qtype = (query_type or "auto").strip().lower()
    if qtype in {"pulsedive_query", "native", "expert"}:
        if not raw or len(raw) > 1000 or "\n" in raw or "\r" in raw:
            raise ValueError("Invalid Pulsedive Explore query.")
        return raw
    if not raw:
        raise ValueError("Pulsedive query cannot be empty.")
    if qtype == "risk":
        risk = raw.lower()
        if risk not in {"unknown", "none", "low", "medium", "high", "critical", "retired"}:
            raise ValueError("Invalid Pulsedive risk filter.")
        return f"risk={risk}"
    if qtype in {"type", "indicator_type"}:
        typ = raw.lower()
        if typ not in {"domain", "ip", "ipv4", "ipv6", "url"}:
            raise ValueError("Invalid Pulsedive indicator type.")
        return f"type={'ip' if typ in {'ipv4', 'ipv6'} else typ}"
    if qtype in {"threat", "malware", "malware_family", "threat_actor", "campaign"}:
        return f"threat={_pd_escape_query_value(raw, wildcard=True)}"
    if qtype in {"feed", "source"}:
        return f"feed={_pd_escape_query_value(raw, wildcard=True)}"
    if qtype in {"port", "protocol", "technology", "seen", "added", "updated", "retired"}:
        return f"{qtype}={_pd_escape_query_value(raw)}"
    if qtype in {"property", "dns", "ssl", "certificate", "http", "content_type"}:
        field = "content-type" if qtype == "content_type" else qtype
        return raw if "=" in raw else f"{field}={_pd_escape_query_value(raw, wildcard=True)}"
    if qtype == "domain" or is_domain(normalize_domain(raw)):
        return f"ioc={_pd_escape_query_value(normalize_domain(raw))}"
    if qtype == "ip" or is_ip(normalize_ip(raw)):
        return f"ioc={_pd_escape_query_value(normalize_ip(raw))}"
    if qtype == "url" or is_url(normalize_url(raw)):
        return f"ioc={_pd_escape_query_value(normalize_url(raw))}"
    return f"ioc={_pd_escape_query_value(raw, wildcard=True)} or threat={_pd_escape_query_value(raw, wildcard=True)}"

def query_pulsedive(indicator: str, api_key: str = "") -> Dict[str, Any]:
    value = (indicator or "").strip()
    raw = _pulsedive_request("/indicator.php", {"indicator": value}, api_key, PULSEDIVE_CACHE_TTL["hit"])
    if is_not_found_error(raw) or raw.get("data") == []:
        return {"data": [], "message": "No existing Pulsedive intelligence found."}
    if raw.get("error"):
        return raw
    normalized = normalize_pulsedive_indicator(raw)
    return {"indicator": raw, "normalized": normalized, "relationships": normalized.get("relationships", []), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_hash(file_hash: str, api_key: str = "") -> Dict[str, Any]:
    return {"data": [], "unsupported": True, "message": "Pulsedive does not document hash indicator lookup; use file-hash providers for hashes."}

def query_pulsedive_indicator_properties(iid: str, api_key: str = "", historical: bool = False) -> Dict[str, Any]:
    raw = _pulsedive_request("/indicator.php", {"iid": iid, "get": "properties", "historical": 1 if historical else 0}, api_key, PULSEDIVE_CACHE_TTL["lazy"])
    if raw.get("error") or raw.get("data") == []:
        return raw
    return {"properties": raw, "normalized": normalize_pulsedive_properties(raw, historical=historical), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_indicator_links(iid: str, api_key: str = "", indicator: str = "") -> Dict[str, Any]:
    raw = _pulsedive_request("/indicator.php", {"iid": iid, "get": "links"}, api_key, PULSEDIVE_CACHE_TTL["lazy"])
    if raw.get("error") or raw.get("data") == []:
        return raw
    normalized = normalize_pulsedive_links(raw, indicator)
    return {"links": raw, "normalized": normalized, "relationships": normalized.get("relationships", []), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_explore(query: str, api_key: str = "", query_type: str = "auto", mode: str = "indicators", limit: int = 50) -> Dict[str, Any]:
    mode = (mode or "indicators").strip().lower()
    if mode not in {"indicators", "threats"}:
        mode = "indicators"
    try:
        q = build_pulsedive_query(query, query_type)
    except ValueError as e:
        return {"error": str(e)}
    try:
        lim = max(1, min(int(limit or 50), 250))
    except (TypeError, ValueError):
        lim = 50
    raw = _pulsedive_request("/explore.php", {"q": q, "type": mode, "limit": lim, "format": "json"}, api_key, PULSEDIVE_CACHE_TTL["search"])
    if raw.get("error"):
        return raw
    if raw.get("data") == []:
        return {"results": [], "query": q, "message": "No existing Pulsedive intelligence found."}
    return {"query": q, "mode": mode, "results": raw.get("results", []), "raw": raw, "normalized": normalize_pulsedive_explore(raw, mode), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_threat(threat: str, api_key: str = "") -> Dict[str, Any]:
    raw = _pulsedive_request("/threat.php", {"threat": (threat or "").strip()}, api_key, PULSEDIVE_CACHE_TTL["hit"])
    if raw.get("error") or raw.get("data") == []:
        return raw if raw.get("error") else {"data": [], "message": "No existing Pulsedive threat intelligence found."}
    return {"threat": raw, "normalized": normalize_pulsedive_threat(raw), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_threat_links(tid: str, api_key: str = "", page: int = 0, summary: bool = False) -> Dict[str, Any]:
    params = {"tid": tid, "get": "links", "summary": 1 if summary else 0, "splitrisk": 1 if summary else 0}
    try:
        page_num = max(0, int(page or 0))
    except (TypeError, ValueError):
        page_num = 0
    if page_num:
        params["page"] = page_num
    raw = _pulsedive_request("/threat.php", params, api_key, PULSEDIVE_CACHE_TTL["lazy"])
    if raw.get("error") or raw.get("data") == []:
        return raw
    return {"tid": tid, "links": raw, "normalized": normalize_pulsedive_linked_indicators(raw), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_feed(fid: str = "", feed: str = "", organization: str = "", api_key: str = "") -> Dict[str, Any]:
    params = {"fid": fid}
    if not fid:
        params = {"feed": (feed or "").strip(), "organization": (organization or "").strip()}
    raw = _pulsedive_request("/feed.php", params, api_key, PULSEDIVE_CACHE_TTL["hit"])
    if raw.get("error") or raw.get("data") == []:
        return raw if raw.get("error") else {"data": [], "message": "No existing Pulsedive feed intelligence found."}
    return {"feed": raw, "normalized": normalize_pulsedive_feed(raw), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_feed_links(fid: str, api_key: str = "", page: int = 0, summary: bool = False) -> Dict[str, Any]:
    params = {"fid": fid, "get": "links", "summary": 1 if summary else 0, "splitrisk": 1 if summary else 0}
    try:
        page_num = max(0, int(page or 0))
    except (TypeError, ValueError):
        page_num = 0
    if page_num:
        params["page"] = page_num
    raw = _pulsedive_request("/feed.php", params, api_key, PULSEDIVE_CACHE_TTL["lazy"])
    if raw.get("error") or raw.get("data") == []:
        return raw
    return {"fid": fid, "links": raw, "normalized": normalize_pulsedive_linked_indicators(raw), "rate_limit": raw.get("rate_limit")}

def query_pulsedive_keyword(keyword: str, api_key: str = "") -> Dict[str, Any]:
    value = (keyword or "").strip()
    results = _collect_callables({
        "explore_indicators": lambda: query_pulsedive_explore(value, api_key, query_type="keyword", mode="indicators", limit=50),
        "explore_threats": lambda: query_pulsedive_explore(value, api_key, query_type="threat", mode="threats", limit=50),
        "threat": lambda: query_pulsedive_threat(value, api_key),
    }, max_workers=3)
    threat = results.get("threat", {})
    tid = None
    if isinstance(threat, dict):
        tid = (threat.get("normalized") or {}).get("tid") or (threat.get("threat") or {}).get("tid")
    if tid:
        results["threat_links_summary"] = query_pulsedive_threat_links(str(tid), api_key, summary=True)
    return _keep_success(results) or {"data": [], "message": "No existing Pulsedive intelligence found."}

NETLAS_API_BASE = "https://app.netlas.io/api"
_NETLAS_CACHE: Dict[str, Dict[str, Any]] = {}
NETLAS_CACHE_TTL = 900


def _netlas_cache_get(key: str) -> Any:
    cached = _NETLAS_CACHE.get(key)
    if cached and time.time() - cached["time"] < NETLAS_CACHE_TTL:
        return cached["value"]
    if cached:
        _NETLAS_CACHE.pop(key, None)
    return None


def _netlas_cache_set(key: str, value: Any) -> None:
    if len(_NETLAS_CACHE) > 256:
        oldest = min(_NETLAS_CACHE, key=lambda item: _NETLAS_CACHE[item]["time"])
        _NETLAS_CACHE.pop(oldest, None)
    _NETLAS_CACHE[key] = {"time": time.time(), "value": value}


def _netlas_query_allowed(query: str) -> bool:
    value = str(query or "").strip()
    return bool(value and len(value) <= 1200 and "\n" not in value and "\r" not in value and ";" not in value)


def build_netlas_query(value: str, query_type: str = "auto") -> str:
    raw = str(value or "").strip()
    qtype = str(query_type or "auto").strip().lower()
    if not raw:
        return ""
    if qtype in {"netlas_query", "expert", "keyword", "infra"} and re.search(r"[a-zA-Z_][\w.]*:", raw):
        return raw[:1200] if _netlas_query_allowed(raw) else ""
    try:
        if "/" in raw:
            return f"ip:{ipaddress.ip_network(raw, strict=False)}"
    except ValueError:
        pass
    ip_value = normalize_ip(raw)
    if is_ip(ip_value):
        return f"ip:{ip_value}"
    domain_value = normalize_domain(raw)
    if is_domain(domain_value):
        return f'(host:{domain_value} OR domain:{domain_value} OR certificate.names:{domain_value})'
    asn = re.fullmatch(r"(?i)(?:AS)?(\d{1,10})", raw)
    if asn:
        return f"whois.asn.number:{asn.group(1)}"
    if raw.isdigit() and 0 < int(raw) <= 65535:
        return f"port:{raw}"
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", raw)[:300].replace('"', '\\"')
    return f'http.title:"{cleaned}" OR protocol:"{cleaned}" OR description:"{cleaned}"'


def normalize_netlas_response(raw: Any, query: str, start: int = 0, size: int = 20) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("error"):
        return {"source": "Netlas", "query": query, "records": [], "total": 0, "start": start, "size": size}
    rows = []
    for key in ("items", "results", "data", "responses"):
        if isinstance(raw.get(key), list):
            rows = raw[key]
            break
    records = []
    for row in rows[:size]:
        if not isinstance(row, dict):
            continue
        certificate = row.get("certificate") if isinstance(row.get("certificate"), dict) else {}
        http_data = row.get("http") if isinstance(row.get("http"), dict) else {}
        whois = row.get("whois") if isinstance(row.get("whois"), dict) else {}
        asn = whois.get("asn") if isinstance(whois.get("asn"), dict) else {}
        record = {
            "ip": row.get("ip") or row.get("host"),
            "host": row.get("host") or row.get("domain"),
            "port": row.get("port"),
            "protocol": row.get("protocol") or row.get("prot7"),
            "uri": row.get("uri"),
            "domain": row.get("domain"),
            "http_title": http_data.get("title") or row.get("http.title"),
            "http_server": (http_data.get("headers") or {}).get("server") if isinstance(http_data.get("headers"), dict) else row.get("http.headers.server"),
            "certificate_subject": certificate.get("subject_dn") or row.get("certificate.subject_dn"),
            "certificate_issuer": certificate.get("issuer_dn") or row.get("certificate.issuer_dn"),
            "certificate_sha256": certificate.get("fingerprint_sha256") or row.get("certificate.fingerprint_sha256"),
            "asn": asn.get("number") or row.get("whois.asn.number"),
            "asn_name": asn.get("name") or row.get("whois.asn.name"),
            "country": (row.get("geo") or {}).get("country") if isinstance(row.get("geo"), dict) else row.get("geo.country"),
            "last_seen": row.get("last_updated") or row.get("timestamp") or row.get("last_seen"),
        }
        records.append({key: value for key, value in record.items() if value not in (None, "", [], {})})
    total = raw.get("total") or raw.get("count") or raw.get("result_count") or len(records)
    if isinstance(total, dict):
        total = total.get("value") or len(records)
    return {
        "source": "Netlas",
        "kind": "response_search",
        "query": query,
        "records": records,
        "total": int(total) if str(total).isdigit() else len(records),
        "start": start,
        "size": size,
        "has_more": len(records) >= size,
        "semantics": {"passive_scan_data": True, "presence_does_not_mean_malicious": True},
    }


def query_netlas_search(query: str, api_key: str = "", size: int = 20, start: int = 0,
                        query_type: str = "netlas_query") -> Dict[str, Any]:
    token = (api_key or os.getenv("NETLAS_API_KEY") or os.getenv("MANTIS_NETLAS_API_KEY") or "").strip()
    if not token:
        return {"error": "Netlas API key required"}
    built = build_netlas_query(query, query_type)
    if not built:
        return {"error": "Invalid Netlas query"}
    size = max(1, min(int(size or 20), 100))
    start = max(0, min(int(start or 0), 9980))
    cache_key = hashlib.sha256(f"{built}|{size}|{start}".encode()).hexdigest()
    cached = _netlas_cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        response = requests.get(
            f"{NETLAS_API_BASE}/responses/",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params={"q": built, "start": start, "fields": "*"},
            timeout=25,
        )
        try:
            raw = response.json()
        except ValueError:
            raw = {"error": f"Netlas returned HTTP {response.status_code}"}
        if response.status_code != 200:
            message = raw.get("detail") or raw.get("message") or raw.get("error") or f"HTTP {response.status_code}"
            return {"error": f"Netlas request failed: {str(message)[:300]}", "status": response.status_code}
        result = {"raw": raw, "normalized": normalize_netlas_response(raw, built, start, size)}
        _netlas_cache_set(cache_key, result)
        return result
    except requests.RequestException as exc:
        return {"error": f"Netlas request failed: {str(exc)[:240]}"}


def query_netlas(indicator: str, query_type: str, api_key: str = "") -> Dict[str, Any]:
    return query_netlas_search(indicator, api_key, query_type=query_type)


DRIFTNET_API_BASE = "https://api.driftnet.io/v1"
DRIFTNET_PASSIVE_PATHS = {
    "/admin/user",
    "/scan/protocols",
    "/scan/protocols/body",
    "/scan/ports",
    "/scan/ipports",
    "/scan/domains",
    "/scan/favicons",
    "/scan/ja4scan",
    "/scan/ja4tscan",
    "/scan/jarm",
    "/domain/fdns",
    "/domain/mx",
    "/domain/txt",
    "/domain/rdns",
    "/domain/whois",
    "/domain/reverse",
    "/ip/whois",
    "/ip/whois/pocs",
    "/ip/pwhois",
    "/ip/rwhois",
    "/ip/rdns",
    "/ip/routes",
    "/ip/reverse",
    "/ct/log",
}
DRIFTNET_ACTIVE_MARKERS = (
    "/prioritize", "prioritize", "scan-on-demand", "live-scan",
    "screenshot", "/submit", "/monitor", "/monitors", "mutation",
)
DRIFTNET_DATASET_PATHS = {
    "protocols": "/scan/protocols",
    "protocol_body": "/scan/protocols/body",
    "body": "/scan/protocols/body",
    "ports": "/scan/ports",
    "ipports": "/scan/ipports",
    "domains": "/scan/domains",
    "domain_scans": "/scan/domains",
    "fdns": "/domain/fdns",
    "mx": "/domain/mx",
    "txt": "/domain/txt",
    "rdns": "/domain/rdns",
    "domain_whois": "/domain/whois",
    "domain_reverse": "/domain/reverse",
    "ip_whois": "/ip/whois",
    "ip_pocs": "/ip/whois/pocs",
    "ip_pwhois": "/ip/pwhois",
    "bgp": "/ip/pwhois",
    "rwhois": "/ip/rwhois",
    "routes": "/ip/routes",
    "ip_rdns": "/ip/rdns",
    "ip_reverse": "/ip/reverse",
    "ct": "/ct/log",
    "favicons": "/scan/favicons",
    "ja4": "/scan/ja4scan",
    "ja4t": "/scan/ja4tscan",
    "jarm": "/scan/jarm",
}
DRIFTNET_CACHE: Dict[str, Any] = {}
DRIFTNET_CACHE_TTL = {"hit": 1800, "empty": 600, "error": 120}

def _driftnet_key(_api_key: str = "") -> str:
    return (
        os.environ.get("DRIFTNET_API_TOKEN")
        or os.environ.get("DRIFTNET_API_KEY")
        or os.environ.get("DRIFTNET_TOKEN")
        or os.environ.get("MANTIS_DRIFTNET_TOKEN")
        or os.environ.get("MANTIS_DRIFTNET_KEY")
        or os.environ.get("IOCINTEL_DRIFTNET_TOKEN")
        or os.environ.get("IOCINTEL_DRIFTNET_KEY")
        or (_api_key or "").strip()
        or ""
    ).strip()

def _driftnet_clean_path(path: str) -> str:
    return "/" + (path or "").split("?", 1)[0].strip().strip("/")

def _driftnet_path_allowed(path: str) -> bool:
    clean = _driftnet_clean_path(path).lower()
    if any(marker in clean for marker in DRIFTNET_ACTIVE_MARKERS):
        return False
    return clean in DRIFTNET_PASSIVE_PATHS

def _driftnet_sanitize(text: Any, token: str = "") -> str:
    out = str(text or "")
    for secret in {token, os.environ.get("DRIFTNET_API_TOKEN", ""), os.environ.get("DRIFTNET_API_KEY", ""),
                   os.environ.get("DRIFTNET_TOKEN", ""), os.environ.get("MANTIS_DRIFTNET_TOKEN", ""),
                   os.environ.get("MANTIS_DRIFTNET_KEY", ""), os.environ.get("IOCINTEL_DRIFTNET_TOKEN", ""),
                   os.environ.get("IOCINTEL_DRIFTNET_KEY", "")}:
        if secret:
            out = out.replace(secret, "[redacted]")
    out = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", out, flags=re.I)
    return out[:800]

def _driftnet_cache_key(path: str, params: Dict[str, Any]) -> str:
    normalized = tuple(sorted((str(k), str(v)) for k, v in (params or {}).items() if v is not None and v != ""))
    return f"{_driftnet_clean_path(path)}::{normalized}"

def _driftnet_cache_get(key: str) -> Any:
    entry = DRIFTNET_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at <= ttl:
            return value
        DRIFTNET_CACHE.pop(key, None)
    except Exception:
        DRIFTNET_CACHE.pop(key, None)
    return None

def _driftnet_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        DRIFTNET_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _driftnet_has_data(data: Any) -> bool:
    if data is None:
        return False
    if isinstance(data, list):
        return any(_driftnet_has_data(v) for v in data)
    if isinstance(data, dict):
        if data.get("error"):
            return False
        for key in ("results", "data", "values", "items", "records"):
            if key in data and _driftnet_has_data(data.get(key)):
                return True
        return any(k not in {"page", "pages", "result_count", "count", "query"} and _driftnet_has_data(v) for k, v in data.items())
    return str(data or "").strip() != ""

def _query_driftnet(path: str, api_key: str = "", params: Dict[str, Any] = None, cache_ttl: int = None) -> Any:
    clean = _driftnet_clean_path(path)
    if not _driftnet_path_allowed(clean):
        return {"error": "Driftnet endpoint not allowlisted (passive-only integration)"}
    token = _driftnet_key(api_key)
    if not token:
        return {"error": "No Driftnet server API token configured"}
    params = {k: v for k, v in (params or {}).items() if v not in (None, "")}
    cache_key = _driftnet_cache_key(clean, params)
    cached = _driftnet_cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        resp = requests.request(
            "GET",
            f"{DRIFTNET_API_BASE}{clean}",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=25,
        )
    except Exception as e:
        result = {"error": "Driftnet request failed", "message": _driftnet_sanitize(str(e), token)}
        _driftnet_cache_set(cache_key, result, DRIFTNET_CACHE_TTL["error"])
        return result

    if resp.status_code == 204 or resp.status_code == 404:
        result = {"data": []}
        _driftnet_cache_set(cache_key, result, DRIFTNET_CACHE_TTL["empty"])
        return result
    if resp.status_code != 200:
        label = "authentication failed" if resp.status_code in {401, 403} else "provider limit reached" if resp.status_code == 429 else "request failed"
        result = {"error": f"Driftnet {label} (HTTP {resp.status_code})", "message": _driftnet_sanitize(resp.text, token)}
        _driftnet_cache_set(cache_key, result, DRIFTNET_CACHE_TTL["error"])
        return result
    try:
        result = resp.json()
    except ValueError:
        result = {"text": _driftnet_sanitize(resp.text, token)}
    if clean == "/admin/user" and isinstance(result, dict):
        result = {k: v for k, v in result.items() if k.lower() != "token"}
    _driftnet_cache_set(cache_key, result, cache_ttl or (DRIFTNET_CACHE_TTL["hit"] if _driftnet_has_data(result) else DRIFTNET_CACHE_TTL["empty"]))
    return result

def _driftnet_quote(value: str) -> str:
    v = (value or "").strip().replace("\\", "\\\\").replace('"', '\\"')
    if not v:
        return ""
    return f'"{v}"' if re.search(r"\s|[:()]", v) else v

def build_driftnet_expression(value: str, query_type: str = "auto") -> str:
    raw = (value or "").strip()
    qtype = (query_type or "auto").strip().lower()
    if not raw:
        return ""
    if any(marker in raw.lower() for marker in DRIFTNET_ACTIVE_MARKERS):
        return ""
    if qtype in {"driftnet_query", "expression", "expert"}:
        return raw[:1000]
    try:
        if "/" in raw:
            ipaddress.ip_network(raw, strict=False)
            return raw
    except ValueError:
        pass
    if is_ip(normalize_ip(raw)):
        return raw
    if qtype in {"domain", "hostname", "host"} or is_domain(normalize_domain(raw)):
        return f"host:{_driftnet_quote(normalize_domain(raw) or raw)}"
    if qtype in {"port", "tcp_port"} and raw.isdigit():
        return f"port-tcp:{raw}"
    if qtype == "udp_port" and raw.isdigit():
        return f"port-udp:{raw}"
    if qtype in {"service", "protocol"}:
        return f"protocol={raw}"
    if qtype in {"certificate", "cert", "issuer", "subject", "title", "url", "http_header"}:
        field = {"certificate": "subject", "cert": "subject", "http_header": "http-header"}.get(qtype, qtype)
        return f"{field}:{_driftnet_quote(raw)}"
    if qtype in {"favicon_sha1", "body_sha1", "content_sha1", "obj_sha1"}:
        return f"obj-sha1:{raw}"
    if qtype in {"nameserver", "dns", "whois", "registration", "keyword"}:
        return f"search-term:{_driftnet_quote(raw)}"
    return f"search-term:{_driftnet_quote(raw)}"

def _dt_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("results", "data", "records", "items", "values"):
            if isinstance(value.get(key), list):
                return value.get(key)
    return []

def _dt_unique(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for item in items:
        key = tuple(sorted((k, str(v)) for k, v in item.items() if v not in (None, "", [], {})))
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out

def normalize_driftnet_report(report: Dict[str, Any], dataset: str = "") -> Dict[str, Any]:
    items = report.get("items") if isinstance(report, dict) else []
    record = {
        "date": report.get("date") if isinstance(report, dict) else "",
        "id": report.get("id") if isinstance(report, dict) else "",
        "dataset": dataset,
        "hosts": [],
        "ips": [],
        "ports": [],
        "protocols": [],
        "urls": [],
        "titles": [],
        "banners": [],
        "certificates": [],
        "fingerprints": {},
        "body_hashes": [],
        "raw_item_count": len(items) if isinstance(items, list) else 0,
    }
    if not isinstance(items, list):
        return record
    for item in items:
        if not isinstance(item, dict):
            continue
        itype = str(item.get("type") or "").lower()
        context = str(item.get("context") or "")
        value = item.get("value")
        if value in (None, "", [], {}):
            continue
        sval = str(value)
        if itype == "ip":
            record["ips"].append(sval)
        elif itype == "host":
            record["hosts"].append(sval)
        elif itype.startswith("port-"):
            record["ports"].append({"port": sval, "transport": itype.replace("port-", "")})
        elif itype in {"protocol"}:
            record["protocols"].append(sval)
        elif itype in {"server-banner", "banner"}:
            record["banners"].append({"protocol": context, "value": sval})
        elif itype == "title":
            record["titles"].append(sval)
        elif itype == "url":
            record["urls"].append(sval)
        elif itype in {"issuer", "subject"}:
            record["certificates"].append({"field": itype, "value": sval})
        elif itype == "obj-sha1":
            record["body_hashes"].append(sval)
            record["fingerprints"].setdefault("content_sha1", []).append(sval)
        elif "favicon" in itype or itype in {"murmur3"}:
            record["fingerprints"].setdefault(itype, []).append(sval)
        elif itype.startswith("ja4scan"):
            record["fingerprints"].setdefault("ja4", []).append(sval)
        elif itype.startswith("ja4tscan"):
            record["fingerprints"].setdefault("ja4t", []).append(sval)
        elif itype.startswith("jarm"):
            record["fingerprints"].setdefault("jarm", []).append(sval)
    for key in ("hosts", "ips", "protocols", "urls", "titles", "body_hashes"):
        record[key] = list(dict.fromkeys(record[key]))
    record["ports"] = _dt_unique(record["ports"])
    record["certificates"] = _dt_unique(record["certificates"])
    record["fingerprints"] = {k: list(dict.fromkeys(v)) for k, v in record["fingerprints"].items()}
    if record["hosts"]:
        record["host"] = record["hosts"][0]
    if record["ips"]:
        record["ip"] = record["ips"][0]
    if record["ports"]:
        record["port"] = record["ports"][0].get("port")
        record["transport"] = record["ports"][0].get("transport")
    if record["protocols"]:
        record["protocol"] = record["protocols"][0]
    return record

def normalize_driftnet_reports(raw: Any, dataset: str = "") -> Dict[str, Any]:
    reports = []
    for entry in _dt_list(raw):
        if isinstance(entry, dict) and isinstance(entry.get("items"), list):
            reports.append(normalize_driftnet_report(entry, dataset))
        elif isinstance(entry, dict):
            reports.append(entry)
    meta = {}
    if isinstance(raw, dict):
        for key in ("page", "pages", "result_count", "count", "next_page"):
            if key in raw:
                meta[key] = raw.get(key)
    return {"dataset": dataset, "meta": meta, "results": reports}

def normalize_driftnet_ports(raw: Any) -> List[Dict[str, Any]]:
    values = raw.get("values") if isinstance(raw, dict) else raw
    rows = []
    if isinstance(values, dict):
        for port, value in values.items():
            if isinstance(value, dict):
                row = {"port": port, **value}
            else:
                row = {"port": port, "count": value}
            rows.append(row)
    elif isinstance(values, list):
        rows = [v for v in values if isinstance(v, dict)]
    return sorted(rows, key=lambda r: int(str(r.get("port", "0")).split("/", 1)[0]) if str(r.get("port", "0")).split("/", 1)[0].isdigit() else 0)

def normalize_driftnet_whois(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("error"):
        return {}
    wanted = (
        "domain", "created", "updated", "expires", "registrar", "nameservers",
        "dnssec", "status", "registrant", "admin", "tech", "billing",
        "net", "org", "as", "as_number", "asn", "cidr", "route", "country",
        "registry", "name", "description", "emails", "pocs", "results",
    )
    out = {k: raw.get(k) for k in wanted if raw.get(k) not in (None, "", [], {})}
    if not out and _dt_list(raw):
        out["results"] = _dt_list(raw)
    return out

def _dt_add_relationship(rels: List[Dict[str, Any]], source: str, relation: str, target: str, target_type: str, observed: str = "", evidence: str = "") -> None:
    if not source or not target:
        return
    row = {"source": source, "relation": relation, "target": target, "target_type": target_type}
    if observed:
        row["observed"] = observed
    if evidence:
        row["evidence"] = evidence
    if row not in rels:
        rels.append(row)

def _dt_dns_relationships(indicator: str, query_type: str, raw: Any, dataset: str, rels: List[Dict[str, Any]]) -> None:
    for report in _dt_list(raw):
        if not isinstance(report, dict):
            continue
        date = str(report.get("date") or report.get("first_seen") or report.get("last_seen") or "")
        hosts, ips, mx, ns, ptr = [], [], [], [], []
        for item in report.get("items", []) if isinstance(report.get("items"), list) else [report]:
            if not isinstance(item, dict):
                continue
            itype = str(item.get("type") or "").lower()
            context = str(item.get("context") or "").lower()
            value = str(item.get("value") or item.get("host") or item.get("ip") or item.get("domain") or item.get("target") or "")
            if not value:
                continue
            if itype == "ip" or is_ip(normalize_ip(value)):
                ips.append(value)
            elif "mx" in context or itype in {"mx", "dns-mx"}:
                mx.append(value)
            elif "ptr" in context or itype in {"ptr", "dns-ptr"}:
                ptr.append(value)
            elif "ns" in context or itype in {"ns", "dns-ns", "nameserver"}:
                ns.append(value)
            elif itype == "host" or is_domain(normalize_domain(value)):
                hosts.append(value)
        if query_type == "domain":
            for ip in ips:
                _dt_add_relationship(rels, indicator, "resolves_to", ip, "ip", date, dataset)
            for host in ns:
                _dt_add_relationship(rels, indicator, "uses_nameserver", host, "domain", date, dataset)
            for host in mx:
                _dt_add_relationship(rels, indicator, "uses_mail_server", host, "domain", date, dataset)
        else:
            for host in hosts:
                _dt_add_relationship(rels, indicator, "historically_resolved_by", host, "domain", date, dataset)
            for host in ptr:
                _dt_add_relationship(rels, indicator, "reverse_resolves_to", host, "domain", date, dataset)

def _dt_scan_relationships(indicator: str, query_type: str, reports: List[Dict[str, Any]], rels: List[Dict[str, Any]], dataset: str) -> None:
    for report in reports:
        date = str(report.get("date") or "")
        ips = report.get("ips") or []
        hosts = report.get("hosts") or []
        ports = report.get("ports") or []
        protocols = report.get("protocols") or []
        for ip in ips:
            if query_type == "domain":
                _dt_add_relationship(rels, indicator, "observed_on", ip, "ip", date, dataset)
        for host in hosts:
            if query_type == "ip":
                _dt_add_relationship(rels, indicator, "served_hostname", host, "domain", date, dataset)
        for port in ports:
            p = str(port.get("port") or "")
            if p:
                _dt_add_relationship(rels, report.get("ip") or indicator, "exposes_service", p, "port", date, dataset)
        for fp_kind, values in (report.get("fingerprints") or {}).items():
            for value in values:
                _dt_add_relationship(rels, report.get("ip") or indicator, "observed_with", value, fp_kind, date, dataset)
        for proto in protocols:
            _dt_add_relationship(rels, report.get("ip") or indicator, "observed_protocol", proto, "protocol", date, dataset)

def normalize_driftnet_result(indicator: str, query_type: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
    norm: Dict[str, Any] = {"kind": query_type, "indicator": indicator, "relationships": []}
    rels = norm["relationships"]
    report_datasets = {
        "protocol_scans": "Internet Scans",
        "domain_scans": "Domain Scans",
        "ct_log": "Certificate Transparency",
        "favicons": "Favicon Fingerprints",
        "ja4": "JA4Scan",
        "ja4t": "JA4TScan",
        "jarm": "JARM",
        "fdns": "Forward DNS",
        "fdns_reverse": "Forward DNS Reverse",
        "rdns": "Reverse DNS",
        "mx": "MX DNS",
        "txt": "TXT DNS",
        "body_matches": "HTTP Body Search",
    }
    for key, label in report_datasets.items():
        if raw_results.get(key) is not None and not (isinstance(raw_results.get(key), dict) and raw_results[key].get("error")):
            norm[key] = normalize_driftnet_reports(raw_results[key], label)
            _dt_scan_relationships(indicator, query_type, norm[key].get("results", []), rels, label)
            if key in {"fdns", "fdns_reverse", "rdns", "mx", "txt"}:
                _dt_dns_relationships(indicator, query_type, raw_results[key], label, rels)
    for key in ("ports", "ip_ports"):
        if raw_results.get(key) is not None and not (isinstance(raw_results.get(key), dict) and raw_results[key].get("error")):
            norm[key] = normalize_driftnet_ports(raw_results[key])
            for row in norm[key]:
                _dt_add_relationship(rels, indicator, "exposes_service", str(row.get("port") or ""), "port", "", key)
    for key in ("whois", "ip_whois", "ip_whois_pocs", "bgp_whois", "rwhois", "routes", "domain_reverse", "ip_reverse"):
        if raw_results.get(key) is not None and not (isinstance(raw_results.get(key), dict) and raw_results[key].get("error")):
            norm[key] = normalize_driftnet_whois(raw_results[key])
    bgp = norm.get("bgp_whois") or {}
    asn = (bgp.get("as") or {}).get("as_number") if isinstance(bgp.get("as"), dict) else bgp.get("as_number") or bgp.get("asn")
    cidr = bgp.get("cidr") or bgp.get("route")
    if asn:
        _dt_add_relationship(rels, indicator, "belongs_to_asn", str(asn), "asn", "", "BGP WHOIS")
    if cidr:
        _dt_add_relationship(rels, indicator, "belongs_to_route", str(cidr), "cidr", "", "BGP WHOIS")
    norm["relationships"] = rels
    norm["empty"] = not any(k != "relationships" and _driftnet_has_data(v) for k, v in norm.items())
    return norm

def query_driftnet_dataset(dataset: str, indicator: str = "", query_type: str = "auto", api_key: str = "", page: int = 0,
                           most_recent: bool = True, summarize: str = "", from_date: str = "", to_date: str = "",
                           filter_value: str = "", expression: str = "") -> Dict[str, Any]:
    dset = (dataset or "protocols").strip().lower()
    path = DRIFTNET_DATASET_PATHS.get(dset)
    if not path:
        return {"error": "Unknown Driftnet dataset"}
    page = max(0, min(int(page or 0), 99))
    params: Dict[str, Any] = {"page": page}
    if most_recent and dset not in {"domain_whois", "ip_whois", "ip_pocs", "ip_pwhois", "routes", "rwhois", "domain_reverse", "ip_reverse"}:
        params["most_recent"] = "true"
    value = (indicator or "").strip()
    qtype = (query_type or "auto").strip().lower()
    if path in {"/domain/whois", "/domain/fdns", "/domain/mx", "/domain/txt", "/scan/domains"} and qtype in {"domain", "auto"} and value and is_domain(normalize_domain(value)):
        params["domain" if path == "/domain/whois" else "host"] = normalize_domain(value)
        if path == "/domain/whois":
            params["apex_domain"] = "true"
    elif path in {"/scan/protocols", "/scan/ports", "/scan/ipports", "/domain/fdns", "/domain/rdns", "/ip/whois", "/ip/whois/pocs", "/ip/pwhois", "/ip/rwhois", "/ip/rdns", "/ip/routes", "/scan/ja4scan", "/scan/ja4tscan", "/scan/jarm"} and value and (
        qtype in {"ip", "cidr"} or (qtype == "auto" and (is_ip(normalize_ip(value)) or "/" in value))
    ):
        params["ip"] = value
    elif path in {"/scan/favicons"} and qtype in {"md5", "sha1", "sha256", "murmur3"}:
        params[qtype] = value
    elif path in {"/scan/ja4scan", "/scan/ja4tscan", "/scan/jarm"} and value and qtype in {"ja4", "ja4t", "jarm", "hash"}:
        params["hash"] = value
    elif path in {"/domain/reverse", "/ip/reverse"} and value:
        params["phrase"] = value
    elif value or expression:
        params["expression"] = expression or build_driftnet_expression(value, qtype)
    if summarize:
        params["summarize"] = summarize[:80]
    if from_date:
        params["from"] = from_date[:32]
    if to_date:
        params["to"] = to_date[:32]
    if filter_value:
        params["filter"] = filter_value[:300]
    raw = _query_driftnet(path, api_key, params=params)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    normalized = normalize_driftnet_reports(raw, dset)
    return {"dataset": dset, "indicator": value, "query_type": qtype, "raw": raw, "normalized": normalized}

def query_driftnet_search(value: str, api_key: str = "", dataset: str = "protocols", query_type: str = "auto", page: int = 0,
                          most_recent: bool = True, summarize: str = "", from_date: str = "", to_date: str = "",
                          filter_value: str = "") -> Dict[str, Any]:
    return query_driftnet_dataset(dataset, value, query_type=query_type, api_key=api_key, page=page,
                                  most_recent=most_recent, summarize=summarize, from_date=from_date,
                                  to_date=to_date, filter_value=filter_value)

def query_driftnet_user(api_key: str = "") -> Dict[str, Any]:
    return _query_driftnet("/admin/user", api_key, params={}, cache_ttl=300)

def query_driftnet_keyword(keyword: str, api_key: str = "") -> Dict[str, Any]:
    calls = {
        "protocol_scans": lambda: query_driftnet_dataset("protocols", keyword, "keyword", api_key=api_key),
        "body_matches": lambda: query_driftnet_dataset("body", keyword, "keyword", api_key=api_key, most_recent=False),
        "domain_reverse": lambda: query_driftnet_dataset("domain_reverse", keyword, "keyword", api_key=api_key, most_recent=False),
        "ip_reverse": lambda: query_driftnet_dataset("ip_reverse", keyword, "keyword", api_key=api_key, most_recent=False),
        "ct_log": lambda: query_driftnet_dataset("ct", keyword, "domain", api_key=api_key, most_recent=False),
    }
    results = _collect_callables(calls, max_workers=5)
    provider_errors = {k: v for k, v in results.items() if isinstance(v, dict) and v.get("error")}
    raw = {k: (v.get("raw") if isinstance(v, dict) and "raw" in v else v) for k, v in results.items() if k not in provider_errors}
    norm = normalize_driftnet_result(keyword, "keyword", raw)
    return {"indicator": keyword, "query_type": "keyword", "data": raw, "normalized": norm, "provider_errors": provider_errors}

def query_driftnet_hash(file_hash: str, api_key: str = "") -> Dict[str, Any]:
    # Driftnet hash support is limited to infrastructure fingerprints, not
    # malware file hash reputation. This helper is kept for explicit favicon
    # pivots and is not exposed as a Hash Lookup source.
    qtype = "md5" if re.fullmatch(r"[a-fA-F0-9]{32}", file_hash or "") else "sha1" if re.fullmatch(r"[a-fA-F0-9]{40}", file_hash or "") else "sha256" if re.fullmatch(r"[a-fA-F0-9]{64}", file_hash or "") else "hash"
    return query_driftnet_dataset("favicons", file_hash, qtype, api_key=api_key)

def query_driftnet(indicator: str, query_type: str, api_key: str = "") -> Dict[str, Any]:
    calls: Dict[str, Any]
    if query_type == "domain":
        calls = {
            "whois": lambda: _query_driftnet("/domain/whois", api_key, {"domain": indicator, "apex_domain": "true"}),
            "fdns": lambda: _query_driftnet("/domain/fdns", api_key, {"host": indicator, "most_recent": "true"}),
            "mx": lambda: _query_driftnet("/domain/mx", api_key, {"host": indicator, "most_recent": "true"}),
            "txt": lambda: _query_driftnet("/domain/txt", api_key, {"host": indicator, "most_recent": "true"}),
            "domain_scans": lambda: _query_driftnet("/scan/domains", api_key, {"host": indicator, "indirect": "true", "most_recent": "true"}),
            "protocol_scans": lambda: _query_driftnet("/scan/protocols", api_key, {"expression": f"host:{indicator}", "host_in_url": "true", "most_recent": "true"}),
            "ct_log": lambda: _query_driftnet("/ct/log", api_key, {"expression": f"host:{indicator}", "page": 0}),
            "favicons": lambda: _query_driftnet("/scan/favicons", api_key, {"expression": f"host:{indicator}", "host_in_url": "true", "most_recent": "true"}),
        }
    elif query_type == "ip":
        calls = {
            "protocol_scans": lambda: _query_driftnet("/scan/protocols", api_key, {"ip": indicator, "indirect": "true", "most_recent": "true"}),
            "ports": lambda: _query_driftnet("/scan/ports", api_key, {"ip": indicator}),
            "ip_ports": lambda: _query_driftnet("/scan/ipports", api_key, {"ip": indicator}),
            "fdns_reverse": lambda: _query_driftnet("/domain/fdns", api_key, {"ip": indicator, "most_recent": "true"}),
            "rdns": lambda: _query_driftnet("/domain/rdns", api_key, {"ip": indicator, "most_recent": "true"}),
            "ip_whois": lambda: _query_driftnet("/ip/whois", api_key, {"ip": indicator}),
            "ip_whois_pocs": lambda: _query_driftnet("/ip/whois/pocs", api_key, {"ip": indicator}),
            "bgp_whois": lambda: _query_driftnet("/ip/pwhois", api_key, {"ip": indicator}),
            "rwhois": lambda: _query_driftnet("/ip/rwhois", api_key, {"ip": indicator}),
            "routes": lambda: _query_driftnet("/ip/routes", api_key, {"ip": indicator}),
            "ja4": lambda: _query_driftnet("/scan/ja4scan", api_key, {"ip": indicator, "most_recent": "true"}),
            "ja4t": lambda: _query_driftnet("/scan/ja4tscan", api_key, {"ip": indicator, "most_recent": "true"}),
            "jarm": lambda: _query_driftnet("/scan/jarm", api_key, {"ip": indicator, "most_recent": "true"}),
        }
    elif query_type in {"keyword", "infra"}:
        return query_driftnet_keyword(indicator, api_key)
    else:
        return {"error": "Invalid Driftnet query type"}

    results = _collect_callables(calls, max_workers=5)
    provider_errors = {k: v for k, v in results.items() if isinstance(v, dict) and v.get("error")}
    raw = {k: v for k, v in results.items() if k not in provider_errors}
    norm = normalize_driftnet_result(indicator, query_type, raw)
    return {"indicator": indicator, "query_type": query_type, "data": raw, "normalized": norm, "provider_errors": provider_errors}

URLSCAN_API_BASE = "https://urlscan.io/api/v1"
# Passive-only: MANTIS performs GET searches and GET result retrieval only.
# Submission (/scan/), rescan, upload or any active crawling is unreachable:
# no helper accepts an arbitrary endpoint and no POST/PUT/DELETE is issued.
URLSCAN_READ_PATHS = ("/search/", "/result/")
URLSCAN_ACTIVE_MARKERS = ("submit", "upload", "/scan/", "rescan", "reanalys", "detonat")
# Paid-only search areas (per official docs). Never queried; a 403 surfaces
# as an error and never triggers an active fallback.
URLSCAN_PAID_FIELDS = ("brand.", "content.", "dom.", "frames.", "image.", "labels",
                       "links.", "scanner.", "submitter.", "text.", "verdicts.",
                       "visible.", "websockets.")
_URLSCAN_CACHE: Dict[str, Any] = {}
_URLSCAN_CACHE_TTL = {"hit": 21600, "report": 86400, "miss": 3600}

def _urlscan_cache_get(key: str) -> Any:
    entry = _URLSCAN_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _URLSCAN_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _urlscan_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _URLSCAN_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _urlscan_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _urlscan_escape(value: str) -> str:
    """Escape a user value for embedding in a quoted Lucene term."""
    return (value or "").replace("\\", "\\\\").replace('"', '\\"').strip()

def _urlscan_get(path: str, api_key: str, params: Dict[str, Any] = None, timeout: int = 20, method: str = "GET") -> Any:
    lowered = (path or "").lower().split("?")[0]
    if (method or "GET").upper() != "GET":
        return {"error": "URLScan only permits GET retrieval (passive-only integration)"}
    for marker in URLSCAN_ACTIVE_MARKERS:
        if marker in lowered:
            return {"error": "URLScan active operation denied (passive-only integration)"}
    if not lowered.startswith(URLSCAN_READ_PATHS):
        return {"error": "URLScan endpoint not allowlisted (passive-only integration)"}
    if not api_key:
        return {"error": "No API Key provided"}
    # Documented auth; the key travels in a header and never appears in
    # errors, logs or normalized results.
    try:
        resp = requests.get(f"{URLSCAN_API_BASE}{path}", headers={"API-Key": api_key}, params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"error": "URLScan returned a malformed response"}
        if resp.status_code in {401, 403}:
            detail = ""
            try:
                body = resp.json()
                detail = str(body.get("message") or body.get("description") or "")
            except Exception:
                detail = ""
            suffix = f": {detail[:200]}" if detail else ""
            if resp.status_code == 403:
                return {"error": f"URLScan access denied (HTTP 403){suffix}. Paid-only capability; no active fallback attempted"}
            return {"error": f"URLScan authentication failure (HTTP 401){suffix}"}
        if resp.status_code == 404:
            return {"error": "Not Found"}
        if resp.status_code == 429:
            return {"error": "URLScan rate limit exceeded (HTTP 429)"}
        if 500 <= resp.status_code < 600:
            return {"error": f"URLScan provider error (HTTP {resp.status_code})"}
        return {"error": f"URLScan request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "URLScan request timeout"}
    except Exception as e:
        return {"error": f"URLScan request failed: {e}"}

def _urlscan_results(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, dict) and isinstance(raw.get("results"), list):
        return [x for x in raw["results"] if isinstance(x, dict)]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    return []

def _urlscan_brief(item: Dict[str, Any]) -> Dict[str, Any]:
    task = item.get("task") if isinstance(item.get("task"), dict) else {}
    page = item.get("page") if isinstance(item.get("page"), dict) else {}
    stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}
    verdicts = item.get("verdicts") if isinstance(item.get("verdicts"), dict) else {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
    files = item.get("files") if isinstance(item.get("files"), list) else []
    return {
        "uuid": task.get("uuid") or item.get("_id") or "",
        "time": task.get("time") or "",
        "task_url": task.get("url") or "",
        "task_domain": task.get("domain") or "",
        "task_apex": task.get("apexDomain") or "",
        "task_method": task.get("method") or "",
        "task_source": task.get("source") or "",
        "task_visibility": task.get("visibility") or "",
        "task_tags": task.get("tags") if isinstance(task.get("tags"), list) else [],
        "page_url": page.get("url") or "",
        "page_domain": page.get("domain") or "",
        "page_apex": page.get("apexDomain") or "",
        "page_ip": page.get("ip") or "",
        "page_asn": page.get("asn") or "",
        "page_asnname": page.get("asnname") or "",
        "page_country": page.get("country") or "",
        "page_server": page.get("server") or "",
        "page_status": page.get("status"),
        "page_title": page.get("title") or "",
        "page_mime": page.get("mimeType") or "",
        "result_url": item.get("result") or "",
        "screenshot_url": item.get("screenshot") or "",
        "malicious": overall.get("malicious") if isinstance(overall.get("malicious"), bool) else None,
        "stats": {"requests": stats.get("requests"), "uniq_ips": stats.get("uniqIPs"),
                  "uniq_countries": stats.get("uniqCountries"), "data_length": stats.get("dataLength")},
        "file_count": len(files),
    }

def _urlscan_match_kind(brief: Dict[str, Any], query: str, kind: str) -> str:
    q = (query or "").lower()
    if kind == "domain":
        if (brief.get("page_domain") or "").lower() == q:
            return "primary"
        if (brief.get("task_domain") or "").lower() == q:
            return "task"
        return "contacted"
    if kind == "ip":
        if (brief.get("page_ip") or "") == query:
            return "primary"
        return "contacted"
    if kind == "url":
        if (brief.get("task_url") or "") == query:
            return "task"
        if (brief.get("page_url") or "") == query:
            return "primary"
        return "contacted"
    return "match"

def normalize_urlscan_search(raw: Any, query: str, query_kind: str) -> Dict[str, Any]:
    briefs = [_urlscan_brief(x) for x in _urlscan_results(raw)]
    seen, unique = set(), []
    for brief in briefs:
        key = brief.get("uuid") or (brief.get("task_url"), brief.get("time"))
        if key and key not in seen:
            seen.add(key)
            unique.append(brief)
    groups: Dict[str, List[Dict[str, Any]]] = {"primary": [], "contacted": [], "task": [], "match": [], "file": []}
    for brief in unique:
        kind = _urlscan_match_kind(brief, query, query_kind)
        brief["match_kind"] = kind
        groups.setdefault(kind, []).append(brief)
    rels: List[Dict[str, Any]] = []
    seen_rel = set()

    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen_rel:
            seen_rel.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    for brief in unique:
        scan = brief.get("uuid") or brief.get("task_url") or query
        if brief.get("task_url"):
            add_rel(scan, "submitted_url", brief["task_url"], "url")
        if brief.get("page_url") and brief["page_url"] != brief.get("task_url"):
            add_rel(scan, "final_page", brief["page_url"], "url")
        if brief.get("page_domain"):
            add_rel(scan, "contacts", brief["page_domain"], "domain")
        if brief.get("page_ip"):
            add_rel(scan, "resolves_to", brief["page_ip"], "ip")
            if brief.get("page_domain"):
                add_rel(brief["page_domain"], "resolves_to", brief["page_ip"], "ip")
        if brief.get("page_asn"):
            add_rel(scan, "hosted_in", str(brief["page_asn"]), "asn")
        if brief.get("page_country"):
            add_rel(scan, "located_in", brief["page_country"], "country")
        if brief.get("page_server"):
            add_rel(scan, "uses_server", brief["page_server"], "server")
    return {
        "source": "URLScan",
        "query": query,
        "query_kind": query_kind,
        "total": (raw.get("total") if isinstance(raw, dict) and isinstance(raw.get("total"), int) else len(unique)),
        "scans": unique,
        "groups": {k: v for k, v in groups.items() if v},
        "relationships": rels,
    }

def normalize_urlscan_files(raw_item: Dict[str, Any], brief: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    files = []
    if isinstance(raw_item, dict) and isinstance(raw_item.get("files"), list):
        files = raw_item["files"]
    elif isinstance(raw_item, dict) and isinstance(raw_item.get("data"), dict) and isinstance(raw_item["data"].get("files"), list):
        files = raw_item["data"]["files"]
    for entry in files:
        if not isinstance(entry, dict):
            continue
        sha256 = entry.get("sha256") or ""
        out.append({
            "filename": entry.get("filename") or "",
            "filesize": entry.get("filesize"),
            "mime": entry.get("mimeType") or entry.get("mimeDescription") or "",
            "sha256": sha256,
            "state": entry.get("state") or "",
            "url": entry.get("url") or "",
            "scan_uuid": (brief or {}).get("uuid") or "",
            "page_url": (brief or {}).get("page_url") or "",
        })
    seen, uniq = set(), []
    for entry in out:
        key = entry["sha256"] or (entry["filename"], entry["url"])
        if key and key not in seen:
            seen.add(key)
            uniq.append(entry)
    return uniq

def _urlscan_search(query: str, api_key: str, size: int = 10) -> Any:
    try:
        size = max(1, min(int(size or 10), 100))
    except (TypeError, ValueError):
        size = 10
    cache_key = f"urlscan:search:{size}:{query}"
    cached = _urlscan_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _urlscan_get("/search/", api_key, {"q": query, "size": size})
    if _urlscan_is_error(raw):
        return raw
    _urlscan_cache_set(cache_key, raw, _URLSCAN_CACHE_TTL["hit"] if _urlscan_results(raw) else _URLSCAN_CACHE_TTL["miss"])
    return raw

def query_urlscan(indicator: str, query_type: str, api_key: str, size: int = 10) -> Dict[str, Any]:
    value = (indicator or "").strip()
    if not value:
        return {"error": "Empty URLScan query"}
    escaped = _urlscan_escape(value)
    if query_type == "domain":
        domain = normalize_domain(value).lower() or value.lower()
        escaped_domain = _urlscan_escape(domain)
        query = f'page.domain:"{escaped_domain}" OR domain:"{escaped_domain}" OR task.domain:"{escaped_domain}"'
        kind = "domain"
    elif query_type == "ip":
        ip = normalize_ip(value) or value
        escaped_ip = _urlscan_escape(ip)
        query = f'page.ip:"{escaped_ip}" OR ip:"{escaped_ip}"'
        kind = "ip"
    elif query_type == "url":
        query = f'task.url:"{escaped}" OR page.url:"{escaped}" OR task.url.keyword:"{escaped}" OR page.url.keyword:"{escaped}"'
        kind = "url"
    elif query_type == "downloaded_file":
        if get_hash_type(value) != "sha256":
            return {"error": "URLScan hash correlation requires a SHA-256 hash (unsupported hash type)"}
        return query_urlscan_hash(value, api_key, size=size)
    else:
        query = value
        kind = "custom"
    raw = _urlscan_search(query, api_key, size=size)
    if _urlscan_is_error(raw):
        return raw
    normalized = normalize_urlscan_search(raw, value if query_type != "domain" else (normalize_domain(value).lower() or value), kind)
    return {"results": _urlscan_results(raw), "total": normalized["total"], "normalized": normalized}

def query_urlscan_hash(file_hash: str, api_key: str, size: int = 10) -> Dict[str, Any]:
    """SHA256 historical correlation, kept separate by artifact type:
    downloaded files (files.sha256) vs HTTP responses (hash)."""
    value = (file_hash or "").strip().lower()
    if get_hash_type(value) != "sha256":
        return {"error": "URLScan hash correlation requires a SHA-256 hash (unsupported hash type)"}
    escaped = _urlscan_escape(value)
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_files = executor.submit(_urlscan_search, f'files.sha256:"{escaped}"', api_key, size)
        future_responses = executor.submit(_urlscan_search, f'hash:"{escaped}"', api_key, size)
        raw_files, raw_responses = future_files.result(), future_responses.result()
    if _urlscan_is_error(raw_files) and _urlscan_is_error(raw_responses):
        return raw_files
    normalized = normalize_urlscan_search(raw_files if not _urlscan_is_error(raw_files) else [], value, "file")
    normalized["query_kind"] = "hash"
    normalized["file_matches"] = [
        {**f, "match_kind": "downloaded_file"}
        for item in _urlscan_results(raw_files if not _urlscan_is_error(raw_files) else [])
        for f in normalize_urlscan_files(item, _urlscan_brief(item))
        if (f.get("sha256") or "").lower() == value
    ]
    normalized["response_matches"] = [
        {**_urlscan_brief(item), "match_kind": "http_response"}
        for item in _urlscan_results(raw_responses if not _urlscan_is_error(raw_responses) else [])
    ]
    rels = normalized.get("relationships", [])
    seen_rel = {(r["source"], r["relation"], r["target"]) for r in rels}
    for entry in normalized["file_matches"]:
        scan = entry.get("scan_uuid") or entry.get("page_url") or value
        if entry.get("page_url") and entry.get("url") and (scan, "downloads", entry["url"]) not in seen_rel:
            seen_rel.add((scan, "downloads", entry["url"]))
            rels.append({"source": scan, "relation": "downloads", "target": entry["url"], "target_type": "url"})
        if entry.get("url") and entry.get("sha256"):
            key = (entry["url"], "downloaded_from", entry["sha256"])
            if key not in seen_rel:
                seen_rel.add(key)
                rels.append({"source": entry["url"], "relation": "downloaded_from", "target": entry["sha256"], "target_type": "hash"})
    normalized["relationships"] = rels
    return {"normalized": normalized,
            "file_search": raw_files, "response_search": raw_responses}

def query_urlscan_downloaded_file(file_hash: str, api_key: str) -> Dict[str, Any]:
    if get_hash_type(file_hash) != "sha256":
        return {"error": "URLScan downloaded-file pivot requires a SHA-256 hash"}
    return query_urlscan_hash(file_hash, api_key)

def query_urlscan_result(uuid: str, api_key: str) -> Dict[str, Any]:
    """Lazy: retrieve ONE existing scan by UUID. Read-only; never submits."""
    value = (uuid or "").strip().lower()
    if not re.match(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", value):
        return {"error": "Invalid URLScan result UUID"}
    cache_key = f"urlscan:result:{value}"
    cached = _urlscan_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _urlscan_get(f"/result/{value}/", api_key)
    if _urlscan_is_error(raw):
        return raw
    result = {"uuid": value, "result": raw, "normalized": normalize_urlscan_detail(raw, value)}
    _urlscan_cache_set(cache_key, result, _URLSCAN_CACHE_TTL["report"])
    return result

def normalize_urlscan_detail(raw: Any, uuid: str) -> Dict[str, Any]:
    data = raw.get("data") if isinstance(raw, dict) and isinstance(raw.get("data"), dict) else (raw if isinstance(raw, dict) else {})
    task = raw.get("task") if isinstance(raw.get("task"), dict) else {}
    page = raw.get("page") if isinstance(raw.get("page"), dict) else {}
    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    lists = raw.get("lists") if isinstance(raw.get("lists"), dict) else {}
    tls = page.get("tls") if isinstance(page.get("tls"), dict) else {}
    cert = tls.get("certificate") if isinstance(tls.get("certificate"), dict) else {}
    normalized = {
        "source": "URLScan",
        "uuid": uuid,
        "task": {
            "url": task.get("url") or "",
            "domain": task.get("domain") or "",
            "apex": task.get("apexDomain") or "",
            "uuid": task.get("uuid") or uuid,
            "method": task.get("method") or "",
            "source": task.get("source") or "",
            "visibility": task.get("visibility") or "",
            "tags": task.get("tags") if isinstance(task.get("tags"), list) else [],
            "time": task.get("time") or "",
        },
        "page": {
            "url": page.get("url") or "",
            "domain": page.get("domain") or "",
            "apex": page.get("apexDomain") or "",
            "ip": page.get("ip") or "",
            "asn": page.get("asn") or "",
            "asnname": page.get("asnname") or "",
            "country": page.get("country") or "",
            "ptr": page.get("ptr") or "",
            "server": page.get("server") or "",
            "status": page.get("status"),
            "title": page.get("title") or "",
            "mime": page.get("mimeType") or "",
            "language": page.get("language") or "",
            "redirect": page.get("redirected") or "",
            "domain_age_days": page.get("domainAgeDays"),
            "tls_issuer": tls.get("issuer") or "",
            "tls_subject": tls.get("subject") or "",
            "tls_valid_from": tls.get("validFrom") or "",
            "tls_valid_to": tls.get("validTo") or "",
            "tls_cert_subject": cert.get("subject") or "",
            "tls_cert_issuer": cert.get("issuer") or "",
        },
        "stats": {
            "requests": stats.get("requests"),
            "uniq_ips": stats.get("uniqIPs"),
            "uniq_countries": stats.get("uniqCountries"),
            "data_length": stats.get("dataLength"),
        },
        "files": normalize_urlscan_files(data, {"uuid": uuid, "page_url": page.get("url") or ""}),
        "network": {"domains": [], "ips": [], "urls": []},
        "relationships": [],
    }
    contacted_domains = [str(x) for x in (lists.get("linkDomains") or []) if isinstance(x, str)]
    normalized["network"]["domains"] = list(dict.fromkeys(contacted_domains))[:50]
    ips = [str(x) for x in (lists.get("ips") or []) if isinstance(x, str)]
    normalized["network"]["ips"] = list(dict.fromkeys(ips))[:50]
    urls = [str(x) for x in (lists.get("linkURLs") or []) if isinstance(x, str)]
    normalized["network"]["urls"] = list(dict.fromkeys(urls))[:50]
    rels: List[Dict[str, Any]] = []
    seen_rel = set()

    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen_rel:
            seen_rel.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    scan = uuid
    task_url, page_url = normalized["task"]["url"], normalized["page"]["url"]
    if task_url:
        add_rel(scan, "submitted_url", task_url, "url")
    if page_url and page_url != task_url:
        add_rel(scan, "final_page", page_url, "url")
    if normalized["page"]["domain"] and normalized["page"]["ip"]:
        add_rel(normalized["page"]["domain"], "resolves_to", normalized["page"]["ip"], "ip")
    if normalized["page"]["asn"]:
        add_rel(scan, "hosted_in", str(normalized["page"]["asn"]), "asn")
    if normalized["page"]["country"]:
        add_rel(scan, "located_in", normalized["page"]["country"], "country")
    if normalized["page"]["server"]:
        add_rel(scan, "uses_server", normalized["page"]["server"], "server")
    if normalized["page"]["tls_issuer"]:
        add_rel(scan, "presents", normalized["page"]["tls_issuer"], "tls")
    for domain in normalized["network"]["domains"]:
        add_rel(scan, "contacts", domain, "domain")
    for ip in normalized["network"]["ips"]:
        add_rel(scan, "contacts", ip, "ip")
    for entry in normalized["files"]:
        if entry.get("url"):
            add_rel(scan, "downloads", entry["url"], "url")
        if entry.get("url") and entry.get("sha256"):
            add_rel(entry["url"], "downloaded_from", entry["sha256"], "hash")
    normalized["relationships"] = rels
    return normalized

def query_urlscan_keyword(keyword: str, api_key: str, size: int = 10) -> Dict[str, Any]:
    """Structured keyword correlation (filename / page title), Community-safe."""
    value = (keyword or "").strip()
    if not value:
        return {"error": "Empty URLScan keyword"}
    escaped = _urlscan_escape(value)
    raw = _urlscan_search(f'filename:"{escaped}" OR page.title:"{escaped}"', api_key, size=size)
    if _urlscan_is_error(raw):
        return raw
    normalized = normalize_urlscan_search(raw, value, "keyword")
    return {"results": _urlscan_results(raw), "total": normalized["total"], "normalized": normalized}

def query_urlscan_infra(query: str, api_key: str, size: int = 10) -> Dict[str, Any]:
    """Historical web-infrastructure correlation (not live scanning)."""
    value = (query or "").strip()
    if not value:
        return {"error": "Empty URLScan infrastructure query"}
    asn_match = re.match(r"^(?:AS)?(\d{1,10})$", value, re.IGNORECASE)
    if asn_match:
        search = f'asn:{asn_match.group(1)} OR page.asn:{asn_match.group(1)}'
    else:
        escaped = _urlscan_escape(value)
        search = f'server:"{escaped}" OR page.tlsIssuer:"{escaped}" OR asnname:"{escaped}"'
    raw = _urlscan_search(search, api_key, size=size)
    if _urlscan_is_error(raw):
        return raw
    normalized = normalize_urlscan_search(raw, value, "infra")
    return {"results": _urlscan_results(raw), "total": normalized["total"], "normalized": normalized}

HA_API_BASE = "https://www.hybrid-analysis.com/api/v2"
# Passive-only allowlist (verified against official API v2 docs). Only
# read-only search/report retrieval is reachable from MANTIS. Anything
# involving submission, upload, quick-scan, rescan/reanalysis or detonation
# is explicitly denied — there is no generic HA proxy.
HA_PASSIVE_GET_PREFIXES = ("/search/hash", "/report/")
HA_PASSIVE_POST_PATHS = ("/search/terms",)
HA_ACTIVE_MARKERS = ("submit", "upload", "quick-scan", "quick_scan", "rescan",
                     "reanalys", "detonat", "file-collection", "file_collection")
HA_SUPPORTED_HASHES = ("md5", "sha1", "sha256", "sha512")
# Historical sandbox intel is stable: searches 6h, report details 12h,
# empty results 1h. Expiry triggers another lookup, never reanalysis.
_HA_CACHE: Dict[str, Any] = {}
_HA_CACHE_TTL = {"hit": 21600, "report": 43200, "miss": 3600}

def _ha_cache_get(key: str) -> Any:
    entry = _HA_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _HA_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _ha_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _HA_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _ha_request(method: str, path: str, api_key: str, params: Dict[str, Any] = None,
                form: Dict[str, Any] = None, timeout: int = 20) -> Any:
    """Shared read-only HA request helper. Rejects anything outside the
    passive allowlist, most importantly all submission/scan/rescan paths."""
    lowered = (path or "").lower()
    for marker in HA_ACTIVE_MARKERS:
        if marker in lowered:
            return {"error": "Hybrid Analysis active operation denied (passive-only integration)"}
    method = (method or "GET").upper()
    allowed = ((method == "GET" and lowered.startswith(HA_PASSIVE_GET_PREFIXES))
               or (method == "POST" and lowered in HA_PASSIVE_POST_PATHS))
    # Binary artifact downloads are out of scope (metadata only).
    if "dropped-files" in lowered:
        return {"error": "Hybrid Analysis artifact download not supported (metadata only)"}
    if not allowed:
        return {"error": "Hybrid Analysis endpoint not allowlisted (passive-only integration)"}
    if not api_key:
        return {"error": "No API Key provided"}
    headers = {"api-key": api_key, "User-Agent": "Falcon Sandbox"}
    try:
        if method == "GET":
            resp = requests.get(f"{HA_API_BASE}{path}", headers=headers, params=params or {}, timeout=timeout)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            resp = requests.post(f"{HA_API_BASE}{path}", headers=headers, data=form or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"error": "Hybrid Analysis returned a malformed response"}
        if resp.status_code == 400:
            return {"error": "Hybrid Analysis rejected the request (HTTP 400)"}
        if resp.status_code in {401, 403}:
            return {"error": "Hybrid Analysis authentication failure (HTTP {})".format(resp.status_code)}
        if resp.status_code == 404:
            return {"error": "Not Found"}
        if resp.status_code == 410:
            return {"error": "Hybrid Analysis report unavailable for archives/containers (HTTP 410)"}
        if resp.status_code == 429:
            return {"error": "Hybrid Analysis rate limit exceeded (HTTP 429)"}
        if 500 <= resp.status_code < 600:
            return {"error": f"Hybrid Analysis provider error (HTTP {resp.status_code})"}
        return {"error": f"Hybrid Analysis request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "Hybrid Analysis request timeout"}
    except Exception as e:
        return {"error": f"Hybrid Analysis request failed: {e}"}

def _ha_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _ha_first_str(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""

def _ha_as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        return [value]
    return []

def _ha_pick_list(obj: Dict[str, Any], *keys: str) -> List[str]:
    out: List[str] = []
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
        elif isinstance(value, list):
            out.extend([str(v).strip() for v in value if isinstance(v, (str, int)) and str(v).strip()])
    return list(dict.fromkeys(out))

def normalize_ha_report_brief(item: Dict[str, Any]) -> Dict[str, Any]:
    """Light per-report normalization for search results (all environments
    preserved, never collapsed)."""
    if not isinstance(item, dict):
        return {}
    try:
        threat_score = int(item.get("threat_score", 0) or 0)
    except (TypeError, ValueError):
        threat_score = 0
    try:
        av_detect = int(item.get("av_detect", 0) or 0)
    except (TypeError, ValueError):
        av_detect = 0
    raw_verdict = str(item.get("verdict") or "").strip().lower()
    # Normalize: empty/none/unknown with score 0 is not informative
    verdict = raw_verdict if raw_verdict and raw_verdict not in {"none", "null", "nan"} else ""
    sha256 = item.get("sha256") or ""
    sha1 = item.get("sha1") or ""
    md5 = item.get("md5") or ""
    # Skip reports with no hash AND no verdict AND no score - they're placeholders
    if not sha256 and not sha1 and not md5 and not verdict and threat_score == 0:
        return {}
    return {
        "id": item.get("job_id") or item.get("id") or "",
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "environment_id": item.get("environment_id"),
        "environment": item.get("environment_description") or item.get("environment") or "",
        "verdict": verdict,
        "threat_score": threat_score,
        "av_detect": av_detect,
        "vx_family": item.get("vxfamily") or item.get("vx_family") or "",
        "filename": item.get("submit_name") or item.get("submitname") or item.get("filename") or "",
        "file_type": item.get("type") or item.get("filetype") or item.get("file_type") or "",
        "file_size": item.get("size") if isinstance(item.get("size"), int) else None,
        "analysis_time": item.get("analysis_start_time") or item.get("start_time") or "",
        "state": item.get("state") or "",
    }

def normalize_ha_search(raw: Any, query: str, query_kind: str) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {
        "source": "Hybrid Analysis",
        "query": query,
        "query_kind": query_kind,
        "sample": {"md5": "", "sha1": "", "sha256": "", "filename": "",
                   "file_type": "", "file_size": None, "mime_type": ""},
        "assessment": {"verdict": "", "threat_score": 0, "av_detect": 0, "vx_family": ""},
        "reports": [],
        "relationships": [],
    }
    items: List[Dict[str, Any]] = []
    if isinstance(raw, dict):
        for key in ("reports", "data", "results", "samples"):
            if isinstance(raw.get(key), list):
                items = [x for x in raw[key] if isinstance(x, dict)]
                break
        else:
            items = []
    elif isinstance(raw, list):
        items = [x for x in raw if isinstance(x, dict)]
    briefs = [normalize_ha_report_brief(x) for x in items]
    briefs = [b for b in briefs if b]
    normalized["reports"] = briefs
    if briefs:
        first = briefs[0]
        normalized["sample"] = {
            "md5": first.get("md5") or "",
            "sha1": first.get("sha1") or "",
            "sha256": first.get("sha256") or "",
            "filename": first.get("filename") or "",
            "file_type": first.get("file_type") or "",
            "file_size": first.get("file_size"),
            "mime_type": "",
        }
        best = max(briefs, key=lambda b: (b.get("threat_score") or 0))
        normalized["assessment"] = {
            "verdict": best.get("verdict") or "",
            "threat_score": best.get("threat_score") or 0,
            "av_detect": max((b.get("av_detect") or 0) for b in briefs),
            "vx_family": best.get("vx_family") or "",
        }
        rels: List[Dict[str, Any]] = []
        seen = set()
        anchor = first.get("sha256") or first.get("sha1") or first.get("md5") or query
        for brief in briefs:
            report_id = str(brief.get("id") or "")
            if report_id and (anchor, "has_report", report_id) not in seen:
                seen.add((anchor, "has_report", report_id))
                rels.append({"source": anchor, "relation": "has_report", "target": report_id, "target_type": "report"})
        normalized["relationships"] = rels
    return normalized

def query_hybrid_analysis(indicator: str, api_key: str) -> Dict[str, Any]:
    # Primary capability: does HA already have intel for this sample?
    # Read-only GET /search/hash (current endpoint; deprecated POST removed).
    file_hash = (indicator or "").strip().lower()
    hash_kind = get_hash_type(file_hash)
    if hash_kind not in HA_SUPPORTED_HASHES:
        return {"error": f"Unsupported hash type for Hybrid Analysis: {hash_kind or 'unknown'}"}
    cache_key = f"ha:hash:{file_hash}"
    cached = _ha_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _ha_request("GET", "/search/hash", api_key, params={"hash": file_hash})
    if _ha_is_error(raw):
        if raw.get("error") == "Not Found":
            result: Dict[str, Any] = {"reports": [], "normalized": normalize_ha_search([], file_hash, "hash")}
            _ha_cache_set(cache_key, result, _HA_CACHE_TTL["miss"])
            return result
        return raw
    items = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    result = {"reports": items, "normalized": normalize_ha_search(items, file_hash, "hash")}
    _ha_cache_set(cache_key, result, _HA_CACHE_TTL["hit"] if items else _HA_CACHE_TTL["miss"])
    return result

# Read-only POST /search/terms fields verified in official API v2 docs.
HA_TERMS_FIELDS = ("filename", "filetype", "env_id", "country", "verdict", "av_detect",
                   "vx_family", "tag", "port", "host", "domain", "url", "similar_to")

def query_ha_terms(field: str, value: str, api_key: str, limit: int = 25) -> Dict[str, Any]:
    """Correlate an indicator against EXISTING sandbox reports only.
    Never submits, rescans or detonates anything."""
    field = (field or "").strip().lower()
    value = (value or "").strip()
    if field not in HA_TERMS_FIELDS:
        return {"error": f"Unsupported Hybrid Analysis search field: {field or 'empty'}"}
    if not value:
        return {"error": "Empty Hybrid Analysis search value"}
    cache_key = f"ha:terms:{field}:{value.lower()}"
    cached = _ha_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _ha_request("POST", "/search/terms", api_key, form={field: value})
    if _ha_is_error(raw):
        if raw.get("error") == "Not Found":
            result = {"reports": [], "normalized": normalize_ha_search([], value, field)}
            _ha_cache_set(cache_key, result, _HA_CACHE_TTL["miss"])
            return result
        return raw
    items = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    items = items[:max(1, min(int(limit or 25), 50))]
    result = {"reports": items, "normalized": normalize_ha_search(items, value, field)}
    _ha_cache_set(cache_key, result, _HA_CACHE_TTL["hit"] if items else _HA_CACHE_TTL["miss"])
    return result

def query_ha_domain(domain: str, api_key: str) -> Dict[str, Any]:
    return query_ha_terms("domain", normalize_domain(domain), api_key)

def query_ha_ip(ip: str, api_key: str) -> Dict[str, Any]:
    return query_ha_terms("host", normalize_ip(ip), api_key)

def query_ha_url(url: str, api_key: str) -> Dict[str, Any]:
    return query_ha_terms("url", (url or "").strip(), api_key)

_HA_REPORT_ID_RE = None

def _ha_report_id(report_id: str) -> str:
    import re as _re
    global _HA_REPORT_ID_RE
    if _HA_REPORT_ID_RE is None:
        _HA_REPORT_ID_RE = _re.compile(r"^[A-Za-z0-9:_\-]{1,128}$")
    value = (report_id or "").strip()
    if not value or "\n" in value or "\r" in value or "/" in value:
        return ""
    if not _HA_REPORT_ID_RE.match(value):
        return ""
    return value

def _ha_detail_list(obj: Dict[str, Any], *keys: str) -> List[Dict[str, Any]]:
    for key in keys:
        value = obj.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []

def normalize_ha_network(summary: Dict[str, Any]) -> Dict[str, Any]:
    network: Dict[str, Any] = {"domains": [], "ips": [], "urls": [], "ports": [], "protocols": []}
    if not isinstance(summary, dict):
        return network
    candidates: List[Dict[str, Any]] = []
    for key in ("network", "network_info", "traffic", "connections", "hosts"):
        value = summary.get(key)
        if isinstance(value, dict):
            candidates.append(value)
        elif isinstance(value, list):
            candidates.extend([x for x in value if isinstance(x, dict)])
    domains, ips, urls, ports, protocols = [], [], [], [], []
    host_lists = _ha_pick_list(summary, "hosts", "contacted_hosts", "ips", "ip_addresses")
    for key in ("hosts", "contacted_hosts", "ips", "ip_addresses"):
        for container in candidates:
            host_lists.extend(_ha_pick_list(container, key))
    for host in host_lists:
        base = host.split(":")[0].strip("[]")
        if is_ip(base):
            ips.append(base)
            if ":" in host and host.rsplit(":", 1)[1].isdigit():
                ports.append(host.rsplit(":", 1)[1])
        elif "." in host:
            domains.append(host.split(":")[0].split("/")[0])
    for key in ("domains", "contacted_domains", "dns", "dns_requests"):
        for container in candidates:
            domains.extend(_ha_pick_list(container, key))
    domains.extend(_ha_pick_list(summary, "domains", "contacted_domains"))
    for key in ("urls", "contacted_urls", "http_requests", "http", "requests"):
        for container in candidates:
            for item in ([container.get(key)] if isinstance(container.get(key), str) else (container.get(key) or [])):
                if isinstance(item, str) and item.strip():
                    urls.append(item.strip())
                elif isinstance(item, dict):
                    for ukey in ("url", "uri", "request", "host"):
                        if isinstance(item.get(ukey), str) and item[ukey].strip():
                            urls.append(item[ukey].strip())
                            break
    urls.extend(_ha_pick_list(summary, "urls", "contacted_urls"))
    for container in candidates:
        for pkey in ("ports", "dst_ports", "destination_ports"):
            value = container.get(pkey)
            if isinstance(value, list):
                ports.extend([str(v) for v in value if str(v).isdigit()])
        for prkey in ("protocols", "proto"):
            value = container.get(prkey)
            if isinstance(value, list):
                protocols.extend([str(v) for v in value if str(v).strip()])
            elif isinstance(value, str) and value.strip():
                protocols.append(value.strip())
    dedupe = lambda seq: list(dict.fromkeys([s for s in seq if s]))
    return {"domains": dedupe(domains)[:50], "ips": dedupe(ips)[:50], "urls": dedupe(urls)[:50],
            "ports": dedupe(ports)[:20], "protocols": dedupe(protocols)[:20]}

def normalize_ha_behavior(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(summary, dict):
        return out
    for key in ("signatures", "behavior", "behaviors", "indicators", "analysis_indicators"):
        for sig in _ha_detail_list(summary, key):
            out.append({
                "id": str(sig.get("identifier") or sig.get("id") or ""),
                "name": sig.get("name") or sig.get("description") or sig.get("title") or "",
                "description": sig.get("description") or "",
                "category": sig.get("category") or "",
                "classification": sig.get("threat_level_readable") or sig.get("threat_level") or sig.get("classification") or "",
                "relevance": sig.get("relevance") if sig.get("relevance") is not None else "",
            })
    seen, uniq = set(), []
    for sig in out:
        key = (sig["id"], sig["name"])
        if key not in seen and (sig["id"] or sig["name"]):
            seen.add(key)
            uniq.append(sig)
    return uniq[:50]

def normalize_ha_mitre(summary: Dict[str, Any], behavior: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    def add(technique_id: str, name: str, tactic: str) -> None:
        technique_id = (technique_id or "").strip().upper()
        if not technique_id or technique_id in seen:
            return
        seen.add(technique_id)
        out.append({"technique_id": technique_id, "name": name or "", "tactic": tactic or ""})
    if isinstance(summary, dict):
        for key in ("mitre_attcks", "mitre", "attack", "ttps"):
            for entry in _ha_detail_list(summary, key):
                add(str(entry.get("attck_id") or entry.get("technique_id") or entry.get("id") or ""),
                    str(entry.get("attck_name") or entry.get("technique") or entry.get("name") or ""),
                    str(entry.get("tactic") or ""))
                text = " ".join([str(entry.get(k) or "") for k in ("description", "signature", "name")])
                for match in re.finditer(r"T\d{4}(?:\.\d{3})?", text):
                    add(match.group(0), "", "")
    for sig in behavior:
        text = " ".join([str(sig.get("name") or ""), str(sig.get("description") or ""), str(sig.get("id") or "")])
        for match in re.finditer(r"T\d{4}(?:\.\d{3})?", text.upper()):
            add(match.group(0), "", "")
    return out[:50]

def normalize_ha_processes(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(summary, dict):
        return out
    for key in ("processes", "process_list", "extracted_processes"):
        for proc in _ha_detail_list(summary, key):
            try:
                pid = int(proc.get("pid") or proc.get("process_id") or 0) or None
            except (TypeError, ValueError):
                pid = None
            try:
                ppid = int(proc.get("ppid") or proc.get("parent_id") or 0) or None
            except (TypeError, ValueError):
                ppid = None
            out.append({
                "name": proc.get("name") or proc.get("process_name") or proc.get("image") or "",
                "pid": pid,
                "ppid": ppid,
                "command_line": proc.get("command_line") or proc.get("cmd") or "",
                "image": proc.get("image") or proc.get("path") or "",
            })
    seen, uniq = set(), []
    for proc in out:
        key = (proc["name"], proc["pid"], proc["command_line"])
        if key not in seen and (proc["name"] or proc["command_line"]):
            seen.add(key)
            uniq.append(proc)
    return uniq[:50]

def normalize_ha_dropped(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(summary, dict):
        return out
    for key in ("extracted_files", "dropped_files", "dropped", "files_extracted", "artifacts"):
        for entry in _ha_detail_list(summary, key):
            hashes = {"md5": entry.get("md5") or "", "sha1": entry.get("sha1") or "", "sha256": entry.get("sha256") or ""}
            out.append({
                "filename": entry.get("name") or entry.get("filename") or entry.get("file") or "",
                "path": entry.get("path") or entry.get("filepath") or "",
                "size": entry.get("size") if isinstance(entry.get("size"), int) else None,
                "file_type": entry.get("type") or entry.get("filetype") or "",
                **hashes,
            })
    seen, uniq = set(), []
    for entry in out:
        key = (entry["sha256"] or entry["sha1"] or entry["md5"] or entry["filename"])
        if key and key not in seen:
            seen.add(key)
            uniq.append(entry)
    return uniq[:50]

def normalize_ha_report_detail(summary: Any, state: Any, report_id: str) -> Dict[str, Any]:
    summary = summary if isinstance(summary, dict) else {}
    behavior = normalize_ha_behavior(summary)
    network = normalize_ha_network(summary)
    mitre = normalize_ha_mitre(summary, behavior)
    processes = normalize_ha_processes(summary)
    dropped = normalize_ha_dropped(summary)
    children: List[Dict[str, Any]] = []
    for source in (state if isinstance(state, dict) else {}, summary):
        for key in ("children", "child_reports", "related_reports", "related"):
            for child in _ha_detail_list(source, key):
                child_id = str(child.get("job_id") or child.get("id") or "")
                if child_id:
                    children.append({"id": child_id,
                                     "verdict": child.get("verdict") or "",
                                     "threat_score": child.get("threat_score") or 0})
    seen, uniq_children = set(), []
    for child in children:
        if child["id"] not in seen:
            seen.add(child["id"])
            uniq_children.append(child)
    anchor = summary.get("sha256") or report_id
    rels: List[Dict[str, Any]] = []
    seen_rel = set()
    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen_rel:
            seen_rel.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})
    for domain in network["domains"]:
        add_rel(anchor, "contacts", domain, "domain")
    for ip in network["ips"]:
        add_rel(anchor, "contacts", ip, "ip")
    for url in network["urls"]:
        add_rel(anchor, "accesses", url, "url")
    for port in network["ports"]:
        add_rel(anchor, "connects_to", port, "port")
    for entry in dropped:
        child_hash = entry.get("sha256") or entry.get("sha1") or entry.get("md5") or ""
        add_rel(anchor, "drops", child_hash, "hash")
    for ttp in mitre:
        add_rel(anchor, "uses_technique", ttp["technique_id"], "attack_id")
    for child in uniq_children:
        add_rel(report_id, "related_report", child["id"], "report")
    return {
        "source": "Hybrid Analysis",
        "report_id": report_id,
        "sample": {"sha256": summary.get("sha256") or "", "sha1": summary.get("sha1") or "",
                   "md5": summary.get("md5") or "", "filename": summary.get("submit_name") or summary.get("submitname") or ""},
        "assessment": {"verdict": summary.get("verdict") or "", "threat_score": summary.get("threat_score") or 0,
                       "av_detect": summary.get("av_detect") or 0, "vx_family": summary.get("vxfamily") or summary.get("vx_family") or ""},
        "network": network,
        "behavior": behavior,
        "mitre": mitre,
        "processes": processes,
        "dropped_files": dropped,
        "related_reports": uniq_children,
        "relationships": rels,
    }

def query_ha_report(report_id: str, api_key: str) -> Dict[str, Any]:
    """Lazy: retrieve ONE existing report summary (+ state for children).
    Read-only; never submits or rescans."""
    validated = _ha_report_id(report_id)
    if not validated:
        return {"error": "Invalid Hybrid Analysis report ID"}
    cache_key = f"ha:report:{validated}"
    cached = _ha_cache_get(cache_key)
    if cached is not None:
        return cached
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_summary = executor.submit(_ha_request, "GET", f"/report/{validated}/summary", api_key)
        future_state = executor.submit(_ha_request, "GET", f"/report/{validated}/state", api_key)
        summary, state = future_summary.result(), future_state.result()
    if _ha_is_error(summary) and _ha_is_error(state):
        return summary
    result: Dict[str, Any] = {"report_id": validated, "summary": summary if not _ha_is_error(summary) else {},
                               "state": state if not _ha_is_error(state) else {},
                               "normalized": normalize_ha_report_detail(summary, state, validated)}
    _ha_cache_set(cache_key, result, _HA_CACHE_TTL["report"])
    return result

def query_shodan(ip: str, api_key: str) -> Dict[str, Any]:
    return query_shodan_ip(ip, api_key)

SHODAN_API_BASE = "https://api.shodan.io"
SHODAN_HOST_FIELDS = (
    "ip_str,port,transport,org,isp,asn,hostnames,domains,timestamp,product,version,"
    "cpe,os,tags,cloud.provider,cloud.region,cloud.service,location.country_code,location.country_name,location.city,"
    "ssl.cert.subject.cn,ssl.cert.issuer.cn,ssl.cert.serial,ssl.cert.fingerprint.sha256,ssl.cert.fingerprint.sha1,"
    "ssl.jarm,ssl.cert.names,ssl.version,ssl.alpn,http.title,http.server,http.favicon.hash,http.html_hash,http.components,http.status,"
    "vulns,data,_shodan.module,devicetype,info"
)
SHODAN_FACETS = "country:10,org:10,asn:10,port:10,product:10,os:10,cloud.provider:10,tag:10"
SHODAN_READ_PREFIXES = (
    "/shodan/host/search",
    "/shodan/host/count",
    "/shodan/host/search/filters",
    "/shodan/host/search/facets",
    "/shodan/host/search/tokens",
    "/dns/domain/",
    "/dns/resolve",
    "/dns/reverse",
)
SHODAN_DENY_MARKERS = (
    "/shodan/scan", "/shodan/alert", "/notifier", "/monitor", "/org", "/account",
    "/shodan/protocols", "/shodan/ports", "/tools/", "/labs/", "/scan",
)
_SHODAN_CACHE: Dict[str, Any] = {}
_SHODAN_CACHE_TTL = {"host": 21600, "history": 86400, "search": 1800, "count": 1800, "metadata": 86400}

def _shodan_key(_api_key: str = "") -> str:
    return (os.environ.get("SHODAN_API_KEY") or os.environ.get("MANTIS_SHODAN_KEY") or os.environ.get("IOCINTEL_SHODAN_KEY") or (_api_key or "").strip() or "").strip()

def _shodan_cache_get(key: str) -> Any:
    entry = _SHODAN_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _SHODAN_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _shodan_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _SHODAN_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _shodan_sanitize_error(message: str, api_key: str = "") -> str:
    text = str(message or "")
    if api_key:
        text = text.replace(api_key, "[redacted]")
    text = re.sub(r"([?&]key=)[^&\s'\"]+", r"\1[redacted]", text, flags=re.IGNORECASE)
    return text[:200]

def _shodan_allowed_path(path: str) -> bool:
    clean = (path or "").split("?", 1)[0]
    lowered = clean.lower()
    if any(marker in lowered for marker in SHODAN_DENY_MARKERS):
        return False
    if re.match(r"^/shodan/host/[0-9a-f:.%]+$", lowered):
        return True
    return any(lowered == prefix or lowered.startswith(prefix) for prefix in SHODAN_READ_PREFIXES)

def _query_shodan(path: str, api_key: str, params: Dict[str, Any] = None,
                  cache_ttl: int = 1800) -> Dict[str, Any]:
    if not _shodan_allowed_path(path):
        return {"error": "Shodan endpoint not allowlisted (passive-only integration)"}
    api_key = _shodan_key(api_key)
    if not api_key:
        return {"error": "No Shodan API key configured on server"}
    all_params = dict(params or {})
    all_params["key"] = api_key
    safe_params = {k: v for k, v in all_params.items() if k != "key"}
    cache_key = f"shodan:{path}:{urllib.parse.urlencode(sorted(safe_params.items()), doseq=True)}"
    cached = _shodan_cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        resp = requests.get(f"{SHODAN_API_BASE}{path}", params=all_params, timeout=25)
        if resp.status_code == 200:
            try:
                result = resp.json()
            except ValueError:
                result = {"error": "Shodan returned malformed JSON"}
        elif resp.status_code == 404:
            result = {"error": "Not Found"}
        elif resp.status_code in {401, 403}:
            result = {"error": f"Shodan authentication or plan failure (HTTP {resp.status_code})"}
        elif resp.status_code == 429:
            result = {"error": "Shodan rate or credit limit exceeded"}
        elif 500 <= resp.status_code < 600:
            result = {"error": f"Shodan provider error (HTTP {resp.status_code})"}
        else:
            result = {"error": f"Shodan request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        result = {"error": "Shodan request timeout"}
    except Exception as e:
        result = {"error": f"Shodan request failed: {_shodan_sanitize_error(str(e), api_key)}"}
    _shodan_cache_set(cache_key, result, cache_ttl)
    return result

def _shodan_text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) and str(value).strip() else ""

def _shodan_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
    text = _shodan_text(value)
    return [text] if text else []

def _shodan_nested(data: Dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current

def normalize_shodan_http(entry: Dict[str, Any]) -> Dict[str, Any]:
    http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
    favicon = http.get("favicon") if isinstance(http.get("favicon"), dict) else {}
    return {
        "title": _shodan_text(http.get("title") or entry.get("http.title")),
        "server": _shodan_text(http.get("server") or entry.get("http.server")),
        "host": _shodan_text(http.get("host") or entry.get("http.host")),
        "status": _shodan_text(http.get("status") or http.get("status_code") or entry.get("http.status")),
        "html_hash": _shodan_text(http.get("html_hash") or entry.get("http.html_hash")),
        "favicon_hash": _shodan_text(favicon.get("hash") or entry.get("http.favicon.hash")),
        "redirects": http.get("redirects") if isinstance(http.get("redirects"), list) else [],
        "components": list((http.get("components") or {}).keys())[:25] if isinstance(http.get("components"), dict) else [],
        "robots_hash": _shodan_text(http.get("robots_hash")),
        "securitytxt_hash": _shodan_text(http.get("securitytxt_hash")),
    }

def normalize_shodan_ssl(entry: Dict[str, Any]) -> Dict[str, Any]:
    ssl = entry.get("ssl") if isinstance(entry.get("ssl"), dict) else {}
    cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
    subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
    issuer = cert.get("issuer") if isinstance(cert.get("issuer"), dict) else {}
    pubkey = cert.get("pubkey") if isinstance(cert.get("pubkey"), dict) else {}
    fp = cert.get("fingerprint") if isinstance(cert.get("fingerprint"), dict) else {}
    fp_sha256 = _shodan_text(fp.get("sha256") if isinstance(fp, dict) else cert.get("fingerprint") or entry.get("ssl.cert.fingerprint.sha256") or entry.get("ssl.cert.fingerprint"))
    fp_sha1 = _shodan_text(fp.get("sha1") if isinstance(fp, dict) else entry.get("ssl.cert.fingerprint.sha1"))
    jarm = _shodan_text(ssl.get("jarm") or entry.get("ssl.jarm") or entry.get("jarm") or ssl.get("ja3s"))
    alpn = _shodan_list(ssl.get("alpn") or entry.get("ssl.alpn"))
    return {
        "subject": {k: _shodan_text(v) for k, v in subject.items() if _shodan_text(v)} if subject else {"cn": _shodan_text(entry.get("ssl.cert.subject.cn"))},
        "issuer": {k: _shodan_text(v) for k, v in issuer.items() if _shodan_text(v)} if issuer else {"cn": _shodan_text(entry.get("ssl.cert.issuer.cn"))},
        "serial": _shodan_text(cert.get("serial") or entry.get("ssl.cert.serial")),
        "fingerprint_sha256": fp_sha256,
        "fingerprint_sha1": fp_sha1,
        "jarm": jarm,
        "alpn": alpn,
        "issued": _shodan_text(cert.get("issued")),
        "expires": _shodan_text(cert.get("expires")),
        "expired": cert.get("expired") if isinstance(cert.get("expired"), bool) else None,
        "version": _shodan_text(cert.get("version")),
        "cipher": _shodan_text(ssl.get("cipher", {}).get("name") if isinstance(ssl.get("cipher"), dict) else ssl.get("cipher")),
        "protocol": _shodan_text(ssl.get("tls_version") or ssl.get("version") or entry.get("ssl.version")),
        "names": _shodan_list(cert.get("names") or entry.get("ssl.cert.names"))[:50],
        "pubkey_type": _shodan_text(pubkey.get("type")),
        "pubkey_bits": pubkey.get("bits"),
    }

def normalize_shodan_vulns(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    out = []
    for cve, detail in value.items():
        if isinstance(detail, dict):
            out.append({
                "cve": str(cve).upper(),
                "cvss": detail.get("cvss"),
                "summary": _shodan_text(detail.get("summary")),
                "verified": detail.get("verified") if isinstance(detail.get("verified"), bool) else None,
            })
        else:
            out.append({"cve": str(cve).upper(), "cvss": None, "summary": "", "verified": None})
    return out[:100]

def normalize_shodan_service(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    shodan_meta = entry.get("_shodan") if isinstance(entry.get("_shodan"), dict) else {}
    http = normalize_shodan_http(entry)
    ssl = normalize_shodan_ssl(entry)
    cloud_raw = entry.get("cloud") if isinstance(entry.get("cloud"), dict) else {}
    cloud = {
        "provider": _shodan_text(cloud_raw.get("provider") or entry.get("cloud.provider")),
        "region": _shodan_text(cloud_raw.get("region") or entry.get("cloud.region")),
        "service": _shodan_text(cloud_raw.get("service") or entry.get("cloud.service")),
    }
    cloud = {k: v for k, v in cloud.items() if v}
    tags = _shodan_list(entry.get("tags"))
    service = {
        "ip": _shodan_text(entry.get("ip_str")),
        "port": entry.get("port"),
        "transport": _shodan_text(entry.get("transport")) or "tcp",
        "timestamp": _shodan_text(entry.get("timestamp")),
        "product": _shodan_text(entry.get("product")),
        "version": _shodan_text(entry.get("version")),
        "info": _shodan_text(entry.get("info")),
        "devicetype": _shodan_text(entry.get("devicetype") or entry.get("device")),
        "tags": tags[:20],
        "cloud": cloud,
        "cpe": _shodan_list(entry.get("cpe")),
        "module": _shodan_text(shodan_meta.get("module") or entry.get("_shodan.module")),
        "banner": _shodan_text(entry.get("data"))[:4000],
        "hostnames": _shodan_list(entry.get("hostnames"))[:50],
        "domains": _shodan_list(entry.get("domains"))[:50],
        "asn": _shodan_text(entry.get("asn")),
        "isp": _shodan_text(entry.get("isp")),
        "organization": _shodan_text(entry.get("org")),
        "os": _shodan_text(entry.get("os")),
        "location": entry.get("location") if isinstance(entry.get("location"), dict) else {},
        "http": {k: v for k, v in http.items() if v not in ("", [], {}, None)},
        "ssl": {k: v for k, v in ssl.items() if v not in ("", [], {}, None)},
        "vulnerabilities": normalize_shodan_vulns(entry.get("vulns")),
    }
    return service

def normalize_shodan_host(raw: Any, query_ip: str = "", history: bool = False) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("error"):
        return {"source": "Shodan", "kind": "host", "ip": query_ip, "services": [], "relationships": []}
    services = [normalize_shodan_service(x) for x in (raw.get("data") or [])]
    services = [s for s in services if s.get("port") is not None or s.get("banner")]
    seen_services, unique_services = set(), []
    for svc in services:
        key = (svc.get("ip") or raw.get("ip_str") or query_ip, svc.get("port"), svc.get("transport"), svc.get("timestamp"))
        if key not in seen_services:
            seen_services.add(key)
            unique_services.append(svc)
    ports = raw.get("ports") if isinstance(raw.get("ports"), list) else sorted({s.get("port") for s in unique_services if s.get("port") is not None})
    ip_value = _shodan_text(raw.get("ip_str") or query_ip)
    hostnames = _shodan_list(raw.get("hostnames"))[:100]
    domains = _shodan_list(raw.get("domains"))[:100]
    vulns = normalize_shodan_vulns(raw.get("vulns"))
    for svc in unique_services:
        for vuln in svc.get("vulnerabilities", []):
            if vuln not in vulns:
                vulns.append(vuln)
    relationships = []
    seen = set()

    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen:
            seen.add(key)
            relationships.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    asn = _shodan_text(raw.get("asn"))
    if asn and not asn.upper().startswith("AS"):
        asn = f"AS{asn}"
    add_rel(ip_value, "belongs_to", asn, "asn")
    add_rel(ip_value, "operated_by", _shodan_text(raw.get("org")), "organization")
    add_rel(ip_value, "provided_by", _shodan_text(raw.get("isp")), "isp")
    for hostname in hostnames:
        add_rel(ip_value, "reverse_resolves_to", hostname, "hostname")
    for domain in domains:
        for hostname in hostnames or [ip_value]:
            add_rel(hostname, "associated_with", domain, "domain")
    for svc in unique_services:
        service_id = f"{ip_value}:{svc.get('port')}/{svc.get('transport')}"
        add_rel(ip_value, "exposes", service_id, "service")
        add_rel(service_id, "runs", " ".join([svc.get("product", ""), svc.get("version", "")]).strip(), "product")
        for cpe in svc.get("cpe") or []:
            add_rel(service_id, "identified_as", cpe, "cpe")
        add_rel(service_id, "observed_at", svc.get("timestamp"), "timestamp")
        ssl = svc.get("ssl") or {}
        http = svc.get("http") or {}
        subject_cn = (ssl.get("subject") or {}).get("CN") or (ssl.get("subject") or {}).get("cn")
        issuer_cn = (ssl.get("issuer") or {}).get("CN") or (ssl.get("issuer") or {}).get("cn")
        add_rel(service_id, "presents_certificate_subject", subject_cn, "certificate_subject")
        add_rel(service_id, "presents_certificate_issuer", issuer_cn, "certificate_issuer")
        add_rel(service_id, "presents_certificate_serial", ssl.get("serial"), "certificate_serial")
        for name in ssl.get("names") or []:
            add_rel(service_id, "certificate_references", name, "domain")
        for vuln in svc.get("vulnerabilities", []):
            add_rel(service_id, "associated_with", vuln.get("cve"), "cve")
        if ssl.get("jarm"):
            add_rel(service_id, "exhibits_jarm_fingerprint", ssl.get("jarm"), "jarm")
        if svc.get("cloud", {}).get("provider"):
            add_rel(ip_value, "hosted_on_cloud", svc["cloud"]["provider"], "cloud_provider")
        for tag in svc.get("tags") or []:
            add_rel(ip_value, "tagged_as", tag, "tag")
        if http.get("favicon_hash"):
            add_rel(service_id, "serves_favicon_hash", http.get("favicon_hash"), "favicon_hash")
    return {
        "source": "Shodan",
        "kind": "host_history" if history else "host",
        "ip": ip_value,
        "last_update": _shodan_text(raw.get("last_update")),
        "hostnames": hostnames,
        "domains": domains,
        "ports": ports,
        "asn": asn,
        "isp": _shodan_text(raw.get("isp")),
        "organization": _shodan_text(raw.get("org")),
        "os": _shodan_text(raw.get("os")),
        "tags": _shodan_list(raw.get("tags"))[:50],
        "location": {
            "country": _shodan_text(raw.get("country_name") or _shodan_nested(raw, "location.country_name")),
            "country_code": _shodan_text(raw.get("country_code") or _shodan_nested(raw, "location.country_code")),
            "city": _shodan_text(raw.get("city") or _shodan_nested(raw, "location.city")),
            "region": _shodan_text(raw.get("region_code") or _shodan_nested(raw, "location.region_code")),
            "latitude": raw.get("latitude") if raw.get("latitude") is not None else _shodan_nested(raw, "location.latitude"),
            "longitude": raw.get("longitude") if raw.get("longitude") is not None else _shodan_nested(raw, "location.longitude"),
        },
        "services": unique_services,
        "vulnerabilities": vulns[:100],
        "semantics": {
            "label": "Internet Infrastructure Intelligence",
            "found_does_not_mean_malicious": True,
            "historical_observation_not_current_state": True,
            "cve_association_not_confirmed_exploitability": True,
        },
        "relationships": relationships,
    }

def normalize_shodan_search(raw: Any, query: str, page: int = 1) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("error"):
        return {"source": "Shodan", "kind": "search", "query": query, "page": page, "matches": [], "facets": {}, "total": 0, "relationships": []}
    matches = [normalize_shodan_service(x) for x in (raw.get("matches") or [])]
    matches = [m for m in matches if m.get("ip") or m.get("port")]
    seen, unique = set(), []
    for match in matches:
        key = (match.get("ip"), match.get("port"), match.get("transport"), match.get("timestamp"))
        if key not in seen:
            seen.add(key)
            unique.append(match)
    total = raw.get("total") if isinstance(raw.get("total"), int) else len(unique)
    relationships = []
    for match in unique[:100]:
        ip = match.get("ip") or ""
        service_id = f"{ip}:{match.get('port')}/{match.get('transport')}"
        if ip and match.get("port") is not None:
            relationships.append({"source": ip, "relation": "exposes", "target": service_id, "target_type": "service"})
    return {
        "source": "Shodan",
        "kind": "search",
        "query": query,
        "page": page,
        "total": total,
        "matches": unique,
        "facets": raw.get("facets") if isinstance(raw.get("facets"), dict) else {},
        "pagination": {"page": page, "per_page": 100, "has_more": bool(total > page * 100)},
        "credit_note": "Search can consume Shodan query credits when filters are used or page > 1.",
        "relationships": relationships,
    }

def normalize_shodan_count(raw: Any, query: str) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("error"):
        return {"source": "Shodan", "kind": "count", "query": query, "total": 0, "facets": {}}
    return {"source": "Shodan", "kind": "count", "query": query,
            "total": raw.get("total", 0), "facets": raw.get("facets") if isinstance(raw.get("facets"), dict) else {}}

SHODAN_SAFE_FILTERS = {
    "ip": "ip", "net": "net", "cidr": "net", "asn": "asn", "hostname": "hostname", "domain": "hostname",
    "port": "port", "product": "product", "version": "version", "cpe": "cpe",
    "org": "org", "isp": "isp", "country": "country", "city": "city", "state": "state", "os": "os",
    "tag": "tag", "tags": "tag", "device": "device", "devicetype": "device",
    "vuln": "vuln", "cve": "vuln", "has_vuln": "has_vuln", "has_ssl": "has_ssl", "has_ipv6": "has_ipv6",
    "has_screenshot": "has_screenshot",
    "http_title": "http.title", "title": "http.title", "http.title": "http.title",
    "favicon_hash": "http.favicon.hash", "favicon": "http.favicon.hash", "http.favicon.hash": "http.favicon.hash", "hash": "http.favicon.hash",
    "http_server": "http.server", "server": "http.server", "http.server": "http.server",
    "http_html": "http.html", "html": "http.html", "http.html": "http.html",
    "http.status": "http.status", "http.component": "http.component",
    "ssl_subject": "ssl.cert.subject.cn", "ssl_issuer": "ssl.cert.issuer.cn", "ssl_serial": "ssl.cert.serial",
    "ssl.cert.subject.cn": "ssl.cert.subject.cn", "ssl.cert.issuer.cn": "ssl.cert.issuer.cn", "ssl.cert.serial": "ssl.cert.serial",
    "ssl.cert.fingerprint": "ssl.cert.fingerprint", "ssl.cert.names": "ssl.cert.names",
    "ssl.version": "ssl.version", "ssl.alpn": "ssl.alpn", "ssl.cipher.name": "ssl.cipher.name",
    "ssl.jarm": "ssl.jarm", "jarm": "ssl.jarm",
    "cloud.provider": "cloud.provider", "cloud": "cloud.provider", "cloud.region": "cloud.region", "cloud.service": "cloud.service",
    "shodan_query": "",
}
SHODAN_ALLOWED_RAW_FILTERS = {
    "ip", "net", "asn", "hostname", "domain", "port", "product", "version", "cpe", "org", "isp",
    "country", "city", "state", "postal", "geo", "os", "tag", "tags", "devicetype", "device",
    "vuln", "cve", "has_vuln", "has_ssl", "has_screenshot", "has_ipv6",
    "ssl", "ssl.alpn", "ssl.version", "ssl.cipher.name", "ssl.cipher.bits",
    "ssl.cert.subject.cn", "ssl.cert.issuer.cn", "ssl.cert.serial", "ssl.cert.fingerprint", "ssl.cert.names",
    "ssl.jarm", "jarm",
    "http.title", "title", "http.html", "html", "http.html_hash", "http.status", "http.server", "server",
    "http.component", "http.component_category", "http.favicon.hash", "favicon_hash", "hash",
    "cloud.provider", "cloud.region", "cloud.service", "cloud",
    "snmp.name", "ssh.cipher", "ssh.mac", "ssh.type", "before", "after",
}

def _shodan_escape_value(value: str) -> str:
    cleaned = re.sub(r"[\r\n\t]", " ", str(value or "")).strip()
    cleaned = cleaned[:200]
    if not cleaned:
        return ""
    if re.search(r"\s|[:\"]", cleaned):
        return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return cleaned

def _shodan_raw_query_allowed(query: str) -> bool:
    value = (query or "").strip()
    if not value or len(value) > 500 or "\n" in value or "\r" in value:
        return False
    scan_value = re.sub(r'"(?:\\.|[^"\\])*"', '""', value)
    for match in re.finditer(r"([A-Za-z0-9_.-]+):", scan_value):
        filter_name = match.group(1).lower()
        if filter_name not in SHODAN_ALLOWED_RAW_FILTERS:
            return False
    return True

def build_shodan_query(value: str, query_type: str = "auto") -> str:
    raw = (value or "").strip()
    qtype = (query_type or "auto").strip().lower()
    if not raw or "\n" in raw or "\r" in raw:
        return ""
    if qtype in {"auto", "keyword", "infra"}:
        if _shodan_raw_query_allowed(raw) and re.search(r"[A-Za-z0-9_.-]+:", raw):
            return raw[:500]
        try:
            network = ipaddress.ip_network(raw, strict=False)
            if "/" in raw:
                return f"net:{network}"
        except ValueError:
            pass
        ip_candidate = normalize_ip(raw)
        if is_ip(ip_candidate):
            return f"ip:{ip_candidate}"
        if re.match(r"^AS\d{1,10}$", raw, re.IGNORECASE):
            return f"asn:{raw.upper()}"
        if re.match(r"^\d{1,5}$", raw):
            port = int(raw)
            if 0 < port <= 65535:
                return f"port:{port}"
        if ":" not in raw:
            domain = normalize_domain(raw)
            if is_domain(domain):
                return f"hostname:{domain}"
        if len(raw) == 2 and raw.isalpha():
            return f"country:{raw.upper()}"
        return _shodan_escape_value(raw)
    if qtype == "ip":
        ip_candidate = normalize_ip(raw)
        return f"ip:{ip_candidate}" if is_ip(ip_candidate) else ""
    if qtype in {"net", "cidr"}:
        try:
            return f"net:{ipaddress.ip_network(raw, strict=False)}"
        except ValueError:
            return ""
    if qtype == "asn":
        return f"asn:{raw.upper() if raw.upper().startswith('AS') else 'AS' + raw}" if re.match(r"^(?:AS)?\d{1,10}$", raw, re.IGNORECASE) else ""
    if qtype == "port":
        return f"port:{int(raw)}" if raw.isdigit() and 0 < int(raw) <= 65535 else ""
    if qtype == "http_server":
        return _shodan_escape_value(f"Server: {raw}")
    field = SHODAN_SAFE_FILTERS.get(qtype)
    if field is None:
        return ""
    if field == "":
        return raw[:500] if _shodan_raw_query_allowed(raw) else ""
    return f"{field}:{_shodan_escape_value(raw)}" if _shodan_escape_value(raw) else ""

def query_shodan_search(query: str, api_key: str, limit_fields: bool = True, page: int = 1,
                        query_type: str = "shodan_query") -> Dict[str, Any]:
    shodan_query = build_shodan_query(query, query_type)
    if not shodan_query:
        return {"error": "Invalid Shodan search query"}
    try:
        page = max(1, min(int(page or 1), 100))
    except (TypeError, ValueError):
        page = 1
    params = {"query": shodan_query, "facets": SHODAN_FACETS, "minify": "false", "page": page}
    if limit_fields:
        params["fields"] = SHODAN_HOST_FIELDS
    raw = _query_shodan("/shodan/host/search", api_key, params, _SHODAN_CACHE_TTL["search"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"raw": raw, "normalized": normalize_shodan_search(raw, shodan_query, page)}

def query_shodan_count(query: str, api_key: str, query_type: str = "shodan_query") -> Dict[str, Any]:
    shodan_query = build_shodan_query(query, query_type)
    if not shodan_query:
        return {"error": "Invalid Shodan count query"}
    raw = _query_shodan("/shodan/host/count", api_key, {"query": shodan_query, "facets": SHODAN_FACETS},
                        _SHODAN_CACHE_TTL["count"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"raw": raw, "normalized": normalize_shodan_count(raw, shodan_query)}

def normalize_shodan_dns_domain(raw: Any, domain: str) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("error"):
        return {}
    subdomains = _shodan_list(raw.get("subdomains"))
    raw_data = raw.get("data") if isinstance(raw.get("data"), list) else []
    records = []
    resolved_ips = set()
    for item in raw_data:
        if not isinstance(item, dict):
            continue
        sub = _shodan_text(item.get("subdomain"))
        full_sub = f"{sub}.{domain}" if sub else domain
        rtype = _shodan_text(item.get("type"))
        val = _shodan_text(item.get("value"))
        last_seen = _shodan_text(item.get("last_seen"))
        if rtype in ("A", "AAAA") and is_ip(val):
            resolved_ips.add(val)
        records.append({
            "subdomain": sub,
            "full_name": full_sub,
            "type": rtype,
            "value": val,
            "last_seen": last_seen,
        })
    tags = _shodan_list(raw.get("tags"))
    more = bool(raw.get("more"))
    return {
        "domain": domain,
        "subdomains": subdomains[:200],
        "total_subdomains": len(subdomains),
        "records": records[:200],
        "resolved_ips": sorted(resolved_ips),
        "tags": tags,
        "more": more,
    }

def query_shodan_domain(domain: str, api_key: str) -> Dict[str, Any]:
    domain = normalize_domain(domain)
    if not is_domain(domain):
        return {"error": "Invalid Shodan domain query"}
    query = build_shodan_query(domain, "domain")
    domain_path = urllib.parse.quote(domain, safe="")
    results = _collect_callables({
        "dns_domain": lambda: _query_shodan(f"/dns/domain/{domain_path}", api_key, cache_ttl=_SHODAN_CACHE_TTL["metadata"]),
        "dns_resolve": lambda: _query_shodan("/dns/resolve", api_key, {"hostnames": domain}, _SHODAN_CACHE_TTL["metadata"]),
        "host_search": lambda: query_shodan_search(domain, api_key, query_type="domain"),
        "host_count": lambda: query_shodan_count(query, api_key),
    }, max_workers=4)
    dns_raw = results.get("dns_domain")
    dns_norm = normalize_shodan_dns_domain(dns_raw, domain) if dns_raw and not (isinstance(dns_raw, dict) and dns_raw.get("error")) else {}
    search_res = results.get("host_search") or {}
    search_norm = search_res.get("normalized") if isinstance(search_res, dict) else {}
    combined_norm = {
        "source": "Shodan",
        "kind": "domain",
        "domain": domain,
        "dns_domain": dns_norm,
        "dns_resolve": results.get("dns_resolve") or {},
        "search": search_norm,
        "total": search_norm.get("total", 0) if search_norm else 0,
        "matches": search_norm.get("matches", []) if search_norm else [],
        "facets": search_norm.get("facets", {}) if search_norm else {},
    }
    results["normalized"] = combined_norm
    return results

def query_shodan_ip(ip: str, api_key: str) -> Dict[str, Any]:
    ip = normalize_ip(ip)
    if not is_ip(ip):
        return {"error": "Invalid Shodan IP query"}
    ip_path = urllib.parse.quote(ip, safe="")
    raw = _query_shodan(f"/shodan/host/{ip_path}", api_key, {"history": "false", "minify": "false"},
                        _SHODAN_CACHE_TTL["host"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_reverse = executor.submit(_query_shodan, "/dns/reverse", api_key, {"ips": ip}, _SHODAN_CACHE_TTL["metadata"])
        future_count = executor.submit(query_shodan_count, ip, api_key, "ip")
        reverse_dns, count = future_reverse.result(), future_count.result()
    result = {
        "source": "Shodan",
        "kind": "host",
        "host": raw,
        "normalized": normalize_shodan_host(raw, ip, history=False),
    }
    if not (isinstance(reverse_dns, dict) and reverse_dns.get("error")):
        result["reverse_dns"] = reverse_dns
    if not (isinstance(count, dict) and count.get("error")):
        result["host_count"] = count
    return result

def query_shodan_host_history(ip: str, api_key: str) -> Dict[str, Any]:
    ip = normalize_ip(ip)
    if not is_ip(ip):
        return {"error": "Invalid Shodan IP query"}
    ip_path = urllib.parse.quote(ip, safe="")
    raw = _query_shodan(f"/shodan/host/{ip_path}", api_key, {"history": "true", "minify": "false"},
                        _SHODAN_CACHE_TTL["history"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "Shodan", "kind": "host_history", "host": raw,
            "normalized": normalize_shodan_host(raw, ip, history=True)}

def query_shodan_keyword(keyword: str, api_key: str) -> Dict[str, Any]:
    query = build_shodan_query(keyword, "infra")
    if not query:
        return {"error": "Invalid Shodan infrastructure query"}
    results = _collect_callables({
        "host_search": lambda: query_shodan_search(query, api_key, query_type="shodan_query"),
        "host_count": lambda: query_shodan_count(query, api_key, query_type="shodan_query"),
        "tokens": lambda: _query_shodan("/shodan/host/search/tokens", api_key, {"query": query},
                                        _SHODAN_CACHE_TTL["metadata"]),
    }, max_workers=3)
    return _keep_success(results) or results

def query_censys_host(ip: str, api_key: str) -> Dict[str, Any]:
    return query_censys(ip, "ip", api_key)

CENSYS_API_BASE = "https://api.platform.censys.io"
CENSYS_SEARCH_FIELDS = [
    "host.ip", "host.location.country", "host.location.country_code", "host.location.city",
    "host.autonomous_system.asn", "host.autonomous_system.name", "host.autonomous_system.description",
    "host.autonomous_system.bgp_prefix", "host.services.port", "host.services.protocol",
    "host.services.transport_protocol", "host.services.scan_time", "host.services.banner_hash_sha256",
    "host.services.software.product", "host.services.software.version", "host.services.software.vendor",
    "host.services.software.cpe", "web.hostname", "web.port", "web.scan_time",
    "web.endpoints.path", "web.endpoints.banner_hash_sha256", "web.endpoints.http.body_hash_sha256",
    "cert.fingerprint_sha256", "cert.names", "cert.parsed.subject_dn", "cert.parsed.issuer_dn",
]
CENSYS_AGGREGATE_FIELDS = {
    "ports": "host.services.port",
    "protocols": "host.services.protocol",
    "countries": "host.location.country",
    "asns": "host.autonomous_system.asn",
}
CENSYS_ACCEPT = {
    "host": "application/vnd.censys.api.v3.host.v1+json",
    "host_timeline": "application/vnd.censys.api.v3.host_timeline_event.v1+json",
    "webproperty": "application/vnd.censys.api.v3.webproperty.v1+json",
    "certificate": "application/vnd.censys.api.v3.certificate.v1+json",
}
CENSYS_ALLOWED_METHOD_PATHS = (
    ("GET", re.compile(r"^/v3/global/asset/host/[^/]+$")),
    ("GET", re.compile(r"^/v3/global/asset/host/[^/]+/timeline$")),
    ("GET", re.compile(r"^/v3/global/asset/webproperty/[^/]+$")),
    ("GET", re.compile(r"^/v3/global/asset/certificate/[A-Fa-f0-9]{64}$")),
    ("POST", re.compile(r"^/v3/global/search/query$")),
    ("POST", re.compile(r"^/v3/global/search/aggregate$")),
)
CENSYS_DENY_MARKERS = (
    "/scans", "/rescan", "/collections", "/accounts", "/tags", "/seeds",
    "/workspace", "/workspaces", "/comments", "/saved", "/exports", "/data-downloads",
)
_CENSYS_CACHE: Dict[str, Any] = {}
_CENSYS_CACHE_TTL = {"asset": 21600, "timeline": 86400, "search": 1800, "aggregate": 1800}

def _censys_key(_api_key: str = "") -> str:
    return (
        os.environ.get("CENSYS_PAT")
        or os.environ.get("CENSYS_API_KEY")
        or os.environ.get("CENSYS_API_TOKEN")
        or os.environ.get("MANTIS_CENSYS_PAT")
        or os.environ.get("MANTIS_CENSYS_KEY")
        or os.environ.get("IOCINTEL_CENSYS_PAT")
        or os.environ.get("IOCINTEL_CENSYS_KEY")
        or (_api_key or "").strip()
        or ""
    ).strip()

def _censys_org_id() -> str:
    return (
        os.environ.get("CENSYS_ORG_ID")
        or os.environ.get("CENSYS_ORGANIZATION_ID")
        or os.environ.get("MANTIS_CENSYS_ORG_ID")
        or os.environ.get("IOCINTEL_CENSYS_ORG_ID")
        or ""
    ).strip()

def _censys_cache_get(key: str) -> Any:
    entry = _CENSYS_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _CENSYS_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _censys_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _CENSYS_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _censys_sanitize_error(message: str, api_key: str = "") -> str:
    text = str(message or "")
    if api_key:
        text = text.replace(api_key, "[redacted]")
    text = re.sub(r"(Authorization:\s*Bearer\s+)[^\s'\"]+", r"\1[redacted]", text, flags=re.IGNORECASE)
    text = re.sub(r"([?&]organization_id=)[^&\s'\"]+", r"\1[redacted]", text, flags=re.IGNORECASE)
    return text[:240]

def _censys_allowed_path(method: str, path: str) -> bool:
    method = (method or "GET").upper()
    clean = (path or "").split("?", 1)[0]
    lowered = clean.lower()
    if any(marker in lowered for marker in CENSYS_DENY_MARKERS):
        return False
    return any(method == allowed_method and pattern.match(clean) for allowed_method, pattern in CENSYS_ALLOWED_METHOD_PATHS)

def _query_censys(path: str, api_key: str = "", method: str = "GET", body: Dict[str, Any] = None,
                  params: Dict[str, Any] = None, accept: str = "application/json",
                  cache_ttl: int = 1800) -> Dict[str, Any]:
    method = (method or "GET").upper()
    if not _censys_allowed_path(method, path):
        return {"error": "Censys endpoint not allowlisted (passive-only integration)"}
    api_key = _censys_key(api_key)
    if not api_key:
        return {"error": "No Censys PAT configured on server"}
    safe_params = dict(params or {})
    org_id = _censys_org_id()
    headers = {"Authorization": f"Bearer {api_key}", "Accept": accept or "application/json"}
    if method == "POST":
        headers["Content-Type"] = "application/json"
    if org_id:
        headers["X-Organization-ID"] = org_id
        safe_params.setdefault("organization_id", org_id)
    cache_body = body or {}
    cache_key = f"censys:{method}:{path}:{urllib.parse.urlencode(sorted(safe_params.items()), doseq=True)}:{repr(sorted(cache_body.items())) if isinstance(cache_body, dict) else repr(cache_body)}"
    cached = _censys_cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        resp = requests.request(method, f"{CENSYS_API_BASE}{path}", headers=headers, params=safe_params,
                                json=body if method == "POST" else None, timeout=25)
        try:
            payload = resp.json() if resp.text else {}
        except ValueError:
            payload = {"message": resp.text[:240]}
        if 200 <= resp.status_code < 300:
            result = payload
        elif resp.status_code == 404:
            result = {"error": "Not Found"}
        elif resp.status_code == 401:
            result = {"error": "Censys authentication failure (HTTP 401)"}
        elif resp.status_code == 403:
            detail = payload.get("message") or payload.get("detail") or payload.get("title") or "Plan or role does not permit this Censys endpoint"
            result = {"error": "Censys entitlement failure (HTTP 403)", "message": _censys_sanitize_error(detail, api_key)}
        elif resp.status_code == 422:
            detail = payload.get("message") or payload.get("detail") or payload.get("title") or "Invalid Censys query or parameters"
            result = {"error": "Censys invalid query or parameters (HTTP 422)", "message": _censys_sanitize_error(detail, api_key)}
        elif resp.status_code == 429:
            result = {"error": "Censys concurrency or rate limit exceeded (HTTP 429)"}
        elif resp.status_code == 503:
            result = {"error": "Censys request-per-second limit exceeded (HTTP 503)"}
        elif 500 <= resp.status_code < 600:
            result = {"error": f"Censys provider error (HTTP {resp.status_code})"}
        else:
            result = {"error": f"Censys request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        result = {"error": "Censys request timeout"}
    except Exception as e:
        result = {"error": f"Censys request failed: {_censys_sanitize_error(str(e), api_key)}"}
    _censys_cache_set(cache_key, result, cache_ttl)
    return result

def _censys_text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) and str(value).strip() else ""

def _censys_list(value: Any) -> List[str]:
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, (str, int, float)) and str(item).strip():
                out.append(str(item).strip())
            elif isinstance(item, dict):
                text = _censys_text(item.get("name") or item.get("value") or item.get("common_name"))
                if text:
                    out.append(text)
        return out
    text = _censys_text(value)
    return [text] if text else []

def _censys_nested(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            vals = []
            for item in current:
                if isinstance(item, dict) and part in item:
                    vals.append(item.get(part))
            current = vals
        else:
            return None
    return current

def _censys_resource(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return {}
    result = raw.get("result")
    if isinstance(result, dict):
        if isinstance(result.get("resource"), dict):
            return result.get("resource")
        if isinstance(result.get("resources"), list):
            return result.get("resources")
        return result
    return raw.get("resource") if isinstance(raw.get("resource"), dict) else raw

def _censys_software_items(value: Any) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    candidates = []
    if isinstance(value, list):
        candidates.extend(value)
    elif isinstance(value, dict):
        candidates.append(value)
        if isinstance(value.get("components"), list):
            candidates.extend(value.get("components"))
    for item in candidates:
        if not isinstance(item, dict):
            continue
        record = {
            "product": _censys_text(item.get("product") or item.get("name")),
            "version": _censys_text(item.get("version")),
            "vendor": _censys_text(item.get("vendor")),
            "cpe": _censys_list(item.get("cpe"))[:20],
            "confidence": item.get("confidence"),
        }
        if any(v not in ("", [], None) for v in record.values()):
            items.append(record)
    return items[:50]

def _censys_normalize_http_from_endpoints(endpoints: Any) -> Dict[str, Any]:
    if isinstance(endpoints, dict):
        endpoints = [endpoints]
    if not isinstance(endpoints, list):
        return {}
    out = {"paths": [], "titles": [], "status_codes": [], "servers": [], "body_hashes": [], "favicon_hashes": [], "redirects": []}
    for endpoint in endpoints[:20]:
        if not isinstance(endpoint, dict):
            continue
        http_obj = endpoint.get("http") if isinstance(endpoint.get("http"), dict) else {}
        if endpoint.get("path"):
            out["paths"].append(str(endpoint.get("path")))
        title = http_obj.get("html_title") or http_obj.get("title")
        if title:
            out["titles"].append(str(title))
        status = http_obj.get("status_code") or http_obj.get("status")
        if status is not None:
            out["status_codes"].append(str(status))
        headers = http_obj.get("headers")
        if isinstance(headers, list):
            for header in headers:
                if isinstance(header, dict) and str(header.get("key", "")).lower() == "server":
                    server = _censys_text(header.get("value"))
                    if server:
                        out["servers"].append(server)
        elif isinstance(headers, dict):
            server = _censys_text(headers.get("Server") or headers.get("server"))
            if server:
                out["servers"].append(server)
        for key in ("body_hash_sha256", "body_hash_sha1", "body_hash_md5"):
            if http_obj.get(key):
                out["body_hashes"].append(str(http_obj.get(key)))
        favicons = http_obj.get("favicons")
        favicons = favicons if isinstance(favicons, list) else ([favicons] if isinstance(favicons, dict) else [])
        for fav in favicons:
            if isinstance(fav, dict):
                for key in ("hash_sha256", "hash_md5", "hash"):
                    if fav.get(key):
                        out["favicon_hashes"].append(str(fav.get(key)))
        redirects = http_obj.get("redirect_chain")
        if isinstance(redirects, list):
            for r in redirects[:10]:
                if isinstance(r, dict):
                    loc = _censys_text(r.get("location") or r.get("url"))
                    if loc:
                        out["redirects"].append(loc)
                else:
                    out["redirects"].append(str(r))
    return {k: list(dict.fromkeys(v)) if isinstance(v, list) else v for k, v in out.items() if v}

def _censys_normalize_cert(cert: Any) -> Dict[str, Any]:
    if not isinstance(cert, dict):
        return {}
    parsed = cert.get("parsed") if isinstance(cert.get("parsed"), dict) else cert
    subject = parsed.get("subject") if isinstance(parsed.get("subject"), dict) else {}
    issuer = parsed.get("issuer") if isinstance(parsed.get("issuer"), dict) else {}
    validity = parsed.get("validity_period") or parsed.get("validity") or {}
    if not isinstance(validity, dict):
        validity = {}
    names = _censys_list(cert.get("names") or parsed.get("names") or parsed.get("subject_alt_names"))
    return {
        "fingerprint_sha256": _censys_text(cert.get("fingerprint_sha256") or parsed.get("fingerprint_sha256")),
        "subject_dn": _censys_text(parsed.get("subject_dn")),
        "issuer_dn": _censys_text(parsed.get("issuer_dn")),
        "subject_cn": _censys_text(subject.get("common_name") or subject.get("cn")),
        "issuer_cn": _censys_text(issuer.get("common_name") or issuer.get("cn")),
        "serial": _censys_text(parsed.get("serial_number") or parsed.get("serial")),
        "signature_algorithm": _censys_text(parsed.get("signature_algorithm", {}).get("name") if isinstance(parsed.get("signature_algorithm"), dict) else parsed.get("signature_algorithm")),
        "valid_from": _censys_text(validity.get("not_before") or validity.get("start")),
        "valid_to": _censys_text(validity.get("not_after") or validity.get("end")),
        "names": names[:100],
    }

def _censys_normalize_service(service: Any) -> Dict[str, Any]:
    if not isinstance(service, dict):
        return {}
    cert = service.get("cert") or _censys_nested(service, "tls.certificates.leaf_data") or _censys_nested(service, "tls.certificates.leaf")
    software = _censys_software_items(service.get("software"))
    vulns = service.get("vulns") if isinstance(service.get("vulns"), list) else []
    normalized_vulns = []
    for vuln in vulns[:50]:
        if isinstance(vuln, dict):
            metrics = vuln.get("metrics") if isinstance(vuln.get("metrics"), dict) else {}
            normalized_vulns.append({
                "id": _censys_text(vuln.get("id")).upper(),
                "severity": _censys_text(vuln.get("severity")),
                "kev": vuln.get("kev") if isinstance(vuln.get("kev"), bool) else None,
                "cvss": _censys_nested(metrics, "cvss_v31.score") or _censys_nested(metrics, "cvss_v30.score") or _censys_nested(metrics, "cvss_v40.score"),
            })
        elif vuln:
            normalized_vulns.append({"id": str(vuln).upper()})
    service_id = {
        "ip": _censys_text(service.get("ip")),
        "port": service.get("port"),
        "protocol": _censys_text(service.get("protocol") or service.get("service_name")),
        "transport": _censys_text(service.get("transport_protocol")) or "tcp",
        "observed_at": _censys_text(service.get("scan_time") or service.get("observed_at")),
        "banner_hash": _censys_text(service.get("banner_hash_sha256")),
        "banner": _censys_text(service.get("banner"))[:4000],
        "software": software,
        "cpe": list(dict.fromkeys([cpe for item in software for cpe in item.get("cpe", [])]))[:50],
        "http": _censys_normalize_http_from_endpoints(service.get("endpoints")),
        "tls": _censys_normalize_cert(cert),
        "metadata": {k: v for k, v in service.items() if k in {"labels", "extended_service_name", "perspective_id"} and v},
        "vulnerabilities": [v for v in normalized_vulns if v.get("id")],
    }
    return {k: v for k, v in service_id.items() if v not in ("", [], {}, None)}

def normalize_censys_host(raw: Any, query_ip: str = "") -> Dict[str, Any]:
    resource = _censys_resource(raw)
    if not isinstance(resource, dict) or (isinstance(raw, dict) and raw.get("error")):
        return {"source": "Censys", "kind": "host", "ip": query_ip, "services": [], "relationships": []}
    ip_value = _censys_text(resource.get("ip") or query_ip)
    asn = resource.get("autonomous_system") if isinstance(resource.get("autonomous_system"), dict) else {}
    whois = resource.get("whois") if isinstance(resource.get("whois"), dict) else {}
    network = whois.get("network") if isinstance(whois.get("network"), dict) else {}
    whois_org = whois.get("organization") if isinstance(whois.get("organization"), dict) else {}
    dns = resource.get("dns") if isinstance(resource.get("dns"), dict) else {}
    reverse_dns = dns.get("reverse_dns") if isinstance(dns.get("reverse_dns"), dict) else {}
    forward_dns = dns.get("forward_dns") if isinstance(dns.get("forward_dns"), dict) else {}
    names = list(dict.fromkeys(_censys_list(dns.get("names")) + _censys_list(reverse_dns.get("names"))))[:200]
    services = [_censys_normalize_service(s) for s in (resource.get("services") or [])]
    services = [s for s in services if s.get("port") is not None or s.get("banner_hash") or s.get("software")]
    relationships = []
    seen = set()
    def add_rel(source: str, relation: str, target: str, target_type: str, observed_at: str = "") -> None:
        if not source or not target:
            return
        key = (source, relation, target, observed_at)
        if key not in seen:
            seen.add(key)
            rel = {"source": source, "relation": relation, "target": target, "target_type": target_type}
            if observed_at:
                rel["observed_at"] = observed_at
            relationships.append(rel)
    asn_value = _censys_text(asn.get("asn"))
    if asn_value and not asn_value.upper().startswith("AS"):
        asn_value = f"AS{asn_value}"
    add_rel(ip_value, "belongs_to", asn_value, "asn")
    add_rel(ip_value, "belongs_to", _censys_text(asn.get("bgp_prefix")), "bgp_prefix")
    add_rel(ip_value, "routed_by", _censys_text(asn.get("name") or asn.get("description")), "asn_organization")
    add_rel(ip_value, "registered_to", _censys_text(whois_org.get("name")), "whois_organization")
    for cidr in _censys_list(network.get("cidrs")):
        add_rel(ip_value, "in_whois_network", cidr, "cidr")
    for name in names:
        add_rel(ip_value, "associated_with", name, "hostname")
        add_rel(name, "resolves_to", ip_value, "ip", _censys_text(forward_dns.get(name, {}).get("resolve_time")) if isinstance(forward_dns.get(name), dict) else "")
        add_rel(ip_value, "reverse_resolves_to", name, "hostname", _censys_text(reverse_dns.get("resolve_time")))
    for svc in services:
        service_id = f"{ip_value}:{svc.get('port')}/{svc.get('transport', 'tcp')}"
        add_rel(ip_value, "exposes", service_id, "service", svc.get("observed_at", ""))
        for sw in svc.get("software") or []:
            add_rel(service_id, "runs", " ".join([sw.get("product", ""), sw.get("version", "")]).strip(), "software", svc.get("observed_at", ""))
            for cpe in sw.get("cpe") or []:
                add_rel(service_id, "identified_as", cpe, "cpe", svc.get("observed_at", ""))
        tls = svc.get("tls") or {}
        add_rel(service_id, "presents_certificate", tls.get("fingerprint_sha256"), "certificate", svc.get("observed_at", ""))
        add_rel(tls.get("fingerprint_sha256"), "issued_by", tls.get("issuer_dn") or tls.get("issuer_cn"), "issuer")
        for name in tls.get("names") or []:
            add_rel(tls.get("fingerprint_sha256"), "references", name, "domain")
        for vuln in svc.get("vulnerabilities") or []:
            add_rel(service_id, "associated_with", vuln.get("id"), "cve", svc.get("observed_at", ""))
    return {
        "source": "Censys",
        "kind": "host",
        "ip": ip_value,
        "location": resource.get("location") if isinstance(resource.get("location"), dict) else {},
        "autonomous_system": {
            "asn": asn_value,
            "name": _censys_text(asn.get("name")),
            "description": _censys_text(asn.get("description")),
            "bgp_prefix": _censys_text(asn.get("bgp_prefix")),
            "country_code": _censys_text(asn.get("country_code")),
        },
        "whois": {
            "network": {k: v for k, v in network.items() if k in {"handle", "name", "cidrs", "created", "updated", "allocation_type"}},
            "organization": {k: v for k, v in whois_org.items() if k in {"handle", "name", "city", "state", "country"}},
        },
        "dns": {"names": names, "reverse_dns": reverse_dns, "forward_dns": forward_dns},
        "service_count": resource.get("service_count") if resource.get("service_count") is not None else len(services),
        "services": services,
        "last_observed": max([s.get("observed_at", "") for s in services] or [""]),
        "semantics": {
            "label": "Internet Infrastructure Intelligence",
            "found_does_not_mean_malicious": True,
            "observed_service_not_malicious": True,
            "historical_observation_not_current_state": True,
            "certificate_reuse_not_common_ownership": True,
        },
        "relationships": relationships,
    }

def normalize_censys_certificate(raw: Any, fingerprint: str = "") -> Dict[str, Any]:
    cert = _censys_normalize_cert(_censys_resource(raw))
    cert["source"] = "Censys"
    cert["kind"] = "certificate"
    if not cert.get("fingerprint_sha256"):
        cert["fingerprint_sha256"] = fingerprint
    cert["relationships"] = []
    if cert.get("issuer_dn") or cert.get("issuer_cn"):
        cert["relationships"].append({"source": cert.get("fingerprint_sha256"), "relation": "issued_by", "target": cert.get("issuer_dn") or cert.get("issuer_cn"), "target_type": "issuer"})
    for name in cert.get("names") or []:
        cert["relationships"].append({"source": cert.get("fingerprint_sha256"), "relation": "references", "target": name, "target_type": "domain"})
    return {k: v for k, v in cert.items() if v not in ("", [], {}, None)}

def normalize_censys_webproperty(raw: Any, webproperty_id: str = "") -> Dict[str, Any]:
    resource = _censys_resource(raw)
    web = resource.get("web") if isinstance(resource, dict) and isinstance(resource.get("web"), dict) else resource
    if not isinstance(web, dict):
        web = {}
    endpoints = web.get("endpoints") if isinstance(web.get("endpoints"), list) else []
    normalized = {
        "source": "Censys",
        "kind": "web_property",
        "id": webproperty_id or _censys_text(web.get("id")),
        "hostname": _censys_text(web.get("hostname")),
        "port": web.get("port"),
        "scan_time": _censys_text(web.get("scan_time") or web.get("scan_timed")),
        "labels": _censys_list(web.get("labels")),
        "software": _censys_software_items(web.get("software")),
        "tls": [_censys_normalize_cert(x) for x in web.get("tls", [])] if isinstance(web.get("tls"), list) else [],
        "http": _censys_normalize_http_from_endpoints(endpoints),
        "endpoints": endpoints[:20],
        "vulnerabilities": web.get("vulns") if isinstance(web.get("vulns"), list) else [],
        "relationships": [],
    }
    source = normalized["id"] or ":".join([str(normalized.get("hostname") or ""), str(normalized.get("port") or "")]).strip(":")
    if normalized.get("hostname"):
        normalized["relationships"].append({"source": source, "relation": "hosted_on_name", "target": normalized["hostname"], "target_type": "hostname"})
    for endpoint in endpoints[:20]:
        if isinstance(endpoint, dict) and endpoint.get("path"):
            normalized["relationships"].append({"source": source, "relation": "exposes", "target": str(endpoint.get("path")), "target_type": "endpoint"})
    return {k: v for k, v in normalized.items() if v not in ("", [], {}, None)}

def normalize_censys_search(raw: Any, query: str, page_token: str = "") -> Dict[str, Any]:
    result = raw.get("result", raw) if isinstance(raw, dict) else {}
    hits = []
    if isinstance(result, dict):
        for key in ("hits", "resources", "results"):
            if isinstance(result.get(key), list):
                hits = result.get(key)
                break
    normalized_hits = []
    for hit in hits[:100]:
        if not isinstance(hit, dict):
            continue
        host_data = hit.get("host") if isinstance(hit.get("host"), dict) else {}
        web_data = hit.get("web") if isinstance(hit.get("web"), dict) else {}
        cert_data = hit.get("cert") if isinstance(hit.get("cert"), dict) else {}
        flat_host = {
            "ip": hit.get("host.ip") or host_data.get("ip") or hit.get("ip"),
            "location": {
                "country": hit.get("host.location.country") or _censys_nested(host_data, "location.country"),
                "country_code": hit.get("host.location.country_code") or _censys_nested(host_data, "location.country_code"),
                "city": hit.get("host.location.city") or _censys_nested(host_data, "location.city"),
            },
            "autonomous_system": {
                "asn": hit.get("host.autonomous_system.asn") or _censys_nested(host_data, "autonomous_system.asn"),
                "name": hit.get("host.autonomous_system.name") or _censys_nested(host_data, "autonomous_system.name"),
                "description": hit.get("host.autonomous_system.description") or _censys_nested(host_data, "autonomous_system.description"),
                "bgp_prefix": hit.get("host.autonomous_system.bgp_prefix") or _censys_nested(host_data, "autonomous_system.bgp_prefix"),
            },
            "services": hit.get("matched_services") or host_data.get("services") or [],
        }
        if flat_host["ip"]:
            normalized_hits.append({"asset_type": "host", "host": normalize_censys_host({"result": {"resource": flat_host}}, flat_host["ip"])})
            continue
        if web_data or hit.get("web.hostname"):
            normalized_hits.append({"asset_type": "web_property", "web_property": normalize_censys_webproperty({"result": {"resource": {"web": web_data or hit}}})})
            continue
        if cert_data or hit.get("cert.fingerprint_sha256"):
            normalized_hits.append({"asset_type": "certificate", "certificate": normalize_censys_certificate({"result": {"resource": cert_data or hit}}, _censys_text(hit.get("cert.fingerprint_sha256")))})
    links = result.get("links") if isinstance(result.get("links"), dict) else {}
    return {
        "source": "Censys",
        "kind": "search",
        "query": query,
        "total": result.get("total") or result.get("total_count") or len(normalized_hits),
        "page_token": page_token,
        "next_page_token": links.get("next") or result.get("next_page_token"),
        "hits": normalized_hits,
        "raw_count": len(hits),
        "credit_note": "Censys Global Data search is plan-dependent and consumes credits.",
    }

def normalize_censys_aggregate(raw: Any, field: str) -> Dict[str, Any]:
    result = raw.get("result", raw) if isinstance(raw, dict) else {}
    buckets = []
    if isinstance(result, dict):
        buckets = result.get("buckets") if isinstance(result.get("buckets"), list) else []
    return {"source": "Censys", "kind": "aggregate", "field": field, "buckets": buckets[:50], "total": result.get("total")}

def normalize_censys_timeline(raw: Any, ip: str = "") -> Dict[str, Any]:
    result = raw.get("result", raw) if isinstance(raw, dict) else {}
    events = []
    if isinstance(result, dict):
        for key in ("events", "timeline", "resources"):
            if isinstance(result.get(key), list):
                events = result.get(key)
                break
    elif isinstance(result, list):
        events = result
    normalized = []
    for event in events[:200]:
        if not isinstance(event, dict):
            continue
        normalized.append({
            "timestamp": _censys_text(event.get("timestamp") or event.get("event_time") or event.get("scan_time")),
            "event_type": _censys_text(event.get("event_type") or event.get("type")),
            "port": event.get("port") or _censys_nested(event, "scan.port"),
            "protocol": _censys_text(event.get("protocol") or _censys_nested(event, "scan.protocol")),
            "description": _censys_text(event.get("description") or event.get("message")),
        })
    return {"source": "Censys", "kind": "host_timeline", "ip": ip, "events": normalized}

def _censys_quote(value: str) -> str:
    text = re.sub(r"[\r\n\t]", " ", str(value or "")).strip()[:300]
    if not text:
        return ""
    if re.match(r"^[A-Za-z][A-Za-z0-9._-]*$", text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

def _censys_raw_query_allowed(query: str) -> bool:
    text = (query or "").strip()
    return bool(text and len(text) <= 800 and "\n" not in text and "\r" not in text)

def build_censys_query(value: str, query_type: str = "auto") -> str:
    raw = (value or "").strip()
    qtype = (query_type or "auto").strip().lower()
    if not raw or "\n" in raw or "\r" in raw:
        return ""
    if qtype in {"censys_query", "cenql"}:
        return raw[:800] if _censys_raw_query_allowed(raw) else ""
    if qtype in {"auto", "infra", "keyword"}:
        if re.search(r"\b(host|web|cert)\.", raw) and _censys_raw_query_allowed(raw):
            return raw[:800]
        try:
            network = ipaddress.ip_network(raw, strict=False)
            if "/" in raw:
                return f'host.ip: "{network}"'
        except ValueError:
            pass
        ip_candidate = normalize_ip(raw)
        if is_ip(ip_candidate):
            return f'host.ip = "{ip_candidate}"'
        if raw.isdigit() and 0 < int(raw) <= 65535:
            return f"host.services.port = {int(raw)}"
        if re.match(r"^AS\d{1,10}$", raw, re.IGNORECASE):
            return f"host.autonomous_system.asn = {int(raw.upper().replace('AS', ''))}"
        domain = normalize_domain(raw)
        if is_domain(domain):
            quoted = _censys_quote(domain)
            return f'(web.hostname = {quoted} or host.dns.names: {quoted} or cert.names: {quoted})'
        return _censys_quote(raw)
    if qtype == "ip":
        ip_candidate = normalize_ip(raw)
        return f'host.ip = "{ip_candidate}"' if is_ip(ip_candidate) else ""
    if qtype in {"net", "cidr"}:
        try:
            return f'host.ip: "{ipaddress.ip_network(raw, strict=False)}"'
        except ValueError:
            return ""
    if qtype == "asn":
        return f"host.autonomous_system.asn = {int(raw.upper().replace('AS', ''))}" if re.match(r"^(?:AS)?\d{1,10}$", raw, re.IGNORECASE) else ""
    if qtype == "port":
        return f"host.services.port = {int(raw)}" if raw.isdigit() and 0 < int(raw) <= 65535 else ""
    if qtype == "protocol":
        return f"host.services.protocol = {_censys_quote(raw.upper())}"
    if qtype == "product":
        return f"product: {_censys_quote(raw)}"
    if qtype == "version":
        return f"host.services.software.version = {_censys_quote(raw)}"
    if qtype == "cpe":
        return f"cpe: {_censys_quote(raw)}"
    if qtype in {"hostname", "domain"}:
        domain = normalize_domain(raw)
        if not is_domain(domain):
            return ""
        quoted = _censys_quote(domain)
        return f'(web.hostname = {quoted} or host.dns.names: {quoted} or cert.names: {quoted})'
    if qtype == "country":
        return f'host.location.country_code = "{raw.upper()}"' if len(raw) == 2 and raw.isalpha() else f"host.location.country: {_censys_quote(raw)}"
    if qtype == "city":
        return f"host.location.city: {_censys_quote(raw)}"
    if qtype in {"org", "organization"}:
        return f"org: {_censys_quote(raw)}"
    if qtype == "bgp_prefix":
        try:
            return f'host.autonomous_system.bgp_prefix = "{ipaddress.ip_network(raw, strict=False)}"'
        except ValueError:
            return ""
    if qtype == "http_body":
        return f"web.endpoints.http.body: {_censys_quote(raw)}"
    if qtype == "http_title":
        return f"host.services: (endpoints.http.html_title = {_censys_quote(raw)})"
    if qtype == "http_server":
        return f'host.services.endpoints.http.headers: (key = "Server" and value = {_censys_quote(raw)})'
    if qtype == "favicon_hash":
        lower = raw.lower()
        if re.match(r"^[a-f0-9]{32}$", lower):
            return f'(host.services.endpoints.http.favicons.hash_md5 = "{lower}" or web.endpoints.http.favicons.hash_md5 = "{lower}")'
        if re.match(r"^[a-f0-9]{64}$", lower):
            return f'(host.services.endpoints.http.favicons.hash_sha256 = "{lower}" or web.endpoints.http.favicons.hash_sha256 = "{lower}")'
        return ""
    if qtype == "cert_subject":
        return f"(cert.parsed.subject_dn: {_censys_quote(raw)} or cert.parsed.subject.common_name: {_censys_quote(raw)})"
    if qtype == "cert_issuer":
        return f"cert.parsed.issuer_dn: {_censys_quote(raw)}"
    if qtype in {"cert_name", "cert_san"}:
        return f"cert.names: {_censys_quote(raw)}"
    if qtype == "cert_serial":
        return f"cert.parsed.serial_number = {_censys_quote(raw)}"
    if qtype in {"cert_fingerprint", "sha256"}:
        lower = raw.lower()
        return f'cert.fingerprint_sha256 = "{lower}"' if re.match(r"^[a-f0-9]{64}$", lower) else ""
    return ""

def query_censys_search(query: str, api_key: str = "", query_type: str = "censys_query",
                        page_token: str = "", page_size: int = 50) -> Dict[str, Any]:
    cenql = build_censys_query(query, query_type)
    if not cenql:
        return {"error": "Invalid Censys query"}
    try:
        page_size = max(1, min(int(page_size or 50), 100))
    except (TypeError, ValueError):
        page_size = 50
    body = {"query": cenql, "page_size": page_size, "fields": CENSYS_SEARCH_FIELDS}
    if page_token:
        body["page_token"] = str(page_token)[:500]
    raw = _query_censys("/v3/global/search/query", api_key, "POST", body=body, cache_ttl=_CENSYS_CACHE_TTL["search"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"raw": raw, "normalized": normalize_censys_search(raw, cenql, page_token)}

def query_censys_aggregate(query: str, field: str, api_key: str = "", query_type: str = "censys_query") -> Dict[str, Any]:
    cenql = build_censys_query(query, query_type)
    agg_field = CENSYS_AGGREGATE_FIELDS.get(field, field)
    if not cenql or agg_field not in CENSYS_AGGREGATE_FIELDS.values():
        return {"error": "Invalid Censys aggregate query"}
    body = {"query": cenql, "field": agg_field, "number_of_buckets": 25, "filter_by_query": False}
    raw = _query_censys("/v3/global/search/aggregate", api_key, "POST", body=body, cache_ttl=_CENSYS_CACHE_TTL["aggregate"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"raw": raw, "normalized": normalize_censys_aggregate(raw, agg_field)}

def query_censys_host_lookup(ip: str, api_key: str = "") -> Dict[str, Any]:
    ip = normalize_ip(ip)
    if not is_ip(ip):
        return {"error": "Invalid Censys IP query"}
    path = f"/v3/global/asset/host/{urllib.parse.quote(ip, safe='')}"
    raw = _query_censys(path, api_key, "GET", accept=CENSYS_ACCEPT["host"], cache_ttl=_CENSYS_CACHE_TTL["asset"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "Censys", "kind": "host", "host": raw, "normalized": normalize_censys_host(raw, ip)}

def query_censys_host_timeline(ip: str, api_key: str = "", days: int = 31) -> Dict[str, Any]:
    ip = normalize_ip(ip)
    if not is_ip(ip):
        return {"error": "Invalid Censys IP query"}
    try:
        days = max(1, min(int(days or 31), 31))
    except (TypeError, ValueError):
        days = 31
    now = time.time()
    params = {
        "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "end_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - days * 86400)),
    }
    path = f"/v3/global/asset/host/{urllib.parse.quote(ip, safe='')}/timeline"
    raw = _query_censys(path, api_key, "GET", params=params, accept=CENSYS_ACCEPT["host_timeline"],
                        cache_ttl=_CENSYS_CACHE_TTL["timeline"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "Censys", "kind": "host_timeline", "timeline": raw, "normalized": normalize_censys_timeline(raw, ip)}

def query_censys_webproperty(webproperty_id: str, api_key: str = "") -> Dict[str, Any]:
    value = re.sub(r"[\r\n\t]", "", str(webproperty_id or "").strip())[:300]
    if not re.match(r"^[A-Za-z0-9_.:-]+$", value) or ":" not in value:
        return {"error": "Invalid Censys web property ID"}
    path = f"/v3/global/asset/webproperty/{urllib.parse.quote(value, safe='')}"
    raw = _query_censys(path, api_key, "GET", accept=CENSYS_ACCEPT["webproperty"], cache_ttl=_CENSYS_CACHE_TTL["asset"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "Censys", "kind": "web_property", "web_property": raw,
            "normalized": normalize_censys_webproperty(raw, value)}

def query_censys_certificate(fingerprint: str, api_key: str = "") -> Dict[str, Any]:
    fp = str(fingerprint or "").strip().lower()
    if not re.match(r"^[a-f0-9]{64}$", fp):
        return {"error": "Invalid Censys certificate fingerprint"}
    path = f"/v3/global/asset/certificate/{fp}"
    raw = _query_censys(path, api_key, "GET", accept=CENSYS_ACCEPT["certificate"], cache_ttl=_CENSYS_CACHE_TTL["asset"])
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "Censys", "kind": "certificate", "certificate": raw,
            "normalized": normalize_censys_certificate(raw, fp)}

def query_censys(indicator: str, query_type: str, api_key: str) -> Dict[str, Any]:
    qtype = (query_type or "auto").strip().lower()
    if qtype == "ip":
        return query_censys_host_lookup(indicator, api_key)
    if qtype in {"certificate", "cert_fingerprint", "sha256"}:
        return query_censys_certificate(indicator, api_key)
    if qtype == "web_property":
        return query_censys_webproperty(indicator, api_key)
    search_type = "domain" if qtype == "domain" else ("censys_query" if qtype in {"keyword", "infra"} else qtype)
    cenql = build_censys_query(indicator, search_type)
    if not cenql:
        return {"error": "Invalid Censys query type"}
    calls = {"search": lambda: query_censys_search(cenql, api_key, query_type="censys_query")}
    for name in ("ports", "protocols", "countries"):
        calls[name] = lambda n=name: query_censys_aggregate(cenql, n, api_key, query_type="censys_query")
    results = _collect_callables(calls, max_workers=2)
    return _keep_success(results) or results

def _etugen_items(data: Any) -> List[Any]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict) or data.get("error"):
        return []
    for key in ("results", "data", "items", "hosts", "threats", "files"):
        if isinstance(data.get(key), list):
            return data[key]
    if any(data.get(key) for key in ("id", "uuid", "ip", "host", "hostname", "domain")):
        return [data]
    return []

def _etugen_host_ids(*responses: Any) -> List[str]:
    ids: List[str] = []
    for response in responses:
        for item in _etugen_items(response):
            if not isinstance(item, dict):
                continue
            host_id = item.get("id") or item.get("uuid") or item.get("host_id") or item.get("threat_id")
            if host_id:
                host_id = str(host_id)
                if host_id not in ids:
                    ids.append(host_id)
    return ids

def _etugen_get(path: str, api_key: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {api_key.strip()}"}
    return _json_request("GET", f"https://app.etugen.io{path}", f"Etugen {path}", headers=headers, params=params or {})

def query_etugen(indicator: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"error": "No Etugen API Key provided"}
    params_key = "ip" if is_ip(indicator) else "domain"
    calls = {
        "search": lambda: _etugen_get("/api/search", api_key, {"q": indicator}),
    }
    if params_key == "ip":
        calls["trashpile_host"] = lambda: _etugen_get(f"/api/trashpile/host/{urllib.parse.quote(indicator, safe='')}", api_key)
    if params_key == "domain":
        calls["whois"] = lambda: _etugen_get(f"/api/whois/{urllib.parse.quote(indicator, safe='')}", api_key)

    results = _collect_callables(calls, max_workers=4)
    host_ids = _etugen_host_ids(results.get("search"), results.get("threat"))
    if host_ids:
        detail_calls = {
            host_id: (lambda host_id=host_id: _etugen_get(f"/api/threats/{urllib.parse.quote(host_id, safe='')}", api_key))
            for host_id in host_ids[:5]
        }
        service_calls = {
            host_id: (lambda host_id=host_id: _etugen_get(f"/api/threats/{urllib.parse.quote(host_id, safe='')}/services", api_key))
            for host_id in host_ids[:5]
        }
        details = _keep_success(_collect_callables(detail_calls, max_workers=5))
        services = _keep_success(_collect_callables(service_calls, max_workers=5))
        if details:
            results["host_details"] = details
        if services:
            results["host_services"] = services
    return _keep_success(results) or results

def query_etugen_keyword(keyword: str, api_key: str) -> Dict[str, Any]:
    """Search Etugen for threat hosts associated with a malware family or keyword."""
    if not api_key:
        return {"error": "No Etugen API Key provided"}
    results = _collect_callables({
        "threats": lambda: _etugen_get("/api/threats", api_key, {"malware": keyword}),
        "search": lambda: _etugen_get("/api/search", api_key, {"q": keyword}),
    }, max_workers=2)
    host_ids = _etugen_host_ids(results.get("search"), results.get("threats"))
    if host_ids:
        details = _keep_success(_collect_callables({
            host_id: (lambda host_id=host_id: _etugen_get(f"/api/threats/{urllib.parse.quote(host_id, safe='')}", api_key))
            for host_id in host_ids[:5]
        }, max_workers=5))
        services = _keep_success(_collect_callables({
            host_id: (lambda host_id=host_id: _etugen_get(f"/api/threats/{urllib.parse.quote(host_id, safe='')}/services", api_key))
            for host_id in host_ids[:5]
        }, max_workers=5))
        if details:
            results["host_details"] = details
        if services:
            results["host_services"] = services
    return _keep_success(results) or results

def query_etugen_open_dir(target: str, api_key: str) -> Dict[str, Any]:
    """Hunt exposed open directories (Trashpile) and leaked files on Etugen."""
    if not api_key:
        return {"error": "No Etugen API Key provided"}
    target = (target or "").strip()
    calls = {
        "search": lambda: _etugen_get("/api/search", api_key, {"q": target}),
    }
    if is_ip(target):
        calls["trashpile_host"] = lambda: _etugen_get(f"/api/trashpile/host/{urllib.parse.quote(target, safe='')}", api_key)
        calls["threat_host"] = lambda: _etugen_get(f"/api/threats/{urllib.parse.quote(target, safe='')}", api_key)
    else:
        calls["trashpile_search"] = lambda: _etugen_get("/api/trashpile", api_key, {"q": target})
        calls["threats"] = lambda: _etugen_get("/api/threats", api_key, {"malware": target})

    results = _collect_callables(calls, max_workers=4)
    return _keep_success(results) or results


TRIAGE_API_BASE = "https://api.tria.ge/v0"

def _triage_headers(api_key: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}

def _triage_get(path: str, api_key: str, params: Dict[str, Any] = None, timeout: int = 20, label: str = "Triage request") -> Dict[str, Any]:
    try:
        resp = requests.get(f"{TRIAGE_API_BASE}{path}", headers=_triage_headers(api_key), params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"text": resp.text}
        if resp.status_code == 404:
            return {"error": f"{label} unavailable (Not Found)"}
        if resp.status_code == 429:
            return {"error": "Rate limited (HTTP 429). Please retry shortly."}
        return {"error": f"Status {resp.status_code}", "message": resp.text[:1000]}
    except requests.exceptions.Timeout:
        return {"error": f"{label} timeout"}
    except Exception as e:
        return {"error": f"{label} failed: {e}"}

def query_triage_summary(sample_id: str, api_key: str) -> Dict[str, Any]:
    """Fetch the rich summary report for a single Triage sample ID."""
    if not api_key:
        return {"error": "No API Key provided"}
    if not (sample_id or "").strip():
        return {"error": "Missing sample ID"}
    return _triage_get(f"/samples/{urllib.parse.quote(sample_id.strip(), safe='')}/summary", api_key, label="Triage summary")

def query_triage_overview(sample_id: str, api_key: str) -> Dict[str, Any]:
    """Fetch the Overview report (default compact report with config/signatures)."""
    if not api_key:
        return {"error": "No API Key provided"}
    if not (sample_id or "").strip():
        return {"error": "Missing sample ID"}
    return _triage_get(f"/samples/{urllib.parse.quote(sample_id.strip(), safe='')}/overview.json", api_key, label="Triage overview")

def query_triage_static(sample_id: str, api_key: str) -> Dict[str, Any]:
    """Lazy: fetch the static report for a sample."""
    if not api_key:
        return {"error": "No API Key provided"}
    if not (sample_id or "").strip():
        return {"error": "Missing sample ID"}
    return _triage_get(f"/samples/{urllib.parse.quote(sample_id.strip(), safe='')}/reports/static", api_key, timeout=30, label="Triage static report")

def query_triage_behavioral(sample_id: str, task_id: str, api_key: str) -> Dict[str, Any]:
    """Lazy: fetch the full behavioral (triage) report for a single task."""
    if not api_key:
        return {"error": "No API Key provided"}
    if not (sample_id or "").strip():
        return {"error": "Missing sample ID"}
    if not (task_id or "").strip():
        return {"error": "Missing task ID"}
    return _triage_get(
        f"/samples/{urllib.parse.quote(sample_id.strip(), safe='')}/{urllib.parse.quote(task_id.strip(), safe='')}/report_triage.json",
        api_key, timeout=30, label="Triage behavioral report")

def _triage_str_list(values: Any) -> List[str]:
    if not values:
        return []
    if isinstance(values, str):
        return [values] if values.strip() else []
    if isinstance(values, list):
        out = []
        for v in values:
            if isinstance(v, str) and v.strip():
                out.append(v.strip())
            elif isinstance(v, dict):
                for key in ("display_name", "name", "value", "ioc", "url", "domain", "ip"):
                    val = v.get(key)
                    if isinstance(val, str) and val.strip():
                        out.append(val.strip())
                        break
        return list(dict.fromkeys(out))
    return []

def _triage_collect_configs(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    configs: List[Dict[str, Any]] = []
    if not isinstance(report, dict):
        return configs
    for section in ("extracted", "targets"):
        items = report.get(section)
        if isinstance(items, list):
            for entry in items:
                if isinstance(entry, dict) and isinstance(entry.get("config"), dict):
                    configs.append(entry["config"])
    # summary-shape fallback: tasks[].extracted[].config
    for task in (report.get("tasks") if isinstance(report.get("tasks"), list) else []):
        if not isinstance(task, dict):
            continue
        for ext in (task.get("extracted") if isinstance(task.get("extracted"), list) else []):
            if isinstance(ext, dict) and isinstance(ext.get("config"), dict):
                configs.append(ext["config"])
    return configs

def _triage_collect_signatures(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    sigs: List[Dict[str, Any]] = []
    if not isinstance(report, dict):
        return sigs
    for key in ("signatures",):
        if isinstance(report.get(key), list):
            sigs.extend([s for s in report[key] if isinstance(s, dict)])
    for target in (report.get("targets") if isinstance(report.get("targets"), list) else []):
        if isinstance(target, dict) and isinstance(target.get("signatures"), list):
            sigs.extend([s for s in target["signatures"] if isinstance(s, dict)])
    for task in (report.get("tasks") if isinstance(report.get("tasks"), list) else []):
        if isinstance(task, dict) and isinstance(task.get("signatures"), list):
            sigs.extend([s for s in task["signatures"] if isinstance(s, dict)])
    # de-dupe by name
    seen = set()
    uniq = []
    for s in sigs:
        name = str(s.get("name") or s.get("label") or "")
        if name and name in seen:
            continue
        if name:
            seen.add(name)
        uniq.append(s)
    return uniq

def _triage_collect_ttps(report: Dict[str, Any], signatures: List[Dict[str, Any]]) -> List[str]:
    ttps: List[str] = []
    for sig in signatures:
        for t in (sig.get("ttp") or sig.get("ttps") or []):
            if isinstance(t, str) and t.strip():
                ttps.append(t.strip())
    if isinstance(report, dict):
        for task in (report.get("tasks") if isinstance(report.get("tasks"), list) else []):
            if isinstance(task, dict):
                for t in (task.get("ttp") or []):
                    if isinstance(t, str) and t.strip():
                        ttps.append(t.strip())
    return list(dict.fromkeys(ttps))

def normalize_triage_sample(report: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(report, dict):
        return {}
    sample = report.get("sample") if isinstance(report.get("sample"), dict) else {}
    analysis = report.get("analysis") if isinstance(report.get("analysis"), dict) else {}
    tasks = report.get("tasks") if isinstance(report.get("tasks"), list) else []
    configs = _triage_collect_configs(report)
    signatures = _triage_collect_signatures(report)
    ttps = _triage_collect_ttps(report, signatures)

    families = _triage_str_list(analysis.get("family"))
    for task in tasks:
        families.extend(_triage_str_list(task.get("families") if isinstance(task, dict) else None))
    for target in (report.get("targets") if isinstance(report.get("targets"), list) else []):
        families.extend(_triage_str_list(target.get("family") if isinstance(target, dict) else None))
    families = list(dict.fromkeys([f for f in families if f]))

    tags = _triage_str_list(analysis.get("tags"))
    for task in tasks:
        if isinstance(task, dict):
            tags.extend(_triage_str_list(task.get("tags")))
    tags = list(dict.fromkeys([t for t in tags if t]))

    score = analysis.get("score", report.get("score", 0)) or 0
    for task in tasks:
        try:
            if isinstance(task, dict) and int(task.get("score", 0) or 0) > int(score or 0):
                score = task["score"]
        except (TypeError, ValueError):
            continue

    merged_config: Dict[str, Any] = {}
    for cfg in configs:
        for key, val in cfg.items():
            if val in (None, "", [], {}):
                continue
            if key not in merged_config:
                merged_config[key] = val
            elif isinstance(merged_config[key], list) and isinstance(val, list):
                merged_config[key] = list(dict.fromkeys(merged_config[key] + [v for v in val if v not in merged_config[key]]))

    c2_ips, c2_domains, c2_urls = [], [], []
    for cfg in configs:
        for c in (cfg.get("c2") or []):
            if isinstance(c, str) and c.strip():
                c = c.strip()
                if c.startswith("http"):
                    c2_urls.append(c)
                elif is_ip(c.split(":")[0].strip("[]")):
                    c2_ips.append(c)
                else:
                    c2_domains.append(c)
        for u in (cfg.get("urls") or cfg.get("url") or []):
            if isinstance(u, str) and u.strip():
                c2_urls.append(u.strip())
    sample_iocs = sample.get("iocs") if isinstance(sample.get("iocs"), dict) else {}
    c2_ips.extend([x for x in _triage_str_list(sample_iocs.get("ips")) if x not in c2_ips])
    c2_domains.extend([x for x in _triage_str_list(sample_iocs.get("domains")) if x not in c2_domains])
    c2_urls.extend([x for x in _triage_str_list(sample_iocs.get("urls")) if x not in c2_urls])

    extracted_files = []
    for entry in (report.get("extracted") if isinstance(report.get("extracted"), list) else []):
        if not isinstance(entry, dict):
            continue
        extracted_files.append({
            "name": entry.get("dumped_file") or entry.get("path") or entry.get("resource") or "",
            "path": entry.get("path") or "",
            "tasks": entry.get("tasks") or [],
            "md5": entry.get("md5") or "",
            "sha1": entry.get("sha1") or "",
            "sha256": entry.get("sha256") or "",
            "sha512": entry.get("sha512") or "",
            "config_family": (entry.get("config") or {}).get("family", "") if isinstance(entry.get("config"), dict) else "",
        })

    network = {"dns": [], "http": [], "connections": [], "tls": []}
    net = report.get("network") if isinstance(report.get("network"), dict) else {}
    for req in (net.get("requests") if isinstance(net.get("requests"), list) else []):
        if isinstance(req, dict) and (req.get("url") or req.get("domain") or req.get("ip")):
            network["connections"].append(req)

    relationships: List[Dict[str, Any]] = []
    sample_hash = sample.get("sha256") or sample.get("sha1") or sample.get("md5") or sample.get("id") or ""
    for fam in families:
        relationships.append({"source": sample_hash, "relation": "analyzed_as", "target": fam, "target_type": "malware_family"})
    for d in c2_domains:
        relationships.append({"source": sample_hash, "relation": "communicates_with", "target": d, "target_type": "domain"})
    for ip in c2_ips:
        relationships.append({"source": sample_hash, "relation": "communicates_with", "target": ip, "target_type": "ip"})
    for u in c2_urls:
        relationships.append({"source": sample_hash, "relation": "communicates_with", "target": u, "target_type": "url"})
    for f in extracted_files:
        child = f.get("sha256") or f.get("sha1") or f.get("md5") or ""
        if child:
            relationships.append({"source": sample_hash, "relation": "drops", "target": child, "target_type": "hash"})
            relationships.append({"source": sample_hash, "relation": "contains", "target": child, "target_type": "hash"})
    for cfg in configs:
        if isinstance(cfg.get("botnet"), str) and cfg["botnet"].strip():
            relationships.append({"source": sample_hash, "relation": "uses_botnet", "target": cfg["botnet"].strip(), "target_type": "botnet"})
        if isinstance(cfg.get("campaign"), str) and cfg["campaign"].strip():
            relationships.append({"source": sample_hash, "relation": "belongs_to_campaign", "target": cfg["campaign"].strip(), "target_type": "campaign"})
        for w in _triage_str_list(cfg.get("wallet")):
            relationships.append({"source": sample_hash, "relation": "uses_wallet", "target": w, "target_type": "wallet"})
        for m in _triage_str_list(cfg.get("mutex")):
            relationships.append({"source": sample_hash, "relation": "uses_mutex", "target": m, "target_type": "mutex"})
    for t in ttps:
        relationships.append({"source": sample_hash, "relation": "uses_technique", "target": t, "target_type": "attack_id"})

    task_ids = [t.get("task_name") or t.get("resource") or "" for t in tasks if isinstance(t, dict)]
    return {
        "source": "Triage",
        "sample": {
            "id": sample.get("id") or report.get("id") or "",
            "filename": sample.get("target") or sample.get("name") or report.get("target") or "",
            "score": score,
            "status": sample.get("status") or report.get("status") or "",
            "platform": (tasks[0].get("platform") if tasks and isinstance(tasks[0], dict) else "") or sample.get("platform") or "",
            "created": sample.get("created") or sample.get("submitted") or report.get("submitted") or "",
            "completed": sample.get("completed") or "",
            "kind": sample.get("kind") or "",
        },
        "hashes": {
            "md5": sample.get("md5") or "",
            "sha1": sample.get("sha1") or "",
            "sha256": sample.get("sha256") or "",
            "sha512": sample.get("sha512") or "",
        },
        "malware": {
            "families": families,
            "tags": tags,
            "botnet": next((c.get("botnet", "") for c in configs if isinstance(c.get("botnet"), str) and c.get("botnet").strip()), ""),
            "campaign": next((c.get("campaign", "") for c in configs if isinstance(c.get("campaign"), str) and c.get("campaign").strip()), ""),
            "version": next((c.get("version", "") for c in configs if c.get("version")), ""),
        },
        "configuration": merged_config,
        "c2": {"ips": list(dict.fromkeys(c2_ips)), "domains": list(dict.fromkeys(c2_domains)), "urls": list(dict.fromkeys(c2_urls))},
        "signatures": signatures,
        "ttps": ttps,
        "extracted_files": extracted_files,
        "network": network,
        "task_ids": [t for t in task_ids if t],
        "relationships": relationships,
    }

def _triage_enrich_one(sample: Dict[str, Any], api_key: str) -> Any:
    """Enrich a single search hit: Overview -> Summary -> raw search fallback.

    Each sample fails independently so one slow/failing Overview never fails
    the whole provider result.
    """
    try:
        if not isinstance(sample, dict):
            return None
        sample_id = sample.get("id")
        if not sample_id:
            return None
        overview = query_triage_overview(sample_id, api_key)
        if isinstance(overview, dict) and "error" not in overview:
            overview["_search"] = sample
            overview["_sample_id"] = sample_id
            return overview
        summary = query_triage_summary(sample_id, api_key)
        if isinstance(summary, dict) and "error" not in summary:
            summary["_search"] = sample
            summary["_sample_id"] = sample_id
            return summary
        # Fall back to the basic search result if reports fail
        return sample
    except Exception:
        return sample if isinstance(sample, dict) else None

def query_triage(query: str, api_key: str, max_overviews: int = 5) -> Dict[str, Any]:
    if not api_key: return {"error": "No API Key provided"}
    query = (query or "").strip()
    if not query:
        return {"error": "Empty Triage query"}
    try:
        search_data = _triage_get("/search", api_key, {"query": query}, label="Triage search")
        if isinstance(search_data, dict) and search_data.get("error"):
            return search_data
        samples = (search_data.get("data", []) if isinstance(search_data, dict) else []) or []
        if not samples:
            return {"data": []}
        try:
            cap = max(1, min(int(max_overviews or 5), 10))
        except (TypeError, ValueError):
            cap = 5

        # Enrich each sample with its Overview report concurrently
        # (compact default: no static/behavioral reports here).
        targets = [s for s in samples[:cap] if isinstance(s, dict) and s.get("id")]
        enriched_samples = []
        if targets:
            with ThreadPoolExecutor(max_workers=min(5, len(targets))) as executor:
                for item in executor.map(lambda s: _triage_enrich_one(s, api_key), targets):
                    if item is not None:
                        enriched_samples.append(item)

        normalized = []
        for item in enriched_samples:
            try:
                norm = normalize_triage_sample(item)
                if norm:
                    normalized.append(norm)
            except Exception:
                continue
        result: Dict[str, Any] = {"data": enriched_samples}
        if normalized:
            result["normalized"] = normalized
        return result
    except Exception as e:
        return {"error": str(e)}

def query_triage_ioc(indicator: str, i_type: str, api_key: str) -> Dict[str, Any]:
    """Reverse search: find Triage samples whose config contains a domain/IP/URL."""
    if not api_key:
        return {"error": "No API Key provided"}
    indicator = (indicator or "").strip()
    if not indicator:
        return {"error": "Empty indicator"}
    if i_type == "domain":
        triage_query = f"domain:{normalize_domain(indicator)}"
    elif i_type == "ip":
        triage_query = f"ip:{normalize_ip(indicator)}"
    elif i_type == "url":
        triage_query = indicator.strip()
        if not triage_query.startswith("http"):
            return {"error": "URL must start with http(s)://"}
        triage_query = f"url:{triage_query}"
    else:
        return {"error": f"Unsupported Triage IOC type: {i_type}"}
    return query_triage(triage_query, api_key, max_overviews=3)

def normalize_ip(indicator: str) -> str:
    value = indicator.strip()
    if not value:
        return ""
    candidates = [value.strip("[]")]
    parsed = urllib.parse.urlsplit(value if "://" in value else f"//{value}")
    if parsed.hostname:
        candidates.append(parsed.hostname)
    for candidate in candidates:
        candidate = candidate.strip().strip("[]")
        if "%" in candidate:
            candidate = candidate.split("%", 1)[0]
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return ""

def get_ip_version(indicator: str) -> int:
    normalized = normalize_ip(indicator)
    if not normalized:
        return 0
    return ipaddress.ip_address(normalized).version

def get_ip_scope(indicator: str) -> str:
    normalized = normalize_ip(indicator)
    if not normalized:
        return "invalid"
    addr = ipaddress.ip_address(normalized)
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_global:
        return "public"
    return "special"

def is_ip(indicator: str) -> bool:
    try:
        return bool(normalize_ip(indicator))
    except ValueError:
        return False

def is_hash(indicator: str) -> bool:
    return bool(get_hash_type(indicator))

def get_hash_type(indicator: str) -> str:
    indicator = indicator.strip()
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "sha256"
    if re.match(r"^[a-fA-F0-9]{96}$", indicator):
        return "sha3_384"
    if re.match(r"^[a-fA-F0-9]{128}$", indicator):
        return "sha512"
    return ""

def triage_hash_field(file_hash: str) -> str:
    algo = get_hash_type(file_hash)
    if algo in {"md5", "sha1", "sha256", "sha512"}:
        return algo
    lowered = file_hash.strip().lower()
    if len(lowered) == 32:
        return "md5"
    if len(lowered) == 40:
        return "sha1"
    if len(lowered) == 128:
        return "sha512"
    return "sha256"

def normalize_domain(indicator: str) -> str:
    value = indicator.strip().lower().rstrip(".")
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname or value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    except ValueError:
        host = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    
    host = host.strip().lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host

def normalize_url(indicator: str) -> str:
    value = (indicator or "").strip()
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        hostname = parsed.hostname.rstrip(".")
    except ValueError:
        return ""
        
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        hostname = hostname.lower()
        
    netloc = hostname
    try:
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
    except ValueError:
        return ""
        
    path = parsed.path or "/"
    try:
        return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, parsed.fragment))
    except ValueError:
        return ""

def is_url(indicator: str) -> bool:
    return bool(normalize_url(indicator))

def is_domain(indicator: str) -> bool:
    domain = normalize_domain(indicator)
    if len(domain) > 253 or domain.startswith("-") or domain.endswith("-"):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    valid_labels = all(re.match(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$", label) for label in labels)
    valid_tld = bool(re.match(r"^(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{2,59})$", labels[-1]))
    return valid_labels and valid_tld

def query_tip_api(path: str, api_key: str, method="GET", json_data=None) -> Dict[str, Any]:
    if not api_key: return {"error": "No API Key provided"}
    url = f"https://tip.kaspersky.com/api{path}"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        if method.upper() == "POST":
            resp = requests.post(url, headers=headers, json=json_data, timeout=15)
        else:
            resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"Status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

KTIP_IOC_SEARCH_SOURCES = ["osint_articles", "reporting"]
KTIP_FULL_SEARCH_SOURCES = ["dark_web", "surface_web", "osint_articles", "osint_summary", "reporting", "vulnerabilities"]

def query_tip_search(keyword: str, api_key: str, sources: list = None, count: int = 20) -> Dict[str, Any]:
    payload = {"query": keyword, "skip": 0, "count": count}
    if sources:
        payload["sources"] = {source: {} for source in sources}
    return query_tip_api("/search", api_key, method="POST", json_data=payload)

def query_tip(indicator_type: str, indicator: str, api_key: str) -> Dict[str, Any]:
    if not api_key: return {"error": "No API Key provided"}
    res = {}
    search_query = indicator
    
    if indicator_type == "url":
        indicator = urllib.parse.quote(indicator, safe='')

    lookup_path = f"/{indicator_type}/{indicator}"
    if indicator_type == "hash":
        sections = [
            "Zone",
            "RelatedObjects",
            "FileGeneralInfo",
            "DetectionsInfo",
            "ExploitedVulnerabilities",
            "FileDownloadedFromUrls",
            "FileAccessedUrls",
            "FileStartedObjects",
            "FileStartedBy",
            "FileDownloadedObjects",
            "FileDownloadedBy",
            "FileCertificates",
            "FileParentCertificates",
            "FileUnpackedFrom",
            "FileUnpackedObjects",
            "TTPs",
            "Actors",
            "Software",
            "Industries",
            "DataFeeds",
        ]
        query = urllib.parse.urlencode({"count": 20, "sections": ",".join(sections)})
        lookup_path = f"{lookup_path}?{query}"
    elif indicator_type == "domain":
        sections = [
            "Zone",
            "RelatedObjects",
            "DomainGeneralInfo",
            "FilesAccessed",
            "FilesDownloaded",
            "Subdomains",
            "UrlReferrals",
            "UrlReferredTo",
            "DomainWhoIsInfo",
            "DomainDnsResolutions",
            "HostSpamInfo",
            "HostPhishingInfo",
            "HostSimilarDomains",
            "DataFeeds",
            "Industries",
            "FeedMasks",
        ]
        query = urllib.parse.urlencode({"count": 20, "sections": ",".join(sections)})
        lookup_path = f"{lookup_path}?{query}"
    elif indicator_type == "ip":
        sections = [
            "Zone",
            "RelatedObjects",
            "IpGeneralInfo",
            "FilesDownloadedFromIp",
            "HostedUrls",
            "IpDnsResolutions",
            "IpWhoIs",
            "IpPhishingInfo",
            "IpSpamInfo",
            "Industries",
            "FeedMasks",
            "DataFeeds",
        ]
        query = urllib.parse.urlencode({"count": 20, "sections": ",".join(sections)})
        lookup_path = f"{lookup_path}?{query}"

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_lookup = executor.submit(query_tip_api, lookup_path, api_key)
        f_zone = executor.submit(query_tip_api, f"/zonelookup/{indicator_type}/{indicator}", api_key)
        f_search = executor.submit(query_tip_search, search_query, api_key, KTIP_IOC_SEARCH_SOURCES, 10)
        
        lookup_res = f_lookup.result()
        zone_res = f_zone.result()
        search_res = f_search.result()
        
        if "error" not in lookup_res:
            res["lookup"] = lookup_res
        else:
            res["lookup_error"] = lookup_res["error"]
            
        if "error" not in zone_res:
            res["zonelookup"] = zone_res
        else:
            res["zone_error"] = zone_res["error"]

        if "error" not in search_res:
            res["search_context"] = search_res
        else:
            res["search_error"] = search_res["error"]
            
        if "lookup" not in res and "zonelookup" not in res and "search_context" not in res:
            return {"error": res.get("lookup_error", "Failed to lookup")}
            
    return res

def query_tip_actors(api_key: str) -> Dict[str, Any]:
    return query_tip_api("/v2/actor-profiles?count=1000", api_key)

def query_tip_actor_profile(actor_id: str, api_key: str) -> Dict[str, Any]:
    return query_tip_api(f"/v2/actor-profiles/{actor_id}", api_key)

def query_tip_actor_samples(actor_id: str, api_key: str) -> Dict[str, Any]:
    return query_tip_api(f"/v2/actor-profiles/{actor_id}/related-samples?count=100", api_key)

DNSDUMPSTER_API_BASE = "https://api.dnsdumpster.com"
# Read-only allowlist (verified against dnsdumpster.com/developer). Only
# stored-dataset retrieval: domain lookup, paged results, domain map and
# CIDR banner dataset. No HackerTarget scanners/enumeration, no generic proxy.
DNSDUMPSTER_READ_PATHS = ("/domain/", "/banners/")
_DNSDUMPSTER_CACHE: Dict[str, Any] = {}
_DNSDUMPSTER_CACHE_TTL = {"hit": 21600, "miss": 3600, "map": 86400}
_DNSDUMPSTER_LAST_CALL = {"at": 0.0}
_DNSDUMPSTER_MIN_INTERVAL = 2.0

def _dnsdumpster_key(_api_key: str = "") -> str:
    return (
        os.environ.get("DNSDUMPSTER_API_KEY")
        or os.environ.get("MANTIS_DNSDUMPSTER_KEY")
        or os.environ.get("IOCINTEL_DNSDUMPSTER_KEY")
        or (_api_key or "").strip()
        or ""
    ).strip()

def _dnsdumpster_throttle() -> None:
    # Documented limit: 1 request per 2 seconds, enforced process-wide.
    try:
        import threading as _threading
        lock = _dnsdumpster_throttle.__dict__.setdefault("lock", _threading.Lock())
    except Exception:
        lock = None
    if lock is not None:
        lock.acquire()
    try:
        wait = _DNSDUMPSTER_MIN_INTERVAL - (time.time() - _DNSDUMPSTER_LAST_CALL["at"])
        if wait > 0:
            time.sleep(wait)
        _DNSDUMPSTER_LAST_CALL["at"] = time.time()
    finally:
        if lock is not None:
            try:
                lock.release()
            except Exception:
                pass

def _dnsdumpster_cache_get(key: str) -> Any:
    entry = _DNSDUMPSTER_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _DNSDUMPSTER_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value

def _dnsdumpster_cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        _DNSDUMPSTER_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass

def _dnsdumpster_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _dnsdumpster_get(path: str, api_key: str, params: Dict[str, Any] = None,
                     timeout: int = 25) -> Any:
    """Single gateway for DNSDumpster access. Only allowlisted read-only
    dataset paths are reachable; the key travels in the X-API-Key header and
    is never logged or echoed in errors/results."""
    lowered = (path or "").lower().split("?")[0]
    if not lowered.startswith(DNSDUMPSTER_READ_PATHS):
        return {"error": "DNSDumpster endpoint not allowlisted (passive-only integration)"}
    api_key = _dnsdumpster_key(api_key)
    if not api_key:
        return {"error": "No DNSDumpster key"}
    _dnsdumpster_throttle()
    try:
        resp = requests.get(f"{DNSDUMPSTER_API_BASE}{path}", headers={"X-API-Key": api_key,
                            "Accept": "application/json"}, params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"error": "DNSDumpster returned a malformed response"}
        if resp.status_code in {401, 403}:
            return {"error": "DNSDumpster authentication failure (HTTP {})".format(resp.status_code)}
        if resp.status_code == 404:
            return {"error": "Not Found"}
        if resp.status_code == 429:
            return {"error": "DNSDumpster rate limit exceeded (1 request per 2 seconds)"}
        if 500 <= resp.status_code < 600:
            return {"error": f"DNSDumpster provider error (HTTP {resp.status_code})"}
        return {"error": f"DNSDumpster request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "DNSDumpster request timeout"}
    except Exception as e:
        return {"error": f"DNSDumpster request failed: {e}"}

def _dnsdumpster_text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) and str(value).strip() else ""

def _dnsdumpster_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
    text = _dnsdumpster_text(value)
    return [text] if text else []

def normalize_dnsdumpster_ip(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    banners = entry.get("banners") if isinstance(entry.get("banners"), dict) else {}
    http = banners.get("http") if isinstance(banners.get("http"), dict) else {}
    https = banners.get("https") if isinstance(banners.get("https"), dict) else {}
    return {
        "ip": _dnsdumpster_text(entry.get("ip") or banners.get("ip") or entry.get("address")),
        "ptr": _dnsdumpster_text(entry.get("ptr") or entry.get("reverse_dns")),
        "asn": _dnsdumpster_text(entry.get("asn")),
        "asn_name": _dnsdumpster_text(entry.get("asn_name") or entry.get("asn_owner") or entry.get("as_name")),
        "asn_range": _dnsdumpster_text(entry.get("asn_range") or entry.get("netblock") or entry.get("network")),
        "country": _dnsdumpster_text(entry.get("country") or entry.get("country_name")),
        "country_code": _dnsdumpster_text(entry.get("country_code") or entry.get("cc")),
        "banners": {
            "http": {"server": _dnsdumpster_text(http.get("server")),
                     "title": _dnsdumpster_text(http.get("title")),
                     "apps": _dnsdumpster_list(http.get("apps"))[:10]},
            "https": {"server": _dnsdumpster_text(https.get("server")),
                      "title": _dnsdumpster_text(https.get("title")),
                      "cn": _dnsdumpster_text(https.get("cn")),
                      "sans": _dnsdumpster_list(https.get("alt_n") or https.get("sans"))[:25],
                      "apps": _dnsdumpster_list(https.get("apps"))[:10],
                      "ip": _dnsdumpster_text(https.get("ip"))},
        },
    }

def normalize_dnsdumpster_host(entry: Any, record_type: str) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    hostname = _dnsdumpster_text(entry.get("host") or entry.get("hostname"))
    target = _dnsdumpster_text(entry.get("target") or entry.get("cname") or entry.get("alias") or entry.get("value"))
    ips = [normalize_dnsdumpster_ip(x) for x in (entry.get("ips") or [])]
    ips = [x for x in ips if x.get("ip")]
    seen, unique = set(), []
    for ip in ips:
        if ip["ip"] not in seen:
            seen.add(ip["ip"])
            unique.append(ip)
    return {"hostname": hostname, "record_type": record_type, "target": target, "ips": unique}

def normalize_dnsdumpster_domain(raw: Any, domain: str, page: int = 1) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {
        "source": "DNSDumpster",
        "kind": "domain",
        "domain": domain,
        "page": page,
        "hosts": {"a": [], "cname": [], "mx": [], "ns": []},
        "txt": [],
        "total_a": None,
        "summary": {"hosts": 0, "unique_ips": 0, "asns": 0, "networks": 0, "countries": 0},
        "relationships": [],
        "raw": raw if isinstance(raw, dict) else {},
    }
    if not isinstance(raw, dict):
        return normalized
    for key, record_type in (("a", "A"), ("cname", "CNAME"), ("mx", "MX"), ("ns", "NS")):
        entries = raw.get(key) if isinstance(raw.get(key), list) else []
        hosts = [normalize_dnsdumpster_host(x, record_type) for x in entries]
        normalized["hosts"][key] = [h for h in hosts if h.get("hostname") or h.get("ips")]
    txt_records = []
    for item in raw.get("txt") or []:
        if isinstance(item, str) and item.strip():
            txt_records.append(item.strip())
        elif isinstance(item, dict):
            value = _dnsdumpster_text(item.get("txt") or item.get("text") or item.get("value") or item.get("record"))
            if value:
                txt_records.append(value)
    normalized["txt"] = list(dict.fromkeys(txt_records))[:50]
    try:
        normalized["total_a"] = int(raw.get("total_a_recs")) if raw.get("total_a_recs") is not None else None
    except (TypeError, ValueError):
        normalized["total_a"] = None
    ips_seen, asns, networks, countries = set(), set(), set(), set()
    host_count = 0
    for record_key, hosts in normalized["hosts"].items():
        record_type = str(record_key).upper()
        for host in hosts:
            host_count += 1
            hostname = host.get("hostname") or ""
            for ip in host.get("ips", []) or []:
                if ip.get("ip"):
                    ips_seen.add(ip["ip"])
                if ip.get("asn"):
                    asns.add(ip["asn"])
                if ip.get("asn_range"):
                    networks.add(ip["asn_range"])
                if ip.get("country"):
                    countries.add(ip["country"])
    normalized["summary"] = {"hosts": host_count, "unique_ips": len(ips_seen),
                             "asns": len(asns), "networks": len(networks), "countries": len(countries)}
    rels: List[Dict[str, Any]] = []
    seen = set()

    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen:
            seen.add(key)
            rels.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    for record_key, hosts in normalized["hosts"].items():
        record_type = str(record_key).upper()
        for host in hosts:
            hostname = host.get("hostname") or ""
            target = host.get("target") or ""
            if hostname and hostname.lower() != domain.lower():
                add_rel(domain, "has_subdomain", hostname, "hostname")
            if record_type == "MX" and hostname:
                add_rel(domain, "mail_server", hostname, "hostname")
            if record_type == "NS" and hostname:
                add_rel(domain, "nameserver", hostname, "hostname")
            if record_type == "CNAME" and hostname and target:
                add_rel(hostname, "aliases_to", target, "hostname")
            for ip in host.get("ips", []) or []:
                address = ip.get("ip") or ""
                if hostname and address:
                    if record_type == "A":
                        add_rel(domain, "resolves_to", address, "ip")
                        add_rel(hostname, "resolves_to", address, "ip")
                    elif record_type == "CNAME":
                        add_rel(hostname, "resolves_to", address, "ip")
                    elif record_type == "MX":
                        add_rel(hostname, "resolves_to", address, "ip")
                    elif record_type == "NS":
                        add_rel(hostname, "resolves_to", address, "ip")
                if address and ip.get("asn"):
                    asn_label = str(ip["asn"]).strip()
                    if not asn_label.upper().startswith("AS"):
                        asn_label = f"AS{asn_label}"
                    add_rel(address, "belongs_to", asn_label, "asn")
                if address and ip.get("asn_range"):
                    add_rel(address, "belongs_to", ip["asn_range"], "netblock")
                if address and ip.get("country"):
                    add_rel(address, "located_in", ip["country"], "country")
                if address and ip.get("ptr"):
                    add_rel(address, "reverse_resolves_to", ip["ptr"], "ptr")
                https = (ip.get("banners") or {}).get("https") or {}
                if hostname and https.get("cn"):
                    add_rel(hostname, "has_certificate_subject", https["cn"], "domain")
                for san in https.get("sans") or []:
                    if hostname and san:
                        add_rel(hostname, "has_certificate_san", san, "domain")
    for txt in normalized["txt"]:
        add_rel(domain, "has_txt_record", txt[:200], "txt")
    normalized["relationships"] = rels
    return normalized

def query_dnsdumpster(domain: str, api_key: str, page: int = 1) -> Dict[str, Any]:
    domain = normalize_domain(domain or "")
    if not domain or not is_domain(domain):
        return {"error": "DNSDumpster requires a valid domain (not an IP/URL/hash)."}
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1
    cache_key = f"dnsdumpster:domain:{domain}:{page}"
    cached = _dnsdumpster_cache_get(cache_key)
    if cached is not None:
        return cached
    params = {} if page <= 1 else {"page": page}
    raw = _dnsdumpster_get(f"/domain/{domain}", api_key, params)
    if _dnsdumpster_is_error(raw):
        return raw
    result: Dict[str, Any] = {"domain": domain, "page": page, "raw": raw,
                              "normalized": normalize_dnsdumpster_domain(raw, domain, page)}
    empty = not any(result["normalized"]["hosts"][k] for k in ("a", "cname", "mx", "ns")) \
        and not result["normalized"]["txt"]
    _dnsdumpster_cache_set(cache_key, result, _DNSDUMPSTER_CACHE_TTL["miss"] if empty else _DNSDUMPSTER_CACHE_TTL["hit"])
    return result

def query_dnsdumpster_map(domain: str, api_key: str) -> Dict[str, Any]:
    """Lazy Plus domain map (base64, large). Never fetched by default."""
    domain = normalize_domain(domain or "")
    if not domain or not is_domain(domain):
        return {"error": "DNSDumpster requires a valid domain (not an IP/URL/hash)."}
    cache_key = f"dnsdumpster:map:{domain}"
    cached = _dnsdumpster_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _dnsdumpster_get(f"/domain/{domain}", api_key, {"map": 1})
    if _dnsdumpster_is_error(raw):
        return raw
    blob = raw.get("map") if isinstance(raw, dict) else None
    if not isinstance(blob, str) or not blob:
        return {"error": "DNSDumpster domain map unavailable for this account/query"}
    result = {"source": "DNSDumpster", "domain": domain, "map": blob}
    _dnsdumpster_cache_set(cache_key, result, _DNSDUMPSTER_CACHE_TTL["map"])
    return result

def query_dnsdumpster_banners(cidr: str, api_key: str) -> Dict[str, Any]:
    """Explicit CIDR banner-dataset retrieval for Infra Search. The query is
    never split: oversized networks are rejected, not subdivided."""
    value = (cidr or "").strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return {"error": "DNSDumpster banners require valid CIDR notation (e.g. 192.0.2.0/24)."}
    if network.num_addresses > 256:
        return {"error": "CIDR too large for DNSDumpster (max ~256 hosts per query); narrow the range instead of splitting it."}
    cache_key = f"dnsdumpster:banners:{str(network)}"
    cached = _dnsdumpster_cache_get(cache_key)
    if cached is not None:
        return cached
    raw = _dnsdumpster_get(f"/banners/{str(network)}", api_key, {})
    if _dnsdumpster_is_error(raw):
        return raw
    entries = raw if isinstance(raw, list) else (raw.get("data") if isinstance(raw, dict) and isinstance(raw.get("data"), list) else [])
    hosts = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        banners = entry.get("banners") if isinstance(entry.get("banners"), dict) else {}
        http = banners.get("http") if isinstance(banners.get("http"), dict) else entry.get("http") if isinstance(entry.get("http"), dict) else {}
        https = banners.get("https") if isinstance(banners.get("https"), dict) else entry.get("https") if isinstance(entry.get("https"), dict) else {}
        ip = _dnsdumpster_text(entry.get("ip") or banners.get("ip") or entry.get("host"))
        if not ip:
            continue
        hosts.append({
            "ip": ip,
            "port": entry.get("port"),
            "protocol": _dnsdumpster_text(entry.get("protocol") or entry.get("scheme")),
            "server": _dnsdumpster_text(http.get("server") or https.get("server") or entry.get("server")),
            "title": _dnsdumpster_text(http.get("title") or https.get("title") or entry.get("title")),
            "hostname": _dnsdumpster_text(entry.get("hostname") or entry.get("host")),
            "ptr": _dnsdumpster_text(entry.get("ptr")),
            "asn": _dnsdumpster_text(entry.get("asn")),
            "asn_name": _dnsdumpster_text(entry.get("asn_name") or entry.get("asn_owner")),
            "asn_range": _dnsdumpster_text(entry.get("asn_range") or entry.get("netblock") or entry.get("network")),
            "country": _dnsdumpster_text(entry.get("country")),
            "country_code": _dnsdumpster_text(entry.get("country_code")),
            "banners": {
                "http": {
                    "server": _dnsdumpster_text(http.get("server")),
                    "title": _dnsdumpster_text(http.get("title")),
                    "apps": _dnsdumpster_list(http.get("apps"))[:10],
                },
                "https": {
                    "server": _dnsdumpster_text(https.get("server")),
                    "title": _dnsdumpster_text(https.get("title")),
                    "cn": _dnsdumpster_text(https.get("cn")),
                    "sans": _dnsdumpster_list(https.get("alt_n") or https.get("sans"))[:25],
                    "apps": _dnsdumpster_list(https.get("apps"))[:10],
                },
            },
        })
    seen, unique = set(), []
    for host in hosts:
        key = (host["ip"], str(host.get("port") or ""))
        if key not in seen:
            seen.add(key)
            unique.append(host)
    relationships = []
    seen_rels = set()

    def add_rel(source: str, relation: str, target: str, target_type: str) -> None:
        if not source or not target:
            return
        key = (source, relation, target)
        if key not in seen_rels:
            seen_rels.add(key)
            relationships.append({"source": source, "relation": relation, "target": target, "target_type": target_type})

    for host in unique:
        address = host.get("ip") or ""
        add_rel(str(network), "contains_observed", address, "ip")
        if host.get("hostname"):
            add_rel(address, "observed_hostname", host["hostname"], "hostname")
        if host.get("asn"):
            asn = host["asn"] if str(host["asn"]).upper().startswith("AS") else f"AS{host['asn']}"
            add_rel(address, "belongs_to", asn, "asn")
        if host.get("asn_range"):
            add_rel(address, "belongs_to", host["asn_range"], "netblock")
        if host.get("country"):
            add_rel(address, "located_in", host["country"], "country")
        if host.get("ptr"):
            add_rel(address, "reverse_resolves_to", host["ptr"], "ptr")
        https = (host.get("banners") or {}).get("https") or {}
        if https.get("cn"):
            add_rel(address, "has_certificate_subject", https["cn"], "domain")
        for san in https.get("sans") or []:
            add_rel(address, "has_certificate_san", san, "domain")

    result = {"source": "DNSDumpster", "kind": "banners", "cidr": str(network),
              "hosts": unique, "relationships": relationships}
    _dnsdumpster_cache_set(cache_key, result, _DNSDUMPSTER_CACHE_TTL["hit"] if unique else _DNSDUMPSTER_CACHE_TTL["miss"])
    return result


def _query_reputation_feeds_domain(domain: str) -> Dict[str, Any]:
    try:
        from feed_intel import match_domain
        res = match_domain(domain)
        matches = res.get("matches", [])
        if not matches:
            return {"matches": [], "note": "No local feed intelligence found."}
        
        feeds_out = {}
        for m in matches:
            src = m.get("source", "Unknown Feed")
            cat = m.get("category")
            if cat:
                src = f"{src} ({cat})"
            feeds_out[src] = {
                "Value": m.get("value"),
                "Confidence": m.get("confidence"),
                "First Seen": m.get("first_seen"),
                "Last Seen": m.get("last_seen")
            }
            if m.get("metadata"):
                feeds_out[src].update(m.get("metadata"))
        return feeds_out if feeds_out else {"matches": [], "note": "No local feed intelligence found."}
    except Exception as e:
        return {"error": f"Local feed query failed: {str(e)}"}

def _query_reputation_feeds_ip(ip: str) -> Dict[str, Any]:
    try:
        from feed_intel import match_ip
        res = match_ip(ip)
        matches = res.get("matches", [])
        if not matches:
            return {"matches": [], "note": "No local feed intelligence found."}
        
        feeds_out = {}
        for m in matches:
            src = m.get("source", "Unknown Feed")
            cat = m.get("category")
            if cat:
                src = f"{src} ({cat})"
            feeds_out[src] = {
                "Value": m.get("value"),
                "Confidence": m.get("confidence"),
                "First Seen": m.get("first_seen"),
                "Last Seen": m.get("last_seen")
            }
            if m.get("metadata"):
                feeds_out[src].update(m.get("metadata"))
        return feeds_out if feeds_out else {"matches": [], "note": "No local feed intelligence found."}
    except Exception as e:
        return {"error": f"Local feed query failed: {str(e)}"}

def do_domain_intel(domain: str, vt_key: str = "", abusech_key: str = "", otx_key: str = "", tip_key: str = "", cb_key: str = "", rwlive_key: str = "", triage_key: str = "", ha_key: str = "", silentpush_key: str = "", driftnet_key: str = "", urlscan_key: str = "", shodan_key: str = "", censys_key: str = "", etugen_key: str = "", pulsedive_key: str = "", fofa_key: str = "", validin_key: str = "", netlas_key: str = "", zoomeye_key: str = "", twitter_key: str = "", github_key: str = "", dnsdumpster_key: str = "", leakix_key: str = "", phishstats_key: str = "", misp_url: str = "", misp_key: str = "", misp_verify_ssl: Any = None, sources: list = None) -> Dict[str, Any]:
    sources = _allowed_sources("domain", sources)
    inc = (lambda s: s in sources)
    domain = normalize_domain(domain)
    started_at = time.perf_counter()
    res = {"indicator": domain, "type": "domain"}

    with ThreadPoolExecutor(max_workers=24) as executor:
        futures = {}
        if inc("tip"): futures["tip"] = executor.submit(query_tip, 'domain', domain, tip_key)
        if inc("virustotal"): futures["virustotal"] = executor.submit(query_vt, domain, 'domain', vt_key)
        if inc("threatfox"): futures["threatfox"] = executor.submit(query_threatfox, domain, abusech_key)
        if inc("alienvault"): futures["alienvault"] = executor.submit(query_otx, domain, 'domain', otx_key)
        if inc("silentpush"): futures["silentpush"] = executor.submit(query_silent_push, domain, 'domain', silentpush_key)
        if inc("driftnet"): futures["driftnet"] = executor.submit(query_driftnet, domain, 'domain', driftnet_key)
        if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan, domain, 'domain', urlscan_key)
        if inc("shodan"): futures["shodan"] = executor.submit(query_shodan_domain, domain, shodan_key)
        if inc("censys"): futures["censys"] = executor.submit(query_censys, domain, 'domain', censys_key)
        if inc("etugen") and etugen_key: futures["etugen"] = executor.submit(query_etugen, domain, etugen_key)
        if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive, domain, pulsedive_key)
        if inc("fofa") and fofa_key: futures["fofa"] = executor.submit(query_fofa_domain, domain, fofa_key)
        if inc("validin") and validin_key: futures["validin"] = executor.submit(query_validin_domain, domain, validin_key)
        if inc("netlas"): futures["netlas"] = executor.submit(query_netlas, domain, "domain", netlas_key)
        if inc("zoomeye"): futures["zoomeye"] = executor.submit(query_zoomeye_domain, domain, zoomeye_key)
        if inc("archive"): futures["archive"] = executor.submit(query_archive_cdx, domain)
        if inc("github") and github_key: futures["github"] = executor.submit(query_github_search, domain, 'domain', github_key)
        if inc("rss_intel"): futures["rss_intel"] = executor.submit(query_local_rss, domain)
        if inc("reputation_feeds"): futures["reputation_feeds"] = executor.submit(_query_reputation_feeds_domain, domain)
        if inc("cti_articles"): futures["cti_mentions"] = executor.submit(_query_cti_mentions, "domain", domain)
        if inc("x_monitor"): futures["x_monitor"] = executor.submit(_query_x_monitor_keyword, domain)
        if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, domain, twitter_key, "domain")
        if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, domain)
        if inc("threatminer"): futures["threatminer"] = executor.submit(query_threatminer_domain, domain)
        if inc("crtsh"): futures["crtsh"] = executor.submit(query_crtsh, domain)
        if inc("leakix") and leakix_key: futures["leakix"] = executor.submit(query_leakix_domain_full, domain, leakix_key)
        if inc("phishstats"): futures["phishstats"] = executor.submit(query_phishstats_domain, domain, phishstats_key)
        if inc("misp"): futures["misp"] = executor.submit(query_misp_ioc, domain, "domain", misp_url, misp_key, misp_verify_ssl)
        if inc("openphish"): futures["openphish"] = executor.submit(_query_openphish_domain, domain)
        if inc("commoncrawl"): futures["commoncrawl"] = executor.submit(query_commoncrawl, domain, "domain")
        if inc("tweetfeed"): futures["tweetfeed"] = executor.submit(query_tweetfeed_ioc, domain)
        if inc("dnsdumpster"): futures["dnsdumpster"] = executor.submit(query_dnsdumpster, domain, dnsdumpster_key)
        if inc("orkl"): futures["orkl"] = executor.submit(query_orkl_exact, domain)
        if inc("cb"): futures["cb"] = executor.submit(query_cb_ioc, domain, cb_key)
        if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_domain, domain, ha_key)
        if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live_victims, domain, rwlive_key)
        if inc("triage"): futures["triage"] = executor.submit(query_triage_ioc, domain, "domain", triage_key)
        res.update(_collect_futures(futures))

    res["sources_queried"] = [key for key in res.keys() if key not in {"indicator", "type", "sources_queried", "duration_ms"}]
    res["duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    return res

def do_ip_intel(ip: str, vt_key: str = "", abusech_key: str = "", otx_key: str = "", tip_key: str = "", cb_key: str = "", threatbook_key: str = "", triage_key: str = "", ha_key: str = "", silentpush_key: str = "", driftnet_key: str = "", urlscan_key: str = "", shodan_key: str = "", censys_key: str = "", etugen_key: str = "", pulsedive_key: str = "", fofa_key: str = "", validin_key: str = "", netlas_key: str = "", zoomeye_key: str = "", twitter_key: str = "", github_key: str = "", abuseipdb_key: str = "", greynoise_key: str = "", leakix_key: str = "", phishstats_key: str = "", misp_url: str = "", misp_key: str = "", misp_verify_ssl: Any = None, sources: list = None) -> Dict[str, Any]:
    sources = _allowed_sources("ip", sources)
    inc = (lambda s: s in sources)
    ip = normalize_ip(ip)
    ip_version = get_ip_version(ip)
    started_at = time.perf_counter()
    res = {"indicator": ip, "type": "ip", "ip_version": ip_version, "ip_scope": get_ip_scope(ip)}

    with ThreadPoolExecutor(max_workers=24) as executor:
        futures = {}
        if inc("tip"): futures["tip"] = executor.submit(query_tip, 'ip', ip, tip_key)
        if inc("virustotal"): futures["virustotal"] = executor.submit(query_vt, ip, 'ip', vt_key)
        if inc("threatfox"): futures["threatfox"] = executor.submit(query_threatfox, ip, abusech_key)
        if inc("alienvault"): futures["alienvault"] = executor.submit(query_otx, ip, 'IPv6' if ip_version == 6 else 'IPv4', otx_key)
        if inc("threatbook"): futures["threatbook"] = executor.submit(query_threatbook_ip, ip, threatbook_key)
        if inc("silentpush"): futures["silentpush"] = executor.submit(query_silent_push, ip, 'ip', silentpush_key)
        if inc("driftnet"): futures["driftnet"] = executor.submit(query_driftnet, ip, 'ip', driftnet_key)
        if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan, ip, 'ip', urlscan_key)
        if inc("shodan"): futures["shodan"] = executor.submit(query_shodan, ip, shodan_key)
        if inc("censys"): futures["censys"] = executor.submit(query_censys, ip, 'ip', censys_key)
        if inc("etugen") and etugen_key: futures["etugen"] = executor.submit(query_etugen, ip, etugen_key)
        if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive, ip, pulsedive_key)
        if inc("fofa") and fofa_key: futures["fofa"] = executor.submit(query_fofa_ip, ip, fofa_key)
        if inc("validin") and validin_key: futures["validin"] = executor.submit(query_validin_ip, ip, validin_key)
        if inc("netlas"): futures["netlas"] = executor.submit(query_netlas, ip, "ip", netlas_key)
        if inc("zoomeye"): futures["zoomeye"] = executor.submit(query_zoomeye_ip, ip, zoomeye_key)
        if inc("rss_intel"): futures["rss_intel"] = executor.submit(query_local_rss, ip)
        if inc("reputation_feeds"): futures["reputation_feeds"] = executor.submit(_query_reputation_feeds_ip, ip)
        if inc("cti_articles"): futures["cti_mentions"] = executor.submit(_query_cti_mentions, "ip", ip)
        if inc("x_monitor"): futures["x_monitor"] = executor.submit(_query_x_monitor_keyword, ip)
        if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, ip, twitter_key, "ip")
        if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, ip)
        if inc("threatminer"): futures["threatminer"] = executor.submit(query_threatminer_host, ip)
        if inc("greynoise"): futures["greynoise"] = executor.submit(query_greynoise, ip, greynoise_key)
        if inc("ripe"): futures["ripe"] = executor.submit(query_ripe_network, ip)
        if inc("leakix") and leakix_key: futures["leakix"] = executor.submit(query_leakix_host, ip, leakix_key)
        if inc("phishstats"): futures["phishstats"] = executor.submit(query_phishstats_ip, ip, phishstats_key)
        if inc("misp"): futures["misp"] = executor.submit(query_misp_ioc, ip, "ip", misp_url, misp_key, misp_verify_ssl)
        if inc("sans"): futures["sans"] = executor.submit(query_sans_ip, ip)
        if inc("tweetfeed"): futures["tweetfeed"] = executor.submit(query_tweetfeed_ioc, ip)
        if inc("abuseipdb") and abuseipdb_key: futures["abuseipdb"] = executor.submit(query_abuseipdb, ip, abuseipdb_key)
        if inc("orkl"): futures["orkl"] = executor.submit(query_orkl_exact, ip)
        if inc("cb"): futures["cb"] = executor.submit(query_cb_ioc, ip, cb_key)
        if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_ip, ip, ha_key)
        if inc("triage"): futures["triage"] = executor.submit(query_triage_ioc, ip, "ip", triage_key)
        res.update(_collect_futures(futures))
        # CIRCL SSL rides along with the PDNS card (one UI card per provider).
        if isinstance(res.get("circl_ssl"), dict) and "error" not in res["circl_ssl"]:
            base = res.get("circl") if isinstance(res.get("circl"), dict) else {}
            if "error" not in base:
                base = dict(base)
                base["ssl_certificates"] = res["circl_ssl"].get("certificates", [])
                res["circl"] = base
        if "circl_ssl" in res:
            del res["circl_ssl"]

    res["sources_queried"] = [key for key in res.keys() if key not in {"indicator", "type", "ip_version", "ip_scope", "sources_queried", "duration_ms"}]
    res["duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    return res

def do_url_intel(url: str, vt_key: str = "", abusech_key: str = "", otx_key: str = "", tip_key: str = "", cb_key: str = "", triage_key: str = "", ha_key: str = "", silentpush_key: str = "", urlscan_key: str = "", pulsedive_key: str = "", twitter_key: str = "", github_key: str = "", phishstats_key: str = "", misp_url: str = "", misp_key: str = "", misp_verify_ssl: Any = None, sources: list = None) -> Dict[str, Any]:
    sources = _allowed_sources("url", sources)
    inc = (lambda s: s in sources)
    url = normalize_url(url)
    started_at = time.perf_counter()
    res = {"indicator": url, "type": "url"}

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {}
        if inc("virustotal"): futures["virustotal"] = executor.submit(query_vt, url, "url", vt_key)
        if inc("threatfox"): futures["threatfox"] = executor.submit(query_threatfox, url, abusech_key)
        if inc("alienvault"): futures["alienvault"] = executor.submit(query_otx, url, "url", otx_key)
        if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan, url, "url", urlscan_key)
        if inc("tip"): futures["tip"] = executor.submit(query_tip, "url", url, tip_key)
        if inc("cb"): futures["cb"] = executor.submit(query_cb_ioc, url, cb_key)
        if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_url, url, ha_key)
        if inc("triage"): futures["triage"] = executor.submit(query_triage_ioc, url, "url", triage_key)
        if inc("orkl"): futures["orkl"] = executor.submit(query_orkl_exact, url)
        if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive, url, pulsedive_key)
        if inc("archive"): futures["archive"] = executor.submit(query_archive_cdx, url)
        if inc("github"): futures["github"] = executor.submit(query_github_search, url, "url", github_key)
        if inc("rss_intel"): futures["rss_intel"] = executor.submit(query_local_rss, url)
        if inc("cti_articles"): futures["cti_mentions"] = executor.submit(_query_cti_mentions, "url", url)
        if inc("x_monitor"): futures["x_monitor"] = executor.submit(_query_x_monitor_keyword, url)
        if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, url, twitter_key, "url")
        if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, url)
        if inc("urlhaus") and abusech_key: futures["urlhaus"] = executor.submit(query_urlhaus_url, url, abusech_key)
        if inc("phishstats"): futures["phishstats"] = executor.submit(query_phishstats_url, url, phishstats_key)
        if inc("misp"): futures["misp"] = executor.submit(query_misp_ioc, url, "url", misp_url, misp_key, misp_verify_ssl)
        if inc("openphish"): futures["openphish"] = executor.submit(_query_openphish_url, url)
        if inc("tweetfeed"): futures["tweetfeed"] = executor.submit(query_tweetfeed_ioc, url)
        res.update(_collect_futures(futures))

    res["sources_queried"] = [key for key in res.keys() if key not in {"indicator", "type", "sources_queried", "duration_ms"}]
    res["duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    return res

def do_infra_intel(indicator: str, silentpush_key: str = "", driftnet_key: str = "", shodan_key: str = "", censys_key: str = "", etugen_key: str = "", pulsedive_key: str = "", fofa_key: str = "", validin_key: str = "", ha_key: str = "", abuseipdb_key: str = "", urlscan_key: str = "", dnsdumpster_key: str = "", greynoise_key: str = "", netlas_key: str = "", vt_key: str = "", sources: list = None) -> Dict[str, Any]:
    sources = _allowed_sources("infra", sources)
    inc = (lambda s: s in sources)
    raw_indicator = (indicator or "").strip()
    domain_candidate = normalize_domain(raw_indicator)
    ip_candidate = normalize_ip(raw_indicator)
    cidr_candidate = ""
    try:
        parsed = ipaddress.ip_network(raw_indicator, strict=False)
        # Only explicit CIDR notation (not bare IPs) takes the block path.
        if "/" in raw_indicator:
            cidr_candidate = str(parsed)
    except ValueError:
        cidr_candidate = ""
    if cidr_candidate:
        query_type = "cidr"
        query_value = cidr_candidate
    elif re.fullmatch(r"(?i)AS\d{1,10}", raw_indicator):
        query_type = "asn"
        query_value = raw_indicator.upper()
        if not query_value.startswith("AS"):
            query_value = "AS" + query_value
    elif is_ip(ip_candidate):
        query_type = "ip"
        query_value = ip_candidate
    elif ":" not in raw_indicator and is_domain(domain_candidate):
        query_type = "domain"
        query_value = domain_candidate
    else:
        query_type = "keyword"
        query_value = raw_indicator

    started_at = time.perf_counter()
    res = {"indicator": query_value, "type": "infra", "infra_query_type": query_type}

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {}
        if query_type == "cidr":
            if inc("abuseipdb") and abuseipdb_key: futures["abuseipdb"] = executor.submit(query_abuseipdb_check_block, query_value, abuseipdb_key)
            if inc("dnsdumpster"): futures["dnsdumpster"] = executor.submit(query_dnsdumpster_banners, query_value, dnsdumpster_key)
            if inc("driftnet"): futures["driftnet"] = executor.submit(query_driftnet, query_value, "ip", driftnet_key)
            if inc("shodan"): futures["shodan"] = executor.submit(query_shodan_search, query_value, shodan_key, query_type="cidr")
            if inc("censys"): futures["censys"] = executor.submit(query_censys, query_value, "cidr", censys_key)
            if inc("fofa") and fofa_key: futures["fofa"] = executor.submit(query_fofa, query_value, fofa_key, query_type="cidr")
            if inc("validin") and validin_key: futures["validin"] = executor.submit(query_validin_cidr, query_value, validin_key)
            if inc("netlas") and netlas_key: futures["netlas"] = executor.submit(query_netlas, query_value, "cidr", netlas_key)
        elif query_type == "ip":
            if inc("silentpush"): futures["silentpush"] = executor.submit(query_silent_push, query_value, "ip", silentpush_key)
            if inc("driftnet"): futures["driftnet"] = executor.submit(query_driftnet, query_value, "ip", driftnet_key)
            if inc("shodan"): futures["shodan"] = executor.submit(query_shodan_ip, query_value, shodan_key)
            if inc("censys"): futures["censys"] = executor.submit(query_censys, query_value, "ip", censys_key)
            if inc("etugen") and etugen_key: futures["etugen"] = executor.submit(query_etugen, query_value, etugen_key)
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive, query_value, pulsedive_key)
            if inc("fofa") and fofa_key: futures["fofa"] = executor.submit(query_fofa_ip, query_value, fofa_key)
            if inc("validin") and validin_key: futures["validin"] = executor.submit(query_validin_ip, query_value, validin_key)
            if inc("abuseipdb") and abuseipdb_key: futures["abuseipdb"] = executor.submit(query_abuseipdb, query_value, abuseipdb_key)
            if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan, query_value, "ip", urlscan_key)
            if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_ip, query_value, ha_key)
            if inc("greynoise"): futures["greynoise"] = executor.submit(query_greynoise, query_value, greynoise_key)
            if inc("ripe"): futures["ripe"] = executor.submit(query_ripe_network, query_value)
            if inc("netlas") and netlas_key: futures["netlas"] = executor.submit(query_netlas, query_value, "ip", netlas_key)
            if (inc("virustotal") or inc("vt")) and vt_key: futures["virustotal"] = executor.submit(query_vt, query_value, "ip", vt_key)

        elif query_type == "domain":
            if inc("silentpush"): futures["silentpush"] = executor.submit(query_silent_push, query_value, "domain", silentpush_key)
            if inc("driftnet"): futures["driftnet"] = executor.submit(query_driftnet, query_value, "domain", driftnet_key)
            if inc("shodan"): futures["shodan"] = executor.submit(query_shodan_domain, query_value, shodan_key)
            if inc("censys"): futures["censys"] = executor.submit(query_censys, query_value, "domain", censys_key)
            if inc("etugen") and etugen_key: futures["etugen"] = executor.submit(query_etugen, query_value, etugen_key)
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive, query_value, pulsedive_key)
            if inc("fofa") and fofa_key: futures["fofa"] = executor.submit(query_fofa_domain, query_value, fofa_key)
            if inc("validin") and validin_key: futures["validin"] = executor.submit(query_validin_domain, query_value, validin_key)
            if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan, query_value, "domain", urlscan_key)
            if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_domain, query_value, ha_key)

            if inc("commoncrawl"): futures["commoncrawl"] = executor.submit(query_commoncrawl, query_value, "domain")
            if inc("crtsh"): futures["crtsh"] = executor.submit(query_crtsh, query_value)
            if inc("netlas") and netlas_key: futures["netlas"] = executor.submit(query_netlas, query_value, "domain", netlas_key)
            if (inc("virustotal") or inc("vt")) and vt_key: futures["virustotal"] = executor.submit(query_vt, query_value, "domain", vt_key)
        elif query_type == "asn":
            if inc("shodan"): futures["shodan"] = executor.submit(query_shodan_search, query_value, shodan_key, query_type="asn")
            if inc("censys"): futures["censys"] = executor.submit(query_censys, query_value, "asn", censys_key)
            if inc("fofa") and fofa_key: futures["fofa"] = executor.submit(query_fofa, query_value, fofa_key, query_type="asn")
            if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan_infra, query_value, urlscan_key)
            if inc("driftnet"): futures["driftnet"] = executor.submit(query_driftnet_keyword, query_value, driftnet_key)
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, query_value, pulsedive_key)
            if inc("etugen") and etugen_key: futures["etugen"] = executor.submit(query_etugen_keyword, query_value, etugen_key)
            if inc("ripe"): futures["ripe"] = executor.submit(query_ripe_asn, query_value)
            if inc("netlas") and netlas_key: futures["netlas"] = executor.submit(query_netlas, query_value, "asn", netlas_key)

        else:
            if inc("silentpush"): futures["silentpush"] = executor.submit(query_silent_push, query_value, "keyword", silentpush_key)
            if inc("driftnet"): futures["driftnet"] = executor.submit(query_driftnet_keyword, query_value, driftnet_key)
            if inc("shodan"): futures["shodan"] = executor.submit(query_shodan_keyword, query_value, shodan_key)
            if inc("censys"): futures["censys"] = executor.submit(query_censys, query_value, "keyword", censys_key)
            if inc("etugen") and etugen_key: futures["etugen"] = executor.submit(query_etugen_keyword, query_value, etugen_key)
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, query_value, pulsedive_key)
            if inc("fofa") and fofa_key: futures["fofa"] = executor.submit(query_fofa, query_value, fofa_key)
            # NOTE: no Validin advanced-query call for free-text infra keywords
            # (Enterprise-only, quota-sensitive). Typed fingerprint pivots are
            # explicit below; the advanced endpoint stays available via the
            # dedicated lazy lookup only.
            if inc("validin") and validin_key:
                fp_kind = _detect_validin_fingerprint_kind(query_value)
                if fp_kind:
                    futures["validin"] = executor.submit(query_validin_fingerprint, query_value, fp_kind, validin_key)
            if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan_infra, query_value, urlscan_key)
            if inc("netlas") and netlas_key: futures["netlas"] = executor.submit(query_netlas, query_value, "infra", netlas_key)
        res.update(_collect_futures(futures))


    res["sources_queried"] = [key for key in res.keys() if key not in {"indicator", "type", "infra_query_type", "sources_queried", "duration_ms"}]
    res["duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    return res

def do_hash_intel(file_hash: str, vt_key: str = "", abusech_key: str = "", otx_key: str = "", triage_key: str = "", tip_key: str = "", cb_key: str = "", ha_key: str = "", malshare_key: str = "", silentpush_key: str = "", driftnet_key: str = "", pulsedive_key: str = "", fofa_key: str = "", validin_key: str = "", urlscan_key: str = "", twitter_key: str = "", github_key: str = "", misp_url: str = "", misp_key: str = "", misp_verify_ssl: Any = None, sources: list = None, github_repos: list = None) -> Dict[str, Any]:
    sources = _allowed_sources("hash", sources)
    inc = (lambda s: s in sources)
    file_hash = file_hash.lower()
    hash_algorithm = get_hash_type(file_hash)
    triage_op = triage_hash_field(file_hash)
    started_at = time.perf_counter()
    res = {
        "indicator": file_hash,
        "type": "hash",
        "hash_algorithm": hash_algorithm,
    }

    with ThreadPoolExecutor(max_workers=24) as executor:
        futures = {}
        if inc("tip"): futures["tip"] = executor.submit(query_tip, 'hash', file_hash, tip_key)
        if inc("virustotal"): futures["virustotal"] = executor.submit(query_vt, file_hash, 'hash', vt_key)
        if inc("threatfox"): futures["threatfox"] = executor.submit(query_threatfox, file_hash, abusech_key)
        if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_malwarebazaar, file_hash, abusech_key)
        if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_hash, file_hash, abusech_key)
        if inc("alienvault"): futures["alienvault"] = executor.submit(query_otx, file_hash, 'file', otx_key)
        if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_hybrid_analysis, file_hash, ha_key)
        if inc("triage"): futures["triage"] = executor.submit(query_triage, f"{triage_op}:{file_hash}", triage_key)
        if inc("cb"): futures["cb"] = executor.submit(query_cb_ioc, file_hash, cb_key)
        if inc("malshare") and malshare_key: futures["malshare"] = executor.submit(query_malshare_hash, file_hash, malshare_key)
        if inc("github"): futures["github"] = executor.submit(query_github_search, file_hash, 'hash', github_key)
        if inc("github_repos"): futures["github_repos"] = executor.submit(query_github_specific_repos, file_hash, github_key, github_repos)
        if inc("rss_intel"): futures["rss_intel"] = executor.submit(query_local_rss, file_hash)
        if inc("cti_articles"): futures["cti_mentions"] = executor.submit(_query_cti_mentions, "hash", file_hash)
        if inc("x_monitor"): futures["x_monitor"] = executor.submit(_query_x_monitor_keyword, file_hash)
        if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, file_hash, twitter_key, "hash")
        if inc("yara_forge"): futures["yara_forge"] = executor.submit(query_local_yara_rules, file_hash, tip_key)
        if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, file_hash)
        if inc("threatminer"): futures["threatminer"] = executor.submit(query_threatminer_sample, file_hash)
        if inc("urlhaus") and abusech_key and get_hash_type(file_hash) == "sha256": futures["urlhaus"] = executor.submit(query_urlhaus_payload, file_hash, abusech_key)
        if inc("tweetfeed"): futures["tweetfeed"] = executor.submit(query_tweetfeed_ioc, file_hash)
        if inc("misp"): futures["misp"] = executor.submit(query_misp_ioc, file_hash, "hash", misp_url, misp_key, misp_verify_ssl)

        res.update(_collect_futures(futures))

    res["sources_queried"] = [key for key in res.keys() if key not in {"indicator", "type", "hash_algorithm", "sources_queried", "duration_ms"}]
    res["duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    return res

def _query_cti_articles(keyword: str) -> Dict[str, Any]:
    """Local CTI article search (deferred import: cti_query imports this module)."""
    from cti_query import query_cti_articles
    try:
        return query_cti_articles(keyword)
    except Exception as e:
        return {"error": str(e)[:300], "total": 0, "results": []}


def _query_cti_mentions(kind: str, value: str) -> Dict[str, Any]:
    """Local CTI article mentions for IOC lookups.

    Local-only, instant, no key, no network. Mentions are context, never a verdict.
    """
    from cti_query import article_mentions
    try:
        return article_mentions(kind, value)
    except Exception as e:
        return {"error": str(e)[:300], "total": 0, "articles": []}


def _query_galaxy_scope(scope: str, keyword: str, source: str) -> Dict[str, Any]:
    """Scoped MISP Galaxy search used by keyword sources."""
    from misp_galaxy import search_scope
    try:
        out = search_scope(scope, keyword, limit=25, offset=0)
        if isinstance(out, dict):
            out["source"] = source
        return out
    except Exception as e:
        return {"error": str(e)[:300], "total": 0, "results": [], "source": source}


def _query_threat_actor_knowledge(keyword: str) -> Dict[str, Any]:
    return _query_galaxy_scope("all-threat-actors", keyword, "Threat Actor")


def _query_malware_tools_knowledge(keyword: str) -> Dict[str, Any]:
    return _query_galaxy_scope("all-malware-tools", keyword, "Malware & Tools")


def _query_ransom_yara_explorer(keyword: str, rwlive_key: str = "") -> Dict[str, Any]:
    """Search the Ransomware Monitor YARA explorer rows for keyword context."""
    from ransomware_monitor import detection_iocs_page
    q = (keyword or "").strip().lower()
    try:
        data = detection_iocs_page({"rwlive_key": rwlive_key or ""})
        rows = data.get("yara") if isinstance(data, dict) else []
        if not isinstance(rows, list):
            rows = []
        if q:
            def matches(row: Any) -> bool:
                if not isinstance(row, dict):
                    return q in str(row).lower()
                fields = [
                    row.get("group"),
                    row.get("filename"),
                    row.get("count"),
                    row.get("content"),
                    json.dumps(row.get("raw"), ensure_ascii=False) if row.get("raw") is not None else "",
                ]
                return q in " ".join(str(v or "").lower() for v in fields)
            rows = [row for row in rows if matches(row)]
        return {
            "query": keyword,
            "total": len(rows),
            "yara": rows[:50],
            "sources": data.get("sources", []) if isinstance(data, dict) else [],
        }
    except Exception as e:
        return {"error": str(e)[:300], "total": 0, "yara": []}


def _query_vulnerability_intel(keyword: str) -> Dict[str, Any]:
    try:
        import pocindex_mod
        out = pocindex_mod.search_poc(query=keyword, limit=25, offset=0, sort_by="NEWEST")
        if isinstance(out, dict):
            out["source"] = "Vulnerability Intelligence"
        return out
    except Exception as e:
        return {"error": str(e)[:300], "total": 0, "results": []}


def _query_x_monitor_keyword(keyword: str) -> Dict[str, Any]:
    try:
        import x_monitor
        out = x_monitor.dashboard({
            "q": keyword,
            "range": "30d",
            "sort": "newest",
            "page": 1,
            "page_size": 12,
        })
        return {
            "query": keyword,
            "posts": out.get("posts", []) if isinstance(out, dict) else [],
            "pagination": out.get("pagination", {}) if isinstance(out, dict) else {},
            "stats": out.get("stats", {}) if isinstance(out, dict) else {},
            "health": out.get("health", {}) if isinstance(out, dict) else {},
        }
    except Exception as e:
        return {"error": str(e)[:300], "posts": [], "pagination": {"total": 0}}


def query_tweetfeed_ioc(indicator: str) -> Dict[str, Any]:
    try:
        return tweetfeed_service.ioc_lookup(indicator)
    except Exception as e:
        return {"error": str(e)[:300], "found": False, "records": []}


def query_threatactorusernames(keyword: str) -> Dict[str, Any]:
    keyword = (keyword or "").strip()
    if not keyword or len(keyword) < 2:
        return {"error": "Keyword too short"}
    try:
        url = f"https://threatactorusernames.com/api/search?q={urllib.parse.quote(keyword)}"
        res = requests.get(url, timeout=15)
        if res.status_code != 200:
            return {"error": f"HTTP {res.status_code}"}
        data = res.json()
        if not data.get("found"):
            return {"error": "No usernames found for this keyword."}
        return {"results": data.get("results", []), "count": data.get("count", 0)}
    except Exception as e:
        return {"error": str(e)[:300]}

def do_keyword_intel(keyword: str, query_type: str, abusech_key: str, otx_key: str = "", triage_key: str = "", tip_key: str = "", malshare_key: str = "", rwlive_key: str = "", cb_key: str = "", ha_key: str = "", urlscan_key: str = "", silentpush_key: str = "", driftnet_key: str = "", shodan_key: str = "", censys_key: str = "", etugen_key: str = "", pulsedive_key: str = "", fofa_key: str = "", validin_key: str = "", twitter_key: str = "", github_key: str = "", dnsdumpster_key: str = "", sources: list = None, github_repos: list = None) -> Dict[str, Any]:
    sources = _allowed_sources("keyword", sources)
    query_type = (query_type or "all").strip() or "all"
    inc = (lambda s: s in sources)
    started_at = time.perf_counter()
    res = {
        "indicator": keyword,
        "type": "keyword",
        "query_type": query_type
    }

    with ThreadPoolExecutor(max_workers=24) as executor:
        futures = {}
        if query_type == "all":
            if inc("threatfox"): futures["threatfox"] = executor.submit(query_tf_keyword, keyword, "taginfo", abusech_key)
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_taginfo", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "clamav", abusech_key)
            if inc("alienvault"): futures["alienvault"] = executor.submit(query_otx_pulse, keyword, otx_key)
            if inc("triage"): futures["triage"] = executor.submit(query_triage, keyword, triage_key)
            if inc("ransomlook"): futures["ransomlook"] = executor.submit(query_ransomlook, keyword)
            if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live, keyword, rwlive_key)
            if inc("malshare") and malshare_key: futures["malshare"] = executor.submit(query_malshare_search, keyword, malshare_key)
            if inc("orkl"): futures["orkl"] = executor.submit(query_orkl, keyword)
            if inc("cb"): futures["cb"] = executor.submit(query_cb_search, keyword, cb_key)
            if inc("misp_galaxy"): futures["misp_galaxy"] = executor.submit(query_misp_galaxy, keyword)
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, keyword, pulsedive_key)
            if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, keyword, twitter_key, "all")
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, 'keyword', github_key)
            if inc("github_repos"): futures["github_repos"] = executor.submit(query_github_specific_repos, keyword, github_key, github_repos)
            if inc("yara_forge"): futures["yara_forge"] = executor.submit(query_local_yara_rules, keyword, tip_key)
            if inc("tip") and tip_key: futures["tip"] = executor.submit(query_tip_search, keyword, tip_key, KTIP_FULL_SEARCH_SOURCES, 20)
            if inc("urlscan") and urlscan_key: futures["urlscan"] = executor.submit(query_urlscan_keyword, keyword, urlscan_key)
            if inc("rss_intel"): futures["rss_intel"] = executor.submit(query_local_rss, keyword)
            if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, keyword, "all")
            if inc("cti_articles"): futures["cti_articles"] = executor.submit(_query_cti_articles, keyword)
            if inc("threatactorusernames"): futures["threatactorusernames"] = executor.submit(query_threatactorusernames, keyword)
        elif query_type == "tag":
            if inc("threatfox"): futures["threatfox"] = executor.submit(query_tf_keyword, keyword, "taginfo", abusech_key)
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_taginfo", abusech_key)
            if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, keyword, twitter_key, "tag")
            if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_terms, "tag", keyword, ha_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "keyword", github_key)
        elif query_type == "signature":
            if inc("threatfox"): futures["threatfox"] = executor.submit(query_tf_keyword, keyword, "malwareinfo", abusech_key)
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_siginfo", abusech_key)
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, keyword, pulsedive_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "malware_family", github_key)
        elif query_type == "malware_family":
            if inc("threatfox"): futures["threatfox"] = executor.submit(query_tf_keyword, keyword, "malwareinfo", abusech_key)
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_siginfo", abusech_key)
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, keyword, pulsedive_key)
            if inc("cb"): futures["cb"] = executor.submit(query_cb_search, keyword, cb_key)
            if inc("orkl"): futures["orkl"] = executor.submit(query_orkl, keyword)
            if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_terms, "vx_family", keyword, ha_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, 'malware_family', github_key)
            if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, keyword, twitter_key, "malware_family")
            if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, keyword, "malware_family")
        elif query_type == "threat_actor":
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, keyword, pulsedive_key)
            if inc("cb"): futures["cb"] = executor.submit(query_cb_threats, keyword, cb_key)
            if inc("ransomlook"): futures["ransomlook"] = executor.submit(query_ransomlook_actor_or_search, keyword)
            if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live_group, keyword, rwlive_key)
            if inc("twitter") and twitter_key: futures["twitter"] = executor.submit(query_twitter_search, keyword, twitter_key, "threat_actor")
            if inc("orkl"): futures["orkl"] = executor.submit(query_orkl, keyword)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "threat_actor", github_key)
            if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, keyword, "threat_actor")
            if inc("threatactorusernames"): futures["threatactorusernames"] = executor.submit(query_threatactorusernames, keyword)
        elif query_type == "ransomware_group":
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, keyword, pulsedive_key)
            if inc("ransomlook"): futures["ransomlook"] = executor.submit(query_ransomlook_group_or_search, keyword)
            if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live_group, keyword, rwlive_key)
            if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, keyword, "ransomware_group")
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "malware_family", github_key)
        elif query_type == "ransomware_victim":
            if inc("ransomlook"): futures["ransomlook"] = executor.submit(query_ransomlook_search, keyword)
            if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live_victims, keyword, rwlive_key)
            if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, keyword, "ransomware_victim")
        elif query_type == "ransomware_country":
            if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live_country, keyword, rwlive_key)
        elif query_type == "ransomware_sector":
            if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live_sector, keyword, rwlive_key)
        elif query_type == "cve":
            if inc("cb"): futures["cb"] = executor.submit(query_cb_cves, keyword, cb_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, 'cve', github_key)
            if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, keyword, "cve")
            if inc("orkl"): futures["orkl"] = executor.submit(query_orkl_exact, keyword)
            if inc("cti_articles"): futures["cti_mentions"] = executor.submit(_query_cti_mentions, "cve", keyword)
        elif query_type == "yara":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_yarainfo", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "yara", abusech_key)
            if inc("rwlive"): futures["rwlive"] = executor.submit(query_ransomware_live_yara, keyword, rwlive_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "yara", github_key)
        elif query_type == "sigma":
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "sigma", github_key)
        elif query_type == "clamav":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_clamavinfo", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "clamav", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "clamav", github_key)
        elif query_type == "imphash":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_imphash", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "imphash", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "hash", github_key)
        elif query_type == "tlsh":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_tlsh", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "tlsh", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "hash", github_key)
        elif query_type == "telfhash":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_telfhash", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "telfhash", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "hash", github_key)
        elif query_type == "gimphash":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_gimphash", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "gimphash", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "hash", github_key)
        elif query_type == "icon_dhash":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_dhash_icon", abusech_key)
            if inc("yaraify"): futures["yaraify"] = executor.submit(query_yaraify_keyword, keyword, "icon_dhash", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "hash", github_key)
        elif query_type == "file_type":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_file_type", abusech_key)
            if inc("hybrid-analysis") or inc("hybrid_analysis"): futures["hybrid-analysis"] = executor.submit(query_ha_terms, "filetype", keyword, ha_key)
            if inc("malshare") and malshare_key: futures["malshare"] = executor.submit(query_malshare_type, keyword, malshare_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "keyword", github_key)
        elif query_type == "filename":
            if inc("malshare") and malshare_key: futures["malshare"] = executor.submit(query_malshare_search, keyword, malshare_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "filename", github_key)
        elif query_type == "malshare_search":
            if inc("malshare") and malshare_key: futures["malshare"] = executor.submit(query_malshare_search, keyword, malshare_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "keyword", github_key)
        elif query_type == "cert_subject":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_subjectinfo", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "certificate", github_key)
        elif query_type == "cert_issuer":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_issuerinfo", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "certificate", github_key)
        elif query_type == "cert_serial":
            if inc("malwarebazaar"): futures["malwarebazaar"] = executor.submit(query_mb_keyword, keyword, "get_certificate", abusech_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "certificate", github_key)
        elif query_type in {"campaign", "tool", "certificate"}:
            if inc("pulsedive"): futures["pulsedive"] = executor.submit(query_pulsedive_keyword, keyword, pulsedive_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, query_type, github_key)
            if inc("github_repos"): futures["github_repos"] = executor.submit(query_github_specific_repos, keyword, github_key, github_repos)
            if inc("orkl"): futures["orkl"] = executor.submit(query_orkl, keyword)
        elif query_type in {"domain", "ip", "url", "hash"}:
            if inc("pulsedive") and query_type in {"domain", "ip", "url"}: futures["pulsedive"] = executor.submit(query_pulsedive, keyword, pulsedive_key)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, query_type, github_key)
            if inc("github_repos"): futures["github_repos"] = executor.submit(query_github_specific_repos, keyword, github_key, github_repos)
            if inc("orkl"): futures["orkl"] = executor.submit(query_orkl_exact, keyword)
            if inc("malware_news"): futures["malware_news"] = executor.submit(query_malware_news, keyword, query_type)
            if inc("rss_intel"): futures["rss_intel"] = executor.submit(query_local_rss, keyword)
            if inc("cti_articles"): futures["cti_mentions"] = executor.submit(_query_cti_mentions, query_type, keyword)
        elif query_type == "repository":
            if inc("github_repos"): futures["github_repos"] = executor.submit(query_github_search, keyword, "repository", github_key, 10, 1)
            if inc("github"): futures["github"] = executor.submit(query_github_search, keyword, "repository", github_key, 10, 1)
        elif query_type == "github_user":
            if inc("github"): futures["github"] = executor.submit(query_github_user, keyword, github_key)
        elif query_type == "github_org":
            if inc("github"): futures["github"] = executor.submit(query_github_org, keyword, github_key)
        elif query_type == "otx_pulse":
            if inc("alienvault"): futures["alienvault"] = executor.submit(query_otx_pulse, keyword, otx_key)
        elif query_type == "triage_family":
            if inc("triage"): futures["triage"] = executor.submit(query_triage, f"family:{keyword}", triage_key)
        elif query_type == "triage_tag":
            if inc("triage"): futures["triage"] = executor.submit(query_triage, f"tag:{keyword}", triage_key)
        elif query_type == "triage_botnet":
            if inc("triage"): futures["triage"] = executor.submit(query_triage, f"botnet:{keyword}", triage_key)
        elif query_type == "triage_wallet":
            if inc("triage"): futures["triage"] = executor.submit(query_triage, f"wallet:{keyword}", triage_key)
        elif query_type == "triage_domain":
            if inc("triage"):
                domain = normalize_domain(keyword)
                if not is_domain(domain):
                    futures["triage"] = executor.submit(lambda: {"error": "Triage domain search requires a valid domain"})
                else:
                    futures["triage"] = executor.submit(query_triage, f"domain:{domain}", triage_key)
        elif query_type == "triage_ip":
            if inc("triage"):
                ip = normalize_ip(keyword)
                if not is_ip(ip):
                    futures["triage"] = executor.submit(lambda: {"error": "Triage IP search requires a valid IPv4 or IPv6 address"})
                else:
                    futures["triage"] = executor.submit(query_triage, f"ip:{ip}", triage_key)
        elif query_type == "triage_url":
            if inc("triage"):
                url_value = keyword.strip()
                if not url_value.lower().startswith(("http://", "https://")):
                    futures["triage"] = executor.submit(lambda: {"error": "Triage URL search requires a full URL starting with http(s)://"})
                else:
                    futures["triage"] = executor.submit(query_triage, f"url:{url_value}", triage_key)
        elif query_type == "triage_hash":
            if inc("triage"):
                if not is_hash(keyword):
                    futures["triage"] = executor.submit(lambda: {"error": "Triage hash search requires an MD5, SHA-1, SHA-256, SHA-512 or SHA3-384 hex digest"})
                else:
                    futures["triage"] = executor.submit(query_triage, f"{triage_hash_field(keyword)}:{keyword.strip().lower()}", triage_key)
        elif query_type == "triage_c2":
            if inc("triage"):
                lowered = keyword.strip().lower()
                if lowered.startswith(("http://", "https://")):
                    triage_query = f"url:{keyword.strip()}"
                elif is_ip(normalize_ip(keyword)):
                    triage_query = f"ip:{normalize_ip(keyword)}"
                elif is_domain(normalize_domain(keyword)):
                    triage_query = f"domain:{normalize_domain(keyword)}"
                else:
                    triage_query = ""
                if not triage_query:
                    futures["triage"] = executor.submit(lambda: {"error": "Triage C2 search requires a URL, IP address or domain"})
                else:
                    futures["triage"] = executor.submit(query_triage, triage_query, triage_key)
        else:
            res["error"] = f"Invalid keyword query type: {query_type}"

        # Local CTI articles apply to every keyword query type (local-only,
        # fast) unless that branch already queued them.
        if inc("cti_articles") and "cti_articles" not in futures and "cti_mentions" not in futures:
            futures["cti_articles"] = executor.submit(_query_cti_articles, keyword)

        local_keyword_sources = {
            "threat_actor_knowledge": (_query_threat_actor_knowledge, (keyword,)),
            "malware_tools_knowledge": (_query_malware_tools_knowledge, (keyword,)),
            "ransom_yara_explorer": (_query_ransom_yara_explorer, (keyword, rwlive_key)),
            "vulnerability_intel": (_query_vulnerability_intel, (keyword,)),
            "x_monitor": (_query_x_monitor_keyword, (keyword,)),
        }
        for source_id, (func, args) in local_keyword_sources.items():
            if inc(source_id) and source_id not in futures:
                futures[source_id] = executor.submit(func, *args)

        res.update(_collect_futures(futures))
            
    res["sources_queried"] = [key for key in res.keys() if key not in {"indicator", "type", "query_type", "sources_queried", "duration_ms", "error"}]
    res["duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    return res

RL_API_BASE = "https://www.ransomlook.io/api"
# Short-lived cache (seconds) so repeated analyst lookups don't hammer RansomLook.
RL_CACHE_TTL = {"group": 1800, "actor": 1800, "crypto": 1800, "search": 600, "posts": 600}
_RL_CACHE: Dict[str, Any] = {}
# Documented export database IDs (verified against ransomlook.io/doc).
RL_EXPORT_DBS = {0: "groups", 2: "posts", 3: "markets", 4: "leaks", 5: "actors"}
RL_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ransomlook")

def _rl_cache_get(key: str, ttl: int) -> Any:
    entry = _RL_CACHE.get(key)
    if not entry:
        return None
    try:
        if time.time() - entry[0] > ttl:
            _RL_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return entry[1]

def _rl_cache_set(key: str, value: Any) -> None:
    try:
        _RL_CACHE[key] = (time.time(), value)
    except Exception:
        pass

def _rl_get(path: str, params: Dict[str, Any] = None, api_key: str = "", timeout: int = 20, label: str = "RansomLook request") -> Any:
    """Documented RansomLook GET helper. Never raises; returns parsed JSON or
    an {"error": ...} dict. Uses requests params for proper URL encoding."""
    headers = {}
    if api_key:
        headers["Authorization"] = api_key
    try:
        resp = requests.get(f"{RL_API_BASE}{path}", headers=headers, params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"error": f"{label} returned a non-JSON response"}
        if resp.status_code == 400:
            return {"error": f"{label} rejected (HTTP 400)"}
        if resp.status_code in {401, 403}:
            return {"error": "RansomLook API access denied", "status": resp.status_code}
        if resp.status_code == 404:
            return {"error": f"{label} not found", "status": 404}
        if resp.status_code == 429:
            return {"error": "RansomLook rate limit exceeded"}
        if 500 <= resp.status_code < 600:
            return {"error": f"RansomLook server error (HTTP {resp.status_code})"}
        return {"error": f"{label} failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "RansomLook request timeout"}
    except Exception as e:
        return {"error": f"{label} failed: {e}"}

def _rl_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _rl_is_not_found(data: Any) -> bool:
    return _rl_is_error(data) and (data.get("status") == 404 or "not found" in str(data.get("error", "")).lower())

def _rl_cached_fetch(cache_key: str, ttl_key: str, fetch) -> Any:
    cached = _rl_cache_get(cache_key, RL_CACHE_TTL.get(ttl_key, 600))
    if cached is not None:
        return cached
    data = fetch()
    if not _rl_is_error(data) and data not in (None, [], {}):
        _rl_cache_set(cache_key, data)
    return data

def query_ransomlook_search(keyword: str) -> Dict[str, Any]:
    """GET /api/search?query= — victims/posts and other entities (no key needed)."""
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty RansomLook query"}
    return _rl_cached_fetch(f"search:{keyword.lower()}", "search",
                            lambda: _rl_get("/search", {"query": keyword}, label="RansomLook search"))

def query_ransomlook_group(group: str) -> Dict[str, Any]:
    """GET /api/group/{group} — exact ransomware group profile (no key needed)."""
    group = (group or "").strip()
    if not group:
        return {"error": "Empty RansomLook group"}
    return _rl_cached_fetch(f"group:{group.lower()}", "group",
                            lambda: _rl_get(f"/group/{urllib.parse.quote(group, safe='')}", label="RansomLook group"))

def query_ransomlook_actor(actor: str) -> Dict[str, Any]:
    """GET /api/actor/{actor} — exact threat actor profile (no key needed)."""
    actor = (actor or "").strip()
    if not actor:
        return {"error": "Empty RansomLook actor"}
    return _rl_cached_fetch(f"actor:{actor.lower()}", "actor",
                            lambda: _rl_get(f"/actor/{urllib.parse.quote(actor, safe='')}", label="RansomLook actor"))

def query_ransomlook_crypto(group: str) -> Dict[str, Any]:
    """GET /api/crypto/{group} — group wallets by chain (no key needed)."""
    group = (group or "").strip()
    if not group:
        return {"error": "Empty RansomLook group"}
    return _rl_cached_fetch(f"crypto:{group.lower()}", "crypto",
                            lambda: _rl_get(f"/crypto/{urllib.parse.quote(group, safe='')}", label="RansomLook crypto"))

def query_ransomlook_posts(days: int = 7) -> Dict[str, Any]:
    """GET /api/posts?days= — recent victims. Manual/lazy use only, never during
    normal IOC lookups."""
    try:
        days = max(1, min(int(days or 7), 90))
    except (TypeError, ValueError):
        days = 7
    data = _rl_cached_fetch(f"posts:{days}", "posts",
                            lambda: _rl_get("/posts", {"days": days}, label="RansomLook posts"))
    if _rl_is_error(data):
        return data
    return _rl_with_normalized({"posts": data if isinstance(data, list) else []}, f"last {days} days")

def query_ransomlook_export(db: int, api_key: str = "") -> Dict[str, Any]:
    """GET /api/export/{db} — manual dataset refresh only. Saves to
    data/ransomlook/ on success; never overwrites cache on failure."""
    try:
        db = int(db)
    except (TypeError, ValueError):
        return {"error": f"Unknown RansomLook export database: {db}"}
    if db not in RL_EXPORT_DBS:
        return {"error": f"Unknown RansomLook export database: {db}"}
    if not api_key:
        return {"error": "RansomLook export requires authentication"}
    data = _rl_get(f"/export/{db}", api_key=api_key, timeout=120, label="RansomLook export")
    if _rl_is_error(data):
        if data.get("status") in {401, 403}:
            return {"error": "RansomLook export unavailable for current API credentials"}
        return data
    name = RL_EXPORT_DBS[db]
    try:
        os.makedirs(RL_CACHE_DIR, exist_ok=True)
        tmp_path = os.path.join(RL_CACHE_DIR, f"{name}.json.tmp")
        final_path = os.path.join(RL_CACHE_DIR, f"{name}.json")
        import json as _json
        with open(tmp_path, "w", encoding="utf-8") as f:
            _json.dump(data, f)
        os.replace(tmp_path, final_path)
    except Exception as e:
        return {"error": f"RansomLook export download ok but local save failed: {e}"}
    count = len(data) if isinstance(data, (list, dict)) else 0
    return {"db": db, "dataset": name, "count": count, "path": f"data/ransomlook/{name}.json"}

def normalize_rl_victim(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return {
        "type": "victim",
        "name": item.get("post_title") or item.get("victim") or item.get("title") or "",
        "group": item.get("group_name") or item.get("group") or "",
        "description": item.get("description") or item.get("post_description") or "",
        "discovered": item.get("discovered") or "",
        "published": item.get("published") or item.get("post_date") or "",
        "country": item.get("country") or "",
        "sector": item.get("sector") or item.get("activity") or "",
        "website": item.get("website") or item.get("post_website") or "",
        "source": "RansomLook",
        "raw": item,
    }

def _rl_infra_role(value: str) -> str:
    v = (value or "").strip().lower()
    if v.endswith(".onion"):
        return "leak_site"
    if v.startswith("http"):
        return "location"
    return "location"

def normalize_rl_group(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    locations = item.get("locations") if isinstance(item.get("locations"), list) else []
    infra = []
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        value = loc.get("slug") or loc.get("url") or loc.get("fqdn") or ""
        if not value:
            continue
        available = loc.get("available")
        infra.append({
            "value": str(value),
            "type": "onion_service" if str(value).lower().endswith(".onion") else "url",
            "role": _rl_infra_role(str(value)),
            "status": "Available" if available is True else ("Offline" if available is False else ""),
            "group": item.get("name") or "",
        })
    return {
        "name": item.get("name") or "",
        "status": item.get("status") or ("Active" if any(l.get("available") for l in locations if isinstance(l, dict)) else ""),
        "description": item.get("description") or "",
        "locations": infra,
        "metadata": {k: v for k, v in item.items() if k not in {"name", "description", "locations"}},
    }

def normalize_rl_actor(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    relations = item.get("relations") if isinstance(item.get("relations"), dict) else {}
    groups = [g for g in (relations.get("groups") or []) if isinstance(g, str) and g.strip()]
    aliases = [a for a in (item.get("aliases") or []) if isinstance(a, str) and a.strip()]
    return {
        "name": item.get("name") or "",
        "aliases": aliases,
        "description": item.get("description") or "",
        "groups": groups,
        "role": item.get("role") or "",
        "relationships": [],
        "metadata": {k: v for k, v in item.items() if k not in {"name", "aliases", "description", "relations", "role"}},
    }

def normalize_rl_wallets(crypto_data: Any, group: str = "") -> List[Dict[str, Any]]:
    wallets: List[Dict[str, Any]] = []
    if not isinstance(crypto_data, dict):
        return wallets
    by_chain = crypto_data.get("by_chain") if isinstance(crypto_data.get("by_chain"), dict) else {}
    for chain, addrs in by_chain.items():
        if not isinstance(addrs, list):
            continue
        for a in addrs:
            if not isinstance(a, dict) or not a.get("address"):
                continue
            try:
                tx = a.get("tx_count", a.get("transactions"))
                tx = int(tx) if tx is not None else None
            except (TypeError, ValueError):
                tx = None
            wallets.append({
                "address": str(a["address"]),
                "blockchain": str(chain),
                "transactions": tx,
                "group": group,
            })
    return wallets

def normalize_ransomlook_result(raw: Any, query: str = "") -> Dict[str, Any]:
    """Common structure with strict victim-vs-infrastructure separation. Raw
    provider data preserved for future expansion."""
    normalized: Dict[str, Any] = {
        "source": "RansomLook",
        "query": query,
        "group": {},
        "victims": [],
        "posts": [],
        "actors": [],
        "crypto": {"wallets": []},
        "infrastructure": [],
        "markets": [],
        "leaks": [],
        "relationships": [],
        "raw": raw if isinstance(raw, dict) else {},
    }
    if not isinstance(raw, dict) or raw.get("error"):
        return normalized
    rels: List[Dict[str, Any]] = []
    group_raw = raw.get("group")
    if isinstance(group_raw, dict) and group_raw.get("name"):
        normalized["group"] = normalize_rl_group(group_raw)
    for v in (raw.get("victims") or raw.get("search") or []):
        if not isinstance(v, dict):
            continue
        victim = normalize_rl_victim(v)
        if not victim.get("name"):
            continue
        normalized["victims"].append(victim)
        if victim["group"]:
            rels.append({"source": victim["group"], "relation": "claimed_victim", "target": victim["name"], "target_type": "victim"})
            rels.append({"source": victim["name"], "relation": "published_by", "target": victim["group"], "target_type": "group"})
        if victim["website"]:
            # Victim website context only — never a malicious-IOC assertion.
            rels.append({"source": victim["name"], "relation": "website", "target": victim["website"], "target_type": "domain"})
    for key in ("posts", "recent_posts"):
        for p in (raw.get(key) or []):
            if isinstance(p, dict):
                victim = normalize_rl_victim(p)
                if victim.get("name"):
                    normalized["posts"].append(victim)
    actor_raw = raw.get("actor")
    actors: List[Dict[str, Any]] = []
    if isinstance(actor_raw, dict) and (actor_raw.get("name") or actor_raw.get("aliases")):
        actors.append(actor_raw)
    for a in (raw.get("actors") or []):
        if isinstance(a, dict):
            actors.append(a)
    for a in actors:
        actor = normalize_rl_actor(a)
        if not actor.get("name"):
            continue
        normalized["actors"].append(actor)
        for alias in actor.get("aliases", []) or []:
            rels.append({"source": actor["name"], "relation": "uses_alias", "target": alias, "target_type": "alias"})
        for g in actor.get("groups", []) or []:
            rels.append({"source": actor["name"], "relation": "associated_with", "target": g, "target_type": "group"})
    crypto_raw = raw.get("crypto")
    group_name = normalized["group"].get("name") or query
    wallets = normalize_rl_wallets(crypto_raw, group_name)
    normalized["crypto"] = {"wallets": wallets}
    for w in wallets:
        rels.append({"source": group_name, "relation": "uses_wallet", "target": w["address"], "target_type": "wallet"})
        rels.append({"source": w["address"], "relation": "blockchain", "target": w["blockchain"], "target_type": "blockchain"})
    for loc in normalized["group"].get("locations", []) or []:
        normalized["infrastructure"].append(loc)
        if loc["role"] == "leak_site":
            rels.append({"source": group_name, "relation": "hosts_leak_site", "target": loc["value"], "target_type": "infrastructure"})
        else:
            rels.append({"source": group_name, "relation": "operates", "target": loc["value"], "target_type": "infrastructure"})
    normalized["relationships"] = rels
    return normalized

def _rl_with_normalized(raw: Any, query: str) -> Any:
    if _rl_is_error(raw):
        return raw
    result = normalize_ransomlook_result(raw, query)
    if isinstance(raw, dict):
        result = {**raw, "normalized": result}
    return result

def query_ransomlook_group_or_search(keyword: str) -> Dict[str, Any]:
    """Exact group profile with search fallback (concurrent)."""
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty RansomLook query"}
    with ThreadPoolExecutor(max_workers=3) as executor:
        fg = executor.submit(query_ransomlook_group, keyword)
        fs = executor.submit(query_ransomlook_search, keyword)
        fc = executor.submit(query_ransomlook_crypto, keyword)
        group, search, crypto = fg.result(), fs.result(), fc.result()
    raw: Dict[str, Any] = {}
    if not _rl_is_error(group):
        raw["group"] = group[0] if isinstance(group, list) and group else group
    if not _rl_is_error(search):
        raw["search"] = search if isinstance(search, list) else []
        raw["victims"] = raw["search"]
    if not _rl_is_error(crypto):
        raw["crypto"] = crypto
    if not raw:
        if _rl_is_not_found(group):
            return {"error": "RansomLook group not found"}
        for candidate in (group, search, crypto):
            if _rl_is_error(candidate):
                return candidate
        return {"error": "No RansomLook matches found for this keyword."}
    return _rl_with_normalized(raw, keyword)

def query_ransomlook_actor_or_search(keyword: str) -> Dict[str, Any]:
    """Exact actor profile with search fallback (concurrent)."""
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty RansomLook query"}
    with ThreadPoolExecutor(max_workers=2) as executor:
        fa = executor.submit(query_ransomlook_actor, keyword)
        fs = executor.submit(query_ransomlook_search, keyword)
        actor, search = fa.result(), fs.result()
    raw: Dict[str, Any] = {}
    if not _rl_is_error(actor):
        raw["actor"] = actor
    if not _rl_is_error(search):
        raw["search"] = search if isinstance(search, list) else []
        raw["victims"] = raw["search"]
    if not raw:
        if _rl_is_not_found(actor):
            return {"error": "RansomLook actor not found"}
        for candidate in (actor, search):
            if _rl_is_error(candidate):
                return candidate
        return {"error": "No RansomLook matches found for this keyword."}
    return _rl_with_normalized(raw, keyword)

def query_ransomlook(keyword: str) -> Dict[str, Any]:
    """Default keyword lookup: exact group + actor + crypto + search, all
    concurrent inside the existing provider concurrency model."""
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty RansomLook query"}
    with ThreadPoolExecutor(max_workers=4) as executor:
        fg = executor.submit(query_ransomlook_group, keyword)
        fa = executor.submit(query_ransomlook_actor, keyword)
        fc = executor.submit(query_ransomlook_crypto, keyword)
        fs = executor.submit(query_ransomlook_search, keyword)
        group, actor, crypto, search = fg.result(), fa.result(), fc.result(), fs.result()
    raw: Dict[str, Any] = {}
    if not _rl_is_error(group):
        raw["group"] = group[0] if isinstance(group, list) and group else group
    if not _rl_is_error(actor):
        raw["actor"] = actor
    if not _rl_is_error(crypto):
        raw["crypto"] = crypto
    if not _rl_is_error(search):
        raw["search"] = search if isinstance(search, list) else []
        raw["victims"] = raw["search"]
    if not raw:
        for candidate in (group, actor, crypto, search):
            if _rl_is_error(candidate) and not _rl_is_not_found(candidate):
                return candidate
        return {"error": "No RansomLook matches found for this keyword."}
    return _rl_with_normalized(raw, keyword)

RANSOMWARE_LIVE_BASE_URL = os.environ.get("RANSOMWARE_LIVE_BASE_URL", "https://api.ransomware.live/v2").rstrip("/")
RANSOMWARE_LIVE_PRO_BASE_URL = os.environ.get("RANSOMWARE_LIVE_PRO_BASE_URL", "https://api-pro.ransomware.live").rstrip("/")
RANSOMWARE_LIVE_PRO_CAPABILITIES = {
    "victim_search": True,
    "victim_details": True,
    "victim_filters": True,
    "recent_victims": True,
    "groups": True,
    "group_details": True,
    "group_victims": True,
    "countries": True,
    "sectors": True,
    "date_filters": True,
    "press": True,
    "statistics": True,
    "infrastructure": True,
    "iocs": True,
    "yara": True,
    "kql": False,
    "ransom_notes": True,
    "negotiations": True,
    "csirt": True,
    "sec_8k": True,
}
_RWLIVE_CACHE: Dict[Any, Any] = {}

def _rwlive_cache_ttl(endpoint: str) -> int:
    endpoint = endpoint.strip("/")
    if endpoint.startswith(("searchvictims/", "countryvictims/", "sectorvictims/", "victims/search", "victims/")):
        return 1800
    if endpoint.startswith(("recentvictims", "recentcyberattacks", "groupvictims/", "victims/recent", "press/")):
        return 1800
    if endpoint.startswith(("group/", "groups")):
        return 3600
    if endpoint.startswith(("yara/", "iocs/", "ransomnotes/", "negotiations/")):
        return 21600
    if endpoint in ("stats", "listsectors", "iocs", "yara", "ransomnotes", "negotiations"):
        return 1800
    return 1800

def _rwlive_has_pro_key(api_key: str = "") -> bool:
    return bool((api_key or os.environ.get("RANSOMWARE_LIVE_API_KEY", "") or "").strip())

def _rwlive_get(endpoint: str, params: Dict[str, Any] = None, api_key: str = "", text: bool = False,
                timeout: int = 20, pro: bool = False) -> Any:
    endpoint = endpoint.lstrip("/")
    params = params or {}
    key = (api_key or os.environ.get("RANSOMWARE_LIVE_API_KEY", "") or "").strip()
    if pro and not key:
        return {"error": "No ransomware.live API-PRO key provided", "missing_key": True}
    key_fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12] if key else "no-key"
    cache_key = ("pro" if pro else "legacy", endpoint, tuple(sorted((str(k), str(v)) for k, v in params.items())), bool(text), key_fingerprint)
    now = time.time()
    cached = _RWLIVE_CACHE.get(cache_key)
    if cached and now - cached["time"] < _rwlive_cache_ttl(endpoint):
        return cached["data"]
    headers = {"Accept": "text/plain" if text else "application/json"}
    if key:
        headers["X-API-KEY"] = key
    try:
        base_url = RANSOMWARE_LIVE_PRO_BASE_URL if pro else RANSOMWARE_LIVE_BASE_URL
        resp = requests.get(f"{base_url}/{endpoint}", headers=headers, params=params, timeout=timeout)
        if resp.status_code == 200:
            if text:
                data = resp.text
            else:
                try:
                    data = resp.json()
                except ValueError:
                    return {"error": "ransomware.live returned a non-JSON response"}
            _RWLIVE_CACHE[cache_key] = {"time": now, "data": data}
            return data
        if resp.status_code == 400:
            return {"error": "ransomware.live rejected the request"}
        if resp.status_code == 401:
            return {"error": "ransomware.live API-PRO key invalid or missing" if pro else "ransomware.live API key invalid", "auth_error": True}
        if resp.status_code == 403:
            return {"error": "Feature unavailable for current ransomware.live API-PRO access" if pro else "Feature unavailable for current ransomware.live API access", "auth_error": True}
        if resp.status_code == 404:
            detail = ""
            try:
                detail = resp.json().get("error", "")
            except Exception:
                detail = ""
            return {"error": detail or "ransomware.live record not found", "not_found": True}
        if resp.status_code == 429:
            return {"error": "ransomware.live API-PRO rate limit exceeded" if pro else "ransomware.live rate limit exceeded", "rate_limited": True}
        if 500 <= resp.status_code < 600:
            return {"error": "ransomware.live API-PRO unavailable" if pro else "ransomware.live API unavailable", "provider_unavailable": True}
        return {"error": f"ransomware.live {'API-PRO ' if pro else ''}request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "ransomware.live API-PRO request timeout" if pro else "ransomware.live request timeout", "timeout": True}
    except Exception as e:
        return {"error": f"ransomware.live {'API-PRO ' if pro else ''}request failed: {e}"}

def _rwlive_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def _rwlive_not_found(data: Any) -> bool:
    return isinstance(data, dict) and data.get("not_found") is True

def _rwlive_should_use_pro(api_key: str = "") -> bool:
    return _rwlive_has_pro_key(api_key)

def _rwlive_paginate(items: List[Any], limit: int = 50, offset: int = 0) -> tuple:
    try:
        limit = max(1, min(int(limit or 50), 100))
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        limit, offset = 50, 0
    sliced = items[offset:offset + limit]
    pagination = {
        "limit": limit,
        "offset": offset,
        "total": len(items),
        "next_offset": offset + limit if len(items) > offset + limit else None,
    }
    return sliced, pagination

def _rwlive_list(data: Any) -> List[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("victims", "results", "data", "items", "cyberattacks", "groups", "iocs", "rules", "notes", "negotiations"):
            if isinstance(data.get(key), list):
                return data[key]
        if not data.get("error"):
            return [data]
    return []

def _rwlive_text(value: Any) -> str:
    if value is None or value is False:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        for key in ("name", "victim", "post_title", "title", "domain", "website", "url", "slug", "fqdn", "value"):
            text = _rwlive_text(value.get(key))
            if text:
                return text
        return ""
    if isinstance(value, list):
        return ", ".join([text for text in (_rwlive_text(v) for v in value) if text])
    return str(value).strip()

def _rwlive_group_name(value: Any) -> str:
    return _rwlive_text(value).strip()

def _rwlive_str_list(value: Any) -> List[str]:
    out: List[str] = []
    if isinstance(value, str):
        if value.strip():
            out.append(value.strip())
    elif isinstance(value, list):
        for entry in value:
            if isinstance(entry, str) and entry.strip():
                out.append(entry.strip())
            elif isinstance(entry, dict):
                name = entry.get("name") or entry.get("value") or entry.get("title")
                if isinstance(name, str) and name.strip():
                    out.append(name.strip())
    return list(dict.fromkeys(out))

def _rwlive_infra_type(value: str) -> str:
    v = (value or "").lower()
    if ".onion" in v:
        return "onion"
    if re.match(r"^https?://", v):
        return "url"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", v):
        return "ip"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v):
        return "domain"
    return "other"

def _rwlive_infra_role(location: Dict[str, Any]) -> str:
    kind = _rwlive_text(location.get("type")).lower()
    title = _rwlive_text(location.get("title")).lower()
    if kind == "dls" or "blog" in title or "leak" in title:
        return "leak_site"
    if "admin" in kind or "admin" in title or "login" in title:
        return "communication"
    if "mirror" in kind or "mirror" in title:
        return "mirror"
    return "other"

def normalize_rwlive_victim(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    name = _rwlive_text(item.get("victim") or item.get("post_title") or item.get("title") or item.get("name"))
    group = _rwlive_group_name(item.get("group") or item.get("group_name") or item.get("gang"))
    website = _rwlive_text(item.get("domain") or item.get("website"))
    return {
        "id": _rwlive_text(item.get("id") or item.get("victim_id")),
        "name": name,
        "group": group,
        "website": website,
        "country": _rwlive_text(item.get("country")),
        "country_code": _rwlive_text(item.get("country_code") or item.get("countrycode") or item.get("country")),
        "sector": _rwlive_text(item.get("activity") or item.get("sector")),
        "activity": _rwlive_text(item.get("activity")),
        "discovered": _rwlive_text(item.get("discovered")),
        "published": _rwlive_text(item.get("published")),
        "attack_date": _rwlive_text(item.get("attackdate") or item.get("attack_date")),
        "description": _rwlive_text(item.get("description")),
        "claim_url": _rwlive_text(item.get("claim_url") or item.get("post_url")),
        "url": _rwlive_text(item.get("permalink") or item.get("url")),
        "source_url": _rwlive_text(item.get("permalink") or item.get("url")),
        "screenshot": _rwlive_text(item.get("screenshot")),
        "infostealer": item.get("infostealer"),
        "press": item.get("press"),
        "data_size": item.get("data_size"),
        "api": _rwlive_text(item.get("api")) or ("pro" if item.get("permalink") or item.get("id") else "legacy"),
        "context": "claimed_victim",
        "source": "ransomware.live",
        "metadata": item,
    }

def normalize_rwlive_group(item: Any, victims: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    locations = item.get("locations") if isinstance(item.get("locations"), list) else []
    infrastructure = []
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        value = _rwlive_text(loc.get("slug") or loc.get("url") or loc.get("fqdn"))
        if not value:
            continue
        infrastructure.append({
            "value": value,
            "type": _rwlive_infra_type(value),
            "role": _rwlive_infra_role(loc),
            "status": "online" if loc.get("available") is True else ("offline" if loc.get("available") is False else ""),
            "group": _rwlive_group_name(item.get("name") or item.get("group")),
            "source": "ransomware.live",
            "api": "pro" if "victims" in item or "has_negotiations" in item else "legacy",
            "metadata": loc,
        })
    victims = victims or []
    victim_count = item.get("victim_count")
    if victim_count is None:
        victim_count = item.get("victims") if isinstance(item.get("victims"), int) else None
    return {
        "id": _rwlive_text(item.get("id") or item.get("slug") or item.get("group")),
        "name": _rwlive_group_name(item.get("name") or item.get("group")),
        "original_name": _rwlive_text(item.get("name") or item.get("group")),
        "aliases": list(dict.fromkeys(
            _rwlive_str_list(item.get("aliases")) + _rwlive_str_list(item.get("altname"))
            + _rwlive_str_list(item.get("aka")) + _rwlive_str_list(item.get("other_names"))
        )),
        "description": _rwlive_text(item.get("description")),
        "status": _rwlive_text(item.get("status")),
        "locations": locations,
        "victim_count": len(victims) if victims else victim_count,
        "victims": victims,
        "countries": [x for x, _ in Counter(v.get("country") for v in victims if v.get("country")).most_common(10)],
        "sectors": [x for x, _ in Counter(v.get("sector") for v in victims if v.get("sector")).most_common(10)],
        "infrastructure": infrastructure,
        "first_seen": _rwlive_text(item.get("firstseen") or item.get("first_seen")),
        "last_seen": _rwlive_text(item.get("lastseen") or item.get("last_seen")),
        "ttps": item.get("ttps") if isinstance(item.get("ttps"), list) else [],
        "tools": _rwlive_str_list(item.get("tools")),
        "malware": _rwlive_str_list(item.get("malware") or item.get("malwares") or item.get("malware_families")),
        "vulnerabilities": item.get("vulnerabilities") if isinstance(item.get("vulnerabilities"), list) else [],
        "has_negotiations": bool(item.get("has_negotiations")),
        "negotiation_count": item.get("negotiation_count"),
        "has_ransomnote": bool(item.get("has_ransomnote")),
        "ransomnotes_count": item.get("ransomnotes_count"),
        "source_url": _rwlive_text(item.get("url")),
        "api": _rwlive_text(item.get("api")) or ("pro" if "victims" in item or "has_negotiations" in item else "legacy"),
        "source": "ransomware.live",
        "metadata": item,
    }

def normalize_rwlive_cyberattack(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return {
        "title": _rwlive_text(item.get("title") or item.get("organization") or item.get("domain")),
        "organization": _rwlive_text(item.get("organization") or item.get("victim") or item.get("domain")),
        "country": _rwlive_text(item.get("country")),
        "sector": _rwlive_text(item.get("sector") or item.get("activity")),
        "date": _rwlive_text(item.get("date") or item.get("added")),
        "description": _rwlive_text(item.get("summary") or item.get("description")),
        "source_url": _rwlive_text(item.get("source_url") or item.get("url") or item.get("link")),
        "domain": _rwlive_text(item.get("domain")),
        "context": "cyberattack_report",
        "metadata": item,
    }

def normalize_rwlive_ioc(item: Any, group_name: str = "") -> Dict[str, Any]:
    if isinstance(item, str):
        value = item.strip()
        raw = {"value": value}
    elif isinstance(item, dict):
        value = _rwlive_text(item.get("value") or item.get("ioc") or item.get("indicator") or item.get("artifact"))
        raw = item
    else:
        return {}
    if not value:
        return {}
    ioc_type = _rwlive_text(raw.get("type")).lower() or _rwlive_infra_type(value)
    if re.match(r"^[a-f0-9]{32,128}$", value.lower()):
        ioc_type = "hash"
    return {
        "value": value,
        "type": ioc_type,
        "group": _rwlive_group_name(raw.get("group") or raw.get("group_name") or group_name),
        "context": _rwlive_text(raw.get("context") or raw.get("description")) or "ransomware_ioc",
        "first_seen": _rwlive_text(raw.get("first_seen") or raw.get("firstseen") or raw.get("date")),
        "source": "ransomware.live",
        "api": "pro",
        "metadata": raw,
    }

def normalize_rwlive_yara(item: Any, group_name: str = "") -> Dict[str, Any]:
    if isinstance(item, str):
        content = item.strip()
        name = group_name
        raw = {"content": content}
    elif isinstance(item, dict):
        content = _rwlive_text(item.get("content") or item.get("rule") or item.get("yara"))
        name = _rwlive_text(item.get("name") or item.get("filename") or item.get("rule_name") or group_name)
        raw = item
    else:
        return {}
    if not content:
        return {}
    return {
        "name": name or group_name or "YARA Rule",
        "group": _rwlive_group_name(raw.get("group") or raw.get("group_name") or group_name),
        "source": "ransomware.live",
        "api": "pro",
        "content": content,
        "metadata": raw,
    }

def normalize_rwlive_ransom_note(item: Any, group_name: str = "") -> Dict[str, Any]:
    if isinstance(item, str):
        raw = {"filename": item}
    elif isinstance(item, dict):
        raw = item
    else:
        return {}
    filename = _rwlive_text(raw.get("filename") or raw.get("name") or raw.get("note") or raw.get("id"))
    content = _rwlive_text(raw.get("content") or raw.get("text") or raw.get("body"))
    return {
        "id": _rwlive_text(raw.get("id") or filename),
        "group": _rwlive_group_name(raw.get("group") or raw.get("group_name") or group_name),
        "filename": filename,
        "extension": _rwlive_text(raw.get("extension")),
        "text": content,
        "source": "ransomware.live",
        "api": "pro",
        "metadata": raw,
    }

def normalize_rwlive_negotiation(item: Any, group_name: str = "") -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    messages = item.get("messages") if isinstance(item.get("messages"), list) else []
    group = _rwlive_group_name(item.get("group") or item.get("group_name") or item.get("name") or group_name)
    message_count = item.get("message_count") or item.get("messages_count") or item.get("count") or item.get("chats") or item.get("negotiation_count") or len(messages)
    chat_id = _rwlive_text(item.get("id") or item.get("chat_id")) or (group if message_count and not messages else "")
    return {
        "id": chat_id,
        "group": group,
        "victim": _rwlive_text(item.get("victim") or item.get("organization")),
        "started": _rwlive_text(item.get("started") or item.get("start") or item.get("created_at")),
        "ended": _rwlive_text(item.get("ended") or item.get("end") or item.get("updated_at")),
        "initial_demand": item.get("initialransom") or item.get("initial_demand"),
        "final_demand": item.get("negotiatedransom") or item.get("final_demand"),
        "paid": item.get("paid"),
        "message_count": message_count,
        "messages": messages,
        "source": "ransomware.live",
        "api": "pro",
        "metadata": item,
    }

def normalize_rwlive_statistics(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else raw
    return {
        "period": {},
        "total_victims": stats.get("victims"),
        "total_groups": stats.get("groups"),
        "total_press": stats.get("press"),
        "groups": [],
        "countries": [],
        "sectors": [],
        "timeline": [],
        "last_update": _rwlive_text(raw.get("last_update") or stats.get("last_update")),
        "source": "ransomware.live",
        "api": "pro",
        "metadata": raw,
    }

def _rwlive_relationships(victims: List[Dict[str, Any]], groups: List[Dict[str, Any]], cyberattacks: List[Dict[str, Any]],
                          detection: Dict[str, Any] = None, ransom_notes: List[Dict[str, Any]] = None,
                          negotiations: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    relationships = []
    detection = detection or {}
    ransom_notes = ransom_notes or []
    negotiations = negotiations or []
    for victim in victims:
        org = victim.get("name")
        group = victim.get("group")
        if org and group:
            relationships.append({"source": group, "source_type": "ransomware_group", "relation": "claimed_victim", "target": org, "target_type": "organization"})
            relationships.append({"source": org, "source_type": "organization", "relation": "claimed_victim_of", "target": group, "target_type": "ransomware_group"})
        if org and victim.get("website"):
            relationships.append({"source": org, "source_type": "organization", "relation": "website", "target": victim["website"], "target_type": "victim_website"})
        if org and victim.get("country"):
            relationships.append({"source": org, "source_type": "organization", "relation": "located_in", "target": victim["country"], "target_type": "country"})
        if org and victim.get("sector"):
            relationships.append({"source": org, "source_type": "organization", "relation": "operates_in", "target": victim["sector"], "target_type": "sector"})
    for group in groups:
        for infra in group.get("infrastructure", []):
            if infra.get("value"):
                relation = "operates" if infra.get("role") == "leak_site" else "uses_infrastructure"
                relationships.append({"source": group.get("name"), "source_type": "ransomware_group", "relation": relation, "target": infra["value"], "target_type": infra.get("role") or "infrastructure"})
        for alias in group.get("aliases", []) or []:
            if alias and alias != group.get("name"):
                relationships.append({"source": group.get("name"), "source_type": "ransomware_group", "relation": "alias_of", "target": alias, "target_type": "alias"})
        for tool in group.get("tools", []) or []:
            if tool:
                relationships.append({"source": group.get("name"), "source_type": "ransomware_group", "relation": "uses", "target": tool, "target_type": "tool"})
        for malware in group.get("malware", []) or []:
            if malware:
                relationships.append({"source": group.get("name"), "source_type": "ransomware_group", "relation": "uses", "target": malware, "target_type": "malware"})
    for attack in cyberattacks:
        if attack.get("title") and attack.get("organization"):
            relationships.append({"source": attack["title"], "source_type": "cyberattack_report", "relation": "targets", "target": attack["organization"], "target_type": "organization"})
    iocs = detection.get("iocs", []) if isinstance(detection.get("iocs"), list) else []
    for ioc in iocs:
        if ioc.get("group") and ioc.get("value"):
            relationships.append({"source": ioc["group"], "source_type": "ransomware_group", "relation": "associated_with", "target": ioc["value"], "target_type": "ransomware_ioc"})
    for note in ransom_notes:
        if note.get("group") and (note.get("filename") or note.get("id")):
            relationships.append({"source": note["group"], "source_type": "ransomware_group", "relation": "uses_ransom_note", "target": note.get("filename") or note.get("id"), "target_type": "ransom_note"})
    for negotiation in negotiations:
        if negotiation.get("id") and negotiation.get("group"):
            relationships.append({"source": negotiation["id"], "source_type": "negotiation", "relation": "associated_with", "target": negotiation["group"], "target_type": "ransomware_group"})
        if negotiation.get("id") and negotiation.get("victim"):
            relationships.append({"source": negotiation["id"], "source_type": "negotiation", "relation": "associated_with", "target": negotiation["victim"], "target_type": "organization"})
    return relationships

def _rwlive_summary(victims: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "victim_claims": len(victims),
        "top_groups": Counter(v.get("group") for v in victims if v.get("group")).most_common(10),
        "top_countries": Counter(v.get("country") for v in victims if v.get("country")).most_common(10),
        "top_sectors": Counter(v.get("sector") for v in victims if v.get("sector")).most_common(10),
        "time_range": "returned results",
    }

def _rwlive_result(query: str = "", victims: List[Dict[str, Any]] = None, groups: List[Dict[str, Any]] = None,
                   cyberattacks: List[Dict[str, Any]] = None, detection: Dict[str, Any] = None, raw: Dict[str, Any] = None,
                   category: str = "ransomware_intelligence", pagination: Dict[str, Any] = None,
                   ransom_notes: List[Dict[str, Any]] = None, negotiations: List[Dict[str, Any]] = None,
                   statistics: Dict[str, Any] = None, api: str = "legacy") -> Dict[str, Any]:
    victims = victims or []
    groups = groups or []
    cyberattacks = cyberattacks or []
    detection = detection or {"yara": [], "kql": [], "iocs": []}
    ransom_notes = ransom_notes or []
    negotiations = negotiations or []
    infrastructure = []
    for group in groups:
        infrastructure.extend(group.get("infrastructure", []))
    return {
        "source": "ransomware.live",
        "api": api,
        "query": query,
        "category": category,
        "victims": victims,
        "groups": groups,
        "cyberattacks": cyberattacks,
        "infrastructure": infrastructure,
        "detection": detection,
        "ransom_notes": ransom_notes,
        "negotiations": negotiations,
        "relationships": _rwlive_relationships(victims, groups, cyberattacks, detection, ransom_notes, negotiations),
        "statistics": statistics or {},
        "summary": _rwlive_summary(victims),
        "pagination": pagination or {},
        "metadata": {
            "api": api,
            "capabilities": RANSOMWARE_LIVE_PRO_CAPABILITIES if api == "pro" else {
                "victim_search": True,
                "groups": True,
                "group_victims": True,
                "recent_victims": True,
                "countries": True,
                "sectors": True,
                "press": True,
                "yara": True,
            },
        },
        "raw": raw or {},
    }

def _rwlive_dedupe_victims(victims: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped = []
    for victim in victims:
        key = (
            (victim.get("id") or "").lower(),
            (victim.get("name") or "").strip().lower(),
            (victim.get("website") or "").strip().lower(),
            (victim.get("group") or "").strip().lower(),
            (victim.get("discovered") or victim.get("attack_date") or "")[:10],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(victim)
    return deduped

def query_ransomware_live_victims(keyword: str, api_key: str = "", limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty ransomware.live victim search"}
    _, bounds = _rwlive_paginate([], limit, offset)
    limit, offset = bounds["limit"], bounds["offset"]
    if _rwlive_should_use_pro(api_key):
        raw = _rwlive_get("victims/search", params={"q": keyword}, api_key=api_key, timeout=20, pro=True)
        if _rwlive_is_error(raw):
            if _rwlive_not_found(raw):
                return _rwlive_result(keyword, raw={"victims/search": raw}, category="victim_search", api="pro")
            return raw
        all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim({**x, "api": "pro"}) for x in _rwlive_list(raw) if isinstance(x, dict)])
        victims, pagination = _rwlive_paginate([v for v in all_victims if v.get("name")], limit, offset)
        return _rwlive_result(keyword, victims=victims, raw={"victims/search": raw}, category="victim_search", pagination=pagination, api="pro")
    raw = _rwlive_get(f"searchvictims/{urllib.parse.quote(keyword, safe='')}", api_key=api_key, timeout=20)
    if _rwlive_is_error(raw):
        if _rwlive_not_found(raw):
            return _rwlive_result(keyword, raw={"searchvictims": raw}, category="victim_search", pagination={"limit": limit, "offset": offset})
        return raw
    all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim(x) for x in _rwlive_list(raw)])
    victims, pagination = _rwlive_paginate([v for v in all_victims if v.get("name")], limit, offset)
    return _rwlive_result(keyword, victims=victims, raw={"searchvictims": raw}, category="victim_search", pagination=pagination)

def query_ransomware_live_group(group_name: str, api_key: str = "") -> Dict[str, Any]:
    group_name = (group_name or "").strip()
    if not group_name:
        return {"error": "Empty ransomware.live group query"}
    if _rwlive_should_use_pro(api_key):
        raw = _rwlive_get(f"groups/{urllib.parse.quote(group_name, safe='')}", api_key=api_key, timeout=20, pro=True)
        if _rwlive_is_error(raw):
            if _rwlive_not_found(raw):
                return _rwlive_result(group_name, raw={"groups": raw}, category="group_profile", api="pro")
            return raw
        group = normalize_rwlive_group({**raw, "api": "pro"} if isinstance(raw, dict) else raw)
        victims = []
        if isinstance(raw, dict) and isinstance(raw.get("victims"), list):
            victims = _rwlive_dedupe_victims([normalize_rwlive_victim({**v, "group": group.get("name"), "api": "pro"}) for v in raw["victims"] if isinstance(v, dict)])
            group["victims"] = victims[:50]
            group["victim_count"] = group.get("victim_count") or len(victims)
            group["countries"] = [x for x, _ in Counter(v.get("country") for v in victims if v.get("country")).most_common(10)]
            group["sectors"] = [x for x, _ in Counter(v.get("sector") for v in victims if v.get("sector")).most_common(10)]
        return _rwlive_result(group_name, victims=victims[:50], groups=[group] if group.get("name") else [], raw={"groups": raw}, category="group_profile", api="pro")
    raw = _rwlive_get(f"group/{urllib.parse.quote(group_name, safe='')}", api_key=api_key, timeout=20)
    if _rwlive_is_error(raw):
        return raw
    group = normalize_rwlive_group(raw)
    return _rwlive_result(group_name, groups=[group] if group.get("name") else [], raw={"group": raw}, category="group_profile")

def query_ransomware_live_group_victims(group_name: str, api_key: str = "", limit: int = 50, offset: int = 0,
                                        year: str = "", month: str = "", date: str = "") -> Dict[str, Any]:
    group_name = (group_name or "").strip()
    if not group_name:
        return {"error": "Empty ransomware.live group query"}
    _, bounds = _rwlive_paginate([], limit, offset)
    limit, offset = bounds["limit"], bounds["offset"]
    if _rwlive_should_use_pro(api_key):
        params = {"group": group_name}
        if year:
            params["year"] = str(year).strip()
        if month:
            params["month"] = str(month).strip()
        if date:
            params["date"] = str(date).strip()
        raw = _rwlive_get("victims/", params=params, api_key=api_key, timeout=30, pro=True)
        if _rwlive_is_error(raw):
            if _rwlive_not_found(raw):
                return _rwlive_result(group_name, raw={"victims": raw}, category="group_victims", api="pro")
            return raw
        all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim({**x, "group": x.get("group") or group_name, "api": "pro"}) for x in _rwlive_list(raw) if isinstance(x, dict)])
        victims, pagination = _rwlive_paginate([v for v in all_victims if v.get("name")], limit, offset)
        group = normalize_rwlive_group({"group": group_name, "api": "pro"}, all_victims)
        return _rwlive_result(group_name, victims=victims, groups=[group], raw={"victims": raw}, category="group_victims", pagination=pagination, api="pro")
    raw = _rwlive_get(f"groupvictims/{urllib.parse.quote(group_name, safe='')}", api_key=api_key, timeout=30)
    if _rwlive_is_error(raw):
        if _rwlive_not_found(raw):
            return _rwlive_result(group_name, raw={"groupvictims": raw}, category="group_victims", pagination={"limit": limit, "offset": offset})
        return raw
    all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim(x) for x in _rwlive_list(raw)])
    victims, pagination = _rwlive_paginate([v for v in all_victims if v.get("name")], limit, offset)
    group = normalize_rwlive_group({"name": group_name}, all_victims)
    return _rwlive_result(group_name, victims=victims, groups=[group], raw={"groupvictims": raw}, category="group_victims", pagination=pagination)

def query_ransomware_live_recent_victims(api_key: str = "", limit: int = 50, offset: int = 0, order: str = "discovered") -> Dict[str, Any]:
    _, bounds = _rwlive_paginate([], limit, offset)
    limit, offset = bounds["limit"], bounds["offset"]
    order = (order or "discovered").strip().lower()
    if order not in {"discovered", "attacked"}:
        order = "discovered"
    if _rwlive_should_use_pro(api_key):
        raw = _rwlive_get("victims/recent", params={"order": order}, api_key=api_key, timeout=25, pro=True)
        if _rwlive_is_error(raw):
            return raw
        all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim({**x, "api": "pro"}) for x in _rwlive_list(raw) if isinstance(x, dict)])
        victims, pagination = _rwlive_paginate(all_victims, limit, offset)
        return _rwlive_result("recent victims", victims=victims, raw={"victims/recent": raw}, category="recent_victims", pagination=pagination, api="pro")
    raw = _rwlive_get("recentvictims", api_key=api_key, timeout=25)
    if _rwlive_is_error(raw):
        return raw
    all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim(x) for x in _rwlive_list(raw)])
    victims, pagination = _rwlive_paginate(all_victims, limit, offset)
    return _rwlive_result("recent victims", victims=victims, raw={"recentvictims": raw}, category="recent_victims", pagination=pagination)

def query_ransomware_live_country(country_code: str, api_key: str = "", limit: int = 50, offset: int = 0,
                                  year: str = "", month: str = "", date: str = "") -> Dict[str, Any]:
    code = (country_code or "").strip().upper()
    if not re.match(r"^[A-Z]{2}$", code):
        return {"error": "ransomware.live country lookup requires an ISO-2 country code"}
    _, bounds = _rwlive_paginate([], limit, offset)
    limit, offset = bounds["limit"], bounds["offset"]
    if _rwlive_should_use_pro(api_key):
        params = {"country": code}
        if year:
            params["year"] = str(year).strip()
        if month:
            params["month"] = str(month).strip()
        if date:
            params["date"] = str(date).strip()
        raw = _rwlive_get("victims/", params=params, api_key=api_key, timeout=25, pro=True)
        if _rwlive_is_error(raw):
            return raw if not _rwlive_not_found(raw) else _rwlive_result(code, raw={"victims": raw}, category="country_victims", api="pro")
        all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim({**x, "api": "pro"}) for x in _rwlive_list(raw) if isinstance(x, dict)])
        victims, pagination = _rwlive_paginate(all_victims, limit, offset)
        return _rwlive_result(code, victims=victims, raw={"victims": raw}, category="country_victims", pagination=pagination, api="pro")
    raw = _rwlive_get(f"countryvictims/{urllib.parse.quote(code, safe='')}", api_key=api_key, timeout=25)
    if _rwlive_is_error(raw):
        return raw if not _rwlive_not_found(raw) else _rwlive_result(code, raw={"countryvictims": raw}, category="country_victims")
    victims = _rwlive_dedupe_victims([normalize_rwlive_victim(x) for x in _rwlive_list(raw)])
    page, pagination = _rwlive_paginate(victims, limit, offset)
    return _rwlive_result(code, victims=page, raw={"countryvictims": raw}, category="country_victims", pagination=pagination)

def query_ransomware_live_sector(sector: str, api_key: str = "", country_code: str = "", limit: int = 50, offset: int = 0,
                                 year: str = "", month: str = "", date: str = "") -> Dict[str, Any]:
    sector = (sector or "").strip()
    if not sector:
        return {"error": "Empty ransomware.live sector query"}
    _, bounds = _rwlive_paginate([], limit, offset)
    limit, offset = bounds["limit"], bounds["offset"]
    if _rwlive_should_use_pro(api_key):
        params = {"sector": sector}
        if country_code:
            params["country"] = country_code.strip().upper()
        if year:
            params["year"] = str(year).strip()
        if month:
            params["month"] = str(month).strip()
        if date:
            params["date"] = str(date).strip()
        raw = _rwlive_get("victims/", params=params, api_key=api_key, timeout=30, pro=True)
        if _rwlive_is_error(raw):
            return raw if not _rwlive_not_found(raw) else _rwlive_result(sector, raw={"victims": raw}, category="sector_victims", api="pro")
        all_victims = _rwlive_dedupe_victims([normalize_rwlive_victim({**x, "api": "pro"}) for x in _rwlive_list(raw) if isinstance(x, dict)])
        victims, pagination = _rwlive_paginate(all_victims, limit, offset)
        return _rwlive_result(sector, victims=victims, raw={"victims": raw}, category="sector_victims", pagination=pagination, api="pro")
    path = f"sectorvictims/{urllib.parse.quote(sector, safe='')}"
    if country_code:
        path += f"/{urllib.parse.quote(country_code.strip().upper(), safe='')}"
    raw = _rwlive_get(path, api_key=api_key, timeout=30)
    if _rwlive_is_error(raw):
        return raw if not _rwlive_not_found(raw) else _rwlive_result(sector, raw={"sectorvictims": raw}, category="sector_victims")
    victims = _rwlive_dedupe_victims([normalize_rwlive_victim(x) for x in _rwlive_list(raw)])
    page, pagination = _rwlive_paginate(victims, limit, offset)
    return _rwlive_result(sector, victims=page, raw={"sectorvictims": raw}, category="sector_victims", pagination=pagination)

def query_ransomware_live_cyberattacks(api_key: str = "", recent: bool = True, limit: int = 50, offset: int = 0,
                                       country: str = "", year: str = "", month: str = "") -> Dict[str, Any]:
    _, bounds = _rwlive_paginate([], limit, offset)
    limit, offset = bounds["limit"], bounds["offset"]
    if _rwlive_should_use_pro(api_key):
        endpoint = "press/recent" if recent else "press/all"
        params = {}
        if country:
            params["country"] = country.strip().upper()
        if not recent:
            if year:
                params["year"] = str(year).strip()
            if month:
                params["month"] = str(month).strip()
        raw = _rwlive_get(endpoint, params=params, api_key=api_key, timeout=25, pro=True)
        if _rwlive_is_error(raw):
            return raw
        attacks = [normalize_rwlive_cyberattack(x) for x in _rwlive_list(raw)]
        page, pagination = _rwlive_paginate(attacks, limit, offset)
        return _rwlive_result("recent cyberattacks" if recent else "all cyberattacks", cyberattacks=page, raw={endpoint: raw}, category="cyberattacks", pagination=pagination, api="pro")
    endpoint = "recentcyberattacks" if recent else "allcyberattacks"
    raw = _rwlive_get(endpoint, api_key=api_key, timeout=25)
    if _rwlive_is_error(raw):
        return raw
    attacks = [normalize_rwlive_cyberattack(x) for x in _rwlive_list(raw)]
    page, pagination = _rwlive_paginate(attacks, limit, offset)
    return _rwlive_result("recent cyberattacks" if recent else "all cyberattacks", cyberattacks=page, raw={endpoint: raw}, category="cyberattacks", pagination=pagination)

def query_ransomware_live_yara(group_name: str, api_key: str = "") -> Dict[str, Any]:
    group_name = (group_name or "").strip()
    if not group_name:
        return {"error": "Empty ransomware.live group query"}
    if _rwlive_should_use_pro(api_key):
        raw = _rwlive_get(f"yara/{urllib.parse.quote(group_name, safe='')}", api_key=api_key, timeout=20, pro=True)
        if _rwlive_is_error(raw):
            return raw if not _rwlive_not_found(raw) else _rwlive_result(group_name, category="detection", raw={"yara": raw}, api="pro")
        yara = [normalize_rwlive_yara(x, group_name) for x in _rwlive_list(raw)]
        detection = {"yara": [x for x in yara if x.get("content")], "kql": [], "iocs": []}
        result = _rwlive_result(group_name, detection=detection, raw={"yara": raw}, category="detection", api="pro")
        for rule in detection["yara"]:
            result["relationships"].append({"source": group_name, "source_type": "ransomware_group", "relation": "associated_with", "target": rule.get("name") or "YARA", "target_type": "detection_rule"})
        return result
    raw = _rwlive_get(f"yara/{urllib.parse.quote(group_name, safe='')}", api_key=api_key, text=True, timeout=20)
    if _rwlive_is_error(raw):
        return raw if not _rwlive_not_found(raw) else _rwlive_result(group_name, category="detection", raw={"yara": raw})
    text = str(raw or "").strip()
    if not text or re.search(r"^\s*(<!doctype html|<html[\s>])", text, re.I):
        return _rwlive_result(group_name, category="detection", raw={"yara": raw})
    if not re.search(r'\brule\s+[A-Za-z0-9_]+\s*\{|import\s+"|meta:|strings:|condition:', text, re.I):
        return _rwlive_result(group_name, category="detection", raw={"yara": raw})
    detection = {"yara": [{"name": group_name, "group": group_name, "source": "ransomware.live", "content": text, "metadata": {}}], "kql": [], "iocs": []}
    result = _rwlive_result(group_name, detection=detection, raw={"yara": raw}, category="detection")
    result["relationships"].append({"source": group_name, "source_type": "ransomware_group", "relation": "associated_with", "target": f"{group_name} YARA", "target_type": "detection_rule"})
    return result

def query_ransomware_live_victim_detail(victim_id: str, api_key: str = "") -> Dict[str, Any]:
    victim_id = (victim_id or "").strip()
    if not victim_id:
        return {"error": "Empty ransomware.live victim id"}
    raw = _rwlive_get(f"victim/{urllib.parse.quote(victim_id, safe='')}", api_key=api_key, timeout=20, pro=True)
    if _rwlive_is_error(raw):
        return raw if not _rwlive_not_found(raw) else _rwlive_result(victim_id, raw={"victim": raw}, category="victim_detail", api="pro")
    victim = normalize_rwlive_victim({**raw, "api": "pro"} if isinstance(raw, dict) else raw)
    return _rwlive_result(victim_id, victims=[victim] if victim.get("name") else [], raw={"victim": raw}, category="victim_detail", api="pro")

def query_ransomware_live_iocs(group_name: str = "", api_key: str = "", ioc_type: str = "", limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    group_name = (group_name or "").strip()
    ioc_type = (ioc_type or "").strip().lower()
    allowed_types = {"", "md5", "sha1", "sha256", "hash", "ip", "domain", "url", "email", "btc"}
    if ioc_type not in allowed_types:
        return {"error": "Invalid ransomware.live IOC type"}
    endpoint = f"iocs/{urllib.parse.quote(group_name, safe='')}" if group_name else "iocs"
    params = {"type": ioc_type} if ioc_type else {}
    raw = _rwlive_get(endpoint, params=params, api_key=api_key, timeout=25, pro=True)
    if _rwlive_is_error(raw):
        return raw if not _rwlive_not_found(raw) else _rwlive_result(group_name or "all IOCs", raw={endpoint: raw}, category="iocs", api="pro")
    iocs = [normalize_rwlive_ioc(x, group_name) for x in _rwlive_list(raw)]
    page, pagination = _rwlive_paginate([x for x in iocs if x.get("value")], limit, offset)
    detection = {"yara": [], "kql": [], "iocs": page}
    return _rwlive_result(group_name or "all IOCs", detection=detection, raw={endpoint: raw}, category="iocs", pagination=pagination, api="pro")

def query_ransomware_live_ransom_notes(group_name: str, api_key: str = "", note_name: str = "", limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    group_name = (group_name or "").strip()
    note_name = (note_name or "").strip()
    if not group_name:
        return {"error": "Empty ransomware.live group query"}
    endpoint = f"ransomnotes/{urllib.parse.quote(group_name, safe='')}"
    if note_name:
        endpoint += f"/{urllib.parse.quote(note_name, safe='')}"
    raw = _rwlive_get(endpoint, api_key=api_key, timeout=25, pro=True)
    if _rwlive_is_error(raw):
        return raw if not _rwlive_not_found(raw) else _rwlive_result(group_name, raw={endpoint: raw}, category="ransom_notes", api="pro")
    if note_name:
        notes = [normalize_rwlive_ransom_note({**raw, "filename": note_name}, group_name)] if isinstance(raw, dict) else [normalize_rwlive_ransom_note({"filename": note_name, "content": raw}, group_name)]
        return _rwlive_result(group_name, ransom_notes=[x for x in notes if x.get("filename") or x.get("text")], raw={endpoint: raw}, category="ransom_notes", api="pro")
    notes = [normalize_rwlive_ransom_note(x, group_name) for x in _rwlive_list(raw)]
    page, pagination = _rwlive_paginate([x for x in notes if x.get("filename") or x.get("id")], limit, offset)
    return _rwlive_result(group_name, ransom_notes=page, raw={endpoint: raw}, category="ransom_notes", pagination=pagination, api="pro")

def query_ransomware_live_negotiations(group_name: str = "", api_key: str = "", chat_id: str = "", limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    group_name = (group_name or "").strip()
    chat_id = (chat_id or "").strip()
    endpoint = "negotiations"
    if group_name:
        endpoint += f"/{urllib.parse.quote(group_name, safe='')}"
    if group_name and chat_id:
        endpoint += f"/{urllib.parse.quote(chat_id, safe='')}"
    raw = _rwlive_get(endpoint, api_key=api_key, timeout=25, pro=True)
    if _rwlive_is_error(raw):
        return raw if not _rwlive_not_found(raw) else _rwlive_result(group_name or "negotiations", raw={endpoint: raw}, category="negotiations", api="pro")
    negotiations = [normalize_rwlive_negotiation(x, group_name) for x in _rwlive_list(raw)]
    page, pagination = _rwlive_paginate([x for x in negotiations if x.get("id") or x.get("message_count")], limit, offset)
    return _rwlive_result(group_name or "negotiations", negotiations=page, raw={endpoint: raw}, category="negotiations", pagination=pagination, api="pro")

def query_ransomware_live_stats(api_key: str = "") -> Dict[str, Any]:
    raw = _rwlive_get("stats", api_key=api_key, timeout=20, pro=True)
    if _rwlive_is_error(raw):
        return raw
    return _rwlive_result("statistics", statistics=normalize_rwlive_statistics(raw), raw={"stats": raw}, category="statistics", api="pro")

def query_ransomware_live_sectors(api_key: str = "") -> Dict[str, Any]:
    raw = _rwlive_get("listsectors", api_key=api_key, timeout=20, pro=True)
    if _rwlive_is_error(raw):
        return raw
    statistics = {"sectors": _rwlive_list(raw), "source": "ransomware.live", "api": "pro", "metadata": raw}
    return _rwlive_result("sectors", statistics=statistics, raw={"listsectors": raw}, category="sectors", api="pro")

def query_ransomware_live_validate(api_key: str = "") -> Dict[str, Any]:
    """Validate an API-PRO key (documented GET /validate). Diagnostic only."""
    if not _rwlive_has_pro_key(api_key):
        return {"error": "No ransomware.live API-PRO key provided", "missing_key": True}
    raw = _rwlive_get("validate", api_key=api_key, timeout=15, pro=True)
    if _rwlive_is_error(raw):
        return raw
    return {"valid": True, "source": "ransomware.live", "api": "pro", "detail": raw}

def query_ransomware_live(keyword: str, api_key: str = "") -> Dict[str, Any]:
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty ransomware.live query"}
    with ThreadPoolExecutor(max_workers=2) as executor:
        fg = executor.submit(query_ransomware_live_group, keyword, api_key)
        fv = executor.submit(query_ransomware_live_victims, keyword, api_key)
        group_res, victim_res = fg.result(), fv.result()
    groups = group_res.get("groups", []) if isinstance(group_res, dict) and not _rwlive_is_error(group_res) else []
    victims = victim_res.get("victims", []) if isinstance(victim_res, dict) and not _rwlive_is_error(victim_res) else []
    raw = {}
    if isinstance(group_res, dict):
        raw["group_lookup"] = group_res.get("raw", group_res)
    if isinstance(victim_res, dict):
        raw["victim_search"] = victim_res.get("raw", victim_res)
    if not groups and not victims:
        for candidate in (group_res, victim_res):
            if _rwlive_is_error(candidate) and not _rwlive_not_found(candidate):
                return candidate
    return _rwlive_result(keyword, victims=victims, groups=groups, raw=raw)

def query_ransomlook_ip(ip: str) -> Dict[str, Any]:
    res = {}
    
    def fetch_rl(endpoint):
        url = f"https://www.ransomlook.io/api/{endpoint}"
        try:
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and 'error' in data[0]:
                    return None
                if isinstance(data, dict) and 'error' in data:
                    return None
                return data
        except:
            pass
        return None

    urls = {
        "torrent": f"torrent/ip/{ip}",
        "timeline": f"torrent/ip/{ip}/timeline"
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {k: executor.submit(fetch_rl, v) for k, v in urls.items()}
        for k, f in futures.items():
            data = f.result()
            if data:
                if isinstance(data, list) and len(data) > 0:
                    res[k] = data
                elif isinstance(data, dict):
                    res[k] = data

    return res

ORKL_API_BASE = "https://orkl.eu/api/v1"
_ORKL_CACHE: Dict[Any, Any] = {}

def _orkl_cache_ttl(path: str) -> int:
    return 600 if path.startswith(("/library/search", "/news/entries")) else 3600

def _orkl_get(path: str, params: Dict[str, Any] = None, timeout: int = 20) -> Any:
    params = params or {}
    cache_key = (path, tuple(sorted((str(k), str(v)) for k, v in params.items())))
    cached = _ORKL_CACHE.get(cache_key)
    now = time.time()
    if cached and now - cached["time"] < _orkl_cache_ttl(path):
        return cached["data"]
    try:
        resp = requests.get(f"{ORKL_API_BASE}{path}", params=params, timeout=timeout)
        if resp.status_code == 200:
            try:
                data = resp.json()
                _ORKL_CACHE[cache_key] = {"time": now, "data": data}
                return data
            except ValueError:
                return {"error": "ORKL returned a non-JSON response"}
        if resp.status_code == 400:
            return {"error": "ORKL rejected the request"}
        if resp.status_code == 404:
            return {"error": "ORKL report not found"}
        if resp.status_code == 429:
            return {"error": "ORKL rate limit exceeded"}
        if 500 <= resp.status_code < 600:
            return {"error": "ORKL service unavailable"}
        return {"error": f"ORKL request failed (HTTP {resp.status_code})"}
    except requests.exceptions.Timeout:
        return {"error": "ORKL request timeout"}
    except Exception as e:
        return {"error": f"ORKL request failed: {e}"}

def _orkl_items(raw: Any) -> List[Any]:
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, dict):
        return []
    for key in ("data", "results", "items", "entries", "values"):
        value = raw.get(key)
        if isinstance(value, list):
            return value
    return []

def normalize_orkl_report(report: Any) -> Dict[str, Any]:
    if not isinstance(report, dict):
        return {}
    files = report.get("files") if isinstance(report.get("files"), dict) else {}
    original_urls = report.get("original_urls") or report.get("originalUrls") or report.get("urls") or report.get("references") or []
    if isinstance(original_urls, str):
        original_urls = [original_urls]
    sources = report.get("sources") or report.get("source") or report.get("source_name") or []
    if isinstance(sources, str):
        sources = [sources]
    actors = report.get("threat_actors") or report.get("threatActors") or report.get("actors") or report.get("ta") or []
    if isinstance(actors, str):
        actors = [actors]
    iocs = report.get("extracted_iocs") or report.get("extractedIocs") or report.get("iocs") or report.get("indicators") or {}
    if not isinstance(iocs, dict):
        iocs = {}
    normalized_iocs = {
        "domains": iocs.get("domains") or iocs.get("domain") or [],
        "ips": iocs.get("ips") or iocs.get("ip") or iocs.get("ipv4") or [],
        "urls": iocs.get("urls") or iocs.get("url") or [],
        "emails": iocs.get("emails") or iocs.get("email") or [],
        "cves": iocs.get("cves") or iocs.get("cve") or [],
        "hashes": iocs.get("hashes") or iocs.get("hash") or iocs.get("sha256") or [],
    }
    for key, value in list(normalized_iocs.items()):
        normalized_iocs[key] = value if isinstance(value, list) else ([value] if value else [])
    return {
        "id": report.get("uuid") or report.get("id") or report.get("_id") or "",
        "title": report.get("title") or report.get("llm_title") or report.get("name") or (report.get("report_names") or ["Untitled Report"])[0],
        "type": report.get("type") or report.get("report_type") or report.get("entry_type") or "",
        "authors": report.get("authors") or report.get("author") or [],
        "language": report.get("language") or report.get("lang") or "",
        "created": report.get("created_at") or report.get("created") or report.get("published") or "",
        "updated": report.get("updated_at") or report.get("updated") or "",
        "original_urls": original_urls,
        "sources": sources,
        "threat_actors": actors,
        "extracted_iocs": normalized_iocs,
        "files": files,
        "sha1_hash": report.get("sha1_hash") or report.get("sha1") or "",
        "report_names": report.get("report_names") or [],
        "file_size": report.get("file_size"),
        "file_creation_date": report.get("file_creation_date") or "",
        "file_modification_date": report.get("file_modification_date") or "",
        "raw": report,
    }

def normalize_orkl_actor(actor: Any) -> Dict[str, Any]:
    if not isinstance(actor, dict):
        return {}
    aliases = actor.get("aliases") or actor.get("alias") or []
    tools = actor.get("tools") or actor.get("tool") or []
    reports = actor.get("linked_reports") or actor.get("reports") or actor.get("library_entries") or []
    return {
        "id": actor.get("uuid") or actor.get("id") or "",
        "name": actor.get("main_name") or actor.get("name") or actor.get("title") or "",
        "aliases": aliases if isinstance(aliases, list) else ([aliases] if aliases else []),
        "tools": tools if isinstance(tools, list) else ([tools] if tools else []),
        "sources": actor.get("sources") or actor.get("source") or actor.get("source_name") or actor.get("source_id") or [],
        "source_namespace": actor.get("source_id") or "",
        "source_name": actor.get("source_name") or "",
        "linked_reports": reports if isinstance(reports, list) else ([reports] if reports else []),
        "metadata": actor,
    }

def _orkl_relationships(reports: List[Dict[str, Any]], query: str = "") -> List[Dict[str, Any]]:
    relationships = []
    for report in reports:
        rid = report.get("id")
        title = report.get("title")
        if query:
            relationships.append({"source": query, "source_type": "query", "relation": "mentioned_in", "target": title, "target_id": rid, "target_type": "report"})
        for actor in report.get("threat_actors", []):
            actor_name = actor.get("name") if isinstance(actor, dict) else str(actor)
            relationships.append({"source": title, "source_id": rid, "source_type": "report", "relation": "mentions_actor", "target": actor_name, "target_type": "threat_actor"})
        for source in report.get("sources", []):
            relationships.append({"source": title, "source_id": rid, "source_type": "report", "relation": "published_from", "target": str(source), "target_type": "source"})
        for ioc_type, values in report.get("extracted_iocs", {}).items():
            target_type = {
                "domains": "domain",
                "ips": "ip",
                "urls": "url",
                "emails": "email",
                "cves": "cve",
                "hashes": "hash",
            }.get(ioc_type, ioc_type)
            for value in values:
                relationships.append({"source": title, "source_id": rid, "source_type": "report", "relation": "references", "target": str(value), "target_type": target_type})
    return relationships

def query_orkl(keyword: str, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    try:
        limit = max(1, min(int(limit or 20), 50))
    except (TypeError, ValueError):
        limit = 20
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    raw = _orkl_get("/library/search", {"query": keyword, "limit": limit, "offset": offset}, timeout=30)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    reports = [normalize_orkl_report(item) for item in _orkl_items(raw)]
    reports = [report for report in reports if report]
    return {
        "source": "ORKL",
        "query": keyword,
        "category": "report_evidence",
        "data": reports,
        "reports": reports,
        "relationships": _orkl_relationships(reports, keyword),
        "pagination": {
            "limit": limit,
            "offset": offset,
            "next_offset": offset + limit if len(reports) >= limit else None,
        },
        "raw": raw,
    }

def query_orkl_library_entry(uuid: str) -> Dict[str, Any]:
    raw = _orkl_get(f"/library/entry/{urllib.parse.quote(uuid, safe='')}", timeout=30)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    report = normalize_orkl_report(raw)
    return {
        "source": "ORKL",
        "category": "report_detail",
        "data": report,
        "report": report,
        "relationships": _orkl_relationships([report], ""),
        "raw": raw,
    }

def query_orkl_report_sha1(sha1: str) -> Dict[str, Any]:
    raw = _orkl_get(f"/library/entry/sha1/{urllib.parse.quote(sha1, safe='')}", timeout=30)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    report = normalize_orkl_report(raw)
    return {"source": "ORKL", "category": "report_sha1_match", "data": report, "report": report, "raw": raw}

def query_orkl_threat_actors(limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    raw = _orkl_get("/ta/entries", {"limit": limit, "offset": offset}, timeout=30)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    actors = [normalize_orkl_actor(item) for item in _orkl_items(raw)]
    actors = [actor for actor in actors if actor]
    return {"source": "ORKL", "category": "threat_actor", "data": actors, "threat_actors": actors, "raw": raw}

def query_orkl_threat_actor(uuid: str) -> Dict[str, Any]:
    raw = _orkl_get(f"/ta/entry/{urllib.parse.quote(uuid, safe='')}", timeout=30)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    actor = normalize_orkl_actor(raw)
    return {"source": "ORKL", "category": "threat_actor_profile", "data": actor, "threat_actor": actor, "raw": raw}

def query_orkl_sources(limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    raw = _orkl_get("/source/entries", {"limit": limit, "offset": offset}, timeout=30)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "ORKL", "category": "source", "data": _orkl_items(raw), "sources": _orkl_items(raw), "raw": raw}

def query_orkl_source(uuid: str) -> Dict[str, Any]:
    raw = _orkl_get(f"/source/entry/{urllib.parse.quote(uuid, safe='')}", timeout=30)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "ORKL", "category": "source_profile", "data": raw, "source_profile": raw, "raw": raw}

def query_orkl_news(limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    raw = _orkl_get("/news/entries", {"limit": limit, "offset": offset}, timeout=20)
    if isinstance(raw, dict) and raw.get("error"):
        return raw
    return {"source": "ORKL", "category": "news", "data": _orkl_items(raw), "news": _orkl_items(raw), "raw": raw}

def query_orkl_exact(indicator: str) -> Dict[str, Any]:
    data = query_orkl(indicator)
    if not isinstance(data, dict) or data.get("error"):
        return data

    reports = data.get("data")
    if not indicator or not isinstance(reports, list):
        return data

    filtered = []
    for report in reports:
        if _report_contains_exact_ioc(report, indicator):
            filtered.append(report)

    data = {**data, "data": filtered, "reports": filtered, "relationships": _orkl_relationships(filtered, indicator)}
    if not filtered:
        data["total"] = 0
        data["message"] = "No exact ORKL CTI report references found for this indicator."
    else:
        data["total"] = len(filtered)
    return data

CB_API_BASE = "https://cyberbriefing.info/api/v1"
CB_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

def _cb_get(path: str, api_key: str, params: Dict[str, Any] = None, timeout: int = 15) -> Any:
    """Documented CyberBriefing GET helper. Never raises; returns parsed JSON
    or an {"error": ...} dict with provider-specific messages."""
    if not api_key:
        return {"error": "No CyberBriefing API key provided"}
    try:
        resp = requests.get(f"{CB_API_BASE}{path}", headers={"X-API-Key": api_key}, params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return {"error": "CyberBriefing returned a non-JSON response"}
        if resp.status_code == 401:
            return {"error": "CyberBriefing API key invalid"}
        if resp.status_code == 403:
            return {"error": "Feature unavailable for current CyberBriefing subscription"}
        if resp.status_code == 404:
            return {"error": "CyberBriefing IOC not found"}
        if resp.status_code == 429:
            return {"error": "CyberBriefing rate limit exceeded"}
        if 500 <= resp.status_code < 600:
            return {"error": f"CyberBriefing server error (HTTP {resp.status_code})"}
        try:
            detail = resp.json().get("detail")
        except Exception:
            detail = None
        return {"error": f"CyberBriefing request failed (HTTP {resp.status_code})" + (f": {detail}" if detail else "")}
    except requests.exceptions.Timeout:
        return {"error": "CyberBriefing request timeout"}
    except Exception as e:
        return {"error": f"CyberBriefing request failed: {e}"}

def _cb_is_error(data: Any) -> bool:
    return isinstance(data, dict) and bool(data.get("error"))

def normalize_cb_ioc(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return {
        "id": item.get("id") or "",
        "type": item.get("type") or "",
        "value": item.get("value") or "",
        "severity": item.get("severity") or "",
        "description": item.get("description") or "",
        "is_active": item.get("is_active"),
        "first_seen": item.get("first_seen") or "",
        "last_seen": item.get("last_seen") or "",
    }

def normalize_cb_search_entity(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    raw_score = item.get("score", 0)
    try:
        relevance = float(raw_score)
    except (TypeError, ValueError):
        relevance = 0
    return {
        "entity_type": item.get("entity_type") or "",
        "entity_id": item.get("entity_id") or "",
        "title": item.get("title") or "",
        "summary": item.get("summary") or "",
        "relevance_score": relevance,
        "raw": item,
    }

def normalize_cb_threat(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    aliases = item.get("aliases") or []
    return {
        "id": item.get("id") or "",
        "name": item.get("name") or "",
        "aliases": [a for a in aliases if isinstance(a, str) and a.strip()] if isinstance(aliases, list) else [],
        "origin_country": item.get("origin_country") or "",
        "motivation": item.get("motivation") or "",
        "description": item.get("description") or "",
        "first_observed": item.get("first_observed") or "",
        "is_active": item.get("is_active"),
        "raw": item,
    }

def normalize_cb_cve(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    try:
        cvss = float(item.get("cvss_score")) if item.get("cvss_score") is not None else None
    except (TypeError, ValueError):
        cvss = None
    return {
        "id": item.get("id") or "",
        "cve_id": item.get("cve_id") or "",
        "description": item.get("description") or "",
        "cvss_score": cvss,
        "severity": item.get("severity") or "",
        "has_exploit": item.get("has_exploit"),
        "published_at": item.get("published_at") or "",
        "raw": item,
    }

def _cb_as_list(data: Any) -> List[Any]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("results", "data", "items", "iocs", "threats", "cves"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        if data.get("error"):
            return []
        return [data]
    return []

def normalize_cb_result(raw: Any, query: str = "") -> Dict[str, Any]:
    """Common normalized structure; raw provider response preserved for the UI."""
    normalized: Dict[str, Any] = {
        "source": "CyberBriefing",
        "query": query,
        "ioc": {},
        "related_iocs": [],
        "search_results": [],
        "threats": [],
        "cves": [],
        "relationships": [],
        "raw": raw,
    }
    if _cb_is_error(raw) or raw is None:
        return normalized
    items = _cb_as_list(raw)
    iocs = [normalize_cb_ioc(x) for x in items if isinstance(x, dict) and (x.get("value") or x.get("type"))]
    iocs = [x for x in iocs if x.get("value")]
    if iocs:
        normalized["ioc"] = iocs[0]
        normalized["related_iocs"] = iocs[1:]
    normalized["search_results"] = [normalize_cb_search_entity(x) for x in items if isinstance(x, dict) and x.get("entity_type")]
    normalized["threats"] = [normalize_cb_threat(x) for x in items if isinstance(x, dict) and (x.get("name") or x.get("aliases")) and not x.get("entity_type") and not x.get("cve_id") and not x.get("value")]
    normalized["cves"] = [normalize_cb_cve(x) for x in items if isinstance(x, dict) and (x.get("cve_id") or x.get("cvss_score") is not None)]
    rels: List[Dict[str, Any]] = []
    if normalized["ioc"].get("value"):
        rels.append({"source": normalized["ioc"]["value"], "relation": "mentioned_in", "target": "CyberBriefing", "target_type": "provider"})
        if normalized["ioc"].get("severity"):
            rels.append({"source": normalized["ioc"]["value"], "relation": "has_severity", "target": normalized["ioc"]["severity"], "target_type": "severity"})
    for t in normalized["threats"]:
        for alias in t.get("aliases", []) or []:
            rels.append({"source": t.get("name"), "relation": "alias", "target": alias, "target_type": "alias"})
        if t.get("origin_country"):
            rels.append({"source": t.get("name"), "relation": "originates_from", "target": t["origin_country"], "target_type": "country"})
        if t.get("motivation"):
            rels.append({"source": t.get("name"), "relation": "motivated_by", "target": t["motivation"], "target_type": "motivation"})
    for c in normalized["cves"]:
        if c.get("severity"):
            rels.append({"source": c.get("cve_id"), "relation": "has_severity", "target": c["severity"], "target_type": "severity"})
        if c.get("cvss_score") is not None:
            rels.append({"source": c.get("cve_id"), "relation": "has_cvss", "target": str(c["cvss_score"]), "target_type": "cvss"})
        if c.get("has_exploit") is True:
            rels.append({"source": c.get("cve_id"), "relation": "exploit_available", "target": "true", "target_type": "exploit"})
    normalized["relationships"] = rels
    return normalized

def _cb_with_normalized(raw: Any, query: str) -> Any:
    if _cb_is_error(raw):
        return raw
    result = normalize_cb_result(raw, query)
    # Keep the raw response accessible under its natural shape too.
    if isinstance(raw, dict):
        result = {**raw, "normalized": result}
    elif isinstance(raw, list):
        result = {"items": raw, "normalized": result}
    return result

def query_cb_ioc(indicator: str, api_key: str) -> Dict[str, Any]:
    value = (indicator or "").strip()
    if not value:
        return {"error": "Empty indicator"}
    encoded = urllib.parse.quote(value, safe="")
    exact = _cb_get(f"/iocs/lookup/{encoded}", api_key)
    if not _cb_is_error(exact):
        # Exact IOC match (single object). A falsy/empty body means not found.
        if exact:
            result = _cb_with_normalized(exact, value)
            norm = result.get("normalized") if isinstance(result, dict) else None
            if isinstance(norm, dict):
                norm["exact_match"] = True
            return result
    else:
        err = str(exact.get("error", ""))
        # Auth / rate-limit / subscription errors: surface directly, no fallback.
        if err in {"CyberBriefing API key invalid", "CyberBriefing rate limit exceeded"} or "subscription" in err:
            return exact
        # Otherwise (404 IOC not found, timeouts, server errors): try broad search.
    fallback = _cb_get("/iocs", api_key, {"q": value, "limit": 10})
    if _cb_is_error(fallback):
        # Prefer the exact-lookup outcome when the fallback also fails.
        if not _cb_is_error(exact):
            return _cb_with_normalized(exact, value)
        return fallback
    result = _cb_with_normalized(fallback, value)
    norm = result.get("normalized") if isinstance(result, dict) else None
    if isinstance(norm, dict):
        norm["exact_match"] = False
    return result

def query_cb_search(keyword: str, api_key: str, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "Empty keyword"}
    try:
        limit = max(1, min(int(limit or 20), 100))
    except (TypeError, ValueError):
        limit = 20
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    raw = _cb_get("/search", api_key, {"q": keyword, "limit": limit})
    if _cb_is_error(raw):
        return raw
    result = _cb_with_normalized(raw, keyword)
    if isinstance(result, dict) and isinstance(result.get("normalized"), dict):
        result["normalized"]["pagination"] = {"limit": limit, "offset": offset}
    return result

def query_cb_ioc_search(query: str, api_key: str, limit: int = 20, offset: int = 0, ioc_type: str = "", severity: str = "") -> Dict[str, Any]:
    try:
        limit = max(1, min(int(limit or 20), 1000))
    except (TypeError, ValueError):
        limit = 20
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    if (query or "").strip():
        params["q"] = query.strip()
    if ioc_type in {"ip", "domain", "hash", "url", "email"}:
        params["type"] = ioc_type
    if severity in {"critical", "high", "medium", "low"}:
        params["severity"] = severity
    raw = _cb_get("/iocs", api_key, params)
    if _cb_is_error(raw):
        return raw
    return _cb_with_normalized(raw, query or "")

def query_cb_threats(name: str, api_key: str, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    name = (name or "").strip()
    if not name:
        return {"error": "Empty threat actor query"}
    try:
        limit = max(1, min(int(limit or 20), 100))
    except (TypeError, ValueError):
        limit = 20
    raw = _cb_get("/threats", api_key, {"q": name, "limit": limit})
    if _cb_is_error(raw):
        return raw
    return _cb_with_normalized(raw, name)

def query_cb_cves(query: str, api_key: str, limit: int = 50, offset: int = 0, severity: str = "", has_exploit: Any = None) -> Dict[str, Any]:
    query = (query or "").strip()
    if not query:
        return {"error": "Empty CVE query"}
    # Exact CVE lookup: GET /cves/{cve_id}
    if CB_CVE_RE.match(query):
        raw = _cb_get(f"/cves/{urllib.parse.quote(query.upper(), safe='')}", api_key)
        if _cb_is_error(raw):
            return raw
        return _cb_with_normalized(raw, query.upper())
    try:
        limit = max(1, min(int(limit or 50), 100))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    params: Dict[str, Any] = {"q": query, "limit": limit}
    if severity in {"critical", "high", "medium", "low"}:
        params["severity"] = severity
    if has_exploit is True or (isinstance(has_exploit, str) and has_exploit.strip().lower() in {"true", "1", "yes"}):
        params["has_exploit"] = True
    raw = _cb_get("/cves", api_key, params)
    if _cb_is_error(raw):
        return raw
    return _cb_with_normalized(raw, query)


# ---------------------------------------------------------------------------
# Batch 1 passive providers: ThreatMiner, Mnemonic PDNS, URLhaus, GreyNoise
# Community (v3), crt.sh, RIPEstat, LeakIX.
# Strictly READ-ONLY. No submissions, downloads, scans, crawls, rescans,
# probing, or target contact anywhere in this section. A zero result stays
# a zero result; provider failures are isolated per call.
# BGPView: public API currently unreachable (DNS fails, 2026-09-11), so it
# is skipped entirely — no scraping, no mirrors, no substitution.
# ---------------------------------------------------------------------------
PROVIDER_BASES = {
    "threatminer": "https://api.threatminer.org/v2/",
    "mnemonic": "https://api.mnemonic.no/pdns/v3/",
    "urlhaus": "https://urlhaus-api.abuse.ch/",
    "greynoise": "https://api.greynoise.io/v3/community/",
    "crtsh": "https://crt.sh/",
    "ripestat": "https://stat.ripe.net/data/",
    "leakix": "https://leakix.net/",
}

_BATCH1_CACHE: Dict[str, Any] = {}
_BATCH1_CACHE_TTL = {"hit": 21600, "miss": 1800}


def _b1_get(key: str):
    entry = _BATCH1_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            _BATCH1_CACHE.pop(key, None)
            return None
    except Exception:
        return None
    return value


def _b1_set(key: str, value: Any, ttl: int):
    try:
        _BATCH1_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass


def _b1_http_error(label: str, status: int, body: str = "") -> Dict[str, Any]:
    """Map HTTP outcomes to structured results. 404 = no record (not an
    error card); 429 surfaces rate limiting with the hint when supplied."""
    if status == 400:
        return {"error": f"{label}: invalid or non-routable input (400)"}
    if status in (401, 403):
        return {"error": f"{label}: unauthorized — check the API key ({status})"}
    if status == 404:
        return {"data": [], "note": f"No {label} record"}
    if status == 429:
        hint = ""
        if body:
            m = re.search(r"[Rr]etry-?[Aa]fter[:\s]+(\d+)", body)
            if m:
                hint = f" (retry after {m.group(1)}s)"
            elif body.strip().isdigit():
                hint = f" (retry after {body.strip()}s)"
        return {"error": f"{label}: rate limited (429){hint}", "rate_limited": True}
    if status in (408, 504):
        return {"error": f"{label}: timed out ({status})"}
    if status >= 500:
        return {"error": f"{label}: provider error ({status})"}
    return {"error": f"{label}: unexpected status ({status})"}


def _b1_get_json(url: str, label: str, params: dict = None,
                 headers: dict = None, timeout: int = 20):
    """GET JSON with status mapping. Returns (ok, payload-or-error-dict)."""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; MANTIS/1.0; passive research client)",
               "Accept": "application/json", **(headers or {})}
    try:
        resp = requests.get(url, params=params or {}, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        return False, {"error": f"{label}: timed out"}
    except Exception as e:
        return False, {"error": f"{label}: request failed ({type(e).__name__})"}
    if resp.status_code == 200:
        try:
            return True, resp.json()
        except ValueError:
            return False, {"error": f"{label}: malformed response"}
    return False, _b1_http_error(label, resp.status_code,
                                 resp.headers.get("Retry-After", ""))


_THREATMINER_RT = {
    "domain": {1: "whois", 2: "pdns", 3: "uris", 5: "subdomains", 6: "reports"},
    "host": {1: "whois", 2: "pdns", 3: "uris", 5: "certs"},
    "sample": {1: "metadata", 3: "related", 6: "av"},
}


def _threatminer_fetch(endpoint: str, indicator: str, rt: int):
    """One ThreatMiner rt call. Returns (kind, results-list, error-or-None)."""
    label = "ThreatMiner"
    cache_key = f"tm:{endpoint}:{rt}:{indicator}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    kind = _THREATMINER_RT.get(endpoint, {}).get(rt, f"rt{rt}")
    ok, payload = _b1_get_json(f"{PROVIDER_BASES['threatminer']}{endpoint}.php",
                               label, params={"q": indicator, "rt": rt}, timeout=20)
    if not ok:
        out = (kind, [], payload.get("error", "failed"))
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    if not isinstance(payload, dict):
        out = (kind, [], f"{label}: unexpected response shape")
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    if str(payload.get("status_code", "")) != "200":
        msg = str(payload.get("status_message", "") or "no results")
        if "no result" in msg.lower() or not payload.get("results"):
            out = (kind, [], "")
        else:
            out = (kind, [], f"{label}: {msg}"[:200])
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    results = payload.get("results")
    if not isinstance(results, list):
        results = [results] if results else []
    out = (kind, results, "")
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


def _tm_str_list(items, *keys, limit=50):
    out = []
    for item in items or []:
        if isinstance(item, str):
            if item.strip():
                out.append(item.strip())
        elif isinstance(item, dict):
            for k in keys:
                v = item.get(k)
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
                    break
        if len(out) >= limit:
            break
    seen, deduped = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            deduped.append(v)
    return deduped


def query_threatminer_domain(domain: str) -> Dict[str, Any]:
    """Domain WHOIS + passive DNS + related URIs + subdomains (+ reports)."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"error": "Empty domain for ThreatMiner lookup"}
    res: Dict[str, Any] = {"source": "ThreatMiner", "query": domain,
                           "pdns": [], "subdomains": [], "uris": [],
                           "reports": [], "whois": {}, "errors": []}
    for rt in (1, 2, 3, 5, 6):
        kind, results, err = _threatminer_fetch("domain", domain, rt)
        if err:
            res["errors"].append(err)
            continue
        if kind == "whois":
            res["whois"] = results[0] if results and isinstance(results[0], dict) else {}
        elif kind == "pdns":
            for r in results[:100]:
                if not isinstance(r, dict):
                    continue
                res["pdns"].append({
                    "domain": str(r.get("domain", "") or domain),
                    "ip": str(r.get("ip", "") or ""),
                    "record_type": "A",
                    "first_seen": str(r.get("first_seen", "") or ""),
                    "last_seen": str(r.get("last_seen", "") or ""),
                    "source": "ThreatMiner"})
        elif kind == "uris":
            res["uris"] = _tm_str_list(results, "uri", "url")
        elif kind == "subdomains":
            res["subdomains"] = _tm_str_list(results, "subdomain", "domain")
        elif kind == "reports":
            for r in results[:50]:
                if isinstance(r, dict):
                    res["reports"].append({
                        "filename": str(r.get("filename", "") or ""),
                        "year": str(r.get("year", "") or "")})
                elif isinstance(r, str) and r.strip():
                    res["reports"].append({"filename": r.strip(), "year": ""})
    return res


def query_threatminer_host(ip: str) -> Dict[str, Any]:
    """IP WHOIS + passive DNS + related URIs + SSL certificates."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for ThreatMiner lookup"}
    res: Dict[str, Any] = {"source": "ThreatMiner", "query": ip,
                           "pdns": [], "uris": [], "certificates": [],
                           "whois": {}, "errors": []}
    for rt in (1, 2, 3, 5):
        kind, results, err = _threatminer_fetch("host", ip, rt)
        if err:
            res["errors"].append(err)
            continue
        if kind == "whois":
            res["whois"] = results[0] if results and isinstance(results[0], dict) else {}
        elif kind == "pdns":
            for r in results[:100]:
                if not isinstance(r, dict):
                    continue
                res["pdns"].append({
                    "domain": str(r.get("domain", "") or ""),
                    "ip": str(r.get("ip", "") or ip),
                    "record_type": "A",
                    "first_seen": str(r.get("first_seen", "") or ""),
                    "last_seen": str(r.get("last_seen", "") or ""),
                    "source": "ThreatMiner"})
        elif kind == "uris":
            res["uris"] = _tm_str_list(results, "uri", "url")
        elif kind == "certs":
            for r in results[:50]:
                if isinstance(r, dict):
                    res["certificates"].append({
                        "issuer": str(r.get("issuer", "") or ""),
                        "subject": str(r.get("subject", "") or ""),
                        "fingerprint": str(r.get("fingerprint", "") or r.get("sha1", "") or "")})
    return res


def query_threatminer_sample(file_hash: str) -> Dict[str, Any]:
    """Sample metadata + related hosts + AV detections."""
    file_hash = (file_hash or "").strip().lower()
    if not file_hash:
        return {"error": "Empty hash for ThreatMiner lookup"}
    res: Dict[str, Any] = {"source": "ThreatMiner", "query": file_hash,
                           "metadata": {}, "related_hosts": [],
                           "av_detections": [], "errors": []}
    for rt in (1, 3, 6):
        kind, results, err = _threatminer_fetch("sample", file_hash, rt)
        if err:
            res["errors"].append(err)
            continue
        if kind == "metadata":
            res["metadata"] = results[0] if results and isinstance(results[0], dict) else {}
        elif kind == "related":
            for r in results[:50]:
                if isinstance(r, dict):
                    res["related_hosts"].append({
                        "host": str(r.get("host", "") or r.get("domain", "") or r.get("ip", "") or ""),
                        "relation": str(r.get("relation", "") or "")})
                elif isinstance(r, str) and r.strip():
                    res["related_hosts"].append({"host": r.strip(), "relation": ""})
        elif kind == "av":
            for r in results[:50]:
                if isinstance(r, dict):
                    vendor = str(r.get("vendor", "") or r.get("av", "") or "")
                    result = str(r.get("result", "") or r.get("detection", "") or "")
                    if vendor or result:
                        res["av_detections"].append({"vendor": vendor, "result": result})
                elif isinstance(r, str) and r.strip():
                    res["av_detections"].append({"vendor": "", "result": r.strip()})
    return res


def _key_tag(api_key: str = "") -> str:
    """Short non-reversible tag so cached entries never cross API keys."""
    if not (api_key or "").strip():
        return "anon"
    return hashlib.sha256(api_key.strip().encode()).hexdigest()[:12]














def _urlhaus_post(path: str, payload: dict, api_key: str) -> tuple:
    """POST to the Community query API (v1/url, v1/payload).

    Never touches the submission endpoint (urlhaus.abuse.ch/api/).
    Returns (ok, data-or-error-dict).
    """
    label = "URLhaus"
    if not (api_key or "").strip():
        return False, {"error": f"{label}: Auth-Key required (Settings)"}
    headers = {"Auth-Key": api_key.strip(), "Accept": "application/json"}
    try:
        resp = requests.post(f"{PROVIDER_BASES['urlhaus']}v1/{path}/",
                             json=payload, headers=headers, timeout=20)
    except requests.exceptions.Timeout:
        return False, {"error": f"{label}: timed out"}
    except Exception as e:
        return False, {"error": f"{label}: request failed ({type(e).__name__})"}
    if resp.status_code == 200:
        try:
            return True, resp.json()
        except ValueError:
            return False, {"error": f"{label}: malformed response"}
    if resp.status_code in (400, 404):
        try:
            body = resp.json()
            if isinstance(body, dict) and body.get("query_status") == "no_results":
                return True, {"query_status": "no_results"}
        except ValueError:
            pass
    return False, _b1_http_error(label, resp.status_code,
                                 resp.headers.get("Retry-After", ""))


def query_urlhaus_url(url: str, api_key: str) -> Dict[str, Any]:
    """URL metadata lookup (status, threat, tags, payloads). Metadata only."""
    url = (url or "").strip()
    if not url:
        return {"error": "Empty URL for URLhaus lookup"}
    cache_key = f"uh:url:{url}:{bool((api_key or '').strip())}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    ok, data = _urlhaus_post("url", {"url": url}, api_key)
    if not ok:
        _b1_set(cache_key, data, _BATCH1_CACHE_TTL["miss"])
        return data
    if not isinstance(data, dict) or data.get("query_status") == "no_results":
        out = {"source": "URLhaus", "url": url, "data": [],
               "note": "No URLhaus record"}
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
        return out
    payloads = []
    for p in (data.get("payloads") or [])[:20]:
        if not isinstance(p, dict):
            continue
        vt = p.get("virustotal") if isinstance(p.get("virustotal"), dict) else {}
        vt_result = str(vt.get("result") or p.get("vt_result") or "")
        try:
            vt_percent = vt.get("percent")
            vt_percent = float(vt_percent) if vt_percent not in (None, "") else None
        except (TypeError, ValueError):
            vt_percent = None
        payloads.append({
            "sha256": str(p.get("sha256_hash", "") or ""),
            "md5": str(p.get("md5_hash", "") or ""),
            "filename": str(p.get("filename", "") or ""),
            "file_type": str(p.get("file_type", "") or ""),
            "signature": str(p.get("signature", "") or ""),
            "firstseen": str(p.get("firstseen", "") or ""),
            "lastseen": str(p.get("lastseen", "") or ""),
            "reporter": str(p.get("reporter", "") or ""),
            "vt_result": vt_result,
            "virustotal_percent": vt_percent})
    out = {"source": "URLhaus", "url": url,
           "status": str(data.get("url_status", "") or ""),
           "threat": str(data.get("threat", "") or ""),
           "tags": data.get("tags", []) if isinstance(data.get("tags"), list) else [],
           "first_seen": str(data.get("date_added", "") or ""),
           "last_seen": str(data.get("last_online", "") or ""),
           "reporter": str(data.get("reporter", "") or ""),
           "payloads": payloads}
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


def query_urlhaus_payload(file_hash: str, api_key: str) -> Dict[str, Any]:
    """Payload metadata by SHA-256 + known delivery URLs. Metadata only."""
    file_hash = (file_hash or "").strip().lower()
    if get_hash_type(file_hash) != "sha256":
        return {"error": "URLhaus payload lookup requires a SHA-256 hash"}
    cache_key = f"uh:payload:{file_hash}:{bool((api_key or '').strip())}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    ok, data = _urlhaus_post("payload", {"sha256_hash": file_hash}, api_key)
    if not ok:
        _b1_set(cache_key, data, _BATCH1_CACHE_TTL["miss"])
        return data
    if not isinstance(data, dict) or data.get("query_status") == "no_results":
        out = {"source": "URLhaus", "sha256": file_hash, "data": [],
               "note": "No URLhaus record"}
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
        return out
    urls = []
    for u in (data.get("urls") or [])[:50]:
        if not isinstance(u, dict):
            continue
        urls.append({"url": str(u.get("url", "") or ""),
                     "status": str(u.get("url_status", "") or ""),
                     "date_added": str(u.get("date_added", "") or "")})
    out = {"source": "URLhaus", "sha256": file_hash,
           "md5": str(data.get("md5_hash", "") or ""),
           "filename": str(data.get("filename", "") or ""),
           "file_type": str(data.get("file_type", "") or ""),
           "file_size": str(data.get("file_size", "") or ""),
           "signature": str(data.get("signature", "") or ""),
           "first_seen": str(data.get("first_seen", "") or ""),
           "last_seen": str(data.get("last_seen", "") or ""),
           "urls": urls}
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


def query_greynoise(ip: str, api_key: str = "") -> Dict[str, Any]:
    """GreyNoise v3 Community IP lookup. 404 = no record (not benign)."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for GreyNoise lookup"}
    try:
        normalized = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"error": "GreyNoise: invalid IP address"}
    cache_key = f"gn:{normalized}:{_key_tag(api_key)}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    headers = {}
    if (api_key or "").strip():
        headers["key"] = api_key.strip()
    ok, payload = _b1_get_json(
        f"{PROVIDER_BASES['greynoise']}{normalized}", "GreyNoise",
        headers=headers, timeout=20)
    if not ok:
        if isinstance(payload, dict) and payload.get("note"):
            out = {"source": "GreyNoise", "ip": normalized, "data": [],
                   "note": payload["note"]}
            _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
            return out
        _b1_set(cache_key, payload, _BATCH1_CACHE_TTL["miss"])
        return payload
    if not isinstance(payload, dict):
        out = {"error": "GreyNoise: unexpected response shape"}
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    out = {"source": "GreyNoise",
           "ip": str(payload.get("ip", "") or normalized),
           "noise": bool(payload.get("noise", False)),
           "riot": bool(payload.get("riot", False)),
           "classification": str(payload.get("classification", "") or ""),
           "name": str(payload.get("name", "") or ""),
           "link": str(payload.get("link", "") or ""),
           "last_seen": str(payload.get("last_seen", "") or ""),
           "message": str(payload.get("message", "") or "")}
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


def _crtsh_fetch(domain: str):
    """One crt.sh query (exact or wildcard). Returns (certs-list, error)."""
    label = "crt.sh"
    cache_key = f"crt:{domain}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    ok, payload = _b1_get_json(PROVIDER_BASES["crtsh"],
                               label, params={"q": domain, "output": "json"},
                               timeout=25)
    if not ok:
        out = ([], payload.get("error", "failed") if isinstance(payload, dict) else "failed")
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    out = (payload if isinstance(payload, list) else [], "")
    _b1_set(cache_key, out, 86400)
    return out


def query_crtsh(domain: str) -> Dict[str, Any]:
    """Certificate Transparency: exact + wildcard certs, SANs deduped."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"error": "Empty domain for crt.sh lookup"}
    seen_ids, certs, errors = set(), [], []
    for q in (domain, f"%.{domain}"):
        results, err = _crtsh_fetch(q)
        if err:
            errors.append(err)
            continue
        for c in results:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if cid in seen_ids:
                continue
            seen_ids.add(cid)
            sans = []
            for name in str(c.get("name_value", "") or "").splitlines():
                name = name.strip().lower().rstrip(".")
                if name and name not in sans:
                    sans.append(name)
            certs.append({
                "certificate_id": cid,
                "common_name": str(c.get("common_name", "") or ""),
                "san": sans[:50],
                "issuer": str(c.get("issuer_name", "") or ""),
                "not_before": str(c.get("not_before", "") or ""),
                "not_after": str(c.get("not_after", "") or ""),
                "serial_number": str(c.get("serial_number", "") or ""),
                "source": "crt.sh"})
            if len(certs) >= 200:
                break
        if len(certs) >= 200:
            break
    res: Dict[str, Any] = {"source": "crt.sh", "domain": domain,
                           "certificates": certs, "count": len(certs)}
    if errors and not certs:
        res["note"] = "; ".join(errors)[:300]
        res["provider_unavailable"] = True
    return res


def _ripe_get(endpoint: str, resource: str):
    """RIPEstat data call. Returns (data-dict, error-or-None)."""
    label = "RIPEstat"
    cache_key = f"ripe:{endpoint}:{resource}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    ok, payload = _b1_get_json(
        f"{PROVIDER_BASES['ripestat']}{endpoint}/data.json",
        label, params={"resource": resource}, timeout=20)
    if not ok:
        out = ({}, payload.get("error", "failed") if isinstance(payload, dict) else "failed")
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        out = ({}, f"{label}: {(payload or {}).get('message', 'unavailable') if isinstance(payload, dict) else 'unavailable'}"[:200])
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
    out = (data, "")
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


def query_ripe_asn(asn: str) -> Dict[str, Any]:
    """ASN overview + announced prefixes + WHOIS for explicit AS input."""
    asn = (asn or "").strip().upper()
    if asn and not asn.startswith("AS"):
        asn = "AS" + asn
    if not re.fullmatch(r"AS\d{1,10}", asn or ""):
        return {"error": "RIPEstat ASN lookup needs an AS number (e.g. AS15169)"}
    res: Dict[str, Any] = {"source": "RIPEstat", "asn": asn, "asns": [asn],
                           "asn_overview": {}, "announced_prefixes": [],
                           "whois": [], "errors": []}
    overview, err = _ripe_get("as-overview", asn)
    if err:
        res["errors"].append(err)
    else:
        res["asn_overview"] = {
            "asn": str(overview.get("resource", "") or asn),
            "announced": bool(overview.get("announced", False)),
            "holder": str(overview.get("holder", "") or ""),
            "block": overview.get("block", {}) if isinstance(overview.get("block"), dict) else {}}
    prefixes_data, err = _ripe_get("announced-prefixes", asn)
    if err:
        res["errors"].append(err)
    else:
        raw_prefixes = prefixes_data.get("prefixes", [])
        if isinstance(raw_prefixes, list):
            for p in raw_prefixes[:20]:
                if isinstance(p, dict) and p.get("prefix"):
                    res["announced_prefixes"].append(str(p["prefix"]))
                elif isinstance(p, str) and p.strip():
                    res["announced_prefixes"].append(p.strip())
    whois, err = _ripe_get("whois", asn)
    if err:
        res["errors"].append(err)
    else:
        records = whois.get("records", []) if isinstance(whois.get("records"), list) else []
        for rec in records[:5]:
            if isinstance(rec, list):
                res["whois"].append({str(e.get("key", "")): str(e.get("value", "") or "")[:300]
                                     for e in rec if isinstance(e, dict) and e.get("key")})
    return res


def query_ripe_network(ip: str) -> Dict[str, Any]:
    """IP -> prefix + ASNs -> ASN overview + announced prefixes + WHOIS."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for RIPEstat lookup"}
    res: Dict[str, Any] = {"source": "RIPEstat", "ip": ip, "prefix": "",
                           "asns": [], "asn_overview": {}, "announced_prefixes": [],
                           "whois": [], "errors": []}
    net, err = _ripe_get("network-info", ip)
    if err:
        res["errors"].append(err)
        return res
    prefixes = net.get("prefix", [])
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    if not isinstance(prefixes, list):
        prefixes = []
    res["prefix"] = str(prefixes[0] if prefixes else "")
    asns = net.get("asns", []) if isinstance(net.get("asns"), list) else []
    res["asns"] = [str(a) for a in asns if a]
    if res["asns"]:
        asn = res["asns"][0]
        asn_id = asn if str(asn).upper().startswith("AS") else f"AS{asn}"
        overview, err = _ripe_get("as-overview", asn_id)
        if err:
            res["errors"].append(err)
        else:
            res["asn_overview"] = {
                "asn": str(overview.get("resource", "") or asn_id),
                "announced": bool(overview.get("announced", False)),
                "holder": str(overview.get("holder", "") or ""),
                "block": overview.get("block", {}) if isinstance(overview.get("block"), dict) else {}}
        prefixes_data, err = _ripe_get("announced-prefixes", asn_id)
        if err:
            res["errors"].append(err)
        else:
            raw_prefixes = prefixes_data.get("prefixes", [])
            if isinstance(raw_prefixes, list):
                for p in raw_prefixes[:20]:
                    if isinstance(p, dict) and p.get("prefix"):
                        res["announced_prefixes"].append(str(p["prefix"]))
                    elif isinstance(p, str) and p.strip():
                        res["announced_prefixes"].append(p.strip())
    whois, err = _ripe_get("whois", ip)
    if err:
        res["errors"].append(err)
    else:
        records = whois.get("records", []) if isinstance(whois.get("records"), list) else []
        for rec in records[:5]:
            if isinstance(rec, list):
                res["whois"].append({str(e.get("key", "")): str(e.get("value", "") or "")[:300]
                                     for e in rec if isinstance(e, dict) and e.get("key")})
            elif isinstance(rec, dict):
                res["whois"].append({k: str(v)[:300] for k, v in rec.items()})
    return res


def _leakix_get(path: str, api_key: str):
    """LeakIX indexed-data GET. Returns (ok, payload-or-error)."""
    label = "LeakIX"
    headers = {"accept": "application/json"}
    if (api_key or "").strip():
        headers["api-key"] = api_key.strip()
    ok, payload = _b1_get_json(f"{PROVIDER_BASES['leakix']}{path}", label,
                               headers=headers, timeout=20)
    if not ok:
        return False, payload
    return True, payload


def _leakix_normalize_service(item: dict) -> dict:
    item = item if isinstance(item, dict) else {}
    software = item.get("software") or item.get("service") or {}
    if not isinstance(software, dict):
        software = {"name": str(software or "")}
    return {
        "host": str(item.get("host", "") or item.get("ip", "") or ""),
        "ip": str(item.get("ip", "") or ""),
        "domain": str(item.get("domain", "") or ""),
        "port": str(item.get("port", "") or ""),
        "protocol": str(item.get("protocol", "") or ""),
        "transport": str(item.get("transport", "") or ""),
        "service": str(software.get("name", "") or item.get("service_name", "") or ""),
        "product": str(software.get("product", "") or ""),
        "version": str(software.get("version", "") or ""),
        "observed_at": str(item.get("time", "") or item.get("observed_at", "") or item.get("date", "") or ""),
        "source": "LeakIX",
    }


def query_leakix_host(ip: str, api_key: str) -> Dict[str, Any]:
    """Existing indexed host observations. No hooks, no new collection."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for LeakIX lookup"}
    cache_key = f"lx:host:{ip}:{_key_tag(api_key)}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    ok, payload = _leakix_get(f"/host/{urllib.parse.quote(ip, safe='')}", api_key)
    if not ok:
        _b1_set(cache_key, payload, _BATCH1_CACHE_TTL["miss"])
        return payload
    services = []
    if isinstance(payload, dict):
        raw_services = payload.get("Services", payload.get("services", []))
        if isinstance(raw_services, list):
            services = [_leakix_normalize_service(s) for s in raw_services[:50]]
    out = {"source": "LeakIX", "ip": ip, "host": ip, "services": services,
           "observed_at": str((payload.get("time", "") if isinstance(payload, dict) else "") or "")}
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


def query_leakix_domain(domain: str, api_key: str) -> Dict[str, Any]:
    """Existing indexed domain observations."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"error": "Empty domain for LeakIX lookup"}
    cache_key = f"lx:domain:{domain}:{_key_tag(api_key)}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    ok, payload = _leakix_get(f"/domain/{urllib.parse.quote(domain, safe='')}", api_key)
    if not ok:
        _b1_set(cache_key, payload, _BATCH1_CACHE_TTL["miss"])
        return payload
    services = []
    if isinstance(payload, dict):
        for key in ("Services", "services", "hosts", "data"):
            raw = payload.get(key, [])
            if isinstance(raw, list) and raw:
                services = [_leakix_normalize_service(s) for s in raw[:50]]
                break
    out = {"source": "LeakIX", "domain": domain, "services": services}
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


def query_leakix_subdomains(domain: str, api_key: str) -> Dict[str, Any]:
    """Known subdomains from the index."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"error": "Empty domain for LeakIX subdomain lookup"}
    cache_key = f"lx:sub:{domain}:{_key_tag(api_key)}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    ok, payload = _leakix_get(f"/api/subdomains/{urllib.parse.quote(domain, safe='')}", api_key)
    if not ok:
        _b1_set(cache_key, payload, _BATCH1_CACHE_TTL["miss"])
        return payload
    subs = []
    raw = payload if isinstance(payload, list) else (payload.get("subdomains", []) if isinstance(payload, dict) else [])
    for s in (raw or [])[:200]:
        if isinstance(s, str) and s.strip():
            subs.append(s.strip().lower())
        elif isinstance(s, dict):
            for k in ("subdomain", "domain", "host"):
                if isinstance(s.get(k), str) and s[k].strip():
                    subs.append(s[k].strip().lower())
                    break
    seen, deduped = set(), []
    for s in subs:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    out = {"source": "LeakIX", "domain": domain, "subdomains": deduped}
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
    return out


# ---------------------------------------------------------------------------
# Batch 2 phishing providers: PhishStats and OpenPhish Community feed (local index).
# Strictly PASSIVE / READ-ONLY. No submissions, reports, scans, crawls,
# target fetches, downloads, or enrichment chains anywhere in this section.
# A zero result stays zero; provider failures are isolated per call.
# ---------------------------------------------------------------------------
PHISH_BASES = {
    "phishstats": "https://api.phishstats.info/api/phishing",
    "openphish": "https://openphish.com/feed.txt",
}
PHISH_UA = "MANTIS-Threat-Intel/1.0"


def _phishstats_headers(api_key: str = "") -> dict:
    headers = {"Accept": "application/json"}
    if (api_key or "").strip():
        headers["X-API-Key"] = api_key.strip()
    return headers


def _phishstats_fetch(params: dict, api_key: str = ""):
    """GET PhishStats with status mapping. Returns (records-list, error)."""
    label = "PhishStats"
    try:
        key_part = "key" if (api_key or "").strip() else "anon"
        cache_key = f"ps:{json.dumps(params, sort_keys=True)}:{key_part}"
    except Exception:
        cache_key = f"ps:{str(params)}"
    cached = _b1_get(cache_key)
    if cached is not None:
        return cached
    try:
        resp = requests.get(PHISH_BASES["phishstats"], params=params,
                            headers={**_phishstats_headers(api_key),
                                     "User-Agent": PHISH_UA}, timeout=20)
    except requests.exceptions.Timeout:
        out = ([], f"{label}: timed out")
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    except Exception as e:
        out = ([], f"{label}: request failed ({type(e).__name__})")
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
        return out
    if resp.status_code == 200:
        try:
            payload = resp.json()
        except ValueError:
            out = ([], f"{label}: malformed response")
            _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
            return out
        records = payload if isinstance(payload, list) else []
        out = (records, "")
        _b1_set(cache_key, out, _BATCH1_CACHE_TTL["hit"])
        return out
    if resp.status_code == 429:
        out = ([], f"{label}: rate limited (429)")
    else:
        out = ([], _b1_http_error(label, resp.status_code,
                                  resp.headers.get("Retry-After", "")).get("error", "failed"))
    _b1_set(cache_key, out, _BATCH1_CACHE_TTL["miss"])
    return out


def _phishstats_normalize(rec: dict) -> Dict[str, Any]:
    rec = rec if isinstance(rec, dict) else {}
    url = str(rec.get("url", "") or "")
    return {
        "source": "PhishStats",
        "provider_record_id": str(rec.get("id", "") or ""),
        "url": url,
        "normalized_url": url,
        "domain": str(rec.get("domain", "") or ""),
        "host": str(rec.get("host", "") or ""),
        "ip": str(rec.get("ip", "") or ""),
        "asn": str(rec.get("asn", "") or ""),
        "countrycode": str(rec.get("countrycode", "") or ""),
        "countryname": str(rec.get("countryname", "") or ""),
        "first_seen": str(rec.get("date", "") or ""),
        "last_seen": str(rec.get("date_update", "") or ""),
        "status": "",
        "classification": "phishing",
        "confidence": rec.get("score", ""),
        "title": str(rec.get("title", "") or ""),
        "tags": rec.get("tags", []) if isinstance(rec.get("tags"), list) else [],
        "provider_url": f"https://phishstats.info/phish/{rec.get('id', '')}" if rec.get("id") else "",
        "metadata": {k: rec.get(k) for k in
                     ("ssl_issuer", "ssl_subject", "ssl_fingerprint", "http_code",
                      "http_server", "technology", "n_times_seen_ip",
                      "n_times_seen_host", "n_times_seen_domain")
                     if rec.get(k) not in (None, "")},
    }


def query_phishstats_url(url: str, api_key: str = "") -> Dict[str, Any]:
    """Exact-URL lookup (verified against returned records, not assumed)."""
    url = (url or "").strip()
    if not url:
        return {"error": "Empty URL for PhishStats lookup"}
    records, err = _phishstats_fetch(
        {"_where": f"(url,eq,{url})", "_sort": "-date", "_p": 1, "_size": 20},
        api_key)
    if err:
        return {"error": err}
    exact, related = [], []
    for rec in records:
        norm = _phishstats_normalize(rec)
        if norm["url"].rstrip("/") == url.rstrip("/"):
            norm["match_type"] = "exact"
            exact.append(norm)
        else:
            norm["match_type"] = "related"
            related.append(norm)
    return {"source": "PhishStats", "query": url, "exact": exact,
            "related": related[:10],
            "note": "" if exact else "No exact PhishStats record (not safe)"}


def query_phishstats_domain(domain: str, api_key: str = "") -> Dict[str, Any]:
    """Host/domain relationships (host eq, domain fallback)."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"error": "Empty domain for PhishStats lookup"}
    records, err = _phishstats_fetch(
        {"_where": f"(host,eq,{domain})", "_sort": "-date", "_p": 1, "_size": 100},
        api_key)
    if err:
        return {"error": err}
    if not records:
        records, err = _phishstats_fetch(
            {"_where": f"(domain,eq,{domain})", "_sort": "-date", "_p": 1, "_size": 100},
            api_key)
        if err:
            return {"error": err}
    return {"source": "PhishStats", "query": domain,
            "records": [_phishstats_normalize(r) for r in records[:100]]}


def query_phishstats_ip(ip: str, api_key: str = "") -> Dict[str, Any]:
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for PhishStats lookup"}
    records, err = _phishstats_fetch(
        {"_where": f"(ip,eq,{ip})", "_sort": "-date", "_p": 1, "_size": 100},
        api_key)
    if err:
        return {"error": err}
    return {"source": "PhishStats", "query": ip,
            "records": [_phishstats_normalize(r) for r in records[:100]]}


def _query_openphish_url(url: str) -> Dict[str, Any]:
    """Local OpenPhish index lookup (deferred import, never raises)."""
    try:
        from phish_feeds import query_openphish_url as _f
        return _f(url)
    except Exception as e:
        return {"error": f"OpenPhish: local index failed ({type(e).__name__})"}


def _query_openphish_domain(domain: str) -> Dict[str, Any]:
    try:
        from phish_feeds import query_openphish_domain as _f
        return _f(domain)
    except Exception as e:
        return {"error": f"OpenPhish: local index failed ({type(e).__name__})"}


def _rep_has_source(source_id: str) -> bool:
    """True when the local feed engine holds any rows for a source."""
    try:
        from feed_intel import feed_status as _st
        for s in (_st().get("sources") or []):
            if s.get("id") == source_id and (s.get("record_count") or 0) > 0:
                return True
    except Exception:
        pass
    return False
def query_leakix_domain_full(domain: str, api_key: str) -> Dict[str, Any]:
    """Domain observations + known subdomains merged (one UI card)."""
    base = query_leakix_domain(domain, api_key)
    if "error" in base:
        return base
    subs = query_leakix_subdomains(domain, api_key)
    if "error" not in subs:
        base["subdomains"] = subs.get("subdomains", [])
    return base


# ---------------------------------------------------------------------------
# Batch 3 providers: BinaryEdge, NetworksDB, CIRCL PDNS/PSL, Common Crawl,
# SANS ISC, Rapid7 Sonar (metadata only).
# Strictly PASSIVE / READ-ONLY: indexed observations only. No scans, jobs,
# crawls, probes, downloads, submissions, validation, or target contact.
# ---------------------------------------------------------------------------
B3_BASES = {
    "commoncrawl": "https://index.commoncrawl.org/",
    "sans": "https://isc.sans.edu/api/",
}

B3_CACHE: Dict[str, Any] = {}
B3_TTL = {"hit": 21600, "miss": 1800, "transient": 60, "long": 86400, "short": 3600}


def _b3_get(key: str):
    entry = B3_CACHE.get(key)
    if not entry:
        return None
    try:
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            B3_CACHE.pop(key, None)
            return None
        return value
    except Exception:
        B3_CACHE.pop(key, None)
        return None


def _b3_set(key: str, value: Any, ttl: int):
    try:
        B3_CACHE[key] = (value, time.time(), ttl)
    except Exception:
        pass
















































def _cc_collection() -> tuple:
    """Newest crawl index id from collinfo (never hardcoded)."""
    cache_key = "cc:collinfo"
    cached = _b3_get(cache_key)
    if cached is not None:
        return cached
    ok, payload = _b1_get_json(f"{B3_BASES['commoncrawl']}collinfo.json",
                               "Common Crawl", timeout=20)
    if not ok:
        out = ("", payload.get("error", "failed") if isinstance(payload, dict) else "failed")
        _b3_set(cache_key, out, B3_TTL["transient"])
        return out
    ids = [c.get("id", "") for c in (payload if isinstance(payload, list) else [])
           if isinstance(c, dict) and c.get("id")]
    out = (sorted(ids)[-1] if ids else "", "")
    if not out[0]:
        out = ("", "Common Crawl: no crawl index available")
        _b3_set(cache_key, out, B3_TTL["miss"])
        return out
    _b3_set(cache_key, out, B3_TTL["long"])
    return out


def query_commoncrawl(url_or_domain: str, match_type: str = "exact") -> Dict[str, Any]:
    """Archived-index lookup only (never the investigated host).

    match_type: exact | domain (wildcard *.domain/*) | url-prefix.
    Index rows only; WARC bodies are never fetched.
    """
    q = (url_or_domain or "").strip()
    if not q:
        return {"error": "Empty query for Common Crawl lookup"}
    if match_type == "domain":
        host = q.lower().rstrip(".")
        if "://" in q:
            try:
                host = (urllib.parse.urlsplit(q).hostname or host).lower()
            except ValueError:
                pass
        cdx_q = f"*.{host}/*"
    elif match_type == "url-prefix":
        cdx_q = q if q.endswith("*") else q + "*"
    else:
        cdx_q = q
    cache_key = f"cc:{match_type}:{cdx_q}"
    cached = _b3_get(cache_key)
    if cached is not None:
        return cached
    index_id, err = _cc_collection()
    if err or not index_id:
        out = {"error": f"Common Crawl: {err or 'no index'}"}
        _b3_set(cache_key, out, B3_TTL["miss"])
        return out
    ok, payload = _b1_get_json(
        f"{B3_BASES['commoncrawl']}{index_id}-index",
        "Common Crawl",
        params={"url": cdx_q, "output": "json", "filter": "status:200",
                "collapse": "digest", "limit": 100}, timeout=30)
    if not ok:
        if isinstance(payload, dict) and payload.get("note"):
            out = {"source": "Common Crawl", "query": q, "observations": [],
                   "note": payload["note"]}
        else:
            out = payload if isinstance(payload, dict) and payload.get("error") else {"error": "Common Crawl: lookup failed"}
        _b3_set(cache_key, out, B3_TTL["transient"])
        return out
    rows = payload if isinstance(payload, list) else []
    obs = []
    for r in rows:
        if not isinstance(r, dict) or not r.get("url"):
            continue
        obs.append({
            "url": str(r.get("url", "")),
            "crawl": index_id,
            "timestamp": str(r.get("timestamp", "") or ""),
            "http_status": str(r.get("status", "") or ""),
            "mime_type": str(r.get("mime", "") or r.get("mime-type", "") or ""),
            "digest": str(r.get("digest", "") or ""),
            "source": "Common Crawl"})
        if len(obs) >= 100:
            break
    out = {"source": "Common Crawl", "query": q, "match_type": match_type,
           "observations": obs}
    _b3_set(cache_key, out, B3_TTL["long"])
    return out


def _sans_get(path: str):
    """SANS ISC public JSON API (no key). Returns (ok, payload)."""
    label = "SANS ISC"
    cache_key = f"sans:{path}"
    cached = _b3_get(cache_key)
    if cached is not None:
        return True, cached
    try:
        resp = requests.get(f"{B3_BASES['sans']}{path}", timeout=20,
                            headers={"User-Agent": PHISH_UA, "Accept": "application/json"})
    except requests.exceptions.Timeout:
        return False, {"error": f"{label}: timed out"}
    except Exception as e:
        return False, {"error": f"{label}: request failed ({type(e).__name__})"}
    if resp.status_code != 200:
        return False, _b3_http_error(label, resp.status_code)
    try:
        payload = resp.json()
    except ValueError:
        return False, {"error": f"{label}: malformed response"}
    _b3_set(cache_key, payload, B3_TTL["short"])
    return True, payload


def query_sans_ip(ip: str) -> Dict[str, Any]:
    """DShield IP context (network, ASN, observations as labeled)."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "Empty IP for SANS lookup"}
    ok, payload = _sans_get(f"ip/{urllib.parse.quote(ip, safe='')}?json")
    if not ok:
        return payload
    info = payload.get("ip", {}) if isinstance(payload, dict) else {}
    if not isinstance(info, dict):
        info = {}
    return {"source": "SANS ISC", "ip": ip,
            "network": str(info.get("network", "") or ""),
            "asn": str(info.get("as", "") or info.get("asn", "") or ""),
            "asname": str(info.get("asname", "") or ""),
            "attacks": info.get("attacks", ""),
            "first_seen": str(info.get("mindate", "") or ""),
            "last_seen": str(info.get("maxdate", "") or ""),
            "updated": str(info.get("updated", "") or ""),
            "comment": str(info.get("comment", "") or "")}


def query_sans_threatcategory() -> Dict[str, Any]:
    """Research/scanner IP list (complements GreyNoise; labels preserved)."""
    ok, payload = _sans_get("threatcategory/research?json")
    if not ok:
        return payload
    items = payload if isinstance(payload, list) else []
    out = []
    for e in items[:200]:
        if not isinstance(e, dict):
            continue
        out.append({"ip": str(e.get("ipv4", "") or ""),
                    "added": str(e.get("added", "") or ""),
                    "last_seen": str(e.get("lastseen", "") or ""),
                    "category": str(e.get("type", "") or "")})
    return {"source": "SANS ISC", "category": "research", "entries": out}


def query_sans_cloudips() -> Dict[str, Any]:
    """Cloud-provider ranges (infrastructure context only)."""
    ok, payload = _sans_get("cloudips?json")
    if not ok:
        return payload
    items = payload if isinstance(payload, list) else []
    out = []
    for e in items[:500]:
        if not isinstance(e, dict):
            continue
        out.append({"ip": str(e.get("ip", "") or ""),
                    "netmask": str(e.get("netmask", "") or ""),
                    "provider": str(e.get("provider", "") or "")})
    return {"source": "SANS ISC", "category": "cloud", "entries": out}


