"""
MANTIS Threat Assessment, Rarity-Weighted Attribution,
Node Role Hypothesis, and Defensive Playbook Engine.

Source inspiration: https://github.com/LeenAdeeb/IOC-Enricher
1. Phase 1: Node Role Hypothesis Engine (`c2-candidate`, `payload-host`, `shared-infrastructure`,
   `fast-flux-dns`, `shared-certificate`) + Free-text IOC extraction & defanging/refanging.
2. Phase 2: Explainable Rarity-Weighted APT Attribution Scorer built on MITRE ATT&CK (STIX 2.1)
   and MISP Galaxy (1,100+ groups) with commodity-tool caps, two-dimension guard rails,
   and CERT-EU style hedged analyst attribution statements.
3. Phase 3: Context-Aware Defensive Playbook & 3-Question Executive Triage Generator
   ("1. What is this IOC? 2. What is it connected to? 3. Who might be behind it?").
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import intel_query

logger = logging.getLogger("mantis.threat_assessment")

DATA_DIR = Path(__file__).resolve().parent / "data" / "misp"
BUNDLED_KB_PATH = DATA_DIR / "attack_misp_groups_kb.json"
MISP_ACTOR_PATH = DATA_DIR / "threat-actor.json"

# =============================================================================
# 1. FREE-TEXT IOC EXTRACTION, REFANGING & DEFANGING
# =============================================================================

_DEFANG_BRACKETS_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I)
_DEFANG_COLON_RE = re.compile(r"\[:\]|\(:\)", re.I)
_DEFANG_SLASH_RE = re.compile(r"\[/\]|\(/\)", re.I)
_HXXP_RE = re.compile(r"\bhxxps?(?=://)", re.I)

_URL_EXTRACT_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s\"'<>)\]]+", re.I)
_IP4_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_JARM_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{62}\b")
_TECHNIQUE_EXTRACT_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_DOMAIN_EXTRACT_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

COMMON_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "py", "sh", "elf",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt", "csv",
    "json", "xml", "yml", "yaml", "html", "htm", "css", "png", "jpg", "jpeg",
    "gif", "svg", "ico", "zip", "rar", "7z", "tar", "gz", "iso", "img", "lnk",
    "msi", "apk", "jar", "war", "php", "asp", "aspx", "jsp", "pdb", "log",
}


def refang_ioc(text: str) -> str:
    """Converts defanged indicators (e.g. hxxp://evil[.]com[:]/path) back to canonical form."""
    s = str(text or "").strip()
    s = re.sub(r"\[:\]\s*//|(?:\(:|\{:)\s*//", "://", s)
    s = re.sub(r"\[:\]\s*/|(?:\(:|\{:)\s*/", "/", s)
    s = _DEFANG_BRACKETS_RE.sub(".", s)
    s = _DEFANG_COLON_RE.sub(":", s)
    s = _DEFANG_SLASH_RE.sub("/", s)
    s = _HXXP_RE.sub(lambda m: "https" if m.group(0).lower().endswith("s") else "http", s)
    return s.strip()


def defang_ioc(value: str) -> str:
    """Safely defangs an IP, domain, or URL for analyst reports and tickets (`evil[.]com`, `hxxps://...`)."""
    s = str(value or "").strip()
    if not s:
        return ""
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", s):
        return s  # Hashes do not need defanging
    s = re.sub(r"(?i)^https://", "hxxps://", s)
    s = re.sub(r"(?i)^http://", "hxxp://", s)
    if "://" in s:
        scheme, rest = s.split("://", 1)
        host, sep, path = rest.partition("/")
        host = host.replace(".", "[.]")
        return f"{scheme}://{host}{sep}{path}"
    if "." in s:
        return s.replace(".", "[.]")
    return s


def extract_iocs_from_text(raw_text: str) -> Dict[str, Any]:
    """
    Extracts and refangs IPs, domains, URLs, file hashes, JARM fingerprints, and MITRE ATT&CK
    technique IDs from unstructured text (threat reports, emails, logs, or defanged snippets).
    """
    refanged = refang_ioc(raw_text or "")
    items: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    def _add(ioc_type: str, val: str) -> None:
        v = val.strip().rstrip(".,;:'\"!?)")
        if not v:
            return
        key = (ioc_type, v.lower())
        if key not in seen:
            seen.add(key)
            items.append({
                "type": ioc_type,
                "value": v,
                "defanged": defang_ioc(v),
            })

    # 1. URLs
    url_hosts: Set[str] = set()
    for m in _URL_EXTRACT_RE.findall(refanged):
        clean_u = m.rstrip(".,;:'\"!?)")
        if intel_query.is_url(clean_u):
            _add("url", intel_query.normalize_url(clean_u))

    # 2. Hashes & JARM
    for m in _SHA256_EXTRACT_RE.findall(refanged):
        _add("hash", m.lower())
    for m in _JARM_EXTRACT_RE.findall(refanged):
        _add("fingerprint", f"jarm:{m.lower()}")
    for m in _SHA1_EXTRACT_RE.findall(refanged):
        _add("hash", m.lower())
    for m in _MD5_EXTRACT_RE.findall(refanged):
        _add("hash", m.lower())

    # 3. IPv4
    for m in _IP4_EXTRACT_RE.findall(refanged):
        if intel_query.is_ip(m):
            _add("ip", intel_query.normalize_ip(m))

    # 4. Domains (excluding file names like payload.exe or URLs already extracted)
    text_without_urls = _URL_EXTRACT_RE.sub(" ", refanged)
    for m in _DOMAIN_EXTRACT_RE.findall(text_without_urls):
        cand = m.lower().rstrip(".")
        tld = cand.rsplit(".", 1)[-1]
        if tld in COMMON_FILE_EXTENSIONS or tld.isdigit():
            continue
        if intel_query.is_domain(cand):
            _add("domain", cand)

    # 5. ATT&CK Techniques
    techniques = sorted({t.upper() for t in _TECHNIQUE_EXTRACT_RE.findall(refanged)})

    primary = items[0] if items else None
    return {
        "primary": primary,
        "indicators": items,
        "count": len(items),
        "techniques": techniques,
    }


# =============================================================================
# 2. PHASE 1: NODE ROLE HYPOTHESIS ENGINE (What is this node *doing*?)
# =============================================================================

C2_KEYWORDS = {
    "c2", "c&c", "cnc", "botnet_cc", "botnet c2", "command and control", "beacon",
}

PAYLOAD_KEYWORDS = {
    "malware_download", "payload_delivery", "payload host", "payload distribution",
    "malware distribution", "malware hosting",
}

DYNAMIC_DNS_SUFFIXES = {
    "duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "ddns.net", "hopto.org",
    "zapto.org", "sytes.net", "myftp.org", "myftp.biz", "servebeer.com",
    "serveblog.net", "serveftp.com", "servegame.com", "servehttp.com",
    "servemp3.com", "servepics.com", "servequake.com", "afraid.org", "mooo.com",
    "chickenkiller.com", "crabdance.com", "ignorelist.com", "strangled.net",
    "twilightparadox.com", "us.to", "uk.to", "fr.to", "dynu.com", "dynu.net",
    "freeddns.org", "changeip.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "workers.dev", "pages.dev",
}

ROTATING_IPS_THRESHOLD = 5
SHARED_HOST_DOMAIN_THRESHOLD = 30
MULTI_TENANT_CERT_THRESHOLD = 25


def is_dynamic_dns_domain(domain: str) -> Optional[str]:
    dom = str(domain or "").strip().lower().rstrip(".")
    for suffix in DYNAMIC_DNS_SUFFIXES:
        if dom == suffix or dom.endswith(f".{suffix}"):
            return suffix
    return None


def _structured_source_facts(value: Dict[str, Any]) -> Dict[str, Any]:
    """Read explicit fields from provider results without inferring roles from free text."""
    facts: Dict[str, Any] = {"actors": set(), "malware": set(), "techniques": set(), "links": set()}
    relation_fields = {"resolutions", "last_dns_records", "dns_records", "passive_dns",
                       "related_ips", "related_domains", "associated_domains", "subdomains",
                       "relationships", "linked_iocs", "communicating_samples", "downloaded_samples"}
    skip_fields = {"comments", "description", "html", "body", "raw", "content", "text", "reports"}
    actor_fields = {"actor", "adversary", "threat_actor", "threat_actor_name"}
    malware_fields = {"malware_family", "malware_families", "malware_printable", "vx_family", "family"}
    technique_fields = {"techniques", "attack_ids", "mitre_attack", "mitre_attcks"}

    def add_terms(target: str, item: Any) -> None:
        for term in item if isinstance(item, list) else [item]:
            if isinstance(term, str) and 2 < len(term) < 90 and term.lower() not in {"unknown", "none", "no result"}:
                facts[target].add(term.strip())

    def walk(item: Any, depth: int = 0, in_relation: bool = False) -> None:
        if depth > 5 or sum(len(v) for v in facts.values()) >= 80:
            return
        if isinstance(item, list):
            for entry in item[:40]:
                walk(entry, depth + 1, in_relation)
        elif in_relation and isinstance(item, str):
            kind = ("ip" if intel_query.is_ip(item) else "domain" if intel_query.is_domain(item)
                    else "url" if intel_query.is_url(item) else "hash" if intel_query.is_hash(item) else "")
            if kind:
                facts["links"].add((kind, item))
        elif isinstance(item, dict):
            for key, child in item.items():
                name = str(key).lower()
                if name in skip_fields or name in {"error", "note"}:
                    continue
                if name in actor_fields:
                    add_terms("actors", child)
                elif name in malware_fields:
                    add_terms("malware", child)
                elif name in technique_fields:
                    add_terms("techniques", child)
                if in_relation and name in {"ip", "ip_address", "domain", "hostname", "host_name", "url", "sha256"} and isinstance(child, str):
                    kind = ("ip" if intel_query.is_ip(child) else "domain" if intel_query.is_domain(child)
                            else "url" if intel_query.is_url(child) else "hash" if intel_query.is_hash(child) else "")
                    if kind:
                        facts["links"].add((kind, child))
                if isinstance(child, (list, dict)):
                    walk(child, depth + 1, in_relation or name in relation_fields)

    walk(value)
    return {key: sorted(values)[:25] for key, values in facts.items()}


def _source_findings(source: str, value: Dict[str, Any], facts: Dict[str, Any]) -> List[str]:
    """Summarize explicit provider fields; a returned object alone is not a finding."""
    found: List[str] = []
    normalized = value.get("normalized")
    norm = normalized if isinstance(normalized, dict) else {}
    src = str(source or "").lower()

    if src == "virustotal":
        data = value.get("data")
        attrs = data.get("attributes", {}) if isinstance(data, dict) else value
        stats = attrs.get("last_analysis_stats") or {}
        count = attrs.get("malicious") or attrs.get("positives") or stats.get("malicious") or 0
        tot = attrs.get("total") or sum(v for v in stats.values() if isinstance(v, int)) or 0
        if isinstance(count, int) and count > 0:
            found.append(f"{count}/{tot} malicious engine detections" if tot and tot > count else f"{count} malicious engine detections")
        elif tot:
            found.append(f"0/{tot} detections (clean baseline)")
        pop_lbl = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if pop_lbl:
            found.append(f"Threat label: {pop_lbl}")
    elif src == "vt_relations":
        rel_counts = []
        for k, v in value.items():
            items = (v.get("data") if isinstance(v, dict) else v) if v else []
            if isinstance(items, list) and items:
                rel_counts.append(f"{len(items)} {str(k).replace('_', ' ')}")
        if rel_counts:
            found.append(f"VT graph relations: {', '.join(rel_counts[:3])}")
    elif src in {"otx", "alienvault"}:
        overview = norm.get("overview") or {}
        pulses = norm.get("pulses") or value.get("pulses") or (value.get("general") or {}).get("pulse_info", {}).get("pulses") or []
        count = overview.get("pulse_count") or (value.get("general") or {}).get("pulse_info", {}).get("count") or (len(pulses) if isinstance(pulses, list) else 0)
        if isinstance(count, int) and count > 0:
            found.append(f"Mentioned in {count} OTX pulse(s)")
        infra = norm.get("infrastructure") or {}
        pdns = infra.get("passive_dns") or (value.get("passive_dns") or {}).get("passive_dns") or []
        if isinstance(pdns, list) and pdns:
            found.append(f"{len(pdns)} passive DNS resolution(s)")
    elif src == "pulsedive":
        indicator = norm.get("indicator") or {}
        risk = indicator.get("risk") or value.get("risk") or value.get("risk_recommended")
        if (norm.get("found") or risk) and risk is not None:
            found.append(f"Indicator risk: {risk}")
        threats = norm.get("threats") or value.get("threats") or []
        if isinstance(threats, list) and threats:
            names = [str(th.get("name") or th.get("threat") or "") for th in threats if isinstance(th, dict) and (th.get("name") or th.get("threat"))]
            found.append(f"{len(threats)} linked threat(s)" + (f": {', '.join(names[:2])}" if names else ""))
        feeds = norm.get("feeds") or value.get("feeds") or []
        if isinstance(feeds, list) and feeds:
            found.append(f"Listed in {len(feeds)} Pulsedive feed(s)")
    elif src == "triage":
        samples = normalized if isinstance(normalized, list) else value.get("data") or []
        if isinstance(samples, list) and samples:
            scores = [s.get("score") or (s.get("sample") or {}).get("score") for s in samples if isinstance(s, dict)]
            max_score = max((sc for sc in scores if isinstance(sc, (int, float))), default=None)
            found.append(f"{len(samples)} matching sandbox sample(s)" + (f" (max score {max_score}/10)" if max_score is not None else ""))
    elif src == "validin":
        summary = norm.get("summary") or {}
        ips = summary.get("ips") or []
        doms = summary.get("domains") or []
        subs = summary.get("hostnames") or []
        certs = norm.get("certificates") or []
        dns_recs = norm.get("dns") or []
        if ips:
            found.append(f"{len(ips)} related IP(s) in passive history")
        if len(doms) > 1 or subs:
            found.append(f"{len(set(doms) | set(subs))} related domain/host record(s)")
        if certs:
            found.append(f"{len(certs)} certificate record(s)")
        elif dns_recs:
            found.append(f"{len(dns_recs)} passive DNS record(s)")
    elif src == "urlscan":
        scans = norm.get("scans") or value.get("results") or []
        count = norm.get("total") or value.get("total") or (len(scans) if isinstance(scans, list) else 0)
        if isinstance(count, int) and count > 0:
            found.append(f"{count} matching URL scan(s)")
        mal_scans = 0
        for sc in (scans if isinstance(scans, list) else [])[:25]:
            if isinstance(sc, dict):
                v = sc.get("verdicts") if isinstance(sc.get("verdicts"), dict) else {}
                ov = v.get("overall") if isinstance(v.get("overall"), dict) else v
                if ov.get("malicious") is True or sc.get("malicious") is True:
                    mal_scans += 1
        if mal_scans:
            found.append(f"{mal_scans} scan(s) flagged malicious")
    elif src == "dnsdumpster":
        hosts = norm.get("hosts") or {}
        count = sum(len(hosts.get(k) or []) for k in ("a", "cname", "mx", "ns"))
        summary = norm.get("summary") or {}
        uniq_ips = summary.get("unique_ips") or 0
        if count:
            found.append(f"{count} DNS host record(s)" + (f" across {uniq_ips} unique IP(s)" if uniq_ips else ""))
    elif src == "threatfox":
        records = value.get("data") or []
        if isinstance(records, list) and records:
            mws = sorted({str(r.get("malware_printable") or r.get("malware") or "") for r in records if isinstance(r, dict) and (r.get("malware_printable") or r.get("malware"))})
            ttypes = sorted({str(r.get("threat_type") or "") for r in records if isinstance(r, dict) and r.get("threat_type")})
            detail = ", ".join((mws + ttypes)[:3])
            found.append(f"{len(records)} ThreatFox record(s)" + (f" ({detail})" if detail else ""))
    elif src == "urlhaus":
        threat = value.get("threat")
        status_str = value.get("status")
        payloads = value.get("payloads") or []
        urls = value.get("urls") or []
        if threat:
            found.append(f"URLhaus threat: {threat}" + (f" ({status_str})" if status_str else ""))
        if isinstance(payloads, list) and payloads:
            found.append(f"{len(payloads)} associated payload sample(s)")
        if isinstance(urls, list) and urls:
            found.append(f"{len(urls)} associated distribution URL(s)")
    elif src == "malwarebazaar":
        rows = value.get("data") if isinstance(value.get("data"), list) else []
        if rows:
            sigs = sorted({str(r.get("signature") or "") for r in rows if isinstance(r, dict) and r.get("signature")})
            found.append(f"{len(rows)} MalwareBazaar sample(s)" + (f": {', '.join(sigs[:2])}" if sigs else ""))
    elif src == "yaraify":
        rows = value.get("data") if isinstance(value.get("data"), list) else []
        if rows:
            found.append(f"{len(rows)} YARAify rule/sample match(es)")
    elif src == "malshare":
        sample = norm.get("sample") or {}
        rows = value.get("data") or value.get("results") or []
        if sample.get("sha256") or sample.get("md5") or (isinstance(rows, list) and rows):
            ft = sample.get("file_type") or ""
            found.append(f"Indexed in MalShare repository" + (f" ({ft})" if ft else ""))
    elif src == "abuseipdb":
        d = value.get("data") if isinstance(value.get("data"), dict) else (norm or value)
        score = d.get("abuseConfidenceScore") if d.get("abuseConfidenceScore") is not None else d.get("score")
        reports = d.get("totalReports") if d.get("totalReports") is not None else d.get("total_reports")
        if score is not None:
            found.append(f"Abuse confidence score: {score}%" + (f" ({reports} report(s))" if reports is not None else ""))
    elif src == "greynoise":
        if value.get("classification"):
            found.append(f"IP classification: {str(value['classification'])[:70]}")
        if value.get("noise") is True:
            found.append("Observed internet background scanning noise")
        if value.get("riot") is True:
            found.append("RIOT: known common business service")
    elif src == "tip":
        lk = value.get("lookup") if isinstance(value.get("lookup"), dict) else {}
        zl = value.get("zonelookup") if isinstance(value.get("zonelookup"), dict) else {}
        gen = lk.get("DomainGeneralInfo") or lk.get("IpGeneralInfo") or lk.get("FileGeneralInfo") or {}
        zone = lk.get("Zone") or zl.get("Zone") or (gen.get("Zone") if isinstance(gen, dict) else None)
        if zone:
            found.append(f"Kaspersky Threat Zone: {zone}")
        if isinstance(gen, dict) and gen.get("HasApt"):
            found.append("Flagged as APT-linked in Kaspersky TIP")
        det = lk.get("DetectionsInfo") or lk.get("FilesDownloaded") or lk.get("FilesDownloadedFromIp") or []
        if isinstance(det, list) and det:
            found.append(f"{len(det)} associated malicious file detection(s)")
        pdns = lk.get("DomainDnsResolutions") or lk.get("IpDnsResolutions") or []
        if isinstance(pdns, list) and pdns:
            found.append(f"{len(pdns)} DNS resolution record(s)")
        if not found and lk:
            found.append("Indicator report returned; review its sections")
    elif src == "reputation_feeds":
        feeds = [name for name, record in value.items()
                 if name not in {"error", "note", "matches", "source", "indicator", "query"} and isinstance(record, dict) and record]
        if feeds:
            names = ", ".join(sorted(feeds)[:3]) + (f" +{len(feeds) - 3}" if len(feeds) > 3 else "")
            found.append(f"Listed in {len(feeds)} reputation feed(s): {names}")
    elif src == "c2_exposure":
        matches = value.get("matches") if isinstance(value.get("matches"), list) else []
        if matches:
            tools = sorted({str(m.get("name") or m.get("tool_id") or "") for m in matches if isinstance(m, dict) and (m.get("name") or m.get("tool_id"))})
            found.append(f"Matched {len(matches)} C2/attack-tool exposure signature(s): {', '.join(tools[:3])}")
    elif src == "openphish":
        m_type = str(value.get("match") or "").lower()
        rows = value.get("results") if isinstance(value.get("results"), list) else []
        if m_type == "exact":
            found.append("Exact URL listed on active OpenPhish feed")
        elif m_type == "domain" and rows:
            found.append(f"{len(rows)} phishing URL(s) on this domain in OpenPhish")
    elif src == "phishstats":
        exact = value.get("exact") if isinstance(value.get("exact"), list) else []
        recs = value.get("records") if isinstance(value.get("records"), list) else []
        rel = value.get("related") if isinstance(value.get("related"), list) else []
        if exact:
            found.append(f"{len(exact)} exact phishing URL record(s)")
        elif recs:
            found.append(f"{len(recs)} phishing record(s) in PhishStats")
        elif rel:
            found.append(f"{len(rel)} related phishing URL record(s)")
    elif src in {"hybrid-analysis", "hybrid_analysis"}:
        assess_blk = norm.get("assessment") if isinstance(norm.get("assessment"), dict) else {}
        verdict = value.get("verdict") or norm.get("verdict") or assess_blk.get("verdict")
        score = value.get("threat_score") if value.get("threat_score") is not None else (norm.get("threat_score") if norm.get("threat_score") is not None else assess_blk.get("threat_score"))
        reports = norm.get("reports") or value.get("reports") or []
        if verdict:
            found.append(f"Sandbox verdict: {str(verdict)[:40]}")
        if score is not None and score != 0:
            found.append(f"Threat score: {score}/100")
        if isinstance(reports, list) and reports:
            found.append(f"{len(reports)} sandbox report(s)")
    elif src == "silentpush":
        enrich = norm.get("enrichment") or norm.get("summary") or {}
        score = enrich.get("risk_score") or value.get("risk_score")
        listings = enrich.get("listings") if isinstance(enrich.get("listings"), list) else []
        f_padns = norm.get("padns_forward") or []
        r_padns = norm.get("padns_reverse") or []
        scans = norm.get("scan_data") or []
        if score is not None and score != 0:
            found.append(f"Risk score: {score}")
        if listings:
            found.append(f"Listed on {len(listings)} Silent Push feed(s)")
        if f_padns or r_padns:
            found.append(f"{len(f_padns) + len(r_padns)} passive DNS record(s)")
        if scans:
            found.append(f"{len(scans)} scan data observation(s)")
    elif src == "driftnet":
        ports = norm.get("ports") or norm.get("ip_ports") or []
        rels = norm.get("relationships") or []
        if isinstance(ports, list) and ports:
            found.append(f"{len(ports)} open port/service observation(s)")
        if isinstance(rels, list) and rels:
            found.append(f"{len(rels)} passive network/DNS correlation(s)")
    elif src == "shodan":
        ports = value.get("ports") or (norm.get("ports") if isinstance(norm, dict) else None) or []
        matches = norm.get("matches") if isinstance(norm, dict) else []
        dns_dom = norm.get("dns_domain") if isinstance(norm, dict) and isinstance(norm.get("dns_domain"), dict) else {}
        subs = dns_dom.get("subdomains") or []
        res_ips = dns_dom.get("resolved_ips") or []
        if isinstance(ports, list) and ports:
            found.append(f"{len(ports)} open port(s): {', '.join(str(p) for p in ports[:5])}")
        if isinstance(res_ips, list) and res_ips:
            found.append(f"Resolves to {len(res_ips)} IP(s) in Shodan DNS")
        if isinstance(subs, list) and subs:
            found.append(f"{len(subs)} subdomain(s) indexed")
        if isinstance(matches, list) and matches and not ports:
            found.append(f"{len(matches)} exposed service banner(s)")
    elif src == "censys":
        services = ((value.get("host") or {}).get("result") or {}).get("services") or norm.get("services") or []
        search_hits = ((value.get("search") or {}).get("normalized") or {}).get("hits") or norm.get("hits") or []
        if isinstance(services, list) and services:
            found.append(f"{len(services)} exposed service(s) on host")
        elif isinstance(search_hits, list) and search_hits:
            found.append(f"{len(search_hits)} Censys search match(es)")
    elif src == "fofa":
        recs = norm.get("records") or value.get("results") or []
        size = norm.get("total") or value.get("size") or (len(recs) if isinstance(recs, list) else 0)
        if isinstance(size, int) and size > 0:
            found.append(f"{size} exposed cyberspace asset record(s)")
    elif src == "zoomeye":
        recs = value.get("records") or value.get("hits") or []
        tot = value.get("total") or (len(recs) if isinstance(recs, list) else 0)
        if isinstance(tot, int) and tot > 0:
            found.append(f"{tot} exposed host/service record(s)")
    elif src == "netlas":
        recs = norm.get("records") or value.get("items") or []
        tot = norm.get("total") or (len(recs) if isinstance(recs, list) else 0)
        if isinstance(tot, int) and tot > 0:
            found.append(f"{tot} Netlas scan response record(s)")
    elif src == "leakix":
        services = value.get("services") if isinstance(value.get("services"), list) else []
        subs = value.get("subdomains") if isinstance(value.get("subdomains"), list) else []
        leaks = value.get("leaks") if isinstance(value.get("leaks"), list) else []
        if leaks:
            found.append(f"{len(leaks)} exposed data/credential leak event(s)")
        if services:
            found.append(f"{len(services)} indexed service observation(s)")
        if subs:
            found.append(f"{len(subs)} subdomain(s) discovered")
    elif src == "crtsh":
        certs = value.get("certificates") if isinstance(value.get("certificates"), list) else []
        if certs:
            sans = {s for c in certs if isinstance(c, dict) for s in (c.get("san") or []) if isinstance(s, str)}
            found.append(f"{len(certs)} TLS certificate(s)" + (f" covering {len(sans)} SAN hostname(s)" if sans else ""))
    elif src == "etugen":
        details = value.get("host_details") if isinstance(value.get("host_details"), dict) else {}
        whois = value.get("whois") if isinstance(value.get("whois"), dict) else {}
        search_items = intel_query._etugen_items(value.get("search")) if hasattr(intel_query, "_etugen_items") else []
        if details:
            found.append(f"{len(details)} Etugen threat host profile(s)")
        if search_items:
            found.append(f"{len(search_items)} Etugen search match(es)")
        if whois and not whois.get("error"):
            found.append("Domain WHOIS registration record retrieved")
    elif src == "threatminer":
        pdns = value.get("pdns") if isinstance(value.get("pdns"), list) else []
        subs = value.get("subdomains") if isinstance(value.get("subdomains"), list) else []
        uris = value.get("uris") if isinstance(value.get("uris"), list) else []
        av = value.get("av_detections") if isinstance(value.get("av_detections"), list) else []
        hosts = value.get("related_hosts") if isinstance(value.get("related_hosts"), list) else []
        reports = value.get("reports") if isinstance(value.get("reports"), list) else []
        if av:
            found.append(f"{len(av)} AV detection(s) in ThreatMiner")
        if pdns:
            found.append(f"{len(pdns)} passive DNS record(s)")
        if subs:
            found.append(f"{len(subs)} subdomain(s)")
        if uris:
            found.append(f"{len(uris)} associated URI(s)")
        if hosts:
            found.append(f"{len(hosts)} related host(s)")
        if reports:
            found.append(f"Referenced in {len(reports)} threat report(s)")
    elif src == "threatbook":
        judgments = ((norm.get("summary") or {}).get("judgments") if isinstance(norm.get("summary"), dict) else None) or []
        ports = (value.get("data") or {}).get("ports") if isinstance(value.get("data"), dict) else []
        samples = (value.get("data") or {}).get("samples") if isinstance(value.get("data"), dict) else []
        if isinstance(judgments, list) and judgments:
            found.append(f"ThreatBook judgments: {', '.join(str(j) for j in judgments[:4])}")
        if isinstance(samples, list) and samples:
            found.append(f"{len(samples)} associated malware sample(s)")
        if isinstance(ports, list) and ports:
            found.append(f"{len(ports)} open port(s)")
    elif src == "ripe":
        pfx = value.get("prefix")
        asns = value.get("asns") if isinstance(value.get("asns"), list) else []
        holder = (value.get("asn_overview") or {}).get("holder") if isinstance(value.get("asn_overview"), dict) else ""
        if pfx or asns:
            found.append(f"BGP prefix {pfx or 'N/A'}" + (f" (AS{asns[0]}" + (f" · {holder}" if holder else "") + ")" if asns else ""))
    elif src == "sans":
        attacks = value.get("attacks")
        asn = value.get("asn")
        if isinstance(attacks, int) and attacks > 0:
            found.append(f"{attacks} DShield honeypot attack packet(s) reported")
        elif asn or value.get("network"):
            found.append(f"Network {value.get('network') or ''} (AS{asn or 'N/A'}) — 0 honeypot attacks")
    elif src == "commoncrawl":
        obs = value.get("observations") if isinstance(value.get("observations"), list) else []
        if obs:
            found.append(f"{len(obs)} web crawl capture(s) in Common Crawl index")
    elif src == "archive":
        snaps = value.get("snapshots") if isinstance(value.get("snapshots"), list) else []
        h_urls = value.get("historical_urls") if isinstance(value.get("historical_urls"), list) else []
        first_disp = (value.get("summary") or {}).get("first_archived_display") if isinstance(value.get("summary"), dict) else ""
        if snaps or h_urls:
            found.append(f"{len(snaps)} Wayback snapshot(s), {len(h_urls)} historical URL(s)" + (f" (since {first_disp[:10]})" if first_disp else ""))
    elif src == "tweetfeed":
        recs = value.get("records") if isinstance(value.get("records"), list) else []
        camps = value.get("campaigns") if isinstance(value.get("campaigns"), list) else []
        if recs:
            tags_tf = sorted({str(tg) for r in recs if isinstance(r, dict) for tg in (r.get("tags") or []) if tg})
            found.append(f"Shared in {len(recs)} TweetFeed IOC report(s)" + (f" ({', '.join(tags_tf[:3])})" if tags_tf else ""))
        if camps:
            found.append(f"Linked to {len(camps)} TweetFeed campaign(s)")
    elif src == "orkl":
        reps = value.get("reports") or value.get("data") or []
        if isinstance(reps, list) and reps:
            titles = [str(r.get("title") or r.get("name") or "")[:55] for r in reps if isinstance(r, dict) and (r.get("title") or r.get("name"))]
            found.append(f"Referenced in {len(reps)} ORKL CTI report(s)" + (f": {titles[0]}" if titles else ""))
    elif src == "cb":
        ioc_obj = norm.get("ioc") if isinstance(norm.get("ioc"), dict) else {}
        threats = norm.get("threats") if isinstance(norm.get("threats"), list) else []
        s_res = norm.get("search_results") if isinstance(norm.get("search_results"), list) else []
        if ioc_obj.get("value"):
            sev = ioc_obj.get("severity") or "indexed"
            found.append(f"CyberBriefing IOC match (severity: {sev})")
        if threats:
            found.append(f"{len(threats)} threat actor profile(s)")
        elif s_res:
            found.append(f"{len(s_res)} intelligence entity match(es)")
    elif src in {"cti_mentions", "cti_articles"}:
        arts = value.get("articles") or value.get("results") or []
        tot = value.get("total") or (len(arts) if isinstance(arts, list) else 0)
        if isinstance(tot, int) and tot > 0:
            titles = [str(a.get("title") or "")[:55] for a in (arts if isinstance(arts, list) else []) if isinstance(a, dict) and a.get("title")]
            found.append(f"Mentioned in {tot} CTI article(s)" + (f": {titles[0]}" if titles else ""))
    elif src == "rss_intel":
        rows = value.get("data") if isinstance(value.get("data"), list) else []
        if rows:
            found.append(f"Matched in {len(rows)} local RSS intelligence article(s)")
    elif src == "malware_news":
        rows = value.get("data") if isinstance(value.get("data"), list) else []
        if rows:
            found.append(f"Mentioned in {len(rows)} Malware.News publication(s)")
    elif src == "x_monitor":
        posts = value.get("posts") if isinstance(value.get("posts"), list) else []
        if posts:
            found.append(f"Referenced in {len(posts)} X/Twitter threat monitor post(s)")
    elif src == "twitter":
        tweets = value.get("tweets") or value.get("data") or []
        if isinstance(tweets, list) and tweets:
            found.append(f"Referenced in {len(tweets)} Twitter/X post(s)")
    elif src in {"github", "github_repos"}:
        items = value.get("items") or value.get("results") or value.get("matches") or []
        tot = value.get("total_count") or value.get("total") or (len(items) if isinstance(items, list) else 0)
        if isinstance(tot, int) and tot > 0:
            found.append(f"Referenced in {tot} GitHub repository result(s)")
    elif src == "rwlive":
        victims = value.get("victims") if isinstance(value.get("victims"), list) else []
        groups = value.get("groups") if isinstance(value.get("groups"), list) else []
        if victims:
            g_names = sorted({str(v.get("group") or "") for v in victims if isinstance(v, dict) and v.get("group")})
            found.append(f"{len(victims)} Ransomware.live victim record(s)" + (f" ({', '.join(g_names[:2])})" if g_names else ""))
        if groups:
            found.append(f"{len(groups)} ransomware group profile(s)")
    elif src == "misp":
        summary = value.get("summary") if isinstance(value.get("summary"), dict) else {}
        ev_cnt = summary.get("event_matches") or len(value.get("events") or [])
        attr_cnt = summary.get("attribute_matches") or len(value.get("attributes") or [])
        if ev_cnt or attr_cnt:
            found.append(f"{attr_cnt} MISP attribute(s) across {ev_cnt} event(s)")
    elif src == "yara_forge":
        matches = value.get("matches") or value.get("rules") or []
        if isinstance(matches, list) and matches:
            found.append(f"Matched {len(matches)} local YARA rule(s)")

    if facts.get("links"):
        found.append(f"{len(facts['links'])} structured infrastructure relation(s)")
    if facts.get("actors"):
        found.append(f"{len(facts['actors'])} reported actor name(s)")
    if facts.get("malware"):
        found.append(f"{len(facts['malware'])} malware family label(s)")
    if facts.get("techniques"):
        found.append(f"{len(facts['techniques'])} ATT&CK technique reference(s)")
    if not found:
        found.extend(_generic_source_findings(value, norm))
    return found[:4]


_GENERIC_SKIP_FIELDS = {"source", "query", "indicator", "query_type", "query_kind", "status", "query_status",
                        "note", "error", "raw", "html", "body", "content", "text", "headers", "links", "tags",
                        "sources", "providers", "errors", "warnings", "fields", "columns", "params"}
_GENERIC_COUNT_FIELDS = ("total", "count", "total_count", "results_count", "match_count", "hits")


def _generic_source_findings(value: Dict[str, Any], norm: Dict[str, Any]) -> List[str]:
    """Fallback for providers without a dedicated parser: report what was returned, labelled by field."""
    containers = [c for c in (norm, value, value.get("data"), value.get("result"), value.get("results"))
                  if isinstance(c, dict) and c]
    for container in containers:
        for field in _GENERIC_COUNT_FIELDS:
            count = container.get(field)
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                return [f"{count} matching record(s) reported"]
    found: List[str] = []
    seen = set()
    for container in containers:
        for field, entries in container.items():
            name = str(field).lower()
            if name in _GENERIC_SKIP_FIELDS or name in seen or not isinstance(entries, list) or not entries:
                continue
            seen.add(name)
            found.append(f"{len(entries)} {name.replace('_', ' ')} returned")
            if len(found) >= 2:
                return found
    if not found:
        top_list = value.get("data") if isinstance(value.get("data"), list) else None
        if top_list:
            found.append(f"{len(top_list)} record(s) returned")
    return found


def assess_asset_roles(
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Evaluates every asset in the investigation graph and assigns explainable
    functional role hypotheses (`c2-candidate`, `payload-host`, `shared-infrastructure`,
    `fast-flux-dns`, `shared-certificate`).
    Confidence is capped at Moderate because passive pivoting does not inspect live packet payloads.
    """
    asset_map = {a["asset_id"]: a for a in assets}
    out_edges: Dict[str, List[Dict[str, Any]]] = {}
    in_edges: Dict[str, List[Dict[str, Any]]] = {}

    for r in relationships:
        src = r.get("source") or r.get("source_asset_id") or ""
        tgt = r.get("target") or r.get("target_asset_id") or ""
        out_edges.setdefault(src, []).append(r)
        in_edges.setdefault(tgt, []).append(r)

    roles_by_asset: Dict[str, List[Dict[str, Any]]] = {}

    for a in assets:
        aid = a["asset_id"]
        atype = a.get("asset_type", "")
        val = str(a.get("value", "")).lower()
        mal = a.get("maliciousness_context") or {}
        meta = a.get("metadata") or {}
        shared_flags = a.get("shared_infra_flags") or []
        a_out = out_edges.get(aid, [])
        a_in = in_edges.get(aid, [])
        all_edges = a_out + a_in

        node_roles: List[Dict[str, Any]] = []

        # 1. Shared Infrastructure / CDN / Cloud Multi-Tenant
        shared_ev: List[str] = []
        if shared_flags:
            shared_ev.append(f"Matched shared/CDN markers: {', '.join(shared_flags[:3])}")
        if mal.get("greynoise_riot"):
            shared_ev.append("Verified benign common business service in GreyNoise RIOT")
        cohosted_domains = [
            e for e in all_edges
            if e.get("relationship_type") in {"resolves_to", "cohosted_on", "hosts"}
        ]
        if atype == "ip" and len(cohosted_domains) >= SHARED_HOST_DOMAIN_THRESHOLD:
            shared_ev.append(f"IP serves {len(cohosted_domains)} domains in graph (shared hosting)")
        if shared_ev:
            node_roles.append({
                "role": "shared-infrastructure",
                "label": "Shared Infra / CDN",
                "badge_class": "shared",
                "confidence": "Moderate",
                "evidence": shared_ev,
            })

        # 2. C2 Candidate vs Payload Host
        c2_ev: List[str] = []
        pay_ev: List[str] = []

        # Match explicit classifications and tags, never arbitrary metadata or provider names.
        role_terms = [str(value).lower() for value in (mal.get("role_tags") or [])]
        if mal.get("threatfox_type"):
            role_terms.append(str(mal["threatfox_type"]).lower())
        matched_c2_kw = sorted({
            kw for term in role_terms for kw in C2_KEYWORDS
            if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", term)
        })
        if matched_c2_kw:
            c2_ev.append(f"Explicit C2 classification: {', '.join(matched_c2_kw[:4])}")

        matched_pay_kw = sorted({
            kw for term in role_terms for kw in PAYLOAD_KEYWORDS
            if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", term)
        })
        if matched_pay_kw:
            pay_ev.append(f"Explicit payload classification: {', '.join(matched_pay_kw[:4])}")

        if mal.get("urlhaus_confirmed") and atype == "url":
            pay_ev.append("Exact URL has a URLhaus malware distribution record")

        if mal.get("c2_exposure_tools") and atype in {"ip", "domain", "url"}:
            c2_ev.append(f"C2/attack-tool exposure index match: {', '.join(mal['c2_exposure_tools'][:3])}")
        if mal.get("triage_c2_samples") and atype in {"ip", "domain", "url"}:
            c2_ev.append(f"Extracted from Triage sandbox C2 config ({mal['triage_c2_samples']} sample(s))")

        # Check communicating vs downloaded malware hash edges
        comm_samples = [
            e for e in all_edges
            if e.get("relationship_type") in {"communicates_with", "contacted_by_malware", "c2_of"}
        ]
        if comm_samples and atype in {"ip", "domain", "url"}:
            c2_ev.append(f"{len(comm_samples)} malware sample(s) communicate with this node")

        dl_samples = [
            e for e in all_edges
            if e.get("relationship_type") in {"distributes_malware", "downloaded_from", "hosts_payload"}
        ]
        if dl_samples and atype in {"ip", "domain", "url"}:
            pay_ev.append(f"Distributes or hosts {len(dl_samples)} malware sample(s)")

        if mal.get("phishing_sources") and atype in {"domain", "url", "ip"}:
            node_roles.append({
                "role": "phishing-host",
                "label": "Phishing / Lure Host",
                "badge_class": "payload",
                "confidence": "Moderate" if len(mal["phishing_sources"]) >= 2 else "Low",
                "evidence": [f"Listed in phishing intelligence: {', '.join(mal['phishing_sources'][:3])}"],
            })

        if c2_ev:
            node_roles.append({
                "role": "c2-candidate",
                "label": "C2 Candidate",
                "badge_class": "c2",
                "confidence": "Moderate" if len(c2_ev) >= 2 else "Low",
                "evidence": c2_ev,
            })

        if pay_ev:
            node_roles.append({
                "role": "payload-host",
                "label": "Payload Host",
                "badge_class": "payload",
                "confidence": "Moderate" if len(pay_ev) >= 2 else "Low",
                "evidence": pay_ev,
            })

        # 3. Domain DNS Behaviour (Dynamic DNS / Fast-Flux / Rotating IPs)
        if atype == "domain":
            dns_ev: List[str] = []
            ddns_provider = is_dynamic_dns_domain(val)
            if ddns_provider:
                dns_ev.append(f"Hosted under Dynamic DNS / ephemeral provider ({ddns_provider})")
            resolved_ips = {
                (e.get("target") if (e.get("source") == aid) else e.get("source"))
                for e in all_edges
                if e.get("relationship_type") in {"resolves_to", "hosts", "a_record"}
                and ("ip:" in str(e.get("target", "")) or "ip:" in str(e.get("source", "")))
            }
            if len(resolved_ips) >= ROTATING_IPS_THRESHOLD:
                dns_ev.append(f"Resolves across {len(resolved_ips)} distinct IPs (possible IP rotation or fast-flux)")
            if dns_ev:
                node_roles.append({
                    "role": "fast-flux-dns",
                    "label": "Dynamic / Rotating DNS",
                    "badge_class": "dns",
                    "confidence": "Moderate" if len(dns_ev) >= 2 else "Low",
                    "evidence": dns_ev,
                })

        # 4. Shared Certificate Pivot Node
        if atype == "certificate" or (atype == "fingerprint" and "jarm" in aid):
            covered = len(all_edges)
            if covered >= 2:
                is_noisy = covered >= MULTI_TENANT_CERT_THRESHOLD
                node_roles.append({
                    "role": "shared-certificate",
                    "label": "Multi-Tenant Cert" if is_noisy else "Shared Certificate",
                    "badge_class": "shared" if is_noisy else "cert",
                    "confidence": "Moderate" if not is_noisy else "Low",
                    "evidence": [f"Links {covered} infrastructure assets in the pivot graph"],
                })

        roles_by_asset[aid] = node_roles
        a["roles"] = node_roles

    return roles_by_asset


# =============================================================================
# 3. PHASE 2: RARITY-WEIGHTED APT ATTRIBUTION ENGINE WITH GUARD RAILS
# =============================================================================

W_MENTION = 30.0
W_SOFTWARE = 14.0
W_TECHNIQUE = 2.0
TECHNIQUE_CAP = 16.0
SATURATION = 55.0
RARE_THRESHOLD = 0.50       # Rarity score >= 0.50 counts as a distinctive/rare tool
CAP_ONE_RARE = 49           # Single rare family with no direct mention -> capped at Moderate (49%)
CAP_COMMODITY = 20          # Only commodity tools (Cobalt Strike, Mimikatz) / TTPs -> capped at Low (20%)
CAP_SINGLE_DIMENSION = 54   # High confidence (>= 55%) requires at least 2 independent dimensions
MIN_PATH_SCALE = 0.35       # Weakly connected nodes (<35% confidence) cannot lift guard rails

INDEPENDENT_DIMENSIONS = ("infrastructure", "malware", "ttp", "reported")
ALL_DIMENSIONS = ("reported", "infrastructure", "malware", "ttp", "victimology", "operational")
NOT_ASSESSED_DIMENSIONS = ("victimology", "operational")

DIMENSION_PHRASES = {
    "reported": "third-party threat reporting on seed",
    "infrastructure": "linked infrastructure attribution",
    "malware": "rarity-weighted malware/tool overlap",
    "ttp": "MITRE ATT&CK technique overlap",
}

ALIAS_STOPLIST = {
    "snake", "carbon", "dragon", "panda", "bear", "kitten", "tiger", "spider",
    "team", "group", "apt", "unknown", "tonto", "equation", "lead", "gold",
    "wolf", "hawk", "viper", "cobra", "lynx", "jackal", "hydra", "ares",
    "zeus", "atlas", "omega", "alpha", "delta", "nexus", "ghost", "shadow",
    "storm", "temp", "unc", "dev", "uta", "cl", "ta", "fin", "wizard",
}

# Ubiquitous commodity / red-team / dual-use tools that must never trigger high-confidence attribution alone
COMMODITY_SOFTWARE_NORMS = {
    "cobaltstrike", "mimikatz", "metasploit", "powershell", "empire", "ps1",
    "psexec", "impacket", "bloodhound", "sharphound", "rubeus", "certify",
    "adfind", "nltest", "net", "whoami", "cmd", "rundll32", "regsvr32",
    "certutil", "bitsadmin", "mshta", "wmic", "schtasks", "at", "sc",
    "ngrok", "plink", "putty", "winscp", "7zip", "winrar", "curl", "wget",
    "procdump", "processhacker", "anydesk", "teamviewer", "screenconnect",
    "atera", "splashtop", "rustdesk", "chisel", "frp", "ligolo", "sliver",
    "mythic", "havoc", "bruteratel", "covenant", "poshc2", "asyncrat",
    "njrat", "quasarrat", "remcos", "nanocore", "netwire", "darkcomet",
    "redline", "raccoon", "vidar", "lumma", "agenttesla", "formbook",
    "lokibot", "XWorm", "xworm", "qakbot", "emotet", "icedid", "trickbot",
}


def _norm_token(s: str) -> str:
    s = str(s or "").lower().strip()
    s = re.sub(r"^(win|elf|osx|apk|ps1|js|php|py|vbs|win32|win64)[._\-]", "", s)
    return re.sub(r"[^a-z0-9]", "", s)


@dataclass
class AttributionEvidence:
    kind: str               # mention | software | technique
    detail: str
    base_weight: float
    dimension: str          # reported | infrastructure | malware | ttp
    rarity: float = 1.0
    scale: float = 1.0      # strongest node confidence scale (0.0..1.0)
    iocs: List[str] = field(default_factory=list)
    matched_term: str = ""

    @property
    def weight(self) -> float:
        return self.base_weight * self.scale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "dimension": self.dimension,
            "detail": self.detail,
            "matched_term": self.matched_term,
            "rarity": round(self.rarity, 2),
            "scale": round(self.scale, 2),
            "weight": round(self.weight, 1),
            "iocs": self.iocs[:8],
        }


@dataclass
class AttributionCandidate:
    group: Dict[str, Any]
    raw_score: float = 0.0
    confidence: int = 0
    evidence: List[AttributionEvidence] = field(default_factory=list)
    capped_reason: Optional[str] = None

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 55:
            return "High"
        if self.confidence >= 25:
            return "Moderate"
        return "Low"

    def dimensions(self) -> Dict[str, Optional[int]]:
        out: Dict[str, Optional[int]] = {
            d: (None if d in NOT_ASSESSED_DIMENSIONS else 0)
            for d in ALL_DIMENSIONS
        }
        for e in self.evidence:
            if out.get(e.dimension) is not None:
                out[e.dimension] = int(out[e.dimension] or 0) + 1
        return out

    def active_dimension_count(self) -> int:
        dims = self.dimensions()
        return sum(1 for d in INDEPENDENT_DIMENSIONS if (dims.get(d) or 0) > 0)

    def statement(self, alternatives: Optional[List["AttributionCandidate"]] = None) -> str:
        """Generates a CERT-EU style hedged analyst attribution assessment statement."""
        dims = [
            DIMENSION_PHRASES[d]
            for d, count in self.dimensions().items()
            if count and d in DIMENSION_PHRASES
        ]
        dim_text = (
            dims[0]
            if len(dims) == 1
            else (", ".join(dims[:-1]) + " and " + dims[-1] if dims else "indicators")
        )
        top_ev = sorted(self.evidence, key=lambda e: -e.weight)[:3]
        parts = [
            f"{self.confidence_label}-confidence assessment ({self.confidence}%): "
            f"the observed {dim_text} exhibit similarities to activity previously associated with "
            f"{self.group['name']}."
        ]
        if top_ev:
            parts.append("Supported by: " + "; ".join(e.detail for e in top_ev) + ".")

        lims: List[str] = ["victimology and operational tempo were not assessed"]
        if self.capped_reason:
            lims.insert(0, self.capped_reason)
        if any(e.kind == "software" and e.rarity < RARE_THRESHOLD for e in self.evidence):
            lims.append("part of the tooling overlap involves commodity software shared across multiple threat groups")
        parts.append("Limitations: " + "; ".join(lims) + ".")

        if alternatives:
            alt_str = ", ".join(
                f"{a.group['name']} ({a.confidence_label}, {a.confidence}%)"
                for a in alternatives[:3]
            )
            parts.append(f"Alternative hypotheses: {alt_str}.")
        parts.append("Treat this assessment as an analytical hypothesis rather than definitive attribution.")
        return " ".join(parts)

    def to_dict(self, alternatives: Optional[List["AttributionCandidate"]] = None) -> Dict[str, Any]:
        g = self.group
        return {
            "group_id": g.get("id", ""),
            "name": g.get("name", ""),
            "aliases": (g.get("aliases") or [])[:10],
            "country": g.get("country") or "",
            "description": (g.get("description") or "")[:360],
            "url": g.get("url") or "",
            "source": g.get("source") or "attack+misp",
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "raw_score": round(self.raw_score, 1),
            "capped_reason": self.capped_reason,
            "dimensions": self.dimensions(),
            "active_dimensions": self.active_dimension_count(),
            "statement": self.statement(alternatives),
            "evidence": [e.to_dict() for e in sorted(self.evidence, key=lambda e: -e.weight)],
        }


class RarityWeightedAttributor:
    """
    Singleton-cached MITRE ATT&CK + MISP Galaxy Rarity-Weighted Attribution Scorer.
    """

    def __init__(self, kb: Dict[str, Any]) -> None:
        self.meta = kb.get("meta", {})
        self.groups: List[Dict[str, Any]] = kb.get("groups", [])
        # Denominator N = number of groups with a software profile in ATT&CK
        self._n = max(sum(1 for g in self.groups if g.get("software")), 2)
        self._sw_index: Dict[str, List[int]] = {}
        self._sw_canonical_name: Dict[str, str] = {}
        self._tech_df: Dict[str, int] = {}
        self._patterns: List[Tuple[re.Pattern, int, str]] = []

        for idx, g in enumerate(self.groups):
            seen_sw: Set[str] = set()
            for sw in g.get("software") or []:
                sw_name = sw.get("name", "")
                for nm in [sw_name, *(sw.get("aliases") or [])]:
                    k = _norm_token(nm)
                    if k and len(k) >= 3 and k not in seen_sw:
                        seen_sw.add(k)
                        self._sw_index.setdefault(k, []).append(idx)
                        self._sw_canonical_name.setdefault(k, sw_name)

            for t in g.get("techniques") or []:
                self._tech_df[t] = self._tech_df.get(t, 0) + 1

            for nm in [g.get("name", ""), *(g.get("aliases") or [])]:
                clean_nm = str(nm or "").strip()
                if len(clean_nm) >= 4 and clean_nm.lower() not in ALIAS_STOPLIST:
                    parts = [x for x in re.split(r"[\s\-_./]+", clean_nm.lower()) if x]
                    if not parts:
                        continue
                    flex = r"[\s\-_.]?".join(re.escape(x) for x in parts)
                    pat = re.compile(rf"(?<![a-z0-9]){flex}(?![a-z0-9])", re.I)
                    self._patterns.append((pat, idx, clean_nm))

    def _idf_rarity(self, df: int) -> float:
        df = max(df, 1)
        return math.log(1.0 + self._n / df) / math.log(1.0 + self._n)

    def software_rarity(self, norm_key: str) -> Tuple[float, int]:
        group_list = self._sw_index.get(norm_key, [])
        df = max(len(group_list), 1)
        rar = self._idf_rarity(df)
        if norm_key in COMMODITY_SOFTWARE_NORMS:
            rar = min(rar, 0.28)  # Enforce commodity ceiling
        return rar, df

    def evaluate(
        self,
        items: List[Dict[str, Any]],
        top_n: int = 5,
    ) -> Dict[str, Any]:
        """
        Evaluates a list of enriched IOC items.
        Each item in `items` has:
          - `ioc`: str (e.g. IP, domain, hash)
          - `is_seed`: bool
          - `scale`: float (0.0..1.0, relationship confidence / 100)
          - `actors`: List[str] (explicit actor/adversary fields)
          - `tags`: List[str] (tags, pulse titles, WHOIS orgs, cert subjects, etc.)
          - `malware`: List[str] (malware / tool families)
          - `techniques`: List[str] (MITRE ATT&CK IDs like T1566.001)
        """
        cands: Dict[int, AttributionCandidate] = {}
        mention_seen: Dict[Tuple[int, str, bool], AttributionEvidence] = {}
        sw_seen: Dict[Tuple[int, str], AttributionEvidence] = {}
        tech_hits: Dict[int, Dict[str, AttributionEvidence]] = {}

        def _touch(ev: AttributionEvidence, ioc_val: str, scale_val: float) -> None:
            if ioc_val and ioc_val not in ev.iocs:
                ev.iocs.append(ioc_val)
            ev.scale = max(ev.scale, scale_val)

        for item in items:
            ioc_val = str(item.get("ioc") or "investigation")
            is_seed = bool(item.get("is_seed", True))
            scale = max(0.15, min(1.0, float(item.get("scale", 1.0))))
            actor_set = {str(x).strip() for x in (item.get("actors") or []) if x and len(str(x).strip()) >= 3}
            tag_set = {str(x).strip() for x in (item.get("tags") or []) if x and len(str(x).strip()) >= 3}
            all_texts = actor_set | tag_set

            # 1. Direct Actor / Group Alias Mentions
            for text in all_texts:
                low = text.lower()
                is_direct_actor_field = text in actor_set
                for pat, gi, matched_alias in self._patterns:
                    if pat.search(low):
                        key = (gi, _norm_token(matched_alias), is_seed)
                        ev = mention_seen.get(key)
                        if ev is None:
                            base = W_MENTION * (1.25 if is_direct_actor_field else 1.0)
                            where = "seed indicator intel" if is_seed else f"linked asset ({defang_ioc(ioc_val)})"
                            ev = AttributionEvidence(
                                kind="mention",
                                detail=f'"{matched_alias}" matched in {where}',
                                base_weight=base,
                                dimension="reported" if is_seed else "infrastructure",
                                rarity=1.0,
                                scale=0.0,
                                matched_term=matched_alias,
                            )
                            mention_seen[key] = ev
                            cands.setdefault(gi, AttributionCandidate(self.groups[gi])).evidence.append(ev)
                        _touch(ev, ioc_val, scale)

            # 2. Software / Malware Family Overlap (Rarity-Weighted)
            malware_inputs = list(item.get("malware") or [])
            # Also scan tags for known software names in _sw_index
            for t in tag_set:
                nk = _norm_token(t)
                if nk in self._sw_index:
                    malware_inputs.append(t)

            for fam in malware_inputs:
                k = _norm_token(fam)
                if not k or k not in self._sw_index:
                    continue
                rar, df = self.software_rarity(k)
                canonical_sw = self._sw_canonical_name.get(k, fam)
                for gi in self._sw_index[k]:
                    key = (gi, k)
                    ev = sw_seen.get(key)
                    if ev is None:
                        tier_note = "rare/distinctive" if rar >= RARE_THRESHOLD else "shared/commodity"
                        ev = AttributionEvidence(
                            kind="software",
                            detail=f"{canonical_sw} is used by {self.groups[gi]['name']} ({tier_note}, {df} ATT&CK group(s))",
                            base_weight=W_SOFTWARE * rar * 2.0,
                            dimension="malware",
                            rarity=rar,
                            scale=0.0,
                            matched_term=canonical_sw,
                        )
                        sw_seen[key] = ev
                        cands.setdefault(gi, AttributionCandidate(self.groups[gi])).evidence.append(ev)
                    _touch(ev, ioc_val, scale)

            # 3. MITRE ATT&CK Technique Overlap
            for raw_tid in (item.get("techniques") or []):
                tid = str(raw_tid).strip().upper()
                if not tid:
                    continue
                for gi, g in enumerate(self.groups):
                    if tid in (g.get("techniques") or []):
                        d = tech_hits.setdefault(gi, {})
                        if tid not in d:
                            t_rar = self._idf_rarity(self._tech_df.get(tid, 1))
                            d[tid] = AttributionEvidence(
                                kind="technique",
                                detail=f"{tid} matches {g['name']} ATT&CK profile",
                                base_weight=W_TECHNIQUE * t_rar * 2.0,
                                dimension="ttp",
                                rarity=t_rar,
                                scale=0.0,
                                matched_term=tid,
                            )
                        _touch(d[tid], ioc_val, scale)

        # Attach technique evidence ONLY to candidates that already have a mention or software match
        # (Guard rail: Technique overlap alone can never invent an APT candidate)
        for gi, d in tech_hits.items():
            if gi not in cands:
                continue
            running_t = 0.0
            for ev in sorted(d.values(), key=lambda e: -e.weight):
                if running_t + ev.weight > TECHNIQUE_CAP:
                    break
                running_t += ev.weight
                cands[gi].evidence.append(ev)

        ranked: List[AttributionCandidate] = []
        for gi, c in cands.items():
            c.raw_score = sum(e.weight for e in c.evidence)
            conf = int(round(100.0 * (1.0 - math.exp(-c.raw_score / SATURATION))))

            strong_mention = any(e.kind == "mention" and e.scale >= MIN_PATH_SCALE for e in c.evidence)
            rare_sw_count = sum(
                1 for e in c.evidence
                if e.kind == "software" and e.rarity >= RARE_THRESHOLD and e.scale >= MIN_PATH_SCALE
            )

            if strong_mention or rare_sw_count >= 2:
                c.confidence = conf
            elif rare_sw_count == 1:
                c.confidence = min(conf, CAP_ONE_RARE)
                if conf > CAP_ONE_RARE:
                    c.capped_reason = "capped at Moderate (49%): only one distinctive malware family supports this group without direct mention"
            else:
                c.confidence = min(conf, CAP_COMMODITY)
                if conf > CAP_COMMODITY:
                    c.capped_reason = "capped at Low (20%): evidence is limited to commodity/shared tooling or weak graph hops"

            active_dims = {
                e.dimension for e in c.evidence
                if e.dimension in INDEPENDENT_DIMENSIONS and e.scale >= MIN_PATH_SCALE
            }
            if c.confidence >= 55 and len(active_dims) < 2:
                c.confidence = CAP_SINGLE_DIMENSION
                c.capped_reason = "capped at Moderate (54%): High confidence requires at least 2 independent evidence dimensions"

            ranked.append(c)

        ranked.sort(key=lambda c: (-c.confidence, -c.raw_score, c.group.get("name", "")))
        top_slice = ranked[: max(1, min(top_n, 15))]

        candidates_out = [
            c.to_dict(alternatives=[other for other in top_slice if other is not c])
            for c in top_slice
        ]

        return {
            "kb_meta": self.meta,
            "candidate_count": len(ranked),
            "top_candidate": candidates_out[0] if candidates_out else None,
            "candidates": candidates_out,
            "guard_rails_applied": [
                "Commodity tools (e.g. Cobalt Strike, Mimikatz, AsyncRAT) are rarity-penalized and capped at Low (20%) when seen alone.",
                "MITRE ATT&CK technique overlap is capped at 16 pts and never creates a candidate without malware or direct mention.",
                "High confidence (>=55%) requires corroboration across at least 2 independent dimensions (reported, infrastructure, malware, ttp).",
                "Victimology and operational tempo are explicitly marked as not assessed.",
            ],
            "note": (
                "No threat actor reached the evidence threshold. An indicator can be malicious without being attributable to a named APT group."
                if not candidates_out
                else "Attribution is probabilistic: shared tooling, reused infrastructure, and false flags can mislead. Treat as analyst hypotheses."
            ),
        }


_ATTRIBUTOR_LOCK = threading.Lock()
_ATTRIBUTOR_INSTANCE: Optional[RarityWeightedAttributor] = None


def get_attributor() -> RarityWeightedAttributor:
    global _ATTRIBUTOR_INSTANCE
    with _ATTRIBUTOR_LOCK:
        if _ATTRIBUTOR_INSTANCE is not None:
            return _ATTRIBUTOR_INSTANCE
        if BUNDLED_KB_PATH.exists():
            kb = json.loads(BUNDLED_KB_PATH.read_text(encoding="utf-8"))
        elif MISP_ACTOR_PATH.exists():
            raw_misp = json.loads(MISP_ACTOR_PATH.read_text(encoding="utf-8"))
            groups = []
            for v in raw_misp.get("values", []):
                meta = v.get("meta", {})
                groups.append({
                    "id": f"MISP-{str(v.get('uuid', ''))[:8]}",
                    "name": v.get("value", ""),
                    "aliases": [a for a in meta.get("synonyms", []) if len(a) >= 4],
                    "country": meta.get("country"),
                    "description": (v.get("description") or "")[:360],
                    "url": next(iter(meta.get("refs", [])), ""),
                    "source": "misp",
                    "software": [],
                    "techniques": [],
                })
            kb = {"meta": {"sources": ["MISP Galaxy threat-actor"], "group_count": len(groups)}, "groups": groups}
        else:
            kb = {"meta": {"sources": [], "group_count": 0}, "groups": []}
        _ATTRIBUTOR_INSTANCE = RarityWeightedAttributor(kb)
        return _ATTRIBUTOR_INSTANCE


# =============================================================================
# 4. PHASE 3: CONTEXT-AWARE DEFENSIVE PLAYBOOK & 3-QUESTION TRIAGE GENERATOR
# =============================================================================

def build_defensive_playbook(
    seed_asset: Dict[str, Any],
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    attribution: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Derives concrete, context-aware SOC defensive recommendations from the pivot graph,
    node roles, and attribution findings. Explicitly warns against blocking shared/CDN IPs.
    """
    actions: List[Dict[str, Any]] = []
    seed_val = seed_asset.get("value", "")
    seed_type = seed_asset.get("asset_type", "")
    seed_mal = seed_asset.get("maliciousness_context") or {}
    seed_roles = {r["role"] for r in (seed_asset.get("roles") or [])}
    seed_shared = "shared-infrastructure" in seed_roles or bool(seed_asset.get("shared_infra_flags"))

    c2_nodes = [
        a for a in assets
        if any(r["role"] == "c2-candidate" for r in (a.get("roles") or []))
    ]
    payload_nodes = [
        a for a in assets
        if any(r["role"] == "payload-host" for r in (a.get("roles") or []))
    ]
    shared_nodes = [
        a for a in assets
        if any(r["role"] == "shared-infrastructure" for r in (a.get("roles") or []))
        or bool(a.get("shared_infra_flags"))
    ]
    dns_nodes = [
        a for a in assets
        if any(r["role"] == "fast-flux-dns" for r in (a.get("roles") or []))
    ]
    cert_nodes = [a for a in assets if a.get("asset_type") == "certificate"]
    hash_nodes = [a for a in assets if a.get("asset_type") == "hash"]
    fp_nodes = [a for a in assets if a.get("asset_type") == "fingerprint"]
    weak_nodes = [
        a for a in assets
        if a.get("depth", 0) > 0
        and a.get("relationship_confidence", 0) < 45
        and a not in shared_nodes
    ]

    # 1. Shared / CDN Infrastructure Guard Rail (CRITICAL Outage Prevention)
    if shared_nodes:
        shared_vals = [defang_ioc(a["value"]) for a in shared_nodes[:5]]
        actions.append({
            "priority": "CRITICAL GUARD RAIL",
            "category": "Do Not Block by IP",
            "color": "amber",
            "icon": "fa-triangle-exclamation",
            "title": "Avoid IP-Level Blocking on Shared / CDN Infrastructure",
            "guidance": (
                f"Do NOT block shared hosting or CDN nodes by IP address ({', '.join(shared_vals)}); "
                "doing so can cause collateral outages across unrelated legitimate services. "
                "Enforce blocks strictly at the FQDN, URL path, or SSL/TLS certificate layer."
            ),
            "indicators": shared_vals,
        })

    # 2. Investigate C2 hypotheses before containment.
    if c2_nodes:
        c2_vals = [defang_ioc(a["value"]) for a in c2_nodes[:8]]
        actions.append({
            "priority": "REVIEW",
            "category": "C2 Investigation",
            "color": "red",
            "icon": "fa-Crosshairs",
            "title": f"Investigate {len(c2_nodes)} Possible C2 Node(s)",
            "guidance": (
                f"Review the evidence for {', '.join(c2_vals)} and hunt DNS, proxy, and EDR telemetry "
                "for repeated outbound connections. Confirm C2 behaviour and check shared hosting "
                "before deciding whether to contain the destination."
            ),
            "indicators": c2_vals,
        })
    elif not seed_shared and (
        (seed_mal.get("vt_malicious", 0) or 0) > 0
        or bool(seed_mal.get("reputation_feeds"))
        or bool(seed_mal.get("phishing_sources"))
        or str(seed_mal.get("tip_zone") or "") == "Red"
        or str(seed_mal.get("pulsedive_risk") or "").lower() in {"high", "critical"}
        or (seed_mal.get("abuseipdb_score") or 0) >= 50
        or (seed_mal.get("ha_score") or 0) >= 70
        or (seed_mal.get("triage_max_score") or 0) >= 7
        or (seed_mal.get("urlscan_malicious") or 0) > 0
        or bool(seed_mal.get("malwarebazaar_samples"))
    ):
        actions.append({
            "priority": "REVIEW",
            "category": "Seed Triage",
            "color": "red",
            "icon": "fa-shield-halved",
            "title": f"Alert & Retro-Hunt Seed Indicator ({defang_ioc(seed_val)})",
            "guidance": (
                f"Seed indicator {defang_ioc(seed_val)} carries malicious telemetry. "
                "Query SIEM, DNS, proxy, and EDR logs for historical egress or DNS resolution."
            ),
            "indicators": [defang_ioc(seed_val)],
        })

    # 3. Investigate payload delivery hypotheses.
    if payload_nodes:
        pay_vals = [defang_ioc(a["value"]) for a in payload_nodes[:6]]
        actions.append({
            "priority": "REVIEW",
            "category": "Payload Investigation",
            "color": "amber",
            "icon": "fa-file-shield",
            "title": f"Investigate {len(payload_nodes)} Possible Payload Host(s)",
            "guidance": (
                f"Inspect proxy and EDR file events for downloads from {', '.join(pay_vals)}. "
                "Confirm the exact malicious URL or file before blocking a host."
            ),
            "indicators": pay_vals,
        })

    # 4. Associated Malware Hashes
    if hash_nodes:
        h_vals = [a["value"] for a in hash_nodes[:6]]
        actions.append({
            "priority": "REVIEW",
            "category": "EDR Endpoint Hunt",
            "color": "red",
            "icon": "fa-bug-slash",
            "title": f"Investigate {len(hash_nodes)} Linked Sample Hash(es)",
            "guidance": (
                "Review linked samples and hunt endpoint process/file "
                f"telemetry for execution or disk write events: {', '.join(h[:16] + '…' for h in h_vals)}."
            ),
            "indicators": h_vals,
        })

    # 5. TLS Certificates & JARM / JA3 / Favicon Fingerprints
    if cert_nodes or fp_nodes:
        fp_vals = [a["value"] for a in (cert_nodes + fp_nodes)[:5]]
        actions.append({
            "priority": "MEDIUM",
            "category": "Network / TLS Hunting",
            "color": "purple",
            "icon": "fa-certificate",
            "title": f"Hunt TLS / Fingerprint Artifacts ({len(cert_nodes)} Certs, {len(fp_nodes)} Fingerprints)",
            "guidance": (
                "Pivot across Zeek `ssl.log`, Suricata TLS alerts, and Certificate Transparency monitors "
                f"for shared certificates or server fingerprints ({', '.join(fp_vals[:4])}) to uncover "
                "dormant sibling C2 servers before domain rotation."
            ),
            "indicators": fp_vals,
        })

    # 6. Dynamic DNS / Rotating IPs
    if dns_nodes:
        dns_vals = [defang_ioc(a["value"]) for a in dns_nodes[:5]]
        actions.append({
            "priority": "MEDIUM",
            "category": "DNS Monitoring",
            "color": "blue",
            "icon": "fa-globe",
            "title": f"Monitor {len(dns_nodes)} Dynamic / Fast-Flux DNS Domain(s)",
            "guidance": (
                f"Domain(s) {', '.join(dns_vals)} exhibit dynamic DNS or multi-IP rotation behavior. "
                "Alert on DNS queries to the parent FQDN rather than relying on static IP firewall blocks."
            ),
            "indicators": dns_vals,
        })

    # 7. Weakly Linked Nodes Guard Rail
    if weak_nodes:
        w_vals = [defang_ioc(a["value"]) for a in weak_nodes[:5]]
        actions.append({
            "priority": "LOW / GUARD RAIL",
            "category": "Hunting Leads Only",
            "color": "slate",
            "icon": "fa-magnifying-glass",
            "title": f"Treat {len(weak_nodes)} Weakly Linked Node(s) as Hunting Leads Only",
            "guidance": (
                f"Do not auto-block the {len(weak_nodes)} low-confidence node(s) (<45% relationship confidence); "
                "use them only for passive correlation in SIEM searches."
            ),
            "indicators": w_vals,
        })

    # 8. Attributed Actor TTP Coverage
    top_cand = attribution.get("top_candidate")
    if top_cand:
        ev_techs = [
            e["matched_term"] for e in top_cand.get("evidence", [])
            if e.get("kind") == "technique" and e.get("matched_term")
        ]
        actions.append({
            "priority": "MEDIUM",
            "category": "Detection Engineering",
            "color": "yellow",
            "icon": "fa-user-secret",
            "title": f"Validate Detection Coverage for {top_cand['name']} Hypothesis ({top_cand['confidence_label']})",
            "guidance": (
                f"Review Sigma and SIEM detection rules mapped to {top_cand['name']}"
                + (f" techniques ({', '.join(ev_techs[:6])})" if ev_techs else "")
                + ". Keep in mind attribution is an analytical hypothesis."
            ),
            "indicators": [top_cand["name"]] + ev_techs[:5],
        })

    if not actions:
        actions.append({
            "priority": "INFO",
            "category": "Baseline Monitoring",
            "color": "slate",
            "icon": "fa-circle-check",
            "title": f"Insufficient Evidence to Assign a Threat Role to {defang_ioc(seed_val)}",
            "guidance": (
                "The available results do not establish C2 or payload delivery behaviour. "
                "Review individual source findings and collect more evidence before taking containment action."
            ),
            "indicators": [defang_ioc(seed_val)],
        })

    return actions


def build_investigation_assessment(
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    observations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Runs the three-phase threat assessment on an investigation:
    1. Assigns node roles to every asset (`assess_asset_roles`).
    2. Extracts signals from assets/observations and runs `RarityWeightedAttributor`.
    3. Builds the 3-Question Executive Triage summary (`what`, `connected`, `who`) and
       the `defensive_playbook`.
    """
    if not assets:
        return {
            "three_questions": {},
            "attribution": {"candidates": [], "top_candidate": None},
            "defensive_playbook": [],
            "role_counts": {},
        }

    # Phase 1: Assess roles on all graph nodes
    assess_asset_roles(assets, relationships)

    seed_asset = next((a for a in assets if a.get("depth") == 0), assets[0])

    # Gather attribution inputs across all nodes in the graph, scaled by relationship_confidence
    attr_inputs: List[Dict[str, Any]] = []
    all_malware: Set[str] = set()
    all_techniques: Set[str] = set()
    earliest_dates: List[Tuple[str, str]] = []

    for a in assets:
        is_seed = a.get("depth", 0) == 0
        scale = 1.0 if is_seed else (float(a.get("relationship_confidence", 50)) / 100.0)
        mal = a.get("maliciousness_context") or {}
        meta = a.get("metadata") or {}

        actors: List[str] = []
        tags: List[str] = []
        malware: List[str] = []
        techniques: List[str] = []

        for k, v in {**meta, **mal}.items():
            if not v:
                continue
            kl = str(k).lower()
            v_str = str(v) if not isinstance(v, list) else ", ".join(str(x) for x in v)
            if any(w in kl for w in ("actor", "adversary", "apt", "group", "intrusion")):
                actors.append(v_str)
            elif any(w in kl for w in ("malware", "family", "tool", "implant", "rat", "ransomware")):
                for part in re.split(r"[,;/|]+", v_str):
                    p = part.strip()
                    if p and p.lower() not in {"none", "unknown", "n/a", "true", "false"}:
                        malware.append(p)
                        all_malware.add(p)
            else:
                tags.append(v_str)

            for tm in _TECHNIQUE_EXTRACT_RE.findall(v_str):
                techniques.append(tm.upper())
                all_techniques.add(tm.upper())

        if a.get("first_seen"):
            prov = (a.get("providers") or ["observed"])[0]
            earliest_dates.append((str(a["first_seen"])[:10], prov))

        attr_inputs.append({
            "ioc": a.get("value", ""),
            "is_seed": is_seed,
            "scale": scale,
            "actors": actors,
            "tags": tags,
            "malware": malware,
            "techniques": techniques,
        })

    # Also scan observation summaries & values for malware/actor/technique mentions
    obs_tags: List[str] = []
    obs_techs: List[str] = []
    for o in observations[:200]:
        for field_key in ("field_value", "summary"):
            txt = str(o.get(field_key) or "").strip()
            if txt:
                obs_tags.append(txt)
                for tm in _TECHNIQUE_EXTRACT_RE.findall(txt):
                    obs_techs.append(tm.upper())
                    all_techniques.add(tm.upper())
        if o.get("first_seen"):
            earliest_dates.append((str(o["first_seen"])[:10], o.get("provider", "intel")))

    if obs_tags or obs_techs:
        attr_inputs.append({
            "ioc": seed_asset.get("value", ""),
            "is_seed": True,
            "scale": 0.85,
            "actors": [],
            "tags": obs_tags[:80],
            "malware": [],
            "techniques": obs_techs,
        })

    # Phase 2: Rarity-weighted attribution
    attributor = get_attributor()
    attribution = attributor.evaluate(attr_inputs, top_n=5)

    # Also record any software matched from tags into all_malware for the summary card
    for cand in attribution.get("candidates", [])[:3]:
        for ev in cand.get("evidence", []):
            if ev.get("kind") == "software" and ev.get("matched_term"):
                all_malware.add(ev["matched_term"])

    # Phase 3: Build Defensive Playbook & 3-Question Summary
    playbook = build_defensive_playbook(seed_asset, assets, relationships, attribution)

    # Count asset types and roles
    type_counts: Dict[str, int] = {}
    role_counts: Dict[str, int] = {}
    for a in assets:
        for r in a.get("roles") or []:
            role_counts[r["role"]] = role_counts.get(r["role"], 0) + 1
        if a.get("depth", 0) > 0:
            t = a.get("asset_type", "other")
            type_counts[t] = type_counts.get(t, 0) + 1

    # Question 1: What is this IOC?
    seed_mal = seed_asset.get("maliciousness_context") or {}
    native_telemetry: List[str] = []
    if "vt_malicious" in seed_mal:
        native_telemetry.append(f"VirusTotal: {seed_mal['vt_malicious']} malicious detections")
    if "otx_pulse_count" in seed_mal:
        native_telemetry.append(f"AlienVault OTX: {seed_mal['otx_pulse_count']} pulse(s)")
    if seed_mal.get("reputation_feeds"):
        rf_list = seed_mal["reputation_feeds"]
        native_telemetry.append(f"Reputation Feeds: {len(rf_list)} match(es) ({', '.join(rf_list[:2])})")
    if "tip_zone" in seed_mal:
        native_telemetry.append(f"Kaspersky TIP: {seed_mal['tip_zone']} Zone" + (" (APT-linked)" if seed_mal.get("tip_has_apt") else ""))
    if "pulsedive_risk" in seed_mal:
        native_telemetry.append(f"Pulsedive: {seed_mal['pulsedive_risk']} risk")
    if "threatfox_malware" in seed_mal:
        native_telemetry.append(f"ThreatFox: {seed_mal['threatfox_malware']}")
    elif "threatfox_type" in seed_mal:
        native_telemetry.append(f"ThreatFox: {seed_mal['threatfox_type']}")
    if "urlhaus_threat" in seed_mal:
        native_telemetry.append(f"URLhaus: {seed_mal['urlhaus_threat']}")
    if seed_mal.get("c2_exposure_tools"):
        native_telemetry.append(f"C2 Exposure: {', '.join(seed_mal['c2_exposure_tools'][:2])}")
    if seed_mal.get("phishing_sources"):
        native_telemetry.append(f"Phishing Intel: {', '.join(seed_mal['phishing_sources'][:2])}")
    if "triage_max_score" in seed_mal:
        native_telemetry.append(f"Triage Sandbox: score {seed_mal['triage_max_score']}/10")
    if "ha_verdict" in seed_mal or "ha_score" in seed_mal:
        ha_lbl = seed_mal.get("ha_verdict") or f"score {seed_mal.get('ha_score')}/100"
        native_telemetry.append(f"Hybrid Analysis: {ha_lbl}")
    if "urlscan_malicious" in seed_mal:
        native_telemetry.append(f"URLScan.io: {seed_mal['urlscan_malicious']} malicious scan(s)")
    elif "urlscan_total" in seed_mal:
        native_telemetry.append(f"URLScan.io: {seed_mal['urlscan_total']} scan(s)")
    if "abuseipdb_score" in seed_mal and seed_mal["abuseipdb_score"]:
        native_telemetry.append(f"AbuseIPDB: {seed_mal['abuseipdb_score']}% confidence")
    if "greynoise_classification" in seed_mal:
        native_telemetry.append(f"GreyNoise: {seed_mal['greynoise_classification']}")
    if seed_mal.get("threatbook_judgments"):
        native_telemetry.append(f"ThreatBook: {', '.join(seed_mal['threatbook_judgments'][:2])}")
    if seed_mal.get("silentpush_score"):
        native_telemetry.append(f"Silent Push: risk {seed_mal['silentpush_score']}")
    if seed_mal.get("malwarebazaar_samples"):
        native_telemetry.append(f"MalwareBazaar: {seed_mal['malwarebazaar_samples']} sample(s)")
    if seed_mal.get("misp_events"):
        native_telemetry.append(f"MISP: {seed_mal['misp_events']} event(s)")
    if seed_mal.get("cti_report_sources"):
        native_telemetry.append(f"CTI Reporting: {', '.join(seed_mal['cti_report_sources'][:3])}")

    seed_meta = seed_asset.get("metadata") or {}
    for mk, mlbl in (("asn", "ASN"), ("isp", "ISP"), ("whois_netname", "Netblock"), ("bgp_prefix", "BGP Prefix"), ("country", "Country")):
        if seed_meta.get(mk):
            native_telemetry.append(f"{mlbl}: {seed_meta[mk]}")
    if seed_meta.get("ports"):
        native_telemetry.append(f"Open Ports: {', '.join(str(p) for p in seed_meta['ports'][:6])}")

    for d_pair in seed_mal.get("earliest_dates") or []:
        if isinstance(d_pair, (list, tuple)) and len(d_pair) == 2:
            earliest_dates.append((str(d_pair[0]), str(d_pair[1])))
    valid_dates = [(d, s) for d, s in earliest_dates if re.match(r"^\d{4}-\d{2}-\d{2}", d)]
    earliest_obs = min(valid_dates, key=lambda x: x[0]) if valid_dates else None

    c2_candidates = [
        defang_ioc(a["value"]) for a in assets
        if any(r["role"] == "c2-candidate" for r in (a.get("roles") or []))
    ]
    payload_hosts = [
        defang_ioc(a["value"]) for a in assets
        if any(r["role"] in {"payload-host", "phishing-host"} for r in (a.get("roles") or []))
    ]
    shared_guards = [
        f"{defang_ioc(a['value'])} ({', '.join(a.get('shared_infra_flags') or ['shared'])})"
        for a in assets
        if any(r["role"] == "shared-infrastructure" for r in (a.get("roles") or []))
    ]

    top_actor = attribution.get("top_candidate")

    three_questions = {
        "what": {
            "ioc": seed_asset.get("value", ""),
            "defanged": defang_ioc(seed_asset.get("value", "")),
            "type": seed_asset.get("asset_type", "").upper(),
            "roles": seed_asset.get("roles") or [],
            "native_telemetry": native_telemetry[:14],
            "first_observed": {"date": earliest_obs[0], "source": earliest_obs[1]} if earliest_obs else None,
            "malware_families": sorted(all_malware)[:12],
        },
        "connected": {
            "total_discovered": max(0, len(assets) - 1),
            "total_relationships": len(relationships),
            "type_counts": type_counts,
            "role_counts": role_counts,
            "c2_candidates": c2_candidates[:6],
            "payload_hosts": payload_hosts[:6],
            "shared_infra_guards": shared_guards[:6],
        },
        "who": {
            "top_candidate": top_actor,
            "candidate_count": attribution.get("candidate_count", 0),
            "statement": top_actor["statement"] if top_actor else attribution.get("note", ""),
            "techniques": sorted(all_techniques)[:10],
        },
    }

    return {
        "three_questions": three_questions,
        "attribution": attribution,
        "defensive_playbook": playbook,
        "role_counts": role_counts,
    }


def enrich_ioc_query(
    indicator: str,
    ioc_type: str = "auto",
    query_results: Optional[Dict[str, Any]] = None,
    pivot_investigation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Assesses an IOC Search query using available source evidence:
    1. Canonicalizes & refangs defanged inputs (`evil[.]com`, `hxxps://...`, `1[.]1[.]1[.]1`).
    2. Builds seed asset and maps multi-provider signals (VT detections, ThreatFox C2,
       URLhaus threats, Shodan ports/services, GreyNoise RIOT, OTX pulses/actors).
    3. Discovers linked infrastructure (co-hosted domains, resolved IPs, downloaded hashes).
    4. Evaluates functional node role hypotheses (`c2-candidate`, `payload-host`, `shared-infrastructure`,
       `fast-flux-dns`, `shared-certificate`).
    5. Evaluates explainable Rarity-Weighted APT Attribution with commodity caps and guard rails.
    6. Generates Context-Aware Defensive Playbook (e.g. 'Do Not Block by IP' for CDNs/shared infra,
       EDR hunt queries, firewall containment).
    7. Synthesizes Executive 3-Question Triage ('1. What is this IOC? 2. What is it connected to? 3. Who might be behind it?').
    """
    raw_ind = str(indicator or "").strip()
    clean_val = refang_ioc(raw_ind)
    results = query_results or {}
    excluded = {"indicator", "type", "sources_queried", "duration_ms", "threat_assessment", "i2a"}
    source_evidence = []
    structured_facts = []
    for source, value in results.items():
        if source in excluded or not isinstance(value, dict):
            continue
        if value.get("error"):
            status = "error"
        elif str(value.get("query_status") or "").lower() in {"no_result", "no_results"} or (
            value.get("note") and "no " in str(value["note"]).lower() and "record" in str(value["note"]).lower()
        ):
            status = "no_result"
        elif str(value.get("status") or "").lower() in {"not_configured", "unavailable", "error", "skipped"}:
            status = "error"
        elif value.get("empty") is True or (isinstance(value.get("normalized"), dict) and value["normalized"].get("empty") is True):
            status = "no_result"
        elif isinstance(value.get("normalized"), dict) and value["normalized"].get("found") is False:
            status = "no_result"
        elif str(value.get("match") or "").lower() == "none" and not value.get("results"):
            status = "no_result"
        elif value.get("found") is False and not value.get("records") and not value.get("campaigns"):
            status = "no_result"
        elif value.get("matches") == [] and not any(v for k, v in value.items() if k not in {"source", "query_status", "status", "note", "indicator", "query", "matches"}):
            status = "no_result"
        elif value.get("total") == 0 and not any(isinstance(v, list) and v for v in value.values()):
            status = "no_result"
        elif value.get("data") == [] and not any(v for k, v in value.items() if k not in {"source", "query_status", "status", "note", "indicator", "query", "data", "message", "unsupported"}):
            status = "no_result"
        elif not any(v for k, v in value.items() if k not in {"source", "query_status", "status", "note", "indicator", "query", "message"}):
            status = "no_result"
        else:
            status = "available"
        facts = _structured_source_facts(value) if status == "available" else {}
        findings = _source_findings(source, value, facts) if status == "available" else []
        if status == "available":
            status = "contributed" if findings else "unassessed"
        source_evidence.append({"source": source, "status": status, "findings": findings,
                                "structured_signals": sum(len(facts.get(key, ())) for key in ("actors", "malware", "techniques", "links"))})
        if facts:
            structured_facts.append((source, facts))

    # Infer IOC type if needed
    t = str(ioc_type or "").strip().lower()
    if t in {"", "auto", "keyword", "infra"}:
        if intel_query.is_ip(clean_val):
            t = "ip"
        elif intel_query.is_url(clean_val):
            t = "url"
        elif intel_query.is_hash(clean_val):
            t = "hash"
        elif intel_query.is_domain(clean_val):
            t = "domain"
        else:
            t = "domain" if "." in clean_val else "keyword"

    seed_id = f"{t}:{clean_val}"
    metadata: Dict[str, Any] = {}
    mal_context: Dict[str, Any] = {}
    shared_flags: List[str] = []
    actors: List[str] = []
    malware: List[str] = []
    techniques: List[str] = []
    tags: List[str] = []
    earliest_dates: List[Tuple[str, str]] = []

    # Providers
    vt_response = results.get("virustotal") or {}
    vt = vt_response.get("data", {}).get("attributes", {}) if isinstance(vt_response, dict) and isinstance(vt_response.get("data"), dict) else vt_response
    vt_rel = results.get("vt_relations") or {}
    tf = results.get("threatfox") or {}
    uh = results.get("urlhaus") or {}
    otx = results.get("alienvault") or results.get("otx") or {}
    aip = results.get("abuseipdb") or {}
    gn = results.get("greynoise") or {}
    shodan = results.get("shodan") or {}
    censys = results.get("censys") or {}
    ha = results.get("hybrid-analysis") or results.get("hybrid_analysis") or {}
    triage = results.get("triage") or {}
    misp = results.get("misp") or {}
    dnsdumpster = results.get("dnsdumpster") or {}
    rep_feeds = results.get("reputation_feeds") or {}
    c2_exp = results.get("c2_exposure") or {}
    pulsedive = results.get("pulsedive") or {}
    tip = results.get("tip") or {}
    validin = results.get("validin") or {}
    silentpush = results.get("silentpush") or {}
    driftnet = results.get("driftnet") or {}
    urlscan = results.get("urlscan") or {}
    crtsh = results.get("crtsh") or {}
    leakix = results.get("leakix") or {}
    openphish = results.get("openphish") or {}
    phishstats = results.get("phishstats") or {}
    threatminer = results.get("threatminer") or {}
    threatbook = results.get("threatbook") or {}
    fofa = results.get("fofa") or {}
    zoomeye = results.get("zoomeye") or {}
    netlas = results.get("netlas") or {}
    ripe = results.get("ripe") or {}
    sans = results.get("sans") or {}
    etugen = results.get("etugen") or {}
    commoncrawl = results.get("commoncrawl") or {}
    archive = results.get("archive") or {}
    tweetfeed = results.get("tweetfeed") or {}
    orkl = results.get("orkl") or {}
    cb = results.get("cb") or {}
    malwarebazaar = results.get("malwarebazaar") or {}
    yaraify = results.get("yaraify") or {}
    malshare = results.get("malshare") or {}
    rwlive = results.get("rwlive") or {}

    linked_by_id: Dict[str, Dict[str, Any]] = {}
    edge_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def _add_linked(kind: str, val: Any, rel_type: str, conf: int, provider: str) -> None:
        raw_v = str(val or "").strip()
        if not raw_v:
            return
        if kind == "ip":
            v_clean = intel_query.normalize_ip(raw_v)
            if not v_clean or not intel_query.is_ip(v_clean):
                return
        elif kind == "domain":
            v_clean = intel_query.normalize_domain(raw_v).lower().rstrip(".")
            if not v_clean or not intel_query.is_domain(v_clean):
                return
        elif kind == "url":
            v_clean = raw_v
            if not intel_query.is_url(v_clean):
                return
        elif kind == "hash":
            v_clean = raw_v.lower()
            if not intel_query.is_hash(v_clean):
                return
        elif kind in {"certificate", "fingerprint"}:
            v_clean = raw_v
        else:
            return
        if kind == t and v_clean.lower() == clean_val.lower():
            return
        tid = f"{kind}:{v_clean}"
        if tid in linked_by_id:
            node = linked_by_id[tid]
            if provider and provider not in node["providers"]:
                node["providers"].append(provider)
            if conf > node["relationship_confidence"]:
                node["relationship_confidence"] = conf
        else:
            if len(linked_by_id) >= 80:
                return
            linked_by_id[tid] = {
                "asset_id": tid,
                "asset_type": kind,
                "value": v_clean,
                "depth": 1,
                "relationship_confidence": conf,
                "providers": [provider] if provider else [],
            }
        ekey = (seed_id, tid, rel_type)
        if ekey in edge_map:
            ed = edge_map[ekey]
            if provider and provider not in ed.setdefault("providers", []):
                ed["providers"].append(provider)
            if conf > ed.get("relationship_confidence", 0):
                ed["relationship_confidence"] = conf
        else:
            edge_map[ekey] = {
                "source": seed_id,
                "target": tid,
                "relationship_type": rel_type,
                "relationship_confidence": conf,
                "providers": [provider] if provider else [],
            }

    def _add_ports(port_items: Any) -> None:
        if not isinstance(port_items, list):
            return
        cur = set(metadata.get("ports", []))
        for p in port_items:
            p_val = p.get("port") if isinstance(p, dict) else p
            if str(p_val).isdigit():
                p_int = int(p_val)
                if 0 < p_int <= 65535:
                    cur.add(p_int)
        if cur:
            metadata["ports"] = sorted(cur)

    def _safe_rows(val: Any, limit: Optional[int] = None) -> list:
        if isinstance(val, list):
            items = val
        elif isinstance(val, (tuple, set)):
            items = list(val)
        else:
            return []
        return items[:limit] if limit is not None else items

    # 1. VirusTotal & VT Relations
    if isinstance(vt, dict) and not vt.get("error"):
        mal_count = vt.get("malicious") or vt.get("positives") or (vt.get("last_analysis_stats") or {}).get("malicious") or 0
        if isinstance(mal_count, int) and mal_count > 0:
            mal_context["vt_malicious"] = mal_count
            mal_context["vt_total"] = vt.get("total") or sum((vt.get("last_analysis_stats") or {}).values())
        pop = vt.get("popular_threat_classification") or {}
        sugg = pop.get("suggested_threat_label")
        if sugg:
            malware.append(str(sugg))
        for pop_item in pop.get("popular_threat_name") or []:
            if isinstance(pop_item, dict) and pop_item.get("value"):
                malware.append(str(pop_item["value"]))
        for tg in vt.get("tags") or []:
            tags.append(str(tg))
        if vt.get("as_owner"):
            metadata.setdefault("isp", vt.get("as_owner"))
        if vt.get("asn"):
            metadata.setdefault("asn", f"AS{str(vt.get('asn')).lstrip('ASas')}")
        if vt.get("country"):
            metadata.setdefault("country", vt.get("country"))
        if vt.get("jarm"):
            metadata.setdefault("jarm", vt.get("jarm"))
        if vt.get("first_submission_date") or vt.get("creation_date"):
            try:
                fs_ts = int(vt.get("first_submission_date") or vt.get("creation_date"))
                dt = datetime.fromtimestamp(fs_ts, timezone.utc).strftime("%Y-%m-%d")
                earliest_dates.append((dt, "VirusTotal"))
            except Exception:
                pass
        for r_entry in vt.get("resolutions") or vt.get("last_dns_records") or []:
            if isinstance(r_entry, dict):
                if t == "ip":
                    h = r_entry.get("host_name") or r_entry.get("hostname")
                    if h:
                        _add_linked("domain", h, "hosts", 82, "virustotal")
                elif t == "domain":
                    ip_addr = r_entry.get("ip_address") or r_entry.get("value")
                    if ip_addr and str(r_entry.get("type", "A")).upper() in {"A", "AAAA", ""}:
                        _add_linked("ip", ip_addr, "resolves_to", 85, "virustotal")
        for s_item in vt.get("communicating_samples") or []:
            if isinstance(s_item, dict):
                sh = s_item.get("sha256") or s_item.get("id") or s_item.get("md5")
                if sh:
                    _add_linked("hash", sh, "communicates_with", 82, "virustotal")
        for s_item in vt.get("downloaded_samples") or []:
            if isinstance(s_item, dict):
                sh = s_item.get("sha256") or s_item.get("id") or s_item.get("md5")
                if sh:
                    _add_linked("hash", sh, "distributes_malware", 82, "virustotal")
    if isinstance(vt_rel, dict) and not vt_rel.get("error"):
        for rel_name, rel_payload in vt_rel.items():
            items = (rel_payload.get("data") if isinstance(rel_payload, dict) else rel_payload) if rel_payload else []
            if not isinstance(items, list):
                continue
            for it in items[:25]:
                if not isinstance(it, dict):
                    continue
                attrs_it = it.get("attributes") if isinstance(it.get("attributes"), dict) else it
                if rel_name in {"communicating_files", "referrer_files"}:
                    sh = attrs_it.get("sha256") or it.get("id")
                    if sh:
                        _add_linked("hash", sh, "communicates_with", 82, "vt_relations")
                elif rel_name in {"downloaded_files", "dropped_files"}:
                    sh = attrs_it.get("sha256") or it.get("id")
                    if sh:
                        _add_linked("hash", sh, "distributes_malware", 82, "vt_relations")
                elif rel_name == "resolutions":
                    ip_a = attrs_it.get("ip_address")
                    hn = attrs_it.get("host_name")
                    if t == "domain" and ip_a:
                        _add_linked("ip", ip_a, "resolves_to", 85, "vt_relations")
                    elif t == "ip" and hn:
                        _add_linked("domain", hn, "hosts", 82, "vt_relations")
                elif rel_name in {"subdomains", "Siblings", "contacted_domains"}:
                    d_id = it.get("id") or attrs_it.get("host_name")
                    if d_id:
                        _add_linked("domain", d_id, "communicates_with" if "contacted" in rel_name else "has_subdomain", 75, "vt_relations")
                elif rel_name == "contacted_ips":
                    ip_id = it.get("id") or attrs_it.get("ip_address")
                    if ip_id:
                        _add_linked("ip", ip_id, "communicates_with", 78, "vt_relations")
                elif rel_name in {"urls", "contacted_urls"}:
                    u_val = attrs_it.get("url")
                    if u_val:
                        _add_linked("url", u_val, "hosts_payload" if rel_name == "urls" else "communicates_with", 72, "vt_relations")

    # 2. ThreatFox
    if isinstance(tf, dict) and not tf.get("error"):
        tf_data = tf.get("data") if isinstance(tf.get("data"), list) else ([tf] if tf.get("malware_printable") or tf.get("malware") else [])
        for entry in tf_data:
            if isinstance(entry, dict):
                reported_ioc = refang_ioc(str(entry.get("ioc") or "")).lower().strip()
                if not reported_ioc:
                    continue
                exact_match = reported_ioc == clean_val.lower()
                if t in {"ip", "domain"} and reported_ioc.startswith(clean_val.lower() + ":"):
                    exact_match = reported_ioc[len(clean_val) + 1:].isdigit()
                if not exact_match:
                    continue
                mw = entry.get("malware_printable") or entry.get("malware")
                if mw and str(mw).lower() not in {"none", "unknown"}:
                    mal_context["threatfox_malware"] = str(mw)
                    malware.append(str(mw))
                for alias in str(entry.get("malware_alias") or "").split(","):
                    if alias.strip() and alias.strip().lower() not in {"none", "unknown"}:
                        malware.append(alias.strip())
                ttype = entry.get("threat_type")
                if ttype:
                    mal_context["threatfox_type"] = str(ttype)
                    mal_context.setdefault("role_tags", []).append(str(ttype))
                    tags.append(str(ttype))
                for t_item in entry.get("tags") or []:
                    tags.append(str(t_item))
                if entry.get("first_seen"):
                    earliest_dates.append((str(entry["first_seen"])[:10], "ThreatFox"))

    # 3. URLhaus (URL and SHA-256 payload modes)
    if isinstance(uh, dict) and not uh.get("error") and not uh.get("note"):
        if t == "url" and uh.get("url") == clean_val:
            mal_context["urlhaus_confirmed"] = bool(uh.get("threat") or uh.get("status") or uh.get("payloads"))
            threat = uh.get("threat")
            if threat:
                mal_context["urlhaus_threat"] = threat
                mal_context.setdefault("role_tags", []).append(str(threat))
                tags.append(threat)
            for tg in uh.get("tags") or []:
                tags.append(str(tg))
            for pl in uh.get("payloads") or []:
                if isinstance(pl, dict):
                    if pl.get("signature"):
                        malware.append(str(pl["signature"]))
                    if pl.get("sha256"):
                        _add_linked("hash", pl["sha256"], "distributes_malware", 88, "urlhaus")
            if uh.get("first_seen") or uh.get("date_added"):
                earliest_dates.append((str(uh.get("first_seen") or uh.get("date_added"))[:10], "URLhaus"))
        elif t == "hash" and str(uh.get("sha256") or "").lower() == clean_val.lower():
            if uh.get("signature"):
                mal_context["urlhaus_threat"] = str(uh["signature"])
                malware.append(str(uh["signature"]))
            for u_entry in uh.get("urls") or []:
                if isinstance(u_entry, dict) and u_entry.get("url"):
                    _add_linked("url", u_entry["url"], "downloaded_from", 85, "urlhaus")
            if uh.get("first_seen"):
                earliest_dates.append((str(uh["first_seen"])[:10], "URLhaus"))

    # 4. AlienVault OTX (result key is "alienvault" in IOC Search)
    if isinstance(otx, dict) and not otx.get("error"):
        otx_norm = otx.get("normalized") if isinstance(otx.get("normalized"), dict) else {}
        otx_gen = otx.get("general") if isinstance(otx.get("general"), dict) else {}
        pulses = (
            otx_norm.get("pulses")
            or otx.get("pulses")
            or (otx.get("pulse_info") or {}).get("pulses")
            or (otx_gen.get("pulse_info") or {}).get("pulses")
            or otx.get("normalized_pulses")
            or []
        )
        p_count = ((otx_norm.get("overview") or {}).get("pulse_count")
                   or (otx_gen.get("pulse_info") or {}).get("count")
                   or (len(pulses) if isinstance(pulses, list) else 0))
        if isinstance(p_count, int) and p_count > 0:
            mal_context["otx_pulse_count"] = p_count
        for p in (pulses if isinstance(pulses, list) else []):
            if not isinstance(p, dict):
                continue
            if p.get("adversary"):
                actors.append(str(p["adversary"]))
            for mf in p.get("malware_families") or []:
                if isinstance(mf, dict):
                    mf = mf.get("display_name") or mf.get("id") or ""
                if mf:
                    malware.append(str(mf))
            for tg in p.get("tags") or []:
                tags.append(str(tg))
            for att in p.get("attack_ids") or []:
                att_id = att.get("id") if isinstance(att, dict) else att
                if att_id:
                    techniques.append(str(att_id).upper())
            if p.get("created"):
                earliest_dates.append((str(p["created"])[:10], "AlienVault OTX"))
        otx_infra = otx_norm.get("infrastructure") if isinstance(otx_norm.get("infrastructure"), dict) else {}
        otx_pdns = otx_infra.get("passive_dns") or (otx.get("passive_dns") or {}).get("passive_dns") or []
        for r in (otx_pdns if isinstance(otx_pdns, list) else [])[:25]:
            if isinstance(r, dict):
                if t == "domain" and r.get("address"):
                    _add_linked("ip", r["address"], "resolves_to", 80, "alienvault")
                elif t == "ip" and r.get("hostname"):
                    _add_linked("domain", r["hostname"], "hosts", 78, "alienvault")
        otx_urls = otx_infra.get("urls") or (otx.get("url_list") or {}).get("url_list") or []
        for u_row in (otx_urls if isinstance(otx_urls, list) else [])[:15]:
            if isinstance(u_row, dict) and u_row.get("url"):
                _add_linked("url", u_row["url"], "associated_url", 70, "alienvault")
        otx_mw = otx_norm.get("malware") or (otx.get("malware") or {}).get("data") or []
        for m_row in (otx_mw if isinstance(otx_mw, list) else [])[:15]:
            if isinstance(m_row, dict) and m_row.get("hash"):
                _add_linked("hash", m_row["hash"], "distributes_malware", 75, "alienvault")
        otx_geo = otx_infra.get("geo") or otx.get("geo") or otx_gen
        if isinstance(otx_geo, dict):
            if otx_geo.get("asn"):
                metadata.setdefault("asn", str(otx_geo["asn"]).split()[0])
            if otx_geo.get("country_name") or otx_geo.get("country_code"):
                metadata.setdefault("country", otx_geo.get("country_name") or otx_geo.get("country_code"))

    # 5. AbuseIPDB
    if isinstance(aip, dict) and not aip.get("error"):
        aip_d = aip.get("data") if isinstance(aip.get("data"), dict) else (aip.get("normalized") if isinstance(aip.get("normalized"), dict) else aip)
        score = aip_d.get("abuseConfidenceScore") if aip_d.get("abuseConfidenceScore") is not None else aip_d.get("score")
        if score is not None:
            mal_context["abuseipdb_score"] = score
        if aip_d.get("isp"):
            metadata.setdefault("isp", aip_d["isp"])
        if aip_d.get("countryCode") or aip_d.get("country"):
            metadata.setdefault("country", aip_d.get("countryCode") or aip_d.get("country"))
        if aip_d.get("domain"):
            metadata.setdefault("domain", aip_d["domain"])
        for h in aip_d.get("hostnames") or []:
            if isinstance(h, str):
                _add_linked("domain", h, "hosts", 75, "abuseipdb")

    # 6. GreyNoise
    if isinstance(gn, dict) and not gn.get("error"):
        cls = gn.get("classification")
        if cls:
            mal_context["greynoise_classification"] = cls
        if gn.get("riot") is True:
            mal_context["greynoise_riot"] = True
            shared_flags.append("GreyNoise RIOT (Verified Benign Business Service)")
        if gn.get("actor") and str(gn["actor"]).lower() not in {"unknown", "none"}:
            actors.append(str(gn["actor"]))
        for tg in gn.get("tags") or []:
            tags.append(str(tg))
        if gn.get("first_seen"):
            earliest_dates.append((str(gn["first_seen"])[:10], "GreyNoise"))

    # 7. Shodan & Censys
    if isinstance(shodan, dict) and not shodan.get("error"):
        sh_norm = shodan.get("normalized") if isinstance(shodan.get("normalized"), dict) else {}
        sh_host = shodan.get("host") if isinstance(shodan.get("host"), dict) else {}
        _add_ports(shodan.get("ports") or sh_norm.get("ports") or sh_host.get("ports") or [])
        for m in sh_norm.get("matches") or []:
            if isinstance(m, dict):
                _add_ports([m.get("port")])
                if t == "domain" and m.get("ip"):
                    _add_linked("ip", m["ip"], "resolves_to", 82, "shodan")
                for hn in m.get("hostnames") or []:
                    _add_linked("domain", hn, "hosts", 78, "shodan")
        for s_src in (shodan, sh_norm, sh_host):
            if isinstance(s_src, dict):
                if s_src.get("asn"):
                    metadata.setdefault("asn", str(s_src["asn"]))
                if s_src.get("org") or s_src.get("isp"):
                    metadata.setdefault("isp", s_src.get("org") or s_src.get("isp"))
                if s_src.get("country") or s_src.get("country_name"):
                    metadata.setdefault("country", s_src.get("country") or s_src.get("country_name"))
                if s_src.get("jarm"):
                    metadata.setdefault("jarm", s_src["jarm"])
                for h in s_src.get("hostnames") or s_src.get("domains") or []:
                    if isinstance(h, str):
                        _add_linked("domain", h, "hosts", 80, "shodan")
        dns_dom = sh_norm.get("dns_domain") if isinstance(sh_norm.get("dns_domain"), dict) else {}
        for ip_a in dns_dom.get("resolved_ips") or []:
            _add_linked("ip", ip_a, "resolves_to", 85, "shodan")
        for sub in _safe_rows(dns_dom.get("subdomains"), 25):
            if isinstance(sub, str) and sub:
                full_sub = f"{sub}.{clean_val}" if "." not in sub and t == "domain" else sub
                _add_linked("domain", full_sub, "has_subdomain", 78, "shodan")
        dns_res = sh_norm.get("dns_resolve") if isinstance(sh_norm.get("dns_resolve"), dict) else {}
        for ip_a in dns_res.values():
            if isinstance(ip_a, str):
                _add_linked("ip", ip_a, "resolves_to", 85, "shodan")
        rev_dns = shodan.get("reverse_dns") if isinstance(shodan.get("reverse_dns"), dict) else {}
        for h_list in rev_dns.values():
            for hn in (h_list if isinstance(h_list, list) else []):
                _add_linked("domain", hn, "hosts", 80, "shodan")

    if isinstance(censys, dict) and not censys.get("error"):
        c_norm = censys.get("normalized") if isinstance(censys.get("normalized"), dict) else {}
        c_res = (censys.get("host") or {}).get("result") if isinstance(censys.get("host"), dict) else {}
        c_as = c_norm.get("autonomous_system") or (c_res.get("autonomous_system") if isinstance(c_res, dict) else {}) or {}
        if isinstance(c_as, dict):
            if c_as.get("asn"):
                metadata.setdefault("asn", f"AS{str(c_as['asn']).lstrip('ASas')}")
            if c_as.get("name") or c_as.get("description"):
                metadata.setdefault("isp", c_as.get("name") or c_as.get("description"))
        c_loc = c_norm.get("location") or (c_res.get("location") if isinstance(c_res, dict) else {}) or {}
        if isinstance(c_loc, dict) and c_loc.get("country"):
            metadata.setdefault("country", c_loc["country"])
        c_services = (c_res.get("services") if isinstance(c_res, dict) else None) or c_norm.get("services") or []
        _add_ports(c_services)
        for dns_n in ((c_norm.get("dns") or {}).get("names") if isinstance(c_norm.get("dns"), dict) else []) or []:
            _add_linked("domain", dns_n, "hosts", 78, "censys")
        c_search = ((censys.get("search") or {}).get("normalized") if isinstance(censys.get("search"), dict) else None) or {}
        for hit in (c_search.get("hits") if isinstance(c_search, dict) else []) or []:
            if isinstance(hit, dict):
                if hit.get("ip"):
                    _add_linked("ip", hit["ip"], "resolves_to", 78, "censys")
                _add_ports(hit.get("services") or hit.get("ports") or [])
                for dn in hit.get("names") or hit.get("domains") or []:
                    _add_linked("domain", dn, "hosts", 75, "censys")

    # 8. Hybrid Analysis & Triage
    if isinstance(ha, dict) and not ha.get("error"):
        ha_norm = ha.get("normalized") if isinstance(ha.get("normalized"), dict) else {}
        ha_assess = ha_norm.get("assessment") if isinstance(ha_norm.get("assessment"), dict) else {}
        ha_reports = ha_norm.get("reports") or ha.get("reports") or []
        verdict = ha.get("verdict") or ha_assess.get("verdict")
        score = ha.get("threat_score") if ha.get("threat_score") is not None else ha_assess.get("threat_score")
        if verdict and str(verdict).lower() not in {"unknown", "no_verdict", "whitelisted"}:
            mal_context["ha_verdict"] = str(verdict)
        if isinstance(score, (int, float)) and score > 0:
            mal_context["ha_score"] = int(score)
        for rep in ([ha, ha_assess] + (ha_reports if isinstance(ha_reports, list) else []))[:15]:
            if not isinstance(rep, dict):
                continue
            vx = rep.get("vx_family")
            if vx and str(vx).lower() not in {"none", "unknown"}:
                malware.append(str(vx))
            for att in rep.get("mitre_attcks") or []:
                att_id = att.get("attck_id") if isinstance(att, dict) else att
                if att_id:
                    techniques.append(str(att_id).upper())
            for tg in rep.get("tags") or rep.get("classification_tags") or []:
                tags.append(str(tg))
            if rep.get("sha256"):
                rel_t = "communicates_with" if t in {"ip", "domain", "url"} else "reported_relation"
                _add_linked("hash", rep["sha256"], rel_t, 80, "hybrid-analysis")
            for dom_c in rep.get("domains") or []:
                _add_linked("domain", dom_c, "communicates_with", 78, "hybrid-analysis")
            for host_c in rep.get("hosts") or rep.get("compromised_hosts") or []:
                _add_linked("ip", host_c, "communicates_with", 78, "hybrid-analysis")

    if isinstance(triage, dict) and not triage.get("error"):
        tr_norm = triage.get("normalized") if isinstance(triage.get("normalized"), list) else []
        tr_data = triage.get("data") if isinstance(triage.get("data"), list) else []
        max_sc = None
        c2_match_samples = 0
        for s_norm in tr_norm[:10]:
            if not isinstance(s_norm, dict):
                continue
            sc = (s_norm.get("sample") or {}).get("score")
            if isinstance(sc, (int, float)):
                max_sc = max(max_sc or 0, int(sc))
            created = (s_norm.get("sample") or {}).get("created")
            if created:
                earliest_dates.append((str(created)[:10], "Triage"))
            s_hash = (s_norm.get("hashes") or {}).get("sha256") or (s_norm.get("hashes") or {}).get("md5")
            if s_hash:
                _add_linked("hash", s_hash, "communicates_with", 82, "triage")
            mw_blk = s_norm.get("malware") if isinstance(s_norm.get("malware"), dict) else {}
            for fam in mw_blk.get("families") or []:
                if fam:
                    malware.append(str(fam))
            for tg in mw_blk.get("tags") or []:
                tags.append(str(tg))
            for ttp in s_norm.get("ttps") or []:
                techniques.append(str(ttp).upper())
            for sig in s_norm.get("signatures") or []:
                if isinstance(sig, dict) and (sig.get("name") or sig.get("label")):
                    tags.append(str(sig.get("name") or sig.get("label")))
            c2_blk = s_norm.get("c2") if isinstance(s_norm.get("c2"), dict) else {}
            c2_ips = [str(x).lower() for x in (c2_blk.get("ips") or [])]
            c2_doms = [str(x).lower() for x in (c2_blk.get("domains") or [])]
            c2_urls = [str(x).lower() for x in (c2_blk.get("urls") or [])]
            if clean_val.lower() in c2_ips or clean_val.lower() in c2_doms or clean_val.lower() in c2_urls:
                c2_match_samples += 1
                mal_context.setdefault("role_tags", []).append("c2")
            for ip_c in c2_blk.get("ips") or []:
                _add_linked("ip", ip_c, "communicates_with", 82, "triage")
            for dom_c in c2_blk.get("domains") or []:
                _add_linked("domain", dom_c, "communicates_with", 82, "triage")
            for url_c in c2_blk.get("urls") or []:
                _add_linked("url", url_c, "communicates_with", 80, "triage")
        for raw_s in tr_data[:10]:
            if isinstance(raw_s, dict):
                if raw_s.get("family"):
                    malware.append(str(raw_s["family"]))
                if isinstance(raw_s.get("score"), (int, float)):
                    max_sc = max(max_sc or 0, int(raw_s["score"]))
        if triage.get("family"):
            malware.append(str(triage["family"]))
        for sig in triage.get("signatures") or []:
            if isinstance(sig, dict) and sig.get("label"):
                tags.append(sig["label"])
        if max_sc is not None:
            mal_context["triage_max_score"] = max_sc
        if c2_match_samples:
            mal_context["triage_c2_samples"] = c2_match_samples

    # 9. MISP
    if isinstance(misp, dict) and not misp.get("error"):
        for cluster in (misp.get("galaxy") or misp.get("galaxies") or []):
            if isinstance(cluster, dict):
                g_name = cluster.get("value") or cluster.get("name") or ""
                g_type = str(cluster.get("type") or "").lower()
                if g_name:
                    if any(k in g_type for k in ("actor", "intrusion", "group", "apt")) or not g_type:
                        actors.append(str(g_name))
                    elif any(k in g_type for k in ("malware", "tool", "ransomware", "rat")):
                        malware.append(str(g_name))
                    else:
                        tags.append(str(g_name))
        for tg in misp.get("tags") or []:
            tags.append(str(tg))
        m_events = misp.get("events") if isinstance(misp.get("events"), list) else []
        if m_events:
            mal_context["misp_events"] = len(m_events)
        for rel_ind in _safe_rows(misp.get("related_indicators"), 25):
            if isinstance(rel_ind, dict) and rel_ind.get("value"):
                rv = str(rel_ind["value"])
                rt = str(rel_ind.get("type") or "").lower()
                if "ip" in rt or intel_query.is_ip(rv):
                    _add_linked("ip", rv, "reported_relation", 72, "misp")
                elif "domain" in rt or "hostname" in rt or intel_query.is_domain(rv):
                    _add_linked("domain", rv, "reported_relation", 72, "misp")
                elif "url" in rt or intel_query.is_url(rv):
                    _add_linked("url", rv, "reported_relation", 70, "misp")
                elif any(h in rt for h in ("md5", "sha1", "sha256")) or intel_query.is_hash(rv):
                    _add_linked("hash", rv, "reported_relation", 75, "misp")

    # 10. Local Reputation Feeds
    if isinstance(rep_feeds, dict) and not rep_feeds.get("error"):
        matched_feeds = []
        for f_name, f_rec in rep_feeds.items():
            if f_name in {"error", "note", "matches", "source", "indicator", "query"} or not isinstance(f_rec, dict) or not f_rec:
                continue
            matched_feeds.append(f_name)
            for k, v in f_rec.items():
                if not v:
                    continue
                kl = str(k).lower()
                if "first" in kl and "seen" in kl:
                    earliest_dates.append((str(v)[:10], f"Feed:{f_name}"))
                elif any(w in kl for w in ("malware", "family")):
                    malware.append(str(v))
                elif any(w in kl for w in ("actor", "apt", "group")):
                    actors.append(str(v))
                elif any(w in kl for w in ("category", "type", "role", "tag", "threat")):
                    tags.append(str(v))
                    mal_context.setdefault("role_tags", []).append(str(v))
            if any(w in f_name.lower() for w in ("c2", "botnet", "feodo", "sslbl", "pony", "bambenek")):
                mal_context.setdefault("role_tags", []).append("c2")
            elif any(w in f_name.lower() for w in ("urlhaus", "payload", "dropper")):
                mal_context.setdefault("role_tags", []).append("payload_delivery")
        if matched_feeds:
            mal_context["reputation_feeds"] = sorted(matched_feeds)

    # 11. C2 & Attack Tool Exposure Monitor
    if isinstance(c2_exp, dict) and not c2_exp.get("error"):
        exp_matches = c2_exp.get("matches") if isinstance(c2_exp.get("matches"), list) else []
        c2_tools = []
        for m in exp_matches:
            if not isinstance(m, dict):
                continue
            t_name = str(m.get("name") or m.get("tool_id") or "").strip()
            if t_name:
                c2_tools.append(t_name)
                malware.append(t_name)
                tags.append(t_name)
            if m.get("port"):
                _add_ports([m["port"]])
            if m.get("country"):
                metadata.setdefault("country", m["country"])
            if m.get("first_checked"):
                earliest_dates.append((str(m["first_checked"])[:10], "C2 Exposure"))
        if c2_tools:
            mal_context["c2_exposure_tools"] = sorted(set(c2_tools))
            mal_context.setdefault("role_tags", []).append("c2")

    # 12. Pulsedive
    if isinstance(pulsedive, dict) and not pulsedive.get("error"):
        pd_norm = pulsedive.get("normalized") if isinstance(pulsedive.get("normalized"), dict) else {}
        pd_ind = pd_norm.get("indicator") if isinstance(pd_norm.get("indicator"), dict) else {}
        pd_risk = pd_ind.get("risk") or pulsedive.get("risk") or pulsedive.get("risk_recommended")
        if pd_risk and str(pd_risk).lower() not in {"none", "unknown"}:
            mal_context["pulsedive_risk"] = str(pd_risk)
        if pd_ind.get("first_seen"):
            earliest_dates.append((str(pd_ind["first_seen"])[:10], "Pulsedive"))
        for th in pd_norm.get("threats") or pulsedive.get("threats") or []:
            if isinstance(th, dict):
                th_name = str(th.get("name") or th.get("threat") or "").strip()
                th_cat = str(th.get("category") or "").lower()
                if th_name:
                    if "actor" in th_cat or "apt" in th_cat or "group" in th_cat:
                        actors.append(th_name)
                    else:
                        malware.append(th_name)
                        tags.append(th_name)
        for fd in pd_norm.get("feeds") or []:
            if isinstance(fd, dict) and (fd.get("name") or fd.get("feed")):
                fname = str(fd.get("name") or fd.get("feed"))
                tags.append(fname)
                if any(w in fname.lower() for w in ("c2", "botnet", "zeus", "feodo")):
                    mal_context.setdefault("role_tags", []).append("c2")
        pd_props = pd_norm.get("properties") if isinstance(pd_norm.get("properties"), dict) else {}
        pd_geo = pd_props.get("geo") if isinstance(pd_props.get("geo"), dict) else {}
        if pd_geo.get("country"):
            metadata.setdefault("country", pd_geo["country"])
        if pd_geo.get("org") or pd_geo.get("isp"):
            metadata.setdefault("isp", pd_geo.get("org") or pd_geo.get("isp"))
        if pd_geo.get("asn"):
            metadata.setdefault("asn", str(pd_geo["asn"]))
        for rel in pd_norm.get("relationships") or []:
            if isinstance(rel, dict) and rel.get("target"):
                tt = str(rel.get("target_type") or "").lower()
                tv = str(rel["target"])
                if tt == "ip" or intel_query.is_ip(tv):
                    _add_linked("ip", tv, "resolves_to", 78, "pulsedive")
                elif tt == "domain" or intel_query.is_domain(tv):
                    _add_linked("domain", tv, "reported_relation", 75, "pulsedive")
                elif tt == "url" or intel_query.is_url(tv):
                    _add_linked("url", tv, "reported_relation", 72, "pulsedive")

    # 13. Kaspersky TIP
    if isinstance(tip, dict) and not tip.get("error"):
        tip_lk = tip.get("lookup") if isinstance(tip.get("lookup"), dict) else {}
        tip_zl = tip.get("zonelookup") if isinstance(tip.get("zonelookup"), dict) else {}
        tip_gen = tip_lk.get("DomainGeneralInfo") or tip_lk.get("IpGeneralInfo") or tip_lk.get("FileGeneralInfo") or {}
        tip_zone = tip_lk.get("Zone") or tip_zl.get("Zone") or (tip_gen.get("Zone") if isinstance(tip_gen, dict) else None)
        if tip_zone:
            mal_context["tip_zone"] = str(tip_zone)
        if isinstance(tip_gen, dict):
            if tip_gen.get("HasApt"):
                mal_context["tip_has_apt"] = True
            for cat in tip_gen.get("Categories") or tip_gen.get("CategoriesWithZone") or []:
                c_name = cat.get("Name") if isinstance(cat, dict) else cat
                if c_name:
                    clean_cat = str(c_name).replace("CATEGORY_", "")
                    tags.append(clean_cat)
                    mal_context.setdefault("role_tags", []).append(clean_cat)
        for act in tip_lk.get("Actors") or []:
            a_name = act.get("Name") if isinstance(act, dict) else act
            if a_name:
                actors.append(str(a_name))
        for sw in tip_lk.get("Software") or []:
            s_name = sw.get("Name") if isinstance(sw, dict) else sw
            if s_name:
                malware.append(str(s_name))
        for ttp in tip_lk.get("TTPs") or []:
            t_id = ttp.get("Id") or ttp.get("TechniqueId") if isinstance(ttp, dict) else ttp
            if t_id:
                techniques.append(str(t_id).upper())
        tip_dets = tip_lk.get("DetectionsInfo") or tip_lk.get("FilesDownloaded") or tip_lk.get("FilesDownloadedFromIp") or tip_lk.get("FilesAccessed")
        for det in _safe_rows(tip_dets, 20):
            if isinstance(det, dict):
                d_name = det.get("DetectionName") or det.get("Name")
                if d_name:
                    malware.append(str(d_name))
                h_val = det.get("Sha256") or det.get("Md5") or det.get("Hash")
                if h_val:
                    _add_linked("hash", h_val, "distributes_malware", 82, "tip")
        tip_pdns = tip_lk.get("DomainDnsResolutions") or tip_lk.get("IpDnsResolutions")
        for pdns_row in _safe_rows(tip_pdns, 25):
            if isinstance(pdns_row, dict):
                if pdns_row.get("Ip"):
                    _add_linked("ip", pdns_row["Ip"], "resolves_to", 82, "tip")
                if pdns_row.get("Domain") or pdns_row.get("Host"):
                    _add_linked("domain", pdns_row.get("Domain") or pdns_row.get("Host"), "hosts", 80, "tip")
        for sub_row in _safe_rows(tip_lk.get("Subdomains"), 20):
            s_dom = sub_row.get("Domain") or sub_row.get("Subdomain") if isinstance(sub_row, dict) else sub_row
            if s_dom:
                _add_linked("domain", s_dom, "has_subdomain", 78, "tip")

    # 14. DNSDumpster (normalized + legacy shapes)
    if isinstance(dnsdumpster, dict) and not dnsdumpster.get("error"):
        dd_norm = dnsdumpster.get("normalized") if isinstance(dnsdumpster.get("normalized"), dict) else {}
        dd_hosts = dd_norm.get("hosts") if isinstance(dd_norm.get("hosts"), dict) else {}
        for rtype, h_list in dd_hosts.items():
            for h_obj in _safe_rows(h_list, 30):
                if not isinstance(h_obj, dict):
                    continue
                h_name = h_obj.get("hostname")
                if h_name and h_name.lower() != clean_val.lower():
                    _add_linked("domain", h_name, "has_subdomain", 82, "dnsdumpster")
                for ip_obj in h_obj.get("ips") or []:
                    if isinstance(ip_obj, dict) and ip_obj.get("ip"):
                        _add_linked("ip", ip_obj["ip"], "resolves_to", 85, "dnsdumpster")
                        if ip_obj.get("asn"):
                            metadata.setdefault("asn", f"AS{str(ip_obj['asn']).lstrip('ASas')}")
                        if ip_obj.get("country"):
                            metadata.setdefault("country", ip_obj["country"])
                        if ip_obj.get("asn_name"):
                            metadata.setdefault("isp", ip_obj["asn_name"])
        for r_host in (dnsdumpster.get("dns_records") or {}).get("host") or []:
            if isinstance(r_host, dict) and r_host.get("domain"):
                _add_linked("domain", r_host["domain"], "hosts", 80, "dnsdumpster")
        for d_ip in (dnsdumpster.get("dns_records") or {}).get("dns") or []:
            if isinstance(d_ip, dict) and d_ip.get("ip"):
                _add_linked("ip", d_ip["ip"], "resolves_to", 85, "dnsdumpster")

    # 15. Validin Passive DNS
    if isinstance(validin, dict) and not validin.get("error"):
        v_norm = validin.get("normalized") if isinstance(validin.get("normalized"), dict) else {}
        v_sum = v_norm.get("summary") if isinstance(v_norm.get("summary"), dict) else {}
        if v_sum.get("first_seen_iso"):
            earliest_dates.append((str(v_sum["first_seen_iso"])[:10], "Validin"))
        for ip_v in _safe_rows(v_sum.get("ips") or validin.get("related_ips"), 25):
            _add_linked("ip", ip_v, "resolves_to", 82, "validin")
        for dom_v in _safe_rows(v_sum.get("domains"), 25):
            _add_linked("domain", dom_v, "hosts" if t == "ip" else "reported_relation", 78, "validin")
        for sub_v in _safe_rows(v_sum.get("hostnames"), 25):
            _add_linked("domain", sub_v, "has_subdomain", 78, "validin")
        for c_row in _safe_rows(v_norm.get("certificates"), 15):
            if isinstance(c_row, dict) and c_row.get("value"):
                v_c = str(c_row["value"])
                if intel_query.is_domain(v_c):
                    _add_linked("domain", v_c, "presents", 75, "validin")
                else:
                    _add_linked("certificate", v_c[:64], "presents", 75, "validin")
        for th_row in v_norm.get("threat_context") or []:
            if isinstance(th_row, dict) and th_row.get("value"):
                tags.append(str(th_row["value"]))

    # 16. Silent Push
    if isinstance(silentpush, dict) and not silentpush.get("error"):
        sp_norm = silentpush.get("normalized") if isinstance(silentpush.get("normalized"), dict) else {}
        sp_enr = sp_norm.get("enrichment") or sp_norm.get("summary") or {}
        if isinstance(sp_enr, dict):
            if sp_enr.get("asn"):
                metadata.setdefault("asn", f"AS{str(sp_enr['asn']).lstrip('ASas')}")
            if sp_enr.get("asname") or sp_enr.get("isp") or sp_enr.get("org"):
                metadata.setdefault("isp", sp_enr.get("asname") or sp_enr.get("isp") or sp_enr.get("org"))
            if sp_enr.get("country"):
                metadata.setdefault("country", sp_enr["country"])
            if sp_enr.get("risk_score"):
                mal_context["silentpush_score"] = sp_enr["risk_score"]
        for row in _safe_rows(sp_norm.get("padns_forward"), 25):
            if isinstance(row, dict) and row.get("value"):
                if str(row.get("record") or "").upper() in {"A", "AAAA"}:
                    _add_linked("ip", row["value"], "resolves_to", 82, "silentpush")
                else:
                    _add_linked("domain", row["value"], "reported_relation", 75, "silentpush")
        for row in _safe_rows(sp_norm.get("padns_reverse"), 25):
            if isinstance(row, dict) and row.get("query"):
                _add_linked("domain", row["query"], "hosts", 80, "silentpush")
        for row in _safe_rows(sp_norm.get("domain_search"), 20):
            d_val = row.get("domain") or row.get("host") if isinstance(row, dict) else row
            if d_val:
                _add_linked("domain", d_val, "has_subdomain", 76, "silentpush")
        for row in _safe_rows(sp_norm.get("scan_data"), 20):
            if isinstance(row, dict):
                if row.get("ip"):
                    _add_linked("ip", row["ip"], "resolves_to", 78, "silentpush")
                if row.get("domain"):
                    _add_linked("domain", row["domain"], "hosts", 76, "silentpush")
                if row.get("port"):
                    _add_ports([row["port"]])
                if row.get("jarm"):
                    metadata.setdefault("jarm", row["jarm"])

    # 17. Driftnet
    if isinstance(driftnet, dict) and not driftnet.get("error"):
        dn_norm = driftnet.get("normalized") if isinstance(driftnet.get("normalized"), dict) else {}
        _add_ports(dn_norm.get("ports") or dn_norm.get("ip_ports") or [])
        bgp = dn_norm.get("bgp_whois") if isinstance(dn_norm.get("bgp_whois"), dict) else {}
        asn_dn = (bgp.get("as") or {}).get("as_number") if isinstance(bgp.get("as"), dict) else bgp.get("as_number") or bgp.get("asn")
        if asn_dn:
            metadata.setdefault("asn", f"AS{str(asn_dn).lstrip('ASas')}")
        if isinstance(bgp.get("as"), dict) and bgp["as"].get("as_name"):
            metadata.setdefault("isp", bgp["as"]["as_name"])
        if bgp.get("cidr"):
            metadata.setdefault("bgp_prefix", bgp["cidr"])
        for rel in _safe_rows(dn_norm.get("relationships"), 30):
            if isinstance(rel, dict) and rel.get("target"):
                rt = str(rel.get("target_type") or "").lower()
                rv = str(rel["target"])
                if rt == "ip" or intel_query.is_ip(rv):
                    _add_linked("ip", rv, "resolves_to", 78, "driftnet")
                elif rt in {"domain", "hostname", "host"} or intel_query.is_domain(rv):
                    _add_linked("domain", rv, "hosts" if t == "ip" else "reported_relation", 75, "driftnet")
                elif rt == "port" and rv.isdigit():
                    _add_ports([int(rv)])

    # 18. URLScan.io
    if isinstance(urlscan, dict) and not urlscan.get("error"):
        us_norm = urlscan.get("normalized") if isinstance(urlscan.get("normalized"), dict) else {}
        us_scans = us_norm.get("scans") or urlscan.get("results") or []
        us_tot = us_norm.get("total") or urlscan.get("total") or (len(us_scans) if isinstance(us_scans, list) else 0)
        if isinstance(us_tot, int) and us_tot > 0:
            mal_context["urlscan_total"] = us_tot
        mal_scans = 0
        for sc in _safe_rows(us_scans, 20):
            if not isinstance(sc, dict):
                continue
            page = sc.get("page") if isinstance(sc.get("page"), dict) else {}
            ip_u = sc.get("page_ip") or page.get("ip")
            dom_u = sc.get("page_domain") or page.get("domain")
            url_u = sc.get("page_url") or sc.get("task_url") or page.get("url")
            asn_u = sc.get("page_asn") or page.get("asn")
            cnt_u = sc.get("page_country") or page.get("country")
            if ip_u:
                _add_linked("ip", ip_u, "resolves_to", 80, "urlscan")
            if dom_u:
                _add_linked("domain", dom_u, "hosts" if t == "ip" else "reported_relation", 75, "urlscan")
            if url_u and t != "url":
                _add_linked("url", url_u, "associated_url", 72, "urlscan")
            if asn_u:
                metadata.setdefault("asn", f"AS{str(asn_u).lstrip('ASas')}")
            if cnt_u:
                metadata.setdefault("country", cnt_u)
            v = sc.get("verdicts") if isinstance(sc.get("verdicts"), dict) else {}
            ov = v.get("overall") if isinstance(v.get("overall"), dict) else v
            if ov.get("malicious") is True or sc.get("malicious") is True:
                mal_scans += 1
            for tg in (ov.get("tags") or sc.get("tags") or []):
                tags.append(str(tg))
                mal_context.setdefault("role_tags", []).append(str(tg))
            for brand in (ov.get("brands") or []):
                b_name = brand.get("name") if isinstance(brand, dict) else brand
                if b_name:
                    tags.append(f"phishing:{b_name}")
        if mal_scans:
            mal_context["urlscan_malicious"] = mal_scans
        for f_match in _safe_rows(us_norm.get("file_matches"), 15):
            if isinstance(f_match, dict):
                if f_match.get("sha256"):
                    _add_linked("hash", f_match["sha256"], "distributes_malware", 80, "urlscan")
                if f_match.get("page_url"):
                    _add_linked("url", f_match["page_url"], "downloaded_from", 78, "urlscan")

    # 19. crt.sh Certificate Transparency
    if isinstance(crtsh, dict) and not crtsh.get("error"):
        for c in _safe_rows(crtsh.get("certificates"), 40):
            if not isinstance(c, dict):
                continue
            if c.get("not_before"):
                earliest_dates.append((str(c["not_before"])[:10], "crt.sh"))
            for san in c.get("san") or []:
                if isinstance(san, str) and not san.startswith("*."):
                    _add_linked("domain", san, "has_subdomain", 76, "crtsh")

    # 20. LeakIX
    if isinstance(leakix, dict) and not leakix.get("error"):
        for svc in _safe_rows(leakix.get("services"), 25):
            if isinstance(svc, dict):
                _add_ports([svc.get("port")])
                if svc.get("ip"):
                    _add_linked("ip", svc["ip"], "resolves_to", 80, "leakix")
                if svc.get("domain"):
                    _add_linked("domain", svc["domain"], "hosts", 78, "leakix")
        for sub in _safe_rows(leakix.get("subdomains"), 25):
            _add_linked("domain", sub, "has_subdomain", 78, "leakix")

    # 21. OpenPhish & PhishStats
    if isinstance(openphish, dict) and not openphish.get("error"):
        op_match = str(openphish.get("match") or "").lower()
        op_rows = openphish.get("results") if isinstance(openphish.get("results"), list) else []
        if op_match in {"exact", "domain"} and op_rows:
            mal_context.setdefault("phishing_sources", []).append("OpenPhish")
            tags.append("phishing")
            for r in _safe_rows(op_rows, 15):
                if isinstance(r, dict):
                    if r.get("url"):
                        _add_linked("url", r["url"], "hosts_payload", 82, "openphish")
                    if r.get("first_seen"):
                        earliest_dates.append((str(r["first_seen"])[:10], "OpenPhish"))
    if isinstance(phishstats, dict) and not phishstats.get("error"):
        ps_rows = _safe_rows(phishstats.get("exact")) + _safe_rows(phishstats.get("records"))
        if ps_rows:
            mal_context.setdefault("phishing_sources", []).append("PhishStats")
            tags.append("phishing")
            for r in _safe_rows(ps_rows, 20):
                if isinstance(r, dict):
                    if r.get("ip"):
                        _add_linked("ip", r["ip"], "resolves_to", 80, "phishstats")
                    if r.get("domain") or r.get("host"):
                        _add_linked("domain", r.get("host") or r.get("domain"), "hosts", 78, "phishstats")
                    if r.get("url") and t != "url":
                        _add_linked("url", r["url"], "hosts_payload", 78, "phishstats")
                    if r.get("asn"):
                        metadata.setdefault("asn", f"AS{str(r['asn']).lstrip('ASas')}")
                    if r.get("countrycode") or r.get("countryname"):
                        metadata.setdefault("country", r.get("countrycode") or r.get("countryname"))
                    if r.get("first_seen"):
                        earliest_dates.append((str(r["first_seen"])[:10], "PhishStats"))

    # 22. ThreatMiner
    if isinstance(threatminer, dict) and not threatminer.get("error"):
        for r in _safe_rows(threatminer.get("pdns"), 25):
            if isinstance(r, dict):
                if t == "domain" and r.get("ip"):
                    _add_linked("ip", r["ip"], "resolves_to", 80, "threatminer")
                elif t == "ip" and r.get("domain"):
                    _add_linked("domain", r["domain"], "hosts", 78, "threatminer")
                if r.get("first_seen"):
                    earliest_dates.append((str(r["first_seen"])[:10], "ThreatMiner"))
        for sub in _safe_rows(threatminer.get("subdomains"), 25):
            _add_linked("domain", sub, "has_subdomain", 76, "threatminer")
        for u_val in _safe_rows(threatminer.get("uris"), 15):
            _add_linked("url", u_val, "associated_url", 70, "threatminer")
        for h_row in _safe_rows(threatminer.get("related_hosts"), 20):
            h_v = h_row.get("host") if isinstance(h_row, dict) else h_row
            if h_v:
                _add_linked("ip" if intel_query.is_ip(str(h_v)) else "domain", h_v, "communicates_with", 76, "threatminer")
        for av_row in _safe_rows(threatminer.get("av_detections"), 15):
            if isinstance(av_row, dict) and av_row.get("result"):
                tags.append(str(av_row["result"]))

    # 23. ThreatBook, FOFA, ZoomEye, Netlas, RIPEstat, SANS ISC, Etugen
    if isinstance(threatbook, dict) and not threatbook.get("error"):
        tb_norm = threatbook.get("normalized") if isinstance(threatbook.get("normalized"), dict) else {}
        tb_judg = (tb_norm.get("summary") or {}).get("judgments") if isinstance(tb_norm.get("summary"), dict) else []
        if isinstance(tb_judg, list) and tb_judg:
            mal_context["threatbook_judgments"] = [str(j) for j in tb_judg]
            for j in tb_judg:
                tags.append(str(j))
                mal_context.setdefault("role_tags", []).append(str(j))
        tb_d = threatbook.get("data") if isinstance(threatbook.get("data"), dict) else {}
        _add_ports(tb_d.get("ports") or tb_norm.get("services") or [])
        for s_row in _safe_rows(tb_d.get("samples"), 15):
            if isinstance(s_row, dict):
                if s_row.get("malware_family"):
                    malware.append(str(s_row["malware_family"]))
                if s_row.get("sha256"):
                    _add_linked("hash", s_row["sha256"], "communicates_with", 80, "threatbook")

    for scan_key, scan_obj in (("fofa", fofa), ("zoomeye", zoomeye), ("netlas", netlas)):
        if not isinstance(scan_obj, dict) or scan_obj.get("error"):
            continue
        sc_norm = scan_obj.get("normalized") if isinstance(scan_obj.get("normalized"), dict) else {}
        sc_recs = sc_norm.get("records") or scan_obj.get("records") or scan_obj.get("hits") or scan_obj.get("results") or []
        for rec in (sc_recs if isinstance(sc_recs, list) else [])[:25]:
            if not isinstance(rec, dict):
                continue
            _add_ports([rec.get("port")])
            if rec.get("ip"):
                _add_linked("ip", rec["ip"], "resolves_to", 80, scan_key)
            if rec.get("domain") or rec.get("host"):
                _add_linked("domain", rec.get("domain") or rec.get("host"), "hosts", 76, scan_key)
            if rec.get("asn"):
                metadata.setdefault("asn", f"AS{str(rec['asn']).lstrip('ASas')}")
            if rec.get("asn_name") or rec.get("org") or rec.get("isp"):
                metadata.setdefault("isp", rec.get("asn_name") or rec.get("org") or rec.get("isp"))
            if rec.get("country"):
                metadata.setdefault("country", rec["country"])
            if rec.get("jarm"):
                metadata.setdefault("jarm", rec["jarm"])

    if isinstance(ripe, dict) and not ripe.get("error"):
        if ripe.get("prefix"):
            metadata.setdefault("bgp_prefix", ripe["prefix"])
        if ripe.get("asns"):
            metadata.setdefault("asn", f"AS{str(ripe['asns'][0]).lstrip('ASas')}")
        holder = (ripe.get("asn_overview") or {}).get("holder") if isinstance(ripe.get("asn_overview"), dict) else ""
        if holder:
            metadata.setdefault("isp", holder)
        for w_rec in ripe.get("whois") or []:
            if isinstance(w_rec, dict) and (w_rec.get("netname") or w_rec.get("descr")):
                metadata.setdefault("whois_netname", w_rec.get("netname") or w_rec.get("descr"))

    if isinstance(sans, dict) and not sans.get("error"):
        if sans.get("asn"):
            metadata.setdefault("asn", f"AS{str(sans['asn']).lstrip('ASas')}")
        if sans.get("asname"):
            metadata.setdefault("isp", sans["asname"])
        if sans.get("network"):
            metadata.setdefault("bgp_prefix", sans["network"])
        if isinstance(sans.get("attacks"), int) and sans["attacks"] > 0:
            mal_context["sans_attacks"] = sans["attacks"]

    if isinstance(etugen, dict) and not etugen.get("error"):
        for h_detail in (etugen.get("host_details") or {}).values() if isinstance(etugen.get("host_details"), dict) else []:
            if isinstance(h_detail, dict):
                if h_detail.get("ip"):
                    _add_linked("ip", h_detail["ip"], "resolves_to", 78, "etugen")
                if h_detail.get("domain") or h_detail.get("hostname"):
                    _add_linked("domain", h_detail.get("domain") or h_detail.get("hostname"), "hosts", 76, "etugen")
                if h_detail.get("malware") or h_detail.get("family"):
                    malware.append(str(h_detail.get("malware") or h_detail.get("family")))

    # 24. MalwareBazaar, YARAify, MalShare, Common Crawl, Archive
    if isinstance(malwarebazaar, dict) and not malwarebazaar.get("error"):
        mb_rows = _safe_rows(malwarebazaar.get("data"))
        if mb_rows:
            mal_context["malwarebazaar_samples"] = len(mb_rows)
        for row in mb_rows[:10]:
            if isinstance(row, dict):
                if row.get("signature"):
                    malware.append(str(row["signature"]))
                for tg in _safe_rows(row.get("tags")):
                    tags.append(str(tg))
                if row.get("first_seen"):
                    earliest_dates.append((str(row["first_seen"])[:10], "MalwareBazaar"))
    if isinstance(yaraify, dict) and not yaraify.get("error"):
        for row in _safe_rows(yaraify.get("data"), 15):
            if isinstance(row, dict):
                if row.get("rule_name"):
                    tags.append(str(row["rule_name"]))
                for task in _safe_rows(row.get("tasks")):
                    if isinstance(task, dict) and task.get("clamav_results"):
                        for cr in _safe_rows(task["clamav_results"]):
                            tags.append(str(cr))
    if isinstance(malshare, dict) and not malshare.get("error"):
        ms_sample = (malshare.get("normalized") or {}).get("sample") if isinstance(malshare.get("normalized"), dict) else {}
        if isinstance(ms_sample, dict) and ms_sample.get("sample_source") and intel_query.is_url(ms_sample["sample_source"]):
            _add_linked("url", ms_sample["sample_source"], "downloaded_from", 78, "malshare")
    if isinstance(commoncrawl, dict) and not commoncrawl.get("error"):
        for obs in _safe_rows(commoncrawl.get("observations"), 10):
            if isinstance(obs, dict) and obs.get("url") and t == "domain":
                _add_linked("url", obs["url"], "associated_url", 60, "commoncrawl")
    if isinstance(archive, dict) and not archive.get("error"):
        first_arch = (archive.get("summary") or {}).get("first_archived_display") if isinstance(archive.get("summary"), dict) else ""
        if first_arch:
            earliest_dates.append((str(first_arch)[:10], "Wayback Machine"))

    # 25. TweetFeed, ORKL, CyberBriefing, Ransomware.live & CTI/News/Social Reporting
    if isinstance(tweetfeed, dict) and not tweetfeed.get("error"):
        for rec in _safe_rows(tweetfeed.get("records"), 25):
            if isinstance(rec, dict):
                if rec.get("first_seen"):
                    earliest_dates.append((str(rec["first_seen"])[:10], "TweetFeed"))
                for tg in _safe_rows(rec.get("tags")):
                    tg_s = str(tg).lstrip("#").strip()
                    if tg_s:
                        tags.append(tg_s)
                        mal_context.setdefault("role_tags", []).append(tg_s)
                        malware.append(tg_s)
        for camp in _safe_rows(tweetfeed.get("campaigns"), 10):
            if isinstance(camp, dict):
                for ttp in _safe_rows(camp.get("ttps")):
                    techniques.append(str(ttp).upper())
                for tg in _safe_rows(camp.get("tags")):
                    tags.append(str(tg))

    if isinstance(cb, dict) and not cb.get("error"):
        cb_norm = cb.get("normalized") if isinstance(cb.get("normalized"), dict) else {}
        for th in _safe_rows(cb_norm.get("threats")):
            if isinstance(th, dict) and th.get("name"):
                actors.append(str(th["name"]))
        for rel_i in _safe_rows(cb_norm.get("related_iocs"), 20):
            if isinstance(rel_i, dict) and rel_i.get("value"):
                rv = str(rel_i["value"])
                if intel_query.is_ip(rv):
                    _add_linked("ip", rv, "reported_relation", 70, "cb")
                elif intel_query.is_domain(rv):
                    _add_linked("domain", rv, "reported_relation", 70, "cb")
                elif intel_query.is_hash(rv):
                    _add_linked("hash", rv, "reported_relation", 72, "cb")

    if isinstance(rwlive, dict) and not rwlive.get("error"):
        for v in _safe_rows(rwlive.get("victims"), 20):
            if isinstance(v, dict) and v.get("group"):
                malware.append(str(v["group"]))
                actors.append(str(v["group"]))
        for g in _safe_rows(rwlive.get("groups"), 10):
            if isinstance(g, dict) and g.get("name"):
                malware.append(str(g["name"]))
                actors.append(str(g["name"]))

    cti_sources_hit: List[str] = []
    for rep_key, rep_label in (
        ("orkl", "ORKL"),
        ("cti_mentions", "CTI Articles"),
        ("cti_articles", "CTI Articles"),
        ("rss_intel", "Local RSS"),
        ("malware_news", "Malware.News"),
        ("x_monitor", "X Monitor"),
        ("twitter", "Twitter/X"),
        ("github", "GitHub"),
        ("github_repos", "Internal CTI Repos"),
    ):
        rep_val = results.get(rep_key)
        if not isinstance(rep_val, dict) or rep_val.get("error"):
            continue
        rep_items = (
            rep_val.get("reports")
            or rep_val.get("articles")
            or rep_val.get("data")
            or rep_val.get("posts")
            or rep_val.get("tweets")
            or rep_val.get("items")
            or rep_val.get("results")
            or []
        )
        if not isinstance(rep_items, list) or not rep_items:
            continue
        if rep_label not in cti_sources_hit:
            cti_sources_hit.append(rep_label)
        for item in rep_items[:20]:
            if not isinstance(item, dict):
                continue
            for text_field in ("title", "name", "excerpt", "snippet", "text", "description", "summary"):
                txt = str(item.get(text_field) or "").strip()
                if txt:
                    tags.append(txt[:240])
                    for tm in _TECHNIQUE_EXTRACT_RE.findall(txt):
                        techniques.append(tm.upper())
            for act_field in ("threat_actors", "actors", "actor", "adversary"):
                for act_item in (item.get(act_field) if isinstance(item.get(act_field), list) else [item.get(act_field)]):
                    a_name = act_item.get("name") if isinstance(act_item, dict) else act_item
                    if a_name and isinstance(a_name, str):
                        actors.append(a_name)
            for dt_field in ("published", "published_date", "created_at", "date", " report_date"):
                dt_v = str(item.get(dt_field.strip()) or "")[:10]
                if re.match(r"^\d{4}-\d{2}-\d{2}", dt_v):
                    earliest_dates.append((dt_v, rep_label))
    if cti_sources_hit:
        mal_context["cti_report_sources"] = cti_sources_hit

    # Shared Infrastructure Detection: CDN / Cloudflare / Fastly / Akamai / Dynamic DNS
    isp_text = f"{metadata.get('isp', '')} {metadata.get('asn', '')} {clean_val}".lower()
    for cdn_kw in ("cloudflare", "akamai", "fastly", "cloudfront", "azure front door", "incapsula", "imperva", "sucuri", "google user content"):
        if cdn_kw in isp_text and not any(cdn_kw in f.lower() for f in shared_flags):
            shared_flags.append(f"Shared CDN / Multi-Tenant ({cdn_kw.title()})")

    if t == "domain":
        dyn_suffix = is_dynamic_dns_domain(clean_val)
        if dyn_suffix:
            shared_flags.append(f"Dynamic DNS Provider ({dyn_suffix})")

    # Build unique clean actor/malware/technique/tag lists + merge structured scanner links
    for source, facts in structured_facts:
        actors.extend(facts["actors"])
        malware.extend(facts["malware"])
        techniques.extend(tk.upper() for tk in facts["techniques"] if _TECHNIQUE_EXTRACT_RE.fullmatch(tk))
        for kind, value in facts["links"]:
            _add_linked(kind, value, "reported_relation", 45, source)

    linked_assets = list(linked_by_id.values())
    relationships = list(edge_map.values())

    mal_context["actors"] = sorted(set(actors))
    mal_context["malware"] = sorted(set(malware))
    mal_context["techniques"] = sorted(set(techniques))
    mal_context["tags"] = sorted(set(tags))
    mal_context["earliest_dates"] = earliest_dates

    seed_asset = {
        "asset_id": seed_id,
        "asset_type": t,
        "value": clean_val,
        "depth": 0,
        "providers": [key for key, value in results.items() if isinstance(value, dict) and not value.get("error")],
        "metadata": metadata,
        "maliciousness_context": mal_context,
        "shared_infra_flags": shared_flags,
    }

    all_assets = [seed_asset] + linked_assets
    pivot_status = "not_started"
    if pivot_investigation:
        pivot_status = str(pivot_investigation.get("status") or "running")
        by_id = {a["asset_id"]: a for a in all_assets}
        for pivot_asset in _safe_rows(pivot_investigation.get("assets"), 30):
            if not isinstance(pivot_asset, dict) or not pivot_asset.get("asset_id"):
                continue
            existing = by_id.get(pivot_asset["asset_id"])
            if existing:
                existing["metadata"] = {**pivot_asset.get("metadata", {}), **existing.get("metadata", {})}
                existing["maliciousness_context"] = {**pivot_asset.get("maliciousness_context", {}), **existing.get("maliciousness_context", {})}
                existing["shared_infra_flags"] = list(set(existing.get("shared_infra_flags", [])) | set(pivot_asset.get("shared_infra_flags", [])))
            else:
                added = dict(pivot_asset)
                added["relationship_confidence"] = added.get("relationship_confidence", 0)
                by_id[added["asset_id"]] = added
                all_assets.append(added)
        seen_edges = {(r.get("source"), r.get("target"), r.get("relationship_type")) for r in relationships}
        for edge in _safe_rows(pivot_investigation.get("relationships"), 60):
            key = (edge.get("source"), edge.get("target"), edge.get("relationship_type"))
            if key not in seen_edges and key[0] in by_id and key[1] in by_id:
                seen_edges.add(key)
                relationships.append(edge)

    # Run full assessment pipeline
    assessment = build_investigation_assessment(all_assets, relationships, (pivot_investigation or {}).get("observations") or [])
    assessment["indicator"] = clean_val
    assessment["defanged"] = defang_ioc(clean_val)
    assessment["ioc_type"] = t
    assessment["source_evidence"] = source_evidence
    assessment["pivot"] = {
        "status": pivot_status,
        "id": (pivot_investigation or {}).get("id", ""),
        "api_calls": ((pivot_investigation or {}).get("progress") or {}).get("api_calls_made", 0),
    }
    return assessment
