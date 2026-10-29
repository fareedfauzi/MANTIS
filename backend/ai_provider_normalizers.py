import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ai_pivot_policy import (
    CA_AND_CERT_DOMAINS,
    CERT_SUPPORT_HOST_TERMS,
    CERT_SUPPORT_PATH_RE,
    PLACEHOLDER_RE,
    PUBLIC_RESOLVERS,
    REPORTING_AND_SANDBOX_DOMAINS,
    SHARED_PLATFORM_DOMAINS,
)
from intel_query import is_domain, is_hash, is_ip, is_url, normalize_domain, normalize_ip, normalize_url


HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{96}\b|\b[a-fA-F0-9]{128}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

ACTOR_KEYS = {"actor", "actors", "adversary", "adversaries", "threat_actor", "threat_actors", "apt", "group", "groups"}
MALWARE_KEYS = {"malware", "malware_family", "malware_families", "family", "families", "signature", "suggested_threat_label"}
REPORT_KEYS = {"pulse", "pulses", "report", "reports", "article", "articles", "title", "name"}


def normalize_case_findings(context: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    root = _root(context)
    out = {"observations": [], "claims": [], "relationships": []}
    findings = context.get("findings") if isinstance(context, dict) else {}
    if isinstance(findings, dict):
        for source, value in findings.items():
            normalized = normalize_provider(str(source), value, root=root)
            _merge(out, normalized)
    for source, value in _provider_like_top_level(context):
        normalized = normalize_provider(source, value, root=root)
        _merge(out, normalized)
    return _dedupe(out)


def normalize_provider(source: str, data: Any, root: Optional[Dict[str, str]] = None) -> Dict[str, List[Dict[str, Any]]]:
    source = str(source or "source").strip() or "source"
    root = root or {}
    out = {"observations": [], "claims": [], "relationships": []}
    _extract_artifacts(data, source, out)
    lowered = source.lower()
    if lowered in {"alienvault", "alienvault_otx", "otx"}:
        _normalize_otx(source, data, root, out)
    elif lowered in {"threatfox"}:
        _normalize_threatfox(source, data, root, out)
    elif lowered in {"malwarebazaar"}:
        _normalize_malwarebazaar(source, data, root, out)
    elif lowered in {"virustotal", "vt"}:
        _normalize_virustotal(source, data, root, out)
    elif lowered in {"urlhaus"}:
        _normalize_urlhaus(source, data, root, out)
    elif lowered in {"triage", "triage_sandbox"}:
        _normalize_sandbox(source, data, root, out)
    elif lowered in {"hybrid-analysis", "hybrid_analysis"}:
        _normalize_sandbox(source, data, root, out)
    elif lowered in {"urlscan", "urlscan.io"}:
        _normalize_urlscan(source, data, root, out)
    elif lowered in {"abuseipdb"}:
        _normalize_abuseipdb(source, data, root, out)
    elif lowered in {"greynoise"}:
        _normalize_greynoise(source, data, root, out)
    elif lowered in {"shodan", "censys", "fofa", "validin", "silentpush", "driftnet"}:
        _normalize_infra(source, data, root, out)
    elif lowered in {"pulsedive"}:
        _normalize_pulsedive(source, data, root, out)
    elif lowered in {"malware_news", "cti_articles", "cti_mentions", "rss_intel", "orkl", "cb"}:
        _normalize_reporting(source, data, root, out)
    elif lowered in {"binary_lab", "omni_idb", "omniidb"}:
        _normalize_binary_lab(source, data, root, out)
    _normalize_generic_claims(source, data, root, out)
    _normalize_embedded_relationships(source, data, root, out)
    return _dedupe(out)


def _normalize_virustotal(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    attrs = _first_dict(data, ["attributes"]) or (data if isinstance(data, dict) else {})
    stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), dict) else attrs.get("stats") if isinstance(attrs.get("stats"), dict) else {}
    if stats:
        malicious = _int(stats.get("malicious")) + _int(stats.get("suspicious"))
        total = sum(_int(v) for v in stats.values())
        if total:
            _add_observation(out, "detection_summary", f"{malicious}/{total}", source, f"VirusTotal reports {malicious}/{total} engines as malicious or suspicious.", "provider_summary", stats)
    classification = _first_dict(attrs, ["popular_threat_classification"])
    if classification:
        label = _clean(classification.get("suggested_threat_label"))
        if label:
            _add_claim(out, "malware", label, source, f"VirusTotal popular threat classification suggests {label}.", "external_provider", classification)
        for item in _as_list(classification.get("popular_threat_name")):
            value = _clean(item.get("value") if isinstance(item, dict) else item)
            if value:
                _add_claim(out, "malware", value, source, f"VirusTotal names malware/tool context {value}.", "external_provider", item)
    
    for h_type in ("md5", "sha1", "sha256", "vhash", "tlsh"):
        h_val = _clean(attrs.get(h_type))
        if h_val:
            _add_observation(out, "hash", h_val, source, f"VirusTotal reports {h_type.upper()} {h_val}.", "provider_metadata", h_val)
    
    pe_info = attrs.get("pe_info")
    if isinstance(pe_info, dict):
        imphash = _clean(pe_info.get("imphash"))
        if imphash:
            _add_observation(out, "hash", imphash, source, f"VirusTotal reports imphash {imphash}.", "provider_metadata", imphash)
        rich_hash = _clean(pe_info.get("rich_pe_header_hash"))
        if rich_hash:
            _add_observation(out, "hash", rich_hash, source, f"VirusTotal reports Rich PE header hash {rich_hash}.", "provider_metadata", rich_hash)

    cert = attrs.get("last_https_certificate")
    if isinstance(cert, dict):
        thumbprint = _clean(cert.get("thumbprint") or (cert.get("cert_signature") or {}).get("thumbprint"))
        if thumbprint:
            _add_observation(out, "certificate_fingerprint", thumbprint, source, f"VirusTotal observed certificate {thumbprint}.", "provider_metadata", cert)
    
    rels = data.get("relationships")
    if isinstance(rels, dict):
        for rel_type, rel_data in rels.items():
            if not isinstance(rel_data, dict):
                continue
            r_data = rel_data.get("data")
            if not isinstance(r_data, list):
                if isinstance(r_data, dict):
                    r_data = [r_data]
                else:
                    continue
            for item in r_data[:50]:
                if not isinstance(item, dict):
                    continue
                t_type = _clean(item.get("type"))
                t_id = _clean(item.get("id"))
                if t_type and t_id:
                    _add_relation(out, root, rel_type, {"type": t_type, "value": t_id}, source, item)
                    if t_type in ("domain", "ip", "url", "file"):
                        obs_type = "hash" if t_type == "file" else t_type
                        _add_observation(out, obs_type, t_id, source, f"VirusTotal relationship {rel_type} -> {t_id}.", "sandbox_behavior", item)

def _normalize_otx(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    normalized = _first_dict(data, ["normalized"]) or {}
    pulses = normalized.get("pulses") if isinstance(normalized, dict) else None
    if not isinstance(pulses, list):
        pulses = _find_lists_by_key(data, {"pulses", "pulse_info"})[:1]
        pulses = pulses[0] if pulses and isinstance(pulses[0], list) else []
    for pulse in pulses[:25]:
        if not isinstance(pulse, dict):
            continue
        title = _clean(pulse.get("name") or pulse.get("title"))
        if title:
            _add_claim(out, "report", title, source, f"AlienVault OTX pulse/report references {title}.", "provider_report", pulse)
            _add_relation(out, root, "reported_by", {"type": "report", "value": title}, source, pulse)
        actor = _clean(pulse.get("adversary") or pulse.get("actor"))
        if actor:
            _add_claim(out, "actor", actor, source, f"AlienVault OTX pulse names actor/cluster {actor}.", "external_provider", pulse)
            _add_relation(out, root, "reported_by", {"type": "actor", "value": actor}, source, pulse)
        for fam in _as_list(pulse.get("malware_families") or pulse.get("malware")):
            value = _clean(fam)
            if value:
                _add_claim(out, "malware", value, source, f"AlienVault OTX pulse names malware/tool family {value}.", "external_provider", pulse)
                _add_relation(out, root, "associated_malware_claim", {"type": "malware", "value": value}, source, pulse)
        for ref in _as_list(pulse.get("references")):
            ref_val = _clean(ref)
            if ref_val:
                _add_observation(out, "url", ref_val, source, f"AlienVault OTX pulse references URL {ref_val}.", "provider_report", pulse)
        for ind in _as_list(pulse.get("indicators")):
            if not isinstance(ind, dict):
                continue
            i_val = _clean(ind.get("indicator"))
            i_type = _clean(ind.get("type")).lower()
            if i_val:
                obs_type = "ip" if "ip" in i_type else "domain" if "domain" in i_type else "hash" if "hash" in i_type or "md5" in i_type else "url" if "url" in i_type else i_type
                _add_observation(out, obs_type, i_val, source, f"AlienVault OTX pulse contains {i_type} {i_val}.", "provider_report", ind)
                _add_relation(out, root, "pulse_indicator", {"type": obs_type, "value": i_val}, source, ind)


def _normalize_threatfox(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in _rows(data)[:50]:
        malware = _clean(row.get("malware") or row.get("malware_printable") or row.get("malware_alias"))
        if malware:
            _add_claim(out, "malware", malware, source, f"ThreatFox associates the IOC with malware/tool {malware}.", "curated_ioc", row)
            _add_relation(out, root, "associated_malware_claim", {"type": "malware", "value": malware}, source, row)
        threat_type = _clean(row.get("threat_type"))
        if threat_type:
            _add_observation(out, "threat_type", threat_type, source, f"ThreatFox classifies the IOC as {threat_type}.", "provider_summary", row)
        ioc_value = _clean(row.get("ioc_value") or row.get("ioc"))
        ioc_type = _clean(row.get("ioc_type"))
        if ioc_value:
            obs_type = "ip" if "ip" in ioc_type else "domain" if "domain" in ioc_type else "hash" if "hash" in ioc_type else "url" if "url" in ioc_type else "ioc"
            _add_observation(out, obs_type, ioc_value, source, f"ThreatFox reported IOC {ioc_value}.", "curated_ioc", row)
            _add_relation(out, root, "threatfox_ioc", {"type": obs_type, "value": ioc_value}, source, row)
        for tag in _as_list(row.get("tags"))[:20]:
            value = _clean(tag)
            if value:
                _add_observation(out, "tag", value, source, f"ThreatFox tag: {value}.", "provider_tag", row)


def _normalize_malwarebazaar(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in _rows(data)[:50]:
        signature = _clean(row.get("signature"))
        if signature:
            _add_claim(out, "malware", signature, source, f"MalwareBazaar sample signature is {signature}.", "sample_repository", row)
            _add_relation(out, root, "sample_signature", {"type": "malware", "value": signature}, source, row)
        for tag in _as_list(row.get("tags"))[:20]:
            value = _clean(tag)
            if value:
                _add_observation(out, "tag", value, source, f"MalwareBazaar tag: {value}.", "provider_tag", row)
        for h_type in ("sha256_hash", "md5_hash", "sha1_hash", "sha3_384_hash", "imphash", "tlsh"):
            h_val = _clean(row.get(h_type))
            if h_val:
                h_name = h_type.replace("_hash", "")
                _add_observation(out, "hash", h_val, source, f"MalwareBazaar sample {h_name} is {h_val}.", "sample_repository", h_val)
        delivery = _clean(row.get("delivery_method"))
        if delivery:
            _add_observation(out, "delivery_method", delivery, source, f"MalwareBazaar delivery method: {delivery}.", "sample_repository", delivery)
        filename = _clean(row.get("file_name"))
        if filename:
            _add_observation(out, "filename", filename, source, f"MalwareBazaar filename: {filename}.", "sample_repository", filename)


def _normalize_urlhaus(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in _rows(data)[:50]:
        threat = _clean(row.get("threat"))
        if threat:
            _add_observation(out, "threat_type", threat, source, f"URLhaus classifies URL threat as {threat}.", "curated_url", row)
        malware = _clean(row.get("signature") or row.get("malware"))
        if malware:
            _add_claim(out, "malware", malware, source, f"URLhaus associates payload/malware context {malware}.", "curated_url", row)


def _normalize_sandbox(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in _rows(data)[:60]:
        family = _clean(row.get("family") or row.get("malware_family") or row.get("verdict") or row.get("classification"))
        if family and family.lower() not in {"malicious", "suspicious", "clean", "unknown"}:
            _add_claim(out, "malware", family, source, f"{source} sandbox reports malware/tool family {family}.", "sandbox_behavior", row)
            _add_relation(out, root, "sandbox_family", {"type": "malware", "value": family}, source, row)
        score = _clean(row.get("score") or row.get("threat_score") or row.get("verdict"))
        if score:
            _add_observation(out, "sandbox_verdict", score, source, f"{source} sandbox verdict/score: {score}.", "sandbox_behavior", row)
    for key in ("signatures", "tags", "ttps", "mitre", "network", "processes"):
        for item in _find_lists_by_key(data, {key})[:4]:
            for value in item[:40]:
                if isinstance(value, dict):
                    label = _clean(value.get("name") or value.get("signature") or value.get("technique") or value.get("id"))
                else:
                    label = _clean(value)
                if label:
                    _add_observation(out, "behavior", label, source, f"{source} behavior signal: {label}.", "sandbox_behavior", value)


def _normalize_urlscan(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in _rows(data)[:50]:
        page = row.get("page") if isinstance(row.get("page"), dict) else {}
        task = row.get("task") if isinstance(row.get("task"), dict) else {}
        verdicts = row.get("verdicts") if isinstance(row.get("verdicts"), dict) else {}
        url = _clean(page.get("url") or task.get("url") or row.get("url"))
        if url:
            _add_observation(out, "url", url, source, "URLScan observed a submitted or loaded URL.", "passive_web", row)
            _add_relation(out, root, "loads_url", {"type": "url", "value": url}, source, row)
        domain = _clean(page.get("domain") or row.get("domain"))
        if domain:
            _add_observation(out, "domain", domain, source, "URLScan observed a page domain.", "passive_web", row)
        malicious = verdicts.get("malicious") if isinstance(verdicts, dict) else None
        if malicious is not None:
            _add_observation(out, "web_verdict", "malicious" if malicious else "not_malicious", source, "URLScan verdict was recorded.", "passive_web", verdicts)


def _normalize_abuseipdb(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    normalized = _first_dict(data, ["normalized"]) or (data if isinstance(data, dict) else {})
    score = _clean(normalized.get("abuse_confidence_score") or normalized.get("abuseConfidenceScore"))
    if score:
        _add_observation(out, "reputation_score", score, source, f"AbuseIPDB abuse confidence score is {score}.", "reputation", normalized)
    total = _clean(normalized.get("total_reports") or normalized.get("totalReports"))
    if total:
        _add_observation(out, "report_count", total, source, f"AbuseIPDB reports count is {total}.", "reputation", normalized)


def _normalize_greynoise(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    row = data if isinstance(data, dict) else {}
    classification = _clean(row.get("classification"))
    noise = row.get("noise")
    riot = row.get("riot")
    if classification:
        _add_observation(out, "noise_classification", classification, source, f"GreyNoise classifies the IP as {classification}.", "noise_context", row)
    if noise is not None:
        _add_observation(out, "internet_noise", str(bool(noise)).lower(), source, f"GreyNoise noise={bool(noise)}.", "noise_context", row)
    if riot is not None:
        _add_observation(out, "benign_service", str(bool(riot)).lower(), source, f"GreyNoise RIOT benign service={bool(riot)}.", "noise_context", row)


def _normalize_infra(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in _rows(data)[:80]:
        org = _clean(row.get("org") or row.get("organization") or row.get("asn_name") or row.get("autonomous_system_organization"))
        asn = _clean(row.get("asn") or row.get("autonomous_system_number"))
        if org:
            _add_observation(out, "hosting_org", org, source, f"{source} reports hosting/org context {org}.", "infra_context", row)
        if asn:
            _add_observation(out, "asn", asn, source, f"{source} reports ASN {asn}.", "infra_context", row)
        for port in _as_list(row.get("ports") or row.get("open_ports"))[:30]:
            val = _clean(port)
            if val:
                _add_observation(out, "open_port", val, source, f"{source} reports open port {val}.", "infra_context", row)


def _normalize_pulsedive(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    row = data if isinstance(data, dict) else {}
    risk = _clean(row.get("risk") or row.get("risk_recommended"))
    if risk:
        _add_observation(out, "reputation_score", risk, source, f"Pulsedive risk is {risk}.", "reputation", row)
    threat = _clean(row.get("threat") or row.get("threats"))
    if threat:
        _add_claim(out, "threat", threat, source, f"Pulsedive threat context includes {threat}.", "external_provider", row)


def _normalize_reporting(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in _rows(data)[:80]:
        title = _clean(row.get("title") or row.get("name") or row.get("headline"))
        if title:
            _add_claim(out, "report", title, source, f"{source} references report/article {title}.", "reporting_context", row)
        for key in ("actors", "threat_actors", "actor", "group"):
            for actor in _scalar_values(row.get(key)):
                _add_claim(out, "actor", actor, source, f"{source} reporting mentions actor/cluster {actor}.", "reporting_context", row)
                _add_relation(out, root, "report_mentions_actor", {"type": "actor", "value": actor}, source, row)
        for key in ("malware", "families", "malware_families", "tools"):
            for malware in _scalar_values(row.get(key)):
                _add_claim(out, "malware", malware, source, f"{source} reporting mentions malware/tool {malware}.", "reporting_context", row)
                _add_relation(out, root, "report_mentions_malware", {"type": "malware", "value": malware}, source, row)


def _normalize_binary_lab(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]]) -> None:
    if not isinstance(data, dict):
        return
    sample = data.get("sample") or {}
    sample_name = _clean(sample.get("name") or sample.get("path"))
    if sample_name:
        _add_observation(out, "filename", sample_name, source, f"Analyzed binary sample: {sample_name}.", "static_analysis", sample)

    meta = data.get("metadata") or {}
    fmt = _clean(meta.get("executable_format") or sample.get("kind"))
    arch = _clean(meta.get("language_id") or meta.get("compiler_spec") or meta.get("architecture"))
    funcs = meta.get("total_functions")
    if fmt or arch:
        detail = f"Binary format: {fmt or 'Native'}" + (f", architecture: {arch}" if arch else "") + (f", {funcs} functions" if funcs else "")
        _add_observation(out, "file_metadata", detail, source, detail, "static_analysis", meta)

    for ind in (data.get("indicators") or [])[:50]:
        text = _clean(ind)
        if text:
            _add_observation(out, "behavior", text, source, f"Binary Lab triage indicator: {text}.", "static_analysis", ind)
            _add_relation(out, root, "exhibits_behavior", {"type": "behavior", "value": text}, source, ind)

    for net in (data.get("network_indicators") or [])[:40]:
        val = _clean(net)
        typ = "url" if val.startswith(("http://", "https://")) else ("ip" if re.match(r"^\d+\.\d+\.\d+\.\d+$", val) else "domain")
        _add_observation(out, typ, val, source, f"Binary Lab extracted string IOC: {val}.", "static_analysis", net)
        _add_relation(out, root, "communicates_with", {"type": typ, "value": val}, source, net)

    for imp in (data.get("imports") or [])[:30]:
        text = _clean(imp)
        if text:
            _add_observation(out, "imported_api", text, source, f"Imported API: {text}.", "static_analysis", imp)

    report_text = _clean(data.get("report_summary") or data.get("report"))
    if report_text:
        _add_claim(out, "malware_report", report_text[:300], source, f"Binary Lab analysis summary: {report_text[:300]}.", "static_analysis", report_text)

    attribution_text = _clean(data.get("threat_attribution"))
    if attribution_text:
        first_lines = [l.strip().lstrip(">").strip() for l in attribution_text.splitlines() if l.strip() and not l.startswith("#")]
        summary = " ".join(first_lines[:4])[:300]
        _add_claim(out, "threat_attribution", summary, source, f"Threat attribution finding: {summary}", "static_analysis", attribution_text[:2000])


def _normalize_generic_claims(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]], parent_key: str = "", budget: Optional[Dict[str, int]] = None) -> None:
    if budget is None:
        budget = {"nodes": 0}
    if budget["nodes"] > 1800:
        return
    budget["nodes"] += 1
    if isinstance(data, dict):
        for key, value in list(data.items())[:120]:
            key_l = str(key or "").lower()
            if key_l in ACTOR_KEYS:
                for item in _scalar_values(value):
                    _add_claim(out, "actor", item, source, f"{source} names actor/cluster {item}.", "external_provider", {key: value})
                    _add_relation(out, root, "reported_actor_claim", {"type": "actor", "value": item}, source, {key: value})
            elif key_l in MALWARE_KEYS:
                for item in _scalar_values(value):
                    _add_claim(out, "malware", item, source, f"{source} names malware/tool context {item}.", "external_provider", {key: value})
                    _add_relation(out, root, "reported_malware_claim", {"type": "malware", "value": item}, source, {key: value})
            elif key_l in REPORT_KEYS and isinstance(value, str):
                item = _clean(value)
                if item and len(item) > 5:
                    _add_claim(out, "report", item, source, f"{source} references report/pulse {item}.", "provider_report", {key: value})
            _normalize_generic_claims(source, value, root, out, key_l, budget)
    elif isinstance(data, list):
        for item in data[:120]:
            _normalize_generic_claims(source, item, root, out, parent_key, budget)


def _normalize_embedded_relationships(source: str, data: Any, root: Dict[str, str], out: Dict[str, List[Dict[str, Any]]], budget: Optional[Dict[str, int]] = None) -> None:
    if budget is None:
        budget = {"nodes": 0}
    if budget["nodes"] > 1200:
        return
    budget["nodes"] += 1
    if isinstance(data, dict):
        rels = data.get("relationships")
        if isinstance(rels, list):
            for rel in rels[:80]:
                if not isinstance(rel, dict):
                    continue
                src = {"type": _clean(rel.get("source_type")) or root.get("type") or "artifact", "value": _clean(rel.get("source")) or root.get("value") or ""}
                dst = {"type": _clean(rel.get("target_type")) or "entity", "value": _clean(rel.get("target"))}
                relation = _clean(rel.get("relation")) or "related_to"
                _add_relation(out, src, relation, dst, source, rel)
        for value in list(data.values())[:120]:
            _normalize_embedded_relationships(source, value, root, out, budget)
    elif isinstance(data, list):
        for item in data[:120]:
            _normalize_embedded_relationships(source, item, root, out, budget)


def _extract_artifacts(data: Any, source: str, out: Dict[str, List[Dict[str, Any]]], budget: Optional[Dict[str, int]] = None, field_context: str = "") -> None:
    if budget is None:
        budget = {"nodes": 0}
    if budget["nodes"] > 2000:
        return
    budget["nodes"] += 1
    if isinstance(data, dict):
        for key, value in list(data.items())[:140]:
            sub_field = f"{field_context}.{key}" if field_context else str(key)
            _extract_artifacts(value, source, out, budget, sub_field)
    elif isinstance(data, list):
        for item in data[:120]:
            _extract_artifacts(item, source, out, budget, field_context)
    elif isinstance(data, str):
        text = data[:8000]
        ctx_desc = f" (field: {field_context})" if field_context else ""
        for value in URL_RE.findall(text)[:60]:
            _add_observation(out, "url", normalize_url(value.rstrip("),.;")), source, f"URL observed in {source}{ctx_desc}.", "observed", value)
        for value in HASH_RE.findall(text)[:60]:
            _add_observation(out, "hash", value.lower(), source, f"Hash observed in {source}{ctx_desc}.", "observed", value)
        for value in CVE_RE.findall(text)[:40]:
            _add_observation(out, "cve", value.upper(), source, f"CVE observed in {source}{ctx_desc}.", "observed", value)
        for value in IP_RE.findall(text)[:60]:
            _add_observation(out, "ip", normalize_ip(value), source, f"IP observed in {source}{ctx_desc}.", "observed", value)
        for value in DOMAIN_RE.findall(text)[:80]:
            domain = normalize_domain(value)
            if is_domain(domain) and not domain.endswith((".local", ".example", ".test")):
                _add_observation(out, "domain", domain, source, f"Domain observed in {source}{ctx_desc}.", "observed", value)


def classify_noise(typ: str, value: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IOC is likely benign, shared, or noise.
    Returns (pivot_value: bool, noise_reason: str).
    """
    text = str(value or "").strip().lower()
    if not text:
        return False, "empty_value"

    if typ == "ip":
        try:
            parsed = ipaddress.ip_address(text)
            if str(parsed) in PUBLIC_RESOLVERS:
                return False, "public_dns_resolver"
            if (
                parsed.is_private
                or parsed.is_loopback
                or parsed.is_link_local
                or parsed.is_multicast
                or parsed.is_reserved
                or parsed.is_unspecified
            ):
                return False, "non_routable_ip"
        except ValueError:
            pass

    if typ in ("domain", "url"):
        domain = text
        if "://" in domain:
            from urllib.parse import urlparse
            parsed_url = urlparse(domain)
            domain = parsed_url.hostname or text
            if CERT_SUPPORT_PATH_RE.search(parsed_url.path or ""):
                return False, "ca_support_endpoint"

        for ca_d in CA_AND_CERT_DOMAINS:
            if domain == ca_d or domain.endswith(f".{ca_d}"):
                return False, "ca_support_endpoint"

        parts = domain.split(".")
        if parts and parts[0] in CERT_SUPPORT_HOST_TERMS:
            return False, "ca_support_endpoint"

        for shared_d in SHARED_PLATFORM_DOMAINS:
            if domain == shared_d or domain.endswith(f".{shared_d}"):
                return False, "shared_cloud_infrastructure"

        for rep_d in REPORTING_AND_SANDBOX_DOMAINS:
            if domain == rep_d or domain.endswith(f".{rep_d}"):
                return False, "security_reporting_domain"

        generic_clouds = {
            "amazonaws.com", "azure.com", "microsoft.com", "google.com",
            "googleapis.com", "1e100.net", "cloudfront.net", "appspot.com",
            "windows.net", "live.com", "office.com"
        }
        for gc in generic_clouds:
            if domain == gc or domain.endswith(f".{gc}"):
                return False, "shared_cloud_infrastructure"

    return True, ""


def _add_observation(out: Dict[str, List[Dict[str, Any]]], typ: str, value: str, source: str, statement: str, confidence: str, raw: Any) -> None:
    value = _normalize_value(typ, value)
    if not value:
        return
    pivot_val, noise_reason = classify_noise(typ, value)
    out["observations"].append({
        "type": typ,
        "value": value,
        "source": source,
        "statement": statement,
        "confidence": confidence,
        "evidence_type": "OBSERVATION",
        "pivot_value": pivot_val,
        "noise_reason": noise_reason,
        "raw": _small_raw(raw)
    })


def _add_claim(out: Dict[str, List[Dict[str, Any]]], claim_type: str, value: str, source: str, statement: str, confidence: str, raw: Any) -> None:
    value = _clean(value)
    if not value:
        return
    src_lower = str(source).lower()
    is_report = (
        src_lower in {"malware_news", "cti_articles", "rss_intel", "orkl", "cb", "report", "article"}
        or claim_type.lower() in REPORT_KEYS
    )
    ev_type = "REPORT_CLAIM" if is_report else "PROVIDER_CLAIM"
    pivot_val, noise_reason = classify_noise("claim", value)
    out["claims"].append({
        "claim_type": claim_type,
        "value": value[:300],
        "source": source,
        "statement": statement,
        "confidence": confidence,
        "evidence_type": ev_type,
        "pivot_value": pivot_val,
        "noise_reason": noise_reason,
        "raw": _small_raw(raw)
    })


def _add_relation(out: Dict[str, List[Dict[str, Any]]], src: Dict[str, str], relation: str, dst: Dict[str, str], source: str, raw: Any) -> None:
    source_value = _clean(src.get("value"))
    target_value = _clean(dst.get("value"))
    if not source_value or not target_value:
        return
    src_type = _clean(src.get("type")) or "artifact"
    dst_type = _clean(dst.get("type")) or "entity"
    rel_name = _clean(relation) or "related_to"
    out["relationships"].append({
        "source_type": src_type,
        "source_value": source_value[:500],
        "relation": rel_name,
        "target_type": dst_type,
        "target_value": target_value[:500],
        "source_entity": f"{src_type}:{source_value[:500]}",
        "target_entity": f"{dst_type}:{target_value[:500]}",
        "evidence_source": source,
        "evidence_ids": [],
        "raw": _small_raw(raw),
    })


def _root(context: Dict[str, Any]) -> Dict[str, str]:
    query = context.get("query") if isinstance(context, dict) else {}
    return {
        "type": str(context.get("page") or "artifact") if isinstance(context, dict) else "artifact",
        "value": str(query.get("value") or "").strip() if isinstance(query, dict) else "",
    }


def _provider_like_top_level(context: Dict[str, Any]) -> List[Tuple[str, Any]]:
    if not isinstance(context, dict):
        return []
    skip = {"page", "title", "query", "providers", "artifacts", "context_meta", "visible_text", "findings", "intelligence", "intel_summary"}
    out = []
    for key, value in context.items():
        if key in skip or not isinstance(value, (dict, list)):
            continue
        out.append((str(key), value))
    return out


def _rows(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            return [x for x in data["data"] if isinstance(x, dict)]
        if isinstance(data.get("results"), list):
            return [x for x in data["results"] if isinstance(x, dict)]
        if isinstance(data.get("urls"), list):
            return [x for x in data["urls"] if isinstance(x, dict)]
        if isinstance(data.get("payloads"), list):
            return [x for x in data["payloads"] if isinstance(x, dict)]
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def _find_lists_by_key(data: Any, keys: Iterable[str], out: Optional[List[List[Any]]] = None, budget: Optional[Dict[str, int]] = None) -> List[List[Any]]:
    if out is None:
        out = []
    if budget is None:
        budget = {"nodes": 0}
    if budget["nodes"] > 1000:
        return out
    budget["nodes"] += 1
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in keys and isinstance(value, list):
                out.append(value)
            _find_lists_by_key(value, keys, out, budget)
    elif isinstance(data, list):
        for item in data[:120]:
            _find_lists_by_key(item, keys, out, budget)
    return out


def _first_dict(data: Any, keys: Iterable[str]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    current = data
    for key in keys:
        value = current.get(key) if isinstance(current, dict) else None
        if not isinstance(value, dict):
            return {}
        current = value
    return current


def _scalar_values(value: Any) -> List[str]:
    if isinstance(value, str):
        return [_clean(value)] if _clean(value) else []
    if isinstance(value, dict):
        vals = []
        for key in ("name", "value", "label", "family", "malware", "actor"):
            if key in value:
                vals.extend(_scalar_values(value.get(key)))
        return vals
    if isinstance(value, list):
        vals = []
        for item in value[:30]:
            vals.extend(_scalar_values(item))
        return vals
    return []


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _clean(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" \t\r\n\"'")
    if not text or PLACEHOLDER_RE.match(text) or "truncated-depth" in text.lower() or "more item(s) omitted" in text.lower():
        return ""
    return text[:500]


def _normalize_value(typ: str, value: str) -> str:
    value = _clean(value)
    if not value:
        return ""
    if typ == "domain":
        value = normalize_domain(value)
        return value if is_domain(value) else ""
    if typ == "ip":
        value = normalize_ip(value)
        return value if is_ip(value) else ""
    if typ == "url":
        value = normalize_url(value)
        return value if is_url(value) else ""
    if typ == "hash":
        value = value.lower()
        return value if is_hash(value) else ""
    return value[:500]


def _small_raw(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k)[:80]: _small_raw(v) for k, v in list(value.items())[:12]}
    if isinstance(value, list):
        return [_small_raw(v) for v in value[:12]]
    if isinstance(value, str):
        return value[:700]
    return value


def _merge(target: Dict[str, List[Dict[str, Any]]], source: Dict[str, List[Dict[str, Any]]]) -> None:
    for key in ("observations", "claims", "relationships"):
        target[key].extend(source.get(key) or [])


def _dedupe(data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    keys = {
        "observations": ("type", "value", "source"),
        "claims": ("claim_type", "value", "source"),
        "relationships": ("source_type", "source_value", "relation", "target_type", "target_value", "evidence_source"),
    }
    out: Dict[str, List[Dict[str, Any]]] = {}
    ev_idx = 1
    val_to_ev_ids: Dict[str, List[str]] = {}

    for bucket, fields in keys.items():
        seen = set()
        rows = []
        for row in data.get(bucket) or []:
            key = tuple(str(row.get(field) or "").lower() for field in fields)
            if key in seen or not any(key):
                continue
            seen.add(key)
            if bucket in ("observations", "claims"):
                ev_id = str(row.get("evidence_id") or "").strip() or f"ev-{ev_idx:03d}"
                ev_idx += 1
                row["evidence_id"] = ev_id
                val_key = str(row.get("value") or "").strip().lower()
                if val_key:
                    val_to_ev_ids.setdefault(val_key, []).append(ev_id)
            rows.append(row)
        out[bucket] = rows

    # Link evidence_ids into relationships
    for rel in out.get("relationships") or []:
        s_val = str(rel.get("source_value") or "").strip().lower()
        t_val = str(rel.get("target_value") or "").strip().lower()
        linked = list(rel.get("evidence_ids") or [])
        for v in (s_val, t_val):
            for eid in val_to_ev_ids.get(v, []):
                if eid not in linked:
                    linked.append(eid)
        rel["evidence_ids"] = linked

    return out


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
