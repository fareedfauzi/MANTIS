from typing import Any, Dict, Iterable, List, Optional

from ai_pivot_policy import classify_action
from intel_query import SOURCE_CAPABILITIES


LOOKUP_TOOL_BY_TYPE = {
    "hash": ("lookup_hash", "hash"),
    "domain": ("lookup_domain", "domain"),
    "ip": ("lookup_ip", "ip"),
    "url": ("lookup_url", "url"),
    "keyword": ("keyword_search", "query"),
    "infra": ("infra_search", "value"),
}

SOURCE_PRIORITY = {
    "hash": [
        "virustotal", "malwarebazaar", "threatfox", "yaraify", "triage", "hybrid-analysis",
        "alienvault", "malshare", "tip", "urlscan", "github_repos", "malware_news", "rss_intel",
    ],
    "domain": [
        "virustotal", "threatfox", "urlhaus", "urlscan", "alienvault", "pulsedive",
        "reputation_feeds", "greynoise", "silentpush", "validin", "crtsh", "dnsdumpster",
        "shodan", "censys", "fofa", "malware_news", "rss_intel",
    ],
    "ip": [
        "virustotal", "threatfox", "urlhaus", "urlscan", "alienvault", "abuseipdb",
        "greynoise", "pulsedive", "reputation_feeds", "shodan", "censys", "ripe",
        "sans", "validin", "silentpush", "fofa",
    ],
    "url": [
        "urlhaus", "urlscan", "virustotal", "threatfox", "alienvault", "pulsedive",
        "phishstats", "openphish", "triage", "hybrid-analysis", "malware_news", "rss_intel",
    ],
    "keyword": [
        "cti_articles", "threat_actor_knowledge", "malware_tools_knowledge", "misp_galaxy",
        "orkl", "cb", "malware_news", "rss_intel", "github_repos", "github", "tweetfeed",
        "x_monitor", "twitter", "vulnerability_intel", "ransomlook", "rwlive",
    ],
    "infra": [
        "silentpush", "validin", "shodan", "censys", "fofa", "driftnet", "urlscan",
        "dnsdumpster", "crtsh", "greynoise", "ripe", "sans",
    ],
}

SOURCE_ROLE = {
    "virustotal": "broad reputation, relationships, and metadata",
    "malwarebazaar": "sample/family corroboration",
    "threatfox": "curated IOC and malware-tag corroboration",
    "yaraify": "technical rule and family evidence",
    "triage": "sandbox behavior and network indicators",
    "hybrid-analysis": "sandbox report and behavior context",
    "alienvault": "provider claims, pulses, references, and related IOCs",
    "urlhaus": "malicious URL and payload corroboration",
    "urlscan": "passive web/page request evidence",
    "abuseipdb": "IP abuse reporting context",
    "greynoise": "internet-noise and scanner suppression context",
    "shodan": "passive host/service context",
    "censys": "host and certificate context",
    "fofa": "internet asset correlation",
    "validin": "passive DNS, HTTP, and certificate correlation",
    "silentpush": "passive DNS and infrastructure relationships",
    "cti_articles": "local CTI reporting context",
    "threat_actor_knowledge": "actor profile context",
    "malware_tools_knowledge": "malware/tool profile context",
    "misp_galaxy": "taxonomy and alias context",
}

SOURCE_SAFETY_CLASS = {
    "cti_articles": "PASSIVE_LOCAL",
    "threat_actor_knowledge": "PASSIVE_LOCAL",
    "malware_tools_knowledge": "PASSIVE_LOCAL",
    "misp_galaxy": "PASSIVE_LOCAL",
    "yara_forge": "PASSIVE_LOCAL",
    "virustotal": "PASSIVE_REMOTE",
    "threatfox": "PASSIVE_REMOTE",
    "malwarebazaar": "PASSIVE_REMOTE",
    "alienvault": "PASSIVE_REMOTE",
    "urlhaus": "PASSIVE_REMOTE",
    "pulsedive": "PASSIVE_REMOTE",
    "abuseipdb": "PASSIVE_REMOTE",
    "greynoise": "PASSIVE_REMOTE",
    "shodan": "PASSIVE_INFRA",
    "censys": "PASSIVE_INFRA",
    "fofa": "PASSIVE_INFRA",
    "validin": "PASSIVE_INFRA",
    "silentpush": "PASSIVE_INFRA",
    "crtsh": "PASSIVE_INFRA",
    "dnsdumpster": "PASSIVE_INFRA",
    "urlscan": "PASSIVE_REMOTE",
    "archive": "PASSIVE_ARCHIVE",
    "commoncrawl": "PASSIVE_ARCHIVE",
    "tweetfeed": "SOCIAL_CONTEXT",
    "twitter": "SOCIAL_CONTEXT",
    "x_monitor": "SOCIAL_CONTEXT",
    "cb": "REPORTING_CONTEXT",
    "malware_news": "REPORTING_CONTEXT",
    "rss_intel": "REPORTING_CONTEXT",
    "orkl": "REPORTING_CONTEXT",
}


def source_skill_inventory() -> List[Dict[str, Any]]:
    rows = []
    for source_id, meta in sorted(SOURCE_CAPABILITIES.items()):
        if meta.get("internal"):
            continue
        rows.append({
            "source_id": source_id,
            "label": meta.get("label") or source_id,
            "category": meta.get("category") or "",
            "safety_class": SOURCE_SAFETY_CLASS.get(source_id, "PASSIVE_REMOTE"),
            "supported_lookup_types": [key for key in ("hash", "domain", "ip", "url", "keyword", "infra") if meta.get(key)],
            "requires_api_key": bool(meta.get("key_required") or meta.get("requires_api_key", meta.get("key") is not None)),
            "agent_role": SOURCE_ROLE.get(source_id, "source-specific enrichment and corroboration"),
        })
    return rows


def route_sources(lookup_type: str, already_queried: Iterable[str], selected_sources: Optional[Iterable[str]] = None, limit: int = 4) -> List[Dict[str, Any]]:
    lookup_type = str(lookup_type or "keyword").lower()
    done = {str(x or "").lower() for x in (already_queried or [])}
    selected = {str(x or "").lower() for x in (selected_sources or []) if x}
    order = SOURCE_PRIORITY.get(lookup_type, SOURCE_PRIORITY["keyword"])
    candidates = []
    for source_id in order:
        meta = SOURCE_CAPABILITIES.get(source_id) or {}
        if not meta.get(lookup_type):
            continue
        if selected and source_id not in selected:
            continue
        if source_id.lower() in done:
            continue
        candidates.append({
            "source_id": source_id,
            "label": meta.get("label") or source_id,
            "safety_class": SOURCE_SAFETY_CLASS.get(source_id, "PASSIVE_REMOTE"),
            "reason": _route_reason(lookup_type, source_id),
            "requires_api_key": bool(meta.get("key_required") or meta.get("requires_api_key", meta.get("key") is not None)),
        })
        if len(candidates) >= limit:
            break
    return candidates


def plan_next_step(case: Dict[str, Any], selected_sources: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    root = case.get("root") if isinstance(case.get("root"), dict) else {}
    lookup_type = str(root.get("type") or "keyword").lower()
    value = str(root.get("value") or "").strip()
    already = [item.get("source") for item in case.get("source_health", []) if isinstance(item, dict)]
    sources = route_sources(lookup_type, already, selected_sources=selected_sources, limit=4)
    tool, arg_name = LOOKUP_TOOL_BY_TYPE.get(lookup_type, LOOKUP_TOOL_BY_TYPE["keyword"])
    args = {"type": "auto", "value": value} if tool == "infra_search" else {arg_name: value}
    action = {"tool": tool, "arguments": args, "reason": "Continue case enrichment from the next prioritized passive source set."}
    policy = classify_action(action)
    if policy.get("verdict") == "reject":
        action = None
    phase = "enrich" if sources else "assess"
    return {
        "phase": phase,
        "root_type": lookup_type,
        "root_value": value,
        "recommended_sources": sources,
        "action": action,
        "reason": _phase_reason(phase, lookup_type, sources),
    }


def _route_reason(lookup_type: str, source_id: str) -> str:
    role = SOURCE_ROLE.get(source_id, "adds corroborating context")
    return f"Use {role} for this {lookup_type} case."


def _phase_reason(phase: str, lookup_type: str, sources: List[Dict[str, Any]]) -> str:
    if phase == "assess":
        return "No higher-priority unqueried source remains in the current routing policy; assess facts, gaps, contradictions, and attribution support."
    labels = ", ".join(item["label"] for item in sources[:3])
    return f"Acquire/enrich next with {labels} before drafting conclusions for this {lookup_type} case."
