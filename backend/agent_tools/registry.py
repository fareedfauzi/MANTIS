import html
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

import ai_case_service
import breach_watcher
import cti_query
import similarity_service
from agent_auth import configured_permissions
from agent_policy import bridge_policy
from cti_extract import extract_indicators
from intel_query import (
    classify_canonical_ioc,
    do_domain_intel,
    do_hash_intel,
    do_ip_intel,
    do_keyword_intel,
    do_url_intel,
    get_hash_type,
    get_source_metadata,
    is_domain,
    is_hash,
    is_ip,
    is_url,
    normalize_domain,
    normalize_ip,
    normalize_url,
)
from misp_query import query_misp_ioc
from yara_repos import engine_status as yara_engine_status
from yara_repos import get_rule_source as yara_get_rule_source
from yara_repos import search_rules as yara_search_rules
from yara_service import scan_limits as yara_scan_limits

from agent_redaction import redact


TOOL_VERSION = "1.0"
MAX_TEXT_CHARS = 120_000


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    permission: str
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    input_schema: Dict[str, Any]


def _ok(tool: str, data: Any, warnings: List[str] = None, evidence: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "ok": True,
        "tool": tool,
        "tool_version": TOOL_VERSION,
        "data": redact(data),
        "evidence": evidence or [],
        "warnings": warnings or [],
        "errors": [],
    }


def _err(tool: str, message: str, data: Any = None) -> Dict[str, Any]:
    return {
        "ok": False,
        "tool": tool,
        "tool_version": TOOL_VERSION,
        "data": redact(data or {}),
        "evidence": [],
        "warnings": [],
        "errors": [{"message": str(message)[:800]}],
    }


def _limit(value: Any, max_chars: int = 80_000) -> Any:
    if isinstance(value, dict):
        return {k: _limit(v, max_chars=max_chars) for k, v in value.items()}
    if isinstance(value, list):
        return [_limit(v, max_chars=max_chars) for v in value[:200]]
    if isinstance(value, str) and len(value) > max_chars:
        return value[:max_chars] + "\n...[truncated]"
    return value


def _as_list(value: Any, limit: int = 40) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value[:limit] if str(v).strip()]
    return [str(value).strip()]


def _provider_keys(args: Dict[str, Any]) -> Dict[str, str]:
    raw = args.get("provider_keys") or {}
    return raw if isinstance(raw, dict) else {}


def _detect_ioc_type(indicator: str, requested: str = "auto") -> str:
    requested = (requested or "auto").strip().lower()
    value = (indicator or "").strip()
    if requested in {"domain", "ip", "url", "hash", "keyword"}:
        return requested
    if is_hash(value):
        return "hash"
    if is_ip(normalize_ip(value)):
        return "ip"
    if is_url(value):
        return "url"
    if is_domain(normalize_domain(value)):
        return "domain"
    kind = classify_canonical_ioc(value)
    if kind == "hash":
        return "hash"
    if kind in {"domain", "ip", "url"}:
        return kind
    return "keyword"


def tool_provider_metadata(args: Dict[str, Any]) -> Dict[str, Any]:
    return _ok("mantis.v1.provider_metadata", get_source_metadata())


def tool_ioc_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    indicator = str(args.get("indicator") or "").strip()
    if not indicator:
        return _err("mantis.v1.ioc_lookup_auto", "indicator is required")
    ioc_type = _detect_ioc_type(indicator, str(args.get("indicator_type") or "auto"))
    sources = _as_list(args.get("sources"))
    keys = _provider_keys(args)
    misp = args.get("misp") if isinstance(args.get("misp"), dict) else {}
    started = time.time()

    if ioc_type == "domain":
        value = normalize_domain(indicator)
        if not value or not is_domain(value):
            return _err("mantis.v1.ioc_lookup_auto", "Invalid domain indicator.")
        data = do_domain_intel(
            value,
            keys.get("virustotal", ""),
            keys.get("abusech", ""),
            keys.get("otx", ""),
            tip_key=keys.get("tip", ""),
            cb_key=keys.get("cyberbriefing", ""),
            rwlive_key=keys.get("ransomware_live", ""),
            triage_key=keys.get("triage", ""),
            ha_key=keys.get("hybrid_analysis", ""),
            silentpush_key=keys.get("silentpush", ""),
            driftnet_key=keys.get("driftnet", ""),
            urlscan_key=keys.get("urlscan", ""),
            shodan_key=keys.get("shodan", ""),
            censys_key=keys.get("censys", ""),
            etugen_key=keys.get("etugen", ""),
            pulsedive_key=keys.get("pulsedive", ""),
            fofa_key=keys.get("fofa", ""),
            validin_key=keys.get("validin", ""),
            twitter_key=keys.get("twitter", ""),
            github_key=keys.get("github", ""),
            dnsdumpster_key=keys.get("dnsdumpster", ""),
            leakix_key=keys.get("leakix", ""),
            phishstats_key=keys.get("phishstats", ""),
            misp_url=misp.get("url", ""),
            misp_key=misp.get("key", ""),
            misp_verify_ssl=misp.get("verify_ssl", True),
            sources=sources,
        )
    elif ioc_type == "ip":
        value = normalize_ip(indicator)
        if not value or not is_ip(value):
            return _err("mantis.v1.ioc_lookup_auto", "Invalid IP indicator.")
        data = do_ip_intel(
            value,
            keys.get("virustotal", ""),
            keys.get("abusech", ""),
            keys.get("otx", ""),
            tip_key=keys.get("tip", ""),
            cb_key=keys.get("cyberbriefing", ""),
            threatbook_key=keys.get("threatbook", ""),
            triage_key=keys.get("triage", ""),
            ha_key=keys.get("hybrid_analysis", ""),
            silentpush_key=keys.get("silentpush", ""),
            driftnet_key=keys.get("driftnet", ""),
            urlscan_key=keys.get("urlscan", ""),
            shodan_key=keys.get("shodan", ""),
            censys_key=keys.get("censys", ""),
            etugen_key=keys.get("etugen", ""),
            pulsedive_key=keys.get("pulsedive", ""),
            fofa_key=keys.get("fofa", ""),
            validin_key=keys.get("validin", ""),
            twitter_key=keys.get("twitter", ""),
            github_key=keys.get("github", ""),
            abuseipdb_key=keys.get("abuseipdb", ""),
            greynoise_key=keys.get("greynoise", ""),
            leakix_key=keys.get("leakix", ""),
            phishstats_key=keys.get("phishstats", ""),
            misp_url=misp.get("url", ""),
            misp_key=misp.get("key", ""),
            misp_verify_ssl=misp.get("verify_ssl", True),
            sources=sources,
        )
    elif ioc_type == "url":
        value = normalize_url(indicator)
        if not value or not is_url(value):
            return _err("mantis.v1.ioc_lookup_auto", "Invalid URL indicator.")
        data = do_url_intel(
            value,
            keys.get("virustotal", ""),
            keys.get("abusech", ""),
            keys.get("otx", ""),
            tip_key=keys.get("tip", ""),
            cb_key=keys.get("cyberbriefing", ""),
            triage_key=keys.get("triage", ""),
            ha_key=keys.get("hybrid_analysis", ""),
            silentpush_key=keys.get("silentpush", ""),
            urlscan_key=keys.get("urlscan", ""),
            pulsedive_key=keys.get("pulsedive", ""),
            github_key=keys.get("github", ""),
            phishstats_key=keys.get("phishstats", ""),
            misp_url=misp.get("url", ""),
            misp_key=misp.get("key", ""),
            misp_verify_ssl=misp.get("verify_ssl", True),
            sources=sources,
        )
    elif ioc_type == "hash":
        value = indicator.strip()
        if not is_hash(value):
            return _err("mantis.v1.ioc_lookup_auto", "Invalid hash indicator.")
        data = do_hash_intel(
            value,
            keys.get("virustotal", ""),
            keys.get("abusech", ""),
            keys.get("otx", ""),
            triage_key=keys.get("triage", ""),
            tip_key=keys.get("tip", ""),
            cb_key=keys.get("cyberbriefing", ""),
            ha_key=keys.get("hybrid_analysis", ""),
            malshare_key=keys.get("malshare", ""),
            silentpush_key=keys.get("silentpush", ""),
            driftnet_key=keys.get("driftnet", ""),
            pulsedive_key=keys.get("pulsedive", ""),
            fofa_key=keys.get("fofa", ""),
            validin_key=keys.get("validin", ""),
            urlscan_key=keys.get("urlscan", ""),
            twitter_key=keys.get("twitter", ""),
            github_key=keys.get("github", ""),
            misp_url=misp.get("url", ""),
            misp_key=misp.get("key", ""),
            misp_verify_ssl=misp.get("verify_ssl", True),
            sources=sources,
            github_repos=_as_list(args.get("github_repos")),
        )
    else:
        value = indicator
        data = do_keyword_intel(
            value,
            str(args.get("query_type") or "keyword"),
            keys.get("abusech", ""),
            otx_key=keys.get("otx", ""),
            triage_key=keys.get("triage", ""),
            tip_key=keys.get("tip", ""),
            malshare_key=keys.get("malshare", ""),
            rwlive_key=keys.get("ransomware_live", ""),
            cb_key=keys.get("cyberbriefing", ""),
            ha_key=keys.get("hybrid_analysis", ""),
            urlscan_key=keys.get("urlscan", ""),
            silentpush_key=keys.get("silentpush", ""),
            driftnet_key=keys.get("driftnet", ""),
            shodan_key=keys.get("shodan", ""),
            censys_key=keys.get("censys", ""),
            etugen_key=keys.get("etugen", ""),
            pulsedive_key=keys.get("pulsedive", ""),
            fofa_key=keys.get("fofa", ""),
            validin_key=keys.get("validin", ""),
            twitter_key=keys.get("twitter", ""),
            github_key=keys.get("github", ""),
            dnsdumpster_key=keys.get("dnsdumpster", ""),
            sources=sources,
            github_repos=_as_list(args.get("github_repos")),
        )
    evidence = [{"id": "mantis:ioc_lookup", "source": "MANTIS", "indicator": indicator, "indicator_type": ioc_type}]
    return _ok("mantis.v1.ioc_lookup_auto", {"indicator": indicator, "indicator_type": ioc_type, "duration_seconds": round(time.time() - started, 3), "result": _limit(data)}, evidence=evidence)


def tool_misp_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    indicator = str(args.get("indicator") or "").strip()
    if not indicator:
        return _err("mantis.v1.misp_lookup_ioc", "indicator is required")
    ioc_type = _detect_ioc_type(indicator, str(args.get("indicator_type") or "auto"))
    if ioc_type == "ip":
        query_type = "ip"
    elif ioc_type in {"domain", "url", "hash"}:
        query_type = ioc_type
    else:
        query_type = str(args.get("query_type") or "keyword")
    misp = args.get("misp") if isinstance(args.get("misp"), dict) else {}
    data = query_misp_ioc(
        indicator,
        query_type,
        misp_url=misp.get("url", ""),
        misp_key=misp.get("key", ""),
        verify_ssl=misp.get("verify_ssl", None),
        limit=max(1, min(int(args.get("limit") or 50), 200)),
    )
    return _ok("mantis.v1.misp_lookup_ioc", _limit(data), evidence=[{"id": "mantis:misp_lookup", "source": "MISP", "indicator": indicator}])


def tool_cti_search(args: Dict[str, Any]) -> Dict[str, Any]:
    query = str(args.get("query") or args.get("q") or "").strip()
    if not query:
        return _err("mantis.v1.cti_search", "query is required")
    limit = max(1, min(int(args.get("limit") or 20), 100))
    category = str(args.get("category") or "").strip()
    data = cti_query.query_cti_articles(query, limit=limit, category=category)
    evidence = [{"id": f"mantis:cti:{item.get('id')}", "source": item.get("source", "CTI Articles"), "title": item.get("title", "")} for item in data.get("results", [])[:20]]
    return _ok("mantis.v1.cti_search", data, evidence=evidence)


def _html_to_text(value: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", value or "", flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def tool_cti_article_get(args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        article_id = int(args.get("article_id") or args.get("id"))
    except (TypeError, ValueError):
        return _err("mantis.v1.cti_article_get", "article_id is required and must be an integer")
    data = cti_query.details(article_id)
    if data.get("error"):
        return _err("mantis.v1.cti_article_get", data["error"])
    include_html = bool(args.get("include_html"))
    content_text = _html_to_text(data.get("content_html", ""))
    out = dict(data)
    out["content_text"] = content_text[: max(1000, min(int(args.get("max_content_chars") or 20000), 80000))]
    if not include_html:
        out.pop("content_html", None)
    return _ok("mantis.v1.cti_article_get", _limit(out), evidence=[{"id": f"mantis:cti:{article_id}", "source": data.get("source", "CTI Articles"), "url": data.get("url", "")}])


def tool_extract_iocs(args: Dict[str, Any]) -> Dict[str, Any]:
    text = str(args.get("text") or "")
    if not text and args.get("article_id"):
        article = tool_cti_article_get({"article_id": args.get("article_id"), "max_content_chars": MAX_TEXT_CHARS})
        if not article.get("ok"):
            return article
        text = article.get("data", {}).get("content_text", "")
    text = text[:MAX_TEXT_CHARS]
    if not text.strip():
        return _err("mantis.v1.extract_iocs", "text or article_id is required")
    groups: Dict[str, List[Dict[str, str]]] = {}
    for itype, value, observed in extract_indicators(text):
        groups.setdefault(itype, []).append({"value": value, "observed": observed})
    counts = {key: len(value) for key, value in groups.items()}
    return _ok("mantis.v1.extract_iocs", {"counts": counts, "total": sum(counts.values()), "indicators": groups})


def tool_breach_feed_search(args: Dict[str, Any]) -> Dict[str, Any]:
    query = str(args.get("query") or args.get("q") or "").strip()
    source = str(args.get("source") or "").strip()
    page = max(1, int(args.get("page") or 1))
    page_size = max(1, min(int(args.get("page_size") or args.get("limit") or 20), 100))
    data = breach_watcher.get_breach_feed(page=page, page_size=page_size, query=query, source_filter=source)
    evidence = [
        {
            "id": f"mantis:breach:{idx + 1}",
            "source": item.get("source", "Breach Watcher"),
            "title": item.get("title", ""),
            "url": item.get("url", ""),
        }
        for idx, item in enumerate(data.get("items", [])[:20])
    ]
    return _ok("mantis.v1.breach_feed_search", data, evidence=evidence)


def tool_breach_stats(args: Dict[str, Any]) -> Dict[str, Any]:
    return _ok("mantis.v1.breach_stats", breach_watcher.get_breach_stats(), evidence=[{"id": "mantis:breach:stats", "source": "Breach Watcher"}])


def tool_yara_status(args: Dict[str, Any]) -> Dict[str, Any]:
    explorer_only = str(args.get("scope") or "").strip().lower() == "explorer"
    data = {**yara_engine_status(explorer_only=explorer_only), "limits": yara_scan_limits()}
    return _ok("mantis.v1.yara_status", data, evidence=[{"id": "mantis:yara:status", "source": "YARA"}])


def tool_yara_rule_search(args: Dict[str, Any]) -> Dict[str, Any]:
    query = str(args.get("query") or args.get("q") or "").strip()
    repo = str(args.get("repo") or "").strip()
    repos = _as_list(args.get("repos"), limit=30) or None
    limit = max(1, min(int(args.get("limit") or 100), 500))
    offset = max(0, int(args.get("offset") or 0))
    status = str(args.get("status") or "all")
    data = yara_search_rules(query, repo_id=repo, repos=repos, limit=limit, offset=offset, status=status, use_regex=bool(args.get("regex")))
    evidence = [
        {
            "id": f"mantis:yara:{item.get('repo') or item.get('repository') or ''}:{item.get('name') or item.get('rule') or idx}",
            "source": "YARA",
            "title": item.get("name") or item.get("rule") or "",
        }
        for idx, item in enumerate((data.get("items") or data.get("rules") or [])[:20])
        if isinstance(item, dict)
    ]
    return _ok("mantis.v1.yara_rule_search", data, evidence=evidence)


def tool_yara_rule_get(args: Dict[str, Any]) -> Dict[str, Any]:
    repo = str(args.get("repo") or "").strip()
    name = str(args.get("name") or args.get("rule") or "").strip()
    namespace = str(args.get("namespace") or "").strip()
    if not repo or not name:
        return _err("mantis.v1.yara_rule_get", "repo and name are required")
    data = yara_get_rule_source(repo, name, namespace)
    if data.get("error"):
        return _err("mantis.v1.yara_rule_get", data.get("error"))
    return _ok("mantis.v1.yara_rule_get", _limit(data), evidence=[{"id": f"mantis:yara:{repo}:{name}", "source": "YARA", "title": name}])


def tool_similarity_dashboard(args: Dict[str, Any]) -> Dict[str, Any]:
    return _ok("mantis.v1.similarity_dashboard", similarity_service.dashboard(), evidence=[{"id": "mantis:similarity:dashboard", "source": "MANTIS Similarity"}])


def tool_similarity_entities(args: Dict[str, Any]) -> Dict[str, Any]:
    data = similarity_service.list_entities()
    evidence = [
        {
            "id": f"mantis:similarity:entity:{item.get('id')}",
            "source": "MANTIS Similarity",
            "title": item.get("name", ""),
        }
        for item in data.get("entities", [])[:20]
        if isinstance(item, dict)
    ]
    return _ok("mantis.v1.similarity_entities", data, evidence=evidence)


def tool_similarity_entity_get(args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        entity_id = int(args.get("entity_id") or args.get("id"))
    except (TypeError, ValueError):
        return _err("mantis.v1.similarity_entity_get", "entity_id is required and must be an integer")
    data = similarity_service.get_entity(entity_id)
    if data.get("error"):
        return _err("mantis.v1.similarity_entity_get", data.get("error"))
    if bool(args.get("include_functions")):
        data["functions"] = similarity_service.get_entity_functions(entity_id, max(1, min(int(args.get("function_limit") or 100), 500)))
    if bool(args.get("include_code")):
        data["code"] = similarity_service.get_entity_code(entity_id)
    return _ok("mantis.v1.similarity_entity_get", _limit(data), evidence=[{"id": f"mantis:similarity:entity:{entity_id}", "source": "MANTIS Similarity", "title": data.get("name", "")}])


def tool_case_list(args: Dict[str, Any]) -> Dict[str, Any]:
    limit = max(1, min(int(args.get("limit") or 30), 100))
    data = ai_case_service.list_cases(limit=limit)
    evidence = [
        {
            "id": f"mantis:case:{item.get('case_id')}",
            "source": "MANTIS Case Workspace",
            "title": item.get("title", ""),
        }
        for item in data.get("cases", [])[:20]
        if isinstance(item, dict)
    ]
    return _ok("mantis.v1.case_list", data, evidence=evidence)


def tool_case_get(args: Dict[str, Any]) -> Dict[str, Any]:
    case_id = str(args.get("case_id") or args.get("id") or "").strip()
    if not case_id:
        return _err("mantis.v1.case_get", "case_id is required")
    try:
        data = ai_case_service.get_case(case_id)
    except ValueError as exc:
        return _err("mantis.v1.case_get", str(exc))
    return _ok("mantis.v1.case_get", _limit(data), evidence=[{"id": f"mantis:case:{case_id}", "source": "MANTIS Case Workspace", "title": data.get("title", "")}])


def tool_case_related(args: Dict[str, Any]) -> Dict[str, Any]:
    case_id = str(args.get("case_id") or args.get("id") or "").strip()
    if not case_id:
        return _err("mantis.v1.case_related", "case_id is required")
    limit = max(1, min(int(args.get("limit") or 10), 50))
    try:
        data = ai_case_service.related_cases(case_id, limit=limit)
    except ValueError as exc:
        return _err("mantis.v1.case_related", str(exc))
    return _ok("mantis.v1.case_related", data, evidence=[{"id": f"mantis:case:{case_id}:related", "source": "MANTIS Case Workspace"}])


def tool_case_report(args: Dict[str, Any]) -> Dict[str, Any]:
    case_id = str(args.get("case_id") or args.get("id") or "").strip()
    if not case_id:
        return _err("mantis.v1.case_report", "case_id is required")
    try:
        data = ai_case_service.draft_case_report(case_id)
    except ValueError as exc:
        return _err("mantis.v1.case_report", str(exc))
    return _ok("mantis.v1.case_report", _limit(data), evidence=[{"id": f"mantis:case:{case_id}:report", "source": "MANTIS Case Workspace"}])


def tool_permission_policy(args: Dict[str, Any]) -> Dict[str, Any]:
    return _ok("mantis.v1.permission_policy", bridge_policy(configured_permissions(), TOOLS.keys()))


COMMON_OBJECT_SCHEMA = {"type": "object", "additionalProperties": False, "properties": {}}
PROVIDER_KEYS_SCHEMA = {
    "type": "object",
    "description": "Optional provider API keys by provider id. Secrets are redacted from logs.",
    "additionalProperties": {"type": "string"},
}
MISP_CONFIG_SCHEMA = {
    "type": "object",
    "description": "Optional MISP connection override. Environment variables are used when omitted.",
    "additionalProperties": False,
    "properties": {
        "url": {"type": "string", "description": "MISP base URL."},
        "key": {"type": "string", "description": "MISP API key. Redacted from logs."},
        "verify_ssl": {"type": "boolean", "default": True},
    },
}
IOC_LOOKUP_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["indicator"],
    "properties": {
        "indicator": {"type": "string", "minLength": 1, "description": "Domain, IP, URL, hash, or keyword to investigate."},
        "indicator_type": {"type": "string", "enum": ["auto", "domain", "ip", "url", "hash", "keyword"], "default": "auto"},
        "sources": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional MANTIS provider/source ids to query. Empty means MANTIS default behavior.",
        },
        "provider_keys": PROVIDER_KEYS_SCHEMA,
        "misp": MISP_CONFIG_SCHEMA,
        "github_repos": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional GitHub repositories for GitHub-backed lookups.",
        },
        "query_type": {"type": "string", "description": "Keyword lookup subtype when indicator_type is keyword."},
    },
}
MISP_LOOKUP_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["indicator"],
    "properties": {
        "indicator": {"type": "string", "minLength": 1},
        "indicator_type": {"type": "string", "enum": ["auto", "domain", "ip", "url", "hash", "keyword"], "default": "auto"},
        "query_type": {"type": "string", "description": "Explicit MISP query type override."},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
        "misp": MISP_CONFIG_SCHEMA,
    },
}
CTI_SEARCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "query": {"type": "string", "minLength": 1, "description": "Keyword or IOC to search in local CTI articles."},
        "q": {"type": "string", "description": "Alias for query."},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
        "category": {"type": "string", "description": "Optional CTI category filter."},
    },
    "anyOf": [{"required": ["query"]}, {"required": ["q"]}],
}
CTI_ARTICLE_GET_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "article_id": {"type": "integer", "minimum": 1},
        "id": {"type": "integer", "minimum": 1, "description": "Alias for article_id."},
        "include_html": {"type": "boolean", "default": False},
        "max_content_chars": {"type": "integer", "minimum": 1000, "maximum": 80000, "default": 20000},
    },
    "anyOf": [{"required": ["article_id"]}, {"required": ["id"]}],
}
EXTRACT_IOCS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "text": {"type": "string", "description": "Text to extract IOCs from. Max 120k chars are processed."},
        "article_id": {"type": "integer", "minimum": 1, "description": "Optional CTI article id to extract from when text is omitted."},
    },
    "anyOf": [{"required": ["text"]}, {"required": ["article_id"]}],
}
BREACH_FEED_SEARCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "query": {"type": "string"},
        "q": {"type": "string", "description": "Alias for query."},
        "source": {"type": "string"},
        "page": {"type": "integer", "minimum": 1, "default": 1},
        "page_size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Alias for page_size."},
    },
}
YARA_STATUS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"scope": {"type": "string", "enum": ["", "explorer"], "default": ""}},
}
YARA_RULE_SEARCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "query": {"type": "string"},
        "q": {"type": "string", "description": "Alias for query."},
        "repo": {"type": "string"},
        "repos": {"type": "array", "items": {"type": "string"}},
        "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        "offset": {"type": "integer", "minimum": 0, "default": 0},
        "status": {"type": "string", "default": "all"},
        "regex": {"type": "boolean", "default": False},
    },
}
YARA_RULE_GET_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "repo": {"type": "string", "minLength": 1},
        "name": {"type": "string", "minLength": 1},
        "rule": {"type": "string", "description": "Alias for name."},
        "namespace": {"type": "string"},
    },
    "required": ["repo"],
    "anyOf": [{"required": ["name"]}, {"required": ["rule"]}],
}
SIMILARITY_ENTITY_GET_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "entity_id": {"type": "integer", "minimum": 1},
        "id": {"type": "integer", "minimum": 1, "description": "Alias for entity_id."},
        "include_functions": {"type": "boolean", "default": False},
        "function_limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        "include_code": {"type": "boolean", "default": False},
    },
    "anyOf": [{"required": ["entity_id"]}, {"required": ["id"]}],
}
CASE_LIST_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 30}},
}
CASE_ID_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "case_id": {"type": "string", "minLength": 1},
        "id": {"type": "string", "description": "Alias for case_id."},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
    },
    "anyOf": [{"required": ["case_id"]}, {"required": ["id"]}],
}

TOOLS: Dict[str, ToolSpec] = {
    "mantis.v1.provider_metadata": ToolSpec(
        "mantis.v1.provider_metadata",
        "Return MANTIS IOC provider metadata and source groups.",
        "read_only",
        tool_provider_metadata,
        COMMON_OBJECT_SCHEMA,
    ),
    "mantis.v1.permission_policy": ToolSpec(
        "mantis.v1.permission_policy",
        "Return the Hermes bridge permission, rate-limit, audit, and blocked-action policy.",
        "read_only",
        tool_permission_policy,
        COMMON_OBJECT_SCHEMA,
    ),
    "mantis.v1.ioc_lookup_auto": ToolSpec(
        "mantis.v1.ioc_lookup_auto",
        "Run a passive MANTIS IOC lookup for a domain, IP, URL, hash, or keyword.",
        "read_only",
        tool_ioc_lookup,
        IOC_LOOKUP_SCHEMA,
    ),
    "mantis.v1.misp_lookup_ioc": ToolSpec(
        "mantis.v1.misp_lookup_ioc",
        "Search configured MISP passively for IOC context, related indicators, tags, galaxies, sightings, warning lists, and event reports.",
        "read_only",
        tool_misp_lookup,
        MISP_LOOKUP_SCHEMA,
    ),
    "mantis.v1.cti_search": ToolSpec(
        "mantis.v1.cti_search",
        "Search local MANTIS CTI articles by keyword or IOC.",
        "read_only",
        tool_cti_search,
        CTI_SEARCH_SCHEMA,
    ),
    "mantis.v1.cti_article_get": ToolSpec(
        "mantis.v1.cti_article_get",
        "Fetch a local CTI article with metadata, text, and extracted intelligence.",
        "read_only",
        tool_cti_article_get,
        CTI_ARTICLE_GET_SCHEMA,
    ),
    "mantis.v1.extract_iocs": ToolSpec(
        "mantis.v1.extract_iocs",
        "Extract and normalize IOCs from provided text or a local CTI article id.",
        "read_only",
        tool_extract_iocs,
        EXTRACT_IOCS_SCHEMA,
    ),
    "mantis.v1.breach_feed_search": ToolSpec(
        "mantis.v1.breach_feed_search",
        "Search passive Breach Watcher feed records from configured breach and leak sources.",
        "read_only",
        tool_breach_feed_search,
        BREACH_FEED_SEARCH_SCHEMA,
    ),
    "mantis.v1.breach_stats": ToolSpec(
        "mantis.v1.breach_stats",
        "Return passive Breach Watcher aggregate statistics.",
        "read_only",
        tool_breach_stats,
        COMMON_OBJECT_SCHEMA,
    ),
    "mantis.v1.yara_status": ToolSpec(
        "mantis.v1.yara_status",
        "Return local YARA engine, repository, and scan-limit status without scanning files.",
        "read_only",
        tool_yara_status,
        YARA_STATUS_SCHEMA,
    ),
    "mantis.v1.yara_rule_search": ToolSpec(
        "mantis.v1.yara_rule_search",
        "Search local YARA rule metadata across configured repositories.",
        "read_only",
        tool_yara_rule_search,
        YARA_RULE_SEARCH_SCHEMA,
    ),
    "mantis.v1.yara_rule_get": ToolSpec(
        "mantis.v1.yara_rule_get",
        "Fetch a local YARA rule source by repository and rule name.",
        "read_only",
        tool_yara_rule_get,
        YARA_RULE_GET_SCHEMA,
    ),
    "mantis.v1.similarity_dashboard": ToolSpec(
        "mantis.v1.similarity_dashboard",
        "Return local sample similarity dashboard statistics.",
        "read_only",
        tool_similarity_dashboard,
        COMMON_OBJECT_SCHEMA,
    ),
    "mantis.v1.similarity_entities": ToolSpec(
        "mantis.v1.similarity_entities",
        "List local sample similarity entities and stored malware families/clusters.",
        "read_only",
        tool_similarity_entities,
        COMMON_OBJECT_SCHEMA,
    ),
    "mantis.v1.similarity_entity_get": ToolSpec(
        "mantis.v1.similarity_entity_get",
        "Fetch a local sample similarity entity, optionally including functions or code-derived features.",
        "read_only",
        tool_similarity_entity_get,
        SIMILARITY_ENTITY_GET_SCHEMA,
    ),
    "mantis.v1.case_list": ToolSpec(
        "mantis.v1.case_list",
        "List existing MANTIS case workspace records.",
        "read_only",
        tool_case_list,
        CASE_LIST_SCHEMA,
    ),
    "mantis.v1.case_get": ToolSpec(
        "mantis.v1.case_get",
        "Fetch an existing MANTIS case workspace record with observations, claims, pivots, timeline, and assessment.",
        "read_only",
        tool_case_get,
        CASE_ID_SCHEMA,
    ),
    "mantis.v1.case_related": ToolSpec(
        "mantis.v1.case_related",
        "Find cases related to an existing MANTIS case.",
        "read_only",
        tool_case_related,
        CASE_ID_SCHEMA,
    ),
    "mantis.v1.case_report": ToolSpec(
        "mantis.v1.case_report",
        "Draft a read-only report from an existing MANTIS case.",
        "read_only",
        tool_case_report,
        CASE_ID_SCHEMA,
    ),
}


def describe_tools() -> Dict[str, Any]:
    return {
        "tools": [
            {
                "name": spec.name,
                "description": spec.description,
                "permission": spec.permission,
                "input_schema": spec.input_schema,
                "tool_version": TOOL_VERSION,
            }
            for spec in TOOLS.values()
        ]
    }


def _schema_type_ok(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def _validate_schema(schema: Dict[str, Any], value: Any, path: str = "$") -> List[str]:
    errors: List[str] = []
    expected_type = schema.get("type")
    if expected_type and not _schema_type_ok(expected_type, value):
        return [f"{path} must be {expected_type}"]

    if "enum" in schema and value not in schema.get("enum", []):
        return [f"{path} must be one of: {', '.join(str(v) for v in schema.get('enum', []))}"]

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(f"{path} is too short")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(f"{path} is too long")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path} must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path} must be <= {schema['maximum']}")

    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                errors.extend(_validate_schema(item_schema, item, f"{path}[{idx}]"))

    if isinstance(value, dict):
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for required in schema.get("required") or []:
            if required not in value:
                errors.append(f"{path}.{required} is required")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                errors.append(f"{path} has unsupported argument(s): {', '.join(unknown)}")
        elif isinstance(schema.get("additionalProperties"), dict):
            extra_schema = schema["additionalProperties"]
            for key, item in value.items():
                if key not in properties:
                    errors.extend(_validate_schema(extra_schema, item, f"{path}.{key}"))
        for key, prop_schema in properties.items():
            if key in value and isinstance(prop_schema, dict):
                errors.extend(_validate_schema(prop_schema, value[key], f"{path}.{key}"))
        for option in schema.get("anyOf") or []:
            if isinstance(option, dict) and not _validate_schema(option, value, path):
                break
        else:
            if schema.get("anyOf"):
                labels = []
                for option in schema.get("anyOf") or []:
                    labels.extend(option.get("required") or [])
                errors.append(f"{path} must include one of: {', '.join(labels)}")
    return errors


def validate_arguments(spec: ToolSpec, arguments: Dict[str, Any]) -> List[str]:
    if not isinstance(arguments, dict):
        return ["arguments must be an object"]
    return _validate_schema(spec.input_schema or COMMON_OBJECT_SCHEMA, arguments)


def run_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    spec = TOOLS.get((name or "").strip())
    if not spec:
        return _err(name or "unknown", f"Unknown MANTIS agent tool: {name}")
    validation_errors = validate_arguments(spec, arguments or {})
    if validation_errors:
        return _err(spec.name, "Invalid tool arguments", {"validation_errors": validation_errors[:20]})
    try:
        return spec.handler(arguments or {})
    except Exception as exc:
        return _err(spec.name, f"Tool execution failed: {exc}")
