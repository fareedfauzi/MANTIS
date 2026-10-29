import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


PLACEHOLDER_RE = re.compile(
    r"^\s*(?:\[?(?:truncated(?:-depth)?|\d+\s+more\s+item\(s\)\s+omitted|omitted|redacted)\]?|__omitted_keys__?)\s*$",
    re.I,
)

CERT_SUPPORT_HOST_TERMS = ("ocsp", "crl", "aia")
CERT_SUPPORT_PATH_RE = re.compile(r"(?:^|/)(?:ocsp|crl|aia|certs?|pki)(?:/|$)|\.(?:cer|crt|crl|pem)(?:$|[?#])", re.I)

CA_AND_CERT_DOMAINS = {
    "verisign.com",
    "digicert.com",
    "comodoca.com",
    "comodo.com",
    "sectigo.com",
    "usertrust.com",
    "globalsign.com",
    "entrust.net",
    "entrust.com",
    "letsencrypt.org",
    "identrust.com",
    "amazontrust.com",
    "pki.goog",
    "msocsp.com",
}

REPORTING_AND_SANDBOX_DOMAINS = {
    "abuse.ch",
    "malwarebazaar.abuse.ch",
    "threatfox.abuse.ch",
    "urlhaus.abuse.ch",
    "virustotal.com",
    "alienvault.com",
    "otx.alienvault.com",
    "urlscan.io",
    "hybrid-analysis.com",
    "tria.ge",
    "any.run",
    "joesandbox.com",
}

SHARED_PLATFORM_DOMAINS = {
    "github.com",
    "github.io",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "cloudflare.com",
    "akamaihd.net",
    "fastly.net",
    "azureedge.net",
}

PUBLIC_RESOLVERS = {
    "1.0.0.1",
    "1.1.1.1",
    "8.8.4.4",
    "8.8.8.8",
    "9.9.9.9",
    "64.6.64.6",
    "64.6.65.6",
    "76.76.2.0",
    "76.76.10.0",
    "94.140.14.14",
    "94.140.15.15",
    "208.67.220.220",
    "208.67.222.222",
}

GENERIC_SEARCH_TERMS = {
    "malware",
    "tool",
    "threat actor",
    "apt",
    "unknown",
    "unidentified",
    "family",
    "actor",
    "cluster",
    "campaign",
}


def action_artifact(action: Dict[str, Any]) -> Dict[str, str]:
    tool = str((action or {}).get("tool") or "").strip()
    args = (action or {}).get("arguments") or {}
    if not isinstance(args, dict):
        args = {}
    if tool == "lookup_hash":
        return {"type": "hash", "value": str(args.get("hash") or "").strip().lower()}
    if tool == "lookup_domain":
        return {"type": "domain", "value": _clean_domain(args.get("domain"))}
    if tool == "lookup_ip":
        return {"type": "ip", "value": str(args.get("ip") or "").strip()}
    if tool == "lookup_url":
        return {"type": "url", "value": str(args.get("url") or "").strip()}
    if tool == "infra_search":
        return {"type": str(args.get("type") or "infra").strip().lower(), "value": str(args.get("value") or "").strip()}
    return {"type": "query", "value": str(args.get("query") or "").strip()}


def classify_action(action: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    artifact = action_artifact(action)
    tool = str((action or {}).get("tool") or "").strip()
    value = artifact.get("value", "")
    value_lower = value.lower()
    tags: List[str] = []

    if _is_placeholder(value):
        return _reject("Placeholder or truncated value is not a valid pivot.", artifact, ["placeholder"])

    if not value:
        return _reject("Pivot value is empty.", artifact, ["empty"])

    if tool in {"search_threat_actor", "search_malware", "search_cti_articles", "keyword_search", "search_yara"}:
        if value_lower in GENERIC_SEARCH_TERMS:
            return _reject("Generic search term is not specific enough for an analyst pivot.", artifact, ["generic"])
        return _allow(artifact, tags)

    if tool == "lookup_ip":
        ip_reason = _ip_rejection_reason(value)
        if ip_reason:
            return _reject(ip_reason, artifact, ["benign_or_non_routable_ip"])
        return _allow(artifact, tags)

    if tool == "lookup_domain":
        domain = _clean_domain(value)
        if _is_cert_support_host(domain):
            return _reject("Certificate support infrastructure is not a meaningful threat pivot by itself.", artifact, ["certificate_support"])
        if _domain_in(domain, REPORTING_AND_SANDBOX_DOMAINS):
            return _reject("Threat intel or sandbox provider domain should not be pivoted as suspect infrastructure.", artifact, ["provider_domain"])
        if _domain_in(domain, SHARED_PLATFORM_DOMAINS):
            return _reject("Shared platform/CDN domain is too broad unless a specific malicious path or account is present.", artifact, ["shared_platform"])
        return _allow(artifact, tags)

    if tool == "lookup_url":
        parsed = urlparse(value if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I) else f"http://{value}")
        host = _clean_domain(parsed.hostname or "")
        path = f"{parsed.path or ''}?{parsed.query or ''}"
        if _is_cert_support_host(host) or CERT_SUPPORT_PATH_RE.search(path):
            return _reject("Certificate AIA/OCSP/CRL URL is a trust-chain artifact, not an investigative threat pivot.", artifact, ["certificate_support_url"])
        if _domain_in(host, REPORTING_AND_SANDBOX_DOMAINS):
            return _reject("Threat intel or sandbox provider URL should not be pivoted as suspect infrastructure.", artifact, ["provider_url"])
        if _domain_in(host, SHARED_PLATFORM_DOMAINS) and not _has_distinctive_shared_path(parsed.path):
            return _reject("Shared platform URL lacks a distinctive malicious path or account.", artifact, ["shared_platform"])
        return _allow(artifact, tags)

    if tool == "infra_search":
        if str(artifact.get("type") or "").lower() in {"auto", "domain"}:
            domain = _clean_domain(value)
            if _is_cert_support_host(domain):
                return _reject("Certificate support infrastructure is not a meaningful infra pivot by itself.", artifact, ["certificate_support"])
        return _allow(artifact, tags)

    return _allow(artifact, tags)


def filter_actions(
    actions: Iterable[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
    limit: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    allowed: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    for action in actions or []:
        if not isinstance(action, dict):
            continue
        policy = classify_action(action, context=context)
        if policy.get("verdict") == "reject":
            rejected.append({
                "action": action,
                "reason": policy.get("reason", "Rejected by pivot policy."),
                "tags": policy.get("tags") or [],
                "artifact": policy.get("artifact") or action_artifact(action),
            })
            continue
        allowed.append(action)
        if limit and len(allowed) >= limit:
            break
    return allowed, rejected


def _allow(artifact: Dict[str, str], tags: List[str]) -> Dict[str, Any]:
    return {"verdict": "allow", "reason": "", "tags": tags, "artifact": artifact}


def _reject(reason: str, artifact: Dict[str, str], tags: List[str]) -> Dict[str, Any]:
    return {"verdict": "reject", "reason": reason, "tags": tags, "artifact": artifact}


def _is_placeholder(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    if PLACEHOLDER_RE.match(text):
        return True
    lowered = text.lower()
    return "[truncated-depth]" in lowered or "more item(s) omitted" in lowered


def _clean_domain(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("[.]", ".").replace("(.)", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
    if "://" in text:
        text = urlparse(text).hostname or text
    return text.strip(".")


def _domain_in(domain: str, candidates: Iterable[str]) -> bool:
    host = _clean_domain(domain)
    for candidate in candidates:
        base = _clean_domain(candidate)
        if host == base or host.endswith(f".{base}"):
            return True
    return False


def _is_cert_support_host(domain: str) -> bool:
    host = _clean_domain(domain)
    if _domain_in(host, CA_AND_CERT_DOMAINS):
        return True
    labels = host.split(".")
    return bool(labels and labels[0] in CERT_SUPPORT_HOST_TERMS)


def _has_distinctive_shared_path(path: str) -> bool:
    parts = [part for part in str(path or "").split("/") if part]
    return len(parts) >= 2 and any(len(part) >= 6 for part in parts)


def _ip_rejection_reason(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if str(parsed) in PUBLIC_RESOLVERS:
        return "Public resolver IP is normally benign shared infrastructure, not a meaningful threat pivot by itself."
    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
        return "Non-routable or reserved IP is not a useful external threat-intel pivot."
    return ""


def validate_candidate_pivot(
    candidate: Dict[str, Any],
    case: Optional[Dict[str, Any]] = None,
    max_depth: int = 3,
    current_depth: int = 1,
    current_pivot_count: int = 0,
    max_auto_pivots: int = 10,
) -> Dict[str, Any]:
    """
    Deterministically validates a candidate pivot from DISCOVER:
    - Verifies passive/read-only nature
    - Verifies pivot_type is registered
    - Validates indicator syntax
    - Deduplicates against root and previous pivots
    - Filters CA/OCSP, CDN, public DNS, and shared cloud noise
    - Enforces max depth and max auto-pivot budget limits
    """
    case = case or {}
    pivot_type = str(candidate.get("pivot_type") or "").strip().lower()
    value = str(candidate.get("value") or "").strip()
    reason = str(candidate.get("reason") or "").strip()
    supporting_evidence = candidate.get("supporting_evidence") or []

    # 1. Check budget and depth limits
    if current_depth > max_depth:
        return {
            "verdict": "reject",
            "reason": f"Maximum investigation depth ({max_depth}) reached.",
            "tags": ["depth_limit"],
            "pivot_type": pivot_type,
            "value": value,
        }
    if current_pivot_count >= max_auto_pivots:
        return {
            "verdict": "reject",
            "reason": f"Maximum auto-pivot budget ({max_auto_pivots}) reached.",
            "tags": ["budget_limit"],
            "pivot_type": pivot_type,
            "value": value,
        }

    # 2. Check placeholder / empty
    if not value or _is_placeholder(value):
        return {
            "verdict": "reject",
            "reason": "Indicator value is empty or an artifact placeholder.",
            "tags": ["placeholder"],
            "pivot_type": pivot_type,
            "value": value,
        }

    # 3. Check registered pivot type
    from ai_pivot_registry import get_pivot_definition, is_valid_pivot_type
    if not is_valid_pivot_type(pivot_type):
        return {
            "verdict": "reject",
            "reason": f"Pivot type '{pivot_type}' is not supported in the passive pivot registry.",
            "tags": ["unsupported_pivot_type"],
            "pivot_type": pivot_type,
            "value": value,
        }

    defn = get_pivot_definition(pivot_type)
    expected_input = (defn or {}).get("input_type", "auto")

    # 4. Indicator syntax check
    from intel_query import is_domain, is_hash, is_ip, is_url, normalize_domain, normalize_ip
    val_clean = value
    if expected_input == "hash":
        val_clean = value.lower()
        if not is_hash(val_clean):
            return {
                "verdict": "reject",
                "reason": f"'{value}' is not a syntactically valid cryptographic hash.",
                "tags": ["invalid_syntax"],
                "pivot_type": pivot_type,
                "value": value,
            }
    elif expected_input == "ip":
        val_clean = normalize_ip(value)
        if not is_ip(val_clean):
            return {
                "verdict": "reject",
                "reason": f"'{value}' is not a valid IP address.",
                "tags": ["invalid_syntax"],
                "pivot_type": pivot_type,
                "value": value,
            }
        ip_reason = _ip_rejection_reason(val_clean)
        if ip_reason:
            return {
                "verdict": "reject",
                "reason": ip_reason,
                "tags": ["benign_or_non_routable_ip"],
                "pivot_type": pivot_type,
                "value": value,
            }
    elif expected_input == "domain":
        val_clean = normalize_domain(value)
        if not is_domain(val_clean):
            return {
                "verdict": "reject",
                "reason": f"'{value}' is not a valid domain name.",
                "tags": ["invalid_syntax"],
                "pivot_type": pivot_type,
                "value": value,
            }
        domain = _clean_domain(val_clean)
        if _is_cert_support_host(domain):
            return {
                "verdict": "reject",
                "reason": "Certificate support infrastructure is not an investigative threat pivot.",
                "tags": ["certificate_support"],
                "pivot_type": pivot_type,
                "value": value,
            }
        if _domain_in(domain, REPORTING_AND_SANDBOX_DOMAINS):
            return {
                "verdict": "reject",
                "reason": "Threat intel / sandbox provider domain should not be pivoted.",
                "tags": ["provider_domain"],
                "pivot_type": pivot_type,
                "value": value,
            }
        if _domain_in(domain, SHARED_PLATFORM_DOMAINS):
            return {
                "verdict": "reject",
                "reason": "Shared platform/CDN domain is too broad for an autonomous pivot.",
                "tags": ["shared_platform"],
                "pivot_type": pivot_type,
                "value": value,
            }
        generic_clouds = {
            "amazonaws.com", "azure.com", "microsoft.com", "google.com",
            "googleapis.com", "1e100.net", "cloudfront.net", "appspot.com",
            "windows.net", "live.com", "office.com"
        }
        for gc in generic_clouds:
            if domain == gc or domain.endswith(f".{gc}"):
                return {
                    "verdict": "reject",
                    "reason": "Shared cloud infrastructure provider domain is not a distinctive threat pivot.",
                    "tags": ["shared_platform"],
                    "pivot_type": pivot_type,
                    "value": value,
                }
    elif expected_input == "url":
        if not is_url(value):
            return {
                "verdict": "reject",
                "reason": f"'{value}' is not a valid URL.",
                "tags": ["invalid_syntax"],
                "pivot_type": pivot_type,
                "value": value,
            }
    elif expected_input == "infra":
        is_asn = bool(re.fullmatch(r"(?i)AS\d{1,10}", value.strip()))
        is_cidr = "/" in value.strip() and not is_url(value)
        is_cert = bool(re.fullmatch(r"[0-9a-fA-F:]{32,64}", value.strip()))
        if not (is_asn or is_cidr or is_cert or is_ip(normalize_ip(value)) or is_domain(normalize_domain(value))):
            return {
                "verdict": "reject",
                "reason": f"'{value}' is not a valid infrastructure identifier (ASN, CIDR, certificate, or network host).",
                "tags": ["invalid_syntax"],
                "pivot_type": pivot_type,
                "value": value,
            }
    elif expected_input == "keyword":
        if value.lower() in GENERIC_SEARCH_TERMS:
            return {
                "verdict": "reject",
                "reason": f"Generic search term '{value}' is not distinctive enough for an autonomous pivot.",
                "tags": ["generic"],
                "pivot_type": pivot_type,
                "value": value,
            }

    # 5. Deduplication against case root and prior pivots
    root_val = str((case.get("root") or {}).get("value") or "").strip().lower()
    if val_clean.lower() == root_val:
        return {
            "verdict": "reject",
            "reason": "Candidate indicator is identical to the root investigation artifact.",
            "tags": ["duplicate_root"],
            "pivot_type": pivot_type,
            "value": value,
        }

    # Check prior executed pivots in case
    prior_pivots = case.get("pivots") or []
    for p in prior_pivots:
        p_val = str(p.get("value") or "").strip().lower()
        p_type = str(p.get("pivot_type") or "").strip().lower()
        if p_val == val_clean.lower() and p_type == pivot_type:
            return {
                "verdict": "reject",
                "reason": f"Indicator '{val_clean}' was already investigated via '{pivot_type}'.",
                "tags": ["duplicate_pivot"],
                "pivot_type": pivot_type,
                "value": value,
            }

    return {
        "verdict": "allow",
        "reason": reason or "Candidate pivot verified as a valid, distinctive passive inquiry.",
        "tags": ["verified_passive"],
        "pivot_type": pivot_type,
        "value": val_clean,
        "supporting_evidence": supporting_evidence,
    }
