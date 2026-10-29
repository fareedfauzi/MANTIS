import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Tuple

from intel_query import is_domain, is_hash, is_ip, is_url, normalize_domain, normalize_ip, normalize_url


CATEGORY_MALWARE = "MALWARE"
CATEGORY_INFRA = "INFRASTRUCTURE"
CATEGORY_CONFIG = "CONFIGURATION"
CATEGORY_PROTOCOL = "PROTOCOL"
CATEGORY_DEV = "DEVELOPER_ARTIFACT"
CATEGORY_BEHAVIOR = "BEHAVIOR"
CATEGORY_TTP = "TTP"
CATEGORY_VICTIM = "VICTIMOLOGY"
CATEGORY_CTI = "CTI_REFERENCE"

STRONG = "STRONG"
SUPPORTING = "SUPPORTING"
WEAK = "WEAK"
CONTRADICTING = "CONTRADICTING"

COMMON_VALUES = {
    "mozilla/5.0", "windows", "microsoft", "https", "http", "tcp", "udp",
    "cloudflare", "namecheap", "godaddy", "let's encrypt", "lets encrypt",
    "msvc", "visual studio", "plugx", "cobalt strike", "t1059",
}

HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{96}\b|\b[a-fA-F0-9]{128}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)
PDB_RE = re.compile(r"[A-Za-z]:\\[^\"'\n\r]{3,}\.pdb|[^\"'\s/\\]+\.pdb", re.I)
PATH_RE = re.compile(r"/[A-Za-z0-9_.~%/-]{4,}", re.I)
UA_RE = re.compile(r"(?:Mozilla/[^\n\r\"']+|[A-Za-z0-9_.-]+/[0-9][A-Za-z0-9_.-]*)")
MUTEX_RE = re.compile(r"(?:mutex|mutant|named[_ -]?pipe|pipe)[\"'\s:=/-]+([A-Za-z0-9_.{}()[\]-]{4,120})", re.I)
CONFIG_TEXT_RE = re.compile(
    r"(?:config(?:uration)?[_ -]?(?:key|value|marker)?|campaign[_ -]?id|c2[_ -]?key)[\"'\s:=/-]+([A-Za-z0-9_.{}()[\]-]{5,160})",
    re.I,
)

FEATURE_RULES = {
    "hash": (CATEGORY_MALWARE, "exact_hash_overlap", STRONG, "high"),
    "domain": (CATEGORY_INFRA, "shared_domain", SUPPORTING, "medium"),
    "ip": (CATEGORY_INFRA, "shared_ip", SUPPORTING, "medium"),
    "url": (CATEGORY_INFRA, "shared_url", SUPPORTING, "medium"),
    "certificate": (CATEGORY_INFRA, "shared_certificate", SUPPORTING, "medium"),
    "pdns": (CATEGORY_INFRA, "passive_dns_overlap", SUPPORTING, "medium"),
    "favicon_hash": (CATEGORY_INFRA, "shared_favicon_hash", SUPPORTING, "medium"),
    "jarm": (CATEGORY_PROTOCOL, "shared_jarm", SUPPORTING, "medium"),
    "ja3": (CATEGORY_PROTOCOL, "shared_ja3", SUPPORTING, "medium"),
    "ja4": (CATEGORY_PROTOCOL, "shared_ja4", SUPPORTING, "medium"),
    "protocol": (CATEGORY_PROTOCOL, "shared_protocol", STRONG, "high"),
    "config": (CATEGORY_CONFIG, "shared_config_value", STRONG, "high"),
    "config_key": (CATEGORY_CONFIG, "shared_config_key", STRONG, "high"),
    "campaign": (CATEGORY_CONFIG, "shared_campaign_identifier", STRONG, "high"),
    "pdb": (CATEGORY_DEV, "shared_pdb_artifact", STRONG, "high"),
    "mutex": (CATEGORY_BEHAVIOR, "shared_mutex_or_pipe", SUPPORTING, "medium"),
    "pipe": (CATEGORY_BEHAVIOR, "shared_mutex_or_pipe", SUPPORTING, "medium"),
    "user_agent": (CATEGORY_PROTOCOL, "shared_user_agent", SUPPORTING, "medium"),
    "uri_path": (CATEGORY_PROTOCOL, "shared_uri_path", SUPPORTING, "medium"),
    "yara": (CATEGORY_MALWARE, "shared_yara_match", SUPPORTING, "medium"),
    "tlsh": (CATEGORY_MALWARE, "shared_tlsh", SUPPORTING, "medium"),
    "ssdeep": (CATEGORY_MALWARE, "shared_ssdeep", SUPPORTING, "medium"),
    "imphash": (CATEGORY_MALWARE, "shared_imphash", SUPPORTING, "medium"),
    "rich_hash": (CATEGORY_MALWARE, "shared_rich_pe_hash", SUPPORTING, "medium"),
    "attack": (CATEGORY_TTP, "shared_attack_technique", WEAK, "low"),
    "malware_family": (CATEGORY_MALWARE, "shared_malware_family", WEAK, "low"),
    "asn": (CATEGORY_INFRA, "shared_asn", WEAK, "low"),
    "registrar": (CATEGORY_INFRA, "shared_registrar", WEAK, "low"),
    "country": (CATEGORY_VICTIM, "shared_country", WEAK, "low"),
    "cti_reference": (CATEGORY_CTI, "shared_cti_reference", SUPPORTING, "medium"),
}

CONTRADICTION_FEATURES = {
    "protocol": "protocol_mismatch",
    "architecture": "architecture_mismatch",
    "config_schema": "config_schema_mismatch",
    "victimology": "victimology_mismatch",
    "code_lineage": "code_lineage_mismatch",
}


def stable_id(*parts: Any) -> str:
    raw = json.dumps(parts, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def norm(value: Any) -> str:
    text = str(value or "").strip()
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", text, flags=re.I)
    text = re.sub(r"\s+", " ", text).strip()
    if is_hash(text):
        return text.lower()
    if is_ip(text):
        return normalize_ip(text)
    if is_url(text):
        return normalize_url(text)
    if is_domain(text):
        return normalize_domain(text).lower()
    return text.lower()


def is_common(value: Any) -> bool:
    value = norm(value)
    return not value or value in COMMON_VALUES or len(value) < 4


def merge_sources(values: List[Any]) -> List[str]:
    out = []
    for item in values:
        if isinstance(item, list):
            out.extend(merge_sources(item))
        elif item:
            text = str(item)[:120]
            if text not in out:
                out.append(text)
    return out[:20]


def collect_sources(value: Any) -> List[str]:
    found: List[str] = []

    def add(item: Any) -> None:
        for src in merge_sources([item]):
            if src and src not in found:
                found.append(src)

    def walk_sources(node: Any, path: str = "") -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                key_l = str(key).lower()
                if key_l in {"source", "sources", "provider", "providers", "repository", "feed", "engine"}:
                    add(child)
                walk_sources(child, f"{path}.{key_l}" if path else key_l)
        elif isinstance(node, list):
            for child in node[:200]:
                walk_sources(child, path)

    walk_sources(value)
    return found[:20]


def parse_time(value: Any) -> str:
    if not value:
        return ""
    text = str(value)
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt).date().isoformat()
        except ValueError:
            pass
    return text[:40]


def add_feature(features: Dict[str, List[Dict[str, Any]]], kind: str, value: Any,
                source: str = "", first_seen: Any = "", last_seen: Any = "", details: Dict[str, Any] = None) -> None:
    value_norm = norm(value)
    if not value_norm:
        return
    features.setdefault(kind, [])
    key = (kind, value_norm)
    for item in features[kind]:
        if (item["kind"], item["value"]) == key:
            item["sources"] = merge_sources([item.get("sources", []), source])
            return
    features[kind].append({
        "kind": kind,
        "value": value_norm,
        "sources": merge_sources([source]),
        "first_seen": parse_time(first_seen),
        "last_seen": parse_time(last_seen),
        "details": details or {},
    })


def add_pdb_features(features: Dict[str, List[Dict[str, Any]]], value: Any, source: str = "") -> None:
    text = str(value or "").strip()
    if not text:
        return
    add_feature(features, "pdb", text, source)
    parts = [part for part in re.split(r"[\\/]+", text) if part]
    if parts:
        add_feature(features, "pdb", parts[-1], source)
    if len(parts) >= 2:
        add_feature(features, "pdb", "/".join(parts[-2:]), source)


def walk(value: Any, path: str = ""):
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from walk(child, child_path)
    elif isinstance(value, list):
        for idx, child in enumerate(value[:500]):
            yield from walk(child, f"{path}[{idx}]")
    else:
        yield path, value


def extract_features(entity: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    data = entity.get("data", entity)
    features: Dict[str, List[Dict[str, Any]]] = {}
    blob = json.dumps(data, ensure_ascii=True, default=str)
    source_hint = merge_sources([entity.get("source"), collect_sources(data), entity.get("label"), entity.get("id")])
    if not source_hint:
        source_hint = ["MANTIS local evidence"]

    for match in HASH_RE.findall(blob):
        add_feature(features, "hash", match, source_hint)
    for match in URL_RE.findall(blob):
        add_feature(features, "url", match, source_hint)
        try:
            for path in PATH_RE.findall(match):
                add_feature(features, "uri_path", path, source_hint)
        except Exception:
            pass
    for match in IP_RE.findall(blob):
        parts = match.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            add_feature(features, "ip", match, source_hint)
    for match in DOMAIN_RE.findall(blob):
        if not match.lower().endswith((".local", ".example", ".test", ".pdb")):
            add_feature(features, "domain", match, source_hint)
    for match in PDB_RE.findall(blob):
        add_pdb_features(features, match, source_hint)
    for match in MUTEX_RE.findall(blob):
        add_feature(features, "mutex", match, source_hint)
    for match in CONFIG_TEXT_RE.findall(blob):
        if not is_common(match):
            add_feature(features, "config", match, source_hint)

    for path, value in walk(data):
        key = path.lower()
        if isinstance(value, dict):
            artifact_type = norm(value.get("type") or value.get("kind") or "")
            artifact_value = value.get("value")
            if artifact_type and artifact_value and artifact_type in FEATURE_RULES:
                add_feature(features, artifact_type, artifact_value, source_hint)
            continue
        if isinstance(value, list):
            continue
        value_text = str(value or "").strip()
        if not value_text:
            continue
        src = source_hint
        if "source" in key or "provider" in key or "repository" in key:
            continue
        if "sources" in key and isinstance(value, str):
            src = value

        if any(k in key for k in ("cert", "certificate", "sha1_fingerprint", "fingerprint_sha1")):
            if len(norm(value_text)) >= 16 and not is_common(value_text):
                add_feature(features, "certificate", value_text, src)
        elif "favicon" in key or "icon_hash" in key:
            add_feature(features, "favicon_hash", value_text, src)
        elif "jarm" in key:
            add_feature(features, "jarm", value_text, src)
        elif "ja3" in key:
            add_feature(features, "ja3", value_text, src)
        elif "ja4" in key:
            add_feature(features, "ja4", value_text, src)
        elif "tlsh" in key:
            add_feature(features, "tlsh", value_text, src)
        elif "ssdeep" in key:
            add_feature(features, "ssdeep", value_text, src)
        elif "imphash" in key:
            add_feature(features, "imphash", value_text, src)
        elif "rich" in key and "hash" in key:
            add_feature(features, "rich_hash", value_text, src)
        elif "pdb" in key or "debug" in key:
            add_pdb_features(features, value_text, src)
        elif "mutex" in key:
            add_feature(features, "mutex", value_text, src)
        elif "pipe" in key:
            add_feature(features, "pipe", value_text, src)
        elif "user_agent" in key or "user-agent" in key:
            add_feature(features, "user_agent", value_text, src)
        elif "uri" in key or "path" in key or "endpoint" in key:
            if value_text.startswith("/") and len(value_text) > 4:
                add_feature(features, "uri_path", value_text, src)
        elif "campaign" in key:
            add_feature(features, "campaign", value_text, src)
        elif "config" in key or "configuration" in key or "c2" in key:
            if not is_common(value_text):
                add_feature(features, "config", value_text, src)
        elif "yara" in key or "rule" in key:
            add_feature(features, "yara", value_text, src)
        elif "attack" in key or "mitre" in key or re.fullmatch(r"T\d{4}(?:\.\d{3})?", value_text, re.I):
            add_feature(features, "attack", value_text, src)
        elif "family" in key or "malware" in key:
            add_feature(features, "malware_family", value_text, src)
        elif key.endswith("asn") or ".asn" in key:
            add_feature(features, "asn", value_text, src)
        elif "registrar" in key:
            add_feature(features, "registrar", value_text, src)
        elif "country" in key:
            add_feature(features, "country", value_text, src)
        elif "article" in key or "report" in key or "cti" in key:
            add_feature(features, "cti_reference", value_text, src)
        elif key.endswith("protocol") or ".protocol" in key:
            add_feature(features, "protocol", value_text, src)
        elif "arch" in key:
            add_feature(features, "architecture", value_text, src)
        elif "schema" in key and "config" in key:
            add_feature(features, "config_schema", value_text, src)
        elif "victim" in key or "sector" in key:
            add_feature(features, "victimology", value_text, src)
        elif "lineage" in key:
            add_feature(features, "code_lineage", value_text, src)

    return features


def entity_id(entity: Dict[str, Any], index: int) -> str:
    return str(entity.get("id") or entity.get("label") or f"entity_{index + 1}")


def evidence_from_overlap(kind: str, value: str, entities: List[str], items: List[Dict[str, Any]]) -> Dict[str, Any]:
    category, ev_type, strength, distinctiveness = FEATURE_RULES.get(kind, (CATEGORY_CONFIG, f"shared_{kind}", SUPPORTING, "medium"))
    if is_common(value):
        strength = WEAK
        distinctiveness = "low"
    sources = merge_sources([item.get("sources", []) for item in items])
    first_seen_values = [item.get("first_seen") for item in items if item.get("first_seen")]
    last_seen_values = [item.get("last_seen") for item in items if item.get("last_seen")]
    ev_id = stable_id(category, ev_type, sorted(entities), value)
    return {
        "id": ev_id,
        "category": category,
        "type": ev_type,
        "entities": sorted(entities),
        "value": value,
        "strength": strength,
        "distinctiveness": distinctiveness,
        "sources": sources,
        "first_seen": min(first_seen_values) if first_seen_values else "",
        "last_seen": max(last_seen_values) if last_seen_values else "",
        "details": {"feature_kind": kind, "provider_count": len(sources)},
        "analyst_mark": "",
        "analyst_note": "",
    }


def contradiction_evidence(kind: str, entity_values: Dict[str, List[str]]) -> Dict[str, Any]:
    ev_type = CONTRADICTION_FEATURES[kind]
    details = {entity: sorted(values) for entity, values in entity_values.items()}
    return {
        "id": stable_id(CONTRADICTING, ev_type, details),
        "category": CATEGORY_PROTOCOL if kind == "protocol" else CATEGORY_CONFIG,
        "type": ev_type,
        "entities": sorted(entity_values),
        "value": kind,
        "strength": CONTRADICTING,
        "distinctiveness": "medium",
        "sources": ["MANTIS correlation"],
        "first_seen": "",
        "last_seen": "",
        "details": details,
        "analyst_mark": "",
        "analyst_note": "",
    }


def apply_overrides(evidence: List[Dict[str, Any]], overrides: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    out = []
    for item in evidence:
        mark = overrides.get(item["id"], {})
        if mark:
            item = dict(item)
            item["analyst_mark"] = mark.get("mark", "")
            item["analyst_note"] = mark.get("note", "")
        if item.get("analyst_mark") in {"false_positive", "not_relevant"}:
            continue
        out.append(item)
    return out


def classify_relationship(evidence: List[Dict[str, Any]]) -> Tuple[str, str, Dict[str, int]]:
    counts = {STRONG: 0, SUPPORTING: 0, WEAK: 0, CONTRADICTING: 0}
    categories = set()
    for item in evidence:
        counts[item["strength"]] = counts.get(item["strength"], 0) + 1
        if item["strength"] in {STRONG, SUPPORTING}:
            categories.add(item["category"])
    if counts[CONTRADICTING] and counts[CONTRADICTING] >= counts[STRONG] + counts[SUPPORTING]:
        return "CONTRADICTORY", "Contradicting evidence outweighs the supporting technical overlap.", counts
    if counts[STRONG] >= 2 and len(categories) >= 2:
        return "STRONG_RELATIONSHIP", "At least two strong overlaps from different categories were found.", counts
    if counts[STRONG] >= 1 and counts[SUPPORTING] >= 3 and len(categories) >= 3:
        return "STRONG_RELATIONSHIP", "One strong overlap plus three supporting overlaps across three categories were found.", counts
    if counts[STRONG] >= 1 and counts[SUPPORTING] >= 1:
        return "MODERATE_RELATIONSHIP", "A strong overlap is supported by additional evidence.", counts
    if counts[SUPPORTING] >= 3 and len(categories) >= 2:
        return "MODERATE_RELATIONSHIP", "At least three supporting overlaps across multiple categories were found.", counts
    if counts[SUPPORTING] or counts[WEAK]:
        return "WEAK_RELATIONSHIP", "Only supporting or weak overlap exists; treat as a lead, not a cluster.", counts
    return "INSUFFICIENT_EVIDENCE", "No meaningful technical overlap was found.", counts


def cluster_candidate(evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    usable = [e for e in evidence if e["strength"] in {STRONG, SUPPORTING}]
    categories = {e["category"] for e in usable}
    strong = [e for e in usable if e["strength"] == STRONG]
    supporting = [e for e in usable if e["strength"] == SUPPORTING]
    qualifies = (len(strong) >= 1 and len(supporting) >= 1) or (len(supporting) >= 3 and len(categories) >= 3)
    members = sorted({ent for e in usable for ent in e["entities"]})
    return {
        "cluster_id": stable_id("cluster", members, [e["id"] for e in usable]) if qualifies else "",
        "suggested": qualifies,
        "members": members if qualifies else [],
        "evidence": [e["id"] for e in usable[:20]] if qualifies else [],
        "strong_count": len(strong),
        "supporting_count": len(supporting),
        "contradicting_count": len([e for e in evidence if e["strength"] == CONTRADICTING]),
        "category_count": len(categories),
    }


def compare_entities(entities: List[Dict[str, Any]], overrides: Dict[str, Dict[str, str]] = None) -> Dict[str, Any]:
    overrides = overrides or {}
    entity_features: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for idx, entity in enumerate(entities[:8]):
        eid = entity_id(entity, idx)
        entity_features[eid] = extract_features(entity)

    evidence_by_key: Dict[Tuple[str, str, Tuple[str, ...]], Dict[str, Any]] = {}
    kinds = sorted({kind for features in entity_features.values() for kind in features})
    for kind in kinds:
        value_map: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        for eid, features in entity_features.items():
            for item in features.get(kind, []):
                value_map.setdefault(item["value"], []).append((eid, item))
        for value, pairs in value_map.items():
            entities_with_value = sorted({eid for eid, _ in pairs})
            if len(entities_with_value) < 2:
                continue
            ev = evidence_from_overlap(kind, value, entities_with_value, [item for _, item in pairs])
            key = (ev["category"], ev["type"], tuple(ev["entities"]), ev["value"])
            if key in evidence_by_key:
                evidence_by_key[key]["sources"] = merge_sources([evidence_by_key[key].get("sources", []), ev.get("sources", [])])
            else:
                evidence_by_key[key] = ev

    for kind in CONTRADICTION_FEATURES:
        values_by_entity = {
            eid: sorted({item["value"] for item in features.get(kind, [])})
            for eid, features in entity_features.items()
        }
        present = {eid: vals for eid, vals in values_by_entity.items() if vals}
        if len(present) >= 2 and len({tuple(vals) for vals in present.values()}) > 1:
            ev = contradiction_evidence(kind, present)
            evidence_by_key[(ev["category"], ev["type"], tuple(ev["entities"]), ev["value"])] = ev

    evidence = list(evidence_by_key.values())
    evidence = apply_overrides(evidence, overrides)
    order = {STRONG: 0, SUPPORTING: 1, CONTRADICTING: 2, WEAK: 3}
    evidence.sort(key=lambda e: (order.get(e["strength"], 9), e["category"], e["type"], e["value"]))
    relationship, reason, counts = classify_relationship(evidence)
    top = {
        STRONG: [e for e in evidence if e["strength"] == STRONG][:8],
        SUPPORTING: [e for e in evidence if e["strength"] == SUPPORTING][:8],
        WEAK: [e for e in evidence if e["strength"] == WEAK][:6],
        CONTRADICTING: [e for e in evidence if e["strength"] == CONTRADICTING][:8],
    }
    return {
        "relationship": relationship,
        "assessment_reason": reason,
        "counts": counts,
        "evidence": evidence[:100],
        "top_evidence": top,
        "cluster_candidate": cluster_candidate(evidence),
        "entities": [{"id": eid, "feature_counts": {k: len(v) for k, v in features.items()}} for eid, features in entity_features.items()],
        "notes": [
            "Correlation suggests possible shared activity only; it is not threat actor attribution.",
            "Weak/common artifacts are retained as context but are not enough to create a cluster.",
        ],
    }
