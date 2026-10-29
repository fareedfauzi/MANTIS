import json
from typing import Any, Dict, List, Tuple

import ai_correlation as correlation


MODEL_VERSION = 1

ATTRIBUTION_WEIGHTS = {
    correlation.CATEGORY_MALWARE: 25.0,
    correlation.CATEGORY_CONFIG: 20.0,
    correlation.CATEGORY_PROTOCOL: 15.0,
    correlation.CATEGORY_INFRA: 15.0,
    correlation.CATEGORY_DEV: 10.0,
    correlation.CATEGORY_TTP: 5.0,
    correlation.CATEGORY_VICTIM: 5.0,
    "TEMPORAL": 5.0,
    correlation.CATEGORY_CTI: 5.0,
    "OPERATIONAL_PATTERN": 5.0,
}

STRENGTH_MULTIPLIERS = {
    correlation.STRONG: 1.0,
    correlation.SUPPORTING: 0.55,
    correlation.WEAK: 0.15,
}

DISTINCTIVENESS_MULTIPLIERS = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.2,
    "unknown": 0.4,
    "": 0.4,
}

CONTRADICTION_PENALTIES = {
    "major": 22.0,
    "moderate": 12.0,
    "minor": 5.0,
}

REQUIRED_CATEGORIES = [
    correlation.CATEGORY_MALWARE,
    correlation.CATEGORY_CONFIG,
    correlation.CATEGORY_PROTOCOL,
    correlation.CATEGORY_INFRA,
    correlation.CATEGORY_DEV,
]


def clamp_score(value: float) -> int:
    return int(round(max(0.0, min(100.0, value))))


def candidate_id(candidate: Dict[str, Any], index: int = 0) -> str:
    return str(
        candidate.get("candidate_id")
        or candidate.get("id")
        or candidate.get("uuid")
        or candidate.get("name")
        or candidate.get("candidate_name")
        or f"candidate_{index + 1}"
    )


def candidate_name(candidate: Dict[str, Any], index: int = 0) -> str:
    return str(candidate.get("candidate_name") or candidate.get("name") or candidate.get("label") or candidate_id(candidate, index))


def normalize_candidate(candidate: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    data = candidate.get("data") if isinstance(candidate.get("data"), dict) else candidate
    cid = candidate_id(candidate, index)
    name = candidate_name(candidate, index)
    ctype = str(candidate.get("candidate_type") or candidate.get("type") or data.get("entity") or data.get("group") or "candidate")
    source = str(candidate.get("source") or data.get("galaxy_label") or data.get("source") or "MANTIS knowledge")
    return {
        "candidate_id": cid,
        "candidate_name": name,
        "candidate_type": ctype,
        "source": source,
        "data": data,
    }


def evidence_category(evidence: Dict[str, Any]) -> str:
    return str(evidence.get("category") or "OPERATIONAL_PATTERN")


def contribution_for_evidence(evidence: Dict[str, Any], category_cap: float) -> float:
    strength = str(evidence.get("strength") or "")
    distinctiveness = str(evidence.get("distinctiveness") or "unknown").lower()
    return category_cap * STRENGTH_MULTIPLIERS.get(strength, 0.0) * DISTINCTIVENESS_MULTIPLIERS.get(distinctiveness, 0.4)


def contradiction_severity(evidence: Dict[str, Any]) -> str:
    distinctiveness = str(evidence.get("distinctiveness") or "").lower()
    ev_type = str(evidence.get("type") or "").lower()
    if "lineage" in ev_type or "timeline" in ev_type:
        return "major"
    if distinctiveness == "high":
        return "major"
    if distinctiveness == "low":
        return "minor"
    return "moderate"


def assessment_band(score: int, contradictions: List[Dict[str, Any]]) -> str:
    major = any(item.get("severity") == "major" for item in contradictions)
    if score >= 80:
        band = "VERY_STRONG_ALIGNMENT"
    elif score >= 60:
        band = "STRONG_ALIGNMENT"
    elif score >= 40:
        band = "MODERATE_ALIGNMENT"
    elif score >= 20:
        band = "WEAK_ALIGNMENT"
    else:
        band = "INSUFFICIENT_EVIDENCE"
    if major and band in {"VERY_STRONG_ALIGNMENT", "STRONG_ALIGNMENT"}:
        return "MODERATE_ALIGNMENT_REQUIRES_REVIEW"
    return band


def missing_evidence(category_scores: Dict[str, Dict[str, Any]]) -> List[str]:
    missing = []
    labels = {
        correlation.CATEGORY_MALWARE: "No malware/code similarity or family evidence was available.",
        correlation.CATEGORY_CONFIG: "No malware configuration overlap was available.",
        correlation.CATEGORY_PROTOCOL: "No C2 protocol or communication-pattern overlap was available.",
        correlation.CATEGORY_INFRA: "No infrastructure overlap was available.",
        correlation.CATEGORY_DEV: "No developer/build artifact overlap was available.",
    }
    for category in REQUIRED_CATEGORIES:
        if category_scores.get(category, {}).get("score", 0) <= 0:
            missing.append(labels[category])
    return missing


def diversity_bonus(category_scores: Dict[str, Dict[str, Any]]) -> float:
    strong_categories = [
        category for category, detail in category_scores.items()
        if any(ev.get("strength") == correlation.STRONG for ev in detail.get("evidence", []))
    ]
    useful_categories = [category for category, detail in category_scores.items() if detail.get("score", 0) > 0]
    if len(strong_categories) >= 3:
        return 5.0
    if len(useful_categories) >= 4:
        return 3.0
    if len(useful_categories) >= 3:
        return 1.5
    return 0.0


def external_claims(candidate: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = candidate.get("data") or {}
    claims = []
    seen = set()
    for ref in data.get("refs", []) or []:
        key = str(ref).strip()
        if key and key not in seen:
            seen.add(key)
            claims.append({
                "type": "EXTERNAL_ATTRIBUTION_CLAIM",
                "candidate": candidate.get("candidate_name", ""),
                "source": candidate.get("source", "MANTIS knowledge"),
                "reference": key,
                "note": "External source links this candidate name or cluster; this is not independent MANTIS verification.",
            })
    for claim in data.get("external_attribution_claims", []) or []:
        if not isinstance(claim, dict):
            continue
        key = json.dumps(claim, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out = dict(claim)
        out.setdefault("type", "EXTERNAL_ATTRIBUTION_CLAIM")
        claims.append(out)
    return claims[:10]


def score_candidate(activity: Dict[str, Any], candidate: Dict[str, Any],
                    overrides: Dict[str, Dict[str, str]] = None) -> Dict[str, Any]:
    cand = normalize_candidate(candidate)
    corr = correlation.compare_entities(
        [
            {
                "id": "activity",
                "label": "Observed activity",
                "type": "activity",
                "data": activity.get("data", activity),
            },
            {
                "id": cand["candidate_id"],
                "label": cand["candidate_name"],
                "type": cand["candidate_type"],
                "source": cand["source"],
                "data": cand["data"],
            },
        ],
        overrides or {},
    )

    category_scores: Dict[str, Dict[str, Any]] = {
        category: {"score": 0.0, "cap": cap, "evidence": []}
        for category, cap in ATTRIBUTION_WEIGHTS.items()
    }
    contradictions = []
    supporting_evidence = []

    for evidence in corr.get("evidence", []):
        if evidence.get("analyst_mark") in {"false_positive", "not_relevant"}:
            continue
        if evidence.get("strength") == correlation.CONTRADICTING:
            severity = contradiction_severity(evidence)
            item = dict(evidence)
            item["severity"] = severity
            item["penalty"] = CONTRADICTION_PENALTIES[severity]
            contradictions.append(item)
            continue
        category = evidence_category(evidence)
        if category not in category_scores:
            category_scores[category] = {"score": 0.0, "cap": ATTRIBUTION_WEIGHTS.get(category, 5.0), "evidence": []}
        detail = category_scores[category]
        contribution = contribution_for_evidence(evidence, detail["cap"])
        detail["score"] = min(detail["cap"], detail["score"] + contribution)
        item = dict(evidence)
        item["score_contribution"] = round(contribution, 2)
        detail["evidence"].append(item)
        supporting_evidence.append(item)

    bonus = diversity_bonus(category_scores)
    penalty = min(35.0, sum(item.get("penalty", 0) for item in contradictions))
    subtotal = sum(detail["score"] for detail in category_scores.values())
    score = clamp_score(subtotal + bonus - penalty)
    category_out = {
        category: {
            "score": round(detail["score"], 2),
            "cap": detail["cap"],
            "evidence_ids": [ev.get("id") for ev in detail.get("evidence", [])[:20]],
            "evidence": detail.get("evidence", [])[:20],
        }
        for category, detail in sorted(category_scores.items())
        if detail["score"] > 0 or category in REQUIRED_CATEGORIES
    }
    assessment = assessment_band(score, contradictions)
    if score < 20 and len([e for e in supporting_evidence if e.get("strength") != correlation.WEAK]) == 0:
        assessment = "INSUFFICIENT_EVIDENCE"

    return {
        "candidate_id": cand["candidate_id"],
        "candidate_name": cand["candidate_name"],
        "candidate_type": cand["candidate_type"],
        "score": score,
        "score_label": "Attribution Evidence Score",
        "assessment": assessment,
        "model_version": MODEL_VERSION,
        "categories": category_out,
        "diversity_bonus": round(bonus, 2),
        "contradiction_penalty": round(penalty, 2),
        "supporting_evidence": supporting_evidence[:40],
        "contradictions": contradictions[:20],
        "missing_evidence": missing_evidence(category_scores),
        "external_attribution_claims": external_claims(cand),
        "sources": correlation.merge_sources([cand.get("source"), [e.get("sources", []) for e in supporting_evidence]]),
        "correlation": {
            "relationship": corr.get("relationship"),
            "assessment_reason": corr.get("assessment_reason"),
            "counts": corr.get("counts"),
        },
    }


def rank_candidates(activity: Dict[str, Any], candidates: List[Dict[str, Any]],
                    overrides: Dict[str, Dict[str, str]] = None, limit: int = 10) -> Dict[str, Any]:
    scored = [score_candidate(activity, candidate, overrides or {}) for candidate in candidates[:25]]
    scored.sort(key=lambda item: (-item["score"], item["candidate_name"].lower(), item["candidate_id"]))
    limit = max(1, min(int(limit or 10), 25))
    return {
        "attribution_model_version": MODEL_VERSION,
        "score_semantics": "Score is deterministic evidence alignment under the configured MANTIS model; it is not probability or confidence.",
        "ranking": scored[:limit],
        "candidate_count": len(scored),
        "weights": ATTRIBUTION_WEIGHTS,
        "strength_multipliers": STRENGTH_MULTIPLIERS,
        "distinctiveness_multipliers": DISTINCTIVENESS_MULTIPLIERS,
        "notes": [
            "MANTIS gathers and scores evidence; the analyst makes the attribution decision.",
            "External attribution claims are shown separately from MANTIS evidence alignment.",
        ],
    }


def candidate_terms(activity: Dict[str, Any]) -> List[str]:
    features = correlation.extract_features({"id": "activity", "data": activity.get("data", activity)})
    priority = ["malware_family", "yara", "campaign", "config", "pdb", "cti_reference", "attack", "domain"]
    out = []
    for kind in priority:
        for item in features.get(kind, [])[:5]:
            value = item.get("value", "")
            if value and not correlation.is_common(value) and value not in out:
                out.append(value)
            if len(out) >= 12:
                return out
    return out
