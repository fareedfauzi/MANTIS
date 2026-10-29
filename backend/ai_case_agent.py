import json
import re
from typing import Any, Dict, List, Optional

from ai_pivot_registry import PIVOT_REGISTRY, get_supported_pivot_types
from ai_service import AIProvider, _settings_raw, get_settings


DISCOVER_SYSTEM_PROMPT = """You are MANTIS Autonomous Discovery Agent, an expert cyber threat intelligence investigator.
Your role is to inspect the normalized case evidence graph and determine which relationship is actually worth investigating next through passive/read-only pivots.

Core Guidelines:
- Inspect observed entities, claims, and relationships.
- Prioritize distinctive relationships (e.g. C2 infrastructure contacted by multiple samples, rare domains, ThreatFox/MalwareBazaar campaign links, YARA matches).
- NEVER propose pivots on benign/shared infrastructure (CDNs, Cloudflare, Akamai, public DNS 8.8.8.8, CA/OCSP endpoints, search engine domains).
- NEVER propose active scans, file uploads, or detonations. Only propose supported passive pivots.
- Every candidate pivot MUST link to supporting evidence IDs (e.g. ["ev-001", "ev-003"]) from the case state.
- If all high-value relationships have been explored or no valuable pivots remain, return an empty candidate list.

Supported Pivot Types:
""" + "\n".join(f"- {k}: {v['description']}" for k, v in PIVOT_REGISTRY.items()) + """

Return strict JSON only matching this schema:
{
  "candidate_pivots": [
    {
      "pivot_type": "domain_to_passive_dns | hash_to_similar_samples | hash_to_network_iocs | ip_to_domains | ...",
      "value": "<indicator_value>",
      "reason": "<Specific reason why this relationship is investigated>",
      "priority": "high" | "medium" | "low",
      "supporting_evidence": ["ev-001", "ev-002"]
    }
  ],
  "stop_reason": "<Explanation if no further pivots are recommended>"
}
"""

ANALYZE_SYSTEM_PROMPT = """You are MANTIS Hypothesis and Correlation Engine.
Your job is to correlate all collected evidence across the investigation, identify corroboration, contradictions, and evidence gaps, and formulate calibrated hypotheses.

Rules:
1. Treat attribution and classification strictly as HYPOTHESES, never definitive proof without corroboration.
2. Assign evidence strength: HIGH, MODERATE, LOW, or INSUFFICIENT EVIDENCE.
3. Every hypothesis MUST explicitly reference supporting evidence IDs (e.g. ["ev-001"]) and any contradicting evidence IDs.
4. Never use generic AI filler phrases (such as "The threat landscape is constantly evolving", "Organizations must remain vigilant", "Further investigation is recommended"). Write strictly technical, evidence-backed findings.
5. Provide a calibrated overall verdict:
   - WELL_FOUNDED_FINDINGS: Corroborated malicious activity across multiple independent sources.
   - FIFTY_FIFTY_SUSPICIOUS: Suspicious telemetry or unverified single-source claims; requires internal correlation.
   - NO_FINDINGS_MOVE_ON: Clean/benign host or scanner; zero malicious findings.
   - DEAD_END_INCONCLUSIVE: Telemetry exhausted without conclusive evidence.

Return strict JSON only matching this schema:
{
  "verdict": "WELL_FOUNDED_FINDINGS" | "FIFTY_FIFTY_SUSPICIOUS" | "NO_FINDINGS_MOVE_ON" | "DEAD_END_INCONCLUSIVE",
  "verdict_label": "Well-Founded Malicious Finding" | "50-50 Result / Suspicious" | "No Findings At All — Let's Move On" | "Dead End / Inconclusive",
  "recommended_action": "Block & Isolate" | "Monitor & Correlate Internal Telemetry" | "Dismiss Alert / Move On" | "Manual Follow-up Required",
  "confidence_score": 0-100,
  "confidence_level": "high" | "medium" | "low" | "benign",
  "threat_classification": "<e.g. Infostealer C2, Ransomware Dropper, Phishing Host, Clean Infrastructure>",
  "mitre_techniques": ["T1071.001", "T1059"],
  "assessment_text": "<Concise, evidence-backed technical narrative explaining what the investigation proved>",
  "hypotheses": [
    {
      "hypothesis_type": "malware_family" | "threat_actor" | "campaign" | "infrastructure",
      "subject": "<Name of family/actor/campaign>",
      "hypothesis": "<Hypothesis statement>",
      "evidence_strength": "HIGH" | "MODERATE" | "LOW" | "INSUFFICIENT EVIDENCE",
      "supporting_evidence_ids": ["ev-001", "ev-003"],
      "contradicting_evidence_ids": [],
      "gaps": ["No independent infrastructure overlap confirmed"]
    }
  ],
  "corroborating_evidence": ["<Specific corroboration found across sources>"],
  "contradictions": ["<List of conflicting claims or vendor disagreements>"],
  "open_questions": ["<Unresolved investigation questions>"]
}
"""

PLANNER_SYSTEM_PROMPT = """You are MANTIS Case Agent, a passive cyber threat intelligence planner.

You receive normalized case state, not raw provider output. Your job is to choose the next passive lookup that can materially improve the case assessment.

Rules:
- Never treat placeholders such as [truncated-depth], [truncated], [N more item(s) omitted], or __omitted_keys as evidence.
- Never pivot on CA/AIA/OCSP/CRL URLs, certificate authority domains, registrar infrastructure, CDN/shared hosting, public resolvers, or security vendor/reporting domains unless the case state explicitly marks them attacker-controlled.
- Provider actor labels are claims, not proof.
- Malware family labels from AV or community sources require technical corroboration.
- Prefer pivots from sandbox network behavior, ThreatFox IOCs, MalwareBazaar related samples, YARA matches, config, mutex, PDB, imphash/TLSH, JA3/JA4/JARM, certificate fingerprint, or distinctive C2 URL/path.
- If no high-value passive pivot remains, stop.

Return strict JSON matching this schema:
{
  "decision": "run_tool" | "stop" | "ask_analyst",
  "tool": "source_id to run (e.g. virustotal, threatfox, malwarebazaar)",
  "arguments": {"type": "hash|domain|ip|url|keyword", "value": "the artifact value"},
  "reason": "Why this changes the case state",
  "expected_value": "What this lookup may prove/disprove",
  "risk": "low|medium|high",
  "stop_reason": "If decision is stop, explain why"
}
"""


def discover_candidate_pivots(case: Dict[str, Any], max_candidates: int = 5) -> List[Dict[str, Any]]:
    """
    DISCOVER Stage:
    Evaluates enriched relationships and evidence in the case state and proposes
    high-value candidate passive pivots.
    """
    settings = _settings_raw()
    provider = AIProvider(settings)

    relationships = case.get("relationships", [])
    observations = case.get("observations", [])
    claims = case.get("claims", [])
    root = case.get("root", {})
    prior_pivots = case.get("pivots", [])

    # Filter relationships to those that have pivot_value != False
    actionable_rels = []
    for r in relationships:
        actionable_rels.append({
            "source": r.get("source_entity") or f"{r.get('source_type')}:{r.get('source_value')}",
            "relation": r.get("relation"),
            "target": r.get("target_entity") or f"{r.get('target_type')}:{r.get('target_value')}",
            "evidence_source": r.get("evidence_source"),
            "evidence_ids": r.get("evidence_ids", [])
        })

    state_summary = {
        "case_id": case.get("case_id"),
        "root": root,
        "observations_count": len(observations),
        "claims_count": len(claims),
        "sample_observations": [
            {"id": o.get("evidence_id"), "type": o.get("type") or o.get("obs_type"), "value": o.get("value"), "pivot_value": o.get("pivot_value", True)}
            for o in observations[:40]
        ],
        "sample_claims": [
            {"id": c.get("evidence_id"), "claim_type": c.get("claim_type"), "value": c.get("value")}
            for c in claims[:30]
        ],
        "relationships": actionable_rels[:40],
        "already_pivoted": [p.get("value") for p in prior_pivots]
    }

    messages = [
        {"role": "system", "content": DISCOVER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Case State:\n{json.dumps(state_summary, indent=2)}\n\nWhat are the most valuable candidate pivots to investigate?"}
    ]

    try:
        response = provider.generate(messages)
        start = response.find("{")
        end = response.rfind("}")
        if start != -1 and end != -1:
            data = json.loads(response[start:end+1])
            candidates = data.get("candidate_pivots") or []
            if isinstance(candidates, list) and candidates:
                return candidates[:max_candidates]
    except Exception:
        pass

    # Deterministic fallback: extract valuable candidate pivots directly from relationships
    return _deterministic_candidate_pivots(case, max_candidates=max_candidates)


def _deterministic_candidate_pivots(case: Dict[str, Any], max_candidates: int = 5) -> List[Dict[str, Any]]:
    """
    Fallback deterministic discovery: identifies unqueried, high-value indicators
    from normalized relationships without requiring an active LLM.
    """
    candidates = []
    root_val = str((case.get("root") or {}).get("value") or "").strip().lower()
    prior_pivoted = {str(p.get("value") or "").strip().lower() for p in (case.get("pivots") or [])}
    prior_pivoted.add(root_val)

    # Check relationships
    for rel in case.get("relationships") or []:
        t_type = str(rel.get("target_type") or "").lower()
        t_val = str(rel.get("target_value") or "").strip()
        evidence_ids = rel.get("evidence_ids") or []
        if not t_val or t_val.lower() in prior_pivoted:
            continue

        if t_type == "domain":
            candidates.append({
                "pivot_type": "domain_to_passive_dns",
                "value": t_val,
                "reason": f"Discovered domain via relation '{rel.get('relation')}' from {rel.get('source_value')}.",
                "priority": "high",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())
        elif t_type == "ip":
            candidates.append({
                "pivot_type": "ip_to_domains",
                "value": t_val,
                "reason": f"Discovered IP via relation '{rel.get('relation')}' from {rel.get('source_value')}.",
                "priority": "medium",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())
        elif t_type == "hash":
            candidates.append({
                "pivot_type": "hash_to_similar_samples",
                "value": t_val,
                "reason": f"Discovered sample hash via relation '{rel.get('relation')}'.",
                "priority": "high",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())
        elif t_type == "url":
            candidates.append({
                "pivot_type": "url_to_telemetry",
                "value": t_val,
                "reason": f"Discovered endpoint URL via relation '{rel.get('relation')}' from {rel.get('source_value')}.",
                "priority": "high",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())
        elif t_type in ("asn", "cidr", "infra"):
            p_type = "asn_to_infrastructure" if (t_val.upper().startswith("AS") or t_type == "asn") else "cidr_to_exposed_hosts"
            candidates.append({
                "pivot_type": p_type,
                "value": t_val,
                "reason": f"Discovered infrastructure routing block via relation '{rel.get('relation')}'.",
                "priority": "medium",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())
        elif t_type in ("actor", "threat_actor"):
            candidates.append({
                "pivot_type": "threat_actor_to_campaign",
                "value": t_val,
                "reason": f"Discovered attributed adversary '{t_val}' via relation '{rel.get('relation')}'.",
                "priority": "high",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())
        elif t_type in ("malware", "malware_family"):
            candidates.append({
                "pivot_type": "malware_family_to_samples",
                "value": t_val,
                "reason": f"Discovered malware family '{t_val}' via relation '{rel.get('relation')}'.",
                "priority": "high",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())
        elif t_type in ("cve", "vulnerability"):
            candidates.append({
                "pivot_type": "cve_to_exploits_and_pocs",
                "value": t_val,
                "reason": f"Discovered associated CVE '{t_val}' via relation '{rel.get('relation')}'.",
                "priority": "high",
                "supporting_evidence": evidence_ids
            })
            prior_pivoted.add(t_val.lower())


        if len(candidates) >= max_candidates:
            break

    return candidates


def analyze_case_hypotheses(case: Dict[str, Any]) -> Dict[str, Any]:
    """
    ANALYZE Stage:
    Correlates full evidence graph, builds hypotheses, and assigns evidence strength.
    """
    settings = _settings_raw()
    provider = AIProvider(settings)

    observations = case.get("observations") or []
    claims = case.get("claims") or []
    relationships = case.get("relationships") or []
    pivots = case.get("pivots") or []
    source_health = case.get("source_health") or []

    state = {
        "root": case.get("root"),
        "observations": [
            {"id": o.get("evidence_id"), "type": o.get("type") or o.get("obs_type"), "value": o.get("value"), "source": o.get("source"), "pivot_value": o.get("pivot_value", True)}
            for o in observations[:60]
        ],
        "claims": [
            {"id": c.get("evidence_id"), "type": c.get("evidence_type", "PROVIDER_CLAIM"), "claim_type": c.get("claim_type"), "value": c.get("value"), "source": c.get("source")}
            for c in claims[:40]
        ],
        "relationships": [
            {"source": r.get("source_entity") or r.get("source_value"), "relation": r.get("relation"), "target": r.get("target_entity") or r.get("target_value"), "evidence_ids": r.get("evidence_ids", [])}
            for r in relationships[:40]
        ],
        "pivots_executed": [
            {"type": p.get("pivot_type"), "value": p.get("value"), "provider": p.get("provider")}
            for p in pivots
        ],
        "source_health": [
            {"source": s.get("source"), "status": s.get("status"), "count": s.get("count", 0)}
            for s in source_health
        ]
    }

    # Heuristic baseline values
    obs_count = len(observations)
    claims_count = len(claims)
    sources_with_data = len([s for s in source_health if s.get("status") == "findings_or_context"])
    malware_claims = [c for c in claims if str(c.get("claim_type")).lower() in {"malware", "family", "signature"}]
    actor_claims = [c for c in claims if str(c.get("claim_type")).lower() in {"actor", "adversary", "threat_actor", "apt"}]

    if sources_with_data >= 2 and (obs_count + claims_count) >= 3:
        fallback_verdict = "WELL_FOUNDED_FINDINGS"
        fallback_label = "Well-Founded Malicious Finding"
        fallback_action = "Block & Isolate"
        fallback_score = 85
        fallback_level = "high"
    elif sources_with_data >= 1 and (obs_count + claims_count) >= 1:
        fallback_verdict = "FIFTY_FIFTY_SUSPICIOUS"
        fallback_label = "50-50 Result / Suspicious"
        fallback_action = "Monitor & Correlate Internal Telemetry"
        fallback_score = 60
        fallback_level = "medium"
    elif sources_with_data == 0 and obs_count == 0:
        fallback_verdict = "NO_FINDINGS_MOVE_ON"
        fallback_label = "No Findings At All — Let's Move On"
        fallback_action = "Dismiss Alert / Move On"
        fallback_score = 10
        fallback_level = "benign"
    else:
        fallback_verdict = "DEAD_END_INCONCLUSIVE"
        fallback_label = "Dead End / Inconclusive"
        fallback_action = "Manual Follow-up Required"
        fallback_score = 30
        fallback_level = "low"

    # Deterministic hypotheses baseline
    fallback_hypotheses = []
    if malware_claims:
        families = list(dict.fromkeys(c.get("value") for c in malware_claims if c.get("value")))
        family_name = " / ".join(families[:2])
        sup_ids = [c.get("evidence_id") for c in malware_claims if c.get("evidence_id")]
        fallback_hypotheses.append({
            "hypothesis_type": "malware_family",
            "subject": family_name,
            "hypothesis": f"Telemetry indicates association with {family_name} malware family.",
            "evidence_strength": "HIGH" if len(sup_ids) >= 2 else "MODERATE",
            "supporting_evidence_ids": sup_ids[:5],
            "contradicting_evidence_ids": [],
            "gaps": ["Requires sandbox behavior or code disassembly confirmation."] if len(sup_ids) < 2 else []
        })
    if actor_claims:
        actors = list(dict.fromkeys(c.get("value") for c in actor_claims if c.get("value")))
        actor_name = actors[0]
        sup_ids = [c.get("evidence_id") for c in actor_claims if c.get("evidence_id")]
        fallback_hypotheses.append({
            "hypothesis_type": "threat_actor",
            "subject": actor_name,
            "hypothesis": f"Reported association with threat actor {actor_name}.",
            "evidence_strength": "LOW",
            "supporting_evidence_ids": sup_ids[:3],
            "contradicting_evidence_ids": [],
            "gaps": ["Single-vendor claim; lacks independent infrastructure or TTP corroboration."]
        })

    messages = [
        {"role": "system", "content": ANALYZE_SYSTEM_PROMPT},
        {"role": "user", "content": f"Case Evidence State:\n{json.dumps(state, indent=2)}\n\nPerform full evidence analysis, correlation, and hypothesis synthesis."}
    ]

    try:
        response = provider.generate(messages)
        start = response.find("{")
        end = response.rfind("}")
        if start != -1 and end != -1:
            data = json.loads(response[start:end+1])
            if not data.get("verdict"):
                data["verdict"] = fallback_verdict
                data["verdict_label"] = fallback_label
            if not data.get("recommended_action"):
                data["recommended_action"] = fallback_action
            if not data.get("confidence_score"):
                data["confidence_score"] = fallback_score
            if not data.get("confidence_level"):
                data["confidence_level"] = fallback_level
            if not isinstance(data.get("hypotheses"), list) or not data.get("hypotheses"):
                data["hypotheses"] = fallback_hypotheses
            if not isinstance(data.get("mitre_techniques"), list):
                data["mitre_techniques"] = []
            return data
    except Exception:
        pass

    return {
        "verdict": fallback_verdict,
        "verdict_label": fallback_label,
        "recommended_action": fallback_action,
        "confidence_score": fallback_score,
        "confidence_level": fallback_level,
        "threat_classification": "Automated CTI Analysis",
        "mitre_techniques": [],
        "assessment_text": f"Telemetry evaluated. Target has {obs_count} observation(s) across {sources_with_data} active source(s).",
        "hypotheses": fallback_hypotheses,
        "corroborating_evidence": [f"{sources_with_data} provider source(s) returned active technical telemetry."],
        "contradictions": [],
        "open_questions": ["Validate network connections against perimeter firewall and EDR logs."]
    }


def plan_agent_next_step(case: Dict[str, Any], allowed_sources: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Backwards-compatible wrapper for single-step planning.
    """
    settings = _settings_raw()
    provider = AIProvider(settings)

    state = {
        "case_id": case.get("case_id"),
        "root": case.get("root"),
        "status": case.get("status"),
        "observations": case.get("observations", [])[:50],
        "claims": case.get("claims", [])[:50],
        "relationships": case.get("relationships", [])[:50],
        "completed_source_runs": [s.get("source") for s in case.get("source_health", [])],
        "allowed_sources_to_pick": [s.get("source_id") for s in (allowed_sources or [])],
    }

    messages = [
        {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Case State:\n{json.dumps(state, indent=2)}\n\nWhat is the next best action?"}
    ]

    try:
        response = provider.generate(messages)
        start = response.find("{")
        end = response.rfind("}")
        if start != -1 and end != -1:
            decision_json = json.loads(response[start:end+1])
            return decision_json
    except Exception as e:
        return {"decision": "stop", "stop_reason": f"Agent planning failed: {str(e)}"}

    return {"decision": "stop", "stop_reason": "Failed to parse agent decision."}


def generate_case_assessment(case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Backwards-compatible wrapper that delegates to analyze_case_hypotheses.
    """
    analysis = analyze_case_hypotheses(case)
    analysis["attribution_summary"] = " / ".join(
        h.get("subject", "") for h in analysis.get("hypotheses", []) if h.get("subject")
    )
    return analysis
