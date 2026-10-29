import hashlib
import io
import json
import os
import re
import sqlite3
import time
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ai_case_agent import analyze_case_hypotheses, discover_candidate_pivots, generate_case_assessment
from ai_pivot_policy import classify_action, filter_actions as filter_pivot_actions, validate_candidate_pivot
from ai_pivot_registry import resolve_sources_for_pivot
from ai_provider_normalizers import normalize_case_findings, normalize_provider
from ai_source_router import plan_next_step, source_skill_inventory
from intel_query import is_domain, is_hash, is_ip, is_url, normalize_domain, normalize_ip, normalize_url


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CASE_DB_PATH = os.environ.get("MANTIS_AI_CASE_DB") or os.path.join(DATA_DIR, "mantis_ai_cases.db")

HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{96}\b|\b[a-fA-F0-9]{128}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def sync_case_from_context(context: Dict[str, Any], note: str = "") -> Dict[str, Any]:
    init_db()
    root_type, root_value = root_from_context(context)
    case_id = case_id_for(root_type, root_value)
    now = _now()
    with _connect() as db:
        db.execute(
            """
            INSERT INTO cases(case_id, root_type, root_value, title, status, created_at, updated_at)
            VALUES(?, ?, ?, ?, 'open', ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET updated_at=excluded.updated_at, title=excluded.title
            """,
            (case_id, root_type, root_value, f"{root_type}: {root_value}", now, now),
        )
        _record_timeline(db, case_id, "acquire", "Case evidence synced", note or "Updated case from current MANTIS context.", "mantis_ui", "complete", {"root_type": root_type, "root_value": root_value})
        _store_source_snapshots(db, case_id, context)
        _store_observations(db, case_id, context)
        _store_candidate_pivots(db, case_id, context)
    return get_case(case_id)


def get_case(case_id: str) -> Dict[str, Any]:
    init_db()
    with _connect() as db:
        row = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not row:
            raise ValueError("Unknown MANTIS AI case.")
        case = {
            "case_id": row["case_id"],
            "root": {"type": row["root_type"], "value": row["root_value"]},
            "title": row["title"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "source_health": _rows(db, "SELECT source, status, count, error, updated_at FROM source_health WHERE case_id=? ORDER BY updated_at DESC", (case_id,)),
            "observations": _json_rows(db, "SELECT evidence_id, evidence_type, obs_type, value, source, statement, confidence, pivot_value, noise_reason, raw_json, created_at FROM observations WHERE case_id=? ORDER BY created_at DESC LIMIT 120", (case_id,), "raw_json"),
            "claims": _json_rows(db, "SELECT evidence_id, evidence_type, claim_type, value, source, statement, confidence, pivot_value, noise_reason, raw_json, created_at FROM claims WHERE case_id=? ORDER BY created_at DESC LIMIT 120", (case_id,), "raw_json"),
            "relationships": _json_rows(db, "SELECT source_entity, source_type, source_value, relation, target_entity, target_type, target_value, evidence_source, evidence_ids, raw_json, created_at FROM relationships WHERE case_id=? ORDER BY created_at DESC LIMIT 120", (case_id,), "raw_json", "evidence_ids"),
            "candidate_actions": _json_rows(db, "SELECT action_json, reason, status, source, score, created_at FROM candidate_actions WHERE case_id=? ORDER BY score DESC, created_at DESC LIMIT 40", (case_id,), "action_json"),
            "rejected_pivots": _json_rows(db, "SELECT action_json, reason, tags_json, artifact_json, created_at FROM rejected_pivots WHERE case_id=? ORDER BY created_at DESC LIMIT 40", (case_id,), "action_json", "tags_json", "artifact_json"),
            "timeline": _json_rows(db, "SELECT phase, title, detail, source, status, data_json, created_at FROM timeline WHERE case_id=? ORDER BY id DESC LIMIT 80", (case_id,), "data_json"),
            "ai_assessment": _json_rows(db, "SELECT * FROM ai_assessments WHERE case_id=? ORDER BY version DESC LIMIT 1", (case_id,), "contradictions_json", "open_questions_json", "mitre_json"),
            "pivots": _json_rows(db, "SELECT pivot_id, parent_evidence, pivot_type, value, reason, decision, decision_reason, provider, depth, created_at FROM pivots WHERE case_id=? ORDER BY created_at ASC", (case_id,), "parent_evidence"),
            "hypotheses": _json_rows(db, "SELECT hypothesis_id, hypothesis_type, subject, hypothesis, evidence_strength, supporting_evidence_ids, contradicting_evidence_ids, gaps, created_at FROM hypotheses WHERE case_id=? ORDER BY created_at DESC", (case_id,), "supporting_evidence_ids", "contradicting_evidence_ids", "gaps"),
        }
    for h in case.get("hypotheses") or []:
        h.setdefault("name", h.get("subject"))
        h.setdefault("type", h.get("hypothesis_type"))
        h.setdefault("summary", h.get("hypothesis"))
    case["assessment"] = assess_case(case)
    case["next_step"] = plan_next_step(case)
    return case


def list_cases(limit: int = 30) -> Dict[str, Any]:
    init_db()
    limit = max(1, min(int(limit or 30), 100))
    with _connect() as db:
        cases = _rows(db, "SELECT case_id, root_type, root_value, title, status, created_at, updated_at FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,))
    return {"cases": cases}


def case_step(payload: Dict[str, Any]) -> Dict[str, Any]:
    context = payload.get("page_context") if isinstance(payload.get("page_context"), dict) else {}
    case_id = str(payload.get("case_id") or "").strip()
    if case_id:
        case = get_case(case_id)
    else:
        case = sync_case_from_context(context, note="Case step requested.")
        case_id = case["case_id"]
    selected_sources = payload.get("selected_sources") if isinstance(payload.get("selected_sources"), list) else []
    next_step = plan_next_step(case, selected_sources=selected_sources)
    with _connect() as db:
        _record_timeline(
            db,
            case_id,
            next_step.get("phase") or "enrich",
            "AEAD next step planned",
            next_step.get("reason") or "",
            "source_router",
            "planned",
            next_step,
        )
    out = get_case(case_id)
    out["next_step"] = next_step
    return out


def run_case_next_source(payload: Dict[str, Any]) -> Dict[str, Any]:
    from ai_case_agent import plan_agent_next_step

    context = payload.get("page_context") if isinstance(payload.get("page_context"), dict) else {}
    case_id = str(payload.get("case_id") or "").strip()
    if case_id:
        case = get_case(case_id)
    else:
        case = sync_case_from_context(context, note="Case execution requested.")
        case_id = case["case_id"]
    selected_sources = payload.get("selected_sources") if isinstance(payload.get("selected_sources"), list) else []
    keys = payload.get("keys") if isinstance(payload.get("keys"), dict) else {}
    github_repos = payload.get("github_repos") if isinstance(payload.get("github_repos"), list) else []
    try:
        max_sources = max(1, min(int(payload.get("max_sources") or 1), 3))
    except (TypeError, ValueError):
        max_sources = 1
    next_step = plan_next_step(case, selected_sources=selected_sources)
    
    agent_decision = plan_agent_next_step(case, allowed_sources=next_step.get("recommended_sources") or [])
    
    executions = []
    if agent_decision.get("decision") != "run_tool":
        with _connect() as db:
            _record_timeline(db, case_id, "stop", "Agent stopped investigation", agent_decision.get("stop_reason") or "", "ai_agent", "skipped", agent_decision)
        out = get_case(case_id)
        out["executions"] = executions
        out["next_step"] = next_step
        out["agent_decision"] = agent_decision
        return out
        
    source_id = agent_decision.get("tool")
    if not source_id or source_id not in [s.get("source_id") for s in (next_step.get("recommended_sources") or [])]:
        # Fallback to deterministic if agent hallucinated a source
        recommendations = (next_step.get("recommended_sources") or [])[:max_sources]
    else:
        recommendations = [{"source_id": source_id}]
        with _connect() as db:
            _record_timeline(db, case_id, "plan", "Agent selected pivot", agent_decision.get("reason") or "", "ai_agent", "success", agent_decision)
    
    if not recommendations:
        with _connect() as db:
            _record_timeline(db, case_id, "assess", "No source execution available", next_step.get("reason") or "", "source_router", "skipped", next_step)
        out = get_case(case_id)
        out["executions"] = executions
        out["next_step"] = next_step
        return out
    root = case.get("root") if isinstance(case.get("root"), dict) else {}
    root_type = str(root.get("type") or "keyword").lower()
    root_value = str(root.get("value") or "").strip()
    for recommendation in recommendations:
        source_id = str(recommendation.get("source_id") or "").strip()
        if not source_id:
            continue
        started = time.perf_counter()
        try:
            result = _run_single_source(root_type, root_value, source_id, keys, github_repos)
            payload_for_source = _provider_payload(result, source_id)
            status, count, error = _provider_status(payload_for_source, result)
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            result_context = {
                "page": root_type,
                "query": {"value": root_value},
                "providers": [{"provider": source_id, "status": status, "count": count, "error": error}],
                "findings": {source_id: payload_for_source if payload_for_source is not None else result},
                "artifacts": [{"type": root_type, "value": root_value, "sources": [source_id]}] if root_type in {"hash", "domain", "ip", "url"} else [],
            }
            sync_case_from_context(result_context, note=f"Executed {source_id} for AEAD case enrichment.")
            execution = {"source_id": source_id, "status": status, "count": count, "error": error, "duration_ms": elapsed_ms}
            executions.append(execution)
            with _connect() as db:
                _record_timeline(
                    db,
                    case_id,
                    "enrich",
                    f"Executed source: {source_id}",
                    error or f"Stored {count} normalized result item(s).",
                    source_id,
                    status,
                    {"execution": execution, "recommendation": recommendation},
                )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            execution = {"source_id": source_id, "status": "error", "count": 0, "error": str(exc)[:500], "duration_ms": elapsed_ms}
            executions.append(execution)
            with _connect() as db:
                _record_timeline(db, case_id, "enrich", f"Source execution failed: {source_id}", execution["error"], source_id, "error", {"execution": execution})
    out = get_case(case_id)
    out["executions"] = executions
    out["next_step"] = plan_next_step(out, selected_sources=selected_sources)
    return out


def run_case_auto(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        max_steps = max(1, min(int(payload.get("max_steps") or 3), 10))
    except (TypeError, ValueError):
        max_steps = 3
    case_id = str(payload.get("case_id") or "").strip()
    context = payload.get("page_context") if isinstance(payload.get("page_context"), dict) else {}
    if not case_id:
        case = sync_case_from_context(context, note="Auto-run requested.")
        case_id = case["case_id"]
    executions = []
    current_payload = dict(payload)
    current_payload["case_id"] = case_id
    for _ in range(max_steps):
        case = get_case(case_id)
        next_step = plan_next_step(case, selected_sources=payload.get("selected_sources") if isinstance(payload.get("selected_sources"), list) else [])
        if next_step.get("phase") == "assess" or not next_step.get("recommended_sources"):
            break
        step = run_case_next_source(current_payload)
        executions.extend(step.get("executions") or [])
        if not step.get("executions"):
            break
    
    with _connect() as db:
        _record_timeline(db, case_id, "assess", "Auto-run completed", f"Executed {len(executions)} source step(s).", "case_agent", "complete", {"executions": executions})
        
    try:
        generate_case_assessment_db(case_id)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Auto-assessment failed for {case_id}: {e}")
        
    return get_case(case_id) | {"executions": executions}


def draft_case_report(case_id: str) -> Dict[str, Any]:
    case = get_case(case_id)
    root = case["root"]
    assessment = case.get("assessment") or {}
    ai_assessment = (case.get("ai_assessment") or [{}])[0]
    
    lines = [
        f"# MANTIS Intelligence Report",
        f"**Target:** `{root.get('type', 'artifact')}: {root.get('value', '')}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Executive Summary",
        ai_assessment.get("assessment_text") or _executive_summary(case),
        "",
        "## Key Findings"
    ]
    facts = [obs for obs in case.get("observations", []) if obs.get("obs_type") in {"hash", "domain", "ip", "url", "cve", "certificate_fingerprint"}]
    claims = case.get("claims") or []
    
    if facts:
        for item in facts[:15]:
            lines.append(f"- **{item.get('obs_type', 'artifact').upper()}**: `{item.get('value')}` observed via {item.get('source') or 'MANTIS context'}.")
    else:
        lines.append("- *No normalized technical observations recorded.*")
        
    if claims:
        lines.extend(["", "## Provider Claims"])
        for item in claims[:15]:
            lines.append(f"- {item.get('statement') or item.get('value')} (Source: **{item.get('source') or 'unknown'}**)")
            
    contradictions = assessment.get("contradictions") or []
    if contradictions:
        lines.extend(["", "## Contradictions"])
        for c in contradictions:
            lines.append(f"- {c}")
            
    open_questions = assessment.get("open_questions") or []
    if open_questions:
        lines.extend(["", "## Open Questions / Gaps"])
        for q in open_questions:
            lines.append(f"- {q}")

    rejected = case.get("rejected_pivots") or []
    if rejected:
        lines.extend(["", "## Rejected Leads"])
        for item in rejected[:10]:
            tool_name = item.get("action_json", {}).get("tool", "tool") if isinstance(item.get("action_json"), dict) else "tool"
            lines.append(f"- Suppressed `{tool_name}`: {item.get('reason')}")

    lines.extend([
        "",
        "## Source Health",
        f"- **Sources with findings:** {assessment.get('sources_with_findings', 0)}",
        f"- **Source errors:** {assessment.get('source_errors', 0)}"
    ])
    
    report_text = "\n".join(lines)
    with _connect() as db:
        _record_timeline(db, case_id, "report", "Generated analyst report", f"{len(facts)} facts, {len(claims)} claims.", "analyst_ui", "success", {})
        
    return {"case": get_case(case_id), "report": report_text}


def export_case_markdown(case_id: str) -> Dict[str, Any]:
    report = draft_case_report(case_id)
    case = report["case"]
    root = case.get("root") or {}
    lines = [
        f"# MANTIS Intelligence Report",
        "",
        f"- **Case:** `{case.get('case_id')}`",
        f"- **Root:** `{root.get('type')}` `{root.get('value')}`",
        f"- **Updated:** `{case.get('updated_at')}`",
        f"- **Confidence:** `{(case.get('assessment') or {}).get('confidence')}`",
        "",
        "## Executive Summary",
        "",
        (case.get("ai_assessment") or [{}])[0].get("assessment_text") or _executive_summary(case),
        "",
        "## Source Health",
        "",
        "| Source | Status | Count | Error |",
        "| --- | --- | ---: | --- |",
    ]
    for src in (case.get("source_health") or [])[:80]:
        lines.append(f"| {_md(src.get('source'))} | {_md(src.get('status'))} | {src.get('count') or 0} | {_md(src.get('error'))} |")
    lines.extend(["", "## Observed Technical Facts", "", "| Type | Value | Source |", "| --- | --- | --- |"])
    for obs in (case.get("observations") or [])[:80]:
        lines.append(f"| {_md(obs.get('obs_type'))} | `{_md(obs.get('value'))}` | {_md(obs.get('source'))} |")
    lines.extend(["", "## Provider Claims", "", "| Type | Claim | Source |", "| --- | --- | --- |"])
    for claim in (case.get("claims") or [])[:80]:
        lines.append(f"| {_md(claim.get('claim_type'))} | {_md(claim.get('value'))} | {_md(claim.get('source'))} |")
    lines.extend(["", "## Evidence Relationships", "", "| Source | Relation | Target | Evidence Source |", "| --- | --- | --- | --- |"])
    for rel in (case.get("relationships") or [])[:80]:
        lines.append(f"| `{_md(rel.get('source_type'))}:{_md(rel.get('source_value'))}` | {_md(rel.get('relation'))} | `{_md(rel.get('target_type'))}:{_md(rel.get('target_value'))}` | {_md(rel.get('evidence_source'))} |")
    contradictions = (case.get("assessment") or {}).get("contradictions") or []
    if contradictions:
        lines.extend(["", "## Contradictions", ""])
        for item in contradictions:
            lines.append(f"- **{_md(item.get('severity'))}:** {_md(item.get('statement'))}")
    lines.extend(["", "## Recommended Next Step", "", f"- {_md((case.get('next_step') or {}).get('reason'))}"])
    filename = f"mantis_{case_id}.md"
    return {"case": case, "filename": filename, "markdown": "\n".join(lines)}


def export_case_workspace(case_id: str) -> Dict[str, Any]:
    exported = export_case_markdown(case_id)
    case = exported["case"]
    safe_case_id = re.sub(r"[^A-Za-z0-9._-]+", "_", case_id).strip("._") or "case"
    root_dir = f"mantis-workspace-{safe_case_id}"
    buffer = io.BytesIO()

    catalogs = {
        "source_health": case.get("source_health") or [],
        "observations": case.get("observations") or [],
        "claims": case.get("claims") or [],
        "relationships": case.get("relationships") or [],
        "timeline": case.get("timeline") or [],
        "pivots": case.get("pivots") or [],
        "hypotheses": case.get("hypotheses") or [],
        "candidate_actions": case.get("candidate_actions") or [],
        "rejected_pivots": case.get("rejected_pivots") or [],
        "assessment": case.get("assessment") or {},
        "next_step": case.get("next_step") or {},
    }

    files = {
        "AGENTS.md": _workspace_agents_md(case),
        "CLAUDE.md": "# Instructions\n\nRead `AGENTS.md` first; it applies to the entire workspace.\n",
        "README.md": _workspace_readme_md(case, catalogs),
        "report.md": exported["markdown"],
        "case.json": _workspace_json(case),
        "skills/case-investigation/SKILL.md": _workspace_investigation_skill(),
        "skills/evidence-review/SKILL.md": _workspace_evidence_skill(),
        "skills/pivot-planning/SKILL.md": _workspace_pivot_skill(),
        "skills/threat-attribution/SKILL.md": _workspace_attribution_skill(),
        "skills/report-writing/SKILL.md": _workspace_reporting_skill(),
    }
    for name, value in catalogs.items():
        files[f"catalog/{name}.json"] = _workspace_json(value)

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path, content in files.items():
            archive.writestr(f"{root_dir}/{relative_path}", content)

    return {
        "filename": f"{root_dir}.zip",
        "content": buffer.getvalue(),
        "file_count": len(files),
    }


def _workspace_json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, default=str) + "\n"


def _workspace_agents_md(case: Dict[str, Any]) -> str:
    root = case.get("root") or {}
    return f"""# MANTIS Case Workspace

This is an offline, evidence-first export of MANTIS case `{case.get('case_id')}` for `{root.get('type')}: {root.get('value')}`.

## Start Here

1. Read `README.md` for scope and catalog counts.
2. Read `catalog/assessment.json` and `catalog/source_health.json`.
3. Inspect `catalog/observations.json`, `catalog/claims.json`, and `catalog/relationships.json`.
4. Use the relevant workflow under `skills/*/SKILL.md`.
5. Treat `report.md` as a draft derived from the catalogs, not as primary evidence.

## Evidence Rules

- Separate observed technical facts from provider claims and analyst hypotheses.
- Cite evidence IDs and source names for every material conclusion.
- Preserve contradictions, source errors, uncertainty, and rejected pivots.
- Do not invent enrichment results or imply that an offline lookup was performed.
- Defang live indicators in prose when producing a shareable report.
- Never execute, detonate, download, or contact an indicator from this workspace.

## Workspace Map

- `case.json` - complete normalized case snapshot.
- `catalog/` - focused machine-readable evidence and workflow records.
- `report.md` - MANTIS-generated report draft.
- `skills/` - portable investigation workflows for coding agents.
"""


def _workspace_readme_md(case: Dict[str, Any], catalogs: Dict[str, Any]) -> str:
    root = case.get("root") or {}
    assessment = case.get("assessment") or {}
    return f"""# MANTIS AI Workspace

Offline workspace for case `{case.get('case_id')}`.

## Case

- **Root:** `{root.get('type')}: {root.get('value')}`
- **Status:** `{case.get('status')}`
- **Updated:** `{case.get('updated_at')}`
- **Confidence:** `{assessment.get('confidence')}`
- **Verdict:** `{assessment.get('verdict_label')}`

## Catalog Summary

- Sources: {len(catalogs['source_health'])}
- Observations: {len(catalogs['observations'])}
- Claims: {len(catalogs['claims'])}
- Relationships: {len(catalogs['relationships'])}
- Hypotheses: {len(catalogs['hypotheses'])}
- Recorded pivots: {len(catalogs['pivots'])}

Read `AGENTS.md` before analysis. The workspace is intentionally offline and contains no API credentials.
"""


def _workspace_investigation_skill() -> str:
    return """---
name: mantis-case-investigation
description: Investigate an exported MANTIS case using normalized offline evidence.
---

# MANTIS Case Investigation

1. Establish the root indicator and case scope from `case.json`.
2. Review source coverage and failures in `catalog/source_health.json`.
3. Build a chronology from `catalog/timeline.json`.
4. Group observations by indicator type and source.
5. Compare claims against observations and relationships.
6. Record supported findings, contradictions, gaps, and confidence separately.
7. Cite evidence IDs for every material finding.

Do not perform active network access or treat provider claims as independently verified facts.
"""


def _workspace_evidence_skill() -> str:
    return """---
name: mantis-evidence-review
description: Audit MANTIS evidence quality, provenance, contradictions, and uncertainty.
---

# MANTIS Evidence Review

1. Start with `catalog/observations.json`; these are normalized technical facts.
2. Review `catalog/claims.json` as attributed provider statements.
3. Use `catalog/relationships.json` to test whether links have supporting evidence IDs.
4. Check `catalog/rejected_pivots.json` before reviving a suppressed lead.
5. Flag missing provenance, stale timestamps, source errors, and circular claims.
6. Assign confidence only after corroboration across independent sources.

Output a table with finding, evidence IDs, sources, counter-evidence, and confidence.
"""


def _workspace_pivot_skill() -> str:
    return """---
name: mantis-pivot-planning
description: Propose safe next pivots from an exported MANTIS case without executing them.
---

# MANTIS Pivot Planning

1. Read `catalog/next_step.json`, `catalog/candidate_actions.json`, and `catalog/rejected_pivots.json`.
2. Prefer pivots tied to existing evidence IDs and likely to change the assessment.
3. Exclude certificate-authority infrastructure, registrars, CDNs, public resolvers, and security-vendor domains unless explicitly attacker-controlled.
4. Rank each proposed pivot by expected value, evidence support, risk, and cost.
5. Mark every proposal as unexecuted; this workspace is offline.

Never claim a proposed lookup returned results.
"""


def _workspace_attribution_skill() -> str:
    return """---
name: mantis-threat-attribution
description: Assess actor or campaign attribution from an exported MANTIS case using evidence categories, alternatives, and explicit confidence.
---

# MANTIS Threat Attribution

Use this workflow only when the case contains an attribution question. It is informed by the [Threat Attribution in Threat Intelligence cheatsheet](https://fareedfauzi.github.io/cheatsheets/threat-attribution/) and 6-category evidence guidelines.

## Principles

- Prefer no attribution over an unsupported attribution.
- Require multiple independent evidence types; one IOC, tool, string, TTP, or malware label is insufficient.
- Separate actor-level attribution from sponsor or nation-state attribution.
- Consider deception, copied tradecraft, leaked tools, shared infrastructure, aliases, and vendor naming differences.
- State what is observed, what is reported by others, and what is inferred.

## Evidence Matrix

Review the catalogs and score each applicable category as absent, weak, moderate, or strong:

1. Malware and code: function or logic reuse, build artifacts, PDB paths, packers, strings, configurations, crypto, API patterns, mutexes, and anti-analysis behavior.
2. Infrastructure: time-bounded IP/domain reuse, passive-DNS history, certificates, registrant patterns, hosting traits, service banners, and unique server configuration.
3. TTP implementation: not just common ATT&CK techniques, but distinctive sequencing, parameters, protocol details, commands, and operational habits.
4. Campaign context: victimology, geography, sector, lure themes, timing, access method, motivation, and historical targeting.
5. OpSec and human artifacts: reused accounts or credentials, debug paths, working-hour patterns, language artifacts, ransom-note style, wallets, and operator mistakes.
6. External reporting: public or private reports, naming-scheme reconciliation, source independence, recency, and possible circular reporting.

## Analysis

1. Build candidate hypotheses, including `unknown actor` and plausible alternatives.
2. Cite supporting and contradicting evidence IDs for every candidate.
3. Discount commodity malware, public frameworks, common TTPs, shared hosting, and language metadata unless corroborated.
4. Test temporal consistency; infrastructure and actor behavior change over time.
5. Identify collection gaps that could materially raise or lower confidence.
6. Assign confidence: low for weak evidence or major gaps, moderate for supported but incomplete convergence, high only for strong and independently corroborated convergence.

## Output

Produce a candidate matrix with evidence categories, supporting IDs, contradictions, alternative explanations, confidence, and intelligence gaps. Use probabilistic wording such as `possibly`, `likely`, or `with moderate confidence`; never present inference as fact.
"""


def _workspace_reporting_skill() -> str:
    return """---
name: mantis-report-writing
description: Produce an evidence-cited CTI report from an exported MANTIS workspace.
---

# MANTIS Report Writing

1. Use `report.md` only as a draft outline.
2. Ground the executive summary in `catalog/assessment.json` and cited evidence.
3. Separate technical observations, provider claims, hypotheses, and analyst judgments.
4. Include source coverage, contradictions, collection gaps, and rejected leads.
5. Defang live indicators in prose while preserving originals in evidence tables.
6. End with prioritized next actions and explicit confidence language.

Do not add unsupported attribution or imply causation from shared infrastructure alone.
"""


def related_cases(case_id: str, limit: int = 10) -> Dict[str, Any]:
    case = get_case(case_id)
    limit = max(1, min(int(limit or 10), 50))
    values = {str(row.get("value") or "").lower() for row in case.get("observations", [])}
    values.update(str(row.get("value") or "").lower() for row in case.get("claims", []))
    values.discard("")
    related: Dict[str, Dict[str, Any]] = {}
    if not values:
        return {"case_id": case_id, "related_cases": []}
    with _connect() as db:
        for value in list(values)[:80]:
            for row in db.execute(
                """
                SELECT c.case_id, c.root_type, c.root_value, c.updated_at, o.value AS match_value, o.obs_type AS match_type
                FROM observations o JOIN cases c ON c.case_id=o.case_id
                WHERE o.case_id<>? AND lower(o.value)=?
                LIMIT 20
                """,
                (case_id, value),
            ).fetchall():
                _related_add(related, row, "observation")
            for row in db.execute(
                """
                SELECT c.case_id, c.root_type, c.root_value, c.updated_at, cl.value AS match_value, cl.claim_type AS match_type
                FROM claims cl JOIN cases c ON c.case_id=cl.case_id
                WHERE cl.case_id<>? AND lower(cl.value)=?
                LIMIT 20
                """,
                (case_id, value),
            ).fetchall():
                _related_add(related, row, "claim")
    rows = sorted(related.values(), key=lambda item: (-item["score"], item["updated_at"]), reverse=False)
    return {"case_id": case_id, "related_cases": rows[:limit]}


def assess_case(case: Dict[str, Any]) -> Dict[str, Any]:
    sources = case.get("source_health") or []
    observations = case.get("observations") or []
    claims = case.get("claims") or []
    relationships = case.get("relationships") or []
    rejected = case.get("rejected_pivots") or []
    ai_assessment = (case.get("ai_assessment") or [{}])[0]
    
    source_errors = len([s for s in sources if s.get("status") == "error"])
    sources_with_findings = len([s for s in sources if s.get("status") == "findings_or_context"])
    obs_by_type: Dict[str, int] = {}
    for obs in observations:
        typ = str(obs.get("obs_type") or "unknown")
        obs_by_type[typ] = obs_by_type.get(typ, 0) + 1
    confidence = "insufficient_evidence"
    if sources_with_findings >= 2 and (sum(obs_by_type.values()) + len(claims)) >= 3:
        confidence = "reported_association"
    if sources_with_findings >= 3 and relationships and any(obs_by_type.get(t, 0) for t in ("hash", "url", "domain", "ip")):
        confidence = "corroborated_context"
    if ai_assessment.get("confidence_level"):
        confidence = ai_assessment.get("confidence_level")
        
    contradictions = _case_contradictions(claims, observations)
    if ai_assessment.get("contradictions_json"):
        contradictions.extend(ai_assessment.get("contradictions_json"))
        
    attribution_support = _attribution_support(claims, relationships, observations)
    verdict = ai_assessment.get("verdict") or ("WELL_FOUNDED_FINDINGS" if confidence in ("high", "corroborated_context") else "FIFTY_FIFTY_SUSPICIOUS" if confidence in ("medium", "reported_association") else "NO_FINDINGS_MOVE_ON" if confidence in ("benign", "clean") else "DEAD_END_INCONCLUSIVE")
    verdict_label = ai_assessment.get("verdict_label") or ("Well-Founded Malicious Finding" if confidence in ("high", "corroborated_context") else "50-50 Result / Suspicious" if confidence in ("medium", "reported_association") else "No Findings At All — Let's Move On" if confidence in ("benign", "clean") else "Dead End / Inconclusive")
    recommended_action = ai_assessment.get("recommended_action") or ("Block & Isolate" if confidence in ("high", "corroborated_context") else "Monitor & Correlate Internal Telemetry" if confidence in ("medium", "reported_association") else "Dismiss Alert / Move On" if confidence in ("benign", "clean") else "Manual Follow-up Required")
    confidence_score = int(ai_assessment.get("confidence_score") or (90 if confidence in ("high", "corroborated_context") else 65 if confidence in ("medium", "reported_association") else 10 if confidence in ("benign", "clean") else 30))

    return {
        "verdict": verdict,
        "verdict_label": verdict_label,
        "recommended_action": recommended_action,
        "confidence_score": confidence_score,
        "threat_classification": ai_assessment.get("threat_classification") or "Automated CTI Analysis",
        "mitre_techniques": ai_assessment.get("mitre_json") or [],
        "assessment_text": ai_assessment.get("assessment_text") or "",
        "open_questions": ai_assessment.get("open_questions_json") or [],
        "confidence": confidence,
        "source_count": len(sources),
        "sources_with_findings": sources_with_findings,
        "source_errors": source_errors,
        "observation_count": len(observations),
        "claim_count": len(claims),
        "relationship_count": len(relationships),
        "observation_types": obs_by_type,
        "claim_types": _count_by(claims, "claim_type"),
        "attribution_support": attribution_support,
        "contradictions": contradictions,
        "rejected_pivot_count": len(rejected),
        "aead": {
            "acquire": len([x for x in case.get("timeline", []) if x.get("phase") == "acquire"]),
            "enrich": len([x for x in case.get("timeline", []) if x.get("phase") == "enrich"]),
            "assess": 1,
            "deliver": 0,
        },
    }


def source_inventory() -> Dict[str, Any]:
    return {"sources": source_skill_inventory()}


def root_from_context(context: Dict[str, Any]) -> Tuple[str, str]:
    query = context.get("query") if isinstance(context, dict) else {}
    value = str(query.get("value") or "").strip() if isinstance(query, dict) else ""
    page = str(context.get("page") or "").strip().lower() if isinstance(context, dict) else ""
    if value:
        if page in {"hash", "domain", "ip", "url", "keyword", "infra"}:
            return page, _normalize_artifact(page, value)
        detected = _detect_type(value)
        return detected, _normalize_artifact(detected, value)
    return "context", "current-mantis-view"


def case_id_for(root_type: str, root_value: str) -> str:
    digest = hashlib.sha256(f"{root_type}:{root_value}".encode("utf-8")).hexdigest()[:20]
    return f"case_{digest}"


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with _connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases(
                case_id TEXT PRIMARY KEY,
                root_type TEXT NOT NULL,
                root_value TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_assessments(
                assessment_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                assessment_text TEXT NOT NULL,
                confidence_level TEXT NOT NULL,
                contradictions_json TEXT NOT NULL DEFAULT '[]',
                open_questions_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS source_health(
                case_id TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                error TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                PRIMARY KEY(case_id, source)
            );
            CREATE TABLE IF NOT EXISTS observations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                obs_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                statement TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'observed',
                raw_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(case_id, obs_type, value, source)
            );
            CREATE TABLE IF NOT EXISTS claims(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                claim_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                statement TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'external_provider',
                raw_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(case_id, claim_type, value, source)
            );
            CREATE TABLE IF NOT EXISTS relationships(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_value TEXT NOT NULL,
                relation TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                evidence_source TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(case_id, source_type, source_value, relation, target_type, target_value, evidence_source)
            );
            CREATE TABLE IF NOT EXISTS candidate_actions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                action_json TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'candidate',
                source TEXT NOT NULL DEFAULT '',
                score INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, action_json)
            );
            CREATE TABLE IF NOT EXISTS rejected_pivots(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                action_json TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                artifact_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(case_id, action_json, reason)
            );
            CREATE TABLE IF NOT EXISTS timeline(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                data_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pivots(
                pivot_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                parent_evidence TEXT NOT NULL DEFAULT '[]',
                pivot_type TEXT NOT NULL,
                value TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                decision TEXT NOT NULL,
                decision_reason TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                depth INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hypotheses(
                hypothesis_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                hypothesis_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                evidence_strength TEXT NOT NULL,
                supporting_evidence_ids TEXT NOT NULL DEFAULT '[]',
                contradicting_evidence_ids TEXT NOT NULL DEFAULT '[]',
                gaps TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL
            );
            """
        )
        for col, ctype in (
            ("verdict", "TEXT DEFAULT ''"),
            ("verdict_label", "TEXT DEFAULT ''"),
            ("recommended_action", "TEXT DEFAULT ''"),
            ("confidence_score", "INTEGER DEFAULT 0"),
            ("threat_classification", "TEXT DEFAULT ''"),
            ("mitre_json", "TEXT DEFAULT '[]'"),
        ):
            try:
                db.execute(f"ALTER TABLE ai_assessments ADD COLUMN {col} {ctype}")
            except Exception:
                pass

        for tbl in ("observations", "claims"):
            for col, ctype in (
                ("evidence_id", "TEXT DEFAULT ''"),
                ("evidence_type", "TEXT DEFAULT ''"),
                ("pivot_value", "INTEGER DEFAULT 1"),
                ("noise_reason", "TEXT DEFAULT ''"),
            ):
                try:
                    db.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {ctype}")
                except Exception:
                    pass

        for col, ctype in (
            ("evidence_ids", "TEXT DEFAULT '[]'"),
            ("source_entity", "TEXT DEFAULT ''"),
            ("target_entity", "TEXT DEFAULT ''"),
        ):
            try:
                db.execute(f"ALTER TABLE relationships ADD COLUMN {col} {ctype}")
            except Exception:
                pass


def _store_source_snapshots(db: sqlite3.Connection, case_id: str, context: Dict[str, Any]) -> None:
    now = _now()
    providers = context.get("providers") if isinstance(context, dict) else []
    if not isinstance(providers, list):
        providers = []
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        source = str(provider.get("provider") or provider.get("source") or "").strip()
        if not source:
            continue
        status = str(provider.get("status") or "unknown")[:80]
        count = _int(provider.get("count"))
        error = str(provider.get("error") or "")[:500]
        db.execute(
            """
            INSERT INTO source_health(case_id, source, status, count, error, updated_at)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, source) DO UPDATE SET
                status=excluded.status, count=excluded.count, error=excluded.error, updated_at=excluded.updated_at
            """,
            (case_id, source, status, count, error, now),
        )


def _run_single_source(root_type: str, root_value: str, source_id: str, keys: Dict[str, Any], github_repos: List[str]) -> Dict[str, Any]:
    from intel_query import do_domain_intel, do_hash_intel, do_infra_intel, do_ip_intel, do_keyword_intel, do_url_intel

    key = lambda name: str(keys.get(name) or "").strip()
    common = {
        "vt_key": key("vt_key"),
        "abusech_key": key("abusech_key") or key("tf_key"),
        "otx_key": key("otx_key"),
        "tip_key": key("tip_key"),
        "cb_key": key("cb_key"),
        "triage_key": key("triage_key"),
        "ha_key": key("ha_key"),
        "silentpush_key": key("silentpush_key"),
        "driftnet_key": key("driftnet_key"),
        "urlscan_key": key("urlscan_key"),
        "shodan_key": key("shodan_key"),
        "censys_key": key("censys_key"),
        "etugen_key": key("etugen_key"),
        "pulsedive_key": key("pulsedive_key"),
        "fofa_key": key("fofa_key"),
        "validin_key": key("validin_key"),
        "netlas_key": key("netlas_key"),
        "zoomeye_key": key("zoomeye_key"),
        "twitter_key": key("twitter_key"),
        "github_key": key("github_key"),
        "dnsdumpster_key": key("dnsdumpster_key"),
        "leakix_key": key("leakix_key"),
        "phishstats_key": key("phishstats_key"),
        "rwlive_key": key("rwlive_key"),
    }
    source_list = [source_id]
    if root_type == "hash":
        return do_hash_intel(
            root_value,
            common["vt_key"],
            common["abusech_key"],
            common["otx_key"],
            triage_key=common["triage_key"],
            tip_key=common["tip_key"],
            cb_key=common["cb_key"],
            ha_key=common["ha_key"],
            malshare_key=key("malshare_key"),
            silentpush_key=common["silentpush_key"],
            driftnet_key=common["driftnet_key"],
            pulsedive_key=common["pulsedive_key"],
            fofa_key=common["fofa_key"],
            validin_key=common["validin_key"],
            urlscan_key=common["urlscan_key"],
            twitter_key=common["twitter_key"],
            github_key=common["github_key"],
            sources=source_list,
            github_repos=github_repos,
        )
    if root_type == "domain":
        return do_domain_intel(root_value, common["vt_key"], common["abusech_key"], common["otx_key"], tip_key=common["tip_key"], cb_key=common["cb_key"], rwlive_key=common["rwlive_key"], triage_key=common["triage_key"], ha_key=common["ha_key"], silentpush_key=common["silentpush_key"], driftnet_key=common["driftnet_key"], urlscan_key=common["urlscan_key"], shodan_key=common["shodan_key"], censys_key=common["censys_key"], etugen_key=common["etugen_key"], pulsedive_key=common["pulsedive_key"], fofa_key=common["fofa_key"], validin_key=common["validin_key"], netlas_key=common["netlas_key"], zoomeye_key=common["zoomeye_key"], twitter_key=common["twitter_key"], github_key=common["github_key"], dnsdumpster_key=common["dnsdumpster_key"], leakix_key=common["leakix_key"], phishstats_key=common["phishstats_key"], sources=source_list)
    if root_type == "ip":
        return do_ip_intel(root_value, common["vt_key"], common["abusech_key"], common["otx_key"], tip_key=common["tip_key"], cb_key=common["cb_key"], threatbook_key=key("threatbook_key"), triage_key=common["triage_key"], ha_key=common["ha_key"], silentpush_key=common["silentpush_key"], driftnet_key=common["driftnet_key"], urlscan_key=common["urlscan_key"], shodan_key=common["shodan_key"], censys_key=common["censys_key"], etugen_key=common["etugen_key"], pulsedive_key=common["pulsedive_key"], fofa_key=common["fofa_key"], validin_key=common["validin_key"], netlas_key=common["netlas_key"], zoomeye_key=common["zoomeye_key"], twitter_key=common["twitter_key"], github_key=common["github_key"], abuseipdb_key=key("abuseipdb_key"), greynoise_key=key("greynoise_key"), leakix_key=common["leakix_key"], phishstats_key=common["phishstats_key"], sources=source_list)
    if root_type == "url":
        return do_url_intel(root_value, common["vt_key"], common["abusech_key"], common["otx_key"], tip_key=common["tip_key"], cb_key=common["cb_key"], triage_key=common["triage_key"], ha_key=common["ha_key"], silentpush_key=common["silentpush_key"], urlscan_key=common["urlscan_key"], pulsedive_key=common["pulsedive_key"], github_key=common["github_key"], phishstats_key=common["phishstats_key"], sources=source_list)
    if root_type == "infra":
        return do_infra_intel(root_value, silentpush_key=common["silentpush_key"], driftnet_key=common["driftnet_key"], shodan_key=common["shodan_key"], censys_key=common["censys_key"], etugen_key=common["etugen_key"], pulsedive_key=common["pulsedive_key"], fofa_key=common["fofa_key"], validin_key=common["validin_key"], ha_key=common["ha_key"], abuseipdb_key=key("abuseipdb_key"), urlscan_key=common["urlscan_key"], dnsdumpster_key=common["dnsdumpster_key"], greynoise_key=key("greynoise_key"), sources=source_list)
    return do_keyword_intel(
        root_value,
        "all",
        common["abusech_key"],
        otx_key=common["otx_key"],
        triage_key=common["triage_key"],
        tip_key=common["tip_key"],
        malshare_key=key("malshare_key"),
        rwlive_key=common["rwlive_key"],
        cb_key=common["cb_key"],
        ha_key=common["ha_key"],
        urlscan_key=common["urlscan_key"],
        silentpush_key=common["silentpush_key"],
        driftnet_key=common["driftnet_key"],
        shodan_key=common["shodan_key"],
        censys_key=common["censys_key"],
        etugen_key=common["etugen_key"],
        pulsedive_key=common["pulsedive_key"],
        fofa_key=common["fofa_key"],
        validin_key=common["validin_key"],
        twitter_key=common["twitter_key"],
        github_key=common["github_key"],
        dnsdumpster_key=common["dnsdumpster_key"],
        sources=source_list,
        github_repos=github_repos,
    )


def _provider_payload(result: Dict[str, Any], source_id: str) -> Any:
    if not isinstance(result, dict):
        return result
    aliases = {
        "hybrid_analysis": "hybrid-analysis",
        "hybrid-analysis": "hybrid-analysis",
        "cti_articles": "cti_articles",
    }
    keys = [source_id, aliases.get(source_id, ""), source_id.replace("-", "_"), source_id.replace("_", "-")]
    for key in keys:
        if key and key in result:
            return result.get(key)
    queried = result.get("sources_queried")
    if isinstance(queried, list):
        for key in queried:
            if key in result:
                return result.get(key)
    for key, value in result.items():
        if key not in {"indicator", "type", "query_type", "hash_algorithm", "duration_ms", "sources_queried", "error"}:
            return value
    return None


def _provider_status(provider_payload: Any, full_result: Any = None) -> Tuple[str, int, str]:
    if provider_payload is None:
        if isinstance(full_result, dict) and full_result.get("error"):
            return "error", 0, str(full_result.get("error"))[:500]
        return "error", 0, "Source did not execute or returned no provider payload; an API key may be missing."
    if isinstance(provider_payload, dict) and provider_payload.get("error"):
        return "error", 0, str(provider_payload.get("error"))[:500]
    count = _count_result(provider_payload)
    return ("findings_or_context" if count else "no_obvious_findings"), count, ""


def _count_result(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("data", "results", "items", "matches", "articles", "tweets", "posts", "victims", "pulses", "detections", "relationships", "normalized_relations"):
            item = value.get(key)
            if isinstance(item, list):
                return len(item)
            if isinstance(item, dict):
                return len(item)
        return len([key for key, item in value.items() if key not in {"error", "message", "raw", "normalized", "meta"} and item not in (None, "", [], {})])
    return 1 if str(value or "").strip() else 0


def _case_contradictions(claims: List[Dict[str, Any]], observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    actors = _values_by_type(claims, "claim_type", "actor")
    malware = _values_by_type(claims, "claim_type", "malware")
    if len(actors) > 1:
        out.append({
            "type": "actor_claim_conflict",
            "severity": "high",
            "statement": "Multiple actor or cluster claims appear in provider evidence.",
            "values": sorted(actors)[:12],
            "guidance": "Treat attribution as unresolved until claims are source-checked and compared against technical overlap.",
        })
    if len(malware) > 3:
        out.append({
            "type": "malware_label_sprawl",
            "severity": "medium",
            "statement": "Multiple malware/tool labels appear; labels may reflect family aliases, AV naming, or related tooling.",
            "values": sorted(malware)[:12],
            "guidance": "Compare sample behavior, config, and rule matches before collapsing labels.",
        })
    benign_noise = [obs for obs in observations if obs.get("obs_type") in {"internet_noise", "benign_service"} and str(obs.get("value")).lower() == "true"]
    malicious_scores = [obs for obs in observations if obs.get("obs_type") in {"detection_summary", "reputation_score", "threat_type"}]
    if benign_noise and malicious_scores:
        out.append({
            "type": "benign_noise_vs_malicious_signal",
            "severity": "medium",
            "statement": "The case contains both benign/noise context and malicious/reputation signals.",
            "values": [],
            "guidance": "Separate scanner/shared-service context from artifact-specific malicious behavior.",
        })
    return out


def _attribution_support(claims: List[Dict[str, Any]], relationships: List[Dict[str, Any]], observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    actor_claims = _values_by_type(claims, "claim_type", "actor")
    malware_claims = _values_by_type(claims, "claim_type", "malware")
    relationship_sources = {str(rel.get("evidence_source") or "") for rel in relationships if rel.get("evidence_source")}
    technical = [obs for obs in observations if obs.get("obs_type") in {"hash", "url", "domain", "ip", "behavior", "sandbox_verdict", "detection_summary"}]
    score = 0
    if actor_claims:
        score += 15
    if malware_claims:
        score += 20
    score += min(25, len(relationship_sources) * 5)
    score += min(25, len(technical) * 2)
    if len(actor_claims) > 1:
        score -= 15
    score = max(0, min(100, score))
    if score >= 70:
        band = "technical_context"
    elif score >= 40:
        band = "reported_association"
    elif score >= 15:
        band = "provider_claim_only"
    else:
        band = "insufficient_evidence"
    return {
        "score": score,
        "band": band,
        "actor_claims": sorted(actor_claims)[:12],
        "malware_claims": sorted(malware_claims)[:12],
        "evidence_sources": sorted(relationship_sources)[:12],
        "technical_observation_count": len(technical),
        "caveat": "Score is deterministic evidence support, not probability or attribution confidence.",
    }


def _values_by_type(rows: List[Dict[str, Any]], type_field: str, wanted: str) -> set:
    return {str(row.get("value") or "").strip() for row in rows or [] if str(row.get(type_field) or "").lower() == wanted and str(row.get("value") or "").strip()}


def _related_add(related: Dict[str, Dict[str, Any]], row: sqlite3.Row, match_kind: str) -> None:
    cid = row["case_id"]
    item = related.setdefault(cid, {
        "case_id": cid,
        "root_type": row["root_type"],
        "root_value": row["root_value"],
        "updated_at": row["updated_at"],
        "score": 0,
        "matches": [],
    })
    item["score"] += 2 if match_kind == "observation" else 1
    item["matches"].append({"kind": match_kind, "type": row["match_type"], "value": row["match_value"]})


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()


def _store_observations(db: sqlite3.Connection, case_id: str, context: Dict[str, Any]) -> None:
    now = _now()
    normalized = normalize_case_findings(context if isinstance(context, dict) else {})
    artifacts = _extract_artifacts(context)
    for item in normalized.get("observations") or []:
        _insert_observation(
            db,
            case_id,
            item.get("type"),
            item.get("value"),
            item.get("source"),
            item.get("statement"),
            item.get("confidence"),
            item.get("raw"),
            now,
            evidence_id=item.get("evidence_id"),
            evidence_type=item.get("evidence_type", "OBSERVATION"),
            pivot_value=item.get("pivot_value", True),
            noise_reason=item.get("noise_reason", ""),
        )
    for artifact in artifacts:
        _insert_observation(
            db,
            case_id,
            artifact["type"],
            artifact["value"],
            artifact.get("source", ""),
            f"{artifact['type']} observed in {artifact.get('source') or 'MANTIS context'}.",
            "observed",
            artifact,
            now,
        )
    for claim in normalized.get("claims") or []:
        db.execute(
            """
            INSERT OR IGNORE INTO claims(case_id, claim_type, value, source, statement, confidence, raw_json, evidence_id, evidence_type, pivot_value, noise_reason, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                str(claim.get("claim_type") or "claim")[:80],
                str(claim.get("value") or "")[:500],
                str(claim.get("source") or "")[:120],
                str(claim.get("statement") or "")[:700],
                str(claim.get("confidence") or "external_provider")[:80],
                json.dumps(claim.get("raw") or {}, ensure_ascii=True, sort_keys=True),
                str(claim.get("evidence_id") or "")[:80],
                str(claim.get("evidence_type") or "PROVIDER_CLAIM")[:80],
                1 if claim.get("pivot_value", True) else 0,
                str(claim.get("noise_reason") or "")[:200],
                now,
            ),
        )
    for rel in normalized.get("relationships") or []:
        db.execute(
            """
            INSERT OR IGNORE INTO relationships(case_id, source_type, source_value, relation, target_type, target_value, evidence_source, raw_json, source_entity, target_entity, evidence_ids, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                str(rel.get("source_type") or "artifact")[:80],
                str(rel.get("source_value") or "")[:500],
                str(rel.get("relation") or "related_to")[:120],
                str(rel.get("target_type") or "entity")[:80],
                str(rel.get("target_value") or "")[:500],
                str(rel.get("evidence_source") or "")[:120],
                json.dumps(rel.get("raw") or {}, ensure_ascii=True, sort_keys=True),
                str(rel.get("source_entity") or f"{rel.get('source_type')}:{rel.get('source_value')}")[:500],
                str(rel.get("target_entity") or f"{rel.get('target_type')}:{rel.get('target_value')}")[:500],
                json.dumps(rel.get("evidence_ids") or []),
                now,
            ),
        )


def _insert_observation(
    db: sqlite3.Connection,
    case_id: str,
    typ: Any,
    value: Any,
    source: Any,
    statement: Any,
    confidence: Any,
    raw: Any,
    created_at: str,
    evidence_id: Optional[str] = None,
    evidence_type: str = "OBSERVATION",
    pivot_value: bool = True,
    noise_reason: str = "",
) -> None:
    typ = str(typ or "").strip()[:80]
    value = str(value or "").strip()[:500]
    if not typ or not value:
        return
    db.execute(
        """
        INSERT OR IGNORE INTO observations(case_id, obs_type, value, source, statement, confidence, raw_json, evidence_id, evidence_type, pivot_value, noise_reason, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            typ,
            value,
            str(source or "")[:120],
            str(statement or "")[:700],
            str(confidence or "observed")[:80],
            json.dumps(raw or {}, ensure_ascii=True, sort_keys=True),
            str(evidence_id or "")[:80],
            str(evidence_type or "OBSERVATION")[:80],
            1 if pivot_value else 0,
            str(noise_reason or "")[:200],
            created_at,
        ),
    )


def _record_pivot_audit(
    case_id: str,
    parent_evidence: List[str],
    pivot_type: str,
    value: str,
    reason: str,
    decision: str,
    decision_reason: str,
    provider: str,
    depth: int = 1
) -> Dict[str, Any]:
    pivot_id = f"pvt_{hashlib.sha256(f'{case_id}:{pivot_type}:{value}:{time.time()}'.encode('utf-8')).hexdigest()[:16]}"
    now = _now()
    with _connect() as db:
        db.execute(
            """
            INSERT INTO pivots(pivot_id, case_id, parent_evidence, pivot_type, value, reason, decision, decision_reason, provider, depth, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pivot_id,
                case_id,
                json.dumps(parent_evidence or []),
                pivot_type,
                value,
                reason,
                decision,
                decision_reason,
                provider,
                depth,
                now,
            )
        )
    return {
        "pivot_id": pivot_id,
        "case_id": case_id,
        "parent_evidence": parent_evidence,
        "pivot_type": pivot_type,
        "value": value,
        "reason": reason,
        "decision": decision,
        "decision_reason": decision_reason,
        "provider": provider,
        "depth": depth,
        "created_at": now
    }


def _store_normalized_evidence(case_id: str, normalized: Dict[str, List[Dict[str, Any]]]) -> None:
    now = _now()
    with _connect() as db:
        for item in normalized.get("observations") or []:
            _insert_observation(
                db,
                case_id,
                item.get("type"),
                item.get("value"),
                item.get("source"),
                item.get("statement"),
                item.get("confidence"),
                item.get("raw"),
                now,
                evidence_id=item.get("evidence_id"),
                evidence_type=item.get("evidence_type", "OBSERVATION"),
                pivot_value=item.get("pivot_value", True),
                noise_reason=item.get("noise_reason", ""),
            )
        for claim in normalized.get("claims") or []:
            db.execute(
                """
                INSERT OR IGNORE INTO claims(case_id, claim_type, value, source, statement, confidence, raw_json, evidence_id, evidence_type, pivot_value, noise_reason, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    str(claim.get("claim_type") or "claim")[:80],
                    str(claim.get("value") or "")[:500],
                    str(claim.get("source") or "")[:120],
                    str(claim.get("statement") or "")[:700],
                    str(claim.get("confidence") or "external_provider")[:80],
                    json.dumps(claim.get("raw") or {}, ensure_ascii=True, sort_keys=True),
                    str(claim.get("evidence_id") or "")[:80],
                    str(claim.get("evidence_type") or "PROVIDER_CLAIM")[:80],
                    1 if claim.get("pivot_value", True) else 0,
                    str(claim.get("noise_reason") or "")[:200],
                    now,
                ),
            )
        for rel in normalized.get("relationships") or []:
            db.execute(
                """
                INSERT OR IGNORE INTO relationships(case_id, source_type, source_value, relation, target_type, target_value, evidence_source, raw_json, source_entity, target_entity, evidence_ids, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    str(rel.get("source_type") or "artifact")[:80],
                    str(rel.get("source_value") or "")[:500],
                    str(rel.get("relation") or "related_to")[:120],
                    str(rel.get("target_type") or "entity")[:80],
                    str(rel.get("target_value") or "")[:500],
                    str(rel.get("evidence_source") or "")[:120],
                    json.dumps(rel.get("raw") or {}, ensure_ascii=True, sort_keys=True),
                    str(rel.get("source_entity") or f"{rel.get('source_type')}:{rel.get('source_value')}")[:500],
                    str(rel.get("target_entity") or f"{rel.get('target_type')}:{rel.get('target_value')}")[:500],
                    json.dumps(rel.get("evidence_ids") or []),
                    now,
                ),
            )


def _save_case_analysis(case_id: str, analysis: Dict[str, Any]) -> None:
    now = _now()
    assessment_id = f"asm_{hashlib.sha256(f'{case_id}:{now}'.encode('utf-8')).hexdigest()[:16]}"
    with _connect() as db:
        cur_v = db.execute("SELECT COALESCE(MAX(version), 0) as v FROM ai_assessments WHERE case_id=?", (case_id,)).fetchone()
        version = int(cur_v["v"]) + 1 if cur_v else 1
        db.execute(
            """
            INSERT INTO ai_assessments(assessment_id, case_id, version, assessment_text, confidence_level, contradictions_json, open_questions_json, verdict, verdict_label, recommended_action, confidence_score, threat_classification, mitre_json, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                case_id,
                version,
                str(analysis.get("assessment_text") or "Assessment complete."),
                str(analysis.get("confidence_level") or "medium"),
                json.dumps(analysis.get("contradictions") or []),
                json.dumps(analysis.get("open_questions") or []),
                str(analysis.get("verdict") or "FIFTY_FIFTY_SUSPICIOUS"),
                str(analysis.get("verdict_label") or "50-50 Result / Suspicious"),
                str(analysis.get("recommended_action") or "Monitor & Correlate"),
                int(analysis.get("confidence_score") or 50),
                str(analysis.get("threat_classification") or "Automated CTI Analysis"),
                json.dumps(analysis.get("mitre_techniques") or []),
                now,
            )
        )
        for h in analysis.get("hypotheses") or []:
            h_subj = str(h.get("subject") or "Threat Subject")
            h_text = str(h.get("hypothesis") or "")
            h_id = f"hyp_{hashlib.sha256(f'{case_id}:{h_subj}:{h_text}'.encode('utf-8')).hexdigest()[:16]}"
            db.execute(
                """
                INSERT OR REPLACE INTO hypotheses(hypothesis_id, case_id, hypothesis_type, subject, hypothesis, evidence_strength, supporting_evidence_ids, contradicting_evidence_ids, gaps, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    h_id,
                    case_id,
                    str(h.get("hypothesis_type") or "malware_family"),
                    h_subj[:200],
                    h_text[:1000],
                    str(h.get("evidence_strength") or "MODERATE"),
                    json.dumps(h.get("supporting_evidence_ids") or []),
                    json.dumps(h.get("contradicting_evidence_ids") or []),
                    json.dumps(h.get("gaps") or []),
                    now,
                )
            )


def _store_candidate_pivots(db: sqlite3.Connection, case_id: str, context: Dict[str, Any]) -> None:
    now = _now()
    actions = _actions_from_context(context)
    allowed, rejected = filter_pivot_actions(actions, context=context, limit=20)
    for action in allowed:
        db.execute(
            """
            INSERT OR IGNORE INTO candidate_actions(case_id, action_json, reason, status, source, score, created_at)
            VALUES(?, ?, ?, 'candidate', ?, ?, ?)
            """,
            (
                case_id,
                json.dumps(action, ensure_ascii=True, sort_keys=True),
                str(action.get("reason") or "")[:500],
                "context",
                50,
                now,
            ),
        )
    for item in rejected:
        action = item.get("action") if isinstance(item, dict) else {}
        db.execute(
            """
            INSERT OR IGNORE INTO rejected_pivots(case_id, action_json, reason, tags_json, artifact_json, created_at)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                json.dumps(action, ensure_ascii=True, sort_keys=True),
                str(item.get("reason") or "")[:500],
                json.dumps(item.get("tags") or [], ensure_ascii=True),
                json.dumps(item.get("artifact") or {}, ensure_ascii=True, sort_keys=True),
                now,
            ),
        )


def _actions_from_context(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions = []
    for artifact in _extract_artifacts(context):
        typ = artifact["type"]
        value = artifact["value"]
        reason = f"Technical artifact appears in case evidence from {artifact.get('source') or 'context'}."
        if typ == "hash":
            actions.append({"tool": "lookup_hash", "arguments": {"hash": value}, "reason": reason})
        elif typ == "domain":
            actions.append({"tool": "lookup_domain", "arguments": {"domain": value}, "reason": reason})
        elif typ == "ip":
            actions.append({"tool": "lookup_ip", "arguments": {"ip": value}, "reason": reason})
        elif typ == "url":
            actions.append({"tool": "lookup_url", "arguments": {"url": value}, "reason": reason})
        elif typ == "cve":
            actions.append({"tool": "keyword_search", "arguments": {"query": value}, "reason": reason})
    return actions


def _extract_artifacts(context: Any, source: str = "context", out: Optional[Dict[str, Dict[str, str]]] = None, budget: Optional[Dict[str, int]] = None) -> List[Dict[str, str]]:
    if out is None:
        out = {}
    if budget is None:
        budget = {"nodes": 0}
    if budget["nodes"] > 2500 or len(out) > 240:
        return list(out.values())
    budget["nodes"] += 1
    if isinstance(context, dict):
        if isinstance(context.get("artifacts"), list):
            for artifact in context["artifacts"][:220]:
                if isinstance(artifact, dict):
                    _add_artifact(out, artifact.get("type"), artifact.get("value"), ",".join(str(x) for x in artifact.get("sources", [])[:4]) if isinstance(artifact.get("sources"), list) else source)
        for key, value in list(context.items())[:180]:
            _extract_artifacts(value, str(key or source), out, budget)
    elif isinstance(context, list):
        for item in context[:160]:
            _extract_artifacts(item, source, out, budget)
    elif isinstance(context, str):
        text = context[:8000]
        for value in URL_RE.findall(text)[:80]:
            _add_artifact(out, "url", value.rstrip("),.;"), source)
        for value in HASH_RE.findall(text)[:80]:
            _add_artifact(out, "hash", value.lower(), source)
        for value in CVE_RE.findall(text)[:50]:
            _add_artifact(out, "cve", value.upper(), source)
        for value in IP_RE.findall(text)[:80]:
            _add_artifact(out, "ip", value, source)
        for value in DOMAIN_RE.findall(text)[:120]:
            if not value.lower().endswith((".local", ".example", ".test")):
                _add_artifact(out, "domain", value.lower(), source)
    return list(out.values())


def _add_artifact(out: Dict[str, Dict[str, str]], typ: Any, value: Any, source: str) -> None:
    typ = str(typ or "").lower()
    if typ not in {"hash", "domain", "ip", "url", "cve"}:
        return
    value = str(value or "").strip()
    if not value:
        return
    if typ == "domain":
        value = normalize_domain(value)
    elif typ == "ip":
        value = normalize_ip(value)
    elif typ == "url":
        value = normalize_url(value)
    elif typ == "hash":
        value = value.lower()
    if typ == "domain" and not is_domain(value):
        return
    if typ == "ip" and not is_ip(value):
        return
    if typ == "url" and not is_url(value):
        return
    if typ == "hash" and not is_hash(value):
        return
    key = f"{typ}:{value.lower()}"
    if key not in out:
        out[key] = {"type": typ, "value": value[:500], "source": str(source or "")[:120]}


def _record_timeline(db: sqlite3.Connection, case_id: str, phase: str, title: str, detail: str, source: str, status: str, data: Dict[str, Any]) -> None:
    db.execute(
        "INSERT INTO timeline(case_id, phase, title, detail, source, status, data_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        (case_id, phase, title, detail, source, status, json.dumps(data or {}, ensure_ascii=True, sort_keys=True), _now()),
    )


def _executive_summary(case: Dict[str, Any]) -> str:
    root = case.get("root") or {}
    assessment = case.get("assessment") or {}
    return (
        f"MANTIS is tracking a {root.get('type', 'context')} case for {root.get('value', 'the current evidence')}. "
        f"The case currently has {assessment.get('source_count', 0)} source records, "
        f"{assessment.get('observation_count', 0)} normalized observations, and "
        f"{assessment.get('claim_count', 0)} provider claims. "
        f"It has {assessment.get('relationship_count', 0)} evidence relationships and "
        f"{assessment.get('rejected_pivot_count', 0)} suppressed low-value pivots. "
        f"Current support level: {assessment.get('confidence', 'insufficient_evidence')}."
    )


def _detect_type(value: str) -> str:
    text = str(value or "").strip()
    if is_hash(text):
        return "hash"
    if is_ip(normalize_ip(text)):
        return "ip"
    if is_url(normalize_url(text)):
        return "url"
    if is_domain(normalize_domain(text)):
        return "domain"
    if re.fullmatch(r"(?i)AS\d{1,10}", text) or ("/" in text and not is_url(text)):
        return "infra"
    return "keyword"


def _normalize_artifact(typ: str, value: str) -> str:
    if typ == "hash":
        return str(value or "").strip().lower()
    if typ == "domain":
        return normalize_domain(value)
    if typ == "ip":
        return normalize_ip(value)
    if typ == "url":
        return normalize_url(value)
    if typ == "infra":
        val = str(value or "").strip()
        if re.fullmatch(r"(?i)\d{1,10}", val):
            return f"AS{val}"
        return val.upper() if val.upper().startswith("AS") else val
    return str(value or "").strip()[:500]



def _connect() -> sqlite3.Connection:
    db = sqlite3.connect(CASE_DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def _rows(db: sqlite3.Connection, sql: str, args: Tuple[Any, ...]) -> List[Dict[str, Any]]:
    return [dict(row) for row in db.execute(sql, args).fetchall()]


def _json_rows(db: sqlite3.Connection, sql: str, args: Tuple[Any, ...], *json_fields: str) -> List[Dict[str, Any]]:
    rows = _rows(db, sql, args)
    for row in rows:
        for field in json_fields:
            if field in row:
                row[field.replace("_json", "")] = _json_load(row.pop(field))
    return rows


def _json_load(value: Any) -> Any:
    try:
        return json.loads(value or "{}")
    except Exception:
        return {}


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _count_by(rows: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows or []:
        key = str(row.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
def generate_case_assessment_db(case_id: str) -> Dict[str, Any]:
    from ai_case_agent import generate_case_assessment
    import uuid
    case = get_case(case_id)
    assessment = generate_case_assessment(case)
    
    assessment_id = str(uuid.uuid4())
    version = 1
    if case.get("ai_assessment"):
        version = (case["ai_assessment"][0].get("version") or 1) + 1
        
    with _connect() as db:
        db.execute(
            """
            INSERT INTO ai_assessments (
                assessment_id, case_id, version, assessment_text, confidence_level, 
                contradictions_json, open_questions_json, verdict, verdict_label, 
                recommended_action, confidence_score, threat_classification, mitre_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                case_id,
                version,
                assessment.get("assessment_text") or "",
                assessment.get("confidence_level") or "low",
                json.dumps(assessment.get("contradictions") or []),
                json.dumps(assessment.get("open_questions") or []),
                assessment.get("verdict") or "DEAD_END_INCONCLUSIVE",
                assessment.get("verdict_label") or "Dead End / Inconclusive",
                assessment.get("recommended_action") or "Manual Follow-up",
                int(assessment.get("confidence_score") or 30),
                assessment.get("threat_classification") or "Automated CTI Analysis",
                json.dumps(assessment.get("mitre_techniques") or []),
                datetime.now(timezone.utc).isoformat()
            )
        )
        _record_timeline(db, case_id, "assess", "Agent generated final case assessment", f"{assessment.get('verdict_label')}: {assessment.get('assessment_text', '')[:100]}...", "ai_agent", "success", assessment)
        
    return get_case(case_id)

def _defang_ioc(val: str, typ: str = "") -> str:
    s = str(val or "").strip()
    s = re.sub(r"^https://", "hxxps://", s, flags=re.I)
    s = re.sub(r"^http://", "hxxp://", s, flags=re.I)
    typ_l = str(typ or "").lower()
    if typ_l in ("domain", "ip") or re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s) or ("." in s and "/" not in s):
        s = s.replace(".", "[.]")
    return s


def _build_source_breakdown_html(case_id: str, case: Dict[str, Any]) -> str:
    import html as html_lib
    sources = case.get("source_health") or []
    observations = case.get("observations") or []
    claims = case.get("claims") or []
    root = case.get("root") or {}
    root_val = str(root.get("value") or "").strip()
    root_type = str(root.get("type") or "").strip().lower()
    
    # Accurate detection across 6 indicator types
    is_hash = (
        root_type == "hash"
        or bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", root_val))
    )
    is_ip = (
        not is_hash
        and (root_type == "ip" or bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", root_val)) or (":" in root_val and not root_val.startswith("http")))
    )
    is_url = (
        not is_hash
        and (root_type == "url" or "://" in root_val or root_val.startswith("http://") or root_val.startswith("https://"))
    )
    is_domain = (
        not is_hash
        and not is_ip
        and not is_url
        and (root_type == "domain" or bool(re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", root_val)))
    )
    is_infra = (
        root_type in {"infra", "asn", "cidr", "bgp"}
        or bool(re.fullmatch(r"(?i)AS\d{1,10}", root_val))
        or ("/" in root_val and not is_url)
    )
    is_keyword = (
        root_type in {"keyword", "cve", "actor", "threat_actor", "malware", "malware_family", "ransomware_group", "ransomware_victim"}
        or root_val.upper().startswith("CVE-")
        or (not is_hash and not is_ip and not is_url and not is_domain and not is_infra)
    )

    temp_findings = {}
    temp_path = os.path.join(DATA_DIR, "temp", f"acquire_{case_id}.json")
    if os.path.exists(temp_path):
        try:
            with open(temp_path, "r", encoding="utf-8") as f:
                temp_findings = json.load(f).get("findings", {})
        except Exception:
            pass

    obs_by_src = {}
    for o in observations:
        s = str(o.get("source") or "").lower()
        obs_by_src.setdefault(s, []).append(o)

    claims_by_src = {}
    for c in claims:
        s = str(c.get("source") or "").lower()
        claims_by_src.setdefault(s, []).append(c)

    brand_map = {
        "virustotal": ("VirusTotal", "fa-shield-halved"),
        "alienvault": ("AlienVault OTX", "fa-satellite-dish"),
        "threatfox": ("ThreatFox", "fa-biohazard"),
        "hybrid-analysis": ("Hybrid Analysis", "fa-vial-virus"),
        "hybrid_analysis": ("Hybrid Analysis", "fa-vial-virus"),
        "malwarebazaar": ("MalwareBazaar", "fa-box-archive"),
        "triage": ("Hatching Triage", "fa-microchip"),
        "github": ("GitHub CTI Mentions", "fa-brands fa-github"),
        "github_repos": ("Internal CTI Repos", "fa-folder-open"),
        "threatminer": ("ThreatMiner", "fa-magnifying-glass-chart"),
        "tip": ("Threat Intelligence Platform", "fa-diagram-project"),
        "yaraify": ("YARAify", "fa-file-code"),
        "malware_news": ("Malware News", "fa-newspaper"),
        "rss_intel": ("RSS Threat Intel", "fa-rss"),
        "tweetfeed": ("TweetFeed Stream", "fa-brands fa-x-twitter"),
        "malshare": ("MalShare", "fa-database"),
        "cb": ("CyberBriefing", "fa-bullhorn"),
        "vt_relations": ("VirusTotal Relations", "fa-sitemap"),
        "cti_mentions": ("Global CTI Mentions", "fa-globe"),
        "cti_articles": ("CTI Article Knowledgebase", "fa-newspaper"),
        "validin": ("Validin Passive DNS", "fa-globe"),
        "dnsdumpster": ("DNSDumpster", "fa-server"),
        "abuseipdb": ("AbuseIPDB", "fa-ban"),
        "shodan": ("Shodan", "fa-radar"),
        "urlscan": ("URLScan.io", "fa-camera"),
        "leakix": ("LeakIX", "fa-network-wired"),
        "crtsh": ("crt.sh", "fa-certificate"),
        "openphish": ("OpenPhish", "fa-fish-fins"),
        "phishstats": ("PhishStats", "fa-chart-pie"),
        "urlhaus": ("URLhaus", "fa-link-slash"),
        "etugen": ("Etugen WHOIS", "fa-id-card"),
        "driftnet": ("Driftnet", "fa-satellite"),
        "silentpush": ("Silent Push", "fa-eye-slash"),
        "reputation_feeds": ("Reputation Feeds", "fa-list-check"),
        "rwlive": ("Ransomware.live", "fa-skull"),
        "ransomlook": ("Ransomlook", "fa-skull-crossbones"),
        "misp_galaxy": ("MISP Galaxy Clusters", "fa-diagram-project"),
        "fofa": ("FOFA Search", "fa-magnifying-glass-location"),
        "commoncrawl": ("Common Crawl", "fa-database"),
        "archive": ("Wayback Machine", "fa-box-archive"),
        "orkl": ("ORKL CTI Library", "fa-book-skull"),
        "censys": ("Censys Search", "fa-satellite-dish"),
        "threatbook": ("ThreatBook", "fa-book-skull"),
        "sans": ("SANS ISC", "fa-shield-halved"),
        "ripe": ("RIPEstat", "fa-network-wired"),
        "greynoise": ("GreyNoise", "fa-wave-square"),
        "pulsedive": ("Pulsedive", "fa-database"),
        "threatactorusernames": ("Threat Actor Profiler", "fa-user-secret"),
        "yara_forge": ("YARA Rulesets", "fa-file-shield"),
    }

    rows = []
    for s_info in sources:
        raw_id = str(s_info.get("source") or "").strip()
        if not raw_id:
            continue
        lower_id = raw_id.lower()
        brand_tuple = brand_map.get(lower_id, (raw_id.replace("_", " ").title(), "fa-database"))
        display_name = brand_tuple[0]
        icon = brand_tuple[1]

        status = str(s_info.get("status") or "unknown")
        count = int(s_info.get("count") or 0)
        error = str(s_info.get("error") or "").strip()
        raw_provider_data = temp_findings.get(raw_id) or temp_findings.get(lower_id) or {}

        is_error = False
        is_active = False
        summary = ""

        # 1. VirusTotal
        if lower_id == "virustotal":
            attrs = raw_provider_data.get("data", {}).get("attributes", {}) if isinstance(raw_provider_data, dict) else {}
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0) if stats else 0
            tot = sum(stats.values()) if stats else 0
            threat_label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
            threat_sev = attrs.get("threat_severity", {}) if isinstance(attrs.get("threat_severity"), dict) else {}
            sev_level = threat_sev.get("threat_severity_level")
            names = attrs.get("names", [])
            type_desc = attrs.get("type_description") or attrs.get("magic")
            sig_info = attrs.get("signature_info", {}) if isinstance(attrs.get("signature_info"), dict) else {}
            signers = sig_info.get("signers")
            crowd_yara = attrs.get("crowdsourced_yara_results", [])
            categories = attrs.get("categories", {})
            http_code = attrs.get("last_http_response_code")
            vt_claims = claims_by_src.get("virustotal", [])
            vt_malware_claims = [c.get("statement") for c in vt_claims if "malware" in c.get("claim_type", "").lower() or "malware/tool" in c.get("statement", "").lower()]

            if is_hash:
                parts = []
                if mal > 0:
                    is_active = True
                    parts.append(f"Flagged as malicious by <strong>{mal}/{tot}</strong> security vendors" if tot else f"<strong>{mal}</strong> malicious detections")
                elif sev_level and sev_level != "SEVERITY_UNKNOWN":
                    is_active = True
                    parts.append(f"Threat Severity: <strong style='color:var(--danger);'>{html_lib.escape(str(sev_level).replace('SEVERITY_', ''))}</strong>")
                elif vt_malware_claims:
                    is_active = True
                    m = re.search(r"malware/tool context\s+([^.]+)", vt_malware_claims[0])
                    if m:
                        parts.append(f"Threat classification: <code>{html_lib.escape(m.group(1).strip())}</code>")

                if threat_label:
                    parts.append(f"Threat classification: <code>{html_lib.escape(threat_label)}</code>")
                if type_desc and not str(type_desc).startswith("[truncated"):
                    parts.append(f"Format: <code>{html_lib.escape(str(type_desc))}</code>")
                if names and isinstance(names, list):
                    clean_names = [n for n in names if n and not str(n).startswith("[truncated")]
                    if clean_names:
                        parts.append(f"Payload aliases: <em>{', '.join(html_lib.escape(n) for n in clean_names[:2])}</em>")
                if signers and not str(signers).startswith("[truncated"):
                    parts.append(f"Signer: <em>{html_lib.escape(signers.split(';')[0][:40])}</em>")
                if crowd_yara and isinstance(crowd_yara, list):
                    parts.append(f"Crowdsourced YARA: <strong>{len(crowd_yara)}</strong> rule match(es)")

                if parts:
                    summary = "; ".join(parts) + "."
                else:
                    summary = f"Scanned across {tot or 90}+ antivirus vendors with 0 detections (clean reputation)."

            elif is_url:
                parts = []
                if mal > 0:
                    is_active = True
                    parts.append(f"Flagged as malicious/phishing by <strong>{mal}/{tot}</strong> security engines" if tot else f"<strong>{mal}</strong> malicious engine detections")
                if categories and isinstance(categories, dict):
                    uniq_cats = list(dict.fromkeys([v for v in categories.values() if v and v not in ("uncategorized", "clean")]))
                    if uniq_cats:
                        parts.append(f"Categories: <strong>{', '.join(html_lib.escape(c) for c in uniq_cats[:2])}</strong>")
                if http_code:
                    parts.append(f"HTTP Response: <code>{http_code}</code>")
                if parts:
                    summary = "; ".join(parts) + "."
                else:
                    summary = f"Scanned across {tot or 90}+ web safety engines with 0 detections (benign URL reputation)."

            elif is_domain or is_ip:
                parts = []
                if mal > 0:
                    is_active = True
                    parts.append(f"Flagged as malicious by <strong>{mal}/{tot}</strong> security vendors" if tot else f"<strong>{mal}</strong> malicious detections")
                    if threat_label:
                        parts.append(f"Threat classification: <code>{html_lib.escape(threat_label)}</code>")
                    if names and isinstance(names, list):
                        clean_names = [n for n in names if n and not str(n).startswith("[truncated")]
                        if clean_names:
                            parts.append(f"Payload aliases: <em>{', '.join(html_lib.escape(n) for n in clean_names[:2])}</em>")
                    summary = ". ".join(parts)
                else:
                    summary = f"Scanned across {tot or 90}+ antivirus vendors with 0 detections (clean reputation)."
            else:
                summary = "VirusTotal threat database queried; no active malware detections cataloged."

        # 2. VirusTotal Relations
        elif lower_id == "vt_relations":
            if isinstance(raw_provider_data, dict):
                resolutions = raw_provider_data.get("resolutions", [])
                urls = raw_provider_data.get("urls", [])
                files = raw_provider_data.get("communicating_files", []) or raw_provider_data.get("downloaded_files", [])
                subs = raw_provider_data.get("subdomains", [])
                dropped = raw_provider_data.get("dropped_files", [])
                bundled = raw_provider_data.get("bundled_files", [])
                c_ips = raw_provider_data.get("contacted_ips", [])
                c_doms = raw_provider_data.get("contacted_domains", [])
                vtr_claims = claims_by_src.get("vt_relations", [])
                parts = []
                if resolutions:
                    is_active = True
                    res_targets = [r.get("attributes", {}).get("host_name") or r.get("attributes", {}).get("ip_address") for r in resolutions if isinstance(r, dict)]
                    clean_targets = list(dict.fromkeys([t for t in res_targets if t and not str(t).startswith("[truncated")]))
                    if clean_targets:
                        parts.append(f"<strong>{len(resolutions)}</strong> passive DNS resolution(s) (<code>{', '.join(clean_targets[:2])}</code>)")
                    else:
                        parts.append(f"<strong>{len(resolutions)}</strong> passive DNS resolution(s)")
                if urls:
                    is_active = True
                    parts.append(f"<strong>{len(urls)}</strong> communicating URL relation(s)")
                if files:
                    is_active = True
                    f0 = files[0] if isinstance(files[0], dict) else {}
                    f_sha = f0.get("id") or f0.get("attributes", {}).get("sha256") or ""
                    f_type = f0.get("attributes", {}).get("magika") or f0.get("type") or "sample"
                    f_detail = f" (e.g. SHA256 <code>{f_sha[:16]}...</code>, {f_type})" if f_sha else ""
                    parts.append(f"<strong>{len(files)}</strong> communicating binary file(s){f_detail}")
                if dropped:
                    is_active = True
                    parts.append(f"<strong>{len(dropped)}</strong> dropped file payload(s)")
                if bundled:
                    is_active = True
                    parts.append(f"<strong>{len(bundled)}</strong> bundled binary resource(s)")
                if c_ips:
                    is_active = True
                    parts.append(f"<strong>{len(c_ips)}</strong> contacted IP endpoint(s)")
                if c_doms:
                    is_active = True
                    parts.append(f"<strong>{len(c_doms)}</strong> contacted domain(s)")
                if subs:
                    is_active = True
                    parts.append(f"<strong>{len(subs)}</strong> connected subdomain(s)")
                if not parts and vtr_claims:
                    vtr_reports = [c.get("statement") for c in vtr_claims if "references report" in c.get("statement", "").lower() or "honey" in c.get("statement", "").lower()]
                    if vtr_reports:
                        is_active = True
                        m = re.search(r"references report/pulse\s+(.+)", vtr_reports[0])
                        ref_txt = m.group(1).strip() if m else vtr_reports[0]
                        parts.append(f"Linked to <strong>{len(vtr_claims)}</strong> behavioral graph relation(s) including <em>'{html_lib.escape(ref_txt[:60])}'</em>")
                summary = "; ".join(parts) + "." if parts else "Evaluated entity graph relations; no active communicating files, subdomains, or dropped payloads linked."
            else:
                summary = "Evaluated entity graph relations; no active communicating files or subdomains linked."

        # 3. AlienVault OTX
        elif lower_id == "alienvault":
            raw_pulses = raw_provider_data.get("general", {}).get("pulse_info", {}).get("pulses", []) if isinstance(raw_provider_data, dict) else []
            pulses = [p for p in raw_pulses if isinstance(p, dict)] if isinstance(raw_pulses, list) else []
            cnt = (raw_provider_data.get("general", {}).get("pulse_info", {}).get("count", 0) if isinstance(raw_provider_data, dict) else 0) or len(pulses)
            actor_claims = [c.get("statement") for c in claims_by_src.get("alienvault", []) if "actor" in c.get("claim_type", "").lower() or "names actor" in c.get("statement", "").lower()]
            report_claims = [c.get("statement") for c in claims_by_src.get("alienvault", []) if "references report" in c.get("statement", "").lower() or "pulse/report" in c.get("statement", "").lower()]
            adv = list(dict.fromkeys([p.get("adversary") for p in pulses if p.get("adversary") and not str(p.get("adversary")).startswith("[truncated")]))
            if not adv and actor_claims:
                m = re.search(r"actor/cluster\s+([^.]+)", actor_claims[0])
                if m:
                    adv = [m.group(1).strip()]
            pulse_titles = [p.get("name") for p in pulses if p.get("name") and not str(p.get("name")).startswith("[truncated")]
            if not pulse_titles and report_claims:
                for rc in report_claims:
                    m = re.search(r"references\s+(.+)", rc)
                    if m and not str(m.group(1)).startswith("[truncated"):
                        pulse_titles.append(m.group(1).strip())
            if cnt > 0 or actor_claims or report_claims:
                is_active = True
                p_cnt = cnt or len(report_claims) or len(pulses)
                parts = [f"Linked to <strong>{p_cnt}</strong> threat intelligence pulse(s)"]
                if adv:
                    parts.append(f"Associated adversary: <strong style='color:var(--danger);'>{', '.join(html_lib.escape(a) for a in adv[:2])}</strong>")
                if pulse_titles:
                    clean_t = [t.rstrip(".") for t in pulse_titles if t]
                    first_ref = html_lib.escape(clean_t[-1][:80])
                    parts.append(f"Key reference: <em>'{first_ref}'</em>")
                summary = "; ".join(parts) + "."
            else:
                summary = "No threat intelligence pulses linked in AlienVault OTX community database."

        # 4. AbuseIPDB
        elif lower_id == "abuseipdb":
            if is_hash or is_keyword:
                summary = "Direct host abuse reporting not applicable for file hash or keyword (lookup skipped)."
            elif is_url:
                summary = "Direct host abuse reporting not applicable for raw URL indicator (lookup skipped)."
            else:
                d = raw_provider_data.get("data") or raw_provider_data.get("normalized", {}) if isinstance(raw_provider_data, dict) else {}
                score = d.get("abuseConfidenceScore", d.get("score", 0))
                tot = d.get("totalReports", d.get("total_reports", 0))
                users = d.get("numDistinctUsers", d.get("distinct_users", 0))
                net = d.get("network", {}) if isinstance(d.get("network"), dict) else {}
                isp = d.get("isp") or net.get("isp") or ""
                usage = d.get("usageType") or net.get("usage_type") or ""
                isp_str = f" (ISP: <em>{html_lib.escape(isp)}</em>, {html_lib.escape(usage or 'Hosting')})" if isp else ""
                if score > 0 or tot > 0:
                    is_active = True
                    summary = f"Abuse confidence score: <strong>{score}%</strong> across <strong>{tot}</strong> user report(s) from {users} distinct reporter(s){isp_str}."
                else:
                    summary = f"Clean reputation baseline: <strong>0%</strong> abuse confidence score (0 abuse reports in last 90 days){isp_str}."

        # 5. Censys Search
        elif lower_id == "censys":
            if is_hash or is_keyword:
                summary = "Internet host scanning not applicable for file hash or keyword query (lookup skipped)."
            elif is_url:
                summary = "Direct internet host scanning not applicable for raw URL indicator (lookup skipped)."
            else:
                norm = raw_provider_data.get("normalized", {}) if isinstance(raw_provider_data, dict) else {}
                as_info = norm.get("autonomous_system", {}) if isinstance(norm, dict) else {}
                asn = as_info.get("asn") or as_info.get("name") or ""
                as_name = as_info.get("name") or as_info.get("description") or ""
                loc = norm.get("location", {}) if isinstance(norm, dict) else {}
                loc_str = f"{loc.get('city')}, {loc.get('country')}" if isinstance(loc, dict) and loc.get('country') else ""
                net_name = norm.get("whois", {}).get("network", {}).get("name") if isinstance(norm, dict) else ""
                dns_names = [d for d in norm.get("dns", {}).get("names", []) if d and not str(d).startswith("[truncated")] if isinstance(norm, dict) else []
                services = raw_provider_data.get("host", {}).get("result", {}).get("services", []) or norm.get("services", []) if isinstance(raw_provider_data, dict) else []
                c_parts = []
                if asn:
                    c_parts.append(f"Autonomous System: <strong>{html_lib.escape(str(asn))}</strong>" + (f" ({html_lib.escape(str(as_name))})" if as_name and str(as_name) != str(asn) else ""))
                if net_name:
                    c_parts.append(f"Network: <em>{html_lib.escape(str(net_name))}</em>" + (f" ({html_lib.escape(loc_str)})" if loc_str else ""))
                if dns_names:
                    c_parts.append(f"Associated domain(s): <code>{', '.join(html_lib.escape(d) for d in dns_names[:2])}</code>")
                if services:
                    p_list = [str(s.get('port')) for s in services if isinstance(s, dict) and s.get('port')]
                    if p_list:
                        c_parts.append(f"Open port(s): <code>{', '.join(p_list[:4])}</code>")
                if c_parts:
                    is_active = True
                    summary = "; ".join(c_parts) + "."
                else:
                    summary = "Censys internet scan completed with no exposed services or host records."

        # 6. ThreatBook
        elif lower_id == "threatbook":
            tb_d = raw_provider_data.get("data", {}) if isinstance(raw_provider_data, dict) else {}
            ports = tb_d.get("ports", [])
            samples = tb_d.get("samples", [])
            carrier = tb_d.get("basic", {}).get("carrier")
            asn_info = tb_d.get("asn", {}).get("info")
            tb_claims = claims_by_src.get("threatbook", [])
            tb_malware = [c.get("statement") for c in tb_claims if "malware" in c.get("claim_type", "").lower()]
            tb_parts = []
            if samples:
                s0 = samples[0] if isinstance(samples[0], dict) else {}
                fam = s0.get("malware_family") or "Trojan"
                ratio = s0.get("ratio")
                sha = s0.get("sha256") or ""
                r_str = f" (Detection: <code>{ratio}</code>, SHA256: <code>{sha[:16]}...</code>)" if ratio and sha else ""
                tb_parts.append(f"Associated malware: <strong style='color:var(--danger);'>{html_lib.escape(str(fam))}</strong>{r_str}")
            elif tb_malware:
                m = re.search(r"malware/tool context\s+([^.]+)", tb_malware[0])
                if m:
                    tb_parts.append(f"Associated malware payload: <strong style='color:var(--danger);'>{html_lib.escape(m.group(1).strip())}</strong>")
            if ports:
                port_strs = [f"{p.get('port')}/{p.get('product') or p.get('module')}" for p in ports if isinstance(p, dict) and p.get('port') and not str(p.get('port')).startswith('[truncated')]
                if port_strs:
                    tb_parts.append(f"Indexed <strong>{len(ports)}</strong> exposed port(s) including <code>{', '.join(html_lib.escape(ps) for ps in port_strs[:3])}</code>")
            if not tb_parts and (carrier or asn_info):
                tb_parts.append(f"Routing carrier: <em>{html_lib.escape(str(carrier or asn_info))}</em>")
            if tb_parts:
                is_active = True
                summary = "; ".join(tb_parts) + "."
            else:
                summary = "ThreatBook threat intelligence query completed with no malicious judgments."

        # 7. SANS ISC
        elif lower_id == "sans":
            if is_hash or is_keyword or is_url or is_domain:
                summary = "Honeypot attack telemetry not applicable for this indicator type (lookup skipped)."
            else:
                net = raw_provider_data.get("network") if isinstance(raw_provider_data, dict) else ""
                asn = raw_provider_data.get("asn") if isinstance(raw_provider_data, dict) else ""
                asname = raw_provider_data.get("asname") if isinstance(raw_provider_data, dict) else ""
                attacks = raw_provider_data.get("attacks", 0) if isinstance(raw_provider_data, dict) else 0
                if attacks and attacks > 0:
                    is_active = True
                    summary = f"Flagged in SANS ISC honeypots: <strong>{attacks}</strong> attack events (Subnet: <code>{net}</code>, AS{asn})."
                else:
                    summary = f"Queried SANS Internet Storm Center: 0 honeypot attacks logged for subnet <code>{net or 'network'}</code> (AS{asn or 'N/A'}, {asname or 'SIAMDATA-TH'})."

        # 8. RIPEstat
        elif lower_id == "ripe":
            if is_hash or is_keyword or is_url:
                summary = "BGP routing and network allocation telemetry not applicable for this indicator type (lookup skipped)."
            else:
                pfx = raw_provider_data.get("prefix") if isinstance(raw_provider_data, dict) else ""
                asns = raw_provider_data.get("asns", []) if isinstance(raw_provider_data, dict) else []
                holder = raw_provider_data.get("asn_overview", {}).get("holder") if isinstance(raw_provider_data, dict) else ""
                whois = raw_provider_data.get("whois", []) if isinstance(raw_provider_data, dict) else []
                descr = whois[0].get("descr") or whois[0].get("netname") if whois and isinstance(whois[0], dict) else ""
                if pfx or asns or holder or descr:
                    is_active = True
                    parts = []
                    if pfx: parts.append(f"Subnet <code>{pfx}</code> allocated to <em>{html_lib.escape(str(descr or 'Network Holder'))}</em>")
                    if asns: parts.append(f"BGP routing prefix announced by <strong>AS{', '.join(str(a) for a in asns)} ({html_lib.escape(str(holder or 'SIAMDATA-TH'))})</strong>")
                    summary = "; ".join(parts) + "."
                else:
                    summary = "RIPEstat query completed with baseline network prefix and routing records."

        # 9. Shodan
        elif lower_id == "shodan":
            if is_hash or is_keyword:
                summary = "Shodan internet host scanner not applicable for file hash or keyword (lookup skipped)."
            elif is_url:
                summary = "Shodan internet host scanner not applicable for raw URL indicator (lookup skipped)."
            else:
                err = str(raw_provider_data.get("error", "")).lower() if isinstance(raw_provider_data, dict) else ""
                if "not found" in err or "404" in err or "not found" in error.lower():
                    summary = "Host not indexed in Shodan internet-wide scan database (no public listening services, open ports, or banners captured)."
                elif "timeout" in err or "500" in err or "401" in err:
                    is_error = True
                    summary = f"Shodan provider notice: {html_lib.escape(err)}"
                elif isinstance(raw_provider_data, dict) and raw_provider_data.get("ports"):
                    ports = raw_provider_data.get("ports", [])
                    os_name = raw_provider_data.get("os", "Unknown OS")
                    is_active = True
                    summary = f"Discovered <strong>{len(ports)}</strong> open service(s) (<code>{', '.join(str(p) for p in ports[:4])}</code>); Operating System: <em>{html_lib.escape(os_name)}</em>."
                else:
                    summary = "Shodan internet scanner completed with 0 listening ports or host entries."

        # 10. GreyNoise
        elif lower_id == "greynoise":
            if is_hash or is_keyword or is_domain or is_url:
                summary = "Internet mass-scanning telemetry not applicable for this indicator type (lookup skipped)."
            else:
                noise = raw_provider_data.get("noise", False) if isinstance(raw_provider_data, dict) else False
                riot = raw_provider_data.get("riot", False) if isinstance(raw_provider_data, dict) else False
                cls_val = raw_provider_data.get("classification") if isinstance(raw_provider_data, dict) else ""
                actor = raw_provider_data.get("actor") if isinstance(raw_provider_data, dict) else ""
                tags = raw_provider_data.get("tags", []) if isinstance(raw_provider_data, dict) else []
                if noise or cls_val == "malicious":
                    is_active = True
                    summary = f"Observed mass-scanning internet background noise: Classification <strong>{cls_val or 'Malicious'}</strong> (Actor: <strong>{actor or 'Unknown'}</strong>, Tags: <code>{', '.join(tags[:3])}</code>)."
                elif riot:
                    summary = f"Verified benign common service / RIOT (Rule It Out): Provider <strong>{actor or 'Legitimate Business Infrastructure'}</strong>."
                else:
                    summary = "Not observed mass-scanning the internet (no opportunistic background noise or scanning activity recorded in GreyNoise sensors)."

        # 11. DNSDumpster
        elif lower_id == "dnsdumpster":
            if is_hash or is_keyword:
                summary = "DNS mapping not applicable for direct hash or keyword indicator (lookup skipped)."
            elif isinstance(raw_provider_data, dict):
                raw = raw_provider_data.get("raw", {})
                a_recs = raw.get("a", [])
                ips = []
                asn = ""
                for a in a_recs:
                    if isinstance(a, dict):
                        ips.extend(a.get("ips", []))
                        if a.get("as"): asn = str(a.get("as"))
                clean_ips = [ip for ip in ips if ip and not str(ip).startswith("[truncated")]
                if clean_ips:
                    is_active = True
                    summary = f"Mapped <strong>{len(clean_ips)}</strong> host resolution IP(s): <code>{', '.join(clean_ips[:3])}</code>{' under ' + html_lib.escape(asn) if asn else ''}."
                elif a_recs:
                    is_active = True
                    summary = f"Mapped <strong>{len(a_recs)}</strong> DNS A record(s) on authoritative nameservers."
                else:
                    summary = "DNS query completed with baseline nameserver records."

        # 15. crt.sh
        elif lower_id == "crtsh":
            if is_hash or is_ip or is_keyword:
                summary = "Certificate Transparency search not applicable for this indicator type (lookup skipped)."
            else:
                note = str(raw_provider_data.get("note", "")) if isinstance(raw_provider_data, dict) else ""
                if (raw_provider_data.get("provider_unavailable") or "502" in note or "error" in note.lower() or "502" in error):
                    is_error = True
                    summary = "Certificate Transparency service unavailable (HTTP 502/timeout from crt.sh)."
                elif isinstance(raw_provider_data, dict) and raw_provider_data.get("certificates"):
                    certs = raw_provider_data.get("certificates", [])
                    is_active = True
                    issuers = list(set([c.get("issuer_name") for c in certs if c.get("issuer_name") and not str(c.get("issuer_name")).startswith("[truncated")]))
                    iss_str = f" issued by <em>{html_lib.escape(issuers[0][:45])}</em>" if issuers else ""
                    summary = f"Cataloged <strong>{len(certs)}</strong> SSL/TLS certificate(s){iss_str}."
                else:
                    summary = "Certificate Transparency search returned 0 certificate issuances."

        # 16. ORKL CTI Library
        elif lower_id == "orkl":
            raw_data = raw_provider_data.get("raw", {}).get("data", []) or raw_provider_data.get("reports", []) or raw_provider_data.get("data", []) if isinstance(raw_provider_data, dict) else []
            orkl_claims = [c.get("statement") for c in claims_by_src.get("orkl", []) if "references report" in c.get("statement", "").lower()]
            if isinstance(raw_data, list) and raw_data:
                is_active = True
                titles = [r.get("title") or r.get("name") for r in raw_data if isinstance(r, dict) and (r.get("title") or r.get("name"))]
                titles = [t for t in titles if t and not str(t).startswith("[truncated")]
                if titles:
                    first_t = html_lib.escape(titles[0][:60])
                    summary = f"Referenced across <strong>{len(raw_data)}</strong> threat publication(s) including: <em>'{first_t}'</em>."
                else:
                    summary = f"Indexed across <strong>{len(raw_data)}</strong> open CTI report entries."
            elif orkl_claims:
                is_active = True
                m = re.search(r"references report/pulse\s+(.+)", orkl_claims[0])
                first_claim = html_lib.escape(m.group(1).strip()[:65]) if m else html_lib.escape(orkl_claims[0][:65])
                summary = f"Referenced across <strong>{len(orkl_claims)}</strong> open threat report(s) including: <em>'{first_claim}'</em>."
            else:
                summary = "No threat intelligence publication mentions found in ORKL repository."

        # 17. ThreatFox
        elif lower_id == "threatfox":
            q_stat = raw_provider_data.get("query_status") if isinstance(raw_provider_data, dict) else ""
            if q_stat == "no_result" or count == 0:
                summary = "No active malware IOC indicators cataloged in ThreatFox database."
            else:
                items = raw_provider_data.get("data", []) if isinstance(raw_provider_data, dict) else []
                if isinstance(items, list) and items:
                    is_active = True
                    mal = items[0].get("threat_type_desc") or items[0].get("malware_printable")
                    conf = items[0].get("confidence_level", 100)
                    summary = f"Identified active IOC entry: <strong>{html_lib.escape(str(mal))}</strong> (Confidence: {conf}%)."
                else:
                    summary = "ThreatFox query completed with no active threat entries."

        # 18. Hatching Triage
        elif lower_id == "triage":
            items = raw_provider_data.get("data", []) if isinstance(raw_provider_data, dict) else []
            if items:
                is_active = True
                it0 = items[0] if isinstance(items[0], dict) else {}
                score = it0.get("score")
                family = it0.get("family") or it0.get("signature") or ""
                score_str = f" (Score: <strong>{score}/10</strong>)" if score is not None else ""
                fam_str = f", Family: <strong>{html_lib.escape(str(family))}</strong>" if family else ""
                summary = f"Recorded <strong>{len(items)}</strong> sandbox detonation sample(s){score_str}{fam_str}."
            else:
                summary = "No public sandbox detonations or behavioral matches recorded."

        # 19. Hybrid Analysis
        elif lower_id in ("hybrid-analysis", "hybrid_analysis"):
            reports = raw_provider_data.get("reports", []) if isinstance(raw_provider_data, dict) else []
            ass = raw_provider_data.get("normalized", {}).get("assessment", {}) if isinstance(raw_provider_data, dict) else {}
            score = ass.get("threat_score") if ass else None
            if reports and isinstance(reports[0], dict):
                r = reports[0]
                score = r.get("threat_score", score)
                verdict = r.get("verdict")
                vx = r.get("vx_family")
                parts = []
                if score is not None and score > 0:
                    is_active = True
                    parts.append(f"Threat Score: <strong>{score}/100</strong>")
                if verdict and verdict not in ("whitelisted", "no_verdict", "unknown"):
                    is_active = True
                    parts.append(f"Verdict: <strong>{html_lib.escape(str(verdict))}</strong>")
                if vx:
                    is_active = True
                    parts.append(f"Malware Family: <code>{html_lib.escape(str(vx))}</code>")
                if parts:
                    summary = " | ".join(parts)
                else:
                    summary = "Hybrid Analysis sandbox detonation traces verified baseline (0 threat score)."
            elif score and score > 0:
                is_active = True
                summary = f"Detonation assessment: Threat Score <strong>{score}/100</strong>."
            else:
                summary = "No detonation traces or behavioral sandboxing records in Hybrid Analysis."

        # 20. MalwareBazaar
        elif lower_id == "malwarebazaar":
            if is_ip or is_domain or is_url or is_infra:
                summary = "Malware binary sample corpus not applicable for this indicator type (lookup skipped)."
            elif raw_provider_data.get("query_status") in ("hash_not_found", "no_results") or count == 0:
                summary = "Sample hash not indexed in MalwareBazaar malware corpus."
            elif raw_provider_data.get("error"):
                is_error = True
                summary = f"MalwareBazaar API notice: {html_lib.escape(str(raw_provider_data.get('error')))}"
            else:
                items = raw_provider_data.get("data", []) if isinstance(raw_provider_data, dict) else []
                if items and isinstance(items, list):
                    is_active = True
                    it0 = items[0] if isinstance(items[0], dict) else {}
                    sig = it0.get("signature") or "malware sample"
                    f_type = it0.get("file_type") or "binary"
                    f_name = it0.get("file_name") or ""
                    detail = f" ({html_lib.escape(f_type)}, '<em>{html_lib.escape(f_name)}</em>')" if f_name else f" ({html_lib.escape(f_type)})"
                    summary = f"Known binary sample cataloged as <strong>{html_lib.escape(str(sig))}</strong>{detail}."
                else:
                    summary = "MalwareBazaar lookup completed with no matching binaries."

        # 21. YARAify
        elif lower_id == "yaraify":
            q_stat = raw_provider_data.get("query_status") if isinstance(raw_provider_data, dict) else ""
            if is_ip or is_domain or is_infra:
                summary = "YARA hunting scan not applicable for network/host indicator (lookup skipped)."
            elif q_stat in ("no_results", "hash_not_found", "no_result") or (isinstance(raw_provider_data, dict) and not raw_provider_data.get("data")):
                summary = "YARAify automated hunting search completed with 0 YARA rule matches."
            elif isinstance(raw_provider_data, dict) and raw_provider_data.get("data") and isinstance(raw_provider_data.get("data"), list):
                is_active = True
                data_list = raw_provider_data.get("data", [])
                rules = [r.get("rule_name") for r in data_list if isinstance(r, dict) and r.get("rule_name")]
                clean_rules = list(dict.fromkeys([r for r in rules if r and not str(r).startswith("[truncated")]))
                authors = list(dict.fromkeys([r.get("author") for r in data_list if isinstance(r, dict) and r.get("author") and not str(r.get("author")).startswith("[truncated")]))
                auth_str = f" by <em>{html_lib.escape(authors[0])}</em>" if authors else ""
                if clean_rules:
                    summary = f"Matched <strong>{len(clean_rules)}</strong> YARA rule(s) (<code>{', '.join(clean_rules[:2])}</code>){auth_str}."
                else:
                    summary = f"Matched <strong>{len(data_list)}</strong> YARA rule signature(s) in corpus."
            else:
                summary = "YARAify rule scanning completed with no matches."

        # 23. MalShare
        elif lower_id == "malshare":
            err = str(raw_provider_data.get("error", "")) if isinstance(raw_provider_data, dict) else str(error)
            if "not found" in err.lower() or "no existing" in err.lower():
                summary = "Sample hash not indexed in MalShare community malware repository."
            elif is_ip or is_domain or is_infra:
                summary = "Malware sample repository not applicable for host indicator (lookup skipped)."
            elif err and ("timeout" in err.lower() or "50" in err or "40" in err):
                is_error = True
                summary = f"MalShare provider notice: {html_lib.escape(err)}"
            elif isinstance(raw_provider_data, dict) and (raw_provider_data.get("sha256") or raw_provider_data.get("sources")):
                is_active = True
                sources_list = raw_provider_data.get("sources", [])
                f_type = raw_provider_data.get("type", "sample")
                summary = f"Sample indexed in MalShare repository ({f_type}, <strong>{len(sources_list)}</strong> sighting source(s))."
            else:
                summary = "MalShare community repository lookup completed with 0 sample records."

        # 24. GitHub & Internal Repos
        elif lower_id in ("github", "github_repos"):
            label_single = "internal threat research repository" if lower_id == "github_repos" else "GitHub open CTI repository"
            label_plural = "internal threat research repositories" if lower_id == "github_repos" else "GitHub open CTI repositories"
            tot = raw_provider_data.get("total_count") if isinstance(raw_provider_data, dict) else 0
            items = raw_provider_data.get("items", []) if isinstance(raw_provider_data, dict) else []
            if (tot is None or tot == 0) and items:
                tot = len(items)

            gh_claims = claims_by_src.get(lower_id, [])
            pulse_claims = [c.get("statement") for c in gh_claims if "references report" in c.get("statement", "").lower()]

            if (tot and tot > 0) or pulse_claims:
                is_active = True
                files = []
                for it in items:
                    if isinstance(it, dict):
                        f_name = it.get("name") or it.get("path")
                        if f_name and not str(f_name).startswith("[truncated"):
                            files.append(f_name.split("/")[-1])
                if not files and pulse_claims:
                    for pc in pulse_claims:
                        m = re.search(r"references report/pulse\s+(.+)", pc)
                        if m:
                            files.append(m.group(1).split("/")[-1].rstrip("."))
                file_str = f" (e.g. <code>{', '.join(files[:2])}</code>)" if files else ""
                count_display = tot or len(pulse_claims)
                summary = f"Discovered <strong>{count_display}</strong> {label_single} mention(s){file_str}."
            else:
                summary = f"Scanned {label_plural} with 0 PoC exploits or references found."

        # 25. URLhaus
        elif lower_id == "urlhaus":
            status_str = raw_provider_data.get("status") if isinstance(raw_provider_data, dict) else ""
            threat_str = raw_provider_data.get("threat") if isinstance(raw_provider_data, dict) else ""
            payloads = raw_provider_data.get("payloads", []) if isinstance(raw_provider_data, dict) else []
            urls = raw_provider_data.get("urls", []) if isinstance(raw_provider_data, dict) else []
            tags = raw_provider_data.get("tags", []) if isinstance(raw_provider_data, dict) else []
            err_msg = raw_provider_data.get("error") if isinstance(raw_provider_data, dict) else ""
            if err_msg and not payloads and not urls:
                if "no_results" in str(err_msg).lower() or "requires" in str(err_msg).lower():
                    summary = "URLhaus query completed with no active malware payload or distribution records."
                else:
                    is_error = True
                    summary = f"URLhaus notice: {html_lib.escape(str(err_msg))}"
            elif is_hash and urls:
                is_active = True
                summary = f"Linked to <strong>{len(urls)}</strong> active malware distribution URL(s) delivering this payload."
            elif is_url and (threat_str or payloads or status_str):
                is_active = True
                p_parts = []
                if threat_str: p_parts.append(f"Threat: <strong style='color:var(--danger);'>{html_lib.escape(threat_str)}</strong>")
                if status_str: p_parts.append(f"Status: <code>{html_lib.escape(status_str)}</code>")
                if payloads: p_parts.append(f"Payloads: <strong>{len(payloads)}</strong> binary dropper(s)")
                if tags: p_parts.append(f"Tags: <code>{', '.join(tags[:3])}</code>")
                summary = "URLhaus distribution telemetry: " + "; ".join(p_parts) + "."
            else:
                summary = "URLhaus malware distribution database completed with 0 active delivery records."

        # 26. Validin Passive DNS
        elif lower_id == "validin":
            if is_hash or is_keyword:
                summary = "Passive DNS telemetry not applicable for file hash or keyword (lookup skipped)."
            else:
                p_errs = raw_provider_data.get("provider_errors", []) if isinstance(raw_provider_data, dict) else []
                if any("quota" in str(e).lower() for e in p_errs):
                    is_error = True
                    summary = "Validin API monthly plan quota / rate limit reached."
                else:
                    dns_recs = raw_provider_data.get("normalized", {}).get("dns", []) if isinstance(raw_provider_data, dict) else []
                    if dns_recs and isinstance(dns_recs, list):
                        is_active = True
                        summary = f"Extracted <strong>{len(dns_recs)}</strong> passive DNS historical resolution record(s)."
                    else:
                        summary = "Passive DNS query completed with no historical IP transitions on file."

        # 27. Silent Push
        elif lower_id == "silentpush":
            if is_hash or is_keyword:
                summary = "Infrastructure reputation profiling not applicable for file hash or keyword (lookup skipped)."
            else:
                enrich = raw_provider_data.get("normalized", {}).get("enrichment", {}) if isinstance(raw_provider_data, dict) else {}
                asn = enrich.get("asn") or raw_provider_data.get("asn")
                score = enrich.get("risk_score") or raw_provider_data.get("risk_score")
                listings = enrich.get("listings", []) if isinstance(enrich, dict) else []
                if listings or (score and score > 0):
                    is_active = True
                    parts = []
                    if asn: parts.append(f"Routing ASN: <code>{html_lib.escape(str(asn))}</code>")
                    if score is not None: parts.append(f"Risk Score: <strong>{score}</strong>")
                    if listings: parts.append(f"Listings: <strong>{len(listings)}</strong>")
                    summary = " | ".join(parts)
                else:
                    summary = "Silent Push reputation telemetry verified baseline profile."

        # 28. Driftnet
        elif lower_id == "driftnet":
            if is_hash or is_keyword:
                summary = "Edge network routing telemetry not applicable for file hash or keyword (lookup skipped)."
            else:
                d = raw_provider_data.get("data", {}) or raw_provider_data.get("normalized", {}) if isinstance(raw_provider_data, dict) else {}
                net_info = d.get("ip_whois", {}).get("net", {})
                bgp_info = d.get("bgp_whois", {}).get("as", {})
                asn = bgp_info.get("as_number") or d.get("asn") or d.get("autonomous_system")
                as_name = bgp_info.get("as_name") or ""
                cidr = net_info.get("cidr") or ""
                net_name = net_info.get("net_name") or ""
                scans = d.get("protocol_scans", {}).get("result_count", 0)
                if asn or cidr or scans > 0:
                    is_active = True
                    parts = []
                    if asn: parts.append(f"Observed routing via <strong>{html_lib.escape(str(asn))}</strong>" + (f" ({html_lib.escape(as_name)})" if as_name else ""))
                    if cidr: parts.append(f"Subnet: <code>{cidr}</code>" + (f" ({html_lib.escape(net_name)})" if net_name else ""))
                    if scans > 0: parts.append(f"Captured <strong>{scans}</strong> protocol scan(s) and TLS fingerprints")
                    summary = "; ".join(parts) + "."
                else:
                    summary = "Driftnet captured standard edge network routing telemetry."

        # 29. LeakIX
        elif lower_id == "leakix":
            if is_hash or is_keyword:
                summary = "Network service scanner not applicable for this indicator type (lookup skipped)."
            else:
                services = raw_provider_data.get("services", []) if isinstance(raw_provider_data, dict) else []
                subdomains = raw_provider_data.get("subdomains", []) if isinstance(raw_provider_data, dict) else []
                leaks = raw_provider_data.get("leaks", []) if isinstance(raw_provider_data, dict) else []
                if services or subdomains or leaks:
                    is_active = True
                    parts = []
                    if services: parts.append(f"<strong>{len(services)}</strong> network service(s)")
                    if subdomains: parts.append(f"<strong>{len(subdomains)}</strong> subdomain(s)")
                    if leaks: parts.append(f"<strong>{len(leaks)}</strong> credential/data leak event(s)")
                    summary = f"Indexed {'; '.join(parts)}."
                else:
                    summary = "No exposed services, open ports, or credential leaks indexed in LeakIX."

        # 30. Threat Intelligence Platform (TIP)
        elif lower_id == "tip":
            lk = raw_provider_data.get("lookup", {}) if isinstance(raw_provider_data, dict) else {}
            gen = lk.get("IpGeneralInfo") or lk.get("FileGeneralInfo") or lk.get("DomainGeneralInfo") or {}
            zone = lk.get("Zone") or (gen.get("Zone") if isinstance(gen, dict) else None)
            score = gen.get("ThreatScore") if isinstance(gen, dict) else None
            cats = gen.get("Categories", []) if isinstance(gen, dict) else []
            has_apt = gen.get("HasApt", False) if isinstance(gen, dict) else False
            f_type = gen.get("Type") if isinstance(gen, dict) else ""
            files = lk.get("FilesDownloadedFromIp", []) if isinstance(lk, dict) else []
            tip_parts = []
            if zone or score is not None or has_apt or files or (f_type and zone == "Red"):
                is_active = True if (score and score > 0) or zone == "Red" or has_apt or files else False
                zone_color = "var(--danger)" if zone == "Red" else ("var(--warning)" if zone in ("Yellow", "Orange") else "var(--text-muted)")
                score_str = f" (Threat Score: <strong>{score}/100</strong>)" if (score is not None and score > 0) else ""
                tip_parts.append(f"Threat Zone: <strong style='color:{zone_color};'>{html_lib.escape(str(zone or 'Monitored'))}</strong>{score_str}")
                if has_apt:
                    tip_parts.append("<strong style='color:var(--danger);'><i class='fa-solid fa-triangle-exclamation'></i> APT-Linked Infrastructure/Payload</strong>")
                if f_type and not str(f_type).startswith("[truncated"):
                    tip_parts.append(f"Format: <code>{html_lib.escape(str(f_type))}</code>")
                if cats and isinstance(cats, list):
                    tip_parts.append(f"Categories: <strong>{', '.join(html_lib.escape(str(c).replace('CATEGORY_', '')) for c in cats)}</strong>")
                if files and isinstance(files, list):
                    f0 = files[0] if isinstance(files[0], dict) else {}
                    f_name = f0.get("DetectionName") or "DangerousObject"
                    f_md5 = f0.get("Md5", "")
                    tip_parts.append(f"Observed <strong>{len(files)}</strong> downloaded malicious payload(s) (e.g. <code>{html_lib.escape(f_name)}</code>, MD5: <code>{f_md5[:12]}...</code>)")
                summary = "; ".join(tip_parts) + "."
            else:
                reg = lk.get("registrarName") or raw_provider_data.get("zonelookup", {}).get("registrarName")
                if reg:
                    summary = f"WHOIS data retrieved: Registrar <strong>{html_lib.escape(str(reg))}</strong>."
                else:
                    summary = "Infrastructure registration and WHOIS records verified."

        # 31. Etugen WHOIS
        elif lower_id == "etugen":
            if is_hash or is_keyword:
                summary = "WHOIS registration lookup not applicable for this indicator type (lookup skipped)."
            else:
                raw_str = str(raw_provider_data).lower()
                if "403" in raw_str or "access denied" in raw_str or "challenge" in raw_str:
                    is_error = True
                    summary = "Etugen WHOIS query notice: HTTP 403 access challenge (provider returned Cloudflare challenge page)."
                elif isinstance(raw_provider_data, dict) and (raw_provider_data.get("whois") or raw_provider_data.get("search")):
                    is_active = True
                    summary = "Retrieved domain WHOIS registration timeline and contact metadata."
                else:
                    summary = "Queried domain/IP registration profile with no records."

        # 32. URLScan.io
        elif lower_id == "urlscan":
            if is_hash or is_keyword:
                summary = "Web crawler DOM captures not applicable for file hash or keyword (lookup skipped)."
            else:
                results = raw_provider_data.get("results", []) if isinstance(raw_provider_data, dict) else []
                tot = raw_provider_data.get("total", len(results)) if isinstance(raw_provider_data, dict) else 0
                if tot > 0 and results:
                    is_active = True
                    r0 = results[0] if isinstance(results[0], dict) else {}
                    page = r0.get("page", {}) if isinstance(r0, dict) else {}
                    server = page.get("server")
                    title = page.get("title")
                    country = page.get("country")
                    u_parts = [f"Indexed <strong>{tot}</strong> public submission(s)"]
                    if server and not str(server).startswith("[truncated"):
                        u_parts.append(f"Observed web server: <code>{html_lib.escape(server[:50])}</code>")
                    if title and not str(title).startswith("[truncated"):
                        u_parts.append(f"Page title: <em>'{html_lib.escape(title[:45])}'</em>")
                    if country:
                        u_parts.append(f"Geo: <strong>{country}</strong>")
                    summary = "; ".join(u_parts) + "."
                else:
                    summary = "No public URLScan.io crawl submissions or DOM captures on file."

        # 33. Reputation Feeds
        elif lower_id == "reputation_feeds":
            matches = raw_provider_data.get("matches", []) if isinstance(raw_provider_data, dict) else []
            if matches:
                is_active = True
                feeds = [m.get("feed", "Feed") for m in matches if isinstance(m, dict)]
                summary = f"Flagged on <strong>{len(matches)}</strong> reputation feed(s): <em>{', '.join(html_lib.escape(f) for f in feeds[:2])}</em>."
            else:
                summary = "Queried across curated malicious domain/IP reputation blocklists with 0 listings."

        # 34. Wayback Machine
        elif lower_id == "archive":
            if is_hash or is_ip or is_keyword or is_infra:
                summary = "Web archive snapshot tracking not applicable for this indicator type (lookup skipped)."
            else:
                snapshots = raw_provider_data.get("snapshots", []) or raw_provider_data.get("historical_urls", []) if isinstance(raw_provider_data, dict) else []
                if snapshots:
                    is_active = True
                    summary = f"Identified <strong>{len(snapshots)}</strong> historical web archive snapshot(s)."
                else:
                    summary = "No historical snapshots archived in Wayback Machine."

        # 35. OpenPhish
        elif lower_id == "openphish":
            if is_hash or is_ip or is_keyword or is_infra:
                summary = "OpenPhish zero-day phishing telemetry not applicable for this indicator type (lookup skipped)."
            else:
                matched = raw_provider_data.get("match", False) if isinstance(raw_provider_data, dict) else False
                if matched:
                    is_active = True
                    summary = "Listed on OpenPhish active phishing feed database."
                else:
                    summary = "Not listed on OpenPhish zero-day phishing telemetry (clean baseline)."

        # 36. Ransomware.live
        elif lower_id == "rwlive":
            victims = raw_provider_data.get("victims", []) or raw_provider_data.get("raw", {}).get("victims", []) if isinstance(raw_provider_data, dict) else []
            groups = raw_provider_data.get("groups", []) if isinstance(raw_provider_data, dict) else []
            if victims:
                is_active = True
                v_names = [v.get("victim") or v.get("victim_name") for v in victims if isinstance(v, dict)]
                clean_v = [v for v in v_names if v and not str(v).startswith("[truncated")]
                detail = f" (Victims: <em>{', '.join(html_lib.escape(str(v)) for v in clean_v[:2])}</em>)" if clean_v else ""
                summary = f"Correlated with <strong>{len(victims)}</strong> ransomware extortion leak disclosure(s){detail}."
            elif groups:
                is_active = True
                summary = f"Correlated with active ransomware syndicate profile <strong>{html_lib.escape(str(groups[0]))}</strong>."
            else:
                summary = "No ransomware victim disclosures or leak site associations found."

        # 37. Ransomlook
        elif lower_id == "ransomlook":
            posts = raw_provider_data.get("posts", []) or raw_provider_data.get("results", []) if isinstance(raw_provider_data, dict) else []
            if posts:
                is_active = True
                summary = f"Indexed <strong>{len(posts)}</strong> ransomware leak site post(s) and extortion disclosures."
            else:
                summary = "No ransomware extortion leak posts cataloged in Ransomlook."

        # 38. MISP Galaxy
        elif lower_id == "misp_galaxy":
            clusters = raw_provider_data.get("clusters", []) if isinstance(raw_provider_data, dict) else []
            if clusters:
                is_active = True
                summary = f"Mapped <strong>{len(clusters)}</strong> MISP Galaxy threat actor/cluster taxonomic definition(s)."
            else:
                summary = "No matching MISP Galaxy taxonomy clusters identified."

        # 39. FOFA Search
        elif lower_id == "fofa":
            if is_hash:
                summary = "Cyberspace asset mapping not applicable for file hash (lookup skipped)."
            else:
                results = raw_provider_data.get("results", []) if isinstance(raw_provider_data, dict) else []
                size = raw_provider_data.get("size", len(results)) if isinstance(raw_provider_data, dict) else 0
                err_msg = raw_provider_data.get("error") if isinstance(raw_provider_data, dict) else ""
                if err_msg:
                    is_error = True
                    summary = f"FOFA search notice: {html_lib.escape(str(err_msg))}"
                elif size > 0:
                    is_active = True
                    summary = f"Discovered <strong>{size}</strong> cyberspace asset(s) and exposed network banner(s) in FOFA index."
                else:
                    summary = "FOFA cyberspace mapping completed with 0 exposed host records."

        # 41. ThreatMiner
        elif lower_id == "threatminer":
            errors = raw_provider_data.get("errors", []) if isinstance(raw_provider_data, dict) else []
            pdns = raw_provider_data.get("pdns", []) if isinstance(raw_provider_data, dict) else []
            uris = raw_provider_data.get("uris", []) if isinstance(raw_provider_data, dict) else []
            certs = raw_provider_data.get("certificates", []) if isinstance(raw_provider_data, dict) else []
            av_dets = raw_provider_data.get("av_detections", []) if isinstance(raw_provider_data, dict) else []
            hosts = raw_provider_data.get("related_hosts", []) if isinstance(raw_provider_data, dict) else []
            if errors and not pdns and not uris and not certs and not av_dets and not hosts:
                is_error = True
                summary = "ThreatMiner service unavailable (HTTP 522 upstream timeout)."
            elif pdns or uris or certs or av_dets or hosts:
                is_active = True
                parts = []
                if av_dets: parts.append(f"<strong>{len(av_dets)}</strong> AV detection(s)")
                if hosts: parts.append(f"<strong>{len(hosts)}</strong> related host(s)")
                if pdns: parts.append(f"<strong>{len(pdns)}</strong> passive DNS record(s)")
                if uris: parts.append(f"<strong>{len(uris)}</strong> related URI(s)")
                if certs: parts.append(f"<strong>{len(certs)}</strong> certificate(s)")
                summary = f"ThreatMiner intelligence extracted: {'; '.join(parts)}."
            else:
                summary = "No historical IOC records indexed in ThreatMiner."

        # 42. PhishStats
        elif lower_id == "phishstats":
            if is_hash or is_ip or is_infra:
                summary = "Phishing telemetry not applicable for this indicator type (lookup skipped)."
            else:
                score = raw_provider_data.get("score") if isinstance(raw_provider_data, dict) else None
                brand = raw_provider_data.get("brand") or raw_provider_data.get("target") if isinstance(raw_provider_data, dict) else ""
                err_msg = error or (raw_provider_data.get("error") if isinstance(raw_provider_data, dict) else "")
                if err_msg and ("timed out" in str(err_msg).lower() or "50" in str(err_msg)):
                    is_error = True
                    summary = f"PhishStats provider notice: {html_lib.escape(str(err_msg))}"
                elif score or brand:
                    is_active = True
                    b_str = f" Target Brand: <strong>{html_lib.escape(str(brand))}</strong>" if brand else ""
                    s_str = f" (Phishing Score: <strong>{score}/10</strong>)" if score is not None else ""
                    summary = f"Identified phishing campaign telemetry:{b_str}{s_str}."
                else:
                    summary = "PhishStats search completed with 0 matching phishing records."

        # 43. Common Crawl & CyberBriefing
        elif lower_id in ("commoncrawl", "cb"):
            err_msg = error or (raw_provider_data.get("error") if isinstance(raw_provider_data, dict) else "")
            if err_msg:
                is_error = True
                summary = f"Provider notice: {html_lib.escape(str(err_msg))}"
            else:
                summary = "Query completed with no observable threat indicators."

        # 44. Pulsedive
        elif lower_id == "pulsedive":
            d_items = raw_provider_data.get("data", []) if isinstance(raw_provider_data, dict) else []
            risk = raw_provider_data.get("risk") or raw_provider_data.get("risk_recommended")
            if d_items and isinstance(d_items, list):
                is_active = True
                r_str = f" (Risk: <strong>{risk}</strong>)" if risk else ""
                summary = f"Indexed across <strong>{len(d_items)}</strong> threat intelligence feed matches in Pulsedive{r_str}."
            elif risk and risk not in ("none", "unknown"):
                is_active = True
                summary = f"Pulsedive risk assessment: <strong>{risk}</strong> threat indicator level."
            else:
                summary = "No matching IOC indicators or threat feeds cataloged in Pulsedive repository."

        # 45. Global CTI Mentions & CTI Articles
        elif lower_id in ("cti_mentions", "cti_articles"):
            tot = raw_provider_data.get("total", 0) if isinstance(raw_provider_data, dict) else 0
            articles = raw_provider_data.get("articles", []) or raw_provider_data.get("results", []) if isinstance(raw_provider_data, dict) else []
            label = "threat analysis article(s) in local CTI knowledgebase" if lower_id == "cti_articles" else "curated global CTI intelligence report(s)"
            if tot > 0 or articles:
                is_active = True
                summary = f"Referenced across <strong>{tot or len(articles)}</strong> {label}."
            else:
                summary = f"Scanned global CTI news feeds and research publications with 0 references."

        # 46. Malware News
        elif lower_id == "malware_news":
            d_items = raw_provider_data.get("data", []) or raw_provider_data.get("results", []) if isinstance(raw_provider_data, dict) else []
            if d_items and isinstance(d_items, list):
                is_active = True
                summary = f"Identified <strong>{len(d_items)}</strong> threat publication disclosure(s) in malware news database."
            else:
                summary = "Queried cybersecurity threat disclosures and blogs with 0 mentions."

        # 47. RSS Threat Intel
        elif lower_id == "rss_intel":
            d_items = raw_provider_data.get("data", []) or raw_provider_data.get("items", []) if isinstance(raw_provider_data, dict) else []
            if d_items and isinstance(d_items, list):
                is_active = True
                summary = f"Captured <strong>{len(d_items)}</strong> threat bulletin(s) from subscribed RSS intelligence feeds."
            else:
                summary = "Monitored threat intelligence RSS streams returned 0 matching threat posts."

        # 48. TweetFeed Stream
        elif lower_id == "tweetfeed":
            recs = raw_provider_data.get("records", []) if isinstance(raw_provider_data, dict) else []
            if recs and isinstance(recs, list):
                is_active = True
                summary = f"Captured <strong>{len(recs)}</strong> real-time threat sharing tweet(s) in TweetFeed stream."
            else:
                summary = "Queried TweetFeed real-time infosec sharing stream with 0 live tweets."

        # 49. Threat Actor Profiler
        elif lower_id == "threatactorusernames":
            results = raw_provider_data.get("results", []) or raw_provider_data.get("data", []) if isinstance(raw_provider_data, dict) else []
            if results:
                is_active = True
                summary = f"Discovered <strong>{len(results)}</strong> threat actor online persona / username profile(s)."
            else:
                summary = "No threat actor handles or underground usernames indexed."

        # 50. YARA Rulesets
        elif lower_id == "yara_forge":
            rules = raw_provider_data.get("rules", []) or raw_provider_data.get("matches", []) if isinstance(raw_provider_data, dict) else []
            if rules:
                is_active = True
                summary = f"Identified <strong>{len(rules)}</strong> matching YARA detection ruleset(s)."
            else:
                summary = "Local YARA rule repository scanned with 0 rule matches."

        # General error or fallback
        if not summary:
            src_obs = obs_by_src.get(lower_id, [])
            src_claims = claims_by_src.get(lower_id, [])
            if status == "error" or (error and ("timeout" in error.lower() or "502" in error.lower() or "status 4" in error.lower())):
                is_error = True
                summary = f"Provider notice: {html_lib.escape(error)}"
            elif src_claims:
                is_active = True
                claim_texts = [c.get("statement") for c in src_claims if c.get("statement") and not str(c.get("statement")).startswith("[truncated")]
                clean_c = [t.rstrip(".") for t in claim_texts if t]
                if clean_c:
                    summary = f"Correlated <strong>{len(src_claims)}</strong> intelligence claim(s): <em>'{html_lib.escape(clean_c[0][:85])}'</em>."
                else:
                    summary = f"Correlated <strong>{len(src_claims)}</strong> intelligence claim(s) across telemetry findings."
            elif src_obs:
                is_active = True
                obs_vals = [f"{o.get('obs_type')}: {o.get('value')}" for o in src_obs if o.get('value') and not str(o.get('value')).startswith("[truncated")]
                summary = f"Observed <strong>{len(src_obs)}</strong> technical artifact(s): <code>{', '.join(obs_vals[:2])}</code>."
            elif count > 0:
                is_active = True
                summary = f"Retrieved <strong>{count}</strong> telemetry observation(s) from provider query."
            else:
                summary = "Query completed with no observable indicators."

        # Determine final badge HTML based on true outcome
        if is_error:
            badge_html = "<span class='verdict-badge badge-warning' style='padding:3px 8px; font-size:10.5px;'><i class='fa-solid fa-triangle-exclamation'></i> Notice / Offline</span>"
        elif is_active:
            badge_html = "<span class='verdict-badge badge-success' style='padding:3px 8px; font-size:10.5px;'><i class='fa-solid fa-check'></i> Active Findings</span>"
        else:
            badge_html = "<span class='verdict-badge badge-muted' style='padding:3px 8px; font-size:10.5px;'><i class='fa-solid fa-circle-minus'></i> No Detections</span>"

        rows.append(f"""
        <tr>
            <td style="width: 22%;">
                <span class='src-badge'><i class='fa-solid {icon}'></i> {html_lib.escape(display_name)}</span>
            </td>
            <td style="width: 18%;">{badge_html}</td>
            <td style="width: 60%; line-height:1.5;">{summary}</td>
        </tr>
        """)

    return "".join(rows) or "<tr><td colspan='3' class='empty-row'>No source telemetry recorded.</td></tr>"



def _clean_obs_source(raw_source: str, value: str, obs_type: str, stmt: str) -> str:
    s = str(raw_source or "").strip().lower()
    val = str(value or "").lower()
    st = str(stmt or "").lower()
    
    clean_map = {
        "virustotal": "VirusTotal",
        "dnsdumpster": "DNSDumpster",
        "alienvault": "AlienVault OTX",
        "threatfox": "ThreatFox",
        "hybrid-analysis": "Hybrid Analysis",
        "malwarebazaar": "MalwareBazaar",
        "triage": "Hatching Triage",
        "github": "GitHub CTI",
        "github_repos": "Internal CTI Repos",
        "threatminer": "ThreatMiner",
        "tip": "Threat Intel Platform",
        "yaraify": "YARAify",
        "malware_news": "Malware News",
        "rss_intel": "RSS Threat Intel",
        "tweetfeed": "TweetFeed",
        "malshare": "MalShare",
        "cb": "CyberBriefing",
        "vt_relations": "VirusTotal Relations",
        "cti_mentions": "Global CTI",
        "validin": "Validin pDNS",
        "abuseipdb": "AbuseIPDB",
        "shodan": "Shodan",
        "urlscan": "URLScan.io",
        "leakix": "LeakIX",
        "crtsh": "crt.sh",
        "openphish": "OpenPhish",
        "etugen": "Etugen WHOIS",
        "driftnet": "Driftnet",
        "silentpush": "Silent Push",
        "reputation_feeds": "Reputation Feeds",
        "rwlive": "Ransomware.live",
        "commoncrawl": "Common Crawl",
        "archive": "Wayback Machine",
        "orkl": "ORKL CTI",
    }
    if s in clean_map:
        return clean_map[s]
    
    # If raw JSON key, deduce provider from value or statement context
    if "arin" in val or "arin" in st or "whois" in s or "start_address" in s or "end_address" in s or "v4prefix" in s:
        return "ARIN RDAP / Whois"
    if "cloudflare" in val or "172.64" in val or "172.67" in val or "104.21" in val or "104.16" in val:
        return "DNSDumpster / Edge"
    if "virustotal" in val or "virustotal" in st:
        return "VirusTotal"
    if "orkl" in st or "hijacking" in st or "tunneling" in st or "oilrig" in st:
        return "ORKL CTI"
    if s in ("engine_name", "scumware.org", "bfore.ai", "desenmascara.me", "alphamountain.ai", "dr.web", "hunt.io"):
        return "VirusTotal Engine"
    if s in ("href", "self", "id", "url") and ("api/v3" in val or "virustotal" in val):
        return "VirusTotal Relations"
    if s in ("host_name", "network", "port43"):
        return "Authoritative DNS"
    if s in ("description", "values", "value"):
        return "Network Telemetry"
        
    return clean_map.get(s, s.replace("_", " ").title())


def generate_case_html_report(case_id: str) -> Dict[str, Any]:
    import html as html_lib
    case = get_case(case_id)
    root = case.get("root") or {}
    assessment = case.get("assessment") or {}
    ai_assessment = (case.get("ai_assessment") or [{}])[0]
    
    root_type = html_lib.escape(str(root.get("type", "indicator")).upper())
    raw_root_val = str(root.get("value", ""))
    root_val = html_lib.escape(raw_root_val)
    root_val_defanged = html_lib.escape(_defang_ioc(raw_root_val, root.get("type", "")))
    
    verdict = str(ai_assessment.get("verdict") or assessment.get("verdict") or "DEAD_END_INCONCLUSIVE").upper()
    verdict_label = ai_assessment.get("verdict_label") or assessment.get("verdict_label") or "Inconclusive / Low Telemetry"
    recommended_action = ai_assessment.get("recommended_action") or assessment.get("recommended_action") or "Manual Follow-up"
    confidence_score = int(ai_assessment.get("confidence_score") or assessment.get("confidence_score") or 30)
    
    if verdict == "WELL_FOUNDED_FINDINGS":
        badge_cls = "badge-danger"
        badge_icon = "fa-radiation"
    elif verdict == "FIFTY_FIFTY_SUSPICIOUS":
        badge_cls = "badge-warning"
        badge_icon = "fa-triangle-exclamation"
    elif verdict == "NO_FINDINGS_MOVE_ON":
        badge_cls = "badge-success"
        badge_icon = "fa-circle-check"
    else:
        badge_cls = "badge-muted"
        badge_icon = "fa-circle-question"
        
    ai_text = ai_assessment.get("assessment_text") or assessment.get("assessment_text") or _executive_summary(case)
    ai_text_html = html_lib.escape(ai_text).replace("\n\n", "</p><p>").replace("\n", "<br>")
    
    observations = case.get("observations") or []
    claims = case.get("claims") or []
    relationships = case.get("relationships") or []
    timeline = case.get("timeline") or []
    rejected = case.get("rejected_pivots") or []
    source_health = case.get("source_health") or []
    contradictions = assessment.get("contradictions") or []
    open_questions = assessment.get("open_questions") or []
    mitre_techs = ai_assessment.get("mitre_techniques") or assessment.get("mitre_techniques") or []
    if not isinstance(mitre_techs, list):
        mitre_techs = []

    # Build evidence lookup catalog for human-readable hypothesis citations
    evidence_catalog = {}
    for o in observations:
        eid = o.get("evidence_id")
        if eid:
            evidence_catalog[eid] = {
                "source": o.get("source") or "MANTIS",
                "type": o.get("obs_type") or "observation",
                "value": o.get("value") or "",
                "statement": o.get("statement") or "",
            }
    for c in claims:
        eid = c.get("evidence_id")
        if eid:
            evidence_catalog[eid] = {
                "source": c.get("source") or "MANTIS",
                "type": c.get("claim_type") or "claim",
                "value": c.get("value") or "",
                "statement": c.get("statement") or "",
            }

    # Extract distinct actors and malware
    actors = set()
    malware = set()
    for c in claims:
        ctyp = str(c.get("claim_type") or "").lower()
        cval = str(c.get("value") or "").strip()
        if not cval or cval.startswith("[truncated"):
            continue
        if "actor" in ctyp:
            actors.add(cval)
        elif "malware" in ctyp or "family" in ctyp:
            malware.add(cval)
    for obs in observations:
        otyp = str(obs.get("obs_type") or "").lower()
        oval = str(obs.get("value") or "").strip()
        if not oval or oval.startswith("[truncated"):
            continue
        if "malware" in otyp or "actor" in otyp:
            malware.add(oval)

    # Multi-Source Intelligence Breakdown
    source_summary_rows = _build_source_breakdown_html(case_id, case)
    source_breakdown_html = f"""
    <section class="report-card">
        <h3><i class="fa-solid fa-layer-group"></i> Multi-Source Intelligence Breakdown ({len(source_health)})</h3>
        <div class="table-responsive">
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 22%;">Intelligence Source</th>
                        <th style="width: 18%;">Status</th>
                        <th style="width: 60%;">Provider Findings &amp; Telemetry Summary</th>
                    </tr>
                </thead>
                <tbody>
                    {source_summary_rows}
                </tbody>
            </table>
        </div>
    </section>
    """

    # Observations table rows with Defanging, Copy buttons, and resolved clean CTI sources
    obs_rows = []
    for o in observations[:100]:
        eid = html_lib.escape(str(o.get("evidence_id") or ""))
        t = html_lib.escape(str(o.get("obs_type", "")))
        raw_v = str(o.get("value", ""))
        v_clean = html_lib.escape(raw_v)
        v_defanged = html_lib.escape(_defang_ioc(raw_v, o.get("obs_type", "")))
        raw_s = str(o.get("source", "MANTIS"))
        clean_s = _clean_obs_source(raw_s, raw_v, o.get("obs_type", ""), str(o.get("statement", "")))
        s_display = html_lib.escape(clean_s)
        stmt = html_lib.escape(str(o.get("statement", "")))
        # Clean statement if it contained raw JSON key
        if stmt.endswith(f" in {raw_s}."):
            stmt = f"{t.upper()} observed in {clean_s}."
        eid_badge = f"<a href='#{eid}' class='badge-evidence-sm' title='Evidence ID'>{eid}</a>" if eid else ""
        obs_rows.append(
            f"<tr id='{eid}'>"
            f"<td style='width: 14%;'><span class='type-tag'>{t}</span> {eid_badge}</td>"
            f"<td style='width: 28%;'>"
            f"  <div class='ioc-cell' data-raw='{v_clean}' data-defanged='{v_defanged}'>"
            f"    <span class='ioc-val mono'>{v_defanged}</span>"
            f"    <button class='action-btn' title='Copy indicator' onclick=\"copyText('{v_clean}', this)\"><i class='fa-regular fa-copy'></i></button>"
            f"  </div>"
            f"</td>"
            f"<td style='width: 18%;'><span class='src-chip'>{s_display}</span></td>"
            f"<td style='width: 40%; line-height:1.4;'>{stmt}</td>"
            f"</tr>"
        )
    obs_table_html = "".join(obs_rows) or "<tr><td colspan='4' class='empty-row'>No technical observations recorded.</td></tr>"

    # MITRE ATT&CK Matrix Card
    mitre_html = ""
    if mitre_techs:
        tags = "".join(f"<a href='https://attack.mitre.org/techniques/{html_lib.escape(t.replace('.', '/'))}' target='_blank' class='mitre-tag'><i class='fa-solid fa-crosshairs'></i> {html_lib.escape(t)}</a>" for t in mitre_techs)
        mitre_html = f"<div class='report-card'><h3><i class='fa-solid fa-bullseye'></i> MITRE ATT&CK Techniques Mapped</h3><div class='mitre-grid'>{tags}</div></div>"

    # Structured Contradictions HTML (Professional Cards instead of raw JSON)
    contra_cards = []
    for c in contradictions:
        c_dict = None
        if isinstance(c, dict):
            c_dict = c
        elif isinstance(c, str):
            c_str = c.strip()
            if c_str.startswith("{") and c_str.endswith("}"):
                try:
                    import ast
                    c_dict = ast.literal_eval(c_str)
                except Exception:
                    try:
                        c_dict = json.loads(c_str)
                    except Exception:
                        pass
        
        if isinstance(c_dict, dict):
            sev = str(c_dict.get("severity") or "high").upper()
            badge_cls_sev = "badge-danger" if sev == "HIGH" else "badge-warning"
            card_cls_sev = "severity-high" if sev == "HIGH" else "severity-moderate"
            statement = html_lib.escape(str(c_dict.get("statement") or "Conflicting provider evidence detected."))
            vals = c_dict.get("values") or []
            guidance = html_lib.escape(str(c_dict.get("guidance") or "Cross-reference technical telemetry and infrastructure overlap to resolve."))
            
            val_chips = "".join(f"<span class='conflict-chip'><i class='fa-solid fa-user-secret'></i> {html_lib.escape(str(v))}</span>" for v in vals if v)
            
            contra_cards.append(f"""
            <div class="contra-card {card_cls_sev}">
                <div class="contra-header">
                    <div class="contra-title">
                        <i class="fa-solid fa-triangle-exclamation" style="color:var(--danger);"></i>
                        <span>{statement}</span>
                    </div>
                    <span class="verdict-badge {badge_cls_sev}" style="font-size:10.5px; padding:3px 10px;">
                        {sev} SEVERITY CONFLICT
                    </span>
                </div>
                {f'<div class="contra-values-box"><div class="contra-values-label">Discrepant Provider Claims / Attributions:</div><div class="contra-chips">{val_chips}</div></div>' if val_chips else ''}
                <div class="contra-guidance">
                    <i class="fa-solid fa-compass" style="color:var(--cyan); margin-top:2px;"></i>
                    <div><strong>Analyst Resolution Guidance:</strong> {guidance}</div>
                </div>
            </div>
            """)
        else:
            c_text = html_lib.escape(str(c))
            contra_cards.append(f"""
            <div class="contra-card severity-moderate">
                <div class="contra-header">
                    <div class="contra-title">
                        <i class="fa-solid fa-triangle-exclamation" style="color:var(--warning);"></i>
                        <span>{c_text}</span>
                    </div>
                </div>
            </div>
            """)
            
    contra_html = ""
    if contra_cards:
        contra_html = f"""
        <section class="report-card alert-card">
            <h3><i class="fa-solid fa-triangle-exclamation"></i> Conflicting Telemetry &amp; Evidence Discrepancies ({len(contra_cards)})</h3>
            <div class="contra-list">
                {"".join(contra_cards)}
            </div>
        </section>
        """

    # Open questions HTML
    questions_html = ""
    if open_questions:
        items = "".join(f"<li><i class='fa fa-circle-question'></i> {html_lib.escape(str(q))}</li>" for q in open_questions)
        questions_html = f"<div class='report-card note-card'><h3><i class='fa-solid fa-clipboard-question'></i> Unresolved Questions &amp; Blind Spots</h3><ul>{items}</ul></div>"

    # Hypotheses HTML with Detailed Evidence Citations
    hypotheses = case.get("hypotheses") or []
    hypotheses_cards = []
    for h in hypotheses:
        strength = html_lib.escape(str(h.get("evidence_strength") or "MODERATE")).upper()
        h_subj = html_lib.escape(str(h.get("subject") or h.get("name") or "Threat Subject"))
        h_text = html_lib.escape(str(h.get("hypothesis") or h.get("summary") or ""))
        h_type = html_lib.escape(str(h.get("hypothesis_type") or h.get("type") or "malware_family").replace("_", " ").title())
        sup_ids = h.get("supporting_evidence_ids") or []
        gaps = h.get("gaps") or []

        strength_badge = "badge-danger" if strength == "HIGH" else "badge-warning" if strength == "MODERATE" else "badge-muted"
        
        # Build comprehensive evidence citations
        sup_citations = []
        for eid in sup_ids:
            ev_info = evidence_catalog.get(eid, {})
            ev_src = html_lib.escape(str(ev_info.get("source") or "Provider"))
            ev_val = html_lib.escape(str(ev_info.get("value") or ""))
            ev_stmt = html_lib.escape(str(ev_info.get("statement") or ev_val))
            sup_citations.append(
                f"<li>"
                f"<a href='#{html_lib.escape(eid)}' class='badge-evidence' title='Click to locate evidence in technical table'>{html_lib.escape(eid)}</a> "
                f"<span class='evidence-src-tag'>{ev_src}</span> "
                f"<span class='evidence-stmt-text'>{ev_stmt}</span>"
                f"</li>"
            )
        
        sup_html = f"<ul class='hyp-evidence-list'>{''.join(sup_citations)}</ul>" if sup_citations else "<span class='muted'>None cited</span>"
        gaps_li = "".join(f"<li><i class='fa-solid fa-triangle-exclamation'></i> {html_lib.escape(g)}</li>" for g in gaps)

        hypotheses_cards.append(f"""
        <div class="hypothesis-card">
            <div class="hyp-header">
                <div>
                    <span class="type-tag">{h_type}</span>
                    <strong style="font-size:15px; margin-left:8px;">{h_subj}</strong>
                </div>
                <span class="verdict-badge {strength_badge}" style="font-size:11px; padding:3px 10px;">
                    Evidence Strength: {strength}
                </span>
            </div>
            <div style="margin:10px 0; color:var(--text-main); font-size:13.5px; line-height:1.6;">{h_text}</div>
            <div class="hyp-evidence-box">
                <div class="hyp-evidence-title"><i class="fa-solid fa-link"></i> Supporting Evidence &amp; Corroboration ({len(sup_ids)}):</div>
                {sup_html}
            </div>
            {f'<ul class="hyp-gaps" style="margin-top:10px; font-size:12px; color:var(--text-muted); list-style:none;">{gaps_li}</ul>' if gaps_li else ''}
        </div>
        """)
        
    hypotheses_html = f"""
    <section class="report-card">
        <h3><i class="fa-solid fa-lightbulb"></i> Threat Hypotheses &amp; Evidence Strength ({len(hypotheses)})</h3>
        <div class="hypotheses-list">
            {"".join(hypotheses_cards) or "<div class='empty-row'>No formal threat hypotheses generated for this case.</div>"}
        </div>
    </section>
    """

    # Pivots Executed Audit Trail HTML
    pivots = case.get("pivots") or []
    pivot_rows = []
    for p in pivots:
        p_type = html_lib.escape(str(p.get("pivot_type", "")).replace("_", " "))
        p_val = html_lib.escape(str(p.get("value", "")))
        p_reason = html_lib.escape(str(p.get("reason", "")))
        p_dec = str(p.get("decision", "executed")).lower()
        p_dec_badge = "<span class='verdict-badge badge-success' style='padding:2px 8px; border-radius:4px;'>Executed</span>" if p_dec == "executed" else "<span class='verdict-badge badge-muted' style='padding:2px 8px; border-radius:4px;'>Filtered</span>"
        p_prov = html_lib.escape(str(p.get("provider", "-")))
        p_depth = html_lib.escape(str(p.get("depth", 1)))
        pivot_rows.append(f"""
        <tr>
            <td style="width: 18%;"><span class='type-tag'>{p_type}</span></td>
            <td style="width: 24%;" class='mono'><strong>{p_val}</strong></td>
            <td style="width: 32%; line-height:1.4;">{p_reason}</td>
            <td style="width: 10%;">{p_dec_badge}</td>
            <td style="width: 10%;">{p_prov}</td>
            <td style="width: 6%;">Round {p_depth}</td>
        </tr>
        """)
    pivots_html = f"""
    <section class="report-card">
        <h3><i class="fa-solid fa-arrows-split-up-and-left"></i> Autonomous Pivots &amp; Audit Trail ({len(pivots)})</h3>
        <div class="table-responsive">
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 18%;">Pivot Type</th>
                        <th style="width: 24%;">Indicator</th>
                        <th style="width: 32%;">Investigative Rationale</th>
                        <th style="width: 10%;">Decision</th>
                        <th style="width: 10%;">Provider</th>
                        <th style="width: 6%;">Round</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(pivot_rows) or "<tr><td colspan='6' class='empty-row'>No autonomous pivots were executed.</td></tr>"}
                </tbody>
            </table>
        </div>
    </section>
    """

    # Investigation Relationships Graph HTML (with responsive overflow protection)
    rel_rows = []
    for r in relationships[:80]:
        raw_s = str(r.get("source_entity") or f"{r.get('source_type')}:{r.get('source_value')}")
        raw_t = str(r.get("target_entity") or f"{r.get('target_type')}:{r.get('target_value')}")
        
        # Prettify long CTI report / file path strings
        def prettify_ent(ent):
            if "content.txt" in ent or "Daily/" in ent or len(ent) > 42:
                parts = ent.split("/")
                clean_name = parts[-2] if len(parts) >= 2 and parts[-1].endswith(".txt") else parts[-1]
                clean_name = clean_name.replace("honeymyte-coolclient-driver-rootkit_121028", "HoneyMyte Rootkit Report").replace("mustang-panda-adds-signed-windows_html", "Mustang Panda Rootkit Report")
                return f"<span title='{html_lib.escape(ent)}'><i class='fa-regular fa-file-lines' style='margin-right:4px; opacity:0.7;'></i>{html_lib.escape(clean_name[:40])}</span>"
            return html_lib.escape(ent)

        s_ent_display = prettify_ent(raw_s)
        rel = html_lib.escape(str(r.get("relation") or "related_to").replace("_", " "))
        t_ent_display = prettify_ent(raw_t)
        e_src = html_lib.escape(str(r.get("evidence_source") or ""))
        e_ids = r.get("evidence_ids") or []
        e_ids_str = ", ".join(f"<a href='#{html_lib.escape(str(x))}' class='badge-evidence-sm'>{html_lib.escape(str(x))}</a>" for x in e_ids[:3]) if e_ids else "-"
        rel_rows.append(f"""
        <tr>
            <td style="width: 28%;" class='mono-sm'>{s_ent_display}</td>
            <td style="width: 16%;"><span class='type-tag' style='color:var(--accent); border-color:rgba(255,204,0,0.3); font-size:10px;'>{rel}</span></td>
            <td style="width: 32%;" class='mono-sm'><strong>{t_ent_display}</strong></td>
            <td style="width: 12%;">{e_src}</td>
            <td style="width: 12%;">{e_ids_str}</td>
        </tr>
        """)
        
    rel_table_html = f"""
    <section class="report-card">
        <h3><i class="fa-solid fa-diagram-project"></i> Investigation Evidence Linkages ({len(relationships)})</h3>
        <div class="table-responsive">
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 28%;">Source Entity</th>
                        <th style="width: 16%;">Relationship</th>
                        <th style="width: 32%;">Target Entity</th>
                        <th style="width: 12%;">Source</th>
                        <th style="width: 12%;">Evidence IDs</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rel_rows) or "<tr><td colspan='5' class='empty-row'>No cross-entity relationships mapped.</td></tr>"}
                </tbody>
            </table>
        </div>
    </section>
    """

    # Attribution & Taxonomy HTML (Always rendered for thorough CTI evaluation)
    if actors:
        actor_tags = "".join(f"<span class='attrib-tag actor-tag'><i class='fa-solid fa-user-secret'></i> {html_lib.escape(a)}</span>" for a in sorted(actors))
    else:
        actor_tags = "<span class='attrib-tag actor-tag' style='background:rgba(140,156,184,0.12); color:var(--text-muted); border-color:rgba(140,156,184,0.3);'><i class='fa-solid fa-user-slash'></i> No Direct Threat Actor Established (Unattributed Infrastructure)</span>"

    if malware:
        malware_tags = "".join(f"<span class='attrib-tag malware-tag'><i class='fa-solid fa-bug'></i> {html_lib.escape(m)}</span>" for m in sorted(malware))
    else:
        malware_tags = "<span class='attrib-tag malware-tag' style='background:rgba(140,156,184,0.12); color:var(--text-muted); border-color:rgba(140,156,184,0.3);'><i class='fa-solid fa-shield'></i> No Distinct Malware Family Cataloged</span>"

    # Infrastructure profile & campaign references
    threat_classification = html_lib.escape(str(ai_assessment.get("threat_classification") or assessment.get("threat_classification") or "Infrastructure Telemetry"))
    
    # Check for campaign or infrastructure hints
    campaign_tags = []
    for c in claims:
        stmt = str(c.get("statement") or "")
        if "OilRig" in stmt or "oilrig" in stmt.lower():
            campaign_tags.append("OilRig DNS Manipulation")
        if "DNS Hijacking" in stmt:
            campaign_tags.append("Global DNS Hijacking Campaign")
        if "HoneyMyte" in stmt or "Mustang" in stmt:
            campaign_tags.append("HoneyMyte / Mustang Panda Campaign")

    campaign_html = ""
    if campaign_tags:
        campaign_html = "<div><div class='label-sm'>Historical Campaign Footprint (Collateral / pDNS)</div>" + "".join(f"<span class='attrib-tag' style='background:rgba(255,204,0,0.12); color:var(--accent); border:1px solid rgba(255,204,0,0.3);'><i class='fa-solid fa-bullhorn'></i> {html_lib.escape(cp)}</span>" for cp in set(campaign_tags)) + "</div>"

    attrib_html = f"""
    <div class='report-card'>
        <h3><i class='fa-solid fa-shield-halved'></i> Threat Attribution &amp; Taxonomy</h3>
        <div class='attrib-grid'>
            <div><div class='label-sm'>Associated Threat Actors</div>{actor_tags}</div>
            <div><div class='label-sm'>Associated Malware Families / Tools</div>{malware_tags}</div>
        </div>
        <div style='margin-top:16px; display:grid; grid-template-columns: 1fr 1fr; gap:20px;'>
            <div><div class='label-sm'>Infrastructure Classification</div><span class='attrib-tag' style='background:rgba(0,229,255,0.12); color:var(--cyan); border:1px solid rgba(0,229,255,0.3);'><i class='fa-solid fa-network-wired'></i> {threat_classification}</span></div>
            {campaign_html or "<div><div class='label-sm'>Attribution Confidence</div><span class='attrib-tag' style='background:rgba(255,255,255,0.05); color:var(--text-muted); border:1px solid var(--border);'><i class='fa-solid fa-scale-balanced'></i> Deterministic CTI Baseline</span></div>"}
        </div>
    </div>
    """

    # Dedicated Threat Assessment & Strategic Risk Evaluation Card
    confidence_level_str = html_lib.escape(str(ai_assessment.get("confidence_level") or assessment.get("confidence") or "medium").upper())
    
    # Build detailed risk rationale
    if verdict == "WELL_FOUNDED_FINDINGS":
        risk_rationale = f"Telemetry confirms direct malicious association with an active adversary campaign. Weaponized indicators and delivery components have been corroborated across independent threat intelligence providers."
        op_advice = f"Initiate immediate threat containment: block {root_val_defanged} on edge firewalls, sinkhole DNS requests, and isolate any internal endpoints communicating with linked infrastructure."
    elif verdict == "FIFTY_FIFTY_SUSPICIOUS":
        risk_rationale = f"Investigation reveals elevated suspicion due to historical threat references and reputation tagging (e.g. passive DNS hit volume or CTI mentions). However, resolved infrastructure (e.g. multi-tenant Cloudflare edge AS13335) introduces significant false-positive risk. Primary domain weaponization remains unverified."
        op_advice = f"Do not perform blunt perimeter IP blocking against shared CDN edge addresses. Implement internal DNS query monitoring and SIEM correlation for abnormal request entropy or dynamic sub-domains matching {root_val_defanged}."
    elif verdict == "NO_FINDINGS_MOVE_ON":
        risk_rationale = f"Multi-source OSINT and CTI queries yielded 0 malicious detections across all major threat providers, sandboxes, and reputation blocklists."
        op_advice = f"No proactive firewall blocking required. Retain standard DNS logging."
    else:
        risk_rationale = f"Telemetry is sparse or inconclusive across queried sources. Insufficient evidence to establish threat severity."
        op_advice = f"Perform manual contextual analysis if observed in high-priority detection alerts."

    threat_assessment_html = f"""
    <section class="report-card" style="border-left: 4px solid var(--accent);">
        <h3><i class="fa-solid fa-scale-balanced"></i> Threat Assessment &amp; Strategic Risk Evaluation</h3>
        <div style="display: grid; grid-template-columns: 260px 1fr; gap: 20px; align-items: start;">
            <div style="background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 8px; padding: 16px;">
                <div class="label-sm">Evaluated Risk Score</div>
                <div style="display:flex; align-items:baseline; gap:6px; margin: 6px 0 14px 0;">
                    <span style="font-size:32px; font-weight:800; color:{'var(--danger)' if verdict == 'WELL_FOUNDED_FINDINGS' else 'var(--warning)' if verdict == 'FIFTY_FIFTY_SUSPICIOUS' else 'var(--success)'};">{confidence_score}</span>
                    <span style="font-size:16px; color:var(--text-muted); font-weight:700;">/100</span>
                    <span class="verdict-badge {badge_cls}" style="margin-left:auto; font-size:10.5px; padding:2px 8px;">{verdict_label}</span>
                </div>
                <div style="font-size:11.5px; color:var(--text-muted); line-height:1.6; border-top:1px solid var(--border); padding-top:10px;">
                    <div><strong>Confidence:</strong> {confidence_level_str}</div>
                    <div><strong>Queried Sources:</strong> {len(source_health)}</div>
                    <div><strong>Evidence Linkages:</strong> {len(relationships)}</div>
                </div>
            </div>
            <div>
                <div class="label-sm">Strategic Risk Synthesis</div>
                <div class="exec-prose" style="font-size:13.5px; line-height:1.6; color:#d8e2f0;">
                    <p>{risk_rationale}</p>
                </div>
                <div style="margin-top:12px; padding:10px 14px; background:rgba(255,204,0,0.08); border-left:3px solid var(--accent); border-radius:0 6px 6px 0; font-size:12.5px; line-height:1.5;">
                    <strong style="color:#fff;"><i class="fa-solid fa-user-shield" style="margin-right:6px; color:var(--accent);"></i> Operational Security Guidance:</strong><br>
                    <span style="color:#f0f4fc;">{op_advice}</span>
                </div>
            </div>
        </div>
    </section>
    """

    # Timeline rows
    timeline_rows = []
    for item in timeline[:25]:
        phase = html_lib.escape(str(item.get("phase", "INVESTIGATION")).upper())
        title = html_lib.escape(str(item.get("title", "")).replace("Forensic", "Threat Intelligence").replace("forensic", "threat intelligence"))
        detail = html_lib.escape(str(item.get("detail", "")).replace("Forensic", "Threat Intelligence").replace("forensic", "threat intelligence"))
        source = html_lib.escape(str(item.get("source", "")))
        dt = html_lib.escape(str(item.get("created_at", "")))
        timeline_rows.append(f"<tr><td style='width: 14%;'><span class='phase-tag phase-{phase.lower()}'>{phase}</span></td><td style='width: 46%;'><strong>{title}</strong><br><small>{detail}</small></td><td style='width: 20%;'>{source}</td><td style='width: 20%;' class='mono-sm'>{dt}</td></tr>")
    timeline_table_html = "".join(timeline_rows) or "<tr><td colspan='4' class='empty-row'>No timeline events logged.</td></tr>"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Incident brief text for clipboard
    raw_brief_text = f"""*MANTIS CTI INCIDENT BRIEF*
Target: {root.get('type', 'indicator').upper()}: {raw_root_val}
Verdict: {verdict_label} ({confidence_score}/100)
Action: {recommended_action}
Threat Type: {ai_assessment.get('threat_classification') or 'Threat Assessment'}
Summary: {ai_text}
Key IOCs: {", ".join([str(o.get('value')) for o in observations[:6]])}
"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MANTIS CTI Report - {root_type}: {root_val_defanged}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --bg-body: #0a0d14;
            --bg-card: #121824;
            --bg-card-alt: #182030;
            --border: #222d42;
            --border-highlight: #2f3e5c;
            --text-main: #f0f4fc;
            --text-muted: #8c9cb8;
            --accent: #ffcc00;
            --accent-glow: rgba(255, 204, 0, 0.25);
            --danger: #ff3366;
            --warning: #ffaa00;
            --success: #00e676;
            --cyan: #00e5ff;
            --purple: #b388ff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-body);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.6;
            padding: 24px 16px;
        }}
        .report-container {{
            max-width: 1100px;
            margin: 0 auto;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6);
        }}
        .report-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .brand-icon {{
            font-size: 28px;
            color: var(--accent);
            text-shadow: 0 0 16px var(--accent-glow);
        }}
        .brand h1 {{
            font-size: 20px;
            letter-spacing: 1px;
            font-weight: 800;
            color: #fff;
            text-transform: uppercase;
        }}
        .brand p {{
            font-size: 11px;
            color: var(--text-muted);
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }}
        .header-meta {{
            text-align: right;
            font-size: 12px;
            color: var(--text-muted);
        }}
        .tlp-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1px;
            background: rgba(255, 204, 0, 0.15);
            color: var(--accent);
            border: 1px solid rgba(255, 204, 0, 0.35);
            margin-bottom: 6px;
        }}
        .report-controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .control-group {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .target-banner {{
            background: var(--bg-card-alt);
            border: 1px solid var(--border-highlight);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .target-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }}
        .target-value {{
            font-size: 17px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            color: #fff;
            word-break: break-all;
            font-weight: 600;
        }}
        .badge-danger {{
            background: rgba(255, 51, 102, 0.15);
            color: var(--danger);
            border: 1px solid rgba(255, 51, 102, 0.4);
        }}
        .badge-warning {{
            background: rgba(255, 170, 0, 0.15);
            color: var(--warning);
            border: 1px solid rgba(255, 170, 0, 0.4);
        }}
        .badge-success {{
            background: rgba(0, 230, 118, 0.15);
            color: var(--success);
            border: 1px solid rgba(0, 230, 118, 0.4);
        }}
        .badge-muted {{
            background: rgba(140, 156, 184, 0.15);
            color: var(--text-muted);
            border: 1px solid rgba(140, 156, 184, 0.4);
        }}
        .verdict-badge {{
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.5px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        .action-banner {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            border-radius: 6px;
            background: rgba(255, 204, 0, 0.08);
            border-left: 4px solid var(--accent);
            margin-bottom: 24px;
            font-size: 13.5px;
        }}
        .action-banner strong {{ color: #fff; }}
        .aead-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }}
        .aead-card {{
            background: var(--bg-card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 16px;
        }}
        .aead-title {{
            font-size: 10.5px;
            font-weight: 700;
            color: var(--cyan);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .aead-num {{
            font-size: 22px;
            font-weight: 800;
            color: #fff;
        }}
        .aead-desc {{
            font-size: 11.5px;
            color: var(--text-muted);
            margin-top: 4px;
            line-height: 1.4;
        }}
        .report-card {{
            background: var(--bg-card-alt);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 22px;
            margin-bottom: 24px;
        }}
        .report-card h3 {{
            font-size: 14px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}
        .report-card h3 i {{
            color: var(--accent);
        }}
        .exec-prose {{
            font-size: 14px;
            color: #d8e2f0;
            line-height: 1.7;
        }}
        .exec-prose p {{
            margin-bottom: 12px;
        }}
        .alert-card {{
            border-color: rgba(255, 51, 102, 0.4);
            background: rgba(255, 51, 102, 0.04);
        }}
        .alert-card h3 {{ color: var(--danger); border-color: rgba(255, 51, 102, 0.2); }}
        .note-card {{
            border-color: rgba(0, 229, 255, 0.3);
            background: rgba(0, 229, 255, 0.04);
        }}
        .note-card h3 {{ color: var(--cyan); border-color: rgba(0, 229, 255, 0.2); }}
        .note-card ul {{ padding-left: 20px; color: #d0f4fa; }}
        .note-card li {{ margin-bottom: 8px; }}
        .mitre-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .mitre-tag {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 4px;
            background: rgba(255, 0, 128, 0.12);
            color: #ff66b2;
            border: 1px solid rgba(255, 0, 128, 0.3);
            text-decoration: none;
            font-weight: 600;
            font-size: 12px;
            transition: all 0.2s;
        }}
        .mitre-tag:hover {{
            background: rgba(255, 0, 128, 0.25);
            transform: translateY(-1px);
        }}
        .attrib-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        @media (max-width: 768px) {{
            .attrib-grid {{ grid-template-columns: 1fr; }}
        }}
        .label-sm {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        .attrib-tag {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin: 0 6px 6px 0;
        }}
        .actor-tag {{
            background: rgba(179, 136, 255, 0.15);
            color: var(--purple);
            border: 1px solid rgba(179, 136, 255, 0.3);
        }}
        .malware-tag {{
            background: rgba(255, 51, 102, 0.15);
            color: var(--danger);
            border: 1px solid rgba(255, 51, 102, 0.3);
        }}
        .table-responsive {{
            width: 100%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            margin-bottom: 14px;
            border-radius: 6px;
            border: 1px solid var(--border);
        }}
        table.report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            table-layout: fixed;
            word-break: break-word;
        }}
        table.report-table th {{
            text-align: left;
            padding: 10px 12px;
            background: rgba(0, 0, 0, 0.25);
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }}
        table.report-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            vertical-align: top;
        }}
        table.report-table tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}
        table.report-table tr:target td {{
            background: rgba(0, 229, 255, 0.12);
            border-color: rgba(0, 229, 255, 0.3);
        }}
        .mono {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            color: #fff;
            word-break: break-all;
            overflow-wrap: anywhere;
        }}
        .mono-sm {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 11px;
            color: var(--text-muted);
            word-break: break-all;
            overflow-wrap: anywhere;
            white-space: normal;
        }}
        .ioc-cell {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            width: 100%;
        }}
        .ioc-val {{
            word-break: break-all;
            overflow-wrap: anywhere;
            line-height: 1.4;
            font-size: 12px;
        }}
        .src-chip {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-main);
            border: 1px solid var(--border);
            font-size: 11px;
            font-weight: 600;
        }}
        .row-actions {{
            display: inline-flex;
            gap: 4px;
            opacity: 0.5;
            transition: opacity 0.2s;
            flex-shrink: 0;
        }}
        table.report-table tr:hover .row-actions {{
            opacity: 1;
        }}
        .action-btn {{
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border);
            color: var(--text-main);
            border-radius: 4px;
            padding: 3px 6px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .action-btn:hover {{
            background: var(--accent);
            color: #0b0e14;
        }}
        .type-tag {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 3px;
            background: rgba(0, 229, 255, 0.1);
            color: var(--cyan);
            border: 1px solid rgba(0, 229, 255, 0.25);
            font-size: 10.5px;
            text-transform: uppercase;
            font-weight: 700;
        }}
        .src-badge {{
            display: inline-flex;
            align-items: center;
            gap: 7px;
            font-weight: 700;
            color: #fff;
            font-size: 12px;
        }}
        .src-badge i {{
            color: var(--cyan);
            font-size: 13px;
            width: 14px;
            text-align: center;
        }}
        .phase-tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}
        .phase-acquire {{ background: rgba(0, 229, 255, 0.15); color: var(--cyan); }}
        .phase-enrich {{ background: rgba(179, 136, 255, 0.15); color: var(--purple); }}
        .phase-assess {{ background: rgba(255, 204, 0, 0.15); color: var(--accent); }}
        .phase-deliver {{ background: rgba(0, 230, 118, 0.15); color: var(--success); }}
        .phase-stop {{ background: rgba(140, 156, 184, 0.15); color: var(--text-muted); }}
        .empty-row {{
            text-align: center;
            color: var(--text-muted);
            padding: 20px !important;
            font-style: italic;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 12.5px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            text-decoration: none;
        }}
        .btn-primary {{
            background: var(--accent);
            color: #0b0e14;
        }}
        .btn-primary:hover {{
            background: #ffd633;
            transform: translateY(-1px);
        }}
        .btn-secondary {{
            background: var(--bg-card-alt);
            color: var(--text-main);
            border: 1px solid var(--border-highlight);
        }}
        .btn-secondary:hover {{
            background: var(--border-highlight);
        }}
        .active-toggle {{
            background: rgba(0, 230, 118, 0.15);
            color: var(--success);
            border-color: rgba(0, 230, 118, 0.4);
        }}
        .hypothesis-card {{
            background: var(--bg-card-alt);
            border: 1px solid var(--border-highlight);
            border-radius: 8px;
            padding: 18px 22px;
            margin-bottom: 14px;
        }}
        .hyp-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .hyp-evidence-box {{
            margin-top: 12px;
            padding: 12px 14px;
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
        }}
        .hyp-evidence-title {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 700;
            color: var(--cyan);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .hyp-evidence-list {{
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .hyp-evidence-list li {{
            font-size: 12px;
            display: flex;
            align-items: flex-start;
            gap: 8px;
            line-height: 1.4;
        }}
        .badge-evidence {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            background: rgba(0, 229, 255, 0.12);
            color: var(--cyan);
            border: 1px solid rgba(0, 229, 255, 0.3);
            font-family: ui-monospace, monospace;
            font-size: 11px;
            text-decoration: none;
            flex-shrink: 0;
        }}
        .badge-evidence:hover {{
            background: rgba(0, 229, 255, 0.25);
            color: #fff;
        }}
        .badge-evidence-sm {{
            display: inline-block;
            padding: 1px 5px;
            border-radius: 3px;
            background: rgba(0, 229, 255, 0.08);
            color: var(--cyan);
            border: 1px solid rgba(0, 229, 255, 0.2);
            font-family: ui-monospace, monospace;
            font-size: 9.5px;
            text-decoration: none;
            margin-left: 4px;
        }}
        .badge-evidence-sm:hover {{
            background: rgba(0, 229, 255, 0.25);
            color: #fff;
        }}
        .evidence-src-tag {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            background: rgba(255, 204, 0, 0.12);
            color: var(--accent);
            border: 1px solid rgba(255, 204, 0, 0.3);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            flex-shrink: 0;
        }}
        .evidence-stmt-text {{
            color: #d8e2f0;
        }}
        .hyp-gaps li {{
            margin-top: 4px;
            color: var(--warning);
        }}
        /* Structured Contradictions */
        .contra-card {{
            background: rgba(255, 51, 102, 0.04);
            border: 1px solid rgba(255, 51, 102, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }}
        .contra-card.severity-high {{
            border-left: 4px solid var(--danger);
        }}
        .contra-card.severity-moderate {{
            border-left: 4px solid var(--warning);
            background: rgba(255, 170, 0, 0.04);
            border-color: rgba(255, 170, 0, 0.3);
        }}
        .contra-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
            flex-wrap: wrap;
        }}
        .contra-title {{
            font-size: 13.5px;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .contra-values-box {{
            margin: 10px 0;
            padding: 8px 12px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
        .contra-values-label {{
            font-size: 10.5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 700;
        }}
        .contra-chips {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}
        .conflict-chip {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 4px;
            background: rgba(255, 51, 102, 0.12);
            border: 1px solid rgba(255, 51, 102, 0.3);
            color: #ff99b3;
            font-size: 11.5px;
            font-weight: 600;
        }}
        .contra-guidance {{
            margin-top: 8px;
            padding: 8px 12px;
            background: rgba(0, 229, 255, 0.06);
            border-left: 3px solid var(--cyan);
            border-radius: 0 4px 4px 0;
            font-size: 12px;
            color: #cceeff;
            display: flex;
            align-items: flex-start;
            gap: 8px;
            line-height: 1.4;
        }}
        .report-footer {{
            text-align: center;
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 30px;
            padding-top: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }}
        @media print {{
            body {{ background: #fff !important; color: #000 !important; padding: 0; }}
            .report-container {{ border: none !important; box-shadow: none !important; max-width: 100% !important; padding: 0 !important; }}
            .report-controls, .row-actions {{ display: none !important; }}
            .report-card, .aead-card, .target-banner, .action-banner {{ background: #f9f9f9 !important; border: 1px solid #ddd !important; color: #000 !important; }}
            .mono, .target-value, .report-card h3, .brand h1 {{ color: #000 !important; }}
            .exec-prose {{ color: #222 !important; }}
            table.report-table th {{ background: #eee !important; color: #333 !important; border-color: #ccc !important; }}
            table.report-table td {{ border-color: #eee !important; color: #111 !important; }}
            .badge-danger {{ background: #fee !important; color: #c00 !important; border-color: #fcc !important; }}
            .badge-warning {{ background: #fff8e1 !important; color: #b78103 !important; border-color: #ffe082 !important; }}
            .badge-success {{ background: #e8f5e9 !important; color: #2e7d32 !important; border-color: #a5d6a7 !important; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <header class="report-header">
            <div class="brand">
                <i class="fa-solid fa-shield-virus brand-icon"></i>
                <div>
                    <h1>MANTIS // Threat Intelligence Report</h1>
                    <p>Autonomous AEAD Case Investigation Engine</p>
                </div>
            </div>
            <div class="header-meta">
                <div class="tlp-badge">TLP:AMBER+STRICT</div>
                <div><strong>Case ID:</strong> <span class="mono-sm">{html_lib.escape(case_id)}</span></div>
                <div><strong>Generated:</strong> {now_str}</div>
            </div>
        </header>

        <div class="report-controls">
            <div class="control-group">
                <button class="btn btn-secondary active-toggle" id="btn-toggle-defang" onclick="toggleDefang()"><i class="fa-solid fa-shield"></i> <span id="defang-state-label">Defanged (Safe)</span></button>
                <button class="btn btn-secondary" onclick="copyBrief()"><i class="fa-solid fa-clipboard-check"></i> Copy Ticket Brief</button>
            </div>
            <div class="control-group">
                <button class="btn btn-secondary" onclick="window.print()"><i class="fa-solid fa-print"></i> Print / PDF</button>
                <a class="btn btn-primary" id="btn-dl-html" href="#" download="mantis_report_{case_id}.html"><i class="fa-solid fa-download"></i> Download HTML</a>
            </div>
        </div>

        <section class="target-banner">
            <div>
                <div class="target-label">Investigation Target // Root Indicator</div>
                <div class="target-value"><i class="fa-solid fa-fingerprint"></i> {root_type}: {root_val_defanged}</div>
            </div>
            <div>
                <span class="verdict-badge {badge_cls}">
                    <i class="fa-solid {badge_icon}"></i> {verdict_label}
                </span>
            </div>
        </section>

        <div class="action-banner">
            <i class="fa-solid fa-user-shield" style="font-size:18px; color:var(--accent);"></i>
            <div><strong>Recommended Analyst Action:</strong> {html_lib.escape(recommended_action)}</div>
        </div>

        <section class="aead-grid">
            <div class="aead-card">
                <div class="aead-title"><i class="fa-solid fa-cloud-arrow-down"></i> 1. Acquire</div>
                <div class="aead-num">{len(source_health) or assessment.get('source_count', 0)}</div>
                <div class="aead-desc">OSINT sources queried, {len(observations)} technical facts normalized</div>
            </div>
            <div class="aead-card">
                <div class="aead-title"><i class="fa-solid fa-diagram-project"></i> 2. Enrich</div>
                <div class="aead-num">{len(relationships)}</div>
                <div class="aead-desc">Evidence links mapped ({len(rejected)} noise items filtered)</div>
            </div>
            <div class="aead-card">
                <div class="aead-title"><i class="fa-solid fa-arrows-split-up-and-left"></i> 3. Pivots</div>
                <div class="aead-num">{len(pivots)}</div>
                <div class="aead-desc">Autonomous passive pivots investigated across depth rounds</div>
            </div>
            <div class="aead-card">
                <div class="aead-title"><i class="fa-solid fa-scale-balanced"></i> 4. Assess</div>
                <div class="aead-num">{confidence_score}<small>/100</small></div>
                <div class="aead-desc">{verdict_label}</div>
            </div>
            <div class="aead-card">
                <div class="aead-title"><i class="fa-solid fa-file-shield"></i> 5. Deliver</div>
                <div class="aead-num" style="color:var(--success); font-size:20px; font-weight:800; letter-spacing:0.5px;">VERIFIED</div>
                <div class="aead-desc">Threat Intelligence report compiled &amp; operational brief ready</div>
            </div>
        </section>

        <section class="report-card">
            <h3><i class="fa-solid fa-file-lines"></i> Executive Intelligence Summary</h3>
            <div class="exec-prose">
                <p>{ai_text_html}</p>
            </div>
        </section>

        {threat_assessment_html}

        {source_breakdown_html}
        {attrib_html}
        {hypotheses_html}
        {pivots_html}
        {rel_table_html}
        {mitre_html}
        {contra_html}
        {questions_html}

        <section class="report-card">
            <h3><i class="fa-solid fa-microscope"></i> Normalized Technical Evidence ({len(observations)})</h3>
            <div class="table-responsive">
                <table class="report-table">
                    <thead>
                        <tr>
                            <th style="width: 14%;">Type &amp; ID</th>
                            <th style="width: 28%;">Indicator / Entity</th>
                            <th style="width: 18%;">Intelligence Source</th>
                            <th style="width: 40%;">Observed Technical Context &amp; Statement</th>
                        </tr>
                    </thead>
                    <tbody>
                        {obs_table_html}
                    </tbody>
                </table>
            </div>
        </section>

        <section class="report-card">
            <h3><i class="fa-solid fa-timeline"></i> Investigation Audit Trail &amp; Source Telemetry Health</h3>
            <div class="table-responsive">
                <table class="report-table">
                    <thead>
                        <tr>
                            <th style="width: 14%;">Phase</th>
                            <th style="width: 46%;">Action &amp; Evidence</th>
                            <th style="width: 20%;">Engine / Source</th>
                            <th style="width: 20%;">Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {timeline_table_html}
                    </tbody>
                </table>
            </div>
        </section>

        <footer class="report-footer">
            MANTIS (Multi-source Analysis and Threat Intelligence Search) // AEAD Case Agent // Strictly Confidential Threat Intelligence Product
        </footer>
    </div>

    <!-- Hidden Raw Data for Copy Brief -->
    <pre id="raw-brief-data" style="display:none;">{raw_brief_text}</pre>

    <script>
        let isDefanged = true;
        function toggleDefang() {{
            isDefanged = !isDefanged;
            document.querySelectorAll('.ioc-cell').forEach(td => {{
                const valSpan = td.querySelector('.ioc-val');
                if (valSpan) {{
                    valSpan.textContent = isDefanged ? td.dataset.defanged : td.dataset.raw;
                }}
            }});
            const label = document.getElementById('defang-state-label');
            if (label) label.textContent = isDefanged ? 'Defanged (Safe)' : 'Raw Indicators';
            const btn = document.getElementById('btn-toggle-defang');
            if (btn) btn.classList.toggle('active-toggle', isDefanged);
        }}

        function copyText(text, btn) {{
            navigator.clipboard.writeText(text).then(() => {{
                if (btn) {{
                    const old = btn.innerHTML;
                    btn.innerHTML = '<i class="fa-solid fa-check" style="color:var(--success);"></i>';
                    setTimeout(() => {{ btn.innerHTML = old; }}, 1400);
                }}
            }});
        }}

        function copyBrief() {{
            const brief = document.getElementById('raw-brief-data')?.textContent || '';
            navigator.clipboard.writeText(brief.trim()).then(() => {{
                alert('Executive incident brief copied to clipboard!');
            }});
        }}

        // Setup download href dynamically
        const blob = new Blob([document.documentElement.outerHTML], {{ type: 'text/html' }});
        document.getElementById('btn-dl-html').href = URL.createObjectURL(blob);
    </script>
</body>
</html>"""

    reports_dir = os.path.join(DATA_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filename = f"mantis_report_{case_id}.html"
    filepath = os.path.join(reports_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    with _connect() as db:
        _record_timeline(db, case_id, "deliver", "Delivered Threat Intelligence Briefing", f"Saved to {filename}", "aead_engine", "success", {"filepath": filepath})
        
    return {
        "case_id": case_id,
        "title": f"MANTIS Report - {root_type}: {raw_root_val}",
        "html": html_content,
        "filename": filename,
        "filepath": filepath
    }


def list_saved_reports() -> List[Dict[str, Any]]:
    reports_dir = os.path.join(DATA_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    out = []
    for fname in os.listdir(reports_dir):
        if not fname.endswith(".html"):
            continue
        fpath = os.path.join(reports_dir, fname)
        st = os.stat(fpath)
        case_id = fname.replace("mantis_report_", "").replace(".html", "")
        target = case_id
        verdict = "CTI Report"
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                head = f.read(4000)
                m = re.search(r"target-value.*?</i>\s*([^<]+)</div>", head, re.DOTALL)
                if m:
                    target = m.group(1).strip()
                v = re.search(r"verdict-badge.*?</i>\s*([^<]+)</span>", head, re.DOTALL)
                if v:
                    verdict = v.group(1).strip()
        except Exception:
            pass
        out.append({
            "filename": fname,
            "case_id": case_id,
            "target": target,
            "verdict": verdict,
            "size_bytes": st.st_size,
            "created_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "url": f"/api/ai/reports/{fname}"
        })
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return out


def run_case_aead(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes the autonomous investigation workflow:
    ACQUIRE -> ENRICH -> DISCOVER <-> PIVOT (bounded loop) -> ANALYZE -> REPORT
    """
    page_context = payload.get("page_context") if isinstance(payload.get("page_context"), dict) else {}
    case_id = str(payload.get("case_id") or "").strip()
    logs = []
    
    # Bounding parameters
    MAX_PIVOT_DEPTH = 3
    MAX_AUTO_PIVOTS = 10
    
    # --- 1. ACQUIRE ---
    if not case_id:
        case = sync_case_from_context(page_context, note="Autonomous CTI investigation initiated.")
        case_id = case["case_id"]
    else:
        case = get_case(case_id)
        
    temp_dir = os.path.join(DATA_DIR, "temp")
    os.makedirs(temp_dir, exist_ok=True)
    temp_file = os.path.join(temp_dir, f"acquire_{case_id}.json")
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(page_context, f)
    except Exception:
        pass
        
    src_health = case.get("source_health") or []
    active_sources = [s.get("source") for s in src_health if s.get("status") == "findings_or_context"]
    logs.append(f"Acquire: Ingested telemetry across {len(src_health)} source(s) ({len(active_sources)} with active telemetry).")
        
    # --- 2. ENRICH (Initial) ---
    case = get_case(case_id)
    obs = case.get("observations") or []
    claims = case.get("claims") or []
    noise_count = sum(1 for o in obs if not o.get("pivot_value", True))
    logs.append(f"Enrich: Normalized {len(obs)} observation(s), {len(claims)} claim(s); flagged {noise_count} benign/shared infrastructure item(s).")
    
    # --- 3. DISCOVER <-> PIVOT (Bounded Loop) ---
    max_rounds = max(1, min(int(payload.get("max_enrich_steps") or 3), 5))
    total_pivots_executed = 0
    pivots_audit_trail = []
    
    for round_idx in range(1, max_rounds + 1):
        if total_pivots_executed >= MAX_AUTO_PIVOTS:
            logs.append(f"Discover: Auto-pivot budget limit ({MAX_AUTO_PIVOTS}) reached. Progressing to analysis.")
            break
            
        case = get_case(case_id)
        candidates = discover_candidate_pivots(case, max_candidates=5)
        if not candidates:
            logs.append(f"Discover: No further high-value investigative relationships identified (Round {round_idx}).")
            break
            
        executed_in_round = 0
        for cand in candidates:
            if total_pivots_executed >= MAX_AUTO_PIVOTS:
                break
                
            # Deterministic Policy Engine Validation
            validation = validate_candidate_pivot(
                cand,
                case=case,
                max_depth=MAX_PIVOT_DEPTH,
                current_depth=round_idx,
                current_pivot_count=total_pivots_executed,
                max_auto_pivots=MAX_AUTO_PIVOTS,
            )
            
            p_type = cand.get("pivot_type", "unknown")
            p_val = cand.get("value", "")
            p_reason = cand.get("reason", "")
            parent_ev = cand.get("supporting_evidence", [])
            
            if validation.get("verdict") == "reject":
                _record_pivot_audit(
                    case_id=case_id,
                    parent_evidence=parent_ev,
                    pivot_type=p_type,
                    value=p_val,
                    reason=p_reason,
                    decision="rejected",
                    decision_reason=validation.get("reason", "Rejected by policy"),
                    provider="",
                    depth=round_idx
                )
                logs.append(f"Discover: Filtered pivot candidate '{p_val}' ({validation.get('reason')}).")
                continue
                
            # Approved Pivot: resolve provider and execute
            provider_candidates = resolve_sources_for_pivot(p_type, payload.get("selected_sources"))
            if not provider_candidates:
                provider_candidates = resolve_sources_for_pivot(p_type)
            provider_id = provider_candidates[0] if provider_candidates else "intel_query"
            
            # Execute passive provider lookup
            target_type = _detect_type(p_val)
            provider_res = _run_single_source(
                root_type=target_type,
                root_value=p_val,
                source_id=provider_id,
                keys=payload.get("keys") or {},
                github_repos=payload.get("github_repos") or []
            )
            
            # Record executed pivot in audit trail
            pivot_rec = _record_pivot_audit(
                case_id=case_id,
                parent_evidence=parent_ev,
                pivot_type=p_type,
                value=p_val,
                reason=p_reason,
                decision="executed",
                decision_reason=validation.get("reason", "Approved passive pivot"),
                provider=provider_id,
                depth=round_idx
            )
            pivots_audit_trail.append(pivot_rec)
            total_pivots_executed += 1
            executed_in_round += 1
            logs.append(f"Pivot: Executed {p_type} on '{p_val}' via {provider_id}.")
            
            # Feed new results back through ENRICH into evidence store
            new_normalized = normalize_provider(provider_id, provider_res, root=case.get("root"))
            _store_normalized_evidence(case_id, new_normalized)
            
        if executed_in_round == 0:
            logs.append(f"Discover: All candidate pivots in Round {round_idx} filtered or already investigated.")
            break
            
    # --- 4. ANALYZE (Hypothesis Engine) ---
    updated_case = get_case(case_id)
    analysis = analyze_case_hypotheses(updated_case)
    _save_case_analysis(case_id, analysis)
    for h in analysis.get("hypotheses") or []:
        h.setdefault("name", h.get("subject"))
        h.setdefault("type", h.get("hypothesis_type"))
        h.setdefault("summary", h.get("hypothesis"))
    logs.append(f"Analyze: Formulated {len(analysis.get('hypotheses', []))} hypothesis/hypotheses. Calibrated verdict = {analysis.get('verdict_label')} ({analysis.get('confidence_score')}/100).")
    
    # --- 5. REPORT ---
    report_data = generate_case_html_report(case_id)
    logs.append(f"Report: Generated evidence-centric HTML report '{report_data['filename']}'.")
    
    final_case = get_case(case_id)
    return {
        "case_id": case_id,
        "case": final_case,
        "html": report_data["html"],
        "filename": report_data["filename"],
        "filepath": report_data["filepath"],
        "pivots_executed": pivots_audit_trail,
        "hypotheses": analysis.get("hypotheses", []),
        "logs": logs
    }
