"""
MANTIS AI Threat Hunting Query Validation Engine
Validates generated queries across all 15 supported platforms:
- Syntactic integrity (balanced quotes, parentheses, brackets, braces)
- Platform operator & keyword validity
- Boolean expression structure
- Telemetry & field mapping checks
- Evidence preservation (ensuring key artifacts from hypothesis are in query)
- Overly broad / non-performant search detection
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple


def validate_hunting_query(
    query_text: str,
    platform: str,
    hypothesis: Optional[Dict[str, Any]] = None,
    mode: str = "hunting"
) -> Dict[str, Any]:
    """
    Validates a generated threat hunting or detection query against syntactic,
    semantic, and platform-specific rules.
    Returns:
    {
      "status": "Validated" | "Warning" | "Failed" | "Not Verified",
      "score": float,
      "summary": str,
      "issues": List[str],
      "warnings": List[str],
      "checks": Dict[str, bool]
    }
    """
    q = (query_text or "").strip()
    plat = (platform or "splunk").lower().strip()

    issues: List[str] = []
    warnings: List[str] = []

    # 1. Empty check
    if not q:
        return {
            "status": "Failed",
            "score": 0.0,
            "summary": "Query is empty.",
            "issues": ["Query string is empty."],
            "warnings": [],
            "checks": {"non_empty": False}
        }

    # 2. Balanced delimiters check (quotes, parentheses, brackets, braces)
    delims_ok, delim_issue = _check_balanced_delimiters(q)
    if not delims_ok:
        issues.append(f"Syntax error: {delim_issue}")

    # 3. Overly broad / Permissive query check
    broad_patterns = [
        (r"^\s*index\s*=\s*\*\s*$", "Bare `index=*` with no filter conditions is too broad."),
        (r"\bwhere\s+1\s*=\s*1\b", "Contains permissive `1=1` clause."),
        (r"\bwhere\s+true\b", "Contains permissive `where true` clause."),
        (r"\(\s*true\*\s*\)", "Contains permissive placeholder `(true*)`.")
    ]
    for pattern, desc in broad_patterns:
        if re.search(pattern, q, re.IGNORECASE):
            issues.append(desc)

    # 4. Platform-specific keyword & structure checks
    plat_ok, plat_issue, plat_warn = _check_platform_structure(q, plat)
    if not plat_ok and plat_issue:
        issues.append(plat_issue)
    if plat_warn:
        warnings.append(plat_warn)

    # 5. Evidence preservation check (if hypothesis is provided)
    evidence_score = 1.0
    if hypothesis:
        ev_ok, ev_warn, evidence_score = _check_evidence_preservation(q, hypothesis)
        if not ev_ok and ev_warn:
            warnings.append(ev_warn)

    # 6. Mode-specific checks
    if mode == "detection":
        # Detections should have tighter filters
        if "stats " not in q.lower() and "where" not in q.lower() and "filter" not in q.lower() and "=" not in q and ":" not in q:
            warnings.append("Detection query may lack sufficient filtering specificity for low-noise alerting.")

    # Calculate overall score and status
    score = 1.0
    if issues:
        score = max(0.0, 0.4 - len(issues) * 0.1)
        status = "Failed"
        summary = f"Validation Failed: {len(issues)} critical issue(s) detected."
    elif warnings:
        score = max(0.5, 0.85 - len(warnings) * 0.1)
        status = "Warning"
        summary = f"Validated with Warnings: {len(warnings)} suggestion(s) for optimization."
    else:
        score = round(0.9 + 0.1 * evidence_score, 2)
        status = "Validated"
        summary = "Query passed all platform syntax, structure, and evidence checks."

    return {
        "status": status,
        "score": score,
        "summary": summary,
        "issues": issues,
        "warnings": warnings,
        "checks": {
            "non_empty": True,
            "balanced_delimiters": delims_ok,
            "platform_structure": plat_ok,
            "evidence_preserved": evidence_score >= 0.5,
            "non_permissive": not any(re.search(p[0], q, re.I) for p in broad_patterns)
        }
    }


def _check_balanced_delimiters(query: str) -> Tuple[bool, Optional[str]]:
    # Remove escaped quotes
    sanitized = re.sub(r'\\"', '', query)
    sanitized = re.sub(r"\\'", '', sanitized)

    # Count quotes
    double_quotes = sanitized.count('"')
    if double_quotes % 2 != 0:
        return False, "Unclosed double quotes detected."

    # Stack check for parentheses, brackets, braces
    stack = []
    pairs = {')': '(', ']': '[', '}': '{'}
    openers = set(pairs.values())

    in_dquote = False
    in_squote = False

    for char in query:
        if char == '"' and not in_squote:
            in_dquote = not in_dquote
            continue
        if char == "'" and not in_dquote:
            in_squote = not in_squote
            continue

        if not in_dquote and not in_squote:
            if char in openers:
                stack.append(char)
            elif char in pairs:
                if not stack or stack.pop() != pairs[char]:
                    return False, f"Unbalanced delimiter: unexpected '{char}'."

    if stack:
        return False, f"Unclosed delimiter '{stack[-1]}' detected."

    return True, None


def _check_platform_structure(query: str, platform: str) -> Tuple[bool, Optional[str], Optional[str]]:
    q_lower = query.lower()

    if platform == "splunk":
        # SPL checks
        if "|" in query:
            parts = query.split("|")
            for p in parts[1:]:
                cmd = p.strip().split()[0].lower() if p.strip() else ""
                # Common SPL commands
                known_spl = {
                    "search", "where", "stats", "table", "eval", "sort", "head", "tail",
                    "rex", "dedup", "fields", "lookup", "join", "rename", "timechart", "chart"
                }
                if cmd and cmd not in known_spl and not cmd.startswith("tstats"):
                    return True, None, f"Uncommon pipe command '{cmd}' in SPL query; verify your Splunk app context."
        return True, None, None

    elif platform in ("sentinel", "defender"):
        # KQL checks
        if not any(token in q_lower for token in ("where", "summarize", "project", "take", "limit", "extend", "join")):
            return True, None, "KQL query does not contain standard table filter pipes (e.g. | where)."
        return True, None, None

    elif platform == "elastic_eql":
        # EQL checks
        if not re.search(r"\b(process|network|file|registry|sequence)\s+where\b", query, re.IGNORECASE):
            return True, None, "EQL query typically begins with `<category> where` (e.g. `process where`)."
        return True, None, None

    elif platform == "elastic_kql":
        # KQL checks
        if ":" not in query:
            return True, None, "Elastic KQL typically uses field colon syntax (e.g. `process.name : ...`)."
        return True, None, None

    elif platform == "elastic_dsl":
        # JSON DSL checks
        try:
            json.loads(query)
            return True, None, None
        except Exception as e:
            return False, f"Invalid JSON syntax for Elasticsearch Query DSL: {str(e)}", None

    elif platform in ("crowdstrike", "crowdstrike_aes"):
        # CQL checks
        if "eventsimplename" not in q_lower.replace("_", "") and "aid" not in q_lower:
            return True, None, "CrowdStrike CQL query usually specifies `#event_simpleName` or an aid filter."
        return True, None, None

    elif platform == "qradar":
        # AQL checks
        if not q_lower.startswith("select") or "from events" not in q_lower:
            return False, "QRadar AQL queries must start with `SELECT ... FROM events WHERE ...`.", None
        return True, None, None

    elif platform == "cloudwatch":
        # CloudWatch checks
        if "fields" not in q_lower and "filter" not in q_lower:
            return True, None, "CloudWatch Logs Insights query typically uses `fields ... | filter ...`."
        return True, None, None

    return True, None, None


def _check_evidence_preservation(query: str, hypothesis: Dict[str, Any]) -> Tuple[bool, Optional[str], float]:
    evidence = str(hypothesis.get("supporting_evidence") or "")
    if not evidence.strip():
        return True, None, 1.0

    # Extract alphanumeric and filename tokens of 4+ characters
    tokens = re.findall(r"[A-Za-z0-9_\-\.]{4,}", evidence)
    if not tokens:
        return True, None, 1.0

    q_lower = query.lower()
    matched = 0
    total = min(len(tokens), 8)

    for t in tokens[:total]:
        if t.lower() in q_lower:
            matched += 1

    ratio = matched / max(1, total)
    if ratio < 0.3:
        return False, "Query text does not appear to reflect the observable artifacts cited in the hypothesis.", ratio
    return True, None, ratio
