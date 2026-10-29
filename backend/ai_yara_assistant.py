import difflib
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from yara_service import MAX_WORKBENCH_BYTES, workbench_validate


MAX_AUTO_FIX_ITERATIONS = 5
MAX_ASSISTANT_RULE_BYTES = min(MAX_WORKBENCH_BYTES, 512 * 1024)
SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9_\-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9\-]{20,}|"
    r"Bearer\s+[A-Za-z0-9._\-]{12,}|[A-Za-z0-9_\-]{32,}\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})"
)

STRING_DEF_RE = re.compile(r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*=")
STRING_LITERAL_RE = re.compile(
    r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"((?:[^\"\\\n]|\\.)*)\"\s*((?:(?:ascii|wide|nocase|fullword|xor|base64wide|base64)\b\s*)*)",
    re.I,
)
RULE_NAME_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)")
SECTION_RE = re.compile(r"^\s*(meta|strings|condition)\s*:\s*$", re.M)


def rule_hash(source: str) -> str:
    return hashlib.sha256((source or "").encode("utf-8", "replace")).hexdigest()


def _ensure_size(source: str) -> None:
    if len((source or "").encode("utf-8", "replace")) > MAX_ASSISTANT_RULE_BYTES:
        raise ValueError(f"Rule source exceeds YARA Assistant limit of {MAX_ASSISTANT_RULE_BYTES} bytes.")


def mask_secrets(text: str) -> str:
    return SECRET_RE.sub("********", str(text or ""))


def unified_diff(original: str, updated: str) -> str:
    return "\n".join(difflib.unified_diff(
        (original or "").splitlines(),
        (updated or "").splitlines(),
        fromfile="original.yar",
        tofile="working-copy.yar",
        lineterm="",
    ))


def nearby_lines(source: str, line: int, radius: int = 2) -> List[Dict[str, Any]]:
    lines = (source or "").splitlines()
    if not line:
        return []
    start = max(1, int(line) - radius)
    end = min(len(lines), int(line) + radius)
    return [{"line": i, "text": mask_secrets(lines[i - 1])[:500]} for i in range(start, end + 1)]


def validation_errors(source: str, validation: Dict[str, Any] = None) -> Dict[str, Any]:
    if validation and isinstance(validation, dict) and "valid" in validation:
        return validation
    return workbench_validate(source or "")


def parse_rule(source: str) -> Dict[str, Any]:
    src = source or ""
    strings = []
    for match in STRING_LITERAL_RE.finditer(src):
        ident, literal, modifiers = match.groups()
        strings.append({
            "id": ident,
            "value_preview": mask_secrets(literal)[:120],
            "modifiers": re.findall(r"\b(ascii|wide|nocase|fullword|xor|base64|base64wide)\b", modifiers or "", re.I),
        })
    names = RULE_NAME_RE.findall(src)
    condition = ""
    m = re.search(r"\bcondition\s*:\s*(.*?)\s*\}\s*$", src, flags=re.M | re.S)
    if m:
        condition = m.group(1).strip()
    sections = sorted({m.group(1) for m in SECTION_RE.finditer(src)})
    return {
        "rule_names": names,
        "strings": strings[:200],
        "string_count": len(STRING_DEF_RE.findall(src)),
        "sections": sections,
        "condition": mask_secrets(condition)[:3000],
        "imports": re.findall(r'^\s*import\s+"([^"]+)"', src, flags=re.M)[:20],
        "hash": rule_hash(src),
    }


def quality_suggestions(source: str, test_result: Dict[str, Any] = None) -> List[Dict[str, str]]:
    parsed = parse_rule(source)
    suggestions = []
    if not parsed["rule_names"]:
        suggestions.append({"severity": "review", "message": "No rule name was detected."})
    if "meta" not in parsed["sections"]:
        suggestions.append({"severity": "review", "message": "No metadata section is present; consider adding description/date/reference if known."})
    if parsed["string_count"] == 0:
        suggestions.append({"severity": "high", "message": "No string identifiers were detected. A stringless rule can be hard to validate and may be broad."})
    condition = parsed.get("condition", "").lower()
    if re.search(r"\btrue\b", condition) and parsed["string_count"] <= 1:
        suggestions.append({"severity": "high", "message": "Condition is very broad; compile success would not prove detection quality."})
    if "any of them" in condition:
        suggestions.append({"severity": "review", "message": "`any of them` can be broad unless the strings are highly distinctive."})
    seen_values = {}
    for s in parsed["strings"]:
        val = s["value_preview"].lower()
        if val:
            seen_values.setdefault(val, []).append(s["id"])
    for ids in seen_values.values():
        if len(ids) > 1:
            suggestions.append({"severity": "review", "message": f"Duplicate string literal appears in {', '.join(ids[:5])}."})
            break
    if test_result:
        coverage = test_result.get("string_coverage") or test_result.get("coverage") or []
        generic = [c for c in coverage if int(c.get("files_matched") or 0) > 10 and float(c.get("coverage") or 0) > 50]
        for c in generic[:3]:
            suggestions.append({"severity": "review", "message": f"{c.get('string')} matched many tested files ({c.get('coverage')}%); validate that it is distinctive."})
    return suggestions[:20]


def explain_rule(source: str, validation: Dict[str, Any] = None, test_result: Dict[str, Any] = None) -> Dict[str, Any]:
    _ensure_size(source)
    parsed = parse_rule(source)
    validation = validation_errors(source, validation)
    status = "COMPILE PASS" if validation.get("valid") else "COMPILE FAIL"
    strings = parsed["strings"]
    lines = [
        f"Compile status: {status} using {validation.get('engine') or 'configured engine'}.",
        f"Rule names: {', '.join(parsed['rule_names']) if parsed['rule_names'] else 'none detected'}.",
        f"Declared strings: {parsed['string_count']}.",
    ]
    if parsed["imports"]:
        lines.append(f"Modules imported: {', '.join(parsed['imports'])}.")
    if parsed["condition"]:
        lines.append("Condition is present and should be interpreted against actual compile/test output.")
    if test_result:
        total = test_result.get("total_files") or (test_result.get("stats") or {}).get("total")
        detected = test_result.get("detected") or (test_result.get("stats") or {}).get("detected")
        if total is not None:
            lines.append(f"Latest local test scope: {detected or 0}/{total or 0} files matched.")
    return {
        "rule_hash": parsed["hash"],
        "status": status,
        "engine": validation.get("engine", ""),
        "summary": "\n".join(lines),
        "parsed": parsed,
        "errors": validation.get("errors", []),
        "quality_suggestions": quality_suggestions(source, test_result),
        "local_only": True,
    }


def analyze_error(source: str, validation: Dict[str, Any] = None) -> Dict[str, Any]:
    _ensure_size(source)
    validation = validation_errors(source, validation)
    errors = validation.get("errors", [])
    findings = []
    for err in errors[:10]:
        message = str(err.get("message") or "")
        lower = message.lower()
        meaning = "Compiler rejected the rule. The compiler output is authoritative."
        if "undefined" in lower and "$" in message:
            meaning = "A condition references an identifier that is not declared in the strings section."
        elif "duplicate" in lower:
            meaning = "The rule likely declares the same identifier or rule name more than once."
        elif "syntax" in lower or "unexpected" in lower:
            meaning = "The parser found syntax it cannot accept near the reported line."
        elif "unterminated" in lower or "quote" in lower:
            meaning = "A string or comment may not be closed correctly."
        findings.append({
            "line": err.get("line"),
            "column": err.get("column"),
            "message": mask_secrets(message),
            "meaning": meaning,
            "nearby_lines": nearby_lines(source, err.get("line") or 0),
        })
    return {
        "valid": bool(validation.get("valid")),
        "engine": validation.get("engine", ""),
        "rule_hash": rule_hash(source or ""),
        "findings": findings,
        "classic_valid": validation.get("classic_valid", False),
        "classic_errors": validation.get("classic_errors", []),
    }


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _extract_undefined_identifier(errors: List[Dict[str, Any]]) -> str:
    for err in errors:
        message = str(err.get("message") or "")
        m = re.search(r"(\$[A-Za-z_][A-Za-z0-9_]*)", message)
        if m and "undefined" in message.lower():
            return m.group(1)
    return ""


def safe_fix_check(original: str, updated: str) -> Tuple[bool, List[str]]:
    reasons = []
    if updated == original:
        reasons.append("No rule change was proposed.")
    parsed = parse_rule(updated)
    cond = parsed.get("condition", "").strip().lower()
    if cond in {"true", "1", "filesize >= 0"}:
        reasons.append("Unsafe destructive fix: condition became trivially true.")
    if parsed["string_count"] == 0 and parse_rule(original)["string_count"] > 0:
        reasons.append("Unsafe destructive fix: all strings were removed.")
    original_lines = max(1, len((original or "").splitlines()))
    updated_lines = len((updated or "").splitlines())
    if original_lines >= 6 and updated_lines < max(3, original_lines // 2):
        reasons.append("Unsafe destructive fix: proposed rule removed too much content.")
    return not reasons, reasons


def suggest_fix(source: str, validation: Dict[str, Any] = None) -> Dict[str, Any]:
    _ensure_size(source)
    validation = validation_errors(source, validation)
    if validation.get("valid"):
        return {
            "changed": False,
            "fixed_source": source or "",
            "diff": "",
            "confidence": "No fix needed",
            "reason": "The rule already compiles.",
            "review_required": False,
            "safe": True,
        }
    errors = validation.get("errors", [])
    original = source or ""
    updated = original
    reason = "No safe fix was identified for this compiler error."
    confidence = "Review required"
    review_required = True

    undefined = _extract_undefined_identifier(errors)
    declared = sorted(set(STRING_DEF_RE.findall(original)))
    if undefined and declared:
        best = min(declared, key=lambda item: _levenshtein(undefined.lower(), item.lower()))
        if _levenshtein(undefined.lower(), best.lower()) <= 2:
            updated = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(undefined)}(?![A-Za-z0-9_])", best, original)
            reason = f"`{undefined}` is referenced but not declared; `{best}` is the nearest declared string identifier."
            confidence = "Safe mechanical fix"
            review_required = False

    # Check for unclosed string quote error (scan all lines with odd quote count)
    if updated == original:
        lines = original.splitlines()
        modified = False
        for i, line_txt in enumerate(lines):
            clean_line = line_txt.split("//")[0]
            if clean_line.count('"') % 2 == 1:
                lines[i] = line_txt + '"'
                modified = True
        if modified:
            candidate = "\n".join(lines)
            cand_val = workbench_validate(candidate)
            orig_err_count = len(errors)
            cand_err_count = len(cand_val.get("errors", []))
            if cand_val.get("valid") or cand_err_count < orig_err_count:
                updated = candidate
                reason = "Closed unclosed string literal quotes."
                confidence = "Safe mechanical fix"
                review_required = False

    # Check for missing closing brace }
    if updated == original:
        for err in errors:
            msg = str(err.get("message") or "").lower()
            if "unexpected end of file" in msg or "expected" in msg or "syntax error" in msg:
                if original.strip().count("{") > original.strip().count("}"):
                    candidate = original.rstrip() + "\n}"
                    if workbench_validate(candidate).get("valid"):
                        updated = candidate
                        reason = "Appended missing closing brace `}` to complete rule block."
                        confidence = "Safe mechanical fix"
                        review_required = False
                        break

    # Check for missing section colons (e.g. meta, strings, condition)
    if updated == original:
        candidate = re.sub(r"^\s*(meta|strings|condition)\s*$", r"\1:", original, flags=re.M)
        if candidate != original and workbench_validate(candidate).get("valid"):
            updated = candidate
            reason = "Added missing colon `:` to section header."
            confidence = "Safe mechanical fix"
            review_required = False

    if updated == original:
        return {
            "changed": False,
            "fixed_source": original,
            "diff": "",
            "confidence": "Review required",
            "reason": reason,
            "review_required": True,
            "safe": True,
            "errors": errors,
            "rule_hash": rule_hash(original),
        }

    safe, unsafe_reasons = safe_fix_check(original, updated)
    return {
        "changed": updated != original and safe,
        "fixed_source": updated if safe else original,
        "diff": unified_diff(original, updated) if updated != original else "",
        "confidence": confidence,
        "reason": reason if safe else "Unsafe fix rejected: " + " ".join(unsafe_reasons),
        "review_required": review_required or not safe,
        "safe": safe,
        "errors": errors,
        "rule_hash": rule_hash(original),
    }


def validate_auto_fix(source: str, max_iterations: int = MAX_AUTO_FIX_ITERATIONS) -> Dict[str, Any]:
    _ensure_size(source)
    original = source or ""
    working = original
    max_iterations = max(1, min(int(max_iterations or MAX_AUTO_FIX_ITERATIONS), MAX_AUTO_FIX_ITERATIONS))
    history = []
    seen_errors = set()
    stopped_reason = ""

    for iteration in range(1, max_iterations + 1):
        validation = workbench_validate(working)
        err_sig = tuple((e.get("line"), e.get("column"), e.get("message")) for e in validation.get("errors", []))
        history.append({
            "iteration": iteration,
            "rule_hash": rule_hash(working),
            "valid": bool(validation.get("valid")),
            "engine": validation.get("engine", ""),
            "errors": validation.get("errors", []),
        })
        if validation.get("valid"):
            stopped_reason = "Compilation succeeded on the temporary working copy."
            break
        if err_sig in seen_errors:
            stopped_reason = "Auto-fix stopped because compiler errors are repeating."
            break
        seen_errors.add(err_sig)
        fix = suggest_fix(working, validation)
        history[-1]["fix"] = {k: fix.get(k) for k in ("changed", "confidence", "reason", "diff", "review_required", "safe")}
        if not fix.get("changed"):
            stopped_reason = fix.get("reason") or "No safe fix available."
            break
        working = fix["fixed_source"]
    else:
        stopped_reason = "Auto-fix stopped after reaching the maximum iteration limit."

    final_validation = workbench_validate(working)
    return {
        "original_hash": rule_hash(original),
        "working_hash": rule_hash(working),
        "original_source": original,
        "working_source": working,
        "changed": working != original,
        "diff": unified_diff(original, working) if working != original else "",
        "compile_status": "COMPILE PASS" if final_validation.get("valid") else "COMPILE FAIL",
        "final_validation": final_validation,
        "history": history,
        "iterations": len(history),
        "max_iterations": max_iterations,
        "stopped_reason": stopped_reason,
        "accept_required": True,
        "local_only": True,
    }


def analyze_test_result(source: str, test_result: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_size(source)
    parsed = parse_rule(source)
    result = test_result or {}
    files = result.get("files") or []
    total = int(result.get("total_files") or len(files) or 0)
    detected = int(result.get("detected") or len([f for f in files if f.get("match")]) or 0)
    coverage = result.get("string_coverage") or []
    matched_strings = [c.get("string") for c in coverage if int(c.get("files_matched") or 0) > 0]
    unmatched = [s["id"] for s in parsed["strings"] if s["id"] not in set(matched_strings)]
    notes = []
    if total and detected == 0:
        notes.append("No selected local sample matched. This is a false-negative candidate only for the tested scope.")
    if unmatched:
        notes.append(f"Declared strings with no recorded matches in this test: {', '.join(unmatched[:10])}.")
    if "all of them" in parsed.get("condition", "").lower() and unmatched:
        notes.append("Condition uses `all of them`; one missing string is enough to prevent a match.")
    if not result.get("negative"):
        notes.append("False-positive behavior has not been validated against a benign set.")
    return {
        "rule_hash": parsed["hash"],
        "status": "MATCH" if detected else "NO MATCH",
        "tested_files": total,
        "matched_files": detected,
        "matched_strings": matched_strings[:50],
        "unmatched_declared_strings": unmatched[:50],
        "notes": notes,
        "quality_suggestions": quality_suggestions(source, result),
        "local_only": True,
    }
