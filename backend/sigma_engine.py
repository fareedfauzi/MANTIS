"""
MANTIS Sigma Engine
High-performance Sigma YAML parser, validator, and detection evaluator.
Supports standard Sigma specifications, field modifiers, condition parsing,
and live event log testing.
"""

from __future__ import annotations
import ast
import re
import base64
import yaml
from typing import Any, Dict, List, Optional, Tuple, Union

SIGMA_STATUS_LEVELS = {"stable", "test", "experimental", "deprecated"}
SIGMA_SEVERITY_LEVELS = {"critical", "high", "medium", "low", "informational"}


def parse_sigma_yaml(raw_yaml: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Parse raw YAML text into a dict; returns (parsed_dict, error_list)."""
    errors = []
    if not raw_yaml or not raw_yaml.strip():
        return None, ["Sigma rule content is empty."]
    try:
        data = yaml.safe_load(raw_yaml)
        if not isinstance(data, dict):
            return None, ["Sigma rule YAML must be a top-level mapping/dictionary."]
        return data, []
    except Exception as e:
        return None, [f"YAML syntax error: {str(e)}"]


def validate_sigma_rule(raw_yaml: str) -> Dict[str, Any]:
    """
    Validate a Sigma rule against the Sigma specification standard.
    Returns status dict with errors, warnings, and normalized metadata.
    """
    data, parse_errs = parse_sigma_yaml(raw_yaml)
    if parse_errs:
        return {
            "valid": False,
            "errors": parse_errs,
            "warnings": [],
            "rule": None
        }

    errors: List[str] = []
    warnings: List[str] = []

    # Required fields
    if not data.get("title"):
        errors.append("Missing required field: 'title'")
    elif not isinstance(data.get("title"), str) or len(data.get("title", "").strip()) < 3:
        errors.append("'title' must be a descriptive string of at least 3 characters.")

    logsource = data.get("logsource")
    if not logsource or not isinstance(logsource, dict):
        errors.append("Missing or invalid required section: 'logsource' (must be a dictionary).")
    else:
        if not (logsource.get("category") or logsource.get("product") or logsource.get("service")):
            warnings.append("Logsource should specify at least one of: 'category', 'product', or 'service'.")

    detection = data.get("detection")
    if not detection or not isinstance(detection, dict):
        errors.append("Missing or invalid required section: 'detection' (must be a dictionary).")
    else:
        condition = detection.get("condition")
        if not condition:
            errors.append("Missing required detection key: 'condition'")
        elif not isinstance(condition, str) or not condition.strip():
            errors.append("'condition' must be a non-empty string expression.")

        # Check that named selections in condition exist in detection
        selections = [k for k in detection.keys() if k != "condition" and not k.startswith("_")]
        if not selections:
            errors.append("Detection section contains no search selections/identifiers.")

    # Status & Level checks
    status = str(data.get("status", "")).lower()
    if status and status not in SIGMA_STATUS_LEVELS:
        warnings.append(f"Unusual status '{status}'. Standard values: {', '.join(sorted(SIGMA_STATUS_LEVELS))}")

    level = str(data.get("level", "")).lower()
    if level and level not in SIGMA_SEVERITY_LEVELS:
        warnings.append(f"Unusual level '{level}'. Standard values: {', '.join(sorted(SIGMA_SEVERITY_LEVELS))}")

    # Tag validation (e.g. mitre, cve)
    tags = data.get("tags", [])
    if tags and not isinstance(tags, list):
        warnings.append("'tags' should be a list of tag strings.")

    # MITRE ATT&CK extractions
    mitre_techniques = []
    mitre_tactics = []
    cves = []
    if isinstance(tags, list):
        for t in tags:
            t_str = str(t).strip().lower()
            if t_str.startswith("attack.t") or re.match(r"^t\d{4}(\.\d{3})?$", t_str):
                m = re.search(r"t\d{4}(\.\d{3})?", t_str, re.IGNORECASE)
                if m:
                    mitre_techniques.append(m.group(0).upper())
            elif t_str.startswith("attack."):
                mitre_tactics.append(t_str.replace("attack.", ""))
            elif t_str.startswith("cve.") or "cve-" in t_str:
                m = re.search(r"cve-\d{4}-\d+", t_str, re.IGNORECASE)
                if m:
                    cves.append(m.group(0).upper())

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "rule": {
            "title": data.get("title", ""),
            "id": data.get("id", ""),
            "status": data.get("status", "experimental"),
            "level": data.get("level", "medium"),
            "description": data.get("description", ""),
            "author": data.get("author", "Unknown"),
            "date": str(data.get("date", "")),
            "modified": str(data.get("modified", "")),
            "logsource": data.get("logsource", {}),
            "detection": data.get("detection", {}),
            "falsepositives": data.get("falsepositives", []),
            "references": data.get("references", []),
            "tags": tags if isinstance(tags, list) else [],
            "mitre_techniques": sorted(list(set(mitre_techniques))),
            "mitre_tactics": sorted(list(set(mitre_tactics))),
            "cves": sorted(list(set(cves)))
        } if len(errors) == 0 else None
    }


def extract_tags_and_mitre(tags: List[Any]) -> Dict[str, List[str]]:
    """Extract MITRE techniques, tactics, and CVE identifiers from tags list."""
    mitre_techniques = []
    mitre_tactics = []
    cves = []
    if isinstance(tags, list):
        for t in tags:
            t_str = str(t).strip().lower()
            if t_str.startswith("attack.t") or re.match(r"^t\d{4}(\.\d{3})?$", t_str):
                m = re.search(r"t\d{4}(\.\d{3})?", t_str, re.IGNORECASE)
                if m:
                    mitre_techniques.append(m.group(0).upper())
            elif t_str.startswith("attack."):
                mitre_tactics.append(t_str.replace("attack.", ""))
            elif t_str.startswith("cve.") or "cve-" in t_str or "cve." in t_str:
                m = re.search(r"cve[-.]\d{4}[-.]\d+", t_str, re.IGNORECASE)
                if m:
                    norm_cve = m.group(0).upper().replace(".", "-")
                    cves.append(norm_cve)
    return {
        "techniques": sorted(list(set(mitre_techniques))),
        "tactics": sorted(list(set(mitre_tactics))),
        "cves": sorted(list(set(cves)))
    }


validate_rule_yaml = validate_sigma_rule


def _match_field_value(field_value: Any, expected: Any, modifiers: List[str]) -> bool:
    """Evaluate a single log field against a single expected pattern using Sigma modifiers."""
    if field_value is None:
        return expected is None

    # If event field value is a list (e.g. Hashes, IPAddresses), check if any item matches
    if isinstance(field_value, list):
        return any(_match_field_value(elem, expected, modifiers) for elem in field_value)

    str_val = str(field_value)
    str_exp = str(expected)

    # Base64 modifiers
    if "base64" in modifiers or "base64offset" in modifiers:
        try:
            exp_b64 = base64.b64encode(str_exp.encode()).decode()
            if exp_b64.lower() in str_val.lower():
                return True
        except Exception:
            pass

    # Regex modifier
    if "re" in modifiers:
        try:
            return bool(re.search(str_exp, str_val, re.IGNORECASE))
        except Exception:
            return False

    # Startswith
    if "startswith" in modifiers:
        return str_val.lower().startswith(str_exp.lower())

    # Endswith
    if "endswith" in modifiers:
        return str_val.lower().endswith(str_exp.lower())

    # Contains (default if contains in modifiers or wildcard present)
    if "contains" in modifiers:
        return str_exp.lower() in str_val.lower()

    # Windows Dash (/ or -)
    if "windash" in modifiers:
        norm_val = re.sub(r"[\/\-]", "-", str_val.lower())
        norm_exp = re.sub(r"[\/\-]", "-", str_exp.lower())
        return norm_exp in norm_val

    # Wildcards in expected string (* and ?)
    if "*" in str_exp or "?" in str_exp:
        # Convert glob to regex
        reg = "^" + re.escape(str_exp).replace(r"\*", ".*").replace(r"\?", ".") + "$"
        try:
            return bool(re.match(reg, str_val, re.IGNORECASE))
        except Exception:
            return False

    # Default: exact case-insensitive match
    return str_val.lower() == str_exp.lower()


def evaluate_selection_item(event: Dict[str, Any], field_def: str, expected_val: Any) -> Dict[str, Any]:
    """
    Evaluate a field pattern like 'Image|endswith' or 'CommandLine|contains|all' against an event log.
    Returns a rich evaluation dict with match status, modifiers, expected, and actual value.
    """
    parts = field_def.split("|")
    field_name = parts[0]
    modifiers = [m.lower() for m in parts[1:]]

    # Find field in event (case-insensitive lookup across keys)
    actual_val = None
    matched_key = None
    for k, v in event.items():
        if k.lower() == field_name.lower():
            actual_val = v
            matched_key = k
            break

    if actual_val is None:
        # Field does not exist in event
        is_matched = (expected_val is None)
        return {
            "field": field_name,
            "raw_field_def": field_def,
            "modifiers": modifiers,
            "expected": expected_val,
            "actual_value": None,
            "field_present": False,
            "matched": is_matched,
            "matched_key": None
        }

    # Handle list of expected values (OR by default, AND if |all)
    if isinstance(expected_val, list):
        if "all" in modifiers:
            is_matched = all(_match_field_value(actual_val, exp, modifiers) for exp in expected_val)
        else:
            is_matched = any(_match_field_value(actual_val, exp, modifiers) for exp in expected_val)
    else:
        is_matched = _match_field_value(actual_val, expected_val, modifiers)

    return {
        "field": field_name,
        "raw_field_def": field_def,
        "modifiers": modifiers,
        "expected": expected_val,
        "actual_value": actual_val,
        "field_present": True,
        "matched": is_matched,
        "matched_key": matched_key
    }


def evaluate_selection_block(event: Dict[str, Any], block_data: Any, block_name: str = "selection") -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Evaluate a selection mapping or list of mappings.
    Returns (is_match, list_of_field_evaluations).
    """
    field_evals: List[Dict[str, Any]] = []

    if isinstance(block_data, list):
        # Case A: list of dicts -> OR between dicts
        if any(isinstance(item, dict) for item in block_data):
            any_dict_matched = False
            for idx, item in enumerate(block_data):
                if isinstance(item, dict):
                    sub_ok, sub_evals = evaluate_selection_block(event, item, block_name=f"{block_name}[{idx}]")
                    field_evals.extend(sub_evals)
                    if sub_ok:
                        any_dict_matched = True
            return any_dict_matched, field_evals

        # Case B: list of string keywords -> search across all event string fields
        all_event_values = [str(v) for v in event.values() if v is not None]
        kw_matched_count = 0
        for kw in block_data:
            str_kw = str(kw)
            matched_in_val = None
            for ev_val in all_event_values:
                if str_kw.lower() in ev_val.lower():
                    matched_in_val = ev_val
                    break
            is_kw_match = matched_in_val is not None
            if is_kw_match:
                kw_matched_count += 1
            field_evals.append({
                "block": block_name,
                "field": "(keyword)",
                "raw_field_def": "keywords|contains",
                "modifiers": ["contains"],
                "expected": str_kw,
                "actual_value": matched_in_val if matched_in_val else "(no matching string in event)",
                "field_present": True,
                "matched": is_kw_match,
                "matched_key": None
            })
        return (kw_matched_count > 0), field_evals

    if not isinstance(block_data, dict):
        # Single string / primitive keyword search
        str_kw = str(block_data)
        all_event_values = [str(v) for v in event.values() if v is not None]
        matched_in_val = next((v for v in all_event_values if str_kw.lower() in v.lower()), None)
        item_eval = {
            "block": block_name,
            "field": "(keyword)",
            "raw_field_def": "keywords|contains",
            "modifiers": ["contains"],
            "expected": str_kw,
            "actual_value": matched_in_val if matched_in_val else "(no matching string in event)",
            "field_present": True,
            "matched": matched_in_val is not None,
            "matched_key": None
        }
        return (matched_in_val is not None), [item_eval]

    # Dict of fields -> AND between fields (evaluate ALL fields for visibility)
    for field_def, expected in block_data.items():
        eval_dict = evaluate_selection_item(event, field_def, expected)
        eval_dict["block"] = block_name
        field_evals.append(eval_dict)

    all_matched = all(f["matched"] for f in field_evals) if field_evals else False
    return all_matched, field_evals


def evaluate_sigma_event(rule_yaml: str, event_data: Union[Dict[str, Any], str]) -> Dict[str, Any]:
    """
    Execute a Sigma rule detection against a test event log.
    Accepts rule_yaml string and event_data (dict or JSON string).
    Returns complete match report with condition trace and matched fields.
    """
    val = validate_sigma_rule(rule_yaml)
    if not val["valid"] or not val["rule"]:
        return {
            "success": False,
            "matched": False,
            "error": "Invalid Sigma rule: " + "; ".join(val["errors"]),
            "field_evaluations": [],
            "details": {}
        }

    # Normalize event log
    if isinstance(event_data, str):
        try:
            import json
            event = json.loads(event_data)
        except Exception:
            # Try key-value parser (e.g. Image="powershell.exe" CommandLine="-enc ...")
            event = {}
            for m in re.finditer(r'([A-Za-z0-9_\.\-]+)=[\"\']?([^\"\'\s]+|[\"\'][^\"\']*[\"\'])', event_data):
                k = m.group(1)
                v = m.group(2).strip("\"'")
                event[k] = v
            # If still empty or partial, store raw log fields
            event["Raw"] = event_data
            event["Message"] = event_data
            event["CommandLine"] = event.get("CommandLine", event_data)
    elif isinstance(event_data, dict):
        event = event_data
    else:
        return {
            "success": False,
            "matched": False,
            "error": "Event log must be a JSON object or string.",
            "field_evaluations": [],
            "details": {}
        }

    rule = val["rule"]
    detection = rule.get("detection", {})
    condition_str = detection.get("condition", "").strip()

    # Evaluate all selection identifiers
    selection_results: Dict[str, bool] = {}
    all_field_evals: List[Dict[str, Any]] = []

    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        matched, block_evals = evaluate_selection_block(event, block, block_name=name)
        selection_results[name] = matched
        all_field_evals.extend(block_evals)

    # Evaluate condition expression
    final_match = _eval_condition_expr(condition_str, selection_results)

    matched_fields_map = {}
    for f in all_field_evals:
        if f["matched"] and f["actual_value"] is not None:
            matched_fields_map[f["field"]] = f["actual_value"]

    return {
        "success": True,
        "matched": final_match,
        "rule_title": rule.get("title", "Untitled Sigma Signature"),
        "rule_level": rule.get("level", "medium"),
        "condition": condition_str,
        "selection_results": selection_results,
        "field_evaluations": all_field_evals,
        "matched_fields": matched_fields_map,
        "evaluated_event_keys": list(event.keys()),
        "explanation": f"Condition '{condition_str}' evaluated to {final_match}."
    }


def _safe_bool_expr(expr: str) -> bool:
    """Evaluate a boolean-only expression without eval().

    Sigma ``condition`` strings are attacker-controlled (downloaded rule packs and
    user-uploaded rules). eval() with ``{"__builtins__": None}`` is not a sandbox:
    ``().__class__.__bases__[0].__subclasses__()`` still reaches arbitrary classes.
    Only names/booleans and and/or/not survive the AST whitelist below.
    """
    tree = ast.parse(expr, mode="eval")

    def ev(node: ast.AST) -> bool:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(ev(v) for v in node.values)
            if isinstance(node.op, ast.Or):
                return any(ev(v) for v in node.values)
            raise ValueError("unsupported boolean operator")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not ev(node.operand)
        if isinstance(node, ast.Constant) and isinstance(node.value, (bool, int)):
            return bool(node.value)
        if isinstance(node, ast.Name) and node.id in ("True", "False"):
            return node.id == "True"
        raise ValueError(f"unsupported expression element: {type(node).__name__}")

    return bool(ev(tree))


def _eval_condition_expr(cond: str, results: Dict[str, bool]) -> bool:
    """Safely evaluates standard Sigma condition expressions with selections."""
    # Standard 1 of selection* / all of selection*
    def replace_quantifiers(m: re.Match) -> str:
        q = m.group(1).lower()  # 1 of / all of
        pattern = m.group(2)    # selection*
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        matched_keys = [k for k in results.keys() if re.match(regex, k, re.IGNORECASE)]
        if not matched_keys:
            return "False"
        bools = [results[k] for k in matched_keys]
        if q == "1 of" or q == "any of":
            return str(any(bools))
        elif q == "all of":
            return str(all(bools))
        return "False"

    expr = cond
    expr = re.sub(r"\b(1 of|any of|all of)\s+([a-zA-Z0-9_\*]+)\b", replace_quantifiers, expr, flags=re.IGNORECASE)
    expr = re.sub(r"\b(1 of|any of)\s+them\b", str(any(results.values()) if results else False), expr, flags=re.IGNORECASE)
    expr = re.sub(r"\ball of them\b", str(all(results.values()) if results else False), expr, flags=re.IGNORECASE)

    # Replace individual selection names with their boolean values
    for name in sorted(results.keys(), key=len, reverse=True):
        expr = re.sub(rf"\b{re.escape(name)}\b", str(results[name]), expr)

    # Standardize boolean operators
    expr = re.sub(r"\band\b", " and ", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bor\b", " or ", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bnot\b", " not ", expr, flags=re.IGNORECASE)

    try:
        return _safe_bool_expr(expr)
    except Exception:
        # Fallback heuristic: check if any selection matched
        return any(results.values())
