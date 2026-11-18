"""
MANTIS Sigma Query Converter
Translates Sigma detection rules into industry-standard SIEM & EDR queries:
- Splunk (SPL) - via pySigma & pySigma-backend-splunk with proper logsource pipelines
- Elasticsearch / Kibana (KQL & Lucene)
- Microsoft Sentinel / Defender for Endpoint (KQL)
- IBM QRadar (AQL)
- CrowdStrike Falcon LogScale / Humio (LQL)
- Google Chronicle / SecOps (YARA-L)
- OpenSearch DSL
- ANSI SQL / DuckDB / Snowflake
- PowerShell (Get-WinEvent)
- Sysmon XML EventFilter
"""

from __future__ import annotations
import re
import uuid
import yaml
from typing import Any, Dict, List, Optional, Tuple, Union
from backend.sigma_engine import validate_sigma_rule

# pySigma framework integration
try:
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    import sigma.pipelines.windows as pw
    import sigma.pipelines.sysmon as ps
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.exceptions import SigmaError, SigmaConditionError, SigmaModifierError, SigmaValueError
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False
    SigmaError = Exception  # type: ignore


SUPPORTED_TARGETS = [
    {"id": "splunk", "name": "Splunk (SPL)", "lang": "splunk", "icon": "fa-magnifying-glass"},
    {"id": "sentinel", "name": "Microsoft Sentinel (KQL)", "lang": "kql", "icon": "fa-shield-halved"},
    {"id": "defender", "name": "Microsoft Defender XDR (KQL)", "lang": "kql", "icon": "fa-shield-virus"},
    {"id": "elastic_kql", "name": "Elastic Security (KQL)", "lang": "kql", "icon": "fa-cube"},
    {"id": "elasticsearch_dsl", "name": "Elasticsearch Query DSL", "lang": "json", "icon": "fa-code"},
    {"id": "crowdstrike", "name": "CrowdStrike LogScale (CQL)", "lang": "lql", "icon": "fa-bolt"},
    {"id": "secops", "name": "Google SecOps / Chronicle (YARA-L)", "lang": "yara", "icon": "fa-shield"},
    {"id": "qradar", "name": "IBM QRadar (AQL)", "lang": "sql", "icon": "fa-server"},
    {"id": "sumologic", "name": "Sumo Logic", "lang": "sumo", "icon": "fa-chart-pie"},
    {"id": "sql", "name": "ANSI SQL / Snowflake / BigQuery", "lang": "sql", "icon": "fa-table"},
    {"id": "opensearch", "name": "OpenSearch Query DSL", "lang": "json", "icon": "fa-code"},
    {"id": "elastic_lucene", "name": "Elastic Lucene Query", "lang": "lucene", "icon": "fa-database"},
    {"id": "powershell", "name": "PowerShell (Get-WinEvent)", "lang": "powershell", "icon": "fa-terminal"},
    {"id": "sysmon", "name": "Sysmon XML EventFilter", "lang": "xml", "icon": "fa-file-code"},
]


def _normalize_yaml_for_pysigma(raw_yaml: str) -> str:
    """
    Normalizes Sigma YAML so that pySigma's strict schema validator accepts
    community rules, partial snippets, or non-standard custom metadata:
    - Synthesizes a 'title' if omitted.
    - Normalizes custom string 'id' into a valid UUIDv5.
    - Normalizes non-namespaced 'tags' into 'custom.<tag>'.
    - Ensures 'logsource' and 'detection' sections exist.
    """
    try:
        data = yaml.safe_load(raw_yaml)
        if not isinstance(data, dict):
            return raw_yaml

        modified = False
        if not data.get("title"):
            data["title"] = "Sigma Detection Rule"
            modified = True

        rule_id = data.get("id")
        if rule_id and not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", str(rule_id)):
            data["id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(rule_id)))
            modified = True

        tags = data.get("tags")
        if isinstance(tags, list):
            new_tags = []
            for t in tags:
                t_str = str(t).strip()
                if "." not in t_str:
                    new_tags.append(f"custom.{t_str}")
                    modified = True
                else:
                    new_tags.append(t_str)
            data["tags"] = new_tags

        if "logsource" not in data or not isinstance(data.get("logsource"), dict):
            data["logsource"] = {}
            modified = True

        if modified:
            return yaml.safe_dump(data, sort_keys=False)
        return raw_yaml
    except Exception:
        return raw_yaml


def _select_splunk_pipeline(pipeline_name: Optional[str], logsource: Dict[str, Any]):
    """
    Selects or builds the Splunk processing pipeline.
    Avoids introducing unnecessary or conflicting Event IDs.
    """
    p_name = (pipeline_name or "auto").strip().lower()

    if p_name in ("none", "raw", "disabled"):
        return None

    if not PYSIGMA_AVAILABLE:
        return None

    if p_name in ("sysmon",):
        return ps.sysmon_pipeline()
    elif p_name in ("windows_audit", "audit"):
        return pw.windows_audit_pipeline()
    elif p_name in ("windows", "windows_logsource"):
        return pw.windows_logsource_pipeline()

    # "auto" pipeline selection based on logsource
    product = str(logsource.get("product", "")).lower()
    service = str(logsource.get("service", "")).lower()

    if product == "windows":
        if service == "sysmon":
            return ps.sysmon_pipeline()
        return pw.windows_logsource_pipeline()
    elif service == "sysmon":
        return ps.sysmon_pipeline()

    return None


def convert_sigma_rule(
    raw_yaml: str,
    target: str = "splunk",
    pipeline: Optional[str] = None,
    mode: str = "standard",
    provider: Optional[str] = None,
    model: Optional[str] = None
) -> Dict[str, Any]:
    """
    Converts a Sigma YAML rule into the requested target query format.
    Supports 3 modes:
    - 'standard': pySigma and rule-based deterministic compiler
    - 'ai': LLM-powered translation using platform schemas and instructions
    - 'ai_repair': Runs pySigma first, then uses AI to review, fix errors, and repair missing logic
    Returns { target, query, success, error, mode, rule_title, rule_level, logsource, validation, ... }.
    """
    if not raw_yaml or not raw_yaml.strip():
        return {
            "success": False,
            "target": target,
            "query": "",
            "mode": mode,
            "error": "Sigma rule content is empty."
        }

    # Normalize YAML (synthesize title if user pasted a detection snippet)
    norm_yaml = _normalize_yaml_for_pysigma(raw_yaml)

    val = validate_sigma_rule(norm_yaml)
    if not val["valid"] or not val["rule"]:
        return {
            "success": False,
            "target": target,
            "query": "",
            "mode": mode,
            "error": "Invalid Sigma rule: " + "; ".join(val["errors"])
        }

    rule = val["rule"]
    detection = rule.get("detection", {})
    condition = detection.get("condition", "selection")
    logsource = rule.get("logsource", {})

    target = target.lower()

    # Route AI conversion
    if mode == "ai":
        from backend.sigma_ai_converter import ai_convert_sigma
        return ai_convert_sigma(
            raw_yaml=raw_yaml,
            target=target,
            provider=provider,
            model=model,
            rule_dict=rule
        )

    # Route AI-Assisted Repair
    if mode == "ai_repair":
        # First execute standard conversion to get baseline / error / warnings
        std_res = convert_sigma_rule(raw_yaml=raw_yaml, target=target, pipeline=pipeline, mode="standard")
        initial_query = std_res.get("query", "")
        error_msg = std_res.get("error", "")
        if not error_msg and std_res.get("validation", {}).get("status") == "Failed":
            error_msg = "; ".join(std_res.get("validation", {}).get("issues", []))

        from backend.sigma_ai_converter import ai_repair_sigma
        return ai_repair_sigma(
            raw_yaml=raw_yaml,
            target=target,
            initial_query=initial_query,
            error_or_warning=error_msg,
            provider=provider,
            model=model,
            rule_dict=rule
        )

    # Standard (pySigma / rule-based) conversion
    try:
        if target == "splunk":
            query = _convert_to_splunk(norm_yaml, detection, condition, logsource, pipeline=pipeline)
        elif target == "sentinel":
            query = _convert_to_sentinel(detection, condition, logsource)
        elif target == "defender":
            query = _convert_to_defender(detection, condition, logsource)
        elif target == "elastic_kql":
            query = _convert_to_elastic_kql(detection, condition, logsource)
        elif target in ("elasticsearch_dsl", "opensearch"):
            query = _convert_to_opensearch(norm_yaml, detection, condition, logsource)
        elif target == "elastic_lucene":
            query = _convert_to_elastic_lucene(norm_yaml, detection, condition, logsource)
        elif target == "qradar":
            query = _convert_to_qradar(detection, condition, logsource)
        elif target in ("crowdstrike", "humio", "cql", "lql"):
            query = _convert_to_crowdstrike(detection, condition, logsource)
        elif target in ("chronicle", "secops", "yara_l"):
            query = _convert_to_chronicle(rule, detection, condition, logsource)
        elif target in ("sumologic", "sumo"):
            query = _convert_to_sumologic(detection, condition, logsource)
        elif target == "sql":
            query = _convert_to_sql(detection, condition, logsource)
        elif target == "powershell":
            query = _convert_to_powershell(detection, condition, logsource)
        elif target == "sysmon":
            query = _convert_to_sysmon_xml(detection, condition, logsource)
        else:
            query = _convert_to_splunk(norm_yaml, detection, condition, logsource, pipeline=pipeline)
            target = "splunk"

        # Deterministic validation layer
        from backend.sigma_ai_converter import validate_conversion
        val_res = validate_conversion(rule_dict=rule, generated_query=query, target=target)

        return {
            "success": True,
            "mode": "standard",
            "target": target,
            "query": query.strip(),
            "rule_title": rule.get("title"),
            "rule_level": rule.get("level"),
            "logsource": logsource,
            "validation": val_res,
            "available_targets": [t["id"] for t in SUPPORTED_TARGETS]
        }
    except Exception as e:
        return {
            "success": False,
            "mode": "standard",
            "target": target,
            "query": "",
            "error": f"Conversion error for target '{target}': {str(e)}",
            "validation": {
                "status": "Failed",
                "summary": f"Conversion failed: {str(e)}",
                "issues": [str(e)]
            }
        }


def convert_all_targets(raw_yaml: str, pipeline: Optional[str] = None) -> Dict[str, Any]:
    """Convert rule to all supported target formats in one call."""
    res = {}
    for t in SUPPORTED_TARGETS:
        cid = t["id"]
        res[cid] = convert_sigma_rule(raw_yaml, target=cid, pipeline=pipeline)
    return {
        "success": True,
        "conversions": res,
        "targets_metadata": SUPPORTED_TARGETS
    }


# ============================================================================
# TARGET CONVERTERS
# ============================================================================

def _compile_selection_block(block: Any, format_fn, op_and: str = " AND ", op_or: str = " OR ") -> str:
    """
    Compiles a Sigma selection block (map or list of maps) respecting official
    Sigma boolean semantics:
    - A list of maps is evaluated with OR logic across the items.
    - A map of key-values is evaluated with AND logic across the keys.
    - A list of values for a key is evaluated with OR (or AND if '|all' is present).
    """
    if isinstance(block, list):
        parts = [_compile_selection_block(item, format_fn, op_and, op_or) for item in block]
        parts = [p for p in parts if p]
        if not parts:
            raise ValueError("Selection block list contains no valid criteria.")
        return parts[0] if len(parts) == 1 else "(" + op_or.join(parts) + ")"

    elif isinstance(block, dict):
        parts = []
        for k, v in block.items():
            field_parts = k.split("|")
            field = field_parts[0]
            mods = [m.lower() for m in field_parts[1:]]
            if isinstance(v, list):
                val_parts = [format_fn(field, mods, single_v) for single_v in v]
                val_parts = [vp for vp in val_parts if vp]
                if not val_parts:
                    continue
                joiner = op_and if "all" in mods else op_or
                parts.append(val_parts[0] if len(val_parts) == 1 else "(" + joiner.join(val_parts) + ")")
            else:
                parts.append(format_fn(field, mods, v))
        if not parts:
            raise ValueError("Selection block map contains no valid criteria.")
        return parts[0] if len(parts) == 1 else "(" + op_and.join(parts) + ")"

    else:
        raise ValueError(f"Unsupported selection block data type: {type(block)}")


def _render_boolean_expression(
    cond: str,
    sub_queries: Dict[str, str],
    op_and: str = " AND ",
    op_or: str = " OR ",
    op_not: str = " NOT "
) -> str:
    """
    Renders condition expressions with isolated token replacements:
    - Supports quantifiers with wildcards: 'all of selection_*', '1 of selection_*', etc.
    - Supports 'all of them', '1 of them', 'any of them'.
    - Validates that every referenced identifier exists, raising clear errors instead of permissive fallbacks.
    - Never corrupts values containing boolean words ('and', 'or', 'not') or backslashes.
    """
    if not cond or not cond.strip():
        raise ValueError("Condition expression cannot be empty.")

    # Assign safe isolated tokens to each subquery
    token_map = {}
    rev_token_map = {}
    for i, (k, v) in enumerate(sub_queries.items()):
        tok = f"__SIGMA_SUBQ_{i}__"
        token_map[k.lower()] = (tok, v)
        rev_token_map[tok] = f"({v})"

    expr = cond.strip()

    # 1. Replace quantifiers with wildcards: e.g. 'all of selection_*', '1 of sel*'
    def rep_quant(m: re.Match) -> str:
        q = m.group(1).lower()
        pat = m.group(2)
        regex = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
        matched_keys = [k for k in sub_queries.keys() if re.match(regex, k, re.IGNORECASE)]
        if not matched_keys:
            raise ValueError(
                f"Quantifier pattern '{pat}' did not match any detection selections. "
                f"Available selections: {list(sub_queries.keys())}"
            )
        toks = [token_map[k.lower()][0] for k in matched_keys]
        if q.startswith("all"):
            return "(" + op_and.join(toks) + ")"
        else:
            return "(" + op_or.join(toks) + ")"

    expr = re.sub(
        r"\b(1\s+of|any\s+of|all\s+of)\s+([a-zA-Z0-9_*]+)(?=\b|\s|\)|$)",
        rep_quant,
        expr,
        flags=re.IGNORECASE
    )

    # 2. Replace 'all of them' / '1 of them' / 'any of them'
    if re.search(r"\b(1\s+of|any\s+of|all\s+of)\s+them\b", expr, flags=re.IGNORECASE):
        if not sub_queries:
            raise ValueError("Condition references 'them', but no detection selections are defined.")
        all_toks = [token_map[k.lower()][0] for k in sub_queries.keys()]
        expr = re.sub(r"\ball\s+of\s+them\b", "(" + op_and.join(all_toks) + ")", expr, flags=re.IGNORECASE)
        expr = re.sub(r"\b(1\s+of|any\s+of)\s+them\b", "(" + op_or.join(all_toks) + ")", expr, flags=re.IGNORECASE)

    # 3. Replace direct selection names with tokens
    for k in sorted(sub_queries.keys(), key=len, reverse=True):
        tok = token_map[k.lower()][0]
        expr = re.sub(rf"\b{re.escape(k)}\b", tok, expr, flags=re.IGNORECASE)

    # 4. Check for any unresolved identifiers in the condition (excluding keywords)
    remaining_words = re.findall(r"\b[a-zA-Z0-9_]+\b", expr)
    allowed_keywords = {"and", "or", "not", "true", "false", "1", "of", "them"}
    for word in remaining_words:
        if word.startswith("__SIGMA_SUBQ_") or word.lower() in allowed_keywords:
            continue
        raise ValueError(
            f"Undefined selection identifier '{word}' referenced in condition. "
            f"Defined selections: {list(sub_queries.keys())}"
        )

    # 5. Replace boolean operators with target operators
    expr = re.sub(r"\band\b", op_and, expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bor\b", op_or, expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bnot\b", op_not, expr, flags=re.IGNORECASE)

    # 6. Re-expand tokens to subquery strings safely
    for tok, subq in rev_token_map.items():
        expr = expr.replace(tok, subq)

    return expr


# 1. SPLUNK (SPL)
def _convert_to_splunk(
    raw_yaml: str,
    detection: Dict[str, Any],
    condition: str,
    logsource: Dict[str, Any],
    pipeline: Optional[str] = None
) -> str:
    """
    Converts a Sigma rule to Splunk SPL using the official pySigma framework
    and pySigma-backend-splunk with proper pipeline mappings.
    """
    if PYSIGMA_AVAILABLE:
        try:
            norm_yaml = _normalize_yaml_for_pysigma(raw_yaml)
            collection = SigmaCollection.from_yaml(norm_yaml)
            proc_pipeline = _select_splunk_pipeline(pipeline, logsource)
            backend = SplunkBackend(processing_pipeline=proc_pipeline)
            queries = backend.convert(collection)
            if not queries:
                raise SigmaError("pySigma Splunk backend produced no queries for this rule.")
            return "\n".join(q.strip() for q in queries if q.strip())
        except (SigmaError, ValueError, yaml.YAMLError) as e:
            # Propagate real rule and syntax errors without generating permissive queries
            raise
        except Exception:
            # Fallback to internal AST compiler if pySigma encountered an unexpected environment issue
            pass

    return _fallback_convert_to_splunk(detection, condition, logsource)


def _fallback_convert_to_splunk(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, _splunk_val, op_and=" AND ", op_or=" OR ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" AND ", op_or=" OR ", op_not=" NOT ")
    return rendered_cond


def _splunk_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val).replace('"', '\\"')
    if "contains" in mods:
        return f'{field}="*{val_str}*"'
    elif "startswith" in mods:
        return f'{field}="{val_str}*"'
    elif "endswith" in mods:
        return f'{field}="*{val_str}"'
    elif "re" in mods:
        return f'{field}=/{val_str}/'
    else:
        return f'{field}="{val_str}"'


# 2. MICROSOFT SENTINEL / DEFENDER (KQL)
def _convert_to_sentinel(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    category = logsource.get("category", "")
    table = "DeviceEvents"
    if category == "process_creation":
        table = "DeviceProcessEvents"
    elif category == "network_connection":
        table = "DeviceNetworkEvents"
    elif category == "file_event":
        table = "DeviceFileEvents"
    elif category == "registry_event":
        table = "DeviceRegistryEvents"

    field_map = {
        "Image": "FileName",
        "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessFileName",
        "ParentCommandLine": "InitiatingProcessCommandLine",
        "User": "AccountName",
        "DestinationIp": "RemoteIP",
        "DestinationPort": "RemotePort",
        "TargetFilename": "FileName"
    }

    def fmt_kql(field: str, mods: List[str], val: Any) -> str:
        mapped = field_map.get(field, field)
        return _kql_val(mapped, mods, val)

    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, fmt_kql, op_and=" and ", op_or=" or ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" and ", op_or=" or ", op_not=" not ")
    return f"{table}\n| where {rendered_cond}\n| project Timestamp, DeviceName, ActionType, {table == 'DeviceProcessEvents' and 'FileName, ProcessCommandLine' or 'AccountName'}"


def _kql_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val).replace('"', '\\"')
    if "contains" in mods:
        return f'{field} has "{val_str}"'
    elif "startswith" in mods:
        return f'{field} startswith "{val_str}"'
    elif "endswith" in mods:
        return f'{field} endswith "{val_str}"'
    elif "re" in mods:
        return f'{field} matches regex "{val_str}"'
    else:
        return f'{field} =~ "{val_str}"'


def _convert_to_defender(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    category = logsource.get("category", "")
    table = "DeviceProcessEvents"
    if category == "network_connection":
        table = "DeviceNetworkEvents"
    elif category == "file_event":
        table = "DeviceFileEvents"
    elif category == "registry_event":
        table = "DeviceRegistryEvents"

    field_map = {
        "Image": "FileName",
        "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessFileName",
        "ParentCommandLine": "InitiatingProcessCommandLine",
        "User": "AccountName",
        "DestinationIp": "RemoteIP",
        "DestinationPort": "RemotePort",
        "TargetFilename": "FileName"
    }

    def fmt_defender_kql(field: str, mods: List[str], val: Any) -> str:
        mapped = field_map.get(field, field)
        return _kql_val(mapped, mods, val)

    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, fmt_defender_kql, op_and=" and ", op_or=" or ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" and ", op_or=" or ", op_not=" not ")
    return f"{table}\n| where {rendered_cond}\n| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine"



# 3. ELASTICSEARCH KQL
def _convert_to_elastic_kql(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, _elastic_kql_val, op_and=" and ", op_or=" or ")

    return _render_boolean_expression(condition, sub_queries, op_and=" and ", op_or=" or ", op_not=" not ")


def _elastic_kql_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val).replace('"', '\\"')
    if "contains" in mods:
        return f'{field}: *"{val_str}"*'
    elif "startswith" in mods:
        return f'{field}: "{val_str}"*'
    elif "endswith" in mods:
        return f'{field}: *"{val_str}"'
    else:
        return f'{field}: "{val_str}"'


# 4. ELASTIC LUCENE
def _convert_to_elastic_lucene(raw_yaml: str, detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    if PYSIGMA_AVAILABLE:
        try:
            norm_yaml = _normalize_yaml_for_pysigma(raw_yaml)
            collection = SigmaCollection.from_yaml(norm_yaml)
            backend = LuceneBackend()
            results = backend.convert(collection)
            if results:
                return "\n".join(r.strip() for r in results if r.strip())
        except (SigmaError, ValueError, yaml.YAMLError):
            raise
        except Exception:
            pass

    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, _lucene_val, op_and=" AND ", op_or=" OR ")

    return _render_boolean_expression(condition, sub_queries, op_and=" AND ", op_or=" OR ", op_not=" NOT ")


def _lucene_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val).replace('"', '\\"')
    if "contains" in mods:
        return f'{field}:*{val_str}*'
    elif "startswith" in mods:
        return f'{field}:{val_str}*'
    elif "endswith" in mods:
        return f'{field}:*{val_str}'
    else:
        return f'{field}:"{val_str}"'


# 5. IBM QRADAR (AQL)
def _convert_to_qradar(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, _aql_val, op_and=" AND ", op_or=" OR ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" AND ", op_or=" OR ", op_not=" NOT ")
    return f"SELECT QIDNAME(qid) as 'Event Name', sourceip, destinationip, username, UTF8(payload) as 'Payload'\nFROM events\nWHERE {rendered_cond}\nLAST 24 HOURS"


def _aql_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val).replace("'", "''")
    if "contains" in mods:
        return f"\"{field}\" ILIKE '%{val_str}%'"
    elif "startswith" in mods:
        return f"\"{field}\" ILIKE '{val_str}%'"
    elif "endswith" in mods:
        return f"\"{field}\" ILIKE '%{val_str}'"
    else:
        return f"\"{field}\" = '{val_str}'"


# 6. CROWDSTRIKE FALCON LOGSCALE (LQL)
def _convert_to_crowdstrike(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    category = logsource.get("category", "")
    prefix = "#event_simpleName=ProcessRollup2 " if category == "process_creation" else ""

    def fmt_lql(field: str, mods: List[str], val: Any) -> str:
        cs_field = "ImageFileName" if field == "Image" else ("ParentBaseFileName" if field == "ParentImage" else field)
        return _lql_val(cs_field, mods, val)

    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, fmt_lql, op_and=" AND ", op_or=" OR ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" AND ", op_or=" OR ", op_not=" NOT ")
    return f"{prefix}{rendered_cond} | table([@timestamp, ComputerName, UserName, {prefix and 'CommandLine, ImageFileName' or 'aid'}])"


def _lql_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val)
    if "contains" in mods:
        return f'{field}=/{re.escape(val_str)}/i'
    elif "startswith" in mods:
        return f'{field}=/^{re.escape(val_str)}/i'
    elif "endswith" in mods:
        return f'{field}=/{re.escape(val_str)}$/i'
    elif "re" in mods:
        return f'{field}=/{val_str}/i'
    else:
        return f'{field}=?="{val_str}"'


# 7. GOOGLE CHRONICLE (YARA-L)
def _convert_to_chronicle(rule: Dict[str, Any], detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", rule.get("title", "SigmaRule"))

    def fmt_chronicle(field: str, mods: List[str], val: Any) -> str:
        udm_field = "$e.target.process.command_line" if field == "CommandLine" else (
            "$e.target.process.file.full_path" if field == "Image" else f"$e.principal.user.userid" if field == "User" else f"$e.target.{field.lower()}"
        )
        return _chronicle_val(udm_field, mods, val)

    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, fmt_chronicle, op_and=" and ", op_or=" or ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" and ", op_or=" or ", op_not=" not ")
    return f"""rule {rule_name} {{
  meta:
    description = "{rule.get('description', '')}"
    severity = "{rule.get('level', 'Medium').upper()}"
    author = "{rule.get('author', 'MANTIS')}"
  events:
    {rendered_cond}
  condition:
    $e
}}"""


def _chronicle_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val)
    if "contains" in mods:
        return f'{field} = /.*{re.escape(val_str)}.*/ nocase'
    elif "startswith" in mods:
        return f'{field} = /^{re.escape(val_str)}.*/ nocase'
    elif "endswith" in mods:
        return f'{field} = /.*{re.escape(val_str)}$/ nocase'
    else:
        return f'{field} = "{val_str}" nocase'


# 8. OPENSEARCH DSL
def _convert_to_opensearch(raw_yaml: str, detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    if PYSIGMA_AVAILABLE:
        try:
            norm_yaml = _normalize_yaml_for_pysigma(raw_yaml)
            collection = SigmaCollection.from_yaml(norm_yaml)
            backend = OpensearchLuceneBackend()
            results = backend.convert(collection)
            if results:
                lucene = results[0]
                escaped_lucene = lucene.replace('"', '\\"')
                return f"""{{
  "query": {{
    "query_string": {{
      "query": "{escaped_lucene}",
      "analyze_wildcard": true
    }}
  }},
  "size": 50,
  "sort": [
    {{ "@timestamp": {{ "order": "desc" }} }}
  ]
}}"""
        except (SigmaError, ValueError, yaml.YAMLError):
            raise
        except Exception:
            pass

    lucene = _convert_to_elastic_lucene(raw_yaml, detection, condition, logsource)
    escaped_lucene = lucene.replace('"', '\\"')
    return f"""{{
  "query": {{
    "query_string": {{
      "query": "{escaped_lucene}",
      "analyze_wildcard": true
    }}
  }},
  "size": 50,
  "sort": [
    {{ "@timestamp": {{ "order": "desc" }} }}
  ]
}}"""


# 9. SQL (Snowflake / DuckDB / Postgres)
def _convert_to_sql(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    table = "security_events"
    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, _sql_val, op_and=" AND ", op_or=" OR ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" AND ", op_or=" OR ", op_not=" NOT ")
    return f"SELECT event_time, host_name, user_name, event_id, image, command_line\nFROM {table}\nWHERE {rendered_cond}\nORDER BY event_time DESC\nLIMIT 100;"


def _sql_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val).replace("'", "''")
    if "contains" in mods:
        return f"LOWER({field}) LIKE '%{val_str.lower()}%'"
    elif "startswith" in mods:
        return f"LOWER({field}) LIKE '{val_str.lower()}%'"
    elif "endswith" in mods:
        return f"LOWER({field}) LIKE '%{val_str.lower()}'"
    else:
        return f"LOWER({field}) = '{val_str.lower()}'"


def _convert_to_sumologic(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    category = logsource.get("category", "")
    src_filter = "_sourceCategory=*windows*" if "windows" in str(logsource).lower() else "_sourceCategory=*"

    def fmt_sumo(field: str, mods: List[str], val: Any) -> str:
        val_str = str(val).replace('"', '\\"')
        if "contains" in mods:
            return f'{field} matches "*{val_str}*"'
        elif "startswith" in mods:
            return f'{field} matches "{val_str}*"'
        elif "endswith" in mods:
            return f'{field} matches "*{val_str}"'
        else:
            return f'{field} = "{val_str}"'

    sub_queries = {}
    fields_used = set()
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        def collector(fld: str, mods: List[str], val: Any) -> str:
            fields_used.add(fld)
            return fmt_sumo(fld, mods, val)
        sub_queries[name] = _compile_selection_block(block, collector, op_and=" and ", op_or=" or ")

    fields_json = ', '.join(f'"{f}"' for f in sorted(fields_used)) if fields_used else '"EventID", "Image", "CommandLine"'
    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" and ", op_or=" or ", op_not=" not ")
    return f'{src_filter} | json {fields_json} nodrop\n| where {rendered_cond}'



# 10. POWERSHELL (Get-WinEvent)
def _convert_to_powershell(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    sub_queries = {}
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue
        sub_queries[name] = _compile_selection_block(block, _ps_val, op_and=" -and ", op_or=" -or ")

    rendered_cond = _render_boolean_expression(condition, sub_queries, op_and=" -and ", op_or=" -or ", op_not=" -not ")
    return f"""# Query Windows Event Logs with PowerShell
Get-WinEvent -FilterHashtable @{{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 }} -MaxEvents 500 |
    Where-Object {{
        $msg = $_.Message
        {rendered_cond}
    }} | Select-Object TimeCreated, Id, RecordId, @{{n='Message';e={{$_.Message.Substring(0,[Math]::Min(120,$_.Message.Length))}}}}"""


def _ps_val(field: str, mods: List[str], val: Any) -> str:
    val_str = str(val).replace("'", "''")
    if "contains" in mods:
        return f"$msg -match '{re.escape(val_str)}'"
    elif "startswith" in mods:
        return f"$msg -match '^{re.escape(val_str)}'"
    elif "endswith" in mods:
        return f"$msg -match '{re.escape(val_str)}$'"
    else:
        return f"$msg -match '{re.escape(val_str)}'"


# 11. SYSMON XML EVENTFILTER
def _convert_to_sysmon_xml(detection: Dict[str, Any], condition: str, logsource: Dict[str, Any]) -> str:
    category = logsource.get("category", "process_creation")
    tag = "ProcessCreate" if category == "process_creation" else (
        "NetworkConnect" if category == "network_connection" else (
            "FileCreate" if category == "file_event" else "RuleGroup"
        )
    )

    items_xml = []
    for name, block in detection.items():
        if name == "condition" or name.startswith("_"):
            continue

        def add_xml_item(fld: str, mods: List[str], val: Any):
            cond_attr = "contains" if "contains" in mods else (
                "end with" if "endswith" in mods else (
                    "begin with" if "startswith" in mods else (
                        "contains any" if isinstance(val, list) else "is"
                    )
                )
            )
            val_text = ";".join(str(v) for v in val) if isinstance(val, list) else str(val)
            val_text = val_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            items_xml.append(f'      <{fld} condition="{cond_attr}">{val_text}</{fld}>')
            return ""

        _compile_selection_block(block, add_xml_item, op_and=" AND ", op_or=" OR ")

    return f"""<Sysmon schemaversion="4.90">
  <EventFiltering>
    <{tag} onmatch="include">
{chr(10).join(items_xml)}
    </{tag}>
  </EventFiltering>
</Sysmon>"""
