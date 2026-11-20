"""Native SIEM/EDR query conversion shared by Query Converter and Hunting Library."""

from __future__ import annotations
import difflib
import json
import logging
import re
from typing import Any, Dict, Optional
try:
    from backend.ai_service import AIProvider, AIProviderError, _settings_raw as get_raw_ai_settings, _settings_available
except ImportError:
    from ai_service import AIProvider, AIProviderError, _settings_raw as get_raw_ai_settings, _settings_available

logger = logging.getLogger("mantis.native_query_converter")
JSON_OUTPUT_MIN_TOKENS = 10000
JSON_OUTPUT_TIMEOUT_SECONDS = 180

HUNTING_PLATFORMS: Dict[str, Dict[str, Any]] = {
    "splunk": {
        "id": "splunk",
        "name": "Splunk",
        "language": "SPL",
        "icon": "fa-magnifying-glass",
        "default_telemetry": "index=* (EventCode=1 OR EventCode=4688)",
        "fields": {
            "process_name": "Image",
            "command_line": "CommandLine",
            "parent_process": "ParentImage",
            "parent_command_line": "ParentCommandLine",
            "user": "User",
            "hash": "SHA256",
            "dest_ip": "DestinationIp",
            "dest_port": "DestinationPort",
            "domain": "QueryName",
            "registry_path": "TargetObject"
        },
        "syntax_guidance": (
            "Splunk Search Processing Language (SPL). Use index/sourcetype, wildcards (*), "
            "IN operator for multi-value match: `CommandLine IN (\"*arg1*\", \"*arg2*\")`, "
            "eval, stats, and table for context output."
        ),
        "example_hunting": 'index=* (EventCode=1 OR EventCode=4688)\n| search Image="*\\powershell.exe" CommandLine IN ("*-enc*", "*-encodedcommand*", "*Invoke-Expression*")\n| stats count min(_time) as first_seen max(_time) as last_seen values(CommandLine) as commands by Computer, User, ParentImage\n| sort - count',
        "example_detection": 'index=* (EventCode=1 OR EventCode=4688) Image="*\\powershell.exe" CommandLine IN ("*-enc*", "*-encodedcommand*") ParentImage!="*\\explorer.exe"'
    },
    "sentinel": {
        "id": "sentinel",
        "name": "Microsoft Sentinel",
        "language": "KQL",
        "icon": "fa-shield-halved",
        "default_telemetry": "DeviceProcessEvents or SecurityEvent",
        "fields": {
            "process_name": "FolderPath",
            "command_line": "ProcessCommandLine",
            "parent_process": "InitiatingProcessFolderPath",
            "parent_command_line": "InitiatingProcessCommandLine",
            "user": "AccountName",
            "hash": "SHA256",
            "dest_ip": "RemoteIP",
            "dest_port": "RemotePort",
            "domain": "RemoteUrl",
            "registry_path": "RegistryKey"
        },
        "syntax_guidance": (
            "Kusto Query Language for Sentinel. Table-first: `DeviceProcessEvents | where ...`. "
            "Use operators `has` (word match), `has_any`, `contains`, `startswith`, `endswith`, `=~` (case-insensitive equal), `in~`. "
            "Project relevant contextual fields."
        ),
        "example_hunting": 'DeviceProcessEvents\n| where (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")\n  and ProcessCommandLine has_any ("-enc", "-encodedcommand", "downloadstring", "iex")\n| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), CommandSamples=make_set(ProcessCommandLine, 5) by DeviceName, AccountName, InitiatingProcessFileName\n| order by FirstSeen desc',
        "example_detection": 'DeviceProcessEvents\n| where FolderPath endswith "\\powershell.exe" and ProcessCommandLine has_any ("-enc", "-encodedcommand")\n| where InitiatingProcessFileName !in~ ("sensu-agent.exe", "scom.exe")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine'
    },
    "defender": {
        "id": "defender",
        "name": "Microsoft Defender XDR",
        "language": "Advanced Hunting KQL",
        "icon": "fa-shield-virus",
        "default_telemetry": "DeviceProcessEvents",
        "fields": {
            "process_name": "FileName",
            "command_line": "ProcessCommandLine",
            "parent_process": "InitiatingProcessFileName",
            "parent_command_line": "InitiatingProcessCommandLine",
            "user": "AccountName",
            "hash": "SHA256",
            "dest_ip": "RemoteIP",
            "dest_port": "RemotePort",
            "domain": "RemoteUrl"
        },
        "syntax_guidance": (
            "Microsoft Defender Advanced Hunting KQL schema. Tables: DeviceProcessEvents, DeviceNetworkEvents, "
            "DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents. Use `FileName =~ ...` or `in~ (...)`."
        ),
        "example_hunting": 'DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "invoke-webrequest")\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName',
        "example_detection": 'DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("-enc", "-encodedcommand")\n| where InitiatingProcessFileName !in~ ("code.exe", "devenv.exe")'
    },
    "elastic_kql": {
        "id": "elastic_kql",
        "name": "Elastic Security",
        "language": "KQL",
        "icon": "fa-cube",
        "default_telemetry": "Elastic Common Schema (ECS)",
        "fields": {
            "process_name": "process.executable",
            "command_line": "process.command_line",
            "parent_process": "process.parent.executable",
            "user": "user.name",
            "hash": "process.hash.sha256",
            "dest_ip": "destination.ip",
            "dest_port": "destination.port",
            "domain": "dns.question.name",
            "registry_path": "registry.path"
        },
        "syntax_guidance": (
            "Kibana Query Language (KQL) using Elastic Common Schema (ECS). "
            "Syntax: `field : \"value\"` or wildcard `field : *pattern*`. Boolean operators: `and`, `or`, `not` with parenthesized groupings."
        ),
        "example_hunting": 'process.executable : (*powershell.exe or *pwsh.exe) and process.command_line : (*-enc* or *-encodedcommand* or *downloadstring*)',
        "example_detection": 'process.executable : (*powershell.exe or *pwsh.exe) and process.command_line : (*-enc* or *-encodedcommand*) and not process.parent.name : "monitoring_agent.exe"'
    },
    "elastic_eql": {
        "id": "elastic_eql",
        "name": "Elasticsearch",
        "language": "EQL",
        "icon": "fa-diagram-project",
        "default_telemetry": "logs-* with ECS",
        "fields": {
            "process_name": "process.name",
            "command_line": "process.command_line",
            "parent_process": "process.parent.name",
            "user": "user.name"
        },
        "syntax_guidance": (
            "Event Query Language (EQL). Format: `<category> where <condition>`. "
            "Supports sequence matching: `sequence by <entity> [category where ...] [category where ...] with maxspan=5m`. "
            "Use wildcard `string == \"*pattern*\"`."
        ),
        "example_hunting": 'process where process.name in ("powershell.exe", "pwsh.exe") and process.command_line == "* -enc *"',
        "example_detection": 'sequence by host.id with maxspan=10m\n  [process where process.name in ("powershell.exe", "pwsh.exe") and process.command_line == "* -enc *"]\n  [network where destination.port in (80, 443, 8080)]'
    },
    "elastic_ppl": {
        "id": "elastic_ppl",
        "name": "Elastic / OpenSearch",
        "language": "PPL",
        "icon": "fa-code-branch",
        "default_telemetry": "source = windows_events",
        "fields": {
            "process_name": "process_name",
            "command_line": "command_line",
            "parent_process": "parent_process_name",
            "user": "user_name"
        },
        "syntax_guidance": (
            "Piped Processing Language (PPL) for OpenSearch / Elasticsearch. "
            "Syntax: `source = <index> | where <condition> | stats count() by <field> | sort - count()`."
        ),
        "example_hunting": "source = logs-endpoint | where process_name in ('powershell.exe', 'pwsh.exe') and (command_line like '%-enc%' or command_line like '%-encodedcommand%') | stats count() as freq by host_name, user_name, command_line | sort - freq",
        "example_detection": "source = logs-endpoint | where process_name in ('powershell.exe', 'pwsh.exe') and (command_line like '%-enc%' or command_line like '%-encodedcommand%') and not parent_process_name = 'management_agent.exe'"
    },
    "elastic_dsl": {
        "id": "elastic_dsl",
        "name": "Elasticsearch",
        "language": "Query DSL",
        "icon": "fa-code",
        "default_telemetry": "indices logs-*",
        "fields": {
            "process_name": "process.executable",
            "command_line": "process.command_line"
        },
        "syntax_guidance": (
            "JSON Query DSL for Elasticsearch clusters. Uses bool with must, filter, should, wildcard, match_phrase."
        ),
        "example_hunting": json.dumps({
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"process.executable": "*powershell.exe"}},
                        {
                            "bool": {
                                "should": [
                                    {"wildcard": {"process.command_line": "*-enc*"}},
                                    {"wildcard": {"process.command_line": "*-encodedcommand*"}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            }
        }, indent=2),
        "example_detection": json.dumps({
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"event.code": 4688}}
                    ],
                    "must": [
                        {"wildcard": {"process.executable": "*powershell.exe"}},
                        {"wildcard": {"process.command_line": "*-enc*"}}
                    ]
                }
            }
        }, indent=2)
    },
    "crowdstrike": {
        "id": "crowdstrike",
        "name": "CrowdStrike LogScale",
        "language": "CQL",
        "icon": "fa-bolt",
        "default_telemetry": "#event_simpleName=ProcessRollup2",
        "fields": {
            "process_name": "ImageFileName",
            "command_line": "CommandLine",
            "parent_process": "ParentBaseFileName",
            "user": "UserName",
            "hash": "SHA256HashData"
        },
        "syntax_guidance": (
            "CrowdStrike Falcon LogScale (formerly Humio) CQL. Start with event type filter: "
            "`#event_simpleName=ProcessRollup2`. Use regex `=/pattern/i` or `test()`."
        ),
        "example_hunting": '#event_simpleName=ProcessRollup2 ImageFileName=/powershell(\\.exe)?$/i CommandLine=/( -enc| -encodedcommand)/i\n| groupBy([aid, ComputerName, UserName, ParentBaseFileName], function=([count(), collect(CommandLine)]))\n| sort(field="_count", order=desc)',
        "example_detection": '#event_simpleName=ProcessRollup2 ImageFileName=/powershell(\\.exe)?$/i CommandLine=/( -enc| -encodedcommand)/i ParentBaseFileName!=/monitoring_agent\\.exe/i'
    },
    "crowdstrike_aes": {
        "id": "crowdstrike_aes",
        "name": "CrowdStrike Falcon AES",
        "language": "Advanced Event Search CQL",
        "icon": "fa-network-wired",
        "default_telemetry": "event_simpleName=ProcessRollup2",
        "fields": {
            "process_name": "ImageFileName",
            "command_line": "CommandLine",
            "parent_process": "ParentBaseFileName",
            "user": "UserName"
        },
        "syntax_guidance": (
            "CrowdStrike Falcon Advanced Event Search (AES). Uses `event_simpleName=ProcessRollup2` "
            "with field matching and pipe aggregations."
        ),
        "example_hunting": 'event_simpleName=ProcessRollup2 ImageFileName=/powershell(\\.exe)?$/i CommandLine=/( -enc| -encodedcommand)/i\n| stats count() by ComputerName, UserName, ParentBaseFileName, CommandLine',
        "example_detection": 'event_simpleName=ProcessRollup2 ImageFileName=/powershell(\\.exe)?$/i CommandLine=/( -enc| -encodedcommand)/i\n| where ParentBaseFileName !~ "monitoring_agent.exe"'
    },
    "qradar": {
        "id": "qradar",
        "name": "IBM QRadar",
        "language": "AQL",
        "icon": "fa-server",
        "default_telemetry": "events",
        "fields": {
            "process_name": '"Image"',
            "command_line": '"CommandLine"',
            "parent_process": '"ParentImage"',
            "user": '"UserName"',
            "event_id": '"EventID"'
        },
        "syntax_guidance": (
            "IBM QRadar Ariel Query Language (AQL). Format: `SELECT ... FROM events WHERE ...`. "
            "Custom properties in double quotes, strings in single quotes with `ILIKE`, time window `START '...'`."
        ),
        "example_hunting": 'SELECT UTF8(payload) as payload, "Image", "CommandLine", "UserName", sourceip, destinationip FROM events WHERE "Image" ILIKE \'%\\powershell.exe\' AND ("CommandLine" ILIKE \'%-enc%\' OR "CommandLine" ILIKE \'%-encodedcommand%\') START \'2026-01-01 00:00:00\'',
        "example_detection": 'SELECT UTF8(payload) as payload, "Image", "CommandLine" FROM events WHERE "EventID" = 4688 AND "Image" ILIKE \'%\\powershell.exe\' AND "CommandLine" ILIKE \'%-enc%\''
    },
    "sentinelone_dv": {
        "id": "sentinelone_dv",
        "name": "SentinelOne Deep Visibility",
        "language": "PowerQuery",
        "icon": "fa-eye",
        "default_telemetry": "Deep Visibility Events",
        "fields": {
            "process_name": "TgtProcName",
            "command_line": "TgtProcCmdLine",
            "parent_process": "SrcProcName",
            "parent_command_line": "SrcProcCmdLine",
            "user": "TgtProcUser"
        },
        "syntax_guidance": (
            "SentinelOne Deep Visibility PowerQuery. Field syntax: `EventType = 'Process Creation' AND TgtProcName in ('powershell.exe', 'pwsh.exe')`. "
            "String operators: `contains`, `in`, `matches`, `startsWith`, `endsWith`."
        ),
        "example_hunting": "EventType = 'Process Creation' AND TgtProcName in ('powershell.exe', 'pwsh.exe') AND (TgtProcCmdLine contains '-enc' OR TgtProcCmdLine contains '-encodedcommand')\n| columns EndpointName, TgtProcUser, SrcProcName, TgtProcCmdLine",
        "example_detection": "EventType = 'Process Creation' AND TgtProcName in ('powershell.exe', 'pwsh.exe') AND (TgtProcCmdLine contains '-enc' OR TgtProcCmdLine contains '-encodedcommand') AND SrcProcName != 's1_management.exe'"
    },
    "sentinelone_star": {
        "id": "sentinelone_star",
        "name": "SentinelOne STAR",
        "language": "STAR Rules & PowerQuery",
        "icon": "fa-star",
        "default_telemetry": "SentinelOne STAR Real-Time Engine",
        "fields": {
            "process_name": "TgtProcName",
            "command_line": "TgtProcCmdLine",
            "parent_process": "SrcProcName"
        },
        "syntax_guidance": (
            "SentinelOne Storyline Active Response (STAR). Uses Deep Visibility query syntax along with STAR rule configuration: "
            "Severity, Scope, Expiration, and Action (Alert / Kill / Quarantine)."
        ),
        "example_hunting": "// STAR Hunting Query Template\n// Severity: High | Action: Alert\nEventType = 'Process Creation' AND TgtProcName in ('powershell.exe', 'pwsh.exe') AND (TgtProcCmdLine contains '-enc' OR TgtProcCmdLine contains '-encodedcommand')",
        "example_detection": "// SentinelOne STAR Custom Detection Rule\n// Name: Suspicious Encoded PowerShell Execution\n// Severity: Medium | Mitigation: Alert Only\nEventType = 'Process Creation' AND TgtProcName in ('powershell.exe', 'pwsh.exe') AND (TgtProcCmdLine contains '-enc' OR TgtProcCmdLine contains '-encodedcommand') AND SrcProcName not in ('powershell_ise.exe')"
    },
    "secops": {
        "id": "secops",
        "name": "Google SecOps / Chronicle",
        "language": "YARA-L 2.0 Search Query",
        "icon": "fa-shield",
        "default_telemetry": "UDM Events ($e)",
        "fields": {
            "process_name": "$e.target.process.file.full_path",
            "command_line": "$e.target.process.command_line",
            "parent_process": "$e.src.process.file.full_path",
            "user": "$e.principal.user.userid"
        },
        "syntax_guidance": (
            "Google Security Operations (Chronicle) YARA-L 2.0 search query syntax. "
            "UDM event predicates: `$e.metadata.event_type = \"PROCESS_LAUNCH\"`, `re.regex($e.target.process.command_line, `.*-enc.*` nocase)`."
        ),
        "example_hunting": '$e.metadata.event_type = "PROCESS_LAUNCH"\nand re.regex($e.target.process.file.full_path, `.*\\\\(powershell|pwsh)\\.exe$` nocase)\nand re.regex($e.target.process.command_line, `.*-(enc|encodedcommand).*` nocase)',
        "example_detection": 'rule suspicious_encoded_powershell {\n  meta:\n    description = "Detects encoded PowerShell commands"\n    severity = "MEDIUM"\n  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n    re.regex($e.target.process.file.full_path, `.*\\\\powershell\\.exe$` nocase)\n    re.regex($e.target.process.command_line, `.*-enc.*` nocase)\n  condition:\n    $e\n}'
    },
    "sumologic": {
        "id": "sumologic",
        "name": "Sumo Logic",
        "language": "Search Query Language",
        "icon": "fa-chart-pie",
        "default_telemetry": "_sourceCategory=*windows*",
        "fields": {
            "process_name": "Image",
            "command_line": "CommandLine",
            "parent_process": "ParentImage",
            "user": "User"
        },
        "syntax_guidance": (
            "Sumo Logic Search Query. Starts with `_sourceCategory=*`, JSON or regex field extraction, "
            "and `| where <field> matches \"*pattern*\"`."
        ),
        "example_hunting": '_sourceCategory=*windows* | json "Image", "CommandLine", "ParentImage" nodrop\n| where (Image matches "*\\powershell.exe" or Image matches "*\\pwsh.exe") and (CommandLine matches "*-enc*" or CommandLine matches "*-encodedcommand*")\n| count by Image, CommandLine, ParentImage\n| sort by _count desc',
        "example_detection": '_sourceCategory=*windows* | json "Image", "CommandLine", "ParentImage" nodrop\n| where Image matches "*\\powershell.exe" and CommandLine matches "*-enc*" and !(ParentImage matches "*\\monitoring.exe")'
    },
    "cloudwatch": {
        "id": "cloudwatch",
        "name": "AWS CloudWatch Logs Insights",
        "language": "Logs Insights QL",
        "icon": "fa-aws",
        "default_telemetry": "CloudWatch Log Groups (/aws/ec2, /aws/lambda, CloudTrail)",
        "fields": {
            "process_name": "processName",
            "command_line": "commandLine",
            "user": "userIdentity.userName",
            "event_name": "eventName"
        },
        "syntax_guidance": (
            "AWS CloudWatch Logs Insights query syntax. Structure: "
            "`fields @timestamp, @message | filter <condition> | sort @timestamp desc | limit 100`."
        ),
        "example_hunting": "fields @timestamp, @message\n| filter @message like /powershell/ and (@message like /-enc/ or @message like /-encodedcommand/)\n| sort @timestamp desc\n| limit 100",
        "example_detection": "fields @timestamp, eventName, userIdentity.arn, sourceIPAddress\n| filter eventSource = 'ec2.amazonaws.com' and eventName in ['StopInstances', 'TerminateInstances', 'DeleteSecurityGroup']\n| sort @timestamp desc\n| limit 50"
    }
}


# ---------------------------------------------------------------------------

SYSTEM_PROMPT_IMPROVE = """You are an expert Query Optimization and Detection Engineering AI.
Your role is to refine, optimize, adapt, or fix SIEM/EDR threat hunting queries while strictly maintaining the core hunting objective.

IMPROVEMENT ACTIONS:
- 'optimize': Reduce query resource consumption, improve index/filtering order, add efficient time/table boundaries.
- 'reduce_fp': Add realistic enterprise exclusion clauses and thresholds to minimize false positive noise.
- 'expand_coverage': Incorporate synonymous attacker cmdlets, obfuscation variations, or broader process trees.
- 'add_context': Enrich output with contextual fields, timestamps, parent processes, user IDs, and pivot aggregations.
- 'fix_syntax': Correct syntax errors, unbalanced parentheses/quotes, invalid operators, or field names.
- 'convert_language': Re-architect the query logic into a different target SIEM/EDR language.

Respond ONLY with valid JSON matching the requested schema.
"""

def improve_query(
    query_text: str,
    action: str,  # 'optimize', 'reduce_fp', 'expand_coverage', 'add_context', 'fix_syntax', 'convert_language'
    platform: str,
    target_platform: Optional[str] = None,
    notes: str = "",
    custom_schema: Optional[Dict[str, Any]] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes Stage 4: Refines or adapts an existing query, computes unified diff,
    and returns improved query text with explanation.
    """
    current_spec = HUNTING_PLATFORMS.get(platform.lower(), HUNTING_PLATFORMS["splunk"])
    dest_spec = HUNTING_PLATFORMS.get((target_platform or platform).lower(), current_spec)

    settings = get_raw_ai_settings()
    if provider:
        settings["provider"] = provider
    if model:
        settings["model"] = model
    settings["max_output_tokens"] = max(int(settings.get("max_output_tokens") or 0), JSON_OUTPUT_MIN_TOKENS)
    settings["timeout_seconds"] = max(int(settings.get("timeout_seconds") or 0), JSON_OUTPUT_TIMEOUT_SECONDS)

    if not _settings_available(settings):
        raise AIProviderError(f"AI Provider '{settings.get('provider')}' is not configured.")

    user_prompt = f"""Improve the following query.

Source Platform: {current_spec['name']} ({current_spec['language']})
Destination Platform: {dest_spec['name']} ({dest_spec['language']})
Requested Action: {action.upper()}
Analyst Notes / Guidance: {notes or 'Apply best practice improvement.'}

CURRENT QUERY:
```
{query_text}
```

Destination Platform Syntax Guidance:
{dest_spec['syntax_guidance']}

OUTPUT SCHEMA:
Respond with a single JSON object:
{{
  "action": "{action}",
  "destination_platform": "{dest_spec['id']}",
  "destination_language": "{dest_spec['language']}",
  "revised_query": "The complete improved query string",
  "explanation": "Detailed explanation of what was changed and why",
  "changes_summary": ["List of specific optimizations or modifications made"]
}}
"""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_IMPROVE},
        {"role": "user", "content": user_prompt}
    ]

    try:
        ai = AIProvider(settings)
        raw = ai.generate(messages)
        parsed = _extract_json_object(raw)
        if not parsed or not isinstance(parsed, dict) or "revised_query" not in parsed:
            # Fallback
            clean_q = raw.strip()
            if "```" in clean_q:
                m = re.search(r"```(?:\w+)?\s*([\s\S]*?)\s*```", clean_q)
                if m:
                    clean_q = m.group(1).strip()
            revised_query = clean_q
            explanation = "Query revised based on analyst guidance."
            changes = ["Applied requested modifications."]
        else:
            revised_query = parsed.get("revised_query", "").strip()
            explanation = parsed.get("explanation", "")
            changes = parsed.get("changes_summary", [])

        # Compute diff
        diff_lines = list(difflib.unified_diff(
            query_text.splitlines(),
            revised_query.splitlines(),
            fromfile=f"Original ({current_spec['name']})",
            tofile=f"Revised ({dest_spec['name']})",
            lineterm=""
        ))
        diff_text = "\n".join(diff_lines)

        return {
            "action": action,
            "platform": dest_spec["id"],
            "query_language": dest_spec["language"],
            "original_query": query_text,
            "revised_query": revised_query,
            "diff": diff_text,
            "explanation": explanation,
            "changes_summary": changes
        }
    except Exception as e:
        logger.error(f"Error improving query: {e}")
        raise


# ---------------------------------------------------------------------------

def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    cleaned = text.strip()
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Try markdown code block ```json ... ```
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except Exception:
            pass

    # Try finding outermost { ... }
    s = cleaned.find("{")
    e = cleaned.rfind("}")
    if s != -1 and e != -1 and e > s:
        try:
            return json.loads(cleaned[s:e + 1])
        except Exception:
            pass

    return None
