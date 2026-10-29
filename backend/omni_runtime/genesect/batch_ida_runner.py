# -*- coding: utf-8 -*-
"""Unattended IDAPython entry point used by ``genesector.exe``.

The Rust application owns discovery, queuing, configuration, and process
lifecycle.  This module runs inside IDA, where the existing Genesect analysis
code and IDA APIs are available.  It deliberately reuses the same workers,
prompts, parsers, validation, IDB markers, and workspace exporter as the
interactive plugin.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
import urllib.request
from pathlib import Path


EVENT_PREFIX = "GENESECT_EVENT "


def emit(kind, message, **fields):
    payload = {"kind": str(kind), "message": str(message)}
    payload.update(fields)
    line = EVENT_PREFIX + json.dumps(payload, ensure_ascii=False, sort_keys=True)
    print(line, flush=True)


def load_args():
    if len(sys.argv) < 2:
        raise RuntimeError("Genesect batch runner did not receive a job JSON path.")
    args_path = Path(sys.argv[-1])
    if not args_path.is_file():
        raise RuntimeError("Genesect batch job JSON does not exist: %s" % args_path)
    return json.loads(args_path.read_text(encoding="utf-8"))


def configure_provider(job, config):
    profile = dict(job.get("profile") or {})
    provider = str(profile.get("provider") or "OpenAI")
    model = str(profile.get("model") or "").strip()
    api_key = str(profile.get("api_key") or "")
    api_url = str(profile.get("api_url") or "").strip()
    executable = str(profile.get("executable") or "").strip()
    config.active_provider = provider

    mapping = {
        "OpenAI": ("openai_key", "openai_url", "openai_model"),
        "Anthropic": ("anthropic_key", "anthropic_url", "anthropic_model"),
        "DeepSeek": ("deepseek_key", "deepseek_url", "deepseek_model"),
        "Ollama": (None, "ollama_host", "ollama_model"),
        "LMStudio": ("lmstudio_key", "lmstudio_url", "lmstudio_model"),
        "OpenAICompatible": ("custom_key", "custom_url", "custom_model"),
        "ChatGPTAccount": (None, None, "chatgpt_account_model"),
        "ClaudeCode": ("claude_code_path", None, "claude_code_model"),
        "AntigravityCLI": ("antigravity_cli_path", None, "antigravity_cli_model"),
        "OpenCode": ("opencode_path", None, "opencode_model"),
    }
    key_attr, url_attr, model_attr = mapping.get(provider, mapping["OpenAICompatible"])
    if key_attr:
        setattr(config, key_attr, executable if provider in ("ClaudeCode", "AntigravityCLI", "OpenCode") else api_key)
    if url_attr and api_url:
        setattr(config, url_attr, api_url)
    if model:
        setattr(config, model_attr, model)

    # The existing bulk workers consume this compact legacy mapping.  A
    # provider-aware adapter below handles account/CLI providers.
    worker_provider = {
        "OpenAI": "openai",
        "Anthropic": "anthropic",
        "DeepSeek": "deepseek",
        "Ollama": "ollama",
        "LMStudio": "lmstudio",
    }.get(provider, "custom")
    return {
        "provider": worker_provider,
        "profile_name": provider,
        "api_url": api_url,
        "api_key": api_key,
        "model": model,
        "batch_size": max(1, int(job.get("batch_size", 5))),
        "parallel_workers": 1,
        "cooldown_seconds": max(0, int(job.get("cooldown_seconds", 0))),
        "asm_max_lines": max(1, int(job.get("asm_max_lines", 25))),
        "force_bulk_rename": True,
        "var_force_rename": True,
        "use_custom_prompt": False,
        "custom_prompt": "",
        "rename_cache_enabled": bool(job.get("rename_cache_enabled", getattr(config, "rename_cache_enabled", True))),
        "rename_cache_path": str(job.get("rename_cache_path") or getattr(config, "rename_cache_path", "")),
    }


def _responses_text(payload):
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    parts = []
    for item in payload.get("output") or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content") or []:
            if not isinstance(content, dict):
                continue
            text = content.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts).strip()


def install_provider_adapter(config, worker_cfg, renamer, var_renamer):
    original_request = renamer.ai_request
    profile_name = worker_cfg.get("profile_name", "OpenAI")

    def request(cfg, prompt, sys_prompt, logger=None, on_chunk=None,
                on_cooldown=None, max_tokens=None, cancel_checker=None, **kwargs):
        del on_cooldown, kwargs
        if cancel_checker and cancel_checker():
            return ""
        if logger:
            logger("Provider request: %s / %s" % (profile_name, worker_cfg.get("model") or "default"))

        if profile_name == "ChatGPTAccount":
            from genesect import chatgpt_oauth
            token = chatgpt_oauth.get_access_token()
            body = {
                "model": worker_cfg.get("model"),
                "instructions": sys_prompt,
                "input": [{"role": "user", "content": prompt}],
                "store": False,
                "max_output_tokens": int(max_tokens or 1024),
            }
            http_request = urllib.request.Request(
                "https://api.openai.com/v1/responses",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Authorization": "Bearer %s" % token,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(http_request, timeout=180) as response:
                result = _responses_text(json.loads(response.read().decode("utf-8")))
        elif profile_name in ("ClaudeCode", "AntigravityCLI", "OpenCode"):
            from genesect.ai_client import SimpleAI
            client = SimpleAI(config)
            result = client._query_signed_in_cli([
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": prompt},
            ])
        else:
            result = original_request(
                cfg, prompt, sys_prompt, logger=logger, on_chunk=None,
                max_tokens=max_tokens, cancel_checker=cancel_checker,
            )
        result = str(result or "").strip()
        if on_chunk and result:
            on_chunk(result)
        return result

    renamer.ai_request = request
    var_renamer.ai_request = request


def collect_sub_functions(renamer):
    import idautils
    import idc

    result = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if name.startswith("sub_") and renamer.is_valid_seg(ea):
            result.append((int(ea), name))
    return result


def configure_raw_shellcode(job):
    """Apply the architecture metadata missing from a raw byte stream."""
    if job.get("sample_kind") != "shellcode":
        return

    import ida_auto
    import ida_funcs
    import ida_ida
    import ida_idaapi
    import ida_segment
    import idaapi

    arch = str(job.get("shellcode_arch") or "x64").lower()
    if arch not in ("x86", "x64"):
        raise RuntimeError("Unsupported raw shellcode architecture: %s" % arch)
    bits = 64 if arch == "x64" else 32
    segment_bitness = 2 if bits == 64 else 1

    try:
        ida_ida.inf_set_app_bitness(bits)
    except (AttributeError, TypeError):
        # Compatibility with IDA releases exposing the information structure.
        idaapi.get_inf_structure().set_app_bitness(bits)

    segment = ida_segment.get_first_seg()
    first_ea = ida_idaapi.BADADDR
    last_ea = ida_idaapi.BADADDR
    while segment:
        ida_segment.set_segm_addressing(segment, segment_bitness)
        if first_ea == ida_idaapi.BADADDR:
            first_ea = int(segment.start_ea)
        last_ea = int(segment.end_ea)
        segment = ida_segment.get_next_seg(segment.start_ea)

    if first_ea == ida_idaapi.BADADDR:
        raise RuntimeError("IDA's binary loader did not create a segment for the shellcode")

    # Raw blobs have no entry-point table. Seed a function at the first byte so
    # Genesect has a sub_* root to analyze and IDA can follow reachable code.
    ida_funcs.add_func(first_ea, ida_idaapi.BADADDR)
    if last_ea != ida_idaapi.BADADDR:
        ida_auto.plan_range(first_ea, last_ea)
    emit(
        "stage",
        "Configured raw %s shellcode at 0x%X" % (arch, first_ea),
        stage="shellcode",
    )


def all_existing_names():
    import idautils
    import idc

    return {
        name for name in (idc.get_func_name(ea) for ea in idautils.Functions())
        if name and not name.startswith("sub_")
    }


def apply_function_name(ea, name):
    import idaapi
    import ida_hexrays
    import ida_name
    import idc
    from genesect.idb_storage import load_from_idb, save_to_idb

    original = load_from_idb(ea, tag=82)
    if not original:
        current = idc.get_func_name(ea)
        if current and not current.startswith("sub_"):
            save_to_idb(ea, current, tag=82)
    candidate = str(name)
    owner = idc.get_name_ea_simple(candidate)
    suffix = 1
    while owner != idaapi.BADADDR and owner != ea:
        candidate = "%s_%d" % (name, suffix)
        suffix += 1
        owner = idc.get_name_ea_simple(candidate)
    ok = ida_name.set_name(ea, candidate, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    if ok:
        save_to_idb(ea, "renamed_by_genesect", tag=83)
        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass
    return bool(ok), candidate


def run_function_rename(sub_functions, cfg, renamer):
    pending = {}
    for ea, name in sub_functions:
        pending[ea] = renamer.FuncData(ea, name)
    existing = all_existing_names()
    renamed = 0
    failed = 0
    round_index = 0

    while pending:
        round_index += 1
        ready = []
        for index, func in enumerate(list(pending.values())):
            func.name = __import__("idc").get_func_name(func.ea) or func.name
            func.code = renamer.get_code_fast(func.ea, 50000, asm_max=1000)
            func.strings = renamer.get_strings_fast(func.ea)
            func.calls = renamer.get_calls_fast(func.ea)
            func.sub_count = renamer.count_sub_calls(func.code, own_name=func.name)
            func.queue = "clear" if func.sub_count == 0 else "blocked"
            if func.queue == "clear":
                ready.append((index, func))

        if not ready:
            minimum = min(func.sub_count for func in pending.values())
            candidates = [func for func in pending.values() if func.sub_count == minimum]
            candidates.sort(key=lambda f: (len(f.strings or []), len(f.calls or [])), reverse=True)
            for index, func in enumerate(candidates[:30]):
                func.status = "Pending (Cycle Breaker - %d sub_* remaining)" % func.sub_count
                ready.append((index, func))
            emit("log", "Dependency cycle detected; promoting %d cycle breaker(s)." % len(ready))

        emit(
            "progress",
            "Function rename round %d: %d ready, %d remaining" % (round_index, len(ready), len(pending)),
            stage="functions",
            current=len(sub_functions) - len(pending),
            total=len(sub_functions),
        )
        results = []
        worker = renamer.AnalyzeWorker(
            cfg, ready, existing,
            renamer.DEFAULT_BATCH_PROMPT if cfg["batch_size"] > 1 else renamer.DEFAULT_PROMPT,
            cfg["batch_size"], is_retry=True,
        )
        worker.batch_done.connect(lambda batch: results.extend(batch))
        worker.log.connect(lambda message, level: emit("log", message, level=level))
        worker.update_status.connect(lambda message: emit("log", message) if message else None)
        worker.run()

        processed = set()
        for _index, func, suggestion, score in results:
            processed.add(func.ea)
            if suggestion and suggestion not in ("DEFERRED", "DEFERRED_LOW_SCORE"):
                ok, final_name = apply_function_name(func.ea, suggestion)
                if ok:
                    renamed += 1
                    existing.add(final_name)
                    emit("log", "%s -> %s (%s)" % (func.name, final_name, score or "unscored"), level="ok")
                else:
                    failed += 1
                    emit("log", "IDA rejected function name %s at 0x%X" % (suggestion, func.ea), level="error")
            else:
                failed += 1
                emit("log", "No function rename produced for 0x%X" % func.ea, level="warning")

        # A worker emits one terminal result per item.  Guard against provider
        # or Qt failures so an unattended job cannot loop forever.
        for _index, func in ready:
            if func.ea not in processed:
                failed += 1
                emit("log", "Function worker produced no result for 0x%X" % func.ea, level="error")
            pending.pop(func.ea, None)

    return {"candidates": len(sub_functions), "renamed": renamed, "failed": failed}


def run_variable_rename(sub_functions, cfg, var_renamer):
    import idc

    items = []
    for index, (ea, original_name) in enumerate(sub_functions):
        items.append((index, var_renamer.FuncData(ea, idc.get_func_name(ea) or original_name)))
    results = []
    emit("progress", "Renaming variables in %d original sub_* function(s)" % len(items), stage="variables", current=0, total=len(items))
    worker = var_renamer.VarRenameWorker(cfg, items, is_retry=True)
    worker.batch_done.connect(lambda batch: results.extend(batch))
    worker.log.connect(lambda message, level: emit("log", message, level=level))
    worker.update_status.connect(lambda message: emit("log", message) if message else None)
    worker.run()

    functions_changed = 0
    variables_renamed = 0
    failed = 0
    for _index, func, suggestions in results:
        if not suggestions:
            continue
        applied, rejected, details = var_renamer.apply_var_renames(
            func.ea,
            suggestions,
            log_fn=lambda message, level="info": emit("log", message, level=level),
        )
        if applied:
            functions_changed += 1
        variables_renamed += applied
        failed += rejected
        emit(
            "log",
            "0x%X: %d variable(s) renamed, %d rejected" % (func.ea, applied, rejected),
            level="ok" if applied else "warning",
            details=details,
        )
    return {
        "candidates": len(items),
        "functions_changed": functions_changed,
        "variables_renamed": variables_renamed,
        "failed": failed,
    }


def run_autonomous_investigation(job, cfg, renamer):
    import idaapi
    import idc
    import idautils
    from genesect.agent_policy import AgentPolicy
    from genesect.agent_runtime import (
        AgentSession,
        build_system_prompt,
        normalize_tool_call,
        parse_agent_response,
    )
    from genesect.bridge_tools import AGENT_TOOL_CATALOG, execute_bridge_tool

    # 1. Determine entry point or primary target
    entry_ea = idaapi.get_entry(idaapi.get_entry_ordinal(0))
    if entry_ea != idaapi.BADADDR:
        func = idaapi.get_func(entry_ea)
        if func:
            entry_ea = int(func.start_ea)
    if entry_ea == idaapi.BADADDR:
        main_ea = idc.get_name_ea_simple("main")
        if main_ea != idaapi.BADADDR:
            entry_ea = int(main_ea)
    if entry_ea == idaapi.BADADDR:
        funcs = list(idautils.Functions())
        entry_ea = int(funcs[0]) if funcs else 0

    root_name = idc.get_func_name(entry_ea) or ("0x%X" % entry_ea if entry_ea else "unknown")
    max_turns = max(3, min(30, int(job.get("investigation_turns") or 10)))

    emit(
        "stage",
        "Autonomous Agentic Investigation (%d turns) on %s (0x%X)" % (max_turns, root_name, entry_ea),
        stage="investigation",
        total=max_turns,
    )
    emit(
        "log",
        "[Agent] Initializing autonomous investigation on %s at 0x%X (budget: %d turns)"
        % (root_name, entry_ea, max_turns),
    )

    policy = AgentPolicy(allow_mutations=False, max_steps=max_turns * 4, max_seconds=900)
    session = AgentSession(
        root_ea=entry_ea,
        function_name=root_name,
        mission="Perform evidence-driven autonomous malware reverse engineering and capability triage.",
    )
    sys_prompt = build_system_prompt(entry_ea, root_name, AGENT_TOOL_CATALOG)

    history = []
    initial_user_prompt = (
        "Begin autonomous reverse-engineering investigation. "
        "Root target function is %s at 0x%X. "
        "Investigate binary capabilities, key imports/strings, behavior, and record findings."
    ) % (root_name, entry_ea)
    history.append({"role": "user", "content": initial_user_prompt})

    final_report = ""
    turn_executed = 0

    for turn in range(1, max_turns + 1):
        turn_executed = turn
        emit(
            "progress",
            "Agent Turn %d/%d: Reasoning and tool planning" % (turn, max_turns),
            stage="investigation",
            current=turn,
            total=max_turns,
        )

        prompt_blocks = [
            "## Target Information",
            "Function: %s at 0x%X" % (root_name, entry_ea),
            "Current Turn: %d of %d\n" % (turn, max_turns),
            "## Session State Snapshot",
            session.snapshot(max_chars=12000),
            "\n## Recent Context",
        ]
        for item in history[-4:]:
            prompt_blocks.append("[%s]:\n%s" % (item["role"].upper(), item["content"]))

        if turn == max_turns:
            prompt_blocks.append(
                "\nCRITICAL: Maximum investigation turns reached (Turn %d/%d). "
                "Do not request more tools. Return action=final with a comprehensive executive dossier report in Markdown."
                % (turn, max_turns)
            )
        else:
            prompt_blocks.append(
                "\nDecide whether to query additional tools or finalize. "
                "Return exactly one JSON envelope with action='tools' or action='final'."
            )

        full_prompt = "\n".join(prompt_blocks)

        try:
            raw_response = renamer.ai_request(cfg, full_prompt, sys_prompt, max_tokens=4096)
        except Exception as exc:
            emit("log", "[Agent] Turn %d: Provider request failed: %s" % (turn, exc), level="error")
            break

        envelope, parse_err = parse_agent_response(raw_response)
        if parse_err or not envelope:
            emit("log", "[Agent] Turn %d: Parse warning: %s" % (turn, parse_err or "Invalid envelope"), level="warning")
            history.append({"role": "assistant", "content": raw_response})
            history.append({
                "role": "user",
                "content": "Protocol error: %s. Return a valid JSON envelope with action='tools' or action='final'." % parse_err,
            })
            continue

        if envelope["action"] == "final":
            final_report = envelope.get("report", "").strip()
            session.final_report = final_report
            emit("log", "[Agent] Turn %d: Completed with final report (%d chars)." % (turn, len(final_report)), level="ok")
            break

        calls = envelope.get("calls", [])
        emit("log", "[Agent] Turn %d: Requested %d tool call(s)" % (turn, len(calls)))
        session.begin_round()
        observations = []

        for call in calls:
            tool_name = str(call.get("tool") or "").strip()
            args = call.get("args") or {}
            normalized, val_err = normalize_tool_call(tool_name, args, entry_ea, AGENT_TOOL_CATALOG)
            if val_err:
                err_msg = "Error: " + val_err
                emit("log", "[Agent] Tool %s rejected: %s" % (tool_name, val_err), level="warning")
                session.record_result(tool_name, args, err_msg)
                session.record_observation(tool_name, args, err_msg)
                observations.append("[%s rejected: %s]" % (tool_name, val_err))
                continue

            t_name = normalized["tool"]
            t_args = normalized["args"]
            session.record_call(t_name, t_args)
            emit("log", "[Agent] Executing: %s(%s)" % (t_name, json.dumps(t_args, ensure_ascii=False)))

            if t_name == "record_finding":
                finding = session.add_finding(
                    t_args.get("claim", ""),
                    t_args.get("confidence", "low"),
                    t_args.get("evidence", []),
                    t_args.get("tags", []),
                )
                tool_res = "Recorded verified finding %s." % finding.finding_id
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)
                emit("log", "[Agent] Finding: %s [%s]" % (finding.claim[:100], finding.confidence), level="ok")
            elif t_name == "mark_examined":
                session.mark_examined(
                    t_args.get("ea", entry_ea),
                    t_args.get("disposition", "examined"),
                    t_args.get("summary", ""),
                )
                tool_res = "Marked address."
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)
            elif t_name == "record_function_analysis":
                session.remember_function(t_args.get("ea", entry_ea), t_args)
                tool_res = "Recorded function analysis."
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)
            else:
                tool_res = execute_bridge_tool(policy, t_name, t_args, address=entry_ea)
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)

            status_summary = tool_res[:160].replace("\n", " ").strip() if tool_res else "ok"
            emit("log", "[Agent] -> %s: %s" % (t_name, status_summary))
            observations.append(policy.untrusted_result(t_name, tool_res))

        history.append({"role": "assistant", "content": raw_response})
        history.append({
            "role": "user",
            "content": "Tool observation results:\n\n" + "\n\n".join(observations),
        })

    # If completed without final report, prompt for final synthesis
    if not final_report:
        emit("progress", "Synthesizing executive investigation dossier...", stage="investigation", current=max_turns, total=max_turns)
        synthesis_prompt = (
            "All investigation turns are complete. Based on all collected findings, observations, and evidence, "
            "produce a detailed Markdown Executive Investigation Dossier. "
            "Include:\n"
            "1. Executive Summary & Malware Triage\n"
            "2. Identified Capabilities & Behaviors\n"
            "3. Key Functions & Addresses Analyzed\n"
            "4. Concrete Indicators of Compromise (IOCs) / Strings\n"
            "5. Strategic Next Steps for Reverse Engineers.\n\n"
            "Return action=final."
        )
        try:
            synth_resp = renamer.ai_request(cfg, synthesis_prompt, sys_prompt, max_tokens=4096)
            env, _ = parse_agent_response(synth_resp)
            if env and env.get("action") == "final":
                final_report = env.get("report", "").strip()
            else:
                final_report = synth_resp.strip()
        except Exception as exc:
            final_report = "Autonomous investigation completed. (Error generating final summary: %s)" % exc

    session.final_report = final_report

    output_root = Path(job["result_path"]).resolve().parent
    output_root.mkdir(parents=True, exist_ok=True)
    dossier_path = output_root / "investigation_dossier.md"
    findings_path = output_root / "investigation_findings.json"

    dossier_lines = [
        "# Autonomous Agentic Investigation Dossier",
        "",
        "| Field | Value |",
        "|---|---|",
        "| **Sample** | `%s` |" % job.get("sample_path", ""),
        "| **Root Target** | `%s` (0x%X) |" % (root_name, entry_ea),
        "| **Turns Executed** | %d / %d |" % (turn_executed, max_turns),
        "| **Verified Findings** | %d |" % len(session.findings),
        "| **Timestamp** | %s |" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "## Executive Summary & Analysis",
        "",
        final_report,
        "",
        "## Verified Findings",
        "",
    ]
    if session.findings:
        for idx, f in enumerate(session.findings, 1):
            dossier_lines.append(f"### {idx}. {f.claim}")
            dossier_lines.append(f"- **Confidence**: `{f.confidence.upper()}`")
            if f.tags:
                dossier_lines.append(f"- **Tags**: {', '.join(f.tags)}")
            if f.evidence:
                dossier_lines.append("- **Evidence / Citations**:")
                for ev in f.evidence:
                    dossier_lines.append(f"  - `{ev}`")
            dossier_lines.append("")
    else:
        dossier_lines.append("_No discrete findings were explicitly tagged during the investigation._\n")

    dossier_lines.extend([
        "## Agent Execution Audit",
        "",
        "| Step | Tool | Category | Status |",
        "|---|---|---|---|",
    ])
    for idx, event in enumerate(policy.timeline, 1):
        status_badge = "Allowed" if event.allowed else "Blocked"
        dossier_lines.append(f"| {idx} | `{event.tool}` | {event.category} | {status_badge} |")
    dossier_lines.append("")

    dossier_text = "\n".join(dossier_lines)
    dossier_path.write_text(dossier_text, encoding="utf-8")
    findings_path.write_text(session.to_json(), encoding="utf-8")

    emit("log", "Investigation dossier saved to: %s" % dossier_path, level="ok")
    emit("log", "Structured findings saved to: %s" % findings_path, level="ok")

    return {
        "dossier_path": str(dossier_path),
        "findings_path": str(findings_path),
        "turns_executed": turn_executed,
        "max_turns": max_turns,
        "findings_count": len(session.findings),
        "root_ea": "0x%X" % entry_ea,
        "root_name": root_name,
    }


def main():
    job = load_args()
    repo_root = str(Path(job["genesect_root"]).resolve())
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    import ida_auto
    import ida_loader
    import ida_pro
    from genesect.config import CONFIG
    from genesect import renamer, var_renamer

    configure_raw_shellcode(job)
    emit("stage", "Waiting for IDA auto-analysis", stage="ida")
    ida_auto.auto_wait()
    cfg = configure_provider(job, CONFIG)
    install_provider_adapter(CONFIG, cfg, renamer, var_renamer)

    sub_functions = collect_sub_functions(renamer)
    emit("stage", "Found %d sub_* function(s)" % len(sub_functions), stage="scan", total=len(sub_functions))
    result = {
        "sample": job.get("sample_path"),
        "idb_path": job.get("idb_path"),
        "workspace_path": "",
        "function_rename": None,
        "variable_rename": None,
        "autonomous_investigation": None,
    }

    if job.get("rename_functions"):
        result["function_rename"] = run_function_rename(sub_functions, cfg, renamer)
    if job.get("rename_variables"):
        result["variable_rename"] = run_variable_rename(sub_functions, cfg, var_renamer)
    if job.get("autonomous_investigation"):
        result["autonomous_investigation"] = run_autonomous_investigation(job, cfg, renamer)

    if job.get("generate_workspace"):
        from genesect.ai_workspace_export import export_ai_workspace
        workspace_path = str(Path(job["workspace_path"]).resolve())
        emit("stage", "Exporting AI workspace", stage="workspace")
        export_result = export_ai_workspace(
            workspace_path,
            show_progress=False,
            progress_callback=lambda label, current, total: emit(
                "progress", label, stage="workspace", current=current, total=total
            ),
        )
        result["workspace_path"] = export_result["path"]
        result["workspace_counts"] = export_result["counts"]

    if job.get("analyze_workspace"):
        from genesect.workspace_analysis import analyze_workspace, get_active_profile_dict
        ws_path = result.get("workspace_path") or str(Path(job.get("workspace_path", "")).resolve())
        if ws_path and Path(ws_path).is_dir():
            emit("stage", "Analyzing exported AI workspace", stage="workspace_analysis")
            profile = job.get("profile") or get_active_profile_dict(CONFIG)
            try:
                ws_res = analyze_workspace(
                    ws_path,
                    profile,
                    log_fn=lambda m: emit("log", m),
                    report_dir=job.get("report_dir"),
                )
                result["workspace_analysis"] = ws_res
            except Exception as exc:
                emit("log", "Workspace analysis failed: %s" % exc, level="error")
                result["workspace_analysis"] = {"error": str(exc)}

    idb_path = str(Path(job["idb_path"]).resolve())
    Path(idb_path).parent.mkdir(parents=True, exist_ok=True)
    emit("stage", "Saving analyzed IDB", stage="save")
    if not ida_loader.save_database(idb_path, ida_loader.DBFL_COMP):
        raise RuntimeError("IDA could not save database to %s" % idb_path)

    result_path = Path(job["result_path"])
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    emit("complete", "Sample completed", result=result)
    ida_pro.qexit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        details = traceback.format_exc()
        emit("error", str(exc), traceback=details)
        try:
            args = load_args()
            failure_path = Path(args.get("failure_path") or "")
            if str(failure_path):
                failure_path.parent.mkdir(parents=True, exist_ok=True)
                failure_path.write_text(details, encoding="utf-8")
        except Exception:
            pass
        try:
            import ida_pro
            ida_pro.qexit(1)
        except Exception:
            raise
