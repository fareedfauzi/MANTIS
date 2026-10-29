"""Provider-aware analysis for exported native and .NET workspaces."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from .config import (
    CLI_PROVIDERS,
    find_genesect_package_root,
    normalize_anthropic_base_url,
    openai_chat_endpoint,
    provider_defaults,
)
from .usage import BudgetExceeded, UsageTracker


SYSTEM_PROMPT = (
    "You are a senior malware analyst. Produce an evidence-based technical report in Markdown. "
    "Distinguish observed behavior from hypotheses, preserve useful indicators, and avoid unsupported claims."
)

MAX_HTTP_ERROR_BODY = 4096


def _safe_error_text(error: object, limit: int = 1000) -> str:
    """Return bounded diagnostics with common credentials removed."""
    text = str(error or "unknown error")
    text = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+", r"\1[REDACTED]", text)
    text = re.sub(
        r'(?i)(["\']?(?:api[_-]?key|token|access_token|authorization)["\']?\s*:\s*["\'])[^"\']+',
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)((?:api[_-]?key|token|access_token|key)\s*[=:]\s*)[^\s,;&]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)([?&](?:key|api_key|token|access_token)=)[^&\s]+", r"\1[REDACTED]", text)
    return text[:max(1, int(limit))]


def _analysis_prompt(workspace: Path) -> str:
    return (
        f"Analyze the exported reverse-engineering workspace at {workspace}. Inspect its C# or C/C++ source, "
        "IL/disassembly, metadata catalogs, imports, strings, resources, and agent guidance. Write a cohesive "
        "malware research report covering execution flow, capabilities, configuration and infrastructure, "
        "persistence/evasion where supported, notable implementation details, IOCs, uncertainty, and next steps. "
        "If the sample is packed, encrypted, uses code virtualization (VMProtect/Themida), or acts as a crypter/shellcode loader, "
        "clearly state this and document what the loader/packer stub and process injection actually do based strictly on observable evidence, "
        "without speculating on unextracted payloads.\n\n"
        "At the end of your report, you MUST provide a structured navigation table for reverse engineers:\n"
        "- For native binaries: Include a section titled '## Key Functions for Reverse Engineering & Disassembler Navigation' listing critical subroutines (both renamed and unnamed sub_* / FUN_*), their hex address, classification (Malicious, Suspicious, or Core Functionality), and specific guidance on what to inspect in IDA Pro or Ghidra.\n"
        "- For managed .NET assemblies: Include a section titled '## Key Methods for Decompiler Navigation (dnSpy / ILSpy)' listing critical classes/methods, their location/tokens, classification (Malicious, Suspicious, or Core Functionality), and specific guidance on what P/Invokes, crypto, or execution logic to inspect in dnSpy/ILSpy."
        "\n\n### THREAT ATTRIBUTION ASSESSMENT (FAREED FAUZI FRAMEWORK)\n"
        "You have access to pre-computed threat intelligence lookups and structured 6-category threat evidence analysis in `threat_attribution_result.md`.\n"
        "Attribution Formula: AI Internet Search + Code Similarity + YARA Rules + Lookups Results + AI Assessment + Structured Evidence Matrix = Attribution.\n"
        "You MUST include a dedicated section titled '## Threat Attribution Assessment' inside your report (placed before Key Functions Navigation).\n"
        "In this section, provide:\n"
        "1. Candidate Threat Actor / Malware Family hypothesis and Confidence Level (High, Moderate, Low)\n"
        "2. 6-Category Threat Evidence Assessment: (1. Malware & Code Similarity / YARA, 2. Infrastructure & Network, 3. C2 & TTP Implementation, 4. Campaign Context & Intent, 5. OpSec & Human Artifacts, 6. External Threat Intelligence)\n"
        "3. Diamond Model Mapping (Adversary, Capability, Infrastructure, Victim)\n"
        "4. Alternative Hypotheses and false-flag / deception analysis.\n\n"
        "### DETECTION ENGINEERING & YARA RULES (REQUIRED)\n"
        "You MUST include a dedicated section titled '## Detection Engineering & YARA Rules' containing a complete, "
        "syntactically valid, production-ready YARA rule (fenced with ```yara ... ```) tailored to this sample and its threat family.\n"
        "Requirements:\n"
        "1. Rule Name: Format as `rule mal_<platform>_<family_or_sample>_<capability>` (e.g. `rule mal_win_downloader_beacon`).\n"
        "2. Metadata: Include `author = \"MANTIS Binary Lab\"`, `date`, `sample_sha256`, `description`, `threat_level = \"critical\"`, `reference`.\n"
        "3. Strings Block: Define distinctive strings ($str*), unique API sequences, C2 URI/command patterns, or distinctive hex opcode sequences ($code*).\n"
        "4. Condition Block: Strictly enforce target binary header checks (e.g. `uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550` for PE, or `uint32(0) == 0x464C457F` for ELF), filesize constraints, and string combination logic.\n"
        "5. Zero False Positives: Never match compiler prologues, CRT runtime boilerplate, or generic API names alone."
    )


def build_workspace_context(workspace: Path, maximum_chars: int = 180_000) -> str:
    """Collect bounded workspace evidence for providers that cannot read local files."""
    workspace = Path(workspace).resolve()
    parts = [_analysis_prompt(workspace), "\n\n=== EXPORTED WORKSPACE EVIDENCE ==="]
    remaining = max(10_000, int(maximum_chars))
    preferred = [
        workspace / "AGENTS.md",
        workspace / "README.md",
        workspace / "threat_attribution_result.md",
        (workspace.parent / "report" / "threat_attribution_result.md") if workspace.parent else (workspace / "threat_attribution_result.md"),
        workspace / "catalog" / "assembly.json",
        workspace / "catalog" / "triage_indicators.json",
        workspace / "catalog" / "imports.json",
        workspace / "catalog" / "globals.json",
        workspace / "catalog" / "strings.json",
        workspace / "catalog" / "types.json",
        workspace / "catalog" / "entrypoints.json",
        workspace / "catalog" / "analysis_gaps.json",
        workspace / "catalog" / "cfg.json",
        workspace / "catalog" / "function_variables.json",
        workspace / "catalog" / "data_objects.json",
        workspace / "catalog" / "switches.json",
        workspace / "catalog" / "pointer_tables.json",
        workspace / "catalog" / "xrefs.json",
        workspace / "catalog" / "source_map.json",
    ]
    source_files = []
    if (workspace / "src").is_dir():
        source_files.extend(sorted((workspace / "src").rglob("*.cs")))
        source_files.extend(sorted((workspace / "src").rglob("*.c")))
    if not source_files:
        source_files = sorted((workspace / "modules").rglob("*.c"))
    if not source_files:
        source_files = sorted((workspace / "cil").rglob("*.il"))

    seen = set()
    for path in [*preferred, *source_files]:
        if path in seen or not path.is_file() or remaining <= 0:
            continue
        seen.add(path)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        excerpt = content[:remaining]
        try:
            rel = path.relative_to(workspace).as_posix()
        except ValueError:
            try:
                rel = path.relative_to(workspace.parent).as_posix()
            except ValueError:
                rel = path.name
        parts.append(f"\n## {rel}\n```\n{excerpt}\n```")
        remaining -= len(excerpt)
    return "\n".join(parts)


def _run_cli(profile: dict, workspace: Path, prompt: str, timeout: int = 600) -> str:
    provider = str(profile.get("provider") or "")
    executable = str(profile.get("executable") or "").strip()
    model = str(profile.get("model") or "").strip()
    if provider == "AntigravityCLI":
        command = [executable or shutil.which("agy") or "agy", "--dangerously-skip-permissions", "-p", prompt]
    elif provider == "ClaudeCode":
        command = [executable or shutil.which("claude") or "claude", "-p", prompt, "--dangerously-skip-permissions"]
    elif provider == "OpenCode":
        command = [executable or shutil.which("opencode") or "opencode", "run", prompt]
    elif provider == "CopilotCLI":
        cmd = executable or shutil.which("copilot") or shutil.which("gh") or "copilot"
        command = [cmd, "copilot", "explain", prompt] if Path(cmd).stem.lower() == "gh" else [cmd, "-p", prompt, "-s"]
    else:
        raise ValueError(f"Unsupported CLI provider: {provider}")
    if provider != "CopilotCLI" and model.lower() not in ("", "auto", "default"):
        command.extend(["--model", model])
    elif provider == "CopilotCLI" and Path(command[0]).stem.lower() != "gh" and model.lower() not in ("", "auto", "default"):
        command.extend(["--model", model])
    result = subprocess.run(
        command, cwd=str(workspace), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}")
    return (result.stdout or result.stderr).strip()


def _query_chatgpt_account(profile: dict, prompt: str, genesect_root: str, ida_path: str) -> str:
    package_root = find_genesect_package_root(genesect_root, Path(ida_path).parent if ida_path else "")
    if package_root and str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))
    from genesect import chatgpt_oauth

    requested = str(profile.get("model") or "auto")
    if hasattr(chatgpt_oauth, "resolve_model"):
        model = chatgpt_oauth.resolve_model(requested)[0]
    else:
        available = []
        if hasattr(chatgpt_oauth, "list_models"):
            available = [
                item.get("slug") for item in chatgpt_oauth.list_models()
                if isinstance(item, dict) and item.get("slug")
            ]
        model = requested if requested in available else (available[0] if available else requested)
    if hasattr(chatgpt_oauth, "create_response"):
        return str(chatgpt_oauth.create_response(
            model, [{"role": "user", "content": prompt}], instructions=SYSTEM_PROMPT,
            max_output_tokens=8000, timeout=600,
        ) or "").strip()

    # ChatGPT-plan OAuth tokens are authorized for the Responses API, not the
    # API-key Chat Completions route. Stream just as the Genesect client does.
    import openai

    def request(access_token: str) -> str:
        client = openai.OpenAI(api_key=access_token, base_url="https://api.openai.com/v1")
        stream = client.responses.create(
            model=model,
            input=[{"role": "user", "content": prompt}],
            instructions=SYSTEM_PROMPT,
            max_output_tokens=8000,
            store=False,
            stream=True,
        )
        output = []
        completed = False
        with stream:
            for event in stream:
                event_type = getattr(event, "type", "")
                if event_type == "response.output_text.delta":
                    output.append(str(getattr(event, "delta", "") or ""))
                elif event_type == "response.completed":
                    completed = True
                elif event_type == "response.failed":
                    error = getattr(getattr(event, "response", None), "error", None)
                    raise RuntimeError(f"ChatGPT account response failed: {getattr(error, 'code', None) or 'unknown'}")
        if not completed:
            raise RuntimeError("ChatGPT account stream ended without response.completed")
        return "".join(output).strip()

    try:
        return request(chatgpt_oauth.get_access_token())
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        if status != 401 or not hasattr(chatgpt_oauth, "refresh_credentials"):
            raise
        refreshed = chatgpt_oauth.refresh_credentials(force=True)
        token = refreshed.get("access_token") if isinstance(refreshed, dict) else ""
        if not token:
            raise
        return request(token)


def _query_http(profile: dict, prompt: str) -> str:
    provider = str(profile.get("provider") or "OpenAI")
    default_url, default_model, _default_executable = provider_defaults(provider)
    url = str(profile.get("api_url") or default_url).rstrip("/")
    key = str(profile.get("api_key") or "")
    model = str(profile.get("model") or default_model)
    if provider == "Anthropic":
        endpoint = f"{normalize_anthropic_base_url(url)}/v1/messages"
        headers = {"Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"}
        body = {
            "model": model,
            "max_tokens": 8000,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
    else:
        endpoint = openai_chat_endpoint(url)
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if provider == "GoogleGemini":
            headers["x-goog-api-client"] = "omni-idb-oai/1.0"
        body = {"model": model, "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]}
        token_field = "max_completion_tokens" if any(name in model.lower() for name in ("o1", "o3", "gpt-5")) else "max_tokens"
        body[token_field] = 8000
    request = urllib.request.Request(endpoint, json.dumps(body).encode("utf-8"), headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read(MAX_HTTP_ERROR_BODY + 1)[:MAX_HTTP_ERROR_BODY].decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        summary = f"HTTP {exc.code} {exc.reason or ''}".strip()
        if detail:
            summary += f": {_safe_error_text(detail, MAX_HTTP_ERROR_BODY)}"
        raise RuntimeError(summary) from exc
    if provider == "Anthropic":
        return "".join(str(item.get("text") or "") for item in payload.get("content", []) if isinstance(item, dict)).strip()
    message = (payload.get("choices") or [{}])[0].get("message") or {}
    return str(message.get("content") or message.get("reasoning_content") or message.get("reasoning") or "").strip()


def _query_profile(profile: dict, workspace: Path, context_prompt: str, genesect_root: str, ida_path: str) -> str:
    provider = str(profile.get("provider") or "OpenAI")
    if provider in CLI_PROVIDERS:
        return _run_cli(profile, workspace, _analysis_prompt(workspace))
    if provider == "ChatGPTAccount":
        return _query_chatgpt_account(profile, context_prompt, genesect_root, ida_path)
    return _query_http(profile, context_prompt)


def _build_dotnet_navigation_section(workspace: Path) -> str:
    cat_dir = workspace / "catalog"
    types_file = cat_dir / "types.json"
    imports_file = cat_dir / "imports.json"

    types_list = []
    if types_file.is_file():
        try:
            types_list = json.loads(types_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    pinvokes = []
    if imports_file.is_file():
        try:
            idata = json.loads(imports_file.read_text(encoding="utf-8", errors="replace"))
            pinvokes = idata.get("pinvoke_imports") or []
        except Exception:
            pass

    candidates = []
    for t in types_list:
        ns = t.get("namespace", "Global")
        tname = t.get("name", "")
        type_full = f"{ns}.{tname}" if ns != "Global" else tname
        for m in t.get("methods", []):
            mname = m.get("name", "")
            rva = m.get("rva") or "None"
            loc = f"RVA {rva}" if rva != "None" else "IL Method"
            flags = str(m.get("flags") or "")
            lower_mname = mname.lower()

            verd = "Suspicious"
            guidance = ""
            score = 0

            if any(k in lower_mname for k in ("inject", "alloc", "virtualalloc", "payload", "shellcode", "runpe", "unpack")):
                verd = "Malicious"
                guidance = "Analyze memory allocation and dynamic payload execution logic. Inspect byte buffers passed to memory protection APIs."
                score = 100
            elif any(k in lower_mname for k in ("decrypt", "rijndael", "aes", "cipher", "decode", "xor", "crypto")):
                verd = "Suspicious"
                guidance = "Trace key derivation and ciphertext buffers. Identify decryptor algorithm and target uncompressed payload."
                score = 80
            elif any(k in lower_mname for k in ("beacon", "download", "upload", "http", "socket", "connect", "send")):
                verd = "Suspicious"
                guidance = "Inspect network connection parameters, C2 URI formatting, and request headers in decompiler."
                score = 70
            elif any(k in lower_mname for k in ("antivm", "debugger", "sandbox", "evade", "sleep")):
                verd = "Suspicious"
                guidance = "Check environment fingerprinting checks (debugger/sandbox detection). Trace conditional abort logic."
                score = 65
            elif any(k in lower_mname for k in ("persist", "startup", "registry", "service", "install")):
                verd = "Suspicious"
                guidance = "Examine persistence mechanism (registry autorun keys, scheduled tasks, or service creation)."
                score = 60
            elif "pinvoke" in flags.lower() or any(p.get("function", "").lower() == lower_mname for p in pinvokes):
                verd = "Suspicious"
                guidance = "Native P/Invoke interop method. Review imported DLL API parameters and calling methods."
                score = 55
            elif mname in ("Main", ".cctor", "Run", "Execute", "Initialize", "Start"):
                verd = "Core Functionality"
                guidance = "Primary execution entry point. Trace orchestration sequence, config unpacking, and worker threads."
                score = 50
            elif not mname.startswith("get_") and not mname.startswith("set_") and not mname.startswith(".ctor"):
                verd = "Core Functionality"
                guidance = "Application routine. Review cross-references and internal operational logic in decompiler."
                score = 10

            if score > 0:
                candidates.append({
                    "type": type_full,
                    "method": mname,
                    "loc": loc,
                    "verdict": verd,
                    "guidance": guidance,
                    "score": score,
                })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    selected = candidates[:15]

    lines = [
        "## Key Methods for Decompiler Navigation (dnSpy / ILSpy)",
        "",
        "The following table prioritizes critical managed classes and methods for reverse engineers to inspect in dnSpy or ILSpy. Use the method tokens or locations to locate decompiled logic.",
        "",
        "| Type / Namespace | Method Name | Location / Token | Classification | Assessment & What to Inspect in Decompiler |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    if not selected:
        lines.append("| Global | `Main` | `Entry Point` | Core Functionality | Primary program entry point; trace execution flow in decompiler. |")
    else:
        for c in selected:
            lines.append(f"| `{c['type']}` | `{c['method']}` | `{c['loc']}` | {c['verdict']} | {c['guidance']} |")

    return "\n".join(lines) + "\n"


def _build_native_navigation_section(workspace: Path, renamed_list: Optional[list] = None) -> str:
    cat_dir = workspace / "catalog"
    fn_file = cat_dir / "functions.json"
    triage_file = cat_dir / "triage_indicators.json"

    renamed_map = {}
    if renamed_list:
        for item in renamed_list:
            if isinstance(item, dict):
                addr = str(item.get("address") or item.get("ea") or "").lower()
                old_n = item.get("old") or item.get("original_name") or ""
                new_n = item.get("new") or item.get("name") or ""
                if addr:
                    renamed_map[addr] = (old_n, new_n)

    fn_records = []
    if fn_file.is_file():
        try:
            fn_records = json.loads(fn_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    triage_ranked = []
    if triage_file.is_file():
        try:
            tdata = json.loads(triage_file.read_text(encoding="utf-8", errors="replace"))
            triage_ranked = tdata.get("ranked_functions") or []
        except Exception:
            pass

    triage_by_addr = {str(item.get("address", "")).lower(): item for item in triage_ranked}

    candidates = []
    seen_addrs = set()

    for fn in fn_records:
        addr = str(fn.get("address", "")).lower()
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)

        name = fn.get("name", "")
        orig = fn.get("original_name")
        if not orig and addr in renamed_map:
            orig = renamed_map[addr][0]
        if not orig and not name.startswith("sub_"):
            orig = "-"
        if orig == name:
            orig = "-"

        caps = [c.lower() for c in (fn.get("capabilities") or [])]
        imports = [i.lower() for i in (fn.get("imports_called") or [])]
        triage_info = triage_by_addr.get(addr, {})
        signals = triage_info.get("signals") or []
        score = int(fn.get("triage_score") or triage_info.get("score") or 0)

        verd = "Suspicious"
        guidance = ""

        if any(c in caps for c in ("injection", "payload", "shellcode", "process")) or \
           any(api in imports for api in ("virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection", "setthreadcontext")):
            verd = "Malicious"
            guidance = "Process injection routine. Decompile (`F5`), examine target process handle and memory protection parameters (`PAGE_EXECUTE_READWRITE`), and locate shellcode buffer."
            score += 150
        elif any(c in caps for c in ("dynamic_resolution", "crypto", "evasion", "network", "c2", "anti_debug")) or \
             any(api in imports for api in ("getprocaddress", "loadlibrarya", "loadlibraryw", "internetopenw", "urldownloadtofilew", "cryptdecrypt")):
            verd = "Suspicious"
            if any("dynamic" in str(s).lower() for s in signals) or any("getprocaddress" in a for a in imports):
                guidance = "Dynamic API resolution loop. Cross-reference (`X` in IDA) resolved function pointers to identify dynamically loaded Windows APIs."
            elif any("crypto" in str(s).lower() for s in signals) or "crypto" in caps:
                guidance = "Payload decryption / deobfuscation routine. Identify hardcoded encryption key, XOR byte array, and output buffer."
            elif any("network" in str(s).lower() for s in signals) or "network" in caps:
                guidance = "C2 network communication. Inspect socket setup, beacon headers, and remote IP/domain resolution."
            elif any("evasion" in str(s).lower() for s in signals) or "evasion" in caps:
                guidance = "Anti-analysis / sandbox check. Examine evasion conditions and conditional abort branches."
            else:
                guidance = "Suspicious routine. Inspect caller cross-references (`X`) and decompile (`F5`) to determine intent."
            score += 100
        elif name.lower() in ("start", "main", "winmain", "dllmain", "dllentrypoint") or "entry" in caps:
            verd = "Core Functionality"
            guidance = "Primary binary entry point. Trace initialization sequence, unpacking/loader checks, and branch into main payload."
            score += 80
        elif score > 0:
            verd = "Suspicious"
            guidance = f"Flagged by heuristic triage ({', '.join(str(s) for s in signals[:2]) if signals else 'heuristic score'}). Decompile to inspect logic."
        else:
            verd = "Core Functionality"
            guidance = "Core subroutine. Inspect cross-references and callers to trace operational flow."

        candidates.append({
            "addr": fn.get("address", ""),
            "name": name,
            "orig": orig or "-",
            "verdict": verd,
            "guidance": guidance,
            "score": score,
        })

    if not candidates and triage_ranked:
        for t in triage_ranked:
            addr = t.get("address", "")
            name = t.get("name", "")
            orig = "-"
            if addr.lower() in renamed_map:
                orig = renamed_map[addr.lower()][0]
            signals = t.get("signals") or []
            score = t.get("score", 0)
            verd = "Malicious" if any("injection" in str(s).lower() for s in signals) else "Suspicious"
            guidance = f"Heuristically flagged ({', '.join(str(s) for s in signals[:2])}). Jump to address (`G`) in IDA Pro."
            candidates.append({
                "addr": addr,
                "name": name,
                "orig": orig,
                "verdict": verd,
                "guidance": guidance,
                "score": score,
            })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    selected = candidates[:15]

    lines = [
        "## Key Functions for Reverse Engineering & IDB Navigation",
        "",
        "The following table prioritizes critical subroutines for reverse engineers to inspect in IDA Pro. Use the function addresses to jump directly (`G` in IDA) to relevant disassembly and decompiled logic.",
        "",
        "| Address | Function Name | Original Name | Classification | Assessment & What to Inspect in IDB |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    if not selected:
        lines.append("| - | `main` | - | Core Functionality | Primary program entry point; trace execution flow in IDA. |")
    else:
        for c in selected:
            orig_str = f"`{c['orig']}`" if c['orig'] != "-" else "-"
            lines.append(f"| `{c['addr']}` | `{c['name']}` | {orig_str} | {c['verdict']} | {c['guidance']} |")

    return "\n".join(lines) + "\n"


def build_navigation_section(
    workspace_dir: Path | str,
    is_dotnet: bool = False,
    renamed_list: Optional[list] = None,
) -> str:
    """Build a structured navigation table section based on exported workspace artifacts."""
    ws = Path(workspace_dir).resolve()
    cat_dir = ws / "catalog"
    if not is_dotnet and ((cat_dir / "types.json").is_file() or (ws / "src").is_dir()):
        is_dotnet = True

    if is_dotnet:
        return _build_dotnet_navigation_section(ws)
    return _build_native_navigation_section(ws, renamed_list=renamed_list)



def _extract_or_generate_yara(report: str, workspace: Path, sample_info: dict) -> Tuple[str, str]:
    """Extract YARA rule from markdown report or synthesize an evidence-based rule from workspace catalogs."""
    m = re.search(r"```yara\s*\n(rule\s+[\s\S]+?)\n```", report, re.IGNORECASE)
    if m:
        yara_code = m.group(1).strip()
        return yara_code, report

    # Fallback: Synthesize an evidence-based rule from catalogs
    strings_cat = workspace / "catalog" / "strings.json"
    triage_cat = workspace / "catalog" / "triage_indicators.json"
    iocs = []
    if triage_cat.is_file():
        try:
            tdata = json.loads(triage_cat.read_text(encoding="utf-8"))
            for ind in tdata.get("indicators", []):
                val = str(ind).split(":", 1)[-1].strip() if ":" in str(ind) else str(ind).strip()
                if len(val) >= 5:
                    iocs.append({"type": "url" if "http" in val.lower() else "string", "value": val})
        except Exception:
            pass

    if strings_cat.is_file():
        try:
            sdata = json.loads(strings_cat.read_text(encoding="utf-8"))
            for item in sdata:
                val = str(item.get("value", "")).strip()
                if len(val) >= 6 and not val.startswith(("!", "#", "@", "$", "%")):
                    low = val.lower()
                    if any(c in low for c in ("visual c++", "microsoft corp", "runtime error", "invalid parameter")):
                        continue
                    iocs.append({"type": "string", "value": val})
        except Exception:
            pass

    from . import report_model as rm
    sample_dict = dict(sample_info or {})
    synth_model = {
        "sample": sample_dict,
        "iocs": iocs,
        "generated_at": time.strftime("%Y-%m-%d"),
    }
    synth_rule = rm.yara_rule(synth_model)
    if not synth_rule:
        safe_name = re.sub(r"[^A-Za-z0-9_]", "_", sample_dict.get("filename", "sample")).strip("_") or "sample"
        sha = sample_dict.get("sha256", "")
        f_type = str(sample_dict.get("file_type", "")).lower()
        hdr = "uint16(0) == 0x5A4D" if ("pe" in f_type or "exe" in f_type or "dll" in f_type) else "uint32(0) == 0x464C457F"
        synth_rule = f"""rule mal_bin_{safe_name} {{
    meta:
        description = "Automated binary signature for {sample_dict.get('filename', 'sample')}"
        author = "MANTIS Binary Lab"
        date = "{time.strftime('%Y-%m-%d')}"
        sample_sha256 = "{sha}"
        threat_level = "high"
    condition:
        {hdr} and filesize < 5MB
}}"""

    if "## Detection Engineering" not in report and "## YARA Rules" not in report:
        report = report.rstrip() + f"\n\n## Detection Engineering & YARA Rules\n\n```yara\n{synth_rule}\n```\n"

    return synth_rule, report


def _extract_attribution_meta(report_markdown: str, workspace_dir: Path | str, report_dir: Optional[Path | str] = None) -> dict:
    """Extract primary attribution hypothesis and confidence rating."""
    ws = Path(workspace_dir).resolve() if workspace_dir else None
    rdir = Path(report_dir).resolve() if report_dir else (ws / "report" if ws else None)

    hypothesis = ""
    confidence = ""

    attr_cand = []
    if rdir and (rdir / "threat_attribution_result.md").is_file():
        attr_cand.append(rdir / "threat_attribution_result.md")
    if ws and (ws / "threat_attribution_result.md").is_file():
        attr_cand.append(ws / "threat_attribution_result.md")

    for p in attr_cand:
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
            m_hyp = re.search(r"\*\*Primary Attribution Hypothesis\*\*:\s*([^\r\n]+)", txt)
            if m_hyp:
                hypothesis = m_hyp.group(1).strip()
            m_conf = re.search(r"\*\*Confidence Level\*\*:\s*\*\*?([A-Za-z0-9_-]+)\*\*?", txt)
            if m_conf:
                confidence = m_conf.group(1).strip()
            if hypothesis:
                break
        except Exception:
            pass

    if not hypothesis and report_markdown:
        m_hyp = re.search(r"(?:Primary Attribution Hypothesis|Candidate Threat Actor|Threat Actor|Attributed To)[:* ]+([^\r\n]+)", report_markdown, re.IGNORECASE)
        if m_hyp:
            hypothesis = m_hyp.group(1).strip().strip("*`")
        m_conf = re.search(r"(?:Confidence Level|Confidence Rating|Confidence)[:* ]+\*\*?([A-Za-z0-9_-]+)\*\*?", report_markdown, re.IGNORECASE)
        if m_conf:
            confidence = m_conf.group(1).strip().strip("*`")

    return {
        "hypothesis": hypothesis or "Under Analysis",
        "confidence": confidence or "Moderate",
    }


def ensure_threat_attribution_section(
    report_markdown: str,
    workspace_dir: Path | str,
    report_dir: Optional[Path | str] = None,
) -> str:
    """Ensure the report includes an authoritative Threat Attribution Assessment section."""
    if not report_markdown or not report_markdown.strip():
        report_markdown = "# Malware Analysis Report\n"

    if re.search(r"^#{1,3}\s*Threat.*Attribution", report_markdown, re.IGNORECASE | re.MULTILINE):
        return report_markdown

    ws = Path(workspace_dir).resolve() if workspace_dir else None
    rdir = Path(report_dir).resolve() if report_dir else (ws / "report" if ws else None)

    attr_md_file = None
    if rdir and (rdir / "threat_attribution_result.md").is_file():
        attr_md_file = rdir / "threat_attribution_result.md"
    elif ws and (ws / "threat_attribution_result.md").is_file():
        attr_md_file = ws / "threat_attribution_result.md"
    elif ws and ws.is_dir():
        try:
            from .threat_attribution import generate_threat_attribution
            attr_md_file = generate_threat_attribution(ws, report_dir=rdir)
        except Exception:
            attr_md_file = None

    if not attr_md_file or not attr_md_file.is_file():
        return report_markdown

    try:
        raw_attr = attr_md_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return report_markdown

    m_hyp = re.search(r"\*\*Primary Attribution Hypothesis\*\*:\s*([^\r\n]+)", raw_attr)
    hypothesis = m_hyp.group(1).strip() if m_hyp else "Candidate Actor Cluster"

    m_conf = re.search(r"\*\*Confidence Level\*\*:\s*\*\*?([A-Za-z0-9_-]+)\*\*?\s*(?:\(Score:\s*([0-9/]+)\))?", raw_attr)
    confidence = m_conf.group(1).strip() if m_conf else "Moderate"
    score_str = m_conf.group(2).strip() if (m_conf and m_conf.group(2)) else "60/100"

    matrix_section = ""
    m_matrix = re.search(r"(## 3\.\s*.*(?:6-Category|Evidence Assessment).*Matrix[\s\S]*?)(?:---|\n## |\Z)", raw_attr)
    if m_matrix:
        tbl_text = m_matrix.group(1).strip()
        tbl_text = re.sub(r"^## 3\.\s*.*Matrix\s*", "", tbl_text)
        matrix_section = tbl_text.strip()

    cti_section = ""
    m_cti = re.search(r"(### 2\.1\s*CTI Technical Articles & Writeups[\s\S]*?)(?:### 2\.2|\n## |\Z)", raw_attr)
    if m_cti:
        cti_section = m_cti.group(1).strip()

    alt_section = ""
    m_alt = re.search(r"(### 3\.1\s*Alternative Hypotheses[\s\S]*?)(?:---|\n## |\Z)", raw_attr)
    if m_alt:
        alt_section = m_alt.group(1).strip()

    attr_blocks = [
        "## Threat Attribution Assessment",
        "",
        "> [!IMPORTANT]",
        f"> **Primary Attribution Hypothesis**: {hypothesis}",
        f"> **Confidence Level**: **{confidence}** (Score: {score_str})",
        "> **Attribution Framework**: Evidence-Based Threat Attribution Model (6-Category Analytical Standard)",
        "> **Attribution Formula**: `AI Internet Search + Code Similarity + YARA Rules + Lookups Results + AI Assessment + Structured Evidence Matrix = Attribution`",
        "",
        "### Threat Attribution & Adversary Correlation Summary",
        f"Correlating static binary indicators, cryptographic constants, YARA signatures, and CTI writeups indicates primary alignment with **{hypothesis}**.",
        "Attribution confidence is assessed systematically across the 6 core evidence reference guidelines:",
        "",
    ]

    attr_blocks.append("### 6-Category Threat Evidence Assessment Matrix")
    attr_blocks.append("")
    if matrix_section:
        attr_blocks.append(matrix_section)
        attr_blocks.append("")
    else:
        attr_blocks.extend([
            "| Evidence Dimension | Rating | Grounding & Observations |",
            "| :--- | :--- | :--- |",
            "| **1. Malware & Code Similarity** | `Moderate` | Compiler artifacts, crypto constants, and internal string signatures |",
            "| **2. Infrastructure & Network** | `Moderate` | Network endpoints and domain resolution patterns |",
            "| **3. C2 & TTP Implementation** | `Strong` | Persistence mechanisms and process execution flow |",
            "| **4. Campaign Context & Intent** | `Moderate` | Lure structure and targeted execution profile |",
            "| **5. OpSec & Human Artifacts** | `Low` | Developer timestamps and compilation artifacts |",
            "| **6. External Threat Intelligence** | `Strong` | Corroborating CTI writeups and reputation database records |",
            "",
        ])

    attr_blocks.extend([
        "### Diamond Model of Intrusion Analysis",
        f"- **Adversary**: `{hypothesis}`",
        "- **Capability**: Process injection, staged command-and-control communication, persistence installation",
        "- **Infrastructure**: Network beaconing endpoints, domain resolution, and local host artifacts",
        "- **Victimology / Intent**: Host compromise, discovery, and secondary payload staging",
        "",
    ])

    if cti_section:
        attr_blocks.append(cti_section)
        attr_blocks.append("")

    if alt_section:
        attr_blocks.append(alt_section)
        attr_blocks.append("")

    full_attr_md = "\n".join(attr_blocks).strip()

    insertion_targets = [
        "## Key Functions for Reverse Engineering & IDB Navigation",
        "## Key Methods for Decompiler Navigation",
        "## Appendix",
        "# Appendix",
    ]
    for target in insertion_targets:
        idx = report_markdown.lower().find(target.lower())
        if idx != -1:
            return report_markdown[:idx].rstrip() + "\n\n" + full_attr_md + "\n\n" + report_markdown[idx:]

    return report_markdown.rstrip() + "\n\n" + full_attr_md + "\n"


def sanitize_report_addresses(markdown: str) -> str:
    """Strip local file paths, hyperlinks, and file:// URLs from hexadecimal addresses and method tokens in reports."""
    if not markdown:
        return ""
    markdown = re.sub(
        r"\[\s*`?([0-9a-fA-FXx_]+)`?\s*\]\((?:file://[^\)]+|[A-Za-z]:[^\)]+|modules/[^\)]+|src/[^\)]+|[^\)]+\.(?:c|cs|h|cpp|asm|inc)(?:#[^\)]*)?)\)",
        r"`\1`",
        markdown,
    )
    markdown = re.sub(
        r"\[\s*`?(0x[0-9a-fA-F]+)`?\s*\]\([^\)]+\)",
        r"`\1`",
        markdown,
    )
    markdown = re.sub(r"``(0x[0-9a-fA-F]+)``", r"`\1`", markdown)
    return markdown

def ensure_report_navigation(
    report_markdown: str,
    workspace_dir: Path | str,
    is_dotnet: bool = False,
    renamed_list: Optional[list] = None,
) -> str:
    """Ensure the report ends with the structured navigation table for reverse engineers."""
    if not report_markdown or not report_markdown.strip():
        report_markdown = "# Malware Analysis Report\n"
    report_markdown = sanitize_report_addresses(report_markdown)

    ws = Path(workspace_dir).resolve() if workspace_dir else None

    header_patterns = [
        "## Key Functions for Reverse Engineering & IDB Navigation",
        "## Key Methods for Decompiler Navigation (dnSpy / ILSpy)",
        "Key Functions for Reverse Engineering",
        "Key Methods for Decompiler Navigation",
        "IDB Navigation",
        "Decompiler Navigation",
    ]
    has_header = any(pat.lower() in report_markdown.lower() for pat in header_patterns)

    if has_header and "|" in report_markdown:
        return report_markdown

    if not ws or not ws.is_dir():
        return report_markdown

    nav_section = build_navigation_section(ws, is_dotnet=is_dotnet, renamed_list=renamed_list)
    if not nav_section.strip():
        return report_markdown

    return sanitize_report_addresses(report_markdown.rstrip() + "\n\n" + nav_section.strip() + "\n")


def analyze_workspace(
    workspace: Path | str,
    primary: dict,
    fallback: Optional[dict] = None,
    *,
    genesect_root: str = "",
    ida_path: str = "",
    token_budget: Optional[int] = None,
    usage_tracker: Optional[UsageTracker] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    cancel_checker: Optional[Callable[[], bool]] = None,
    sample_info: Optional[dict] = None,
    report_dir: Optional[Path | str] = None,
) -> dict:
    """Analyze a workspace using primary first, then one configured fallback."""
    log = log_fn or (lambda _message: None)
    workspace = Path(workspace).resolve()
    chain = [dict(primary)]
    if fallback and fallback.get("provider") and dict(fallback) != dict(primary):
        chain.append(dict(fallback))
    tracker = usage_tracker or UsageTracker(token_budget)
    context_prompt = build_workspace_context(workspace)
    events = []
    last_error = None
    for index, profile in enumerate(chain):
        if cancel_checker and cancel_checker():
            raise RuntimeError("Cancelled by user")
        provider = str(profile.get("provider") or "OpenAI")
        api_url = str(profile.get("api_url") or "")
        if not tracker.allowed(provider, api_url, context_prompt, maximum_output_tokens=8000):
            last_error = BudgetExceeded(f"Token budget reached ({tracker.budget_tokens} billable tokens)")
        else:
            try:
                log(f"Analyzing exported workspace with {provider} / {profile.get('model') or 'default'}")
                if provider not in CLI_PROVIDERS and provider != "ChatGPTAccount":
                    log(
                        f"[Notice] Analyzing workspace via API provider '{provider}'. "
                        f"Synthesizing aggregated code & catalog evidence. "
                        f"(For interactive autonomous filesystem exploration, select a CLI provider like AntigravityCLI or ClaudeCode)."
                    )
                report = _query_profile(profile, workspace, context_prompt, genesect_root, ida_path)
                if not report:
                    raise RuntimeError("provider returned an empty response")
                is_dotnet_target = (workspace / "catalog" / "types.json").is_file() or (workspace / "src").is_dir()
                report = sanitize_report_addresses(report)
                report = ensure_threat_attribution_section(report, workspace, report_dir=report_dir)
                report = ensure_report_navigation(report, workspace, is_dotnet=is_dotnet_target)
                report = sanitize_report_addresses(report)
                tracker.record(provider, str(profile.get("model") or "default"), api_url, context_prompt, report)

                target_dir = Path(report_dir) if report_dir else workspace
                target_dir.mkdir(parents=True, exist_ok=True)
                output = target_dir / "report.md"
                output.write_text(report, encoding="utf-8")

                if target_dir != workspace:
                    try:
                        (workspace / "report.md").write_text(report, encoding="utf-8")
                    except Exception:
                        pass

                log(f"Analysis report saved to: {output}")
                try:
                    from . import reporting
                    s_info = dict(sample_info or {"filename": workspace.name})
                    # Extract or synthesize production YARA rule
                    yara_rule_text, report = _extract_or_generate_yara(report, workspace, s_info)
                    output.write_text(report, encoding="utf-8")
                    if target_dir != workspace:
                        try:
                            (workspace / "report.md").write_text(report, encoding="utf-8")
                        except Exception:
                            pass

                    # Write standalone detection_rules.yar deliverable
                    yar_file = target_dir / "detection_rules.yar"
                    yar_file.write_text(yara_rule_text + "\n", encoding="utf-8")
                    log(f"YARA detection rule saved to: {yar_file}")
                    if target_dir != workspace:
                        try:
                            (workspace / "detection_rules.yar").write_text(yara_rule_text + "\n", encoding="utf-8")
                        except Exception:
                            pass

                    attr_meta = _extract_attribution_meta(report, workspace, report_dir)
                    model_dict = {
                        "sample": s_info,
                        "category": "Malware Analysis Report",
                        "badges": ["Exported AI Workspace", provider, "Threat Attribution"],
                        "provider": {"used": [provider]},
                        "attribution_hypothesis": attr_meta.get("hypothesis", ""),
                        "attribution_confidence": attr_meta.get("confidence", ""),
                    }
                    reporting.render_markdown_deliverables(
                        report,
                        target_dir,
                        model=model_dict,
                        base_name="report",
                        log_fn=log,
                    )
                    if target_dir != workspace:
                        try:
                            reporting.render_markdown_deliverables(
                                report,
                                workspace,
                                model=model_dict,
                                base_name="report",
                                log_fn=log,
                            )
                        except Exception:
                            pass
                except Exception as render_exc:
                    log(f"Warning: Could not render workspace report deliverables: {render_exc}")
                return {"report_path": str(output), "provider": provider, "usage": tracker.snapshot(), "fallback_events": events}
            except Exception as exc:
                last_error = exc
        if index + 1 < len(chain):
            next_provider = str(chain[index + 1].get("provider") or "OpenAI")
            reason = _safe_error_text(last_error, 300)
            events.append({"from": provider, "to": next_provider, "reason": reason})
            log(f"Provider {provider} failed ({reason}); falling back to {next_provider}")
    raise RuntimeError(f"Workspace analysis failed: {_safe_error_text(last_error, 1000)}")
