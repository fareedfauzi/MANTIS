"""Provider-aware analysis and reporting for exported reverse-engineering workspaces."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from genesect.usage import BudgetExceeded, UsageTracker

CLI_PROVIDERS = {
    "AntigravityCLI",
    "ClaudeCode",
    "OpenCode",
    "CopilotCLI",
    "CodexCLI",
    "GeminiCLI",
    "QwenCode",
    "HermesCLI",
}

DEFAULT_PROVIDER_URLS = {
    "OpenAI": "https://api.openai.com/v1",
    "Anthropic": "https://api.anthropic.com",
    "DeepSeek": "https://api.deepseek.com/v1",
    "Gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "OpenRouter": "https://openrouter.ai/api/v1",
    "Mistral": "https://api.mistral.ai/v1",
    "Groq": "https://api.groq.com/openai/v1",
    "xAI": "https://api.x.ai/v1",
    "Cerebras": "https://api.cerebras.ai/v1",
    "Together": "https://api.together.xyz/v1",
    "Fireworks": "https://api.fireworks.ai/inference/v1",
    "Ollama": "http://localhost:11434/v1",
    "LMStudio": "http://localhost:1234/v1",
    "OpenAICompatible": "",
}

DEFAULT_PROVIDER_MODELS = {
    "OpenAI": "gpt-4o",
    "ChatGPTAccount": "gpt-6.1-sol",
    "AntigravityCLI": "default",
    "ClaudeCode": "default",
    "OpenCode": "default",
    "CopilotCLI": "default",
    "CodexCLI": "default",
    "GeminiCLI": "default",
    "QwenCode": "default",
    "HermesCLI": "default",
    "Anthropic": "claude-sonnet-4-5",
    "DeepSeek": "deepseek-chat",
    "Gemini": "gemini-2.5-pro",
    "OpenRouter": "openai/gpt-4o",
    "Mistral": "mistral-large-latest",
    "Groq": "llama-3.3-70b-versatile",
    "xAI": "grok-4",
    "Cerebras": "llama3.1-70b",
    "Together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "Fireworks": "accounts/fireworks/models/llama-v3p1-70b-instruct",
    "Ollama": "llama3",
    "LMStudio": "local-model",
    "OpenAICompatible": "",
}

SYSTEM_PROMPT = (
    "You are a senior malware analyst. Produce an evidence-based technical report in Markdown. "
    "Distinguish observed behavior from hypotheses, preserve useful indicators, and avoid unsupported claims."
)


def normalize_openai_base_url(url: str) -> str:
    """Normalize an OpenAI-compatible base URL supplied as a base or endpoint."""
    value = str(url or "").strip().rstrip("/")
    lowered = value.lower()
    for suffix in ("/chat/completions", "/completions", "/responses", "/models"):
        if lowered.endswith(suffix):
            value = value[:-len(suffix)].rstrip("/")
            break
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.path in ("", "/"):
        value += "/v1"
    return value


def openai_chat_endpoint(url: str) -> str:
    base = normalize_openai_base_url(url)
    return f"{base}/chat/completions"


def normalize_anthropic_base_url(url: str) -> str:
    value = str(url or "").strip().rstrip("/")
    lowered = value.lower()
    for suffix in ("/v1/messages", "/v1/models", "/v1"):
        if lowered.endswith(suffix):
            return value[:-len(suffix)].rstrip("/")
    return value


def get_active_profile_dict(config=None) -> dict:
    """Extract active profile dictionary from Genesect's configuration."""
    from genesect.config import CONFIG
    from genesect.provider_config import normalize_provider, DEFAULTS

    cfg = config or CONFIG
    raw_provider = getattr(cfg, "active_provider", "OpenAI")
    provider = normalize_provider(raw_provider)

    key = ""
    url = ""
    model = ""
    executable = ""

    if provider == "OpenAI":
        key = getattr(cfg, "openai_key", "")
        url = getattr(cfg, "openai_url", "https://api.openai.com/v1")
        model = getattr(cfg, "openai_model", "gpt-4o")
    elif provider == "ChatGPTAccount":
        model = getattr(cfg, "chatgpt_account_model", "gpt-6.1-sol")
    elif provider == "AntigravityCLI":
        executable = getattr(cfg, "antigravity_cli_path", "agy")
        model = getattr(cfg, "antigravity_cli_model", "default")
    elif provider == "ClaudeCode":
        executable = getattr(cfg, "claude_code_path", "claude")
        model = getattr(cfg, "claude_code_model", "default")
    elif provider == "OpenCode":
        executable = getattr(cfg, "opencode_path", "opencode")
        model = getattr(cfg, "opencode_model", "default")
    elif provider == "CodexCLI":
        executable = getattr(cfg, "codex_cli_path", "codex")
        model = getattr(cfg, "codex_cli_model", "default")
    elif provider == "GeminiCLI":
        executable = getattr(cfg, "gemini_cli_path", "gemini")
        model = getattr(cfg, "gemini_cli_model", "default")
    elif provider == "QwenCode":
        executable = getattr(cfg, "qwen_code_path", "qwen")
        model = getattr(cfg, "qwen_code_model", "default")
    elif provider == "HermesCLI":
        executable = getattr(cfg, "hermes_cli_path", "hermes-agent")
        model = getattr(cfg, "hermes_cli_model", "default")
    elif provider == "Anthropic":
        key = getattr(cfg, "anthropic_key", "")
        url = getattr(cfg, "anthropic_url", "https://api.anthropic.com")
        model = getattr(cfg, "anthropic_model", "claude-sonnet-4-5")
    elif provider == "DeepSeek":
        key = getattr(cfg, "deepseek_key", "")
        url = getattr(cfg, "deepseek_url", "https://api.deepseek.com/v1")
        model = getattr(cfg, "deepseek_model", "deepseek-chat")
    elif provider == "Gemini":
        key = getattr(cfg, "gemini_key", "")
        url = "https://generativelanguage.googleapis.com/v1beta/openai"
        model = getattr(cfg, "gemini_model", "gemini-2.5-pro")
    elif provider == "Ollama":
        url = getattr(cfg, "ollama_host", "http://localhost:11434/v1")
        model = getattr(cfg, "ollama_model", "llama3")
    elif provider == "LMStudio":
        key = getattr(cfg, "lmstudio_key", "lm-studio")
        url = getattr(cfg, "lmstudio_url", "http://localhost:1234/v1")
        model = getattr(cfg, "lmstudio_model", "local-model")
    elif provider in ("OpenRouter", "Mistral", "Groq", "xAI", "Cerebras", "Together", "Fireworks"):
        prefix = provider.lower()
        key = getattr(cfg, f"{prefix}_key", "")
        url = getattr(cfg, f"{prefix}_url", "")
        model = getattr(cfg, f"{prefix}_model", "")
    else:  # OpenAICompatible / custom
        key = getattr(cfg, "custom_key", "")
        url = getattr(cfg, "custom_url", "")
        model = getattr(cfg, "custom_model", "")

    defaults = DEFAULTS.get(provider, {})
    if not url and defaults.get("url"):
        url = defaults["url"]
    if not model and defaults.get("model"):
        model = defaults["model"]

    return {
        "provider": provider,
        "api_key": key,
        "api_url": url,
        "model": model,
        "executable": executable,
    }


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
        "- For native binaries: Include a section titled '## Key Functions for Reverse Engineering & IDB Navigation' listing critical subroutines (both renamed and unnamed sub_*), their hex address, classification (Malicious, Suspicious, or Core Functionality), and specific guidance on what to inspect in IDA Pro.\n"
        "- For managed .NET assemblies: Include a section titled '## Key Methods for Decompiler Navigation (dnSpy / ILSpy)' listing critical classes/methods, their location/tokens, classification (Malicious, Suspicious, or Core Functionality), and specific guidance on what P/Invokes, crypto, or execution logic to inspect in dnSpy/ILSpy.\n\n"
        "### DETECTION ENGINEERING & YARA RULES (REQUIRED)\n"
        "You MUST include a dedicated section titled '## Detection Engineering & YARA Rules' containing a complete, "
        "syntactically valid, production-ready YARA rule (fenced with ```yara ... ```) tailored to this sample and its threat family.\n"
        "Requirements:\n"
        "1. Rule Name: Format as `rule mal_<platform>_<family_or_sample>_<capability>`.\n"
        "2. Metadata: Include `author = \"MANTIS Binary Lab\"`, `date`, `sample_sha256`, `description`, `threat_level = \"critical\"`, `reference`.\n"
        "3. Strings Block: Define distinctive strings ($str*), unique API sequences, C2 patterns, or distinctive hex opcode sequences ($code*).\n"
        "4. Condition Block: Strictly enforce target binary headers (PE/ELF), filesize constraints, and string combination logic.\n"
        "5. Zero False Positives: Never match compiler boilerplate, CRT runtime code, or generic API names alone."
    )


def build_workspace_context(workspace: Path, maximum_chars: int = 180_000) -> str:
    """Collect bounded workspace evidence for providers that cannot read local files directly."""
    workspace = Path(workspace).resolve()
    parts = [_analysis_prompt(workspace), "\n\n=== EXPORTED WORKSPACE EVIDENCE ==="]
    remaining = max(10_000, int(maximum_chars))
    preferred = [
        workspace / "AGENTS.md",
        workspace / "README.md",
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
    elif provider == "CodexCLI":
        command = [executable or shutil.which("codex") or "codex", "-p", prompt]
    elif provider == "GeminiCLI":
        command = [executable or shutil.which("gemini") or "gemini", "-p", prompt]
    elif provider == "QwenCode":
        command = [executable or shutil.which("qwen") or "qwen", "-p", prompt]
    elif provider == "HermesCLI":
        command = [executable or shutil.which("hermes-agent") or "hermes-agent", "-p", prompt]
    else:
        raise ValueError(f"Unsupported CLI provider: {provider}")

    if provider not in ("CopilotCLI",) and model.lower() not in ("", "auto", "default"):
        command.extend(["--model", model])
    elif provider == "CopilotCLI" and Path(command[0]).stem.lower() != "gh" and model.lower() not in ("", "auto", "default"):
        command.extend(["--model", model])

    result = subprocess.run(
        command,
        cwd=str(workspace),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}")

    raw_output = (result.stdout or result.stderr).strip()

    # Detect if agent (e.g. Antigravity CLI / agy) wrote an artifact report file and printed a link
    artifact_pattern = re.search(r"\[([^\]]+\.md)\]\((file://[^\)]+)\)", raw_output, re.IGNORECASE)
    if artifact_pattern:
        file_url = artifact_pattern.group(2)
        try:
            parsed = urllib.parse.urlparse(file_url)
            if parsed.netloc and len(parsed.netloc) >= 2 and parsed.netloc[1] == ":":
                local_path = parsed.netloc + parsed.path
            else:
                local_path = urllib.parse.unquote(parsed.path)
                if local_path.startswith("/") and len(local_path) > 3 and local_path[2] == ":":
                    local_path = local_path[1:]
            art_file = Path(local_path)
            if art_file.is_file() and art_file.stat().st_size > len(raw_output):
                full_content = art_file.read_text(encoding="utf-8", errors="replace")
                if full_content.strip():
                    return full_content
        except Exception:
            pass

    return raw_output


def _query_chatgpt_account(profile: dict, prompt: str) -> str:
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
    default_url = DEFAULT_PROVIDER_URLS.get(provider, "https://api.openai.com/v1")
    default_model = DEFAULT_PROVIDER_MODELS.get(provider, "gpt-4o")

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
        if provider == "GoogleGemini" or provider == "Gemini":
            headers["x-goog-api-client"] = "genesect-ai-ws/1.0"
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        token_field = "max_completion_tokens" if any(name in model.lower() for name in ("o1", "o3", "gpt-5")) else "max_tokens"
        body[token_field] = 8000

    request = urllib.request.Request(endpoint, json.dumps(body).encode("utf-8"), headers, method="POST")
    with urllib.request.urlopen(request, timeout=600) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if provider == "Anthropic":
        return "".join(str(item.get("text") or "") for item in payload.get("content", []) if isinstance(item, dict)).strip()

    message = (payload.get("choices") or [{}])[0].get("message") or {}
    return str(message.get("content") or message.get("reasoning_content") or message.get("reasoning") or "").strip()


def _query_profile(profile: dict, workspace: Path, context_prompt: str) -> str:
    provider = str(profile.get("provider") or "OpenAI")
    if provider in CLI_PROVIDERS:
        return _run_cli(profile, workspace, _analysis_prompt(workspace))
    if provider == "ChatGPTAccount":
        return _query_chatgpt_account(profile, context_prompt)
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


def ensure_report_navigation(
    report_markdown: str,
    workspace_dir: Path | str,
    is_dotnet: bool = False,
    renamed_list: Optional[list] = None,
) -> str:
    """Ensure the report ends with the structured navigation table for reverse engineers."""
    if not report_markdown or not report_markdown.strip():
        report_markdown = "# Malware Analysis Report\n"

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

    return report_markdown.rstrip() + "\n\n" + nav_section.strip() + "\n"


def analyze_workspace(
    workspace: Path | str,
    primary: Optional[dict] = None,
    fallback: Optional[dict] = None,
    *,
    token_budget: int = 0,
    log_fn: Optional[Callable[[str], None]] = None,
    cancel_checker: Optional[Callable[[], bool]] = None,
    sample_info: Optional[dict] = None,
    report_dir: Optional[Path | str] = None,
) -> dict:
    """Analyze a workspace using primary provider first, with optional fallback."""
    log = log_fn or (lambda _message: None)
    workspace = Path(workspace).resolve()

    if primary is None:
        primary = get_active_profile_dict()

    chain = [dict(primary)]
    if fallback and fallback.get("provider") and dict(fallback) != dict(primary):
        chain.append(dict(fallback))

    tracker = UsageTracker(token_budget)
    context_prompt = build_workspace_context(workspace)
    events = []
    last_error = None

    for index, profile in enumerate(chain):
        if cancel_checker and cancel_checker():
            raise RuntimeError("Cancelled by user")
        provider = str(profile.get("provider") or "OpenAI")
        api_url = str(profile.get("api_url") or "")
        if not tracker.allowed(provider, api_url):
            last_error = BudgetExceeded(f"Token budget reached ({tracker.budget_tokens} billable tokens)")
        else:
            try:
                log(f"Analyzing exported workspace with {provider} / {profile.get('model') or 'default'}...")
                report = _query_profile(profile, workspace, context_prompt)
                if not report:
                    raise RuntimeError("Provider returned an empty response")

                is_dotnet_target = (workspace / "catalog" / "types.json").is_file() or (workspace / "src").is_dir()
                report = ensure_report_navigation(report, workspace, is_dotnet=is_dotnet_target)
                tracker.record(provider, str(profile.get("model") or "default"), api_url, context_prompt, report)

                output = workspace / "malware_analysis_report.md"
                output.write_text(report, encoding="utf-8")
                log(f"Workspace analysis report saved to: {output}")

                # Render deliverables (MD, HTML, and vector PDF)
                deliverables = {}
                try:
                    from genesect import reporting
                    s_info = dict(sample_info or {"filename": workspace.name})
                    model_dict = {
                        "sample": s_info,
                        "category": "Malware Analysis Report",
                        "badges": ["Exported AI Workspace", provider],
                        "provider": {"used": [provider]},
                    }
                    deliverables = reporting.render_markdown_deliverables(
                        report,
                        workspace,
                        model=model_dict,
                        base_name="malware_analysis_report",
                        log_fn=log,
                    )
                    if report_dir:
                        r_dir = Path(report_dir)
                        r_dir.mkdir(parents=True, exist_ok=True)
                        reporting.render_markdown_deliverables(
                            report,
                            r_dir,
                            model=model_dict,
                            base_name="workspace_analysis",
                            log_fn=log,
                        )
                except Exception as render_exc:
                    log(f"Warning: Could not render workspace report deliverables: {render_exc}")

                return {
                    "report_path": str(output),
                    "deliverables": deliverables,
                    "provider": provider,
                    "usage": tracker.snapshot(),
                    "fallback_events": events,
                }
            except Exception as exc:
                last_error = exc

        if index + 1 < len(chain):
            next_provider = str(chain[index + 1].get("provider") or "OpenAI")
            reason = str(last_error)[:300]
            events.append({"from": provider, "to": next_provider, "reason": reason})
            log(f"Provider {provider} failed ({reason}); falling back to {next_provider}")

    raise RuntimeError(f"Workspace analysis failed: {last_error}")
