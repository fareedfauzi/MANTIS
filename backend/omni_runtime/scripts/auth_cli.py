# -*- coding: utf-8 -*-
"""Small standalone entry point for Genesect account authentication.

This intentionally imports only the existing ChatGPT OAuth implementation.  It
can be started by the Binary Lab launcher with the user's regular Python interpreter,
without starting IDA first.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _bootstrap_repo():
    package_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(package_dir)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    ida_plugin_candidates = []
    if sys.platform == "win32":
        for version in ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3"):
            ida_plugin_candidates.append(Path(rf"C:\Program Files\IDA Professional {version}\plugins"))
        appdata = os.environ.get("APPDATA")
        if appdata:
            ida_plugin_candidates.append(Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins")
    elif sys.platform == "darwin":
        for version in ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3"):
            ida_plugin_candidates.append(Path(f"/Applications/IDA Professional {version}/plugins"))
        ida_plugin_candidates.append(Path.home() / "Library" / "Application Support" / "Hex-Rays" / "IDA Pro" / "plugins")
        ida_plugin_candidates.append(Path.home() / ".idapro" / "plugins")
    else:
        for version in ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3"):
            ida_plugin_candidates.append(Path(f"/opt/idapro-{version}/plugins"))
        ida_plugin_candidates.append(Path.home() / ".idapro" / "plugins")
        ida_plugin_candidates.append(Path.home() / ".local" / "share" / "Hex-Rays" / "IDA Pro" / "plugins")

    for candidate in ida_plugin_candidates:
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.append(str(candidate))


def _opencode_status():
    try:
        from genesect import opencode_auth
        return opencode_auth.credential_status()
    except (ImportError, AttributeError):
        pass
    candidates = []
    try:
        home = Path.home()
        candidates.append(home / ".local" / "share" / "opencode" / "auth.json")
        candidates.append(home / ".config" / "opencode" / "auth.json")
        if sys.platform == "darwin":
            candidates.append(home / "Library" / "Application Support" / "opencode" / "auth.json")
    except Exception:
        pass
    for var in ("LOCALAPPDATA", "APPDATA", "XDG_DATA_HOME", "XDG_CONFIG_HOME"):
        val = os.environ.get(var)
        if val:
            candidates.append(Path(val) / "opencode" / "auth.json")
    for path in candidates:
        if path.is_file():
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict) and parsed:
                    return {"signed_in": True, "providers": list(parsed.keys())}
            except Exception:
                continue
    return {"signed_in": False, "providers": []}


def _opencode_sign_in(exe_arg=None):
    try:
        from genesect import opencode_auth
        return opencode_auth.launch_sign_in_terminal(executable=exe_arg)
    except (ImportError, AttributeError):
        pass
    import shutil
    import subprocess
    cmd = exe_arg or shutil.which("opencode") or "opencode"
    try:
        if sys.platform == "win32":
            subprocess.Popen(["cmd.exe", "/c", "start", cmd, "auth", "login"], shell=False)
        else:
            subprocess.Popen([cmd, "auth", "login"])
        return True, "Launched OpenCode sign-in terminal."
    except Exception as exc:
        return False, str(exc)


def _cli_executable(provider, configured=""):
    import shutil

    if configured:
        return configured
    defaults = {
        "ClaudeCode": "claude",
        "AntigravityCLI": "agy",
        "OpenCode": "opencode",
        "CopilotCLI": "copilot",
    }
    name = defaults[provider]
    if provider == "CopilotCLI":
        return shutil.which("copilot") or shutil.which("gh") or name
    return shutil.which(name) or name


def _discover_cli_models(provider, executable):
    import subprocess

    defaults = {
        "ClaudeCode": ["default", "sonnet", "opus", "haiku", "claude-sonnet-4-6"],
        "AntigravityCLI": ["default", "gemini-3.8-flash-low", "gemini-3.8-flash-medium", "gemini-3.8-flash-high"],
        "OpenCode": ["default"],
        "CopilotCLI": ["default"],
    }
    models = list(defaults[provider])
    if provider not in ("AntigravityCLI", "OpenCode"):
        return models
    try:
        result = subprocess.run(
            [executable, "models"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        discovered = []
        for line in result.stdout.splitlines():
            value = line.strip()
            if not value or value.lower().startswith(("fetching", "available")):
                continue
            model_id = value.split()[0]
            if model_id and model_id not in discovered:
                discovered.append(model_id)
        if discovered:
            models = ["default", *[item for item in discovered if item != "default"]]
    except Exception:
        pass
    return models


def _test_cli_provider(provider, executable, model, timeout=60):
    """Run a real minimal provider request rather than accepting --version."""
    import shutil
    import subprocess

    command_path = _cli_executable(provider, executable)
    is_gh = provider == "CopilotCLI" and Path(command_path).stem.lower() == "gh"
    prompt = "Reply with exactly OK. Do not use tools or inspect files."
    if provider == "AntigravityCLI":
        command = [command_path, "-p", prompt, "--disable-slash-commands", "--print-timeout", f"{int(timeout)}s"]
    elif provider == "ClaudeCode":
        command = [command_path, "-p", prompt]
    elif provider == "OpenCode":
        command = [command_path, "run", prompt]
    elif is_gh:
        command = [command_path, "copilot", "explain", prompt]
    else:
        command = [command_path, "-p", prompt, "-s"]

    if not is_gh and model.lower() not in ("", "auto", "default"):
        command.extend(["--model", model])

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=max(10, int(timeout)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
    except FileNotFoundError:
        if provider == "CopilotCLI" and not executable and shutil.which("gh"):
            result = subprocess.run(
                [shutil.which("gh"), "copilot", "explain", prompt],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=max(10, int(timeout)),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
            )
            command_path = shutil.which("gh")
        else:
            raise
    output = (result.stdout or result.stderr or "").strip()
    if result.returncode != 0:
        raise RuntimeError("%s exited with code %s: %s" % (
            provider, result.returncode, output[:300] or "no diagnostic output"
        ))
    if not output:
        raise RuntimeError("%s returned no response to the connection probe" % provider)
    return command_path, output


def _chatgpt_responses_probe(chatgpt_oauth, model):
    """Exercise the same OAuth Responses API used by batch analysis."""
    import openai

    def request(token):
        client = openai.OpenAI(api_key=token, base_url="https://api.openai.com/v1")
        completed = False
        with client.responses.create(
            model=model,
            input=[{"role": "user", "content": "Reply with exactly OK."}],
            instructions="Connection test.",
            max_output_tokens=32,
            store=False,
            stream=True,
        ) as stream:
            for event in stream:
                event_type = getattr(event, "type", "")
                if event_type == "response.completed":
                    completed = True
                elif event_type == "response.failed":
                    error = getattr(getattr(event, "response", None), "error", None)
                    raise RuntimeError(getattr(error, "message", None) or getattr(error, "code", None) or "response failed")
        if not completed:
            raise RuntimeError("ChatGPT account stream ended without response.completed")

    try:
        request(chatgpt_oauth.get_access_token())
    except Exception as exc:
        if getattr(exc, "status_code", None) != 401 or not hasattr(chatgpt_oauth, "refresh_credentials"):
            raise
        refreshed = chatgpt_oauth.refresh_credentials(force=True)
        token = refreshed.get("access_token") if isinstance(refreshed, dict) else ""
        if not token:
            raise
        request(token)


_NON_CHAT_KEYWORDS = (
    "embedding",
    "embed",
    "rerank",
    "whisper",
    "guard",
    "moderator",
    "transcribe",
    "tts",
    "audio",
    "image-generation",
    "dall-e",
)


def _is_chat_model(name):
    low = str(name or "").lower()
    return not any(kw in low for kw in _NON_CHAT_KEYWORDS)


def _score_model_for_chat(name):
    low = str(name or "").lower()
    if not _is_chat_model(low):
        return -100
    score = 0
    if "best-for-code" in low or "best-code" in low:
        score += 70
    elif "code" in low or "coder" in low:
        score += 40
    if "instruct" in low:
        score += 35
    if "best-for-chat" in low or "best-chat" in low:
        score += 30
    elif "chat" in low:
        score += 25
    if "reason" in low:
        score += 20
    if any(k in low for k in ("qwen", "deepseek", "gpt", "llama", "claude", "devstral", "mistral")):
        score += 15
    if "autocomplete" in low:
        score -= 60
    return score


def _sort_available_models(models):
    """Sort models so chat and coding models appear first, non-chat models last."""
    if not models:
        return []
    return sorted(models, key=_score_model_for_chat, reverse=True)


def _select_probe_model(configured, available, fallback):
    configured = str(configured or "").strip()
    placeholders = {"", "auto", "default", "local-model", "loaded-model", "custom-model", "embeddings", "embedding"}

    # Separate chat-capable models from non-chat models (embeddings, rerankers, etc.)
    chat_models = [m for m in available if _is_chat_model(m)]
    candidates = chat_models if chat_models else list(available)
    candidates = _sort_available_models(candidates)

    if configured and configured.lower() not in placeholders:
        # 1. Exact match in available
        if configured in available:
            return configured
        # 2. Case-insensitive match in available
        for m in available:
            if m.lower() == configured.lower():
                return m
        # 3. Suffix match (e.g. "qwen3.6-35b-a3b" matches "hosted_vllm/qwen3.6-35b-a3b")
        for m in available:
            if m.lower().endswith("/" + configured.lower()):
                return m
        # 4. Partial/fuzzy match among chat candidates
        conf_low = configured.lower()
        for m in candidates:
            m_low = m.lower()
            if conf_low in m_low or m_low in conf_low:
                return m
        # 5. If fallback is present in candidates, prefer fallback
        if fallback in candidates:
            return fallback
        # 6. If candidates are available, choose the best chat candidate
        if candidates:
            return candidates[0]
        return configured

    # Configured is a placeholder, embeddings, or empty
    if fallback in candidates:
        return fallback
    if candidates:
        return candidates[0]
    return fallback


def _normalize_openai_base_url(url):
    from urllib.parse import urlparse

    value = str(url or "").strip().rstrip("/")
    lowered = value.lower()
    for suffix in ("/chat/completions", "/completions", "/responses", "/models"):
        if lowered.endswith(suffix):
            value = value[:-len(suffix)].rstrip("/")
            break
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.path in ("", "/"):
        value += "/v1"
    return value


def _normalize_anthropic_base_url(url):
    value = str(url or "").strip().rstrip("/")
    lowered = value.lower()
    for suffix in ("/v1/messages", "/v1/models", "/v1"):
        if lowered.endswith(suffix):
            return value[:-len(suffix)].rstrip("/")
    return value


def test_connection(cfg):
    import time
    import urllib.request
    import urllib.error

    provider = str(cfg.get("provider") or "OpenAI")
    api_url = str(cfg.get("api_url") or "").strip()
    api_key = str(cfg.get("api_key") or "").strip()
    model = str(cfg.get("model") or "").strip()
    executable = str(cfg.get("executable") or "").strip()
    t0 = time.time()

    if provider == "ChatGPTAccount":
        from genesect import chatgpt_oauth
        status = chatgpt_oauth.credential_status()
        if not status.get("signed_in"):
            return {"ok": False, "message": "Not signed in to ChatGPT Account. Click 'Sign In' first."}
        try:
            available_models = []
            if hasattr(chatgpt_oauth, "list_models"):
                try:
                    raw_m = chatgpt_oauth.list_models()
                    available_models = [m.get("slug") for m in raw_m if isinstance(m, dict) and m.get("slug")]
                except Exception:
                    pass

            selected_model = _select_probe_model(
                model, available_models, available_models[0] if available_models else "auto"
            )
            if hasattr(chatgpt_oauth, "resolve_model"):
                selected_model, _available = chatgpt_oauth.resolve_model(model)
                if not available_models and _available:
                    available_models = list(_available)

            if hasattr(chatgpt_oauth, "create_response"):
                chatgpt_oauth.create_response(
                    selected_model,
                    [{"role": "user", "content": "Reply with OK."}],
                    instructions="Connection test.",
                    max_output_tokens=32,
                    timeout=30,
                )
            else:
                _chatgpt_responses_probe(chatgpt_oauth, selected_model)

            elapsed = int((time.time() - t0) * 1000)
            message = f"Connected to ChatGPT Account using {selected_model} ({elapsed}ms)"
            return {
                "ok": True,
                "message": message,
                "model": selected_model,
                "available_models": available_models,
            }
        except Exception as exc:
            return {"ok": False, "message": f"ChatGPT Account error: {exc}"}

    elif provider in ("ClaudeCode", "AntigravityCLI", "OpenCode", "CopilotCLI"):
        cmd_name = _cli_executable(provider, executable)
        available_models = _discover_cli_models(provider, cmd_name)
        selected_model = model or "default"
        try:
            used_command, _output = _test_cli_provider(provider, executable, selected_model)
            elapsed = int((time.time() - t0) * 1000)
            return {
                "ok": True,
                "message": f"Connected to {provider} using its signed-in session ({elapsed}ms)",
                "model": selected_model,
                "available_models": available_models,
            }
        except Exception as exc:
            return {"ok": False, "message": f"{provider} connection test failed: {exc}", "available_models": available_models}

    elif provider == "Anthropic":
        url = _normalize_anthropic_base_url(api_url or "https://api.anthropic.com")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        available_models = []
        try:
            req_m = urllib.request.Request(f"{url}/v1/models", headers=headers, method="GET")
            with urllib.request.urlopen(req_m, timeout=10) as resp_m:
                m_data = json.loads(resp_m.read().decode("utf-8"))
                available_models = [
                    item["id"] for item in m_data.get("data", [])
                    if isinstance(item, dict) and item.get("id")
                ]
        except Exception:
            pass

        req_url = f"{url}/v1/messages"
        probe_model = _select_probe_model(model, available_models, "claude-sonnet-4-6")
        body = {
            "model": probe_model,
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "ping"}],
        }
        try:
            req = urllib.request.Request(req_url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "ok": True,
                    "message": f"Connected to Anthropic ({probe_model}, {elapsed}ms)",
                    "model": probe_model,
                    "available_models": available_models or ["claude-sonnet-5", "claude-sonnet-4-6", "claude-opus-5", "claude-haiku-4-5-20251001"],
                }
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:120]
            return {"ok": False, "message": f"Anthropic completion probe failed with HTTP {exc.code}: {err_body}", "available_models": available_models}
        except Exception as exc:
            return {"ok": False, "message": f"Anthropic error: {exc}"}

    else:
        # OpenAI, DeepSeek, GoogleGemini, OpenRouter, Groq, Mistral, Ollama, LMStudio, OpenAICompatible
        default_url_map = {
            "OpenAI": "https://api.openai.com/v1",
            "DeepSeek": "https://api.deepseek.com/v1",
            "GoogleGemini": "https://generativelanguage.googleapis.com/v1beta/openai",
            "OpenRouter": "https://openrouter.ai/api/v1",
            "Groq": "https://api.groq.com/openai/v1",
            "Mistral": "https://api.mistral.ai/v1",
            "Ollama": "http://localhost:11434/v1",
            "LMStudio": "http://localhost:1234/v1",
            "OpenAICompatible": "http://localhost:1234/v1",
        }
        default_probe_map = {
            "OpenAI": "gpt-5.1",
            "DeepSeek": "deepseek-flash",
            "GoogleGemini": "gemini-3.8-flash",
            "OpenRouter": "openrouter/auto",
            "Groq": "openai/gpt-oss-120b",
            "Mistral": "mistral-medium-3-5",
            "Ollama": "llama3.2",
            "LMStudio": "local-model",
            "OpenAICompatible": "local-model",
        }
        fallback_url = default_url_map.get(provider, "https://api.openai.com/v1")
        base_url = _normalize_openai_base_url(api_url or fallback_url)

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if provider == "GoogleGemini":
            headers["x-goog-api-client"] = "omni-idb-oai/1.0"

        available_models = []
        model_endpoints = []
        model_endpoints.append(f"{base_url}/models")
        if not base_url.lower().endswith(("/v1", "/openai")):
            model_endpoints.append(f"{base_url}/v1/models")
        if provider == "Ollama":
            ollama_host = base_url[:-3] if base_url.endswith("/v1") else base_url
            model_endpoints.append(f"{ollama_host}/api/tags")

        import ssl

        try:
            ssl_ctx = ssl.create_default_context()
        except Exception:
            ssl_ctx = None

        def _open_url(request, timeout):
            try:
                if ssl_ctx is not None:
                    try:
                        return urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx)
                    except TypeError:
                        return urllib.request.urlopen(request, timeout=timeout)
                return urllib.request.urlopen(request, timeout=timeout)
            except urllib.error.URLError as err:
                if "certificate" in str(err).lower() or "ssl" in str(err).lower():
                    try:
                        unverified = ssl._create_unverified_context()
                        return urllib.request.urlopen(request, timeout=timeout, context=unverified)
                    except Exception:
                        pass
                raise

        for m_url in model_endpoints:
            try:
                req_m = urllib.request.Request(m_url, headers=headers, method="GET")
                with _open_url(req_m, timeout=10) as resp_m:
                    m_data = json.loads(resp_m.read().decode("utf-8"))
                    items = m_data.get("data") or m_data.get("models") or []
                    for item in items:
                        if isinstance(item, dict):
                            mid = item.get("id") or item.get("name") or item.get("model")
                            if mid and mid not in available_models:
                                available_models.append(mid)
                    if available_models:
                        break
            except Exception:
                continue

        available_models = _sort_available_models(available_models)
        req_url = f"{base_url}/chat/completions"
        probe_model = _select_probe_model(model, available_models, default_probe_map.get(provider, "gpt-5.1"))
        body = {
            "model": probe_model,
            "messages": [{"role": "user", "content": "ping"}],
        }
        if any(name in probe_model.lower() for name in ("o1", "o3", "gpt-5")):
            body["max_completion_tokens"] = 32
        else:
            body["max_tokens"] = 16

        def _try_post(target_model):
            post_body = dict(body)
            post_body["model"] = target_model
            if any(name in target_model.lower() for name in ("o1", "o3", "gpt-5")):
                post_body["max_completion_tokens"] = 32
                post_body.pop("max_tokens", None)
            else:
                post_body["max_tokens"] = 16
                post_body.pop("max_completion_tokens", None)
            req = urllib.request.Request(
                req_url,
                data=json.dumps(post_body).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with _open_url(req, timeout=15) as resp:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "ok": True,
                    "message": f"Connected to {provider} ({target_model}, {elapsed}ms)",
                    "model": target_model,
                    "available_models": available_models,
                }

        try:
            return _try_post(probe_model)
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:160]
            # If 404 / NotFound or route failure, attempt other chat-capable candidate models
            if exc.code == 404 or "not found" in err_body.lower():
                chat_candidates = [m for m in available_models if _is_chat_model(m) and m != probe_model]
                for alt in chat_candidates[:3]:
                    try:
                        return _try_post(alt)
                    except Exception:
                        continue
            return {
                "ok": False,
                "message": f"{provider} completion probe failed with HTTP {exc.code}: {err_body}",
                "model": probe_model,
                "available_models": available_models,
            }
        except Exception as exc:
            return {
                "ok": False,
                "message": f"{provider} completion probe failed: {exc}",
                "model": probe_model,
                "available_models": available_models,
            }


def main(argv=None):
    _bootstrap_repo()

    args = list(argv if argv is not None else sys.argv[1:])
    command = args[0].lower() if args else "status"

    if command in ("sign-in", "sign-out", "status"):
        try:
            from genesect import chatgpt_oauth
        except ImportError as exc:
            print(json.dumps({"ok": False, "message": f"ChatGPT OAuth module not found: {exc}"}))
            return 1
        if command == "sign-in":
            data = chatgpt_oauth.sign_in_interactive()
            print(json.dumps({
                "ok": True,
                "email": data.get("email", ""),
                "message": "ChatGPT sign-in complete.",
            }))
            return 0
        if command == "sign-out":
            chatgpt_oauth.sign_out()
            print(json.dumps({"ok": True, "message": "ChatGPT signed out."}))
            return 0
        if command == "status":
            print(json.dumps(chatgpt_oauth.credential_status(), sort_keys=True))
            return 0
    if command == "opencode-status":
        print(json.dumps(_opencode_status(), sort_keys=True))
        return 0
    if command == "opencode-sign-in":
        exe_arg = args[1] if len(args) > 1 else None
        ok, msg = _opencode_sign_in(exe_arg=exe_arg)
        print(json.dumps({"ok": ok, "message": msg}))
        return 0 if ok else 1
    if command == "test-connection":
        raw = sys.stdin.read().strip() if (len(args) <= 1 or args[1] == "-") else args[1]
        payload = json.loads(raw) if raw else {}
        print(json.dumps(test_connection(payload)))
        return 0
    print(json.dumps({"ok": False, "message": "Expected sign-in, sign-out, status, opencode-status, opencode-sign-in, or test-connection."}))
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        raise SystemExit(1)
