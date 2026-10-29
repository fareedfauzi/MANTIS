# -*- coding: utf-8 -*-
"""Small standalone entry point for Genesect account authentication.

This intentionally imports only the existing ChatGPT OAuth implementation.  It
can be started by the Rust launcher with the user's regular Python interpreter,
without starting IDA first.
"""

from __future__ import annotations

import json
import os
import sys


def _bootstrap_repo():
    package_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(package_dir)
    repo_key = os.path.normcase(os.path.realpath(repo_root))

    # The regular Python process can inherit IDA's plugin directory through
    # PYTHONPATH.  Merely checking whether the repo is already present leaves a
    # lower-priority entry in place, causing imports to resolve to the older
    # installed plugin. Always move this repository to index zero.
    retained = []
    for entry in sys.path:
        candidate = entry or os.getcwd()
        try:
            if os.path.normcase(os.path.realpath(candidate)) == repo_key:
                continue
        except Exception:
            pass
        retained.append(entry)
    sys.path[:] = [repo_root] + retained

    package_key = os.path.normcase(os.path.realpath(package_dir))
    for name, module in list(sys.modules.items()):
        if name != "genesect" and not name.startswith("genesect."):
            continue
        module_path = getattr(module, "__file__", "") or ""
        try:
            current_key = os.path.normcase(os.path.realpath(module_path))
        except Exception:
            current_key = ""
        if not current_key.startswith(package_key + os.sep):
            sys.modules.pop(name, None)


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
            selected_model, _available = chatgpt_oauth.resolve_model(model)
            chatgpt_oauth.create_response(
                selected_model,
                [{"role": "user", "content": "Reply with OK."}],
                instructions="Connection test.",
                max_output_tokens=32,
                timeout=30,
            )
            elapsed = int((time.time() - t0) * 1000)
            if selected_model != model:
                message = (
                    f"Connected to ChatGPT Account ({elapsed}ms). "
                    f"Model '{model or 'auto'}' was unavailable; selected '{selected_model}'."
                )
            else:
                message = f"Connected to ChatGPT Account using {selected_model} ({elapsed}ms)"
            return {"ok": True, "message": message, "model": selected_model}
        except Exception as exc:
            return {"ok": False, "message": f"ChatGPT Account error: {exc}"}

    elif provider == "OpenCode":
        from genesect import opencode_auth
        st = opencode_auth.credential_status()
        elapsed = int((time.time() - t0) * 1000)
        if st.get("signed_in"):
            provs = ", ".join(st.get("providers", []))
            return {"ok": True, "message": f"Connected to OpenCode (providers: {provs}) ({elapsed}ms)"}
        # Fall back to CLI presence check if auth.json not populated
        import subprocess
        cmd_name = executable or opencode_auth.find_opencode_executable()
        try:
            res = subprocess.run([cmd_name, "--version"], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                ver = (res.stdout.strip() or res.stderr.strip()).splitlines()[0] if res.stdout or res.stderr else "ready"
                return {"ok": True, "message": f"OpenCode ready: {ver} ({elapsed}ms), but no saved accounts in auth.json"}
            return {"ok": False, "message": "Not signed in to OpenCode. Click 'Sign In' to authenticate."}
        except Exception:
            return {"ok": False, "message": "Not signed in to OpenCode. Click 'Sign In' or run 'opencode auth login'."}

    elif provider in ("ClaudeCode", "AntigravityCLI"):
        import subprocess
        cmd_name = executable or ("claude" if provider == "ClaudeCode" else "agy")
        try:
            res = subprocess.run([cmd_name, "--version"], capture_output=True, text=True, timeout=10)
            elapsed = int((time.time() - t0) * 1000)
            if res.returncode == 0:
                ver = (res.stdout.strip() or res.stderr.strip()).splitlines()[0] if res.stdout or res.stderr else "ready"
                return {"ok": True, "message": f"{provider} ready: {ver} ({elapsed}ms)"}
            return {"ok": False, "message": f"{cmd_name} returned code {res.returncode}: {res.stderr.strip()[:100]}"}
        except Exception as exc:
            return {"ok": False, "message": f"Could not run {cmd_name}: {exc}"}

    elif provider == "Anthropic":
        url = api_url.rstrip("/") or "https://api.anthropic.com"
        req_url = f"{url}/v1/messages"
        body = {
            "model": model or "claude-sonnet-4-5",
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "ping"}],
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        try:
            req = urllib.request.Request(req_url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = int((time.time() - t0) * 1000)
                return {"ok": True, "message": f"Connected to Anthropic ({model}, {elapsed}ms)"}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:120]
            return {"ok": False, "message": f"Anthropic HTTP {exc.code}: {err_body}"}
        except Exception as exc:
            return {"ok": False, "message": f"Anthropic error: {exc}"}

    else:
        # OpenAI, DeepSeek, Ollama, LMStudio, OpenAICompatible
        url = api_url.rstrip("/") or "https://api.openai.com/v1"
        if not url.endswith("/chat/completions") and not url.endswith("/models"):
            req_url = f"{url}/chat/completions"
        else:
            req_url = url

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        body = {
            "model": model or "gpt-5.1",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 5,
        }
        try:
            req = urllib.request.Request(req_url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = int((time.time() - t0) * 1000)
                return {"ok": True, "message": f"Connected to {provider} ({model}, {elapsed}ms)"}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:120]
            return {"ok": False, "message": f"HTTP {exc.code}: {err_body}"}
        except Exception as exc:
            return {"ok": False, "message": f"Connection error: {exc}"}


def main(argv=None):
    _bootstrap_repo()
    from genesect import chatgpt_oauth

    args = list(argv if argv is not None else sys.argv[1:])
    command = args[0].lower() if args else "status"
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
        from genesect import opencode_auth
        print(json.dumps(opencode_auth.credential_status(), sort_keys=True))
        return 0
    if command == "opencode-sign-in":
        from genesect import opencode_auth
        exe_arg = args[1] if len(args) > 1 else None
        ok, msg = opencode_auth.launch_sign_in_terminal(executable=exe_arg)
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
