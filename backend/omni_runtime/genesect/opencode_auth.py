# -*- coding: utf-8 -*-
"""OpenCode CLI authentication and credential helper for Genesect.

OpenCode (https://opencode.ai) stores provider tokens in an `auth.json` file:
  - Windows: %USERPROFILE%\\.local\\share\\opencode\\auth.json or %LOCALAPPDATA%\\opencode\\auth.json
  - Linux/macOS: ~/.local/share/opencode/auth.json or ~/.config/opencode/auth.json

Users authenticate using `opencode auth login`. This module reads the stored
credential state, launches the interactive login terminal, and tests connectivity.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple


def get_candidate_auth_paths() -> List[str]:
    home = os.path.expanduser("~")
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    app_data = os.environ.get("APPDATA", "")
    xdg_data = os.environ.get("XDG_DATA_HOME", "")
    xdg_config = os.environ.get("XDG_CONFIG_HOME", "")

    candidates = [
        os.path.join(home, ".local", "share", "opencode", "auth.json"),
        os.path.join(home, ".config", "opencode", "auth.json"),
    ]
    if local_app_data:
        candidates.append(os.path.join(local_app_data, "opencode", "auth.json"))
    if app_data:
        candidates.append(os.path.join(app_data, "opencode", "auth.json"))
    if xdg_data:
        candidates.append(os.path.join(xdg_data, "opencode", "auth.json"))
    if xdg_config:
        candidates.append(os.path.join(xdg_config, "opencode", "auth.json"))

    return candidates


def find_auth_file() -> Optional[str]:
    for path in get_candidate_auth_paths():
        if os.path.isfile(path):
            return path
    return None


def find_opencode_executable() -> str:
    # 1. PATH search
    found = shutil.which("opencode")
    if found:
        return found
    if sys.platform == "win32":
        found_cmd = shutil.which("opencode.cmd") or shutil.which("opencode.exe")
        if found_cmd:
            return found_cmd

    # 2. Well-known Windows desktop app locations
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        desktop_exe = os.path.join(local_app_data, "Programs", "@opencode-aidesktop", "OpenCode.exe")
        if os.path.isfile(desktop_exe):
            return desktop_exe

    # 3. Node/npm global shims
    app_data = os.environ.get("APPDATA", "")
    if app_data:
        npm_cmd = os.path.join(app_data, "npm", "opencode.cmd")
        if os.path.isfile(npm_cmd):
            return npm_cmd

    return "opencode"


def credential_status() -> Dict[str, object]:
    auth_path = find_auth_file()
    if not auth_path:
        exe = find_opencode_executable()
        installed = (exe != "opencode") or (shutil.which("opencode") is not None)
        return {
            "installed": installed,
            "signed_in": False,
            "auth_file": "",
            "providers": [],
            "message": "Not signed in. Run 'opencode auth login' or click 'Sign in with OpenCode'.",
        }

    try:
        with open(auth_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return {
            "installed": True,
            "signed_in": False,
            "auth_file": auth_path,
            "providers": [],
            "message": f"Could not read {auth_path}: {exc}",
        }

    if not isinstance(data, dict):
        return {
            "installed": True,
            "signed_in": False,
            "auth_file": auth_path,
            "providers": [],
            "message": f"Invalid format in {auth_path}.",
        }

    active_providers: List[str] = []
    details: Dict[str, Dict[str, object]] = {}

    for provider_name, val in data.items():
        if isinstance(val, dict):
            p_type = val.get("type", "unknown")
            has_access = bool(val.get("access") or val.get("key") or val.get("token"))
            expires = val.get("expires")
            active_providers.append(provider_name)
            details[provider_name] = {
                "type": p_type,
                "has_token": has_access,
                "expires": expires,
                "account_id": val.get("accountId") or val.get("account_id") or "",
            }
        elif isinstance(val, str) and val.strip():
            active_providers.append(provider_name)
            details[provider_name] = {"type": "key", "has_token": True}

    if not active_providers:
        return {
            "installed": True,
            "signed_in": False,
            "auth_file": auth_path,
            "providers": [],
            "message": f"OpenCode auth file found at {auth_path}, but no provider accounts configured.",
        }

    provider_list = ", ".join(active_providers)
    return {
        "installed": True,
        "signed_in": True,
        "auth_file": auth_path,
        "providers": active_providers,
        "details": details,
        "message": f"OpenCode signed in with provider(s): {provider_list}",
    }


def launch_sign_in_terminal(executable: Optional[str] = None) -> Tuple[bool, str]:
    exe = (executable or "").strip() or find_opencode_executable()

    if sys.platform == "win32":
        try:
            # Launch Windows Command Prompt running `opencode auth login`
            subprocess.Popen(
                ["cmd.exe", "/K", f'"{exe}" auth login'],
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            return True, f"Opened terminal for '{exe} auth login'."
        except Exception as exc:
            return False, f"Failed to launch terminal: {exc}"
    else:
        # Linux / macOS
        terms = ["x-terminal-emulator", "gnome-terminal", "konsole", "xterm"]
        for term in terms:
            if shutil.which(term):
                try:
                    subprocess.Popen([term, "-e", f"{exe} auth login"])
                    return True, f"Opened {term} for '{exe} auth login'."
                except Exception:
                    continue
        try:
            # Fallback direct spawn
            subprocess.Popen([exe, "auth", "login"])
            return True, f"Spawned '{exe} auth login'."
        except Exception as exc:
            return False, f"Failed to launch terminal: {exc}"
