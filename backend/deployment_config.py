import os
import sys
import shutil
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger("mantis.deployment")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
ROOT_DIR = os.path.dirname(BASE_DIR)
ENV_PATH = os.path.join(ROOT_DIR, ".env")

# Standard server staging and tool paths
TOOLS_DIR = os.path.join(DATA_DIR, "tools")
STAGING_DIR = os.path.join(DATA_DIR, "staging")
WORKSPACE_DIR = os.path.join(DATA_DIR, "workspace")

STAGING_SAMPLES_DIR = os.path.join(STAGING_DIR, "samples")
STAGING_STEALER_DIR = os.path.join(STAGING_DIR, "stealer_logs")

TOOL_DIRS = {
    "ida": os.path.join(TOOLS_DIR, "ida"),
    "ghidra": os.path.join(TOOLS_DIR, "ghidra"),
    "goresym": os.path.join(TOOLS_DIR, "goresym"),
    "ilspycmd": os.path.join(TOOLS_DIR, "ilspycmd"),
}


def load_env_file() -> Dict[str, str]:
    """Parse .env file without external dependencies and populate os.environ."""
    loaded: Dict[str, str] = {}
    if not os.path.exists(ENV_PATH):
        return loaded

    try:
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k:
                    loaded[k] = v
                    if k not in os.environ:
                        os.environ[k] = v
    except Exception as e:
        logger.warning(f"Error loading .env file: {e}")
    return loaded


# Load environment on module import
load_env_file()


def get_deployment_mode() -> str:
    """Return 'server' or 'workstation' (default: workstation)."""
    mode = os.environ.get("MANTIS_MODE", "").strip().lower()
    if mode in ("server", "team_server", "team", "headless"):
        return "server"
    return "workstation"


def is_server_mode() -> bool:
    """Check if server mode is active."""
    return get_deployment_mode() == "server"


def set_deployment_mode(new_mode: str) -> str:
    """Update MANTIS_MODE in os.environ and persist to .env file."""
    mode = "server" if new_mode.lower() in ("server", "team", "team_server") else "workstation"
    os.environ["MANTIS_MODE"] = mode

    lines: List[str] = []
    found = False
    if os.path.exists(ENV_PATH):
        try:
            with open(ENV_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            lines = []

    new_lines = []
    for line in lines:
        if line.strip().startswith("MANTIS_MODE="):
            new_lines.append(f"MANTIS_MODE={mode}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append(f"\n# Deployment Mode (workstation | server)\nMANTIS_MODE={mode}\n")

    try:
        with open(ENV_PATH, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception as e:
        logger.warning(f"Failed to write MANTIS_MODE to .env: {e}")

    # Ensure folders are provisioned if server mode
    if mode == "server":
        ensure_server_directories()

    return mode


def ensure_server_directories() -> Dict[str, str]:
    """Create the standard server directory tree if it does not exist."""
    created = {}
    for path, name in [
        (TOOLS_DIR, "tools_root"),
        (STAGING_DIR, "staging_root"),
        (WORKSPACE_DIR, "workspace"),
        (STAGING_SAMPLES_DIR, "staging_samples"),
        (STAGING_STEALER_DIR, "staging_stealer"),
        (TOOL_DIRS["ida"], "tool_ida"),
        (TOOL_DIRS["ghidra"], "tool_ghidra"),
        (TOOL_DIRS["goresym"], "tool_goresym"),
        (TOOL_DIRS["ilspycmd"], "tool_ilspycmd"),
    ]:
        os.makedirs(path, exist_ok=True)
        created[name] = path

    # Add a README inside staging and tools for team reference
    readme_staging = os.path.join(STAGING_DIR, "README.txt")
    if not os.path.exists(readme_staging):
        try:
            with open(readme_staging, "w", encoding="utf-8") as f:
                f.write(
                    "MANTIS Server Staging Directory\n"
                    "=================================\n\n"
                    "- samples/ : Drop malware binaries (.exe, .bin, .elf, etc.) here.\n"
                    "             They will appear in Binary Lab & Similarity dropdowns.\n\n"
                    "- stealer_logs/ : Drop credential logs (.zip, .rar, folders) here.\n"
                    "                 They will appear in Credential Stealer drop selection.\n"
                )
        except Exception:
            pass

    return created


def find_tool_binary(tool_name: str) -> Dict[str, Any]:
    """Auto-detect executable path for a reverse engineering tool."""
    candidates = []
    env_keys = {
        "ida": ["IDA_PATH", "IDAT64_PATH", "IDA64_PATH"],
        "ghidra": ["GHIDRA_PATH", "GHIDRA_HEADLESS_PATH", "GHIDRA_HOME"],
        "goresym": ["GORESYM_PATH"],
        "ilspycmd": ["ILSPYCMD_PATH"],
    }

    # 1. Check environment variables
    for k in env_keys.get(tool_name, []):
        val = os.environ.get(k, "").strip().strip('"')
        if val and os.path.exists(val):
            return {"found": True, "path": os.path.abspath(val), "source": f"env:{k}"}

    # 2. Check dedicated server tools directory
    tool_dir = TOOL_DIRS.get(tool_name)
    if tool_dir and os.path.exists(tool_dir):
        if tool_name == "ida":
            names = ["idat64.exe", "ida64.exe", "idat.exe", "ida.exe", "idat64", "ida64", "idal64", "idat", "ida"]
            for n in names:
                p = os.path.join(tool_dir, n)
                if os.path.isfile(p):
                    return {"found": True, "path": os.path.abspath(p), "source": "server_tools_dir"}
        elif tool_name == "ghidra":
            # Can be root folder containing support/analyzeHeadless or direct batch/binary
            headless_sub = os.path.join(tool_dir, "support", "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
            if os.path.isfile(headless_sub):
                return {"found": True, "path": os.path.abspath(headless_sub), "source": "server_tools_dir"}
            names = ["analyzeHeadless.bat", "analyzeHeadless", "ghidraRun.bat", "ghidraRun"]
            for n in names:
                p = os.path.join(tool_dir, n)
                if os.path.isfile(p):
                    return {"found": True, "path": os.path.abspath(p), "source": "server_tools_dir"}
        elif tool_name == "goresym":
            names = ["GoReSym.exe", "goresym.exe", "GoReSym", "goresym"]
            for n in names:
                p = os.path.join(tool_dir, n)
                if os.path.isfile(p):
                    return {"found": True, "path": os.path.abspath(p), "source": "server_tools_dir"}
        elif tool_name == "ilspycmd":
            names = ["ilspycmd.exe", "ilspycmd.dll", "ilspycmd"]
            for n in names:
                p = os.path.join(tool_dir, n)
                if os.path.isfile(p):
                    return {"found": True, "path": os.path.abspath(p), "source": "server_tools_dir"}

    # 3. Check system PATH
    which_names = {
        "ida": ["idat64", "ida64", "idat", "ida"],
        "ghidra": ["analyzeHeadless", "ghidraRun"],
        "goresym": ["GoReSym", "goresym"],
        "ilspycmd": ["ilspycmd"],
    }
    for n in which_names.get(tool_name, []):
        w = shutil.which(n)
        if w:
            return {"found": True, "path": os.path.abspath(w), "source": "system_path"}

    return {"found": False, "path": "", "source": "not_found"}


def get_all_tools_status() -> Dict[str, Any]:
    """Return status of all reverse engineering tool binaries."""
    return {
        "ida": find_tool_binary("ida"),
        "ghidra": find_tool_binary("ghidra"),
        "goresym": find_tool_binary("goresym"),
        "ilspycmd": find_tool_binary("ilspycmd"),
    }


def list_staging_items(category: str = "all") -> Dict[str, List[Dict[str, Any]]]:
    """List files/folders available in the staging directories."""
    result: Dict[str, List[Dict[str, Any]]] = {}

    def scan_dir(target_dir: str) -> List[Dict[str, Any]]:
        if not os.path.exists(target_dir):
            return []
        items = []
        try:
            for entry in os.scandir(target_dir):
                if entry.name.startswith(".") or entry.name == "README.txt":
                    continue
                try:
                    stat = entry.stat()
                    items.append({
                        "name": entry.name,
                        "path": os.path.abspath(entry.path),
                        "is_dir": entry.is_dir(),
                        "size_bytes": stat.st_size if entry.is_file() else 0,
                        "modified": int(stat.st_mtime),
                    })
                except OSError:
                    continue
        except Exception as e:
            logger.warning(f"Error scanning staging dir {target_dir}: {e}")
        items.sort(key=lambda x: x["name"].lower())
        return items

    if category in ("all", "samples"):
        result["samples"] = scan_dir(STAGING_SAMPLES_DIR)
    if category in ("all", "stealer_logs"):
        result["stealer_logs"] = scan_dir(STAGING_STEALER_DIR)

    return result


def get_deployment_summary() -> Dict[str, Any]:
    """Complete summary of deployment mode, paths, tools, and staging state."""
    mode = get_deployment_mode()
    tools = get_all_tools_status()
    staging = list_staging_items("all")

    return {
        "mode": mode,
        "is_server": mode == "server",
        "directories": {
            "root": ROOT_DIR,
            "data": DATA_DIR,
            "tools": TOOLS_DIR,
            "staging": STAGING_DIR,
            "workspace": WORKSPACE_DIR,
            "staging_samples": STAGING_SAMPLES_DIR,
            "staging_stealer": STAGING_STEALER_DIR,
        },
        "tools": tools,
        "staging": staging,
    }


# Auto-provision server directories if started in server mode
if is_server_mode():
    ensure_server_directories()
