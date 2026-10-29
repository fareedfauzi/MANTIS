"""Persistent settings, provider defaults and tool auto-detection."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Optional

PROVIDERS = [
    "OpenAI",
    "Anthropic",
    "DeepSeek",
    "GoogleGemini",
    "OpenRouter",
    "Groq",
    "Mistral",
    "OpenAICompatible",
    "Ollama",
    "LMStudio",
    "ChatGPTAccount",
    "ClaudeCode",
    "AntigravityCLI",
    "OpenCode",
    "CopilotCLI",
]

SIGNED_IN_PROVIDERS = {"ChatGPTAccount", "ClaudeCode", "AntigravityCLI", "OpenCode", "CopilotCLI"}
CLI_PROVIDERS = ("ClaudeCode", "AntigravityCLI", "OpenCode", "CopilotCLI")
# These providers may run without a key. The UI still exposes the key field for
# authenticated LM Studio or remote OpenAI-compatible deployments.
KEYLESS_PROVIDERS = {"OpenAICompatible", "Ollama", "LMStudio"}

# provider -> (api_url, model, executable)
_PROVIDER_DEFAULTS = {
    "OpenAI": ("https://api.openai.com/v1", "gpt-5.1", ""),
    "Anthropic": ("https://api.anthropic.com", "claude-sonnet-4-6", ""),
    "DeepSeek": ("https://api.deepseek.com/v1", "deepseek-flash", ""),
    "GoogleGemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-3.8-flash", ""),
    "OpenRouter": ("https://openrouter.ai/api/v1", "openrouter/auto", ""),
    "Groq": ("https://api.groq.com/openai/v1", "openai/gpt-oss-120b", ""),
    "Mistral": ("https://api.mistral.ai/v1", "mistral-medium-3-5", ""),
    "OpenAICompatible": ("http://localhost:1234/v1", "local-model", ""),
    "Ollama": ("http://localhost:11434/v1", "llama3.2", ""),
    "LMStudio": ("http://localhost:1234/v1", "local-model", ""),
    "ChatGPTAccount": ("", "auto", ""),
    "ClaudeCode": ("", "default", "claude"),
    "AntigravityCLI": ("", "gemini-3.8-flash-low", "agy"),
    "OpenCode": ("", "default", "opencode"),
    "CopilotCLI": ("", "default", "copilot"),
}

DEFAULT_PROVIDER_MODELS = {
    "OpenAI": ["gpt-5.1", "gpt-4o", "gpt-4o-mini", "o3-mini", "o1"],
    "Anthropic": ["claude-sonnet-5", "claude-sonnet-4-6", "claude-opus-5", "claude-haiku-4-5-20251001"],
    "DeepSeek": ["deepseek-flash", "deepseek-v4-pro"],
    "GoogleGemini": ["gemini-3.8-flash", "gemini-3.5-flash", "gemini-3.5-pro"],
    "OpenRouter": ["openrouter/auto", "anthropic/claude-sonnet-4.6", "openai/gpt-5.1", "google/gemini-3.8-flash"],
    "Groq": ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"],
    "Mistral": ["mistral-medium-3-5", "mistral-small-4", "mistral-large-3", "codestral-latest"],
    "OpenAICompatible": ["local-model"],
    "Ollama": ["llama3.2", "llama3.1", "qwen2.5-coder", "deepseek-r1"],
    "LMStudio": ["local-model"],
    "ChatGPTAccount": ["auto", "gpt-6.1-sol", "gpt-6-astra", "gpt-6-sol", "gpt-5.6-sol", "gpt-4o"],
    "ClaudeCode": ["default", "sonnet", "opus", "haiku", "claude-sonnet-4-6", "claude-opus-5"],
    "AntigravityCLI": [
        "gemini-3.8-flash-low",
        "gemini-3.8-flash-medium",
        "gemini-3.8-flash-high",
        "claude-sonnet-5-5-low",
        "gemini-4-argon-low",
        "default",
    ],
    "OpenCode": ["default", "openai/gpt-5.1", "anthropic/claude-sonnet-4-6", "google/gemini-3.8-flash"],
    "CopilotCLI": ["default", "gpt-4o", "claude-3.5-sonnet", "o1"],
}


def provider_defaults(provider: str) -> tuple[str, str, str]:
    return _PROVIDER_DEFAULTS.get(provider, ("https://api.openai.com/v1", "gpt-5.1", ""))


def default_models_for_provider(provider: str) -> list[str]:
    return list(DEFAULT_PROVIDER_MODELS.get(provider, []))


def normalize_openai_base_url(url: str) -> str:
    """Normalize an OpenAI-compatible base URL supplied as a base or endpoint."""
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


def openai_chat_endpoint(url: str) -> str:
    base = normalize_openai_base_url(url)
    return f"{base}/chat/completions"


def openai_model_endpoints(url: str) -> list[str]:
    base = normalize_openai_base_url(url)
    endpoints = [f"{base}/models"]
    if base and not base.lower().endswith(("/v1", "/openai")):
        endpoints.append(f"{base}/v1/models")
    return endpoints


def normalize_anthropic_base_url(url: str) -> str:
    value = str(url or "").strip().rstrip("/")
    lowered = value.lower()
    for suffix in ("/v1/messages", "/v1/models", "/v1"):
        if lowered.endswith(suffix):
            return value[:-len(suffix)].rstrip("/")
    return value


def is_signed_in_provider(provider: str) -> bool:
    return provider in SIGNED_IN_PROVIDERS


def is_cli_provider(provider: str) -> bool:
    return provider in CLI_PROVIDERS


def project_root() -> Path:
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass and Path(meipass).is_dir():
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def app_dir() -> Path:
    """Return the actual directory where the executable or script is installed/located.

    Unlike project_root(), this does NOT point to PyInstaller's temporary _MEIPASS extraction folder.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent



def _config_dir(app: str) -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / app


def _cache_dir(app: str) -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / app


def settings_path() -> Path:
    path = _config_dir("BinaryLab") / "settings.json"
    if path.is_file():
        return path
    legacy_omni = _config_dir("OmniIDB") / "settings.json"
    if legacy_omni.is_file():
        return legacy_omni
    legacy = _config_dir("Genesector") / "settings.json"
    return legacy if legacy.is_file() else path


def cache_path() -> Path:
    primary = _config_dir("BinaryLab") / "rename_cache.sqlite3"
    if primary.is_file():
        return primary
    # Check fallback/legacy locations (e.g. LocalAppData on Windows, or older cache dir)
    candidates = [
        _config_dir("OmniIDB") / "rename_cache.sqlite3",
        _cache_dir("BinaryLab") / "rename_cache.sqlite3",
        _cache_dir("OmniIDB") / "rename_cache.sqlite3",
        _config_dir("Genesector") / "rename_cache.sqlite3",
        _cache_dir("Genesector") / "rename_cache.sqlite3",
    ]
    if sys.platform == "win32":
        for var in ("LOCALAPPDATA", "APPDATA"):
            val = os.environ.get(var)
            if val:
                candidates.append(Path(val) / "BinaryLab" / "rename_cache.sqlite3")
                candidates.append(Path(val) / "OmniIDB" / "rename_cache.sqlite3")
                candidates.append(Path(val) / "Genesector" / "rename_cache.sqlite3")
    for cand in candidates:
        if cand.is_file():
            return cand
    return primary


def path_text(path) -> str:
    return str(path)


def runner_script(root: Path | str) -> Path:
    """Locate batch_ida_runner.py under an engine root (``scripts/`` or ``genesect/``)."""
    root = Path(root)
    for sub in ("scripts", "genesect"):
        candidate = root / sub / "batch_ida_runner.py"
        if candidate.is_file():
            return candidate
    return root / "scripts" / "batch_ida_runner.py"


def auth_script(root: Path | str) -> Path:
    root = Path(root)
    for sub in ("scripts", "genesect"):
        candidate = root / sub / "auth_cli.py"
        if candidate.is_file():
            return candidate
    return root / "scripts" / "auth_cli.py"


def find_genesect_package_root(*hints: Path | str) -> Optional[Path]:
    """Return the directory containing the ``genesect`` package (the analysis library).

    The batch/auth scripts do ``from genesect import ...``; the package normally lives
    in IDA's ``plugins`` folder rather than next to this project.
    """
    candidates: list[Path] = []
    for hint in hints:
        text = str(hint or "").strip()
        if not text:
            continue
        p = Path(text)
        candidates += [p, p / "plugins", p.parent / "plugins"]
    candidates += [project_root(), project_root().parent]

    # Standard per-user IDA plugin directories
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins")
    elif sys.platform == "darwin":
        candidates.append(Path.home() / "Library" / "Application Support" / "Hex-Rays" / "IDA Pro" / "plugins")
        candidates.append(Path.home() / ".idapro" / "plugins")
    else:
        candidates.append(Path.home() / ".idapro" / "plugins")
        candidates.append(Path.home() / ".local" / "share" / "Hex-Rays" / "IDA Pro" / "plugins")

    ida_names = ("IDA Professional", "IDA Pro", "IDA Home", "IDA Free", "IDA")
    ida_versions = ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3", "8.2", "8.1", "8.0", "7.7", "7.6", "7.5", "7.0")

    if sys.platform == "win32":
        for name in ida_names:
            for version in ida_versions:
                candidates.append(Path(rf"C:\Program Files\{name} {version}\plugins"))
                candidates.append(Path(rf"C:\Program Files (x86)\{name} {version}\plugins"))
                candidates.append(Path(rf"C:\Program Files\{name}\plugins"))
    elif sys.platform == "darwin":
        mac_bases = [Path("/Applications"), Path.home() / "Applications"]
        for base in mac_bases:
            for version in ida_versions:
                for name in ida_names:
                    candidates.append(base / f"{name} {version}" / "plugins")
            for name in ida_names:
                candidates.append(base / name / "plugins")
    else:
        linux_bases = [Path("/opt"), Path.home(), Path.home() / ".idapro", Path("/usr/local"), Path("/usr/share")]
        for base in linux_bases:
            for version in ida_versions:
                for prefix in ("idapro-", "idapro", "ida-", "ida"):
                    candidates.append(base / f"{prefix}{version}" / "plugins")
            candidates.append(base / "plugins")

    for candidate in candidates:
        if (candidate / "genesect" / "__init__.py").is_file():
            return candidate
    return None


def detect_engine_root() -> Optional[Path]:
    starts = [project_root(), Path.cwd()]
    for start in starts:
        for directory in [start, *list(start.parents)[:8]]:
            if runner_script(directory).is_file():
                return directory

    # Also search IDA Pro plugins directories where genesect may be installed
    ida_names = ("IDA Professional", "IDA Pro")
    ida_versions = ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3")
    if sys.platform == "win32":
        for version in ida_versions:
            plugin = Path(rf"C:\Program Files\IDA Professional {version}\plugins")
            if (plugin / "genesect").is_dir():
                return plugin
    elif sys.platform == "darwin":
        for version in ida_versions:
            for name in ida_names:
                plugin = Path(f"/Applications/{name} {version}/plugins")
                if (plugin / "genesect").is_dir():
                    return plugin
    else:
        for version in ida_versions:
            for prefix in ("idapro-", "idapro", "ida-"):
                plugin = Path(f"/opt/{prefix}{version}/plugins")
                if (plugin / "genesect").is_dir():
                    return plugin
    return None


def detect_ida() -> Optional[Path]:
    import shutil

    # 1. Search PATH for any standard IDA Pro / IDAT headless binary
    for exe in ("idat64", "idat64.exe", "ida64", "ida64.exe", "idat", "idat.exe", "ida", "ida.exe"):
        found = shutil.which(exe)
        if found and Path(found).is_file():
            return Path(found)

    names = ["IDA Professional", "IDA Pro", "IDA Home", "IDA Free", "IDA"]
    versions = ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3", "8.2", "8.1", "8.0", "7.7", "7.6", "7.5", "7.0")

    if sys.platform == "win32":
        for base in (r"C:\Program Files", r"C:\Program Files (x86)"):
            for version in versions:
                for name in names:
                    for exe in ("idat64.exe", "ida64.exe", "idat.exe", "ida.exe"):
                        candidate = Path(rf"{base}\{name} {version}\{exe}")
                        if candidate.is_file():
                            return candidate
            for name in names:
                for exe in ("idat64.exe", "ida64.exe", "idat.exe", "ida.exe"):
                    candidate = Path(rf"{base}\{name}\{exe}")
                    if candidate.is_file():
                        return candidate
    elif sys.platform == "darwin":
        mac_bases = [Path("/Applications"), Path.home() / "Applications"]
        for base in mac_bases:
            for version in versions:
                for name in names:
                    folder = base / f"{name} {version}"
                    if folder.is_dir():
                        for app_name in ("ida64.app", "ida.app", "idat64.app", "idat.app"):
                            cand = folder / app_name / "Contents" / "MacOS" / app_name.replace(".app", "")
                            if cand.is_file():
                                return cand
                        for exe in ("idat64", "ida64", "idat", "ida"):
                            cand = folder / exe
                            if cand.is_file():
                                return cand
            for name in names:
                folder = base / name
                if folder.is_dir():
                    for app_name in ("ida64.app", "ida.app"):
                        cand = folder / app_name / "Contents" / "MacOS" / app_name.replace(".app", "")
                        if cand.is_file():
                            return cand
                    for exe in ("idat64", "ida64", "idat", "ida"):
                        cand = folder / exe
                        if cand.is_file():
                            return cand
        for p in (Path("/usr/local/bin/ida64"), Path("/usr/local/bin/idat64"), Path("/opt/homebrew/bin/ida64")):
            if p.is_file():
                return p
    else:
        linux_bases = [Path("/opt"), Path.home(), Path.home() / ".idapro", Path("/usr/local"), Path("/usr/share")]
        for base in linux_bases:
            for version in versions:
                for prefix in ("idapro-", "idapro", "ida-", "ida"):
                    folder = base / f"{prefix}{version}"
                    if folder.is_dir():
                        for exe in ("idat64", "ida64", "idat", "ida"):
                            cand = folder / exe
                            if cand.is_file():
                                return cand
            for exe in ("idat64", "ida64", "idat", "ida"):
                cand = base / exe
                if cand.is_file():
                    return cand
        for p in (Path("/usr/local/bin/idat64"), Path("/usr/local/bin/ida64"), Path("/usr/bin/idat64"), Path("/usr/bin/ida64")):
            if p.is_file():
                return p
    return None


def resolve_ghidra_headless(path: Path | str | None) -> Optional[Path]:
    """Resolve an analyzeHeadless binary from a direct file or a Ghidra installation folder."""
    if not path:
        return None
    p = Path(str(path).strip().strip("\"'")).expanduser()
    if p.is_file():
        name_lower = p.name.lower()
        stem_lower = p.stem.lower()
        # Strictly accept only analyzeHeadless executable/script files
        if stem_lower == "analyzeheadless" or name_lower in ("analyzeheadless.bat", "analyzeheadless.cmd", "analyzeheadless.sh", "analyzeheadless"):
            return p
        # If user pointed to ghidraRun, resolve to the associated analyzeHeadless in support/
        if stem_lower == "ghidrarun" or name_lower in ("ghidrarun.bat", "ghidrarun.cmd", "ghidrarun.sh", "ghidrarun"):
            for cand_name in (("analyzeHeadless.bat", "analyzeHeadless.cmd") if sys.platform == "win32" else ("analyzeHeadless", "analyzeHeadless.sh")):
                sibling = p.parent / "support" / cand_name
                if sibling.is_file():
                    return sibling
        # Reject any other arbitrary executable
        return None
    if p.is_dir():
        for cand_name in (("analyzeHeadless.bat", "analyzeHeadless.cmd") if sys.platform == "win32" else ("analyzeHeadless", "analyzeHeadless.sh")):
            cand = p / "support" / cand_name
            if cand.is_file():
                return cand
            cand_root = p / cand_name
            if cand_root.is_file():
                return cand_root
    return None


def detect_ghidra() -> Optional[Path]:
    """Auto-detect Ghidra's analyzeHeadless from PATH, environment variables, or standard install locations."""
    import shutil

    # 1. Search PATH
    for exe in ("analyzeHeadless.bat", "analyzeHeadless", "ghidraRun.bat", "ghidraRun"):
        found = shutil.which(exe)
        if found:
            resolved = resolve_ghidra_headless(found)
            if resolved:
                return resolved

    # 2. Check environment variables
    for env_var in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_DIR"):
        val = os.environ.get(env_var)
        if val:
            resolved = resolve_ghidra_headless(val)
            if resolved:
                return resolved

    # 3. Check common installation roots
    candidates: list[Path] = []
    if sys.platform == "win32":
        bases = [
            Path(r"C:\Tools"),
            Path(r"C:\Program Files"),
            Path(r"C:\Program Files (x86)"),
            Path(r"C:\\"),
            Path.home(),
            Path.home() / "Tools",
            Path.home() / "AppData" / "Local" / "Programs",
        ]
        for base in bases:
            if not base.is_dir():
                continue
            try:
                for entry in base.glob("*ghidra*"):
                    if entry.is_dir():
                        candidates.append(entry)
            except OSError:
                pass
    elif sys.platform == "darwin":
        bases = [Path("/Applications"), Path.home() / "Applications", Path("/opt"), Path.home() / "Tools"]
        for base in bases:
            if not base.is_dir():
                continue
            try:
                for entry in base.glob("*ghidra*"):
                    if entry.is_dir():
                        candidates.append(entry)
            except OSError:
                pass
    else:
        bases = [Path("/opt"), Path("/usr/local"), Path("/usr/share"), Path.home(), Path.home() / "tools"]
        for base in bases:
            if not base.is_dir():
                continue
            try:
                for entry in base.glob("*ghidra*"):
                    if entry.is_dir():
                        candidates.append(entry)
            except OSError:
                pass

    for cand in candidates:
        resolved = resolve_ghidra_headless(cand)
        if resolved:
            return resolved
    return None


@dataclass
class AppSettings:
    input_path: str = ""
    output_root: str = ""
    ida_path: str = ""
    ghidra_path: str = ""
    disassembler: str = "ida"  # "ida" | "ghidra" | "auto"
    genesect_root: str = ""
    provider: str = "OpenAI"
    api_url: str = "https://api.openai.com/v1"
    model: str = "gpt-5.1"
    executable: str = ""
    rename_functions: bool = False
    rename_functions_with_address: bool = False
    rename_variables: bool = False
    generate_workspace: bool = True
    analyze_workspace: bool = False
    autonomous_investigation: bool = False
    threat_attribution_lookup: bool = False
    dotnet_mode: str = "decompile"  # "skip" | "decompile"
    goresym_path: str = ""
    ilspycmd_path: str = ""
    investigation_turns: int = 10
    recursive: bool = True
    batch_size: int = 15
    workers: int = 3
    low_score_rescan: bool = False
    cooldown_seconds: int = 1
    use_rename_cache: bool = True
    token_budget: int = 0
    fallback_enabled: bool = False
    fallback_provider: str = "Ollama"
    fallback_api_url: str = "http://localhost:11434/v1"
    fallback_model: str = "llama3.2"
    fallback_executable: str = ""
    api_keys: dict[str, str] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "AppSettings":
        ida = detect_ida()
        ghidra = detect_ghidra()
        root = detect_engine_root()
        disasm = "ida" if ida else ("ghidra" if ghidra else "auto")
        return cls(
            ida_path=str(ida) if ida else "",
            ghidra_path=str(ghidra) if ghidra else "",
            disassembler=disasm,
            genesect_root=str(root) if root else "",
        )

    @classmethod
    def load(cls) -> "AppSettings":
        settings = cls.default()
        try:
            data = json.loads(settings_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return settings
        if not isinstance(data, dict):
            return settings
        known = {f.name: f for f in fields(cls)}
        for key, value in data.items():
            if key in known:
                if key == "api_keys" and isinstance(value, dict):
                    setattr(settings, key, {str(k): str(v) for k, v in value.items()})
                elif isinstance(value, type(getattr(settings, key))):
                    setattr(settings, key, value)
        # Migrate single legacy api_key if present
        if "api_key" in data and isinstance(data["api_key"], str) and data["api_key"].strip():
            if settings.provider not in settings.api_keys:
                settings.api_keys[settings.provider] = data["api_key"].strip()
        return settings

    def get_api_key(self, provider: str) -> str:
        if not hasattr(self, "api_keys") or not isinstance(self.api_keys, dict):
            self.api_keys = {}
        return self.api_keys.get(provider, "")

    def set_api_key(self, provider: str, key: str) -> None:
        if not hasattr(self, "api_keys") or not isinstance(self.api_keys, dict):
            self.api_keys = {}
        cleaned = key.strip()
        if cleaned:
            self.api_keys[provider] = cleaned
        elif provider in self.api_keys:
            del self.api_keys[provider]

    def save(self) -> None:
        path = _config_dir("BinaryLab") / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        try:
            if sys.platform != "win32":
                os.chmod(path, 0o600)
        except OSError:
            pass

    def apply_provider_defaults(self) -> None:
        self.api_url, self.model, self.executable = provider_defaults(self.provider)

    def apply_fallback_provider_defaults(self) -> None:
        self.fallback_api_url, self.fallback_model, self.fallback_executable = provider_defaults(
            self.fallback_provider
        )

    def infer_output_root(self) -> None:
        text = self.input_path.strip()
        if not text:
            return
        p = Path(text)
        base = p if p.is_dir() else p.parent
        self.output_root = str(base / "omni-idb-output")
