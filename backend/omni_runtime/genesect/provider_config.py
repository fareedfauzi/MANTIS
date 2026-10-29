"""Provider profiles, validation, and normalized request options."""

from dataclasses import dataclass, field
from urllib.parse import urlparse


PROVIDER_NAMES = (
    "OpenAI", "ChatGPTAccount", "CodexCLI", "ClaudeCode", "AntigravityCLI",
    "GeminiCLI", "QwenCode", "OpenCode", "HermesCLI", "Anthropic", "DeepSeek",
    "Gemini", "OpenRouter", "Mistral", "Groq", "xAI", "Cerebras", "Together",
    "Fireworks", "Ollama", "LMStudio", "OpenAICompatible",
)

SIGNED_IN_CLI_PROVIDERS = {
    "CodexCLI", "ClaudeCode", "AntigravityCLI", "GeminiCLI", "QwenCode",
    "OpenCode", "HermesCLI",
}

OPENAI_COMPATIBLE_PRESET_PROVIDERS = {
    "OpenRouter", "Mistral", "Groq", "xAI", "Cerebras", "Together", "Fireworks",
}

ALIASES = {
    "openai": "OpenAI",
    "chatgpt": "ChatGPTAccount",
    "chatgptaccount": "ChatGPTAccount",
    "chatgptplan": "ChatGPTAccount",
    "signinwithchatgpt": "ChatGPTAccount",
    "codex": "CodexCLI",
    "codexcli": "CodexCLI",
    "signinwithcodex": "CodexCLI",
    "claude": "ClaudeCode",
    "claudecode": "ClaudeCode",
    "signinwithclaude": "ClaudeCode",
    "antigravity": "AntigravityCLI",
    "antigravitycli": "AntigravityCLI",
    "agy": "AntigravityCLI",
    "geminicli": "GeminiCLI",
    "signinwithgemini": "GeminiCLI",
    "qwen": "QwenCode",
    "qwencode": "QwenCode",
    "opencode": "OpenCode",
    "opencodecli": "OpenCode",
    "hermes": "HermesCLI",
    "hermescli": "HermesCLI",
    "anthropic": "Anthropic",
    "deepseek": "DeepSeek",
    "gemini": "Gemini",
    "openrouter": "OpenRouter",
    "mistral": "Mistral",
    "groq": "Groq",
    "grok": "xAI",
    "xai": "xAI",
    "cerebras": "Cerebras",
    "together": "Together",
    "togetherai": "Together",
    "fireworks": "Fireworks",
    "fireworksai": "Fireworks",
    "ollama": "Ollama",
    "lmstudio": "LMStudio",
    "custom": "OpenAICompatible",
    "openaicompatible": "OpenAICompatible",
}

DEFAULTS = {
    "OpenAI": {"key": "", "url": "https://api.openai.com/v1", "model": "gpt-4o"},
    "ChatGPTAccount": {"key": "", "url": "https://api.openai.com/v1", "model": "gpt-6.1-sol"},
    "CodexCLI": {"key": "codex", "url": "", "model": "default"},
    "ClaudeCode": {"key": "claude", "url": "", "model": "default"},
    "AntigravityCLI": {"key": "agy", "url": "", "model": "default"},
    "GeminiCLI": {"key": "gemini", "url": "", "model": "default"},
    "QwenCode": {"key": "qwen", "url": "", "model": "default"},
    "OpenCode": {"key": "opencode", "url": "", "model": "default"},
    "HermesCLI": {"key": "hermes-agent", "url": "", "model": "default"},
    "Anthropic": {"key": "", "url": "https://api.anthropic.com", "model": "claude-sonnet-4-5"},
    "DeepSeek": {"key": "", "url": "https://api.deepseek.com/v1", "model": "deepseek-chat"},
    "Gemini": {"key": "", "url": "", "model": "gemini-2.5-pro"},
    "OpenRouter": {"key": "", "url": "https://openrouter.ai/api/v1", "model": "openai/gpt-4o"},
    "Mistral": {"key": "", "url": "https://api.mistral.ai/v1", "model": "mistral-large-latest"},
    "Groq": {"key": "", "url": "https://api.groq.com/openai/v1", "model": "llama-3.3-70b-versatile"},
    "xAI": {"key": "", "url": "https://api.x.ai/v1", "model": "grok-4"},
    "Cerebras": {"key": "", "url": "https://api.cerebras.ai/v1", "model": "llama3.1-70b"},
    "Together": {"key": "", "url": "https://api.together.xyz/v1", "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo"},
    "Fireworks": {"key": "", "url": "https://api.fireworks.ai/inference/v1", "model": "accounts/fireworks/models/llama-v3p1-70b-instruct"},
    "Ollama": {"key": "", "url": "http://localhost:11434/v1", "model": "llama3"},
    "LMStudio": {"key": "lm-studio", "url": "http://localhost:1234/v1", "model": "local-model"},
    "OpenAICompatible": {"key": "", "url": "", "model": ""},
}

MODEL_OPTIONS = {
    "OpenAI": (
        "gpt-5.1", "gpt-5", "gpt-4.1", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini",
        "o3", "o3-mini", "o1",
    ),
    "ChatGPTAccount": (
        "gpt-6.1-sol", "gpt-5.1", "gpt-5", "gpt-4.1", "gpt-4o",
    ),
    "CodexCLI": ("default", "gpt-5.1", "gpt-5", "gpt-4.1"),
    "ClaudeCode": (
        "default", "claude-sonnet-4-5", "claude-opus-4-1", "claude-opus-4",
        "claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest",
    ),
    "AntigravityCLI": (
        "default", "gemini-3.8-flash-high", "gemini-3.8-flash-medium",
        "gemini-3.8-flash-low", "gemini-3.7-flash-high",
        "gemini-3.7-flash-medium", "gemini-3.7-flash-low",
        "gemini-3.1-pro-high", "gemini-3.1-pro-low",
        "claude-opus-5-5-high", "claude-opus-5-5-medium",
        "claude-opus-5-5-low",
    ),
    "GeminiCLI": (
        "default", "gemini-2.5-pro", "gemini-2.5-flash",
        "gemini-2.5-flash-lite", "gemini-1.5-pro", "gemini-1.5-flash",
    ),
    "QwenCode": (
        "default", "qwen3-coder-plus", "qwen3-coder-flash",
        "qwen3-max", "qwen-plus", "qwen-turbo",
    ),
    "OpenCode": (
        "default", "anthropic/claude-sonnet-4-5", "openai/gpt-5.1",
        "openai/gpt-5", "google/gemini-2.5-pro",
    ),
    "HermesCLI": (
        "default", "openai-codex", "antigravity-agy", "claude-code",
        "openrouter", "copilot",
    ),
    "Anthropic": (
        "claude-sonnet-4-5", "claude-opus-4-1", "claude-opus-4",
        "claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest",
    ),
    "DeepSeek": ("deepseek-chat", "deepseek-reasoner", "deepseek-coder"),
    "Gemini": (
        "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite",
        "gemini-1.5-pro", "gemini-1.5-flash",
    ),
    "OpenRouter": (
        "openai/gpt-4o", "openai/gpt-4o-mini", "anthropic/claude-sonnet-4.5",
        "google/gemini-2.5-pro", "deepseek/deepseek-chat",
        "meta-llama/llama-3.3-70b-instruct",
    ),
    "Mistral": (
        "mistral-large-latest", "mistral-medium-latest", "mistral-small-latest",
        "codestral-latest", "devstral-medium-latest", "devstral-small-latest",
    ),
    "Groq": (
        "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
        "mixtral-8x7b-32768", "gemma2-9b-it",
    ),
    "xAI": ("grok-4", "grok-3", "grok-3-mini", "grok-2"),
    "Cerebras": ("llama3.1-70b", "llama3.1-8b", "qwen-3-coder-480b"),
    "Together": (
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
        "Qwen/Qwen2.5-Coder-32B-Instruct",
        "deepseek-ai/DeepSeek-R1",
    ),
    "Fireworks": (
        "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "accounts/fireworks/models/llama-v3p1-405b-instruct",
        "accounts/fireworks/models/deepseek-r1",
        "accounts/fireworks/models/qwen2p5-coder-32b-instruct",
    ),
    "Ollama": (
        "llama3", "llama3.1", "llama3.2", "codellama", "qwen2.5-coder",
        "deepseek-r1", "mistral", "mixtral",
    ),
    "LMStudio": ("local-model", "loaded-model"),
    "OpenAICompatible": ("", "local-model", "custom-model"),
}

KEY_REQUIRED = {"OpenAI", "Anthropic", "DeepSeek", "Gemini"} | OPENAI_COMPATIBLE_PRESET_PROVIDERS
URL_REQUIRED = (
    {"OpenAI", "Anthropic", "DeepSeek", "Ollama", "LMStudio", "OpenAICompatible"}
    | OPENAI_COMPATIBLE_PRESET_PROVIDERS
)


def normalize_provider(value):
    return ALIASES.get(str(value or "").replace("-", "").replace("_", "").lower(), "OpenAI")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple = ()
    warnings: tuple = ()


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    key: str
    url: str
    model: str

    @property
    def client_name(self):
        if self.name == "OpenAICompatible":
            return "custom"
        if self.name in OPENAI_COMPATIBLE_PRESET_PROVIDERS:
            return "custom"
        if self.name == "ChatGPTAccount":
            return "chatgptaccount"
        if self.name == "CodexCLI":
            return "codexcli"
        if self.name == "ClaudeCode":
            return "claudecode"
        if self.name == "AntigravityCLI":
            return "antigravitycli"
        if self.name == "GeminiCLI":
            return "geminicli"
        if self.name == "QwenCode":
            return "qwencode"
        if self.name == "OpenCode":
            return "opencode"
        if self.name == "HermesCLI":
            return "hermescli"
        return self.name.lower()


@dataclass(frozen=True)
class RequestOptions:
    timeout_seconds: int = 120
    max_completion_tokens: int = 8192
    temperature: float = 0.2
    retry_attempts: int = 2
    retry_backoff_seconds: float = 1.5


def validate_profile(profile, require_api_key=True):
    errors = []
    warnings = []
    if require_api_key and profile.name in KEY_REQUIRED and not profile.key.strip():
        errors.append("API key is required for this provider.")
    elif profile.name in KEY_REQUIRED and not profile.key.strip():
        warnings.append("API key is empty; settings can be saved, but requests may fail until one is configured.")
    if not profile.model.strip():
        errors.append("Model name is required.")
    if profile.name in URL_REQUIRED:
        parsed = urlparse(profile.url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            errors.append("Base URL must be a complete http:// or https:// URL.")
        elif parsed.scheme == "http" and profile.name not in {"Ollama", "LMStudio"}:
            warnings.append("This provider uses an unencrypted HTTP connection.")
    return ValidationResult(not errors, tuple(errors), tuple(warnings))


def profile_from_config(config):
    name = normalize_provider(getattr(config, "active_provider", "OpenAI"))
    mapping = {
        "OpenAI": ("openai_key", "openai_url", "openai_model"),
        "ChatGPTAccount": (None, None, "chatgpt_account_model"),
        "CodexCLI": ("codex_cli_path", "codex_cli_profile", "codex_cli_model"),
        "ClaudeCode": ("claude_code_path", None, "claude_code_model"),
        "AntigravityCLI": ("antigravity_cli_path", None, "antigravity_cli_model"),
        "GeminiCLI": ("gemini_cli_path", None, "gemini_cli_model"),
        "QwenCode": ("qwen_code_path", None, "qwen_code_model"),
        "OpenCode": ("opencode_path", None, "opencode_model"),
        "HermesCLI": ("hermes_cli_path", "hermes_cli_provider", "hermes_cli_model"),
        "Anthropic": ("anthropic_key", "anthropic_url", "anthropic_model"),
        "DeepSeek": ("deepseek_key", "deepseek_url", "deepseek_model"),
        "Gemini": ("gemini_key", None, "gemini_model"),
        "OpenRouter": ("openrouter_key", "openrouter_url", "openrouter_model"),
        "Mistral": ("mistral_key", "mistral_url", "mistral_model"),
        "Groq": ("groq_key", "groq_url", "groq_model"),
        "xAI": ("xai_key", "xai_url", "xai_model"),
        "Cerebras": ("cerebras_key", "cerebras_url", "cerebras_model"),
        "Together": ("together_key", "together_url", "together_model"),
        "Fireworks": ("fireworks_key", "fireworks_url", "fireworks_model"),
        "Ollama": (None, "ollama_host", "ollama_model"),
        "LMStudio": ("lmstudio_key", "lmstudio_url", "lmstudio_model"),
        "OpenAICompatible": ("custom_key", "custom_url", "custom_model"),
    }
    key_attr, url_attr, model_attr = mapping[name]
    return ProviderProfile(
        name,
        getattr(config, key_attr, "") if key_attr else "",
        getattr(config, url_attr, "") if url_attr else "",
        getattr(config, model_attr, "") or getattr(config, "model", ""),
    )


def request_options_from_config(config):
    return RequestOptions(
        timeout_seconds=max(10, int(getattr(config, "request_timeout_seconds", 120))),
        max_completion_tokens=max(128, int(getattr(config, "request_max_completion_tokens", 8192))),
        temperature=max(0.0, min(2.0, float(getattr(config, "request_temperature", 0.2)))),
        retry_attempts=max(0, min(5, int(getattr(config, "request_retry_attempts", 2)))),
        retry_backoff_seconds=max(0.0, float(getattr(config, "request_retry_backoff_seconds", 1.5))),
    )
