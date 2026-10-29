# -*- coding: utf-8 -*-
"""
Configuration management and logging for Genesect.
"""

import os
import datetime
import configparser

from genesect.qt_compat import QtCore, Signal, QtWidgets


LEGACY_NAME = "Pseudo" + "Note"
LEGACY_ENV_PREFIX = "PSEUDO" + "NOTE_"
LEGACY_USER_CONFIG_FILE = "." + "pseudo" + "note-extended.ini"


class Config:
    def __init__(self):
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))
        # Location in the plugin directory (might be read-only if in Program Files)
        self.plugin_config_path = os.path.join(self.plugin_dir, "Genesect.ini")
        # Writable fallback in user home directory
        self.user_config_path = os.path.join(os.path.expanduser("~"), ".genesect.ini")
        self.legacy_user_config_path = os.path.join(os.path.expanduser("~"), LEGACY_USER_CONFIG_FILE)
        
        # Determine the primary path to use (prefer the one that exists or the user one for writing)
        if os.path.exists(self.user_config_path):
            self.config_path = self.user_config_path
        else:
            self.config_path = self.plugin_config_path

        self.model = "gpt-4"
        self.proxy = ""

        self.openai_key = ""
        self.openai_url = "https://api.openai.com/v1"

        self.deepseek_key = ""
        self.deepseek_url = "https://api.deepseek.com/v1"

        self.anthropic_key = ""
        self.anthropic_url = "https://api.anthropic.com"

        self.gemini_key = ""

        self.ollama_host = "http://localhost:11434/v1"
        self.ollama_model = "llama3"

        self.lmstudio_url = "http://localhost:1234/v1"
        self.lmstudio_key = "lm-studio"

        self.custom_key = ""
        self.custom_url = ""
        self.custom_model = ""

        self.active_provider = "openai"
        self.openai_model = "gpt-4"
        self.chatgpt_account_model = "gpt-6.1-sol"
        self.codex_cli_path = "codex"
        self.codex_cli_profile = ""
        self.codex_cli_model = "default"
        self.claude_code_path = "claude"
        self.claude_code_model = "default"
        self.antigravity_cli_path = "agy"
        self.antigravity_cli_model = "default"
        self.gemini_cli_path = "gemini"
        self.gemini_cli_model = "default"
        self.qwen_code_path = "qwen"
        self.qwen_code_model = "default"
        self.opencode_path = "opencode"
        self.opencode_model = "default"
        self.hermes_cli_path = "hermes-agent"
        self.hermes_cli_provider = ""
        self.hermes_cli_model = "default"
        self.deepseek_model = "deepseek-coder"
        self.anthropic_model = "claude-3-opus-20240229"
        self.gemini_model = "gemini-1.5-pro"
        self.openrouter_key = ""
        self.openrouter_url = "https://openrouter.ai/api/v1"
        self.openrouter_model = "openai/gpt-4o"
        self.mistral_key = ""
        self.mistral_url = "https://api.mistral.ai/v1"
        self.mistral_model = "mistral-large-latest"
        self.groq_key = ""
        self.groq_url = "https://api.groq.com/openai/v1"
        self.groq_model = "llama-3.3-70b-versatile"
        self.xai_key = ""
        self.xai_url = "https://api.x.ai/v1"
        self.xai_model = "grok-4"
        self.cerebras_key = ""
        self.cerebras_url = "https://api.cerebras.ai/v1"
        self.cerebras_model = "llama3.1-70b"
        self.together_key = ""
        self.together_url = "https://api.together.xyz/v1"
        self.together_model = "meta-llama/Llama-3.3-70B-Instruct-Turbo"
        self.fireworks_key = ""
        self.fireworks_url = "https://api.fireworks.ai/inference/v1"
        self.fireworks_model = "accounts/fireworks/models/llama-v3p1-70b-instruct"
        self.lmstudio_model = "local-model"

        self.request_timeout_seconds = 120
        self.request_max_completion_tokens = 8192
        # Zero means provider-aware automatic sizing. Local providers default
        # to 4096, which matches the common LM Studio/Ollama model load size.
        self.request_context_window_tokens = 0
        self.request_temperature = 0.2
        self.request_retry_attempts = 2
        self.request_retry_backoff_seconds = 1.5

        self.ui_font = "'Inter', 'Ubuntu', 'Cantarell', 'DejaVu Sans', 'Liberation Sans', 'Arial', 'Segoe UI'"
        self.ui_font_size = 9
        self.code_font = "'JetBrains Mono', 'Fira Code', 'DejaVu Sans Mono', 'Liberation Mono', 'Consolas', 'Courier New', monospace"
        self.code_font_size = 10
        self.markdown_font = "'JetBrains Mono', 'Fira Code', 'DejaVu Sans Mono', 'Liberation Mono', 'Consolas', 'Courier New', monospace"
        self.markdown_font_size = 10
        
        # UI Appearance
        self.highlight_color = "#ffaaff"
        self.indent_guides_enabled = True
        self.indent_guides_color = "#57CFDC"
        self.pseudocode_folding_enabled = True
        self.pseudocode_folding_color = "#3F3F3F"
        self.argument_name_hints_enabled = False
        self.call_explanations_enabled = True
        self.rust_string_fixups_enabled = True
        self.zoom_all_views_enabled = True
        self.bookmarked_actions = [
            "genesect:explain_document",
            "genesect:ask_chat",
            "genesect:hex_viewer",
            "genesect:dnspy_xrefs",
        ]

        # Analysis Defaults (Shared/Fallback)
        self.batch_size = 10
        self.parallel_workers = 1
        self.cooldown_seconds = 0

        # Bulk Function Renamer (Specific)
        self.bulk_batch_size = 10
        self.bulk_parallel_workers = 5
        self.bulk_cooldown = 0
        self.bulk_asm_max = 25

        # Bulk Variable Renamer (Specific)
        self.var_batch_size = 5
        self.var_parallel_workers = 3
        self.var_cooldown = 0
        self.var_asm_max = 25

        # Bulk Function Analyzer (Specific)
        self.analyze_batch_size = 10
        self.analyze_parallel_workers = 5
        self.analyze_cooldown = 0

        # Deep Analyzer (Specific)
        self.deep_batch_size = 5
        self.deep_parallel_workers = 1
        self.deep_cooldown = 0
        self.deep_max_lines = 200
        
        # Autonomous Agent (Specific)
        self.agent_cooldown = 240
        
        # New: Graph and analysis limits (Bug #4)
        self.max_graph_nodes = 500
        self.max_graph_depth = 15
        self.max_callees_per_node = 64
        self.max_queue_size = 5000
        
        # New: Thresholds for risk assessment (Bug #7)
        self.high_confidence_threshold = 75
        self.min_coverage_for_report = 80
        self.malicious_confidence_cutoff = 75
        self.max_graph_ascii_lines = 2500

        self.deep_do_var_rename = True
        self.deep_do_func_comment = True
        self.deep_do_analysis_rename = True
        self.deep_do_refinement = True
        self.deep_do_bottom_up_rename = True
        
        self.rename_prefix = ""
        self.function_prefix = ""
        self.use_rename_prefix = False
        self.use_bulk_prefix = False
        self.filter_system = True
        self.filter_empty = True
        self.asm_max_lines = 25
        self.force_bulk_rename = False
        self.bulk_append_address = False
        self.bulk_use_0x = False
        self.rename_append_address = False
        self.rename_use_0x = False
        self.deep_use_0x = False
        self.deep_use_prefix = False
        self.deep_prefix = ""
        self.deep_append_address = True
        
        self.analyzer_use_prefix = False
        self.analyzer_prefix = ""
        self.analyzer_append_address = True
        self.var_auto_apply = True
        self.var_force_rename = False
        self.bulk_force_rename_sub = False
        self.auto_apply_bulk = True
        self.show_pro_tip = True
        self.floss_path = ""
        self.goresym_path = ""
        self.rift_server_url = "http://127.0.0.1:5001"
        self.rift_output_folder = ""
        self.rename_cache_enabled = True
        self.rename_cache_path = os.path.join(os.path.expanduser("~"), ".genesect", "rename_cache.sqlite")

        # External signed-in agent / MCP bridge
        self.mcp_bridge_enabled = False
        self.mcp_bridge_port = 0
        self.mcp_bridge_token_file = ""
        self.mcp_bridge_allow_http = False
        self.mcp_bridge_allow_remote_tunnel = False
        self.mcp_bridge_session_dir = "~/.genesect/mcp/sessions"

        # Human-in-the-loop permission cards
        self.permission_write_idb = "ask"
        self.permission_patch_bytes = "ask"
        self.permission_execute = "off"
        self.permission_filesystem = "ask"
        self.permission_runtime = "ask"
        self.permission_network = "off"

        # Runtime artifacts and local emulation helpers
        self.runtime_artifact_dir = "~/.genesect/runtime_artifacts"
        self.runtime_auto_load_last = True
        self.coverage_overlay_enabled = True
        self.coverage_color = "#2D7D46"
        self.speakeasy_path = ""
        self.speakeasy_timeout = 60
        self.speakeasy_max_api_count = 10000
        self.speakeasy_snapshot_memory = True
        self.speakeasy_dropped_files = True
        self.speakeasy_default_arch = ""

        self.load()

    def load(self):
        self.openai_key = os.environ.get("GENESECT_OPENAI_API_KEY", os.environ.get(LEGACY_ENV_PREFIX + "OPENAI_API_KEY", ""))
        self.deepseek_key = os.environ.get("GENESECT_DEEPSEEK_API_KEY", os.environ.get(LEGACY_ENV_PREFIX + "DEEPSEEK_API_KEY", ""))
        self.anthropic_key = os.environ.get("GENESECT_ANTHROPIC_API_KEY", os.environ.get(LEGACY_ENV_PREFIX + "ANTHROPIC_API_KEY", ""))
        self.gemini_key = os.environ.get("GENESECT_GEMINI_API_KEY", os.environ.get(LEGACY_ENV_PREFIX + "GEMINI_API_KEY", ""))

        parser = configparser.ConfigParser()
        # Read from both. User config overrides plugin config if both exist.
        configs_to_read = []
        if os.path.exists(self.plugin_config_path):
            configs_to_read.append(self.plugin_config_path)
        if os.path.exists(self.legacy_user_config_path):
            configs_to_read.append(self.legacy_user_config_path)
        if os.path.exists(self.user_config_path):
            configs_to_read.append(self.user_config_path)
        
        if not configs_to_read:
            return

        parser.read(configs_to_read, encoding="utf-8")

        settings_section = "Genesect" if parser.has_section("Genesect") else LEGACY_NAME
        if parser.has_section(settings_section):
            if parser.has_option(settings_section, "MODEL"):
                self.model = parser.get(settings_section, "MODEL")
            if parser.has_option(settings_section, "PROXY"):
                self.proxy = parser.get(settings_section, "PROXY")
            if parser.has_option(settings_section, "PROVIDER"):
                self.active_provider = parser.get(settings_section, "PROVIDER")
            self.request_timeout_seconds = parser.getint(settings_section, "REQUEST_TIMEOUT", fallback=120)
            self.request_max_completion_tokens = parser.getint(settings_section, "MAX_COMPLETION_TOKENS", fallback=8192)
            self.request_context_window_tokens = parser.getint(settings_section, "CONTEXT_WINDOW_TOKENS", fallback=0)
            self.request_temperature = parser.getfloat(settings_section, "TEMPERATURE", fallback=0.2)
            self.request_retry_attempts = parser.getint(settings_section, "RETRY_ATTEMPTS", fallback=2)
            self.request_retry_backoff_seconds = parser.getfloat(settings_section, "RETRY_BACKOFF", fallback=1.5)

        if parser.has_section("OpenAI"):
            if parser.has_option("OpenAI", "API_KEY"):
                k = parser.get("OpenAI", "API_KEY")
                if k: self.openai_key = k
            if parser.has_option("OpenAI", "BASE_URL"):
                u = parser.get("OpenAI", "BASE_URL")
                if u: self.openai_url = u
            if parser.has_option("OpenAI", "MODEL"):
                m = parser.get("OpenAI", "MODEL")
                if m: self.openai_model = m

        if parser.has_section("ChatGPTAccount"):
            if parser.has_option("ChatGPTAccount", "MODEL"):
                m = parser.get("ChatGPTAccount", "MODEL")
                if m: self.chatgpt_account_model = m

        if parser.has_section("CodexCLI"):
            self.codex_cli_path = parser.get("CodexCLI", "EXECUTABLE", fallback=self.codex_cli_path) or self.codex_cli_path
            self.codex_cli_profile = parser.get("CodexCLI", "PROFILE", fallback=self.codex_cli_profile)
            self.codex_cli_model = parser.get("CodexCLI", "MODEL", fallback=self.codex_cli_model) or self.codex_cli_model

        if parser.has_section("ClaudeCode"):
            if parser.has_option("ClaudeCode", "EXECUTABLE"):
                p = parser.get("ClaudeCode", "EXECUTABLE")
                if p: self.claude_code_path = p
            if parser.has_option("ClaudeCode", "MODEL"):
                m = parser.get("ClaudeCode", "MODEL")
                if m: self.claude_code_model = m

        if parser.has_section("AntigravityCLI"):
            if parser.has_option("AntigravityCLI", "EXECUTABLE"):
                p = parser.get("AntigravityCLI", "EXECUTABLE")
                if p: self.antigravity_cli_path = p
            if parser.has_option("AntigravityCLI", "MODEL"):
                m = parser.get("AntigravityCLI", "MODEL")
                if m: self.antigravity_cli_model = m

        if parser.has_section("GeminiCLI"):
            self.gemini_cli_path = parser.get("GeminiCLI", "EXECUTABLE", fallback=self.gemini_cli_path) or self.gemini_cli_path
            self.gemini_cli_model = parser.get("GeminiCLI", "MODEL", fallback=self.gemini_cli_model) or self.gemini_cli_model

        if parser.has_section("QwenCode"):
            self.qwen_code_path = parser.get("QwenCode", "EXECUTABLE", fallback=self.qwen_code_path) or self.qwen_code_path
            self.qwen_code_model = parser.get("QwenCode", "MODEL", fallback=self.qwen_code_model) or self.qwen_code_model

        if parser.has_section("OpenCode"):
            self.opencode_path = parser.get("OpenCode", "EXECUTABLE", fallback=self.opencode_path) or self.opencode_path
            self.opencode_model = parser.get("OpenCode", "MODEL", fallback=self.opencode_model) or self.opencode_model

        if parser.has_section("HermesCLI"):
            self.hermes_cli_path = parser.get("HermesCLI", "EXECUTABLE", fallback=self.hermes_cli_path) or self.hermes_cli_path
            self.hermes_cli_provider = parser.get("HermesCLI", "PROVIDER", fallback=self.hermes_cli_provider)
            self.hermes_cli_model = parser.get("HermesCLI", "MODEL", fallback=self.hermes_cli_model) or self.hermes_cli_model

        if parser.has_section("DeepSeek"):
            if parser.has_option("DeepSeek", "API_KEY"):
                k = parser.get("DeepSeek", "API_KEY")
                if k: self.deepseek_key = k
            if parser.has_option("DeepSeek", "BASE_URL"):
                u = parser.get("DeepSeek", "BASE_URL")
                if u: self.deepseek_url = u
            if parser.has_option("DeepSeek", "MODEL"):
                m = parser.get("DeepSeek", "MODEL")
                if m: self.deepseek_model = m

        if parser.has_section("Anthropic"):
            if parser.has_option("Anthropic", "API_KEY"):
                k = parser.get("Anthropic", "API_KEY")
                if k: self.anthropic_key = k
            if parser.has_option("Anthropic", "BASE_URL"):
                u = parser.get("Anthropic", "BASE_URL")
                if u: self.anthropic_url = u
            if parser.has_option("Anthropic", "MODEL"):
                m = parser.get("Anthropic", "MODEL")
                if m: self.anthropic_model = m

        if parser.has_section("Gemini"):
            if parser.has_option("Gemini", "API_KEY"):
                k = parser.get("Gemini", "API_KEY")
                if k: self.gemini_key = k
            if parser.has_option("Gemini", "MODEL"):
                m = parser.get("Gemini", "MODEL")
                if m: self.gemini_model = m

        for section, prefix in (
            ("OpenRouter", "openrouter"),
            ("Mistral", "mistral"),
            ("Groq", "groq"),
            ("xAI", "xai"),
            ("Cerebras", "cerebras"),
            ("Together", "together"),
            ("Fireworks", "fireworks"),
        ):
            if parser.has_section(section):
                key = parser.get(section, "API_KEY", fallback=getattr(self, prefix + "_key"))
                url = parser.get(section, "BASE_URL", fallback=getattr(self, prefix + "_url"))
                model = parser.get(section, "MODEL", fallback=getattr(self, prefix + "_model"))
                setattr(self, prefix + "_key", key)
                setattr(self, prefix + "_url", url)
                setattr(self, prefix + "_model", model)

        if parser.has_section("Ollama"):
             if parser.has_option("Ollama", "HOST"):
                h = parser.get("Ollama", "HOST")
                if h: self.ollama_host = h.rstrip('/')
                if not self.ollama_host.endswith("/v1"): self.ollama_host += "/v1"
             if parser.has_option("Ollama", "MODEL"):
                m = parser.get("Ollama", "MODEL")
                if m: self.ollama_model = m

        if parser.has_section("LMStudio"):
            if parser.has_option("LMStudio", "BASE_URL"):
                u = parser.get("LMStudio", "BASE_URL")
                if u: self.lmstudio_url = u
            if parser.has_option("LMStudio", "API_KEY"):
                k = parser.get("LMStudio", "API_KEY")
                if k: self.lmstudio_key = k
            if parser.has_option("LMStudio", "MODEL"):
                m = parser.get("LMStudio", "MODEL")
                if m: self.lmstudio_model = m

        if parser.has_section("OpenAICompatible"):
            self.custom_key = parser.get("OpenAICompatible", "API_KEY", fallback="")
            self.custom_url = parser.get("OpenAICompatible", "BASE_URL", fallback="")
            self.custom_model = parser.get("OpenAICompatible", "MODEL_NAME", fallback="")

        if parser.has_section("Fonts"):
            self.ui_font = parser.get("Fonts", "UI_FONT", fallback="'Inter', 'Segoe UI'")
            self.ui_font_size = parser.getint("Fonts", "UI_SIZE", fallback=9)
            self.code_font = parser.get("Fonts", "CODE_FONT", fallback="Consolas")
            self.code_font_size = parser.getint("Fonts", "CODE_SIZE", fallback=10)
            self.markdown_font = parser.get("Fonts", "MD_FONT", fallback="Consolas")
            self.markdown_font_size = parser.getint("Fonts", "MD_SIZE", fallback=10)
            self.highlight_color = parser.get("Fonts", "HIGHLIGHT_COLOR", fallback="#ffaaff")
            if self.highlight_color.strip().lower() == "#325a32":
                # Migrate the former built-in default without affecting custom colors.
                self.highlight_color = "#ffaaff"
            self.indent_guides_enabled = parser.getboolean("Fonts", "INDENT_GUIDES_ENABLED", fallback=True)
            self.indent_guides_color = parser.get("Fonts", "INDENT_GUIDES_COLOR", fallback="#57CFDC")
            self.pseudocode_folding_enabled = parser.getboolean("Fonts", "PSEUDOCODE_FOLDING_ENABLED", fallback=True)
            self.pseudocode_folding_color = parser.get("Fonts", "PSEUDOCODE_FOLDING_COLOR", fallback="#3F3F3F")
            self.argument_name_hints_enabled = parser.getboolean("Fonts", "ARGUMENT_NAME_HINTS_ENABLED", fallback=False)
            self.call_explanations_enabled = parser.getboolean("Fonts", "CALL_EXPLANATIONS_ENABLED", fallback=True)
            self.rust_string_fixups_enabled = parser.getboolean("Fonts", "RUST_STRING_FIXUPS_ENABLED", fallback=True)
            self.zoom_all_views_enabled = parser.getboolean("Fonts", "ZOOM_ALL_VIEWS_ENABLED", fallback=True)

        if parser.has_section("UI"):
            raw_bookmarks = parser.get("UI", "BOOKMARK_ACTIONS", fallback="")
            self.bookmarked_actions = [value.strip() for value in raw_bookmarks.split(",") if value.strip()]

        if parser.has_section("ExternalTools"):
            self.floss_path = parser.get("ExternalTools", "FLOSS_PATH", fallback="")
            self.goresym_path = parser.get("ExternalTools", "GORESYM_PATH", fallback="")
            self.rift_server_url = parser.get("ExternalTools", "RIFT_SERVER_URL", fallback="http://127.0.0.1:5001")
            self.rift_output_folder = parser.get("ExternalTools", "RIFT_OUTPUT_FOLDER", fallback="")
            self.speakeasy_path = parser.get("ExternalTools", "SPEAKEASY_PATH", fallback=self.speakeasy_path)

        if parser.has_section("ExternalAgents"):
            self.mcp_bridge_enabled = parser.getboolean("ExternalAgents", "MCP_BRIDGE_ENABLED", fallback=False)
            self.mcp_bridge_port = parser.getint("ExternalAgents", "MCP_BRIDGE_PORT", fallback=0)
            self.mcp_bridge_token_file = parser.get("ExternalAgents", "MCP_BRIDGE_TOKEN_FILE", fallback="")
            self.mcp_bridge_allow_http = parser.getboolean("ExternalAgents", "MCP_BRIDGE_ALLOW_HTTP", fallback=False)
            self.mcp_bridge_allow_remote_tunnel = parser.getboolean("ExternalAgents", "MCP_BRIDGE_ALLOW_REMOTE_TUNNEL", fallback=False)
            self.mcp_bridge_session_dir = parser.get("ExternalAgents", "MCP_BRIDGE_SESSION_DIR", fallback=self.mcp_bridge_session_dir)

        if parser.has_section("Permissions"):
            self.permission_write_idb = parser.get("Permissions", "WRITE_IDB", fallback="ask")
            self.permission_patch_bytes = parser.get("Permissions", "PATCH_BYTES", fallback="ask")
            self.permission_execute = parser.get("Permissions", "EXECUTE", fallback="off")
            self.permission_filesystem = parser.get("Permissions", "FILESYSTEM", fallback="ask")
            self.permission_runtime = parser.get("Permissions", "RUNTIME", fallback="ask")
            self.permission_network = parser.get("Permissions", "NETWORK", fallback="off")

        if parser.has_section("RuntimeArtifacts"):
            self.runtime_artifact_dir = parser.get("RuntimeArtifacts", "ARTIFACT_DIR", fallback=self.runtime_artifact_dir)
            self.runtime_auto_load_last = parser.getboolean("RuntimeArtifacts", "AUTO_LOAD_LAST", fallback=True)
            self.coverage_overlay_enabled = parser.getboolean("RuntimeArtifacts", "COVERAGE_OVERLAY_ENABLED", fallback=True)
            self.coverage_color = parser.get("RuntimeArtifacts", "COVERAGE_COLOR", fallback="#2D7D46")
            self.speakeasy_timeout = parser.getint("RuntimeArtifacts", "SPEAKEASY_TIMEOUT", fallback=60)
            self.speakeasy_max_api_count = parser.getint("RuntimeArtifacts", "SPEAKEASY_MAX_API_COUNT", fallback=10000)
            self.speakeasy_snapshot_memory = parser.getboolean("RuntimeArtifacts", "SPEAKEASY_SNAPSHOT_MEMORY", fallback=True)
            self.speakeasy_dropped_files = parser.getboolean("RuntimeArtifacts", "SPEAKEASY_DROPPED_FILES", fallback=True)
            self.speakeasy_default_arch = parser.get("RuntimeArtifacts", "SPEAKEASY_DEFAULT_ARCH", fallback="")

        if parser.has_section("Analysis"):
            self.batch_size = parser.getint("Analysis", "BATCH_SIZE", fallback=10)
            self.parallel_workers = parser.getint("Analysis", "WORKERS", fallback=1)
            self.rename_prefix = parser.get("Analysis", "RENAME_PREFIX", fallback="")
            self.function_prefix = parser.get("Analysis", "FUNCTION_PREFIX", fallback="")
            self.use_rename_prefix = parser.getboolean("Analysis", "USE_PREFIX", fallback=False)
            self.use_bulk_prefix = parser.getboolean("Analysis", "USE_BULK_PREFIX", fallback=False)
            self.filter_system = parser.getboolean("Analysis", "FILTER_SYS", fallback=True)
            self.filter_empty = parser.getboolean("Analysis", "FILTER_EMPTY", fallback=True)
            self.cooldown_seconds = parser.getint("Analysis", "COOLDOWN_SECONDS", fallback=0)
            self.asm_max_lines = parser.getint("Analysis", "ASM_MAX_LINES", fallback=25)
            self.force_bulk_rename = parser.getboolean("Analysis", "FORCE_RENAME", fallback=False)
            self.bulk_force_rename_sub = parser.getboolean("Analysis", "BULK_FORCE_RENAME_SUB", fallback=False)
            self.bulk_append_address = parser.getboolean("Analysis", "BULK_APPEND_ADDR", fallback=False)
            self.bulk_use_0x = parser.getboolean("Analysis", "BULK_USE_0X", fallback=False)
            self.rename_append_address = parser.getboolean("Analysis", "RENAME_APPEND_ADDR", fallback=False)
            self.rename_use_0x = parser.getboolean("Analysis", "RENAME_USE_0X", fallback=False)
            self.deep_use_prefix = parser.getboolean("Analysis", "DEEP_USE_PREFIX", fallback=False)
            self.deep_prefix = parser.get("Analysis", "DEEP_PREFIX", fallback="")
            self.deep_append_address = parser.getboolean("Analysis", "DEEP_APPEND_ADDR", fallback=True)
            self.deep_use_0x = parser.getboolean("General", "deep_use_0x", fallback=False)
            self.analyzer_use_prefix = parser.getboolean("General", "analyzer_use_prefix", fallback=False)
            self.analyzer_prefix = parser.get("General", "analyzer_prefix", fallback="")
            self.analyzer_append_address = parser.getboolean("General", "analyzer_append_address", fallback=True)
            self.var_auto_apply = parser.getboolean("General", "var_auto_apply", fallback=True)
            self.var_force_rename = parser.getboolean("Analysis", "VAR_FORCE_RENAME", fallback=False)
            self.auto_apply_bulk = parser.getboolean("Analysis", "BULK_AUTO_APPLY", fallback=True)
            self.rename_cache_enabled = parser.getboolean("Analysis", "RENAME_CACHE_ENABLED", fallback=True)
            self.rename_cache_path = parser.get("Analysis", "RENAME_CACHE_PATH", fallback=self.rename_cache_path)
            
            # Specifics
            self.bulk_batch_size = parser.getint("Analysis", "BULK_BATCH_SIZE", fallback=10)
            self.bulk_parallel_workers = parser.getint("Analysis", "BULK_WORKERS", fallback=5)
            self.bulk_cooldown = parser.getint("Analysis", "BULK_COOLDOWN", fallback=0)
            self.bulk_asm_max = parser.getint("Analysis", "BULK_ASM_MAX", fallback=25)
            
            self.var_batch_size = parser.getint("Analysis", "VAR_BATCH_SIZE", fallback=5)
            self.var_parallel_workers = parser.getint("Analysis", "VAR_WORKERS", fallback=3)
            self.var_cooldown = parser.getint("Analysis", "VAR_COOLDOWN", fallback=0)
            self.var_asm_max = parser.getint("Analysis", "VAR_ASM_MAX", fallback=25)
            
            self.analyze_parallel_workers = parser.getint("Analysis", "ANALYZE_WORKERS", fallback=5)
            self.analyze_batch_size = parser.getint("Analysis", "ANALYZE_BATCH_SIZE", fallback=10)
            self.analyze_cooldown = parser.getint("Analysis", "ANALYZE_COOLDOWN", fallback=0)

            # Deep Analyzer
            self.deep_batch_size = parser.getint("Analysis", "DEEP_BATCH_SIZE", fallback=10)
            self.deep_parallel_workers = parser.getint("Analysis", "DEEP_WORKERS", fallback=1)
            self.deep_cooldown = parser.getint("Analysis", "DEEP_COOLDOWN", fallback=0)
            self.deep_max_lines = parser.getint("Analysis", "DEEP_MAX_LINES", fallback=200)

            # Autonomous Agent
            self.agent_cooldown = parser.getint("Analysis", "AGENT_COOLDOWN", fallback=240)

            # Limits
            self.max_graph_nodes = parser.getint("Analysis", "MAX_GRAPH_NODES", fallback=500)
            self.max_graph_depth = parser.getint("Analysis", "MAX_GRAPH_DEPTH", fallback=15)
            self.max_callees_per_node = parser.getint("Analysis", "MAX_CALLEES", fallback=64)
            self.max_queue_size = parser.getint("Analysis", "MAX_QUEUE", fallback=5000)

            # Thresholds
            self.high_confidence_threshold = parser.getint("Analysis", "HIGH_CONF_THRESH", fallback=75)
            self.min_coverage_for_report = parser.getint("Analysis", "MIN_COV_REPORT", fallback=80)
            self.malicious_confidence_cutoff = parser.getint("Analysis", "MAL_CONF_CUTOFF", fallback=75)
            self.max_graph_ascii_lines = parser.getint("Analysis", "MAX_GRAPH_ASCII", fallback=2500)

            self.deep_do_var_rename = parser.getboolean("Analysis", "DEEP_VAR_RENAME", fallback=True)
            self.deep_do_func_comment = parser.getboolean("Analysis", "DEEP_FUNC_COMMENT", fallback=True)
            self.deep_do_analysis_rename = parser.getboolean("Analysis", "DEEP_ANALYSIS_RENAME", fallback=True)
            self.deep_do_refinement = parser.getboolean("Analysis", "DEEP_REFINEMENT", fallback=True)
            self.deep_do_bottom_up_rename = parser.getboolean("Analysis", "DEEP_BOTTOM_UP_RENAME", fallback=True)

            self.show_pro_tip = parser.getboolean("Analysis", "SHOW_PRO_TIP", fallback=True)

    def reload(self):
        new = type(self)()  # create fresh config from disk
        self.__dict__.update(new.__dict__)

    def save(self):
        parser = configparser.ConfigParser()
        parser.optionxform = str

        # Do not read existing file to avoid carrying over old/unused attributes
        # if os.path.exists(self.config_path):
        #     parser.read(self.config_path, encoding="utf-8")

        if not parser.has_section("Genesect"): parser.add_section("Genesect")
        parser.set("Genesect", "MODEL", self.model)
        parser.set("Genesect", "PROXY", self.proxy)
        parser.set("Genesect", "PROVIDER", self.active_provider)
        parser.set("Genesect", "REQUEST_TIMEOUT", str(self.request_timeout_seconds))
        parser.set("Genesect", "MAX_COMPLETION_TOKENS", str(self.request_max_completion_tokens))
        parser.set("Genesect", "CONTEXT_WINDOW_TOKENS", str(self.request_context_window_tokens))
        parser.set("Genesect", "TEMPERATURE", str(self.request_temperature))
        parser.set("Genesect", "RETRY_ATTEMPTS", str(self.request_retry_attempts))
        parser.set("Genesect", "RETRY_BACKOFF", str(self.request_retry_backoff_seconds))

        if not parser.has_section("OpenAI"): parser.add_section("OpenAI")
        parser.set("OpenAI", "API_KEY", self.openai_key)
        parser.set("OpenAI", "BASE_URL", self.openai_url)
        parser.set("OpenAI", "MODEL", self.openai_model)

        if not parser.has_section("ChatGPTAccount"): parser.add_section("ChatGPTAccount")
        parser.set("ChatGPTAccount", "MODEL", self.chatgpt_account_model)

        if not parser.has_section("CodexCLI"): parser.add_section("CodexCLI")
        parser.set("CodexCLI", "EXECUTABLE", self.codex_cli_path)
        parser.set("CodexCLI", "PROFILE", self.codex_cli_profile)
        parser.set("CodexCLI", "MODEL", self.codex_cli_model)

        if not parser.has_section("ClaudeCode"): parser.add_section("ClaudeCode")
        parser.set("ClaudeCode", "EXECUTABLE", self.claude_code_path)
        parser.set("ClaudeCode", "MODEL", self.claude_code_model)

        if not parser.has_section("AntigravityCLI"): parser.add_section("AntigravityCLI")
        parser.set("AntigravityCLI", "EXECUTABLE", self.antigravity_cli_path)
        parser.set("AntigravityCLI", "MODEL", self.antigravity_cli_model)

        if not parser.has_section("GeminiCLI"): parser.add_section("GeminiCLI")
        parser.set("GeminiCLI", "EXECUTABLE", self.gemini_cli_path)
        parser.set("GeminiCLI", "MODEL", self.gemini_cli_model)

        if not parser.has_section("QwenCode"): parser.add_section("QwenCode")
        parser.set("QwenCode", "EXECUTABLE", self.qwen_code_path)
        parser.set("QwenCode", "MODEL", self.qwen_code_model)

        if not parser.has_section("OpenCode"): parser.add_section("OpenCode")
        parser.set("OpenCode", "EXECUTABLE", self.opencode_path)
        parser.set("OpenCode", "MODEL", self.opencode_model)

        if not parser.has_section("HermesCLI"): parser.add_section("HermesCLI")
        parser.set("HermesCLI", "EXECUTABLE", self.hermes_cli_path)
        parser.set("HermesCLI", "PROVIDER", self.hermes_cli_provider)
        parser.set("HermesCLI", "MODEL", self.hermes_cli_model)

        if not parser.has_section("DeepSeek"): parser.add_section("DeepSeek")
        parser.set("DeepSeek", "API_KEY", self.deepseek_key)
        parser.set("DeepSeek", "BASE_URL", self.deepseek_url)
        parser.set("DeepSeek", "MODEL", self.deepseek_model)

        if not parser.has_section("Anthropic"): parser.add_section("Anthropic")
        parser.set("Anthropic", "API_KEY", self.anthropic_key)
        parser.set("Anthropic", "BASE_URL", self.anthropic_url)
        parser.set("Anthropic", "MODEL", self.anthropic_model)

        if not parser.has_section("Gemini"): parser.add_section("Gemini")
        parser.set("Gemini", "API_KEY", self.gemini_key)
        parser.set("Gemini", "MODEL", self.gemini_model)

        for section, prefix in (
            ("OpenRouter", "openrouter"),
            ("Mistral", "mistral"),
            ("Groq", "groq"),
            ("xAI", "xai"),
            ("Cerebras", "cerebras"),
            ("Together", "together"),
            ("Fireworks", "fireworks"),
        ):
            if not parser.has_section(section): parser.add_section(section)
            parser.set(section, "API_KEY", getattr(self, prefix + "_key"))
            parser.set(section, "BASE_URL", getattr(self, prefix + "_url"))
            parser.set(section, "MODEL", getattr(self, prefix + "_model"))

        if not parser.has_section("Ollama"): parser.add_section("Ollama")
        parser.set("Ollama", "HOST", self.ollama_host)
        parser.set("Ollama", "MODEL", self.ollama_model)

        if not parser.has_section("LMStudio"): parser.add_section("LMStudio")
        parser.set("LMStudio", "BASE_URL", self.lmstudio_url)
        parser.set("LMStudio", "API_KEY", self.lmstudio_key)
        parser.set("LMStudio", "MODEL", self.lmstudio_model)

        if not parser.has_section("OpenAICompatible"): parser.add_section("OpenAICompatible")
        parser.set("OpenAICompatible", "API_KEY", self.custom_key)
        parser.set("OpenAICompatible", "BASE_URL", self.custom_url)
        parser.set("OpenAICompatible", "MODEL_NAME", self.custom_model)

        if not parser.has_section("ExternalTools"): parser.add_section("ExternalTools")
        parser.set("ExternalTools", "FLOSS_PATH", self.floss_path)
        parser.set("ExternalTools", "GORESYM_PATH", self.goresym_path)
        parser.set("ExternalTools", "RIFT_SERVER_URL", self.rift_server_url)
        parser.set("ExternalTools", "RIFT_OUTPUT_FOLDER", self.rift_output_folder)
        parser.set("ExternalTools", "SPEAKEASY_PATH", self.speakeasy_path)

        if not parser.has_section("ExternalAgents"): parser.add_section("ExternalAgents")
        parser.set("ExternalAgents", "MCP_BRIDGE_ENABLED", str(self.mcp_bridge_enabled))
        parser.set("ExternalAgents", "MCP_BRIDGE_PORT", str(self.mcp_bridge_port))
        parser.set("ExternalAgents", "MCP_BRIDGE_TOKEN_FILE", self.mcp_bridge_token_file)
        parser.set("ExternalAgents", "MCP_BRIDGE_ALLOW_HTTP", str(self.mcp_bridge_allow_http))
        parser.set("ExternalAgents", "MCP_BRIDGE_ALLOW_REMOTE_TUNNEL", str(self.mcp_bridge_allow_remote_tunnel))
        parser.set("ExternalAgents", "MCP_BRIDGE_SESSION_DIR", self.mcp_bridge_session_dir)

        if not parser.has_section("Permissions"): parser.add_section("Permissions")
        parser.set("Permissions", "WRITE_IDB", self.permission_write_idb)
        parser.set("Permissions", "PATCH_BYTES", self.permission_patch_bytes)
        parser.set("Permissions", "EXECUTE", self.permission_execute)
        parser.set("Permissions", "FILESYSTEM", self.permission_filesystem)
        parser.set("Permissions", "RUNTIME", self.permission_runtime)
        parser.set("Permissions", "NETWORK", self.permission_network)

        if not parser.has_section("RuntimeArtifacts"): parser.add_section("RuntimeArtifacts")
        parser.set("RuntimeArtifacts", "ARTIFACT_DIR", self.runtime_artifact_dir)
        parser.set("RuntimeArtifacts", "AUTO_LOAD_LAST", str(self.runtime_auto_load_last))
        parser.set("RuntimeArtifacts", "COVERAGE_OVERLAY_ENABLED", str(self.coverage_overlay_enabled))
        parser.set("RuntimeArtifacts", "COVERAGE_COLOR", self.coverage_color)
        parser.set("RuntimeArtifacts", "SPEAKEASY_TIMEOUT", str(self.speakeasy_timeout))
        parser.set("RuntimeArtifacts", "SPEAKEASY_MAX_API_COUNT", str(self.speakeasy_max_api_count))
        parser.set("RuntimeArtifacts", "SPEAKEASY_SNAPSHOT_MEMORY", str(self.speakeasy_snapshot_memory))
        parser.set("RuntimeArtifacts", "SPEAKEASY_DROPPED_FILES", str(self.speakeasy_dropped_files))
        parser.set("RuntimeArtifacts", "SPEAKEASY_DEFAULT_ARCH", self.speakeasy_default_arch)

        if not parser.has_section("Fonts"): parser.add_section("Fonts")
        parser.set("Fonts", "UI_FONT", self.ui_font)
        parser.set("Fonts", "UI_SIZE", str(self.ui_font_size))
        parser.set("Fonts", "CODE_FONT", self.code_font)
        parser.set("Fonts", "CODE_SIZE", str(self.code_font_size))
        parser.set("Fonts", "MD_FONT", self.markdown_font)
        parser.set("Fonts", "MD_SIZE", str(self.markdown_font_size))
        parser.set("Fonts", "HIGHLIGHT_COLOR", self.highlight_color)
        parser.set("Fonts", "INDENT_GUIDES_ENABLED", str(self.indent_guides_enabled))
        parser.set("Fonts", "INDENT_GUIDES_COLOR", self.indent_guides_color)
        parser.set("Fonts", "PSEUDOCODE_FOLDING_ENABLED", str(self.pseudocode_folding_enabled))
        parser.set("Fonts", "PSEUDOCODE_FOLDING_COLOR", self.pseudocode_folding_color)
        parser.set("Fonts", "ARGUMENT_NAME_HINTS_ENABLED", str(self.argument_name_hints_enabled))
        parser.set("Fonts", "CALL_EXPLANATIONS_ENABLED", str(self.call_explanations_enabled))
        parser.set("Fonts", "RUST_STRING_FIXUPS_ENABLED", str(self.rust_string_fixups_enabled))
        parser.set("Fonts", "ZOOM_ALL_VIEWS_ENABLED", str(self.zoom_all_views_enabled))

        if not parser.has_section("UI"): parser.add_section("UI")
        parser.set("UI", "BOOKMARK_ACTIONS", ",".join(self.bookmarked_actions))

        if not parser.has_section("Analysis"): parser.add_section("Analysis")
        parser.set("Analysis", "BATCH_SIZE", str(self.batch_size))
        parser.set("Analysis", "WORKERS", str(self.parallel_workers))
        parser.set("Analysis", "RENAME_PREFIX", self.rename_prefix)
        parser.set("Analysis", "FUNCTION_PREFIX", self.function_prefix)
        parser.set("Analysis", "USE_PREFIX", str(self.use_rename_prefix))
        parser.set("Analysis", "USE_BULK_PREFIX", str(self.use_bulk_prefix))
        parser.set("Analysis", "FILTER_SYS", str(self.filter_system))
        parser.set("Analysis", "FILTER_EMPTY", str(self.filter_empty))
        parser.set("Analysis", "COOLDOWN_SECONDS", str(self.cooldown_seconds))
        parser.set("Analysis", "ASM_MAX_LINES", str(self.asm_max_lines))
        parser.set("Analysis", "FORCE_RENAME", str(self.force_bulk_rename))
        parser.set("Analysis", "BULK_FORCE_RENAME_SUB", str(self.bulk_force_rename_sub))
        parser.set("Analysis", "BULK_APPEND_ADDR", str(self.bulk_append_address))
        parser.set("Analysis", "BULK_USE_0X", str(self.bulk_use_0x))
        parser.set("Analysis", "RENAME_APPEND_ADDR", str(self.rename_append_address))
        parser.set("Analysis", "RENAME_USE_0X", str(self.rename_use_0x))
        parser.set("Analysis", "DEEP_USE_PREFIX", str(self.deep_use_prefix))
        parser.set("Analysis", "DEEP_PREFIX", self.deep_prefix)
        parser.set("Analysis", "DEEP_APPEND_ADDR", str(self.deep_append_address))
        if not parser.has_section("General"): parser.add_section("General")
        parser.set("General", "deep_use_0x", str(self.deep_use_0x))
        parser.set("General", "analyzer_use_prefix", str(self.analyzer_use_prefix))
        parser.set("General", "analyzer_prefix", str(self.analyzer_prefix))
        parser.set("General", "analyzer_append_address", str(self.analyzer_append_address))
        parser.set("General", "var_auto_apply", str(self.var_auto_apply))
        parser.set("Analysis", "VAR_FORCE_RENAME", str(self.var_force_rename))
        parser.set("Analysis", "BULK_AUTO_APPLY", str(self.auto_apply_bulk))
        
        parser.set("Analysis", "BULK_BATCH_SIZE", str(self.bulk_batch_size))
        parser.set("Analysis", "BULK_WORKERS", str(self.bulk_parallel_workers))
        parser.set("Analysis", "BULK_COOLDOWN", str(self.bulk_cooldown))
        parser.set("Analysis", "BULK_ASM_MAX", str(self.bulk_asm_max))
        
        parser.set("Analysis", "VAR_BATCH_SIZE", str(self.var_batch_size))
        parser.set("Analysis", "VAR_WORKERS", str(self.var_parallel_workers))
        parser.set("Analysis", "VAR_COOLDOWN", str(self.var_cooldown))
        parser.set("Analysis", "VAR_ASM_MAX", str(self.var_asm_max))
        
        parser.set("Analysis", "ANALYZE_BATCH_SIZE", str(self.analyze_batch_size))
        parser.set("Analysis", "ANALYZE_WORKERS", str(self.analyze_parallel_workers))
        parser.set("Analysis", "ANALYZE_COOLDOWN", str(self.analyze_cooldown))

        # Deep Analyzer
        parser.set("Analysis", "DEEP_BATCH_SIZE", str(self.deep_batch_size))
        parser.set("Analysis", "DEEP_WORKERS", str(self.deep_parallel_workers))
        parser.set("Analysis", "DEEP_COOLDOWN", str(self.deep_cooldown))
        parser.set("Analysis", "DEEP_MAX_LINES", str(self.deep_max_lines))

        # Autonomous Agent
        parser.set("Analysis", "AGENT_COOLDOWN", str(self.agent_cooldown))

        parser.set("Analysis", "MAX_GRAPH_NODES", str(self.max_graph_nodes))
        parser.set("Analysis", "MAX_GRAPH_DEPTH", str(self.max_graph_depth))
        parser.set("Analysis", "MAX_CALLEES", str(self.max_callees_per_node))
        parser.set("Analysis", "MAX_QUEUE", str(self.max_queue_size))
        
        parser.set("Analysis", "HIGH_CONF_THRESH", str(self.high_confidence_threshold))
        parser.set("Analysis", "MIN_COV_REPORT", str(self.min_coverage_for_report))
        parser.set("Analysis", "MAL_CONF_CUTOFF", str(self.malicious_confidence_cutoff))
        parser.set("Analysis", "MAX_GRAPH_ASCII", str(self.max_graph_ascii_lines))

        parser.set("Analysis", "DEEP_VAR_RENAME", str(self.deep_do_var_rename))
        parser.set("Analysis", "DEEP_FUNC_COMMENT", str(self.deep_do_func_comment))
        parser.set("Analysis", "DEEP_ANALYSIS_RENAME", str(self.deep_do_analysis_rename))
        parser.set("Analysis", "DEEP_REFINEMENT", str(self.deep_do_refinement))
        parser.set("Analysis", "DEEP_BOTTOM_UP_RENAME", str(self.deep_do_bottom_up_rename))

        parser.set("Analysis", "SHOW_PRO_TIP", str(self.show_pro_tip))
        parser.set("Analysis", "RENAME_CACHE_ENABLED", str(self.rename_cache_enabled))
        parser.set("Analysis", "RENAME_CACHE_PATH", str(self.rename_cache_path))

        # Try saving. Handle Permission Denied (e.g. Program Files) by falling back to user home.
        success = False
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                parser.write(f)
            LOGGER.log(f"Configuration saved to {self.config_path}")
            success = True
        except (IOError, OSError) as e:
            if self.config_path != self.user_config_path:
                LOGGER.log(f"Permission denied writing to {self.config_path}. Falling back to user home...")
                self.config_path = self.user_config_path
                try:
                    with open(self.config_path, 'w', encoding='utf-8') as f:
                        parser.write(f)
                    LOGGER.log(f"Configuration saved to {self.config_path}")
                    success = True
                    if QtWidgets:
                        QtWidgets.QMessageBox.information(
                            None,
                            "Genesect - Permission Notice",
                            f"The configuration file was saved to your home directory:\n{self.config_path}\n\n"
                            "This happened because Genesect does not have permission to write to the "
                            "IDA installation folder. Your settings will be loaded from this home directory location in the future."
                        )
                except Exception as e2:
                    LOGGER.log(f"Failed to save to user home: {e2}")
            else:
                LOGGER.log(f"Error saving config: {e}")

        if not success:
             LOGGER.log("CRITICAL: Could not save configuration to any location.")


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_LoggerBase = QtCore.QObject if QtCore else object


class PseudoLogger(_LoggerBase):
    if Signal:
        log_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.logs = []

    def log(self, message):
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            entry = f"[{timestamp}] {message}"
            self.logs.append(entry)

            if hasattr(self, 'log_signal'):
                self.log_signal.emit(entry)
        except:
            print(message)


# Module singletons
LOGGER = PseudoLogger()
CONFIG = Config()
