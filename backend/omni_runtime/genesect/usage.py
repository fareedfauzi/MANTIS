"""Token / cost accounting and budget enforcement for AI requests.

Providers reached through Genesect return plain text, so token counts here are
*estimates* (about 3.5 characters per token for code-heavy prompts). They are good
enough to compare runs and to stop a batch from running away, not for invoicing.

Only "billable" providers count against the budget. Local models (Ollama, LM Studio,
localhost OpenAI-compatible servers) and signed-in CLI/account providers are tracked
but never block a run, so a budget cap can fall back to a free local model.
"""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

CHARS_PER_TOKEN = 3.5

FREE_PROVIDERS = {"Ollama", "LMStudio", "ChatGPTAccount", "ClaudeCode", "AntigravityCLI", "OpenCode", "CopilotCLI"}

# (model-name prefix, USD per 1M input tokens, USD per 1M output tokens).
# Approximate public list prices; first matching prefix wins, so keep specific ones first.
# Override or extend by dropping a pricing.json ({"prefix": [in, out]}) next to settings.json.
DEFAULT_PRICES = [
    ("gpt-4o-mini", 0.15, 0.60),
    ("gpt-4o", 2.50, 10.00),
    ("o3-mini", 1.10, 4.40),
    ("o1", 15.00, 60.00),
    ("claude-3-5-haiku", 0.80, 4.00),
    ("claude-3-haiku", 0.25, 1.25),
    ("claude-3-opus", 15.00, 75.00),
    ("claude-opus", 15.00, 75.00),
    ("claude-3-7-sonnet", 3.00, 15.00),
    ("claude-3-5-sonnet", 3.00, 15.00),
    ("claude-sonnet", 3.00, 15.00),
    ("deepseek-reasoner", 0.55, 2.19),
    ("deepseek-chat", 0.27, 1.10),
    ("gemini-2.0-flash-lite", 0.075, 0.30),
    ("gemini-2.0-flash", 0.10, 0.40),
    ("gemini-1.5-flash", 0.075, 0.30),
    ("gemini-1.5-pro", 1.25, 5.00),
    ("mistral-large", 2.00, 6.00),
    ("mistral-small", 0.20, 0.60),
    ("codestral", 0.30, 0.90),
    ("llama-3.3-70b", 0.59, 0.79),
    ("llama-3.1-8b", 0.05, 0.08),
]


class BudgetExceeded(RuntimeError):
    """Raised when the token budget is spent and there is nowhere free to fall back to."""


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, int(len(text) / CHARS_PER_TOKEN + 0.5))


def _is_local_url(url: str) -> bool:
    host = (urlparse(url if "://" in (url or "") else "//" + (url or "")).hostname or "").lower()
    if host in ("localhost", ""):
        return host == "localhost"
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return host.endswith(".local") or host.endswith(".lan")


def is_billable(provider: str, api_url: str = "") -> bool:
    if provider in FREE_PROVIDERS:
        return False
    if provider == "OpenAICompatible" and _is_local_url(api_url):
        return False
    return True


def load_price_overrides(path) -> list:
    """Read ``pricing.json`` if present; malformed files are ignored."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = []
    if isinstance(data, dict):
        for prefix, pair in data.items():
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                try:
                    rows.append((str(prefix).lower(), float(pair[0]), float(pair[1])))
                except (TypeError, ValueError):
                    continue
    return rows


def price_for(model: str, overrides: Optional[list] = None) -> Optional[tuple]:
    name = (model or "").lower()
    for prefix, price_in, price_out in [*(overrides or []), *DEFAULT_PRICES]:
        if name.startswith(prefix) or ("/" in name and name.split("/", 1)[1].startswith(prefix)):
            return price_in, price_out
    return None


class UsageTracker:
    def __init__(self, budget_tokens: int = 0, price_overrides: Optional[list] = None):
        self.budget_tokens = max(0, int(budget_tokens or 0))
        self.price_overrides = price_overrides or []
        self.requests = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.billable_tokens = 0
        self.cost_usd = 0.0
        self.unpriced_models: set = set()
        self.exhausted = False
        self.cache_requests_saved = 0
        self._by_profile: dict = defaultdict(lambda: {"requests": 0, "input_tokens": 0, "output_tokens": 0})

    def allowed(self, provider: str, api_url: str = "") -> bool:
        """May this provider be called right now?"""
        if not is_billable(provider, api_url):
            return True
        return not self.exhausted

    def record(self, provider: str, model: str, api_url: str, input_text: str, output_text: str) -> None:
        tokens_in = estimate_tokens(input_text)
        tokens_out = estimate_tokens(output_text)
        self.requests += 1
        self.input_tokens += tokens_in
        self.output_tokens += tokens_out
        entry = self._by_profile["%s / %s" % (provider, model or "default")]
        entry["requests"] += 1
        entry["input_tokens"] += tokens_in
        entry["output_tokens"] += tokens_out
        if is_billable(provider, api_url):
            self.billable_tokens += tokens_in + tokens_out
            price = price_for(model, self.price_overrides)
            if price:
                self.cost_usd += (tokens_in * price[0] + tokens_out * price[1]) / 1_000_000.0
            else:
                self.unpriced_models.add(model or "default")
            if self.budget_tokens and self.billable_tokens >= self.budget_tokens:
                self.exhausted = True

    def snapshot(self) -> dict:
        return {
            "estimated": True,
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            "billable_tokens": self.billable_tokens,
            "estimated_cost_usd": round(self.cost_usd, 4),
            "unpriced_models": sorted(self.unpriced_models),
            "budget_tokens": self.budget_tokens,
            "budget_exhausted": self.exhausted,
            "by_profile": {k: dict(v) for k, v in self._by_profile.items()},
        }


def format_tokens(value: int) -> str:
    value = int(value or 0)
    if value >= 1_000_000:
        return "%.2fM" % (value / 1_000_000)
    if value >= 1_000:
        return "%.1fk" % (value / 1_000)
    return str(value)


def describe_usage(usage: dict) -> str:
    """One-line summary for logs and the status bar."""
    if not usage:
        return "no AI requests"
    text = "%d request(s), ~%s in / ~%s out tokens" % (
        usage.get("requests", 0), format_tokens(usage.get("input_tokens", 0)), format_tokens(usage.get("output_tokens", 0)))
    if usage.get("billable_tokens"):
        cost = usage.get("estimated_cost_usd", 0.0)
        suffix = "+" if usage.get("unpriced_models") else ""
        text += ", est. cost $%.2f%s" % (cost, suffix)
    if usage.get("budget_exhausted"):
        text += " [token budget reached]"
    return text
