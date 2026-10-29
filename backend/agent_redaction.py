import re
from typing import Any


MASK = "********"

SECRET_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|cookie|authorization|auth[_-]?header|session)", re.I)
SECRET_VALUE_RE = re.compile(
    r"(?i)(Bearer\s+[A-Za-z0-9._\-]{12,}|"
    r"[A-Za-z0-9_\-]{20,}:[A-Za-z0-9_\-]{20,}|"
    r"sk-[A-Za-z0-9_\-]{20,}|"
    r"ghp_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def redact(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                out[key] = MASK if item else ""
            else:
                out[key] = redact(item, depth + 1)
        return out
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value[:200]]
    if isinstance(value, tuple):
        return tuple(redact(item, depth + 1) for item in value[:200])
    if isinstance(value, str):
        return SECRET_VALUE_RE.sub(MASK, value)
    return value


def compact_summary(value: Any, limit: int = 1200) -> str:
    text = str(redact(value))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]
