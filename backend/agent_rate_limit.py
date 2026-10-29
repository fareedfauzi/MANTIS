import os
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import HTTPException


_WINDOWS: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def check_rate_limit(token_tag: str, tool: str) -> None:
    window_seconds = max(1, _int_env("MANTIS_AGENT_RATE_WINDOW_SECONDS", 60))
    max_calls = max(1, _int_env("MANTIS_AGENT_RATE_MAX_CALLS", 60))
    now = time.time()
    key = (token_tag or "unknown", tool or "unknown")
    bucket = _WINDOWS[key]
    while bucket and now - bucket[0] > window_seconds:
        bucket.popleft()
    if len(bucket) >= max_calls:
        raise HTTPException(status_code=429, detail=f"Agent tool rate limit exceeded for {tool}.")
    bucket.append(now)
