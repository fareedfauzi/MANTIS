"""Login throttling for the MANTIS team server.

`/api/auth/login` had no failed-attempt limit at all: a client could keep
guessing passwords for as long as it liked, and each guess only cost the server
one PBKDF2 hash. This module adds an in-process, memory-bounded throttle:

* per (username, client address): 5 failures in 10 minutes, then a cooldown that
  starts at 60s and doubles with every further failure, capped at 15 minutes;
* per username across all addresses: 50 failures in 10 minutes, so a distributed
  attempt against one account still slows down.

A successful login clears that key. Decisions are deliberately cheap and local:
no database write on the login path, no lock held across hashing. Failures are
counted, not logged with the attempted password (never stored).

Env: MANTIS_LOGIN_MAX_FAILURES (default 5), MANTIS_LOGIN_WINDOW_S (600),
MANTIS_LOGIN_MAX_KEYS (20000) to bound memory.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Dict, Tuple

_DEFAULT_MAX_FAILURES = 5
_DEFAULT_WINDOW_S = 600
_DEFAULT_MAX_KEYS = 20000
_USER_WIDE_FACTOR = 10          # username-wide allowance = per-key allowance * this
_MAX_COOLDOWN_S = 900


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "").strip() or default))
    except (TypeError, ValueError):
        return default


class LoginThrottle:
    def __init__(self, max_failures: int = _DEFAULT_MAX_FAILURES,
                 window_s: int = _DEFAULT_WINDOW_S, max_keys: int = _DEFAULT_MAX_KEYS):
        self.max_failures = max_failures
        self.window_s = window_s
        self.max_keys = max_keys
        self.user_wide_limit = max_failures * _USER_WIDE_FACTOR
        self._lock = threading.Lock()
        # key -> [failure timestamps], insertion-ordered for cheap eviction
        self._fails: Dict[Tuple[str, str], list] = {}

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _keys(username: str, client: str) -> Tuple[Tuple[str, str], Tuple[str, str]]:
        user = (username or "").strip().lower()[:128]
        addr = (client or "").strip()[:64]
        return (user, addr), (user, "*")

    def _recent(self, key, now: float) -> list:
        stamps = self._fails.get(key)
        if not stamps:
            return []
        cutoff = now - self.window_s
        return [t for t in stamps if t > cutoff]

    def _evict_locked(self) -> None:
        if len(self._fails) <= self.max_keys:
            return
        # Drop the oldest-inserted keys until back under the cap.
        excess = len(self._fails) - self.max_keys
        for key in list(self._fails.keys())[:excess]:
            self._fails.pop(key, None)

    # -- public API ------------------------------------------------------
    def retry_after(self, username: str, client: str) -> int:
        """Seconds until this caller may try again; 0 when not throttled."""
        now = time.monotonic()
        per_key, user_wide = self._keys(username, client)
        with self._lock:
            worst = 0
            for key, limit in ((per_key, self.max_failures), (user_wide, self.user_wide_limit)):
                recent = self._recent(key, now)
                if len(recent) < limit:
                    continue
                over = len(recent) - limit
                cooldown = min(_MAX_COOLDOWN_S, 60 * (2 ** min(over, 8)))
                ready_at = recent[-1] + cooldown
                worst = max(worst, int(ready_at - now) + 1)
            return max(0, worst)

    def register_failure(self, username: str, client: str) -> int:
        now = time.monotonic()
        per_key, user_wide = self._keys(username, client)
        with self._lock:
            for key in (per_key, user_wide):
                recent = self._recent(key, now)
                recent.append(now)
                self._fails[key] = recent
            self._evict_locked()
        return self.retry_after(username, client)

    def reset(self, username: str, client: str) -> None:
        per_key, _user_wide = self._keys(username, client)
        with self._lock:
            self._fails.pop(per_key, None)

    def clear(self) -> None:
        with self._lock:
            self._fails.clear()


_throttle: LoginThrottle | None = None
_throttle_lock = threading.Lock()


def get_throttle() -> LoginThrottle:
    global _throttle
    with _throttle_lock:
        if _throttle is None:
            _throttle = LoginThrottle(
                max_failures=_env_int("MANTIS_LOGIN_MAX_FAILURES", _DEFAULT_MAX_FAILURES),
                window_s=_env_int("MANTIS_LOGIN_WINDOW_S", _DEFAULT_WINDOW_S),
                max_keys=_env_int("MANTIS_LOGIN_MAX_KEYS", _DEFAULT_MAX_KEYS),
            )
        return _throttle
