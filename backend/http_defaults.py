"""Default socket timeout for every outbound HTTP call made through `requests`.

MANTIS makes provider calls from request handlers (VirusTotal, Shodan, FOFA,
urlhaus, MalShare, feeds ...). A provider that accepts the connection and then
never answers used to pin the worker thread for as long as the OS allowed:
`POST /api/ai/sso/signin` and the ransomware infrastructure page both hung for
more than three minutes that way.

23 call sites had no `timeout=`. Instead of editing each one with a guessed
value, this installs a default on `requests.Session.send`, which every helper
(`requests.get`, `session.post`, ...) funnels through. An explicit `timeout=`
in the call always wins, so per-endpoint tuning still works.

Environment:
    MANTIS_HTTP_DEFAULTS=0        disable the default entirely
    MANTIS_HTTP_TIMEOUT=10,60     connect,read seconds (a single value sets both)
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("http_defaults")

DEFAULT_CONNECT_S = 10.0
DEFAULT_READ_S = 60.0

_INSTALLED = False
_ORIGINAL_SEND = None


def default_timeout() -> tuple:
    """(connect, read) seconds, from the environment when it is set."""
    raw = (os.environ.get("MANTIS_HTTP_TIMEOUT") or "").strip()
    if not raw:
        return (DEFAULT_CONNECT_S, DEFAULT_READ_S)
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    try:
        values = [float(p) for p in parts]
    except ValueError:
        logger.warning("MANTIS_HTTP_TIMEOUT=%r is not numeric; using the defaults", raw)
        return (DEFAULT_CONNECT_S, DEFAULT_READ_S)
    if len(values) == 1:
        return (values[0], values[0])
    return (values[0], values[1])


def _enabled() -> bool:
    return (os.environ.get("MANTIS_HTTP_DEFAULTS") or "1").strip().lower() not in {
        "0", "false", "no", "off"}


def install() -> bool:
    """Patch `requests.Session.send` once. Returns True when the default is active."""
    global _INSTALLED, _ORIGINAL_SEND
    if _INSTALLED:
        return _enabled()
    if not _enabled():
        return False
    try:
        import requests
    except Exception:  # pragma: no cover - requests is a hard dependency
        logger.warning("requests is unavailable; outbound timeout default not installed")
        return False

    _ORIGINAL_SEND = requests.Session.send

    def send_with_default(self, request, **kwargs):
        if kwargs.get("timeout") is None and _enabled():
            kwargs["timeout"] = default_timeout()
        return _ORIGINAL_SEND(self, request, **kwargs)

    requests.Session.send = send_with_default
    _INSTALLED = True
    logger.info("outbound HTTP default timeout: connect %.0fs / read %.0fs",
                *default_timeout())
    return True


def uninstall() -> None:
    """Restore the original `requests.Session.send` (used by tests)."""
    global _INSTALLED
    if not _INSTALLED or _ORIGINAL_SEND is None:
        return
    import requests
    requests.Session.send = _ORIGINAL_SEND
    _INSTALLED = False
