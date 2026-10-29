"""Structured, dependency-free diagnostic primitives for Extended."""

from __future__ import annotations

import datetime as _datetime
import traceback
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class DiagnosticEvent:
    timestamp: str
    level: str
    component: str
    message: str
    operation: Optional[str] = None
    exception_type: Optional[str] = None
    traceback_text: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def make_event(level, component, message, *, operation=None, exception=None):
    exception_type = None
    traceback_text = None
    if exception is not None:
        exception_type = type(exception).__name__
        traceback_text = "".join(
            traceback.format_exception(type(exception), exception, exception.__traceback__)
        )
    return DiagnosticEvent(
        timestamp=_datetime.datetime.now(_datetime.timezone.utc).isoformat(),
        level=str(level).upper(),
        component=str(component),
        message=str(message),
        operation=operation,
        exception_type=exception_type,
        traceback_text=traceback_text,
    )


def guarded(component, operation, report, fallback=None):
    """Report unexpected callback failures while returning a safe fallback."""
    def decorate(function):
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception as exc:
                report(make_event(
                    "error", component, str(exc), operation=operation, exception=exc
                ))
                return fallback
        return wrapped
    return decorate
