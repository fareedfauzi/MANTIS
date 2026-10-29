import json
import os
import time
from typing import Any, Dict

from agent_redaction import compact_summary, redact


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
AUDIT_PATH = os.environ.get("MANTIS_AGENT_AUDIT_PATH") or os.path.join(DATA_DIR, "agent_audit.jsonl")


def write_audit(event: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
    safe_event = redact({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **event,
    })
    if "input" in safe_event:
        safe_event["input_summary"] = compact_summary(safe_event.pop("input"), 1600)
    with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(safe_event, ensure_ascii=False, sort_keys=True) + "\n")


def recent(limit: int = 50) -> Dict[str, Any]:
    if not os.path.exists(AUDIT_PATH):
        return {"items": []}
    items = []
    with open(AUDIT_PATH, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return {"items": items[-max(1, min(int(limit or 50), 200)):][::-1]}
