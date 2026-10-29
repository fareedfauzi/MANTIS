"""Command-line wrapper for MANTIS agent tools.

This is a local fallback for agent runtimes that can call terminal commands.
The HTTP/API bridge remains the preferred integration surface.
"""

import argparse
import json
import sys

from agent_redaction import redact
from agent_tools.registry import describe_tools, run_tool


def _load_args(raw: str) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON arguments: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("Arguments JSON must be an object.")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local MANTIS agent tools.")
    parser.add_argument("tool", help="Tool name, or 'list'")
    parser.add_argument("--args", default="{}", help="Tool arguments as JSON object")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parsed = parser.parse_args()

    if parsed.tool == "list":
        result = describe_tools()
    else:
        result = run_tool(parsed.tool, _load_args(parsed.args))
    print(json.dumps(redact(result), indent=2 if parsed.pretty else None, ensure_ascii=False))
    return 0 if result.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
