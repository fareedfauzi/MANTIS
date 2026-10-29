from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent.parent

RESOURCES: Dict[str, Dict[str, str]] = {
    "mantis://docs/hermes-bridge": {
        "name": "Hermes Bridge README",
        "description": "Operator documentation for the Hermes -> MANTIS bridge.",
        "mimeType": "text/markdown",
        "path": "docs/hermes_bridge/README.md",
    },
    "mantis://docs/analyst-output-contract": {
        "name": "Analyst Output Contract",
        "description": "Human-readable contract for Hermes analyst responses.",
        "mimeType": "text/markdown",
        "path": "docs/hermes_bridge/output_contract.md",
    },
    "mantis://schemas/analyst-output-v1": {
        "name": "Analyst Output Schema v1",
        "description": "JSON schema for structured Hermes analyst output.",
        "mimeType": "application/schema+json",
        "path": "docs/hermes_bridge/schemas/analyst_output.schema.json",
    },
}


def list_resources() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "resources": [
            {
                "uri": uri,
                "name": meta["name"],
                "description": meta["description"],
                "mimeType": meta["mimeType"],
            }
            for uri, meta in RESOURCES.items()
        ]
    }


def read_resource(uri: str) -> Dict[str, Any]:
    meta = RESOURCES.get((uri or "").strip())
    if not meta:
        raise KeyError(f"Unknown resource: {uri}")
    path = ROOT / meta["path"]
    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": meta["mimeType"],
                "text": path.read_text(encoding="utf-8"),
            }
        ]
    }
