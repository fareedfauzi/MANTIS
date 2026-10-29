import json
from pathlib import Path
from typing import Any, Dict, List

from agent_redaction import redact


PROMPT_DIR = Path(__file__).resolve().parent.parent / "docs" / "hermes_bridge" / "prompts"

PROMPTS: Dict[str, Dict[str, Any]] = {
    "mantis_cti_analyst": {
        "file": "mantis_cti_analyst.md",
        "description": "General operating instructions for using MANTIS as a passive CTI and OSINT tool server.",
        "arguments": [
            {"name": "task", "description": "Analyst task or question to answer.", "required": False},
            {"name": "scope", "description": "Allowed investigation scope.", "required": False},
        ],
    },
    "ioc_triage": {
        "file": "ioc_triage.md",
        "description": "Evidence-backed IOC triage workflow using local CTI, MISP, and MANTIS lookup tools.",
        "arguments": [
            {"name": "indicator", "description": "IOC to investigate.", "required": True},
            {"name": "indicator_type", "description": "Optional type: auto, domain, ip, url, hash, or keyword.", "required": False},
        ],
    },
    "misp_context_expansion": {
        "file": "misp_context_expansion.md",
        "description": "Passive MISP context expansion workflow for events, related indicators, tags, galaxies, sightings, and reports.",
        "arguments": [
            {"name": "indicator", "description": "IOC to expand in MISP.", "required": True},
        ],
    },
    "cti_article_analysis": {
        "file": "cti_article_analysis.md",
        "description": "Analyze a CTI article, extract IOCs, and recommend evidence-backed pivots.",
        "arguments": [
            {"name": "article_id", "description": "MANTIS CTI article id.", "required": True},
        ],
    },
    "yara_rule_hunting": {
        "file": "yara_rule_hunting.md",
        "description": "Search and inspect local YARA rules to support detection engineering and CTI pivots.",
        "arguments": [
            {"name": "query", "description": "Rule, malware family, actor, string, or technique to search.", "required": True},
        ],
    },
    "similarity_triage": {
        "file": "similarity_triage.md",
        "description": "Interpret local sample similarity entities and comparison context without making unsupported attribution claims.",
        "arguments": [
            {"name": "entity_id", "description": "Optional similarity entity id to inspect.", "required": False},
        ],
    },
    "case_review": {
        "file": "case_review.md",
        "description": "Review an existing MANTIS case workspace and produce an evidence-backed analyst assessment.",
        "arguments": [
            {"name": "case_id", "description": "MANTIS case id to review.", "required": True},
        ],
    },
}


def list_prompts() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "prompts": [
            {
                "name": name,
                "description": meta["description"],
                "arguments": meta.get("arguments", []),
            }
            for name, meta in PROMPTS.items()
        ]
    }


def get_prompt(name: str, arguments: Dict[str, Any] = None) -> Dict[str, Any]:
    meta = PROMPTS.get((name or "").strip())
    if not meta:
        raise KeyError(f"Unknown prompt: {name}")
    path = PROMPT_DIR / meta["file"]
    text = path.read_text(encoding="utf-8")
    args = redact(arguments or {})
    if args:
        text += "\n\n## Runtime Inputs\n\n```json\n"
        text += json.dumps(args, indent=2, ensure_ascii=False)
        text += "\n```\n"
    return {
        "description": meta["description"],
        "messages": [
            {
                "role": "user",
                "content": {"type": "text", "text": text},
            }
        ],
    }
