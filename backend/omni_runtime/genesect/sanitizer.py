"""
AI response sanitization, refusal detection, and safe batch parsing.

Prevents AI model refusals (e.g. Gemini/OpenAI safety filter blocks like
"This request was blocked by Gemini safety policy...") from being mistakenly
parsed into bogus unscored function renames like:
    sub_6025CFD -> this_6025CFD (unscored)
    sub_604176D -> request_604176D (unscored)
    sub_604409D -> was_604409D (unscored)
    sub_6044575 -> blocked_6044575 (unscored)
    sub_6044A29 -> gemini_6044A29 (unscored)
"""

from __future__ import annotations

import re
from typing import Callable, Sequence

REFUSAL_INDICATORS = (
    "request was blocked",
    "request is blocked",
    "request blocked",
    "blocked by gemini's filters",
    "blocked by gemini",
    "gemini's filters",
    "gemini filters",
    "blocked by",
    "safety policy",
    "content policy",
    "policy violation",
    "safety filter",
    "safety filters",
    "safety reasons",
    "harmful content",
    "malicious code",
    "cybersecurity policy",
    "trigger by mistake on safe coding",
    "biology-related queries",
    "rephrasing your prompt",
    "try rephrasing",
    "send feedback",
    "i cannot fulfill",
    "i cannot assist",
    "i cannot analyze",
    "i am unable to analyze",
    "i am unable to provide",
    "i am unable to",
    "as an ai language model",
    "as a responsible ai",
    "cannot complete this request",
    "cannot provide names",
    "cannot assist with malware",
    "violate our terms",
    "violates the safety",
)

DISALLOWED_PROSE_WORDS = {
    # Refusal words & AI names
    "this", "request", "was", "were", "blocked", "gemini", "google", "openai", "claude",
    "copilot", "anthropic", "sorry", "cannot", "unable", "assistant", "model", "policy",
    "safety", "filter", "filters", "violation", "harmful", "malicious", "cybersecurity",
    "content", "guidelines", "prompt", "response", "result", "results", "batch",
    "queries", "query", "mistake", "trigger", "feedback", "rephrasing", "biology",
    # Conversational filler
    "here", "there", "these", "those", "following", "below", "above", "suggested",
    "suggestions", "list", "name", "names", "function", "functions", "func", "sub",
    "please", "sure", "okay", "note", "check", "hello", "code", "analysis", "decompiled",
    # Common English stop-words
    "and", "for", "with", "from", "that", "have", "they", "been", "will", "would",
    "could", "should", "about", "which", "when", "what", "where", "them", "then",
    "error", "failed", "timeout", "exception", "unknown", "unnamed", "noname",
    # C keywords that shouldn't be bare function names
    "void", "int", "char", "return", "include", "const", "unsigned", "static", "bool",
}


def is_ai_refusal(text: str) -> bool:
    """Return True if text contains common AI safety/policy refusal phrases."""
    if not text:
        return False
    lower = text.lower()
    return any(phrase in lower for phrase in REFUSAL_INDICATORS)


def is_valid_identifier(name: str | None, score: str | None = "") -> bool:
    """
    Validate that name is a plausible reverse engineering function identifier.

    Rejects:
    - Non-alphanumeric tokens
    - Disallowed prose stop-words / refusal words
    - Unscored single plain dictionary words (which usually stem from conversational prose)
    """
    if not name or not isinstance(name, str):
        return False
    name = name.strip()
    if len(name) < 3 or len(name) > 80:
        return False

    # Must be valid identifier syntax
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False

    lower = name.lower()
    if lower in DISALLOWED_PROSE_WORDS:
        return False

    # If unscored (no confidence score provided by model), require structured naming
    # like snake_case (contains '_') or camelCase (has both lowercase and uppercase).
    # Single lowercase words like 'this', 'request', 'was', 'blocked' are rejected.
    has_score = bool(score and str(score).strip() and str(score).strip() != "unscored")
    if not has_score:
        has_underscore = "_" in name
        has_camel_case = any(c.islower() for c in name) and any(c.isupper() for c in name[1:])
        has_re_prefix = any(lower.startswith(p) for p in (
            "sub_", "fn_", "init_", "free_", "alloc_", "parse_", "send_", "recv_",
            "get_", "set_", "do_", "run_", "process_", "dispatch_", "handle_",
        ))
        if not (has_underscore or has_camel_case or has_re_prefix):
            return False

    return True


def safe_parse_batch_response(
    resp: str,
    expected: int,
    log_fn: Callable[[str, str], None] | None = None,
) -> tuple[list[str | None], list[str], int]:
    """
    Parse a batch response from an AI provider into (names, scores, count).

    Guarantees:
    - Never extracts tokens from AI refusals or error messages.
    - Rejects conversational prose words.
    - Requires structured identifier syntax for unscored fallback items.
    """
    def _log(msg: str, level: str = "info") -> None:
        if log_fn:
            try:
                log_fn(msg, level)
            except Exception:
                pass

    if not resp or not resp.strip():
        _log("AI returned empty response", "warn")
        return [None] * expected, [''] * expected, 0

    clean_resp = resp.strip()

    # Refusal check: If model refused the prompt, return immediately
    if is_ai_refusal(clean_resp):
        _log("AI provider refused or blocked request due to safety/policy filters.", "warn")
        return [None] * expected, [''] * expected, 0

    names: list[str] = []
    scores: list[str] = []

    # Strategy 1: Split by lines and try to extract one name per line
    for line in clean_resp.split("\n"):
        line = line.strip()
        if not line or "```" in line:
            continue

        # Strip list prefixes: "1. ", "- ", "* ", "[1] ", "**1.**"
        clean = re.sub(r'^[\s\d\.\)\-\*\#\[\]\:\|]+', '', line).strip()
        # Strip leading "Function", "Fn", etc.
        clean = re.sub(r'^(function|func|fn|sub)\s*[\d\.\)\:\-]*\s*', '', clean, flags=re.IGNORECASE).strip()

        if not clean or len(clean) < 3:
            continue

        # Split line to find [score]
        score_match = re.search(r'\[(\d+)%?\]', line)
        if score_match:
            raw_score = int(score_match.group(1))
            clamped = max(0, min(raw_score, 100))
            score_val = f"{clamped}%"
        else:
            score_val = ""

        # Extract the first token that looks like an identifier
        parts = re.split(r'[\s,\:\(\)\|\[\]]+', clean)
        if not parts:
            continue
        nm = parts[0].strip(' "\'`*')
        nm = re.sub(r'[^a-zA-Z0-9_]', '', nm)

        if is_valid_identifier(nm, score=score_val):
            names.append(nm)
            scores.append(score_val)

    # Strategy 2: Fallback regex scan for identifiers.
    # ONLY run if we already found at least one scored/valid name in Strategy 1
    # or if the response clearly doesn't read as conversational English sentences.
    if len(names) < expected and (names or not re.search(r'\b(the|this|that|with|from|please|sorry)\b', clean_resp.lower())):
        found = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]+)\b', clean_resp)
        for n in found:
            # Must satisfy strict identifier format without score
            if is_valid_identifier(n, score=""):
                if n not in names:
                    if len(names) < expected:
                        names.append(n)
                        scores.append('')
                    else:
                        break

    actual_count = min(len(names), expected)
    final_names = (names + [None] * expected)[:expected]
    final_scores = (scores + [''] * expected)[:expected]
    return final_names, final_scores, actual_count
