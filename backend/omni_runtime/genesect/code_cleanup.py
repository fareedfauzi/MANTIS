# -*- coding: utf-8 -*-
"""Helpers for extracting code-only AI conversion responses."""

import re


CONVERT_REASONING_MARKERS = (
    "Here's a thinking process",
    "Here is a thinking process",
    "thinking process:",
    "**Analyze the Request",
    "**Analyze the Input Code",
    "**Trace Assembly Execution",
    "Trace Assembly Execution",
    "Analyze the Request",
    "Analyze the Input Code",
    "Function signature:",
    "Local variables:",
    "Parameters:",
    "Logic:",
    "EVIDENCE-PRESERVATION RULES",
    "CRITICAL RULES:",
    "FIRST LINE",
    "Output ONLY",
    "Let's trace",
    "Let's check",
)


def _first_significant_line(text):
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def extract_code_blocks(text):
    blocks = []
    for match in re.finditer(r"```[^\n`]*\n(.*?)```", text or "", re.S):
        block = match.group(1).strip()
        if block:
            blocks.append(block)
    return blocks


def looks_like_code(text, language):
    code = (text or "").strip()
    if not code:
        return False
    first_lines = "\n".join(code.splitlines()[:30])
    if any(marker.lower() in first_lines.lower() for marker in CONVERT_REASONING_MARKERS):
        return False
    first = _first_significant_line(code)
    if first.startswith(("-", "*")) or re.match(r"^\d+\.\s", first):
        return False
    if re.match(r"(?i)^(here|this|below|analysis|summary|step|first|now|let's)\b", first):
        return False
    language = str(language or "").lower()
    if language in ("python", "nim"):
        patterns = (r"^\s*(def|class|proc|let|var|if|for|while|return|result)\b",)
        first_patterns = patterns + (r"^\s*#",)
    elif language == "rust":
        patterns = (r"\bfn\s+\w+\s*\(", r"\blet\s+\w+", r"\bmatch\s+")
        first_patterns = (r"^\s*(//|/\*|\bfn\b|\blet\b|\bpub\b|\buse\b|\bstruct\b|\benum\b)",)
    elif language == "go":
        patterns = (r"\bfunc\s+\w+\s*\(", r"\bvar\s+\w+", r"\breturn\b")
        first_patterns = (r"^\s*(//|/\*|\bpackage\b|\bfunc\b|\bvar\b|\bconst\b|\btype\b)",)
    elif language in ("c#", "csharp"):
        patterns = (r"\b(public|private|internal|static|void|int|long|bool|string)\b.*\(", r"\breturn\b", r"[{};]")
        first_patterns = (r"^\s*(//|/\*|\busing\b|\bnamespace\b|\bpublic\b|\bprivate\b|\binternal\b|\bstatic\b|\bvoid\b|\bclass\b)",)
    else:
        patterns = (r"\b[A-Za-z_][\w\s\*\:&<>]*\s+\w+\s*\(", r"\breturn\b", r"[{};]")
        first_patterns = (r"^\s*(//|/\*|#\s*include|#\s*define|\b(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*\:&<>]*\s+\w+\s*\()",)
    if not any(re.search(pattern, first) for pattern in first_patterns):
        return False
    return any(re.search(pattern, code, re.M) for pattern in patterns)


def clean_converted_code_response(response, language):
    """Extract code-only conversion output and reject model reasoning dumps."""
    text = (response or "").strip()
    if not text:
        return "", ["empty response"]
    blocks = extract_code_blocks(text)
    code = "\n\n".join(blocks).strip() if blocks else text
    if any(marker.lower() in code[:3500].lower() for marker in CONVERT_REASONING_MARKERS):
        return code, ["model returned analysis/prose instead of converted code"]
    if not looks_like_code(code, language):
        return code, ["response does not look like %s code" % language]
    return code, []
