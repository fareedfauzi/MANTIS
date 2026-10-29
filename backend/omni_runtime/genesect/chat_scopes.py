"""Scope definitions shared by the unified AI Chat UI and tests."""

SCOPE_CURRENT_FUNCTION = "current_function"
SCOPE_FUNCTION_CHAIN = "function_chain"
SCOPE_CHAIN_SUMMARY = "chain_summary"

CHAT_SCOPES = (
    (
        SCOPE_CURRENT_FUNCTION,
        "Current Function",
        "Open an interactive chat using the current function's decompiled code.",
        "Open Function Chat",
    ),
    (
        SCOPE_FUNCTION_CHAIN,
        "Function Chain",
        "Build a selectable caller/callee graph and chat with multiple related functions in context.",
        "Open Chain Chat",
    ),
    (
        SCOPE_CHAIN_SUMMARY,
        "Function Chain Summary",
        "Run the map-reduce summarizer and generate a structured execution-flow report.",
        "Open Chain Summary",
    ),
)


def normalize_chat_scope(scope):
    valid = {item[0] for item in CHAT_SCOPES}
    return scope if scope in valid else SCOPE_CURRENT_FUNCTION


def chat_scope_definition(scope):
    normalized = normalize_chat_scope(scope)
    return next(item for item in CHAT_SCOPES if item[0] == normalized)

