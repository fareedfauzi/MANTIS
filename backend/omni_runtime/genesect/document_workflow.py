"""Stable section identifiers for the unified function documentation workspace."""

SECTION_EXPLANATION = "explanation"
SECTION_READABLE_CODE = "readable_code"
SECTION_ANALYST_NOTES = "analyst_notes"
SECTION_OVERVIEW = "overview"
SECTION_EXECUTION_FLOW = "execution_flow"
SECTION_FUNCTION_INTELLIGENCE = "function_intelligence"
SECTION_CUSTOM_PROMPT = "custom_prompt"

PRIMARY_DOCUMENT_SECTIONS = (
    SECTION_EXPLANATION,
    SECTION_READABLE_CODE,
    SECTION_ANALYST_NOTES,
)

DOCUMENT_SECTION_ORDER = PRIMARY_DOCUMENT_SECTIONS + (
    SECTION_OVERVIEW,
    SECTION_EXECUTION_FLOW,
    SECTION_FUNCTION_INTELLIGENCE,
    SECTION_CUSTOM_PROMPT,
)


def normalize_document_section(section):
    return section if section in DOCUMENT_SECTION_ORDER else SECTION_EXPLANATION

