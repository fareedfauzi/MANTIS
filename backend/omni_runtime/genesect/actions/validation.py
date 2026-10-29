"""Dependency-free parsing and validation of AI action proposals."""

import json
import re
from dataclasses import dataclass


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    value: object = None
    error: str = ""


def strip_code_fence(text):
    value = str(text or "").strip()
    match = re.search(r"```(?:[A-Za-z0-9_+.-]+)?\s*\n?(.*?)```", value, re.DOTALL)
    return match.group(1).strip() if match else value


def parse_json_object(text):
    value = strip_code_fence(text)
    try:
        parsed = json.loads(value)
    except Exception:
        start, end = value.find("{"), value.rfind("}")
        if start < 0 or end <= start:
            return ValidationResult(False, error="Response does not contain a JSON object.")
        try:
            parsed = json.loads(value[start:end + 1])
        except Exception as exc:
            return ValidationResult(False, error=f"Invalid JSON object: {exc}")
    if not isinstance(parsed, dict):
        return ValidationResult(False, error="Expected a JSON object.")
    return ValidationResult(True, parsed)


def validate_identifier(value):
    name = str(value or "").strip().strip("`'\"")
    if not IDENTIFIER_RE.fullmatch(name):
        return ValidationResult(False, error="Suggested name is not a valid IDA identifier.")
    return ValidationResult(True, name)


def validate_rename_mapping(mapping):
    if not isinstance(mapping, dict):
        return ValidationResult(False, error="Rename proposal must be an object.")
    clean = {}
    for old_name, new_name in mapping.items():
        old_result = validate_identifier(old_name)
        new_result = validate_identifier(new_name)
        if old_result.valid and new_result.valid and old_result.value != new_result.value:
            clean[old_result.value] = new_result.value
    if not clean:
        return ValidationResult(False, error="No valid rename proposals were returned.")
    return ValidationResult(True, clean)


def validate_prototype(text, original=""):
    value = strip_code_fence(text).split("{")[0].strip().rstrip(";")
    if "\n" in value:
        value = " ".join(line.strip() for line in value.splitlines() if line.strip())
    if len(value) > 2000:
        return ValidationResult(False, error="Prototype is unexpectedly large.")
    if not value or "(" not in value or ")" not in value:
        return ValidationResult(False, error="Response is not a complete C function prototype.")
    if re.search(r"[{}#;\x00-\x08\x0b\x0c\x0e-\x1f]", value):
        return ValidationResult(False, error="Prototype contains unsupported declaration content.")
    if value.count("(") != value.count(")") or not value.endswith(")"):
        return ValidationResult(False, error="Prototype has unbalanced or trailing declaration content.")
    if not re.search(r"\b[A-Za-z_]\w*\s*\(", value):
        return ValidationResult(False, error="Prototype does not contain a valid function name.")
    if "__usercall" in str(original) and "__usercall" not in value:
        return ValidationResult(False, error="Suggested prototype removed the required __usercall convention.")
    original_registers = set(re.findall(r"@<[^>]+>", str(original)))
    if original_registers and not original_registers.issubset(set(re.findall(r"@<[^>]+>", value))):
        return ValidationResult(False, error="Suggested prototype removed required register annotations.")
    return ValidationResult(True, value)


def validate_struct(text):
    value = strip_code_fence(text)
    if len(value) > 100000:
        return ValidationResult(False, error="Structure definition is unexpectedly large.")
    if re.search(r"(^|\n)\s*#", value):
        return ValidationResult(False, error="Preprocessor directives are not allowed in a structure proposal.")
    if not re.search(r"\bstruct\s+[A-Za-z_]\w*\s*\{", value):
        return ValidationResult(False, error="A named C struct definition is required.")
    if "};" not in value:
        return ValidationResult(False, error="Struct definition must end with };.")
    if re.search(r"\[[^\]]*[-+*/][^\]]*\]", value):
        return ValidationResult(False, error="Array sizes must be integer literals, not expressions.")
    return ValidationResult(True, value)
