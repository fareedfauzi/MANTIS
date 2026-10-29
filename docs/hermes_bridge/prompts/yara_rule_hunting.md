# YARA Rule Hunting With MANTIS

Goal: use local YARA rule metadata and source as analyst context for detection engineering and CTI pivots.

Use this workflow:

1. Call `mantis.v1.yara_status` to understand repository and engine availability when needed.
2. Call `mantis.v1.yara_rule_search` for the malware family, actor, technique, string, or rule name.
3. Call `mantis.v1.yara_rule_get` only for rules that are relevant enough to inspect.
4. Cross-reference rule names, metadata, strings, malware families, and references with `mantis.v1.cti_search` or IOC lookup tools when justified.

Rules:

- Do not claim a sample matches a rule unless MANTIS provides an actual scan result.
- Treat rule names and metadata as detection context, not ground-truth attribution.
- Highlight repository coverage and missing/failed indexes as source-health caveats.
- Do not ask MANTIS to save, edit, or scan with YARA in this read-only workflow.

Return:

```markdown
## Rule Hunting Summary
## Relevant Rules
## Detection Context
## CTI Pivots
## Caveats
## Evidence
```
