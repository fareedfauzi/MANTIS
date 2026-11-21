# Similarity Triage With MANTIS

Goal: interpret existing local sample similarity entities, comparisons, and code-derived context.

Use this workflow:

1. Call `mantis.v1.similarity_dashboard` to understand corpus state.
2. Call `mantis.v1.similarity_entities` to list known entities when the target family or cluster is unknown.
3. Call `mantis.v1.similarity_entity_get` for a specific entity. Include functions only when the question requires code-level context.
4. Use CTI or MISP tools to corroborate names, families, infrastructure, or actor claims.

Rules:

- Similarity indicates possible relationship, not actor attribution.
- Separate exact hash/sample overlap from fuzzy, string, import, function, or semantic similarity.
- Report the score band (STRONG, LIKELY, WEAK, NO MATCH, INSUFFICIENT EVIDENCE) and the features behind it, not just a number.
- Include configuration caveats: an empty corpus, a family with fewer than four samples (shared runtime code cannot be filtered, so a WEAK call may include an unrelated sample), a skipped or packed sample, or a missing VirusTotal key.
- Do not request sample upload, entity creation, entity deletion, or setting changes in this read-only workflow.

Return:

```markdown
## Similarity Summary
## Corpus Context
## Entity Findings
## Code Or Feature Signals
## Caveats
## Recommended Pivots
```
