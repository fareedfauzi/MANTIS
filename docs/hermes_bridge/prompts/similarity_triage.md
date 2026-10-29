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
- Include configuration caveats such as disabled IDA, disabled semantic similarity, empty corpus, or stale entity data.
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
