# Hermes Analyst Output Contract

Hermes should return analyst results in both readable Markdown and, when the client supports it, structured JSON matching `mantis://schemas/analyst-output-v1`.

Required analyst habits:

- Keep observed facts separate from provider claims and analyst assessment.
- Cite MANTIS evidence ids when available.
- Mark uncertainty clearly.
- Include source-health issues such as provider errors, missing keys, empty results, stale context, or noisy correlation.
- Recommend pivots only when they are justified by evidence.
- Do not expose secrets, raw credentials, or unnecessary personal data.

Recommended Markdown shape:

```markdown
## Summary
## Verdict
## Observed Facts
## Provider Claims
## Correlations
## MISP Context
## Caveats
## Source Health
## Recommended Pivots
## Evidence
```

Verdict values:

- `malicious`
- `suspicious`
- `benign`
- `unknown`
- `informational`

Confidence is an integer from 0 to 100. Use low confidence when the result depends on a single weak source, incomplete provider coverage, stale context, or broad event-level association.
