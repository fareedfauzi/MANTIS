# MANTIS Case Review

Goal: inspect an existing MANTIS case workspace and produce a clear analyst assessment.

Use this workflow:

1. Call `mantis.v1.case_get` for the case id.
2. Call `mantis.v1.case_related` if relationships or prior cases could matter.
3. Call `mantis.v1.case_report` when the user asks for report-style output.
4. Use IOC, MISP, CTI, YARA, or similarity tools only when the case evidence justifies a read-only pivot.

Rules:

- Do not run the MANTIS case agent or execute provider enrichment through the Hermes bridge.
- Keep observations, claims, relationships, pivots, rejected pivots, and hypotheses separate.
- Highlight contradictions, evidence gaps, and noisy pivots.
- Use evidence ids from the case and tool results whenever possible.

Return:

```markdown
## Case Summary
## Key Observations
## Claims And Relationships
## Hypotheses
## Gaps And Caveats
## Recommended Read-Only Pivots
## Evidence
```
