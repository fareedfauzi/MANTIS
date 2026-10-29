# MISP Context Expansion

Goal: use MISP as a structured intelligence knowledge source and correlation layer.

Use this workflow:

1. Call `mantis.v1.misp_lookup_ioc` for the IOC.
2. Identify matching events, attributes, tags, taxonomies, galaxies, warning-list hits, sightings, and event reports.
3. Extract related indicators only when they are connected by MISP event context.
4. Use `mantis.v1.cti_search` for matching MISP event names, malware names, actors, campaigns, or related indicators when useful.

Interpretation rules:

- MISP is not just a reputation provider. Treat it as structured context.
- Separate direct IOC matches from event-level associations.
- Do not infer actor attribution unless MISP galaxies, tags, event reports, or corroborating CTI support it.
- Explain whether the IOC match appears weak, broad, stale, or highly contextual.

Return:

```markdown
## MISP Match Status
## Events And Context
## Tags, Taxonomies, And Galaxies
## Related Indicators
## Sightings And Reports
## Analyst Assessment
## Recommended Pivots
```
