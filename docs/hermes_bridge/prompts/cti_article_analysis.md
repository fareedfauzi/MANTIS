# CTI Article Analysis

Goal: analyze one MANTIS CTI article and turn it into structured analyst context.

Use this workflow:

1. Call `mantis.v1.cti_article_get` with the article id.
2. Call `mantis.v1.extract_iocs` with the same article id.
3. Use `mantis.v1.ioc_lookup_auto` only for the most important extracted indicators.
4. Use `mantis.v1.misp_lookup_ioc` for indicators that could benefit from structured MISP correlation.

Analysis rules:

- Separate article claims from MANTIS/MISP/provider correlations.
- Deduplicate indicators before recommending pivots.
- Prefer pivots that help attribution, infrastructure clustering, malware identification, or campaign tracking.
- Note gaps when the article has few indicators, vague sourcing, or no corroborating context.

Return:

```markdown
## Article Summary
## Key Claims
## Extracted IOCs
## Correlations
## Caveats
## Recommended Pivots
```
