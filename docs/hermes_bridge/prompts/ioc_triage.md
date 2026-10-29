# IOC Triage With MANTIS

Goal: determine what MANTIS knows about one IOC and recommend useful pivots.

Use this workflow:

1. Call `mantis.v1.provider_metadata` if you need available source names.
2. Call `mantis.v1.ioc_lookup_auto` with the IOC and type when known.
3. Call `mantis.v1.misp_lookup_ioc` when MISP context is relevant or available.
4. Call `mantis.v1.cti_search` for the IOC value and any normalized variants.
5. If CTI articles look relevant, call `mantis.v1.cti_article_get`, then `mantis.v1.extract_iocs`.

Analysis rules:

- Do not treat a single provider hit as confirmation of maliciousness.
- Highlight source-health problems such as missing API keys, empty MISP config, provider errors, or noisy detections.
- Prefer pivots with clear rationale: related domains, IPs, URLs, hashes, malware, actors, campaigns, tags, galaxies, reports, or CTI articles.
- Keep passive boundaries. Do not request active scanning or external modification.

Return:

```markdown
## Verdict
## Evidence-Backed Findings
## MISP Context
## Related Indicators
## Caveats
## Recommended Pivots
```
