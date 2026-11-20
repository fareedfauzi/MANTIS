# Similarity

Similarity compares a sample against a local library of entities (malware families, actors and campaigns) and ranks the closest matches. It combines structural signals with optional decompiler-based signals from IDA Pro or Hex-Rays.

Sidebar: **Similarity** (`similarity`). Sub-tabs: **Similarity**, **All Entities**, **Create Entity**, **Compare Sample**, **Settings**.

Data is stored in `backend/data/similarity.db`.

## Entities

An entity is a named profile: a family, actor or campaign with one or more reference samples.

- **All Entities** lists them; filter by type (for example Threat Actor Public, Malware Distribution).
- **Create Entity** adds one: name, type, description and reference samples.
- Entities can be updated and deleted through `/api/similarity/entities`.

## Compare Sample

1. Open **Compare Sample** and upload the sample.
2. MANTIS extracts its features and ranks the closest entities.
3. Read the scores and the features that matched. A high score on one feature type only (for example a common import table) is weak evidence on its own.

## Similarity

The main view. It lists the entities nearest to a chosen sample or entity, with a score per signal.

If the page shows **Loading similarity engine…**, the engine is still building its index. When it shows **0 local profiles available**, no entities have been created yet, so create some first.

## Settings

Tune the engine and its decompiler backends. **Hex-Rays Timeout Seconds** sets how long decompilation can run per function. Decompiler status is reported by `/api/similarity/hexrays/status` and `/api/similarity/ida/status`; if neither is available, those signals are skipped.

## Tutorial: attribute a sample to a family

1. Go to **All Entities** and confirm the family you suspect has reference samples. Add them with **Create Entity** if not.
2. Open **Compare Sample**, upload the sample, and run the comparison.
3. Open the top matches. Check the matched signals, not just the score.
4. Record the result in [MANTIS AI](mantis-ai.md) to combine it with other evidence, or in your case notes.

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/similarity/entities` | GET, POST | List or create entities. |
| `/api/similarity/entities/{id}` | GET, PUT, DELETE | Read, update or delete an entity. |
| `/api/similarity/entities/{id}/samples` | POST | Add reference samples. |
| `/api/similarity/entities/{id}/code/rebuild` | POST | Rebuild the code index for an entity. |
| `/api/similarity/compare` | POST | Compare a sample against entities. |
| `/api/similarity/comparisons/{id}`, `/progress/{id}` | GET | Comparison result and progress. |
| `/api/similarity/dashboard` | GET | Summary view. |
| `/api/similarity/settings` | GET, POST | Engine settings. |
| `/api/similarity/hexrays/status`, `/ida/status` | GET | Decompiler availability. |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Stuck on **Loading similarity engine…** | Wait for indexing to finish; check the server log. |
| **0 local profiles available** | Create entities first. |
| No decompiler signal | Neither IDA nor Hex-Rays is available; the signal is skipped. |
