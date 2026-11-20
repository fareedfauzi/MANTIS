# Sigma Rules

The Sigma workbench browses, converts, classifies and manages Sigma detection rules. It is backed by the SigmaHQ and community repositories you sync, plus rules you write yourself.

Sidebar (under Threat Knowledge): **Rules Explorer** (`sigma-rules`), **Rules Stats** (`sigma-stats`), **Emerging Threats** (`sigma-emerging`), **MITRE ATT&CK** (`sigma-mitre`), **Convert to Query** (`sigma-convert`), **Manager** (`sigma-manager`).

## Rules Explorer

Browse and filter the rule set.

- Severity: All Severities, Critical, High, Medium, Low, Informational.
- Status: All Statuses, Stable, Test, Experimental.
- Log category: All Log Categories, Process Creation, File Event, Pipe Created, Network Connection, General.
- Open a rule to read its YAML.

Rules are served by `/api/sigma/rules`. Load a single rule with `/api/sigma/rule` (by path) or `/api/sigma/rule/uuid`.

## Rules Stats

Counts by severity, status, product and tag, computed over the loaded rule set (`/api/sigma/stats`).

## Emerging Threats

Rules grouped by threat theme, with counts per group:

- **All Emerging**, **CVE & Exploits**, **Ransomware**, **APT Groups**, **LOLBAS**.

The list is paged on the server (60 per page, up to 200 with `limit`). Use the **Load more (N of M)** button under the list to fetch the next page. Each request carries the category, search text and offset (`/api/sigma/emerging?category=&search=&limit=&offset=`), so the page does not load the whole set at once.

## MITRE ATT&CK

A matrix view of the rule set. Each technique shows how many rules cover it. Click a technique to list its rules (`/api/sigma/mitre`).

## Convert to Query

Turns a Sigma rule into a query for a SIEM.

1. Open **Convert to Query**.
2. Choose a preloaded rule from **Choose a preloaded Sigma Rule**, or paste your own.
3. Pick the target: **Splunk SPL**, **Sentinel KQL**, or **Defender XDR**.
4. Pick a conversion mode:
   - **Standard (pySigma)**: deterministic conversion with pySigma.
   - **AI Conversion**: AI writes the query.
   - **AI-Assisted Repair**: runs the deterministic conversion first and uses AI only to repair errors. Use **Switch to Repair** to move to it from the other modes.
5. Click **Convert**. The output appears with **Copy Query**. **Breakdown** explains the conversion.

AI modes use the provider and model shown in the AI configuration panel. **Loading providers...** shows while the provider list loads.

### Tutorial: convert and validate a rule

1. In **Rules Explorer**, open a rule you want to deploy and copy its YAML.
2. In **Convert to Query**, paste it, select **Splunk SPL**, and choose **Standard (pySigma)**.
3. Click **Convert**. If it fails, switch to **AI-Assisted Repair** and convert again. Read the **Breakdown** to confirm the repair did not change the logic.
4. Test the query in your SIEM before you deploy it.

## Manager

Add, edit and sync the rule sources.

- **Sync Repos** pulls the configured repositories.
- **Sync All** syncs every source.
- **Add Source** adds a Git repository as a rule source (`/api/sigma/sources/add`). Edit or delete it with `/sources/update` and `/sources/delete`.
- **New Rule** opens the editor; **Create Rule** saves it as a custom rule (`/api/sigma/rule/create`).
- **Edit Rule** opens an existing rule; **Save Changes** writes it back (`/api/sigma/rule/save`).
- **Clone to custom rules** copies a rule into your custom set (`/api/sigma/rule/clone`).
- Custom rules can be exported with `/api/sigma/custom/export`.

Validate a rule before saving with `/api/sigma/validate`.

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/sigma/rules` | GET | List rules with filters. |
| `/api/sigma/rule`, `/api/sigma/rule/uuid` | GET | Read one rule. |
| `/api/sigma/stats` | GET | Rule statistics. |
| `/api/sigma/emerging` | GET | Emerging-threat groups, paged (`category`, `search`, `limit`, `offset`). |
| `/api/sigma/mitre` | GET | ATT&CK matrix data. |
| `/api/sigma/convert` | POST | Convert a rule to a query. |
| `/api/sigma/validate` | POST | Validate a rule. |
| `/api/sigma/templates` | GET | Editor templates. |
| `/api/sigma/rule/create`, `/rule/save`, `/rule/clone`, `/rule/delete` | POST | Manage custom rules. |
| `/api/sigma/repos`, `/api/sigma/repos/sync`, `/api/sigma/repos/sync-all` | GET, POST | Repository status and sync. |
| `/api/sigma/sources/add`, `/sources/update`, `/sources/delete` | POST | Manage rule sources. |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Emerging list shows few rules | Run **Sync All**; the groups count only synced rules. |
| Provider list says Loading providers... | Wait for it, or check the AI provider in Settings -> AI. |
| Conversion fails | Try **AI-Assisted Repair**, then check the **Breakdown**. |
| Empty Rules Explorer | Add a source in **Manager** and sync it. |
