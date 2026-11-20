# Threat Knowledge

Threat Knowledge holds reference material: threat actors, malware and tools, the Kaspersky TIP view, a hunting-query library, and the malware sample repository.

Sidebar: **Threat Actor** (`ta`), **Kaspersky** (`ktip-ta`), **Malware & Tools** (`mwtools`), **Threat Hunting Library** (`hunting-library`), and **Malware Repository** (`malware-db`, under Reverse Engineering).

## Threat Actor and Malware & Tools

Both views are built from MISP galaxy data (`/api/misp-galaxy/categories`, `/api/misp-galaxy/search`). Each entry shows aliases, description, references and linked clusters.

- Use the search to find an actor or tool by name or alias.
- Use the category list to move between galaxy sections.
- **Refresh** (`POST /api/misp-galaxy/refresh`) reloads the galaxy data from upstream.

### Tutorial: profile an actor

1. Open **Threat Actor** and search for the name or an alias.
2. Read the description and aliases. Check the references before you rely on an alias match.
3. Open the linked malware and tools, then open them in **Malware & Tools** for their own profiles.
4. To find recent activity, take the actor name to [IOC Search](ioc-search.md) as a keyword, or to [Threat Intelligence](threat-intelligence.md) for the CTI corpus.

## Kaspersky

Sidebar: **Kaspersky** (`ktip-ta`). Kaspersky TIP data, when a Kaspersky TIP key is configured in **Settings -> API Keys**.

- **Actors** list (`/api/ktip/actors`) and actor detail (`/api/ktip/actors/{id}`).
- **Samples** for an actor (`/api/ktip/actors/{id}/samples`).
- **Reports search** (`/api/ktip/reports/search`).
- **Lookup** of an indicator (`/api/ktip/lookup`).
- **Sandbox** outputs for a task (`/api/ktip/sandbox/{task_id}/{kind}/{md5}`).

The **Reset Filters** control clears the actor filters. Without a key, the page shows the configuration state instead of data.

## Threat Hunting Library

Sidebar: **Threat Hunting Library** (`hunting-library`).

A library of hunting rules and VirusTotal hunting notifications.

- **Rulesets** (`/api/vt/hunting/rulesets`): create and open YARA-style rulesets for VT Livehunt or Retrohunt.
- **Notifications** (`/api/vt/hunting/notifications`): matches from your hunts. Open one to see its files (`/notifications/{id}/files`). Delete one or several in a batch (`delete-batch`).
- **Status** (`/api/vt/hunting/status`) shows whether the VirusTotal key supports hunting.

### Tutorial: review a hunting match

1. Open **Threat Hunting Library** and check that the status shows the hunting key as active.
2. Open the notification list and select a match.
3. Read the matched files. Send a file hash to [IOC Search](ioc-search.md), or to the **AI Binary Analysis Lab** if you want to study the sample.
4. Delete reviewed notifications so the list stays current.

## Malware Repository

Sidebar: **Malware Repository** (`malware-db`).

A local store of malware samples (`backend/data/malware_db.db`), keyed by SHA-256.

- **Upload** (`POST /api/malware-db/upload`) adds a sample. Upload only files you are allowed to handle, and handle them in an isolated VM.
- **Stage** (`POST /api/malware-db/sample/{sha256}/stage`) prepares a sample for analysis.
- **Download** (`GET /api/malware-db/sample/{sha256}/download`) returns the file.
- Delete a sample with `DELETE /api/malware-db/sample/{sha256}`.

Samples are stored as-is. MANTIS does not execute them.

## Tutorial: build a hunting list for a family

1. In **Threat Hunting Library**, open the rulesets and find the family.
2. In **Malware & Tools**, look up the family to get its aliases and related tools. Add those names to the ruleset search.
3. In [IOC Search](ioc-search.md), use the family name as a keyword to gather reports.
4. Store the relevant samples in the **Malware Repository** and run [YARA](yara.md) scans against them.

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/misp-galaxy/categories`, `/api/misp-galaxy/search` | GET | Galaxy browse and search. |
| `/api/misp-galaxy/refresh` | POST | Refresh galaxy data. |
| `/api/ktip/actors`, `/api/ktip/actors/{id}`, `/api/ktip/actors/{id}/samples` | GET | Kaspersky actors and samples. |
| `/api/ktip/reports/search`, `/api/ktip/lookup` | GET, POST | Kaspersky reports and lookups. |
| `/api/vt/hunting/rulesets` | GET, POST | List or create rulesets. |
| `/api/vt/hunting/rulesets/{id}` | GET, DELETE | Read or delete a ruleset. |
| `/api/vt/hunting/notifications` | GET | List matches. |
| `/api/vt/hunting/notifications/delete-batch` | POST | Delete several matches. |
| `/api/malware-db/samples` | GET | List stored samples. |
| `/api/malware-db/upload` | POST | Upload a sample. |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Kaspersky page is empty | Add the Kaspersky TIP key in **Settings -> API Keys**. |
| Hunting status says not available | The VirusTotal key lacks hunting access. |
| Galaxy entry out of date | Run **Refresh** on the galaxy data. |
