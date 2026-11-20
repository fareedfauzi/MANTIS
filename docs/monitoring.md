# Monitoring

Monitoring covers three sources that MANTIS watches for you: X accounts, breach and leak feeds, and credential-stealer log reports.

## X Monitor

Sidebar: **X** (`x-monitor`).

Tracks a list of accounts and summarises their recent posts.

- **Open API Settings** opens the X API key. Without it the page shows **X API key required**.
- **Manage Accounts** adds or removes accounts. A seed list is in `backend/data/x_monitor_accounts_seed.txt`.
- Pick a time window: **Today**, **Past 24H**, **Past 7D**, **Past 30D**, or **Custom**.
- Filter posts by type (for example **Contains URL**, **Contains Domain**, **Contains IP**, **Contains Hash**, **Contains CVE**, **Has Media**). Sort by **Newest** or **Oldest**, then click **Apply**.
- **Refresh Recent** fetches new posts. Data is kept in `backend/data/x_monitor.db`.
- **MANTIS AI** works on the selected post or account. It offers **Summarize**, **Recommend Pivots**, **Compare Relationship**, **Attribution**, **Agent Investigation** and **Draft Report**.

### Tutorial: follow a threat-research account

1. Open **X**, click **Manage Accounts**, and add the handle.
2. Set the window to **Past 7D**, filter **Contains Hash** or **Contains CVE**, and click **Apply**.
3. Click **Refresh Recent** to pull new posts.
4. Open a post, then use **Recommend Pivots** in MANTIS AI to get next steps.

## Breach Watcher

Sidebar: **Breach** (`breach-watcher`).

Feeds of breach and leak reports, plus search over leak catalogues.

- **Refresh Feeds** pulls the enabled sources. Source filter: **All Sources**, DailyDarkWeb, HaveIBeenPwned, DataBreaches.net, DarkWebInformer, Securenza CTI, Infostealers Stats, RecentBreaches, DataBreach.watch.
- **Live Breach Feed** shows the latest items.
- **HaveIBeenPwned Catalog** lists breaches from the HIBP catalogue.
- **Leak-Lookup Search** searches leaks by **Domain**, **Email Address**, **Username** or **IP Address** (requires a Leak-Lookup key). **Search Leaks** runs it; results appear under **Evidence**.
- **Filter** and **Search Catalog** narrow the catalogue.
- AI helpers: **AI Summarizer** and **AI IOC Extractor**.

Search only identifiers you are authorised to check, and handle results as personal data.

## Credential Stealer

Sidebar: **Credential Stealer** (`credential-stealer`). Data is stored in `backend/data/credential_stealer.db`.

A pipeline for infostealer log dumps:

1. **Sources.** Add a local folder (`/api/credential-stealer/sources/local`), upload a file (`/sources/upload`), or sync a Telegram channel (`/sources/telegram`). Scan a local source again with `/sources/local/{source_id}/scan`, or use `/sync-all`.
2. **Parsers.** Each log format needs a parser. Test one on sample lines with `/parsers/test`, or have AI draft one with `/parsers/ai-generate`.
3. **Credentials.** Parsed rows are listed with `/credentials`, and rows that no parser matched are kept under `/unparsed`. Export or batch-delete from the list.
4. **Watchlist.** Add domains or accounts to `/watchlist` so matches are flagged.
5. **Overview.** `/overview` summarises the totals; `/jobs` shows running and past ingest jobs.

Handle these dumps as sensitive data. Keep the store on a machine you control and delete sources you no longer need.

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/x-monitor/accounts` | GET, POST | List or add accounts. |
| `/api/x-monitor/accounts/update`, `/accounts/delete` | POST | Edit or remove an account. |
| `/api/x-monitor/dashboard` | POST | Posts for the selected window and filters. |
| `/api/x-monitor/refresh` | POST | Fetch recent posts (X API key required). |
| `/api/breach-watcher/feed`, `/api/breach-watcher/stats` | GET | Breach feed and counts. |
| `/api/breach-watcher/hibp/breaches`, `/hibp/breach/{name}`, `/hibp/latest`, `/hibp/dataclasses` | GET | HIBP catalogue. |
| `/api/breach-watcher/leak-lookup/search` | POST | Leak-Lookup search. |
| `/api/credential-stealer/overview`, `/jobs`, `/credentials`, `/unparsed` | GET | Stealer pipeline views. |
| `/api/credential-stealer/sources`, `/parsers`, `/watchlist` | GET, POST | Sources, parsers and watchlist. |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| **X API key required** | Add the key from **Open API Settings**. |
| Breach feed empty | Click **Refresh Feeds**; check the source is enabled. |
| Leak-Lookup returns nothing | Check the Leak-Lookup key is set in **Settings -> API Keys**. |
| Stealer rows missing | Add a parser for the log format, then rescan the source. |
