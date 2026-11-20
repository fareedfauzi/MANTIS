# Threat Intelligence

The Threat Intelligence group covers what is happening now: the daily brief, ransomware activity, CTI articles, country and industry reports, vulnerability exploitation, and malicious packages.

## Today's Intelligence

Sidebar: **Today's Intelligence** (`todays-intel`).

A single view of recent intelligence across the local CTI corpus and feeds.

- **Period:** Today, Past 24H, Past 7D.
- **Source type:** Analyst CTI, Media / news, Vendor research, Government / CERT, Community.
- **Severity:** Critical, High, Medium, Low.
- **Refresh** reloads the view. **Clear** resets the filters.

### Tutorial: morning brief

1. Open **Today's Intelligence** and set period to **Past 24H**.
2. Keep source type to **Analyst CTI** and **Government / CERT** for a short list.
3. Click **AI Daily Brief** for a short summary of the period.
4. For a structured write-up, click **Create Report (AI)**. The report is stored in **IOC Lookup History** under AI Reports.

## Ransomware Intelligence

Sidebar: **Ransomware Intelligence** (`ransom-overview`). Sub-tabs (each has its own tab ID):

| Sub-tab label | Tab ID | What it shows |
| --- | --- | --- |
| Overview | `ransom-overview` | Headline counts and recent activity. |
| Recent Victims | `ransom-victims` | Leak-site victims. |
| Ransomware Groups | `ransom-groups` | Group profiles, infrastructure and negotiation data. |
| Activity & Trends | `ransom-trends` | Activity over time. |
| Regions & Countries | `ransom-regions` | Victims by country. |
| Ransom Notes | `ransom-notes` | Collected ransom notes, plus your own custom notes. |
| Crypto Addresses | `ransom-crypto` | Wallet addresses found in notes. |

Data comes from Ransomware.live and RansomLook. Ransomware.live's PRO features need a PRO key; the page shows "Ransomware.live: No API-PRO key" when it is missing.

### Tutorial: track a group

1. Open **Groups** and search for the group.
2. Read its profile and infrastructure list.
3. Open **Recent Victims** and open a victim for detail.
4. Use **Ransom Notes** to compare the note text with other groups.

## CTI Articles

Sidebar: **CTI Articles** (`cti`).

A local corpus of threat-intelligence articles from RSS and vendor feeds, stored in `backend/data/cti_articles.db`.

- **Sync** pulls the configured sources.
- **Recent Intelligence**, **Sources**, **Malware.News** and **Kaspersky TIP Reports** switch the view.
- Filter by source (**All Sources**) and period (**24h**, **7d**, **30d**, **All time**), and search with **Search reports**. Use **Load more** for older items.
- Open an article to read it, run **AI summary**, or run **AI IOC extraction** to pull indicators out of the article text.
- Sources and categories are managed through `/api/cti/sources` and `/api/cti/categories`.

### Tutorial: from article to pivot

1. Search for a family or actor.
2. Open the article and run **AI IOC extraction**.
3. Send the extracted indicators to [IOC Search](ioc-search.md), or ask MANTIS AI to recommend pivots.

## Country & Industry Reports

Sidebar: **Country & Industry Reports** (`intel-reports`).

AI-written reports built from the CTI corpus, by country, by industry, or by tag.

1. Pick a country or industry.
2. Click to generate the report. Long runs can take a while on reasoning models.
3. If a run fails with "used its whole output budget", raise **Max Output To** in Settings -> AI. Intel Reports uses an 8192-token floor for output, so a reasoning model has room to answer.

## Vulnerability Intel

Sidebar: **Vulnerability Intel** (`poc-index`).

An index of CVEs with public proof-of-concept code, KEV status and EPSS scores.

- **Lists:** Trending PoCs, Newest PoCs, Most PoCs, Highest EPSS, Browse All.
- **Severity:** CRITICAL, HIGH, MEDIUM, LOW.
- **Filters:** KEV, and the PoC source: GITHUB, NUCLEI, METASPLOIT, EXPLOITDB, VULHUB.
- The **CVEs by published year** stats load separately from the **Results** list.

### Tutorial: prioritise a patch cycle

1. Open **Vulnerability Intel**, choose **Highest EPSS**, and turn on **KEV**.
2. Turn on **NUCLEI** or **METASPLOIT** to see which items are easy to test.
3. Use the CVE link to pivot into IOC Search for exploitation reports.

## Malicious Packages

Sidebar: **Malicious Packages** (`osv-malicious`).

Malicious-package advisories from OSV.

- **All Ecosystems** or one of **npm**, **PyPI**, **crates.io**, **RubyGems**, **Go**, **Maven**, **NuGet**.
- The API also supports looking up one package and version (`/api/osv/query`) and opening an advisory by ID (`/api/osv/vuln/{id}`).

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/todays-intelligence` | POST | Filtered daily view. |
| `/api/todays-intelligence/ai-brief` | POST | AI daily brief. |
| `/api/todays-intelligence/ai-report` | POST | AI structured report. |
| `/api/ransomware-monitor/overview` | POST | Ransomware overview. |
| `/api/ransomware-monitor/victims`, `/groups`, `/trends`, `/regions`, `/crypto`, `/ransom-notes` | POST | Ransomware sub-tabs. |
| `/api/ransomware-monitor/watchlist`, `/watchlist/add`, `/watchlist/delete` | POST | Watchlist read and changes. |
| `/api/ransomware-monitor/custom-notes` | GET, POST | Custom notes; `PUT`/`DELETE` on `/{note_id}`. |
| `/api/cti/articles`, `/api/cti/article/{id}` | GET | Articles. |
| `/api/cti/article/{id}/ai-summary`, `/ai-iocs` | POST | AI summary and IOC extraction. |
| `/api/cti/sync` | POST | Sync sources. |
| `/api/intel-reports/countries`, `/industries`, `/tag` | POST | Report lists and generation. |
| `/api/intel-reports/status` | GET | Report availability. |
| `/api/poc/search`, `/api/poc/stats`, `/api/poc/trending` | GET | PoC index. |
| `/api/osv/recent`, `/api/osv/query`, `/api/osv/vuln/{id}`, `/api/osv/ecosystems`, `/api/osv/malicious-stats` | GET, POST | Malicious packages. |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| CTI Articles empty | Run **Sync**, then check **Sources** is enabled. |
| "No API-PRO key" on Ransomware | Add the Ransomware.live PRO key in **Settings -> API Keys**. |
| Intel report fails | Raise **Max Output To** in Settings -> AI. |
| PoC list slow on first open | Stats load separately; wait for the trending list. |
