# Interface Tour

The sidebar groups every workbench. Labels below are the ones shown in the UI. Sub-tabs sit under their parent entry.

## Layout

- **Home**: the entry screen. Entering a workbench opens it in the main area.
- **Sidebar**: eight sections. Collapsed, it shows icons only.
- **Workspace**: the open tab. Several tabs have sub-navigation (Ransomware Intelligence, Sigma, YARA, Similarity, Threat Actor/Kaspersky, Malware & Tools).
- **MANTIS AI panel**: opens over most result pages and reads the visible results and the current case.
- **Settings**: API keys, AI provider, GitHub repositories, deployment mode, and (Team Server) user management.

## IOC Intelligence

| Sidebar label | Tab ID | Purpose | Guide |
| --- | --- | --- | --- |
| IOC Search | `ioc-search` | Lookup of hashes, domains, IPs, URLs, keywords | [IOC Search](ioc-search.md) |
| IOC Lookup History | `history` | Local record of past lookups; saved AI reports | [IOC Search](ioc-search.md#history) |
| Infra Search | `infra` | Seed fingerprinting and multi-engine hunts | [Infrastructure Hunting](infrastructure-hunting.md) |
| Infra Pivot | `infra-pivoting` | Pivot from an infrastructure seed | [Infrastructure Hunting](infrastructure-hunting.md#pivoting) |
| Infra History | `infra-history` | Saved hunts and their run history | [Infrastructure Hunting](infrastructure-hunting.md#saved-hunts-and-scheduling) |
| OpenDir Hunt | `opendir` | Open-directory discovery | [Infrastructure Hunting](infrastructure-hunting.md#opendir-hunt) |
| C2 Hunting Catalog | `c2-hunting-catalog` | Searchable C2 playbook queries | [Infrastructure Hunting](infrastructure-hunting.md#c2-playbook-catalog) |
| C2 & Tool Exposure | `exposure-monitor` | Tracked exposure queries for C2 and tooling | [Infrastructure Hunting](infrastructure-hunting.md#c2--tool-exposure) |
| Data Feeds | `data-feeds` | Feed catalog, toggles, API key status | [IOC Search](ioc-search.md#data-feeds) |

## Threat Intelligence

| Sidebar label | Tab ID | Purpose | Guide |
| --- | --- | --- | --- |
| Today's Intelligence | `todays-intel` | Daily consolidated view and AI brief | [Threat Intelligence](threat-intelligence.md#todays-intelligence) |
| Ransomware Intelligence | `ransom-overview` | Overview; sub-tabs Victims, Groups, Trends, Regions, Notes, Crypto | [Threat Intelligence](threat-intelligence.md#ransomware-intelligence) |
| CTI Articles | `cti` | Local CTI article corpus and AI summaries | [Threat Intelligence](threat-intelligence.md#cti-articles) |
| Country & Industry Reports | `intel-reports` | AI-written reports by country, industry or tag | [Threat Intelligence](threat-intelligence.md#country--industry-reports) |
| Vulnerability Intel | `poc-index` | CVE, PoC, KEV and EPSS index | [Threat Intelligence](threat-intelligence.md#vulnerability-intel) |
| Malicious Packages | `osv-malicious` | OSV malicious-package intelligence | [Threat Intelligence](threat-intelligence.md#malicious-packages) |

## Threat Knowledge

| Sidebar label | Tab ID | Purpose | Guide |
| --- | --- | --- | --- |
| Threat Actor | `ta` | MISP galaxy threat-actor profiles | [Threat Knowledge](threat-knowledge.md#threat-actor-and-malware--tools) |
| Kaspersky | `ktip-ta` | Kaspersky TIP actors and reports | [Threat Knowledge](threat-knowledge.md#kaspersky) |
| Malware & Tools | `mwtools` | MISP galaxy malware and tool profiles | [Threat Knowledge](threat-knowledge.md#threat-actor-and-malware--tools) |
| Threat Hunting Library | `hunting-library` | Hunting queries and VT hunting notifications | [Threat Knowledge](threat-knowledge.md#threat-hunting-library) |
| Sigma: Rules Explorer, Rules Stats, Emerging Threats, MITRE ATT&CK, Convert to Query, Manager | `sigma-rules`, `sigma-stats`, `sigma-emerging`, `sigma-mitre`, `sigma-convert`, `sigma-manager` | Sigma rule work | [Sigma Rules](sigma-rules.md) |
| YARA: Rule Explorer, Sample Scanner, Rule Workbench | `yara-explorer`, `yara-scanner`, `yara-workbench` | YARA work | [YARA](yara.md) |
| Similarity: Overview, Families, Compare | `similarity-dashboard`, `similarity-entities`, `similarity-compare` | Malware similarity | [Similarity](similarity.md) |

## Monitor

| Sidebar label | Tab ID | Purpose | Guide |
| --- | --- | --- | --- |
| X | `x-monitor` | Public X account timeline | [Monitoring](monitoring.md#x-monitor) |
| Breach | `breach-watcher` | Breach feeds, HIBP and leak lookup, detection rules | [Monitoring](monitoring.md#breach-watcher) |
| Credential Stealer | `credential-stealer` | Stealer-log parsing and credential search | [Monitoring](monitoring.md#credential-stealer) |

## Drawer and Viewer

| Sidebar label | Tab ID | Guide |
| --- | --- | --- |
| Diagram | `diagram-draw` | [Drawing Tools](drawing-tools.md) |
| Flow Chart | `flowchart-draw` | [Drawing Tools](drawing-tools.md) |
| Mindmap | `mindmap-draw` | [Drawing Tools](drawing-tools.md) |
| Map Chart | `mapchart-draw` | [Drawing Tools](drawing-tools.md) |
| Chart Creator | `chart-creator` | [Drawing Tools](drawing-tools.md) |
| Mermaid Viewer | `mermaid-draw` | [Drawing Tools](drawing-tools.md) |
| Markdown Viewer | `markdown-draw` | [Drawing Tools](drawing-tools.md) |

## Reverse Engineering

| Sidebar label | Tab ID | Guide |
| --- | --- | --- |
| AI Binary Analysis Lab | `binary-lab` | [AI Binary Analysis Lab](ai_binary_lab.md) |
| Malware Repository | `malware-db` | [Threat Knowledge](threat-knowledge.md#malware-repository) |

## Samples Downloader

| Sidebar label | Tab ID | Guide |
| --- | --- | --- |
| VT Samples Downloader | `samples-downloader` | [Samples Downloader](vt_bulk_downloader.md) |

## Telegram Toolkit

| Sidebar label | Tab ID | Guide |
| --- | --- | --- |
| Telegram | `tg-channel-mon` | [Telegram Toolkit](telegram-toolkit.md#telegram-auth-settings) |
| Bot Info | `tg-info` | [Telegram Toolkit](telegram-toolkit.md#telegram-auth-settings) |
| Dump Messages | `tg-invest` | [Telegram Toolkit](telegram-toolkit.md#dump-messages) |
| Discord C2 Dump | `discord-c2-dump` | [Telegram Toolkit](telegram-toolkit.md#discord-c2-dump) |
| Telegram Auth Settings | `tg-auth-settings` | [Telegram Toolkit](telegram-toolkit.md#telegram-auth-settings) |
