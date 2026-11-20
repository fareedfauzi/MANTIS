# MANTIS Documentation

MANTIS is a self-hosted threat-intelligence workbench. The web UI is one page with a sidebar of workbenches; the backend is a FastAPI service that queries intelligence providers, runs local engines (YARA, Similarity, Binary Lab, Infrastructure Hunt) and hosts the MANTIS AI case tools.

Start with the guide that matches your task. Each feature guide has the same layout: what it is, the screens, a step-by-step tutorial, and troubleshooting.

## Start here

| Guide | Read it when |
| --- | --- |
| [Getting Started](getting-started.md) | You are installing MANTIS, choosing a deployment mode, or setting up API keys and admin access. |
| [Interface Tour](interface-tour.md) | You want the map of every sidebar group and tab. |

## Investigation

| Guide | Sidebar group | Covers |
| --- | --- | --- |
| [IOC Search](ioc-search.md) | IOC Intelligence | Hash, domain, IP, URL, keyword lookups; source selection; pivots; history; data feeds. |
| [MANTIS AI](mantis-ai.md) | Panel (all pages) | Chat, pivot recommendations, agent runs, case sync, attribution, reports, AI workspace export. |
| [Infrastructure Hunting](infrastructure-hunting.md) | IOC Intelligence | Seed fingerprinting, C2 playbooks, multi-engine hunts, pivots, confidence tiers, scheduled runs. |
| [Threat Intelligence](threat-intelligence.md) | Threat Intelligence | Today's Intelligence, CTI Articles, Ransomware Monitor, Intel Reports, PoC Index, OSV. |
| [Threat Knowledge](threat-knowledge.md) | Threat Knowledge | Threat Actors, Kaspersky TIP, Malware & Tools, Hunting Library. |
| [Sigma Rules](sigma-rules.md) | Threat Knowledge | Rules Explorer, Stats, Emerging Threats, MITRE ATT&CK, Convert, Manager. |
| [YARA](yara.md) | Threat Knowledge | Rule Explorer, Sample Scanner, Rule Workbench. |
| [Similarity](similarity.md) | Threat Knowledge | Entities, reference samples, feature extraction, comparison. |

## Monitoring and collection

| Guide | Sidebar group | Covers |
| --- | --- | --- |
| [Monitoring](monitoring.md) | Monitor | X Monitor, Breach Watcher, Credential Stealer. |
| [Telegram Toolkit](telegram-toolkit.md) | Telegram Toolkit | Account login, channel monitoring, targets, bots, message dumps, Discord C2 dump. |
| [Samples Downloader](vt_bulk_downloader.md) | Samples Downloader | Batch VirusTotal sample acquisition, folder or encrypted ZIP. |

## Reverse engineering and drawing

| Guide | Sidebar group | Covers |
| --- | --- | --- |
| [AI Binary Analysis Lab](ai_binary_lab.md) | Reverse Engineering | IDA/Ghidra analysis, .NET and Go support, renaming, AI workspace, reports. |
| [Malware Repository](threat-knowledge.md#malware-repository) | Reverse Engineering | Local sample store, staging and downloads. |
| [Drawing Tools](drawing-tools.md) | Drawer and Viewer | Diagrams, flowcharts, mind maps, maps, charts, Mermaid, Markdown. |

## Reference

| Guide | Covers |
| --- | --- |
| [API Reference](api-reference.md) | Endpoint families and what each does. |
| [Data and Storage](data-and-storage.md) | Where MANTIS writes databases, caches, reports and uploads. |

## Conventions used in these guides

- **Bold labels** are buttons or tabs as they appear in the UI.
- `code` is a field name, endpoint, file or environment variable.
- Examples use documentation indicators (RFC 5737 IPs, `example.com`). Replace them with your own.
- Several features call external services. Check the provider key status in **Settings -> API Keys** before a run.

## Safety

MANTIS is built for passive, read-only collection. Some features still contact third parties: provider APIs, Telegram, URLScan, and AI providers. The Binary Lab and Similarity tools analyse files statically and do not execute submitted samples, but uploaded files stay on the server until you delete them. Handle live malware in an isolated environment.
