# IOC Search

IOC Search is where most investigations start. You enter an indicator, pick the sources to query, and MANTIS returns one card per provider rather than a single merged verdict. Results can be pivoted, saved to history, exported, or handed to MANTIS AI.

## Supported inputs

| Type | Examples | Notes |
| --- | --- | --- |
| Hash | MD5, SHA-1, SHA-256 | Detected by length and format. |
| Domain | `example.com` | Subdomains are accepted. |
| IP | `192.0.2.10`, IPv6 | Public IPs get the widest source coverage. |
| URL | `https://example.com/a/b` | Parsed into host and path where a source needs it. |
| Keyword | `Cobalt Strike`, `CVE-2024-3400`, an actor name | Searches the local catalogs and keyword-capable providers. |
| Infrastructure | ASN, CIDR, certificate SHA-256 | Also available as the **Infra** type; see [Infrastructure Hunting](infrastructure-hunting.md). |

Leave the type on **Auto-detect** unless the value is ambiguous (for example, a keyword that looks like a domain).

## The screen

- **Search box**: the indicator. Press Enter or **Search**.
- **Type selector**: Auto-detect, Hash, Domain, IP, URL, Keyword, Infra.
- **Sources**: the provider list. Sources are grouped into free or local, and API-backed. Sources without a key show as not configured.
- **Result cards**: one card per source, with reputation, detections, passive DNS, certificates, sightings, MISP context, and so on. Each card opens a drawer with the full record. Some details load lazily when you open them.
- **Pivots**: values inside a card (a domain, IP, hash, certificate) can be clicked to run a new lookup.

## Tutorial: investigate a suspicious domain

1. Open **IOC Intelligence -> IOC Search**.
2. Type `example.com` and leave the type on Auto-detect.
3. In **Sources**, keep the free sources (crt.sh, RIPEstat, ThreatMiner, OpenPhish) and add any keyed sources you configured, such as VirusTotal or URLScan.
4. Click **Search**. Wait for the cards to fill in. A source that errors shows its message on its own card, so one failing provider does not stop the rest.
5. Open the crt.sh card to see certificates. Click an IP in the passive DNS section to pivot to it.
6. Open the **MANTIS AI** panel and choose **Recommend Pivots** to see ranked next steps. Suppressed pivots (placeholders, noisy shared infrastructure, duplicates) are listed with a reason.
7. Use **Export** to download the results as JSON or CSV, or keep the page open and use **IOC Lookup History** to return to it later.

## Tutorial: hash triage

1. Enter a SHA-256 and search.
2. Read the detection and sandbox cards first (VirusTotal, Hybrid Analysis, Triage, MalwareBazaar, if configured).
3. Open the family or signature fields. A family name can be used as a keyword lookup, which shows related reports and Malware & Tools entries.
4. If the sample is a real binary you want to study, open **Samples Downloader** or the **AI Binary Analysis Lab** (see [Samples Downloader](vt_bulk_downloader.md) and [AI Binary Analysis Lab](ai_binary_lab.md)).

## Tutorial: keyword research

1. Set the type to **Keyword**.
2. Enter an actor, malware family or CVE.
3. Results come from the CTI article corpus, MISP galaxy, PoC and KEV indexes, and any configured keyword providers.
4. Use the result to open **Threat Knowledge -> Threat Actors** or **Malware & Tools** for the full profile.

## Sources

Free and local sources need no key: crt.sh, RIPEstat, SANS ISC, OpenPhish, PhishStats, ThreatMiner, ORKL CTI, Malware.News, RansomLook.io, MISP Galaxy, the CTI article database, the PoC/KEV/OSV indexes, Common Crawl and Wayback lookups, and the Telegram and X local caches.

API-backed sources need a key in **Settings -> API Keys**: VirusTotal, Abuse.ch (ThreatFox, MalwareBazaar, URLhaus, YARAify), AlienVault OTX, AbuseIPDB, URLScan.io, Hatching Triage, Hybrid Analysis, MalShare, Kaspersky TIP, Shodan, Censys, Silent Push, Driftnet, Validin, Pulsedive, FOFA, DNSDumpster, GreyNoise, LeakIX, ThreatBook, Ransomware.live PRO, GitHub, and Twitter/X via TwitterAPI.io.

A source with no key does not fail the search. It shows a "not configured" state on its card.

## History

**IOC Lookup History** keeps a local record of lookups, with filters for **All**, **Hash**, **Domain**, **IP**, **URL** and **Keyword**. Use **Clear History** to remove the local record. It also lists **AI Reports** you saved, so you can reopen or delete them.

## Data Feeds

**Data Feeds** is the catalog of built-in threat sources (31 at last count, by type: hash, domain, IP, URL, infra, keyword). For each feed you can:

- Enable or disable it. **Enable visible feeds**, **Disable visible feeds** and **Clear selection** act on the current filter.
- Filter by **Enabled**, **Disabled**, **Built-in**, **Community**, or by configured or missing key.
- Click **Download selected CSV** to export the selected feeds.
- **Sync directory** to refresh the catalog.
- **Export API Keys** / **Import API Keys** to move keys between installs. Treat the export file as a secret.

Under **API Key Configuration**, each keyed feed shows configured or not configured. Under **GitHub Target Repositories**, set the repositories and branch to search, then click **Save Repositories**. Click **Save Settings** after changing the X source choice.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| A card says "API key required" | Add the key in **Settings -> API Keys**. |
| Few results for a domain | Free passive sources cover limited data. Add a keyed source. |
| A card says rate limited | The provider quota is used up for the day. Retry later or remove that source for this run. |
| Keyword search is slow the first time | Local indexes load on first use. |
