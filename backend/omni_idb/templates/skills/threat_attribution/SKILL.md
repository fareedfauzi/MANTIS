---
name: threat-attribution
description: Autonomous threat actor and campaign attribution skill based on the structured 6-Category Threat Attribution Framework and active internet OSINT searching.
---

# Threat Attribution via Autonomous Reverse Engineering & Live Threat Intelligence

This skill guides an autonomous AI agent to perform rigorous, evidence-grounded threat actor and campaign attribution. It synthesizes findings from `threat_attribution_result.md` and hands-on reverse engineering (`catalog/`, `modules/`, `headers/`, and `src/`) with **active live internet searches** and external OSINT lookups.

This framework is built upon the **Evidence-Based Threat Attribution Model** (structured 6-category analytical guideline) and professional intelligence community standards (ODNI ICD 203).

---

## 1. Core Principles & Attribution Architecture

### The 3 Levels of Attribution
Attribution must never jump directly to a nation-state. Maintain strict separation across three hierarchical tiers:
1. **Technical Attribution (The Capability & Infrastructure)**:
   - Specific malware family (e.g., *QakBot*, *PlugX*, *Chuxian*, *Sliver*).
   - Build environment, code reuse, encryption algorithms, PDB paths, mutex naming schemes, C2 protocols.
2. **Operational Attribution (The Intrusion Set / Operator Cluster)**:
   - Tactical threat cluster or activity group (e.g., *UNC2596*, *DEV-0586*, *Storm-0501*).
   - Operational cadence, targeting profile, victimology, persistence preferences, lateral movement tradecraft.
3. **Strategic Attribution (The Entity & Sponsor)**:
   - The sponsoring government or parent organization (e.g., *FSB*, *GRU Unit 74455*, *MSS*, *DPRK RGB*).
   - Requires political/geopolitical intelligence convergence; mark as an inference or cite external agency reporting.

### Fundamental Attribution Rules
- **Prefer No Attribution Over Speculative Attribution**: If evidence is ambiguous, commodity, or circumstantial, conclude `Unknown Actor / Uncorrelated Activity` or `Commodity Malware`.
- **Multi-Source Convergence**: A single artifact (one IP, domain, mutex, registry key, or hash) is **never** sufficient. Attribution requires convergence across multiple independent evidence categories.
- **Deception and False-Flag Awareness**: Threat actors frequently plant deceptive strings (e.g., false language code pages, borrowed mutexes, misleading PDB paths) or adopt publicly available open-source tools to evade or misdirect attribution.
- **Evidence Citation**: Cite specific decompiled function addresses (`0x...`), catalog files, or external CTI identifiers for every analytical assertion.

---

## 2. Active Internet Search & Googling (Mandatory Agent Workflow)

> [!IMPORTANT]
> **Do NOT rely solely on internal API services, pre-computed local databases, or cached results.**
> As an autonomous AI agent, you must **actively perform live internet searches (Googling / web searching)** just like you normally do when conducting threat intelligence research. Treat local lookup results as initial leads, and independently search the web to verify, enrich, and cross-reference every artifact.

### 2.1 Use Your Native Web Search & Googling Capabilities
Use your built-in web search tools (such as `search_web`, Google search, DuckDuckGo, browser tools, or terminal curl/fetch) throughout the entire attribution workflow. Formulate precise, quoted search queries for:

1. **Googling Unique String Literals & Mutexes**:
   - Query: `"<mutex_name>"` `malware OR "threat actor" OR "intrusion set" OR writeup`
   - Query: `"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\<KeyName>"`
   - Search for unique error messages, user-agents, URI paths, or configuration markers.
   - *Goal*: Identify existing DFIR analysis, sandbox writeups (VirusTotal, Any.Run, Hatching Triage, JoeSandbox), or public detection rules (YARA, Sigma).

2. **Googling Cryptographic & API Hashing Constants**:
   - Query: `"<hex_constant>"` `hashing OR "API resolver" OR "string decrypt" OR algorithm`
   - Look up magic constants (e.g. `0xEDB88320`, `0x811C9DC5`, custom S-boxes, or distinctive byte arrays) to identify known malware families or crypto implementations.
   - *Goal*: Confirm whether the cryptographic or hashing routine matches a documented proprietary implementation or a public library.

3. **Googling PDB Debug Paths & Developer Usernames**:
   - Query: `"<project_name>.pdb"` OR `"<internal_solution_path>"`
   - *Goal*: Check for leaked source code repositories, CTF writeups, public GitHub repos, or previous malware campaigns by the same developer.

4. **Googling GitHub for Open-Source & Commodity Proof**:
   - Query: `"<unique_function_name>"` `site:github.com`
   - Query: `"<distinctive_struct_or_variable>"` `site:github.com`
   - *Goal*: Determine whether the technique or code was simply copied verbatim from a public tool (e.g., Havoc, Sliver, SharpHound, Mimikatz, Meterpreter, AsyncRAT, QuasarRAT) or is genuinely custom adversary tradecraft.

5. **Googling Threat Actor Aliases & Vendor Concordance**:
   - Query: `"<Actor_Name>" "aka" OR "aliases" OR "associated with"`
   - Query: `"<Malware_Family>" technical analysis site:mandiant.com OR site:crowdstrike.com OR site:securelist.com OR site:microsoft.com OR site:sentinelone.com OR site:unit42.paloaltonetworks.com`
   - *Goal*: Reconcile vendor naming differences:
     - **Microsoft**: *Storm-XXXX*, *DEV-XXXX*, *Forest Blizzard*, *Midnight Blizzard*, *Aqua Blizzard*
     - **CrowdStrike**: *FANCY BEAR*, *COZY BEAR*, *WIZARD SPIDER*, *LUMINOUS PANDA*
     - **Mandiant**: *APT28*, *APT29*, *UNC2452*, *FIN7*
     - **Kaspersky (GReAT)**: *Sofacy*, *CozyCar*, *Lazarus*, *Equation*

### 2.2 Workspace OSINT CLI Tool (`osint_lookup.py`)
In addition to your direct Googling / web searches, you can execute the bundled standalone OSINT CLI tool in the workspace terminal:

```bash
# Query file hash across public databases (CIRCL Hashlookup, AlienVault OTX)
python osint_lookup.py --hash <sha256>

# Query domain or IP for live RDAP registration, registrar, ASN, and network CIDR
python osint_lookup.py --domain <c2-domain.com>
python osint_lookup.py --ip <ip-address>

# Search public CTI and GitHub for unique mutexes, PDBs, registry keys, or error strings
python osint_lookup.py --query "Global\\YourExtractedMutex"
python osint_lookup.py --query "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\CustomKey"
```

---

## 3. Autonomous Reverse Engineering Verification

Do not accept external CTI claims at face value. Actively verify them against the sample's code in the workspace:

### 1. Code & Payload Verification
- **String Decryption & Constants**:
  - Check `catalog/strings.json` and functions categorized under `crypto` or `encoding`.
  - Inspect decryption algorithms (e.g., custom XOR key, AES with hardcoded IV, RC4 with distinctive key derivation, byte-rolling).
  - Verify if string encryption matches documented actor-specific implementations.
- **API Resolution & Evasion**:
  - Check `catalog/triage_indicators.json` and `catalog/imports.json`.
  - Is the sample using API hashing (e.g., ROR13, MurmurHash, CRC32, custom polynomial)? Check the hash constants in `catalog/functions.json` and decompiled C files.
  - Look for anti-debug, anti-VM, process hollowing, or direct system calls (`syscall`).
- **Configuration Extraction**:
  - Locate configuration parsing functions (frequently in `01_initialization` or `03_network`).
  - Confirm C2 fallback lists, campaign IDs, beacon interval parameters, or encryption flags.

### 2. Host Artifact Verification
- **Registry & Persistence**:
  - Cross-check registry paths in `catalog/strings.json` with decompiled logic in `04_persistence` or `06_system`.
  - Note exact subkey paths, value names, and execution parameters (e.g., `cmd.exe /c`, `rundll32.exe`, PowerShell payloads).
- **Mutex & Synchronization**:
  - Search for `CreateMutexA`/`CreateMutexW` calls in `catalog/imports.json`.
  - Confirm the hardcoded mutex string format (e.g., `Global\{UUID}`, specific naming patterns, or environment-derived tokens).

### 3. Network & Infrastructure Verification
- **C2 Beacon Structure**:
  - Check decompiled functions calling WinINet, WinHTTP, or raw sockets in `03_network`.
  - Analyze User-Agent strings, custom HTTP headers, URI patterns, and beacon payload serialization.
  - Determine whether network communication relies on proprietary binary protocols or commodity frameworks (e.g., Cobalt Strike malleable C2, Metasploit stagers).

---

## 4. 6-Category Threat Evidence Assessment Matrix

Construct and evaluate the six evidence dimensions:

| Category | Evidence Dimension | What to Look For | Rating |
| :--- | :--- | :--- | :--- |
| **1. Malware & Code** | Unique code reuse, build artifacts, crypto, packers | Custom algorithms, unique PDB paths, custom packers, distinctive API hashing, proprietary config blocks | Absent / Weak / Moderate / Strong |
| **2. Infrastructure** | C2 domains, IPs, dynamic DNS, hosting, certificates | Dedicated IP ranges, bulletproof hosters, distinctive SSL cert subjects, consistent registration traits | Absent / Weak / Moderate / Strong |
| **3. TTP Implementation** | Distinctive behaviors & procedural execution | Unique persistence combos, distinctive process injection targets, specific command execution syntax | Absent / Weak / Moderate / Strong |
| **4. Campaign Context & Intent** | Target industry, geography, lures, motivations | Financial extortion (ransomware), cyber espionage, destructive wiper, specific regional victimology | Absent / Weak / Moderate / Strong |
| **5. OpSec & Human Artifacts** | Developer artifacts, language, compile timestamps | Real vs stomped PE timestamps, developer paths, typoglycemia, language code pages, operator errors | Absent / Weak / Moderate / Strong |
| **6. External Reporting** | Published CTI articles, MISP galaxy profiles, live OSINT | Corroborating vendor reports, non-circular multi-vendor writeups, Malpedia entries, active web search hits | Absent / Weak / Moderate / Strong |

### Deception & False Flags Checklist
Before finalizing attribution, test the following counter-hypotheses:
- [ ] **Commodity / Shared Tooling**: Is the binary a standard build of Sliver, Cobalt Strike, Metasploit, Havoc, or an open-source GitHub tool? If yes, downgrade code confidence unless proprietary modifications are proven.
- [ ] **Shared / Cloud Infrastructure**: Are the IP addresses or domains hosted on shared CDNs (Cloudflare, Fastly, AWS) or sinkholes? Shared infrastructure alone cannot attribute an actor.
- [ ] **False Flag Remnants**: Are there glaringly obvious language strings, debug comments, or known signatures that contradict the rest of the sample's tradecraft?
- [ ] **Circular Reporting**: Are multiple vendor reports merely quoting the same initial tweet or blog post without independent analysis?
- [ ] **Timestomping**: Is the compile timestamp plausible (e.g. aligns with working hours of the suspected region) or intentionally altered (e.g., 1970, 2099, or zeroed out)?

---

## 5. Calibrated Attribution Confidence & Reporting

Assign a standardized confidence level:
- **High Confidence**: Supported by strong evidence in at least 3 categories (including confirmed code/config similarity and infrastructure/TTP overlap), verified via live OSINT, with zero unresolved contradictions.
- **Moderate Confidence**: Supported by plausible code or infrastructure overlap and corroborating CTI writeups, but with incomplete data or potential shared tools.
- **Low Confidence**: Weak or ambiguous indicators (e.g. only matching a common IP, generic detection rule, or open-source tool).
- **Inconclusive**: Activity appears commodity, generic, or conflicting evidence suggests intentional deception.

### Incorporating Findings into Reports:
When synthesizing the final `report.md` or `investigation.md`:
1. Include a dedicated **"Threat Attribution & Campaign Context"** section.
2. Present the **Attribution Candidate Matrix** with confidence ratings, supporting evidence IDs, cited code addresses (`0x...`), and live OSINT citations.
3. Explicitly state **Contradictions, Deception Analysis, and Collection Gaps**.
4. Use probabilistic intelligence language (*"almost certainly"*, *"highly likely"*, *"likely"*, *"tentatively"*).
