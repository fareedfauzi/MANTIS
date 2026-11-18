/**
 * MANTIS Mermaid Viewer & Live Studio
 * Interactive Mermaid.js Diagram Editor, Cyber Template Library & High-DPI Exporter
 * Features:
 * - Live Mermaid Code Editor with line numbers, instant debounced rendering & syntax error diagnostics
 * - 10 Cyber Threat Intel, DFIR, Red Team, Detection Engineering & Architecture Mermaid Templates
 *   (Flowchart, Sequence Diagram, State Diagram, Gantt Incident Timeline, ER Schema, Class Diagram, Mindmap, GitGraph, Pie)
 * - Quick Syntax Snippet Inserter & One-Click Graph Direction Flipper (TD / LR / BT / RL)
 * - 6 Mermaid Visual Themes (Cyber Neon Dark, Mermaid Dark, Clean White, Executive Neutral, Forest, High-Contrast)
 * - Interactive Pan & Zoom SVG Viewport with Fit-to-Screen
 * - Export High-DPI PNG & SVG in Transparent, Dark, and White backgrounds + .mmd / Markdown (.md) Save & Load
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'mantis_mermaid_viewer_v1';
    const MERMAID_CDN = 'https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js';

    const FONTS = [
        { id: 'Plus Jakarta Sans', label: 'Plus Jakarta Sans (Default)' },
        { id: 'Inter', label: 'Inter (Clean UI)' },
        { id: 'Space Grotesk', label: 'Space Grotesk (Tech)' },
        { id: 'JetBrains Mono', label: 'JetBrains Mono (Code)' },
        { id: 'IBM Plex Mono', label: 'IBM Plex Mono (Terminal)' },
        { id: 'Rajdhani', label: 'Rajdhani (Tactical)' },
        { id: 'Orbitron', label: 'Orbitron (Cyber)' },
    ];

    const THEMES = [
        { id: 'cyber-dark', label: 'Cyber Dark (MANTIS)' },
        { id: 'dark', label: 'Mermaid Dark' },
        { id: 'default', label: 'Clean Light (Default)' },
        { id: 'neutral', label: 'Executive Neutral' },
        { id: 'forest', label: 'Forest Matrix' },
        { id: 'base', label: 'High-Contrast Base' },
    ];

    const CURVE_STYLES = [
        { id: 'basis', label: 'Smooth Curved (basis)' },
        { id: 'monotoneX', label: 'Horizontal Elbow (monotoneX)' },
        { id: 'stepAfter', label: 'Orthogonal Step (step)' },
        { id: 'linear', label: 'Direct Straight (linear)' },
    ];

    const TEMPLATES = [
        {
            id: 'killchain-flow',
            category: 'Flowchart',
            title: 'Ransomware Intrusion & SOC Containment',
            badge: 'FLOWCHART',
            color: '#38bdf8',
            code: `flowchart LR
    subgraph EXT["External Adversary Infrastructure"]
        A["APT Initial Access Broker\\n185.220.101.44"]
        C2["Mythic C2 Redirector\\ncdn-update- edge[.]com"]
        EX["Mega.nz Exfil Bucket\\n42 GB Archive"]
    end

    subgraph DMZ["Perimeter Edge / DMZ"]
        VPN["SSL VPN Gateway\\nCVE-2024-xxxx Exploit"]
        FW["Perimeter NGFW\\n TLS Inspection"]
    end

    subgraph LAN["Corporate LAN & Tier-0 AD"]
        WK["WKSTN-FIN-042\\nPowerShell Stager"]
        DC["DC01.corp.local\\nDCSync krbtgt"]
        FS["FS01-FINANCE\\nLockBit 3.0 Payload"]
        SOC["MANTIS SOC / EDR\\nAutomated Host Isolation"]
    end

    A -->|"1. Exploit VPN RCE"| VPN
    VPN -->|"2. Stolen VPN Session"| WK
    WK -.->|"3. HTTPS Beacon :443"| FW
    FW -.-> C2
    WK -->|"4. LSASS Dump & Kerberoast"| DC
    DC -->|"5. GPO & SMB PsExec"| FS
    FS -.->|"6. Rclone Outbound"| EX
    DC -->|"Event ID 4662 Alert"| SOC
    SOC ==>|"7. Contain & Revoke"| WK
    SOC ==>|"8. Block C2 IOC"| FW

    style A fill:#3b0712,stroke:#f43f5e,color:#fecdd3
    style C2 fill:#3b0712,stroke:#f43f5e,color:#fecdd3
    style EX fill:#451a03,stroke:#f59e0b,color:#fde68a
    style VPN fill:#431407,stroke:#f97316,color:#fed7aa
    style WK fill:#1e1b4b,stroke:#818cf8,color:#e0e7ff
    style DC fill:#2e1065,stroke:#c084fc,color:#f3e8ff
    style FS fill:#3b0712,stroke:#ef4444,color:#fee2e2
    style SOC fill:#062e22,stroke:#10b981,color:#d1fae5`
        },
        {
            id: 'aitm-sequence',
            category: 'Sequence',
            title: 'AiTM Phishing & MFA Session Hijack',
            badge: 'SEQUENCE',
            color: '#a855f7',
            code: `sequenceDiagram
    autonumber
    actor Victim as Target User (Finance)
    participant Lure as Evilginx3 AiTM Proxy<br/>(login-corp-sso.com)
    participant IdP as Corporate Identity Provider<br/>(Okta / Entra ID)
    actor Attacker as Threat Actor<br/>(Session Replay)

    Attacker->>Victim: Spear-Phishing Email (Urgent Invoice PDF Link)
    Victim->>Lure: GET /oauth2/authorize (Clicks Lure URL)
    Lure->>IdP: Proxies Request to Legitimate IdP
    IdP-->>Lure: Returns Login + FIDO/Push MFA Prompt
    Lure-->>Victim: Renders Cloned Login Page
    Victim->>Lure: Submits Username + Password + Approves MFA
    Lure->>IdP: Forwards Credentials & MFA Challenge
    IdP-->>Lure: Issues Authenticated Session Cookie (ESTSAUTH)
    Note over Lure,Attacker: Session Token Intercepted & Logged!
    Lure-->>Victim: Redirects to Benign SharePoint Document
    Attacker->>IdP: Imports Stolen Session Cookie into Browser
    IdP-->>Attacker: Grants Full Mailbox & Cloud Access (Bypasses MFA)
    Attacker->>IdP: Registers Rogue Authenticator App & Inbox Rule`
        },
        {
            id: 'kerberos-sequence',
            category: 'Sequence',
            title: 'Active Directory Kerberoasting & DCSync',
            badge: 'AD ATTACK',
            color: '#f43f5e',
            code: `sequenceDiagram
    autonumber
    participant Foothold as Compromised Workstation<br/>(WKSTN-042)
    participant KDC as Domain Controller (KDC)<br/>(DC01.corp.local)
    participant Cracker as Offline GPU Rig<br/>(Hashcat Mode 13100)
    participant Tier0 as AD Replication Service<br/>(MS-DRSR)

    Foothold->>KDC: LDAP Query for User Accounts with SPN Set
    KDC-->>Foothold: Returns svc_sqlprod (SPN: MSSQLSvc/sql01:1433)
    Foothold->>KDC: TGS-REQ for MSSQLSvc/sql01 (RC4-HMAC 0x17)
    KDC-->>Foothold: TGS-REP Encrypted with svc_sqlprod NTLM Hash
    Foothold->>Cracker: Exports Kirbi / Hashcat $krb5tgs$23$ Ticket
    Cracker-->>Foothold: Cracks Password Offline -> "Summer2024!Sql"
    Note over Foothold,Tier0: svc_sqlprod is Member of Domain Admins!
    Foothold->>Tier0: DRSGetNCChanges (DCSync) Request as svc_sqlprod
    Tier0-->>Foothold: Replicates krbtgt & All Domain NTLM Hashes`
        },
        {
            id: 'soc-state',
            category: 'State',
            title: 'SOC Incident Response Lifecycle States',
            badge: 'STATE',
            color: '#10b981',
            code: `stateDiagram-v2
    [*] --> AlertIngested: SIEM / EDR Telemetry

    state "Automated Enrichment (SOAR)" as SOAR {
        AlertIngested --> IOCLookup: Extract Hashes, IPs, Domains
        IOCLookup --> ThreatScoring: Query MANTIS CTI & VirusTotal
    }

    ThreatScoring --> AutoClosed: Score < 20 (Known Benign)
    ThreatScoring --> Tier1Triage: Score 20-75 (Suspicious)
    ThreatScoring --> CriticalIncident: Score > 75 (High Confidence Threat)

    Tier1Triage --> AutoClosed: Confirmed False Positive
    Tier1Triage --> CriticalIncident: True Positive Escalated

    state "Active DFIR & Containment" as DFIR {
        CriticalIncident --> HostIsolation: Isolate Endpoint via EDR
        HostIsolation --> ForensicAcquisition: Collect KAPE & Memory Dump
        ForensicAcquisition --> Eradication: Purge Persistence & Rotate Creds
    }

    Eradication --> PostIncidentReview: Recovery Verified
    PostIncidentReview --> DetectionUpdate: Deploy New Sigma / YARA Rules
    AutoClosed --> [*]
    DetectionUpdate --> [*]`
        },
        {
            id: 'dfir-gantt',
            category: 'Timeline',
            title: 'DFIR 72-Hour Intrusion & Response Timeline',
            badge: 'GANTT',
            color: '#f59e0b',
            code: `gantt
    title DFIR Incident IR-2026-089 — Intrusion vs. Response Timeline
    dateFormat  YYYY-MM-DD HH:mm
    axisFormat  %m/%d %H:%M

    section Adversary Activity
    VPN Exploit & Foothold (T1190)       :crit, a1, 2026-11-15 01:00, 3h
    Cobalt Strike Beacon & Recon         :crit, a2, 2026-11-15 04:00, 6h
    LSASS Dump & AD Lateral Movement     :crit, a3, 2026-11-15 10:00, 8h
    Rclone Staging & Exfiltration        :crit, a4, 2026-11-15 18:00, 5h

    section SOC Detection & Triage
    SIEM Alert EID 4662 DCSync Fired     :active, s1, 2026-11-15 19:30, 2h
    Tier-2 Triage & Scope Assessment     :active, s2, 2026-11-15 21:30, 3h

    section DFIR Containment & Recovery
    EDR Fleet Network Containment        :done, d1, 2026-11-16 00:30, 4h
    KAPE Triage & Memory Forensics       :d2, 2026-11-16 04:30, 10h
    Double-Reset krbtgt & VPN Patch      :d3, 2026-11-16 14:30, 6h
    Deploy YARA/Sigma & Threat Hunt      :d4, 2026-11-16 20:30, 8h`
        },
        {
            id: 'cti-er',
            category: 'ER Schema',
            title: 'Threat Intelligence & IOC Graph Schema',
            badge: 'ER DIAGRAM',
            color: '#06b6d4',
            code: `erDiagram
    THREAT_ACTOR ||--o{ CAMPAIGN : orchestrates
    THREAT_ACTOR ||--o{ MALWARE_FAMILY : operates
    CAMPAIGN ||--|{ INTRUSION_SET : includes
    CAMPAIGN ||--o{ IOC_INDICATOR : deploys
    MALWARE_FAMILY ||--o{ YARA_RULE : detected_by
    MALWARE_FAMILY ||--o{ IOC_INDICATOR : generates
    IOC_INDICATOR }o--|| MITRE_TECHNIQUE : maps_to

    THREAT_ACTOR {
        string actor_id PK
        string primary_name
        string origin_country
        string motivation
        int sophistication_tier
    }
    CAMPAIGN {
        string campaign_id PK
        string codename
        date first_seen
        date last_seen
        string target_sector
    }
    IOC_INDICATOR {
        string ioc_id PK
        string ioc_type "ipv4 | domain | sha256 | ja3"
        string ioc_value
        int confidence_score
        string tlp_marking
    }
    MALWARE_FAMILY {
        string malware_id PK
        string family_name
        string category "loader | rat | ransomware | stealer"
        string platform
    }
    YARA_RULE {
        string rule_name PK
        string author
        string severity
    }`
        },
        {
            id: 'c2-class',
            category: 'Class',
            title: 'C2 Implant, Tasking & Transport Architecture',
            badge: 'CLASS',
            color: '#ec4899',
            code: `classDiagram
    class C2TeamServer {
        +String BindAddress
        +Map~String,Session~ ActiveSessions
        +List~Listener~ Listeners
        +registerBeacon(BeaconMetadata meta)
        +queueTask(String sessionId, TaskCommand cmd)
        +decryptTelemetry( byte[] payload )
    }

    class ImplantBeacon {
        +String BeaconUUID
        +Int SleepIntervalMs
        +Float JitterPercent
        +CryptoProvider Cipher
        +checkIn()
        +executeTask(TaskCommand cmd)
        +evadeETWAndAMSI()
    }

    class TransportChannel {
        <<interface>>
        +connect()
        +sendFrame(byte[] frame)
        +receiveFrame() byte[]
    }

    class HttpsMtlsTransport {
        +String UserAgent
        +String HostHeader
        +String Ja3Profile
    }

    class DnsOverHttpsTransport {
        +String ResolverUrl
        +String BaseDomain
    }

    C2TeamServer "1" *-- "many" ImplantBeacon : manages
    ImplantBeacon --> TransportChannel : communicates via
    TransportChannel <|.. HttpsMtlsTransport : implements
    TransportChannel <|.. DnsOverHttpsTransport : implements`
        },
        {
            id: 'mitre-mindmap',
            category: 'Mindmap',
            title: 'Detection Engineering & Telemetry Coverage',
            badge: 'MINDMAP',
            color: '#84cc16',
            code: `mindmap
  root((Detection Engineering Matrix))
    Endpoint Telemetry
      Sysmon & Windows Events
        EID 1 Process Creation
        EID 10 LSASS Access
        EID 4624 / 4662 AD Auth
      Linux eBPF Sensors
        execve & ptrace hooks
        Hidden LKM detection
    Network & Perimeter
      Zeek & Suricata IDS
        JA3 / JA4 TLS Fingerprints
        DNS Beaconing Entropy
      Firewall & Proxy Logs
        Unusual Rclone / Cloud Uploads
    Identity & Cloud
      Entra ID / Okta Logs
        Impossible Travel & AiTM
        OAuth Illicit Consent Grant
      AWS CloudTrail
        IAM AssumeRole Anomalies`
        },
        {
            id: 'sigma-gitgraph',
            category: 'GitGraph',
            title: 'Detection-as-Code (Sigma / YARA) CI/CD Pipeline',
            badge: 'GITGRAPH',
            color: '#6366f1',
            code: `gitGraph
    commit id: "Baseline SIEM Rules v2.4"
    branch threat-intel-intake
    checkout threat-intel-intake
    commit id: "Ingest CTI Report: UNC-4820"
    branch rule-dev-shadowloader
    checkout rule-dev-shadowloader
    commit id: "Author YARA & Sigma Draft"
    commit id: "Replay vs 30d Benign Telemetry (0 FP)"
    checkout threat-intel-intake
    merge rule-dev-shadowloader id: "PR #418 Approved"
    checkout main
    merge threat-intel-intake tag: "v2.5-canary"
    commit id: "Promote to Production EDR & SIEM"`
        },
        {
            id: 'soc-pie',
            category: 'Metrics',
            title: 'Q4 SOC Confirmed Intrusion Initial Access Vectors',
            badge: 'PIE CHART',
            color: '#eab308',
            code: `pie showData
    title Q4 Confirmed Incidents by Initial Access Vector
    "Stolen VPN / SSO Credentials (Infostealer)" : 38
    "AiTM Spear-Phishing Proxy" : 27
    "Public-Facing Edge Appliance CVE" : 19
    "Third-Party / Supply Chain RMM" : 10
    "Malicious NPM / PyPI Package" : 6`
        }
    ];

    const SNIPPETS = [
        { label: '+ Node', snippet: '\n    N1["New Node"] --> N2["Target Node"]' },
        { label: '+ Decision', snippet: '\n    D{"Decision?"} -->|"Yes"| Y["Action A"]\n    D -->|"No"| N["Action B"]' },
        { label: '+ Subgraph', snippet: '\n    subgraph ZONE["Security Zone"]\n        S1["Host A"] --> S2["Host B"]\n    end' },
        { label: '+ Dotted Link', snippet: '\n    A -.->|"C2 Beacon"| B' },
        { label: '+ Thick Link', snippet: '\n    A ==>|"Critical Path"| B' },
        { label: '+ Node Style', snippet: '\n    style A fill:#1e1b4b,stroke:#38bdf8,color:#f8fafc' },
        { label: '+ Seq Msg', snippet: '\n    Alice->>Bob: Request Payload\n    Bob-->>Alice: Response 200 OK' },
        { label: '+ Seq Note', snippet: '\n    Note over Alice,Bob: Encrypted TLS 1.3 Channel' },
    ];

    const state = {
        initialized: false,
        title: TEMPLATES[0].title,
        code: TEMPLATES[0].code,
        theme: 'cyber-dark',
        curve: 'basis',
        fontFamily: 'Plus Jakarta Sans',
        canvasBg: 'dark', // 'dark' | 'white' | 'transparent'
        view: 'split', // 'code' | 'split' | 'preview'
        split: 45, // editor width % in split view
        userMoved: false,
        globalBound: false,
        resizeObserver: null,
        fitRaf: 0,
        presetFilter: 'All',
        presetQuery: '',
        zoom: 1,
        panX: 0,
        panY: 0,
        isPanning: false,
        panStart: { x: 0, y: 0 },
        lastValidSvg: '',
        lastError: null,
        renderCounter: 1,
        debounceTimer: null,
        history: [],
        historyIndex: -1,
    };

    function esc(str) {
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function saveToStorage() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                title: state.title,
                code: state.code,
                theme: state.theme,
                curve: state.curve,
                fontFamily: state.fontFamily,
                canvasBg: state.canvasBg,
                view: state.view,
                split: state.split,
            }));
        } catch (e) { /* ignore */ }
    }

    function loadFromStorage() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return false;
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed.code === 'string' && parsed.code.trim()) {
                state.title = parsed.title || TEMPLATES[0].title;
                state.code = parsed.code;
                state.theme = parsed.theme || 'cyber-dark';
                state.curve = parsed.curve || 'basis';
                state.fontFamily = parsed.fontFamily || 'Plus Jakarta Sans';
                state.canvasBg = parsed.canvasBg || 'dark';
                state.view = ['code', 'split', 'preview'].includes(parsed.view) ? parsed.view : 'split';
                state.split = Number(parsed.split) >= 22 && Number(parsed.split) <= 75 ? Number(parsed.split) : 45;
                return true;
            }
        } catch (e) { /* ignore */ }
        return false;
    }

    function ensureMermaidLoaded() {
        return new Promise((resolve, reject) => {
            if (window.mermaid && typeof window.mermaid.render === 'function') {
                resolve(window.mermaid);
                return;
            }
            let existing = document.querySelector('script[data-mermaid-sdk="1"]');
            if (existing) {
                existing.addEventListener('load', () => resolve(window.mermaid));
                existing.addEventListener('error', reject);
                return;
            }
            const s = document.createElement('script');
            s.src = MERMAID_CDN;
            s.async = true;
            s.setAttribute('data-mermaid-sdk', '1');
            s.onload = () => resolve(window.mermaid);
            s.onerror = (err) => reject(err);
            document.head.appendChild(s);
        });
    }

    function adaptMermaidSvgTheme(svgEl, isWhite) {
        if (!svgEl) return;
        const svgId = svgEl.getAttribute('id') || 'mmd-live-svg';

        let styleTag = svgEl.querySelector('style.mmd-theme-force');
        if (!styleTag) {
            styleTag = document.createElementNS('http://www.w3.org/2000/svg', 'style');
            styleTag.setAttribute('class', 'mmd-theme-force');
            svgEl.appendChild(styleTag);
        }

        if (isWhite) {
            styleTag.textContent = `
                #${svgId} { color: #0f172a !important; fill: #0f172a !important; }
                
                /* 1. All diagram titles & timeline titles: PURE DEEP BLACK */
                #${svgId} .title-text,
                #${svgId} text.title-text,
                #${svgId} .timeline-title,
                #${svgId} .flowchartTitleText,
                #${svgId} .titleText,
                #${svgId} text[id*="title"],
                #${svgId} .title,
                #${svgId} .gitTitleText,
                #${svgId} .statediagram-title,
                #${svgId} .sectionTitle,
                #${svgId} text.sectionTitle {
                    fill: #000000 !important;
                    color: #000000 !important;
                    font-weight: 800 !important;
                    font-size: 19px !important;
                    opacity: 1 !important;
                }

                /* 2. All arrow lines, connector paths, relations & flowchart links: PURE BLACK */
                #${svgId} .edgePath path,
                #${svgId} .edgePath .path,
                #${svgId} .flowchart-link,
                #${svgId} .transition,
                #${svgId} .messageLine0,
                #${svgId} .messageLine1,
                #${svgId} .loopLine,
                #${svgId} .relation,
                #${svgId} path.path,
                #${svgId} .actor-line {
                    stroke: #000000 !important;
                }

                /* 3. Timeline axis lines & dashed tick lines: PURE BLACK */
                #${svgId} .lineWrapper line,
                #${svgId} line.line-wrapper,
                #${svgId} path.line-wrapper,
                #${svgId} .timeline-line,
                #${svgId} line {
                    stroke: #000000 !important;
                }

                /* 4. Arrow markers & arrowheads: PURE BLACK */
                #${svgId} .marker,
                #${svgId} marker path,
                #${svgId} marker polygon,
                #${svgId} .arrowMarkerPath,
                #${svgId} .arrowheadPath,
                #${svgId} #arrowhead path,
                #${svgId} [id*="arrow"] path {
                    fill: #000000 !important;
                    stroke: #000000 !important;
                }

                /* 5. Edge labels & cluster text */
                #${svgId} .edgeLabel span,
                #${svgId} .edgeLabel p,
                #${svgId} .edgeLabel text,
                #${svgId} .edgeLabel {
                    color: #000000 !important;
                    fill: #000000 !important;
                    font-weight: 600 !important;
                }
                #${svgId} .edgeLabel rect {
                    fill: #ffffff !important;
                    opacity: 0.98 !important;
                    stroke: #cbd5e1 !important;
                    stroke-width: 1px !important;
                }
                #${svgId} .cluster text,
                #${svgId} .cluster-label text,
                #${svgId} .cluster-label span,
                #${svgId} .cluster-label p {
                    fill: #000000 !important;
                    color: #000000 !important;
                    font-weight: 700 !important;
                }
                #${svgId} .cluster rect {
                    fill: rgba(241, 245, 249, 0.88) !important;
                    stroke: #64748b !important;
                }

                /* 6. Sequence Actors & Messages */
                #${svgId} .actor text,
                #${svgId} .messageText {
                    fill: #000000 !important;
                    color: #000000 !important;
                    font-weight: 600 !important;
                }

                /* 7. Timeline events, periods, and section labels */
                #${svgId} .timeline-node text,
                #${svgId} .timeline-node tspan,
                #${svgId} [class*="period"] text,
                #${svgId} [class*="period"] tspan,
                #${svgId} [class*="event"] text,
                #${svgId} [class*="event"] tspan,
                #${svgId} [class*="section-"] text,
                #${svgId} [class*="section-"] tspan,
                #${svgId} .taskText,
                #${svgId} .taskTextOutsideRight,
                #${svgId} .taskTextOutsideLeft {
                    fill: #0f172a !important;
                    color: #0f172a !important;
                    font-weight: 600 !important;
                }
                #${svgId} .grid .tick text {
                    fill: #475569 !important;
                }
            `;

            svgEl.querySelectorAll('.title-text, text.title-text, .flowchartTitleText, .titleText, text[id*="title"], .statediagram-title, .gitTitleText, .sectionTitle').forEach(t => {
                t.setAttribute('fill', '#000000');
                t.style.fill = '#000000';
                t.style.color = '#000000';
                t.style.opacity = '1';
                t.style.fontWeight = '800';
            });
            svgEl.querySelectorAll('.edgePath path, .edgePath .path, .flowchart-link, .transition, .messageLine0, .messageLine1, .loopLine, .relation, .actor-line').forEach(p => {
                p.setAttribute('stroke', '#000000');
                p.style.stroke = '#000000';
            });
            svgEl.querySelectorAll('.lineWrapper line, line.line-wrapper, path.line-wrapper, line').forEach(l => {
                l.setAttribute('stroke', '#000000');
                l.style.stroke = '#000000';
            });
            svgEl.querySelectorAll('marker path, marker polygon, .arrowMarkerPath, .arrowheadPath, #arrowhead path').forEach(m => {
                m.setAttribute('fill', '#000000');
                m.setAttribute('stroke', '#000000');
                m.style.fill = '#000000';
                m.style.stroke = '#000000';
            });

            svgEl.querySelectorAll('text, tspan').forEach(t => {
                if (t.classList.contains('title-text') || t.classList.contains('flowchartTitleText') || t.classList.contains('titleText')) {
                    t.setAttribute('fill', '#000000');
                    t.style.fill = '#000000';
                    return;
                }
                const parentG = t.closest('g');
                const rect = parentG ? parentG.querySelector('rect, polygon, path.node-bkg') : null;
                let isDarkNode = false;
                if (rect) {
                    const fill = (rect.getAttribute('fill') || rect.style.fill || '').trim().toLowerCase();
                    if (fill.startsWith('#') && fill.length >= 7) {
                        const r = parseInt(fill.slice(1, 3), 16);
                        const g = parseInt(fill.slice(3, 5), 16);
                        const b = parseInt(fill.slice(5, 7), 16);
                        const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
                        if (lum < 0.45) isDarkNode = true;
                    }
                }
                const chosenColor = isDarkNode ? '#ffffff' : '#0f172a';
                t.setAttribute('fill', chosenColor);
                t.style.fill = chosenColor;
                t.style.color = chosenColor;
            });
        } else {
            // Dark Background: crisp white arrows, lines, and text
            styleTag.textContent = `
                #${svgId} { color: #f8fafc !important; fill: #f8fafc !important; }
                
                /* 1. All diagram titles & timeline titles: PURE WHITE */
                #${svgId} .title-text,
                #${svgId} text.title-text,
                #${svgId} .timeline-title,
                #${svgId} .flowchartTitleText,
                #${svgId} .titleText,
                #${svgId} text[id*="title"],
                #${svgId} .title,
                #${svgId} .gitTitleText,
                #${svgId} .statediagram-title,
                #${svgId} .sectionTitle,
                #${svgId} text.sectionTitle {
                    fill: #ffffff !important;
                    color: #ffffff !important;
                    font-weight: 800 !important;
                    font-size: 19px !important;
                    opacity: 1 !important;
                }

                /* 2. All arrow lines, connector paths, relations & flowchart links: PURE WHITE */
                #${svgId} .edgePath path,
                #${svgId} .edgePath .path,
                #${svgId} .flowchart-link,
                #${svgId} .transition,
                #${svgId} .messageLine0,
                #${svgId} .messageLine1,
                #${svgId} .loopLine,
                #${svgId} .relation,
                #${svgId} path.path,
                #${svgId} .actor-line {
                    stroke: #ffffff !important;
                }

                /* 3. Timeline axis lines & dashed tick lines: PURE WHITE */
                #${svgId} .lineWrapper line,
                #${svgId} line.line-wrapper,
                #${svgId} path.line-wrapper,
                #${svgId} .timeline-line,
                #${svgId} line {
                    stroke: #ffffff !important;
                }

                /* 4. Arrow markers & arrowheads: PURE WHITE */
                #${svgId} .marker,
                #${svgId} marker path,
                #${svgId} marker polygon,
                #${svgId} .arrowMarkerPath,
                #${svgId} .arrowheadPath,
                #${svgId} #arrowhead path,
                #${svgId} [id*="arrow"] path {
                    fill: #ffffff !important;
                    stroke: #ffffff !important;
                }

                /* 5. Edge labels & cluster text */
                #${svgId} .edgeLabel span,
                #${svgId} .edgeLabel p,
                #${svgId} .edgeLabel text,
                #${svgId} .edgeLabel {
                    color: #ffffff !important;
                    fill: #ffffff !important;
                }
                #${svgId} .edgeLabel rect {
                    fill: #0b101b !important;
                    opacity: 0.92 !important;
                }
                #${svgId} .cluster text,
                #${svgId} .cluster-label text,
                #${svgId} .cluster-label span,
                #${svgId} .cluster-label p {
                    fill: #ffffff !important;
                    color: #ffffff !important;
                    font-weight: 700 !important;
                }
                #${svgId} .cluster rect {
                    fill: rgba(15, 23, 42, 0.72) !important;
                    stroke: #475569 !important;
                }

                /* 6. Sequence Actors & Messages */
                #${svgId} .actor text,
                #${svgId} .messageText {
                    fill: #ffffff !important;
                    color: #ffffff !important;
                }

                /* 7. Timeline events, periods, and section labels */
                #${svgId} text,
                #${svgId} tspan,
                #${svgId} .timeline-node text,
                #${svgId} .timeline-node tspan,
                #${svgId} [class*="period"] text,
                #${svgId} [class*="period"] tspan,
                #${svgId} [class*="event"] text,
                #${svgId} [class*="event"] tspan,
                #${svgId} [class*="section-"] text,
                #${svgId} [class*="section-"] tspan,
                #${svgId} .taskText,
                #${svgId} .taskTextOutsideRight,
                #${svgId} .taskTextOutsideLeft {
                    fill: #f8fafc !important;
                    color: #f8fafc !important;
                    font-weight: 600 !important;
                }
                #${svgId} .grid .tick text {
                    fill: #94a3b8 !important;
                }
            `;

            svgEl.querySelectorAll('.title-text, text.title-text, .flowchartTitleText, .titleText, text[id*="title"], .statediagram-title, .gitTitleText, .sectionTitle').forEach(t => {
                t.setAttribute('fill', '#ffffff');
                t.style.fill = '#ffffff';
                t.style.color = '#ffffff';
                t.style.opacity = '1';
                t.style.fontWeight = '800';
            });
            svgEl.querySelectorAll('text, tspan').forEach(t => {
                t.setAttribute('fill', '#f8fafc');
                t.style.fill = '#f8fafc';
                t.style.color = '#f8fafc';
            });
            svgEl.querySelectorAll('.edgePath path, .edgePath .path, .flowchart-link, .transition, .messageLine0, .messageLine1, .loopLine, .relation, .actor-line').forEach(p => {
                p.setAttribute('stroke', '#ffffff');
                p.style.stroke = '#ffffff';
            });
            svgEl.querySelectorAll('.lineWrapper line, line.line-wrapper, path.line-wrapper, line').forEach(l => {
                l.setAttribute('stroke', '#ffffff');
                l.style.stroke = '#ffffff';
            });
            svgEl.querySelectorAll('marker path, marker polygon, .arrowMarkerPath, .arrowheadPath, #arrowhead path').forEach(m => {
                m.setAttribute('fill', '#ffffff');
                m.setAttribute('stroke', '#ffffff');
                m.style.fill = '#ffffff';
                m.style.stroke = '#ffffff';
            });
        }

        // Ensure title at top has ample clearance in viewBox so it never clips
        const titleEl = svgEl.querySelector('.title-text, text.title-text, .flowchartTitleText, .titleText');
        if (titleEl && svgEl.viewBox && svgEl.viewBox.baseVal) {
            const vb = svgEl.viewBox.baseVal;
            if (vb.y >= 0) {
                const shift = 45;
                svgEl.setAttribute('viewBox', `${vb.x} ${vb.y - shift} ${vb.width} ${vb.height + shift}`);
            }
        }
    }

    function configureMermaid(themeOverride, bgOverride) {
        if (!window.mermaid) return;
        const activeTheme = themeOverride || state.theme;
        const isCyberDark = activeTheme === 'cyber-dark';
        const isWhite = (bgOverride || state.canvasBg) === 'white';

        const config = {
            startOnLoad: false,
            securityLevel: 'loose',
            fontFamily: `'${state.fontFamily}', sans-serif`,
            flowchart: {
                htmlLabels: true,
                curve: state.curve || 'basis',
                padding: 16,
                nodeSpacing: 45,
                rankSpacing: 55,
            },
            sequence: {
                diagramMarginX: 30,
                diagramMarginY: 20,
                actorMargin: 55,
                boxMargin: 12,
                messageMargin: 36,
                mirrorActors: true,
                useMaxWidth: false,
            },
            theme: isCyberDark ? (isWhite ? 'default' : 'base') : activeTheme,
        };

        if (isCyberDark) {
            if (isWhite) {
                config.themeVariables = {
                    darkMode: false,
                    background: '#ffffff',
                    fontFamily: `'${state.fontFamily}', sans-serif`,
                    primaryColor: '#f1f5f9',
                    primaryTextColor: '#0f172a',
                    primaryBorderColor: '#0f172a',
                    secondaryColor: '#e2e8f0',
                    secondaryTextColor: '#0f172a',
                    secondaryBorderColor: '#475569',
                    tertiaryColor: '#cbd5e1',
                    tertiaryTextColor: '#0f172a',
                    tertiaryBorderColor: '#64748b',
                    lineColor: '#000000',
                    defaultLinkColor: '#000000',
                    arrowheadColor: '#000000',
                    textColor: '#0f172a',
                    titleColor: '#000000',
                    mainBkg: '#f8fafc',
                    nodeBorder: '#000000',
                    clusterBkg: 'rgba(241, 245, 249, 0.88)',
                    clusterBorder: '#64748b',
                    edgeLabelBackground: '#ffffff',
                    actorBkg: '#f8fafc',
                    actorBorder: '#000000',
                    actorTextColor: '#0f172a',
                    actorLineColor: '#000000',
                    signalColor: '#000000',
                    signalTextColor: '#0f172a',
                    labelBoxBkgColor: '#f1f5f9',
                    labelBoxBorderColor: '#000000',
                    labelTextColor: '#0f172a',
                    loopTextColor: '#000000',
                    noteBkgColor: '#fef3c7',
                    noteTextColor: '#78350f',
                    noteBorderColor: '#d97706',
                    cScale0: '#f8fafc',
                    cScale1: '#e2e8f0',
                    cScale2: '#dcfce7',
                    cScale3: '#fee2e2',
                };
            } else {
                config.themeVariables = {
                    darkMode: true,
                    background: 'transparent',
                    fontFamily: `'${state.fontFamily}', sans-serif`,
                    primaryColor: '#131c31',
                    primaryTextColor: '#f8fafc',
                    primaryBorderColor: '#38bdf8',
                    secondaryColor: '#1e1b4b',
                    secondaryTextColor: '#e0e7ff',
                    secondaryBorderColor: '#818cf8',
                    tertiaryColor: '#0f172a',
                    tertiaryTextColor: '#cbd5e1',
                    tertiaryBorderColor: '#334155',
                    lineColor: '#ffffff',
                    defaultLinkColor: '#ffffff',
                    arrowheadColor: '#ffffff',
                    textColor: '#f1f5f9',
                    mainBkg: '#131c31',
                    nodeBorder: '#38bdf8',
                    clusterBkg: 'rgba(15, 23, 42, 0.72)',
                    clusterBorder: '#475569',
                    titleColor: '#ffffff',
                    edgeLabelBackground: '#0b101b',
                    actorBkg: '#131c31',
                    actorBorder: '#38bdf8',
                    actorTextColor: '#f8fafc',
                    actorLineColor: '#ffffff',
                    signalColor: '#ffffff',
                    signalTextColor: '#f8fafc',
                    labelBoxBkgColor: '#0f172a',
                    labelBoxBorderColor: '#38bdf8',
                    labelTextColor: '#f8fafc',
                    loopTextColor: '#ffffff',
                    noteBkgColor: '#1e1b4b',
                    noteTextColor: '#e0e7ff',
                    noteBorderColor: '#818cf8',
                    cScale0: '#131c31',
                    cScale1: '#1e1b4b',
                    cScale2: '#062e22',
                    cScale3: '#3b0712',
                };
            }
        }

        window.mermaid.initialize(config);
    }

    // =========================================================================
    // UI INITIALIZATION & SHELL
    // =========================================================================
    function initMermaidDraw() {
        const pane = document.getElementById('mermaid-draw-pane');
        if (!pane) return;

        if (!state.initialized) {
            loadFromStorage();
            state.initialized = true;
        }

        renderShell(pane);
        renderTemplateGallery();
        updateEditorLineNumbers();
        bindEvents();
        renderMermaidDiagram(true);
    }

    function renderShell(pane) {
        const view = state.view;
        pane.innerHTML = `
            <div class="mmd-root" id="mmd-studio-root" data-view="${view}">
                <header class="mmd-top">
                    <div class="mmd-top-left">
                        <div class="mmd-logo"><i class="fa-solid fa-code-merge"></i></div>
                        <input type="text" class="mmd-title" id="mmd-title-input" value="${esc(state.title)}" title="Rename diagram" spellcheck="false" />
                        <span class="mmd-status" id="mmd-status-pill" data-ok="1">VALID</span>
                    </div>

                    <div class="mmd-seg" role="tablist" aria-label="View mode">
                        <button type="button" role="tab" data-mmd-view="code" class="${view === 'code' ? 'active' : ''}"><i class="fa-solid fa-code"></i><span>Editor</span></button>
                        <button type="button" role="tab" data-mmd-view="split" class="${view === 'split' ? 'active' : ''}"><i class="fa-solid fa-table-columns"></i><span>Split</span></button>
                        <button type="button" role="tab" data-mmd-view="preview" class="${view === 'preview' ? 'active' : ''}"><i class="fa-solid fa-eye"></i><span>Preview</span></button>
                    </div>

                    <div class="mmd-top-right">
                        <button type="button" class="mmd-tbtn" id="mmd-btn-presets"><i class="fa-solid fa-layer-group"></i><span>Presets</span></button>

                        <div class="mmd-pop-wrap">
                            <button type="button" class="mmd-tbtn" data-mmd-pop="style"><i class="fa-solid fa-sliders"></i><span>Style</span><i class="fa-solid fa-chevron-down mmd-caret"></i></button>
                            <div class="mmd-pop mmd-pop-right" id="mmd-pop-style">
                                <div class="mmd-pop-label">Flow direction</div>
                                <div class="mmd-mini-seg">
                                    <button type="button" data-mmd-dir="LR"><i class="fa-solid fa-arrow-right"></i> LR</button>
                                    <button type="button" data-mmd-dir="TD"><i class="fa-solid fa-arrow-down"></i> TD</button>
                                    <button type="button" data-mmd-dir="RL"><i class="fa-solid fa-arrow-left"></i> RL</button>
                                    <button type="button" data-mmd-dir="BT"><i class="fa-solid fa-arrow-up"></i> BT</button>
                                </div>
                                <div class="mmd-pop-label">Theme</div>
                                <select id="mmd-theme-select" class="dd-select">
                                    ${THEMES.map(t => `<option value="${t.id}" ${state.theme === t.id ? 'selected' : ''}>${esc(t.label)}</option>`).join('')}
                                </select>
                                <div class="mmd-pop-label">Connector curve</div>
                                <select id="mmd-curve-select" class="dd-select">
                                    ${CURVE_STYLES.map(c => `<option value="${c.id}" ${state.curve === c.id ? 'selected' : ''}>${esc(c.label)}</option>`).join('')}
                                </select>
                                <div class="mmd-pop-label">Font</div>
                                <select id="mmd-font-select" class="dd-select">
                                    ${FONTS.map(f => `<option value="${f.id}" ${state.fontFamily === f.id ? 'selected' : ''}>${esc(f.label)}</option>`).join('')}
                                </select>
                            </div>
                        </div>

                        <div class="mmd-pop-wrap">
                            <button type="button" class="mmd-tbtn mmd-primary" data-mmd-pop="export"><i class="fa-solid fa-download"></i><span>Export</span><i class="fa-solid fa-chevron-down mmd-caret"></i></button>
                            <div class="mmd-pop mmd-pop-right" id="mmd-pop-export">
                                <div class="mmd-pop-label">Image (2x PNG)</div>
                                <button type="button" class="mmd-item" data-mmd-export="png-transparent"><span class="dd-dot-swatch dd-dot-transparent"></span>PNG &middot; Transparent</button>
                                <button type="button" class="mmd-item" data-mmd-export="png-dark"><span class="dd-dot-swatch dd-dot-dark"></span>PNG &middot; Dark</button>
                                <button type="button" class="mmd-item" data-mmd-export="png-white"><span class="dd-dot-swatch dd-dot-white"></span>PNG &middot; White</button>
                                <div class="mmd-pop-label">Vector</div>
                                <button type="button" class="mmd-item" data-mmd-export="svg-transparent"><i class="fa-solid fa-bezier-curve"></i>SVG &middot; Transparent</button>
                                <button type="button" class="mmd-item" data-mmd-export="svg-dark"><i class="fa-solid fa-moon"></i>SVG &middot; Dark</button>
                                <button type="button" class="mmd-item" data-mmd-export="svg-white"><i class="fa-solid fa-sun"></i>SVG &middot; White</button>
                                <div class="mmd-pop-label">Source</div>
                                <button type="button" class="mmd-item" id="mmd-btn-copy-code"><i class="fa-regular fa-copy"></i><span>Copy code</span></button>
                                <button type="button" class="mmd-item" id="mmd-btn-copy-md"><i class="fa-brands fa-markdown"></i><span>Copy as Markdown</span></button>
                                <button type="button" class="mmd-item" id="mmd-save-mmd"><i class="fa-solid fa-floppy-disk"></i>Save .mmd</button>
                                <button type="button" class="mmd-item" id="mmd-save-md"><i class="fa-solid fa-file-lines"></i>Save .md</button>
                                <button type="button" class="mmd-item" id="mmd-open-file"><i class="fa-solid fa-folder-open"></i>Open file&hellip;</button>
                            </div>
                        </div>
                        <input type="file" id="mmd-file-input" accept=".mmd,.mermaid,.md,.txt,.json" style="display:none;" />
                    </div>
                </header>

                <div class="mmd-body" id="mmd-body">
                    <!-- EDITOR -->
                    <section class="mmd-editor" id="mmd-editor-panel" style="--mmd-split:${state.split}%;" aria-label="Mermaid code editor">
                        <div class="mmd-editor-bar">
                            <span class="mmd-editor-label"><i class="fa-solid fa-terminal"></i> mermaid</span>
                            <div class="mmd-snippets" id="mmd-snippet-bar">
                                ${SNIPPETS.map((s, idx) => `<button type="button" data-mmd-snippet="${idx}" title="Insert at cursor">${esc(s.label)}</button>`).join('')}
                            </div>
                        </div>
                        <div class="mmd-code-wrap">
                            <div class="mmd-lines" id="mmd-line-numbers">1</div>
                            <textarea id="mmd-code-textarea" class="mmd-code" spellcheck="false" wrap="off" placeholder="Enter Mermaid syntax here...">${esc(state.code)}</textarea>
                        </div>
                        <div class="mmd-error" id="mmd-error-box"></div>
                    </section>

                    <div class="mmd-divider" id="mmd-divider" title="Drag to resize"></div>

                    <!-- PREVIEW -->
                    <section class="mmd-preview theme-${state.canvasBg}" id="mmd-canvas-wrap" aria-label="Diagram preview">
                        <div id="mmd-viewport-stage" class="mmd-stage">
                            <div id="mmd-svg-holder" class="mmd-holder"></div>
                        </div>

                        <div class="mmd-float">
                            <div class="mmd-float-group" role="group" aria-label="Background">
                                <button type="button" class="mmd-chip ${state.canvasBg === 'dark' ? 'active' : ''}" data-mmd-bg="dark" title="Dark canvas"><span class="dd-dot-swatch dd-dot-dark"></span></button>
                                <button type="button" class="mmd-chip ${state.canvasBg === 'white' ? 'active' : ''}" data-mmd-bg="white" title="White canvas"><span class="dd-dot-swatch dd-dot-white"></span></button>
                                <button type="button" class="mmd-chip ${state.canvasBg === 'transparent' ? 'active' : ''}" data-mmd-bg="transparent" title="Transparent canvas"><span class="dd-dot-swatch dd-dot-transparent"></span></button>
                            </div>
                            <span class="mmd-sep"></span>
                            <div class="mmd-float-group" role="group" aria-label="Zoom">
                                <button type="button" class="mmd-chip" id="mmd-zoom-out" title="Zoom out"><i class="fa-solid fa-minus"></i></button>
                                <span class="mmd-zoom" id="mmd-zoom-label">100%</span>
                                <button type="button" class="mmd-chip" id="mmd-zoom-in" title="Zoom in"><i class="fa-solid fa-plus"></i></button>
                                <button type="button" class="mmd-chip" id="mmd-zoom-fit" title="Fit &amp; center"><i class="fa-solid fa-expand"></i></button>
                            </div>
                        </div>
                    </section>

                    <!-- PRESETS DRAWER (overlay, closed by default) -->
                    <div class="mmd-scrim" id="mmd-presets-scrim"></div>
                    <aside class="mmd-drawer" id="mmd-presets-drawer" aria-label="Presets">
                        <div class="mmd-drawer-head">
                            <span><i class="fa-solid fa-layer-group"></i> Presets</span>
                            <button type="button" class="mmd-x" id="mmd-presets-close" title="Close"><i class="fa-solid fa-xmark"></i></button>
                        </div>
                        <div class="mmd-drawer-tools">
                            <input type="text" class="dd-input" id="mmd-presets-search" placeholder="Search presets..." value="${esc(state.presetQuery)}" />
                            <div class="mmd-filter" id="mmd-presets-filter"></div>
                        </div>
                        <div class="mmd-drawer-list dark-scroll" id="mmd-inspector-body"></div>
                    </aside>
                </div>
            </div>
        `;
    }

    function renderTemplateGallery() {
        const list = document.getElementById('mmd-inspector-body');
        const filterEl = document.getElementById('mmd-presets-filter');
        if (!list) return;

        const cats = ['All', ...Array.from(new Set(TEMPLATES.map(t => t.category)))];
        if (filterEl) {
            filterEl.innerHTML = cats.map(c => `<button type="button" class="${state.presetFilter === c ? 'active' : ''}" data-mmd-pfilter="${esc(c)}">${esc(c)}</button>`).join('');
            filterEl.querySelectorAll('[data-mmd-pfilter]').forEach(b => b.addEventListener('click', () => {
                state.presetFilter = b.getAttribute('data-mmd-pfilter');
                renderTemplateGallery();
            }));
        }

        const q = (state.presetQuery || '').trim().toLowerCase();
        const items = TEMPLATES.filter(t =>
            (state.presetFilter === 'All' || t.category === state.presetFilter) &&
            (!q || (t.title + ' ' + t.category + ' ' + t.badge).toLowerCase().includes(q)));

        list.innerHTML = items.length ? items.map(tpl => `
            <button type="button" class="mmd-card" data-mmd-tpl="${tpl.id}" style="--c:${tpl.color};">
                <span class="mmd-card-bar"></span>
                <span class="mmd-card-body">
                    <span class="mmd-card-title">${esc(tpl.title)}</span>
                    <span class="mmd-card-tag">${esc(tpl.badge)}</span>
                </span>
            </button>`).join('') : '<div class="mmd-empty">No presets match.</div>';

        list.querySelectorAll('[data-mmd-tpl]').forEach(btn => {
            btn.addEventListener('click', () => {
                const tpl = TEMPLATES.find(t => t.id === btn.getAttribute('data-mmd-tpl'));
                if (!tpl) return;
                state.title = tpl.title;
                state.code = tpl.code;
                const titleIn = document.getElementById('mmd-title-input');
                if (titleIn) titleIn.value = state.title;
                const ta = document.getElementById('mmd-code-textarea');
                if (ta) ta.value = state.code;
                updateEditorLineNumbers();
                saveToStorage();
                closePresets();
                state.userMoved = false;
                renderMermaidDiagram(true);
            });
        });
    }

    function openPresets() {
        document.getElementById('mmd-body')?.classList.add('presets-open');
        setTimeout(() => document.getElementById('mmd-presets-search')?.focus(), 120);
    }
    function closePresets() {
        document.getElementById('mmd-body')?.classList.remove('presets-open');
    }

    function setView(view) {
        if (!['code', 'split', 'preview'].includes(view)) return;
        state.view = view;
        const root = document.getElementById('mmd-studio-root');
        if (root) root.setAttribute('data-view', view);
        document.querySelectorAll('[data-mmd-view]').forEach(b => b.classList.toggle('active', b.getAttribute('data-mmd-view') === view));
        saveToStorage();
        // Re-center once the layout has settled
        state.userMoved = false;
        setTimeout(fitToScreen, 30);
        setTimeout(fitToScreen, 220);
    }

    function closePopovers() {
        document.querySelectorAll('.mmd-pop.open').forEach(p => p.classList.remove('open'));
        document.querySelectorAll('[data-mmd-pop].open').forEach(b => b.classList.remove('open'));
    }

    function updateEditorLineNumbers() {
        const ta = document.getElementById('mmd-code-textarea');
        const ln = document.getElementById('mmd-line-numbers');
        if (!ta || !ln) return;
        const count = Math.max(1, ta.value.split('\n').length);
        const nums = [];
        for (let i = 1; i <= count; i++) nums.push(i);
        ln.innerHTML = nums.join('<br/>');
    }

    function updateActiveDirection() {
        const m = (state.code || '').match(/^\s*(?:flowchart|graph)\s+(LR|RL|TD|TB|BT)\b/im);
        const activeDir = m ? (m[1].toUpperCase() === 'TB' ? 'TD' : m[1].toUpperCase()) : '';
        document.querySelectorAll('[data-mmd-dir]').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-mmd-dir') === activeDir);
        });
    }

    // =========================================================================
    // MERMAID LIVE RENDERING ENGINE
    // =========================================================================
    async function renderMermaidDiagram(autoFit = false) {
        const holder = document.getElementById('mmd-svg-holder');
        const statusPill = document.getElementById('mmd-status-pill');
        const errBox = document.getElementById('mmd-error-box');
        if (!holder) return;

        updateActiveDirection();

        const code = (state.code || '').trim();
        if (!code) {
            holder.innerHTML = '';
            return;
        }

        try {
            await ensureMermaidLoaded();
            configureMermaid();

            state.renderCounter += 1;
            const renderId = `mmd_svg_${Date.now()}_${state.renderCounter}`;
            const { svg } = await window.mermaid.render(renderId, code);

            state.lastValidSvg = svg;
            state.lastError = null;
            holder.innerHTML = svg;

            const svgEl = holder.querySelector('svg');
            if (svgEl) {
                svgEl.style.maxWidth = 'none';
                svgEl.style.height = 'auto';
                adaptMermaidSvgTheme(svgEl, state.canvasBg === 'white');
            }

            if (statusPill) {
                statusPill.textContent = 'VALID';
                statusPill.setAttribute('data-ok', '1');
            }
            if (errBox) {
                errBox.classList.remove('show');
                errBox.textContent = '';
            }

            if (autoFit || !state.userMoved) {
                requestAnimationFrame(() => requestAnimationFrame(fitToScreen));
            } else {
                applyViewportTransform();
            }
        } catch (err) {
            state.lastError = err && (err.message || String(err));
            if (statusPill) {
                statusPill.textContent = 'SYNTAX ERROR';
                statusPill.setAttribute('data-ok', '0');
            }
            if (errBox) {
                errBox.classList.add('show');
                errBox.textContent = state.lastError;
            }
            // Remove any leftover mermaid error temp element
            document.querySelectorAll('[id^="dmmd_svg_"], [id^="mmd_svg_"]').forEach(el => {
                if (!holder.contains(el)) el.remove();
            });
        }
    }

    function applyViewportTransform() {
        const holder = document.getElementById('mmd-svg-holder');
        const zoomLbl = document.getElementById('mmd-zoom-label');
        if (holder) {
            holder.style.transform = `translate(${state.panX}px, ${state.panY}px) scale(${state.zoom})`;
        }
        if (zoomLbl) {
            zoomLbl.textContent = `${Math.round(state.zoom * 100)}%`;
        }
    }

    function fitToScreen() {
        const stage = document.getElementById('mmd-viewport-stage');
        const holder = document.getElementById('mmd-svg-holder');
        if (!stage || !holder) return;
        const svgEl = holder.querySelector('svg');
        if (!svgEl) return;

        const stageRect = stage.getBoundingClientRect();
        if (!stageRect.width || !stageRect.height) return;
        state.userMoved = false;

        // Natural diagram size
        let vw, vh;
        const vbv = svgEl.viewBox && svgEl.viewBox.baseVal;
        if (vbv && vbv.width) { vw = vbv.width; vh = vbv.height; }
        else {
            const bb = svgEl.getBBox ? svgEl.getBBox() : { width: 800, height: 500 };
            vw = Math.max(200, bb.width + 40); vh = Math.max(150, bb.height + 40);
        }
        svgEl.setAttribute('width', String(vw));
        svgEl.setAttribute('height', String(vh));

        // Symmetric padding so the diagram is truly centered (floating bar is small and sits at the bottom)
        const padX = 48, padY = 64;
        const scale = Math.min(1.25, Math.max(0.1, Math.min((stageRect.width - padX * 2) / vw, (stageRect.height - padY * 2) / vh)));

        state.zoom = scale;
        state.panX = (stageRect.width - vw * scale) / 2;
        state.panY = (stageRect.height - vh * scale) / 2;
        applyViewportTransform();
    }

    // =========================================================================
    // INTERACTIONS & EVENT BINDINGS
    // =========================================================================
    function bindEvents() {
        const ta = document.getElementById('mmd-code-textarea');
        const ln = document.getElementById('mmd-line-numbers');
        const stage = document.getElementById('mmd-viewport-stage');
        const body = document.getElementById('mmd-body');

        document.getElementById('mmd-title-input')?.addEventListener('change', (e) => {
            state.title = e.target.value.trim() || 'Untitled Mermaid Diagram';
            saveToStorage();
        });

        // View switcher
        document.querySelectorAll('[data-mmd-view]').forEach(btn => {
            btn.addEventListener('click', () => setView(btn.getAttribute('data-mmd-view')));
        });

        // Resizable split divider
        const divider = document.getElementById('mmd-divider');
        const editorPanel = document.getElementById('mmd-editor-panel');
        if (divider && body && editorPanel) {
            let dragging = false;
            divider.addEventListener('mousedown', (ev) => {
                dragging = true;
                body.classList.add('resizing');
                ev.preventDefault();
            });
            const move = (ev) => {
                if (!dragging) return;
                const r = body.getBoundingClientRect();
                const pct = Math.min(75, Math.max(22, ((ev.clientX - r.left) / r.width) * 100));
                state.split = Math.round(pct * 10) / 10;
                editorPanel.style.setProperty('--mmd-split', state.split + '%');
            };
            const up = () => {
                if (!dragging) return;
                dragging = false;
                body.classList.remove('resizing');
                saveToStorage();
            };
            window.addEventListener('mousemove', move);
            window.addEventListener('mouseup', up);
            divider.addEventListener('dblclick', () => {
                state.split = 45;
                editorPanel.style.setProperty('--mmd-split', '45%');
                saveToStorage();
            });
        }

        // Code editor
        if (ta) {
            ta.addEventListener('scroll', () => { if (ln) ln.scrollTop = ta.scrollTop; });
            ta.addEventListener('input', () => {
                state.code = ta.value;
                updateEditorLineNumbers();
                saveToStorage();
                clearTimeout(state.debounceTimer);
                state.debounceTimer = setTimeout(() => renderMermaidDiagram(false), 260);
            });
            ta.addEventListener('keydown', (ev) => {
                if (ev.key === 'Tab') {
                    ev.preventDefault();
                    const start = ta.selectionStart;
                    const end = ta.selectionEnd;
                    ta.value = ta.value.substring(0, start) + '    ' + ta.value.substring(end);
                    ta.selectionStart = ta.selectionEnd = start + 4;
                    state.code = ta.value;
                    updateEditorLineNumbers();
                } else if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') {
                    ev.preventDefault();
                    state.userMoved = false;
                    renderMermaidDiagram(true);
                }
            });
        }

        // Snippets
        document.querySelectorAll('[data-mmd-snippet]').forEach(btn => {
            btn.addEventListener('click', () => {
                const item = SNIPPETS[Number(btn.getAttribute('data-mmd-snippet'))];
                if (!item || !ta) return;
                const pos = ta.selectionEnd || ta.value.length;
                ta.value = ta.value.slice(0, pos) + item.snippet + ta.value.slice(pos);
                state.code = ta.value;
                updateEditorLineNumbers();
                saveToStorage();
                renderMermaidDiagram(false);
                ta.focus();
            });
        });

        // Direction
        document.querySelectorAll('[data-mmd-dir]').forEach(btn => {
            btn.addEventListener('click', () => {
                const dir = btn.getAttribute('data-mmd-dir');
                const updated = state.code.replace(/^(\s*(?:flowchart|graph)\s+)(?:LR|RL|TD|TB|BT)\b/im, `$1${dir}`);
                if (updated !== state.code) {
                    state.code = updated;
                    if (ta) ta.value = updated;
                    saveToStorage();
                    state.userMoved = false;
                    renderMermaidDiagram(true);
                }
            });
        });

        // Appearance
        document.getElementById('mmd-theme-select')?.addEventListener('change', (e) => {
            state.theme = e.target.value;
            if (state.theme === 'default' || state.theme === 'neutral') setCanvasBg('white');
            else if (state.canvasBg === 'white') setCanvasBg('dark');
            saveToStorage();
            renderMermaidDiagram(false);
        });
        document.getElementById('mmd-curve-select')?.addEventListener('change', (e) => {
            state.curve = e.target.value; saveToStorage(); renderMermaidDiagram(false);
        });
        document.getElementById('mmd-font-select')?.addEventListener('change', (e) => {
            state.fontFamily = e.target.value; saveToStorage(); renderMermaidDiagram(false);
        });

        // Popovers (Style / Export)
        document.querySelectorAll('[data-mmd-pop]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const popName = btn.getAttribute('data-mmd-pop');
                const pop = document.getElementById('mmd-pop-' + popName);
                const wasOpen = pop && pop.classList.contains('open');
                closePopovers();
                if (pop && !wasOpen) {
                    if (popName === 'style') updateActiveDirection();
                    pop.classList.add('open');
                    btn.classList.add('open');
                }
            });
        });
        document.querySelectorAll('.mmd-pop').forEach(p => p.addEventListener('click', (e) => e.stopPropagation()));

        // Presets drawer
        document.getElementById('mmd-btn-presets')?.addEventListener('click', (e) => { e.stopPropagation(); closePopovers(); openPresets(); });
        document.getElementById('mmd-presets-close')?.addEventListener('click', closePresets);
        document.getElementById('mmd-presets-scrim')?.addEventListener('click', closePresets);
        document.getElementById('mmd-presets-search')?.addEventListener('input', (e) => {
            state.presetQuery = e.target.value;
            renderTemplateGallery();
        });

        // Copy
        document.getElementById('mmd-btn-copy-code')?.addEventListener('click', (e) => {
            navigator.clipboard?.writeText(state.code);
            flashButtonText(e.currentTarget, 'Copied!');
        });
        document.getElementById('mmd-btn-copy-md')?.addEventListener('click', (e) => {
            const md = `### ${state.title}\n\n\`\`\`mermaid\n${state.code.trim()}\n\`\`\`\n`;
            navigator.clipboard?.writeText(md);
            flashButtonText(e.currentTarget, 'Copied!');
        });

        // Canvas background
        document.querySelectorAll('[data-mmd-bg]').forEach(btn => {
            btn.addEventListener('click', () => setCanvasBg(btn.getAttribute('data-mmd-bg')));
        });

        // Exports
        document.querySelectorAll('#mmd-pop-export [data-mmd-export]').forEach(btn => {
            btn.addEventListener('click', () => {
                const [fmt, bg] = btn.getAttribute('data-mmd-export').split('-');
                closePopovers();
                if (fmt === 'png') exportMermaidPNG(bg);
                else if (fmt === 'svg') exportMermaidSVG(bg);
            });
        });

        // Save / Open
        document.getElementById('mmd-save-mmd')?.addEventListener('click', () => {
            closePopovers();
            downloadTextFile(`${slugTitle()}.mmd`, state.code, 'text/plain;charset=utf-8');
        });
        document.getElementById('mmd-save-md')?.addEventListener('click', () => {
            closePopovers();
            const md = `# ${state.title}\n\n\`\`\`mermaid\n${state.code.trim()}\n\`\`\`\n`;
            downloadTextFile(`${slugTitle()}.md`, md, 'text/markdown;charset=utf-8');
        });
        document.getElementById('mmd-open-file')?.addEventListener('click', () => {
            closePopovers();
            document.getElementById('mmd-file-input')?.click();
        });
        document.getElementById('mmd-file-input')?.addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = () => {
                let raw = String(reader.result || '');
                const mMatch = raw.match(/```mermaid\s*([\s\S]*?)```/i);
                if (mMatch && mMatch[1]) raw = mMatch[1].trim();
                state.code = raw;
                state.title = file.name.replace(/\.(mmd|mermaid|md|txt)$/i, '');
                if (ta) ta.value = state.code;
                const titleIn = document.getElementById('mmd-title-input');
                if (titleIn) titleIn.value = state.title;
                updateEditorLineNumbers();
                saveToStorage();
                state.userMoved = false;
                renderMermaidDiagram(true);
            };
            reader.readAsText(file);
            e.target.value = '';
        });

        // Preview pan & zoom
        if (stage) {
            stage.addEventListener('mousedown', (ev) => {
                if (ev.button !== 0) return;
                state.isPanning = true;
                stage.classList.add('grabbing');
                state.panStart = { x: ev.clientX - state.panX, y: ev.clientY - state.panY };
            });
            window.addEventListener('mousemove', (ev) => {
                if (!state.isPanning) return;
                state.userMoved = true;
                state.panX = ev.clientX - state.panStart.x;
                state.panY = ev.clientY - state.panStart.y;
                applyViewportTransform();
            });
            window.addEventListener('mouseup', () => {
                if (state.isPanning) {
                    state.isPanning = false;
                    document.getElementById('mmd-viewport-stage')?.classList.remove('grabbing');
                }
            });
            stage.addEventListener('wheel', (ev) => {
                ev.preventDefault();
                state.userMoved = true;
                const factor = ev.deltaY < 0 ? 1.12 : 0.89;
                const nextZoom = Math.min(4.0, Math.max(0.1, state.zoom * factor));
                const rect = stage.getBoundingClientRect();
                const mx = ev.clientX - rect.left;
                const my = ev.clientY - rect.top;
                state.panX = mx - (mx - state.panX) * (nextZoom / state.zoom);
                state.panY = my - (my - state.panY) * (nextZoom / state.zoom);
                state.zoom = nextZoom;
                applyViewportTransform();
            }, { passive: false });

            // Keep the diagram centered whenever the preview resizes (until the user pans/zooms)
            if (state.resizeObserver) state.resizeObserver.disconnect();
            if (window.ResizeObserver) {
                state.resizeObserver = new ResizeObserver(() => {
                    if (state.userMoved) return;
                    cancelAnimationFrame(state.fitRaf);
                    state.fitRaf = requestAnimationFrame(fitToScreen);
                });
                state.resizeObserver.observe(stage);
            }
        }

        document.getElementById('mmd-zoom-in')?.addEventListener('click', () => {
            state.userMoved = true; zoomAtCenter(1.18);
        });
        document.getElementById('mmd-zoom-out')?.addEventListener('click', () => {
            state.userMoved = true; zoomAtCenter(1 / 1.18);
        });
        document.getElementById('mmd-zoom-fit')?.addEventListener('click', fitToScreen);
        document.getElementById('mmd-zoom-label')?.addEventListener('click', fitToScreen);

        // Global listeners are registered once (the shell is re-rendered on every tab open)
        if (!state.globalBound) {
            state.globalBound = true;
            document.addEventListener('click', closePopovers);
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') { closePopovers(); closePresets(); }
            });
        }
    }

    function zoomAtCenter(factor) {
        const stage = document.getElementById('mmd-viewport-stage');
        if (!stage) return;
        const rect = stage.getBoundingClientRect();
        const cx = rect.width / 2, cy = rect.height / 2;
        const nextZoom = Math.min(4.0, Math.max(0.1, state.zoom * factor));
        state.panX = cx - (cx - state.panX) * (nextZoom / state.zoom);
        state.panY = cy - (cy - state.panY) * (nextZoom / state.zoom);
        state.zoom = nextZoom;
        applyViewportTransform();
    }

    function setCanvasBg(bg) {
        state.canvasBg = bg;
        const wrap = document.getElementById('mmd-canvas-wrap');
        if (wrap) wrap.className = `mmd-preview theme-${state.canvasBg}`;
        document.querySelectorAll('[data-mmd-bg]').forEach(b => {
            b.classList.toggle('active', b.getAttribute('data-mmd-bg') === bg);
        });
        saveToStorage();
        configureMermaid();
        renderMermaidDiagram(false);
    }

    function flashButtonText(btn, msg) {
        if (!btn) return;
        const span = btn.querySelector('span');
        if (!span) return;
        const orig = span.textContent;
        span.textContent = msg;
        setTimeout(() => { span.textContent = orig; }, 1200);
    }

    function slugTitle() {
        return (state.title || 'mantis-mermaid').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    }

    function downloadTextFile(filename, content, mime) {
        const blob = new Blob([content], { type: mime });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // =========================================================================
    // EXPORT ENGINE: HIGH-DPI PNG & VECTOR SVG (TRANSPARENT / DARK / WHITE)
    // =========================================================================
    async function buildExportSvg(bgMode) {
        await ensureMermaidLoaded();
        const holder = document.getElementById('mmd-svg-holder');
        const liveSvg = holder ? holder.querySelector('svg') : null;
        if (!liveSvg) return null;

        const clone = liveSvg.cloneNode(true);
        const isWhite = bgMode === 'white';
        adaptMermaidSvgTheme(clone, isWhite);

        const bbox = liveSvg.getBBox ? liveSvg.getBBox() : { x: 0, y: 0, width: 900, height: 600 };
        const pad = 32;
        const vx = Math.floor(bbox.x - pad);
        const vy = Math.floor(bbox.y - pad);
        const vw = Math.ceil(bbox.width + pad * 2);
        const vh = Math.ceil(bbox.height + pad * 2);

        clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
        clone.setAttribute('width', String(vw));
        clone.setAttribute('height', String(vh));
        clone.setAttribute('viewBox', `${vx} ${vy} ${vw} ${vh}`);

        if (bgMode !== 'transparent') {
            const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            bgRect.setAttribute('x', String(vx));
            bgRect.setAttribute('y', String(vy));
            bgRect.setAttribute('width', String(vw));
            bgRect.setAttribute('height', String(vh));
            bgRect.setAttribute('fill', bgMode === 'white' ? '#ffffff' : '#090d16');
            clone.insertBefore(bgRect, clone.firstChild);
        }

        const svgStr = new XMLSerializer().serializeToString(clone);
        return { svgStr, width: vw, height: vh };
    }

    async function exportMermaidSVG(bgMode) {
        const res = await buildExportSvg(bgMode);
        if (!res) return;
        downloadTextFile(`${slugTitle()}-${bgMode}.svg`, res.svgStr, 'image/svg+xml;charset=utf-8');
    }

    async function exportMermaidPNG(bgMode) {
        const res = await buildExportSvg(bgMode);
        if (!res) return;
        const { svgStr, width, height } = res;
        const img = new Image();
        const encoded = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svgStr);
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = width * 2;
            canvas.height = height * 2;
            const ctx = canvas.getContext('2d');
            ctx.scale(2, 2);
            ctx.drawImage(img, 0, 0);
            canvas.toBlob((pngBlob) => {
                if (!pngBlob) return;
                const pngUrl = URL.createObjectURL(pngBlob);
                const a = document.createElement('a');
                a.href = pngUrl;
                a.download = `${slugTitle()}-${bgMode}.png`;
                a.click();
                setTimeout(() => URL.revokeObjectURL(pngUrl), 1000);
            }, 'image/png');
        };
        img.src = encoded;
    }

    window.openMermaidDraw = initMermaidDraw;
})();
