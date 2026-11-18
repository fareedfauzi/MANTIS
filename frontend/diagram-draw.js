/* ==========================================================================
   MANTIS Diagram Draw — Executive Cyber & Network Diagramming Studio (v4)
   Inspired by https://mr-r3b00t.github.io/net_draw/ & toddatlarge/net-draw
   Features:
   - Zero-truncation dynamic node sizing (full titles & subtitles always visible)
   - Ultra-clean full-bleed Linear/Figma-grade dark studio UI
   - Specialized Graph Templates & 115+ Icons across CTI, DFIR, Threat Hunting,
     Detection Engineering, and Red Team / Offensive Security
   - Native .mantis-draw Project Export & Import
   - Transparent, Dark, and White Background Exports (PNG & SVG)
   - Insert Image, Copy & Paste Image (Ctrl+C / Ctrl+V), and 12 Fonts
   ========================================================================== */
(() => {
    const STORAGE_KEY = 'mantis_diagram_draw_v5';
    const FILE_FORMAT_MAGIC = 'mantis-diagram-draw';
    const FILE_FORMAT_VERSION = '2.0';

    // Color Palette Swatches
    const SWATCH_COLORS = [
        '#38bdf8', // Cyan (Network / CTI)
        '#10b981', // Emerald (Security / Detection)
        '#ffcc00', // Gold (MANTIS Accent / Core)
        '#a855f7', // Purple (Servers / DFIR)
        '#ef4444', // Red (Threat / Red Team / Compromised)
        '#f97316', // Orange (Hunting / Targeted / Alert)
        '#ec4899', // Pink (Identity / OSINT)
        '#6366f1', // Indigo (Cloud / Telemetry)
        '#14b8a6', // Teal (OT / ICS / AD)
        '#64748b', // Slate (Neutral / Baseline)
    ];

    // Supported Font Families
    const FONT_OPTIONS = [
        { id: 'Plus Jakarta Sans', label: 'Plus Jakarta Sans', stack: '"Plus Jakarta Sans", system-ui, sans-serif' },
        { id: 'Inter', label: 'Inter', stack: '"Inter", system-ui, sans-serif' },
        { id: 'Space Grotesk', label: 'Space Grotesk', stack: '"Space Grotesk", sans-serif' },
        { id: 'IBM Plex Mono', label: 'IBM Plex Mono', stack: '"IBM Plex Mono", monospace' },
        { id: 'JetBrains Mono', label: 'JetBrains Mono', stack: '"JetBrains Mono", monospace' },
        { id: 'Rajdhani', label: 'Rajdhani', stack: '"Rajdhani", sans-serif' },
        { id: 'Orbitron', label: 'Orbitron', stack: '"Orbitron", sans-serif' },
        { id: 'Michroma', label: 'Michroma', stack: '"Michroma", sans-serif' },
        { id: 'Merriweather', label: 'Merriweather', stack: '"Merriweather", Georgia, serif' },
        { id: 'Caveat', label: 'Caveat (Sketch)', stack: '"Caveat", cursive' },
        { id: 'Georgia', label: 'Georgia', stack: 'Georgia, serif' },
        { id: 'Courier New', label: 'Courier New', stack: '"Courier New", monospace' },
    ];

    const FONT_MAP = new Map(FONT_OPTIONS.map((f) => [f.id, f.stack]));

    // Offscreen canvas context for accurate dynamic text measurement (so subtitles & titles never truncate)
    const measureCanvas = document.createElement('canvas');
    const measureCtx = measureCanvas.getContext('2d');

    // In-memory HTMLImageElement cache
    const imageCache = new Map();
    const getOrLoadImage = (src) => {
        if (!src) return null;
        if (imageCache.has(src)) {
            return imageCache.get(src);
        }
        const img = new Image();
        img.crossOrigin = 'anonymous';
        const entry = { img, loaded: false, error: false, width: 160, height: 120 };
        imageCache.set(src, entry);
        img.onload = () => {
            entry.loaded = true;
            entry.width = img.naturalWidth || 160;
            entry.height = img.naturalHeight || 120;
            requestRender();
        };
        img.onerror = () => {
            entry.error = true;
            requestRender();
        };
        img.src = src;
        return entry;
    };

    // =========================================================================
    // Comprehensive Asset & Entity Library Across All 5 Cyber Disciplines
    // =========================================================================
    const ASSET_CATEGORIES = [
        {
            id: 'flow',
            name: 'Process Flow',
            color: '#60a5fa',
            isFlowGrid: true,
            items: [
                { type: 'flow_start_end', name: 'Start / End', flowShape: 'stadium', icon: '\uf111', fa: 'fa-circle', color: '#10b981', sub: 'Start / End' },
                { type: 'flow_process', name: 'Process', flowShape: 'rect', icon: '\uf0c8', fa: 'fa-square', color: '#60a5fa', sub: 'Process Step' },
                { type: 'flow_decision', name: 'Decision', flowShape: 'diamond', icon: '\uf3a5', fa: 'fa-gem', color: '#eab308', sub: 'Condition Check' },
                { type: 'flow_data_io', name: 'Data / I-O', flowShape: 'parallelogram', icon: '\uf362', fa: 'fa-right-left', color: '#22d3ee', sub: 'Input / Output' },
                { type: 'flow_document', name: 'Document', flowShape: 'document', icon: '\uf15c', fa: 'fa-file-lines', color: '#94a3b8', sub: 'Document Artifact' },
                { type: 'flow_subprocess', name: 'Subprocess', flowShape: 'subprocess', icon: '\uf1b3', fa: 'fa-cubes', color: '#818cf8', sub: 'Sub-Workflow' },
                { type: 'flow_preparation', name: 'Preparation', flowShape: 'hexagon', icon: '\uf085', fa: 'fa-gears', color: '#a855f7', sub: 'Setup Step' },
                { type: 'flow_manual_input', name: 'Manual Input', flowShape: 'manual_input', icon: '\uf11c', fa: 'fa-keyboard', color: '#f472b6', sub: 'User Input' },
                { type: 'flow_delay', name: 'Delay', flowShape: 'delay', icon: '\uf017', fa: 'fa-clock', color: '#fb923c', sub: 'Wait / Timer' },
                { type: 'flow_connector', name: 'Connector', flowShape: 'connector', icon: '\uf111', fa: 'fa-circle-dot', color: '#94a3b8', sub: 'Flow Jump' },
                { type: 'flow_step', name: 'Step Marker', flowShape: 'step', icon: '\uf192', fa: 'fa-circle-dot', color: '#ef4444', sub: 'Step 1..∞', isStep: true },
            ],
        },
        {
            id: 'cti_osint',
            name: 'CTI & OSINT Entities',
            color: '#ec4899',
            items: [
                { type: 'ioc_ip', name: 'IPv4 / IPv6 Node', icon: '\uf05b', fa: 'fa-location-crosshairs', color: '#ec4899', sub: '198.51.100.42' },
                { type: 'ioc_domain', name: 'Domain / FQDN', icon: '\uf0ac', fa: 'fa-globe', color: '#ec4899', sub: 'login-auth-cdn[.]com' },
                { type: 'ioc_url', name: 'URL / URI Endpoint', icon: '\uf0c1', fa: 'fa-link', color: '#ec4899', sub: 'https://.../gate.php' },
                { type: 'ssl_cert', name: 'SSL/TLS Certificate', icon: '\uf0a3', fa: 'fa-certificate', color: '#ec4899', sub: 'SHA1 / Serial / CN' },
                { type: 'jarm_ja3', name: 'JA3 / JARM Fingerprint', icon: '\uf577', fa: 'fa-fingerprint', color: '#ec4899', sub: 'TLS Fingerprint' },
                { type: 'whois_reg', name: 'WHOIS / Registrar', icon: '\uf2bb', fa: 'fa-address-card', color: '#ec4899', sub: 'Registrant / Namecheap' },
                { type: 'asn_bgp', name: 'ASN / BGP Prefix', icon: '\uf542', fa: 'fa-diagram-project', color: '#ec4899', sub: 'AS48091 /24' },
                { type: 'ioc_email', name: 'Email Address', icon: '\uf1fa', fa: 'fa-at', color: '#ec4899', sub: 'admin@registrar.org' },
                { type: 'tg_actor', name: 'Telegram Channel / Bot', icon: '\uf1d8', fa: 'fa-paper-plane', color: '#ec4899', sub: 'api.telegram.org/bot' },
                { type: 'tor_onion', name: 'Tor .onion Service', icon: '\uf21b', fa: 'fa-user-secret', color: '#ec4899', sub: 'v3 Onion Service' },
                { type: 'crypto_wallet', name: 'Crypto Wallet', icon: '\uf51e', fa: 'fa-coins', color: '#ec4899', sub: 'BTC / XMR / USDT' },
                { type: 'paste_leak', name: 'Paste / Leak Site', icon: '\uf0ea', fa: 'fa-paste', color: '#ec4899', sub: 'DLS / Breach Forum' },
                { type: 'diamond_vertex', name: 'Diamond Model Vertex', icon: '\uf3a5', fa: 'fa-gem', color: '#ec4899', sub: 'Adversary / Infra / Cap' },
                { type: 'target_org', name: 'Target Sector / Victim', icon: '\uf1ad', fa: 'fa-building-shield', color: '#ec4899', sub: 'Victim Organization' },
            ],
        },
        {
            id: 'dfir',
            name: 'Digital Forensics (DFIR)',
            color: '#6366f1',
            items: [
                { type: 'dfir_proc', name: 'Process (PID / PPID)', icon: '\uf120', fa: 'fa-terminal', color: '#6366f1', sub: 'PID 4192 powershell.exe' },
                { type: 'dfir_dll', name: 'DLL / Shared Library', icon: '\uf12e', fa: 'fa-puzzle-piece', color: '#6366f1', sub: 'Side-Loaded DLL' },
                { type: 'dfir_reg', name: 'Registry Key / Value', icon: '\uf00b', fa: 'fa-rectangle-list', color: '#6366f1', sub: 'HKCU\\...\\CurrentVersion\\Run' },
                { type: 'dfir_schtask', name: 'Scheduled Task / Cron', icon: '\uf017', fa: 'fa-clock', color: '#6366f1', sub: 'schtasks /create' },
                { type: 'dfir_service', name: 'Windows Service', icon: '\uf085', fa: 'fa-gears', color: '#6366f1', sub: 'EventID 7045 Service' },
                { type: 'dfir_mem', name: 'Memory Dump / LSASS', icon: '\uf538', fa: 'fa-memory', color: '#6366f1', sub: 'lsass.dmp / Volatility' },
                { type: 'dfir_evtx', name: 'Event Log (EVTX)', icon: '\uf15c', fa: 'fa-file-lines', color: '#6366f1', sub: 'Security.evtx / EID 4624' },
                { type: 'dfir_mft', name: 'Disk / $MFT / $UsnJrnl', icon: '\uf0a0', fa: 'fa-hard-drive', color: '#6366f1', sub: 'NTFS File System' },
                { type: 'dfir_mutex', name: 'Mutex / Named Pipe', icon: '\uf023', fa: 'fa-lock', color: '#6366f1', sub: '\\\\.\\pipe\\msagent_12' },
                { type: 'dfir_sample', name: 'File / Sample (SHA256)', icon: '\uf1c9', fa: 'fa-file-code', color: '#6366f1', sub: 'Dropped Binary' },
                { type: 'dfir_container', name: 'LNK / ISO / VHD Archive', icon: '\uf1c6', fa: 'fa-file-zipper', color: '#6366f1', sub: 'Delivery Container' },
                { type: 'dfir_browser', name: 'Browser / Cookie Artifact', icon: '\uf268', fa: 'fa-compass', color: '#6366f1', sub: 'Login Data / Session' },
                { type: 'dfir_prefetch', name: 'Prefetch / Amcache.hve', icon: '\uf0e7', fa: 'fa-bolt', color: '#6366f1', sub: 'Execution Evidence' },
                { type: 'dfir_wmi', name: 'WMI Event Consumer', icon: '\uf0e8', fa: 'fa-sitemap', color: '#6366f1', sub: 'root\\subscription' },
            ],
        },
        {
            id: 'hunt_detect',
            name: 'Hunting & Detection Eng.',
            color: '#f97316',
            items: [
                { type: 'sigma_rule', name: 'Sigma Detection Rule', icon: '\uf121', fa: 'fa-code', color: '#f97316', sub: 'SIEM Detection Logic' },
                { type: 'yara_rule', name: 'YARA Signature Rule', icon: '\uf577', fa: 'fa-fingerprint', color: '#f97316', sub: 'Binary / Memory Rule' },
                { type: 'suricata_rule', name: 'Suricata / Snort Rule', icon: '\uf6ff', fa: 'fa-network-wired', color: '#f97316', sub: 'NDR Signature' },
                { type: 'sysmon_sensor', name: 'Sysmon Telemetry', icon: '\uf06e', fa: 'fa-eye', color: '#f97316', sub: 'EventID 1 / 3 / 8 / 10' },
                { type: 'etw_kernel', name: 'ETW / Kernel Sensor', icon: '\uf2db', fa: 'fa-microchip', color: '#f97316', sub: 'Microsoft-Windows-TI' },
                { type: 'ebpf_auditd', name: 'Auditd / eBPF Probe', icon: '\uf120', fa: 'fa-terminal', color: '#f97316', sub: 'Linux Syscall Trace' },
                { type: 'zeek_pcap', name: 'Zeek / PCAP Flow', icon: '\uf550', fa: 'fa-wave-square', color: '#f97316', sub: 'conn.log / ssl.log' },
                { type: 'hunt_hyp', name: 'Hunt Hypothesis', icon: '\uf0eb', fa: 'fa-lightbulb', color: '#f97316', sub: 'Tactical Hunt Idea' },
                { type: 'soar_playbook', name: 'SOAR Playbook', icon: '\uf544', fa: 'fa-robot', color: '#f97316', sub: 'Auto-Containment' },
                { type: 'fp_filter', name: 'False Positive Filter', icon: '\uf0b0', fa: 'fa-filter', color: '#f97316', sub: 'Baseline Tuning' },
                { type: 'datalake', name: 'Security Data Lake', icon: '\uf1c0', fa: 'fa-database', color: '#f97316', sub: 'Hot / Cold Retention' },
                { type: 'mitre', name: 'MITRE ATT&CK TTP', icon: '\uf05b', fa: 'fa-crosshairs', color: '#f97316', sub: 'T1059 / T1003' },
            ],
        },
        {
            id: 'redteam_ad',
            name: 'Red Team & Active Directory',
            color: '#ef4444',
            items: [
                { type: 'ad_user', name: 'AD User Account', icon: '\uf007', fa: 'fa-user', color: '#ef4444', sub: 'svc_sql@corp.local' },
                { type: 'ad_group', name: 'AD Security Group', icon: '\uf0c0', fa: 'fa-users', color: '#ef4444', sub: 'Domain Admins / Tier-0' },
                { type: 'ad_computer', name: 'AD Computer Object', icon: '\uf390', fa: 'fa-desktop', color: '#ef4444', sub: 'SRV-SQL01.corp.local' },
                { type: 'ad_gpo', name: 'AD Group Policy (GPO)', icon: '\uf0ae', fa: 'fa-list-check', color: '#ef4444', sub: 'Default Domain Policy' },
                { type: 'ad_ou', name: 'AD Org Unit (OU)', icon: '\uf07c', fa: 'fa-folder-tree', color: '#ef4444', sub: 'OU=Servers,DC=corp' },
                { type: 'krb_ticket', name: 'Kerberos Ticket (TGT)', icon: '\uf3ff', fa: 'fa-ticket', color: '#ef4444', sub: 'Golden / Silver Ticket' },
                { type: 'ntlm_hash', name: 'NTLM / NetNTLMv2 Hash', icon: '\uf292', fa: 'fa-hashtag', color: '#ef4444', sub: 'Pass-the-Hash' },
                { type: 'lsass_secrets', name: 'LSASS / DPAPI / NTDS', icon: '\uf084', fa: 'fa-key', color: '#ef4444', sub: 'DCSync / NTDS.dit' },
                { type: 'socks_pivot', name: 'SOCKS5 / Ligolo Pivot', icon: '\uf362', fa: 'fa-route', color: '#ef4444', sub: 'Chisel / Proxychains' },
                { type: 'smb_pipe', name: 'SMB Named Pipe Pivot', icon: '\uf6ff', fa: 'fa-network-wired', color: '#ef4444', sub: 'P2P Beacon Mesh' },
                { type: 'c2_beacon', name: 'C2 Beacon / Implant', icon: '\uf188', fa: 'fa-bug', color: '#ef4444', sub: 'Cobalt Strike / Sliver' },
                { type: 'cloud_iam', name: 'Cloud IAM Role / Token', icon: '\uf505', fa: 'fa-id-badge', color: '#ef4444', sub: 'STS AssumeRole / OAuth' },
                { type: 'smart_redir', name: 'Smart HTTPS Redirector', icon: '\uf0ec', fa: 'fa-arrows-split-up-and-left', color: '#ef4444', sub: 'Apache Mod_Rewrite' },
                { type: 'lolbin_bof', name: 'LOLBin / COFF BOF', icon: '\uf135', fa: 'fa-rocket', color: '#ef4444', sub: 'In-Memory Execution' },
            ],
        },
        {
            id: 'threats',
            name: 'Adversaries & Malware',
            color: '#ef4444',
            items: [
                { type: 'threat_actor', name: 'Threat Actor / APT', icon: '\uf21b', fa: 'fa-user-secret', color: '#ef4444', sub: 'External Adversary' },
                { type: 'c2', name: 'C2 Teamserver', icon: '\uf519', fa: 'fa-tower-broadcast', color: '#ef4444', sub: 'Command & Control' },
                { type: 'phishing', name: 'Phishing Lure', icon: '\uf0e0', fa: 'fa-envelope-open-text', color: '#ef4444', sub: 'T1566 Spearphish' },
                { type: 'malware', name: 'Malware / Loader', icon: '\uf188', fa: 'fa-bug', color: '#ef4444', sub: 'Trojan / Loader' },
                { type: 'ransomware', name: 'Ransomware Payload', icon: '\uf714', fa: 'fa-skull-crossbones', color: '#ef4444', sub: 'T1486 Encryption' },
                { type: 'stealer', name: 'Credential Stealer', icon: '\uf084', fa: 'fa-key', color: '#ef4444', sub: 'Infostealer Logs' },
                { type: 'exploit', name: 'Exploit / 0-Day CVE', icon: '\uf0e7', fa: 'fa-bolt-lightning', color: '#ef4444', sub: 'T1190 Initial Access' },
                { type: 'botnet', name: 'Botnet / ORB Proxy', icon: '\uf6ff', fa: 'fa-circle-nodes', color: '#ef4444', sub: 'Residential Proxy Mesh' },
                { type: 'exfil', name: 'Exfiltration Staging', icon: '\uf093', fa: 'fa-cloud-arrow-up', color: '#ef4444', sub: 'T1041 Cloud Drop' },
                { type: 'insider', name: 'Insider Threat', icon: '\uf4fc', fa: 'fa-user-ninja', color: '#ef4444', sub: 'Malicious Insider' },
            ],
        },
        {
            id: 'network',
            name: 'Network & Cloud',
            color: '#38bdf8',
            items: [
                { type: 'internet', name: 'Internet / WAN', icon: '\uf0ac', fa: 'fa-globe', color: '#38bdf8', sub: 'Public WAN' },
                { type: 'cloud', name: 'Cloud VPC', icon: '\uf0c2', fa: 'fa-cloud', color: '#38bdf8', sub: 'AWS / Azure / GCP' },
                { type: 'router', name: 'Core Router', icon: '\uf6ff', fa: 'fa-network-wired', color: '#38bdf8', sub: 'BGP / OSPF' },
                { type: 'switch', name: 'L2/L3 Switch', icon: '\uf362', fa: 'fa-right-left', color: '#38bdf8', sub: 'VLAN Trunk' },
                { type: 'wifi', name: 'Wireless AP', icon: '\uf1eb', fa: 'fa-wifi', color: '#38bdf8', sub: '802.11ax' },
                { type: 'vpn', name: 'VPN Gateway', icon: '\uf502', fa: 'fa-user-lock', color: '#38bdf8', sub: 'IPsec / SSL VPN' },
                { type: 'dns', name: 'DNS Server', icon: '\uf519', fa: 'fa-compass', color: '#38bdf8', sub: 'UDP/53 Resolver' },
                { type: 'lb', name: 'Load Balancer', icon: '\uf0e8', fa: 'fa-sitemap', color: '#38bdf8', sub: 'Reverse Proxy' },
                { type: 'cdn', name: 'CDN / Edge', icon: '\uf0e7', fa: 'fa-bolt', color: '#38bdf8', sub: 'Cloudflare / Edge' },
                { type: 'asn', name: 'ASN / ISP', icon: '\uf542', fa: 'fa-diagram-project', color: '#38bdf8', sub: 'AS64512' },
            ],
        },
        {
            id: 'security',
            name: 'Security & Defensive Controls',
            color: '#10b981',
            items: [
                { type: 'firewall', name: 'NGFW Firewall', icon: '\uf3ed', fa: 'fa-shield-halved', color: '#10b981', sub: 'Perimeter Policy' },
                { type: 'waf', name: 'Web App Firewall', icon: '\uf132', fa: 'fa-shield', color: '#10b981', sub: 'OWASP Filter' },
                { type: 'proxy', name: 'Web Proxy / SWG', icon: '\uf0b0', fa: 'fa-filter', color: '#10b981', sub: 'TLS Inspection' },
                { type: 'ids', name: 'IDS / IPS Sensor', icon: '\uf06e', fa: 'fa-eye', color: '#10b981', sub: 'Suricata / Zeek' },
                { type: 'siem', name: 'SIEM / SOC Platform', icon: '\uf201', fa: 'fa-chart-line', color: '#10b981', sub: 'Log Telemetry' },
                { type: 'edr', name: 'EDR / XDR Agent', icon: '\uf577', fa: 'fa-fingerprint', color: '#10b981', sub: 'Endpoint Sensor' },
                { type: 'seg', name: 'Email Security Gateway', icon: '\uf658', fa: 'fa-envelope-circle-check', color: '#10b981', sub: 'DMARC / Anti-Phish' },
                { type: 'bastion', name: 'Jump Host / PAM Vault', icon: '\uf084', fa: 'fa-key', color: '#10b981', sub: 'SSH / RDP Bastion' },
            ],
        },
        {
            id: 'servers',
            name: 'Servers & Infrastructure',
            color: '#a855f7',
            items: [
                { type: 'dc', name: 'Domain Controller', icon: '\uf509', fa: 'fa-users-gear', color: '#a855f7', sub: 'Active Directory' },
                { type: 'web', name: 'Web Server', icon: '\uf233', fa: 'fa-server', color: '#a855f7', sub: 'HTTPS :443' },
                { type: 'app', name: 'App / API Server', icon: '\uf1b2', fa: 'fa-cube', color: '#a855f7', sub: 'Microservice' },
                { type: 'db', name: 'Database Server', icon: '\uf1c0', fa: 'fa-database', color: '#a855f7', sub: 'PostgreSQL / MSSQL' },
                { type: 'fileserver', name: 'File / NAS / SMB', icon: '\uf07c', fa: 'fa-folder-open', color: '#a855f7', sub: 'SMB :445 Shares' },
                { type: 'mail', name: 'Mail / Exchange Server', icon: '\uf0e0', fa: 'fa-envelope', color: '#a855f7', sub: 'SMTP / OWA' },
                { type: 'backup', name: 'Backup Vault', icon: '\uf0a0', fa: 'fa-hard-drive', color: '#a855f7', sub: 'Veeam / Snapshots' },
                { type: 'hypervisor', name: 'Hypervisor / ESXi', icon: '\uf5fd', fa: 'fa-layer-group', color: '#a855f7', sub: 'vCenter / KVM' },
                { type: 'k8s', name: 'Kubernetes Cluster', icon: '\uf1b3', fa: 'fa-cubes', color: '#a855f7', sub: 'EKS / GKE Pods' },
                { type: 'rmm', name: 'Management / RMM', icon: '\uf085', fa: 'fa-gears', color: '#a855f7', sub: 'SCCM / Ansible' },
            ],
        },
        {
            id: 'endpoints',
            name: 'Endpoints & Users',
            color: '#ffcc00',
            items: [
                { type: 'workstation', name: 'Workstation', icon: '\uf390', fa: 'fa-desktop', color: '#ffcc00', sub: 'Windows 11 Pro' },
                { type: 'laptop', name: 'Corporate Laptop', icon: '\uf109', fa: 'fa-laptop', color: '#ffcc00', sub: 'Remote Endpoint' },
                { type: 'linux_ws', name: 'Developer / Linux Host', icon: '\uf120', fa: 'fa-terminal', color: '#ffcc00', sub: 'Ubuntu / SSH' },
                { type: 'mobile', name: 'Mobile Device', icon: '\uf3cd', fa: 'fa-mobile-screen', color: '#ffcc00', sub: 'iOS / Android' },
                { type: 'user', name: 'Employee User', icon: '\uf007', fa: 'fa-user', color: '#ffcc00', sub: 'Standard Account' },
                { type: 'admin', name: 'IT / Domain Admin', icon: '\uf505', fa: 'fa-user-shield', color: '#ffcc00', sub: 'Tier-0 Privileged' },
                { type: 'vip', name: 'Executive / VIP', icon: '\uf508', fa: 'fa-user-tie', color: '#ffcc00', sub: 'High-Value Target' },
                { type: 'iot', name: 'IoT / IP Camera', icon: '\uf030', fa: 'fa-camera', color: '#ffcc00', sub: 'Embedded Device' },
            ],
        },
        {
            id: 'ot',
            name: 'Industrial / OT & ICS',
            color: '#14b8a6',
            items: [
                { type: 'scada', name: 'SCADA Master', icon: '\uf2db', fa: 'fa-microchip', color: '#14b8a6', sub: 'Supervisory Control' },
                { type: 'historian', name: 'OT Historian DB', icon: '\uf1c0', fa: 'fa-database', color: '#14b8a6', sub: 'Time-Series DB' },
                { type: 'hmi', name: 'HMI Operator Console', icon: '\uf108', fa: 'fa-tv', color: '#14b8a6', sub: 'Control Panel' },
                { type: 'plc', name: 'PLC Controller', icon: '\uf085', fa: 'fa-gears', color: '#14b8a6', sub: 'Modbus / S7comm' },
                { type: 'rtu', name: 'RTU Telemetry Unit', icon: '\uf519', fa: 'fa-satellite-dish', color: '#14b8a6', sub: 'Field Telemetry' },
                { type: 'sensor', name: 'Actuator / Valve', icon: '\uf624', fa: 'fa-gauge-high', color: '#14b8a6', sub: 'Level 0 Process' },
            ],
        },
    ];

    const ALL_ASSETS_MAP = new Map();
    ASSET_CATEGORIES.forEach((cat) => {
        cat.items.forEach((item) => {
            ALL_ASSETS_MAP.set(item.type, { ...item, category: cat.id });
        });
    });
    ALL_ASSETS_MAP.set('image', {
        type: 'image',
        name: 'Inserted Image',
        icon: '\uf03e',
        fa: 'fa-image',
        color: '#38bdf8',
        sub: 'Custom Image',
        category: 'media',
    });
    ALL_ASSETS_MAP.set('step_marker', {
        type: 'flow_step',
        name: 'Step Marker',
        flowShape: 'step',
        icon: '\uf192',
        fa: 'fa-circle-dot',
        color: '#ef4444',
        sub: 'Step 1..∞',
        isStep: true,
        category: 'flow',
    });

    const STATUS_BADGES = {
        none: { label: 'None', color: '' },
        adversary: { label: 'ADVERSARY', color: '#f97316' },
        victim: { label: 'VICTIM', color: '#eab308' },
        compromised: { label: 'COMPROMISED', color: '#ef4444' },
        targeted: { label: 'TARGETED', color: '#f97316' },
        protected: { label: 'PROTECTED', color: '#10b981' },
        alert: { label: 'ALERT', color: '#eab308' },
        offline: { label: 'OFFLINE', color: '#64748b' },
    };

    // =========================================================================
    // Spacious, Zero-Truncation Templates Across All 5 Cyber Disciplines
    // =========================================================================
    const TEMPLATES = {
        ransomware: () => ({
            title: 'Ransomware Intrusion & Lateral Movement',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'EXTERNAL ADVERSARY INFRASTRUCTURE', sub: 'Untrusted WAN / Bulletproof Hosting', x: 60, y: 80, w: 340, h: 520, color: '#ef4444', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'DMZ & PERIMETER EDGE', sub: 'Subnet: 172.16.10.0/24', x: 450, y: 80, w: 340, h: 520, color: '#38bdf8', style: 'dashed', opacity: 0.06 },
                { id: 'z3', label: 'CORPORATE LAN & TIER-0 CORE', sub: '10.20.0.0/16 (corp.local)', x: 840, y: 80, w: 720, h: 520, color: '#a855f7', style: 'dashed', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'threat_actor', label: 'APT / Initial Access Broker', sub: 'ASN 209xxx (External)', x: 230, y: 185, color: '#ef4444', status: 'none', step: '1. Recon' },
                { id: 'n2', type: 'c2', label: 'Mythic C2 Redirector', sub: '185.220.101.44 :443', x: 230, y: 360, color: '#ef4444', status: 'alert', step: '4. C2 Beacon' },
                { id: 'n3', type: 'exfil', label: 'Mega / Rclone Staging', sub: 'Cloud Storage Exfil Drop', x: 230, y: 520, color: '#ef4444', status: 'none', step: '7. Exfil' },
                { id: 'n4', type: 'firewall', label: 'Perimeter NGFW', sub: 'fw01.edge.corp', x: 620, y: 245, color: '#10b981', status: 'protected', step: '' },
                { id: 'n5', type: 'vpn', label: 'SSL VPN Appliance', sub: 'vpn.corp.com (CVE-2024)', x: 620, y: 440, color: '#f97316', status: 'targeted', step: '2. Exploit' },
                { id: 'n6', type: 'workstation', label: 'WKSTN-FIN-042', sub: '10.20.14.42 (Finance)', x: 1020, y: 215, color: '#ffcc00', status: 'compromised', step: '3. Foothold' },
                { id: 'n7', type: 'dc', label: 'DC01.corp.local', sub: '10.20.1.10 (Tier-0 AD)', x: 1020, y: 440, color: '#a855f7', status: 'compromised', step: '5. DCSync' },
                { id: 'n8', type: 'fileserver', label: 'FS01-FINANCE', sub: '10.20.2.50 (SMB Shares)', x: 1380, y: 245, color: '#ef4444', status: 'compromised', step: '6. Ransomware' },
                { id: 'n9', type: 'siem', label: 'MANTIS SOC / SIEM', sub: 'EDR + NDR Telemetry', x: 1380, y: 440, color: '#10b981', status: 'protected', step: 'Detect' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n5', label: 'T1190 Exploit Public VPN', color: '#ef4444', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n5', to: 'n6', label: 'RDP Stolen Session', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n6', to: 'n2', label: 'HTTPS Beacon :443', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e4', from: 'n6', to: 'n7', label: 'T1003 Kerberoast / SMB', color: '#ef4444', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n7', to: 'n8', label: 'GPO / PsExec Payload', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'e6', from: 'n8', to: 'n3', label: 'T1048 Rclone Exfil (42 GB)', color: '#f97316', style: 'animated', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e7', from: 'n7', to: 'n9', label: 'EventID 4662 / 4624 Alert', color: '#38bdf8', style: 'dotted', curve: 'bezier', dir: 'forward', width: 1.8 },
            ],
            notes: [
                { id: 't1', text: 'KILL-CHAIN FLOW: Public VPN Exploit -> Endpoint Foothold -> AD DCSync -> Rclone Exfil & Encryption', x: 450, y: 28, color: '#ffcc00' },
            ],
        }),

        cti_diamond: () => ({
            title: 'CTI Diamond Model of Intrusion Analysis',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'DIAMOND MODEL CORE QUADRANTS', sub: 'Socio-Political Axis (Adversary <-> Victim) & Technical Axis (Infrastructure <-> Capability)', x: 120, y: 70, w: 1120, h: 550, color: '#ec4899', style: 'dashed', opacity: 0.05 },
            ],
            nodes: [
                { id: 'n1', type: 'threat_actor', label: 'ADVERSARY: APT29 / Midnight Blizzard', sub: 'Foreign Intelligence Service (SVR)', x: 680, y: 155, color: '#ef4444', status: 'alert', step: 'VERTEX: ADVERSARY' },
                { id: 'n2', type: 'c2', label: 'INFRASTRUCTURE: ORB & Cloud C2', sub: '185.220.101.44 + Compromised Routers', x: 320, y: 350, color: '#38bdf8', status: 'alert', step: 'VERTEX: INFRA' },
                { id: 'n3', type: 'malware', label: 'CAPABILITY: EnvyScout & WINELOADER', sub: 'ISO Stager + DLL Side-Loading', x: 1040, y: 350, color: '#a855f7', status: 'compromised', step: 'VERTEX: CAPABILITY' },
                { id: 'n4', type: 'target_org', label: 'VICTIM: Diplomatic & Gov Ministries', sub: 'NATO / EU Foreign Affairs', x: 680, y: 530, color: '#ffcc00', status: 'targeted', step: 'VERTEX: VICTIM' },
                { id: 'n5', type: 'ssl_cert', label: 'Let\'s Encrypt TLS Cert', sub: 'JARM: 27d3ed3ed00027d1dc42d43d', x: 320, y: 530, color: '#ec4899', status: 'none', step: 'Pivot IOC' },
                { id: 'n6', type: 'mitre', label: 'T1566.002 + T1078.004', sub: 'OAuth Device Code Phishing', x: 1040, y: 530, color: '#f97316', status: 'none', step: 'ATT&CK TTP' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'Operates / Leases', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n1', to: 'n3', label: 'Develops & Deploys', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n2', to: 'n4', label: 'Delivers Phish & C2 Traffic', color: '#38bdf8', style: 'animated', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e4', from: 'n3', to: 'n4', label: 'Executes In-Memory on', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n1', to: 'n4', label: 'Socio-Political Axis (Espionage)', color: '#ffcc00', style: 'dashed', curve: 'straight', dir: 'forward', width: 1.8 },
                { id: 'e6', from: 'n2', to: 'n3', label: 'Technical Axis (Hosts Payload)', color: '#ec4899', style: 'dashed', curve: 'straight', dir: 'both', width: 1.8 },
                { id: 'e7', from: 'n2', to: 'n5', label: 'Presents TLS Cert', color: '#ec4899', style: 'dotted', curve: 'bezier', dir: 'forward', width: 1.8 },
                { id: 'e8', from: 'n3', to: 'n6', label: 'Implements TTP', color: '#f97316', style: 'dotted', curve: 'bezier', dir: 'forward', width: 1.8 },
            ],
            notes: [
                { id: 't1', text: 'CTI DIAMOND MODEL: Adversary, Infrastructure, Capability, and Victim Analysis (TLP:AMBER)', x: 330, y: 22, color: '#ec4899' },
            ],
        }),

        cti_pivot: () => ({
            title: 'CTI Infrastructure Footprint & Pivot Graph',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'INITIAL SEED INDICATOR', sub: 'Observed in SOC Alert', x: 50, y: 180, w: 320, h: 250, color: '#ef4444', style: 'solid', opacity: 0.06 },
                { id: 'z2', label: 'PASSIVE DNS, TLS & WHOIS PIVOTS', sub: 'Enriched via MANTIS IOC Search', x: 420, y: 70, w: 620, h: 510, color: '#ec4899', style: 'dashed', opacity: 0.06 },
                { id: 'z3', label: 'ATTRIBUTED CLUSTER & PAYLOADS', sub: 'Newly Discovered Sibling Assets', x: 1090, y: 70, w: 380, h: 510, color: '#a855f7', style: 'dashed', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'ioc_domain', label: 'update-ms-defender[.]com', sub: 'Seed C2 Domain', x: 210, y: 310, color: '#ef4444', status: 'compromised', step: '1. Seed IOC' },
                { id: 'n2', type: 'ioc_ip', label: '91.215.85.114', sub: 'Passive DNS A Record', x: 600, y: 165, color: '#38bdf8', status: 'alert', step: '2. pDNS A' },
                { id: 'n3', type: 'ssl_cert', label: 'Serial: 04:8a:91:c2:ff', sub: 'Issuer: Let\'s Encrypt R3', x: 600, y: 315, color: '#ec4899', status: 'alert', step: '2. TLS Cert' },
                { id: 'n4', type: 'whois_reg', label: 'reg_privacy_88@proton.me', sub: 'Historical WHOIS Email', x: 600, y: 470, color: '#ffcc00', status: 'none', step: '2. WHOIS' },
                { id: 'n5', type: 'jarm_ja3', label: 'JARM: 07d14d16d21d21d', sub: 'Cobalt Strike Default JARM', x: 880, y: 235, color: '#f97316', status: 'alert', step: '3. JARM' },
                { id: 'n6', type: 'ioc_domain', label: 'sso-okta-portal[.]net', sub: 'Co-Hosted Sibling Domain', x: 1280, y: 165, color: '#ef4444', status: 'targeted', step: '4. New IOC' },
                { id: 'n7', type: 'dfir_sample', label: 'beacon_x64.dll', sub: 'SHA256: e3b0c44298fc1c149afbf4c8', x: 1280, y: 315, color: '#a855f7', status: 'compromised', step: '4. Sample' },
                { id: 'n8', type: 'threat_actor', label: 'UNC3944 / Scattered Spider', sub: 'High-Confidence Attribution', x: 1280, y: 470, color: '#ef4444', status: 'alert', step: '5. Actor' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'Resolves To (A)', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n1', to: 'n3', label: 'Serves TLS Cert', color: '#ec4899', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n1', to: 'n4', label: 'Registered By', color: '#ffcc00', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n2', to: 'n5', label: 'Scanner JARM Match', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n2', to: 'n6', label: 'Co-Hosted pDNS', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e6', from: 'n3', to: 'n7', label: 'C2 Traffic Observed In', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e7', from: 'n4', to: 'n8', label: 'Reuse of WHOIS Persona', color: '#ef4444', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
            ],
            notes: [],
        }),

        dfir_proc_tree: () => ({
            title: 'DFIR Process Execution Lineage & Memory Forensics Tree',
            defaultFont: 'IBM Plex Mono',
            zones: [
                { id: 'z1', label: 'INITIAL DELIVERY & USER EXECUTION', sub: 'Workstation: WKSTN-HR-09 (10.10.4.22)', x: 50, y: 70, w: 380, h: 500, color: '#ffcc00', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'PROCESS LINEAGE & DEFENSE EVASION', sub: 'Sysmon EventID 1 / 4688 Process Tree', x: 480, y: 70, w: 460, h: 500, color: '#6366f1', style: 'dashed', opacity: 0.06 },
                { id: 'z3', label: 'CREDENTIAL ACCESS, PERSISTENCE & C2', sub: 'Memory & Registry Forensic Artifacts', x: 990, y: 70, w: 420, h: 500, color: '#ef4444', style: 'dashed', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'dfir_container', label: 'Invoice_Q4.iso -> .lnk', sub: 'Mark-of-the-Web Bypass', x: 240, y: 195, color: '#ffcc00', status: 'targeted', step: 'T1566.001' },
                { id: 'n2', type: 'dfir_proc', label: 'explorer.exe (PID 2104)', sub: 'User: CORP\\jdoe', x: 240, y: 390, color: '#38bdf8', status: 'none', step: 'PPID 1840' },
                { id: 'n3', type: 'dfir_proc', label: 'cmd.exe (PID 5412)', sub: '/c start rundll32.exe', x: 710, y: 185, color: '#f97316', status: 'alert', step: 'PID 5412' },
                { id: 'n4', type: 'dfir_proc', label: 'powershell.exe (PID 6088)', sub: '-NoP -W Hidden -enc JAB...', x: 710, y: 340, color: '#ef4444', status: 'compromised', step: 'T1059.001' },
                { id: 'n5', type: 'dfir_dll', label: 'version.dll (Side-Loaded)', sub: 'Unsigned Loader in AppData', x: 710, y: 490, color: '#a855f7', status: 'compromised', step: 'T1574.002' },
                { id: 'n6', type: 'dfir_mem', label: 'lsass.exe (PID 788)', sub: 'Sysmon EID 10 (GrantedAccess 0x1fffff)', x: 1200, y: 185, color: '#ef4444', status: 'compromised', step: 'T1003.001 Dump' },
                { id: 'n7', type: 'dfir_reg', label: 'HKCU\\...\\CurrentVersion\\Run', sub: 'Value: "OneDriveSync"', x: 1200, y: 340, color: '#6366f1', status: 'alert', step: 'T1547.001 Persist' },
                { id: 'n8', type: 'ioc_ip', label: '45.142.214.99 :8443', sub: 'Sysmon EID 3 Outbound C2', x: 1200, y: 490, color: '#ef4444', status: 'alert', step: 'T1071.001 C2' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'Mounted & Executed', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n2', to: 'n3', label: 'Spawns Child (EID 4688)', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n3', to: 'n4', label: 'Executes Encoded PS', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n4', to: 'n5', label: 'Drops & Loads DLL (EID 7)', color: '#a855f7', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n4', to: 'n6', label: 'MiniDumpWriteDump Access', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'e6', from: 'n5', to: 'n7', label: 'Sysmon EID 13 RegSetValue', color: '#6366f1', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e7', from: 'n5', to: 'n8', label: 'HTTPS Beacon (60s Jitter)', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'both', width: 2 },
            ],
            notes: [],
        }),

        dfir_persistence: () => ({
            title: 'DFIR Host Persistence & Disk/Registry Artifact Map',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'PERSISTENCE MECHANISMS', sub: 'Survives Reboot / Re-Logon', x: 60, y: 80, w: 620, h: 480, color: '#ef4444', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'FORENSIC EVIDENCE SOURCES', sub: 'Triage Collection (KAPE / Velociraptor)', x: 740, y: 80, w: 680, h: 480, color: '#6366f1', style: 'solid', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'dfir_sample', label: 'svchost_helper.exe', sub: 'C:\\ProgramData\\svchost_helper.exe', x: 220, y: 310, color: '#ef4444', status: 'compromised', step: 'Payload' },
                { id: 'n2', type: 'dfir_reg', label: 'Run / Winlogon Shell', sub: 'NTUSER.DAT & SOFTWARE Hive', x: 520, y: 175, color: '#f97316', status: 'alert', step: 'T1547' },
                { id: 'n3', type: 'dfir_schtask', label: 'UpdaterTask XML', sub: 'C:\\Windows\\System32\\Tasks', x: 520, y: 310, color: '#f97316', status: 'alert', step: 'T1053.005' },
                { id: 'n4', type: 'dfir_service', label: 'Malicious Win32 Service', sub: 'SYSTEM\\CurrentControlSet\\Services', x: 520, y: 445, color: '#f97316', status: 'alert', step: 'T1543.003' },
                { id: 'n5', type: 'dfir_mft', label: '$MFT & $UsnJrnl:$J', sub: 'Timestomp & File Creation', x: 920, y: 175, color: '#6366f1', status: 'protected', step: 'NTFS Artifact' },
                { id: 'n6', type: 'dfir_prefetch', label: 'Prefetch & Amcache.hve', sub: 'Run Count + Last Run Time + SHA1', x: 920, y: 310, color: '#6366f1', status: 'protected', step: 'Exec Artifact' },
                { id: 'n7', type: 'dfir_evtx', label: 'Security & System.evtx', sub: 'EID 4698 (Task) & EID 7045 (Service)', x: 920, y: 445, color: '#10b981', status: 'protected', step: 'Event Logs' },
                { id: 'n8', type: 'report', label: 'DFIR Timeline Report', sub: 'Plaso / Timesketch SuperTimeline', x: 1260, y: 310, color: '#ffcc00', status: 'protected', step: 'Output' },
            ],
            edges: [
                { id: 'e1', from: 'n2', to: 'n1', label: 'Autostarts on Logon', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n3', to: 'n1', label: 'Triggers Daily at 02:00', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n4', to: 'n1', label: 'Runs as NT AUTHORITY\\SYSTEM', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n1', to: 'n5', label: 'Logged in $MFT Record', color: '#6366f1', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n1', to: 'n6', label: 'SVCHOST_HELPER-8A2F.PF', color: '#6366f1', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e6', from: 'n3', to: 'n7', label: 'Generates EID 4698 / 106', color: '#10b981', style: 'dotted', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e7', from: 'n4', to: 'n7', label: 'Generates EID 7045', color: '#10b981', style: 'dotted', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e8', from: 'n5', to: 'n8', label: 'Correlated In', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 1.8 },
                { id: 'e9', from: 'n6', to: 'n8', label: 'Correlated In', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 1.8 },
                { id: 'e10', from: 'n7', to: 'n8', label: 'Correlated In', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 1.8 },
            ],
            notes: [],
        }),

        hunt_hypothesis: () => ({
            title: 'Threat Hunt Hypothesis & Telemetry Decision Tree',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: '1. HYPOTHESIS & TTP SCOPE', sub: 'Intelligence-Driven Trigger', x: 50, y: 80, w: 360, h: 460, color: '#ffcc00', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: '2. TELEMETRY & ANALYTICS', sub: 'EDR / Sysmon / Zeek / SIEM Queries', x: 460, y: 80, w: 540, h: 460, color: '#38bdf8', style: 'dashed', opacity: 0.06 },
                { id: 'z3', label: '3. TRIAGE & ENGINEERING OUTCOME', sub: 'Escalation vs. Detection Rule Conversion', x: 1050, y: 80, w: 400, h: 460, color: '#10b981', style: 'dashed', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'hunt_hyp', label: 'Hypothesis: RMM Abuse', sub: 'Adversaries abusing AnyDesk / ScreenConnect', x: 230, y: 205, color: '#ffcc00', status: 'targeted', step: 'HUNT-042' },
                { id: 'n2', type: 'mitre', label: 'T1219 Remote Access Software', sub: 'Living-off-the-Land RMM', x: 230, y: 400, color: '#f97316', status: 'none', step: 'ATT&CK' },
                { id: 'n3', type: 'sysmon_sensor', label: 'Sysmon EID 1 + EID 3 + EID 7', sub: 'Unsigned RMM in Non-Standard Path', x: 615, y: 200, color: '#38bdf8', status: 'protected', step: 'Host Logs' },
                { id: 'n4', type: 'zeek_pcap', label: 'Zeek ssl.log & dns.log', sub: '*.relay.screenconnect.com', x: 615, y: 400, color: '#38bdf8', status: 'protected', step: 'Net Logs' },
                { id: 'n5', type: 'fp_filter', label: 'Exclude Approved IT RMM', sub: 'Filter Known Code-Signing Thumbprints', x: 870, y: 300, color: '#a855f7', status: 'none', step: 'Baseline' },
                { id: 'n6', type: 'dfir_evtx', label: 'True Positive Incident!', sub: 'Rogue ScreenConnect in C:\\Users\\Public', x: 1250, y: 200, color: '#ef4444', status: 'compromised', step: 'Escalate IR' },
                { id: 'n7', type: 'sigma_rule', label: 'Promote to Sigma Detection', sub: 'Automated Continuous SIEM Alerting', x: 1250, y: 400, color: '#10b981', status: 'protected', step: 'Codify Rule' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'Maps to TTP', color: '#ffcc00', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n1', to: 'n3', label: 'Query Endpoint Telemetry', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n2', to: 'n4', label: 'Query SNI / DNS Beacons', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n3', to: 'n5', label: 'Join & Deduplicate', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n4', to: 'n5', label: 'Enrich with ASN', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e6', from: 'n5', to: 'n6', label: 'Anomalous / Unapproved Hit', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'e7', from: 'n5', to: 'n7', label: 'High-Fidelity Logic Verified', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
            ],
            notes: [],
        }),

        detect_pipeline: () => ({
            title: 'Detection Engineering & Telemetry Pipeline Architecture',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'ATTACK SIMULATION (PURPLE TEAM)', sub: 'Atomic Red Team / Adversary TTP', x: 40, y: 80, w: 320, h: 470, color: '#ef4444', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'SENSOR & TELEMETRY COLLECTION', sub: 'Endpoint, Kernel & Network Probes', x: 400, y: 80, w: 340, h: 470, color: '#38bdf8', style: 'dashed', opacity: 0.06 },
                { id: 'z3', label: 'DETECTION RULES & CORRELATION ENGINE', sub: 'Detection-as-Code (Sigma / YARA / NDR)', x: 780, y: 80, w: 360, h: 470, color: '#f97316', style: 'solid', opacity: 0.06 },
                { id: 'z4', label: 'SOC ALERTING & SOAR RESPONSE', sub: 'Automated Triage & Isolation', x: 1180, y: 80, w: 340, h: 470, color: '#10b981', style: 'dashed', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'lolbin_bof', label: 'Direct Syscalls / BOF', sub: 'In-Memory Credential Dump', x: 200, y: 220, color: '#ef4444', status: 'compromised', step: 'T1003.001' },
                { id: 'n2', type: 'c2_beacon', label: 'HTTPS Malleable C2', sub: 'Domain Fronted Beacon', x: 200, y: 400, color: '#ef4444', status: 'alert', step: 'T1071.001' },
                { id: 'n3', type: 'etw_kernel', label: 'ETW Threat-Intelligence', sub: 'EtwTiReadVirtualMemory', x: 570, y: 175, color: '#38bdf8', status: 'protected', step: 'Kernel Sensor' },
                { id: 'n4', type: 'sysmon_sensor', label: 'Sysmon EID 10 + EDR', sub: 'CallTrace: UNKNOWN_MODULE', x: 570, y: 315, color: '#38bdf8', status: 'protected', step: 'Host Sensor' },
                { id: 'n5', type: 'zeek_pcap', label: 'Zeek + Suricata NDR', sub: 'JA3 / JARM + Beaconing Score', x: 570, y: 455, color: '#38bdf8', status: 'protected', step: 'Net Sensor' },
                { id: 'n6', type: 'yara_rule', label: 'YARA Memory Signature', sub: 'Scans Unbacked RWX Pages', x: 960, y: 175, color: '#f97316', status: 'protected', step: 'YARA-X' },
                { id: 'n7', type: 'sigma_rule', label: 'Sigma Correlation Rule', sub: 'proc_access_win_lsass_susp', x: 960, y: 315, color: '#f97316', status: 'protected', step: 'Sigma v2' },
                { id: 'n8', type: 'suricata_rule', label: 'Suricata ET PRO Rule', sub: 'SID:2038412 C2 Profile', x: 960, y: 455, color: '#f97316', status: 'protected', step: 'NDR Rule' },
                { id: 'n9', type: 'siem', label: 'SIEM High-Severity Incident', sub: 'Composite Risk Score: 95', x: 1350, y: 230, color: '#10b981', status: 'protected', step: 'Alert' },
                { id: 'n10', type: 'soar_playbook', label: 'SOAR Host Containment', sub: 'Isolate Host + Revoke Sessions', x: 1350, y: 410, color: '#10b981', status: 'protected', step: 'Auto-Action' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n3', label: 'Hookless Syscall Event', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n1', to: 'n4', label: 'Unbacked CallStack', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n2', to: 'n5', label: 'TLS Handshake Metadata', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n3', to: 'n6', label: 'Triggers Memory Scan', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n4', to: 'n7', label: 'Matches Sigma Condition', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e6', from: 'n5', to: 'n8', label: 'Matches Packet Signature', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e7', from: 'n6', to: 'n9', label: 'Fires Detection', color: '#10b981', style: 'animated', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e8', from: 'n7', to: 'n9', label: 'Fires Detection', color: '#10b981', style: 'animated', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e9', from: 'n8', to: 'n9', label: 'Correlates Network Hit', color: '#10b981', style: 'animated', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e10', from: 'n9', to: 'n10', label: 'Webhook Playbook Trigger', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'forward', width: 2.2 },
            ],
            notes: [],
        }),

        red_bloodhound: () => ({
            title: 'Red Team Active Directory / BloodHound Attack Path to Tier-0',
            defaultFont: 'IBM Plex Mono',
            zones: [
                { id: 'z1', label: 'INITIAL FOOTHOLD (TIER-2)', sub: 'Phished Standard Workstation User', x: 40, y: 80, w: 370, h: 460, color: '#ffcc00', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'ACL & GPO ABUSE (TIER-1)', sub: 'BloodHound Shortest Path Traversal', x: 460, y: 80, w: 470, h: 460, color: '#f97316', style: 'dashed', opacity: 0.06 },
                { id: 'z3', label: 'DOMAIN DOMINANCE (TIER-0)', sub: 'corp.local Forest Root Compromise', x: 980, y: 80, w: 420, h: 460, color: '#ef4444', style: 'solid', opacity: 0.07 },
            ],
            nodes: [
                { id: 'n1', type: 'ad_user', label: 'M.SMITH@CORP.LOCAL', sub: 'Owned Principal (Initial Phish)', x: 225, y: 215, color: '#ef4444', status: 'compromised', step: '1. Owned' },
                { id: 'n2', type: 'ad_group', label: 'IT-HELPDESK-OPERATORS', sub: 'Nested Security Group', x: 225, y: 405, color: '#ffcc00', status: 'targeted', step: '2. MemberOf' },
                { id: 'n3', type: 'ad_user', label: 'SVC_BACKUP@CORP.LOCAL', sub: 'SPN Set (Kerberoastable)', x: 695, y: 185, color: '#f97316', status: 'compromised', step: '3. GenericWrite' },
                { id: 'n4', type: 'ad_gpo', label: 'GPO: SERVER-ADMIN-POLICY', sub: 'Linked to OU=Tier1_Servers', x: 695, y: 325, color: '#f97316', status: 'targeted', step: '4. WriteDacl' },
                { id: 'n5', type: 'ad_computer', label: 'SRV-SCCM01.CORP.LOCAL', sub: 'HasSession: DA_JADMIN', x: 695, y: 465, color: '#ef4444', status: 'compromised', step: '5. LocalAdmin' },
                { id: 'n6', type: 'krb_ticket', label: 'TGT: DA_JADMIN@CORP.LOCAL', sub: 'Rubeus Unconstrained Delegation', x: 1190, y: 185, color: '#ef4444', status: 'compromised', step: '6. TGT Dump' },
                { id: 'n7', type: 'dc', label: 'DC01.CORP.LOCAL', sub: 'Primary Domain Controller', x: 1190, y: 325, color: '#ef4444', status: 'compromised', step: '7. DCSync' },
                { id: 'n8', type: 'lsass_secrets', label: 'KRBTGT NTLM & AES256 Keys', sub: 'Full Forest Persistence', x: 1190, y: 465, color: '#ef4444', status: 'compromised', step: '8. Golden Ticket' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'MemberOf', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n2', to: 'n3', label: 'ForceChangePassword / GenericAll', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n3', to: 'n4', label: 'WriteDacl (ImmediateTask)', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n4', to: 'n5', label: 'AppliesTo -> AdminTo', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n5', to: 'n6', label: 'HasSession -> Harvest TGT', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'e6', from: 'n6', to: 'n7', label: 'GetChanges + GetChangesAll', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'e7', from: 'n7', to: 'n8', label: 'DRSGetNCChanges (NTDS.dit)', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
            ],
            notes: [],
        }),

        c2_infra: () => ({
            title: 'Red Team OpSec C2, Smart Redirector & Internal Pivot Mesh',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'OPERATOR & CORE C2 TIER (HIDDEN)', sub: 'WireGuard VPN + Firewall Whitelist', x: 40, y: 80, w: 350, h: 460, color: '#ef4444', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'SMART REDIRECTOR & CDN EDGE', sub: 'Apache Mod_Rewrite + Cloudflare', x: 440, y: 80, w: 380, h: 460, color: '#f97316', style: 'dashed', opacity: 0.06 },
                { id: 'z3', label: 'COMPROMISED INTERNAL ENCLAVE', sub: 'SOCKS5 + SMB Named Pipe P2P Mesh', x: 870, y: 80, w: 620, h: 460, color: '#38bdf8', style: 'solid', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'threat_actor', label: 'Red Team Operator', sub: 'Ops Workstation', x: 215, y: 200, color: '#ef4444', status: 'none', step: 'Operator' },
                { id: 'n2', type: 'c2', label: 'Mythic / Sliver Teamserver', sub: 'Accepts Redirector mTLS Only', x: 215, y: 400, color: '#ef4444', status: 'protected', step: 'Core C2' },
                { id: 'n3', type: 'cdn', label: 'CDN / Cloud Worker Edge', sub: 'Valid TLS + High-Rep Domain', x: 630, y: 200, color: '#38bdf8', status: 'none', step: 'Edge Front' },
                { id: 'n4', type: 'smart_redir', label: 'Smart HTTPS Redirector', sub: 'Filters Scanners -> Decoy Site', x: 630, y: 400, color: '#f97316', status: 'protected', step: 'Smart Filter' },
                { id: 'n5', type: 'c2_beacon', label: 'Egress HTTPS Beacon', sub: 'WKSTN-01 (Indirect Syscalls)', x: 1050, y: 200, color: '#ef4444', status: 'compromised', step: 'Hop 1: Egress' },
                { id: 'n6', type: 'socks_pivot', label: 'Ligolo-ng / SOCKS5 Tunnel', sub: 'In-Memory TUN Interface', x: 1050, y: 400, color: '#a855f7', status: 'alert', step: 'Hop 2: Tunnel' },
                { id: 'n7', type: 'smb_pipe', label: 'SMB Pipe Beacon (DC01)', sub: 'No Internet Egress (\\\\.\\pipe\\mojo)', x: 1340, y: 300, color: '#ef4444', status: 'compromised', step: 'Hop 3: P2P' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'WireGuard + SSH :50050', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n5', to: 'n3', label: 'HTTPS Jitter 35% :443', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e3', from: 'n3', to: 'n4', label: 'Origin Forward (Valid URI/UA)', color: '#f97316', style: 'solid', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e4', from: 'n4', to: 'n2', label: 'Reverse WireGuard Backhaul', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e5', from: 'n5', to: 'n6', label: 'Spawns SOCKS / Ligolo Agent', color: '#a855f7', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e6', from: 'n5', to: 'n7', label: 'SMB Named Pipe :445 Relay', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'both', width: 2 },
            ],
            notes: [],
        }),

        enterprise: () => ({
            title: 'Enterprise Defense-in-Depth Network Topology',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'PUBLIC EDGE & CDN', sub: 'Anycast DDoS Protection', x: 60, y: 80, w: 320, h: 450, color: '#38bdf8', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'DMZ TIER', sub: 'Subnet: 172.16.0.0/24', x: 430, y: 80, w: 340, h: 450, color: '#10b981', style: 'solid', opacity: 0.06 },
                { id: 'z3', label: 'INTERNAL PRODUCTION VPC', sub: 'Subnet: 10.100.0.0/16', x: 820, y: 80, w: 660, h: 450, color: '#a855f7', style: 'dashed', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'internet', label: 'Public Clients', sub: 'HTTPS Traffic', x: 220, y: 205, color: '#38bdf8', status: 'none', step: '' },
                { id: 'n2', type: 'cdn', label: 'Cloudflare WAF / CDN', sub: 'TLS 1.3 Edge Protection', x: 220, y: 395, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'n3', type: 'firewall', label: 'HA Perimeter NGFW', sub: 'Palo Alto PA-5220', x: 600, y: 205, color: '#10b981', status: 'protected', step: '' },
                { id: 'n4', type: 'lb', label: 'Ingress Load Balancer', sub: 'NGINX / Envoy Reverse Proxy', x: 600, y: 395, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'n5', type: 'k8s', label: 'App Worker Cluster', sub: 'EKS / GKE Production Nodes', x: 1000, y: 205, color: '#a855f7', status: 'protected', step: '' },
                { id: 'n6', type: 'db', label: 'Primary RDS Cluster', sub: 'PostgreSQL :5432 Encrypted', x: 1320, y: 205, color: '#a855f7', status: 'protected', step: '' },
                { id: 'n7', type: 'siem', label: 'SOC Telemetry Lake', sub: 'SIEM + NDR + EDR Correlation', x: 1000, y: 395, color: '#10b981', status: 'protected', step: '' },
                { id: 'n8', type: 'backup', label: 'Immutable Vault', sub: 'Air-Gapped WORM Snapshots', x: 1320, y: 395, color: '#ffcc00', status: 'protected', step: '' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'TLS 1.3 :443', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n2', to: 'n3', label: 'mTLS Origin Pull', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n3', to: 'n4', label: 'Inspected HTTPS', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n4', to: 'n5', label: 'gRPC / REST :8443', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n5', to: 'n6', label: 'Encrypted SQL :5432', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e6', from: 'n6', to: 'n8', label: 'Nightly WORM Snapshot', color: '#ffcc00', style: 'dashed', curve: 'bezier', dir: 'forward', width: 1.8 },
                { id: 'e7', from: 'n5', to: 'n7', label: 'Syslog / OpenTelemetry', color: '#10b981', style: 'dotted', curve: 'bezier', dir: 'forward', width: 1.8 },
            ],
            notes: [],
        }),

        ot_ics: () => ({
            title: 'OT / ICS Purdue Model & Industrial Segmentation',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'IT ENTERPRISE ZONE (LEVEL 4)', sub: 'Corporate IT Network', x: 60, y: 80, w: 340, h: 450, color: '#38bdf8', style: 'dashed', opacity: 0.06 },
                { id: 'z2', label: 'INDUSTRIAL DMZ (LEVEL 3.5)', sub: 'Jump Host & Historian Mirror', x: 450, y: 80, w: 360, h: 450, color: '#ffcc00', style: 'solid', opacity: 0.06 },
                { id: 'z3', label: 'OT CONTROL & CELL ZONE (LEVEL 1-3)', sub: 'SCADA / PLC / Field I/O', x: 860, y: 80, w: 620, h: 450, color: '#14b8a6', style: 'dashed', opacity: 0.06 },
            ],
            nodes: [
                { id: 'n1', type: 'workstation', label: 'Engineering Laptop', sub: 'Corporate IT VLAN 10', x: 230, y: 210, color: '#38bdf8', status: 'none', step: 'Level 4' },
                { id: 'n2', type: 'firewall', label: 'IT/OT Conduit Firewall', sub: 'Unidirectional Policies', x: 630, y: 210, color: '#10b981', status: 'protected', step: 'Level 3.5' },
                { id: 'n3', type: 'bastion', label: 'OT Jump Server (PAM)', sub: 'MFA + Session Recording', x: 630, y: 400, color: '#ffcc00', status: 'protected', step: 'Level 3.5' },
                { id: 'n4', type: 'scada', label: 'SCADA Master Server', sub: 'OPC-UA / DNP3 Control', x: 1030, y: 210, color: '#14b8a6', status: 'protected', step: 'Level 3' },
                { id: 'n5', type: 'hmi', label: 'Plant HMI Station', sub: 'Control Room Console', x: 1330, y: 210, color: '#14b8a6', status: 'none', step: 'Level 2' },
                { id: 'n6', type: 'plc', label: 'Siemens S7-1500 PLC', sub: 'S7comm :102 Controller', x: 1030, y: 400, color: '#14b8a6', status: 'protected', step: 'Level 1' },
                { id: 'n7', type: 'sensor', label: 'Turbine Valve Actuator', sub: '4-20mA Field Loop', x: 1330, y: 400, color: '#14b8a6', status: 'none', step: 'Level 0' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'HTTPS / RDP Request', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n2', to: 'n3', label: 'Inspected Bastion Session', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n3', to: 'n4', label: 'Restricted Engineering Access', color: '#14b8a6', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n4', to: 'n5', label: 'Telemetry Polling', color: '#14b8a6', style: 'solid', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e5', from: 'n4', to: 'n6', label: 'Modbus TCP / S7comm', color: '#14b8a6', style: 'solid', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e6', from: 'n6', to: 'n7', label: 'Fieldbus / Hardwired I/O', color: '#14b8a6', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
            ],
            notes: [],
        }),

        netdraw_enterprise: () => ({
            title: 'Enterprise Multi-VLAN Network & M365 Hybrid Architecture',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z_remote', label: 'Remote & Hybrid Workers', sub: 'Home broadband, mobiles & remote laptops', x: 40, y: 50, w: 340, h: 420, color: '#ec4899', style: 'dashed', opacity: 0.05 },
                { id: 'z_suppliers', label: 'Suppliers & Partners', sub: 'Vendor portals, MSP & payroll partners', x: 40, y: 500, w: 340, h: 320, color: '#38bdf8', style: 'dashed', opacity: 0.05 },
                { id: 'z_mgmt', label: 'Mgmt: VLAN 99 - 10.10.99.0/24', sub: 'Dedicated Tier-0 privileged jump hosts', x: 40, y: 850, w: 340, h: 220, color: '#a855f7', style: 'solid', opacity: 0.06 },
                { id: 'z_core_spine', label: 'Perimeter, Routing & Core Switching', sub: 'WAN Edge, HA Firewall + VPN, Core-SW-01 & Access-SW', x: 420, y: 50, w: 340, h: 860, color: '#ef4444', style: 'solid', opacity: 0.05 },
                { id: 'z_user_vlan', label: 'User VLAN 10 - 10.10.10.0/24 - ~50 Staff', sub: 'Office Wi-Fi, staff laptops, desktops & network printers', x: 40, y: 1100, w: 720, h: 260, color: '#10b981', style: 'dashed', opacity: 0.05 },
                { id: 'z_m365', label: 'Microsoft 365 Tenant - Entra Hybrid', sub: 'Exchange Online, Teams, OneDrive & Entra ID P1/P2', x: 800, y: 50, w: 760, h: 370, color: '#38bdf8', style: 'dashed', opacity: 0.05 },
                { id: 'z_servers', label: 'Server VLAN 20 - 10.10.20.0/24 - VMs on Hyper-V', sub: 'AD CS, DC01/DC02, Entra Connect, SQL & File Services', x: 800, y: 450, w: 760, h: 410, color: '#a855f7', style: 'solid', opacity: 0.06 },
                { id: 'z_lob', label: 'Line of Business Applications', sub: 'HR system, Sales CRM, Finance & ERP cluster', x: 800, y: 890, w: 760, h: 180, color: '#10b981', style: 'dashed', opacity: 0.05 },
                { id: 'z_public_web', label: 'Public Website - Third-Party Hosted (Off-Network)', sub: 'Customer-facing website, cloud CDN & web host', x: 800, y: 1100, w: 760, h: 260, color: '#f97316', style: 'dashed', opacity: 0.05 },
            ],
            nodes: [
                // Remote Workers
                { id: 'nw_staff', type: 'user', label: 'Hybrid Staff', sub: '450 Users (Home / Office)', x: 130, y: 160, color: '#ec4899', status: 'none', step: '' },
                { id: 'nw_laptops', type: 'laptop', label: 'Remote Laptops x12', sub: 'Intune-managed (BitLocker)', x: 290, y: 160, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'nw_mobiles', type: 'mobile', label: 'Mobiles x50', sub: 'Secure MDM / iOS & Android', x: 130, y: 320, color: '#a855f7', status: 'protected', step: '' },
                { id: 'nw_home_wan', type: 'internet', label: 'Home Broadband', sub: 'Dynamic IP / ISP WAN', x: 290, y: 320, color: '#38bdf8', status: 'none', step: '' },

                // Suppliers
                { id: 'nw_erp_vendor', type: 'cloud', label: 'ERP Vendor', sub: 'Software Supplier Portal', x: 130, y: 590, color: '#38bdf8', status: 'none', step: '' },
                { id: 'nw_ms_cloud', type: 'cloud', label: 'Microsoft', sub: 'Cloud Provider (SaaS)', x: 290, y: 590, color: '#38bdf8', status: 'none', step: '' },
                { id: 'nw_payroll', type: 'app', label: 'Payroll Bureau', sub: 'Finance Third-Party API', x: 130, y: 730, color: '#10b981', status: 'none', step: '' },
                { id: 'nw_msp', type: 'rmm', label: 'MSP - Managed IT', sub: 'Outsourced IT Support', x: 290, y: 730, color: '#10b981', status: 'protected', step: '' },

                // Mgmt VLAN 99
                { id: 'nw_pam02', type: 'bastion', label: 'Admin PAM 02', sub: '10.10.99.21 (Tier-0)', x: 130, y: 950, color: '#a855f7', status: 'protected', step: 'PAM' },
                { id: 'nw_pam01', type: 'bastion', label: 'Admin PAM 01', sub: '10.10.99.11 (Tier-1)', x: 290, y: 950, color: '#a855f7', status: 'protected', step: 'PAM' },

                // Spine
                { id: 'nw_internet', type: 'internet', label: 'Internet', sub: 'Global IPv4/IPv6 BGP', x: 590, y: 130, color: '#38bdf8', status: 'none', step: 'WAN' },
                { id: 'nw_isp_router', type: 'router', label: 'ISP Router', sub: '1 Gbps Fiber • 203.0.113.1', x: 590, y: 250, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'nw_fw_vpn', type: 'firewall', label: 'Firewall + VPN', sub: 'FortiGate 100F • 203.0.113.10', x: 590, y: 460, color: '#ef4444', status: 'protected', step: 'Perimeter' },
                { id: 'nw_core_sw', type: 'switch', label: 'Core Switch', sub: 'Core-SW-01 • 10.10.0.1/16', x: 590, y: 640, color: '#38bdf8', status: 'protected', step: '10 GbE' },
                { id: 'nw_access_sw', type: 'switch', label: 'Access Switches x3', sub: 'PoE+ • 10.10.0.10-12', x: 590, y: 770, color: '#38bdf8', status: 'protected', step: '1 GbE' },

                // User VLAN 10
                { id: 'nw_staff_laptops', type: 'laptop', label: 'Staff Laptops x40', sub: 'Win11 Enterprise + EDR', x: 130, y: 1220, color: '#ffcc00', status: 'none', step: '' },
                { id: 'nw_wifi', type: 'wifi', label: 'Office Wi-Fi x3', sub: 'WPA3-Enterprise (AP01-03)', x: 300, y: 1220, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'nw_desktops', type: 'workstation', label: 'Desktops x8', sub: 'Finance / Admin Workstations', x: 470, y: 1220, color: '#ffcc00', status: 'none', step: '' },
                { id: 'nw_printers', type: 'iot', label: 'Printers x2', sub: 'Secure Print Release (IPP/TLS)', x: 630, y: 1220, color: '#10b981', status: 'protected', step: '' },

                // M365 Tenant
                { id: 'nw_mde', type: 'edr', label: 'Defender for Endpoint', sub: 'M365 E5 Security Telemetry', x: 910, y: 150, color: '#10b981', status: 'protected', step: '' },
                { id: 'nw_exo', type: 'mail', label: 'Exchange Online', sub: 'M365 Hybrid Mailbox', x: 1110, y: 150, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'nw_teams', type: 'app', label: 'Microsoft Teams', sub: 'Collaboration & VoIP', x: 1310, y: 150, color: '#38bdf8', status: 'none', step: '' },
                { id: 'nw_spo', type: 'cloud', label: 'SharePoint Online', sub: 'Corporate Intranet Docs', x: 910, y: 300, color: '#38bdf8', status: 'none', step: '' },
                { id: 'nw_onedrive', type: 'cloud', label: 'OneDrive', sub: 'Cloud Document Sync', x: 1110, y: 300, color: '#38bdf8', status: 'none', step: '' },
                { id: 'nw_entra', type: 'cloud_iam', label: 'Entra ID (Hybrid)', sub: 'Conditional Access + MFA', x: 1380, y: 300, color: '#38bdf8', status: 'protected', step: 'SSO' },

                // Server VLAN 20
                { id: 'nw_ca01', type: 'ssl_cert', label: 'CA01 - AD CS', sub: 'Enterprise CA • 10.10.20.12', x: 910, y: 540, color: '#ec4899', status: 'protected', step: 'PKI' },
                { id: 'nw_dc01', type: 'dc', label: 'DC01 - AD DS', sub: 'Primary DC • 10.10.20.10', x: 1110, y: 540, color: '#a855f7', status: 'protected', step: 'Tier-0' },
                { id: 'nw_dc02', type: 'dc', label: 'DC02 - AD DS', sub: 'Replica DC • 10.10.20.11', x: 1310, y: 540, color: '#a855f7', status: 'protected', step: 'Tier-0' },
                { id: 'nw_entra_conn', type: 'rmm', label: 'Entra Connect', sub: 'Password Hash Sync • 10.10.20.14', x: 1470, y: 540, color: '#38bdf8', status: 'protected', step: 'PHS' },
                { id: 'nw_hyperv', type: 'hypervisor', label: 'Hyper-V Hosts x2', sub: 'Failover Cluster • 10.10.20.5', x: 910, y: 720, color: '#a855f7', status: 'protected', step: 'SAN' },
                { id: 'nw_backup', type: 'backup', label: 'Backup Server', sub: 'Veeam Vault • 10.10.20.80', x: 1110, y: 720, color: '#ffcc00', status: 'protected', step: 'Immutable' },
                { id: 'nw_fileserver', type: 'fileserver', label: 'File Server (FS01)', sub: 'SMB Shares • 10.10.20.30', x: 1310, y: 720, color: '#a855f7', status: 'protected', step: 'SMB' },
                { id: 'nw_sql', type: 'db', label: 'SQL Server Cluster', sub: 'MSSQL AlwaysOn • 10.10.20.50', x: 1470, y: 720, color: '#a855f7', status: 'protected', step: 'DB' },

                // LOB Apps
                { id: 'nw_hr', type: 'app', label: 'HR System', sub: '10.10.20.61', x: 900, y: 970, color: '#10b981', status: 'protected', step: '' },
                { id: 'nw_crm', type: 'app', label: 'Sales CRM', sub: '10.10.20.62', x: 1080, y: 970, color: '#10b981', status: 'protected', step: '' },
                { id: 'nw_finance', type: 'app', label: 'Finance Engine', sub: '10.10.20.63', x: 1260, y: 970, color: '#10b981', status: 'protected', step: '' },
                { id: 'nw_erp', type: 'app', label: 'ERP Core', sub: '10.10.20.64', x: 1440, y: 970, color: '#10b981', status: 'protected', step: '' },

                // Public Web
                { id: 'nw_public_users', type: 'user', label: 'Customers & Public', sub: 'External Internet Visitors', x: 920, y: 1220, color: '#ec4899', status: 'none', step: '' },
                { id: 'nw_corp_web', type: 'web', label: 'Corporate Website', sub: 'www.cortoso.co.uk', x: 1170, y: 1220, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'nw_web_host', type: 'cloud', label: 'Web Hosting Provider', sub: 'Off-Network Cloud Host', x: 1420, y: 1220, color: '#f97316', status: 'protected', step: 'Cloud' },
            ],
            edges: [
                { id: 'e_net1', from: 'nw_internet', to: 'nw_isp_router', label: 'WAN Fiber 1 Gbps', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'forward', width: 2.2 },
                { id: 'e_net2', from: 'nw_isp_router', to: 'nw_fw_vpn', label: 'Perimeter Outside / DMZ', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2.2 },
                { id: 'e_net3', from: 'nw_home_wan', to: 'nw_fw_vpn', label: 'Always-on VPN + MFA', color: '#ec4899', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e_net4', from: 'nw_erp_vendor', to: 'nw_fw_vpn', label: 'Supplier VPN + MFA', color: '#38bdf8', style: 'dashed', curve: 'bezier', dir: 'forward', width: 1.8 },
                { id: 'e_net5', from: 'nw_fw_vpn', to: 'nw_core_sw', label: 'Core-LAN 10.10.0.0/16', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2.4 },
                { id: 'e_net6', from: 'nw_core_sw', to: 'nw_access_sw', label: '10 GbE Trunk', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2.2 },
                { id: 'e_net7', from: 'nw_core_sw', to: 'nw_pam01', label: 'Mgmt - VLAN 99 only', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'e_net8', from: 'nw_access_sw', to: 'nw_staff_laptops', label: 'User VLAN 10', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e_net9', from: 'nw_access_sw', to: 'nw_wifi', label: 'PoE+ 802.11ax', color: '#38bdf8', style: 'solid', curve: 'bezier', dir: 'both', width: 1.8 },
                { id: 'e_net10', from: 'nw_core_sw', to: 'nw_hyperv', label: 'VLAN 20 (Server Trunk)', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'both', width: 2.2 },
                { id: 'e_net11', from: 'nw_internet', to: 'nw_entra', label: 'M365 - HTTPS 443', color: '#38bdf8', style: 'animated', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e_net12', from: 'nw_dc01', to: 'nw_dc02', label: 'Replication :389/:636', color: '#a855f7', style: 'solid', curve: 'straight', dir: 'both', width: 2 },
                { id: 'e_net13', from: 'nw_dc01', to: 'nw_ca01', label: 'Auto-Enrollment (RPC)', color: '#ec4899', style: 'solid', curve: 'straight', dir: 'both', width: 1.8 },
                { id: 'e_net14', from: 'nw_dc01', to: 'nw_entra_conn', label: 'LDAP / DirSync', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'forward', width: 1.8 },
                { id: 'e_net15', from: 'nw_entra_conn', to: 'nw_entra', label: 'Sync - PHS :443', color: '#38bdf8', style: 'animated', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'e_net16', from: 'nw_hyperv', to: 'nw_backup', label: 'Nightly Backup VSS', color: '#ffcc00', style: 'dashed', curve: 'straight', dir: 'forward', width: 1.8 },
                { id: 'e_net17', from: 'nw_hyperv', to: 'nw_fileserver', label: 'Hyper-V VM Storage', color: '#a855f7', style: 'solid', curve: 'straight', dir: 'forward', width: 1.8 },
                { id: 'e_net18', from: 'nw_hyperv', to: 'nw_sql', label: 'Hyper-V SQL Virtualization', color: '#a855f7', style: 'solid', curve: 'straight', dir: 'forward', width: 1.8 },
                { id: 'e_net19', from: 'nw_finance', to: 'nw_sql', label: 'Encrypted SQL :1433', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'both', width: 2 },
                { id: 'e_net20', from: 'nw_public_users', to: 'nw_corp_web', label: 'HTTPS :443', color: '#ec4899', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'e_net21', from: 'nw_corp_web', to: 'nw_web_host', label: 'DNS / CDN Origin Pull', color: '#f97316', style: 'dashed', curve: 'straight', dir: 'both', width: 1.8 },
            ],
            notes: [
                { id: 'nt_ent', text: 'ENTERPRISE NETWORK TOPOLOGY: Perimeter NGFW, VLAN Segmentation (User, Server, Mgmt) & Microsoft 365 Entra Hybrid', x: 420, y: 18, color: '#38bdf8' }
            ]
        }),

        apt_campaign_ad: () => ({
            title: 'APT-29 Full Intrusion Campaign: Ingress, Lateral Movement & AD Forest Compromise',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z_adv', label: 'EXTERNAL ADVERSARY INFRASTRUCTURE', sub: 'APT-29 (Nation-State SVR) & Mirai Botnet Mesh', x: 40, y: 60, w: 340, h: 420, color: '#ef4444', style: 'dashed', opacity: 0.06 },
                { id: 'z_wan_edge', label: 'PERIMETER EDGE & DMZ EXPOSURE', sub: 'WAN Router, Edge Firewall (fw-edge-01) & Ingress Filter', x: 420, y: 60, w: 340, h: 420, color: '#f97316', style: 'solid', opacity: 0.06 },
                { id: 'z_victim_user', label: 'INITIAL COMPROMISE & WIRELESS VLAN', sub: 'Jordan Blake (Target) • Laptop (802.11ax Wireless)', x: 800, y: 60, w: 360, h: 420, color: '#ec4899', style: 'dashed', opacity: 0.06 },
                { id: 'z_core_sw', label: 'CORE NETWORK & LATERAL SEGMENTATION', sub: '10.0.0.0/16 Core Router & Switch Backplane', x: 420, y: 520, w: 340, h: 360, color: '#38bdf8', style: 'solid', opacity: 0.05 },
                { id: 'z_internal_srv', label: 'SERVERS VLAN 20 - TARGETED ENCLAVE', sub: 'Web Server, Database, NAS Exfil & Admin Workstations', x: 40, y: 520, w: 340, h: 620, color: '#a855f7', style: 'dashed', opacity: 0.06 },
                { id: 'z_forest_root', label: 'ACTIVE DIRECTORY FOREST ROOT (TIER-0)', sub: 'corp.local • Forest Compromise, AD CS ESC1 & Golden Ticket', x: 800, y: 520, w: 760, h: 620, color: '#ef4444', style: 'solid', opacity: 0.07 },
            ],
            nodes: [
                // Adversary
                { id: 'apt_actor', type: 'threat_actor', label: 'APT-29 (Cozy Bear)', sub: 'Nation-State Threat Actor (SVR)', x: 190, y: 150, color: '#ef4444', status: 'adversary', step: 'ADVERSARY' },
                { id: 'apt_botnet', type: 'botnet', label: 'Mirai Botnet Fleet', sub: '100 Gbps DDoS & Proxy Mesh', x: 190, y: 350, color: '#f97316', status: 'adversary', step: 'ADVERSARY' },

                // Perimeter
                { id: 'apt_wan_inet', type: 'internet', label: 'Internet', sub: 'Public WAN Gateway', x: 580, y: 150, color: '#38bdf8', status: 'none', step: '' },
                { id: 'apt_edge_fw', type: 'firewall', label: 'Edge Firewall (fw-edge-01)', sub: '203.0.113.1 (DMZ)', x: 580, y: 350, color: '#ef4444', status: 'victim', step: 'VICTIM' },

                // Victim User
                { id: 'apt_lure', type: 'phishing', label: 'Invoice Lure (Q3 Invoice)', sub: 'Spearphishing PDF with LNK Payload', x: 970, y: 150, color: '#f97316', status: 'targeted', step: '1. Phish' },
                { id: 'apt_victim', type: 'user', label: 'Jordan Blake', sub: 'Business Person • j.blake@corp.example', x: 970, y: 270, color: '#ec4899', status: 'victim', step: 'VICTIM' },
                { id: 'apt_laptop', type: 'laptop', label: 'Corporate Laptop', sub: '10.0.14.88 (Wireless Ingress)', x: 970, y: 390, color: '#ef4444', status: 'compromised', step: '2. Foothold' },

                // Core Switching
                { id: 'apt_core_rtr', type: 'router', label: 'Core Router', sub: '10.0.0.1 (Gateway)', x: 580, y: 610, color: '#38bdf8', status: 'protected', step: '' },
                { id: 'apt_core_sw', type: 'switch', label: 'Core Switch (Core-SW-01)', sub: '10 GbE Inter-VLAN Trunk', x: 580, y: 770, color: '#38bdf8', status: 'protected', step: '' },

                // Servers VLAN 20
                { id: 'apt_web_srv', type: 'web', label: 'Web Server (web01)', sub: '10.0.20.11 (corp.local)', x: 190, y: 600, color: '#ffcc00', status: 'compromised', step: '3. Pivot' },
                { id: 'apt_db_srv', type: 'db', label: 'PostgreSQL Server', sub: '10.0.20.21 (Production DB)', x: 190, y: 740, color: '#ef4444', status: 'compromised', step: '4. Data Theft' },
                { id: 'apt_nas_srv', type: 'fileserver', label: 'NAS Backup Storage', sub: '10.0.20.31 (SMB Volume)', x: 190, y: 880, color: '#f97316', status: 'compromised', step: '5. Exfil Drop' },
                { id: 'apt_admin_ws', type: 'workstation', label: 'Admin Workstation', sub: 'WKSTN-ADMIN-01 • DA Session Active', x: 190, y: 1040, color: '#ef4444', status: 'compromised', step: '6. LSASS Dump' },

                // AD Forest Root Tier-0
                { id: 'apt_adcs_ca', type: 'ssl_cert', label: 'Enterprise CA (CA01.corp.local)', sub: 'AD CS ESC1 Vulnerable Template (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)', x: 1020, y: 620, color: '#ec4899', status: 'compromised', step: '7. Certipy ESC1' },
                { id: 'apt_tgt_cert', type: 'krb_ticket', label: 'Forged DA Certificate & TGT', sub: 'Administrator@corp.local Ticket', x: 1350, y: 620, color: '#ef4444', status: 'compromised', step: '8. Shadow Auth' },
                { id: 'apt_dc01', type: 'dc', label: 'DC01.corp.local (Forest Root)', sub: '10.0.20.10 • Primary Domain Controller', x: 1020, y: 820, color: '#ef4444', status: 'compromised', step: '9. DCSync NTDS' },
                { id: 'apt_krbtgt', type: 'lsass_secrets', label: 'KRBTGT AES256 & NTLM Key', sub: 'Forest-Wide Master Secret Key', x: 1350, y: 820, color: '#ef4444', status: 'compromised', step: '10. Golden Ticket' },
                { id: 'apt_forest_takeover', type: 'ad_group', label: 'ENTERPRISE ADMINS & FOREST PERSISTENCE', sub: 'Full Forest Takeover Across All Child Domains & Trusts', x: 1180, y: 1040, color: '#ef4444', status: 'compromised', step: 'FOREST COMPROMISED' },
            ],
            edges: [
                { id: 'ae1', from: 'apt_actor', to: 'apt_botnet', label: 'controls', color: '#f97316', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae2', from: 'apt_botnet', to: 'apt_edge_fw', label: 'DDoS Flood / Distraction', color: '#f97316', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'ae3', from: 'apt_actor', to: 'apt_lure', label: 'Spearphishing Email', color: '#ef4444', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'ae4', from: 'apt_lure', to: 'apt_victim', label: 'targets', color: '#ec4899', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae5', from: 'apt_victim', to: 'apt_laptop', label: 'Executes malicious LNK', color: '#ec4899', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae6', from: 'apt_laptop', to: 'apt_wan_inet', label: 'HTTPS C2 Beacon :443', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'both', width: 2.2 },
                { id: 'ae7', from: 'apt_wan_inet', to: 'apt_edge_fw', label: 'WAN Transit', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae8', from: 'apt_edge_fw', to: 'apt_core_rtr', label: 'Core - 10.0.0.0/16', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2.2 },
                { id: 'ae9', from: 'apt_core_rtr', to: 'apt_core_sw', label: '10 GbE Trunk', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2.4 },
                { id: 'ae10', from: 'apt_laptop', to: 'apt_core_sw', label: 'Wireless VLAN 10 Hop', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'ae11', from: 'apt_core_sw', to: 'apt_web_srv', label: 'Lateral WMI / WinRM Pivot', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'ae12', from: 'apt_web_srv', to: 'apt_db_srv', label: 'Dumps Database Records', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae13', from: 'apt_db_srv', to: 'apt_nas_srv', label: 'Stages 85 GB Tar Archive', color: '#f97316', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae14', from: 'apt_nas_srv', to: 'apt_actor', label: 'Encrypted Rclone Exfil Drop', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'ae15', from: 'apt_web_srv', to: 'apt_admin_ws', label: 'Pass-the-Hash / PsExec', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae16', from: 'apt_admin_ws', to: 'apt_adcs_ca', label: 'Certipy req -ca CA01 -template ESC1', color: '#ec4899', style: 'solid', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'ae17', from: 'apt_adcs_ca', to: 'apt_tgt_cert', label: 'Issues Forged Admin PFX', color: '#ec4899', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'ae18', from: 'apt_tgt_cert', to: 'apt_dc01', label: 'PKINIT Auth -> DA TGT Ticket', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2.2 },
                { id: 'ae19', from: 'apt_admin_ws', to: 'apt_dc01', label: 'secretsdump DCSync (Event 4662)', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.4 },
                { id: 'ae20', from: 'apt_dc01', to: 'apt_krbtgt', label: 'Extracts KRBTGT Hash (NTDS.dit)', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2.2 },
                { id: 'ae21', from: 'apt_krbtgt', to: 'apt_forest_takeover', label: 'Forge Golden Ticket (10-Yr Persistence)', color: '#ef4444', style: 'animated', curve: 'straight', dir: 'forward', width: 2.5 },
            ],
            notes: [
                { id: 'nt_apt', text: 'APT-29 THREAT CAMPAIGN: Initial Access -> Ingress Lateral Pivot -> AD CS ESC1 -> DCSync -> Complete Active Directory Forest Takeover', x: 410, y: 20, color: '#ef4444' }
            ]
        }),

        ad_forest_takeover: () => ({
            title: 'Active Directory Multi-Domain Forest Compromise & Trust Path Abuse',
            defaultFont: 'IBM Plex Mono',
            zones: [
                { id: 'z_child', label: 'CHILD DOMAIN: EMEA.CORP.LOCAL', sub: 'Compromised Subsidiary Domain Controller & OU Hierarchy', x: 50, y: 70, w: 440, h: 560, color: '#f97316', style: 'dashed', opacity: 0.06 },
                { id: 'z_trust', label: 'INTRA-FOREST & CROSS-FOREST TRUSTS', sub: 'Kerberos Referral Tickets, SID Filtering & Forest Boundaries', x: 530, y: 70, w: 420, h: 560, color: '#a855f7', style: 'solid', opacity: 0.06 },
                { id: 'z_root', label: 'ROOT DOMAIN: CORP.LOCAL (TIER-0)', sub: 'Forest Root Domain Controller, Enterprise Admins & AD CS PKI', x: 990, y: 70, w: 480, h: 560, color: '#ef4444', style: 'solid', opacity: 0.07 },
            ],
            nodes: [
                // Child Domain
                { id: 'ad_child_user', type: 'ad_user', label: 'emea_helpdesk@emea.corp.local', sub: 'Compromised Tier-1 Support Account', x: 270, y: 160, color: '#ffcc00', status: 'compromised', step: '1. Child Foothold' },
                { id: 'ad_child_gpo', type: 'ad_gpo', label: 'GPO: Default Workstation Policy', sub: 'WriteDacl Abuse -> Immediate Scheduled Task', x: 270, y: 310, color: '#f97316', status: 'compromised', step: '2. GPO Poisoning' },
                { id: 'ad_child_dc', type: 'dc', label: 'DC-EMEA-01.emea.corp.local', sub: '10.30.1.10 • Child Domain Controller (Owned)', x: 270, y: 470, color: '#ef4444', status: 'compromised', step: '3. Child DA' },

                // Trust Path Abuse
                { id: 'ad_sid_hist', type: 'lsass_secrets', label: 'sIDHistory Injection', sub: 'Injects Enterprise Admins SID (S-1-5-21-...-519)', x: 740, y: 160, color: '#ef4444', status: 'compromised', step: '4. SID Injection' },
                { id: 'ad_trust_key', type: 'krb_ticket', label: 'Inter-Realm Trust Key [KDC]', sub: 'EMEA$ Trust Account NTLM Hash', x: 740, y: 310, color: '#ef4444', status: 'compromised', step: '5. Inter-Realm TGT' },
                { id: 'ad_forest_trust', type: 'ad_ou', label: 'Two-Way Transitive Forest Trust', sub: 'TrustAttributes: TREAT_AS_EXTERNAL=0 (No SID Filtering)', x: 740, y: 470, color: '#a855f7', status: 'alert', step: 'Trust Hop' },

                // Forest Root
                { id: 'ad_root_dc', type: 'dc', label: 'DC-ROOT-01.corp.local', sub: '10.10.1.10 • Forest Root Domain Controller', x: 1230, y: 160, color: '#ef4444', status: 'compromised', step: '6. Forest Root DC' },
                { id: 'ad_dcsync_ntds', type: 'lsass_secrets', label: 'DRSGetNCChanges (NTDS.dit)', sub: 'DCSync All Domain Hashes (12,000 Accounts)', x: 1230, y: 310, color: '#ef4444', status: 'compromised', step: '7. Full DCSync' },
                { id: 'ad_krbtgt_master', type: 'krb_ticket', label: 'Forest KRBTGT Golden Ticket', sub: 'Unrevocable Domain Dominance (Tier-0)', x: 1230, y: 470, color: '#ef4444', status: 'compromised', step: '8. Forest Dominance' },
            ],
            edges: [
                { id: 'te1', from: 'ad_child_user', to: 'ad_child_gpo', label: 'Modifies GPO Extension Script', color: '#f97316', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'te2', from: 'ad_child_gpo', to: 'ad_child_dc', label: 'Elevates to SYSTEM on Child DC', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2.2 },
                { id: 'te3', from: 'ad_child_dc', to: 'ad_trust_key', label: 'Extracts Inter-Realm Trust Key', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'te4', from: 'ad_trust_key', to: 'ad_sid_hist', label: 'Mitm / Rubeus Golden Ticket with sIDHistory', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2.2 },
                { id: 'te5', from: 'ad_child_dc', to: 'ad_forest_trust', label: 'Kerberos TGS Referral Request', color: '#a855f7', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'te6', from: 'ad_sid_hist', to: 'ad_root_dc', label: 'Enterprise Admins Ticket Presented (No SID Filtering)', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.4 },
                { id: 'te7', from: 'ad_root_dc', to: 'ad_dcsync_ntds', label: 'Replication RPC (EventID 4662)', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2.2 },
                { id: 'te8', from: 'ad_dcsync_ntds', to: 'ad_krbtgt_master', label: 'Extracts Forest Root KRBTGT Secret', color: '#ef4444', style: 'animated', curve: 'straight', dir: 'forward', width: 2.5 },
            ],
            notes: [
                { id: 'nt_trust', text: 'ACTIVE DIRECTORY TRUST ABUSE: Child Domain Takeover -> Inter-Realm TGT with sIDHistory -> Forest Root Dominance', x: 420, y: 22, color: '#ef4444' }
            ]
        }),

        cloud_hybrid: () => ({
            title: 'Enterprise Multi-VPC AWS & Azure Hybrid Cloud Architecture',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z_onprem', label: 'ON-PREMISES DATACENTER', sub: 'Core Switching, DirectConnect & ExpressRoute Edge', x: 50, y: 80, w: 340, h: 520, color: '#a855f7', style: 'solid', opacity: 0.06 },
                { id: 'z_transit', label: 'HYBRID TRANSIT NETWORK HUB', sub: 'AWS Transit Gateway (TGW) & Azure Virtual WAN Hub', x: 430, y: 80, w: 360, h: 520, color: '#38bdf8', style: 'dashed', opacity: 0.06 },
                { id: 'z_cloud_prod', label: 'MULTI-CLOUD PRODUCTION WORKLOADS', sub: 'AWS EKS Production VPC & Azure AKS Microservices', x: 830, y: 80, w: 680, h: 520, color: '#10b981', style: 'dashed', opacity: 0.05 },
            ],
            nodes: [
                { id: 'ch_core_dc', type: 'router', label: 'Datacenter Edge Router', sub: 'BGP ASN 64512 • On-Prem Core', x: 220, y: 190, color: '#a855f7', status: 'protected', step: 'On-Prem' },
                { id: 'ch_dx_circuit', type: 'router', label: 'AWS DirectConnect (10G)', sub: 'Dedicated Fiber Interconnect', x: 220, y: 350, color: '#38bdf8', status: 'protected', step: 'DirectConnect' },
                { id: 'ch_expressroute', type: 'router', label: 'Azure ExpressRoute (10G)', sub: 'Private Peering to MS Edge', x: 220, y: 500, color: '#38bdf8', status: 'protected', step: 'ExpressRoute' },

                { id: 'ch_aws_tgw', type: 'lb', label: 'AWS Transit Gateway', sub: 'Hub Router (VPC Attachments)', x: 610, y: 220, color: '#38bdf8', status: 'protected', step: 'AWS TGW' },
                { id: 'ch_inspection_vpc', type: 'firewall', label: 'Palo Alto VM-Series WAF', sub: 'Central Inspection VPC (Geneve)', x: 610, y: 370, color: '#10b981', status: 'protected', step: 'Firewall Hub' },
                { id: 'ch_azure_vwan', type: 'lb', label: 'Azure Virtual WAN Hub', sub: 'Global Secure Routing Transit', x: 610, y: 520, color: '#38bdf8', status: 'protected', step: 'Azure vWAN' },

                { id: 'ch_aws_eks', type: 'k8s', label: 'AWS EKS Worker Nodes', sub: 'App VPC (10.100.0.0/16)', x: 1010, y: 200, color: '#10b981', status: 'protected', step: 'AWS Prod' },
                { id: 'ch_aws_rds', type: 'db', label: 'AWS Aurora PostgreSQL', sub: 'Multi-AZ Database Cluster', x: 1330, y: 200, color: '#10b981', status: 'protected', step: 'Encrypted DB' },
                { id: 'ch_azure_aks', type: 'k8s', label: 'Azure AKS Microservices', sub: 'Spoke VNet (10.200.0.0/16)', x: 1010, y: 400, color: '#38bdf8', status: 'protected', step: 'Azure Prod' },
                { id: 'ch_cloud_iam', type: 'cloud_iam', label: 'IAM Identity Center (SSO)', sub: 'OIDC / SAML 2.0 Auth', x: 1330, y: 400, color: '#a855f7', status: 'protected', step: 'Zero Trust' },
                { id: 'ch_guardduty', type: 'siem', label: 'GuardDuty & Sentinel SIEM', sub: 'Cloud Threat Detection Pipeline', x: 1170, y: 530, color: '#ffcc00', status: 'protected', step: 'SOC Telemetry' },
            ],
            edges: [
                { id: 'ce1', from: 'ch_core_dc', to: 'ch_dx_circuit', label: 'BGP Peering', color: '#a855f7', style: 'solid', curve: 'straight', dir: 'both', width: 2 },
                { id: 'ce2', from: 'ch_core_dc', to: 'ch_expressroute', label: 'BGP Peering', color: '#a855f7', style: 'solid', curve: 'straight', dir: 'both', width: 2 },
                { id: 'ce3', from: 'ch_dx_circuit', to: 'ch_aws_tgw', label: 'Transit VIF 10G', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2.2 },
                { id: 'ce4', from: 'ch_expressroute', to: 'ch_azure_vwan', label: 'Virtual Network Gateway', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2.2 },
                { id: 'ce5', from: 'ch_aws_tgw', to: 'ch_inspection_vpc', label: 'Geneve Encapsulation', color: '#10b981', style: 'solid', curve: 'straight', dir: 'both', width: 2 },
                { id: 'ce6', from: 'ch_aws_tgw', to: 'ch_aws_eks', label: 'VPC Attachment', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2 },
                { id: 'ce7', from: 'ch_aws_eks', to: 'ch_aws_rds', label: 'Encrypted SQL :5432', color: '#10b981', style: 'solid', curve: 'straight', dir: 'both', width: 2 },
                { id: 'ce8', from: 'ch_azure_vwan', to: 'ch_azure_aks', label: 'VNet Peering', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'both', width: 2 },
                { id: 'ce9', from: 'ch_aws_eks', to: 'ch_cloud_iam', label: 'IRSA / STS Tokens', color: '#a855f7', style: 'solid', curve: 'bezier', dir: 'forward', width: 1.8 },
                { id: 'ce10', from: 'ch_aws_eks', to: 'ch_guardduty', label: 'VPC Flow Logs & EKS Audit', color: '#ffcc00', style: 'dotted', curve: 'bezier', dir: 'forward', width: 1.8 },
                { id: 'ce11', from: 'ch_azure_aks', to: 'ch_guardduty', label: 'Azure Activity Logs', color: '#ffcc00', style: 'dotted', curve: 'bezier', dir: 'forward', width: 1.8 },
            ],
            notes: [
                { id: 'nt_cloud', text: 'HYBRID MULTI-CLOUD ARCHITECTURE: AWS Transit Gateway & Azure vWAN Hub with Central Palo Alto Inspection VPC', x: 420, y: 28, color: '#38bdf8' }
            ]
        }),

        supply_chain_cicd: () => ({
            title: 'CI/CD Pipeline Software Supply Chain Compromise (Sunburst Style)',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z_sc_adv', label: 'ADVERSARY (APT29 / COZY BEAR)', sub: 'Token Theft & Reconnaissance', x: 50, y: 80, w: 340, h: 480, color: '#ef4444', style: 'dashed', opacity: 0.06 },
                { id: 'z_sc_build', label: 'INTERNAL BUILD PIPELINE ENCLAVE', sub: 'GitHub Enterprise, Jenkins Runner & Code-Signing HSM', x: 430, y: 80, w: 600, h: 480, color: '#f97316', style: 'solid', opacity: 0.06 },
                { id: 'z_sc_victims', label: 'DOWNSTREAM SOFTWARE DISTRIBUTION', sub: 'Update CDN & 18,000 Infected Enterprise Customers', x: 1070, y: 80, w: 420, h: 480, color: '#ef4444', style: 'dashed', opacity: 0.07 },
            ],
            nodes: [
                { id: 'sc_actor', type: 'threat_actor', label: 'APT29 / Midnight Blizzard', sub: 'Foreign Intelligence Service (SVR)', x: 220, y: 190, color: '#ef4444', status: 'adversary', step: 'Threat Actor' },
                { id: 'sc_dev_laptop', type: 'laptop', label: 'Lead Developer Laptop', sub: 'Token Stolen via Password Spray / Infostealer', x: 220, y: 380, color: '#ffcc00', status: 'compromised', step: '1. Cred Theft' },

                { id: 'sc_github', type: 'app', label: 'GitHub Enterprise Server', sub: 'Private Source Code Repositories', x: 570, y: 190, color: '#38bdf8', status: 'compromised', step: '2. Repo Access' },
                { id: 'sc_runner', type: 'app', label: 'CI/CD Build Runner (Jenkins)', sub: 'Sunspot Implant Injects Code During msbuild', x: 570, y: 380, color: '#ef4444', status: 'compromised', step: '3. Build Injection' },
                { id: 'sc_signing_hsm', type: 'ssl_cert', label: 'Corporate Code-Signing HSM', sub: 'Valid Authenticode Certificate (Legit Signature)', x: 880, y: 285, color: '#10b981', status: 'targeted', step: '4. Code Signing' },

                { id: 'sc_cdn_release', type: 'cdn', label: 'Software Update CDN', sub: 'downloads.vendor.com (Signed MSI)', x: 1280, y: 190, color: '#38bdf8', status: 'compromised', step: '5. Distribution' },
                { id: 'sc_backdoor_dll', type: 'dfir_dll', label: 'SolarWinds.Orion.Core.dll', sub: 'Trojanized Sunburst Backdoor (C2 DGA)', x: 1280, y: 340, color: '#ef4444', status: 'compromised', step: '6. Sunburst Payload' },
                { id: 'sc_victim_orgs', type: 'target_org', label: '18,000 Enterprise Victims', sub: 'Government, Defense & Fortune 500 Networks', x: 1280, y: 470, color: '#ef4444', status: 'victim', step: '7. Downstream Infiltration' },
            ],
            edges: [
                { id: 'se1', from: 'sc_actor', to: 'sc_dev_laptop', label: 'Phishing / Infostealer Log', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'se2', from: 'sc_dev_laptop', to: 'sc_github', label: 'Stolen PAT Token Auth', color: '#ffcc00', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'se3', from: 'sc_github', to: 'sc_runner', label: 'Triggers Automated Webhook', color: '#38bdf8', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'se4', from: 'sc_actor', to: 'sc_runner', label: 'Deploys Sunspot Memory Implant', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'se5', from: 'sc_runner', to: 'sc_signing_hsm', label: 'Submits Compiled Binary for Signing', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'forward', width: 2 },
                { id: 'se6', from: 'sc_signing_hsm', to: 'sc_cdn_release', label: 'Publishes Cryptographically Signed MSI', color: '#10b981', style: 'solid', curve: 'bezier', dir: 'forward', width: 2.2 },
                { id: 'se7', from: 'sc_cdn_release', to: 'sc_backdoor_dll', label: 'Includes Backdoor Assembly', color: '#ef4444', style: 'solid', curve: 'straight', dir: 'forward', width: 2 },
                { id: 'se8', from: 'sc_cdn_release', to: 'sc_victim_orgs', label: 'Auto-Update Pull Over HTTPS :443', color: '#ef4444', style: 'animated', curve: 'bezier', dir: 'forward', width: 2.4 },
            ],
            notes: [
                { id: 'nt_sc', text: 'SUPPLY CHAIN INTRUSION: Source Code Access -> CI/CD Build Runner Tampering -> Legitimate Code Signing -> 18,000 Downstream Victims', x: 380, y: 25, color: '#f97316' }
            ]
        }),
    };

    // Studio State
    const state = {
        initialized: false,
        title: 'Ransomware Intrusion & Lateral Movement',
        defaultFont: 'Plus Jakarta Sans',
        mode: 'select', // 'select' | 'connect' | 'zone' | 'text' | 'pan'
        canvasTheme: 'dark', // 'dark' | 'white' | 'transparent'
        showGrid: true,
        snapToGrid: true,
        animateFlows: true,
        searchQuery: '',
        activeCatFilter: 'all',
        paletteCollapsed: false,
        inspectorCollapsed: false,
        collapsedCats: new Set(['hunt_detect', 'redteam_ad', 'threats', 'network', 'security', 'servers', 'endpoints', 'ot']),

        // Viewport transform
        panX: 20,
        panY: 20,
        zoom: 1,
        lastMouseWorld: { x: 480, y: 280 },

        // Diagram entities
        zones: [],
        nodes: [],
        edges: [],
        notes: [],

        // Selection & Internal Clipboard
        selectedType: null, // 'node' | 'edge' | 'zone' | 'note'
        selectedIds: new Set(),
        clipboard: null,

        // Interaction state
        isPanning: false,
        spacePressed: false,
        dragStartWorld: null,
        dragStartScreen: null,
        draggingItems: null,
        resizingZone: null,
        resizingNode: null,
        drawingZone: null,
        connectingFrom: null,
        draggingEdgeEnd: null,
        draggingEdgeStep: null,
        marquee: null,
        hoveredNodeId: null,

        // Undo / Redo stacks
        undoStack: [],
        redoStack: [],
        animFrameId: null,
        animTick: 0,
    };

    const NODE_MIN_W = 196;
    const NODE_MIN_H = 68;
    const GRID_SIZE = 20;

    const resolveFontStack = (fontId, fallbackId = null) => {
        if (fontId && fontId !== 'default' && FONT_MAP.has(fontId)) {
            return FONT_MAP.get(fontId);
        }
        const globalId = fallbackId || state.defaultFont || 'Plus Jakarta Sans';
        return FONT_MAP.get(globalId) || '"Plus Jakarta Sans", system-ui, sans-serif';
    };

    const buildCanvasFont = ({ family, size = 12, bold = true, italic = false, fallbackFamily = null }) => {
        const styleStr = italic ? 'italic ' : '';
        const weightStr = bold ? '700 ' : '500 ';
        const px = Math.max(8, Math.min(48, Number(size) || 12));
        const stack = resolveFontStack(family, fallbackFamily);
        return `${styleStr}${weightStr}${px}px ${stack}`;
    };

    // Dynamic Zero-Truncation Node Size Calculator:
    // Automatically expands node width so neither the title nor the subtitle is EVER truncated!
    const getNodeSize = (n) => {
        if (n.type === 'image') {
            return {
                w: Math.max(80, Number(n.w) || 210),
                h: Math.max(60, Number(n.h) || 145),
            };
        }
        if (n.isStep || n.type === 'flow_step' || n.type === 'step_marker' || n.shape === 'step') {
            const baseSize = Math.max(22, Number(n.size) || Number(n.w) || 36);
            const labelText = String(n.label ?? '1');
            let textW = 0;
            if (measureCtx) {
                const fs = Number(n.fontSize) || Math.max(12, Math.round(baseSize * 0.44));
                measureCtx.font = buildCanvasFont({
                    family: n.fontFamily && n.fontFamily !== 'default' ? n.fontFamily : 'Plus Jakarta Sans',
                    size: fs,
                    bold: n.fontBold !== false,
                    italic: !!n.fontItalic,
                });
                textW = measureCtx.measureText(labelText).width;
            } else {
                textW = labelText.length * 8.5;
            }
            const diameter = Math.max(baseSize, Math.ceil(textW + 16));
            return { w: diameter, h: diameter };
        }
        const asset = ALL_ASSETS_MAP.get(n.type) || { name: 'Node', sub: '' };
        const labelFontSize = Number(n.fontSize) || 12.5;
        const subFontSize = Math.max(9.5, labelFontSize - 1.5);

        const labelText = String(n.label ?? asset.name ?? '');
        const subText = String(n.sub ?? asset.sub ?? '');

        let measuredW = 0;
        if (measureCtx) {
            measureCtx.font = buildCanvasFont({
                family: n.fontFamily,
                size: labelFontSize,
                bold: n.fontBold !== false,
                italic: !!n.fontItalic,
            });
            const lw = measureCtx.measureText(labelText).width;

            measureCtx.font = buildCanvasFont({
                family: n.fontFamily && n.fontFamily !== 'default' ? n.fontFamily : 'IBM Plex Mono',
                size: subFontSize,
                bold: false,
                italic: !!n.fontItalic,
            });
            const sw = measureCtx.measureText(subText).width;
            measuredW = Math.max(lw, sw);
        } else {
            measuredW = Math.max(labelText.length * 7.5, subText.length * 6.8);
        }

        // 60px left icon area + measured text width + 22px right padding (or extra side padding for geometric Process Flow shapes)
        const isFlow = !!asset.flowShape;
        const padW = isFlow ? (asset.flowShape === 'diamond' ? 88 : 54) : 82;
        const minW = isFlow ? (asset.flowShape === 'connector' ? 92 : 164) : NODE_MIN_W;
        const minH = isFlow ? (asset.flowShape === 'diamond' ? 86 : (asset.flowShape === 'connector' ? 92 : 66)) : NODE_MIN_H;
        const autoW = Math.ceil(measuredW + padW);
        const autoH = Math.max(minH, Math.ceil(labelFontSize + subFontSize + 36));

        return {
            w: Math.max(minW, Number(n.w) || 0, autoW),
            h: Math.max(minH, Number(n.h) || 0, autoH),
        };
    };

    // Auto-Sequenced Step Marker Calculation (1 to Infinite)
    const getNextStepNumber = () => {
        const existing = state.nodes
            .filter((n) => n.isStep || n.type === 'flow_step' || n.type === 'step_marker' || n.shape === 'step')
            .map((n) => {
                const num = parseInt(String(n.label).trim(), 10);
                return isNaN(num) ? 0 : num;
            })
            .filter((num) => num > 0);
        return existing.length > 0 ? Math.max(...existing) + 1 : 1;
    };

    const uid = (prefix = 'id') => `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;

    const esc = (v) => String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');

    const snap = (val) => (state.snapToGrid ? Math.round(val / GRID_SIZE) * GRID_SIZE : Math.round(val));

    // =========================================================================
    // Serialization, Undo/Redo, & Native .mantis-draw Project Format
    // =========================================================================
    const serializeDiagram = () => ({
        title: state.title,
        defaultFont: state.defaultFont || 'Plus Jakarta Sans',
        canvasTheme: state.canvasTheme || 'dark',
        showGrid: state.showGrid,
        snapToGrid: state.snapToGrid,
        animateFlows: state.animateFlows,
        zones: JSON.parse(JSON.stringify(state.zones)),
        nodes: JSON.parse(JSON.stringify(state.nodes)),
        edges: JSON.parse(JSON.stringify(state.edges)),
        notes: JSON.parse(JSON.stringify(state.notes)),
    });

    const buildMantisDrawFilePayload = () => ({
        format: FILE_FORMAT_MAGIC,
        version: FILE_FORMAT_VERSION,
        exportedAt: new Date().toISOString(),
        application: 'MANTIS Diagram Draw Studio',
        diagram: serializeDiagram(),
    });

    const parseImportedProjectPayload = (rawObj) => {
        if (!rawObj || typeof rawObj !== 'object') {
            throw new Error('File does not contain a valid JSON object.');
        }
        const diag = (rawObj.format === FILE_FORMAT_MAGIC && rawObj.diagram)
            ? rawObj.diagram
            : rawObj;
        if (!Array.isArray(diag.nodes) && !Array.isArray(diag.zones) && !Array.isArray(diag.edges)) {
            throw new Error('Unrecognized diagram file structure.');
        }
        return diag;
    };

    const saveToLocalStorage = () => {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(serializeDiagram()));
        } catch (_) {}
    };

    const pushHistory = () => {
        state.undoStack.push(serializeDiagram());
        if (state.undoStack.length > 40) state.undoStack.shift();
        state.redoStack = [];
        saveToLocalStorage();
        updateToolbarButtons();
    };

    const applySnapshot = (snapData) => {
        if (!snapData) return;
        state.title = snapData.title || 'Untitled Threat Diagram';
        state.defaultFont = snapData.defaultFont || 'Plus Jakarta Sans';
        if (snapData.canvasTheme) state.canvasTheme = snapData.canvasTheme;
        state.zones = JSON.parse(JSON.stringify(snapData.zones || []));
        state.nodes = JSON.parse(JSON.stringify(snapData.nodes || []));
        state.edges = JSON.parse(JSON.stringify(snapData.edges || []));
        state.notes = JSON.parse(JSON.stringify(snapData.notes || []));
        state.selectedIds.clear();
        state.selectedType = null;

        state.nodes.forEach((n) => {
            if (n.imageSrc) getOrLoadImage(n.imageSrc);
        });

        const topFont = document.getElementById('dd-global-font');
        if (topFont) topFont.value = state.defaultFont;
        const disp = document.getElementById('dd-diagram-title-input');
        if (disp) disp.value = state.title;

        saveToLocalStorage();
        updateToolbarButtons();
        renderInspector();
        requestRender();
    };

    const undo = () => {
        if (!state.undoStack.length) return;
        state.redoStack.push(serializeDiagram());
        const prev = state.undoStack.pop();
        applySnapshot(prev);
        showToast('Undid last action');
    };

    const redo = () => {
        if (!state.redoStack.length) return;
        state.undoStack.push(serializeDiagram());
        const next = state.redoStack.pop();
        applySnapshot(next);
        showToast('Redid action');
    };

    let toastTimer = null;
    const showToast = (msg, isError = false) => {
        const el = document.getElementById('dd-toast');
        if (!el) return;
        el.innerHTML = `<i class="fa-solid ${isError ? 'fa-circle-exclamation' : 'fa-circle-check'}"></i> <span>${esc(msg)}</span>`;
        el.style.display = 'inline-flex';
        el.style.borderColor = isError ? 'rgba(239,68,68,0.5)' : 'rgba(16,185,129,0.5)';
        el.style.color = isError ? '#fca5a5' : '#6ee7b7';
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
            el.style.display = 'none';
        }, 3200);
    };

    const screenToWorld = (sx, sy) => ({
        x: (sx - state.panX) / state.zoom,
        y: (sy - state.panY) / state.zoom,
    });

    const getNodePorts = (n) => {
        const { w, h } = getNodeSize(n);
        const hw = w / 2;
        const hh = h / 2;
        return [
            { side: 'top', x: n.x, y: n.y - hh },
            { side: 'right', x: n.x + hw, y: n.y },
            { side: 'bottom', x: n.x, y: n.y + hh },
            { side: 'left', x: n.x - hw, y: n.y },
        ];
    };

    const hitTestPort = (wx, wy) => {
        for (let i = state.nodes.length - 1; i >= 0; i--) {
            const n = state.nodes[i];
            const ports = getNodePorts(n);
            for (const p of ports) {
                const dx = wx - p.x;
                const dy = wy - p.y;
                if (dx * dx + dy * dy <= 64) {
                    return { node: n, port: p };
                }
            }
        }
        return null;
    };

    const hitTestNodeResize = (wx, wy) => {
        for (let i = state.nodes.length - 1; i >= 0; i--) {
            const n = state.nodes[i];
            if (!state.selectedIds.has(n.id) || state.selectedType !== 'node') continue;
            const { w, h } = getNodeSize(n);
            const rx = n.x + w / 2;
            const ry = n.y + h / 2;
            if (Math.abs(wx - rx) <= 10 && Math.abs(wy - ry) <= 10) {
                return n;
            }
        }
        return null;
    };

    const hitTestNode = (wx, wy) => {
        for (let i = state.nodes.length - 1; i >= 0; i--) {
            const n = state.nodes[i];
            const { w, h } = getNodeSize(n);
            const hw = w / 2;
            const hh = h / 2;
            const isStep = n.isStep || n.type === 'flow_step' || n.type === 'step_marker' || n.shape === 'step';
            if (isStep) {
                const dx = wx - n.x;
                const dy = wy - n.y;
                if (dx * dx + dy * dy <= (hw + 6) * (hh + 6)) {
                    return n;
                }
            } else if (wx >= n.x - hw && wx <= n.x + hw && wy >= n.y - hh && wy <= n.y + hh) {
                return n;
            }
        }
        return null;
    };

    const getNoteSize = (t) => {
        const fontSz = Number(t.fontSize) || 11.5;
        let textW = (t.text || '').length * (fontSz * 0.58);
        if (measureCtx) {
            measureCtx.font = buildCanvasFont({
                family: t.fontFamily,
                size: fontSz,
                bold: t.fontBold !== false,
                italic: !!t.fontItalic,
            });
            textW = measureCtx.measureText(t.text || 'Note').width;
        }
        return {
            w: Math.max(120, Math.ceil(textW + 28)),
            h: Math.max(32, Math.ceil(fontSz + 20)),
        };
    };

    const hitTestNote = (wx, wy) => {
        for (let i = state.notes.length - 1; i >= 0; i--) {
            const t = state.notes[i];
            const { w, h } = getNoteSize(t);
            if (wx >= t.x && wx <= t.x + w && wy >= t.y && wy <= t.y + h) {
                return t;
            }
        }
        return null;
    };

    const distToSegment = (px, py, x1, y1, x2, y2) => {
        const l2 = (x2 - x1) ** 2 + (y2 - y1) ** 2;
        if (l2 === 0) return Math.hypot(px - x1, py - y1);
        let t = ((px - x1) * (x2 - x1) + (py - y1) * (y2 - y1)) / l2;
        t = Math.max(0, Math.min(1, t));
        return Math.hypot(px - (x1 + t * (x2 - x1)), py - (y1 + t * (y2 - y1)));
    };

    // ---------------------------------------------------------------------
    // Free connection points: every edge may pin its start (fromPort) and/or
    // end (toPort) to any side of a node (top | right | bottom | left).
    // A null / missing port means "Auto" (nearest facing side).
    // ---------------------------------------------------------------------
    const PORT_SIDES = ['top', 'right', 'bottom', 'left'];
    const SIDE_DIR = {
        top: { x: 0, y: -1 },
        right: { x: 1, y: 0 },
        bottom: { x: 0, y: 1 },
        left: { x: -1, y: 0 },
    };

    const getPortPoint = (n, side) => {
        const { w, h } = getNodeSize(n);
        if (side === 'top') return { x: n.x, y: n.y - h / 2 };
        if (side === 'bottom') return { x: n.x, y: n.y + h / 2 };
        if (side === 'left') return { x: n.x - w / 2, y: n.y };
        return { x: n.x + w / 2, y: n.y };
    };

    const getEdgeEndpoints = (e) => {
        const n1 = state.nodes.find((n) => n.id === e.from);
        const n2 = state.nodes.find((n) => n.id === e.to);
        if (!n1 || !n2) return null;
        const s1 = getNodeSize(n1);
        const s2 = getNodeSize(n2);
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const autoSide1 = Math.abs(dx) * (s1.h / 2) > Math.abs(dy) * (s1.w / 2)
            ? (dx > 0 ? 'right' : 'left')
            : (dy > 0 ? 'bottom' : 'top');
        const autoSide2 = Math.abs(dx) * (s2.h / 2) > Math.abs(dy) * (s2.w / 2)
            ? (dx > 0 ? 'left' : 'right')
            : (dy > 0 ? 'top' : 'bottom');
        const side1 = PORT_SIDES.includes(e.fromPort) ? e.fromPort : autoSide1;
        const side2 = PORT_SIDES.includes(e.toPort) ? e.toPort : autoSide2;
        const p1 = getPortPoint(n1, side1);
        const p2 = getPortPoint(n2, side2);
        return {
            x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y, n1, n2,
            side1, side2, d1: SIDE_DIR[side1], d2: SIDE_DIR[side2],
        };
    };

    // Geometry honouring the chosen sides: { kind: 'poly'|'bezier', ... }
    const getEdgeGeometry = (e, pts, mode) => {
        const { x1, y1, x2, y2, d1, d2 } = pts;
        if (mode === 'straight') return { kind: 'poly', pts: [[x1, y1], [x2, y2]] };
        if (mode === 'step') {
            const GAP = 26;
            const P = [[x1, y1]];
            const h1 = d1.x !== 0;
            const h2 = d2.x !== 0;
            const offset = Number(e.stepOffset) || 0;
            if (h1 && h2) {
                if (d1.x === d2.x) {
                    const m = (d1.x > 0 ? Math.max(x1, x2) + GAP : Math.min(x1, x2) - GAP) + offset;
                    P.push([m, y1], [m, y2]);
                } else if (d1.x > 0 ? x2 >= x1 : x2 <= x1) {
                    const m = (x1 + x2) / 2 + offset;
                    P.push([m, y1], [m, y2]);
                } else {
                    const m1 = x1 + d1.x * GAP;
                    const m2 = x2 + d2.x * GAP;
                    const my = (y1 + y2) / 2 + offset;
                    P.push([m1, y1], [m1, my], [m2, my], [m2, y2]);
                }
            } else if (!h1 && !h2) {
                if (d1.y === d2.y) {
                    const m = (d1.y > 0 ? Math.max(y1, y2) + GAP : Math.min(y1, y2) - GAP) + offset;
                    P.push([x1, m], [x2, m]);
                } else if (d1.y > 0 ? y2 >= y1 : y2 <= y1) {
                    const m = (y1 + y2) / 2 + offset;
                    P.push([x1, m], [x2, m]);
                } else {
                    const m1 = y1 + d1.y * GAP;
                    const m2 = y2 + d2.y * GAP;
                    const mx = (x1 + x2) / 2 + offset;
                    P.push([x1, m1], [mx, m1], [mx, m2], [x2, m2]);
                }
            } else if (h1) {
                if (offset !== 0) {
                    const my = y1 + offset;
                    const mx1 = x1 + (d1.x || 1) * GAP;
                    P.push([mx1, y1], [mx1, my], [x2, my]);
                } else {
                    P.push([x2, y1]);
                }
            } else {
                if (offset !== 0) {
                    const mx = x1 + offset;
                    const my1 = y1 + (d1.y || 1) * GAP;
                    P.push([x1, my1], [mx, my1], [mx, y2]);
                } else {
                    P.push([x1, y2]);
                }
            }
            P.push([x2, y2]);
            return { kind: 'poly', pts: P };
        }
        const dist = Math.max(40, Math.hypot(x2 - x1, y2 - y1) * 0.4);
        return {
            kind: 'bezier',
            p1: [x1, y1],
            c1: [x1 + d1.x * dist, y1 + d1.y * dist],
            c2: [x2 + d2.x * dist, y2 + d2.y * dist],
            p2: [x2, y2],
        };
    };

    const geomFlatten = (g) => {
        if (g.kind === 'poly') return g.pts;
        const out = [];
        for (let i = 0; i <= 28; i++) {
            const t = i / 28;
            const u = 1 - t;
            out.push([
                u * u * u * g.p1[0] + 3 * u * u * t * g.c1[0] + 3 * u * t * t * g.c2[0] + t * t * t * g.p2[0],
                u * u * u * g.p1[1] + 3 * u * u * t * g.c1[1] + 3 * u * t * t * g.c2[1] + t * t * t * g.p2[1],
            ]);
        }
        return out;
    };

    const geomTrace = (ctx2, g) => {
        if (g.kind === 'poly') {
            ctx2.moveTo(g.pts[0][0], g.pts[0][1]);
            for (let i = 1; i < g.pts.length; i++) ctx2.lineTo(g.pts[i][0], g.pts[i][1]);
        } else {
            ctx2.moveTo(g.p1[0], g.p1[1]);
            ctx2.bezierCurveTo(g.c1[0], g.c1[1], g.c2[0], g.c2[1], g.p2[0], g.p2[1]);
        }
    };

    const geomSvgD = (g, ox, oy) => {
        if (g.kind === 'poly') {
            return g.pts.map((p, i) => `${i ? 'L' : 'M'} ${p[0] + ox} ${p[1] + oy}`).join(' ');
        }
        return `M ${g.p1[0] + ox} ${g.p1[1] + oy} C ${g.c1[0] + ox} ${g.c1[1] + oy}, ${g.c2[0] + ox} ${g.c2[1] + oy}, ${g.p2[0] + ox} ${g.p2[1] + oy}`;
    };

    const geomMid = (g) => {
        if (g.kind === 'bezier') {
            return {
                x: 0.125 * g.p1[0] + 0.375 * g.c1[0] + 0.375 * g.c2[0] + 0.125 * g.p2[0],
                y: 0.125 * g.p1[1] + 0.375 * g.c1[1] + 0.375 * g.c2[1] + 0.125 * g.p2[1],
            };
        }
        const P = g.pts;
        let total = 0;
        for (let i = 1; i < P.length; i++) total += Math.hypot(P[i][0] - P[i - 1][0], P[i][1] - P[i - 1][1]);
        let acc = total / 2;
        for (let i = 1; i < P.length; i++) {
            const seg = Math.hypot(P[i][0] - P[i - 1][0], P[i][1] - P[i - 1][1]);
            if (acc <= seg && seg > 0) {
                const t = acc / seg;
                return { x: P[i - 1][0] + (P[i][0] - P[i - 1][0]) * t, y: P[i - 1][1] + (P[i][1] - P[i - 1][1]) * t };
            }
            acc -= seg;
        }
        return { x: P[0][0], y: P[0][1] };
    };

    // Points just before the end / just after the start (for arrowhead angle)
    const geomRefs = (g) => {
        if (g.kind === 'bezier') return { endRef: g.c2, startRef: g.c1 };
        const P = g.pts;
        const last = P[P.length - 1];
        const first = P[0];
        let endRef = P[P.length - 2];
        for (let i = P.length - 2; i >= 0; i--) {
            if (Math.hypot(P[i][0] - last[0], P[i][1] - last[1]) > 0.5) { endRef = P[i]; break; }
        }
        let startRef = P[1];
        for (let i = 1; i < P.length; i++) {
            if (Math.hypot(P[i][0] - first[0], P[i][1] - first[1]) > 0.5) { startRef = P[i]; break; }
        }
        return { endRef, startRef };
    };

    const hitTestEdge = (wx, wy) => {
        for (let i = state.edges.length - 1; i >= 0; i--) {
            const e = state.edges[i];
            const pts = getEdgeEndpoints(e);
            if (!pts) continue;
            const flat = geomFlatten(getEdgeGeometry(e, pts, e.curve || 'bezier'));
            for (let k = 1; k < flat.length; k++) {
                if (distToSegment(wx, wy, flat[k - 1][0], flat[k - 1][1], flat[k][0], flat[k][1]) <= 9) return e;
            }
        }
        return null;
    };

    // Drag handles on both ends of the selected connector (re-route / re-attach)
    const hitTestEdgeEndHandle = (wx, wy) => {
        if (state.selectedType !== 'edge') return null;
        for (const id of state.selectedIds) {
            const e = state.edges.find((it) => it.id === id);
            if (!e) continue;
            const pts = getEdgeEndpoints(e);
            if (!pts) continue;
            if (Math.hypot(wx - pts.x2, wy - pts.y2) <= 10) return { edge: e, end: 'to' };
            if (Math.hypot(wx - pts.x1, wy - pts.y1) <= 10) return { edge: e, end: 'from' };
        }
        return null;
    };

    // Calculate middle segment handle position and axis for orthogonal step links
    const getEdgeStepHandle = (e, pts) => {
        if (!pts || (e.curve !== 'step')) return null;
        const { x1, y1, x2, y2, d1, d2 } = pts;
        const GAP = 26;
        const h1 = d1.x !== 0;
        const h2 = d2.x !== 0;
        const offset = Number(e.stepOffset) || 0;

        if (h1 && h2) {
            if (d1.x === d2.x) {
                const m = (d1.x > 0 ? Math.max(x1, x2) + GAP : Math.min(x1, x2) - GAP) + offset;
                return { x: m, y: (y1 + y2) / 2, isVertical: true, axis: 'x' };
            } else if (d1.x > 0 ? x2 >= x1 : x2 <= x1) {
                const m = (x1 + x2) / 2 + offset;
                return { x: m, y: (y1 + y2) / 2, isVertical: true, axis: 'x' };
            } else {
                const m1 = x1 + d1.x * GAP;
                const m2 = x2 + d2.x * GAP;
                const my = (y1 + y2) / 2 + offset;
                return { x: (m1 + m2) / 2, y: my, isVertical: false, axis: 'y' };
            }
        } else if (!h1 && !h2) {
            if (d1.y === d2.y) {
                const m = (d1.y > 0 ? Math.max(y1, y2) + GAP : Math.min(y1, y2) - GAP) + offset;
                return { x: (x1 + x2) / 2, y: m, isVertical: false, axis: 'y' };
            } else if (d1.y > 0 ? y2 >= y1 : y2 <= y1) {
                const m = (y1 + y2) / 2 + offset;
                return { x: (x1 + x2) / 2, y: m, isVertical: false, axis: 'y' };
            } else {
                const m1 = y1 + d1.y * GAP;
                const m2 = y2 + d2.y * GAP;
                const mx = (x1 + x2) / 2 + offset;
                return { x: mx, y: (m1 + m2) / 2, isVertical: true, axis: 'x' };
            }
        } else if (h1) {
            if (offset !== 0) {
                const my = y1 + offset;
                const mx1 = x1 + (d1.x || 1) * GAP;
                return { x: (mx1 + x2) / 2, y: my, isVertical: false, axis: 'y' };
            } else {
                return { x: (x1 + x2) / 2, y: y1, isVertical: false, axis: 'y' };
            }
        } else {
            if (offset !== 0) {
                const mx = x1 + offset;
                const my1 = y1 + (d1.y || 1) * GAP;
                return { x: mx, y: (my1 + y2) / 2, isVertical: true, axis: 'x' };
            } else {
                return { x: x1, y: (y1 + y2) / 2, isVertical: true, axis: 'x' };
            }
        }
    };

    // Drag handle on middle segment of selected orthogonal step connector
    const hitTestEdgeStepHandle = (wx, wy) => {
        if (state.selectedType !== 'edge') return null;
        for (const id of state.selectedIds) {
            const e = state.edges.find((it) => it.id === id);
            if (!e || e.curve !== 'step') continue;
            const pts = getEdgeEndpoints(e);
            if (!pts) continue;
            const h = getEdgeStepHandle(e, pts);
            if (!h) continue;
            if (Math.hypot(wx - h.x, wy - h.y) <= 13) {
                return { edge: e, handle: h };
            }
        }
        return null;
    };

    const portSelectOptions = (value) => ['auto', 'top', 'right', 'bottom', 'left']
        .map((s) => `<option value="${s}" ${(value || 'auto') === s ? 'selected' : ''}>${s === 'auto' ? 'Auto (nearest)' : s.charAt(0).toUpperCase() + s.slice(1)}</option>`)
        .join('');

    const hitTestZoneResize = (wx, wy) => {
        for (let i = state.zones.length - 1; i >= 0; i--) {
            const z = state.zones[i];
            const rx = z.x + z.w;
            const ry = z.y + z.h;
            if (Math.abs(wx - rx) <= 10 && Math.abs(wy - ry) <= 10) {
                return z;
            }
        }
        return null;
    };

    const hitTestZone = (wx, wy) => {
        for (let i = state.zones.length - 1; i >= 0; i--) {
            const z = state.zones[i];
            if (wx >= z.x && wx <= z.x + z.w && wy >= z.y && wy <= z.y + z.h) {
                return z;
            }
        }
        return null;
    };

    const roundRect = (ctx, x, y, w, h, r) => {
        const radius = Math.max(0, Math.min(r, w / 2, h / 2));
        ctx.beginPath();
        ctx.moveTo(x + radius, y);
        ctx.arcTo(x + w, y, x + w, y + h, radius);
        ctx.arcTo(x + w, y + h, x, y + h, radius);
        ctx.arcTo(x, y + h, x, y, radius);
        ctx.arcTo(x, y, x + w, y, radius);
        ctx.closePath();
    };

    // Geometric Flowchart Shape Path Builder (Canvas)
    const traceFlowShapePath = (ctx, shape, x, y, w, h) => {
        ctx.beginPath();
        if (shape === 'stadium') {
            roundRect(ctx, x, y, w, h, h / 2);
            return;
        }
        if (shape === 'diamond') {
            ctx.moveTo(x + w / 2, y);
            ctx.lineTo(x + w, y + h / 2);
            ctx.lineTo(x + w / 2, y + h);
            ctx.lineTo(x, y + h / 2);
            ctx.closePath();
            return;
        }
        if (shape === 'parallelogram') {
            const skew = Math.min(24, w * 0.16);
            ctx.moveTo(x + skew, y);
            ctx.lineTo(x + w, y);
            ctx.lineTo(x + w - skew, y + h);
            ctx.lineTo(x, y + h);
            ctx.closePath();
            return;
        }
        if (shape === 'document') {
            const waveH = 10;
            ctx.moveTo(x, y);
            ctx.lineTo(x + w, y);
            ctx.lineTo(x + w, y + h - waveH);
            ctx.bezierCurveTo(
                x + w * 0.72, y + h + waveH * 0.7,
                x + w * 0.28, y + h - waveH * 1.6,
                x, y + h - waveH * 0.4
            );
            ctx.closePath();
            return;
        }
        if (shape === 'hexagon') {
            const inset = Math.min(24, w * 0.16);
            ctx.moveTo(x + inset, y);
            ctx.lineTo(x + w - inset, y);
            ctx.lineTo(x + w, y + h / 2);
            ctx.lineTo(x + w - inset, y + h);
            ctx.lineTo(x + inset, y + h);
            ctx.lineTo(x, y + h / 2);
            ctx.closePath();
            return;
        }
        if (shape === 'manual_input') {
            const slant = Math.min(18, h * 0.26);
            ctx.moveTo(x, y + slant);
            ctx.lineTo(x + w, y);
            ctx.lineTo(x + w, y + h);
            ctx.lineTo(x, y + h);
            ctx.closePath();
            return;
        }
        if (shape === 'delay') {
            const r = h / 2;
            ctx.moveTo(x, y);
            ctx.lineTo(x + w - r, y);
            ctx.arc(x + w - r, y + r, r, -Math.PI / 2, Math.PI / 2);
            ctx.lineTo(x, y + h);
            ctx.closePath();
            return;
        }
        if (shape === 'connector' || shape === 'step') {
            const rad = Math.min(w, h) / 2;
            ctx.arc(x + w / 2, y + h / 2, rad, 0, Math.PI * 2);
            ctx.closePath();
            return;
        }
        // Default 'rect' or 'subprocess'
        roundRect(ctx, x, y, w, h, 8);
    };

    // SVG Icon Preview for the 2-column Process Flow Palette Grid
    const getFlowShapeSvgIcon = (shape, color) => {
        const s = esc(color || '#60a5fa');
        switch (shape) {
            case 'stadium':
                return `<svg viewBox="0 0 24 24"><rect x="3" y="7" width="18" height="10" rx="5" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
            case 'diamond':
                return `<svg viewBox="0 0 24 24"><polygon points="12,3 21,12 12,21 3,12" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'parallelogram':
                return `<svg viewBox="0 0 24 24"><polygon points="7,6 21,6 17,18 3,18" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'document':
                return `<svg viewBox="0 0 24 24"><path d="M4,5 H20 V16 Q16,20 12,17 T4,18 Z" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'subprocess':
                return `<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="1.5" fill="none" stroke="${s}" stroke-width="2"/><line x1="7" y1="6" x2="7" y2="18" stroke="${s}" stroke-width="2"/><line x1="17" y1="6" x2="17" y2="18" stroke="${s}" stroke-width="2"/></svg>`;
            case 'hexagon':
                return `<svg viewBox="0 0 24 24"><polygon points="7,6 17,6 21,12 17,18 7,18 3,12" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'manual_input':
                return `<svg viewBox="0 0 24 24"><polygon points="3,9 21,5 21,18 3,18" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'delay':
                return `<svg viewBox="0 0 24 24"><path d="M4,6 H13 A6,6 0 0 1 13,18 H4 Z" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'connector':
                return `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="6" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
            case 'step':
                return `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="${s}" stroke="#ffffff" stroke-width="1.5"/><text x="12" y="16" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="900" font-family="sans-serif">1</text></svg>`;
            default:
                return `<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="1.5" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
        }
    };

    const hexToRgba = (hex, alpha = 1) => {
        const clean = String(hex || '#38bdf8').replace('#', '');
        const num = parseInt(clean.length === 3 ? clean.split('').map((c) => c + c).join('') : clean, 16);
        const r = (num >> 16) & 255;
        const g = (num >> 8) & 255;
        const b = num & 255;
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    };

    // =========================================================================
    // Image Insertion & Clipboard Paste Helpers
    // =========================================================================
    const insertImageFromSrc = (src, label = 'Inserted Image', worldPos = null, naturalW = 240, naturalH = 160) => {
        if (!src) return;
        pushHistory();
        getOrLoadImage(src);

        const maxDim = 240;
        let w = naturalW || 200;
        let h = naturalH || 140;
        if (w > maxDim || h > maxDim) {
            const ratio = Math.min(maxDim / w, maxDim / h);
            w = Math.max(80, Math.round(w * ratio));
            h = Math.max(60, Math.round(h * ratio));
        }

        const pos = worldPos || state.lastMouseWorld || { x: 450, y: 260 };
        const newNode = {
            id: uid('img'),
            type: 'image',
            label: label || 'Image',
            sub: '',
            imageSrc: src,
            showFrame: true,
            showCaption: true,
            x: snap(pos.x),
            y: snap(pos.y),
            w: snap(w),
            h: snap(h),
            color: '#38bdf8',
            status: 'none',
            step: '',
            fontFamily: 'default',
            fontSize: 12,
            fontBold: true,
            fontItalic: false,
        };
        state.nodes.push(newNode);
        state.selectedType = 'node';
        state.selectedIds = new Set([newNode.id]);
        saveToLocalStorage();
        renderInspector();
        requestRender();
        showToast(`Inserted image: ${newNode.label}`);
    };

    const readImageFileAndInsert = (file, worldPos = null, asCustomIconForNode = null) => {
        if (!file || !file.type.startsWith('image/')) {
            showToast('Unsupported file — please choose an image (.png, .jpg, .svg, .webp, .gif)', true);
            return;
        }
        const reader = new FileReader();
        reader.onload = () => {
            const dataUrl = String(reader.result || '');
            if (!dataUrl) return;
            const probe = new Image();
            probe.onload = () => {
                if (asCustomIconForNode) {
                    pushHistory();
                    asCustomIconForNode.imageSrc = dataUrl;
                    getOrLoadImage(dataUrl);
                    saveToLocalStorage();
                    renderInspector();
                    requestRender();
                    showToast('Updated node custom icon');
                } else {
                    const cleanName = (file.name || 'Pasted Image').replace(/\.[^.]+$/, '');
                    insertImageFromSrc(dataUrl, cleanName, worldPos, probe.naturalWidth || 220, probe.naturalHeight || 150);
                }
            };
            probe.onerror = () => {
                insertImageFromSrc(dataUrl, file.name || 'Image', worldPos, 200, 140);
            };
            probe.src = dataUrl;
        };
        reader.readAsDataURL(file);
    };

    const importProjectFile = (file) => {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            try {
                const parsed = JSON.parse(String(reader.result || '{}'));
                const diag = parseImportedProjectPayload(parsed);
                pushHistory();
                applySnapshot(diag);
                setTimeout(fitToScreen, 30);
                showToast(`Imported diagram file: ${file.name}`);
            } catch (err) {
                showToast(`Failed to import file: ${err.message}`, true);
            }
        };
        reader.readAsText(file);
    };

    const handlePasteFromClipboardButton = async () => {
        try {
            if (navigator.clipboard && navigator.clipboard.read) {
                const items = await navigator.clipboard.read();
                for (const item of items) {
                    const imgType = item.types.find((t) => t.startsWith('image/'));
                    if (imgType) {
                        const blob = await item.getType(imgType);
                        const file = new File([blob], 'Clipboard Image.png', { type: imgType });
                        readImageFileAndInsert(file, state.lastMouseWorld);
                        return;
                    }
                }
            }
        } catch (_) {}
        if (state.clipboard && state.clipboard.items?.length) {
            pasteInternalClipboard();
        } else {
            showToast('Press Ctrl+V to paste an image or copied element from your clipboard.');
        }
    };

    const copySelectedToClipboard = async () => {
        if (!state.selectedIds.size) {
            showToast('Select a node, image, zone, or note first to copy', true);
            return;
        }
        if (state.selectedType === 'node') {
            const items = state.nodes.filter((n) => state.selectedIds.has(n.id));
            state.clipboard = { type: 'node', items: JSON.parse(JSON.stringify(items)) };
            if (items.length === 1 && items[0].imageSrc && items[0].imageSrc.startsWith('data:image/png')) {
                try {
                    const res = await fetch(items[0].imageSrc);
                    const blob = await res.blob();
                    if (navigator.clipboard?.write && typeof ClipboardItem !== 'undefined') {
                        await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
                    }
                } catch (_) {}
            }
            showToast(`Copied ${items.length} node(s) (Ctrl+V to paste)`);
        } else if (state.selectedType === 'zone') {
            const items = state.zones.filter((z) => state.selectedIds.has(z.id));
            state.clipboard = { type: 'zone', items: JSON.parse(JSON.stringify(items)) };
            showToast(`Copied ${items.length} zone(s) (Ctrl+V to paste)`);
        } else if (state.selectedType === 'note') {
            const items = state.notes.filter((t) => state.selectedIds.has(t.id));
            state.clipboard = { type: 'note', items: JSON.parse(JSON.stringify(items)) };
            showToast(`Copied ${items.length} note(s) (Ctrl+V to paste)`);
        }
    };

    const pasteInternalClipboard = () => {
        if (!state.clipboard || !state.clipboard.items?.length) return false;
        pushHistory();
        const newIds = new Set();
        const { type, items } = state.clipboard;
        if (type === 'node') {
            items.forEach((n) => {
                const copy = { ...JSON.parse(JSON.stringify(n)), id: uid('n'), x: n.x + 30, y: n.y + 30 };
                if (copy.imageSrc) getOrLoadImage(copy.imageSrc);
                state.nodes.push(copy);
                newIds.add(copy.id);
            });
            state.selectedType = 'node';
        } else if (type === 'zone') {
            items.forEach((z) => {
                const copy = { ...JSON.parse(JSON.stringify(z)), id: uid('z'), x: z.x + 30, y: z.y + 30 };
                state.zones.push(copy);
                newIds.add(copy.id);
            });
            state.selectedType = 'zone';
        } else if (type === 'note') {
            items.forEach((t) => {
                const copy = { ...JSON.parse(JSON.stringify(t)), id: uid('t'), x: t.x + 25, y: t.y + 25 };
                state.notes.push(copy);
                newIds.add(copy.id);
            });
            state.selectedType = 'note';
        }
        state.selectedIds = newIds;
        saveToLocalStorage();
        renderInspector();
        requestRender();
        showToast('Pasted from clipboard');
        return true;
    };

    function resolveDiagramEdgeColor(eColor, isWhite) {
        if (isWhite) {
            if (!eColor || eColor === '#ffffff' || eColor === '#f8fafc' || eColor === '#f1f5f9' || eColor === '#fff' || eColor === '#e2e8f0' || eColor === '#38bdf8') {
                return '#0f172a';
            }
            return eColor;
        } else {
            if (!eColor || eColor === '#000000' || eColor === '#080c14' || eColor === '#0f172a' || eColor === '#111827' || eColor === '#000') {
                return '#ffffff';
            }
            return eColor;
        }
    }

    // =========================================================================
    // Core Scene Renderer (Zero Truncation on Titles & Subtitles)
    // =========================================================================
    const renderSceneToContext = (ctx, opts = {}) => {
        const {
            width,
            height,
            panX = state.panX,
            panY = state.panY,
            zoom = state.zoom,
            themeMode = state.canvasTheme,
            isExport = false,
            showGrid = state.showGrid,
        } = opts;

        const isWhite = themeMode === 'white';
        const isTransparent = themeMode === 'transparent';

        ctx.save();

        // 1. Background Fill
        if (isTransparent) {
            ctx.clearRect(0, 0, width, height);
        } else if (isWhite) {
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, width, height);
        } else {
            ctx.fillStyle = '#080c14';
            ctx.fillRect(0, 0, width, height);
        }

        if (showGrid && !isTransparent && isExport) {
            ctx.fillStyle = isWhite ? 'rgba(15, 23, 42, 0.10)' : 'rgba(148, 163, 184, 0.12)';
            const step = 24;
            for (let gx = step / 2; gx < width; gx += step) {
                for (let gy = step / 2; gy < height; gy += step) {
                    ctx.fillRect(gx, gy, 1.5, 1.5);
                }
            }
        }

        ctx.translate(panX, panY);
        ctx.scale(zoom, zoom);

        // 2. Render Zones (Security Boundaries / Subnets)
        state.zones.forEach((z) => {
            const isSelected = !isExport && state.selectedType === 'zone' && state.selectedIds.has(z.id);
            const zColor = z.color || '#38bdf8';
            const fillAlpha = isWhite ? Math.max(0.05, (z.opacity ?? 0.06) * 0.9) : (z.opacity ?? 0.06);

            roundRect(ctx, z.x, z.y, z.w, z.h, 12);
            ctx.fillStyle = hexToRgba(zColor, fillAlpha);
            ctx.fill();

            ctx.lineWidth = isSelected ? 2.2 : 1.4;
            ctx.strokeStyle = isSelected ? '#ffcc00' : hexToRgba(zColor, isWhite ? 0.65 : 0.48);
            if (z.style === 'dashed') {
                ctx.setLineDash([7, 5]);
            } else {
                ctx.setLineDash([]);
            }
            ctx.stroke();
            ctx.setLineDash([]);

            // Zone Header Pill
            const titleText = (z.label || 'ZONE').toUpperCase();
            const zFontSize = Number(z.fontSize) || 11;
            ctx.font = buildCanvasFont({
                family: z.fontFamily,
                size: zFontSize,
                bold: z.fontBold !== false,
                italic: !!z.fontItalic,
            });
            const titleW = ctx.measureText(titleText).width;
            const pillH = Math.max(22, zFontSize + 10);
            const pillW = titleW + 20;
            roundRect(ctx, z.x + 14, z.y + 12, pillW, pillH, 6);
            ctx.fillStyle = isWhite ? hexToRgba(zColor, 0.14) : 'rgba(8, 12, 20, 0.88)';
            ctx.fill();
            ctx.lineWidth = 1;
            ctx.strokeStyle = hexToRgba(zColor, 0.45);
            ctx.stroke();

            ctx.fillStyle = isWhite ? '#0f172a' : zColor;
            ctx.textBaseline = 'middle';
            ctx.textAlign = 'left';
            ctx.fillText(titleText, z.x + 24, z.y + 12 + pillH / 2);

            if (z.sub) {
                ctx.font = buildCanvasFont({
                    family: z.fontFamily,
                    size: Math.max(10, zFontSize - 0.5),
                    bold: false,
                    italic: !!z.fontItalic,
                });
                ctx.fillStyle = isWhite ? '#475569' : '#8b9bb4';
                ctx.fillText(z.sub, z.x + 16, z.y + 22 + pillH);
            }

            if (isSelected) {
                ctx.fillStyle = '#ffcc00';
                ctx.fillRect(z.x + z.w - 6, z.y + z.h - 6, 12, 12);
            }
        });

        // Preview Zone being drawn
        if (!isExport && state.drawingZone) {
            const dz = state.drawingZone;
            const x = Math.min(dz.x1, dz.x2);
            const y = Math.min(dz.y1, dz.y2);
            const w = Math.abs(dz.x2 - dz.x1);
            const h = Math.abs(dz.y2 - dz.y1);
            roundRect(ctx, x, y, w, h, 10);
            ctx.fillStyle = 'rgba(56, 189, 248, 0.08)';
            ctx.fill();
            ctx.setLineDash([6, 5]);
            ctx.strokeStyle = '#38bdf8';
            ctx.lineWidth = 1.8;
            ctx.stroke();
            ctx.setLineDash([]);
        }

        // 3. Render Edges (Connections & Attack Paths)
        state.edges.forEach((e) => {
            const pts = getEdgeEndpoints(e);
            if (!pts) return;
            const isSelected = !isExport && state.selectedType === 'edge' && state.selectedIds.has(e.id);
            const color = isSelected ? '#ffcc00' : resolveDiagramEdgeColor(e.color, isWhite);
            const widthVal = Number(e.width) || 2;

            const curveMode = e.curve || 'bezier';
            const geo = getEdgeGeometry(e, pts, curveMode);

            ctx.beginPath();
            geomTrace(ctx, geo);

            ctx.strokeStyle = color;
            ctx.lineWidth = isSelected ? widthVal + 1 : widthVal;
            if (e.style === 'dashed') {
                ctx.setLineDash([7, 5]);
            } else if (e.style === 'dotted') {
                ctx.setLineDash([3, 5]);
            } else if (e.style === 'animated') {
                ctx.setLineDash([8, 6]);
                ctx.lineDashOffset = -state.animTick * 0.7;
            } else {
                ctx.setLineDash([]);
            }
            ctx.stroke();
            ctx.setLineDash([]);
            ctx.lineDashOffset = 0;

            const drawArrow = (tx, ty, fx, fy) => {
                const angle = Math.atan2(ty - fy, tx - fx);
                const headLen = 9.5;
                ctx.beginPath();
                ctx.moveTo(tx, ty);
                ctx.lineTo(tx - headLen * Math.cos(angle - Math.PI / 6), ty - headLen * Math.sin(angle - Math.PI / 6));
                ctx.lineTo(tx - headLen * Math.cos(angle + Math.PI / 6), ty - headLen * Math.sin(angle + Math.PI / 6));
                ctx.closePath();
                ctx.fillStyle = color;
                ctx.fill();
            };

            const refs = geomRefs(geo);
            if (e.dir !== 'none') {
                drawArrow(pts.x2, pts.y2, refs.endRef[0], refs.endRef[1]);
            }
            if (e.dir === 'both') {
                drawArrow(pts.x1, pts.y1, refs.startRef[0], refs.startRef[1]);
            }

            // Drag handles on both ends of the selected connector
            if (isSelected) {
                [[pts.x1, pts.y1], [pts.x2, pts.y2]].forEach(([hx, hy]) => {
                    ctx.beginPath();
                    ctx.arc(hx, hy, 6, 0, Math.PI * 2);
                    ctx.fillStyle = '#ffffff';
                    ctx.fill();
                    ctx.lineWidth = 2;
                    ctx.strokeStyle = '#ffcc00';
                    ctx.stroke();
                });

                // Step routing middle segment customizer handle
                if (curveMode === 'step') {
                    const sh = getEdgeStepHandle(e, pts);
                    if (sh) {
                        ctx.save();
                        // Glow ring
                        ctx.beginPath();
                        ctx.arc(sh.x, sh.y, 11, 0, Math.PI * 2);
                        ctx.fillStyle = isWhite ? 'rgba(14, 165, 233, 0.22)' : 'rgba(14, 165, 233, 0.38)';
                        ctx.fill();

                        // Central pill / handle
                        ctx.beginPath();
                        ctx.arc(sh.x, sh.y, 6.5, 0, Math.PI * 2);
                        ctx.fillStyle = '#0ea5e9';
                        ctx.fill();
                        ctx.lineWidth = 2;
                        ctx.strokeStyle = '#ffffff';
                        ctx.stroke();

                        // Direction icon line inside handle
                        ctx.beginPath();
                        if (sh.axis === 'x') {
                            ctx.moveTo(sh.x - 3.5, sh.y);
                            ctx.lineTo(sh.x + 3.5, sh.y);
                        } else {
                            ctx.moveTo(sh.x, sh.y - 3.5);
                            ctx.lineTo(sh.x, sh.y + 3.5);
                        }
                        ctx.strokeStyle = '#ffffff';
                        ctx.lineWidth = 1.5;
                        ctx.stroke();
                        ctx.restore();
                    }
                }
            }

            // Edge Label Pill
            if (e.label) {
                const midPt = geomMid(geo);
                const mx = midPt.x;
                const my = midPt.y - 2;
                const eFontSize = Number(e.fontSize) || 10.5;
                ctx.font = buildCanvasFont({
                    family: e.fontFamily,
                    size: eFontSize,
                    bold: e.fontBold !== false,
                    italic: !!e.fontItalic,
                });
                const tw = ctx.measureText(e.label).width;
                const pw = tw + 16;
                const ph = Math.max(20, eFontSize + 9);
                roundRect(ctx, mx - pw / 2, my - ph / 2, pw, ph, 6);
                ctx.fillStyle = isWhite ? 'rgba(255, 255, 255, 0.96)' : 'rgba(10, 15, 25, 0.94)';
                ctx.fill();
                ctx.lineWidth = 1;
                ctx.strokeStyle = hexToRgba(color, 0.55);
                ctx.stroke();

                ctx.fillStyle = isWhite ? '#0f172a' : '#e2e8f0';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(e.label, mx, my);
            }
        });

        // Preview Connection line while dragging
        if (!isExport && state.connectingFrom) {
            const cf = state.connectingFrom;
            ctx.beginPath();
            ctx.moveTo(cf.x1, cf.y1);
            ctx.lineTo(cf.x2, cf.y2);
            ctx.strokeStyle = '#ffcc00';
            ctx.lineWidth = 2;
            ctx.setLineDash([6, 4]);
            ctx.stroke();
            ctx.setLineDash([]);
        }

        // Preview while re-attaching an existing connector end
        if (!isExport && state.draggingEdgeEnd) {
            const de = state.draggingEdgeEnd;
            const dpts = getEdgeEndpoints(de.edge);
            if (dpts) {
                const fx = de.end === 'to' ? dpts.x1 : dpts.x2;
                const fy = de.end === 'to' ? dpts.y1 : dpts.y2;
                ctx.beginPath();
                ctx.moveTo(fx, fy);
                ctx.lineTo(de.x, de.y);
                ctx.strokeStyle = '#ffcc00';
                ctx.lineWidth = 2;
                ctx.setLineDash([6, 4]);
                ctx.stroke();
                ctx.setLineDash([]);
            }
        }

        // 4. Render Nodes (Full Un-Truncated Titles & Subtitles)
        state.nodes.forEach((n) => {
            const asset = ALL_ASSETS_MAP.get(n.type) || { icon: '\uf233', color: '#38bdf8', name: 'Node' };
            const isSelected = !isExport && state.selectedType === 'node' && state.selectedIds.has(n.id);
            const isHovered = !isExport && state.hoveredNodeId === n.id;
            const nColor = n.color || asset.color || '#38bdf8';
            const { w, h } = getNodeSize(n);
            const x = n.x - w / 2;
            const y = n.y - h / 2;
            const labelFontSize = Number(n.fontSize) || 12.5;
            const subFontSize = Math.max(9.5, labelFontSize - 1.5);

            const isStep = n.isStep || n.type === 'flow_step' || n.type === 'step_marker' || n.shape === 'step';
            if (isStep) {
                const r = w / 2;
                const cx = n.x;
                const cy = n.y;
                const stepColor = n.color || '#ef4444';

                // Drop shadow
                ctx.save();
                ctx.shadowColor = isSelected
                    ? 'rgba(255, 204, 0, 0.55)'
                    : (isWhite ? 'rgba(15, 23, 42, 0.22)' : 'rgba(0, 0, 0, 0.55)');
                ctx.shadowBlur = isSelected ? 18 : 10;
                ctx.shadowOffsetY = 2;

                // Filled Circular Badge
                ctx.beginPath();
                ctx.arc(cx, cy, r, 0, Math.PI * 2);
                ctx.fillStyle = stepColor;
                ctx.fill();
                ctx.restore();

                // Outer border / highlight
                ctx.beginPath();
                ctx.arc(cx, cy, r, 0, Math.PI * 2);
                ctx.lineWidth = isSelected ? 2.5 : 1.5;
                ctx.strokeStyle = isSelected ? '#ffcc00' : 'rgba(255, 255, 255, 0.4)';
                ctx.stroke();

                // Dashed selection ring if selected
                if (isSelected) {
                    ctx.beginPath();
                    ctx.arc(cx, cy, r + 4, 0, Math.PI * 2);
                    ctx.lineWidth = 1.6;
                    ctx.setLineDash([3, 3]);
                    ctx.strokeStyle = '#ffcc00';
                    ctx.stroke();
                    ctx.setLineDash([]);
                }

                // Step Number / Text Centered
                const labelStr = String(n.label ?? '1');
                let fs = Number(n.fontSize) || Math.max(12, Math.round(r * 0.92));
                if (labelStr.length > 2) {
                    fs = Math.max(9, Math.round(fs * (2.2 / labelStr.length)));
                }
                ctx.font = buildCanvasFont({
                    family: n.fontFamily && n.fontFamily !== 'default' ? n.fontFamily : 'Plus Jakarta Sans',
                    size: fs,
                    bold: n.fontBold !== false,
                    italic: !!n.fontItalic,
                });
                ctx.fillStyle = '#ffffff';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(labelStr, cx, cy);

                // Connection Ports on Hover, Selected, or Connect mode
                if (!isExport && (isHovered || isSelected || state.mode === 'connect' || state.connectingFrom || state.draggingEdgeEnd)) {
                    const ports = getNodePorts(n);
                    const portR = (state.connectingFrom || state.draggingEdgeEnd) ? 6 : 4.5;
                    ports.forEach((p) => {
                        ctx.beginPath();
                        ctx.arc(p.x, p.y, portR, 0, Math.PI * 2);
                        ctx.fillStyle = '#ffffff';
                        ctx.fill();
                        ctx.lineWidth = 1.5;
                        ctx.strokeStyle = '#080c14';
                        ctx.stroke();
                    });
                }
                return;
            }

            if (n.type === 'image') {
                const showFrame = n.showFrame !== false;
                if (showFrame) {
                    ctx.save();
                    ctx.shadowColor = isSelected
                        ? 'rgba(255, 204, 0, 0.35)'
                        : (isWhite ? 'rgba(15, 23, 42, 0.10)' : 'rgba(0, 0, 0, 0.45)');
                    ctx.shadowBlur = isSelected ? 16 : 12;
                    ctx.shadowOffsetY = 4;
                    roundRect(ctx, x, y, w, h, 10);
                    ctx.fillStyle = isWhite ? '#ffffff' : '#111827';
                    ctx.fill();
                    ctx.restore();
                }

                const captionHeight = (n.showCaption !== false && n.label) ? (labelFontSize + 14) : 0;
                const pad = showFrame ? 6 : 0;
                const imgX = x + pad;
                const imgY = y + pad;
                const imgW = Math.max(20, w - pad * 2);
                const imgH = Math.max(20, h - pad * 2 - captionHeight);

                const imgEntry = getOrLoadImage(n.imageSrc);
                ctx.save();
                roundRect(ctx, imgX, imgY, imgW, imgH, showFrame ? 7 : 6);
                ctx.clip();
                if (imgEntry && imgEntry.loaded) {
                    ctx.drawImage(imgEntry.img, imgX, imgY, imgW, imgH);
                } else {
                    ctx.fillStyle = hexToRgba(nColor, 0.14);
                    ctx.fillRect(imgX, imgY, imgW, imgH);
                    ctx.font = '900 24px "Font Awesome 6 Free"';
                    ctx.fillStyle = nColor;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('\uf03e', imgX + imgW / 2, imgY + imgH / 2);
                }
                ctx.restore();

                if (showFrame || isSelected) {
                    roundRect(ctx, x, y, w, h, 10);
                    ctx.lineWidth = isSelected ? 2 : 1.2;
                    ctx.strokeStyle = isSelected ? '#ffcc00' : hexToRgba(nColor, 0.5);
                    ctx.stroke();
                }

                if (n.showCaption !== false && n.label) {
                    ctx.font = buildCanvasFont({
                        family: n.fontFamily,
                        size: labelFontSize,
                        bold: n.fontBold !== false,
                        italic: !!n.fontItalic,
                    });
                    ctx.fillStyle = isWhite ? '#0f172a' : '#f8fafc';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(n.label, n.x, y + h - captionHeight / 2 - 2);
                }

                if (isSelected) {
                    ctx.fillStyle = '#ffcc00';
                    ctx.fillRect(x + w - 6, y + h - 6, 12, 12);
                }
            } else if (asset.flowShape) {
                // Geometric Process Flow Shape Node (Start/End, Process, Decision, Data I/O, Document, Subprocess, Preparation, Manual Input, Delay, Connector)
                ctx.save();
                ctx.shadowColor = isSelected
                    ? 'rgba(255, 204, 0, 0.32)'
                    : (isWhite ? 'rgba(15, 23, 42, 0.09)' : 'rgba(0, 0, 0, 0.5)');
                ctx.shadowBlur = isSelected ? 18 : 14;
                ctx.shadowOffsetY = 4;

                traceFlowShapePath(ctx, asset.flowShape, x, y, w, h);
                ctx.fillStyle = isWhite ? '#ffffff' : '#111827';
                ctx.fill();
                ctx.restore();

                // Tinted Inner Overlay + Crisp Geometric Stroke
                traceFlowShapePath(ctx, asset.flowShape, x, y, w, h);
                ctx.fillStyle = hexToRgba(nColor, isWhite ? 0.08 : 0.12);
                ctx.fill();
                ctx.lineWidth = isSelected ? 2.2 : 1.8;
                ctx.strokeStyle = isSelected ? '#ffcc00' : nColor;
                ctx.stroke();

                // Subprocess double vertical inner bars
                if (asset.flowShape === 'subprocess') {
                    ctx.beginPath();
                    ctx.moveTo(x + 14, y);
                    ctx.lineTo(x + 14, y + h);
                    ctx.moveTo(x + w - 14, y);
                    ctx.lineTo(x + w - 14, y + h);
                    ctx.lineWidth = 1.5;
                    ctx.strokeStyle = isSelected ? '#ffcc00' : hexToRgba(nColor, 0.75);
                    ctx.stroke();
                }

                // Centered Title & Subtitle inside Geometric Shape
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.font = buildCanvasFont({
                    family: n.fontFamily,
                    size: labelFontSize,
                    bold: n.fontBold !== false,
                    italic: !!n.fontItalic,
                });
                ctx.fillStyle = isWhite ? '#0f172a' : '#f8fafc';
                const labelStr = String(n.label || asset.name || '');
                const subStr = String(n.sub ?? '');

                if (subStr && asset.flowShape !== 'connector') {
                    ctx.fillText(labelStr, n.x, y + h * 0.4);
                    ctx.font = buildCanvasFont({
                        family: n.fontFamily && n.fontFamily !== 'default' ? n.fontFamily : 'IBM Plex Mono',
                        size: subFontSize,
                        bold: false,
                        italic: !!n.fontItalic,
                    });
                    ctx.fillStyle = isWhite ? '#475569' : '#94a3b8';
                    ctx.fillText(subStr, n.x, y + h * 0.68);
                } else {
                    ctx.fillText(labelStr, n.x, y + h * 0.5);
                }

                if (isSelected) {
                    ctx.fillStyle = '#ffcc00';
                    ctx.fillRect(x + w - 5, y + h - 5, 10, 10);
                }
            } else {
                // Standard Asset Card Node — Sleek Elevated Surface
                ctx.save();
                ctx.shadowColor = isSelected
                    ? 'rgba(255, 204, 0, 0.3)'
                    : (isWhite ? 'rgba(15, 23, 42, 0.09)' : 'rgba(0, 0, 0, 0.5)');
                ctx.shadowBlur = isSelected ? 18 : 14;
                ctx.shadowOffsetY = 4;

                roundRect(ctx, x, y, w, h, 10);
                ctx.fillStyle = isWhite ? '#ffffff' : '#111827';
                ctx.fill();
                ctx.restore();

                // Left Accent Bar
                ctx.save();
                roundRect(ctx, x, y, w, h, 10);
                ctx.clip();
                ctx.fillStyle = nColor;
                ctx.fillRect(x, y, 4.5, h);
                ctx.restore();

                // Card Border
                roundRect(ctx, x, y, w, h, 10);
                ctx.lineWidth = isSelected ? 2 : 1.15;
                ctx.strokeStyle = isSelected
                    ? '#ffcc00'
                    : (isWhite ? hexToRgba(nColor, 0.45) : hexToRgba(nColor, 0.34));
                ctx.stroke();

                // Icon Box
                const ix = x + 14;
                const iy = y + (h - 38) / 2;
                roundRect(ctx, ix, iy, 38, 38, 8);
                ctx.fillStyle = hexToRgba(nColor, isWhite ? 0.12 : 0.15);
                ctx.fill();
                ctx.lineWidth = 1;
                ctx.strokeStyle = hexToRgba(nColor, 0.32);
                ctx.stroke();

                if (n.imageSrc) {
                    const customEntry = getOrLoadImage(n.imageSrc);
                    if (customEntry && customEntry.loaded) {
                        ctx.save();
                        roundRect(ctx, ix + 2, iy + 2, 34, 34, 6);
                        ctx.clip();
                        ctx.drawImage(customEntry.img, ix + 2, iy + 2, 34, 34);
                        ctx.restore();
                    }
                } else {
                    ctx.font = '900 15px "Font Awesome 6 Free"';
                    ctx.fillStyle = nColor;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(asset.icon || '\uf233', ix + 19, iy + 19);
                }

                // Full Un-Truncated Node Label & Subtitle
                const textX = ix + 48;
                ctx.textAlign = 'left';
                ctx.textBaseline = 'middle';
                ctx.font = buildCanvasFont({
                    family: n.fontFamily,
                    size: labelFontSize,
                    bold: n.fontBold !== false,
                    italic: !!n.fontItalic,
                });
                ctx.fillStyle = isWhite ? '#0f172a' : '#f8fafc';
                const labelStr = String(n.label || asset.name || '');
                const subStr = String(n.sub ?? asset.sub ?? '');

                if (subStr) {
                    ctx.fillText(labelStr, textX, y + h * 0.37);
                    ctx.font = buildCanvasFont({
                        family: n.fontFamily && n.fontFamily !== 'default' ? n.fontFamily : 'IBM Plex Mono',
                        size: subFontSize,
                        bold: false,
                        italic: !!n.fontItalic,
                    });
                    ctx.fillStyle = isWhite ? '#475569' : '#94a3b8';
                    ctx.fillText(subStr, textX, y + h * 0.67);
                } else {
                    ctx.fillText(labelStr, textX, y + h * 0.5);
                }

                if (isSelected) {
                    ctx.fillStyle = '#ffcc00';
                    ctx.fillRect(x + w - 5, y + h - 5, 10, 10);
                }
            }

            // Step / MITRE Tag Pill (Top-Left above node)
            if (n.step) {
                ctx.font = buildCanvasFont({ family: 'IBM Plex Mono', size: 9.5, bold: true });
                const sw = ctx.measureText(n.step).width + 12;
                roundRect(ctx, x + 8, y - 10, sw, 18, 4);
                ctx.fillStyle = isWhite ? '#0f172a' : '#161f33';
                ctx.fill();
                ctx.lineWidth = 1;
                ctx.strokeStyle = hexToRgba(nColor, 0.7);
                ctx.stroke();
                ctx.fillStyle = isWhite ? '#ffffff' : '#fde047';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(n.step, x + 8 + sw / 2, y - 1);
            }

            // Status Badge (Top-Right of node)
            if (n.status && n.status !== 'none' && STATUS_BADGES[n.status]) {
                const badge = STATUS_BADGES[n.status];
                ctx.font = buildCanvasFont({ family: 'IBM Plex Mono', size: 8.5, bold: true });
                const bw = ctx.measureText(badge.label).width + 10;
                roundRect(ctx, x + w - bw - 8, y - 10, bw, 17, 4);
                ctx.fillStyle = badge.color;
                ctx.fill();
                ctx.fillStyle = '#ffffff';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(badge.label, x + w - bw / 2 - 8, y - 1.5);
            }

            // Connection Ports on Hover or Connect mode
            if (!isExport && (isHovered || isSelected || state.mode === 'connect' || state.connectingFrom || state.draggingEdgeEnd)) {
                const ports = getNodePorts(n);
                const portR = (state.connectingFrom || state.draggingEdgeEnd) ? 6 : 4.5;
                ports.forEach((p) => {
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, portR, 0, Math.PI * 2);
                    ctx.fillStyle = '#ffcc00';
                    ctx.fill();
                    ctx.lineWidth = 1.5;
                    ctx.strokeStyle = '#080c14';
                    ctx.stroke();
                });
            }
        });

        // 5. Render Callout Notes / Annotations
        state.notes.forEach((t) => {
            const isSelected = !isExport && state.selectedType === 'note' && state.selectedIds.has(t.id);
            const tColor = t.color || '#ffcc00';
            const nFontSize = Number(t.fontSize) || 11.5;
            ctx.font = buildCanvasFont({
                family: t.fontFamily,
                size: nFontSize,
                bold: t.fontBold !== false,
                italic: !!t.fontItalic,
            });
            const tw = Math.max(120, ctx.measureText(t.text || 'Note').width + 28);
            const th = Math.max(32, nFontSize + 20);

            roundRect(ctx, t.x, t.y, tw, th, 7);
            ctx.fillStyle = isWhite ? 'rgba(254, 249, 195, 0.96)' : 'rgba(13, 19, 31, 0.94)';
            ctx.fill();
            ctx.lineWidth = isSelected ? 2 : 1.1;
            ctx.strokeStyle = isSelected ? '#ffcc00' : hexToRgba(tColor, 0.55);
            ctx.stroke();

            ctx.fillStyle = isWhite ? '#0f172a' : tColor;
            ctx.textAlign = 'left';
            ctx.textBaseline = 'middle';
            ctx.fillText(t.text || 'Note', t.x + 14, t.y + th / 2);
        });

        // 6. Marquee Selection Box
        if (!isExport && state.marquee) {
            const m = state.marquee;
            const mx = Math.min(m.x1, m.x2);
            const my = Math.min(m.y1, m.y2);
            const mw = Math.abs(m.x2 - m.x1);
            const mh = Math.abs(m.y2 - m.y1);
            ctx.fillStyle = 'rgba(255, 204, 0, 0.07)';
            ctx.fillRect(mx, my, mw, mh);
            ctx.strokeStyle = 'rgba(255, 204, 0, 0.7)';
            ctx.lineWidth = 1.2;
            ctx.setLineDash([4, 4]);
            ctx.strokeRect(mx, my, mw, mh);
            ctx.setLineDash([]);
        }

        ctx.restore();
    };

    // =========================================================================
    // Export Engine: .mantis-draw, .json, PNG & SVG (Transparent, Dark, White)
    // =========================================================================
    const computeDiagramBounds = () => {
        let minX = Infinity;
        let minY = Infinity;
        let maxX = -Infinity;
        let maxY = -Infinity;

        state.zones.forEach((z) => {
            minX = Math.min(minX, z.x);
            minY = Math.min(minY, z.y);
            maxX = Math.max(maxX, z.x + z.w);
            maxY = Math.max(maxY, z.y + z.h);
        });

        state.nodes.forEach((n) => {
            const { w, h } = getNodeSize(n);
            minX = Math.min(minX, n.x - w / 2 - 14);
            minY = Math.min(minY, n.y - h / 2 - 20);
            maxX = Math.max(maxX, n.x + w / 2 + 14);
            maxY = Math.max(maxY, n.y + h / 2 + 14);
        });

        state.notes.forEach((t) => {
            const { w, h } = getNoteSize(t);
            minX = Math.min(minX, t.x);
            minY = Math.min(minY, t.y);
            maxX = Math.max(maxX, t.x + w);
            maxY = Math.max(maxY, t.y + h);
        });

        if (!Number.isFinite(minX)) {
            return { x: 0, y: 0, w: 960, h: 540 };
        }
        const pad = 48;
        return {
            x: minX - pad,
            y: minY - pad,
            w: Math.max(400, maxX - minX + pad * 2),
            h: Math.max(260, maxY - minY + pad * 2),
        };
    };

    const renderOffscreenCanvas = (bgTheme = 'transparent') => {
        const bounds = computeDiagramBounds();
        const scale = 2;
        const offCanvas = document.createElement('canvas');
        offCanvas.width = Math.round(bounds.w * scale);
        offCanvas.height = Math.round(bounds.h * scale);
        const ctx = offCanvas.getContext('2d');

        ctx.save();
        ctx.scale(scale, scale);
        renderSceneToContext(ctx, {
            width: bounds.w,
            height: bounds.h,
            panX: -bounds.x,
            panY: -bounds.y,
            zoom: 1,
            themeMode: bgTheme,
            isExport: true,
            showGrid: bgTheme !== 'transparent' && state.showGrid,
        });
        ctx.restore();
        return offCanvas;
    };

    const exportPNG = (bgTheme = 'transparent') => {
        if (!state.nodes.length && !state.zones.length && !state.notes.length) {
            showToast('Canvas is empty — add nodes or load a template first.', true);
            return;
        }
        const offCanvas = renderOffscreenCanvas(bgTheme);
        const slug = (state.title || 'mantis-diagram')
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-|-$/g, '') || 'mantis-diagram';

        const link = document.createElement('a');
        link.download = `${slug}-${bgTheme}-bg.png`;
        link.href = offCanvas.toDataURL('image/png');
        document.body.appendChild(link);
        link.click();
        link.remove();

        const labelMap = {
            transparent: 'Transparent Background PNG',
            dark: 'Dark Background PNG',
            white: 'White Background PNG',
        };
        showToast(`Downloaded ${labelMap[bgTheme] || 'PNG'}`);
    };

    const copyDiagramPNGToClipboard = (bgTheme = state.canvasTheme) => {
        const offCanvas = renderOffscreenCanvas(bgTheme);
        offCanvas.toBlob(async (blob) => {
            if (!blob) return;
            try {
                if (navigator.clipboard?.write && typeof ClipboardItem !== 'undefined') {
                    await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
                    showToast(`Copied diagram PNG (${bgTheme} background) to clipboard!`);
                } else {
                    showToast('Clipboard image API not supported in this browser context', true);
                }
            } catch (err) {
                showToast(`Copy failed: ${err.message}`, true);
            }
        }, 'image/png');
    };

    const exportSVG = (bgTheme = 'transparent') => {
        const bounds = computeDiagramBounds();
        const isWhite = bgTheme === 'white';
        const isTransparent = bgTheme === 'transparent';
        const ox = -bounds.x;
        const oy = -bounds.y;
        const defaultStack = esc(resolveFontStack(state.defaultFont));

        const parts = [];
        parts.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${Math.round(bounds.w)} ${Math.round(bounds.h)}" width="${Math.round(bounds.w)}" height="${Math.round(bounds.h)}" font-family="${defaultStack}">`);

        if (!isTransparent) {
            parts.push(`<rect width="100%" height="100%" fill="${isWhite ? '#ffffff' : '#080c14'}"/>`);
        }

        state.zones.forEach((z) => {
            const zx = z.x + ox;
            const zy = z.y + oy;
            const zc = z.color || '#38bdf8';
            const dash = z.style === 'dashed' ? ' stroke-dasharray="7 5"' : '';
            const zStack = esc(resolveFontStack(z.fontFamily));
            const zSz = Number(z.fontSize) || 11;
            parts.push(`<rect x="${zx}" y="${zy}" width="${z.w}" height="${z.h}" rx="12" fill="${zc}" fill-opacity="${z.opacity ?? 0.06}" stroke="${zc}" stroke-opacity="0.55" stroke-width="1.5"${dash}/>`);
            parts.push(`<text x="${zx + 18}" y="${zy + 26}" fill="${isWhite ? '#0f172a' : zc}" font-family="${zStack}" font-size="${zSz}" font-weight="${z.fontBold !== false ? '700' : '500'}" font-style="${z.fontItalic ? 'italic' : 'normal'}">${esc((z.label || 'ZONE').toUpperCase())}</text>`);
            if (z.sub) {
                parts.push(`<text x="${zx + 18}" y="${zy + 44}" fill="${isWhite ? '#475569' : '#94a3b8'}" font-family="${zStack}" font-size="${Math.max(10, zSz - 0.5)}">${esc(z.sub)}</text>`);
            }
        });

        state.edges.forEach((e) => {
            const pts = getEdgeEndpoints(e);
            if (!pts) return;
            const x1 = pts.x1 + ox;
            const y1 = pts.y1 + oy;
            const x2 = pts.x2 + ox;
            const y2 = pts.y2 + oy;
            const color = resolveDiagramEdgeColor(e.color, isWhite);
            const dash = e.style === 'dashed' || e.style === 'animated' ? ' stroke-dasharray="7 5"' : (e.style === 'dotted' ? ' stroke-dasharray="3 5"' : '');
            const expGeo = getEdgeGeometry(e, pts, e.curve || 'bezier');
            parts.push(`<path d="${geomSvgD(expGeo, ox, oy)}" fill="none" stroke="${color}" stroke-width="${e.width || 2}"${dash}/>`);
            {
                const expRefs = geomRefs(expGeo);
                const arrowSvg = (tx, ty, fx, fy) => {
                    const ang = Math.atan2(ty - fy, tx - fx);
                    const hl = 9.5;
                    const ax = tx + ox;
                    const ay = ty + oy;
                    return `<polygon points="${ax},${ay} ${ax - hl * Math.cos(ang - Math.PI / 6)},${ay - hl * Math.sin(ang - Math.PI / 6)} ${ax - hl * Math.cos(ang + Math.PI / 6)},${ay - hl * Math.sin(ang + Math.PI / 6)}" fill="${color}"/>`;
                };
                if (e.dir !== 'none') parts.push(arrowSvg(pts.x2, pts.y2, expRefs.endRef[0], expRefs.endRef[1]));
                if (e.dir === 'both') parts.push(arrowSvg(pts.x1, pts.y1, expRefs.startRef[0], expRefs.startRef[1]));
            }
            if (e.label) {
                const expMid = geomMid(expGeo);
                const mx = expMid.x + ox;
                const my = expMid.y + oy;
                const eStack = esc(resolveFontStack(e.fontFamily));
                const eSz = Number(e.fontSize) || 10.5;
                const pw = Math.max(90, e.label.length * 6.8 + 18);
                parts.push(`<rect x="${mx - pw / 2}" y="${my - 10}" width="${pw}" height="20" rx="5" fill="${isWhite ? '#ffffff' : '#0a0f19'}" stroke="${color}" stroke-width="1"/>`);
                parts.push(`<text x="${mx}" y="${my + 4}" text-anchor="middle" fill="${isWhite ? '#0f172a' : '#e2e8f0'}" font-family="${eStack}" font-size="${eSz}" font-weight="${e.fontBold !== false ? '600' : '400'}">${esc(e.label)}</text>`);
            }
        });

        state.nodes.forEach((n) => {
            const asset = ALL_ASSETS_MAP.get(n.type) || { name: 'Node', color: '#38bdf8' };
            const { w, h } = getNodeSize(n);
            const nx = n.x - w / 2 + ox;
            const ny = n.y - h / 2 + oy;
            const nc = n.color || asset.color || '#38bdf8';
            const nStack = esc(resolveFontStack(n.fontFamily));
            const nSz = Number(n.fontSize) || 12.5;

            const isStep = n.isStep || n.type === 'flow_step' || n.type === 'step_marker' || n.shape === 'step';
            if (isStep) {
                const r = w / 2;
                const cx = nx + r;
                const cy = ny + r;
                parts.push(`<circle cx="${cx}" cy="${cy}" r="${r}" fill="${nc}" stroke="rgba(255,255,255,0.4)" stroke-width="1.5"/>`);
                parts.push(`<text x="${cx}" y="${cy + Math.round(nSz * 0.35)}" text-anchor="middle" fill="#ffffff" font-family="${nStack}" font-size="${nSz}" font-weight="700">${esc(n.label)}</text>`);
            } else if (n.type === 'image' && n.imageSrc) {
                if (n.showFrame !== false) {
                    parts.push(`<rect x="${nx}" y="${ny}" width="${w}" height="${h}" rx="10" fill="${isWhite ? '#ffffff' : '#111827'}" stroke="${nc}" stroke-width="1.4"/>`);
                }
                const capH = (n.showCaption !== false && n.label) ? (nSz + 14) : 0;
                parts.push(`<image href="${esc(n.imageSrc)}" x="${nx + 6}" y="${ny + 6}" width="${Math.max(20, w - 12)}" height="${Math.max(20, h - 12 - capH)}" preserveAspectRatio="xMidYMid meet"/>`);
                if (n.showCaption !== false && n.label) {
                    parts.push(`<text x="${nx + w / 2}" y="${ny + h - 8}" text-anchor="middle" fill="${isWhite ? '#0f172a' : '#f8fafc'}" font-family="${nStack}" font-size="${nSz}" font-weight="700">${esc(n.label)}</text>`);
                }
            } else {
                parts.push(`<rect x="${nx}" y="${ny}" width="${w}" height="${h}" rx="10" fill="${isWhite ? '#ffffff' : '#111827'}" stroke="${nc}" stroke-width="1.4"/>`);
                parts.push(`<rect x="${nx}" y="${ny}" width="4.5" height="${h}" rx="2" fill="${nc}"/>`);
                if (n.imageSrc) {
                    parts.push(`<image href="${esc(n.imageSrc)}" x="${nx + 14}" y="${ny + (h - 36) / 2}" width="36" height="36" preserveAspectRatio="xMidYMid meet"/>`);
                }
                parts.push(`<text x="${nx + 62}" y="${ny + 28}" fill="${isWhite ? '#0f172a' : '#f8fafc'}" font-family="${nStack}" font-size="${nSz}" font-weight="${n.fontBold !== false ? '700' : '500'}" font-style="${n.fontItalic ? 'italic' : 'normal'}">${esc(n.label || asset.name)}</text>`);
                parts.push(`<text x="${nx + 62}" y="${ny + 47}" fill="${isWhite ? '#475569' : '#94a3b8'}" font-family="${nStack}" font-size="${Math.max(9.5, nSz - 1.5)}">${esc(n.sub ?? asset.sub ?? '')}</text>`);
            }
        });

        state.notes.forEach((t) => {
            const tx = t.x + ox;
            const ty = t.y + oy;
            const tc = t.color || '#ffcc00';
            const tStack = esc(resolveFontStack(t.fontFamily));
            const tSz = Number(t.fontSize) || 11.5;
            const { w, h } = getNoteSize(t);
            parts.push(`<rect x="${tx}" y="${ty}" width="${w}" height="${h}" rx="7" fill="${isWhite ? '#fef9c3' : '#0d131f'}" stroke="${tc}" stroke-width="1.2"/>`);
            parts.push(`<text x="${tx + 14}" y="${ty + h / 2 + 4}" fill="${isWhite ? '#0f172a' : tc}" font-family="${tStack}" font-size="${tSz}" font-weight="${t.fontBold !== false ? '600' : '400'}" font-style="${t.fontItalic ? 'italic' : 'normal'}">${esc(t.text)}</text>`);
        });

        parts.push('</svg>');

        const blob = new Blob([parts.join('\n')], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const slug = (state.title || 'mantis-diagram').toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'mantis-diagram';
        const link = document.createElement('a');
        link.download = `${slug}-${bgTheme}-bg.svg`;
        link.href = url;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        showToast(`Downloaded SVG (${bgTheme} background)`);
    };

    const exportProjectFile = (ext = 'mantis-draw') => {
        const payload = ext === 'mantis-draw' ? buildMantisDrawFilePayload() : serializeDiagram();
        const data = JSON.stringify(payload, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const slug = (state.title || 'mantis-diagram')
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-|-$/g, '') || 'mantis-diagram';
        const link = document.createElement('a');
        link.download = `${slug}.${ext}`;
        link.href = url;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        showToast(`Exported project file: ${slug}.${ext}`);
    };

    // =========================================================================
    // Canvas Render Loop & Viewport Management
    // =========================================================================
    let renderPending = false;
    const requestRender = () => {
        if (renderPending) return;
        renderPending = true;
        requestAnimationFrame(() => {
            renderPending = false;
            drawInteractiveCanvas();
        });
    };

    const drawInteractiveCanvas = () => {
        const canvas = document.getElementById('dd-canvas');
        if (!canvas) return;
        const rect = canvas.getBoundingClientRect();
        if (!rect.width || !rect.height) return;

        const dpr = window.devicePixelRatio || 1;
        if (canvas.width !== Math.round(rect.width * dpr) || canvas.height !== Math.round(rect.height * dpr)) {
            canvas.width = Math.round(rect.width * dpr);
            canvas.height = Math.round(rect.height * dpr);
        }

        const ctx = canvas.getContext('2d');
        ctx.save();
        ctx.scale(dpr, dpr);
        renderSceneToContext(ctx, {
            width: rect.width,
            height: rect.height,
            panX: state.panX,
            panY: state.panY,
            zoom: state.zoom,
            themeMode: state.canvasTheme,
            isExport: false,
            showGrid: state.showGrid,
        });
        ctx.restore();

        const zoomEl = document.getElementById('dd-zoom-readout');
        if (zoomEl) zoomEl.textContent = `${Math.round(state.zoom * 100)}%`;
    };

    const startAnimationLoop = () => {
        if (state.animFrameId) cancelAnimationFrame(state.animFrameId);
        const step = () => {
            const pane = document.getElementById('diagram-draw-pane');
            if (pane && pane.style.display !== 'none' && state.animateFlows) {
                const hasAnimated = state.edges.some((e) => e.style === 'animated');
                if (hasAnimated) {
                    state.animTick = (state.animTick + 1) % 1000;
                    drawInteractiveCanvas();
                }
            }
            state.animFrameId = requestAnimationFrame(step);
        };
        state.animFrameId = requestAnimationFrame(step);
    };

    const fitToScreen = () => {
        const canvas = document.getElementById('dd-canvas');
        if (!canvas) return;
        const rect = canvas.getBoundingClientRect();
        if (!rect.width || !rect.height) return;
        const b = computeDiagramBounds();
        const padTop = 64;
        const padBottom = 56;
        const padX = 56;
        const availW = Math.max(200, rect.width - padX * 2);
        const availH = Math.max(180, rect.height - padTop - padBottom);
        const scaleX = availW / b.w;
        const scaleY = availH / b.h;
        state.zoom = Math.max(0.18, Math.min(1.15, Math.min(scaleX, scaleY)));
        state.panX = (rect.width - b.w * state.zoom) / 2 - b.x * state.zoom;
        state.panY = padTop + (availH - b.h * state.zoom) / 2 - b.y * state.zoom;
        requestRender();
    };

    // =========================================================================
    // DOM UI Rendering (Single-Row Header, Non-Truncated Palette, Inspector)
    // =========================================================================
    const renderFontOptionsHtml = (selectedFont, includeDefault = true) => `
        ${includeDefault ? `<option value="default" ${(!selectedFont || selectedFont === 'default') ? 'selected' : ''}>Default (${esc(state.defaultFont || 'Plus Jakarta Sans')})</option>` : ''}
        ${FONT_OPTIONS.map((f) => `
            <option value="${esc(f.id)}" ${selectedFont === f.id ? 'selected' : ''} style="font-family:${esc(f.stack)};">${esc(f.label)}</option>
        `).join('')}
    `;

    const renderTypographyControls = (item, prefix) => `
        <div class="dd-insp-section">
            <div class="dd-insp-sec-title">Typography</div>
            <div class="dd-insp-row">
                <label>Font</label>
                <div class="dd-insp-row-control">
                    <select id="${prefix}-font-family">
                        ${renderFontOptionsHtml(item.fontFamily || 'default', true)}
                    </select>
                </div>
            </div>
            <div class="dd-insp-row">
                <label>Size &amp; Style</label>
                <div class="dd-insp-row-control">
                    <input type="number" id="${prefix}-font-size" min="8" max="42" step="1" value="${Number(item.fontSize) || 12}" style="width:62px;">
                    <div class="dd-style-toggles">
                        <button type="button" class="dd-style-toggle ${item.fontBold !== false ? 'active' : ''}" id="${prefix}-font-bold" title="Bold">
                            <i class="fa-solid fa-bold"></i>
                        </button>
                        <button type="button" class="dd-style-toggle ${item.fontItalic ? 'active' : ''}" id="${prefix}-font-italic" title="Italic">
                            <i class="fa-solid fa-italic"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    const CAT_PILLS = [
        { id: 'all', label: 'All' },
        { id: 'flow', label: 'Process Flow' },
        { id: 'cti_osint', label: 'CTI' },
        { id: 'dfir', label: 'DFIR' },
        { id: 'hunt_detect', label: 'Hunt / Detect' },
        { id: 'redteam_ad', label: 'Red Team' },
        { id: 'threats', label: 'Malware' },
        { id: 'network', label: 'Network' },
        { id: 'security', label: 'Security' },
        { id: 'servers', label: 'Servers' },
        { id: 'endpoints', label: 'Endpoints' },
        { id: 'ot', label: 'OT / ICS' },
    ];

    const renderStudioShell = () => {
        const pane = document.getElementById('diagram-draw-pane');
        if (!pane) return;

        pane.innerHTML = `
            <!-- Spacious 3-Section Studio Topbar (Never Crowded) -->
            <header class="dd-topbar">
                <!-- Left: Icon + Spacious Editable Diagram Title -->
                <div class="dd-topbar-left">
                    <div class="dd-brand-icon"><i class="fa-solid fa-diagram-project"></i></div>
                    <div class="dd-brand-title-wrap">
                        <input type="text" id="dd-diagram-title-input" class="dd-brand-title-input" value="${esc(state.title)}" title="Click to rename diagram">
                    </div>
                </div>

                <!-- Center: Graph Templates + Font Family + Undo/Redo -->
                <div class="dd-topbar-center">
                    <div class="dd-dropdown" id="dd-templates-dropdown">
                        <button type="button" class="dd-btn dd-btn-surface" id="dd-btn-templates">
                            <i class="fa-solid fa-wand-magic-sparkles" style="color:var(--dd-accent);"></i>
                            <span>Graph Templates</span>
                            <i class="fa-solid fa-chevron-down" style="font-size:0.6rem; opacity:0.65;"></i>
                        </button>
                        <div class="dd-dropdown-menu dark-scroll">
                            <div class="dd-dropdown-sec">Enterprise &amp; Network Topologies</div>
                            <button type="button" class="dd-dropdown-item" data-dd-template="netdraw_enterprise">
                                <i class="fa-solid fa-network-wired" style="color:#06b6d4;"></i> Enterprise Multi-VLAN &amp; M365 Hybrid
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="cloud_hybrid">
                                <i class="fa-solid fa-cloud" style="color:#0284c7;"></i> AWS &amp; Azure Hybrid Cloud Architecture
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="enterprise">
                                <i class="fa-solid fa-shield-halved" style="color:#10b981;"></i> Enterprise Defense-in-Depth
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="ot_ics">
                                <i class="fa-solid fa-microchip" style="color:#14b8a6;"></i> OT / SCADA Purdue Segmentation
                            </button>

                            <div class="dd-dropdown-sec">APT Campaigns &amp; Threat Intelligence</div>
                            <button type="button" class="dd-dropdown-item" data-dd-template="apt_campaign_ad">
                                <i class="fa-solid fa-skull" style="color:#f97316;"></i> APT-29 Full Intrusion &amp; AD Compromise
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="supply_chain_cicd">
                                <i class="fa-solid fa-code-merge" style="color:#eab308;"></i> CI/CD Software Supply Chain Intrusion
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="cti_diamond">
                                <i class="fa-solid fa-gem" style="color:#ec4899;"></i> Diamond Model of Intrusion
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="cti_pivot">
                                <i class="fa-solid fa-compass" style="color:#ec4899;"></i> CTI Infrastructure Pivot Graph
                            </button>

                            <div class="dd-dropdown-sec">Active Directory &amp; Red Team</div>
                            <button type="button" class="dd-dropdown-item" data-dd-template="ad_forest_takeover">
                                <i class="fa-solid fa-diagram-project" style="color:#ef4444;"></i> AD Forest Compromise &amp; Trust Abuse
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="red_bloodhound">
                                <i class="fa-solid fa-sitemap" style="color:#ef4444;"></i> AD / BloodHound Attack Path
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="c2_infra">
                                <i class="fa-solid fa-tower-broadcast" style="color:#ef4444;"></i> OpSec C2 &amp; Smart Redirector Mesh
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="ransomware">
                                <i class="fa-solid fa-skull-crossbones" style="color:#ef4444;"></i> Ransomware Kill-Chain
                            </button>

                            <div class="dd-dropdown-sec">Digital Forensics (DFIR)</div>
                            <button type="button" class="dd-dropdown-item" data-dd-template="dfir_proc_tree">
                                <i class="fa-solid fa-terminal" style="color:#6366f1;"></i> Process Execution Lineage Tree
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="dfir_persistence">
                                <i class="fa-solid fa-hard-drive" style="color:#6366f1;"></i> Host Persistence &amp; Artifact Map
                            </button>

                            <div class="dd-dropdown-sec">Threat Hunting &amp; Detection Eng.</div>
                            <button type="button" class="dd-dropdown-item" data-dd-template="hunt_hypothesis">
                                <i class="fa-solid fa-lightbulb" style="color:#ffcc00;"></i> Hunt Hypothesis Decision Tree
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-template="detect_pipeline">
                                <i class="fa-solid fa-code" style="color:#f97316;"></i> Detection &amp; Telemetry Pipeline
                            </button>

                            <div class="dd-dropdown-sec">Canvas</div>
                            <button type="button" class="dd-dropdown-item" id="dd-btn-clear-all" style="color:#fca5a5;">
                                <i class="fa-solid fa-broom" style="color:#ef4444;"></i> New Blank Canvas
                            </button>
                        </div>
                    </div>

                    <div class="dd-pill-group" role="group" aria-label="Font & History">
                        <select id="dd-global-font" class="dd-font-select-top" title="Default Diagram Font Family">
                            ${renderFontOptionsHtml(state.defaultFont, false)}
                        </select>
                        <span class="dd-divider"></span>
                        <button type="button" class="dd-btn icon-only" id="dd-btn-undo" title="Undo (Ctrl+Z)" disabled>
                            <i class="fa-solid fa-rotate-left"></i>
                        </button>
                        <button type="button" class="dd-btn icon-only" id="dd-btn-redo" title="Redo (Ctrl+Y)" disabled>
                            <i class="fa-solid fa-rotate-right"></i>
                        </button>
                    </div>
                </div>

                <!-- Right: PNG Download (Transparent, Dark, White) & Project / SVG Menu -->
                <div class="dd-topbar-right">
                    <div class="dd-pill-group" role="group" aria-label="Download PNG">
                        <span class="dd-export-label"><i class="fa-solid fa-download"></i> PNG</span>
                        <button type="button" class="dd-export-btn" id="dd-dl-png-transparent" title="Download PNG (Transparent Background)">
                            <span class="dd-dot-swatch dd-dot-transparent"></span> Transparent
                        </button>
                        <button type="button" class="dd-export-btn" id="dd-dl-png-dark" title="Download PNG (Dark Background)">
                            <span class="dd-dot-swatch dd-dot-dark"></span> Dark
                        </button>
                        <button type="button" class="dd-export-btn" id="dd-dl-png-white" title="Download PNG (White Background)">
                            <span class="dd-dot-swatch dd-dot-white"></span> White
                        </button>
                    </div>

                    <div class="dd-dropdown" id="dd-svg-dropdown">
                        <button type="button" class="dd-btn dd-btn-surface" id="dd-btn-svg-menu" title="Save/Import .mantis-draw Project or Export SVG">
                            <i class="fa-solid fa-file-shield" style="color:var(--dd-emerald);"></i>
                            <span>Project / SVG</span>
                            <i class="fa-solid fa-chevron-down" style="font-size:0.6rem; opacity:0.65;"></i>
                        </button>
                        <div class="dd-dropdown-menu">
                            <div class="dd-dropdown-sec">Editable Project Format (.mantis-draw)</div>
                            <button type="button" class="dd-dropdown-item" id="dd-menu-export-mantis">
                                <i class="fa-solid fa-file-arrow-down" style="color:#10b981;"></i> Export .mantis-draw File (Ctrl+S)
                            </button>
                            <button type="button" class="dd-dropdown-item" id="dd-menu-import-file">
                                <i class="fa-solid fa-file-arrow-up" style="color:#38bdf8;"></i> Import .mantis-draw / .json File
                            </button>
                            <button type="button" class="dd-dropdown-item" id="dd-menu-export-json">
                                <i class="fa-solid fa-file-code" style="color:#94a3b8;"></i> Export Raw .json File
                            </button>
                            <div class="dd-dropdown-sec">Vector SVG Download</div>
                            <button type="button" class="dd-dropdown-item" data-dd-svg="transparent">
                                <i class="fa-solid fa-chess-board" style="color:#38bdf8;"></i> SVG — Transparent BG
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-svg="dark">
                                <i class="fa-solid fa-moon" style="color:#94a3b8;"></i> SVG — Dark BG
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-svg="white">
                                <i class="fa-solid fa-sun" style="color:#ffcc00;"></i> SVG — White BG
                            </button>
                            <div class="dd-dropdown-sec">Copy Diagram to Clipboard</div>
                            <button type="button" class="dd-dropdown-item" data-dd-copy-png="transparent">
                                <i class="fa-regular fa-copy" style="color:#38bdf8;"></i> Copy PNG (Transparent)
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-copy-png="dark">
                                <i class="fa-regular fa-copy" style="color:#94a3b8;"></i> Copy PNG (Dark BG)
                            </button>
                            <button type="button" class="dd-dropdown-item" data-dd-copy-png="white">
                                <i class="fa-regular fa-copy" style="color:#ffcc00;"></i> Copy PNG (White BG)
                            </button>
                        </div>
                    </div>

                    <input type="file" id="dd-project-file-input" accept=".mantis-draw,.json,application/json" style="display:none;">
                    <input type="file" id="dd-img-file-input" accept="image/*" multiple style="display:none;">
                    <input type="file" id="dd-node-icon-file-input" accept="image/*" style="display:none;">

                    <button type="button" class="dd-btn dd-btn-surface icon-only" id="dd-btn-toggle-inspector" title="Toggle Right Properties Bar" style="width:34px;">
                        <i class="fa-solid fa-table-columns"></i>
                    </button>
                </div>
            </header>

            <!-- Main 3-Column Studio Workspace -->
            <div class="dd-workspace ${state.paletteCollapsed ? 'palette-collapsed' : ''} ${state.inspectorCollapsed ? 'inspector-collapsed' : ''}" id="dd-workspace">
                <!-- Left Entity & Icon Library (Manual Collapse Toggle) -->
                <aside class="dd-palette" aria-label="Diagram Asset Library">
                    <div class="dd-palette-header">
                        <div class="dd-palette-top-row">
                            <span>Assets &amp; Shapes</span>
                            <button type="button" class="dd-inspector-collapse-btn" id="dd-btn-collapse-palette" title="Collapse Left Sidebar">
                                <i class="fa-solid fa-angles-left"></i>
                            </button>
                        </div>
                        <div class="dd-palette-search">
                            <i class="fa-solid fa-magnifying-glass"></i>
                            <input type="text" id="dd-asset-search" placeholder="Search 120+ icons &amp; flow shapes...">
                        </div>
                        <div class="dd-cat-pills" id="dd-cat-pills">
                            ${CAT_PILLS.map((p) => `
                                <button type="button" class="dd-cat-pill ${state.activeCatFilter === p.id ? 'active' : ''}" data-dd-cat-pill="${p.id}">${esc(p.label)}</button>
                            `).join('')}
                        </div>
                    </div>
                    <div class="dd-palette-body dark-scroll" id="dd-palette-list"></div>
                </aside>

                <!-- Center Interactive Canvas with Floating Figma-Style Tool Dock -->
                <section class="dd-canvas-wrap theme-${state.canvasTheme}" id="dd-canvas-wrap">
                    <div class="dd-floating-dock-wrap">
                        <!-- Left Expand Palette Pill (Shown when left bar is collapsed) -->
                        <div style="display:flex; justify-content:flex-start; min-width:110px;">
                            <button type="button" class="dd-expand-palette-pill" id="dd-btn-expand-palette" title="Expand Assets Sidebar">
                                <span>Assets</span>
                                <i class="fa-solid fa-angles-right" style="color:var(--dd-accent);"></i>
                            </button>
                        </div>

                        <!-- Center Floating Drawing Tool Dock -->
                        <div class="dd-floating-dock" role="toolbar" aria-label="Drawing tools">
                            <button type="button" class="dd-dock-btn active" data-dd-mode="select" title="Select & Move (V)">
                                <i class="fa-solid fa-arrow-pointer"></i> <span>Select</span> <kbd>V</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-dd-mode="connect" title="Connect Nodes (C)">
                                <i class="fa-solid fa-share-nodes"></i> <span>Connect</span> <kbd>C</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-dd-mode="zone" title="Draw Security Zone (Z)">
                                <i class="fa-regular fa-object-group"></i> <span>Zone</span> <kbd>Z</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-dd-mode="text" title="Add Callout Note (T)">
                                <i class="fa-solid fa-font"></i> <span>Note</span> <kbd>T</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-dd-mode="step" title="Numbered Step Marker 1..∞ (S)">
                                <i class="fa-solid fa-circle-dot" style="color:#ef4444;"></i> <span>Step</span> <kbd>S</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" id="dd-btn-insert-img" title="Insert Image onto Canvas (I)">
                                <i class="fa-regular fa-image" style="color:var(--dd-cyan);"></i> <span>Image</span> <kbd>I</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-dd-mode="pan" title="Pan Canvas (H or Space+Drag)">
                                <i class="fa-solid fa-hand"></i> <span>Pan</span> <kbd>H</kbd>
                            </button>
                            <span class="dd-divider"></span>
                            <button type="button" class="dd-dock-btn icon-only" id="dd-btn-copy" title="Copy Selected (Ctrl+C)">
                                <i class="fa-regular fa-copy"></i>
                            </button>
                            <button type="button" class="dd-dock-btn icon-only" id="dd-btn-paste" title="Paste Image or Copied Item (Ctrl+V)">
                                <i class="fa-solid fa-paste" style="color:var(--dd-accent);"></i>
                            </button>
                            <button type="button" class="dd-dock-btn icon-only dd-dock-btn-danger" id="dd-btn-delete" title="Delete Selected (Del)">
                                <i class="fa-regular fa-trash-can"></i>
                            </button>
                        </div>

                        <!-- Right Expand Inspector Pill (Shown when right bar is collapsed) -->
                        <div style="display:flex; justify-content:flex-end; min-width:110px;">
                            <button type="button" class="dd-expand-inspector-pill" id="dd-btn-expand-inspector" title="Expand Properties Bar">
                                <i class="fa-solid fa-angles-left" style="color:var(--dd-accent);"></i>
                                <span>Properties</span>
                            </button>
                        </div>
                    </div>

                    <canvas id="dd-canvas" class="dd-canvas"></canvas>

                    <div class="dd-canvas-hud-bottom">
                        <div class="dd-canvas-hud-pill">
                            <span>Canvas:</span>
                            <div class="dd-bg-switcher">
                                <button type="button" class="dd-bg-chip ${state.canvasTheme === 'dark' ? 'active' : ''}" data-dd-bg="dark">Dark</button>
                                <button type="button" class="dd-bg-chip ${state.canvasTheme === 'white' ? 'active' : ''}" data-dd-bg="white">White</button>
                                <button type="button" class="dd-bg-chip ${state.canvasTheme === 'transparent' ? 'active' : ''}" data-dd-bg="transparent">Transparent</button>
                            </div>
                            <span style="opacity:0.25;">|</span>
                            <label style="display:inline-flex; align-items:center; gap:5px; cursor:pointer;">
                                <input type="checkbox" id="dd-chk-snap" ${state.snapToGrid ? 'checked' : ''}> Snap
                            </label>
                            <label style="display:inline-flex; align-items:center; gap:5px; cursor:pointer;">
                                <input type="checkbox" id="dd-chk-anim" ${state.animateFlows ? 'checked' : ''}> Animate
                            </label>
                        </div>

                        <div class="dd-zoom-controls">
                            <button type="button" class="dd-zoom-btn" id="dd-zoom-out" title="Zoom Out"><i class="fa-solid fa-minus"></i></button>
                            <span class="dd-zoom-readout" id="dd-zoom-readout">100%</span>
                            <button type="button" class="dd-zoom-btn" id="dd-zoom-in" title="Zoom In"><i class="fa-solid fa-plus"></i></button>
                            <button type="button" class="dd-zoom-btn" id="dd-zoom-fit" title="Fit Diagram to Screen"><i class="fa-solid fa-expand"></i></button>
                        </div>
                    </div>
                </section>

                <!-- Right Property Inspector -->
                <aside class="dd-inspector" aria-label="Properties Inspector">
                    <div class="dd-inspector-header">
                        <span style="display:inline-flex; align-items:center; gap:7px;">
                            <span>Properties</span>
                            <span id="dd-inspector-type-badge" class="dd-inspector-badge">DIAGRAM</span>
                        </span>
                        <button type="button" class="dd-inspector-collapse-btn" id="dd-btn-collapse-inspector" title="Collapse Properties Bar">
                            <i class="fa-solid fa-angles-right"></i>
                        </button>
                    </div>
                    <div class="dd-inspector-body dark-scroll" id="dd-inspector-body"></div>
                </aside>
            </div>

            <div id="dd-toast" class="dd-toast"></div>
        `;

        renderPaletteList();
        renderInspector();
        bindStudioEvents();
        updateToolbarButtons();
    };

    const renderPaletteList = () => {
        const container = document.getElementById('dd-palette-list');
        if (!container) return;
        const q = (state.searchQuery || '').trim().toLowerCase();
        const catFilter = state.activeCatFilter || 'all';

        const html = ASSET_CATEGORIES.map((cat) => {
            if (catFilter !== 'all' && cat.id !== catFilter) return '';
            const items = cat.items.filter((it) => !q
                || it.name.toLowerCase().includes(q)
                || it.type.toLowerCase().includes(q)
                || cat.name.toLowerCase().includes(q)
                || (it.sub && it.sub.toLowerCase().includes(q)));
            if (!items.length) return '';
            const isCollapsed = !q && catFilter === 'all' && state.collapsedCats.has(cat.id);
            if (cat.isFlowGrid) {
                return `
                    <div class="dd-cat-group ${isCollapsed ? 'collapsed' : ''}" data-cat-id="${esc(cat.id)}">
                        <button type="button" class="dd-cat-header" data-cat-toggle="${esc(cat.id)}">
                            <span class="dd-cat-header-left">
                                <span class="dd-cat-dot" style="background:${esc(cat.color)};"></span>
                                <span>${esc(cat.name)}</span>
                            </span>
                            <span class="dd-cat-count">${items.length}</span>
                            <i class="fa-solid fa-chevron-down dd-cat-caret" style="font-size:0.64rem; color:#64748b;"></i>
                        </button>
                        <div class="dd-flow-grid">
                            ${items.map((it) => `
                                <button type="button" class="dd-flow-tile" draggable="true" data-asset-type="${esc(it.type)}" title="Click or drag ${esc(it.name)}">
                                    <span class="dd-flow-tile-icon" style="background:${hexToRgba(it.color, 0.14)};">
                                        ${getFlowShapeSvgIcon(it.flowShape, it.color)}
                                    </span>
                                    <span class="dd-flow-tile-label">${esc(it.name)}</span>
                                </button>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            return `
                <div class="dd-cat-group ${isCollapsed ? 'collapsed' : ''}" data-cat-id="${esc(cat.id)}">
                    <button type="button" class="dd-cat-header" data-cat-toggle="${esc(cat.id)}">
                        <span class="dd-cat-header-left">
                            <span class="dd-cat-dot" style="background:${esc(cat.color)};"></span>
                            <span>${esc(cat.name)}</span>
                        </span>
                        <span class="dd-cat-count">${items.length}</span>
                        <i class="fa-solid fa-chevron-down dd-cat-caret" style="font-size:0.64rem; color:#64748b;"></i>
                    </button>
                    <div class="dd-cat-items">
                        ${items.map((it) => `
                            <button type="button" class="dd-asset-item" draggable="true" data-asset-type="${esc(it.type)}">
                                <span class="dd-asset-icon" style="background:${hexToRgba(it.color, 0.14)}; color:${esc(it.color)};">
                                    <i class="fa-solid ${esc(it.fa)}"></i>
                                </span>
                                <span class="dd-asset-meta">
                                    <span class="dd-asset-name">${esc(it.name)}</span>
                                    <span class="dd-asset-sub">${esc(it.sub)}</span>
                                </span>
                            </button>
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = html || '<div style="padding:20px; text-align:center; color:#64748b; font-size:0.76rem;">No matching entities found.</div>';
    };

    const renderSwatches = (activeColor, attrName) => `
        <div class="dd-color-swatches">
            ${SWATCH_COLORS.map((c) => `
                <button type="button" class="dd-color-swatch ${String(activeColor).toLowerCase() === c.toLowerCase() ? 'active' : ''}"
                    style="background:${c};" data-dd-swatch="${c}" data-dd-target="${attrName}" title="${c}"></button>
            `).join('')}
        </div>
    `;

    const renderInspector = () => {
        const body = document.getElementById('dd-inspector-body');
        const badge = document.getElementById('dd-inspector-type-badge');
        if (!body) return;

        const firstId = [...state.selectedIds][0];

        if (state.selectedType === 'node' && firstId) {
            const n = state.nodes.find((item) => item.id === firstId);
            if (n) {
                const { w, h } = getNodeSize(n);
                const isImgNode = n.type === 'image';
                const isStep = n.isStep || n.type === 'flow_step' || n.type === 'step_marker' || n.shape === 'step';
                if (isStep) {
                    if (badge) badge.textContent = `Step Marker · ${state.selectedIds.size}`;
                    const curSize = Number(n.size) || Number(n.w) || 36;
                    body.innerHTML = `
                        <div class="dd-insp-section">
                            <div class="dd-insp-sec-title">Step Marker Sequence</div>
                            <div class="dd-field">
                                <label>Step Number / Sequence</label>
                                <div style="display:flex; gap:6px; align-items:center;">
                                    <input type="text" id="dd-insp-step-num" value="${esc(n.label)}" placeholder="e.g. 1, 2, 3..">
                                    <button type="button" class="dd-btn dd-btn-surface" id="dd-insp-step-dec" title="Previous step (-1)" style="padding:6px 10px; font-weight:700;"><i class="fa-solid fa-minus"></i></button>
                                    <button type="button" class="dd-btn dd-btn-surface" id="dd-insp-step-inc" title="Next step (+1)" style="padding:6px 10px; font-weight:700;"><i class="fa-solid fa-plus"></i></button>
                                </div>
                                <div style="font-size:0.7rem; color:#64748b; margin-top:4px;">
                                    Supports any sequence number (1 to &infin;) or phase tag (e.g. 1, 2, 3, 1a, Phase 1).
                                </div>
                            </div>
                            <div class="dd-insp-row" style="margin-top:10px;">
                                <label>Diameter</label>
                                <div class="dd-insp-row-control">
                                    <input type="number" id="dd-insp-step-size" min="20" max="140" step="2" value="${Math.round(curSize)}">
                                </div>
                            </div>
                            <div style="display:flex; gap:6px; margin-top:8px;">
                                <button type="button" class="dd-btn dd-btn-surface ${curSize === 28 ? 'active' : ''}" data-step-preset-size="28" style="flex:1; font-size:0.72rem; padding:4px 6px;">
                                    28px
                                </button>
                                <button type="button" class="dd-btn dd-btn-surface ${curSize === 36 ? 'active' : ''}" data-step-preset-size="36" style="flex:1; font-size:0.72rem; padding:4px 6px;">
                                    36px
                                </button>
                                <button type="button" class="dd-btn dd-btn-surface ${curSize === 46 ? 'active' : ''}" data-step-preset-size="46" style="flex:1; font-size:0.72rem; padding:4px 6px;">
                                    46px
                                </button>
                                <button type="button" class="dd-btn dd-btn-surface ${curSize === 56 ? 'active' : ''}" data-step-preset-size="56" style="flex:1; font-size:0.72rem; padding:4px 6px;">
                                    56px
                                </button>
                            </div>
                        </div>

                        <div class="dd-insp-section">
                            <div class="dd-insp-sec-title">Badge Color</div>
                            ${renderSwatches(n.color || '#ef4444', 'node-color')}
                        </div>

                        ${renderTypographyControls(n, 'dd-insp-node')}

                        <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="dd-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22); margin-top:12px;">
                            <i class="fa-regular fa-trash-can"></i> Delete Step Marker
                        </button>
                    `;
                    bindInspectorInputs();
                    return;
                }
                if (badge) badge.textContent = isImgNode ? 'Image' : `Node · ${state.selectedIds.size}`;
                body.innerHTML = `
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">${isImgNode ? 'Image Details' : 'Identity'}</div>
                        <div class="dd-field">
                            <label>${isImgNode ? 'Caption' : 'Title / Hostname'}</label>
                            <input type="text" id="dd-insp-node-label" value="${esc(n.label)}">
                        </div>
                        ${!isImgNode ? `
                            <div class="dd-field">
                                <label>Subtitle / IOC</label>
                                <input type="text" id="dd-insp-node-sub" value="${esc(n.sub || '')}" placeholder="e.g. PID 4192, SHA256, 10.20.1.10">
                            </div>
                        ` : ''}
                    </div>

                    ${renderTypographyControls(n, 'dd-insp-node')}

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">${isImgNode ? 'Dimensions & Frame' : 'Classification'}</div>
                        ${isImgNode ? `
                            <div class="dd-insp-row">
                                <label>Size (W × H)</label>
                                <div class="dd-insp-row-control">
                                    <input type="number" id="dd-insp-node-w" min="60" max="900" step="10" value="${Math.round(w)}">
                                    <input type="number" id="dd-insp-node-h" min="50" max="900" step="10" value="${Math.round(h)}">
                                </div>
                            </div>
                            <div class="dd-img-preview-box">
                                ${n.imageSrc ? `<img src="${esc(n.imageSrc)}" alt="Preview">` : '<span>No image</span>'}
                            </div>
                            <div style="display:flex; gap:14px; font-size:0.73rem; color:#cbd5e1;">
                                <label style="display:inline-flex; align-items:center; gap:5px; cursor:pointer;">
                                    <input type="checkbox" id="dd-insp-img-frame" ${n.showFrame !== false ? 'checked' : ''}> Frame
                                </label>
                                <label style="display:inline-flex; align-items:center; gap:5px; cursor:pointer;">
                                    <input type="checkbox" id="dd-insp-img-caption" ${n.showCaption !== false ? 'checked' : ''}> Caption
                                </label>
                            </div>
                            <button type="button" class="dd-image-upload-btn" id="dd-insp-replace-img">
                                <i class="fa-regular fa-image"></i> Replace Image
                            </button>
                        ` : `
                            <div class="dd-insp-row">
                                <label>Type</label>
                                <div class="dd-insp-row-control">
                                    <select id="dd-insp-node-type">
                                        ${ASSET_CATEGORIES.map((cat) => `
                                            <optgroup label="${esc(cat.name)}">
                                                ${cat.items.map((it) => `
                                                    <option value="${esc(it.type)}" ${n.type === it.type ? 'selected' : ''}>${esc(it.name)}</option>
                                                `).join('')}
                                            </optgroup>
                                        `).join('')}
                                    </select>
                                </div>
                            </div>
                            <div class="dd-insp-row">
                                <label>Status</label>
                                <div class="dd-insp-row-control">
                                    <select id="dd-insp-node-status">
                                        ${Object.entries(STATUS_BADGES).map(([k, v]) => `
                                            <option value="${k}" ${(n.status || 'none') === k ? 'selected' : ''}>${esc(v.label)}</option>
                                        `).join('')}
                                    </select>
                                </div>
                            </div>
                            <div class="dd-insp-row">
                                <label>Step / TTP</label>
                                <div class="dd-insp-row-control">
                                    <input type="text" id="dd-insp-node-step" value="${esc(n.step || '')}" placeholder="e.g. T1003.001">
                                </div>
                            </div>
                            <div style="display:flex; gap:6px; margin-top:2px;">
                                <button type="button" class="dd-image-upload-btn" id="dd-insp-replace-img" style="flex:1;">
                                    <i class="fa-regular fa-image"></i> ${n.imageSrc ? 'Change Custom Icon' : 'Custom Icon Image'}
                                </button>
                                ${n.imageSrc ? `
                                    <button type="button" class="dd-btn dd-dock-btn-danger icon-only" id="dd-insp-clear-img" title="Reset icon">
                                        <i class="fa-solid fa-xmark"></i>
                                    </button>
                                ` : ''}
                            </div>
                        `}
                    </div>

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Accent Color</div>
                        ${renderSwatches(n.color || '#38bdf8', 'node-color')}
                    </div>

                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="dd-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22);">
                        <i class="fa-regular fa-trash-can"></i> Delete Node
                    </button>
                `;
                bindInspectorInputs();
                return;
            }
        }

        if (state.selectedType === 'edge' && firstId) {
            const e = state.edges.find((item) => item.id === firstId);
            if (e) {
                if (badge) badge.textContent = 'Connection';
                body.innerHTML = `
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Relationship</div>
                        <div class="dd-field">
                            <label>Label / Protocol / TTP</label>
                            <input type="text" id="dd-insp-edge-label" value="${esc(e.label || '')}" placeholder="e.g. Spawns Process / HTTPS :443">
                        </div>
                    </div>

                    ${renderTypographyControls({ ...e, fontSize: e.fontSize || 11 }, 'dd-insp-edge')}

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Line Geometry</div>
                        <div class="dd-insp-row">
                            <label>From Side</label>
                            <div class="dd-insp-row-control">
                                <select id="dd-insp-edge-fromport">${portSelectOptions(e.fromPort)}</select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>To Side</label>
                            <div class="dd-insp-row-control">
                                <select id="dd-insp-edge-toport">${portSelectOptions(e.toPort)}</select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Pattern</label>
                            <div class="dd-insp-row-control">
                                <select id="dd-insp-edge-style">
                                    <option value="solid" ${e.style === 'solid' ? 'selected' : ''}>Solid</option>
                                    <option value="dashed" ${e.style === 'dashed' ? 'selected' : ''}>Dashed</option>
                                    <option value="dotted" ${e.style === 'dotted' ? 'selected' : ''}>Dotted</option>
                                    <option value="animated" ${e.style === 'animated' ? 'selected' : ''}>Animated Flow</option>
                                </select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Routing</label>
                            <div class="dd-insp-row-control">
                                <select id="dd-insp-edge-curve">
                                    <option value="bezier" ${(e.curve || 'bezier') === 'bezier' ? 'selected' : ''}>Curved Bezier</option>
                                    <option value="step" ${e.curve === 'step' ? 'selected' : ''}>Orthogonal Step</option>
                                    <option value="straight" ${e.curve === 'straight' ? 'selected' : ''}>Straight Line</option>
                                </select>
                            </div>
                        </div>
                        ${e.curve === 'step' ? `
                            <div class="dd-insp-row">
                                <label>Step Offset</label>
                                <div class="dd-insp-row-control">
                                    <input type="number" id="dd-insp-edge-step-offset" min="-1200" max="1200" step="5" value="${Math.round(Number(e.stepOffset) || 0)}" style="width:70px;" title="Offset middle segment (px)">
                                    <button type="button" class="dd-btn dd-btn-surface dd-btn-xs" id="dd-insp-edge-step-reset" title="Reset to Center (0px)">Reset</button>
                                </div>
                            </div>
                            <div class="dd-insp-row" style="margin-top:-4px;">
                                <label style="font-size:0.75rem; color:var(--dd-text-muted);">Quick Shift</label>
                                <div class="dd-insp-row-control" style="gap:4px;">
                                    <button type="button" class="dd-btn dd-btn-surface dd-btn-xs" id="dd-insp-edge-step-sub" title="Shift -40px">-40px</button>
                                    <button type="button" class="dd-btn dd-btn-surface dd-btn-xs" id="dd-insp-edge-step-add" title="Shift +40px">+40px</button>
                                </div>
                            </div>
                            <div style="font-size:0.7rem; color:var(--dd-text-muted); line-height:1.35; padding:2px 0 8px 0;">
                                <i class="fa-solid fa-arrows-up-down-left-right" style="color:#0ea5e9; margin-right:3px;"></i>
                                Drag the cyan handle on the middle segment or adjust offset to route around nodes.
                            </div>
                        ` : ''}
                        <div class="dd-insp-row">
                            <label>Direction</label>
                            <div class="dd-insp-row-control">
                                <select id="dd-insp-edge-dir">
                                    <option value="forward" ${(e.dir || 'forward') === 'forward' ? 'selected' : ''}>Forward (→)</option>
                                    <option value="both" ${e.dir === 'both' ? 'selected' : ''}>Bidirectional (↔)</option>
                                    <option value="none" ${e.dir === 'none' ? 'selected' : ''}>Undirected (—)</option>
                                </select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Thickness</label>
                            <div class="dd-insp-row-control">
                                <input type="number" id="dd-insp-edge-width" min="1" max="6" step="0.5" value="${Number(e.width) || 2}" style="width:70px;">
                            </div>
                        </div>
                    </div>

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Color</div>
                        ${renderSwatches(e.color || '#38bdf8', 'edge-color')}
                    </div>

                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="dd-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22);">
                        <i class="fa-regular fa-trash-can"></i> Delete Connection
                    </button>
                `;
                bindInspectorInputs();
                return;
            }
        }

        if (state.selectedType === 'zone' && firstId) {
            const z = state.zones.find((item) => item.id === firstId);
            if (z) {
                if (badge) badge.textContent = 'Zone';
                body.innerHTML = `
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Security Boundary</div>
                        <div class="dd-field">
                            <label>Zone Title</label>
                            <input type="text" id="dd-insp-zone-label" value="${esc(z.label || '')}" placeholder="e.g. DMZ / TIER-0">
                        </div>
                        <div class="dd-field">
                            <label>Subnet / Description</label>
                            <input type="text" id="dd-insp-zone-sub" value="${esc(z.sub || '')}" placeholder="e.g. 10.20.0.0/16">
                        </div>
                    </div>

                    ${renderTypographyControls({ ...z, fontSize: z.fontSize || 11 }, 'dd-insp-zone')}

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Appearance</div>
                        <div class="dd-insp-row">
                            <label>Border</label>
                            <div class="dd-insp-row-control">
                                <select id="dd-insp-zone-style">
                                    <option value="dashed" ${(z.style || 'dashed') === 'dashed' ? 'selected' : ''}>Dashed</option>
                                    <option value="solid" ${z.style === 'solid' ? 'selected' : ''}>Solid</option>
                                </select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Dimensions</label>
                            <div class="dd-insp-row-control">
                                <input type="text" value="${Math.round(z.w)} × ${Math.round(z.h)} px" disabled>
                            </div>
                        </div>
                        ${renderSwatches(z.color || '#38bdf8', 'zone-color')}
                    </div>

                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="dd-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22);">
                        <i class="fa-regular fa-trash-can"></i> Delete Zone
                    </button>
                `;
                bindInspectorInputs();
                return;
            }
        }

        if (state.selectedType === 'note' && firstId) {
            const t = state.notes.find((item) => item.id === firstId);
            if (t) {
                if (badge) badge.textContent = 'Note';
                body.innerHTML = `
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Annotation</div>
                        <div class="dd-field">
                            <textarea id="dd-insp-note-text">${esc(t.text || '')}</textarea>
                        </div>
                    </div>

                    ${renderTypographyControls({ ...t, fontSize: t.fontSize || 12 }, 'dd-insp-note')}

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Color</div>
                        ${renderSwatches(t.color || '#ffcc00', 'note-color')}
                    </div>

                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="dd-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22);">
                        <i class="fa-regular fa-trash-can"></i> Delete Note
                    </button>
                `;
                bindInspectorInputs();
                return;
            }
        }

        // Default Overview Inspector when nothing is selected (Clean, soothing, non-redundant)
        if (badge) badge.textContent = 'Canvas';
        body.innerHTML = `
            <div class="dd-summary-pill">
                <span><strong>${state.nodes.length}</strong> Nodes</span>
                <span>·</span>
                <span><strong>${state.edges.length}</strong> Links</span>
                <span>·</span>
                <span><strong>${state.zones.length}</strong> Zones</span>
            </div>

            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">
                    <span>Typography</span>
                    <button type="button" class="dd-insp-sec-link" id="dd-insp-apply-font-all" title="Apply this font to all existing elements">Apply to all</button>
                </div>
                <div class="dd-insp-row">
                    <label>Default Font</label>
                    <div class="dd-insp-row-control">
                        <select id="dd-insp-global-font">
                            ${renderFontOptionsHtml(state.defaultFont, false)}
                        </select>
                    </div>
                </div>
            </div>

            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">Insert Media</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                    <button type="button" class="dd-image-upload-btn" id="dd-insp-upload-img-btn">
                        <i class="fa-regular fa-image" style="color:var(--dd-cyan);"></i> Upload Image
                    </button>
                    <button type="button" class="dd-image-upload-btn" id="dd-insp-paste-img-btn">
                        <i class="fa-solid fa-paste" style="color:var(--dd-accent);"></i> Paste (Ctrl+V)
                    </button>
                </div>
                <div class="dd-url-insert-bar">
                    <i class="fa-solid fa-link dd-url-icon"></i>
                    <input type="text" id="dd-insp-img-url" class="dd-url-input" placeholder="Paste image URL (https://...)" spellcheck="false" autocomplete="off">
                    <button type="button" class="dd-url-btn" id="dd-insp-add-img-url" title="Insert image from URL">
                        <i class="fa-solid fa-plus"></i> Add
                    </button>
                </div>
            </div>

            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">Project File (.mantis-draw)</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                    <button type="button" class="dd-image-upload-btn" id="dd-insp-export-mantis">
                        <i class="fa-solid fa-download" style="color:#10b981;"></i> Save Project
                    </button>
                    <button type="button" class="dd-image-upload-btn" id="dd-insp-import-mantis">
                        <i class="fa-solid fa-upload" style="color:#38bdf8;"></i> Open Project
                    </button>
                </div>
            </div>
        `;
        bindInspectorInputs();
    };

    const bindTypographyHandlers = (item, prefix) => {
        document.getElementById(`${prefix}-font-family`)?.addEventListener('change', (ev) => {
            pushHistory();
            item.fontFamily = ev.target.value;
            saveToLocalStorage();
            requestRender();
        });
        document.getElementById(`${prefix}-font-size`)?.addEventListener('input', (ev) => {
            item.fontSize = Math.max(8, Math.min(48, Number(ev.target.value) || 12));
            saveToLocalStorage();
            requestRender();
        });
        document.getElementById(`${prefix}-font-bold`)?.addEventListener('click', (ev) => {
            pushHistory();
            item.fontBold = item.fontBold === false;
            ev.currentTarget.classList.toggle('active', item.fontBold !== false);
            saveToLocalStorage();
            requestRender();
        });
        document.getElementById(`${prefix}-font-italic`)?.addEventListener('click', (ev) => {
            pushHistory();
            item.fontItalic = !item.fontItalic;
            ev.currentTarget.classList.toggle('active', !!item.fontItalic);
            saveToLocalStorage();
            requestRender();
        });
    };

    const bindInspectorInputs = () => {
        const firstId = [...state.selectedIds][0];

        document.getElementById('dd-insp-export-mantis')?.addEventListener('click', () => exportProjectFile('mantis-draw'));
        document.getElementById('dd-insp-import-mantis')?.addEventListener('click', () => {
            document.getElementById('dd-project-file-input')?.click();
        });
        document.getElementById('dd-insp-upload-img-btn')?.addEventListener('click', () => {
            document.getElementById('dd-img-file-input')?.click();
        });
        document.getElementById('dd-insp-paste-img-btn')?.addEventListener('click', handlePasteFromClipboardButton);

        const globalFontInsp = document.getElementById('dd-insp-global-font');
        if (globalFontInsp) {
            globalFontInsp.addEventListener('change', (ev) => {
                pushHistory();
                state.defaultFont = ev.target.value;
                const topSel = document.getElementById('dd-global-font');
                if (topSel) topSel.value = state.defaultFont;
                saveToLocalStorage();
                requestRender();
            });
        }

        document.getElementById('dd-insp-apply-font-all')?.addEventListener('click', () => {
            pushHistory();
            state.nodes.forEach((n) => { n.fontFamily = state.defaultFont; });
            state.edges.forEach((e) => { e.fontFamily = state.defaultFont; });
            state.zones.forEach((z) => { z.fontFamily = state.defaultFont; });
            state.notes.forEach((t) => { t.fontFamily = state.defaultFont; });
            saveToLocalStorage();
            requestRender();
            showToast(`Applied ${state.defaultFont} to all diagram elements`);
        });

        document.getElementById('dd-insp-add-img-url')?.addEventListener('click', () => {
            const urlInp = document.getElementById('dd-insp-img-url');
            const val = (urlInp?.value || '').trim();
            if (!val) {
                showToast('Enter an image URL or data:image URI first', true);
                return;
            }
            insertImageFromSrc(val, 'Remote Image', state.lastMouseWorld, 200, 140);
            if (urlInp) urlInp.value = '';
        });

        document.getElementById('dd-insp-img-url')?.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter') {
                ev.preventDefault();
                document.getElementById('dd-insp-add-img-url')?.click();
            }
        });

        document.querySelectorAll('[data-dd-quick-dl]').forEach((btn) => {
            btn.addEventListener('click', () => exportPNG(btn.dataset.ddQuickDl));
        });

        // Node inputs
        if (state.selectedType === 'node' && firstId) {
            const n = state.nodes.find((it) => it.id === firstId);
            if (!n) return;
            bindTypographyHandlers(n, 'dd-insp-node');

            document.getElementById('dd-insp-step-num')?.addEventListener('input', (ev) => {
                n.label = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-step-dec')?.addEventListener('click', () => {
                pushHistory();
                const cur = parseInt(String(n.label).trim(), 10);
                const nextVal = isNaN(cur) ? 1 : Math.max(1, cur - 1);
                n.label = String(nextVal);
                const inp = document.getElementById('dd-insp-step-num');
                if (inp) inp.value = n.label;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-step-inc')?.addEventListener('click', () => {
                pushHistory();
                const cur = parseInt(String(n.label).trim(), 10);
                const nextVal = isNaN(cur) ? 2 : cur + 1;
                n.label = String(nextVal);
                const inp = document.getElementById('dd-insp-step-num');
                if (inp) inp.value = n.label;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-step-size')?.addEventListener('input', (ev) => {
                const sz = Math.max(20, Math.min(160, Number(ev.target.value) || 36));
                n.w = sz;
                n.h = sz;
                n.size = sz;
                saveToLocalStorage();
                requestRender();
            });
            document.querySelectorAll('[data-step-preset-size]').forEach((b) => {
                b.addEventListener('click', () => {
                    pushHistory();
                    const sz = Number(b.dataset.stepPresetSize) || 36;
                    n.w = sz;
                    n.h = sz;
                    n.size = sz;
                    saveToLocalStorage();
                    renderInspector();
                    requestRender();
                });
            });

            document.getElementById('dd-insp-node-label')?.addEventListener('input', (ev) => {
                n.label = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-node-sub')?.addEventListener('input', (ev) => {
                n.sub = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-node-w')?.addEventListener('input', (ev) => {
                n.w = Math.max(60, Math.min(900, Number(ev.target.value) || NODE_MIN_W));
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-node-h')?.addEventListener('input', (ev) => {
                n.h = Math.max(50, Math.min(900, Number(ev.target.value) || NODE_MIN_H));
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-img-frame')?.addEventListener('change', (ev) => {
                pushHistory();
                n.showFrame = ev.target.checked;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-img-caption')?.addEventListener('change', (ev) => {
                pushHistory();
                n.showCaption = ev.target.checked;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-replace-img')?.addEventListener('click', () => {
                const iconInput = document.getElementById('dd-node-icon-file-input');
                iconInput?.click();
            });
            document.getElementById('dd-insp-clear-img')?.addEventListener('click', () => {
                pushHistory();
                delete n.imageSrc;
                saveToLocalStorage();
                renderInspector();
                requestRender();
            });
            document.getElementById('dd-insp-node-status')?.addEventListener('change', (ev) => {
                pushHistory();
                n.status = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-node-step')?.addEventListener('input', (ev) => {
                n.step = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-node-type')?.addEventListener('change', (ev) => {
                pushHistory();
                n.type = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
        }

        // Edge inputs
        if (state.selectedType === 'edge' && firstId) {
            const e = state.edges.find((it) => it.id === firstId);
            if (!e) return;
            bindTypographyHandlers(e, 'dd-insp-edge');

            document.getElementById('dd-insp-edge-label')?.addEventListener('input', (ev) => {
                e.label = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-style')?.addEventListener('change', (ev) => {
                pushHistory();
                e.style = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-curve')?.addEventListener('change', (ev) => {
                pushHistory();
                e.curve = ev.target.value;
                saveToLocalStorage();
                renderInspector();
                requestRender();
            });
            document.getElementById('dd-insp-edge-step-offset')?.addEventListener('input', (ev) => {
                e.stepOffset = Number(ev.target.value) || 0;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-step-reset')?.addEventListener('click', () => {
                pushHistory();
                e.stepOffset = 0;
                const inp = document.getElementById('dd-insp-edge-step-offset');
                if (inp) inp.value = 0;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-step-sub')?.addEventListener('click', () => {
                pushHistory();
                e.stepOffset = (Number(e.stepOffset) || 0) - 40;
                const inp = document.getElementById('dd-insp-edge-step-offset');
                if (inp) inp.value = e.stepOffset;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-step-add')?.addEventListener('click', () => {
                pushHistory();
                e.stepOffset = (Number(e.stepOffset) || 0) + 40;
                const inp = document.getElementById('dd-insp-edge-step-offset');
                if (inp) inp.value = e.stepOffset;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-fromport')?.addEventListener('change', (ev) => {
                pushHistory();
                e.fromPort = ev.target.value === 'auto' ? null : ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-toport')?.addEventListener('change', (ev) => {
                pushHistory();
                e.toPort = ev.target.value === 'auto' ? null : ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-dir')?.addEventListener('change', (ev) => {
                pushHistory();
                e.dir = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-edge-width')?.addEventListener('input', (ev) => {
                e.width = Number(ev.target.value) || 2;
                saveToLocalStorage();
                requestRender();
            });
        }

        // Zone inputs
        if (state.selectedType === 'zone' && firstId) {
            const z = state.zones.find((it) => it.id === firstId);
            if (!z) return;
            bindTypographyHandlers(z, 'dd-insp-zone');

            document.getElementById('dd-insp-zone-label')?.addEventListener('input', (ev) => {
                z.label = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-zone-sub')?.addEventListener('input', (ev) => {
                z.sub = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('dd-insp-zone-style')?.addEventListener('change', (ev) => {
                pushHistory();
                z.style = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
        }

        // Note inputs
        if (state.selectedType === 'note' && firstId) {
            const t = state.notes.find((it) => it.id === firstId);
            if (!t) return;
            bindTypographyHandlers(t, 'dd-insp-note');

            document.getElementById('dd-insp-note-text')?.addEventListener('input', (ev) => {
                t.text = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
        }

        // Color swatches
        document.querySelectorAll('[data-dd-swatch]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const color = btn.dataset.ddSwatch;
                pushHistory();
                if (state.selectedType === 'node') {
                    state.nodes.forEach((n) => {
                        if (state.selectedIds.has(n.id)) n.color = color;
                    });
                } else if (state.selectedType === 'edge') {
                    state.edges.forEach((e) => {
                        if (state.selectedIds.has(e.id)) e.color = color;
                    });
                } else if (state.selectedType === 'zone') {
                    state.zones.forEach((z) => {
                        if (state.selectedIds.has(z.id)) z.color = color;
                    });
                } else if (state.selectedType === 'note') {
                    state.notes.forEach((t) => {
                        if (state.selectedIds.has(t.id)) t.color = color;
                    });
                }
                saveToLocalStorage();
                renderInspector();
                requestRender();
            });
        });

        document.getElementById('dd-insp-delete-btn')?.addEventListener('click', deleteSelected);
    };

    // =========================================================================
    // Actions: Add Node, Duplicate, Delete, Mode Switch
    // =========================================================================
    const setMode = (mode) => {
        state.mode = mode;
        const canvas = document.getElementById('dd-canvas');
        if (canvas) {
            canvas.className = `dd-canvas mode-${mode}`;
        }
        document.querySelectorAll('[data-dd-mode]').forEach((btn) => {
            btn.classList.toggle('active', btn.dataset.ddMode === mode);
        });
    };

    const updateToolbarButtons = () => {
        const undoBtn = document.getElementById('dd-btn-undo');
        const redoBtn = document.getElementById('dd-btn-redo');
        if (undoBtn) undoBtn.disabled = state.undoStack.length === 0;
        if (redoBtn) redoBtn.disabled = state.redoStack.length === 0;
    };

    const addNodeAt = (assetType, wx, wy) => {
        const asset = ALL_ASSETS_MAP.get(assetType);
        if (!asset) return;
        pushHistory();
        const isStep = asset.isStep || assetType === 'flow_step' || assetType === 'step_marker';
        const stepNum = isStep ? getNextStepNumber() : 1;
        const newNode = {
            id: uid(isStep ? 'step' : 'n'),
            type: asset.type,
            isStep: isStep,
            label: isStep ? String(stepNum) : asset.name,
            sub: isStep ? '' : (asset.sub || ''),
            x: snap(wx),
            y: snap(wy),
            w: isStep ? 36 : undefined,
            h: isStep ? 36 : undefined,
            size: isStep ? 36 : undefined,
            color: isStep ? (asset.color || '#ef4444') : asset.color,
            status: 'none',
            step: '',
            shape: isStep ? 'step' : 'card',
            fontFamily: 'default',
            fontSize: isStep ? 15 : 12.5,
            fontBold: true,
            fontItalic: false,
        };
        state.nodes.push(newNode);
        state.selectedType = 'node';
        state.selectedIds = new Set([newNode.id]);
        saveToLocalStorage();
        renderInspector();
        requestRender();
    };

    const deleteSelected = () => {
        if (!state.selectedIds.size) return;
        pushHistory();
        if (state.selectedType === 'node') {
            const delSet = new Set(state.selectedIds);
            state.nodes = state.nodes.filter((n) => !delSet.has(n.id));
            state.edges = state.edges.filter((e) => !delSet.has(e.from) && !delSet.has(e.to));
        } else if (state.selectedType === 'edge') {
            state.edges = state.edges.filter((e) => !state.selectedIds.has(e.id));
        } else if (state.selectedType === 'zone') {
            state.zones = state.zones.filter((z) => !state.selectedIds.has(z.id));
        } else if (state.selectedType === 'note') {
            state.notes = state.notes.filter((t) => !state.selectedIds.has(t.id));
        }
        state.selectedIds.clear();
        state.selectedType = null;
        saveToLocalStorage();
        renderInspector();
        requestRender();
    };

    const duplicateSelected = () => {
        if (!state.selectedIds.size) return;
        pushHistory();
        const newIds = new Set();
        if (state.selectedType === 'node') {
            state.nodes.forEach((n) => {
                if (state.selectedIds.has(n.id)) {
                    const isStep = n.isStep || n.type === 'flow_step' || n.type === 'step_marker' || n.shape === 'step';
                    const copy = { ...JSON.parse(JSON.stringify(n)), id: uid(isStep ? 'step' : 'n'), x: n.x + 30, y: n.y + 30 };
                    if (isStep) {
                        copy.label = String(getNextStepNumber());
                    }
                    state.nodes.push(copy);
                    newIds.add(copy.id);
                }
            });
        } else if (state.selectedType === 'zone') {
            state.zones.forEach((z) => {
                if (state.selectedIds.has(z.id)) {
                    const copy = { ...JSON.parse(JSON.stringify(z)), id: uid('z'), x: z.x + 30, y: z.y + 30 };
                    state.zones.push(copy);
                    newIds.add(copy.id);
                }
            });
        } else if (state.selectedType === 'note') {
            state.notes.forEach((t) => {
                if (state.selectedIds.has(t.id)) {
                    const copy = { ...JSON.parse(JSON.stringify(t)), id: uid('t'), x: t.x + 25, y: t.y + 25 };
                    state.notes.push(copy);
                    newIds.add(copy.id);
                }
            });
        }
        if (newIds.size) {
            state.selectedIds = newIds;
            saveToLocalStorage();
            renderInspector();
            requestRender();
            showToast('Duplicated selection');
        }
    };

    // =========================================================================
    // Event Listeners
    // =========================================================================
    const bindStudioEvents = () => {
        const pane = document.getElementById('diagram-draw-pane');
        const canvas = document.getElementById('dd-canvas');
        const wrap = document.getElementById('dd-canvas-wrap');
        if (!pane || !canvas || !wrap) return;

        // Editable diagram title in topbar
        document.getElementById('dd-diagram-title-input')?.addEventListener('input', (ev) => {
            state.title = ev.target.value;
            saveToLocalStorage();
        });

        // Mode buttons
        pane.querySelectorAll('[data-dd-mode]').forEach((btn) => {
            btn.addEventListener('click', () => setMode(btn.dataset.ddMode));
        });

        // Global Font selector in Topbar
        document.getElementById('dd-global-font')?.addEventListener('change', (ev) => {
            pushHistory();
            state.defaultFont = ev.target.value;
            saveToLocalStorage();
            renderInspector();
            requestRender();
            showToast(`Default font set to ${state.defaultFont}`);
        });

        // Insert Image buttons & file inputs
        const imgInput = document.getElementById('dd-img-file-input');
        const nodeIconInput = document.getElementById('dd-node-icon-file-input');
        const triggerInsertImage = () => imgInput?.click();

        document.getElementById('dd-btn-insert-img')?.addEventListener('click', triggerInsertImage);
        document.getElementById('dd-palette-insert-img')?.addEventListener('click', triggerInsertImage);
        document.getElementById('dd-palette-paste-img')?.addEventListener('click', handlePasteFromClipboardButton);

        imgInput?.addEventListener('change', (ev) => {
            const files = Array.from(ev.target.files || []);
            const rect = canvas.getBoundingClientRect();
            const baseWorld = screenToWorld(rect.width / 2, rect.height / 2);
            files.forEach((f, idx) => {
                readImageFileAndInsert(f, { x: baseWorld.x + idx * 35, y: baseWorld.y + idx * 35 });
            });
            ev.target.value = '';
        });

        nodeIconInput?.addEventListener('change', (ev) => {
            const file = ev.target.files?.[0];
            const firstId = [...state.selectedIds][0];
            const targetNode = state.selectedType === 'node' ? state.nodes.find((n) => n.id === firstId) : null;
            if (file && targetNode) {
                readImageFileAndInsert(file, null, targetNode);
            }
            ev.target.value = '';
        });

        // Copy / Paste / Undo / Redo / Delete
        document.getElementById('dd-btn-copy')?.addEventListener('click', copySelectedToClipboard);
        document.getElementById('dd-btn-paste')?.addEventListener('click', handlePasteFromClipboardButton);
        document.getElementById('dd-btn-undo')?.addEventListener('click', undo);
        document.getElementById('dd-btn-redo')?.addEventListener('click', redo);
        document.getElementById('dd-btn-delete')?.addEventListener('click', deleteSelected);

        // Collapse / Expand Left Assets Sidebar & Right Properties Inspector Bar
        const setPaletteCollapsed = (collapsed) => {
            state.paletteCollapsed = !!collapsed;
            const ws = document.getElementById('dd-workspace');
            if (ws) ws.classList.toggle('palette-collapsed', state.paletteCollapsed);
            setTimeout(() => requestRender(), 30);
        };
        document.getElementById('dd-btn-collapse-palette')?.addEventListener('click', () => setPaletteCollapsed(true));
        document.getElementById('dd-btn-expand-palette')?.addEventListener('click', () => setPaletteCollapsed(false));

        const setInspectorCollapsed = (collapsed) => {
            state.inspectorCollapsed = !!collapsed;
            const ws = document.getElementById('dd-workspace');
            if (ws) ws.classList.toggle('inspector-collapsed', state.inspectorCollapsed);
            setTimeout(() => requestRender(), 30);
        };
        document.getElementById('dd-btn-collapse-inspector')?.addEventListener('click', () => setInspectorCollapsed(true));
        document.getElementById('dd-btn-expand-inspector')?.addEventListener('click', () => setInspectorCollapsed(false));
        document.getElementById('dd-btn-toggle-inspector')?.addEventListener('click', () => setInspectorCollapsed(!state.inspectorCollapsed));

        // Direct PNG Export Buttons (Transparent, Dark, White)
        document.getElementById('dd-dl-png-transparent')?.addEventListener('click', () => exportPNG('transparent'));
        document.getElementById('dd-dl-png-dark')?.addEventListener('click', () => exportPNG('dark'));
        document.getElementById('dd-dl-png-white')?.addEventListener('click', () => exportPNG('white'));

        // Dropdown toggles
        const closeDropdowns = () => {
            pane.querySelectorAll('.dd-dropdown.open').forEach((d) => d.classList.remove('open'));
        };
        document.getElementById('dd-btn-templates')?.addEventListener('click', (e) => {
            e.stopPropagation();
            const dd = document.getElementById('dd-templates-dropdown');
            const wasOpen = dd?.classList.contains('open');
            closeDropdowns();
            if (!wasOpen) dd?.classList.add('open');
        });
        document.getElementById('dd-btn-svg-menu')?.addEventListener('click', (e) => {
            e.stopPropagation();
            const dd = document.getElementById('dd-svg-dropdown');
            const wasOpen = dd?.classList.contains('open');
            closeDropdowns();
            if (!wasOpen) dd?.classList.add('open');
        });
        document.addEventListener('click', closeDropdowns);

        // Project File Export / Import (.mantis-draw & .json)
        const projectFileInput = document.getElementById('dd-project-file-input');
        document.getElementById('dd-menu-export-mantis')?.addEventListener('click', () => {
            exportProjectFile('mantis-draw');
            closeDropdowns();
        });
        document.getElementById('dd-menu-export-json')?.addEventListener('click', () => {
            exportProjectFile('json');
            closeDropdowns();
        });
        document.getElementById('dd-menu-import-file')?.addEventListener('click', () => {
            projectFileInput?.click();
            closeDropdowns();
        });
        projectFileInput?.addEventListener('change', (ev) => {
            const file = ev.target.files?.[0];
            if (file) importProjectFile(file);
            ev.target.value = '';
        });

        // SVG & Copy PNG Exports
        pane.querySelectorAll('[data-dd-svg]').forEach((btn) => {
            btn.addEventListener('click', () => {
                exportSVG(btn.dataset.ddSvg);
                closeDropdowns();
            });
        });
        pane.querySelectorAll('[data-dd-copy-png]').forEach((btn) => {
            btn.addEventListener('click', () => {
                copyDiagramPNGToClipboard(btn.dataset.ddCopyPng);
                closeDropdowns();
            });
        });

        // Specialized Templates
        pane.querySelectorAll('[data-dd-template]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const key = btn.dataset.ddTemplate;
                if (TEMPLATES[key]) {
                    pushHistory();
                    applySnapshot(TEMPLATES[key]());
                    setTimeout(fitToScreen, 30);
                    showToast(`Loaded template: ${state.title}`);
                }
                closeDropdowns();
            });
        });

        document.getElementById('dd-btn-clear-all')?.addEventListener('click', () => {
            pushHistory();
            applySnapshot({ title: 'Untitled Threat Diagram', defaultFont: state.defaultFont, zones: [], nodes: [], edges: [], notes: [] });
            closeDropdowns();
            showToast('Cleared canvas');
        });

        // Live Preview BG Switcher (Dark / White / Transparent)
        pane.querySelectorAll('[data-dd-bg]').forEach((btn) => {
            btn.addEventListener('click', () => {
                state.canvasTheme = btn.dataset.ddBg;
                wrap.className = `dd-canvas-wrap theme-${state.canvasTheme}`;
                pane.querySelectorAll('[data-dd-bg]').forEach((b) => b.classList.toggle('active', b === btn));
                requestRender();
            });
        });

        // Snap & Animate checkboxes
        document.getElementById('dd-chk-snap')?.addEventListener('change', (e) => {
            state.snapToGrid = e.target.checked;
        });
        document.getElementById('dd-chk-anim')?.addEventListener('change', (e) => {
            state.animateFlows = e.target.checked;
            requestRender();
        });

        // Zoom buttons
        document.getElementById('dd-zoom-in')?.addEventListener('click', () => {
            state.zoom = Math.min(3.0, state.zoom * 1.15);
            requestRender();
        });
        document.getElementById('dd-zoom-out')?.addEventListener('click', () => {
            state.zoom = Math.max(0.15, state.zoom / 1.15);
            requestRender();
        });
        document.getElementById('dd-zoom-fit')?.addEventListener('click', fitToScreen);

        // Palette search, discipline filter pills & category collapse & drag/click
        document.getElementById('dd-asset-search')?.addEventListener('input', (ev) => {
            state.searchQuery = ev.target.value;
            renderPaletteList();
        });
        document.getElementById('dd-cat-pills')?.addEventListener('click', (ev) => {
            const pill = ev.target.closest('[data-dd-cat-pill]');
            if (!pill) return;
            state.activeCatFilter = pill.dataset.ddCatPill;
            pane.querySelectorAll('[data-dd-cat-pill]').forEach((b) => b.classList.toggle('active', b === pill));
            renderPaletteList();
        });
        const paletteList = document.getElementById('dd-palette-list');
        paletteList?.addEventListener('click', (ev) => {
            const catBtn = ev.target.closest('[data-cat-toggle]');
            if (catBtn) {
                const cid = catBtn.dataset.catToggle;
                if (state.collapsedCats.has(cid)) state.collapsedCats.delete(cid);
                else state.collapsedCats.add(cid);
                renderPaletteList();
                return;
            }
            const assetBtn = ev.target.closest('[data-asset-type]');
            if (assetBtn) {
                const rect = canvas.getBoundingClientRect();
                const center = screenToWorld(rect.width / 2 + (Math.random() - 0.5) * 80, rect.height / 2 + (Math.random() - 0.5) * 80);
                addNodeAt(assetBtn.dataset.assetType, center.x, center.y);
            }
        });
        paletteList?.addEventListener('dragstart', (ev) => {
            const assetBtn = ev.target.closest('[data-asset-type]');
            if (assetBtn && ev.dataTransfer) {
                ev.dataTransfer.setData('text/plain', assetBtn.dataset.assetType);
            }
        });

        // Drag & Drop onto Canvas (Assets, Images, and .mantis-draw / .json Project Files)
        canvas.addEventListener('dragover', (ev) => {
            ev.preventDefault();
            wrap.classList.add('drag-over');
        });
        canvas.addEventListener('dragleave', () => {
            wrap.classList.remove('drag-over');
        });
        canvas.addEventListener('drop', (ev) => {
            ev.preventDefault();
            wrap.classList.remove('drag-over');
            const rect = canvas.getBoundingClientRect();
            const pt = screenToWorld(ev.clientX - rect.left, ev.clientY - rect.top);

            const files = Array.from(ev.dataTransfer?.files || []);
            const projectFile = files.find((f) => /\.(mantis-draw|json)$/i.test(f.name || ''));
            if (projectFile) {
                importProjectFile(projectFile);
                return;
            }

            const imgFiles = files.filter((f) => f.type.startsWith('image/'));
            if (imgFiles.length > 0) {
                imgFiles.forEach((f, idx) => {
                    readImageFileAndInsert(f, { x: pt.x + idx * 35, y: pt.y + idx * 35 });
                });
                return;
            }

            const assetType = ev.dataTransfer?.getData('text/plain');
            if (assetType && ALL_ASSETS_MAP.has(assetType)) {
                addNodeAt(assetType, pt.x, pt.y);
            }
        });

        // System Clipboard Paste Event (`Ctrl+V`)
        window.addEventListener('paste', (ev) => {
            const p = document.getElementById('diagram-draw-pane');
            if (!p || p.style.display === 'none') return;
            const tag = document.activeElement?.tagName;
            if (tag === 'INPUT' || tag === 'TEXTAREA') return;

            const items = Array.from(ev.clipboardData?.items || []);
            const imgItem = items.find((it) => it.type.startsWith('image/'));
            if (imgItem) {
                ev.preventDefault();
                const file = imgItem.getAsFile();
                if (file) {
                    readImageFileAndInsert(file, state.lastMouseWorld);
                    return;
                }
            }

            const pastedText = (ev.clipboardData?.getData('text/plain') || '').trim();
            if (pastedText && (pastedText.startsWith('data:image/') || /^https?:\/\/.+\.(png|jpe?g|gif|webp|svg)(\?.*)?$/i.test(pastedText))) {
                ev.preventDefault();
                insertImageFromSrc(pastedText, 'Pasted Image', state.lastMouseWorld, 200, 140);
                return;
            }

            if (state.clipboard && state.clipboard.items?.length) {
                ev.preventDefault();
                pasteInternalClipboard();
            }
        });

        // Canvas Mouse / Pointer Interactions
        canvas.addEventListener('mousedown', (ev) => {
            const rect = canvas.getBoundingClientRect();
            const sx = ev.clientX - rect.left;
            const sy = ev.clientY - rect.top;
            const wpt = screenToWorld(sx, sy);
            state.lastMouseWorld = wpt;

            if (ev.button === 1 || state.spacePressed || state.mode === 'pan') {
                state.isPanning = true;
                state.dragStartScreen = { x: ev.clientX - state.panX, y: ev.clientY - state.panY };
                return;
            }
            if (ev.button !== 0) return;

            if (state.mode === 'step') {
                pushHistory();
                const nextStepNum = getNextStepNumber();
                const newStepNode = {
                    id: uid('step'),
                    type: 'flow_step',
                    isStep: true,
                    label: String(nextStepNum),
                    sub: '',
                    x: snap(wpt.x),
                    y: snap(wpt.y),
                    w: 36,
                    h: 36,
                    size: 36,
                    color: '#ef4444',
                    status: 'none',
                    step: '',
                    shape: 'step',
                    fontFamily: 'default',
                    fontSize: 15,
                    fontBold: true,
                    fontItalic: false,
                };
                state.nodes.push(newStepNode);
                state.selectedType = 'node';
                state.selectedIds = new Set([newStepNode.id]);
                if (!ev.shiftKey) {
                    setMode('select');
                }
                saveToLocalStorage();
                renderInspector();
                requestRender();
                return;
            }

            if (state.mode === 'text') {
                pushHistory();
                const newNote = {
                    id: uid('t'),
                    text: 'T1059 Command Execution / Analyst Note',
                    x: snap(wpt.x),
                    y: snap(wpt.y),
                    color: '#ffcc00',
                    fontFamily: 'default',
                    fontSize: 12,
                    fontBold: true,
                    fontItalic: false,
                };
                state.notes.push(newNote);
                state.selectedType = 'note';
                state.selectedIds = new Set([newNote.id]);
                setMode('select');
                saveToLocalStorage();
                renderInspector();
                requestRender();
                return;
            }

            if (state.mode === 'zone') {
                state.drawingZone = { x1: snap(wpt.x), y1: snap(wpt.y), x2: snap(wpt.x), y2: snap(wpt.y) };
                requestRender();
                return;
            }

            const nodeResizeHit = hitTestNodeResize(wpt.x, wpt.y);
            if (nodeResizeHit) {
                const sz = getNodeSize(nodeResizeHit);
                pushHistory();
                state.resizingNode = { node: nodeResizeHit, startW: sz.w, startH: sz.h, sx: wpt.x, sy: wpt.y };
                return;
            }

            const endHandleHit = hitTestEdgeEndHandle(wpt.x, wpt.y);
            if (endHandleHit) {
                pushHistory();
                state.draggingEdgeEnd = { edge: endHandleHit.edge, end: endHandleHit.end, x: wpt.x, y: wpt.y };
                requestRender();
                return;
            }

            const stepHandleHit = hitTestEdgeStepHandle(wpt.x, wpt.y);
            if (stepHandleHit) {
                pushHistory();
                state.draggingEdgeStep = {
                    edge: stepHandleHit.edge,
                    handle: stepHandleHit.handle,
                    startOffset: Number(stepHandleHit.edge.stepOffset) || 0,
                    sx: wpt.x,
                    sy: wpt.y,
                };
                requestRender();
                return;
            }

            const portHit = hitTestPort(wpt.x, wpt.y);
            if (state.mode === 'connect' || portHit) {
                const sourceNode = portHit ? portHit.node : hitTestNode(wpt.x, wpt.y);
                if (sourceNode) {
                    state.connectingFrom = {
                        nodeId: sourceNode.id,
                        side: portHit ? portHit.port.side : null,
                        x1: portHit ? portHit.port.x : sourceNode.x,
                        y1: portHit ? portHit.port.y : sourceNode.y,
                        x2: wpt.x,
                        y2: wpt.y,
                    };
                    requestRender();
                    return;
                }
            }

            const nodeHit = hitTestNode(wpt.x, wpt.y);
            if (nodeHit) {
                if (ev.shiftKey && state.selectedType === 'node') {
                    if (state.selectedIds.has(nodeHit.id)) state.selectedIds.delete(nodeHit.id);
                    else state.selectedIds.add(nodeHit.id);
                } else if (!state.selectedIds.has(nodeHit.id) || state.selectedType !== 'node') {
                    state.selectedType = 'node';
                    state.selectedIds = new Set([nodeHit.id]);
                }
                pushHistory();
                state.dragStartWorld = wpt;
                state.draggingItems = state.nodes
                    .filter((n) => state.selectedIds.has(n.id))
                    .map((n) => ({ item: n, ox: n.x, oy: n.y }));
                renderInspector();
                requestRender();
                return;
            }

            const noteHit = hitTestNote(wpt.x, wpt.y);
            if (noteHit) {
                state.selectedType = 'note';
                state.selectedIds = new Set([noteHit.id]);
                pushHistory();
                state.dragStartWorld = wpt;
                state.draggingItems = [{ item: noteHit, ox: noteHit.x, oy: noteHit.y }];
                renderInspector();
                requestRender();
                return;
            }

            const edgeHit = hitTestEdge(wpt.x, wpt.y);
            if (edgeHit) {
                state.selectedType = 'edge';
                state.selectedIds = new Set([edgeHit.id]);
                renderInspector();
                requestRender();
                return;
            }

            const zoneResize = hitTestZoneResize(wpt.x, wpt.y);
            if (zoneResize && state.selectedType === 'zone' && state.selectedIds.has(zoneResize.id)) {
                pushHistory();
                state.resizingZone = { zone: zoneResize, startW: zoneResize.w, startH: zoneResize.h, sx: wpt.x, sy: wpt.y };
                return;
            }

            const zoneHit = hitTestZone(wpt.x, wpt.y);
            if (zoneHit) {
                state.selectedType = 'zone';
                state.selectedIds = new Set([zoneHit.id]);
                pushHistory();
                state.dragStartWorld = wpt;
                state.draggingItems = [{ item: zoneHit, ox: zoneHit.x, oy: zoneHit.y }];
                renderInspector();
                requestRender();
                return;
            }

            state.selectedIds.clear();
            state.selectedType = null;
            state.marquee = { x1: wpt.x, y1: wpt.y, x2: wpt.x, y2: wpt.y };
            renderInspector();
            requestRender();
        });

        window.addEventListener('mousemove', (ev) => {
            const rect = canvas.getBoundingClientRect();
            const sx = ev.clientX - rect.left;
            const sy = ev.clientY - rect.top;
            const wpt = screenToWorld(sx, sy);
            if (ev.target === canvas) {
                state.lastMouseWorld = wpt;
            }

            if (state.isPanning && state.dragStartScreen) {
                state.panX = ev.clientX - state.dragStartScreen.x;
                state.panY = ev.clientY - state.dragStartScreen.y;
                requestRender();
                return;
            }

            if (state.drawingZone) {
                state.drawingZone.x2 = snap(wpt.x);
                state.drawingZone.y2 = snap(wpt.y);
                requestRender();
                return;
            }

            if (state.draggingEdgeEnd) {
                state.draggingEdgeEnd.x = wpt.x;
                state.draggingEdgeEnd.y = wpt.y;
                requestRender();
                return;
            }

            if (state.draggingEdgeStep) {
                const s = state.draggingEdgeStep;
                const delta = s.handle.axis === 'x' ? (wpt.x - s.sx) : (wpt.y - s.sy);
                let newOffset = Math.round(s.startOffset + delta);
                if (state.snapToGrid) {
                    newOffset = Math.round(newOffset / 10) * 10;
                }
                s.edge.stepOffset = newOffset;
                const inp = document.getElementById('dd-insp-edge-step-offset');
                if (inp) inp.value = newOffset;
                requestRender();
                return;
            }

            if (state.connectingFrom) {
                state.connectingFrom.x2 = wpt.x;
                state.connectingFrom.y2 = wpt.y;
                requestRender();
                return;
            }

            if (state.resizingNode) {
                const rn = state.resizingNode;
                rn.node.w = Math.max(70, snap(rn.startW + (wpt.x - rn.sx) * 2));
                rn.node.h = Math.max(50, snap(rn.startH + (wpt.y - rn.sy) * 2));
                const wInp = document.getElementById('dd-insp-node-w');
                const hInp = document.getElementById('dd-insp-node-h');
                if (wInp) wInp.value = Math.round(rn.node.w);
                if (hInp) hInp.value = Math.round(rn.node.h);
                saveToLocalStorage();
                requestRender();
                return;
            }

            if (state.resizingZone) {
                const rz = state.resizingZone;
                rz.zone.w = Math.max(140, snap(rz.startW + (wpt.x - rz.sx)));
                rz.zone.h = Math.max(100, snap(rz.startH + (wpt.y - rz.sy)));
                saveToLocalStorage();
                requestRender();
                return;
            }

            if (state.draggingItems && state.dragStartWorld) {
                const dx = wpt.x - state.dragStartWorld.x;
                const dy = wpt.y - state.dragStartWorld.y;
                state.draggingItems.forEach(({ item, ox, oy }) => {
                    item.x = snap(ox + dx);
                    item.y = snap(oy + dy);
                });
                saveToLocalStorage();
                requestRender();
                return;
            }

            if (state.marquee) {
                state.marquee.x2 = wpt.x;
                state.marquee.y2 = wpt.y;
                requestRender();
                return;
            }

            if (ev.target === canvas) {
                const hovered = hitTestNode(wpt.x, wpt.y);
                const hid = hovered ? hovered.id : null;
                if (hid !== state.hoveredNodeId) {
                    state.hoveredNodeId = hid;
                    requestRender();
                }

                const hoverStepHandle = hitTestEdgeStepHandle(wpt.x, wpt.y);
                if (hoverStepHandle) {
                    canvas.style.cursor = hoverStepHandle.handle.axis === 'x' ? 'ew-resize' : 'ns-resize';
                } else if (!state.isPanning && state.mode === 'select' && !state.draggingItems && !state.resizingNode && !state.resizingZone && !state.draggingEdgeEnd && !state.draggingEdgeStep) {
                    canvas.style.cursor = '';
                }
            }
        });

        window.addEventListener('mouseup', (ev) => {
            if (state.isPanning) {
                state.isPanning = false;
                state.dragStartScreen = null;
                return;
            }

            if (state.draggingEdgeStep) {
                state.draggingEdgeStep = null;
                saveToLocalStorage();
                renderInspector();
                requestRender();
                return;
            }

            if (state.drawingZone) {
                const dz = state.drawingZone;
                state.drawingZone = null;
                const x = Math.min(dz.x1, dz.x2);
                const y = Math.min(dz.y1, dz.y2);
                const w = Math.max(200, Math.abs(dz.x2 - dz.x1));
                const h = Math.max(140, Math.abs(dz.y2 - dz.y1));
                pushHistory();
                const newZone = {
                    id: uid('z'),
                    label: 'NEW SECURITY ZONE',
                    sub: '10.0.0.0/24',
                    x,
                    y,
                    w,
                    h,
                    color: '#38bdf8',
                    style: 'dashed',
                    opacity: 0.06,
                    fontFamily: 'default',
                    fontSize: 11,
                    fontBold: true,
                    fontItalic: false,
                };
                state.zones.push(newZone);
                state.selectedType = 'zone';
                state.selectedIds = new Set([newZone.id]);
                setMode('select');
                saveToLocalStorage();
                renderInspector();
                requestRender();
                return;
            }

            if (state.draggingEdgeEnd) {
                const de = state.draggingEdgeEnd;
                state.draggingEdgeEnd = null;
                const drect = canvas.getBoundingClientRect();
                const dwpt = screenToWorld(ev.clientX - drect.left, ev.clientY - drect.top);
                const dPort = hitTestPort(dwpt.x, dwpt.y);
                const dNode = dPort ? dPort.node : hitTestNode(dwpt.x, dwpt.y);
                if (dNode) {
                    const otherId = de.end === 'to' ? de.edge.from : de.edge.to;
                    if (dNode.id !== otherId) {
                        if (de.end === 'to') {
                            de.edge.to = dNode.id;
                            de.edge.toPort = dPort ? dPort.port.side : null;
                        } else {
                            de.edge.from = dNode.id;
                            de.edge.fromPort = dPort ? dPort.port.side : null;
                        }
                        saveToLocalStorage();
                        renderInspector();
                    }
                }
                requestRender();
                return;
            }

            if (state.connectingFrom) {
                const rect = canvas.getBoundingClientRect();
                const wpt = screenToWorld(ev.clientX - rect.left, ev.clientY - rect.top);
                const targetPort = hitTestPort(wpt.x, wpt.y);
                const targetNode = targetPort ? targetPort.node : hitTestNode(wpt.x, wpt.y);
                const fromId = state.connectingFrom.nodeId;
                const fromSide = state.connectingFrom.side || null;
                state.connectingFrom = null;
                if (targetNode && targetNode.id !== fromId) {
                    pushHistory();
                    const newEdge = {
                        id: uid('e'),
                        from: fromId,
                        to: targetNode.id,
                        fromPort: fromSide,
                        toPort: targetPort ? targetPort.port.side : null,
                        label: 'HTTPS :443',
                        color: state.canvasTheme === 'white' ? '#0f172a' : '#ffffff',
                        style: 'solid',
                        curve: 'bezier',
                        dir: 'forward',
                        width: 2,
                        fontFamily: 'default',
                        fontSize: 10.5,
                        fontBold: true,
                        fontItalic: false,
                    };
                    state.edges.push(newEdge);
                    state.selectedType = 'edge';
                    state.selectedIds = new Set([newEdge.id]);
                    saveToLocalStorage();
                    renderInspector();
                }
                requestRender();
                return;
            }

            if (state.marquee) {
                const m = state.marquee;
                state.marquee = null;
                const minX = Math.min(m.x1, m.x2);
                const maxX = Math.max(m.x1, m.x2);
                const minY = Math.min(m.y1, m.y2);
                const maxY = Math.max(m.y1, m.y2);
                if (maxX - minX > 8 || maxY - minY > 8) {
                    const hits = state.nodes.filter((n) => n.x >= minX && n.x <= maxX && n.y >= minY && n.y <= maxY);
                    if (hits.length) {
                        state.selectedType = 'node';
                        state.selectedIds = new Set(hits.map((n) => n.id));
                        renderInspector();
                    }
                }
                requestRender();
            }

            state.draggingItems = null;
            state.resizingZone = null;
            state.resizingNode = null;
            state.dragStartWorld = null;
        });

        canvas.addEventListener('dblclick', (ev) => {
            const rect = canvas.getBoundingClientRect();
            const wpt = screenToWorld(ev.clientX - rect.left, ev.clientY - rect.top);
            const hit = hitTestNode(wpt.x, wpt.y) || hitTestEdge(wpt.x, wpt.y) || hitTestZone(wpt.x, wpt.y) || hitTestNote(wpt.x, wpt.y);
            if (hit) {
                const isStepNode = hit.isStep || hit.type === 'flow_step' || hit.type === 'step_marker' || hit.shape === 'step';
                if (isStepNode) {
                    const nextVal = prompt('Edit Step Number (1 to ∞) or Label:', hit.label || '1');
                    if (nextVal !== null && nextVal.trim() !== '') {
                        pushHistory();
                        hit.label = nextVal.trim();
                        saveToLocalStorage();
                        renderInspector();
                        requestRender();
                        return;
                    }
                }
                if (state.inspectorCollapsed) {
                    setInspectorCollapsed(false);
                }
                const inp = document.querySelector('#dd-inspector-body input[type="text"], #dd-inspector-body textarea');
                if (inp) {
                    inp.focus();
                    inp.select();
                }
            }
        });

        canvas.addEventListener('wheel', (ev) => {
            ev.preventDefault();
            const rect = canvas.getBoundingClientRect();
            const mx = ev.clientX - rect.left;
            const my = ev.clientY - rect.top;
            const before = screenToWorld(mx, my);
            const factor = ev.deltaY < 0 ? 1.1 : 0.9;
            state.zoom = Math.max(0.15, Math.min(3.0, state.zoom * factor));
            state.panX = mx - before.x * state.zoom;
            state.panY = my - before.y * state.zoom;
            requestRender();
        }, { passive: false });

        window.addEventListener('keydown', (ev) => {
            const p = document.getElementById('diagram-draw-pane');
            if (!p || p.style.display === 'none') return;
            const tag = document.activeElement?.tagName;
            if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

            if (ev.code === 'Space') {
                state.spacePressed = true;
                canvas.classList.add('mode-pan');
                return;
            }
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's') {
                ev.preventDefault();
                exportProjectFile('mantis-draw');
                return;
            }
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'c') {
                ev.preventDefault();
                copySelectedToClipboard();
                return;
            }
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'z') {
                ev.preventDefault();
                undo();
                return;
            }
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'y') {
                ev.preventDefault();
                redo();
                return;
            }
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'd') {
                ev.preventDefault();
                duplicateSelected();
                return;
            }
            if (ev.key === 'Delete' || ev.key === 'Backspace') {
                ev.preventDefault();
                deleteSelected();
                return;
            }
            const k = ev.key.toLowerCase();
            if (k === 'v') setMode('select');
            else if (k === 'c') setMode('connect');
            else if (k === 'z') setMode('zone');
            else if (k === 't') setMode('text');
            else if (k === 's') setMode('step');
            else if (k === 'h') setMode('pan');
            else if (k === 'i') document.getElementById('dd-img-file-input')?.click();
        });

        window.addEventListener('keyup', (ev) => {
            if (ev.code === 'Space') {
                state.spacePressed = false;
                if (state.mode !== 'pan') {
                    canvas.classList.remove('mode-pan');
                }
            }
        });

        window.addEventListener('resize', () => {
            const p = document.getElementById('diagram-draw-pane');
            if (p && p.style.display !== 'none') requestRender();
        });

        if (typeof ResizeObserver !== 'undefined') {
            const ro = new ResizeObserver(() => {
                const p = document.getElementById('diagram-draw-pane');
                if (p && p.style.display !== 'none') requestRender();
            });
            ro.observe(wrap);
        }
    };

    // =========================================================================
    // Public Entrypoint called when user clicks "Diagram Draw" in Sidebar
    // =========================================================================
    window.openDiagramDraw = () => {
        if (!state.initialized) {
            state.initialized = true;
            let loaded = null;
            try {
                const raw = localStorage.getItem(STORAGE_KEY);
                if (raw) loaded = JSON.parse(raw);
            } catch (_) {}

            if (loaded && (loaded.nodes?.length || loaded.zones?.length)) {
                applySnapshot(loaded);
            } else {
                applySnapshot(TEMPLATES.ransomware());
            }
            renderStudioShell();
            startAnimationLoop();
            setTimeout(fitToScreen, 60);
        } else {
            setTimeout(() => {
                requestRender();
            }, 20);
        }
    };

    window.__diagramDraw = {
        state,
        applySnapshot,
        pushHistory,
        renderInspector,
        requestRender,
        fitToScreen,
        getEdgeStepHandle,
        hitTestEdgeStepHandle,
    };
})();
