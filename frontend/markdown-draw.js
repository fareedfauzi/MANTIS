/**
 * MANTIS Markdown Viewer & Live Studio
 * Inspired by StackEdit (https://github.com/benweet/stackedit)
 * Features:
 * - 3-View Switcher: Split (Side-by-Side), Editor Only, Preview Only with Resizable Draggable Splitter
 * - Live GFM Markdown parsing with GFM tables, checklists, GitHub alert callouts, and code blocks
 * - Robust Syntax Highlighting (Highlight.js + built-in cyber fallback) strictly formatted with JetBrains Mono
 * - Embedded Mermaid.js diagram support inside ```mermaid code blocks with asynchronous rendering & error diagnostics
 * - Export to PDF (Print-ready document with @media print styling), Download as .md, Download as .html, Copy MD/HTML
 * - Rapid Formatting Toolbar (H1-H3, Bold, Italic, Strikethrough, Code, Table, Link, Image, Task list, Alerts)
 * - 4 Pre-built Cyber Threat Intelligence, DFIR, SOC SOP, and Malware Analysis Presets
 * - Synchronized Scrolling between editor and preview
 * - Line numbers gutter, Tab key indentation, and Drag & Drop file import
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'mantis_markdown_viewer_v1';
    const MARKED_CDN = 'https://cdn.jsdelivr.net/npm/marked/marked.min.js';
    const MERMAID_CDN = 'https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js';
    const HLJS_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js';

    const PRESETS = {
        'dfir-postmortem': {
            title: 'DFIR Incident Response & Post-Mortem Report',
            category: 'Incident Response',
            desc: 'Comprehensive post-mortem report covering initial access, containment, timeline, and remediation.',
            badge: 'INCIDENT',
            markdown: `# DFIR Incident Response & Post-Mortem Report
**Incident ID:** INC-2026-0842  
**Target Entity:** MANTIS Core Payment Processing Cluster  
**Severity:** Critical (SEV-1) | **Lead Responder:** Senior DFIR Specialist  
**Status:** Contained & Remediated  

---

> [!IMPORTANT]
> Executive Statement: Zero customer PII or encrypted transaction keys were exfiltrated during the 48-hour containment cycle. Primary persistence hooks have been eradicated across all domain controllers.

## 1. Executive Summary
On **November 14, 2026**, the SOC detected unauthorized lateral traversal via compromised VPN credentials. The adversary (attributed to **UNC-4820**) attempted DCSync attacks against primary Domain Controllers to harvest credentials. Containment was enacted within 4 hours, and full Active Directory double-reset was executed.

## 2. Attack Lifecycle & Kill Chain
| Stage | Technique ID | Method Observed | Detection Source |
|---|---|---|---|
| **Initial Access** | T1133 | Stolen SSL-VPN session token via InfoStealer | Fortinet VPN Log |
| **Execution** | T1059.001 | Encoded PowerShell payload downloading Cobalt Strike | EDR (Process Guid 4402) |
| **Persistence** | T1053.005 | Malicious Scheduled Task \`SecurityHealthCheck\` | Windows Event ID 4698 |
| **Credential Access** | T1003.006 | DCSync via DRSGetNCChanges against DC01 | Windows Event ID 4662 |
| **Exfiltration Attempt** | T1567.002 | Rclone upload toward Mega.nz cloud bucket | Perimeter NGFW Alert |

## 3. Incident Timeline
- **11/14 02:00 UTC** - VPN Authentication from residential proxy IP \`188.220.101.44\`
- **11/14 02:15 UTC** - LSASS memory dump attempt flagged on host \`WKSTN-FIN-042\`
- **11/14 03:00 UTC** - EDR containment initiated on 3 affected endpoints
- **11/14 04:30 UTC** - Active Directory Double-Password Reset executed
- **11/15 12:00 UTC** - Clean system restores verified from immutable backups

## 4. Attack Architecture (Mermaid)
\`\`\`mermaid
flowchart LR
    VPN[SSL-VPN Gateway<br/>Compromised Creds] -->|T1133| WK[WKSTN-FIN-042<br/>User Session]
    WK -->|T1059 PowerShell| C2[Mythic C2<br/>cdn-update-edge.com]
    WK -->|T1003 DCSync| DC[Domain Controller<br/>DC01.corp.local]
    DC -.->|Blocked| EX[Mega.nz<br/>Exfil Bucket]
    
    style VPN fill:#b91c1c,stroke:#f87171,color:#fff
    style WK fill:#d97706,stroke:#fbbf24,color:#fff
    style C2 fill:#431407,stroke:#ef4444,color:#fff
    style DC fill:#1e3a8a,stroke:#38bdf8,color:#fff
    style EX fill:#064e3b,stroke:#34d399,color:#fff
\`\`\`

## 5. Containment & Remediation Checklist
- [x] Host network isolation via EDR agent on \`WKSTN-FIN-042\` and \`WKSTN-HR-009\`
- [x] Invalidation of all Active Directory Kerberos TGT tickets (\`krbtgt\` reset x2)
- [x] Revocation of Azure AD Refresh Tokens & enforcement of FIDO2 WebAuthn
- [x] Deployment of Sigma rule \`proc_creation_win_cobalt_strike_beacon.yml\`
- [ ] Complete external firmware audit on edge VPN appliances (Target: 11/20)

> [!TIP]
> Recommendation: Mandatory migration to hardware-bound FIDO2 tokens for all administrative and remote VPN accounts to prevent adversary session-hijacking.
`
        },
        'threat-advisory': {
            title: 'CTI Flash Advisory: UNC-4820 Cyber Espionage Campaign',
            category: 'Threat Intel',
            desc: 'Adversary attribution, weaponization techniques, infrastructure topology, and YARA signatures.',
            badge: 'ADVISORY',
            markdown: `# CTI Flash Advisory: UNC-4820 Cyber Espionage
**Threat Actor:** UNC-4820 (State-Sponsored Cyber Espionage)  
**Target Sectors:** Defense Industrial Base, Aerospace, Semiconductor  
**First Observed:** Q3 2026 | **Confidence Level:** High  

---

> [!WARNING]
> Threat Warning: UNC-4820 is actively leveraging living-off-the-land binaries (LOLBins) combined with fast-flux VPS infrastructure to bypass standard DNS reputation filters.

## Threat Actor Overview
UNC-4820 operates out of the UTC+8 timezone with strict military shift cadence (09:00 - 18:00). Their primary objective is intellectual property theft concerning next-generation semiconductor fabrication telemetry.

## Indicators of Compromise (IoCs)
### 1. Network C2 Infrastructure
- \`185.220.101.44\` (Mythic C2 Ingress)
- \`194.26.29.112\` (Payload Staging Server)
- \`dns-resolver-edge[.]com\` (DoH C2 Beacon)
- \`api-telemetry-cloud[.]net\` (Fallback Dead-Drop Resolver)

### 2. Malicious File Hashes (SHA-256)
\`\`\`text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ShadowDrop_Loader.dll
8f42a1b9c8301d4a0298bb35e390c8841490218fa40182390a48f0291ba48012  PlugX_Payload.bin
d41d8cd98f00b204e9800998ecf8427e02948190391204891024981092481092  MemoryInject_x64.sys
\`\`\`

## YARA Hunting Rule
\`\`\`yara
rule APT_UNC4820_ShadowDrop_Loader {
    meta:
        description = "Detects UNC-4820 second-stage DLL loader"
        author = "MANTIS CTI Team"
        date = "2026-11-14"
        severity = "Critical"
    strings:
        $s1 = "ShadowDrop_Engine_v4" ascii wide
        $s2 = "XOR_Crypt_Payload_Buffer" ascii
        $s3 = "\\\\Device\\\\MantisNullDriver" wide
        $magic = { 4D 5A 90 00 03 00 00 00 }
    condition:
        $magic at 0 and ($s1 and ($s2 or $s3)) and filesize < 2MB
}
\`\`\`

## Defensive Recommendations
1. Block all traffic to \`185.220.101.0/24\` at perimeter firewalls.
2. Enable Windows Defender Credential Guard to thwart LSASS dumping.
3. Restrict PowerShell script execution via AppLocker constrained language mode.
`
        },
        'malware-analysis': {
            title: 'Malware Reverse Engineering: AsyncRAT Modular Variant',
            category: 'Malware Lab',
            desc: 'Static disassembly, dynamic unpacking, configuration extraction, and C2 protocol decoding.',
            badge: 'MALWARE',
            markdown: `# Malware Analysis Report: AsyncRAT Modular Variant
**Sample Name:** \`Invoice_Payment_Nov2026.exe\`  
**File Size:** 482.5 KB | **Compiler:** .NET v4.0.30319  
**SHA-256:** \`4a89012f901284a1029481204910294810294812049102481029481204910248\`  

---

> [!NOTE]
> Classification: Commodity Remote Access Trojan (AsyncRAT) heavily armored with ConfuserEx v1.9, process hollowing into \`aspnet_compiler.exe\`, and certificate-pinned TLS communications.

## 1. Static PE Structure
- **Subsystem:** Windows GUI (PE32 executable)
- **Entropy:** 7.92 (High entropy indicative of encrypted payload overlay)
- **Exported Symbols:** None
- **Imported DLLs:** \`mscoree.dll\`, \`kernel32.dll\`

## 2. Decrypted Configuration Table
| Setting Key | Decrypted Value | Description |
|---|---|---|
| **C2 Host** | \`relay-sync-node.org:8808\` | Primary SSL socket endpoint |
| **Fallback C2** | \`194.26.29.99:7707\` | Secondary raw TCP fallback |
| **AES Salt** | \`k9$m!9024JkLm#@1\` | AES-256-CBC string decryption key |
| **Anti-Analysis** | \`Enabled\` | Process termination on VM discovery |
`
        },
        'soc-sop': {
            title: 'SOC Tier-1 Alert Triage Standard Operating Procedure',
            category: 'SOC / SOP',
            desc: 'Actionable playbook for triaging high-severity endpoint and network security events.',
            badge: 'RUNBOOK',
            markdown: `# SOC Runbook: High-Severity Endpoint Alert Triage
**Document Version:** 3.2 | **Review Cycle:** Quarterly  
**Target Audience:** SOC Tier-1 / Tier-2 Incident Handlers  

---

## 1. Initial Assessment Protocol
When an alert with SEV-1 or SEV-2 triggers on the SIEM:
- [ ] Verify Alert ID, Event Timestamp, and Affected Asset Hostname
- [ ] Cross-reference user account with active Employee Directory & PIM
- [ ] Determine if the affected asset belongs to **Tier-0 (Crown Jewels)**

## 2. Escalation Matrix
| Asset Category | Target SLA | Tier-1 Action | Primary Contact |
|---|---|---|---|
| **Tier-0 Domain Controller** | < 15 Mins | Immediate Host Isolation + PagerDuty Call | Lead Security Architect |
| **Production Payment DB** | < 30 Mins | Network Ingress Block + Capture Memory | Core Infrastructure Lead |
| **Corporate Workstation** | < 60 Mins | EDR Quarantine + Credential Lock | Tier-2 Incident Responder |

> [!CAUTION]
> Under NO circumstances should an analyst reboot an infected machine before acquiring volatile memory (RAM) dump using WinPmem or FTK Imager.
`
        }
    };

    const THEMES = [
        { id: 'dark', label: 'Dark', previewClass: 'theme-cyber-dark' },
        { id: 'white', label: 'White', previewClass: 'theme-white' }
    ];

    const FONTS = [
        { id: 'Plus Jakarta Sans', label: 'Plus Jakarta Sans (Default)' },
        { id: 'Inter', label: 'Inter (Clean Technical)' },
        { id: 'JetBrains Mono', label: 'JetBrains Mono (Code Focus)' },
        { id: 'Merriweather', label: 'Merriweather (Academic Serif)' }
    ];

    const state = {
        initialized: false,
        title: PRESETS['dfir-postmortem'].title,
        markdown: PRESETS['dfir-postmortem'].markdown,
        view: 'split',
        split: 50,
        theme: 'dark',
        font: 'Plus Jakarta Sans',
        syncScroll: true,
        isScrollingEditor: false,
        isScrollingPreview: false,
        markedReady: false,
        mermaidReady: false,
        hljsReady: false
    };

    let mermaidBlockCounter = 0;
    let mermaidRenderSession = 0;

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Unpack marked v12+ token object or legacy (code, lang) arguments
    function extractCodeAndLang(codeOrToken, infostring) {
        let text = '';
        let lang = '';
        if (codeOrToken && typeof codeOrToken === 'object') {
            text = codeOrToken.text || '';
            lang = (codeOrToken.lang || '').trim();
        } else {
            text = String(codeOrToken || '');
            lang = String(infostring || '').trim();
        }
        const cleanLang = (lang.split(/\s+/)[0] || 'text').toLowerCase();
        return { text, lang: cleanLang, rawLang: lang };
    }

    // Built-in syntax highlighter for offline or fallback operation
    function simpleSyntaxHighlight(code, lang) {
        if (!code) return '';
        let escaped = esc(code);
        // Strings
        escaped = escaped.replace(/(["'`])(?:\\.|(?!\1)[^\\\r\n])*\1/g, '<span class="hljs-string">$&</span>');
        // Comments
        escaped = escaped.replace(/(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)/g, '<span class="hljs-comment">$&</span>');
        // Keywords
        escaped = escaped.replace(/\b(function|return|if|else|for|while|const|let|var|import|export|from|class|def|async|await|try|catch|finally|throw|new|switch|case|break|continue|default|typeof|instanceof|void|delete|in|of|rule|strings|condition|meta|and|or|not|true|false|null|undefined|None|True|False)\b/g, '<span class="hljs-keyword">$&</span>');
        // Numbers
        escaped = escaped.replace(/\b(\d+(\.\d+)?|0x[0-9a-fA-F]+)\b/g, '<span class="hljs-number">$&</span>');
        return escaped;
    }

    function highlightCode(code, lang) {
        if (!code) return '';
        if (window.hljs) {
            try {
                if (lang && window.hljs.getLanguage(lang)) {
                    return window.hljs.highlight(code, { language: lang }).value;
                } else {
                    return window.hljs.highlightAuto(code).value;
                }
            } catch (e) {
                return esc(code);
            }
        }
        return simpleSyntaxHighlight(code, lang);
    }

    function saveToStorage() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                title: state.title,
                markdown: state.markdown,
                view: state.view,
                split: state.split,
                theme: state.theme,
                font: state.font,
                syncScroll: state.syncScroll
            }));
        } catch (e) { /* ignore */ }
    }

    function loadFromStorage() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return false;
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed.markdown === 'string') {
                state.title = parsed.title || state.title;
                state.markdown = parsed.markdown;
                state.view = ['code', 'split', 'preview'].includes(parsed.view) ? parsed.view : 'split';
                state.split = Number(parsed.split) >= 20 && Number(parsed.split) <= 80 ? Number(parsed.split) : 50;
                state.theme = (parsed.theme === 'white' || parsed.theme === 'clean-white') ? 'white' : 'dark';
                state.font = parsed.font || 'Plus Jakarta Sans';
                state.syncScroll = parsed.syncScroll !== false;
                return true;
            }
        } catch (e) { /* ignore */ }
        return false;
    }

    function ensureMarkedLoaded(callback) {
        if (typeof window.marked !== 'undefined') {
            state.markedReady = true;
            if (callback) callback();
            return;
        }
        const script = document.createElement('script');
        script.src = MARKED_CDN;
        script.onload = () => {
            state.markedReady = true;
            if (callback) callback();
        };
        script.onerror = () => {
            if (callback) callback();
        };
        document.head.appendChild(script);
    }

    function ensureHighlightLoaded(callback) {
        if (typeof window.hljs !== 'undefined') {
            state.hljsReady = true;
            if (callback) callback();
            return;
        }
        const script = document.createElement('script');
        script.src = HLJS_CDN;
        script.onload = () => {
            state.hljsReady = true;
            if (callback) callback();
        };
        script.onerror = () => {
            if (callback) callback();
        };
        document.head.appendChild(script);
    }

    function ensureMermaidLoaded(callback) {
        if (typeof window.mermaid !== 'undefined') {
            state.mermaidReady = true;
            if (callback) callback();
            return;
        }
        const script = document.createElement('script');
        script.src = MERMAID_CDN;
        script.onload = () => {
            state.mermaidReady = true;
            try {
                window.mermaid.initialize({
                    startOnLoad: false,
                    theme: state.theme === 'white' ? 'default' : 'dark',
                    securityLevel: 'loose',
                    fontFamily: `'JetBrains Mono', monospace`
                });
            } catch (e) { /* ignore */ }
            if (callback) callback();
        };
        document.head.appendChild(script);
    }

    function fallbackParseMarkdown(md) {
        if (!md) return '';
        let out = md.replace(/\r\n/g, '\n');
        const codeBlocks = [];
        out = out.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
            const idx = codeBlocks.length;
            codeBlocks.push({ lang: (lang || '').trim().toLowerCase(), code });
            return `%%CODE_BLOCK_${idx}%%`;
        });
        const inlineCodes = [];
        out = out.replace(/`([^`\n]+)`/g, (match, code) => {
            const idx = inlineCodes.length;
            inlineCodes.push(code);
            return `%%INLINE_CODE_${idx}%%`;
        });
        out = out.replace(/^>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*\n((?:>.*\n?)*)/gim, (match, type, content) => {
            const cleanContent = content.replace(/^>\s?/gm, '');
            const alertType = type.toLowerCase();
            return `<div class="md-alert md-alert-${alertType}"><div class="md-alert-title"><i class="fa-solid fa-circle-info"></i> ${type.toUpperCase()}</div><div>${fallbackParseMarkdown(cleanContent)}</div></div>\n`;
        });
        out = out.replace(/^(?:>[ \t]?)(.+)$/gm, '<blockquote>$1</blockquote>');
        out = out.replace(/<\/blockquote>\n<blockquote>/g, '\n');
        out = out.replace(/^######\s+(.+)$/gm, '<h6>$1</h6>');
        out = out.replace(/^#####\s+(.+)$/gm, '<h5>$1</h5>');
        out = out.replace(/^####\s+(.+)$/gm, '<h4>$1</h4>');
        out = out.replace(/^###\s+(.+)$/gm, '<h3>$1</h3>');
        out = out.replace(/^##\s+(.+)$/gm, '<h2>$1</h2>');
        out = out.replace(/^#\s+(.+)$/gm, '<h1>$1</h1>');
        out = out.replace(/^(\*{3,}|-{3,}|_{3,})$/gm, '<hr />');
        out = out.replace(/^- \[ \]\s+(.+)$/gm, '<li class="md-task-item"><input type="checkbox" disabled /> <span>$1</span></li>');
        out = out.replace(/^- \[x\]\s+(.+)$/gim, '<li class="md-task-item"><input type="checkbox" checked disabled /> <span>$1</span></li>');
        out = out.replace(/^[\*\-]\s+(.+)$/gm, '<li>$1</li>');
        out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        out = out.replace(/__([^_]+)__/g, '<strong>$1</strong>');
        out = out.replace(/\*([^*]+)\*/g, '<em>$1</em>');
        out = out.replace(/_([^_]+)_/g, '<em>$1</em>');
        out = out.replace(/~~([^~]+)~~/g, '<del>$1</del>');
        out = out.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" style="max-width:100%;border-radius:8px;" />');
        out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
        out = out.replace(/((?:\|[^\n]+\|\n?)+)/g, (match) => {
            const lines = match.trim().split('\n').filter(Boolean);
            if (lines.length < 2) return match;
            let html = '<table>';
            lines.forEach((l, i) => {
                if (i === 1 && l.includes('---')) return;
                const cells = l.split('|').slice(1, -1).map(c => c.trim());
                if (i === 0) {
                    html += '<thead><tr>' + cells.map(c => `<th>${c}</th>`).join('') + '</tr></thead><tbody>';
                } else {
                    html += '<tr>' + cells.map(c => `<td>${c}</td>`).join('') + '</tr>';
                }
            });
            html += '</tbody></table>';
            return html;
        });
        const blocks = out.split('\n\n');
        out = blocks.map(block => {
            const trimmed = block.trim();
            if (!trimmed) return '';
            if (/^<(h[1-6]|table|blockquote|div|hr|li|pre|img)/i.test(trimmed)) return trimmed;
            return `<p>${trimmed.replace(/\n/g, '<br />')}</p>`;
        }).join('\n');
        out = out.replace(/%%INLINE_CODE_(\d+)%%/g, (m, idx) => `<code>${esc(inlineCodes[idx])}</code>`);
        out = out.replace(/%%CODE_BLOCK_(\d+)%%/g, (m, idx) => {
            const item = codeBlocks[idx];
            if (item.lang === 'mermaid') {
                mermaidBlockCounter++;
                const mId = 'md-mermaid-' + mermaidBlockCounter;
                return `<div class="md-mermaid-wrap" data-mermaid-code="${encodeURIComponent(item.code.trim())}"><div id="${mId}" class="md-mermaid-target"><div class="md-mermaid-loading"><i class="fa-solid fa-spinner fa-spin"></i> Rendering diagram...</div></div></div>`;
            }
            const highlighted = highlightCode(item.code, item.lang);
            return `<div class="md-code-block">
                <div class="md-code-header">
                    <span><i class="fa-solid fa-code" style="color:var(--md-accent);margin-right:6px;"></i>${esc(item.lang || "text")}</span>
                    <button type="button" class="md-copy-code-btn" onclick="navigator.clipboard.writeText(decodeURIComponent('${encodeURIComponent(item.code)}')); this.innerHTML='<i class=\\\'fa-solid fa-check\\\'></i> Copied!'; setTimeout(()=>this.innerHTML='<i class=\\\'fa-regular fa-copy\\\'></i> Copy', 1500);"><i class="fa-regular fa-copy"></i> Copy</button>
                </div>
                <pre class="md-code-pre"><code class="hljs language-${esc(item.lang || "text")}">${highlighted}</code></pre>
            </div>`;
        });
        return out;
    }

    function renderMarkdownToHtml(md) {
        mermaidBlockCounter = 0;
        if (state.markedReady && typeof window.marked !== 'undefined') {
            try {
                const renderer = new window.marked.Renderer();
                
                renderer.code = function(codeOrToken, infostring) {
                    const { text, lang } = extractCodeAndLang(codeOrToken, infostring);
                    
                    if (lang === 'mermaid') {
                        mermaidBlockCounter++;
                        const mId = 'md-mermaid-' + mermaidBlockCounter;
                        return `<div class="md-mermaid-wrap" data-mermaid-code="${encodeURIComponent(text.trim())}"><div id="${mId}" class="md-mermaid-target"><div class="md-mermaid-loading"><i class="fa-solid fa-spinner fa-spin"></i> Rendering diagram...</div></div></div>`;
                    }

                    const highlighted = highlightCode(text, lang);
                    return `<div class="md-code-block">
                        <div class="md-code-header">
                            <span><i class="fa-solid fa-code" style="color:var(--md-accent);margin-right:6px;"></i>${esc(lang || "text")}</span>
                            <button type="button" class="md-copy-code-btn" onclick="navigator.clipboard.writeText(decodeURIComponent('${encodeURIComponent(text)}')); this.innerHTML='<i class=\\\'fa-solid fa-check\\\'></i> Copied!'; setTimeout(()=>this.innerHTML='<i class=\\\'fa-regular fa-copy\\\'></i> Copy', 1500);"><i class="fa-regular fa-copy"></i> Copy</button>
                        </div>
                        <pre class="md-code-pre"><code class="hljs language-${esc(lang || "text")}">${highlighted}</code></pre>
                    </div>`;
                };

                window.marked.setOptions({ renderer: renderer, gfm: true, breaks: true });
                let parsed = window.marked.parse(md);

                // Convert GitHub alert syntax
                parsed = parsed.replace(/<blockquote>\s*<p>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*<br\s*\/?>([\s\S]*?)<\/blockquote>/gi, (m, type, body) => {
                    const alertType = type.toLowerCase();
                    return `<div class="md-alert md-alert-${alertType}"><div class="md-alert-title"><i class="fa-solid fa-circle-info"></i> ${type.toUpperCase()}</div><div>${body}</div></div>`;
                });
                return parsed;
            } catch (err) {
                console.warn('Marked parse failed, using fallback:', err);
            }
        }
        return fallbackParseMarkdown(md);
    }

    async function renderMermaidBlocks(container) {
        if (!container) return;
        const currentSession = ++mermaidRenderSession;
        const wraps = container.querySelectorAll('.md-mermaid-wrap[data-mermaid-code]');
        if (!wraps.length) return;

        if (!window.mermaid) {
            ensureMermaidLoaded(() => {
                if (currentSession === mermaidRenderSession) {
                    renderMermaidBlocks(container);
                }
            });
            return;
        }

        try {
            window.mermaid.initialize({
                startOnLoad: false,
                theme: state.theme === 'white' ? 'default' : 'dark',
                securityLevel: 'loose',
                fontFamily: `'JetBrains Mono', monospace`
            });
        } catch (e) { /* ignore */ }

        for (let i = 0; i < wraps.length; i++) {
            if (currentSession !== mermaidRenderSession) return;
            const wrap = wraps[i];
            const rawCode = decodeURIComponent(wrap.getAttribute('data-mermaid-code') || '');
            if (!rawCode) continue;
            const target = wrap.querySelector('.md-mermaid-target');
            if (!target) continue;

            const renderId = 'md_mermaid_svg_' + Date.now() + '_' + i;
            try {
                const { svg } = await window.mermaid.render(renderId, rawCode);
                if (currentSession === mermaidRenderSession) {
                    target.innerHTML = svg;
                    const svgEl = target.querySelector('svg');
                    if (svgEl) {
                        svgEl.style.maxWidth = '100%';
                        svgEl.style.height = 'auto';
                        svgEl.style.display = 'block';
                        if (typeof window.adaptMermaidSvgTheme === 'function') {
                            window.adaptMermaidSvgTheme(svgEl, state.theme === 'white' ? 'white' : 'dark');
                        }
                    }
                }
            } catch (err) {
                if (currentSession === mermaidRenderSession) {
                    console.warn('Mermaid render error for block', i, err);
                    target.innerHTML = `<div class="md-mermaid-error">
                        <div style="font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:6px;">
                            <i class="fa-solid fa-triangle-exclamation"></i> Mermaid Syntax Diagnostic
                        </div>
                        <div style="font-size:0.75rem;opacity:0.9;">${esc(err.message || 'Diagram syntax error')}</div>
                        <pre class="md-code-pre" style="margin-top:8px;padding:8px 12px;font-size:0.75rem;background:rgba(0,0,0,0.3);border-radius:6px;"><code>${esc(rawCode)}</code></pre>
                    </div>`;
                    const strayErr = document.getElementById('d' + renderId);
                    if (strayErr) strayErr.remove();
                }
            }
        }
    }

    function initMarkdownStudio() {
        const pane = document.getElementById('markdown-draw-pane');
        if (!pane) return;
        loadFromStorage();
        renderShell(pane);
        bindEvents(pane);
        updateLineNumbers();
        updateStats();
        renderPreview();
        ensureMarkedLoaded(() => { renderPreview(); });
        ensureHighlightLoaded(() => { renderPreview(); });
        ensureMermaidLoaded(() => { renderPreview(); });
        state.initialized = true;
    }

    function renderShell(pane) {
        pane.innerHTML = `
            <div class="md-root" id="md-studio-root" data-view="${state.view}">
                <header class="md-top">
                    <div class="md-top-left">
                        <div class="md-logo" title="MANTIS Markdown Studio">
                            <i class="fa-brands fa-markdown"></i>
                        </div>
                        <input type="text" class="md-title" id="md-title-input" value="${esc(state.title)}" title="Click to rename document" />
                        <span class="md-status" id="md-status-pill">LIVE BUFFER</span>
                    </div>
                    <div class="md-tools">
                        <div class="md-seg" role="tablist" aria-label="Editor View">
                            <button type="button" role="tab" data-md-view="code" class="${state.view === "code" ? "active" : ""}" title="Editor Only">
                                <i class="fa-solid fa-code"></i><span>Editor</span>
                            </button>
                            <button type="button" role="tab" data-md-view="split" class="${state.view === "split" ? "active" : ""}" title="Side-by-Side Split">
                                <i class="fa-solid fa-table-columns"></i><span>Split</span>
                            </button>
                            <button type="button" role="tab" data-md-view="preview" class="${state.view === "preview" ? "active" : ""}" title="Rendered Preview">
                                <i class="fa-solid fa-eye"></i><span>Preview</span>
                            </button>
                        </div>
                    </div>
                    <div class="md-top-right">
                        <button type="button" class="md-tbtn" id="md-btn-presets" title="Browse Documentation Presets">
                            <i class="fa-solid fa-wand-magic-sparkles" style="color:var(--md-accent);"></i>
                            <span>Presets</span>
                        </button>
                        <div class="map-pop-wrap">
                            <button type="button" class="md-tbtn" id="md-btn-style-pop" title="Typography & Preview Style">
                                <i class="fa-solid fa-sliders"></i>
                                <span>Style</span>
                                <i class="fa-solid fa-chevron-down mmd-caret"></i>
                            </button>
                            <div class="map-pop" id="md-style-pop">
                                <div class="map-pop-sec">PREVIEW THEME</div>
                                <div class="md-theme-toggle-pills" id="md-theme-pills">
                                    <button type="button" class="md-theme-pill ${state.theme === 'dark' ? 'active' : ''}" data-theme="dark">
                                        <i class="fa-solid fa-moon"></i>
                                        <span>Dark</span>
                                    </button>
                                    <button type="button" class="md-theme-pill ${state.theme === 'white' ? 'active' : ''}" data-theme="white">
                                        <i class="fa-solid fa-sun"></i>
                                        <span>White</span>
                                    </button>
                                </div>
                                <div class="map-pop-sec" style="margin-top:10px;">TYPOGRAPHY FONT</div>
                                <div class="md-select-wrap">
                                    <select id="md-select-font" class="md-style-select">
                                        ${FONTS.map(f => `<option value="${f.id}" ${state.font === f.id ? "selected" : ""}>${f.label}</option>`).join("")}
                                    </select>
                                    <i class="fa-solid fa-chevron-down md-select-chevron"></i>
                                </div>
                                <div class="map-pop-sec" style="margin-top:10px;">SCROLL BEHAVIOR</div>
                                <label class="md-toggle-item">
                                    <input type="checkbox" id="md-toggle-sync-scroll" ${state.syncScroll ? "checked" : ""} />
                                    <span>Synchronized Scrolling</span>
                                </label>
                            </div>
                        </div>
                        <div class="map-pop-wrap">
                            <button type="button" class="md-tbtn md-primary" id="md-btn-export-pop">
                                <i class="fa-solid fa-arrow-down-to-bracket"></i>
                                <span>Export</span>
                                <i class="fa-solid fa-chevron-down mmd-caret"></i>
                            </button>
                            <div class="map-pop" id="md-export-pop">
                                <div class="map-pop-sec">DOCUMENT & PDF</div>
                                <button type="button" class="map-pop-item" id="md-export-pdf">
                                    <i class="fa-solid fa-file-pdf" style="color:#f87171;"></i>Print / Save as PDF
                                </button>
                                <button type="button" class="map-pop-item" id="md-export-md">
                                    <i class="fa-brands fa-markdown" style="color:#38bdf8;"></i>Download Markdown (.md)
                                </button>
                                <button type="button" class="map-pop-item" id="md-export-html">
                                    <i class="fa-solid fa-file-code" style="color:#10b981;"></i>Download HTML (.html)
                                </button>
                                <div class="map-pop-sec" style="margin-top:6px;">CLIPBOARD</div>
                                <button type="button" class="map-pop-item" id="md-copy-md">
                                    <i class="fa-solid fa-copy" style="color:#c084fc;"></i>Copy Markdown Text
                                </button>
                                <button type="button" class="map-pop-item" id="md-copy-html">
                                    <i class="fa-solid fa-code" style="color:#fbbf24;"></i>Copy Rendered HTML
                                </button>
                                <div class="map-pop-sec" style="margin-top:6px;">IMPORT</div>
                                <button type="button" class="map-pop-item" id="md-import-file-btn">
                                    <i class="fa-solid fa-folder-open" style="color:#94a3b8;"></i>Open .md File...
                                </button>
                            </div>
                        </div>
                        <input type="file" id="md-file-input" accept=".md,.markdown,.txt" style="display:none;" />
                    </div>
                </header>
                <div class="md-format-bar">
                    <button type="button" class="md-fbtn" data-action="h1" title="Heading 1 (#)"><i class="fa-solid fa-heading"></i><sub style="font-size:9px;">1</sub></button>
                    <button type="button" class="md-fbtn" data-action="h2" title="Heading 2 (##)"><i class="fa-solid fa-heading"></i><sub style="font-size:9px;">2</sub></button>
                    <button type="button" class="md-fbtn" data-action="h3" title="Heading 3 (###)"><i class="fa-solid fa-heading"></i><sub style="font-size:9px;">3</sub></button>
                    <span class="md-fsep"></span>
                    <button type="button" class="md-fbtn" data-action="bold" title="Bold (Ctrl+B)"><i class="fa-solid fa-bold"></i></button>
                    <button type="button" class="md-fbtn" data-action="italic" title="Italic (Ctrl+I)"><i class="fa-solid fa-italic"></i></button>
                    <button type="button" class="md-fbtn" data-action="strike" title="Strikethrough (~~)"><i class="fa-solid fa-strikethrough"></i></button>
                    <span class="md-fsep"></span>
                    <button type="button" class="md-fbtn" data-action="code-inline" title="Inline Code (\`)"><i class="fa-solid fa-code"></i></button>
                    <button type="button" class="md-fbtn" data-action="code-block" title="Code Block (\`\`\`)"><i class="fa-solid fa-file-code"></i></button>
                    <button type="button" class="md-fbtn" data-action="quote" title="Quote (>)"><i class="fa-solid fa-quote-left"></i></button>
                    <span class="md-fsep"></span>
                    <button type="button" class="md-fbtn" data-action="link" title="Insert Link (Ctrl+K)"><i class="fa-solid fa-link"></i></button>
                    <button type="button" class="md-fbtn" data-action="image" title="Insert Image (![alt](url))"><i class="fa-regular fa-image"></i></button>
                    <button type="button" class="md-fbtn" data-action="table" title="Insert Table"><i class="fa-solid fa-table"></i></button>
                    <span class="md-fsep"></span>
                    <button type="button" class="md-fbtn" data-action="task" title="Task / Checklist Item (- [ ])"><i class="fa-regular fa-square-check"></i></button>
                    <button type="button" class="md-fbtn" data-action="ul" title="Bulleted List (-)"><i class="fa-solid fa-list-ul"></i></button>
                    <button type="button" class="md-fbtn" data-action="ol" title="Numbered List (1.)"><i class="fa-solid fa-list-ol"></i></button>
                    <button type="button" class="md-fbtn" data-action="hr" title="Horizontal Divider (---)"><i class="fa-solid fa-minus"></i></button>
                    <span class="md-fsep"></span>
                    <button type="button" class="md-fbtn" data-action="alert-note" title="Alert Note" style="color:#38bdf8;"><i class="fa-solid fa-circle-info"></i></button>
                    <button type="button" class="md-fbtn" data-action="alert-warn" title="Alert Warning" style="color:#fbbf24;"><i class="fa-solid fa-triangle-exclamation"></i></button>
                </div>
                <div class="md-workspace" id="md-workspace">
                    <section class="md-editor" id="md-editor-panel" style="--md-split:${state.split}%;">
                        <div class="md-editor-header">
                            <span><i class="fa-solid fa-terminal" style="color:var(--md-accent);margin-right:6px;"></i>MARKDOWN SOURCE</span>
                            <span id="md-editor-cursor-pos">Ln 1, Col 1</span>
                        </div>
                        <div class="md-editor-body">
                            <div class="md-gutter" id="md-gutter">1</div>
                            <textarea class="md-textarea dark-scroll" id="md-textarea" spellcheck="false" placeholder="Write or paste Markdown here...">${esc(state.markdown)}</textarea>
                        </div>
                    </section>
                    <div class="md-divider" id="md-divider" title="Drag to resize editor & preview (Double-click to reset 50/50)"></div>
                    <section class="md-preview ${THEMES.find(t => t.id === state.theme)?.previewClass || "theme-cyber-dark"}" id="md-preview-panel">
                        <div class="md-preview-header">
                            <span><i class="fa-solid fa-book-open" style="color:var(--md-accent);margin-right:6px;"></i>LIVE DOCUMENT PREVIEW</span>
                            <div style="display:flex;align-items:center;gap:10px;">
                                <button type="button" class="md-copy-code-btn" id="md-btn-copy-preview" title="Copy all rendered preview text to clipboard" style="padding:2px 8px;font-size:0.68rem;"><i class="fa-regular fa-copy"></i> Copy Preview</button>
                                <span id="md-preview-stats">READY</span>
                            </div>
                        </div>
                        <div class="md-preview-scroll dark-scroll" id="md-preview-scroll">
                            <article class="md-doc" id="md-doc" style="font-family:'${state.font}', sans-serif;"></article>
                        </div>
                    </section>
                </div>
                <footer class="md-status-bar">
                    <div class="md-stats-pills">
                        <span id="md-stat-words">0 WORDS</span>
                        <span id="md-stat-chars">0 CHARACTERS</span>
                        <span id="md-stat-reading-time">~1 MIN READ</span>
                    </div>
                    <div class="md-stats-pills">
                        <span><kbd>Ctrl+S</kbd> Save .md</span>
                        <span><kbd>Ctrl+P</kbd> Print/PDF</span>
                        <span><kbd>Tab</kbd> Indent</span>
                    </div>
                </footer>
                <div id="md-presets-scrim"></div>
                <aside id="md-presets-drawer">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,0.08);background:#090e17;">
                        <div>
                            <div style="font-weight:700;font-size:0.95rem;color:#f8fafc;display:flex;align-items:center;gap:8px;">
                                <i class="fa-solid fa-wand-magic-sparkles" style="color:var(--md-accent);"></i>
                                <span>Markdown Presets</span>
                            </div>
                            <div style="font-size:0.75rem;color:#64748b;margin-top:2px;">Cyber Threat Intel, DFIR & Engineering Templates</div>
                        </div>
                        <button type="button" class="dd-close-btn" id="md-btn-close-presets" style="background:none;border:none;color:#94a3b8;font-size:16px;cursor:pointer;">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                    <div style="flex:1;overflow-y:auto;padding:16px;" class="dark-scroll">
                        <div style="display:flex;flex-direction:column;gap:12px;">
                            ${Object.entries(PRESETS).map(([key, p]) => `
                                <div class="dd-preset-card" data-md-preset="${key}" style="background:#090e17;border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:14px;cursor:pointer;transition:all 0.15s;">
                                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                                        <span style="font-size:0.68rem;font-weight:700;padding:2px 7px;border-radius:4px;background:rgba(56,189,248,0.15);color:#38bdf8;">${esc(p.badge)}</span>
                                        <span style="font-size:0.72rem;color:#64748b;">${esc(p.category)}</span>
                                    </div>
                                    <div style="font-weight:700;font-size:0.86rem;color:#f1f5f9;margin-bottom:4px;">${esc(p.title)}</div>
                                    <div style="font-size:0.76rem;color:#94a3b8;line-height:1.4;">${esc(p.desc)}</div>
                                </div>
                            `).join("")}
                        </div>
                    </div>
                </aside>
            </div>
        `;
    }

    function bindEvents(pane) {
        const root = document.getElementById('md-studio-root');
        const textarea = document.getElementById('md-textarea');
        const titleInput = document.getElementById('md-title-input');
        const stylePop = document.getElementById('md-style-pop');
        const exportPop = document.getElementById('md-export-pop');
        const btnStyle = document.getElementById('md-btn-style-pop');
        const btnExport = document.getElementById('md-btn-export-pop');
        const btnPresets = document.getElementById('md-btn-presets');
        const btnClosePresets = document.getElementById('md-btn-close-presets');
        const presetsScrim = document.getElementById('md-presets-scrim');

        if (titleInput) {
            titleInput.addEventListener('input', (e) => {
                state.title = e.target.value.trim() || 'Untitled Document';
                saveToStorage();
            });
        }

        pane.querySelectorAll('[data-md-view]').forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.getAttribute('data-md-view');
                setView(view);
            });
        });

        const divider = document.getElementById('md-divider');
        const editorPanel = document.getElementById('md-editor-panel');
        if (divider && editorPanel) {
            let dragging = false;
            divider.addEventListener('mousedown', () => {
                dragging = true;
                divider.classList.add('dragging');
                document.body.style.cursor = 'col-resize';
                document.body.style.userSelect = 'none';
            });
            window.addEventListener('mousemove', (e) => {
                if (!dragging) return;
                const workspace = document.getElementById('md-workspace');
                if (!workspace) return;
                const rect = workspace.getBoundingClientRect();
                const pct = Math.min(80, Math.max(20, ((e.clientX - rect.left) / rect.width) * 100));
                state.split = Math.round(pct * 10) / 10;
                editorPanel.style.setProperty('--md-split', `${state.split}%`);
            });
            window.addEventListener('mouseup', () => {
                if (dragging) {
                    dragging = false;
                    divider.classList.remove('dragging');
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                    saveToStorage();
                }
            });
            divider.addEventListener('dblclick', () => {
                state.split = 50;
                editorPanel.style.setProperty('--md-split', '50%');
                saveToStorage();
            });
        }

        let debounceTimer = null;
        if (textarea) {
            textarea.addEventListener('input', () => {
                state.markdown = textarea.value;
                updateLineNumbers();
                updateStats();
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    renderPreview();
                    saveToStorage();
                }, 100);
            });

            const previewScroll = document.getElementById('md-preview-scroll');
            if (previewScroll) {
                textarea.addEventListener('scroll', () => {
                    updateGutterScroll();
                    if (!state.syncScroll || state.isScrollingPreview) return;
                    state.isScrollingEditor = true;
                    const editorPct = textarea.scrollTop / (textarea.scrollHeight - textarea.clientHeight || 1);
                    previewScroll.scrollTop = editorPct * (previewScroll.scrollHeight - previewScroll.clientHeight);
                    setTimeout(() => { state.isScrollingEditor = false; }, 50);
                });

                previewScroll.addEventListener('scroll', () => {
                    if (!state.syncScroll || state.isScrollingEditor) return;
                    state.isScrollingPreview = true;
                    const previewPct = previewScroll.scrollTop / (previewScroll.scrollHeight - previewScroll.clientHeight || 1);
                    textarea.scrollTop = previewPct * (textarea.scrollHeight - textarea.clientHeight);
                    updateGutterScroll();
                    setTimeout(() => { state.isScrollingPreview = false; }, 50);
                });
            }

            textarea.addEventListener('keydown', (e) => {
                if (e.key === 'Tab') {
                    e.preventDefault();
                    insertAtCursor('  ');
                } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
                    e.preventDefault();
                    surroundSelection('**', '**', 'bold text');
                } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'i') {
                    e.preventDefault();
                    surroundSelection('*', '*', 'italic text');
                } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                    e.preventDefault();
                    surroundSelection('[', '](https://example.com)', 'link text');
                } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
                    e.preventDefault();
                    downloadMarkdownFile();
                } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'p') {
                    e.preventDefault();
                    exportPdfDocument();
                }
            });

            textarea.addEventListener('dragover', (e) => { e.preventDefault(); });
            textarea.addEventListener('drop', (e) => {
                e.preventDefault();
                if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
                    loadFile(e.dataTransfer.files[0]);
                }
            });

            textarea.addEventListener('keyup', updateCursorPos);
            textarea.addEventListener('click', updateCursorPos);
        }

        pane.querySelectorAll('.md-fbtn[data-action]').forEach(btn => {
            btn.addEventListener('click', () => {
                const act = btn.getAttribute('data-action');
                handleFormatAction(act);
            });
        });

        function closePopovers() {
            if (stylePop) stylePop.classList.remove('open');
            if (exportPop) exportPop.classList.remove('open');
        }

        if (btnStyle) {
            btnStyle.addEventListener('click', (e) => {
                e.stopPropagation();
                const isOpen = stylePop.classList.contains('open');
                closePopovers();
                if (!isOpen) stylePop.classList.add('open');
            });
        }
        if (btnExport) {
            btnExport.addEventListener('click', (e) => {
                e.stopPropagation();
                const isOpen = exportPop.classList.contains('open');
                closePopovers();
                if (!isOpen) exportPop.classList.add('open');
            });
        }
        window.addEventListener('click', () => { closePopovers(); });
        if (stylePop) stylePop.addEventListener('click', (e) => e.stopPropagation());
        if (exportPop) exportPop.addEventListener('click', (e) => e.stopPropagation());

        const themePills = document.querySelectorAll('.md-theme-pill');
        themePills.forEach((pill) => {
            pill.addEventListener('click', () => {
                const newTheme = pill.getAttribute('data-theme');
                if (!newTheme || newTheme === state.theme) return;
                state.theme = newTheme;
                themePills.forEach(p => p.classList.toggle('active', p.getAttribute('data-theme') === newTheme));
                const previewPanel = document.getElementById('md-preview-panel');
                if (previewPanel) {
                    previewPanel.classList.remove('theme-cyber-dark', 'theme-white');
                    previewPanel.classList.add(newTheme === 'white' ? 'theme-white' : 'theme-cyber-dark');
                }
                saveToStorage();
                renderPreview();
            });
        });

        const selectFont = document.getElementById('md-select-font');
        if (selectFont) {
            selectFont.addEventListener('change', (e) => {
                state.font = e.target.value;
                const doc = document.getElementById('md-doc');
                if (doc) doc.style.fontFamily = `'${state.font}', sans-serif`;
                saveToStorage();
            });
        }

        const toggleSync = document.getElementById('md-toggle-sync-scroll');
        if (toggleSync) {
            toggleSync.addEventListener('change', (e) => {
                state.syncScroll = e.target.checked;
                saveToStorage();
            });
        }

        const btnPdf = document.getElementById('md-export-pdf');
        if (btnPdf) btnPdf.addEventListener('click', () => { closePopovers(); exportPdfDocument(); });

        const btnMd = document.getElementById('md-export-md');
        if (btnMd) btnMd.addEventListener('click', () => { closePopovers(); downloadMarkdownFile(); });

        const btnHtml = document.getElementById('md-export-html');
        if (btnHtml) btnHtml.addEventListener('click', () => { closePopovers(); downloadHtmlReport(); });

        const btnCopyMd = document.getElementById('md-copy-md');
        if (btnCopyMd) btnCopyMd.addEventListener('click', () => { closePopovers(); copyMarkdown(); });

        const btnCopyHtml = document.getElementById('md-copy-html');
        if (btnCopyHtml) btnCopyHtml.addEventListener('click', () => { closePopovers(); copyHtml(); });

        const btnCopyPreview = document.getElementById('md-btn-copy-preview');
        if (btnCopyPreview) {
            btnCopyPreview.addEventListener('click', async () => {
                const doc = document.getElementById('md-doc');
                if (!doc) return;
                try {
                    const text = doc.innerText || doc.textContent || '';
                    await navigator.clipboard.writeText(text);
                    btnCopyPreview.innerHTML = '<i class="fa-solid fa-check" style="color:#22c55e;"></i> Copied!';
                    setTimeout(() => {
                        btnCopyPreview.innerHTML = '<i class="fa-regular fa-copy"></i> Copy Preview';
                    }, 1800);
                } catch (err) {
                    console.warn('Copy preview failed:', err);
                }
            });
        }

        const fileInput = document.getElementById('md-file-input');
        const btnImport = document.getElementById('md-import-file-btn');
        if (btnImport && fileInput) {
            btnImport.addEventListener('click', () => {
                closePopovers();
                fileInput.value = '';
                fileInput.click();
            });
            fileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) {
                    loadFile(e.target.files[0]);
                }
            });
        }

        if (btnPresets) {
            btnPresets.addEventListener('click', () => { root.classList.add('presets-open'); });
        }
        if (btnClosePresets) {
            btnClosePresets.addEventListener('click', () => { root.classList.remove('presets-open'); });
        }
        if (presetsScrim) {
            presetsScrim.addEventListener('click', () => { root.classList.remove('presets-open'); });
        }

        pane.querySelectorAll('[data-md-preset]').forEach(card => {
            card.addEventListener('click', () => {
                const key = card.getAttribute('data-md-preset');
                const preset = PRESETS[key];
                if (preset) {
                    state.title = preset.title;
                    state.markdown = preset.markdown;
                    if (titleInput) titleInput.value = state.title;
                    if (textarea) textarea.value = state.markdown;
                    updateLineNumbers();
                    updateStats();
                    renderPreview();
                    saveToStorage();
                    root.classList.remove('presets-open');
                }
            });
        });
    }

    function setView(view) {
        if (!['code', 'split', 'preview'].includes(view)) return;
        state.view = view;
        const root = document.getElementById('md-studio-root');
        if (root) root.setAttribute('data-view', view);
        document.querySelectorAll('.md-seg button[data-md-view]').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-md-view') === view);
        });
        if (view === 'preview' || view === 'split') {
            renderPreview();
        }
        saveToStorage();
    }

    function handleFormatAction(action) {
        switch (action) {
            case 'h1': prefixLines('# '); break;
            case 'h2': prefixLines('## '); break;
            case 'h3': prefixLines('### '); break;
            case 'bold': surroundSelection('**', '**', 'bold text'); break;
            case 'italic': surroundSelection('*', '*', 'italic text'); break;
            case 'strike': surroundSelection('~~', '~~', 'strikethrough text'); break;
            case 'code-inline': surroundSelection('`', '`', 'code'); break;
            case 'code-block': surroundSelection('```bash\n', '\n```', 'echo "hello world"'); break;
            case 'quote': prefixLines('> '); break;
            case 'link': surroundSelection('[', '](https://example.com)', 'link text'); break;
            case 'image': surroundSelection('![', '](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600)', 'diagram image'); break;
            case 'table':
                insertAtCursor('\n| Column 1 | Column 2 | Column 3 |\n|---|---|---|\n| Item A | Value 1 | Active |\n| Item B | Value 2 | Pending |\n\n');
                break;
            case 'task': prefixLines('- [ ] '); break;
            case 'ul': prefixLines('- '); break;
            case 'ol': prefixLines('1. '); break;
            case 'hr': insertAtCursor('\n\n---\n\n'); break;
            case 'alert-note':
                insertAtCursor('\n> [!NOTE]\n> Key takeaway or background information here.\n\n');
                break;
            case 'alert-warn':
                insertAtCursor('\n> [!WARNING]\n> Critical security risk or warning notice.\n\n');
                break;
        }
    }

    function insertAtCursor(text) {
        const ta = document.getElementById('md-textarea');
        if (!ta) return;
        const start = ta.selectionStart;
        const end = ta.selectionEnd;
        const val = ta.value;
        ta.value = val.substring(0, start) + text + val.substring(end);
        ta.selectionStart = ta.selectionEnd = start + text.length;
        ta.focus();
        ta.dispatchEvent(new Event('input'));
    }

    function surroundSelection(prefix, suffix, defaultText) {
        const ta = document.getElementById('md-textarea');
        if (!ta) return;
        const start = ta.selectionStart;
        const end = ta.selectionEnd;
        const val = ta.value;
        const selected = val.substring(start, end) || defaultText;
        const replacement = prefix + selected + suffix;
        ta.value = val.substring(0, start) + replacement + val.substring(end);
        ta.selectionStart = start + prefix.length;
        ta.selectionEnd = start + prefix.length + selected.length;
        ta.focus();
        ta.dispatchEvent(new Event('input'));
    }

    function prefixLines(prefix) {
        const ta = document.getElementById('md-textarea');
        if (!ta) return;
        const start = ta.selectionStart;
        const end = ta.selectionEnd;
        const val = ta.value;
        const lineStart = val.lastIndexOf('\n', start - 1) + 1;
        let lineEnd = val.indexOf('\n', end);
        if (lineEnd === -1) lineEnd = val.length;
        const selectedText = val.substring(lineStart, lineEnd);
        const modified = selectedText.split('\n').map(l => prefix + l).join('\n');
        ta.value = val.substring(0, lineStart) + modified + val.substring(lineEnd);
        ta.selectionStart = lineStart;
        ta.selectionEnd = lineStart + modified.length;
        ta.focus();
        ta.dispatchEvent(new Event('input'));
    }

    function updateLineNumbers() {
        const ta = document.getElementById('md-textarea');
        const gutter = document.getElementById('md-gutter');
        if (!ta || !gutter) return;
        const count = Math.max(1, ta.value.split('\n').length);
        const nums = [];
        for (let i = 1; i <= count; i++) nums.push(i);
        gutter.textContent = nums.join('\n');
    }

    function updateGutterScroll() {
        const ta = document.getElementById('md-textarea');
        const gutter = document.getElementById('md-gutter');
        if (ta && gutter) gutter.scrollTop = ta.scrollTop;
    }

    function updateCursorPos() {
        const ta = document.getElementById('md-textarea');
        const posEl = document.getElementById('md-editor-cursor-pos');
        if (!ta || !posEl) return;
        const lines = ta.value.substring(0, ta.selectionStart).split('\n');
        const line = lines.length;
        const col = lines[lines.length - 1].length + 1;
        posEl.textContent = `Ln ${line}, Col ${col}`;
    }

    function updateStats() {
        const text = state.markdown || '';
        const words = (text.match(/\b\w+\b/g) || []).length;
        const chars = text.length;
        const readTime = Math.max(1, Math.ceil(words / 200));
        const wEl = document.getElementById('md-stat-words');
        const cEl = document.getElementById('md-stat-chars');
        const rEl = document.getElementById('md-stat-reading-time');
        const statusPill = document.getElementById('md-status-pill');
        if (wEl) wEl.textContent = `${words.toLocaleString()} WORDS`;
        if (cEl) cEl.textContent = `${chars.toLocaleString()} CHARS`;
        if (rEl) rEl.textContent = `~${readTime} MIN READ`;
        if (statusPill) statusPill.textContent = `${words} WORDS`;
    }

    function renderPreview() {
        const doc = document.getElementById('md-doc');
        if (!doc) return;
        const html = renderMarkdownToHtml(state.markdown);
        doc.innerHTML = html;
        renderMermaidBlocks(doc);
    }

    function downloadMarkdownFile() {
        const safeTitle = (state.title || 'document').replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        const blob = new Blob([state.markdown], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${safeTitle}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function exportPdfDocument() {
        const doc = document.getElementById('md-doc');
        if (!doc) return;

        // Clone doc and remove any copy buttons so they never appear in print/PDF
        const clone = doc.cloneNode(true);
        clone.querySelectorAll('.md-copy-code-btn, button').forEach(b => b.remove());
        const docHtml = clone.innerHTML;

        const title = state.title || 'MANTIS Report';
        const printWindow = window.open('', '_blank');
        if (!printWindow) {
            window.print();
            return;
        }
        printWindow.document.write(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,600;0,700;1,400&family=Plus+Jakarta+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
  @page { margin: 20mm 15mm; size: A4; }
  body {
    font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
    color: #1e293b; line-height: 1.6; font-size: 10pt; margin: 0; padding: 0;
    background: #ffffff;
  }
  .print-header {
    border-bottom: 2px solid #0284c7; padding-bottom: 8px; margin-bottom: 20px;
    display: flex; justify-content: space-between; align-items: flex-end;
  }
  .print-header h1 { margin: 0; font-size: 18pt; color: #0f172a; }
  .print-header .meta { font-size: 8pt; color: #64748b; }
  h1, h2, h3, h4 { color: #0f172a; margin-top: 1.3em; margin-bottom: 0.4em; }
  h1 { font-size: 16pt; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
  h2 { font-size: 13pt; border-bottom: 1px solid #f1f5f9; padding-bottom: 3px; }
  h3 { font-size: 11pt; }
  table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 9.5pt; page-break-inside: avoid; }
  th, td { border: 1px solid #cbd5e1; padding: 6px 10px; text-align: left; }
  th { background: #f8fafc; font-weight: bold; }
  tr:nth-child(even) td { background: #f8fafc; }
  pre, .md-code-block {
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
    margin: 12px 0; font-family: 'JetBrains Mono', monospace !important; font-size: 8.5pt; page-break-inside: avoid;
    overflow: hidden;
  }
  .md-code-header {
    background: #f1f5f9; border-bottom: 1px solid #e2e8f0; padding: 6px 12px;
    font-size: 7.5pt; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .md-code-pre {
    margin: 0; padding: 10px 14px; background: transparent; overflow-x: auto;
  }
  code, pre code { font-family: 'JetBrains Mono', monospace !important; font-size: 8.5pt; line-height: 1.5; }
  code:not(pre code) { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; color: #0284c7; }
  .md-copy-code-btn, button { display: none !important; }
  blockquote { border-left: 3px solid #0284c7; padding: 6px 14px; margin: 12px 0; background: #f0f9ff; color: #334155; }
  .md-alert { border-left: 4px solid #0284c7; padding: 8px 12px; margin: 12px 0; background: #f0f9ff; border-radius: 4px; }
  .md-alert-title { font-weight: bold; color: #0284c7; margin-bottom: 4px; }
  .md-task-item { list-style-type: none; display: flex; align-items: center; gap: 6px; }
  .print-footer {
    position: fixed; bottom: 0; left: 0; right: 0;
    border-top: 1px solid #e2e8f0; padding-top: 6px;
    display: flex; justify-content: space-between; font-size: 8pt; color: #94a3b8;
  }
</style>
</head>
<body>
  <div class="print-header">
    <div>
      <h1>${esc(title)}</h1>
      <div class="meta">MANTIS Threat Intelligence & Research Report</div>
    </div>
    <div class="meta">Exported: ${new Date().toLocaleDateString()}</div>
  </div>
  ${docHtml}
  <script>
    window.addEventListener('load', () => {
      setTimeout(() => {
        window.print();
        setTimeout(() => window.close(), 1000);
      }, 400);
    });
  <\/script>
</body>
</html>`);
        printWindow.document.close();
    }

    function downloadHtmlReport() {
        const safeTitle = (state.title || 'document').replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        const docHtml = document.getElementById('md-doc') ? document.getElementById('md-doc').innerHTML : '';
        const fullHtml = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>${esc(state.title)}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
  body { font-family: 'Plus Jakarta Sans', system-ui, sans-serif; background: #070b12; color: #e2e8f0; line-height: 1.7; padding: 40px; }
  .container { max-width: 860px; margin: 0 auto; background: #090e17; padding: 40px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); }
  h1, h2, h3 { color: #f8fafc; font-weight: 700; }
  h1 { border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.3em; }
  table { width: 100%; border-collapse: collapse; margin: 20px 0; border: 1px solid rgba(255,255,255,0.1); }
  th, td { padding: 8px 12px; border: 1px solid rgba(255,255,255,0.08); }
  th { background: rgba(255,255,255,0.05); }
  code, pre { font-family: 'JetBrains Mono', monospace !important; }
  code { background: rgba(255,255,255,0.08); color: #38bdf8; padding: 2px 6px; border-radius: 4px; }
  pre { background: #05080f; padding: 14px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); overflow-x: auto; }
  blockquote { border-left: 4px solid #38bdf8; padding: 8px 16px; background: rgba(56,189,248,0.05); }
  .md-alert { border-left: 4px solid #38bdf8; padding: 12px 16px; border-radius: 8px; background: rgba(56,189,248,0.08); margin: 1em 0; }
  .md-alert-title { font-weight: 700; color: #38bdf8; margin-bottom: 4px; }
  a { color: #38bdf8; text-decoration: none; }
</style>
</head>
<body>
  <div class="container">
    ${docHtml}
  </div>
</body>
</html>`;
        const blob = new Blob([fullHtml], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${safeTitle}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function copyMarkdown() {
        navigator.clipboard.writeText(state.markdown).then(() => {
            const pill = document.getElementById('md-status-pill');
            if (pill) {
                const prev = pill.textContent;
                pill.textContent = 'COPIED MD!';
                setTimeout(() => pill.textContent = prev, 1500);
            }
        });
    }

    function copyHtml() {
        const doc = document.getElementById('md-doc');
        if (!doc) return;
        navigator.clipboard.writeText(doc.innerHTML).then(() => {
            const pill = document.getElementById('md-status-pill');
            if (pill) {
                const prev = pill.textContent;
                pill.textContent = 'COPIED HTML!';
                setTimeout(() => pill.textContent = prev, 1500);
            }
        });
    }

    function loadFile(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            state.markdown = e.target.result || '';
            const name = file.name.replace(/\.[^/.]+$/, '');
            state.title = name;
            const titleInput = document.getElementById('md-title-input');
            const textarea = document.getElementById('md-textarea');
            if (titleInput) titleInput.value = state.title;
            if (textarea) textarea.value = state.markdown;
            updateLineNumbers();
            updateStats();
            renderPreview();
            saveToStorage();
        };
        reader.readAsText(file);
    }

    window.openMarkdownDraw = function () {
        initMarkdownStudio();
    };

    document.addEventListener('DOMContentLoaded', () => {
        const pane = document.getElementById('markdown-draw-pane');
        if (pane && pane.style.display !== 'none') {
            initMarkdownStudio();
        }
    });

})();
