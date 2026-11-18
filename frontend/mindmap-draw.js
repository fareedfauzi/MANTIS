/**
 * MANTIS Mind Map Studio — Executive Threat Modeling & Brainstorming Engine
 * Redesigned for maximum clarity, speed, and focus (inspired by XMind, MindNode, & Whimsical)
 *
 * Key Highlights:
 * - Always-Centered Viewport: Mindmap centers perfectly on canvas every time it opens or re-layouts
 * - Balanced Horizontal Mind Map Engine (left & right branching) + Logic Chart (right) + Org Chart (down)
 * - Outline Treeview in Left Sidebar (replaces 50+ useless decorative emoji markers)
 * - Focused Topic Inspector: Title, Note, Shape, Color swatch, Priority tag (P1..P4), +Subtopic, +Sibling, Delete
 * - Streamlined Topbar: Structure selector, Theme palette, Tab/Enter quick-actions, Presets, Style, Export
 * - Full High-DPI 2X Export: PNG (Transparent, Dark, White), Vector SVG, Markdown Outline (.md), .mantis-mindmap
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'mantis_mindmap_v3';
    const SVG_NS = 'http://www.w3.org/2000/svg';

    // Curated Theme Palettes
    const THEMES = {
        'cyber-neon': {
            label: 'Cyber Neon (MANTIS)',
            bgDark: '#080c14',
            canvasDark: '#070b12',
            rootFill: '#1a1033',
            rootStroke: '#a855f7',
            rootColor: '#f8fafc',
            branchColors: ['#a855f7', '#06b6d4', '#f59e0b', '#ec4899', '#10b981', '#3b82f6', '#f97316'],
            nodeFill: '#0d1526',
            nodeStroke: '#1e293b',
            textColor: '#e2e8f0',
            subtextColor: '#94a3b8'
        },
        'cyber-dark': {
            label: 'Cyber Dark (Minimal)',
            bgDark: '#05070b',
            canvasDark: '#040609',
            rootFill: '#0f172a',
            rootStroke: '#38bdf8',
            rootColor: '#f8fafc',
            branchColors: ['#38bdf8', '#818cf8', '#34d399', '#fbbf24', '#f87171', '#c084fc'],
            nodeFill: '#0b1120',
            nodeStroke: '#1e293b',
            textColor: '#e2e8f0',
            subtextColor: '#64748b'
        },
        'nordic-slate': {
            label: 'Nordic Slate (Blue)',
            bgDark: '#0b0f19',
            canvasDark: '#090d16',
            rootFill: '#1e293b',
            rootStroke: '#60a5fa',
            rootColor: '#ffffff',
            branchColors: ['#60a5fa', '#38bdf8', '#4ade80', '#fbbf24', '#f472b6', '#a78bfa'],
            nodeFill: '#111827',
            nodeStroke: '#1f2937',
            textColor: '#f3f4f6',
            subtextColor: '#9ca3af'
        },
        'executive-gold': {
            label: 'Executive Gold (Finance)',
            bgDark: '#0c0e12',
            canvasDark: '#090a0d',
            rootFill: '#272010',
            rootStroke: '#f59e0b',
            rootColor: '#fffbeb',
            branchColors: ['#f59e0b', '#d97706', '#ca8a04', '#65a30d', '#0d9488', '#2563eb'],
            nodeFill: '#171920',
            nodeStroke: '#2a2d38',
            textColor: '#f8fafc',
            subtextColor: '#a1a1aa'
        },
        'monochrome': {
            label: 'Monochrome Stealth (DoD)',
            bgDark: '#000000',
            canvasDark: '#050505',
            rootFill: '#171717',
            rootStroke: '#ffffff',
            rootColor: '#ffffff',
            branchColors: ['#ffffff', '#d4d4d4', '#a3a3a3', '#737373', '#e5e5e5'],
            nodeFill: '#121212',
            nodeStroke: '#262626',
            textColor: '#f5f5f5',
            subtextColor: '#737373'
        }
    };

    // Prebuilt Mindmap Scenarios
    const PREBUILT_TEMPLATES = {
        'cti-campaign': {
            title: 'Operation ShadowGrid: APT Attribution & Threat Model',
            structure: 'mindmap',
            theme: 'cyber-neon',
            lineStyle: 'curved',
            topics: [
                { id: 'root', text: 'Operation ShadowGrid\n(UNC-4820 Campaign)', note: 'Strategic Intrusion Analysis & Attribution Q4', shape: 'rounded', priority: null },
                // Branch 1: Initial Access
                { id: 't1', parentId: 'root', text: 'Initial Access Vectors', note: 'External Edge Exploitation', priority: 'P1' },
                { id: 't1_1', parentId: 't1', text: 'CVE-2024-21887 (Ivanti VPN RCE)', note: 'Zero-Day Auth Bypass' },
                { id: 't1_2', parentId: 't1', text: 'Spear-Phishing via QR / AiTM', note: 'Targeted Executive Inboxes' },
                { id: 't1_3', parentId: 't1', text: 'Compromised Contractor Creds', note: 'Stolen via Lumma Stealer' },
                // Branch 2: C2 Infrastructure
                { id: 't2', parentId: 'root', text: 'C2 & Comm Infrastructure', note: 'Resilient Multi-Tier Proxy Mesh', priority: 'P1' },
                { id: 't2_1', parentId: 't2', text: 'ShadowMesh Fast-Flux VPS Mesh', note: 'Hosting in Bulletproof ASNs' },
                { id: 't2_2', parentId: 't2', text: 'DNS-over-HTTPS Tunneling', note: 'Bypassing Perimeter Next-Gen FW' },
                { id: 't2_3', parentId: 't2', text: 'Telegram API Fallback Beacon', note: 'Dead-Drop Dead Resolver' },
                // Branch 3: Lateral Movement
                { id: 't3', parentId: 'root', text: 'Lateral Movement & Privilege', note: 'Living-off-the-Land (LOTL)', priority: 'P2' },
                { id: 't3_1', parentId: 't3', text: 'NTDS.dit & LSASS Extraction', note: 'DCSync Attack Executed' },
                { id: 't3_2', parentId: 't3', text: 'GPO Scheduled Task Push', note: 'Deployed to 420 Workstations' },
                { id: 't3_3', parentId: 't3', text: 'BloodHound Path Traversal', note: 'Identified Tier-0 Admin Path' },
                // Branch 4: Attribution
                { id: 't4', parentId: 'root', text: 'Attribution & Geopolitics', note: 'High Confidence State Actor', priority: 'P1' },
                { id: 't4_1', parentId: 't4', text: 'Working Hours (UTC+8 Cluster)', note: 'Strict 09:00 - 18:00 Commits' },
                { id: 't4_2', parentId: 't4', text: 'Code Reuse: PlugX / ShadowPad', note: 'Shared Custom XOR Crypter' },
                { id: 't4_3', parentId: 't4', text: 'Targeting: Defense & Semiconductors', note: 'APAC & North America' }
            ]
        },
        'incident-response': {
            title: 'DFIR 72-Hour Ransomware Incident Response Playbook',
            structure: 'logic-right',
            theme: 'cyber-dark',
            lineStyle: 'curved',
            topics: [
                { id: 'root', text: 'Ransomware Containment\n& Forensics War Room', note: 'SEV-1 Incident Playbook', shape: 'rounded' },
                { id: 'ir1', parentId: 'root', text: 'Phase 1: Identification & Triage', priority: 'P1' },
                { id: 'ir1_1', parentId: 'ir1', text: 'Isolate Hyper-V & ESXi Hosts' },
                { id: 'ir1_2', parentId: 'ir1', text: 'Revoke KRBTGT Account Password' },
                { id: 'ir1_3', parentId: 'ir1', text: 'Preserve RAM Artifacts with LiME' },
                { id: 'ir2', parentId: 'root', text: 'Phase 2: Scope & Eradication', priority: 'P2' },
                { id: 'ir2_1', parentId: 'ir2', text: 'Scan Domain for Cobalt Strike Beacons' },
                { id: 'ir2_2', parentId: 'ir2', text: 'Purge Persistence Registry Run Keys' },
                { id: 'ir2_3', parentId: 'ir2', text: 'Block Egress IP Addresses on Perimeter' },
                { id: 'ir3', parentId: 'root', text: 'Phase 3: Clean Recovery & Hardening', priority: 'P3' },
                { id: 'ir3_1', parentId: 'ir3', text: 'Restore from Immutable Cold Backups' },
                { id: 'ir3_2', parentId: 'ir3', text: 'Enforce FIDO2 WebAuthn MFA' }
            ]
        },
        'malware-analysis': {
            title: 'Reverse Engineering: Advanced Loader Detonation',
            structure: 'mindmap',
            theme: 'nordic-slate',
            lineStyle: 'rounded',
            topics: [
                { id: 'root', text: 'Malware Sample Analysis\nSHA256: 8f4e2a...c01', note: 'Threat Intel Artifact Breakdown' },
                { id: 'm1', parentId: 'root', text: 'Static Characteristics' },
                { id: 'm1_1', parentId: 'm1', text: 'Packed with Custom VMProtect 3.8' },
                { id: 'm1_2', parentId: 'm1', text: 'Signed with Stolen WHQL Certificate' },
                { id: 'm2', parentId: 'root', text: 'Anti-Analysis & Evasion' },
                { id: 'm2_1', parentId: 'm2', text: 'Checks for Sandbox Hardware IDs' },
                { id: 'm2_2', parentId: 'm2', text: 'Hooks NtQueryInformationProcess' },
                { id: 'm3', parentId: 'root', text: 'Payload Extraction' },
                { id: 'm3_1', parentId: 'm3', text: 'Reflective DLL Injection into explorer.exe' },
                { id: 'm3_2', parentId: 'm3', text: 'Encrypted RC4 Payload in .rsrc Section' }
            ]
        },
        'blank': {
            title: 'New Brainstorming Mind Map',
            structure: 'mindmap',
            theme: 'cyber-neon',
            lineStyle: 'curved',
            topics: [
                { id: 'root', text: 'Central Topic', note: 'Start brainstorming here...' }
            ]
        }
    };

    const state = {
        initialized: false,
        title: PREBUILT_TEMPLATES['cti-campaign'].title,
        structure: 'mindmap', // 'mindmap' | 'logic-right' | 'org-chart'
        theme: 'cyber-neon',
        lineStyle: 'curved', // 'curved' | 'rounded' | 'straight'
        canvasBg: 'dark', // 'dark' | 'white' | 'transparent'
        globalFont: 'Plus Jakarta Sans',
        topics: JSON.parse(JSON.stringify(PREBUILT_TEMPLATES['cti-campaign'].topics)),
        selectedId: 'root',
        searchQuery: '',
        zoom: 1,
        panX: 0,
        panY: 0,
        isPanning: false,
        panStart: { x: 0, y: 0 },
        dragDistance: 0,
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

    function getTopic(id) {
        return state.topics.find(t => t.id === id) || null;
    }

    function getChildren(parentId) {
        return state.topics.filter(t => t.parentId === parentId);
    }

    function isDescendant(candidateId, ancestorId) {
        let cur = getTopic(candidateId);
        while (cur && cur.parentId) {
            if (cur.parentId === ancestorId) return true;
            cur = getTopic(cur.parentId);
        }
        return false;
    }

    function pushHistory() {
        const snap = JSON.stringify({
            title: state.title,
            structure: state.structure,
            theme: state.theme,
            lineStyle: state.lineStyle,
            topics: state.topics
        });
        if (state.historyIndex >= 0 && state.history[state.historyIndex] === snap) return;
        state.history = state.history.slice(0, state.historyIndex + 1);
        state.history.push(snap);
        if (state.history.length > 50) state.history.shift();
        state.historyIndex = state.history.length - 1;
        saveToStorage();
    }

    function saveToStorage() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                title: state.title,
                structure: state.structure,
                theme: state.theme,
                lineStyle: state.lineStyle,
                canvasBg: state.canvasBg,
                globalFont: state.globalFont,
                topics: state.topics
            }));
        } catch (e) { /* ignore */ }
    }

    function loadFromStorage() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return false;
            const parsed = JSON.parse(raw);
            if (parsed && Array.isArray(parsed.topics) && parsed.topics.length > 0) {
                state.title = parsed.title || PREBUILT_TEMPLATES['cti-campaign'].title;
                state.structure = parsed.structure || 'mindmap';
                state.theme = parsed.theme || 'cyber-neon';
                state.lineStyle = parsed.lineStyle || 'curved';
                state.canvasBg = parsed.canvasBg || 'dark';
                state.globalFont = parsed.globalFont || 'Plus Jakarta Sans';
                state.topics = parsed.topics;
                return true;
            }
        } catch (e) { /* ignore */ }
        return false;
    }

    function loadTemplate(key) {
        const tpl = PREBUILT_TEMPLATES[key];
        if (!tpl) return;
        state.title = tpl.title;
        state.structure = tpl.structure || 'mindmap';
        state.theme = tpl.theme || 'cyber-neon';
        state.lineStyle = tpl.lineStyle || 'curved';
        state.topics = JSON.parse(JSON.stringify(tpl.topics));
        state.selectedId = 'root';

        const titleIn = document.getElementById('mm-title-input');
        if (titleIn) titleIn.value = state.title;
        const structSel = document.getElementById('mm-struct-select');
        if (structSel) structSel.value = state.structure;
        const themeSel = document.getElementById('mm-theme-select');
        if (themeSel) themeSel.value = state.theme;

        pushHistory();
        computeLayout();
        renderPalette();
        renderCanvas();
        renderInspector();
        closePresets();
        setTimeout(centerView, 50);
    }

    // =========================================================================
    // MEASUREMENT & BALANCED HORIZONTAL MINDMAP LAYOUT
    // =========================================================================
    function measureTopicBox(t, isRoot) {
        const text = t.text || (isRoot ? 'Central Topic' : 'Subtopic');
        const lines = text.split('\n');
        const maxLen = lines.reduce((m, l) => Math.max(m, l.length), 0);

        if (isRoot) {
            t._w = Math.max(180, Math.min(320, maxLen * 10 + 44));
            t._h = lines.length > 1 ? 58 : 46;
            if (t.note) t._h += 16;
        } else {
            t._w = Math.max(120, Math.min(260, maxLen * 7.5 + 32));
            t._h = lines.length > 1 ? 44 : 32;
            if (t.note) t._h += 14;
        }
    }

    function computeLayout() {
        const root = getTopic('root') || state.topics[0];
        if (!root) return;

        state.topics.forEach(t => {
            measureTopicBox(t, t.id === root.id);
        });

        // Center origin coordinates for layout space
        const originX = 1000;
        const originY = 600;
        root.x = originX - root._w / 2;
        root.y = originY - root._h / 2;
        root._side = 'center';

        const curTheme = THEMES[state.theme] || THEMES['cyber-neon'];
        const branchColors = curTheme.branchColors;

        // Assign distinct branch colors to root's immediate children
        const rootKids = getChildren(root.id);
        rootKids.forEach((k, idx) => {
            const col = branchColors[idx % branchColors.length];
            assignColorDownTree(k, col);
        });

        const H_GAP = 72;
        const V_GAP = 18;

        function calcSubtreeHeight(t) {
            if (t.collapsed) {
                t._subtreeH = t._h;
                return t._subtreeH;
            }
            const kids = getChildren(t.id);
            if (!kids.length) {
                t._subtreeH = t._h;
                return t._subtreeH;
            }
            let total = 0;
            kids.forEach((k, i) => {
                total += calcSubtreeHeight(k);
                if (i > 0) total += V_GAP;
            });
            t._subtreeH = Math.max(t._h, total);
            return t._subtreeH;
        }

        function layoutHorizontal(t, startX, centerY, dir) {
            t._side = dir > 0 ? 'right' : 'left';
            t.x = dir > 0 ? startX : (startX - t._w);
            t.y = centerY - t._h / 2;

            if (t.collapsed) return;
            const kids = getChildren(t.id);
            if (!kids.length) return;

            let totalKidsH = 0;
            kids.forEach((k, i) => {
                totalKidsH += k._subtreeH;
                if (i > 0) totalKidsH += V_GAP;
            });

            const nextStartX = dir > 0 ? (t.x + t._w + H_GAP) : (t.x - H_GAP);
            let curY = centerY - totalKidsH / 2;

            kids.forEach(k => {
                const kCenterY = curY + k._subtreeH / 2;
                layoutHorizontal(k, nextStartX, kCenterY, dir);
                curY += k._subtreeH + V_GAP;
            });
        }

        if (state.structure === 'mindmap') {
            // CLASSIC BALANCED HORIZONTAL MIND MAP:
            // Half children go Right, half go Left!
            const rightKids = [];
            const leftKids = [];

            rootKids.forEach((k, i) => {
                if (i % 2 === 0) rightKids.push(k);
                else leftKids.push(k);
            });

            rightKids.forEach(calcSubtreeHeight);
            leftKids.forEach(calcSubtreeHeight);

            // Layout Right Branch
            let totalRightH = 0;
            rightKids.forEach((k, i) => {
                totalRightH += k._subtreeH;
                if (i > 0) totalRightH += V_GAP;
            });
            let curRightY = originY - totalRightH / 2;
            rightKids.forEach(k => {
                const kCy = curRightY + k._subtreeH / 2;
                layoutHorizontal(k, root.x + root._w + H_GAP, kCy, 1);
                curRightY += k._subtreeH + V_GAP;
            });

            // Layout Left Branch
            let totalLeftH = 0;
            leftKids.forEach((k, i) => {
                totalLeftH += k._subtreeH;
                if (i > 0) totalLeftH += V_GAP;
            });
            let curLeftY = originY - totalLeftH / 2;
            leftKids.forEach(k => {
                const kCy = curLeftY + k._subtreeH / 2;
                layoutHorizontal(k, root.x - H_GAP, kCy, -1);
                curLeftY += k._subtreeH + V_GAP;
            });

        } else if (state.structure === 'logic-right') {
            // LOGIC CHART: All children branch out to the right
            rootKids.forEach(calcSubtreeHeight);
            let totalH = 0;
            rootKids.forEach((k, i) => {
                totalH += k._subtreeH;
                if (i > 0) totalH += V_GAP;
            });
            let curY = originY - totalH / 2;
            rootKids.forEach(k => {
                const kCy = curY + k._subtreeH / 2;
                layoutHorizontal(k, root.x + root._w + H_GAP, kCy, 1);
                curY += k._subtreeH + V_GAP;
            });

        } else if (state.structure === 'org-chart') {
            // ORG CHART: Root at top, children cascade downward
            const ORG_HGAP = 32;
            const ORG_VGAP = 54;

            function calcSubtreeW(t) {
                if (t.collapsed) {
                    t._subtreeW = t._w;
                    return t._subtreeW;
                }
                const kids = getChildren(t.id);
                if (!kids.length) {
                    t._subtreeW = t._w;
                    return t._subtreeW;
                }
                let total = 0;
                kids.forEach((k, i) => {
                    total += calcSubtreeW(k);
                    if (i > 0) total += ORG_HGAP;
                });
                t._subtreeW = Math.max(t._w, total);
                return t._subtreeW;
            }

            function layoutOrg(t, centerX, startY) {
                t._side = 'down';
                t.x = centerX - t._w / 2;
                t.y = startY;

                if (t.collapsed) return;
                const kids = getChildren(t.id);
                if (!kids.length) return;

                let totalKidsW = 0;
                kids.forEach((k, i) => {
                    totalKidsW += k._subtreeW;
                    if (i > 0) totalKidsW += ORG_HGAP;
                });

                let curX = centerX - totalKidsW / 2;
                const nextY = t.y + t._h + ORG_VGAP;

                kids.forEach(k => {
                    const kCx = curX + k._subtreeW / 2;
                    layoutOrg(k, kCx, nextY);
                    curX += k._subtreeW + ORG_HGAP;
                });
            }

            calcSubtreeW(root);
            layoutOrg(root, originX, originY);
        }
    }

    function assignColorDownTree(topic, color) {
        if (!topic.customColor) topic._branchColor = color;
        getChildren(topic.id).forEach(k => assignColorDownTree(k, color));
    }

    // =========================================================================
    // CENTER VIEWPORT (FIXES "CHART AT BOTTOM" BUG!)
    // =========================================================================
    function centerView() {
        const svg = document.getElementById('mm-svg-canvas');
        if (!svg || !state.topics.length) return;
        const rect = svg.getBoundingClientRect();
        if (!rect.width || !rect.height) return;

        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        state.topics.forEach(t => {
            if (typeof t.x !== 'number') return;
            minX = Math.min(minX, t.x);
            minY = Math.min(minY, t.y);
            maxX = Math.max(maxX, t.x + (t._w || 160));
            maxY = Math.max(maxY, t.y + (t._h || 48));
        });

        const contentW = Math.max(240, maxX - minX);
        const contentH = Math.max(180, maxY - minY);
        const contentCenterX = (minX + maxX) / 2;
        const contentCenterY = (minY + maxY) / 2;

        const padding = 60;
        const scale = Math.min(1.05, Math.max(0.35, Math.min(
            (rect.width - padding * 2) / contentW,
            (rect.height - padding * 2) / contentH
        )));

        state.zoom = scale;
        state.panX = rect.width / 2 - contentCenterX * scale;
        state.panY = rect.height / 2 - contentCenterY * scale;

        const vp = document.getElementById('mm-viewport');
        if (vp) vp.setAttribute('transform', `translate(${state.panX}, ${state.panY}) scale(${state.zoom})`);

        const zoomLbl = document.getElementById('mm-zoom-label');
        if (zoomLbl) zoomLbl.textContent = `${Math.round(state.zoom * 100)}%`;
    }

    // =========================================================================
    // UI SHELL INITIALIZATION
    // =========================================================================
    function initMindmapStudio() {
        const pane = document.getElementById('mindmap-draw-pane');
        if (!pane) return;

        if (!state.initialized) {
            if (!loadFromStorage()) {
                const tpl = PREBUILT_TEMPLATES['cti-campaign'];
                state.title = tpl.title;
                state.structure = tpl.structure;
                state.theme = tpl.theme;
                state.lineStyle = tpl.lineStyle;
                state.topics = JSON.parse(JSON.stringify(tpl.topics));
            }
            state.initialized = true;
            pushHistory();
        }

        renderShell(pane);
        computeLayout();
        renderPalette();
        renderCanvas();
        renderInspector();
        bindEvents();

        // Immediate + delayed centerView ensures clean layout after DOM paint
        centerView();
        setTimeout(centerView, 60);
        setTimeout(centerView, 180);
    }

    function renderShell(pane) {
        pane.innerHTML = `
            <div class="mm-root" id="mm-studio-root">
                <!-- TOP BAR (52px Linear/Geist Style) -->
                <header class="mm-top">
                    <!-- Left: Brand + Title + Topic Count -->
                    <div class="mm-top-left">
                        <div class="mm-logo" title="MANTIS Mind Map Studio">
                            <i class="fa-solid fa-brain"></i>
                        </div>
                        <input type="text" class="mm-title" id="mm-title-input" value="${esc(state.title)}" title="Click to rename Mindmap" />
                        <span class="mm-status" id="mm-status-pill">${state.topics.length} TOPICS</span>
                    </div>

                    <!-- Center: Layout + Theme + Quick Add Buttons -->
                    <div class="mm-tools">
                        <div class="mm-seg" role="group" aria-label="Layout & Theme">
                            <select id="mm-struct-select" title="Mindmap Structure">
                                <option value="mindmap" ${state.structure === 'mindmap' ? 'selected' : ''}>Mind Map (Balanced)</option>
                                <option value="logic-right" ${state.structure === 'logic-right' ? 'selected' : ''}>Logic Chart (Right)</option>
                                <option value="org-chart" ${state.structure === 'org-chart' ? 'selected' : ''}>Org Chart (Down)</option>
                            </select>
                            <select id="mm-theme-select" title="Visual Theme">
                                ${Object.entries(THEMES).map(([k, v]) => `<option value="${k}" ${state.theme === k ? 'selected' : ''}>Theme: ${esc(v.label)}</option>`).join('')}
                            </select>
                        </div>

                        <div class="mm-seg" role="group" aria-label="Topic Actions">
                            <button type="button" id="mm-btn-add-subtopic" class="primary" title="Add Child Topic (Tab)">
                                <i class="fa-solid fa-plus"></i><span>+ Subtopic</span>
                            </button>
                            <button type="button" id="mm-btn-add-sibling" title="Add Sibling Topic (Enter)">
                                <i class="fa-solid fa-arrows-split-up-and-left"></i><span>+ Sibling</span>
                            </button>
                        </div>
                    </div>

                    <!-- Right: Presets + Style + Export -->
                    <div class="mm-top-right">
                        <button type="button" class="mm-tbtn" id="mm-btn-presets" title="Browse Mindmap Scenarios">
                            <i class="fa-solid fa-wand-magic-sparkles" style="color:#c084fc;"></i>
                            <span>Presets</span>
                        </button>

                        <div class="map-pop-wrap">
                            <button type="button" class="mm-tbtn" id="mm-btn-style-pop" title="Mindmap Style Settings">
                                <i class="fa-solid fa-sliders"></i>
                                <span>Style</span>
                                <i class="fa-solid fa-chevron-down mmd-caret"></i>
                            </button>
                            <div class="map-pop" id="mm-style-pop">
                                <div class="map-pop-sec">CONNECTOR BRANCH STYLE</div>
                                <div class="map-pop-item" data-line-style="curved"><i class="fa-solid fa-bezier-curve"></i>Organic Curved (Smooth)</div>
                                <div class="map-pop-item" data-line-style="rounded"><i class="fa-solid fa-draw-polygon"></i>Rounded Orthogonal</div>
                                <div class="map-pop-item" data-line-style="straight"><i class="fa-solid fa-slash"></i>Straight Lines</div>
                                <div class="map-pop-sec" style="margin-top:8px;">TYPOGRAPHY</div>
                                <select class="dd-select" id="mm-font-select" style="width:100%;font-size:0.75rem;">
                                    <option value="Plus Jakarta Sans" ${state.globalFont.includes('Jakarta') ? 'selected' : ''}>Plus Jakarta Sans</option>
                                    <option value="Inter" ${state.globalFont === 'Inter' ? 'selected' : ''}>Inter</option>
                                    <option value="JetBrains Mono" ${state.globalFont.includes('Mono') ? 'selected' : ''}>JetBrains Mono</option>
                                </select>
                            </div>
                        </div>

                        <div class="map-pop-wrap">
                            <button type="button" class="mm-tbtn mm-primary" id="mm-btn-export-pop">
                                <i class="fa-solid fa-arrow-down-to-bracket"></i>
                                <span>Export</span>
                                <i class="fa-solid fa-chevron-down mmd-caret"></i>
                            </button>
                            <div class="map-pop" id="mm-export-pop">
                                <div class="map-pop-sec">HIGH-DPI PNG (2X)</div>
                                <button type="button" class="map-pop-item" data-mm-export="png-transparent"><span class="dd-dot-swatch dd-dot-transparent"></span>Transparent Background</button>
                                <button type="button" class="map-pop-item" data-mm-export="png-dark"><span class="dd-dot-swatch dd-dot-dark"></span>Dark Background</button>
                                <button type="button" class="map-pop-item" data-mm-export="png-white"><span class="dd-dot-swatch dd-dot-white"></span>White Background</button>
                                <div class="map-pop-sec" style="margin-top:6px;">VECTOR & DOCUMENT</div>
                                <button type="button" class="map-pop-item" data-mm-export="svg-dark"><i class="fa-solid fa-bezier-curve" style="color:#c084fc;"></i>Vector SVG Image</button>
                                <button type="button" class="map-pop-item" id="mm-export-markdown"><i class="fa-solid fa-file-lines" style="color:#38bdf8;"></i>Markdown Outline (.md)</button>
                                <div class="map-pop-sec" style="margin-top:6px;">PROJECT BACKUP</div>
                                <button type="button" class="map-pop-item" id="mm-save-project"><i class="fa-solid fa-floppy-disk" style="color:#10b981;"></i>Save .mantis-mindmap</button>
                                <button type="button" class="map-pop-item" id="mm-load-project"><i class="fa-solid fa-folder-open" style="color:#f59e0b;"></i>Open .mantis-mindmap</button>
                            </div>
                        </div>

                        <input type="file" id="mm-file-import-input" accept=".mantis-mindmap,.json" style="display:none;" />
                    </div>
                </header>

                <!-- WORKSPACE -->
                <div class="dd-workspace" id="mm-workspace">
                    <!-- LEFT SIDEBAR: TOPIC OUTLINE (REPLACES 50+ USELESS MARKERS) -->
                    <aside class="dd-palette" id="mm-palette" aria-label="Topic Outline">
                        <div class="dd-palette-header">
                            <div class="dd-palette-top-row">
                                <span style="display:flex;align-items:center;gap:7px;font-weight:700;font-size:0.75rem;">
                                    <i class="fa-solid fa-list-tree" style="color:#c084fc;"></i> TOPIC OUTLINE
                                </span>
                                <button type="button" class="dd-inspector-collapse-btn" id="mm-btn-collapse-palette" title="Collapse Left Sidebar">
                                    <i class="fa-solid fa-angles-left"></i>
                                </button>
                            </div>
                            <div class="dd-palette-search" style="margin-top:8px;">
                                <i class="fa-solid fa-magnifying-glass"></i>
                                <input type="text" id="mm-outline-search" placeholder="Search mindmap topics...">
                            </div>
                        </div>
                        <div class="dd-palette-body dark-scroll" id="mm-palette-list" style="padding:6px;"></div>
                    </aside>

                    <!-- CENTER CANVAS -->
                    <div class="dd-canvas-wrap theme-${state.canvasBg}" id="mm-canvas-wrap" style="position:relative;">
                        <button type="button" class="dd-expand-palette-pill" id="mm-btn-expand-palette" title="Expand Outline Panel">
                            <i class="fa-solid fa-angles-right"></i>
                            <span>OUTLINE</span>
                        </button>

                        <!-- Canvas Floating Dock -->
                        <div class="dd-floating-dock-wrap">
                            <div class="dd-floating-dock">
                                <div class="dd-bg-switcher">
                                    <button type="button" class="dd-bg-chip ${state.canvasBg === 'dark' ? 'active' : ''}" data-mm-bg="dark">Dark</button>
                                    <button type="button" class="dd-bg-chip ${state.canvasBg === 'white' ? 'active' : ''}" data-mm-bg="white">White</button>
                                    <button type="button" class="dd-bg-chip ${state.canvasBg === 'transparent' ? 'active' : ''}" data-mm-bg="transparent">Transparent</button>
                                </div>
                                <span class="dd-divider"></span>
                                <button type="button" class="dd-dock-btn" id="mm-btn-center-dock" title="Center Mindmap to Viewport">
                                    <i class="fa-solid fa-crosshairs" style="color:#c084fc;"></i><span>Center View</span>
                                </button>
                                <button type="button" class="dd-dock-btn" id="mm-btn-expand-all" title="Expand All Nodes">
                                    <i class="fa-solid fa-diagram-project"></i><span>Expand All</span>
                                </button>
                            </div>
                        </div>

                        <!-- Main SVG Canvas -->
                        <svg id="mm-svg-canvas" class="dd-svg-canvas" xmlns="http://www.w3.org/2000/svg">
                            <defs>
                                <filter id="mm-glow" x="-20%" y="-20%" width="140%" height="140%">
                                    <feGaussianBlur stdDeviation="4" result="blur" />
                                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                                </filter>
                            </defs>
                            <g id="mm-viewport">
                                <g id="mm-layer-branches"></g>
                                <g id="mm-layer-topics"></g>
                            </g>
                        </svg>

                        <!-- Bottom HUD Controls -->
                        <div class="dd-canvas-hud-bottom">
                            <div class="dd-canvas-hud-pill">
                                <span><kbd>Tab</kbd> Subtopic</span>
                                <span><kbd>Enter</kbd> Sibling</span>
                                <span><kbd>Dbl-Click</kbd> Edit Text</span>
                                <span><kbd>Del</kbd> Delete</span>
                                <span><kbd>Drag</kbd> Pan</span>
                            </div>
                            <div class="dd-zoom-controls">
                                <button type="button" class="dd-zoom-btn" id="mm-zoom-out" title="Zoom Out"><i class="fa-solid fa-minus"></i></button>
                                <span class="dd-zoom-readout" id="mm-zoom-label">100%</span>
                                <button type="button" class="dd-zoom-btn" id="mm-zoom-in" title="Zoom In"><i class="fa-solid fa-plus"></i></button>
                                <button type="button" class="dd-zoom-btn" id="mm-zoom-fit" title="Fit to Screen"><i class="fa-solid fa-expand"></i></button>
                            </div>
                        </div>

                        <button type="button" class="dd-expand-inspector-pill" id="mm-btn-expand-inspector" title="Open Topic Properties">
                            <i class="fa-solid fa-angles-left"></i>
                            <span>TOPIC PROPERTIES</span>
                        </button>
                    </div>

                    <!-- RIGHT SIDEBAR: CONTEXT-SENSITIVE INSPECTOR -->
                    <aside class="dd-inspector" id="mm-inspector" aria-label="Topic Properties">
                        <div class="dd-inspector-header">
                            <span style="display:inline-flex; align-items:center; gap:7px;">
                                <span>TOPIC PROPERTIES</span>
                                <span class="dd-inspector-badge" id="mm-inspector-badge">TOPIC</span>
                            </span>
                            <button type="button" class="dd-inspector-collapse-btn" id="mm-btn-collapse-inspector" title="Collapse Panel">
                                <i class="fa-solid fa-angles-right"></i>
                            </button>
                        </div>
                        <div class="dd-inspector-body dark-scroll" id="mm-inspector-body"></div>
                    </aside>
                </div>

                <!-- SLIDE-IN PRESETS DRAWER -->
                <div id="mm-presets-scrim"></div>
                <aside id="mm-presets-drawer">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 18px 12px;border-bottom:1px solid rgba(255,255,255,0.08);">
                        <div style="font-size:0.9rem;font-weight:700;display:flex;align-items:center;gap:8px;color:#f8fafc;">
                            <i class="fa-solid fa-wand-magic-sparkles" style="color:#c084fc;"></i>
                            <span>Mindmap Scenarios</span>
                        </div>
                        <button type="button" id="mm-presets-close" style="width:28px;height:28px;border-radius:6px;border:none;background:transparent;color:#94a3b8;cursor:pointer;">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                    <div style="flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:8px;" class="dark-scroll">
                        <div class="map-preset-card" data-load-mm-tpl="cti-campaign">
                            <div class="badge" style="color:#c084fc;background:rgba(192,132,252,0.15);border:1px solid rgba(192,132,252,0.3);">THREAT ATTRIBUTION</div>
                            <div class="name">Operation ShadowGrid (APT Campaign)</div>
                            <div class="desc">CTI breakdown spanning Initial Access, C2 Infrastructure, Lateral Movement, and Geopolitical Attribution.</div>
                        </div>
                        <div class="map-preset-card" data-load-mm-tpl="incident-response">
                            <div class="badge" style="color:#38bdf8;background:rgba(56,189,248,0.15);border:1px solid rgba(56,189,248,0.3);">DFIR INCIDENT</div>
                            <div class="name">72-Hour Ransomware Response Playbook</div>
                            <div class="desc">SOC war-room containment, identification, forensics extraction, and remediation workflow.</div>
                        </div>
                        <div class="map-preset-card" data-load-mm-tpl="malware-analysis">
                            <div class="badge" style="color:#34d399;background:rgba(52,211,153,0.15);border:1px solid rgba(52,211,153,0.3);">MALWARE LAB</div>
                            <div class="name">Reverse Engineering & Evasion Analysis</div>
                            <div class="desc">Static characteristics, anti-debugging evasion checks, and reflective injection extraction.</div>
                        </div>
                        <div class="map-preset-card" data-load-mm-tpl="blank">
                            <div class="badge" style="color:#94a3b8;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);">CLEAN SLATE</div>
                            <div class="name">Blank Mind Map</div>
                            <div class="desc">Clean canvas with single central root node ready for free-form brainstorming.</div>
                        </div>
                    </div>
                </aside>
            </div>
        `;
    }

    // =========================================================================
    // LEFT SIDEBAR: INTERACTIVE TOPIC OUTLINE
    // =========================================================================
    function renderPalette() {
        const listEl = document.getElementById('mm-palette-list');
        if (!listEl) return;

        const q = (state.searchQuery || '').toLowerCase().trim();
        const root = getTopic('root') || state.topics[0];
        if (!root) {
            listEl.innerHTML = '<div style="padding:16px;text-align:center;color:#64748b;">No topics created</div>';
            return;
        }

        let html = '';
        function buildTreeHtml(topic, depth) {
            const match = !q || (topic.text || '').toLowerCase().includes(q) || (topic.note || '').toLowerCase().includes(q);
            const kids = getChildren(topic.id);
            const isSel = state.selectedId === topic.id;
            const branchCol = topic._branchColor || '#c084fc';

            if (match) {
                const cleanText = (topic.text || 'Untitled').replace(/\n/g, ' ');
                const padLeft = depth * 14 + 6;
                html += `
                    <div class="mm-outline-item ${isSel ? 'active' : ''}" data-pick-topic="${topic.id}" style="padding-left:${padLeft}px;">
                        <span class="mm-outline-dot" style="background:${depth === 0 ? '#c084fc' : branchCol};"></span>
                        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;">${esc(cleanText)}</span>
                        ${topic.priority ? `<span class="mm-outline-badge" style="background:rgba(239,68,68,0.18);color:#ef4444;border:1px solid rgba(239,68,68,0.3);">${topic.priority}</span>` : ''}
                        ${kids.length > 0 ? `<span style="font-size:0.64rem;color:#64748b;margin-left:auto;">(${kids.length})</span>` : ''}
                    </div>
                `;
            }

            kids.forEach(k => buildTreeHtml(k, depth + 1));
        }

        buildTreeHtml(root, 0);
        listEl.innerHTML = html;

        listEl.querySelectorAll('[data-pick-topic]').forEach(btn => {
            btn.addEventListener('click', () => {
                const tId = btn.getAttribute('data-pick-topic');
                state.selectedId = tId;
                renderPalette();
                renderCanvas();
                renderInspector();

                // Focus/pan to this topic
                const t = getTopic(tId);
                if (t && typeof t.x === 'number') {
                    const svg = document.getElementById('mm-svg-canvas');
                    if (svg) {
                        const rect = svg.getBoundingClientRect();
                        state.panX = rect.width / 2 - (t.x + t._w / 2) * state.zoom;
                        state.panY = rect.height / 2 - (t.y + t._h / 2) * state.zoom;
                        const vp = document.getElementById('mm-viewport');
                        if (vp) vp.setAttribute('transform', `translate(${state.panX}, ${state.panY}) scale(${state.zoom})`);
                    }
                }
            });
        });
    }

    // =========================================================================
    // CANVAS RENDERER: BRANCH CONNECTORS & TOPIC NODES
    // =========================================================================
    function createSvgEl(tag, attrs = {}) {
        const el = document.createElementNS(SVG_NS, tag);
        for (const [k, v] of Object.entries(attrs)) {
            if (v !== undefined && v !== null) el.setAttribute(k, String(v));
        }
        return el;
    }

    function renderCanvas() {
        const vp = document.getElementById('mm-viewport');
        const lBranches = document.getElementById('mm-layer-branches');
        const lTopics = document.getElementById('mm-layer-topics');
        if (!vp || !lBranches || !lTopics) return;

        vp.setAttribute('transform', `translate(${state.panX}, ${state.panY}) scale(${state.zoom})`);
        const zoomLbl = document.getElementById('mm-zoom-label');
        if (zoomLbl) zoomLbl.textContent = `${Math.round(state.zoom * 100)}%`;

        lBranches.innerHTML = '';
        lTopics.innerHTML = '';

        const curTheme = THEMES[state.theme] || THEMES['cyber-neon'];
        const isLight = state.canvasBg === 'white';
        const root = getTopic('root') || state.topics[0];

        // 1. RENDER BRANCH CONNECTORS
        state.topics.forEach(t => {
            if (!t.parentId) return;
            const p = getTopic(t.parentId);
            if (!p || p.collapsed) return;

            const rawBranchCol = t.customColor || t._branchColor || curTheme.rootStroke;
            const branchCol = isLight
                ? ((!rawBranchCol || rawBranchCol === '#ffffff' || rawBranchCol === '#f8fafc' || rawBranchCol === '#d4d4d4' || rawBranchCol === '#e5e5e5' || rawBranchCol === '#a3a3a3') ? '#0f172a' : rawBranchCol)
                : ((!rawBranchCol || rawBranchCol === '#000000' || rawBranchCol === '#080c14' || rawBranchCol === '#0f172a') ? '#ffffff' : rawBranchCol);
            let pathD = '';

            if (state.structure === 'org-chart') {
                // Downward connectors
                const x1 = p.x + p._w / 2;
                const y1 = p.y + p._h;
                const x2 = t.x + t._w / 2;
                const y2 = t.y;
                const midY = (y1 + y2) / 2;

                if (state.lineStyle === 'curved') {
                    pathD = `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`;
                } else if (state.lineStyle === 'rounded') {
                    pathD = `M ${x1} ${y1} L ${x1} ${midY} L ${x2} ${midY} L ${x2} ${y2}`;
                } else {
                    pathD = `M ${x1} ${y1} L ${x2} ${y2}`;
                }
            } else {
                // Horizontal connectors (Left or Right)
                const isRight = t._side === 'right';
                const x1 = isRight ? (p.x + p._w) : p.x;
                const y1 = p.y + p._h / 2;
                const x2 = isRight ? t.x : (t.x + t._w);
                const y2 = t.y + t._h / 2;
                const midX = (x1 + x2) / 2;

                if (state.lineStyle === 'curved') {
                    pathD = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
                } else if (state.lineStyle === 'rounded') {
                    pathD = `M ${x1} ${y1} L ${midX} ${y1} L ${midX} ${y2} L ${x2} ${y2}`;
                } else {
                    pathD = `M ${x1} ${y1} L ${x2} ${y2}`;
                }
            }

            const branchEl = createSvgEl('path', {
                d: pathD,
                fill: 'none',
                stroke: branchCol,
                'stroke-width': (t.parentId === root.id) ? 2.5 : 1.8,
                'stroke-linecap': 'round',
                'stroke-linejoin': 'round',
                opacity: isLight ? '0.85' : '0.92'
            });
            lBranches.appendChild(branchEl);
        });

        // 2. RENDER TOPIC NODES
        state.topics.forEach(t => {
            const p = t.parentId ? getTopic(t.parentId) : null;
            if (p && p.collapsed) return; // Hide collapsed subtrees

            const isRoot = t.id === root.id;
            const isSel = state.selectedId === t.id;
            const rawBranchCol = t.customColor || t._branchColor || curTheme.rootStroke;
            const branchCol = isLight
                ? ((!rawBranchCol || rawBranchCol === '#ffffff' || rawBranchCol === '#f8fafc' || rawBranchCol === '#d4d4d4' || rawBranchCol === '#e5e5e5' || rawBranchCol === '#a3a3a3') ? '#0f172a' : rawBranchCol)
                : ((!rawBranchCol || rawBranchCol === '#000000' || rawBranchCol === '#080c14' || rawBranchCol === '#0f172a') ? '#ffffff' : rawBranchCol);
            const kids = getChildren(t.id);

            const g = createSvgEl('g', {
                transform: `translate(${t.x}, ${t.y})`,
                style: 'cursor:pointer;',
                'data-topic-id': t.id
            });

            // Node background card
            let nodeFill = isLight ? '#ffffff' : curTheme.nodeFill;
            let nodeStroke = isLight ? 'rgba(0,0,0,0.14)' : curTheme.nodeStroke;
            let strokeW = 1.2;

            if (isRoot) {
                nodeFill = isLight ? '#f8fafc' : curTheme.rootFill;
                nodeStroke = isLight ? '#2563eb' : curTheme.rootStroke;
                strokeW = 2.4;
            } else if (isSel) {
                nodeStroke = '#c084fc';
                strokeW = 2.2;
            } else if (t.customColor) {
                nodeStroke = t.customColor;
                strokeW = 1.8;
            }

            const shape = t.shape || (isRoot ? 'rounded' : 'rounded');
            const rx = shape === 'pill' ? t._h / 2 : (shape === 'rounded' ? 8 : 3);

            if (shape === 'underline') {
                // Sleek XMind underline style
                g.appendChild(createSvgEl('line', {
                    x1: 0, y1: t._h, x2: t._w, y2: t._h,
                    stroke: branchCol,
                    'stroke-width': 2.5
                }));
            } else {
                g.appendChild(createSvgEl('rect', {
                    x: 0, y: 0, width: t._w, height: t._h, rx,
                    fill: nodeFill,
                    stroke: nodeStroke,
                    'stroke-width': strokeW,
                    filter: (isRoot || isSel) ? 'drop-shadow(0 4px 14px rgba(168,85,247,0.3))' : 'drop-shadow(0 2px 6px rgba(0,0,0,0.25))'
                }));
            }

            // Left decorative accent bar for primary branches
            if (!isRoot && t.parentId === root.id && shape !== 'underline') {
                g.appendChild(createSvgEl('rect', {
                    x: 0, y: 0, width: 4.5, height: t._h, rx: 2,
                    fill: branchCol
                }));
            }

            // Priority Badge if set
            let textStartX = 14;
            if (t.priority) {
                const pG = createSvgEl('g');
                pG.appendChild(createSvgEl('rect', {
                    x: 10, y: 8, width: 20, height: 14, rx: 3,
                    fill: '#ef4444',
                    opacity: '0.9'
                }));
                const pText = createSvgEl('text', {
                    x: 20, y: 18,
                    fill: '#ffffff',
                    'font-family': `'${state.globalFont}', sans-serif`,
                    'font-size': '8.5px',
                    'font-weight': '800',
                    'text-anchor': 'middle'
                });
                pText.textContent = t.priority;
                pG.appendChild(pText);
                g.appendChild(pG);
                textStartX = 34;
            }

            // Text rendering (multi-line supported)
            const lines = (t.text || (isRoot ? 'Central Topic' : 'Subtopic')).split('\n');
            const textColor = isLight ? '#0f172a' : curTheme.textColor;
            const textYStart = lines.length > 1 ? 18 : (t.note ? 18 : t._h / 2 + 4);

            lines.forEach((line, idx) => {
                const textEl = createSvgEl('text', {
                    x: isRoot ? t._w / 2 : textStartX,
                    y: textYStart + idx * 15,
                    fill: isRoot ? (isLight ? '#0f172a' : curTheme.rootColor) : textColor,
                    'font-family': `'${state.globalFont}', sans-serif`,
                    'font-size': isRoot ? '12.5px' : '11px',
                    'font-weight': isRoot ? '800' : '600',
                    'text-anchor': isRoot ? 'middle' : 'start'
                });
                textEl.textContent = line;
                g.appendChild(textEl);
            });

            // Subtitle / Note
            if (t.note) {
                const noteEl = createSvgEl('text', {
                    x: isRoot ? t._w / 2 : textStartX,
                    y: t._h - 8,
                    fill: isLight ? '#64748b' : curTheme.subtextColor,
                    'font-family': `'${state.globalFont}', sans-serif`,
                    'font-size': '9px',
                    'font-weight': '500',
                    'text-anchor': isRoot ? 'middle' : 'start'
                });
                noteEl.textContent = t.note;
                g.appendChild(noteEl);
            }

            // Expand / Collapse Badge for nodes with children
            if (kids.length > 0) {
                const badgeX = (t._side === 'left') ? -9 : (t._w + 9);
                const badgeY = t._h / 2;

                const cBadge = createSvgEl('g', { style: 'cursor:pointer;' });
                cBadge.appendChild(createSvgEl('circle', {
                    cx: badgeX, cy: badgeY, r: 7.5,
                    fill: isLight ? '#ffffff' : '#0f172a',
                    stroke: branchCol,
                    'stroke-width': 1.5
                }));
                const bTxt = createSvgEl('text', {
                    x: badgeX, y: badgeY + 3.5,
                    fill: branchCol,
                    'font-family': `'${state.globalFont}', sans-serif`,
                    'font-size': '9px',
                    'font-weight': '800',
                    'text-anchor': 'middle'
                });
                bTxt.textContent = t.collapsed ? `+` : `−`;
                cBadge.appendChild(bTxt);

                cBadge.addEventListener('click', (ev) => {
                    ev.stopPropagation();
                    t.collapsed = !t.collapsed;
                    pushHistory();
                    computeLayout();
                    renderCanvas();
                    renderInspector();
                });
                g.appendChild(cBadge);
            }

            // Click node -> select
            g.addEventListener('click', (ev) => {
                if (state.dragDistance > 5) return;
                ev.stopPropagation();
                state.selectedId = t.id;
                renderPalette();
                renderCanvas();
                renderInspector();
            });

            // Double Click -> inline node text editor
            g.addEventListener('dblclick', (ev) => {
                ev.stopPropagation();
                startInlineNodeEdit(t);
            });

            lTopics.appendChild(g);
        });
    }

    // =========================================================================
    // INLINE NODE TEXT EDITOR (ON DOUBLE CLICK)
    // =========================================================================
    function startInlineNodeEdit(topic) {
        const wrap = document.getElementById('mm-canvas-wrap');
        if (!wrap) return;

        const old = document.querySelector('.mm-inline-editor');
        if (old) old.remove();

        const screenX = state.panX + topic.x * state.zoom;
        const screenY = state.panY + topic.y * state.zoom;
        const screenW = Math.max(160, topic._w * state.zoom);

        const edWrap = document.createElement('div');
        edWrap.className = 'mm-inline-editor';
        edWrap.style.left = `${screenX}px`;
        edWrap.style.top = `${screenY}px`;
        edWrap.style.width = `${screenW}px`;

        const ta = document.createElement('textarea');
        ta.value = topic.text || '';
        edWrap.appendChild(ta);

        function commit() {
            const val = ta.value.trim();
            if (val) {
                topic.text = val;
                pushHistory();
                computeLayout();
                renderPalette();
                renderCanvas();
                renderInspector();
            }
            edWrap.remove();
        }

        ta.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' && !ev.shiftKey) {
                ev.preventDefault();
                commit();
            } else if (ev.key === 'Escape') {
                edWrap.remove();
            }
        });

        ta.addEventListener('blur', commit);
        wrap.appendChild(edWrap);
        ta.focus();
        ta.select();
    }

    // =========================================================================
    // RIGHT INSPECTOR: TOPIC EDITING & CLEAN CONTROLS
    // =========================================================================
    function renderInspector() {
        const body = document.getElementById('mm-inspector-body');
        const badge = document.getElementById('mm-inspector-badge');
        if (!body) return;

        const t = getTopic(state.selectedId) || getTopic('root') || state.topics[0];
        if (!t) return;

        const isRoot = t.id === 'root';
        if (badge) badge.textContent = isRoot ? 'ROOT' : 'TOPIC';

        const root = getTopic('root') || state.topics[0];
        const kids = getChildren(t.id);

        body.innerHTML = `
            <div class="dd-stats-grid" style="grid-template-columns:1fr 1fr;">
                <div class="dd-stat-box">
                    <div class="dd-stat-num" style="color:#c084fc;">${state.topics.length}</div>
                    <div class="dd-stat-label">TOTAL TOPICS</div>
                </div>
                <div class="dd-stat-box">
                    <div class="dd-stat-num" style="color:#38bdf8;">${kids.length}</div>
                    <div class="dd-stat-label">SUBTOPICS</div>
                </div>
            </div>

            <!-- TOPIC TEXT & NOTES -->
            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">TOPIC CONTENT</div>
                <div class="dd-field">
                    <label>Topic Title</label>
                    <textarea class="dd-textarea" id="mm-insp-text" rows="2" style="font-size:0.8rem;">${esc(t.text || '')}</textarea>
                </div>
                <div class="dd-field" style="margin-top:8px;">
                    <label>Subtitle / Investigation Note</label>
                    <input type="text" class="dd-input" id="mm-insp-note" value="${esc(t.note || '')}" placeholder="Optional details..." />
                </div>
            </div>

            <!-- TOPIC STYLING -->
            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">TOPIC STYLING</div>
                
                <div class="dd-insp-row">
                    <span class="dd-insp-row-label">Shape</span>
                    <div class="dd-insp-row-control">
                        <select class="dd-select" id="mm-insp-shape">
                            <option value="rounded" ${t.shape === 'rounded' || !t.shape ? 'selected' : ''}>Rounded Box</option>
                            <option value="pill" ${t.shape === 'pill' ? 'selected' : ''}>Pill / Capsule</option>
                            <option value="underline" ${t.shape === 'underline' ? 'selected' : ''}>Underline</option>
                            <option value="bordered" ${t.shape === 'bordered' ? 'selected' : ''}>Sharp Border</option>
                        </select>
                    </div>
                </div>

                <div class="dd-insp-row" style="margin-top:8px;">
                    <span class="dd-insp-row-label">Priority Tag</span>
                    <div class="dd-insp-row-control">
                        <select class="dd-select" id="mm-insp-priority">
                            <option value="" ${!t.priority ? 'selected' : ''}>None</option>
                            <option value="P1" ${t.priority === 'P1' ? 'selected' : ''}>P1 - Critical Focus</option>
                            <option value="P2" ${t.priority === 'P2' ? 'selected' : ''}>P2 - High Priority</option>
                            <option value="P3" ${t.priority === 'P3' ? 'selected' : ''}>P3 - Medium Priority</option>
                            <option value="P4" ${t.priority === 'P4' ? 'selected' : ''}>P4 - Low / Backlog</option>
                        </select>
                    </div>
                </div>

                <div class="dd-insp-row" style="margin-top:8px;">
                    <span class="dd-insp-row-label">Branch Color</span>
                    <div class="dd-insp-row-control" style="display:flex;align-items:center;gap:8px;">
                        <input type="color" id="mm-insp-color-picker" value="${t.customColor || t._branchColor || '#a855f7'}" style="width:32px;height:26px;border:none;background:transparent;cursor:pointer;padding:0;" />
                        <span style="font-size:0.75rem;color:#94a3b8;font-family:monospace;">${t.customColor || 'Auto Color'}</span>
                    </div>
                </div>
            </div>

            <!-- QUICK ACTIONS -->
            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">ACTIONS</div>
                <div style="display:flex;flex-direction:column;gap:6px;">
                    <button type="button" class="dd-image-upload-btn" id="mm-insp-add-sub" style="color:#c084fc;border-color:rgba(192,132,252,0.3);font-weight:700;">
                        <i class="fa-solid fa-plus"></i> + Add Subtopic (Tab)
                    </button>
                    ${!isRoot ? `
                        <button type="button" class="dd-image-upload-btn" id="mm-insp-add-sib" style="color:#38bdf8;border-color:rgba(56,189,248,0.3);">
                            <i class="fa-solid fa-arrows-split-up-and-left"></i> + Add Sibling Topic (Enter)
                        </button>
                        <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="mm-insp-del-topic" style="color:#fca5a5;border-color:rgba(239,68,68,0.25);">
                            <i class="fa-solid fa-trash"></i> Delete Selected Topic
                        </button>
                    ` : ''}
                </div>
            </div>
        `;

        document.getElementById('mm-insp-text')?.addEventListener('input', (e) => {
            t.text = e.target.value;
            pushHistory();
            computeLayout();
            renderCanvas();
            renderPalette();
        });

        document.getElementById('mm-insp-note')?.addEventListener('input', (e) => {
            t.note = e.target.value;
            pushHistory();
            computeLayout();
            renderCanvas();
            renderPalette();
        });

        document.getElementById('mm-insp-shape')?.addEventListener('change', (e) => {
            t.shape = e.target.value;
            pushHistory();
            renderCanvas();
        });

        document.getElementById('mm-insp-priority')?.addEventListener('change', (e) => {
            t.priority = e.target.value || null;
            pushHistory();
            renderCanvas();
            renderPalette();
        });

        document.getElementById('mm-insp-color-picker')?.addEventListener('input', (e) => {
            t.customColor = e.target.value;
            pushHistory();
            computeLayout();
            renderCanvas();
            renderPalette();
        });

        document.getElementById('mm-insp-add-sub')?.addEventListener('click', () => {
            addSubtopic(t.id);
        });

        document.getElementById('mm-insp-add-sib')?.addEventListener('click', () => {
            addSiblingTopic(t.id);
        });

        document.getElementById('mm-insp-del-topic')?.addEventListener('click', () => {
            deleteTopic(t.id);
        });
    }

    // =========================================================================
    // TOPIC CREATION & DELETION HELPERS
    // =========================================================================
    function addSubtopic(parentId) {
        const p = getTopic(parentId) || getTopic('root') || state.topics[0];
        if (!p) return;

        const newId = `t_${Date.now()}`;
        state.topics.push({
            id: newId,
            parentId: p.id,
            text: 'New Subtopic',
            note: ''
        });
        p.collapsed = false;
        state.selectedId = newId;

        pushHistory();
        computeLayout();
        renderPalette();
        renderCanvas();
        renderInspector();

        // Focus and start editing new node
        setTimeout(() => {
            const newTopic = getTopic(newId);
            if (newTopic) startInlineNodeEdit(newTopic);
        }, 40);
    }

    function addSiblingTopic(targetId) {
        const cur = getTopic(targetId);
        if (!cur || !cur.parentId) {
            addSubtopic('root');
            return;
        }

        const newId = `t_${Date.now()}`;
        const pId = cur.parentId;

        const curIdx = state.topics.findIndex(t => t.id === cur.id);
        const newTopic = { id: newId, parentId: pId, text: 'New Topic', note: '' };

        if (curIdx >= 0) {
            state.topics.splice(curIdx + 1, 0, newTopic);
        } else {
            state.topics.push(newTopic);
        }

        state.selectedId = newId;
        pushHistory();
        computeLayout();
        renderPalette();
        renderCanvas();
        renderInspector();

        setTimeout(() => {
            startInlineNodeEdit(newTopic);
        }, 40);
    }

    function deleteTopic(topicId) {
        if (topicId === 'root') {
            alert('Cannot delete root topic.');
            return;
        }
        const cur = getTopic(topicId);
        if (!cur) return;

        // Collect topic and all its descendants
        const idsToDelete = new Set([topicId]);
        let added = true;
        while (added) {
            added = false;
            state.topics.forEach(t => {
                if (t.parentId && idsToDelete.has(t.parentId) && !idsToDelete.has(t.id)) {
                    idsToDelete.add(t.id);
                    added = true;
                }
            });
        }

        state.topics = state.topics.filter(t => !idsToDelete.has(t.id));
        state.selectedId = cur.parentId || 'root';

        pushHistory();
        computeLayout();
        renderPalette();
        renderCanvas();
        renderInspector();
    }

    // =========================================================================
    // EVENT BINDINGS
    // =========================================================================
    function bindEvents() {
        const svg = document.getElementById('mm-svg-canvas');
        if (!svg) return;

        document.getElementById('mm-title-input')?.addEventListener('change', (e) => {
            state.title = e.target.value.trim() || 'Untitled Mind Map';
            pushHistory();
        });

        document.getElementById('mm-struct-select')?.addEventListener('change', (e) => {
            state.structure = e.target.value;
            pushHistory();
            computeLayout();
            renderCanvas();
            centerView();
        });

        document.getElementById('mm-theme-select')?.addEventListener('change', (e) => {
            state.theme = e.target.value;
            pushHistory();
            computeLayout();
            renderCanvas();
            renderPalette();
            renderInspector();
        });

        document.getElementById('mm-btn-add-subtopic')?.addEventListener('click', () => {
            addSubtopic(state.selectedId || 'root');
        });

        document.getElementById('mm-btn-add-sibling')?.addEventListener('click', () => {
            addSiblingTopic(state.selectedId || 'root');
        });

        // Outline Search Filter
        document.getElementById('mm-outline-search')?.addEventListener('input', (e) => {
            state.searchQuery = e.target.value;
            renderPalette();
        });

        // Presets Drawer
        const root = document.getElementById('mm-studio-root');
        document.getElementById('mm-btn-presets')?.addEventListener('click', () => {
            root?.classList.add('presets-open');
        });
        document.getElementById('mm-presets-close')?.addEventListener('click', closePresets);
        document.getElementById('mm-presets-scrim')?.addEventListener('click', closePresets);

        document.querySelectorAll('[data-load-mm-tpl]').forEach(card => {
            card.addEventListener('click', () => {
                loadTemplate(card.getAttribute('data-load-mm-tpl'));
            });
        });

        // Style Popover & Export Popover
        const stylePop = document.getElementById('mm-style-pop');
        const exportPop = document.getElementById('mm-export-pop');

        document.getElementById('mm-btn-style-pop')?.addEventListener('click', (e) => {
            e.stopPropagation();
            exportPop?.classList.remove('open');
            stylePop?.classList.toggle('open');
        });

        document.getElementById('mm-btn-export-pop')?.addEventListener('click', (e) => {
            e.stopPropagation();
            stylePop?.classList.remove('open');
            exportPop?.classList.toggle('open');
        });

        document.addEventListener('click', (e) => {
            if (!e.target.closest('#mm-style-pop') && !e.target.closest('#mm-btn-style-pop')) {
                stylePop?.classList.remove('open');
            }
            if (!e.target.closest('#mm-export-pop') && !e.target.closest('#mm-btn-export-pop')) {
                exportPop?.classList.remove('open');
            }
        });

        // Style Options
        document.querySelectorAll('[data-line-style]').forEach(item => {
            item.addEventListener('click', () => {
                state.lineStyle = item.getAttribute('data-line-style');
                pushHistory();
                renderCanvas();
                stylePop?.classList.remove('open');
            });
        });

        document.getElementById('mm-font-select')?.addEventListener('change', (e) => {
            state.globalFont = e.target.value;
            pushHistory();
            renderCanvas();
        });

        // Floating Dock Actions
        document.getElementById('mm-btn-center-dock')?.addEventListener('click', centerView);
        document.getElementById('mm-btn-expand-all')?.addEventListener('click', () => {
            state.topics.forEach(t => t.collapsed = false);
            pushHistory();
            computeLayout();
            renderCanvas();
            centerView();
        });

        // Collapse / Expand Sidebar
        const ws = document.getElementById('mm-workspace');
        document.getElementById('mm-btn-collapse-palette')?.addEventListener('click', () => {
            ws?.classList.add('palette-collapsed');
        });
        document.getElementById('mm-btn-expand-palette')?.addEventListener('click', () => {
            ws?.classList.remove('palette-collapsed');
        });
        document.getElementById('mm-btn-collapse-inspector')?.addEventListener('click', () => {
            ws?.classList.add('inspector-collapsed');
        });
        document.getElementById('mm-btn-expand-inspector')?.addEventListener('click', () => {
            ws?.classList.remove('inspector-collapsed');
        });

        // Background Switcher
        document.querySelectorAll('[data-mm-bg]').forEach(btn => {
            btn.addEventListener('click', () => {
                state.canvasBg = btn.getAttribute('data-mm-bg');
                const wrap = document.getElementById('mm-canvas-wrap');
                if (wrap) wrap.className = `dd-canvas-wrap theme-${state.canvasBg}`;
                document.querySelectorAll('[data-mm-bg]').forEach(b => b.classList.toggle('active', b === btn));
                renderCanvas();
                saveToStorage();
            });
        });

        // Exports
        document.querySelectorAll('[data-mm-export]').forEach(btn => {
            btn.addEventListener('click', () => {
                const [fmt, bg] = btn.getAttribute('data-mm-export').split('-');
                if (fmt === 'png') exportMindmapPNG(bg);
                else if (fmt === 'svg') exportMindmapSVG(bg);
                exportPop?.classList.remove('open');
            });
        });

        document.getElementById('mm-export-markdown')?.addEventListener('click', () => {
            exportMarkdownOutline();
            exportPop?.classList.remove('open');
        });
        document.getElementById('mm-save-project')?.addEventListener('click', () => {
            saveProjectFile();
            exportPop?.classList.remove('open');
        });
        document.getElementById('mm-load-project')?.addEventListener('click', () => {
            document.getElementById('mm-file-import-input')?.click();
            exportPop?.classList.remove('open');
        });

        // Project File Load
        document.getElementById('mm-file-import-input')?.addEventListener('change', (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (ev) => {
                try {
                    const parsed = JSON.parse(ev.target.result);
                    if (parsed && Array.isArray(parsed.topics)) {
                        state.title = parsed.title || state.title;
                        state.structure = parsed.structure || state.structure;
                        state.theme = parsed.theme || state.theme;
                        state.lineStyle = parsed.lineStyle || state.lineStyle;
                        state.topics = parsed.topics;
                        pushHistory();
                        computeLayout();
                        renderPalette();
                        renderCanvas();
                        renderInspector();
                        centerView();
                        alert('Mind Map Project imported successfully!');
                    }
                } catch (err) {
                    alert('Invalid mindmap project file.');
                }
            };
            reader.readAsText(file);
        });

        // Pan & Wheel Zoom
        svg.addEventListener('mousedown', (ev) => {
            if (ev.button !== 0) return;
            state.isPanning = true;
            state.dragDistance = 0;
            state.panStart = { x: ev.clientX - state.panX, y: ev.clientY - state.panY };
        });

        window.addEventListener('mousemove', (ev) => {
            if (state.isPanning) {
                const curX = ev.clientX - state.panStart.x;
                const curY = ev.clientY - state.panStart.y;
                state.dragDistance += Math.hypot(curX - state.panX, curY - state.panY);
                state.panX = curX;
                state.panY = curY;
                const vp = document.getElementById('mm-viewport');
                if (vp) vp.setAttribute('transform', `translate(${state.panX}, ${state.panY}) scale(${state.zoom})`);
            }
        });

        window.addEventListener('mouseup', () => {
            state.isPanning = false;
        });

        svg.addEventListener('wheel', (ev) => {
            ev.preventDefault();
            const factor = ev.deltaY < 0 ? 1.1 : 0.9;
            const nextZoom = Math.min(3.5, Math.max(0.2, state.zoom * factor));
            const rect = svg.getBoundingClientRect();
            const mx = ev.clientX - rect.left;
            const my = ev.clientY - rect.top;
            state.panX = mx - (mx - state.panX) * (nextZoom / state.zoom);
            state.panY = my - (my - state.panY) * (nextZoom / state.zoom);
            state.zoom = nextZoom;
            renderCanvas();
        }, { passive: false });

        document.getElementById('mm-zoom-in')?.addEventListener('click', () => {
            state.zoom = Math.min(3.5, state.zoom * 1.18);
            renderCanvas();
        });
        document.getElementById('mm-zoom-out')?.addEventListener('click', () => {
            state.zoom = Math.max(0.2, state.zoom / 1.18);
            renderCanvas();
        });
        document.getElementById('mm-zoom-fit')?.addEventListener('click', centerView);

        // Global Keyboard Shortcuts (active when mindmap pane is displayed)
        window.addEventListener('keydown', (ev) => {
            const pane = document.getElementById('mindmap-draw-pane');
            if (!pane || pane.style.display === 'none') return;
            const tag = (ev.target && ev.target.tagName) ? ev.target.tagName.toLowerCase() : '';
            if (tag === 'input' || tag === 'textarea' || tag === 'select') return;

            if (ev.key === 'Tab') {
                ev.preventDefault();
                addSubtopic(state.selectedId || 'root');
            } else if (ev.key === 'Enter') {
                ev.preventDefault();
                addSiblingTopic(state.selectedId || 'root');
            } else if (ev.key === 'Delete' || ev.key === 'Backspace') {
                if (state.selectedId && state.selectedId !== 'root') {
                    ev.preventDefault();
                    deleteTopic(state.selectedId);
                }
            } else if (ev.key === 'F2' || ev.key === ' ') {
                const t = getTopic(state.selectedId);
                if (t) {
                    ev.preventDefault();
                    startInlineNodeEdit(t);
                }
            }
        });
    }

    function closePresets() {
        document.getElementById('mm-studio-root')?.classList.remove('presets-open');
    }

    // =========================================================================
    // EXPORT ENGINE: PNG (2X HIGH-DPI), VECTOR SVG, MARKDOWN OUTLINE (.MD), JSON
    // =========================================================================
    function buildExportSvgString(bgMode) {
        const prevBg = state.canvasBg;
        state.canvasBg = bgMode === 'white' ? 'white' : 'dark';
        renderCanvas();

        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        state.topics.forEach(t => {
            minX = Math.min(minX, t.x - 40);
            minY = Math.min(minY, t.y - 40);
            maxX = Math.max(maxX, t.x + (t._w || 160) + 40);
            maxY = Math.max(maxY, t.y + (t._h || 48) + 40);
        });

        const pad = 50;
        const w = Math.ceil(maxX - minX + pad * 2);
        const h = Math.ceil(maxY - minY + pad * 2);

        const origSvg = document.getElementById('mm-svg-canvas');
        const clone = origSvg.cloneNode(true);
        clone.setAttribute('width', String(w));
        clone.setAttribute('height', String(h));
        clone.setAttribute('viewBox', `0 0 ${w} ${h}`);

        const vp = clone.querySelector('#mm-viewport');
        if (vp) {
            vp.setAttribute('transform', `translate(${-minX + pad}, ${-minY + pad}) scale(1)`);
        }

        if (bgMode !== 'transparent') {
            const bgRect = createSvgEl('rect', {
                x: 0, y: 0, width: w, height: h,
                fill: bgMode === 'white' ? '#ffffff' : '#080c14'
            });
            clone.insertBefore(bgRect, clone.firstChild);
        }

        state.canvasBg = prevBg;
        renderCanvas();

        return { svgStr: new XMLSerializer().serializeToString(clone), width: w, height: h };
    }

    function slugTitle() {
        return (state.title || 'mantis-mindmap').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    }

    function exportMindmapSVG(bgMode) {
        const { svgStr } = buildExportSvgString(bgMode);
        const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${slugTitle()}-${bgMode}.svg`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function exportMindmapPNG(bgMode) {
        const { svgStr, width, height } = buildExportSvgString(bgMode);
        const img = new Image();
        const svgBlob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(svgBlob);
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = width * 2;
            canvas.height = height * 2;
            const ctx = canvas.getContext('2d');
            ctx.scale(2, 2);
            ctx.drawImage(img, 0, 0);
            URL.revokeObjectURL(url);
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
        img.src = url;
    }

    function exportMarkdownOutline() {
        const root = getTopic('root') || state.topics[0];
        if (!root) return;

        let md = `# ${state.title}\n\n`;

        function traverse(t, depth) {
            const indent = '  '.repeat(depth);
            const bullet = depth === 0 ? '#' : '-';
            const cleanText = (t.text || '').replace(/\n/g, ' ');
            const noteText = t.note ? ` *(${t.note})*` : '';
            const priText = t.priority ? ` **[${t.priority}]**` : '';
            md += `${indent}${bullet} ${cleanText}${priText}${noteText}\n`;

            getChildren(t.id).forEach(k => traverse(k, depth + 1));
        }

        traverse(root, 0);

        const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${slugTitle()}-outline.md`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function saveProjectFile() {
        const payload = {
            format: 'mantis-mindmap-v3',
            savedAt: new Date().toISOString(),
            title: state.title,
            structure: state.structure,
            theme: state.theme,
            lineStyle: state.lineStyle,
            topics: state.topics
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${slugTitle()}.mantis-mindmap`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    window.openMindmapDraw = initMindmapStudio;
})();
