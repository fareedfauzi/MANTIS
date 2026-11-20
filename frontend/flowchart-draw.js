/* ==========================================================================
   MANTIS Flow Chart Studio — Draw.io Inspired Flowchart & Swimlane Designer
   Under Sidebar: Drawer -> Flow Chart
   Features:
   - 36+ Draw.io Geometric Flowchart, General, Swimlane & SOC Playbook Shapes
   - Draw.io Signature Quick-Add Direction Arrows (▲ ▶ ▼ ◀) on selected shapes
   - Double-Click Inline On-Canvas Text Editing
   - Swimlane Containers (Horizontal & Vertical Header Bands)
   - Orthogonal (90° Elbow), Curved & Straight Connectors
   - Auto-Layout (Top-to-Bottom & Left-to-Right) + Multi-Node Alignment Tools
   - Transparent, Dark, and White Background Exports (PNG & SVG)
   - Native .mantis-flow / .json Project Save & Re-Import + Image Copy/Paste
   ========================================================================== */
(() => {
    const STORAGE_KEY = 'mantis_flowchart_draw_v1';
    const FILE_FORMAT_MAGIC = 'mantis-flowchart-draw';
    const FILE_FORMAT_VERSION = '1.0';

    const SWATCH_COLORS = [
        '#38bdf8', // Cyan
        '#60a5fa', // Blue
        '#10b981', // Emerald
        '#eab308', // Gold / Amber
        '#f97316', // Orange
        '#ef4444', // Red
        '#a855f7', // Purple
        '#ec4899', // Pink
        '#14b8a6', // Teal
        '#94a3b8', // Slate
    ];

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

    const measureCanvas = document.createElement('canvas');
    const measureCtx = measureCanvas.getContext('2d');

    const imageCache = new Map();
    const getOrLoadImage = (src) => {
        if (!src) return null;
        if (imageCache.has(src)) return imageCache.get(src);
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
    // Draw.io Shape Libraries
    // =========================================================================
    const SHAPE_CATEGORIES = [
        {
            id: 'flowchart',
            name: 'Flowchart Shapes',
            color: '#60a5fa',
            items: [
                { type: 'fc_start', name: 'Start / End', shape: 'stadium', color: '#10b981', sub: '' },
                { type: 'fc_process', name: 'Process', shape: 'rect', color: '#60a5fa', sub: '' },
                { type: 'fc_decision', name: 'Decision', shape: 'diamond', color: '#eab308', sub: '' },
                { type: 'fc_data', name: 'Data / I-O', shape: 'parallelogram', color: '#22d3ee', sub: '' },
                { type: 'fc_subprocess', name: 'Subprocess', shape: 'subprocess', color: '#818cf8', sub: '' },
                { type: 'fc_document', name: 'Document', shape: 'document', color: '#94a3b8', sub: '' },
                { type: 'fc_multidoc', name: 'Multi-Doc', shape: 'multidoc', color: '#94a3b8', sub: '' },
                { type: 'fc_preparation', name: 'Preparation', shape: 'hexagon', color: '#a855f7', sub: '' },
                { type: 'fc_manual_input', name: 'Manual Input', shape: 'manual_input', color: '#f472b6', sub: '' },
                { type: 'fc_manual_op', name: 'Manual Op', shape: 'trapezoid_inv', color: '#fb923c', sub: '' },
                { type: 'fc_delay', name: 'Delay', shape: 'delay', color: '#f97316', sub: '' },
                { type: 'fc_database', name: 'Database', shape: 'cylinder', color: '#38bdf8', sub: '' },
                { type: 'fc_internal_store', name: 'Internal Store', shape: 'internal_storage', color: '#6366f1', sub: '' },
                { type: 'fc_stored_data', name: 'Stored Data', shape: 'stored_data', color: '#14b8a6', sub: '' },
                { type: 'fc_loop_limit', name: 'Loop Limit', shape: 'loop_limit', color: '#a855f7', sub: '' },
                { type: 'fc_offpage', name: 'Off-Page Ref', shape: 'offpage', color: '#eab308', sub: '' },
                { type: 'fc_or', name: 'Or Junction', shape: 'junction_or', color: '#f472b6', sub: '' },
                { type: 'fc_merge', name: 'Merge / Triangle', shape: 'merge', color: '#60a5fa', sub: '' },
                { type: 'fc_connector', name: 'Connector', shape: 'connector', color: '#94a3b8', sub: '' },
                { type: 'fc_callout', name: 'Callout', shape: 'callout', color: '#eab308', sub: '' },
            ],
        },
        {
            id: 'general',
            name: 'General & Containers',
            color: '#a855f7',
            items: [
                { type: 'gen_rounded', name: 'Rounded Box', shape: 'rounded', color: '#38bdf8', sub: '' },
                { type: 'gen_ellipse', name: 'Ellipse', shape: 'ellipse', color: '#a855f7', sub: '' },
                { type: 'gen_cloud', name: 'Cloud', shape: 'cloud', color: '#38bdf8', sub: '' },
                { type: 'gen_actor', name: 'Actor / User', shape: 'actor', color: '#eab308', sub: '' },
                { type: 'gen_cube', name: '3D Box / Cube', shape: 'cube', color: '#818cf8', sub: '' },
                { type: 'gen_step', name: 'Chevron Step', shape: 'step', color: '#10b981', sub: '' },
                { type: 'gen_note', name: 'Note Card', shape: 'note_card', color: '#eab308', sub: '' },
                { type: 'gen_star', name: 'Milestone Star', shape: 'star', color: '#f97316', sub: '' },
            ],
        },
        {
            id: 'soc_playbook',
            name: 'SOC & IR Playbook Steps',
            color: '#10b981',
            items: [
                { type: 'soc_trigger', name: 'Alert Trigger', shape: 'stadium', color: '#ef4444', sub: 'SIEM / EDR Detection' },
                { type: 'soc_enrich', name: 'TI Enrichment', shape: 'subprocess', color: '#38bdf8', sub: 'MANTIS IOC Lookup' },
                { type: 'soc_triage', name: 'Malicious?', shape: 'diamond', color: '#eab308', sub: 'Analyst / SOAR Gate' },
                { type: 'soc_contain', name: 'Isolate Host', shape: 'rect', color: '#ef4444', sub: 'EDR Network Contain' },
                { type: 'soc_hunt', name: 'Threat Hunt', shape: 'hexagon', color: '#a855f7', sub: 'Sweep SIEM / Zeek' },
                { type: 'soc_escalate', name: 'Escalate Tier-3', shape: 'offpage', color: '#f97316', sub: 'DFIR Hand-off' },
                { type: 'soc_soar', name: 'Block IOC', shape: 'parallelogram', color: '#10b981', sub: 'Firewall / Proxy API' },
                { type: 'soc_close', name: 'Close Ticket', shape: 'stadium', color: '#10b981', sub: 'Resolved / Benign' },
            ],
        },
    ];

    const ALL_SHAPES_MAP = new Map();
    SHAPE_CATEGORIES.forEach((cat) => {
        cat.items.forEach((it) => {
            ALL_SHAPES_MAP.set(it.type, { ...it, category: cat.id });
        });
    });
    ALL_SHAPES_MAP.set('image', {
        type: 'image',
        name: 'Inserted Image',
        shape: 'image',
        color: '#38bdf8',
        sub: '',
    });

    // =========================================================================
    // Built-in Draw.io Flowchart Templates
    // =========================================================================
    const TEMPLATES = {
        soc_playbook: () => ({
            title: 'SOC Phishing & Malware Alert Triage Playbook',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'LANE 1: SIEM & SOAR AUTOMATION', sub: 'Tier-0 Automated Ingestion & Enrichment', x: 60, y: 70, w: 380, h: 610, color: '#38bdf8', style: 'solid', opacity: 0.05 },
                { id: 'z2', label: 'LANE 2: TIER-1 / TIER-2 SOC ANALYST', sub: 'Triage, Verification & Scoping', x: 460, y: 70, w: 420, h: 610, color: '#eab308', style: 'solid', opacity: 0.05 },
                { id: 'z3', label: 'LANE 3: CONTAINMENT & DFIR ESCALATION', sub: 'Response & Remediation Actions', x: 900, y: 70, w: 420, h: 610, color: '#ef4444', style: 'solid', opacity: 0.05 },
            ],
            nodes: [
                { id: 'n1', type: 'soc_trigger', label: 'SIEM Alert Fired', sub: 'Suspicious Attachment / Beacon', x: 250, y: 170, color: '#ef4444', step: 'Start' },
                { id: 'n2', type: 'soc_enrich', label: 'Query MANTIS Intel', sub: 'Hash, Domain, IP & Sandbox', x: 250, y: 330, color: '#38bdf8', step: 'Auto-Enrich' },
                { id: 'n3', type: 'fc_database', label: 'MANTIS TI Cache', sub: 'VT + MISP + ThreatFox', x: 250, y: 520, color: '#a855f7', step: 'DB' },
                { id: 'n4', type: 'soc_triage', label: 'Confirmed Malicious?', sub: 'Risk Score >= 75', x: 670, y: 330, color: '#eab308', step: 'Decision' },
                { id: 'n5', type: 'soc_close', label: 'Close as False Positive', sub: 'Update Baseline Filter', x: 670, y: 550, color: '#10b981', step: 'End (Benign)' },
                { id: 'n6', type: 'soc_contain', label: 'Isolate Endpoint & Reset Creds', sub: 'EDR Contain + Revoke OAuth', x: 1110, y: 200, color: '#ef4444', step: 'Contain' },
                { id: 'n7', type: 'soc_soar', label: 'Push IOCs to NGFW / DNS', sub: 'Block C2 Domains & IPs', x: 1110, y: 370, color: '#f97316', step: 'Block' },
                { id: 'n8', type: 'soc_escalate', label: 'Open DFIR Incident Case', sub: 'Full Memory & Disk Triage', x: 1110, y: 550, color: '#a855f7', step: 'Escalate' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'Webhook Trigger', color: '#38bdf8', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n2', to: 'n3', label: 'Lookup IOCs', color: '#a855f7', style: 'dashed', curve: 'step', dir: 'both', width: 1.8 },
                { id: 'e3', from: 'n2', to: 'n4', label: 'Enriched Context', color: '#38bdf8', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n4', to: 'n5', label: 'No (Benign)', color: '#10b981', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n4', to: 'n6', label: 'Yes (True Positive)', color: '#ef4444', style: 'animated', curve: 'step', dir: 'forward', width: 2.2 },
                { id: 'e6', from: 'n6', to: 'n7', label: 'Auto-Block', color: '#f97316', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e7', from: 'n7', to: 'n8', label: 'Hand-off to IR', color: '#a855f7', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
            ],
            notes: [],
        }),

        ir_lifecycle: () => ({
            title: 'NIST SP 800-61 Incident Response Lifecycle Flowchart',
            defaultFont: 'Plus Jakarta Sans',
            zones: [
                { id: 'z1', label: 'INCIDENT RESPONSE LIFECYCLE (NIST SP 800-61r2)', sub: 'Continuous Feedback & Lessons Learned Loop', x: 70, y: 80, w: 1240, h: 480, color: '#38bdf8', style: 'dashed', opacity: 0.05 },
            ],
            nodes: [
                { id: 'n1', type: 'fc_preparation', label: '1. Preparation', sub: 'Tools, Playbooks, Telemetry', x: 220, y: 230, color: '#38bdf8', step: 'Phase 1' },
                { id: 'n2', type: 'fc_process', label: '2. Detection & Analysis', sub: 'Alert Triage & IOC Scoping', x: 520, y: 230, color: '#eab308', step: 'Phase 2' },
                { id: 'n3', type: 'fc_decision', label: 'Breach Confirmed?', sub: 'Severity Assessment', x: 520, y: 430, color: '#f97316', step: 'Gate' },
                { id: 'n4', type: 'fc_subprocess', label: '3. Containment & Eradication', sub: 'Isolate Hosts & Wipe Persistence', x: 860, y: 230, color: '#ef4444', step: 'Phase 3' },
                { id: 'n5', type: 'fc_data', label: '4. Recovery & Validation', sub: 'Restore Clean Backups & Monitor', x: 860, y: 430, color: '#10b981', step: 'Phase 4' },
                { id: 'n6', type: 'fc_document', label: '5. Post-Incident Report', sub: 'Root Cause & Detection Tuning', x: 1160, y: 330, color: '#a855f7', step: 'Phase 5' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'Continuous Monitoring', color: '#38bdf8', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n2', to: 'n3', label: 'Evaluate Findings', color: '#eab308', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n3', to: 'n4', label: 'Yes — Contain', color: '#ef4444', style: 'animated', curve: 'step', dir: 'forward', width: 2.2 },
                { id: 'e4', from: 'n4', to: 'n5', label: 'Threat Eradicated', color: '#10b981', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e5', from: 'n5', to: 'n6', label: 'Document Lessons', color: '#a855f7', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e6', from: 'n6', to: 'n1', label: 'Update Detections & Controls', color: '#38bdf8', style: 'dashed', curve: 'bezier', dir: 'forward', width: 2 },
            ],
            notes: [],
        }),

        vuln_mgmt: () => ({
            title: 'Vulnerability Triage & Emergency Patching Workflow',
            defaultFont: 'Plus Jakarta Sans',
            zones: [],
            nodes: [
                { id: 'n1', type: 'fc_start', label: 'New CVE Published', sub: 'MANTIS Vulnerability Intel Feed', x: 200, y: 260, color: '#38bdf8', step: 'Trigger' },
                { id: 'n2', type: 'fc_data', label: 'Check Asset Inventory', sub: 'SBOM & External Attack Surface', x: 470, y: 260, color: '#60a5fa', step: 'Scan' },
                { id: 'n3', type: 'fc_decision', label: 'Asset Affected?', sub: 'Present in Environment', x: 740, y: 260, color: '#eab308', step: 'Check 1' },
                { id: 'n4', type: 'fc_decision', label: 'CISA KEV or Public PoC?', sub: 'EPSS > 0.5 / Active Exploit', x: 740, y: 460, color: '#ef4444', step: 'Check 2' },
                { id: 'n5', type: 'fc_process', label: 'Emergency 24h Patch + WAF', sub: 'Virtual Patch + Change Freeze Override', x: 1080, y: 360, color: '#ef4444', step: 'Critical SLA' },
                { id: 'n6', type: 'fc_delay', label: 'Standard 30-Day Patch Cycle', sub: 'Scheduled Maintenance Window', x: 1080, y: 530, color: '#10b981', step: 'Normal SLA' },
            ],
            edges: [
                { id: 'e1', from: 'n1', to: 'n2', label: 'Ingest CVE', color: '#38bdf8', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e2', from: 'n2', to: 'n3', label: 'Query CMDB', color: '#60a5fa', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e3', from: 'n3', to: 'n4', label: 'Yes', color: '#eab308', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
                { id: 'e4', from: 'n4', to: 'n5', label: 'Yes (Actively Exploited)', color: '#ef4444', style: 'animated', curve: 'step', dir: 'forward', width: 2.2 },
                { id: 'e5', from: 'n4', to: 'n6', label: 'No (Standard Risk)', color: '#10b981', style: 'solid', curve: 'step', dir: 'forward', width: 2 },
            ],
            notes: [],
        }),
    };

    // Studio State
    const state = {
        initialized: false,
        title: 'SOC Phishing & Malware Alert Triage Playbook',
        defaultFont: 'Plus Jakarta Sans',
        mode: 'select', // 'select' | 'connect' | 'zone' | 'text' | 'pan'
        canvasTheme: 'dark',
        showGrid: true,
        snapToGrid: true,
        animateFlows: true,
        searchQuery: '',
        activeCatFilter: 'all',
        paletteCollapsed: false,
        inspectorCollapsed: false,
        collapsedCats: new Set(),

        panX: 20,
        panY: 20,
        zoom: 1,
        lastMouseWorld: { x: 480, y: 280 },

        zones: [],
        nodes: [],
        edges: [],
        notes: [],

        selectedType: null,
        selectedIds: new Set(),
        clipboard: null,

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
        marquee: null,
        hoveredNodeId: null,

        undoStack: [],
        redoStack: [],
        animFrameId: null,
        animTick: 0,
    };

    const NODE_MIN_W = 168;
    const NODE_MIN_H = 68;
    const GRID_SIZE = 20;

    const uid = (prefix = 'fc') => `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;

    const esc = (v) => String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');

    const snap = (val) => (state.snapToGrid ? Math.round(val / GRID_SIZE) * GRID_SIZE : Math.round(val));

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

    const getNodeSize = (n) => {
        if (n.type === 'image') {
            return {
                w: Math.max(80, Number(n.w) || 210),
                h: Math.max(60, Number(n.h) || 145),
            };
        }
        const asset = ALL_SHAPES_MAP.get(n.type) || { name: 'Step', shape: 'rect', sub: '' };
        const shape = n.shape || asset.shape || 'rect';
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

        const isCompactCircle = shape === 'connector' || shape === 'junction_or';
        if (isCompactCircle && !subText && labelText.length <= 6) {
            const sz = Math.max(64, Number(n.w) || 68);
            return { w: sz, h: sz };
        }

        const padW = (shape === 'diamond' || shape === 'merge') ? 96 : 54;
        const minW = (shape === 'diamond') ? 190 : NODE_MIN_W;
        const minH = (shape === 'diamond' || shape === 'cylinder' || shape === 'actor') ? 88 : NODE_MIN_H;
        const autoW = Math.ceil(measuredW + padW);
        const autoH = Math.max(minH, Math.ceil(labelFontSize + (subText ? subFontSize + 36 : 28)));

        return {
            w: Math.max(minW, Number(n.w) || 0, autoW),
            h: Math.max(minH, Number(n.h) || 0, autoH),
        };
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

    const hexToRgba = (hex, alpha = 1) => {
        const clean = String(hex || '#38bdf8').replace('#', '');
        const num = parseInt(clean.length === 3 ? clean.split('').map((c) => c + c).join('') : clean, 16);
        const r = (num >> 16) & 255;
        const g = (num >> 8) & 255;
        const b = num & 255;
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    };

    // =========================================================================
    // Draw.io Geometric Shape Path Builder (Canvas & SVG Preview)
    // =========================================================================
    const traceDrawioShapePath = (ctx, shape, x, y, w, h) => {
        ctx.beginPath();
        switch (shape) {
            case 'stadium':
                roundRect(ctx, x, y, w, h, h / 2);
                return;
            case 'rounded':
                roundRect(ctx, x, y, w, h, 14);
                return;
            case 'ellipse':
                ctx.ellipse(x + w / 2, y + h / 2, w / 2, h / 2, 0, 0, Math.PI * 2);
                ctx.closePath();
                return;
            case 'connector':
            case 'junction_or': {
                const rad = Math.min(w, h) / 2;
                ctx.arc(x + w / 2, y + h / 2, rad, 0, Math.PI * 2);
                ctx.closePath();
                return;
            }
            case 'diamond':
                ctx.moveTo(x + w / 2, y);
                ctx.lineTo(x + w, y + h / 2);
                ctx.lineTo(x + w / 2, y + h);
                ctx.lineTo(x, y + h / 2);
                ctx.closePath();
                return;
            case 'parallelogram': {
                const skew = Math.min(24, w * 0.15);
                ctx.moveTo(x + skew, y);
                ctx.lineTo(x + w, y);
                ctx.lineTo(x + w - skew, y + h);
                ctx.lineTo(x, y + h);
                ctx.closePath();
                return;
            }
            case 'trapezoid_inv': {
                const skew = Math.min(22, w * 0.14);
                ctx.moveTo(x, y);
                ctx.lineTo(x + w, y);
                ctx.lineTo(x + w - skew, y + h);
                ctx.lineTo(x + skew, y + h);
                ctx.closePath();
                return;
            }
            case 'hexagon': {
                const inset = Math.min(24, w * 0.15);
                ctx.moveTo(x + inset, y);
                ctx.lineTo(x + w - inset, y);
                ctx.lineTo(x + w, y + h / 2);
                ctx.lineTo(x + w - inset, y + h);
                ctx.lineTo(x + inset, y + h);
                ctx.closePath();
                ctx.lineTo(x, y + h / 2);
                ctx.closePath();
                return;
            }
            case 'document':
            case 'multidoc': {
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
            case 'manual_input': {
                const slant = Math.min(18, h * 0.25);
                ctx.moveTo(x, y + slant);
                ctx.lineTo(x + w, y);
                ctx.lineTo(x + w, y + h);
                ctx.lineTo(x, y + h);
                ctx.closePath();
                return;
            }
            case 'delay': {
                const r = h / 2;
                ctx.moveTo(x, y);
                ctx.lineTo(x + w - r, y);
                ctx.arc(x + w - r, y + r, r, -Math.PI / 2, Math.PI / 2);
                ctx.lineTo(x, y + h);
                ctx.closePath();
                return;
            }
            case 'stored_data': {
                const curve = Math.min(20, w * 0.14);
                ctx.moveTo(x + curve, y);
                ctx.lineTo(x + w, y);
                ctx.quadraticCurveTo(x + w - curve, y + h / 2, x + w, y + h);
                ctx.lineTo(x + curve, y + h);
                ctx.quadraticCurveTo(x - curve * 0.4, y + h / 2, x + curve, y);
                ctx.closePath();
                return;
            }
            case 'loop_limit': {
                const c = 16;
                ctx.moveTo(x + c, y);
                ctx.lineTo(x + w - c, y);
                ctx.lineTo(x + w, y + c);
                ctx.lineTo(x + w, y + h);
                ctx.lineTo(x, y + h);
                ctx.lineTo(x, y + c);
                ctx.closePath();
                return;
            }
            case 'offpage': {
                const tip = Math.min(20, h * 0.28);
                ctx.moveTo(x, y);
                ctx.lineTo(x + w, y);
                ctx.lineTo(x + w, y + h - tip);
                ctx.lineTo(x + w / 2, y + h);
                ctx.lineTo(x, y + h - tip);
                ctx.closePath();
                return;
            }
            case 'merge':
                ctx.moveTo(x, y);
                ctx.lineTo(x + w, y);
                ctx.lineTo(x + w / 2, y + h);
                ctx.closePath();
                return;
            case 'step': {
                const notch = 18;
                ctx.moveTo(x, y);
                ctx.lineTo(x + w - notch, y);
                ctx.lineTo(x + w, y + h / 2);
                ctx.lineTo(x + w - notch, y + h);
                ctx.lineTo(x, y + h);
                ctx.lineTo(x + notch * 0.7, y + h / 2);
                ctx.closePath();
                return;
            }
            case 'note_card': {
                const fold = 16;
                ctx.moveTo(x, y);
                ctx.lineTo(x + w - fold, y);
                ctx.lineTo(x + w, y + fold);
                ctx.lineTo(x + w, y + h);
                ctx.lineTo(x, y + h);
                ctx.closePath();
                return;
            }
            case 'callout': {
                const tail = 12;
                const bh = h - tail;
                roundRect(ctx, x, y, w, bh, 8);
                return;
            }
            case 'cylinder': {
                const ry = Math.min(12, h * 0.18);
                ctx.moveTo(x, y + ry);
                ctx.bezierCurveTo(x, y - ry * 0.3, x + w, y - ry * 0.3, x + w, y + ry);
                ctx.lineTo(x + w, y + h - ry);
                ctx.bezierCurveTo(x + w, y + h + ry * 0.3, x, y + h + ry * 0.3, x, y + h - ry);
                ctx.closePath();
                return;
            }
            default:
                roundRect(ctx, x, y, w, h, 6);
        }
    };

    const getDrawioTileSvg = (shape, color) => {
        const s = esc(color || '#60a5fa');
        switch (shape) {
            case 'stadium':
                return `<svg viewBox="0 0 24 24"><rect x="3" y="7" width="18" height="10" rx="5" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
            case 'rounded':
                return `<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="4" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
            case 'ellipse':
                return `<svg viewBox="0 0 24 24"><ellipse cx="12" cy="12" rx="9" ry="6" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
            case 'diamond':
                return `<svg viewBox="0 0 24 24"><polygon points="12,3 21,12 12,21 3,12" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'parallelogram':
                return `<svg viewBox="0 0 24 24"><polygon points="7,6 21,6 17,18 3,18" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'trapezoid_inv':
                return `<svg viewBox="0 0 24 24"><polygon points="3,6 21,6 17,18 7,18" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'document':
                return `<svg viewBox="0 0 24 24"><path d="M4,5 H20 V16 Q16,20 12,17 T4,18 Z" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'multidoc':
                return `<svg viewBox="0 0 24 24"><path d="M6,4 H21 V14 M3,7 H18 V17 Q14,20 10,18 T3,19 Z" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'subprocess':
                return `<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="1.5" fill="none" stroke="${s}" stroke-width="2"/><line x1="7" y1="6" x2="7" y2="18" stroke="${s}" stroke-width="2"/><line x1="17" y1="6" x2="17" y2="18" stroke="${s}" stroke-width="2"/></svg>`;
            case 'hexagon':
                return `<svg viewBox="0 0 24 24"><polygon points="7,6 17,6 21,12 17,18 7,18 3,12" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'manual_input':
                return `<svg viewBox="0 0 24 24"><polygon points="3,9 21,5 21,18 3,18" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'delay':
                return `<svg viewBox="0 0 24 24"><path d="M4,6 H13 A6,6 0 0 1 13,18 H4 Z" fill="none" stroke="${s}" stroke-width="2" stroke-linejoin="round"/></svg>`;
            case 'cylinder':
                return `<svg viewBox="0 0 24 24"><ellipse cx="12" cy="6.5" rx="7.5" ry="2.8" fill="none" stroke="${s}" stroke-width="1.8"/><path d="M4.5,6.5 V17.5 A7.5,2.8 0 0 0 19.5,17.5 V6.5" fill="none" stroke="${s}" stroke-width="1.8"/></svg>`;
            case 'internal_storage':
                return `<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="1.5" fill="none" stroke="${s}" stroke-width="1.8"/><line x1="7.5" y1="5" x2="7.5" y2="19" stroke="${s}" stroke-width="1.8"/><line x1="3" y1="9.5" x2="21" y2="9.5" stroke="${s}" stroke-width="1.8"/></svg>`;
            case 'stored_data':
                return `<svg viewBox="0 0 24 24"><path d="M7,6 H20 Q16,12 20,18 H7 Q2,12 7,6 Z" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'loop_limit':
                return `<svg viewBox="0 0 24 24"><polygon points="7,6 17,6 21,10 21,18 3,18 3,10" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'offpage':
                return `<svg viewBox="0 0 24 24"><polygon points="4,5 20,5 20,15 12,20 4,15" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'junction_or':
                return `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="7" fill="none" stroke="${s}" stroke-width="1.8"/><line x1="12" y1="5" x2="12" y2="19" stroke="${s}" stroke-width="1.8"/><line x1="5" y1="12" x2="19" y2="12" stroke="${s}" stroke-width="1.8"/></svg>`;
            case 'merge':
                return `<svg viewBox="0 0 24 24"><polygon points="4,6 20,6 12,19" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'connector':
                return `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="6" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
            case 'callout':
                return `<svg viewBox="0 0 24 24"><path d="M4,5 H20 V15 H11 L7,19 V15 H4 Z" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'cloud':
                return `<svg viewBox="0 0 24 24"><path d="M7,18 H18 A4,4 0 0 0 18,10 A5,5 0 0 0 8.5,8 A4.5,4.5 0 0 0 7,18 Z" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'actor':
                return `<svg viewBox="0 0 24 24"><circle cx="12" cy="6" r="3" fill="none" stroke="${s}" stroke-width="1.8"/><path d="M12,9 V15 M7,11 H17 M12,15 L8,20 M12,15 L16,20" fill="none" stroke="${s}" stroke-width="1.8" stroke-linecap="round"/></svg>`;
            case 'cube':
                return `<svg viewBox="0 0 24 24"><polygon points="3,8 8,4 21,4 21,16 16,20 3,20" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/><path d="M3,8 L16,8 L21,4 M16,8 L16,20" fill="none" stroke="${s}" stroke-width="1.6" stroke-linejoin="round"/></svg>`;
            case 'step':
                return `<svg viewBox="0 0 24 24"><polygon points="3,6 17,6 21,12 17,18 3,18 7,12" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
            case 'note_card':
                return `<svg viewBox="0 0 24 24"><polygon points="4,4 16,4 20,8 20,20 4,20" fill="none" stroke="${s}" stroke-width="1.8" stroke-linejoin="round"/><polyline points="16,4 16,8 20,8" fill="none" stroke="${s}" stroke-width="1.6"/></svg>`;
            case 'star':
                return `<svg viewBox="0 0 24 24"><polygon points="12,3 14.8,8.8 21,9.7 16.5,14.1 17.6,20.3 12,17.3 6.4,20.3 7.5,14.1 3,9.7 9.2,8.8" fill="none" stroke="${s}" stroke-width="1.7" stroke-linejoin="round"/></svg>`;
            default:
                return `<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="1.5" fill="none" stroke="${s}" stroke-width="2"/></svg>`;
        }
    };

    // =========================================================================
    // Serialization & History
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
        state.title = snapData.title || 'Untitled Flowchart';
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

        const topFont = document.getElementById('fc-global-font');
        if (topFont) topFont.value = state.defaultFont;
        const disp = document.getElementById('fc-diagram-title-input');
        if (disp) disp.value = state.title;

        saveToLocalStorage();
        updateToolbarButtons();
        renderInspector();
        requestRender();
    };

    const undo = () => {
        if (!state.undoStack.length) return;
        state.redoStack.push(serializeDiagram());
        applySnapshot(state.undoStack.pop());
        showToast('Undid last action');
    };

    const redo = () => {
        if (!state.redoStack.length) return;
        state.undoStack.push(serializeDiagram());
        applySnapshot(state.redoStack.pop());
        showToast('Redid action');
    };

    let toastTimer = null;
    const showToast = (msg, isError = false) => {
        const el = document.getElementById('fc-toast');
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

    // =========================================================================
    // Ports, Draw.io Quick-Add Arrows (▲ ▶ ▼ ◀), & Hit Testing
    // =========================================================================
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

    // Draw.io Quick-Add Directional Triangles outside a single selected shape
    const getQuickAddArrows = (n) => {
        const { w, h } = getNodeSize(n);
        const offset = 22;
        return [
            { dir: 'top', x: n.x, y: n.y - h / 2 - offset, dx: 0, dy: -(h + 84) },
            { dir: 'right', x: n.x + w / 2 + offset, y: n.y, dx: w + 100, dy: 0 },
            { dir: 'bottom', x: n.x, y: n.y + h / 2 + offset, dx: 0, dy: h + 84 },
            { dir: 'left', x: n.x - w / 2 - offset, y: n.y, dx: -(w + 100), dy: 0 },
        ];
    };

    const hitTestQuickAddArrow = (wx, wy) => {
        if (state.selectedType !== 'node' || state.selectedIds.size !== 1) return null;
        const firstId = [...state.selectedIds][0];
        const n = state.nodes.find((it) => it.id === firstId);
        if (!n) return null;
        const arrows = getQuickAddArrows(n);
        for (const a of arrows) {
            if (Math.hypot(wx - a.x, wy - a.y) <= 11) {
                return { node: n, arrow: a };
            }
        }
        return null;
    };

    const hitTestPort = (wx, wy) => {
        for (let i = state.nodes.length - 1; i >= 0; i--) {
            const n = state.nodes[i];
            const ports = getNodePorts(n);
            for (const p of ports) {
                if (Math.hypot(wx - p.x, wy - p.y) <= 8) {
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
            if (Math.abs(wx - (n.x + w / 2)) <= 10 && Math.abs(wy - (n.y + h / 2)) <= 10) {
                return n;
            }
        }
        return null;
    };

    const hitTestNode = (wx, wy) => {
        for (let i = state.nodes.length - 1; i >= 0; i--) {
            const n = state.nodes[i];
            const { w, h } = getNodeSize(n);
            if (wx >= n.x - w / 2 && wx <= n.x + w / 2 && wy >= n.y - h / 2 && wy <= n.y + h / 2) {
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
    // Free connection points: every connector may pin its start (fromPort)
    // and/or end (toPort) to any side of a shape (top | right | bottom | left).
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
            if (h1 && h2) {
                if (d1.x === d2.x) {
                    const m = d1.x > 0 ? Math.max(x1, x2) + GAP : Math.min(x1, x2) - GAP;
                    P.push([m, y1], [m, y2]);
                } else if (d1.x > 0 ? x2 >= x1 : x2 <= x1) {
                    const m = (x1 + x2) / 2;
                    P.push([m, y1], [m, y2]);
                } else {
                    const m1 = x1 + d1.x * GAP;
                    const m2 = x2 + d2.x * GAP;
                    const my = (y1 + y2) / 2;
                    P.push([m1, y1], [m1, my], [m2, my], [m2, y2]);
                }
            } else if (!h1 && !h2) {
                if (d1.y === d2.y) {
                    const m = d1.y > 0 ? Math.max(y1, y2) + GAP : Math.min(y1, y2) - GAP;
                    P.push([x1, m], [x2, m]);
                } else if (d1.y > 0 ? y2 >= y1 : y2 <= y1) {
                    const m = (y1 + y2) / 2;
                    P.push([x1, m], [x2, m]);
                } else {
                    const m1 = y1 + d1.y * GAP;
                    const m2 = y2 + d2.y * GAP;
                    const mx = (x1 + x2) / 2;
                    P.push([x1, m1], [mx, m1], [mx, m2], [x2, m2]);
                }
            } else if (h1) {
                P.push([x2, y1]);
            } else {
                P.push([x1, y2]);
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
            const flat = geomFlatten(getEdgeGeometry(e, pts, e.curve || 'step'));
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

    const portSelectOptions = (value) => ['auto', 'top', 'right', 'bottom', 'left']
        .map((s) => `<option value="${s}" ${(value || 'auto') === s ? 'selected' : ''}>${s === 'auto' ? 'Auto (nearest)' : s.charAt(0).toUpperCase() + s.slice(1)}</option>`)
        .join('');

    const hitTestZoneResize = (wx, wy) => {
        for (let i = state.zones.length - 1; i >= 0; i--) {
            const z = state.zones[i];
            if (Math.abs(wx - (z.x + z.w)) <= 10 && Math.abs(wy - (z.y + z.h)) <= 10) {
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

    // =========================================================================
    // Auto-Layout & Multi-Node Alignment (Draw.io Arrange Tools)
    // =========================================================================
    const autoLayoutFlowchart = (direction = 'TB') => {
        if (state.nodes.length < 2) return;
        pushHistory();
        const inDeg = new Map(state.nodes.map((n) => [n.id, 0]));
        const adj = new Map(state.nodes.map((n) => [n.id, []]));
        state.edges.forEach((e) => {
            if (adj.has(e.from) && inDeg.has(e.to)) {
                adj.get(e.from).push(e.to);
                inDeg.set(e.to, (inDeg.get(e.to) || 0) + 1);
            }
        });

        const levels = new Map();
        const queue = [];
        state.nodes.forEach((n) => {
            if ((inDeg.get(n.id) || 0) === 0) {
                levels.set(n.id, 0);
                queue.push(n.id);
            }
        });
        if (!queue.length && state.nodes.length) {
            levels.set(state.nodes[0].id, 0);
            queue.push(state.nodes[0].id);
        }

        while (queue.length) {
            const curr = queue.shift();
            const l = levels.get(curr) || 0;
            (adj.get(curr) || []).forEach((nxt) => {
                if (!levels.has(nxt) || levels.get(nxt) < l + 1) {
                    if ((levels.get(nxt) || 0) < 12) {
                        levels.set(nxt, l + 1);
                        queue.push(nxt);
                    }
                }
            });
        }

        const groups = new Map();
        state.nodes.forEach((n) => {
            const lv = levels.get(n.id) ?? 0;
            if (!groups.has(lv)) groups.set(lv, []);
            groups.get(lv).push(n);
        });

        const startX = 240;
        const startY = 160;
        const gapMain = direction === 'LR' ? 280 : 150;
        const gapCross = direction === 'LR' ? 140 : 260;

        [...groups.keys()].sort((a, b) => a - b).forEach((lv) => {
            const row = groups.get(lv);
            row.forEach((n, idx) => {
                const offsetCross = (idx - (row.length - 1) / 2) * gapCross;
                if (direction === 'LR') {
                    n.x = snap(startX + lv * gapMain);
                    n.y = snap(320 + offsetCross);
                } else {
                    n.x = snap(640 + offsetCross);
                    n.y = snap(startY + lv * gapMain);
                }
            });
        });

        saveToLocalStorage();
        fitToScreen();
        showToast(`Applied ${direction === 'LR' ? 'Left-to-Right' : 'Top-to-Bottom'} Flowchart Layout`);
    };

    // =========================================================================
    // Core Scene Renderer (Draw.io Shapes, Swimlanes, Orthogonal Links, Quick-Add Arrows)
    // =========================================================================
    function resolveFlowchartEdgeColor(eColor, isWhite) {
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

        if (isTransparent) {
            ctx.clearRect(0, 0, width, height);
        } else if (isWhite) {
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, width, height);
        } else {
            ctx.fillStyle = '#070b12';
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

        // 1. Render Swimlanes & Containers
        state.zones.forEach((z) => {
            const isSelected = !isExport && state.selectedType === 'zone' && state.selectedIds.has(z.id);
            const zColor = z.color || '#38bdf8';
            const fillAlpha = isWhite ? Math.max(0.04, (z.opacity ?? 0.05) * 0.9) : (z.opacity ?? 0.05);

            roundRect(ctx, z.x, z.y, z.w, z.h, 10);
            ctx.fillStyle = hexToRgba(zColor, fillAlpha);
            ctx.fill();

            // Draw.io Swimlane Top Header Band
            ctx.save();
            roundRect(ctx, z.x, z.y, z.w, z.h, 10);
            ctx.clip();
            ctx.fillStyle = hexToRgba(zColor, isWhite ? 0.14 : 0.16);
            ctx.fillRect(z.x, z.y, z.w, 36);
            ctx.beginPath();
            ctx.moveTo(z.x, z.y + 36);
            ctx.lineTo(z.x + z.w, z.y + 36);
            ctx.strokeStyle = hexToRgba(zColor, 0.45);
            ctx.lineWidth = 1;
            ctx.stroke();
            ctx.restore();

            roundRect(ctx, z.x, z.y, z.w, z.h, 10);
            ctx.lineWidth = isSelected ? 2.2 : 1.4;
            ctx.strokeStyle = isSelected ? '#ffcc00' : hexToRgba(zColor, isWhite ? 0.65 : 0.48);
            if (z.style === 'dashed') ctx.setLineDash([7, 5]);
            else ctx.setLineDash([]);
            ctx.stroke();
            ctx.setLineDash([]);

            const titleText = (z.label || 'SWIMLANE').toUpperCase();
            const zFontSize = Number(z.fontSize) || 11;
            ctx.font = buildCanvasFont({
                family: z.fontFamily,
                size: zFontSize,
                bold: z.fontBold !== false,
                italic: !!z.fontItalic,
            });
            ctx.fillStyle = isWhite ? '#0f172a' : '#f8fafc';
            ctx.textBaseline = 'middle';
            ctx.textAlign = 'center';
            ctx.fillText(titleText, z.x + z.w / 2, z.y + 18);

            if (z.sub) {
                ctx.font = buildCanvasFont({
                    family: z.fontFamily,
                    size: Math.max(9.5, zFontSize - 1),
                    bold: false,
                    italic: !!z.fontItalic,
                });
                ctx.fillStyle = isWhite ? '#475569' : '#8b9bb4';
                ctx.fillText(z.sub, z.x + z.w / 2, z.y + 52);
            }

            if (isSelected) {
                ctx.fillStyle = '#ffcc00';
                ctx.fillRect(z.x + z.w - 6, z.y + z.h - 6, 12, 12);
            }
        });

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

        // 2. Render Connectors (Edges)
        state.edges.forEach((e) => {
            const pts = getEdgeEndpoints(e);
            if (!pts) return;
            const isSelected = !isExport && state.selectedType === 'edge' && state.selectedIds.has(e.id);
            const color = isSelected ? '#ffcc00' : resolveFlowchartEdgeColor(e.color, isWhite);
            const widthVal = Number(e.width) || 2;
            const curveMode = e.curve || 'step'; // Default 'step' (orthogonal) in Flow Chart!

            const geo = getEdgeGeometry(e, pts, curveMode);

            ctx.beginPath();
            geomTrace(ctx, geo);

            ctx.strokeStyle = color;
            ctx.lineWidth = isSelected ? widthVal + 1 : widthVal;
            if (e.style === 'dashed') ctx.setLineDash([7, 5]);
            else if (e.style === 'dotted') ctx.setLineDash([3, 5]);
            else if (e.style === 'animated') {
                ctx.setLineDash([8, 6]);
                ctx.lineDashOffset = -state.animTick * 0.7;
            } else ctx.setLineDash([]);
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
            if (e.dir !== 'none') drawArrow(pts.x2, pts.y2, refs.endRef[0], refs.endRef[1]);
            if (e.dir === 'both') drawArrow(pts.x1, pts.y1, refs.startRef[0], refs.startRef[1]);

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
            }

            if (e.label) {
                const midPt = geomMid(geo);
                const mx = midPt.x;
                const my = midPt.y;
                const eFontSize = Number(e.fontSize) || 10.5;
                ctx.font = buildCanvasFont({
                    family: e.fontFamily,
                    size: eFontSize,
                    bold: e.fontBold !== false,
                    italic: !!e.fontItalic,
                });
                const tw = ctx.measureText(e.label).width;
                const pw = tw + 16;
                const ph = Math.max(20, eFontSize + 8);
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

        // 3. Render Draw.io Geometric Flowchart Nodes
        state.nodes.forEach((n) => {
            const asset = ALL_SHAPES_MAP.get(n.type) || { name: 'Step', shape: 'rect', color: '#38bdf8' };
            const shape = n.shape || asset.shape || 'rect';
            const isSelected = !isExport && state.selectedType === 'node' && state.selectedIds.has(n.id);
            const isHovered = !isExport && state.hoveredNodeId === n.id;
            const nColor = n.color || asset.color || '#38bdf8';
            const { w, h } = getNodeSize(n);
            const x = n.x - w / 2;
            const y = n.y - h / 2;
            const labelFontSize = Number(n.fontSize) || 12.5;
            const subFontSize = Math.max(9.5, labelFontSize - 1.5);

            if (n.type === 'image') {
                const showFrame = n.showFrame !== false;
                if (showFrame) {
                    ctx.save();
                    ctx.shadowColor = isSelected ? 'rgba(255, 204, 0, 0.35)' : 'rgba(0, 0, 0, 0.45)';
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
                roundRect(ctx, imgX, imgY, imgW, imgH, 6);
                ctx.clip();
                if (imgEntry && imgEntry.loaded) {
                    ctx.drawImage(imgEntry.img, imgX, imgY, imgW, imgH);
                }
                ctx.restore();
                if (showFrame || isSelected) {
                    roundRect(ctx, x, y, w, h, 10);
                    ctx.lineWidth = isSelected ? 2 : 1.2;
                    ctx.strokeStyle = isSelected ? '#ffcc00' : hexToRgba(nColor, 0.5);
                    ctx.stroke();
                }
                if (n.showCaption !== false && n.label) {
                    ctx.font = buildCanvasFont({ family: n.fontFamily, size: labelFontSize, bold: true });
                    ctx.fillStyle = isWhite ? '#0f172a' : '#f8fafc';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(n.label, n.x, y + h - captionHeight / 2 - 2);
                }
            } else {
                // Draw Geometric Shape Shadow & Base Fill
                ctx.save();
                ctx.shadowColor = isSelected
                    ? 'rgba(255, 204, 0, 0.32)'
                    : (isWhite ? 'rgba(15, 23, 42, 0.09)' : 'rgba(0, 0, 0, 0.5)');
                ctx.shadowBlur = isSelected ? 18 : 14;
                ctx.shadowOffsetY = 4;

                traceDrawioShapePath(ctx, shape, x, y, w, h);
                ctx.fillStyle = isWhite ? '#ffffff' : '#111827';
                ctx.fill();
                ctx.restore();

                // Tinted Inner Overlay + Crisp Geometric Stroke
                traceDrawioShapePath(ctx, shape, x, y, w, h);
                ctx.fillStyle = hexToRgba(nColor, isWhite ? 0.09 : 0.13);
                ctx.fill();
                ctx.lineWidth = isSelected ? 2.2 : 1.8;
                ctx.strokeStyle = isSelected ? '#ffcc00' : nColor;
                ctx.stroke();

                // Shape-specific inner detail lines (Subprocess, Internal Storage, Cylinder top cap, Note fold, Junction cross)
                ctx.strokeStyle = isSelected ? '#ffcc00' : hexToRgba(nColor, 0.72);
                ctx.lineWidth = 1.4;
                if (shape === 'subprocess') {
                    ctx.beginPath();
                    ctx.moveTo(x + 14, y);
                    ctx.lineTo(x + 14, y + h);
                    ctx.moveTo(x + w - 14, y);
                    ctx.lineTo(x + w - 14, y + h);
                    ctx.stroke();
                } else if (shape === 'internal_storage') {
                    ctx.beginPath();
                    ctx.moveTo(x + 16, y);
                    ctx.lineTo(x + 16, y + h);
                    ctx.moveTo(x, y + 14);
                    ctx.lineTo(x + w, y + 14);
                    ctx.stroke();
                } else if (shape === 'cylinder') {
                    const ry = Math.min(12, h * 0.18);
                    ctx.beginPath();
                    ctx.moveTo(x, y + ry);
                    ctx.bezierCurveTo(x, y + ry * 2.2, x + w, y + ry * 2.2, x + w, y + ry);
                    ctx.stroke();
                } else if (shape === 'note_card') {
                    const fold = 16;
                    ctx.beginPath();
                    ctx.moveTo(x + w - fold, y);
                    ctx.lineTo(x + w - fold, y + fold);
                    ctx.lineTo(x + w, y + fold);
                    ctx.stroke();
                } else if (shape === 'junction_or') {
                    const rad = Math.min(w, h) / 2;
                    ctx.beginPath();
                    ctx.moveTo(n.x - rad * 0.65, n.y);
                    ctx.lineTo(n.x + rad * 0.65, n.y);
                    ctx.moveTo(n.x, n.y - rad * 0.65);
                    ctx.lineTo(n.x, n.y + rad * 0.65);
                    ctx.stroke();
                }

                // Centered Title & Subtitle inside Shape
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

                if (subStr) {
                    ctx.fillText(labelStr, n.x, y + h * 0.4);
                    ctx.font = buildCanvasFont({
                        family: n.fontFamily && n.fontFamily !== 'default' ? n.fontFamily : 'IBM Plex Mono',
                        size: subFontSize,
                        bold: false,
                        italic: !!n.fontItalic,
                    });
                    ctx.fillStyle = isWhite ? '#475569' : '#94a3b8';
                    ctx.fillText(subStr, n.x, y + h * 0.67);
                } else {
                    ctx.fillText(labelStr, n.x, y + h * 0.5);
                }
            }

            if (n.step) {
                ctx.font = buildCanvasFont({ family: 'IBM Plex Mono', size: 9, bold: true });
                const sw = ctx.measureText(n.step).width + 12;
                roundRect(ctx, n.x - sw / 2, y - 19, sw, 16, 4);
                ctx.fillStyle = isWhite ? '#0f172a' : '#161f33';
                ctx.fill();
                ctx.lineWidth = 1;
                ctx.strokeStyle = hexToRgba(nColor, 0.7);
                ctx.stroke();
                ctx.fillStyle = isWhite ? '#ffffff' : '#fde047';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(n.step, n.x, y - 11);
            }

            // Resize handle & Connection Ports
            if (!isExport && (isHovered || isSelected || state.mode === 'connect' || state.connectingFrom || state.draggingEdgeEnd)) {
                const ports = getNodePorts(n);
                const portR = (state.connectingFrom || state.draggingEdgeEnd) ? 6 : 4.5;
                ports.forEach((p) => {
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, portR, 0, Math.PI * 2);
                    ctx.fillStyle = '#ffcc00';
                    ctx.fill();
                    ctx.lineWidth = 1.5;
                    ctx.strokeStyle = '#070b12';
                    ctx.stroke();
                });
            }

            if (!isExport && isSelected) {
                ctx.fillStyle = '#ffcc00';
                ctx.fillRect(x + w - 5, y + h - 5, 10, 10);

                // Draw.io Quick-Add Directional Arrows (▲ ▶ ▼ ◀) when single node is selected
                if (state.selectedIds.size === 1) {
                    const arrows = getQuickAddArrows(n);
                    arrows.forEach((a) => {
                        ctx.save();
                        ctx.beginPath();
                        ctx.arc(a.x, a.y, 9, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(15, 23, 42, 0.92)';
                        ctx.fill();
                        ctx.lineWidth = 1.2;
                        ctx.strokeStyle = 'rgba(56, 189, 248, 0.65)';
                        ctx.stroke();

                        ctx.fillStyle = '#38bdf8';
                        ctx.beginPath();
                        const s = 4.2;
                        if (a.dir === 'top') {
                            ctx.moveTo(a.x, a.y - s);
                            ctx.lineTo(a.x + s, a.y + s * 0.8);
                            ctx.lineTo(a.x - s, a.y + s * 0.8);
                        } else if (a.dir === 'right') {
                            ctx.moveTo(a.x + s, a.y);
                            ctx.lineTo(a.x - s * 0.8, a.y - s);
                            ctx.lineTo(a.x - s * 0.8, a.y + s);
                        } else if (a.dir === 'bottom') {
                            ctx.moveTo(a.x, a.y + s);
                            ctx.lineTo(a.x + s, a.y - s * 0.8);
                            ctx.lineTo(a.x - s, a.y - s * 0.8);
                        } else {
                            ctx.moveTo(a.x - s, a.y);
                            ctx.lineTo(a.x + s * 0.8, a.y - s);
                            ctx.lineTo(a.x + s * 0.8, a.y + s);
                        }
                        ctx.closePath();
                        ctx.fill();
                        ctx.restore();
                    });
                }
            }
        });

        // 4. Render Callout Notes
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

        // 5. Marquee Selection Box
        if (!isExport && state.marquee) {
            const m = state.marquee;
            const mx = Math.min(m.x1, m.x2);
            const my = Math.min(m.y1, m.y2);
            const mw = Math.abs(m.x2 - m.x1);
            const mh = Math.abs(m.y2 - m.y1);
            ctx.fillStyle = 'rgba(56, 189, 248, 0.08)';
            ctx.fillRect(mx, my, mw, mh);
            ctx.strokeStyle = 'rgba(56, 189, 248, 0.75)';
            ctx.lineWidth = 1.2;
            ctx.setLineDash([4, 4]);
            ctx.strokeRect(mx, my, mw, mh);
            ctx.setLineDash([]);
        }

        ctx.restore();
    };

    // =========================================================================
    // Exports: PNG, SVG (Transparent, Dark, White) & .mantis-flow / .json
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
            minY = Math.min(minY, n.y - h / 2 - 22);
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

        if (!Number.isFinite(minX)) return { x: 0, y: 0, w: 960, h: 540 };
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
            showToast('Canvas is empty — add flowchart shapes first.', true);
            return;
        }
        const offCanvas = renderOffscreenCanvas(bgTheme);
        const slug = (state.title || 'mantis-flowchart').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'mantis-flowchart';
        const link = document.createElement('a');
        link.download = `${slug}-${bgTheme}-bg.png`;
        link.href = offCanvas.toDataURL('image/png');
        document.body.appendChild(link);
        link.click();
        link.remove();
        showToast(`Downloaded Flowchart PNG (${bgTheme} background)`);
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
            parts.push(`<rect width="100%" height="100%" fill="${isWhite ? '#ffffff' : '#070b12'}"/>`);
        }

        state.zones.forEach((z) => {
            const zx = z.x + ox;
            const zy = z.y + oy;
            const zc = z.color || '#38bdf8';
            parts.push(`<rect x="${zx}" y="${zy}" width="${z.w}" height="${z.h}" rx="10" fill="${zc}" fill-opacity="0.05" stroke="${zc}" stroke-opacity="0.55" stroke-width="1.5"/>`);
            parts.push(`<text x="${zx + z.w / 2}" y="${zy + 22}" text-anchor="middle" fill="${isWhite ? '#0f172a' : '#f8fafc'}" font-size="11" font-weight="700">${esc((z.label || 'SWIMLANE').toUpperCase())}</text>`);
        });

        state.edges.forEach((e) => {
            const pts = getEdgeEndpoints(e);
            if (!pts) return;
            const x1 = pts.x1 + ox;
            const y1 = pts.y1 + oy;
            const x2 = pts.x2 + ox;
            const y2 = pts.y2 + oy;
            const color = resolveFlowchartEdgeColor(e.color, isWhite);
            const expGeo = getEdgeGeometry(e, pts, e.curve || 'step');
            parts.push(`<path d="${geomSvgD(expGeo, ox, oy)}" fill="none" stroke="${color}" stroke-width="${e.width || 2}"/>`);
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
                const pw = Math.max(80, e.label.length * 6.8 + 16);
                parts.push(`<rect x="${mx - pw / 2}" y="${my - 10}" width="${pw}" height="20" rx="5" fill="${isWhite ? '#ffffff' : '#0a0f19'}" stroke="${color}" stroke-width="1"/>`);
                parts.push(`<text x="${mx}" y="${my + 4}" text-anchor="middle" fill="${isWhite ? '#0f172a' : '#e2e8f0'}" font-size="10.5" font-weight="600">${esc(e.label)}</text>`);
            }
        });

        state.nodes.forEach((n) => {
            const asset = ALL_SHAPES_MAP.get(n.type) || { name: 'Step', shape: 'rect', color: '#38bdf8' };
            const { w, h } = getNodeSize(n);
            const nx = n.x - w / 2 + ox;
            const ny = n.y - h / 2 + oy;
            const nc = n.color || asset.color || '#38bdf8';
            const rx = (n.shape || asset.shape) === 'stadium' ? h / 2 : 8;
            parts.push(`<rect x="${nx}" y="${ny}" width="${w}" height="${h}" rx="${rx}" fill="${isWhite ? '#ffffff' : '#111827'}" stroke="${nc}" stroke-width="1.8"/>`);
            parts.push(`<text x="${nx + w / 2}" y="${ny + (n.sub ? h * 0.42 : h * 0.54)}" text-anchor="middle" fill="${isWhite ? '#0f172a' : '#f8fafc'}" font-size="${Number(n.fontSize) || 12.5}" font-weight="700">${esc(n.label || asset.name)}</text>`);
            if (n.sub) {
                parts.push(`<text x="${nx + w / 2}" y="${ny + h * 0.7}" text-anchor="middle" fill="${isWhite ? '#475569' : '#94a3b8'}" font-size="10.5">${esc(n.sub)}</text>`);
            }
        });

        parts.push('</svg>');
        const blob = new Blob([parts.join('\n')], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const slug = (state.title || 'mantis-flowchart').toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'mantis-flowchart';
        const link = document.createElement('a');
        link.download = `${slug}-${bgTheme}-bg.svg`;
        link.href = url;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        showToast(`Downloaded SVG (${bgTheme} background)`);
    };

    const exportProjectFile = (ext = 'mantis-flow') => {
        const payload = {
            format: FILE_FORMAT_MAGIC,
            version: FILE_FORMAT_VERSION,
            exportedAt: new Date().toISOString(),
            diagram: serializeDiagram(),
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const slug = (state.title || 'mantis-flowchart').toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'mantis-flowchart';
        const link = document.createElement('a');
        link.download = `${slug}.${ext}`;
        link.href = url;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        showToast(`Saved ${slug}.${ext}`);
    };

    const importProjectFile = (file) => {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            try {
                const raw = JSON.parse(String(reader.result || '{}'));
                const diag = raw.diagram || raw;
                pushHistory();
                applySnapshot(diag);
                setTimeout(fitToScreen, 30);
                showToast(`Imported ${file.name}`);
            } catch (err) {
                showToast(`Failed to import file: ${err.message}`, true);
            }
        };
        reader.readAsText(file);
    };

    // =========================================================================
    // Canvas Render Loop & Fit to Screen
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
        const canvas = document.getElementById('fc-canvas');
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

        const zoomEl = document.getElementById('fc-zoom-readout');
        if (zoomEl) zoomEl.textContent = `${Math.round(state.zoom * 100)}%`;
    };

    const startAnimationLoop = () => {
        if (state.animFrameId) cancelAnimationFrame(state.animFrameId);
        const step = () => {
            const pane = document.getElementById('flowchart-draw-pane');
            if (pane && pane.style.display !== 'none' && state.animateFlows) {
                if (state.edges.some((e) => e.style === 'animated')) {
                    state.animTick = (state.animTick + 1) % 1000;
                    drawInteractiveCanvas();
                }
            }
            state.animFrameId = requestAnimationFrame(step);
        };
        state.animFrameId = requestAnimationFrame(step);
    };

    const fitToScreen = () => {
        const canvas = document.getElementById('fc-canvas');
        if (!canvas) return;
        const rect = canvas.getBoundingClientRect();
        if (!rect.width || !rect.height) return;
        const b = computeDiagramBounds();
        const padTop = 64;
        const padBottom = 56;
        const padX = 56;
        const availW = Math.max(200, rect.width - padX * 2);
        const availH = Math.max(180, rect.height - padTop - padBottom);
        state.zoom = Math.max(0.3, Math.min(1.12, Math.min(availW / b.w, availH / b.h)));
        state.panX = (rect.width - b.w * state.zoom) / 2 - b.x * state.zoom;
        state.panY = padTop + (availH - b.h * state.zoom) / 2 - b.y * state.zoom;
        requestRender();
    };

    // =========================================================================
    // Inline On-Canvas Double-Click Text Editor (Draw.io style)
    // =========================================================================
    const openInlineEditor = (targetItem, targetKind) => {
        const wrap = document.getElementById('fc-canvas-wrap');
        if (!wrap) return;
        document.getElementById('fc-inline-editor')?.remove();

        const textarea = document.createElement('textarea');
        textarea.id = 'fc-inline-editor';
        textarea.className = 'dd-inline-editor';
        const sx = (targetItem.x ?? 400) * state.zoom + state.panX;
        const sy = (targetItem.y ?? 250) * state.zoom + state.panY;
        const w = Math.max(160, 200 * state.zoom);
        const h = Math.max(54, 68 * state.zoom);
        textarea.style.left = `${Math.round(sx - w / 2)}px`;
        textarea.style.top = `${Math.round(sy - h / 2)}px`;
        textarea.style.width = `${Math.round(w)}px`;
        textarea.style.height = `${Math.round(h)}px`;
        textarea.value = targetKind === 'note' ? (targetItem.text || '') : (targetItem.label || '');

        wrap.appendChild(textarea);
        textarea.focus();
        textarea.select();

        const commit = () => {
            if (!textarea.isConnected) return;
            pushHistory();
            if (targetKind === 'note') targetItem.text = textarea.value;
            else targetItem.label = textarea.value;
            textarea.remove();
            saveToLocalStorage();
            renderInspector();
            requestRender();
        };

        textarea.addEventListener('blur', commit);
        textarea.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' && !ev.shiftKey) {
                ev.preventDefault();
                commit();
            } else if (ev.key === 'Escape') {
                textarea.remove();
            }
        });
    };

    // =========================================================================
    // UI Shell, Shape Library & Inspector
    // =========================================================================
    const renderFontOptionsHtml = (selectedFont, includeDefault = true) => `
        ${includeDefault ? `<option value="default" ${(!selectedFont || selectedFont === 'default') ? 'selected' : ''}>Default (${esc(state.defaultFont || 'Plus Jakarta Sans')})</option>` : ''}
        ${FONT_OPTIONS.map((f) => `
            <option value="${esc(f.id)}" ${selectedFont === f.id ? 'selected' : ''} style="font-family:${esc(f.stack)};">${esc(f.label)}</option>
        `).join('')}
    `;

    const renderSwatches = (activeColor, attrName) => `
        <div class="dd-color-swatches">
            ${SWATCH_COLORS.map((c) => `
                <button type="button" class="dd-color-swatch ${String(activeColor).toLowerCase() === c.toLowerCase() ? 'active' : ''}"
                    style="background:${c};" data-fc-swatch="${c}" data-fc-target="${attrName}" title="${c}"></button>
            `).join('')}
        </div>
    `;

    const CAT_PILLS = [
        { id: 'all', label: 'All Shapes' },
        { id: 'flowchart', label: 'Flowchart' },
        { id: 'general', label: 'General' },
        { id: 'soc_playbook', label: 'SOC Playbook' },
    ];

    const renderStudioShell = () => {
        const pane = document.getElementById('flowchart-draw-pane');
        if (!pane) return;

        pane.innerHTML = `
            <header class="dd-topbar">
                <div class="dd-topbar-left">
                    <div class="dd-brand-icon" style="color:#ffcc00; border-color:rgba(255,204,0,0.4);"><i class="fa-solid fa-sitemap"></i></div>
                    <div class="dd-brand-title-wrap">
                        <input type="text" id="fc-diagram-title-input" class="dd-brand-title-input" value="${esc(state.title)}" title="Click to rename flowchart">
                    </div>
                </div>

                <div class="dd-topbar-center">
                    <div class="dd-dropdown" id="fc-templates-dropdown">
                        <button type="button" class="dd-btn dd-btn-surface" id="fc-btn-templates">
                            <i class="fa-solid fa-wand-magic-sparkles" style="color:var(--dd-accent);"></i>
                            <span>Flowchart Templates</span>
                            <i class="fa-solid fa-chevron-down" style="font-size:0.6rem; opacity:0.65;"></i>
                        </button>
                        <div class="dd-dropdown-menu dark-scroll">
                            <div class="dd-dropdown-sec">Cyber &amp; SOC Playbooks</div>
                            <button type="button" class="dd-dropdown-item" data-fc-template="soc_playbook">
                                <i class="fa-solid fa-sitemap" style="color:#ffcc00;"></i> SOC Alert Triage Swimlane Flow
                            </button>
                            <button type="button" class="dd-dropdown-item" data-fc-template="ir_lifecycle">
                                <i class="fa-solid fa-rotate" style="color:#10b981;"></i> NIST Incident Response Lifecycle
                            </button>
                            <button type="button" class="dd-dropdown-item" data-fc-template="vuln_mgmt">
                                <i class="fa-solid fa-shield-halved" style="color:#eab308;"></i> Vulnerability &amp; Patching Workflow
                            </button>
                            <div class="dd-dropdown-sec">Auto-Layout</div>
                            <button type="button" class="dd-dropdown-item" id="fc-menu-layout-tb">
                                <i class="fa-solid fa-arrow-down-short-wide" style="color:#ffcc00;"></i> Auto-Layout Top-to-Bottom (↓)
                            </button>
                            <button type="button" class="dd-dropdown-item" id="fc-menu-layout-lr">
                                <i class="fa-solid fa-arrow-right-arrow-left" style="color:#a855f7;"></i> Auto-Layout Left-to-Right (→)
                            </button>
                            <div class="dd-dropdown-sec">Canvas</div>
                            <button type="button" class="dd-dropdown-item" id="fc-btn-clear-all" style="color:#fca5a5;">
                                <i class="fa-solid fa-broom" style="color:#ef4444;"></i> New Blank Flowchart
                            </button>
                        </div>
                    </div>

                    <div class="dd-pill-group" role="group" aria-label="Font & History">
                        <select id="fc-global-font" class="dd-font-select-top" title="Default Flowchart Font">
                            ${renderFontOptionsHtml(state.defaultFont, false)}
                        </select>
                        <span class="dd-divider"></span>
                        <button type="button" class="dd-btn icon-only" id="fc-btn-undo" title="Undo (Ctrl+Z)" disabled>
                            <i class="fa-solid fa-rotate-left"></i>
                        </button>
                        <button type="button" class="dd-btn icon-only" id="fc-btn-redo" title="Redo (Ctrl+Y)" disabled>
                            <i class="fa-solid fa-rotate-right"></i>
                        </button>
                    </div>
                </div>

                <div class="dd-topbar-right">
                    <div class="dd-pill-group" role="group" aria-label="Download PNG">
                        <span class="dd-export-label"><i class="fa-solid fa-download"></i> PNG</span>
                        <button type="button" class="dd-export-btn" id="fc-dl-png-transparent" title="Download PNG (Transparent Background)">
                            <span class="dd-dot-swatch dd-dot-transparent"></span> Transparent
                        </button>
                        <button type="button" class="dd-export-btn" id="fc-dl-png-dark" title="Download PNG (Dark Background)">
                            <span class="dd-dot-swatch dd-dot-dark"></span> Dark
                        </button>
                        <button type="button" class="dd-export-btn" id="fc-dl-png-white" title="Download PNG (White Background)">
                            <span class="dd-dot-swatch dd-dot-white"></span> White
                        </button>
                    </div>

                    <div class="dd-dropdown" id="fc-svg-dropdown">
                        <button type="button" class="dd-btn dd-btn-surface" id="fc-btn-svg-menu">
                            <i class="fa-solid fa-file-shield" style="color:var(--dd-emerald);"></i>
                            <span>Project / SVG</span>
                            <i class="fa-solid fa-chevron-down" style="font-size:0.6rem; opacity:0.65;"></i>
                        </button>
                        <div class="dd-dropdown-menu">
                            <div class="dd-dropdown-sec">Editable Project Format (.mantis-flow)</div>
                            <button type="button" class="dd-dropdown-item" id="fc-menu-export-flow">
                                <i class="fa-solid fa-file-arrow-down" style="color:#10b981;"></i> Export .mantis-flow File (Ctrl+S)
                            </button>
                            <button type="button" class="dd-dropdown-item" id="fc-menu-import-file">
                                <i class="fa-solid fa-file-arrow-up" style="color:#ffcc00;"></i> Import .mantis-flow / .json File
                            </button>
                            <div class="dd-dropdown-sec">Vector SVG Download</div>
                            <button type="button" class="dd-dropdown-item" data-fc-svg="transparent">
                                <i class="fa-solid fa-chess-board" style="color:#ffcc00;"></i> SVG — Transparent BG
                            </button>
                            <button type="button" class="dd-dropdown-item" data-fc-svg="dark">
                                <i class="fa-solid fa-moon" style="color:#94a3b8;"></i> SVG — Dark BG
                            </button>
                            <button type="button" class="dd-dropdown-item" data-fc-svg="white">
                                <i class="fa-solid fa-sun" style="color:#ffcc00;"></i> SVG — White BG
                            </button>
                        </div>
                    </div>

                    <input type="file" id="fc-project-file-input" accept=".mantis-flow,.mantis-draw,.json,application/json" style="display:none;">
                    <input type="file" id="fc-img-file-input" accept="image/*" multiple style="display:none;">

                    <button type="button" class="dd-btn dd-btn-surface icon-only" id="fc-btn-toggle-inspector" title="Toggle Right Properties Bar" style="width:34px;">
                        <i class="fa-solid fa-table-columns"></i>
                    </button>
                </div>
            </header>

            <div class="dd-workspace ${state.paletteCollapsed ? 'palette-collapsed' : ''} ${state.inspectorCollapsed ? 'inspector-collapsed' : ''}" id="fc-workspace">
                <aside class="dd-palette" aria-label="Flowchart Shape Library">
                    <div class="dd-palette-header">
                        <div class="dd-palette-top-row">
                            <span>Draw.io Shapes</span>
                            <button type="button" class="dd-inspector-collapse-btn" id="fc-btn-collapse-palette" title="Collapse Shapes Sidebar">
                                <i class="fa-solid fa-angles-left"></i>
                            </button>
                        </div>
                        <div class="dd-palette-search">
                            <i class="fa-solid fa-magnifying-glass"></i>
                            <input type="text" id="fc-asset-search" placeholder="Search flowchart shapes...">
                        </div>
                        <div class="dd-cat-pills" id="fc-cat-pills">
                            ${CAT_PILLS.map((p) => `
                                <button type="button" class="dd-cat-pill ${state.activeCatFilter === p.id ? 'active' : ''}" data-fc-cat-pill="${p.id}">${esc(p.label)}</button>
                            `).join('')}
                        </div>
                    </div>
                    <div class="dd-palette-body dark-scroll" id="fc-palette-list"></div>
                </aside>

                <section class="dd-canvas-wrap theme-${state.canvasTheme}" id="fc-canvas-wrap">
                    <div class="dd-floating-dock-wrap">
                        <div style="display:flex; justify-content:flex-start; min-width:110px;">
                            <button type="button" class="dd-expand-palette-pill" id="fc-btn-expand-palette" title="Expand Shapes Sidebar">
                                <span>Shapes</span>
                                <i class="fa-solid fa-angles-right" style="color:var(--dd-accent);"></i>
                            </button>
                        </div>

                        <div class="dd-floating-dock" role="toolbar" aria-label="Flowchart tools">
                            <button type="button" class="dd-dock-btn active" data-fc-mode="select" title="Select & Move (V)">
                                <i class="fa-solid fa-arrow-pointer"></i> <span>Select</span> <kbd>V</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-fc-mode="connect" title="Connect Shapes (C)">
                                <i class="fa-solid fa-share-nodes"></i> <span>Connect</span> <kbd>C</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-fc-mode="zone" title="Draw Swimlane / Pool (Z)">
                                <i class="fa-solid fa-table-columns"></i> <span>Swimlane</span> <kbd>Z</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-fc-mode="text" title="Add Note (T)">
                                <i class="fa-solid fa-font"></i> <span>Note</span> <kbd>T</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" id="fc-btn-insert-img" title="Insert Image (I)">
                                <i class="fa-regular fa-image" style="color:var(--dd-cyan);"></i> <span>Image</span> <kbd>I</kbd>
                            </button>
                            <button type="button" class="dd-dock-btn" data-fc-mode="pan" title="Pan Canvas (H or Space+Drag)">
                                <i class="fa-solid fa-hand"></i> <span>Pan</span> <kbd>H</kbd>
                            </button>
                            <span class="dd-divider"></span>
                            <button type="button" class="dd-dock-btn icon-only" id="fc-btn-layout-tb" title="Auto-Layout Top-to-Bottom">
                                <i class="fa-solid fa-arrow-down-short-wide" style="color:#ffcc00;"></i>
                            </button>
                            <button type="button" class="dd-dock-btn icon-only" id="fc-btn-layout-lr" title="Auto-Layout Left-to-Right">
                                <i class="fa-solid fa-arrow-right-arrow-left" style="color:#a855f7;"></i>
                            </button>
                            <button type="button" class="dd-dock-btn icon-only dd-dock-btn-danger" id="fc-btn-delete" title="Delete Selected (Del)">
                                <i class="fa-regular fa-trash-can"></i>
                            </button>
                        </div>

                        <div style="display:flex; justify-content:flex-end; min-width:110px;">
                            <button type="button" class="dd-expand-inspector-pill" id="fc-btn-expand-inspector" title="Expand Properties Bar">
                                <i class="fa-solid fa-angles-left" style="color:var(--dd-accent);"></i>
                                <span>Properties</span>
                            </button>
                        </div>
                    </div>

                    <canvas id="fc-canvas" class="dd-canvas"></canvas>

                    <div class="dd-canvas-hud-bottom">
                        <div class="dd-canvas-hud-pill">
                            <span>Canvas:</span>
                            <div class="dd-bg-switcher">
                                <button type="button" class="dd-bg-chip ${state.canvasTheme === 'dark' ? 'active' : ''}" data-fc-bg="dark">Dark</button>
                                <button type="button" class="dd-bg-chip ${state.canvasTheme === 'white' ? 'active' : ''}" data-fc-bg="white">White</button>
                                <button type="button" class="dd-bg-chip ${state.canvasTheme === 'transparent' ? 'active' : ''}" data-fc-bg="transparent">Transparent</button>
                            </div>
                            <span style="opacity:0.25;">|</span>
                            <label style="display:inline-flex; align-items:center; gap:5px; cursor:pointer;">
                                <input type="checkbox" id="fc-chk-snap" ${state.snapToGrid ? 'checked' : ''}> Snap
                            </label>
                            <label style="display:inline-flex; align-items:center; gap:5px; cursor:pointer;">
                                <input type="checkbox" id="fc-chk-anim" ${state.animateFlows ? 'checked' : ''}> Animate
                            </label>
                        </div>

                        <div class="dd-zoom-controls">
                            <button type="button" class="dd-zoom-btn" id="fc-zoom-out" title="Zoom Out"><i class="fa-solid fa-minus"></i></button>
                            <span class="dd-zoom-readout" id="fc-zoom-readout">100%</span>
                            <button type="button" class="dd-zoom-btn" id="fc-zoom-in" title="Zoom In"><i class="fa-solid fa-plus"></i></button>
                            <button type="button" class="dd-zoom-btn" id="fc-zoom-fit" title="Fit to Screen"><i class="fa-solid fa-expand"></i></button>
                        </div>
                    </div>
                </section>

                <aside class="dd-inspector" aria-label="Properties Inspector">
                    <div class="dd-inspector-header">
                        <span style="display:inline-flex; align-items:center; gap:7px;">
                            <span>Properties</span>
                            <span id="fc-inspector-type-badge" class="dd-inspector-badge">Flowchart</span>
                        </span>
                        <button type="button" class="dd-inspector-collapse-btn" id="fc-btn-collapse-inspector" title="Collapse Properties Bar">
                            <i class="fa-solid fa-angles-right"></i>
                        </button>
                    </div>
                    <div class="dd-inspector-body dark-scroll" id="fc-inspector-body"></div>
                </aside>
            </div>

            <div id="fc-toast" class="dd-toast"></div>
        `;

        renderPaletteList();
        renderInspector();
        bindStudioEvents();
        updateToolbarButtons();
    };

    const renderPaletteList = () => {
        const container = document.getElementById('fc-palette-list');
        if (!container) return;
        const q = (state.searchQuery || '').trim().toLowerCase();
        const catFilter = state.activeCatFilter || 'all';

        const html = SHAPE_CATEGORIES.map((cat) => {
            if (catFilter !== 'all' && cat.id !== catFilter) return '';
            const items = cat.items.filter((it) => !q
                || it.name.toLowerCase().includes(q)
                || it.shape.toLowerCase().includes(q)
                || (it.sub && it.sub.toLowerCase().includes(q)));
            if (!items.length) return '';
            const isCollapsed = !q && catFilter === 'all' && state.collapsedCats.has(cat.id);
            return `
                <div class="dd-cat-group ${isCollapsed ? 'collapsed' : ''}" data-cat-id="${esc(cat.id)}">
                    <button type="button" class="dd-cat-header" data-fc-cat-toggle="${esc(cat.id)}">
                        <span class="dd-cat-header-left">
                            <span class="dd-cat-dot" style="background:${esc(cat.color)};"></span>
                            <span>${esc(cat.name)}</span>
                        </span>
                        <span class="dd-cat-count">${items.length}</span>
                        <i class="fa-solid fa-chevron-down dd-cat-caret" style="font-size:0.64rem; color:#64748b;"></i>
                    </button>
                    <div class="dd-flow-grid">
                        ${items.map((it) => `
                            <button type="button" class="dd-flow-tile" draggable="true" data-fc-asset-type="${esc(it.type)}" title="Click or drag ${esc(it.name)}">
                                <span class="dd-flow-tile-icon" style="background:${hexToRgba(it.color, 0.14)};">
                                    ${getDrawioTileSvg(it.shape, it.color)}
                                </span>
                                <span class="dd-flow-tile-label">${esc(it.name)}</span>
                            </button>
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = html || '<div style="padding:20px; text-align:center; color:#64748b; font-size:0.76rem;">No matching shapes found.</div>';
    };

    const renderInspector = () => {
        const body = document.getElementById('fc-inspector-body');
        const badge = document.getElementById('fc-inspector-type-badge');
        if (!body) return;

        const firstId = [...state.selectedIds][0];

        if (state.selectedType === 'node' && firstId) {
            const n = state.nodes.find((it) => it.id === firstId);
            if (n) {
                if (badge) badge.textContent = 'Shape';
                body.innerHTML = `
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Shape Text (or Double-Click Shape)</div>
                        <div class="dd-field">
                            <label>Main Label</label>
                            <input type="text" id="fc-insp-node-label" value="${esc(n.label)}">
                        </div>
                        <div class="dd-field">
                            <label>Subtitle / Condition</label>
                            <input type="text" id="fc-insp-node-sub" value="${esc(n.sub || '')}" placeholder="Optional subtitle...">
                        </div>
                        <div class="dd-insp-row">
                            <label>Step Badge</label>
                            <div class="dd-insp-row-control">
                                <input type="text" id="fc-insp-node-step" value="${esc(n.step || '')}" placeholder="e.g. Step 1">
                            </div>
                        </div>
                    </div>

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Geometry &amp; Font</div>
                        <div class="dd-insp-row">
                            <label>Shape</label>
                            <div class="dd-insp-row-control">
                                <select id="fc-insp-node-type">
                                    ${SHAPE_CATEGORIES.map((cat) => `
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
                            <label>Font</label>
                            <div class="dd-insp-row-control">
                                <select id="fc-insp-node-font">
                                    ${renderFontOptionsHtml(n.fontFamily || 'default', true)}
                                </select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Font Size</label>
                            <div class="dd-insp-row-control">
                                <input type="number" id="fc-insp-node-fsize" min="8" max="42" value="${Number(n.fontSize) || 12.5}" style="width:70px;">
                            </div>
                        </div>
                    </div>

                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Shape Color</div>
                        ${renderSwatches(n.color || '#38bdf8', 'node-color')}
                    </div>

                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="fc-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22);">
                        <i class="fa-regular fa-trash-can"></i> Delete Shape
                    </button>
                `;
                bindInspectorInputs();
                return;
            }
        }

        if (state.selectedType === 'edge' && firstId) {
            const e = state.edges.find((it) => it.id === firstId);
            if (e) {
                if (badge) badge.textContent = 'Connector';
                body.innerHTML = `
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Connector Label</div>
                        <div class="dd-field">
                            <input type="text" id="fc-insp-edge-label" value="${esc(e.label || '')}" placeholder="e.g. Yes / No / True Positive">
                        </div>
                    </div>
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Routing &amp; Style</div>
                        <div class="dd-insp-row">
                            <label>From Side</label>
                            <div class="dd-insp-row-control">
                                <select id="fc-insp-edge-fromport">${portSelectOptions(e.fromPort)}</select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>To Side</label>
                            <div class="dd-insp-row-control">
                                <select id="fc-insp-edge-toport">${portSelectOptions(e.toPort)}</select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Routing</label>
                            <div class="dd-insp-row-control">
                                <select id="fc-insp-edge-curve">
                                    <option value="step" ${(e.curve || 'step') === 'step' ? 'selected' : ''}>Orthogonal (90° Elbow)</option>
                                    <option value="bezier" ${e.curve === 'bezier' ? 'selected' : ''}>Curved Bezier</option>
                                    <option value="straight" ${e.curve === 'straight' ? 'selected' : ''}>Straight Line</option>
                                </select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Pattern</label>
                            <div class="dd-insp-row-control">
                                <select id="fc-insp-edge-style">
                                    <option value="solid" ${e.style === 'solid' ? 'selected' : ''}>Solid</option>
                                    <option value="dashed" ${e.style === 'dashed' ? 'selected' : ''}>Dashed</option>
                                    <option value="dotted" ${e.style === 'dotted' ? 'selected' : ''}>Dotted</option>
                                    <option value="animated" ${e.style === 'animated' ? 'selected' : ''}>Animated Flow</option>
                                </select>
                            </div>
                        </div>
                        <div class="dd-insp-row">
                            <label>Arrows</label>
                            <div class="dd-insp-row-control">
                                <select id="fc-insp-edge-dir">
                                    <option value="forward" ${(e.dir || 'forward') === 'forward' ? 'selected' : ''}>Forward (→)</option>
                                    <option value="both" ${e.dir === 'both' ? 'selected' : ''}>Bidirectional (↔)</option>
                                    <option value="none" ${e.dir === 'none' ? 'selected' : ''}>None (—)</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Color</div>
                        ${renderSwatches(e.color || '#38bdf8', 'edge-color')}
                    </div>
                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="fc-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22);">
                        <i class="fa-regular fa-trash-can"></i> Delete Connector
                    </button>
                `;
                bindInspectorInputs();
                return;
            }
        }

        if (state.selectedType === 'zone' && firstId) {
            const z = state.zones.find((it) => it.id === firstId);
            if (z) {
                if (badge) badge.textContent = 'Swimlane';
                body.innerHTML = `
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Swimlane Header</div>
                        <div class="dd-field">
                            <label>Swimlane Title</label>
                            <input type="text" id="fc-insp-zone-label" value="${esc(z.label || '')}">
                        </div>
                        <div class="dd-field">
                            <label>Subtitle / Role</label>
                            <input type="text" id="fc-insp-zone-sub" value="${esc(z.sub || '')}">
                        </div>
                    </div>
                    <div class="dd-insp-section">
                        <div class="dd-insp-sec-title">Swimlane Color</div>
                        ${renderSwatches(z.color || '#38bdf8', 'zone-color')}
                    </div>
                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="fc-insp-delete-btn" style="color:#fca5a5; border-color:rgba(239,68,68,0.22);">
                        <i class="fa-regular fa-trash-can"></i> Delete Swimlane
                    </button>
                `;
                bindInspectorInputs();
                return;
            }
        }

        if (badge) badge.textContent = 'Canvas';
        body.innerHTML = `
            <div class="dd-summary-pill">
                <span><strong>${state.nodes.length}</strong> Shapes</span>
                <span>·</span>
                <span><strong>${state.edges.length}</strong> Links</span>
                <span>·</span>
                <span><strong>${state.zones.length}</strong> Lanes</span>
            </div>

            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">Auto-Arrange Flowchart</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                    <button type="button" class="dd-image-upload-btn" id="fc-insp-layout-tb">
                        <i class="fa-solid fa-arrow-down-short-wide" style="color:#ffcc00;"></i> Top-to-Bottom
                    </button>
                    <button type="button" class="dd-image-upload-btn" id="fc-insp-layout-lr">
                        <i class="fa-solid fa-arrow-right-arrow-left" style="color:#a855f7;"></i> Left-to-Right
                    </button>
                </div>
            </div>

            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">Project File (.mantis-flow)</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                    <button type="button" class="dd-image-upload-btn" id="fc-insp-save-btn">
                        <i class="fa-solid fa-download" style="color:#10b981;"></i> Save Flow
                    </button>
                    <button type="button" class="dd-image-upload-btn" id="fc-insp-open-btn">
                        <i class="fa-solid fa-upload" style="color:#ffcc00;"></i> Open Flow
                    </button>
                </div>
            </div>

            <div class="dd-insp-section" style="font-size:0.72rem; color:#8b9bb4; line-height:1.5;">
                <div class="dd-insp-sec-title">Draw.io Tips</div>
                <div>• Select any shape and click its <strong>▲ ▶ ▼ ◀</strong> arrows to quick-add the next connected step.</div>
                <div>• <strong>Double-click</strong> any shape to edit text directly on the canvas.</div>
            </div>
        `;
        bindInspectorInputs();
    };

    const bindInspectorInputs = () => {
        const firstId = [...state.selectedIds][0];

        document.getElementById('fc-insp-layout-tb')?.addEventListener('click', () => autoLayoutFlowchart('TB'));
        document.getElementById('fc-insp-layout-lr')?.addEventListener('click', () => autoLayoutFlowchart('LR'));
        document.getElementById('fc-insp-save-btn')?.addEventListener('click', () => exportProjectFile('mantis-flow'));
        document.getElementById('fc-insp-open-btn')?.addEventListener('click', () => document.getElementById('fc-project-file-input')?.click());

        if (state.selectedType === 'node' && firstId) {
            const n = state.nodes.find((it) => it.id === firstId);
            if (!n) return;
            document.getElementById('fc-insp-node-label')?.addEventListener('input', (ev) => {
                n.label = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-node-sub')?.addEventListener('input', (ev) => {
                n.sub = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-node-step')?.addEventListener('input', (ev) => {
                n.step = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-node-type')?.addEventListener('change', (ev) => {
                pushHistory();
                const newAsset = ALL_SHAPES_MAP.get(ev.target.value);
                n.type = ev.target.value;
                if (newAsset) n.shape = newAsset.shape;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-node-font')?.addEventListener('change', (ev) => {
                pushHistory();
                n.fontFamily = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-node-fsize')?.addEventListener('input', (ev) => {
                n.fontSize = Number(ev.target.value) || 12.5;
                saveToLocalStorage();
                requestRender();
            });
        }

        if (state.selectedType === 'edge' && firstId) {
            const e = state.edges.find((it) => it.id === firstId);
            if (!e) return;
            document.getElementById('fc-insp-edge-label')?.addEventListener('input', (ev) => {
                e.label = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-edge-fromport')?.addEventListener('change', (ev) => {
                pushHistory();
                e.fromPort = ev.target.value === 'auto' ? null : ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-edge-toport')?.addEventListener('change', (ev) => {
                pushHistory();
                e.toPort = ev.target.value === 'auto' ? null : ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-edge-curve')?.addEventListener('change', (ev) => {
                pushHistory();
                e.curve = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-edge-style')?.addEventListener('change', (ev) => {
                pushHistory();
                e.style = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-edge-dir')?.addEventListener('change', (ev) => {
                pushHistory();
                e.dir = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
        }

        if (state.selectedType === 'zone' && firstId) {
            const z = state.zones.find((it) => it.id === firstId);
            if (!z) return;
            document.getElementById('fc-insp-zone-label')?.addEventListener('input', (ev) => {
                z.label = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
            document.getElementById('fc-insp-zone-sub')?.addEventListener('input', (ev) => {
                z.sub = ev.target.value;
                saveToLocalStorage();
                requestRender();
            });
        }

        document.querySelectorAll('[data-fc-swatch]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const color = btn.dataset.fcSwatch;
                pushHistory();
                if (state.selectedType === 'node') state.nodes.forEach((n) => { if (state.selectedIds.has(n.id)) n.color = color; });
                else if (state.selectedType === 'edge') state.edges.forEach((e) => { if (state.selectedIds.has(e.id)) e.color = color; });
                else if (state.selectedType === 'zone') state.zones.forEach((z) => { if (state.selectedIds.has(z.id)) z.color = color; });
                saveToLocalStorage();
                renderInspector();
                requestRender();
            });
        });

        document.getElementById('fc-insp-delete-btn')?.addEventListener('click', deleteSelected);
    };

    const setMode = (mode) => {
        state.mode = mode;
        const canvas = document.getElementById('fc-canvas');
        if (canvas) canvas.className = `dd-canvas mode-${mode}`;
        document.querySelectorAll('[data-fc-mode]').forEach((btn) => {
            btn.classList.toggle('active', btn.dataset.fcMode === mode);
        });
    };

    const updateToolbarButtons = () => {
        const undoBtn = document.getElementById('fc-btn-undo');
        const redoBtn = document.getElementById('fc-btn-redo');
        if (undoBtn) undoBtn.disabled = state.undoStack.length === 0;
        if (redoBtn) redoBtn.disabled = state.redoStack.length === 0;
    };

    const addNodeAt = (assetType, wx, wy) => {
        const asset = ALL_SHAPES_MAP.get(assetType);
        if (!asset) return;
        pushHistory();
        const newNode = {
            id: uid('n'),
            type: asset.type,
            shape: asset.shape,
            label: asset.name,
            sub: asset.sub || '',
            x: snap(wx),
            y: snap(wy),
            color: asset.color,
            step: '',
            fontFamily: 'default',
            fontSize: 12.5,
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

    // =========================================================================
    // Event Listeners
    // =========================================================================
    const bindStudioEvents = () => {
        const pane = document.getElementById('flowchart-draw-pane');
        const canvas = document.getElementById('fc-canvas');
        const wrap = document.getElementById('fc-canvas-wrap');
        if (!pane || !canvas || !wrap) return;

        document.getElementById('fc-diagram-title-input')?.addEventListener('input', (ev) => {
            state.title = ev.target.value;
            saveToLocalStorage();
        });

        pane.querySelectorAll('[data-fc-mode]').forEach((btn) => {
            btn.addEventListener('click', () => setMode(btn.dataset.fcMode));
        });

        document.getElementById('fc-global-font')?.addEventListener('change', (ev) => {
            pushHistory();
            state.defaultFont = ev.target.value;
            saveToLocalStorage();
            requestRender();
        });

        document.getElementById('fc-btn-undo')?.addEventListener('click', undo);
        document.getElementById('fc-btn-redo')?.addEventListener('click', redo);
        document.getElementById('fc-btn-delete')?.addEventListener('click', deleteSelected);
        document.getElementById('fc-btn-layout-tb')?.addEventListener('click', () => autoLayoutFlowchart('TB'));
        document.getElementById('fc-btn-layout-lr')?.addEventListener('click', () => autoLayoutFlowchart('LR'));
        document.getElementById('fc-menu-layout-tb')?.addEventListener('click', () => autoLayoutFlowchart('TB'));
        document.getElementById('fc-menu-layout-lr')?.addEventListener('click', () => autoLayoutFlowchart('LR'));

        // Collapse / Expand Left & Right Bars
        const setPaletteCollapsed = (c) => {
            state.paletteCollapsed = !!c;
            document.getElementById('fc-workspace')?.classList.toggle('palette-collapsed', state.paletteCollapsed);
            setTimeout(requestRender, 30);
        };
        const setInspectorCollapsed = (c) => {
            state.inspectorCollapsed = !!c;
            document.getElementById('fc-workspace')?.classList.toggle('inspector-collapsed', state.inspectorCollapsed);
            setTimeout(requestRender, 30);
        };
        document.getElementById('fc-btn-collapse-palette')?.addEventListener('click', () => setPaletteCollapsed(true));
        document.getElementById('fc-btn-expand-palette')?.addEventListener('click', () => setPaletteCollapsed(false));
        document.getElementById('fc-btn-collapse-inspector')?.addEventListener('click', () => setInspectorCollapsed(true));
        document.getElementById('fc-btn-expand-inspector')?.addEventListener('click', () => setInspectorCollapsed(false));
        document.getElementById('fc-btn-toggle-inspector')?.addEventListener('click', () => setInspectorCollapsed(!state.inspectorCollapsed));

        // PNG & SVG Exports
        document.getElementById('fc-dl-png-transparent')?.addEventListener('click', () => exportPNG('transparent'));
        document.getElementById('fc-dl-png-dark')?.addEventListener('click', () => exportPNG('dark'));
        document.getElementById('fc-dl-png-white')?.addEventListener('click', () => exportPNG('white'));

        const closeDropdowns = () => pane.querySelectorAll('.dd-dropdown.open').forEach((d) => d.classList.remove('open'));
        document.getElementById('fc-btn-templates')?.addEventListener('click', (e) => {
            e.stopPropagation();
            const dd = document.getElementById('fc-templates-dropdown');
            const was = dd?.classList.contains('open');
            closeDropdowns();
            if (!was) dd?.classList.add('open');
        });
        document.getElementById('fc-btn-svg-menu')?.addEventListener('click', (e) => {
            e.stopPropagation();
            const dd = document.getElementById('fc-svg-dropdown');
            const was = dd?.classList.contains('open');
            closeDropdowns();
            if (!was) dd?.classList.add('open');
        });

        pane.querySelectorAll('[data-fc-svg]').forEach((btn) => {
            btn.addEventListener('click', () => {
                exportSVG(btn.dataset.fcSvg);
                closeDropdowns();
            });
        });

        const projInput = document.getElementById('fc-project-file-input');
        document.getElementById('fc-menu-export-flow')?.addEventListener('click', () => {
            exportProjectFile('mantis-flow');
            closeDropdowns();
        });
        document.getElementById('fc-menu-import-file')?.addEventListener('click', () => {
            projInput?.click();
            closeDropdowns();
        });
        projInput?.addEventListener('change', (ev) => {
            const file = ev.target.files?.[0];
            if (file) importProjectFile(file);
            ev.target.value = '';
        });

        const imgInput = document.getElementById('fc-img-file-input');
        document.getElementById('fc-btn-insert-img')?.addEventListener('click', () => imgInput?.click());
        imgInput?.addEventListener('change', (ev) => {
            const files = Array.from(ev.target.files || []);
            files.forEach((f) => {
                const reader = new FileReader();
                reader.onload = () => {
                    pushHistory();
                    const src = String(reader.result || '');
                    getOrLoadImage(src);
                    const n = {
                        id: uid('img'),
                        type: 'image',
                        shape: 'image',
                        label: f.name.replace(/\.[^.]+$/, ''),
                        imageSrc: src,
                        showFrame: true,
                        showCaption: true,
                        x: snap(state.lastMouseWorld.x),
                        y: snap(state.lastMouseWorld.y),
                        w: 200,
                        h: 140,
                        color: '#38bdf8',
                    };
                    state.nodes.push(n);
                    state.selectedType = 'node';
                    state.selectedIds = new Set([n.id]);
                    saveToLocalStorage();
                    renderInspector();
                    requestRender();
                };
                reader.readAsDataURL(f);
            });
            ev.target.value = '';
        });

        pane.querySelectorAll('[data-fc-template]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const key = btn.dataset.fcTemplate;
                if (TEMPLATES[key]) {
                    pushHistory();
                    applySnapshot(TEMPLATES[key]());
                    setTimeout(fitToScreen, 30);
                    showToast(`Loaded flowchart: ${state.title}`);
                }
                closeDropdowns();
            });
        });

        document.getElementById('fc-btn-clear-all')?.addEventListener('click', () => {
            pushHistory();
            applySnapshot({ title: 'Untitled Flowchart', defaultFont: state.defaultFont, zones: [], nodes: [], edges: [], notes: [] });
            closeDropdowns();
        });

        pane.querySelectorAll('[data-fc-bg]').forEach((btn) => {
            btn.addEventListener('click', () => {
                state.canvasTheme = btn.dataset.fcBg;
                wrap.className = `dd-canvas-wrap theme-${state.canvasTheme}`;
                pane.querySelectorAll('[data-fc-bg]').forEach((b) => b.classList.toggle('active', b === btn));
                requestRender();
            });
        });

        document.getElementById('fc-chk-snap')?.addEventListener('change', (e) => { state.snapToGrid = e.target.checked; });
        document.getElementById('fc-chk-anim')?.addEventListener('change', (e) => { state.animateFlows = e.target.checked; requestRender(); });
        document.getElementById('fc-zoom-in')?.addEventListener('click', () => { state.zoom = Math.min(2.5, state.zoom * 1.15); requestRender(); });
        document.getElementById('fc-zoom-out')?.addEventListener('click', () => { state.zoom = Math.max(0.28, state.zoom / 1.15); requestRender(); });
        document.getElementById('fc-zoom-fit')?.addEventListener('click', fitToScreen);

        document.getElementById('fc-asset-search')?.addEventListener('input', (ev) => {
            state.searchQuery = ev.target.value;
            renderPaletteList();
        });
        document.getElementById('fc-cat-pills')?.addEventListener('click', (ev) => {
            const pill = ev.target.closest('[data-fc-cat-pill]');
            if (!pill) return;
            state.activeCatFilter = pill.dataset.fcCatPill;
            pane.querySelectorAll('[data-fc-cat-pill]').forEach((b) => b.classList.toggle('active', b === pill));
            renderPaletteList();
        });

        const paletteList = document.getElementById('fc-palette-list');
        paletteList?.addEventListener('click', (ev) => {
            const catBtn = ev.target.closest('[data-fc-cat-toggle]');
            if (catBtn) {
                const cid = catBtn.dataset.fcCatToggle;
                if (state.collapsedCats.has(cid)) state.collapsedCats.delete(cid);
                else state.collapsedCats.add(cid);
                renderPaletteList();
                return;
            }
            const assetBtn = ev.target.closest('[data-fc-asset-type]');
            if (assetBtn) {
                const rect = canvas.getBoundingClientRect();
                const center = screenToWorld(rect.width / 2 + (Math.random() - 0.5) * 80, rect.height / 2 + (Math.random() - 0.5) * 80);
                addNodeAt(assetBtn.dataset.fcAssetType, center.x, center.y);
            }
        });
        paletteList?.addEventListener('dragstart', (ev) => {
            const assetBtn = ev.target.closest('[data-fc-asset-type]');
            if (assetBtn && ev.dataTransfer) {
                ev.dataTransfer.setData('text/plain', assetBtn.dataset.fcAssetType);
            }
        });

        canvas.addEventListener('dragover', (ev) => { ev.preventDefault(); wrap.classList.add('drag-over'); });
        canvas.addEventListener('dragleave', () => wrap.classList.remove('drag-over'));
        canvas.addEventListener('drop', (ev) => {
            ev.preventDefault();
            wrap.classList.remove('drag-over');
            const rect = canvas.getBoundingClientRect();
            const pt = screenToWorld(ev.clientX - rect.left, ev.clientY - rect.top);
            const assetType = ev.dataTransfer?.getData('text/plain');
            if (assetType && ALL_SHAPES_MAP.has(assetType)) {
                addNodeAt(assetType, pt.x, pt.y);
            }
        });

        // Canvas Mouse Interactions (including Draw.io Quick-Add Directional Arrows!)
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

            // Check Draw.io Quick-Add Arrow click first!
            const qaHit = hitTestQuickAddArrow(wpt.x, wpt.y);
            if (qaHit) {
                pushHistory();
                const srcNode = qaHit.node;
                const newNode = {
                    ...JSON.parse(JSON.stringify(srcNode)),
                    id: uid('n'),
                    x: snap(srcNode.x + qaHit.arrow.dx),
                    y: snap(srcNode.y + qaHit.arrow.dy),
                };
                state.nodes.push(newNode);
                state.edges.push({
                    id: uid('e'),
                    from: srcNode.id,
                    to: newNode.id,
                    label: '',
                    color: srcNode.color || '#38bdf8',
                    style: 'solid',
                    curve: 'step',
                    dir: 'forward',
                    width: 2,
                });
                state.selectedType = 'node';
                state.selectedIds = new Set([newNode.id]);
                saveToLocalStorage();
                renderInspector();
                requestRender();
                return;
            }

            if (state.mode === 'text') {
                pushHistory();
                const newNote = { id: uid('t'), text: 'Flowchart Note', x: snap(wpt.x), y: snap(wpt.y), color: '#ffcc00' };
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
                state.draggingItems = state.nodes.filter((n) => state.selectedIds.has(n.id)).map((n) => ({ item: n, ox: n.x, oy: n.y }));
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
            const p = document.getElementById('flowchart-draw-pane');
            if (!p || p.style.display === 'none') return;
            const rect = canvas.getBoundingClientRect();
            const wpt = screenToWorld(ev.clientX - rect.left, ev.clientY - rect.top);

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
                saveToLocalStorage();
                requestRender();
                return;
            }
            if (state.resizingZone) {
                const rz = state.resizingZone;
                rz.zone.w = Math.max(160, snap(rz.startW + (wpt.x - rz.sx)));
                rz.zone.h = Math.max(120, snap(rz.startH + (wpt.y - rz.sy)));
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
            }
        });

        window.addEventListener('mouseup', (ev) => {
            const p = document.getElementById('flowchart-draw-pane');
            if (!p || p.style.display === 'none') return;

            if (state.isPanning) {
                state.isPanning = false;
                state.dragStartScreen = null;
                return;
            }
            if (state.drawingZone) {
                const dz = state.drawingZone;
                state.drawingZone = null;
                const newZone = {
                    id: uid('z'),
                    label: 'NEW SWIMLANE',
                    sub: 'Team / System Role',
                    x: Math.min(dz.x1, dz.x2),
                    y: Math.min(dz.y1, dz.y2),
                    w: Math.max(240, Math.abs(dz.x2 - dz.x1)),
                    h: Math.max(180, Math.abs(dz.y2 - dz.y1)),
                    color: '#38bdf8',
                    style: 'solid',
                    opacity: 0.05,
                };
                pushHistory();
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
                        label: '',
                        color: '#38bdf8',
                        style: 'solid',
                        curve: 'step',
                        dir: 'forward',
                        width: 2,
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

        // Double-Click on Shape opens Draw.io Inline Floating Text Editor!
        canvas.addEventListener('dblclick', (ev) => {
            const rect = canvas.getBoundingClientRect();
            const wpt = screenToWorld(ev.clientX - rect.left, ev.clientY - rect.top);
            const nodeHit = hitTestNode(wpt.x, wpt.y);
            if (nodeHit) {
                openInlineEditor(nodeHit, 'node');
                return;
            }
            const noteHit = hitTestNote(wpt.x, wpt.y);
            if (noteHit) {
                openInlineEditor(noteHit, 'note');
                return;
            }
            const edgeHit = hitTestEdge(wpt.x, wpt.y);
            if (edgeHit) {
                const pts = getEdgeEndpoints(edgeHit);
                if (pts) {
                    const dMid = geomMid(getEdgeGeometry(edgeHit, pts, edgeHit.curve || 'step'));
                    openInlineEditor(
                        Object.assign(edgeHit, { x: dMid.x, y: dMid.y }),
                        'edge'
                    );
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
            state.zoom = Math.max(0.25, Math.min(2.6, state.zoom * factor));
            state.panX = mx - before.x * state.zoom;
            state.panY = my - before.y * state.zoom;
            requestRender();
        }, { passive: false });

        if (typeof ResizeObserver !== 'undefined') {
            const ro = new ResizeObserver(() => {
                const p = document.getElementById('flowchart-draw-pane');
                if (p && p.style.display !== 'none') requestRender();
            });
            ro.observe(wrap);
        }
    };

    window.openFlowchartDraw = () => {
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
                applySnapshot(TEMPLATES.soc_playbook());
            }
            renderStudioShell();
            startAnimationLoop();
            setTimeout(fitToScreen, 60);
        } else {
            setTimeout(requestRender, 20);
        }
    };
})();
