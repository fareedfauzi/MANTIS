/**
 * MANTIS Map Chart Studio — Clean Professional Geo-Mapper & Legend Editor
 * Inspired by MapChart and Chloromaps
 *
 * Streamlined Features:
 * - High-Precision Geographic World Map (256 official ISO countries & territories)
 * - MapChart Click-to-Color Painter with Interactive Legend Colors as Brushes
 * - Fully Editable Legend (custom title, editable color swatches, editable text labels, add/remove items)
 * - High-Contrast Map Labels: Targeted Only (ultra-legible badges) | All Names | All ISO | Off
 * - Custom Country Map Labels (type any label to display on country)
 * - Clean Inspector (Selected Country info, Color picker, Custom Label, Metric Value, Notes)
 * - Regional Projections: Global World, North America, Latin America, Europe, Asia-Pacific, Middle East & Africa
 * - Slide-In Map Presets Drawer
 * - High-DPI 2X Export: PNG (Transparent, Dark, White), Vector SVG, CSV Data, & .mantis-map Project Files
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'mantis_map_chart_v3';
    const SVG_NS = 'http://www.w3.org/2000/svg';

    // Regional Viewport Bounds on 1010 x 666 Equirectangular Geographic Grid
    const REGION_BOUNDS = {
        'world': { x: 20, y: 35, w: 970, h: 610, title: 'Global World Map' },
        'NA': { x: 30, y: 130, w: 320, h: 300, title: 'North America' },
        'SA': { x: 190, y: 390, w: 220, h: 270, title: 'Latin & South America' },
        'EU': { x: 420, y: 210, w: 210, h: 180, title: 'Europe' },
        'APAC': { x: 650, y: 250, w: 340, h: 400, title: 'Asia-Pacific' },
        'MEA': { x: 450, y: 300, w: 260, h: 330, title: 'Middle East & Africa' },
    };

    // Curated Theme Palettes that seed default legend colors
    const THEME_PALETTES = {
        'crimson-threat': {
            label: 'Crimson Threat (SEV-1)',
            bgDark: '#080c14',
            landDefault: '#151d2d',
            landStroke: '#253554',
            legendTitle: 'Threat Severity',
            legendItems: [
                { id: 'l1', color: '#ef4444', label: 'Critical Threat (SEV-1)' },
                { id: 'l2', color: '#f97316', label: 'High Priority (SEV-2)' },
                { id: 'l3', color: '#eab308', label: 'Medium Impact' },
                { id: 'l4', color: '#38bdf8', label: 'Low / Monitoring' }
            ]
        },
        'matrix-cyan': {
            label: 'Volt Matrix (Teal/Cyan)',
            bgDark: '#040d12',
            landDefault: '#0d2229',
            landStroke: '#163f4c',
            legendTitle: 'Sovereignty Impact',
            legendItems: [
                { id: 'l1', color: '#06b6d4', label: 'Critical Infrastructure Hit' },
                { id: 'l2', color: '#0284c7', label: 'Telecom / Gov Compromise' },
                { id: 'l3', color: '#0d9488', label: 'Telemetry Recon' },
                { id: 'l4', color: '#10b981', label: 'Hardened / Secure' }
            ]
        },
        'cyber-gold': {
            label: 'Executive Gold (Finance)',
            bgDark: '#0c0e12',
            landDefault: '#1f242d',
            landStroke: '#333b49',
            legendTitle: 'Financial Loss Tier',
            legendItems: [
                { id: 'l1', color: '#f59e0b', label: 'Loss > $50M' },
                { id: 'l2', color: '#d97706', label: 'Loss $10M - $50M' },
                { id: 'l3', color: '#ca8a04', label: 'Loss $1M - $10M' },
                { id: 'l4', color: '#65a30d', label: 'Sub-Million Impact' }
            ]
        },
        'nordic-frost': {
            label: 'Nordic Frost (Espionage)',
            bgDark: '#0b0f19',
            landDefault: '#192237',
            landStroke: '#2e3d5e',
            legendTitle: 'Espionage Activity',
            legendItems: [
                { id: 'l1', color: '#818cf8', label: 'Confirmed APT Intrusion' },
                { id: 'l2', color: '#6366f1', label: 'Credential Harvesting' },
                { id: 'l3', color: '#3b82f6', label: 'Phishing Delivery' },
                { id: 'l4', color: '#06b6d4', label: 'Passive Scanning' }
            ]
        },
        'monochrome': {
            label: 'Monochrome Stealth',
            bgDark: '#0a0a0a',
            landDefault: '#1c1c1c',
            landStroke: '#333333',
            legendTitle: 'Target Classification',
            legendItems: [
                { id: 'l1', color: '#ffffff', label: 'Tier 1 Target' },
                { id: 'l2', color: '#a3a3a3', label: 'Tier 2 Target' },
                { id: 'l3', color: '#737373', label: 'Tier 3 Target' },
                { id: 'l4', color: '#525252', label: 'Baseline Observation' }
            ]
        }
    };

    // Prebuilt Map Presets
    const PREBUILT_TEMPLATES = {
        'ransomware-surge': {
            title: 'Global Ransomware Surge & Victimology Map',
            theme: 'crimson-threat',
            region: 'world',
            legendTitle: 'Threat Severity',
            legendItems: [
                { id: 'l1', color: '#ef4444', label: 'Critical Threat' },
                { id: 'l2', color: '#f97316', label: 'High Priority' },
                { id: 'l3', color: '#eab308', label: 'Medium Impact' },
                { id: 'l4', color: '#38bdf8', label: 'Low / Monitoring' }
            ],
            labelMode: 'targeted',
            targetingData: {
                'US': { color: '#ef4444', label: 'United States' },
                'GB': { color: '#f97316', label: 'United Kingdom' },
                'DE': { color: '#eab308', label: 'Germany' },
                'FR': { color: '#eab308', label: 'France' },
                'AU': { color: '#eab308', label: 'Australia' },
                'CA': { color: '#f97316', label: 'Canada' },
                'IT': { color: '#38bdf8', label: 'Italy' },
                'JP': { color: '#38bdf8', label: 'Japan' },
                'SG': { color: '#38bdf8', label: 'Singapore' }
            }
        },
        'volt-typhoon': {
            title: 'Volt Typhoon Critical Infrastructure Targeting',
            theme: 'matrix-cyan',
            region: 'world',
            legendTitle: 'Sovereignty Impact',
            legendItems: [
                { id: 'l1', color: '#06b6d4', label: 'Critical Utility Pivot' },
                { id: 'l2', color: '#0284c7', label: 'Maritime / Radar Compromise' },
                { id: 'l3', color: '#0d9488', label: 'Subsea Cable Recon' },
                { id: 'l4', color: '#10b981', label: 'Coast Guard Telemetry' }
            ],
            labelMode: 'targeted',
            targetingData: {
                'US': { color: '#06b6d4', label: 'United States (Guam)' },
                'AU': { color: '#0d9488', label: 'Australia' },
                'JP': { color: '#0284c7', label: 'Japan' },
                'TW': { color: '#06b6d4', label: 'Taiwan' },
                'SG': { color: '#0284c7', label: 'Singapore' },
                'PH': { color: '#10b981', label: 'Philippines' }
            }
        },
        'fin7-global': {
            title: 'FIN7 Financial Services Global Exploitation',
            theme: 'cyber-gold',
            region: 'world',
            legendTitle: 'Target Sector',
            legendItems: [
                { id: 'l1', color: '#f59e0b', label: 'Severe POS Breach' },
                { id: 'l2', color: '#d97706', label: 'Luxury Banking Fraud' },
                { id: 'l3', color: '#ca8a04', label: 'FinTech / Card Processors' },
                { id: 'l4', color: '#65a30d', label: 'Private Wealth Management' }
            ],
            labelMode: 'targeted',
            targetingData: {
                'US': { color: '#f59e0b', label: 'United States' },
                'FR': { color: '#d97706', label: 'France' },
                'GB': { color: '#d97706', label: 'United Kingdom' },
                'AE': { color: '#ca8a04', label: 'United Arab Emirates' },
                'SG': { color: '#ca8a04', label: 'Singapore' }
            }
        },
        'blank': {
            title: 'Global Threat & Victimology Map',
            theme: 'crimson-threat',
            region: 'world',
            legendTitle: 'Threat Severity',
            legendItems: [
                { id: 'l1', color: '#ef4444', label: 'Critical Threat' },
                { id: 'l2', color: '#f97316', label: 'High Priority' },
                { id: 'l3', color: '#eab308', label: 'Medium Impact' },
                { id: 'l4', color: '#38bdf8', label: 'Low Impact' }
            ],
            labelMode: 'none',
            targetingData: {}
        }
    };

    const state = {
        initialized: false,
        title: PREBUILT_TEMPLATES['ransomware-surge'].title,
        theme: 'crimson-threat',
        region: 'world',
        legendTitle: PREBUILT_TEMPLATES['ransomware-surge'].legendTitle,
        legendItems: JSON.parse(JSON.stringify(PREBUILT_TEMPLATES['ransomware-surge'].legendItems)),
        labelMode: 'targeted', // 'none' | 'targeted' | 'iso' | 'names'
        labelColor: '#ffffff',
        canvasBg: 'dark', // 'dark' | 'white' | 'transparent'
        targetingData: JSON.parse(JSON.stringify(PREBUILT_TEMPLATES['ransomware-surge'].targetingData)),
        selectedCountryId: 'US',
        activeBrushColor: '#ef4444', // active hex color or 'eraser'
        searchQuery: '',
        activeRegionFilter: 'all',
        collapsedCats: new Set(),
        showBorders: true,
        showLegend: true,
        globalFont: 'Plus Jakarta Sans',
        labelFontSize: 11,
        labelFontWeight: '700',
        labelFontStyle: 'normal',
        labelCase: 'normal',
        zoom: 1,
        panX: 0,
        panY: 0,
        isPanning: false,
        panStart: { x: 0, y: 0 },
        dragDistance: 0,
        history: [],
        historyIndex: -1,
    };

    function getCountryList() {
        if (window.WORLD_MAP_DATA && Array.isArray(window.WORLD_MAP_DATA.locations)) {
            return window.WORLD_MAP_DATA.locations;
        }
        return [];
    }

    function getCountry(id) {
        const list = getCountryList();
        return list.find(c => c.id === id) || { id, name: id, region: 'other', c: [500, 330] };
    }

    function esc(str) {
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function pushHistory() {
        const snap = JSON.stringify({
            title: state.title,
            theme: state.theme,
            region: state.region,
            legendTitle: state.legendTitle,
            legendItems: state.legendItems,
            labelMode: state.labelMode,
            labelColor: state.labelColor,
            globalFont: state.globalFont,
            labelFontSize: state.labelFontSize,
            labelFontWeight: state.labelFontWeight,
            labelFontStyle: state.labelFontStyle,
            labelCase: state.labelCase,
            targetingData: state.targetingData
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
                theme: state.theme,
                region: state.region,
                legendTitle: state.legendTitle,
                legendItems: state.legendItems,
                labelMode: state.labelMode,
                canvasBg: state.canvasBg,
                globalFont: state.globalFont,
                labelFontSize: state.labelFontSize,
                labelFontWeight: state.labelFontWeight,
                labelFontStyle: state.labelFontStyle,
                labelCase: state.labelCase,
                targetingData: state.targetingData
            }));
        } catch (e) { /* ignore */ }
    }

    function loadFromStorage() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return false;
            const parsed = JSON.parse(raw);
            if (parsed && parsed.targetingData) {
                state.title = parsed.title || PREBUILT_TEMPLATES['ransomware-surge'].title;
                state.theme = parsed.theme || 'crimson-threat';
                state.region = parsed.region || 'world';
                state.legendTitle = parsed.legendTitle || 'Threat Level';
                state.legendItems = parsed.legendItems || PREBUILT_TEMPLATES['ransomware-surge'].legendItems;
                state.labelMode = parsed.labelMode || 'targeted';
                state.labelColor = parsed.labelColor || '#ffffff';
                state.canvasBg = parsed.canvasBg || 'dark';
                state.globalFont = parsed.globalFont || 'Plus Jakarta Sans';
                state.labelFontSize = typeof parsed.labelFontSize === 'number' ? parsed.labelFontSize : 11;
                state.labelFontWeight = parsed.labelFontWeight || '700';
                state.labelFontStyle = parsed.labelFontStyle || 'normal';
                state.labelCase = parsed.labelCase || 'normal';
                state.targetingData = parsed.targetingData;
                return true;
            }
        } catch (e) { /* ignore */ }
        return false;
    }

    function loadTemplate(key) {
        const tpl = PREBUILT_TEMPLATES[key];
        if (!tpl) return;
        state.title = tpl.title;
        state.theme = tpl.theme;
        state.region = tpl.region;
        state.legendTitle = tpl.legendTitle;
        state.legendItems = JSON.parse(JSON.stringify(tpl.legendItems));
        state.labelMode = tpl.labelMode || 'targeted';
        state.targetingData = JSON.parse(JSON.stringify(tpl.targetingData));
        state.selectedCountryId = Object.keys(state.targetingData)[0] || 'US';
        state.activeBrushColor = state.legendItems[0] ? state.legendItems[0].color : '#ef4444';

        const titleIn = document.getElementById('map-title-input');
        if (titleIn) titleIn.value = state.title;
        const themeSel = document.getElementById('map-theme-select');
        if (themeSel) themeSel.value = state.theme;
        const regionSel = document.getElementById('map-region-select');
        if (regionSel) regionSel.value = state.region;
        const labelSel = document.getElementById('map-label-select');
        if (labelSel) labelSel.value = state.labelMode;

        pushHistory();
        renderPalette();
        renderCanvas();
        renderInspector();
        closePresets();
        setTimeout(fitToScreen, 60);
    }

    // =========================================================================
    // INITIALIZATION & CLEAN TOPBAR
    // =========================================================================
    function initMapChartStudio() {
        const pane = document.getElementById('mapchart-draw-pane');
        if (!pane) return;

        if (!state.initialized) {
            if (!loadFromStorage()) {
                const tpl = PREBUILT_TEMPLATES['ransomware-surge'];
                state.title = tpl.title;
                state.theme = tpl.theme;
                state.region = tpl.region;
                state.legendTitle = tpl.legendTitle;
                state.legendItems = JSON.parse(JSON.stringify(tpl.legendItems));
                state.labelMode = tpl.labelMode || 'targeted';
                state.targetingData = JSON.parse(JSON.stringify(tpl.targetingData));
            }
            state.initialized = true;
            pushHistory();
        }

        renderShell(pane);
        renderPalette();
        renderCanvas();
        renderInspector();
        bindEvents();
        setTimeout(fitToScreen, 70);
    }

    function renderShell(pane) {
        pane.innerHTML = `
            <div class="map-root" id="map-studio-root">
                <!-- STREAMLINED TOP BAR -->
                <header class="map-top">
                    <!-- Left: Brand + Title + Status -->
                    <div class="map-top-left">
                        <div class="map-logo" title="MANTIS MapChart Studio">
                            <i class="fa-solid fa-earth-americas"></i>
                        </div>
                        <input type="text" class="map-title" id="map-title-input" value="${esc(state.title)}" title="Click to rename Map Chart" />
                        <span class="map-status" id="map-status-pill">256 NATIONS</span>
                    </div>

                    <!-- Center: Geographic Region + Theme + Country Labels + Typography -->
                    <div class="map-tools">
                        <div class="map-seg" role="group" aria-label="Map Controls">
                            <select id="map-region-select" title="Focus Geographic Region">
                                ${Object.entries(REGION_BOUNDS).map(([k, v]) => `<option value="${k}" ${state.region === k ? 'selected' : ''}>${esc(v.title)}</option>`).join('')}
                            </select>
                            <select id="map-theme-select" title="Palette Presets">
                                ${Object.entries(THEME_PALETTES).map(([k, v]) => `<option value="${k}" ${state.theme === k ? 'selected' : ''}>Theme: ${esc(v.label)}</option>`).join('')}
                            </select>
                            <select id="map-label-select" title="Display Country Names / Custom Labels on Map">
                                <option value="targeted" ${state.labelMode === 'targeted' ? 'selected' : ''}>Labels: Targeted Only</option>
                                <option value="names" ${state.labelMode === 'names' ? 'selected' : ''}>Labels: All Country Names</option>
                                <option value="iso" ${state.labelMode === 'iso' ? 'selected' : ''}>Labels: All ISO Codes</option>
                                <option value="none" ${state.labelMode === 'none' ? 'selected' : ''}>Labels: Off</option>
                            </select>
                        </div>

                        <!-- Quick Font Size & Style Stepper -->
                        <div class="map-seg map-seg-font" role="group" aria-label="Typography Controls" title="Quick Label Font Size & Style Controls">
                            <button type="button" id="map-btn-font-dec" title="Decrease Font Size (A-)" class="map-font-step-btn">
                                <i class="fa-solid fa-font" style="font-size:0.68rem;"></i><i class="fa-solid fa-minus" style="font-size:0.55rem;margin-left:2px;"></i>
                            </button>
                            <div class="map-font-size-box" title="Click or type font size (8-48px)">
                                <input type="number" id="map-font-size-toolbar-input" min="8" max="48" step="1" value="${state.labelFontSize || 11}" class="map-font-quick-input" aria-label="Font size in pixels" />
                                <span class="map-font-quick-unit">px</span>
                            </div>
                            <button type="button" id="map-btn-font-inc" title="Increase Font Size (A+)" class="map-font-step-btn">
                                <i class="fa-solid fa-font" style="font-size:0.76rem;"></i><i class="fa-solid fa-plus" style="font-size:0.55rem;margin-left:2px;"></i>
                            </button>
                            <div class="map-seg-divider"></div>
                            <button type="button" id="map-btn-font-bold" class="${Number(state.labelFontWeight) >= 700 ? 'active' : ''}" title="Toggle Bold Weight" style="padding: 5px 8px;">
                                <i class="fa-solid fa-bold"></i>
                            </button>
                            <button type="button" id="map-btn-font-italic" class="${state.labelFontStyle === 'italic' ? 'active' : ''}" title="Toggle Italic Style" style="padding: 5px 8px;">
                                <i class="fa-solid fa-italic"></i>
                            </button>
                            <button type="button" id="map-btn-font-case" class="${state.labelCase === 'uppercase' ? 'active' : ''}" title="Toggle UPPERCASE" style="padding: 5px 8px; font-weight:800; font-size:0.7rem;">
                                AA
                            </button>
                        </div>

                        <button type="button" class="map-tbtn" id="map-btn-clear-colors" style="color:#f87171;" title="Clear All Country Colors">
                            <i class="fa-solid fa-eraser"></i><span>Reset Colors</span>
                        </button>
                    </div>

                    <!-- Right: Presets Drawer + Style Popover + Export -->
                    <div class="map-top-right">
                        <button type="button" class="map-tbtn" id="map-btn-presets" title="Browse Threat Scenarios">
                            <i class="fa-solid fa-map-location-dot" style="color:#22d3ee;"></i>
                            <span>Presets</span>
                        </button>

                        <div class="map-pop-wrap">
                            <button type="button" class="map-tbtn" id="map-btn-style-pop" title="Map Appearance & Typography Settings">
                                <i class="fa-solid fa-sliders"></i>
                                <span>Style</span>
                                <i class="fa-solid fa-chevron-down mmd-caret"></i>
                            </button>
                            <div class="map-pop" id="map-style-pop" style="min-width: 260px;">
                                <div class="map-pop-sec">MAP APPEARANCE</div>
                                <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 6px;">
                                    <label style="font-size:0.75rem; color:#cbd5e1; cursor:pointer;" for="map-opt-borders">Show Country Borders</label>
                                    <input type="checkbox" id="map-opt-borders" ${state.showBorders ? 'checked' : ''} style="cursor:pointer;" />
                                </div>
                                <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 6px;">
                                    <label style="font-size:0.75rem; color:#cbd5e1; cursor:pointer;" for="map-opt-legend">Show Legend</label>
                                    <input type="checkbox" id="map-opt-legend" ${state.showLegend ? 'checked' : ''} style="cursor:pointer;" />
                                </div>

                                <div class="map-pop-sec" style="margin-top:10px;">TYPOGRAPHY & FONT STYLES</div>
                                <div style="display:flex; flex-direction:column; gap:8px; padding:4px 6px;">
                                    <div>
                                        <label style="font-size:0.7rem; color:#94a3b8; display:block; margin-bottom:3px;">Font Family</label>
                                        <select class="dd-select" id="map-font-select" style="width:100%; font-size:0.75rem;">
                                            <option value="Plus Jakarta Sans" ${state.globalFont.includes('Jakarta') ? 'selected' : ''}>Plus Jakarta Sans (Modern)</option>
                                            <option value="Inter" ${state.globalFont === 'Inter' ? 'selected' : ''}>Inter (Clean UI)</option>
                                            <option value="JetBrains Mono" ${state.globalFont.includes('JetBrains') ? 'selected' : ''}>JetBrains Mono (Cyber)</option>
                                            <option value="Space Grotesk" ${state.globalFont.includes('Space') ? 'selected' : ''}>Space Grotesk (Tech)</option>
                                            <option value="IBM Plex Mono" ${state.globalFont.includes('IBM') ? 'selected' : ''}>IBM Plex Mono (Terminal)</option>
                                            <option value="Rajdhani" ${state.globalFont.includes('Rajdhani') ? 'selected' : ''}>Rajdhani (Tactical)</option>
                                            <option value="Orbitron" ${state.globalFont.includes('Orbitron') ? 'selected' : ''}>Orbitron (Futuristic)</option>
                                            <option value="Merriweather" ${state.globalFont.includes('Merriweather') ? 'selected' : ''}>Merriweather (Serif)</option>
                                            <option value="Caveat" ${state.globalFont.includes('Caveat') ? 'selected' : ''}>Caveat (Handwritten)</option>
                                            <option value="Arial" ${state.globalFont === 'Arial' ? 'selected' : ''}>Arial (System Sans)</option>
                                            <option value="Impact" ${state.globalFont === 'Impact' ? 'selected' : ''}>Impact (Heavy Display)</option>
                                            <option value="Georgia" ${state.globalFont === 'Georgia' ? 'selected' : ''}>Georgia (Editorial Serif)</option>
                                        </select>
                                    </div>
                                    <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                                        <label style="font-size:0.7rem; color:#94a3b8; flex:1;">Font Size</label>
                                        <div style="display:flex; align-items:center; gap:4px;">
                                            <input type="range" id="map-font-size-slider" min="8" max="28" step="1" value="${state.labelFontSize || 11}" style="width:75px; cursor:pointer;" />
                                            <input type="number" id="map-font-size-input" min="8" max="40" step="1" value="${state.labelFontSize || 11}" style="width:44px; height:24px; font-size:0.75rem; text-align:center; background:#0f172a; border:1px solid rgba(255,255,255,0.15); border-radius:4px; color:#fff;" />
                                            <span style="font-size:0.7rem; color:#64748b;">px</span>
                                        </div>
                                    </div>
                                    <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                                        <label style="font-size:0.7rem; color:#94a3b8; flex:1;">Font Weight</label>
                                        <select class="dd-select" id="map-font-weight-select" style="width:115px; font-size:0.75rem;">
                                            <option value="400" ${state.labelFontWeight === '400' ? 'selected' : ''}>Regular (400)</option>
                                            <option value="500" ${state.labelFontWeight === '500' ? 'selected' : ''}>Medium (500)</option>
                                            <option value="600" ${state.labelFontWeight === '600' ? 'selected' : ''}>Semi-Bold (600)</option>
                                            <option value="700" ${state.labelFontWeight === '700' ? 'selected' : ''}>Bold (700)</option>
                                            <option value="800" ${state.labelFontWeight === '800' ? 'selected' : ''}>Extra Bold (800)</option>
                                            <option value="900" ${state.labelFontWeight === '900' ? 'selected' : ''}>Black (900)</option>
                                        </select>
                                    </div>
                                    <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                                        <label style="font-size:0.7rem; color:#94a3b8;">Font Style</label>
                                        <select class="dd-select" id="map-font-style-select" style="width:115px; font-size:0.75rem;">
                                            <option value="normal" ${state.labelFontStyle === 'normal' ? 'selected' : ''}>Normal</option>
                                            <option value="italic" ${state.labelFontStyle === 'italic' ? 'selected' : ''}>Italic</option>
                                        </select>
                                    </div>
                                    <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                                        <label style="font-size:0.7rem; color:#94a3b8;">Text Case</label>
                                        <select class="dd-select" id="map-font-case-select" style="width:115px; font-size:0.75rem;">
                                            <option value="normal" ${state.labelCase === 'normal' ? 'selected' : ''}>Standard</option>
                                            <option value="uppercase" ${state.labelCase === 'uppercase' ? 'selected' : ''}>UPPERCASE</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="map-pop-wrap">
                            <button type="button" class="map-tbtn map-primary" id="map-btn-export-pop">
                                <i class="fa-solid fa-arrow-down-to-bracket"></i>
                                <span>Export</span>
                                <i class="fa-solid fa-chevron-down mmd-caret"></i>
                            </button>
                            <div class="map-pop" id="map-export-pop">
                                <div class="map-pop-sec">HIGH-DPI PNG (2X)</div>
                                <button type="button" class="map-pop-item" data-map-export="png-transparent"><span class="dd-dot-swatch dd-dot-transparent"></span>Transparent Background</button>
                                <button type="button" class="map-pop-item" data-map-export="png-dark"><span class="dd-dot-swatch dd-dot-dark"></span>Dark Background</button>
                                <button type="button" class="map-pop-item" data-map-export="png-white"><span class="dd-dot-swatch dd-dot-white"></span>White Background (Black Font)</button>
                                <div class="map-pop-sec" style="margin-top:6px;">VECTOR & SPREADSHEET</div>
                                <button type="button" class="map-pop-item" data-map-export="svg-dark"><i class="fa-solid fa-bezier-curve" style="color:#22d3ee;"></i>Vector SVG (Dark)</button>
                                <button type="button" class="map-pop-item" data-map-export="svg-white"><i class="fa-solid fa-bezier-curve" style="color:#f8fafc;"></i>Vector SVG (White Background)</button>
                                <button type="button" class="map-pop-item" id="map-action-export-csv"><i class="fa-solid fa-file-csv" style="color:#f59e0b;"></i>Victimology CSV</button>
                                <div class="map-pop-sec" style="margin-top:6px;">PROJECT BACKUP</div>
                                <button type="button" class="map-pop-item" id="map-action-save-project"><i class="fa-solid fa-floppy-disk" style="color:#10b981;"></i>Save .mantis-map</button>
                                <button type="button" class="map-pop-item" id="map-action-load-project"><i class="fa-solid fa-folder-open" style="color:#38bdf8;"></i>Open .mantis-map</button>
                            </div>
                        </div>

                        <input type="file" id="map-file-import-input" accept=".mantis-map,.json" style="display:none;" />
                    </div>
                </header>

                <!-- WORKSPACE -->
                <div class="dd-workspace" id="map-workspace">
                    <!-- LEFT SIDEBAR: MAPCHART PAINTER BRUSH & COUNTRY PICKER -->
                    <aside class="dd-palette" id="map-palette" aria-label="MapChart Colorizer">
                        <div class="dd-palette-header">
                            <div class="dd-palette-top-row">
                                <span style="display:flex;align-items:center;gap:7px;font-weight:700;font-size:0.75rem;">
                                    <i class="fa-solid fa-palette" style="color:#22d3ee;"></i> MAPCHART PAINTER
                                </span>
                                <button type="button" class="dd-inspector-collapse-btn" id="map-btn-collapse-palette" title="Collapse Left Sidebar">
                                    <i class="fa-solid fa-angles-left"></i>
                                </button>
                            </div>

                            <!-- MapChart Active Brush Swatch Bar -->
                            <div style="margin-top:8px;" id="map-brush-bar"></div>

                            <!-- Country Search -->
                            <div class="dd-palette-search" style="margin-top:8px;">
                                <i class="fa-solid fa-magnifying-glass"></i>
                                <input type="text" id="map-country-search" placeholder="Search 256 countries, ISO...">
                            </div>

                            <!-- Regional Filter Pills -->
                            <div class="dd-cat-pills" id="map-region-pills" style="margin-top:6px;">
                                <button type="button" class="dd-cat-pill active" data-map-region-pill="all">All</button>
                                <button type="button" class="dd-cat-pill" data-map-region-pill="NA">NA</button>
                                <button type="button" class="dd-cat-pill" data-map-region-pill="EU">EU</button>
                                <button type="button" class="dd-cat-pill" data-map-region-pill="APAC">APAC</button>
                                <button type="button" class="dd-cat-pill" data-map-region-pill="SA">SA</button>
                                <button type="button" class="dd-cat-pill" data-map-region-pill="MEA">MEA</button>
                            </div>
                        </div>
                        <div class="dd-palette-body dark-scroll" id="map-palette-list"></div>
                    </aside>

                    <!-- CENTER CANVAS -->
                    <div class="dd-canvas-wrap theme-${state.canvasBg}" id="map-canvas-wrap" style="position:relative;">
                        <button type="button" class="dd-expand-palette-pill" id="map-btn-expand-palette" title="Expand Palette Panel">
                            <i class="fa-solid fa-angles-right"></i>
                            <span>PAINTER</span>
                        </button>

                        <!-- Clean Floating Dock (BG & Fit only) -->
                        <div class="dd-floating-dock-wrap">
                            <div class="dd-floating-dock">
                                <div class="dd-bg-switcher">
                                    <button type="button" class="dd-bg-chip ${state.canvasBg === 'dark' ? 'active' : ''}" data-map-bg="dark">Dark</button>
                                    <button type="button" class="dd-bg-chip ${state.canvasBg === 'white' ? 'active' : ''}" data-map-bg="white">White</button>
                                    <button type="button" class="dd-bg-chip ${state.canvasBg === 'transparent' ? 'active' : ''}" data-map-bg="transparent">Transparent</button>
                                </div>
                                <span class="dd-divider"></span>
                                <button type="button" class="dd-dock-btn" id="map-btn-fit-dock" title="Fit Map to Viewport">
                                    <i class="fa-solid fa-expand"></i><span>Fit Map</span>
                                </button>
                            </div>
                        </div>

                        <!-- Main High-Precision Map SVG (viewBox: 0 0 1010 666) -->
                        <svg id="map-svg-canvas" class="dd-svg-canvas" viewBox="0 0 1010 666" xmlns="http://www.w3.org/2000/svg">
                            <defs>
                                <filter id="map-threat-glow" x="-20%" y="-20%" width="140%" height="140%">
                                    <feGaussianBlur stdDeviation="3" result="blur" />
                                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                                </filter>
                            </defs>
                            <g id="map-viewport">
                                <rect id="map-ocean-bg" x="0" y="0" width="1010" height="666" fill="transparent" />
                                <g id="map-layer-countries"></g>
                                <g id="map-layer-labels"></g>
                                <g id="map-layer-legend"></g>
                            </g>
                        </svg>

                        <!-- Floating Tooltip (react-simple-maps style) -->
                        <div class="map-tooltip" id="map-hover-tooltip">
                            <div class="map-tooltip-header">
                                <span id="map-tt-country">United States</span>
                                <span class="map-tooltip-badge" id="map-tt-badge" style="background:rgba(239,68,68,0.2); color:#ef4444; border:1px solid rgba(239,68,68,0.4);">TARGETED</span>
                            </div>
                            <div class="map-tooltip-detail" id="map-tt-victims">Targeted Nation</div>
                        </div>

                        <!-- Bottom HUD info -->
                        <div class="dd-canvas-hud-bottom">
                            <div class="dd-canvas-hud-pill">
                                <span><kbd>Click</kbd> Paint Active Color</span>
                                <span><kbd>Right-Click</kbd> Erase Country</span>
                                <span><kbd>Drag</kbd> Pan</span>
                                <span><kbd>Scroll</kbd> Zoom</span>
                            </div>
                            <div class="dd-zoom-controls">
                                <button type="button" class="dd-zoom-btn" id="map-zoom-out" title="Zoom Out"><i class="fa-solid fa-minus"></i></button>
                                <span class="dd-zoom-readout" id="map-zoom-label">100%</span>
                                <button type="button" class="dd-zoom-btn" id="map-zoom-in" title="Zoom In"><i class="fa-solid fa-plus"></i></button>
                                <button type="button" class="dd-zoom-btn" id="map-zoom-fit" title="Fit Map to Screen"><i class="fa-solid fa-expand"></i></button>
                            </div>
                        </div>

                        <button type="button" class="dd-expand-inspector-pill" id="map-btn-expand-inspector" title="Open Country Properties">
                            <i class="fa-solid fa-angles-left"></i>
                            <span>TARGET DETAILS</span>
                        </button>
                    </div>

                    <!-- RIGHT SIDEBAR: VICTIMOLOGY & EDITABLE LEGEND INSPECTOR -->
                    <aside class="dd-inspector" id="map-inspector" aria-label="Victimology Properties">
                        <div class="dd-inspector-header">
                            <span style="display:inline-flex; align-items:center; gap:7px;">
                                <span>MAP INSPECTOR</span>
                                <span class="dd-inspector-badge" id="map-inspector-badge">US</span>
                            </span>
                            <button type="button" class="dd-inspector-collapse-btn" id="map-btn-collapse-inspector" title="Collapse Panel">
                                <i class="fa-solid fa-angles-right"></i>
                            </button>
                        </div>
                        <div class="dd-inspector-body dark-scroll" id="map-inspector-body"></div>
                    </aside>
                </div>

                <!-- SLIDE-IN PRESETS DRAWER -->
                <div id="map-presets-scrim"></div>
                <aside id="map-presets-drawer">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 18px 12px;border-bottom:1px solid rgba(255,255,255,0.08);">
                        <div style="font-size:0.9rem;font-weight:700;display:flex;align-items:center;gap:8px;color:#f8fafc;">
                            <i class="fa-solid fa-map-location-dot" style="color:#22d3ee;"></i>
                            <span>Threat Map Presets</span>
                        </div>
                        <button type="button" id="map-presets-close" style="width:28px;height:28px;border-radius:6px;border:none;background:transparent;color:#94a3b8;cursor:pointer;">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                    <div style="flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:8px;" class="dark-scroll">
                        <div class="map-preset-card" data-load-tpl="ransomware-surge">
                            <div class="badge" style="color:#ef4444;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);">SEV-1 CRIMSON</div>
                            <div class="name">Global Ransomware Surge (LockBit 3.0)</div>
                            <div class="desc">Multi-continent ransomware offensive with high impact on US, UK, DE, FR, AU, and JP critical sectors.</div>
                        </div>
                        <div class="map-preset-card" data-load-tpl="volt-typhoon">
                            <div class="badge" style="color:#06b6d4;background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);">CRITICAL INFRA</div>
                            <div class="name">Volt Typhoon Pacific Infrastructure</div>
                            <div class="desc">Living-off-the-Land state espionage targeting ports, subsea communications, and utilities across US (Guam), Taiwan, and Australia.</div>
                        </div>
                        <div class="map-preset-card" data-load-tpl="fin7-global">
                            <div class="badge" style="color:#f59e0b;background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.3);">FINANCIAL FRAUD</div>
                            <div class="name">FIN7 Financial Services Campaign</div>
                            <div class="desc">Point-of-sale malware and payment card harvesting campaign striking banking and luxury hospitality across the US, UK, and France.</div>
                        </div>
                        <div class="map-preset-card" data-load-tpl="blank">
                            <div class="badge" style="color:#94a3b8;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);">CLEAN SLATE</div>
                            <div class="name">Blank World Map</div>
                            <div class="desc">Clean canvas ready for custom country threat coloring, victim counts, and labels from scratch.</div>
                        </div>
                    </div>
                </aside>
            </div>
        `;
    }

    // =========================================================================
    // LEFT SIDEBAR: PAINTER WITH LEGEND SWATCHES AS BRUSHES
    // =========================================================================
    function renderPalette() {
        const brushBar = document.getElementById('map-brush-bar');
        const listEl = document.getElementById('map-palette-list');
        if (!brushBar || !listEl) return;

        brushBar.innerHTML = `
            <div style="font-size:0.67rem;font-weight:700;color:#94a3b8;margin-bottom:6px;display:flex;align-items:center;justify-content:space-between;">
                <span>ACTIVE PAINT BRUSH</span>
                <span style="font-size:0.62rem;color:#64748b;">Click swatches to set brush</span>
            </div>
            <div class="map-swatch-row">
                ${state.legendItems.map(item => `
                    <button type="button" class="map-swatch-btn ${state.activeBrushColor === item.color ? 'active' : ''}" data-brush-color="${item.color}" style="background:${item.color};" title="${esc(item.label)}"></button>
                `).join('')}
                
                <!-- Custom Color Picker -->
                <label class="map-color-input-btn ${state.activeBrushColor !== 'eraser' && !state.legendItems.some(i => i.color === state.activeBrushColor) ? 'active' : ''}" title="Custom Color Picker">
                    <i class="fa-solid fa-eye-dropper" style="color:${state.activeBrushColor !== 'eraser' ? state.activeBrushColor : '#cbd5e1'};"></i>
                    <input type="color" id="map-custom-color-picker" value="${state.activeBrushColor !== 'eraser' ? state.activeBrushColor : '#38bdf8'}" />
                </label>

                <!-- Eraser -->
                <button type="button" class="map-swatch-btn eraser ${state.activeBrushColor === 'eraser' ? 'active' : ''}" data-brush-color="eraser" title="Eraser Brush: click country to clear color">
                    <i class="fa-solid fa-eraser"></i>
                </button>
            </div>
        `;

        brushBar.querySelectorAll('[data-brush-color]').forEach(btn => {
            btn.addEventListener('click', () => {
                state.activeBrushColor = btn.getAttribute('data-brush-color');
                renderPalette();
            });
        });

        document.getElementById('map-custom-color-picker')?.addEventListener('input', (e) => {
            state.activeBrushColor = e.target.value;
            renderPalette();
        });

        const q = (state.searchQuery || '').toLowerCase().trim();
        const reg = state.activeRegionFilter || 'all';
        const countries = getCountryList();

        // 1. Targeted Nations list
        const targetedList = Object.entries(state.targetingData).map(([cId, tData]) => {
            const cObj = countries.find(c => c.id === cId) || { id: cId, name: cId, region: 'other' };
            return { id: cId, name: cObj.name, region: cObj.region, ...tData };
        }).filter(c => {
            if (reg !== 'all' && c.region !== reg) return false;
            if (!q) return true;
            return c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q) || (c.label || '').toLowerCase().includes(q) || (c.note || '').toLowerCase().includes(q);
        }).sort((a, b) => (b.count || 0) - (a.count || 0));

        // 2. All Countries list
        const allList = countries.filter(c => {
            if (reg !== 'all' && c.region !== reg) return false;
            if (!q) return true;
            return c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q) || c.region.toLowerCase().includes(q);
        });

        let html = '';

        // Category 1: Targeted Nations
        const isCol1 = state.collapsedCats.has('targeted');
        html += `
            <div class="dd-cat-group">
                <div class="dd-cat-header" data-map-cat-toggle="targeted">
                    <span class="dd-cat-dot" style="background:#ef4444;"></span>
                    <span class="dd-cat-name">Targeted Nations</span>
                    <span class="dd-cat-count">${targetedList.length}</span>
                    <i class="fa-solid fa-chevron-${isCol1 ? 'right' : 'down'} dd-cat-caret"></i>
                </div>
                ${!isCol1 ? `
                    <div class="dd-cat-items" style="display:flex;flex-direction:column;gap:3px;padding:4px 6px;">
                        ${targetedList.length === 0 ? `<div style="font-size:0.75rem;color:#64748b;padding:8px 10px;text-align:center;">No targeted nations match filter</div>` : ''}
                        ${targetedList.map(c => {
                            const col = c.color || '#ef4444';
                            return `
                                <div class="dd-asset-item ${state.selectedCountryId === c.id ? 'active' : ''}" data-map-pick-country="${c.id}" style="cursor:pointer;padding:6px 8px;">
                                    <div class="dd-asset-icon">
                                        <span style="display:inline-block;width:12px;height:12px;border-radius:3px;background:${col};box-shadow:0 0 6px ${col}88;"></span>
                                    </div>
                                    <div class="dd-asset-meta">
                                        <div class="dd-asset-name">${esc(c.name)} <span style="font-size:0.65rem;color:#64748b;">(${c.id})</span></div>
                                        <div class="dd-asset-sub"><span style="color:${col};font-weight:700;">${esc(c.label || 'Targeted')}</span> • ${c.region}</div>
                                    </div>
                                    <button type="button" class="dd-dock-btn-danger" data-map-remove-target="${c.id}" style="border:none;background:transparent;color:#f87171;padding:2px 6px;cursor:pointer;" title="Remove Country Targeting">
                                        <i class="fa-solid fa-xmark"></i>
                                    </button>
                                </div>
                            `;
                        }).join('')}
                    </div>
                ` : ''}
            </div>
        `;

        // Category 2: Full Country Directory
        const isCol2 = state.collapsedCats.has('all');
        html += `
            <div class="dd-cat-group">
                <div class="dd-cat-header" data-map-cat-toggle="all">
                    <span class="dd-cat-dot" style="background:#38bdf8;"></span>
                    <span class="dd-cat-name">Country Catalog</span>
                    <span class="dd-cat-count">${allList.length}</span>
                    <i class="fa-solid fa-chevron-${isCol2 ? 'right' : 'down'} dd-cat-caret"></i>
                </div>
                ${!isCol2 ? `
                    <div class="dd-cat-items" style="display:flex;flex-direction:column;gap:3px;padding:4px 6px;max-height:280px;overflow-y:auto;">
                        ${allList.map(c => {
                            const tData = state.targetingData[c.id];
                            const isTgt = !!tData;
                            const col = isTgt ? (tData.color || '#ef4444') : '#475569';
                            return `
                                <div class="dd-asset-item ${state.selectedCountryId === c.id ? 'active' : ''}" data-map-pick-country="${c.id}" style="cursor:pointer;padding:5px 8px;">
                                    <div class="dd-asset-icon" style="color:${col};">
                                        <i class="fa-solid fa-earth-americas"></i>
                                    </div>
                                    <div class="dd-asset-meta">
                                        <div class="dd-asset-name">${esc(c.name)} <span style="font-size:0.65rem;color:#64748b;">(${c.id})</span></div>
                                        <div class="dd-asset-sub">${isTgt ? `<strong style="color:${col};">${esc(tData.label || 'Targeted')}</strong>` : `Region: ${c.region}`}</div>
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                ` : ''}
            </div>
        `;

        listEl.innerHTML = html;

        listEl.querySelectorAll('[data-map-cat-toggle]').forEach(hdr => {
            hdr.addEventListener('click', () => {
                const cat = hdr.getAttribute('data-map-cat-toggle');
                if (state.collapsedCats.has(cat)) state.collapsedCats.delete(cat);
                else state.collapsedCats.add(cat);
                renderPalette();
            });
        });

        listEl.querySelectorAll('[data-map-pick-country]').forEach(btn => {
            btn.addEventListener('click', (ev) => {
                if (ev.target.closest('[data-map-remove-target]')) return;
                const cId = btn.getAttribute('data-map-pick-country');
                const cObj = getCountry(cId);

                // Directly highlight country with active brush color (MapChart workflow)
                const activeColor = state.activeBrushColor === 'eraser' ? null : (state.activeBrushColor || '#ef4444');
                if (activeColor) {
                    if (!state.targetingData[cId]) {
                        state.targetingData[cId] = {
                            color: activeColor,
                            label: cObj.name
                        };
                    } else {
                        state.targetingData[cId].color = activeColor;
                    }
                } else {
                    delete state.targetingData[cId];
                }

                state.selectedCountryId = cId;
                pushHistory();
                renderPalette();
                renderCanvas();
                renderInspector();
            });
        });

        listEl.querySelectorAll('[data-map-remove-target]').forEach(btn => {
            btn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                const cId = btn.getAttribute('data-map-remove-target');
                delete state.targetingData[cId];
                pushHistory();
                renderPalette();
                renderCanvas();
                renderInspector();
            });
        });
    }

    // =========================================================================
    // SVG MAP RENDERER (High-Contrast Labels & Country Fills)
    // =========================================================================
    function createSvgEl(tag, attrs = {}) {
        const el = document.createElementNS(SVG_NS, tag);
        for (const [k, v] of Object.entries(attrs)) {
            if (v !== undefined && v !== null) el.setAttribute(k, String(v));
        }
        return el;
    }

    function renderCanvas() {
        const vp = document.getElementById('map-viewport');
        const lCountries = document.getElementById('map-layer-countries');
        const lLabels = document.getElementById('map-layer-labels');
        const lLegend = document.getElementById('map-layer-legend');
        if (!vp || !lCountries) return;

        const svg = document.getElementById('map-svg-canvas');
        if (svg) {
            const rect = svg.getBoundingClientRect();
            if (rect.width && rect.height) {
                svg.setAttribute('viewBox', `0 0 ${Math.round(rect.width)} ${Math.round(rect.height)}`);
            }
        }

        vp.setAttribute('transform', `translate(${state.panX}, ${state.panY}) scale(${state.zoom})`);
        const zoomLbl = document.getElementById('map-zoom-label');
        if (zoomLbl) zoomLbl.textContent = `${Math.round(state.zoom * 100)}%`;

        lCountries.innerHTML = '';
        if (lLabels) lLabels.innerHTML = '';
        lLegend.innerHTML = '';

        const curPalette = THEME_PALETTES[state.theme] || THEME_PALETTES['crimson-threat'];
        const isLight = state.canvasBg === 'white';
        const countries = getCountryList();

        // 1. RENDER REAL GEOGRAPHIC COUNTRIES
        countries.forEach(c => {
            const tData = state.targetingData[c.id];
            let fillCol = isLight ? '#94a3b8' : curPalette.landDefault;
            let fillOpacity = isLight ? '0.45' : '0.65';

            if (tData) {
                fillCol = tData.color || '#ef4444';
                fillOpacity = '0.92';
            }

            const strokeCol = state.showBorders ? (isLight ? '#64748b' : curPalette.landStroke) : 'transparent';
            const strokeW = 0.7;

            const pathEl = createSvgEl('path', {
                d: c.path,
                fill: fillCol,
                'fill-opacity': fillOpacity,
                stroke: strokeCol,
                'stroke-width': strokeW,
                'stroke-linejoin': 'round',
                'stroke-linecap': 'round',
                class: 'map-country-path',
                'data-country-id': c.id
            });

            // Hover Tooltip
            pathEl.addEventListener('mouseenter', (ev) => {
                showTooltip(ev, c);
            });
            pathEl.addEventListener('mousemove', (ev) => {
                moveTooltip(ev);
            });
            pathEl.addEventListener('mouseleave', () => {
                hideTooltip();
            });

            // MapChart Click-to-Color Painter (ignoring drags)
            pathEl.addEventListener('click', (ev) => {
                if (state.dragDistance > 5) return;
                ev.stopPropagation();
                state.selectedCountryId = c.id;

                if (state.activeBrushColor === 'eraser') {
                    delete state.targetingData[c.id];
                } else {
                    const activeColor = state.activeBrushColor || '#ef4444';
                    if (!state.targetingData[c.id]) {
                        state.targetingData[c.id] = { color: activeColor, label: c.name };
                    } else if (state.targetingData[c.id].color === activeColor) {
                        delete state.targetingData[c.id];
                    } else {
                        state.targetingData[c.id].color = activeColor;
                    }
                }

                pushHistory();
                renderPalette();
                renderCanvas();
                renderInspector();
            });

            // Right-Click to Erase
            pathEl.addEventListener('contextmenu', (ev) => {
                ev.preventDefault();
                ev.stopPropagation();
                delete state.targetingData[c.id];
                state.selectedCountryId = c.id;
                pushHistory();
                renderPalette();
                renderCanvas();
                renderInspector();
            });

            // Double Click to Inspect
            pathEl.addEventListener('dblclick', (ev) => {
                ev.stopPropagation();
                state.selectedCountryId = c.id;
                document.getElementById('map-workspace')?.classList.remove('inspector-collapsed');
                renderInspector();
            });

            lCountries.appendChild(pathEl);
        });

        // 2. RENDER COUNTRY LABELS DIRECTLY ON MAP (CLEAN TEXT WITH CONTRAST HALO)
        if (lLabels && state.labelMode !== 'none') {
            countries.forEach(c => {
                const tData = state.targetingData[c.id];
                const isTargeted = !!tData;

                if (state.labelMode === 'targeted' && !isTargeted) return;

                const pos = c.c;
                if (!pos || isNaN(pos[0]) || isNaN(pos[1])) return;

                let labelText = '';
                if (state.labelMode === 'iso') {
                    labelText = c.id;
                } else if (state.labelMode === 'names') {
                    labelText = c.name;
                } else if (state.labelMode === 'targeted') {
                    labelText = (tData && tData.label) ? tData.label : c.name;
                }

                if (!labelText) return;

                // Handle text transform
                if (state.labelCase === 'uppercase' || (tData && tData.labelCase === 'uppercase')) {
                    labelText = labelText.toUpperCase();
                }

                const g = createSvgEl('g', { style: 'pointer-events:none;' });

                // FONT COLOR LOGIC:
                // When isLight (white background export or white background canvas view):
                // Font MUST be black (#000000) for maximum legibility!
                // White text on white background is prevented.
                let fontColor;
                if (isLight) {
                    const custom = (tData && tData.labelColor);
                    if (custom && custom.toLowerCase() !== '#ffffff' && custom.toLowerCase() !== '#fff' && custom.toLowerCase() !== '#f8fafc' && custom.toLowerCase() !== '#f1f5f9') {
                        fontColor = custom;
                    } else {
                        fontColor = '#000000';
                    }
                } else {
                    fontColor = (tData && tData.labelColor) || state.labelColor || '#ffffff';
                }

                // Font size, weight, and style resolution
                const baseSize = state.labelFontSize || (state.labelMode === 'targeted' ? 11 : 9.5);
                const fontSize = (tData && tData.fontSize) ? tData.fontSize : baseSize;
                const fontWeight = (tData && tData.fontWeight) || state.labelFontWeight || (state.labelMode === 'targeted' ? '700' : '600');
                const fontStyle = (tData && tData.fontStyle) || state.labelFontStyle || 'normal';

                // In white mode, a bright stroke halo around the black text guarantees absolute legibility on red/colored countries AND white ocean!
                // Scaling the halo proportionally with fontSize prevents text from being overwhelmed at small sizes or losing contrast at large sizes.
                const haloColor = isLight ? '#ffffff' : 'rgba(7, 11, 18, 0.95)';
                const haloWidth = (Math.min(2.8, Math.max(1.3, fontSize * 0.22))).toFixed(1) + 'px';

                // Clean text without background box, with high-contrast text stroke halo
                const textEl = createSvgEl('text', {
                    x: pos[0],
                    y: pos[1],
                    class: 'map-country-label',
                    'font-family': `'${state.globalFont}', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif`,
                    'font-size': `${fontSize}px`,
                    'font-weight': String(fontWeight),
                    'font-style': fontStyle,
                    'fill': fontColor,
                    'stroke': haloColor,
                    'stroke-width': haloWidth,
                    'stroke-linejoin': 'round',
                    'paint-order': 'stroke fill',
                    'text-anchor': 'middle',
                    'dominant-baseline': 'central',
                    'style': 'pointer-events:none;user-select:none;'
                });
                textEl.textContent = labelText;
                g.appendChild(textEl);
                lLabels.appendChild(g);
            });
        }

        // 3. RENDER EDITABLE THREAT LEGEND (MapChart / Chloromaps style)
        if (state.showLegend && state.legendItems.length > 0) {
            const legG = createSvgEl('g');
            const legW = 185;
            const legH = 34 + state.legendItems.length * 20;
            const legX = 35;
            const legY = Math.max(20, 640 - legH);

            legG.appendChild(createSvgEl('rect', {
                x: legX, y: legY, width: legW, height: legH, rx: 8,
                fill: isLight ? 'rgba(255,255,255,0.98)' : 'rgba(11,16,27,0.94)',
                stroke: isLight ? 'rgba(0,0,0,0.18)' : 'rgba(255,255,255,0.12)',
                'stroke-width': 1,
                'box-shadow': '0 8px 24px rgba(0,0,0,0.4)'
            }));

            const legTitle = createSvgEl('text', {
                x: legX + 12, y: legY + 20,
                fill: isLight ? '#000000' : '#f8fafc',
                'font-family': `'${state.globalFont}', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif`,
                'font-size': '10.5px',
                'font-weight': '800'
            });
            legTitle.textContent = (state.legendTitle || 'LEGEND').toUpperCase();
            legG.appendChild(legTitle);

            state.legendItems.forEach((item, idx) => {
                const itemY = legY + 38 + idx * 20;
                legG.appendChild(createSvgEl('rect', {
                    x: legX + 12, y: itemY - 9, width: 13, height: 13, rx: 3,
                    fill: item.color
                }));
                const itemTxt = createSvgEl('text', {
                    x: legX + 32, y: itemY + 1,
                    fill: isLight ? '#000000' : '#cbd5e1',
                    'font-family': `'${state.globalFont}', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif`,
                    'font-size': '10px',
                    'font-weight': '600'
                });
                itemTxt.textContent = item.label || 'Category';
                legG.appendChild(itemTxt);
            });
            lLegend.appendChild(legG);
        }
    }

    // =========================================================================
    // HOVER TOOLTIP (react-simple-maps style)
    // =========================================================================
    function showTooltip(ev, country) {
        const tt = document.getElementById('map-hover-tooltip');
        if (!tt) return;
        const tData = state.targetingData[country.id];

        const nameEl = document.getElementById('map-tt-country');
        const badgeEl = document.getElementById('map-tt-badge');
        const vicEl = document.getElementById('map-tt-victims');
        const noteEl = document.getElementById('map-tt-note');

        if (nameEl) nameEl.textContent = `${country.name} (${country.id})`;

        if (tData) {
            const col = tData.color || '#ef4444';
            if (badgeEl) {
                badgeEl.textContent = 'TARGETED';
                badgeEl.style.color = col;
                badgeEl.style.background = `${col}22`;
                badgeEl.style.borderColor = `${col}55`;
                badgeEl.style.display = 'inline-block';
            }
            if (vicEl) vicEl.textContent = tData.label || 'Targeted Nation';
            if (noteEl) noteEl.style.display = 'none';
        } else {
            if (badgeEl) {
                badgeEl.textContent = 'UNTARGETED';
                badgeEl.style.color = '#94a3b8';
                badgeEl.style.background = 'rgba(255,255,255,0.06)';
                badgeEl.style.borderColor = 'rgba(255,255,255,0.15)';
                badgeEl.style.display = 'inline-block';
            }
            if (vicEl) vicEl.textContent = 'Untargeted';
            if (noteEl) noteEl.style.display = 'none';
        }

        tt.classList.add('visible');
        moveTooltip(ev);
    }

    function moveTooltip(ev) {
        const tt = document.getElementById('map-hover-tooltip');
        const wrap = document.getElementById('map-canvas-wrap');
        if (!tt || !wrap) return;

        const rect = wrap.getBoundingClientRect();
        const x = ev.clientX - rect.left;
        const y = ev.clientY - rect.top;

        tt.style.left = `${x}px`;
        tt.style.top = `${y}px`;
    }

    function hideTooltip() {
        const tt = document.getElementById('map-hover-tooltip');
        if (tt) tt.classList.remove('visible');
    }

    // =========================================================================
    // RIGHT INSPECTOR: CLEAN SELECTED COUNTRY & FULL LEGEND EDITOR
    // =========================================================================
    function renderInspector() {
        const body = document.getElementById('map-inspector-body');
        const badge = document.getElementById('map-inspector-badge');
        if (!body) return;

        const cId = state.selectedCountryId;
        const cObj = getCountry(cId);
        const tData = state.targetingData[cId] || { color: '#ef4444', label: cObj.name };

        if (badge) badge.textContent = cId;

        const targetedCount = Object.keys(state.targetingData).length;
        const isLight = state.canvasBg === 'white';
        const activeLabelColor = tData.labelColor || state.labelColor || (isLight ? '#0f172a' : '#ffffff');

        body.innerHTML = `
            <div class="dd-stats-grid" style="grid-template-columns:1fr;">
                <div class="dd-stat-box" style="text-align:center;">
                    <div class="dd-stat-num" style="color:#ef4444;">${targetedCount}</div>
                    <div class="dd-stat-label">TARGETED NATIONS</div>
                </div>
            </div>

            <!-- SELECTED COUNTRY PROPERTIES -->
            <div class="dd-insp-section">
                <div class="dd-insp-sec-title">Selected: ${esc(cObj.name)} (${cId})</div>
                
                <div class="dd-insp-row">
                    <span class="dd-insp-row-label">Country Color</span>
                    <div class="dd-insp-row-control" style="display:flex;align-items:center;gap:8px;">
                        <input type="color" id="map-insp-color-picker" value="${tData.color || '#ef4444'}" style="width:32px;height:28px;padding:0;border:none;border-radius:4px;cursor:pointer;background:transparent;" />
                        <span style="font-size:0.75rem;color:#94a3b8;font-family:monospace;">${tData.color || '#ef4444'}</span>
                    </div>
                </div>

                <div class="dd-field" style="margin-top:8px;">
                    <label>Country Map Label</label>
                    <input type="text" class="dd-input" id="map-insp-custom-label" value="${esc(tData.label !== undefined ? tData.label : cObj.name)}" placeholder="${esc(cObj.name)}" />
                </div>

                <div class="dd-insp-row" style="margin-top:8px;">
                    <span class="dd-insp-row-label">Label Font Color</span>
                    <div class="dd-insp-row-control" style="display:flex;align-items:center;gap:8px;">
                        <input type="color" id="map-insp-label-color" value="${activeLabelColor}" style="width:32px;height:28px;padding:0;border:none;border-radius:4px;cursor:pointer;background:transparent;" />
                        <span style="font-size:0.75rem;color:#94a3b8;font-family:monospace;">${activeLabelColor}</span>
                    </div>
                </div>

                <div class="dd-insp-row" style="margin-top:8px;">
                    <span class="dd-insp-row-label">Country Font Size</span>
                    <div class="dd-insp-row-control" style="display:flex;align-items:center;gap:6px;">
                        <input type="number" id="map-insp-font-size" value="${tData.fontSize || ''}" placeholder="${state.labelFontSize || 11}" min="8" max="48" style="width:52px;height:26px;font-size:0.75rem;padding:2px 6px;background:#0f172a;border:1px solid rgba(255,255,255,0.15);border-radius:4px;color:#fff;" />
                        <span style="font-size:0.7rem;color:#64748b;">px</span>
                        <button type="button" id="map-insp-font-size-reset" style="background:transparent;border:none;color:#94a3b8;cursor:pointer;font-size:0.7rem;" title="Reset to Global Font Size">
                            <i class="fa-solid fa-rotate-left"></i>
                        </button>
                    </div>
                </div>

                <div style="margin-top:10px;">
                    <button type="button" class="dd-image-upload-btn dd-dock-btn-danger" id="map-insp-clear-country" style="width:100%;color:#fca5a5;border-color:rgba(239,68,68,0.25);">
                        <i class="fa-solid fa-eraser"></i> Clear Country Color
                    </button>
                </div>
            </div>

            <!-- FULLY EDITABLE LEGEND BUILDER (MapChart style) -->
            <div class="dd-insp-section">
                <div class="dd-insp-sec-title" style="display:flex;justify-content:space-between;align-items:center;">
                    <span>EDITABLE MAP LEGEND</span>
                    <button type="button" id="map-insp-add-legend-item" style="background:transparent;border:none;color:#22d3ee;cursor:pointer;font-size:0.75rem;font-weight:700;">
                        <i class="fa-solid fa-plus"></i> Add Item
                    </button>
                </div>

                <div class="dd-field" style="margin-bottom:10px;">
                    <label>Legend Title</label>
                    <input type="text" class="dd-input" id="map-insp-leg-title" value="${esc(state.legendTitle)}" />
                </div>

                <div style="display:flex;flex-direction:column;gap:6px;" id="map-legend-items-list">
                    ${state.legendItems.map((item, idx) => `
                        <div style="display:flex;align-items:center;gap:6px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:6px;padding:5px 8px;">
                            <input type="color" data-leg-color-idx="${idx}" value="${item.color}" style="width:26px;height:24px;border:none;border-radius:4px;cursor:pointer;background:transparent;padding:0;" title="Change legend color" />
                            <input type="text" class="dd-input" data-leg-text-idx="${idx}" value="${esc(item.label)}" style="flex:1;height:26px;font-size:0.76rem;padding:2px 6px;" placeholder="Legend label" />
                            <button type="button" class="dd-btn dd-dock-btn-danger" data-leg-del-idx="${idx}" style="padding:2px 6px;height:24px;border-radius:4px;" title="Delete Legend Item">
                                <i class="fa-solid fa-xmark"></i>
                            </button>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        // Bind Inspector Listeners
        document.getElementById('map-insp-color-picker')?.addEventListener('input', (e) => {
            const val = e.target.value;
            if (!state.targetingData[cId]) {
                state.targetingData[cId] = { label: cObj.name };
            }
            state.targetingData[cId].color = val;
            pushHistory();
            renderPalette();
            renderCanvas();
        });

        document.getElementById('map-insp-custom-label')?.addEventListener('input', (e) => {
            if (!state.targetingData[cId]) {
                state.targetingData[cId] = { color: '#ef4444' };
            }
            state.targetingData[cId].label = e.target.value;
            pushHistory();
            renderCanvas();
            renderPalette();
        });

        document.getElementById('map-insp-label-color')?.addEventListener('input', (e) => {
            const val = e.target.value;
            if (!state.targetingData[cId]) {
                state.targetingData[cId] = { color: '#ef4444', label: cObj.name };
            }
            state.targetingData[cId].labelColor = val;
            state.labelColor = val;
            pushHistory();
            renderCanvas();
        });

        document.getElementById('map-insp-font-size')?.addEventListener('input', (e) => {
            const val = parseInt(e.target.value, 10);
            if (!state.targetingData[cId]) {
                state.targetingData[cId] = { color: '#ef4444', label: cObj.name };
            }
            if (!isNaN(val) && val >= 8) {
                state.targetingData[cId].fontSize = Math.min(48, Math.max(8, val));
            } else {
                delete state.targetingData[cId].fontSize;
            }
            pushHistory();
            renderCanvas();
        });

        document.getElementById('map-insp-font-size-reset')?.addEventListener('click', () => {
            if (state.targetingData[cId]) {
                delete state.targetingData[cId].fontSize;
            }
            const input = document.getElementById('map-insp-font-size');
            if (input) input.value = '';
            pushHistory();
            renderCanvas();
        });

        document.getElementById('map-insp-clear-country')?.addEventListener('click', () => {
            delete state.targetingData[cId];
            pushHistory();
            renderPalette();
            renderCanvas();
            renderInspector();
        });

        document.getElementById('map-insp-leg-title')?.addEventListener('input', (e) => {
            state.legendTitle = e.target.value;
            pushHistory();
            renderCanvas();
        });

        document.getElementById('map-insp-add-legend-item')?.addEventListener('click', () => {
            state.legendItems.push({
                id: `l_${Date.now()}`,
                color: '#38bdf8',
                label: `New Category ${state.legendItems.length + 1}`
            });
            pushHistory();
            renderPalette();
            renderCanvas();
            renderInspector();
        });

        body.querySelectorAll('[data-leg-color-idx]').forEach(input => {
            input.addEventListener('input', (e) => {
                const idx = Number(e.target.getAttribute('data-leg-color-idx'));
                if (state.legendItems[idx]) {
                    state.legendItems[idx].color = e.target.value;
                    pushHistory();
                    renderPalette();
                    renderCanvas();
                }
            });
        });

        body.querySelectorAll('[data-leg-text-idx]').forEach(input => {
            input.addEventListener('input', (e) => {
                const idx = Number(e.target.getAttribute('data-leg-text-idx'));
                if (state.legendItems[idx]) {
                    state.legendItems[idx].label = e.target.value;
                    pushHistory();
                    renderCanvas();
                    renderPalette();
                }
            });
        });

        body.querySelectorAll('[data-leg-del-idx]').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = Number(btn.getAttribute('data-leg-del-idx'));
                state.legendItems.splice(idx, 1);
                pushHistory();
                renderPalette();
                renderCanvas();
                renderInspector();
            });
        });
    }

    // =========================================================================
    // EVENT BINDINGS & FIXED POPOVERS
    // =========================================================================
    function bindEvents() {
        const svg = document.getElementById('map-svg-canvas');
        if (!svg) return;

        document.getElementById('map-title-input')?.addEventListener('change', (e) => {
            state.title = e.target.value.trim() || 'Untitled Map Chart';
            pushHistory();
        });

        document.getElementById('map-region-select')?.addEventListener('change', (e) => {
            state.region = e.target.value;
            pushHistory();
            fitToScreen();
        });

        document.getElementById('map-theme-select')?.addEventListener('change', (e) => {
            state.theme = e.target.value;
            const themeObj = THEME_PALETTES[state.theme];
            if (themeObj) {
                state.legendTitle = themeObj.legendTitle;
                state.legendItems = JSON.parse(JSON.stringify(themeObj.legendItems));
                state.activeBrushColor = state.legendItems[0] ? state.legendItems[0].color : '#ef4444';
            }
            pushHistory();
            renderPalette();
            renderCanvas();
            renderInspector();
        });

        document.getElementById('map-label-select')?.addEventListener('change', (e) => {
            state.labelMode = e.target.value;
            pushHistory();
            renderCanvas();
        });

        document.getElementById('map-btn-clear-colors')?.addEventListener('click', () => {
            if (confirm('Clear all country threat targeting colors?')) {
                state.targetingData = {};
                pushHistory();
                renderPalette();
                renderCanvas();
                renderInspector();
            }
        });

        // Search & Region Filter Pills
        document.getElementById('map-country-search')?.addEventListener('input', (e) => {
            state.searchQuery = e.target.value;
            renderPalette();
        });

        document.querySelectorAll('[data-map-region-pill]').forEach(pill => {
            pill.addEventListener('click', () => {
                state.activeRegionFilter = pill.getAttribute('data-map-region-pill');
                document.querySelectorAll('[data-map-region-pill]').forEach(p => p.classList.toggle('active', p === pill));
                renderPalette();
            });
        });

        // Presets Drawer
        const root = document.getElementById('map-studio-root');
        document.getElementById('map-btn-presets')?.addEventListener('click', () => {
            root?.classList.add('presets-open');
        });
        document.getElementById('map-presets-close')?.addEventListener('click', closePresets);
        document.getElementById('map-presets-scrim')?.addEventListener('click', closePresets);

        document.querySelectorAll('[data-load-tpl]').forEach(card => {
            card.addEventListener('click', () => {
                loadTemplate(card.getAttribute('data-load-tpl'));
            });
        });

        // Style Popover & Export Popover
        const stylePop = document.getElementById('map-style-pop');
        const exportPop = document.getElementById('map-export-pop');

        document.getElementById('map-btn-style-pop')?.addEventListener('click', (e) => {
            e.stopPropagation();
            exportPop?.classList.remove('open');
            stylePop?.classList.toggle('open');
        });

        document.getElementById('map-btn-export-pop')?.addEventListener('click', (e) => {
            e.stopPropagation();
            stylePop?.classList.remove('open');
            exportPop?.classList.toggle('open');
        });

        document.addEventListener('click', (e) => {
            if (!e.target.closest('#map-style-pop') && !e.target.closest('#map-btn-style-pop')) {
                stylePop?.classList.remove('open');
            }
            if (!e.target.closest('#map-export-pop') && !e.target.closest('#map-btn-export-pop')) {
                exportPop?.classList.remove('open');
            }
        });

        function syncTypographyControls() {
            const sizeDisp = document.getElementById('map-font-size-display');
            if (sizeDisp) sizeDisp.textContent = `${state.labelFontSize || 11}px`;
            const tbInput = document.getElementById('map-font-size-toolbar-input');
            if (tbInput) tbInput.value = state.labelFontSize || 11;
            const sizeIn = document.getElementById('map-font-size-input');
            if (sizeIn) sizeIn.value = state.labelFontSize || 11;
            const sizeSlider = document.getElementById('map-font-size-slider');
            if (sizeSlider) sizeSlider.value = state.labelFontSize || 11;

            const boldBtn = document.getElementById('map-btn-font-bold');
            if (boldBtn) boldBtn.classList.toggle('active', Number(state.labelFontWeight) >= 700);
            const italicBtn = document.getElementById('map-btn-font-italic');
            if (italicBtn) italicBtn.classList.toggle('active', state.labelFontStyle === 'italic');
            const caseBtn = document.getElementById('map-btn-font-case');
            if (caseBtn) caseBtn.classList.toggle('active', state.labelCase === 'uppercase');

            const fontSel = document.getElementById('map-font-select');
            if (fontSel) fontSel.value = state.globalFont;
            const weightSel = document.getElementById('map-font-weight-select');
            if (weightSel) weightSel.value = state.labelFontWeight || '700';
            const styleSel = document.getElementById('map-font-style-select');
            if (styleSel) styleSel.value = state.labelFontStyle || 'normal';
            const caseSel = document.getElementById('map-font-case-select');
            if (caseSel) caseSel.value = state.labelCase || 'normal';
        }

        // Toolbar Quick Steppers
        document.getElementById('map-btn-font-dec')?.addEventListener('click', () => {
            state.labelFontSize = Math.max(8, (state.labelFontSize || 11) - 1);
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-btn-font-inc')?.addEventListener('click', () => {
            state.labelFontSize = Math.min(48, (state.labelFontSize || 11) + 1);
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        const tbSizeInput = document.getElementById('map-font-size-toolbar-input');
        if (tbSizeInput) {
            tbSizeInput.addEventListener('change', (e) => {
                const val = Math.max(8, Math.min(48, parseInt(e.target.value, 10) || 11));
                state.labelFontSize = val;
                tbSizeInput.value = val;
                syncTypographyControls();
                pushHistory();
                renderCanvas();
            });
            tbSizeInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    tbSizeInput.blur();
                }
            });
        }
        document.getElementById('map-btn-font-bold')?.addEventListener('click', () => {
            state.labelFontWeight = (Number(state.labelFontWeight) >= 700) ? '400' : '700';
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-btn-font-italic')?.addEventListener('click', () => {
            state.labelFontStyle = (state.labelFontStyle === 'italic') ? 'normal' : 'italic';
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-btn-font-case')?.addEventListener('click', () => {
            state.labelCase = (state.labelCase === 'uppercase') ? 'normal' : 'uppercase';
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });

        // Popover Typography Listeners
        document.getElementById('map-font-select')?.addEventListener('change', (e) => {
            state.globalFont = e.target.value;
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-font-size-slider')?.addEventListener('input', (e) => {
            state.labelFontSize = parseInt(e.target.value, 10) || 11;
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-font-size-input')?.addEventListener('change', (e) => {
            const v = Math.max(6, Math.min(48, parseInt(e.target.value, 10) || 11));
            state.labelFontSize = v;
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-font-weight-select')?.addEventListener('change', (e) => {
            state.labelFontWeight = e.target.value;
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-font-style-select')?.addEventListener('change', (e) => {
            state.labelFontStyle = e.target.value;
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });
        document.getElementById('map-font-case-select')?.addEventListener('change', (e) => {
            state.labelCase = e.target.value;
            syncTypographyControls();
            pushHistory();
            renderCanvas();
        });

        // Style options
        document.getElementById('map-opt-borders')?.addEventListener('change', (e) => {
            state.showBorders = e.target.checked;
            renderCanvas();
        });
        document.getElementById('map-opt-legend')?.addEventListener('change', (e) => {
            state.showLegend = e.target.checked;
            renderCanvas();
        });

        // Floating Dock Actions
        document.getElementById('map-btn-fit-dock')?.addEventListener('click', fitToScreen);

        // Collapse / Expand
        const ws = document.getElementById('map-workspace');
        document.getElementById('map-btn-collapse-palette')?.addEventListener('click', () => {
            ws?.classList.add('palette-collapsed');
        });
        document.getElementById('map-btn-expand-palette')?.addEventListener('click', () => {
            ws?.classList.remove('palette-collapsed');
        });
        document.getElementById('map-btn-collapse-inspector')?.addEventListener('click', () => {
            ws?.classList.add('inspector-collapsed');
        });
        document.getElementById('map-btn-expand-inspector')?.addEventListener('click', () => {
            ws?.classList.remove('inspector-collapsed');
        });

        // Background switcher
        document.querySelectorAll('[data-map-bg]').forEach(btn => {
            btn.addEventListener('click', () => {
                state.canvasBg = btn.getAttribute('data-map-bg');
                const wrap = document.getElementById('map-canvas-wrap');
                if (wrap) wrap.className = `dd-canvas-wrap theme-${state.canvasBg}`;
                document.querySelectorAll('[data-map-bg]').forEach(b => b.classList.toggle('active', b === btn));
                renderCanvas();
                saveToStorage();
            });
        });

        // Exports
        document.querySelectorAll('[data-map-export]').forEach(btn => {
            btn.addEventListener('click', () => {
                const [fmt, bg] = btn.getAttribute('data-map-export').split('-');
                if (fmt === 'png') exportMapPNG(bg);
                else if (fmt === 'svg') exportMapSVG(bg);
                exportPop?.classList.remove('open');
            });
        });
        document.getElementById('map-action-save-project')?.addEventListener('click', () => {
            saveProjectFile();
            exportPop?.classList.remove('open');
        });
        document.getElementById('map-action-load-project')?.addEventListener('click', () => {
            document.getElementById('map-file-import-input')?.click();
            exportPop?.classList.remove('open');
        });
        document.getElementById('map-action-export-csv')?.addEventListener('click', () => {
            exportVictimologyCSV();
            exportPop?.classList.remove('open');
        });

        // Project File Load
        document.getElementById('map-file-import-input')?.addEventListener('change', (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (ev) => {
                try {
                    const parsed = JSON.parse(ev.target.result);
                    if (parsed && parsed.targetingData) {
                        state.title = parsed.title || state.title;
                        state.theme = parsed.theme || state.theme;
                        state.region = parsed.region || 'world';
                        state.legendTitle = parsed.legendTitle || state.legendTitle;
                        state.legendItems = parsed.legendItems || state.legendItems;
                        state.labelMode = parsed.labelMode || 'targeted';
                        state.globalFont = parsed.globalFont || 'Plus Jakarta Sans';
                        state.labelFontSize = typeof parsed.labelFontSize === 'number' ? parsed.labelFontSize : 11;
                        state.labelFontWeight = parsed.labelFontWeight || '700';
                        state.labelFontStyle = parsed.labelFontStyle || 'normal';
                        state.labelCase = parsed.labelCase || 'normal';
                        state.targetingData = parsed.targetingData;
                        syncTypographyControls();
                        pushHistory();
                        renderPalette();
                        renderCanvas();
                        renderInspector();
                        alert('Map Chart Project imported successfully!');
                    }
                } catch (err) {
                    alert('Invalid map project file.');
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
                const vp = document.getElementById('map-viewport');
                if (vp) vp.setAttribute('transform', `translate(${state.panX}, ${state.panY}) scale(${state.zoom})`);
            }
        });

        window.addEventListener('mouseup', () => {
            state.isPanning = false;
        });

        svg.addEventListener('wheel', (ev) => {
            ev.preventDefault();
            const factor = ev.deltaY < 0 ? 1.1 : 0.9;
            const nextZoom = Math.min(4.0, Math.max(0.2, state.zoom * factor));
            const rect = svg.getBoundingClientRect();
            const mx = ev.clientX - rect.left;
            const my = ev.clientY - rect.top;
            state.panX = mx - (mx - state.panX) * (nextZoom / state.zoom);
            state.panY = my - (my - state.panY) * (nextZoom / state.zoom);
            state.zoom = nextZoom;
            renderCanvas();
        }, { passive: false });

        document.getElementById('map-zoom-in')?.addEventListener('click', () => {
            state.zoom = Math.min(4.0, state.zoom * 1.18);
            renderCanvas();
        });
        document.getElementById('map-zoom-out')?.addEventListener('click', () => {
            state.zoom = Math.max(0.2, state.zoom / 1.18);
            renderCanvas();
        });
        document.getElementById('map-zoom-fit')?.addEventListener('click', fitToScreen);
    }

    function closePresets() {
        document.getElementById('map-studio-root')?.classList.remove('presets-open');
    }

    function fitToScreen() {
        const svg = document.getElementById('map-svg-canvas');
        if (!svg) return;
        const rect = svg.getBoundingClientRect();
        if (!rect.width || !rect.height) return;

        const bounds = REGION_BOUNDS[state.region] || REGION_BOUNDS['world'];
        const scale = Math.min(2.5, Math.max(0.35, Math.min((rect.width - 50) / bounds.w, (rect.height - 60) / bounds.h)));
        state.zoom = scale;
        state.panX = (rect.width - bounds.w * scale) / 2 - bounds.x * scale;
        state.panY = (rect.height - bounds.h * scale) / 2 - bounds.y * scale + 15;
        renderCanvas();
    }

    function buildExportSvgString(bgMode) {
        const prevBg = state.canvasBg;
        state.canvasBg = bgMode === 'white' ? 'white' : 'dark';
        renderCanvas();

        const origSvg = document.getElementById('map-svg-canvas');
        const rect = origSvg ? origSvg.getBoundingClientRect() : { width: 1010, height: 666 };
        const w = Math.max(400, Math.round(rect.width) || 1010);
        const h = Math.max(300, Math.round(rect.height) || 666);

        const clone = origSvg.cloneNode(true);
        clone.setAttribute('width', String(w));
        clone.setAttribute('height', String(h));
        clone.setAttribute('viewBox', `0 0 ${w} ${h}`);

        const vp = clone.querySelector('#map-viewport');
        if (vp) {
            // Keep the active zoom and pan so exported view matches the exact visible region on screen!
            vp.setAttribute('transform', `translate(${state.panX}, ${state.panY}) scale(${state.zoom})`);
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
        return (state.title || 'mantis-mapchart').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    }

    function exportMapSVG(bgMode) {
        const { svgStr } = buildExportSvgString(bgMode);
        const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${slugTitle()}-${bgMode}.svg`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function exportMapPNG(bgMode) {
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

    function saveProjectFile() {
        const payload = {
            format: 'mantis-map-v3',
            savedAt: new Date().toISOString(),
            title: state.title,
            theme: state.theme,
            region: state.region,
            legendTitle: state.legendTitle,
            legendItems: state.legendItems,
            labelMode: state.labelMode,
            labelColor: state.labelColor,
            globalFont: state.globalFont,
            labelFontSize: state.labelFontSize,
            labelFontWeight: state.labelFontWeight,
            labelFontStyle: state.labelFontStyle,
            labelCase: state.labelCase,
            targetingData: state.targetingData
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${slugTitle()}.mantis-map`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function exportVictimologyCSV() {
        const rows = [
            ['Country Code', 'Country Name', 'Color', 'Map Label']
        ];
        const countries = getCountryList();
        Object.entries(state.targetingData).forEach(([cId, data]) => {
            const cObj = countries.find(c => c.id === cId) || { name: cId };
            rows.push([cId, cObj.name, data.color || '', data.label || '']);
        });
        const csvContent = rows.map(r => r.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${slugTitle()}-targeting.csv`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    window.MantisMapChart = { getState: () => state, renderCanvas, fitToScreen, buildExportSvgString };
    window.openMapChartDraw = initMapChartStudio;
})();
