/**
 * MANTIS Chart Creator
 * Standalone chart builder: the user types or pastes their own table, picks a chart type,
 * and exports PNG or CSV. Charts are saved in the browser (localStorage). No MANTIS data is read.
 * Chart types (v1): bar, horizontal bar, stacked bar, line, area, pie, doughnut, radar,
 * polar area, scatter, bubble. Rendering uses the vendored Chart.js (chart.umd.min.js).
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'mantis_chart_creator_v1';
    const PALETTE = ['#f5c518', '#4fa3ff', '#ff6b6b', '#3ddc97', '#c792ea', '#ff9f43', '#22d3ee', '#f472b6', '#a3e635', '#94a3b8'];

    const TYPES = [
        { id: 'bar', label: 'Bar', kind: 'category' },
        { id: 'barh', label: 'Horizontal bar', kind: 'category' },
        { id: 'stacked', label: 'Stacked bar', kind: 'category' },
        { id: 'line', label: 'Line', kind: 'category' },
        { id: 'area', label: 'Area', kind: 'category' },
        { id: 'pie', label: 'Pie', kind: 'slice' },
        { id: 'doughnut', label: 'Doughnut', kind: 'slice' },
        { id: 'radar', label: 'Radar', kind: 'category' },
        { id: 'polar', label: 'Polar area', kind: 'slice' },
        { id: 'scatter', label: 'Scatter', kind: 'xy' },
        { id: 'bubble', label: 'Bubble', kind: 'xyr' },
    ];

    const DEFAULT_HEADERS = ['Label', 'Series 1', 'Series 2'];
    const DEFAULT_ROWS = [['Item A', '12', '7'], ['Item B', '19', '11'], ['Item C', '8', '15']];

    let state = { charts: [], activeId: null };
    let chartInstance = null;
    let initialized = false;

    // ---------- helpers ----------
    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const uid = () => 'cc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const typeInfo = (id) => TYPES.find((t) => t.id === id) || TYPES[0];
    const toast = (msg, isError) => { if (typeof window.showToast === 'function') window.showToast(msg, !!isError); };

    function parseNumber(v) {
        const s = String(v == null ? '' : v).trim().replace(/,/g, '');
        if (s === '') return null;
        const n = Number(s);
        return Number.isFinite(n) ? n : NaN;
    }

    function getActive() { return state.charts.find((c) => c.id === state.activeId) || null; }

    function newChart(title) {
        const now = new Date().toISOString();
        return {
            id: uid(), title: title || 'Untitled chart', type: 'bar', legend: true, stacked: false,
            headers: DEFAULT_HEADERS.slice(), rows: DEFAULT_ROWS.map((r) => r.slice()),
            seriesColors: [], created: now, updated: now,
        };
    }

    function save() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch (e) { toast('Could not save chart locally: ' + e.message, true); }
    }

    function load() {
        try {
            const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
            if (raw && Array.isArray(raw.charts)) state = raw;
        } catch (e) { /* keep defaults */ }
        if (!state.charts.length) {
            const c = newChart('Sample: alerts per rule');
            state.charts.push(c);
            state.activeId = c.id;
            save();
        }
        if (!getActive()) state.activeId = state.charts[0].id;
    }

    // ---------- validation & chart config ----------
    function validate(chart) {
        const issues = [];
        const t = typeInfo(chart.type);
        const dataRows = chart.rows.filter((r) => r.some((v) => String(v).trim() !== ''));
        if (!dataRows.length) issues.push('Add at least one row of data.');
        const numericFrom = t.kind === 'category' || t.kind === 'slice' ? 1 : 0;
        const numericTo = t.kind === 'xyr' ? 2 : t.kind === 'xy' ? 1 : chart.headers.length - 1;
        if (t.kind === 'xy' || t.kind === 'xyr') {
            if (chart.headers.length < (t.kind === 'xyr' ? 3 : 2)) issues.push(t.kind === 'xyr' ? 'Bubble needs X, Y and R columns.' : 'Scatter needs X and Y columns.');
        }
        if (t.kind === 'slice' && chart.headers.length > 2) issues.push(`${t.label} uses only the first series (${chart.headers[1]}).`);
        chart.rows.forEach((r, i) => {
            if (!r.some((v) => String(v).trim() !== '')) return;
            for (let j = numericFrom; j <= numericTo && j < chart.headers.length; j++) {
                const n = parseNumber(r[j]);
                if (Number.isNaN(n)) issues.push(`Row ${i + 1}, ${chart.headers[j] || 'column ' + (j + 1)}: "${String(r[j]).slice(0, 30)}" is not a number.`);
            }
        });
        return { issues, dataRows };
    }

    function colorFor(chart, idx) { return chart.seriesColors[idx] || PALETTE[idx % PALETTE.length]; }

    function buildConfig(chart) {
        const t = typeInfo(chart.type);
        const rows = chart.rows.filter((r) => r.some((v) => String(v).trim() !== ''));
        const num = (v) => { const n = parseNumber(v); return Number.isFinite(n) ? n : null; };
        const legend = { display: !!chart.legend, labels: { color: '#cbd5e1' } };
        const title = { display: true, text: chart.title, color: '#f8fafc', font: { size: 16, weight: '600' } };
        const cfg = { type: 'bar', data: { labels: [], datasets: [] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend, title } } };
        const axisColor = { color: '#94a3b8' }, grid = { color: 'rgba(148,163,184,0.15)' };

        if (t.kind === 'category') {
            cfg.data.labels = rows.map((r) => r[0]);
            const series = chart.headers.slice(1);
            cfg.data.datasets = series.map((name, j) => {
                const c = colorFor(chart, j);
                return { label: name, data: rows.map((r) => num(r[j + 1])), backgroundColor: c + 'cc', borderColor: c, borderWidth: 2, tension: 0.3, fill: chart.type === 'area' ? true : false };
            });
            if (chart.type === 'bar' || chart.type === 'stacked') cfg.type = 'bar';
            if (chart.type === 'barh') { cfg.type = 'bar'; cfg.options.indexAxis = 'y'; }
            if (chart.type === 'line' || chart.type === 'area') cfg.type = 'line';
            if (chart.type === 'radar') cfg.type = 'radar';
            if (chart.type === 'stacked') { cfg.options.scales = { x: { stacked: true, ticks: axisColor, grid }, y: { stacked: true, ticks: axisColor, grid } }; }
            else if (chart.type !== 'radar') { cfg.options.scales = { x: { ticks: axisColor, grid }, y: { ticks: axisColor, grid } }; }
            if (chart.type === 'radar') cfg.options.scales = { r: { ticks: axisColor, grid, pointLabels: { color: '#cbd5e1' } } };
        } else if (t.kind === 'slice') {
            cfg.type = chart.type;
            cfg.data.labels = rows.map((r) => r[0]);
            cfg.data.datasets = [{
                label: chart.headers[1] || 'Value',
                data: rows.map((r) => num(r[1])),
                backgroundColor: rows.map((_, i) => colorFor(chart, i) + 'cc'),
                borderColor: rows.map((_, i) => colorFor(chart, i)),
                borderWidth: 1,
            }];
            if (chart.type === 'polar') cfg.options.scales = { r: { ticks: { display: false }, grid } };
        } else if (t.kind === 'xy') {
            cfg.type = 'scatter';
            cfg.data.datasets = [{
                label: `${chart.headers[1] || 'Y'} vs ${chart.headers[0] || 'X'}`,
                data: rows.map((r) => ({ x: num(r[0]), y: num(r[1]) })).filter((p) => p.x !== null && p.y !== null),
                backgroundColor: colorFor(chart, 0) + 'cc', borderColor: colorFor(chart, 0), pointRadius: 5,
            }];
            cfg.options.scales = { x: { title: { display: true, text: chart.headers[0] || 'X', color: '#94a3b8' }, ticks: axisColor, grid }, y: { title: { display: true, text: chart.headers[1] || 'Y', color: '#94a3b8' }, ticks: axisColor, grid } };
        } else {
            cfg.type = 'bubble';
            cfg.data.datasets = [{
                label: chart.headers[2] || 'R',
                data: rows.map((r) => ({ x: num(r[0]), y: num(r[1]), r: Math.max(2, Math.min(40, Math.abs(num(r[2]) || 0))) }))
                    .filter((p) => p.x !== null && p.y !== null),
                backgroundColor: colorFor(chart, 0) + '99', borderColor: colorFor(chart, 0),
            }];
            cfg.options.scales = { x: { title: { display: true, text: chart.headers[0] || 'X', color: '#94a3b8' }, ticks: axisColor, grid }, y: { title: { display: true, text: chart.headers[1] || 'Y', color: '#94a3b8' }, ticks: axisColor, grid } };
        }
        return cfg;
    }

    // ---------- rendering ----------
    function renderChart() {
        const chart = getActive();
        const canvas = $('cc-canvas');
        const empty = $('cc-empty');
        if (!canvas || !chart) return;
        if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
        const { issues } = validate(chart);
        renderIssues(issues);
        const hasData = chart.rows.some((r) => r.some((v) => String(v).trim() !== ''));
        empty.style.display = hasData ? 'none' : 'flex';
        const meta = $('cc-stage-meta');
        if (meta) meta.textContent = typeInfo(chart.type).label + ' · ' + chart.rows.filter((r) => r.some((v) => String(v).trim() !== '')).length + ' rows';
        canvas.style.display = hasData ? 'block' : 'none';
        if (!hasData || typeof window.Chart !== 'function') return;
        try {
            chartInstance = new window.Chart(canvas.getContext('2d'), buildConfig(chart));
        } catch (e) {
            renderIssues([...issues, 'Chart could not be drawn: ' + e.message]);
        }
    }

    function renderIssues(issues) {
        const box = $('cc-issues');
        if (!box) return;
        box.innerHTML = issues.length
            ? issues.slice(0, 8).map((m) => `<div class="cc-issue"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(m)}</div>`).join('') +
              (issues.length > 8 ? `<div class="cc-issue">…and ${issues.length - 8} more</div>` : '')
            : '';
    }

    function renderDrawer() {
        const list = $('cc-chart-list');
        if (!list) return;
        list.innerHTML = state.charts.map((c) => `
            <div class="cc-chart-item ${c.id === state.activeId ? 'active' : ''}" data-cc-id="${esc(c.id)}">
                <div class="cc-chart-item-main">
                    <div class="cc-chart-item-title">${esc(c.title)}</div>
                    <div class="cc-chart-item-meta">${esc(typeInfo(c.type).label)} · ${c.rows.length} rows</div>
                </div>
            </div>`).join('') || '<div class="cc-muted">No charts yet.</div>';
    }

    function renderSettings() {
        const chart = getActive();
        if (!chart) return;
        $('cc-title').value = chart.title;
        $('cc-type').innerHTML = TYPES.map((t) => `<option value="${t.id}" ${t.id === chart.type ? 'selected' : ''}>${esc(t.label)}</option>`).join('');
        $('cc-legend').checked = !!chart.legend;
        const seriesCount = Math.max(0, chart.headers.length - 1);
        const sw = $('cc-colors');
        sw.innerHTML = '';
        for (let j = 0; j < seriesCount; j++) {
            const wrap = document.createElement('label');
            wrap.className = 'cc-color';
            const input = document.createElement('input');
            input.type = 'color';
            input.value = colorFor(chart, j);
            input.dataset.ccSeries = String(j);
            const span = document.createElement('span');
            span.textContent = chart.headers[j + 1] || 'Series ' + (j + 1);
            wrap.append(input, span);
            sw.appendChild(wrap);
        }
    }

    function renderTable() {
        const chart = getActive();
        const wrap = $('cc-table-wrap');
        if (!chart || !wrap) return;
        const head = chart.headers.map((h, j) => `<th><input class="cc-input cc-head" data-cc-head="${j}" value="${esc(h)}" aria-label="Column ${j + 1} name"></th>`).join('');
        const body = chart.rows.map((r, i) => `<tr>${chart.headers.map((_, j) =>
            `<td><input class="cc-input" data-cc-r="${i}" data-cc-c="${j}" value="${esc(r[j] == null ? '' : r[j])}"></td>`).join('')}
            <td class="cc-rowdel"><button type="button" class="cc-icon-btn" data-cc-delrow="${i}" title="Delete row"><i class="fa-solid fa-xmark"></i></button></td></tr>`).join('');
        wrap.innerHTML = `<table class="cc-table"><thead><tr>${head}<th class="cc-rowdel"></th></tr></thead><tbody>${body}</tbody></table>`;
    }

    function refreshAll() {
        renderDrawer();
        renderSettings();
        renderTable();
        renderChart();
    }

    function touch() { const c = getActive(); if (c) c.updated = new Date().toISOString(); save(); }

    // ---------- actions ----------
    function selectChart(id) { state.activeId = id; save(); refreshAll(); }

    function addChart() {
        const c = newChart('Untitled chart ' + (state.charts.length + 1));
        state.charts.push(c);
        state.activeId = c.id;
        save();
        refreshAll();
    }

    function duplicateChart() {
        const src = getActive();
        if (!src) return;
        const copy = JSON.parse(JSON.stringify(src));
        copy.id = uid();
        copy.title = src.title + ' (copy)';
        copy.created = copy.updated = new Date().toISOString();
        state.charts.push(copy);
        state.activeId = copy.id;
        save();
        refreshAll();
    }

    async function deleteChart() {
        const c = getActive();
        if (!c) return;
        const ok = await window.mantisConfirm({ title: 'Delete chart', message: `Delete "${esc(c.title)}"? This cannot be undone.`, confirmText: 'Delete', danger: true });
        if (!ok) return;
        state.charts = state.charts.filter((x) => x.id !== c.id);
        if (!state.charts.length) { const n = newChart('Untitled chart 1'); state.charts.push(n); }
        state.activeId = state.charts[0].id;
        save();
        refreshAll();
    }

    function setCell(i, j, value) {
        const c = getActive();
        if (!c) return;
        c.rows[i][j] = value;
        touch();
        renderChart();
    }

    function addRow() { const c = getActive(); c.rows.push(c.headers.map(() => '')); touch(); renderTable(); renderChart(); }
    function delRow(i) { const c = getActive(); c.rows.splice(i, 1); touch(); renderTable(); renderChart(); }
    function addCol() {
        const c = getActive();
        c.headers.push('Series ' + c.headers.length);
        c.rows.forEach((r) => r.push(''));
        touch(); renderSettings(); renderTable(); renderChart();
    }
    function delCol() {
        const c = getActive();
        if (c.headers.length <= 2) { toast('A chart needs at least one value column.', true); return; }
        c.headers.pop();
        c.rows.forEach((r) => r.pop());
        touch(); renderSettings(); renderTable(); renderChart();
    }

    // Minimal CSV/TSV parser with quoted-field support. First row is the header row.
    function parseDelimited(text) {
        const firstLine = text.split(/\r?\n/)[0] || '';
        const delim = firstLine.includes('\t') ? '\t' : ',';
        const rows = [];
        let row = [], field = '', inQ = false;
        for (let i = 0; i < text.length; i++) {
            const ch = text[i];
            if (inQ) {
                if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
                else if (ch === '"') inQ = false;
                else field += ch;
            } else if (ch === '"') inQ = true;
            else if (ch === delim) { row.push(field); field = ''; }
            else if (ch === '\n' || ch === '\r') {
                if (ch === '\r' && text[i + 1] === '\n') i++;
                row.push(field); rows.push(row); row = []; field = '';
            } else field += ch;
        }
        if (field !== '' || row.length) { row.push(field); rows.push(row); }
        return rows.filter((r) => r.some((v) => String(v).trim() !== ''));
    }

    function importData() {
        const text = $('cc-import-text').value;
        const parsed = parseDelimited(text);
        if (parsed.length < 2) { toast('Paste a header row plus at least one data row.', true); return; }
        const width = Math.max(...parsed.map((r) => r.length));
        if (width < 2) { toast('Need at least two columns: a label and one value.', true); return; }
        const pad = (r) => Array.from({ length: width }, (_, j) => (r[j] == null ? '' : String(r[j]).trim()));
        const c = getActive();
        c.headers = pad(parsed[0]).map((h, j) => h || (j === 0 ? 'Label' : 'Series ' + j));
        c.rows = parsed.slice(1).map(pad);
        $('cc-import-text').value = '';
        touch();
        refreshAll();
        toast('Data imported.');
    }

    function exportPng() {
        const canvas = $('cc-canvas');
        if (!chartInstance) { toast('Nothing to export yet.', true); return; }
        const out = document.createElement('canvas');
        out.width = canvas.width; out.height = canvas.height;
        const ctx = out.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, out.width, out.height);
        ctx.drawImage(canvas, 0, 0);
        out.toBlob((blob) => {
            if (!blob) { toast('PNG export failed.', true); return; }
            downloadBlob(blob, safeName(getActive().title) + '.png');
            toast('PNG downloaded.');
        }, 'image/png');
    }

    // Prefix cells that spreadsheets would evaluate as formulas.
    function csvCell(v) {
        let s = String(v == null ? '' : v);
        if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
        return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }

    function exportCsv() {
        const c = getActive();
        const lines = [c.headers.map(csvCell).join(',')].concat(c.rows.map((r) => r.map(csvCell).join(',')));
        downloadBlob(new Blob([lines.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' }), safeName(c.title) + '.csv');
        toast('CSV downloaded.');
    }

    function safeName(s) { return (String(s || 'chart').replace(/[^a-z0-9_\- ]+/gi, '').trim() || 'chart').slice(0, 80); }

    function downloadBlob(blob, name) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = name;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // ---------- wiring ----------
    function bindOnce() {
        const pane = $('chart-creator-pane');
        if (!pane || pane.dataset.ccBound) return;
        pane.dataset.ccBound = '1';

        pane.addEventListener('click', (e) => {
            const t = e.target.closest('button, [data-cc-id]');
            if (!t) return;
            if (t.dataset.ccId && !t.closest('button')) { selectChart(t.dataset.ccId); return; }
            const act = t.id;
            const del = t.dataset.ccDelrow;
            if (del !== undefined) return delRow(Number(del));
            if (act === 'cc-new') addChart();
            else if (act === 'cc-dup') duplicateChart();
            else if (act === 'cc-del') deleteChart();
            else if (act === 'cc-add-row') addRow();
            else if (act === 'cc-add-col') addCol();
            else if (act === 'cc-del-col') delCol();
            else if (act === 'cc-import') importData();
            else if (act === 'cc-png') exportPng();
            else if (act === 'cc-csv') exportCsv();
        });

        pane.addEventListener('input', (e) => {
            const el = e.target;
            const c = getActive();
            if (!c) return;
            if (el.dataset.ccR !== undefined) setCell(Number(el.dataset.ccR), Number(el.dataset.ccC), el.value);
            else if (el.dataset.ccHead !== undefined) { c.headers[Number(el.dataset.ccHead)] = el.value; touch(); renderSettings(); renderChart(); }
            else if (el.id === 'cc-title') { c.title = el.value || 'Untitled chart'; touch(); renderDrawer(); renderChart(); }
            else if (el.dataset.ccSeries !== undefined) { c.seriesColors[Number(el.dataset.ccSeries)] = el.value; touch(); renderChart(); }
        });

        pane.addEventListener('change', (e) => {
            const el = e.target;
            const c = getActive();
            if (!c) return;
            if (el.id === 'cc-type') { c.type = el.value; touch(); renderChart(); }
            else if (el.id === 'cc-legend') { c.legend = el.checked; touch(); renderChart(); }
        });
    }

    function initChartCreator() {
        const pane = $('chart-creator-pane');
        if (!pane) return;
        if (!initialized) { load(); initialized = true; }
        if (!pane.dataset.ccRendered) {
            pane.dataset.ccRendered = '1';
            pane.innerHTML = `
                <div class="cc-root">
                    <aside class="cc-drawer">
                        <div class="cc-drawer-head">
                            <span class="cc-eyebrow">Charts</span>
                            <button type="button" id="cc-new" class="cc-btn cc-btn-primary cc-new-btn"><i class="fa-solid fa-plus"></i> New</button>
                        </div>
                        <div id="cc-chart-list" class="cc-chart-list"></div>
                    </aside>
                    <section class="cc-main">
                        <div class="cc-toolbar">
                            <input id="cc-title" class="cc-input cc-title-input" aria-label="Chart title" placeholder="Untitled chart">
                            <div class="cc-toolbar-group">
                                <button type="button" id="cc-dup" class="cc-btn" title="Duplicate chart"><i class="fa-regular fa-copy"></i> Duplicate</button>
                            </div>
                            <span class="cc-toolbar-sep"></span>
                            <div class="cc-toolbar-group">
                                <button type="button" id="cc-png" class="cc-btn" title="Download PNG"><i class="fa-solid fa-image"></i> PNG</button>
                                <button type="button" id="cc-csv" class="cc-btn" title="Download CSV"><i class="fa-solid fa-file-csv"></i> CSV</button>
                            </div>
                            <span class="cc-toolbar-sep"></span>
                            <button type="button" id="cc-del" class="cc-btn cc-btn-danger" title="Delete chart"><i class="fa-regular fa-trash-can"></i></button>
                        </div>
                        <div class="cc-body">
                            <div class="cc-editor">
                                <div class="cc-panel">
                                    <div class="cc-panel-head"><h4>Chart</h4></div>
                                    <label class="cc-field">Type <select id="cc-type" class="cc-input"></select></label>
                                    <label class="cc-check"><input type="checkbox" id="cc-legend"> Show legend</label>
                                    <div class="cc-field" style="margin-top:14px">Series colours <div id="cc-colors" class="cc-colors"></div></div>
                                </div>
                                <div class="cc-panel">
                                    <div class="cc-panel-head"><h4>Data</h4></div>
                                    <div class="cc-table-scroll" id="cc-table-wrap"></div>
                                    <div class="cc-row-btns">
                                        <button type="button" id="cc-add-row" class="cc-btn cc-btn-sm"><i class="fa-solid fa-plus"></i> Row</button>
                                        <button type="button" id="cc-add-col" class="cc-btn cc-btn-sm"><i class="fa-solid fa-plus"></i> Column</button>
                                        <button type="button" id="cc-del-col" class="cc-btn cc-btn-sm"><i class="fa-solid fa-minus"></i> Column</button>
                                    </div>
                                    <details class="cc-import">
                                        <summary>Paste or import CSV / tab-separated data</summary>
                                        <p class="cc-muted">First row = column headers. Replaces the current table.</p>
                                        <textarea id="cc-import-text" class="cc-input" rows="5" placeholder="Label,Count&#10;Phishing,42&#10;Ransomware,17"></textarea>
                                        <button type="button" id="cc-import" class="cc-btn cc-btn-sm"><i class="fa-solid fa-file-import"></i> Import</button>
                                    </details>
                                    <div id="cc-issues"></div>
                                </div>
                            </div>
                            <div class="cc-viewer">
                                <div class="cc-stage">
                                    <div class="cc-stage-head"><span class="cc-eyebrow">Preview</span><span class="cc-stage-meta" id="cc-stage-meta"></span></div>
                                    <div class="cc-canvas-wrap">
                                        <div id="cc-empty" class="cc-empty"><i class="fa-solid fa-chart-simple"></i><strong>No data yet</strong><span>Add rows in the table or paste CSV to see your chart.</span></div>
                                        <canvas id="cc-canvas"></canvas>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>
                </div>`;
            bindOnce();
        }
        refreshAll();
    }

    window.openChartCreator = initChartCreator;
    window.ChartCreator = { types: TYPES, parseDelimited, validate, buildConfig };
})();
