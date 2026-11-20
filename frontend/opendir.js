/**
 * Open Directory Hunting UI. Talks only to /api/opendir/*.
 * Discovered URLs point at hostile infrastructure, so they are rendered as plain text
 * with a copy button and are never turned into clickable links.
 */
(function () {
    const VIEWS = [
        ['overview', 'Overview', 'fa-gauge'],
        ['explorer', 'Directory Explorer', 'fa-folder-tree'],
        ['files', 'File Search', 'fa-magnifying-glass'],
        ['jobs', 'Hunting Jobs', 'fa-bullseye'],
        ['watchlist', 'Watchlist', 'fa-eye'],
        ['settings', 'Settings', 'fa-sliders'],
    ];
    const state = {
        view: 'overview', error: '', busy: false, detailId: null, detail: null,
        providers: null, overview: null, dirs: null, files: null, jobs: null, watch: null,
        scoring: null, activeJob: null,
        dirFilter: { status: 'verified', classification: '', min_score: 0, host: '' },
        fileFilter: { name: '', extension: '', min_score: 0 },
        jobForm: { mode: 'global', query: '', providers: [], country: '', max_depth: '', max_dirs: '' },
        notice: '',
    };
    let pollTimer = null;

    const pane = () => document.getElementById('opendir-pane');
    const esc = v => escapeHtml(String(v == null ? '' : v));

    async function api(path, opts) {
        const res = await fetch('/api/opendir' + path, opts);
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            const d = data.detail;
            throw new Error(typeof d === 'string' ? d : (Array.isArray(d) ? d.map(x => x.msg).join('; ') : `Request failed (${res.status})`));
        }
        return data;
    }
    const send = (path, method, body) => api(path, {
        method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined,
    });
    const qs = obj => {
        const p = new URLSearchParams();
        Object.entries(obj).forEach(([k, v]) => { if (v !== '' && v != null && v !== 0) p.set(k, v); });
        const s = p.toString();
        return s ? '?' + s : '';
    };

    function fmtSize(n) {
        if (n == null) return '';
        const u = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0, v = Number(n);
        while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
        return (i ? v.toFixed(1) : v) + ' ' + u[i];
    }
    const fmtTs = s => (s ? esc(String(s).replace('T', ' ').replace(/\.\d+/, '').replace('+00:00', 'Z')) : '');

    function badge(cls) {
        const c = cls || 'low';
        return `<span class="od-badge od-${esc(c)}">${esc(c)}</span>`;
    }
    function score(n, cls) {
        return `<span class="od-score od-${esc(cls || 'low')}">${esc(n)}</span>`;
    }
    function copyBtn(text) {
        return `<button type="button" class="od-copy" data-od-copy="${esc(text)}" title="Copy URL"><i class="fa-regular fa-copy"></i></button>`;
    }
    function urlText(url) {
        return `<span class="od-url">${esc(url)}</span>${copyBtn(url)}`;
    }

    // ----------------------------------------------------------------- views
    function overviewView() {
        const o = state.overview;
        if (!o) return '<p class="od-muted">Loading…</p>';
        const d = o.directories || {};
        const c = o.verified_by_class || {};
        const jobs = o.jobs || {};
        const total = Object.values(d).reduce((a, b) => a + b, 0);
        const tile = (label, val) => `<div class="od-tile"><b>${esc(val)}</b><span>${esc(label)}</span></div>`;
        const top = (o.top_directories || []).map(r => `
            <tr data-od-open="${r.id}"><td>${score(r.interest_score, r.interest_class)}</td>
            <td>${urlText(r.url)}</td><td class="od-num">${esc(r.file_count)}</td><td>${fmtTs(r.last_seen)}</td></tr>`).join('');
        const noProv = state.providers && !state.providers.some(p => p.status === 'ready');
        return `
            ${noProv ? `<div class="od-warn"><i class="fa-solid fa-triangle-exclamation"></i>
                No discovery provider is ready. Global and keyword hunts need a FOFA, ZoomEye, Shodan or Censys key in Settings → API keys.
                Targeted hunts of a known URL still work.</div>` : ''}
            <div class="od-tiles">
                ${tile('Directories tracked', total)}
                ${tile('Verified', d.verified || 0)}
                ${tile('High interest', c.high || 0)}
                ${tile('Medium interest', c.medium || 0)}
                ${tile('Files indexed', o.active_files || 0)}
                ${tile('Watching', o.watchlist_enabled || 0)}
                ${tile('Jobs running', (jobs.running || 0) + (jobs.queued || 0))}
            </div>
            <h4>Top directories by interest score</h4>
            ${top ? `<div class="od-table-wrap"><table class="od-table"><thead><tr><th>Score</th><th>Directory</th><th class="od-num">Files</th><th>Last seen</th></tr></thead><tbody>${top}</tbody></table></div>`
                  : '<p class="od-muted">No verified directories yet. Start a hunt from Hunting Jobs.</p>'}`;
    }

    function explorerView() {
        const f = state.dirFilter;
        const sel = (name, opts, val) => `<select class="od-input" data-od-dirf="${name}">${opts.map(([v, l]) =>
            `<option value="${v}" ${String(val) === String(v) ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
        const items = (state.dirs && state.dirs.items) || [];
        const rows = items.map(r => `
            <tr data-od-open="${r.id}">
                <td>${score(r.interest_score, r.effective_class)}</td>
                <td>${urlText(r.url)}</td>
                <td>${esc(r.listing_type || '')}</td>
                <td>${esc(r.server || '')}</td>
                <td class="od-num">${esc(r.file_count)}</td>
                <td><span class="od-status od-st-${esc(r.status)}">${esc(r.status)}</span>${r.override ? ` <span class="od-tag">${esc(r.override.replace('_', ' '))}</span>` : ''}</td>
                <td>${fmtTs(r.last_seen)}</td></tr>`).join('');
        return `
            <div class="od-filters">
                ${sel('status', [['', 'Any status'], ['verified', 'Verified'], ['discovered', 'Discovered'], ['rejected', 'Rejected'], ['inaccessible', 'Inaccessible'], ['error', 'Error']], f.status)}
                ${sel('classification', [['', 'Any class'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']], f.classification)}
                <input class="od-input" data-od-dirf="min_score" type="number" min="0" max="100" placeholder="Min score" value="${f.min_score || ''}">
                <input class="od-input" data-od-dirf="host" placeholder="Host contains…" value="${esc(f.host)}">
                <button type="button" class="od-btn" data-od-act="dirs-load">Apply</button>
                <span class="od-muted">${state.dirs ? state.dirs.total : 0} matching${state.dirs && state.dirs.total > items.length ? ` (showing ${items.length})` : ''}</span>
            </div>
            <details class="dc-panel od-score-hist" id="od-score-hist" ${state.histOpen ? 'open' : ''}>
                <summary><b>Score distribution</b> <span class="od-muted">verified directories by interest score</span></summary>
                <div class="dc-chart dc-short" id="od-score-hist-chart"></div>
                <div class="dc-note" id="od-score-hist-note"></div>
            </details>
            ${rows ? `<div class="od-table-wrap"><table class="od-table"><thead><tr><th>Score</th><th>Directory</th><th>Listing</th><th>Server</th><th class="od-num">Files</th><th>Status</th><th>Last seen</th></tr></thead><tbody>${rows}</tbody></table></div>`
                   : '<p class="od-muted">No directories match these filters.</p>'}`;
    }

    async function loadScoreHistogram() {
        const box = document.getElementById('od-score-hist-chart');
        if (!box || !window.MantisCharts) return;
        const det = document.getElementById('od-score-hist');
        if (det && !det.dataset.wired) {
            det.dataset.wired = '1';
            det.addEventListener('toggle', () => { state.histOpen = det.open; if (det.open) loadScoreHistogram(); });
        }
        if (det && !det.open) return;
        try {
            const h = await api('/score-histogram');
            const note = document.getElementById('od-score-hist-note');
            if (note) note.textContent = `${h.total} verified · ${h.above_threshold} above the score-10 threshold (explorer lists only these)`;
            window.MantisCharts.bar(box, {
                labels: h.buckets.map(b => b.label),
                datasets: [{ label: 'Directories', data: h.buckets.map(b => b.count) }],
                emptyText: 'No verified directories scored yet.',
            });
        } catch (e) {
            box.innerHTML = `<div class="dc-empty">Score distribution unavailable: ${esc(e.message || e)}</div>`;
        }
    }

    function filesView() {
        const f = state.fileFilter;
        const items = (state.files && state.files.items) || [];
        const rows = items.map(r => `
            <tr data-od-open="${r.directory_id}">
                <td>${score(r.interest_score, r.interest_class)}</td>
                <td class="od-fname">${esc(r.name)}</td>
                <td>${esc(r.extension)}</td>
                <td class="od-num">${esc(fmtSize(r.size))}</td>
                <td>${fmtTs(r.modified_at)}</td>
                <td>${esc(r.host)}</td>
                <td>${copyBtn(r.url)}</td></tr>`).join('');
        return `
            <div class="od-filters">
                <input class="od-input" data-od-filef="name" placeholder="File name contains…" value="${esc(f.name)}">
                <input class="od-input" data-od-filef="extension" placeholder="Extension (exe)" value="${esc(f.extension)}">
                <input class="od-input" data-od-filef="min_score" type="number" min="0" max="100" placeholder="Min dir score" value="${f.min_score || ''}">
                <button type="button" class="od-btn" data-od-act="files-load">Search</button>
                <span class="od-muted">${state.files ? state.files.total : 0} files${state.files && state.files.total > items.length ? ` (showing ${items.length})` : ''}</span>
            </div>
            ${rows ? `<div class="od-table-wrap"><table class="od-table"><thead><tr><th>Dir score</th><th>Name</th><th>Ext</th><th class="od-num">Size</th><th>Modified</th><th>Host</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
                   : '<p class="od-muted">No files indexed match. Files appear after a hunt enumerates a verified directory.</p>'}`;
    }

    function jobFormView() {
        const j = state.jobForm;
        const ready = (state.providers || []).filter(p => p.status === 'ready');
        const provBoxes = (state.providers || []).map(p => {
            const ok = p.status === 'ready';
            const why = p.status === 'missing_key' ? 'no key' : (p.status === 'missing_config' ? 'Censys org ID not configured' : p.status);
            return `<label class="od-check ${ok ? '' : 'od-disabled'}"><input type="checkbox" data-od-prov="${esc(p.provider)}"
                ${ok ? '' : 'disabled'} ${j.providers.includes(p.provider) ? 'checked' : ''}> ${esc(p.label)}${ok ? '' : ` <i class="od-muted">(${esc(why)})</i>`}</label>`;
        }).join('');
        const needsProv = j.mode !== 'targeted';
        const queryLabel = { global: 'Query (optional — leave empty for built-in open-directory patterns)', targeted: 'Directory URL', keyword: 'Keyword (file or directory name)' }[j.mode];
        return `
            <div class="od-card">
                <h4>New hunt</h4>
                <div class="od-seg">${['global', 'targeted', 'keyword'].map(m =>
                    `<button type="button" class="${j.mode === m ? 'active' : ''}" data-od-mode="${m}">${m[0].toUpperCase() + m.slice(1)}</button>`).join('')}</div>
                <label class="od-lbl">${queryLabel}
                    <input class="od-input od-wide" data-od-jf="query" value="${esc(j.query)}" placeholder="${j.mode === 'targeted' ? 'http://203.0.113.5:8080/files/' : (j.mode === 'keyword' ? 'loader.exe' : '')}"></label>
                ${needsProv ? `<div class="od-lbl">Providers<div class="od-checks">${provBoxes}</div>
                    ${ready.length ? '' : '<span class="od-muted">No provider is ready.</span>'}</div>
                    <label class="od-lbl">Country (optional, 2-letter)
                        <input class="od-input" data-od-jf="country" maxlength="2" value="${esc(j.country)}" style="width:80px"></label>` : ''}
                <div class="od-row">
                    <label class="od-lbl">Max depth <input class="od-input" data-od-jf="max_depth" type="number" min="0" max="6" value="${esc(j.max_depth)}" style="width:80px" placeholder="default"></label>
                    <label class="od-lbl">Max directories <input class="od-input" data-od-jf="max_dirs" type="number" min="1" max="500" value="${esc(j.max_dirs)}" style="width:100px" placeholder="default"></label>
                </div>
                <button type="button" class="od-btn od-primary" data-od-act="job-start" ${state.busy ? 'disabled' : ''}><i class="fa-solid fa-play"></i> Start hunt</button>
            </div>`;
    }

    function jobsView() {
        const items = (state.jobs && state.jobs.items) || [];
        const rows = items.map(r => `
            <tr data-od-job="${esc(r.id)}">
                <td><span class="od-status od-st-${esc(r.status)}">${esc(r.status)}</span></td>
                <td>${esc(r.mode)}</td>
                <td class="od-trunc">${esc(r.query || '—')}</td>
                <td>${esc((r.providers || []).join(', ') || '—')}</td>
                <td>${esc(r.stage || '')}</td>
                <td class="od-muted">${esc(Object.entries(r.counters || {}).map(([k, v]) => `${k}:${v}`).join(' '))}</td>
                <td>${fmtTs(r.created_at)}</td></tr>`).join('');
        const aj = state.activeJob;
        const active = aj ? `
            <div class="od-card">
                <div class="od-row od-between"><h4>Job ${esc(aj.id.slice(0, 8))} · <span class="od-status od-st-${esc(aj.status)}">${esc(aj.status)}</span> · ${esc(aj.stage || '')}</h4>
                    <span>${['queued', 'running'].includes(aj.status) ? `<button type="button" class="od-btn" data-od-act="job-cancel" data-od-id="${esc(aj.id)}">Cancel</button>` : ''}
                    <button type="button" class="od-btn" data-od-act="job-close">Close</button></span></div>
                ${aj.error ? `<div class="od-warn">${esc(aj.error)}</div>` : ''}
                <div class="od-muted">${esc(Object.entries(aj.counters || {}).map(([k, v]) => `${k}: ${v}`).join(' · ') || 'no counters yet')}</div>
                <ul class="od-events">${(aj.events || []).map(e => `<li class="od-ev-${esc(e.level)}"><span class="od-muted">${fmtTs(e.ts)}</span> ${esc(e.message)}</li>`).join('') || '<li class="od-muted">No events yet.</li>'}</ul>
            </div>` : '';
        return `${jobFormView()}${active}
            <h4>Recent jobs</h4>
            ${rows ? `<div class="od-table-wrap"><table class="od-table"><thead><tr><th>Status</th><th>Mode</th><th>Query</th><th>Providers</th><th>Stage</th><th>Counters</th><th>Created</th></tr></thead><tbody>${rows}</tbody></table></div>`
                   : '<p class="od-muted">No jobs yet.</p>'}`;
    }

    function watchlistView() {
        const items = (state.watch && state.watch.items) || [];
        const rows = items.map(r => `
            <tr data-od-open="${r.directory_id}">
                <td>${score(r.interest_score, r.interest_class)}</td>
                <td>${urlText(r.url)}</td>
                <td>${r.enabled ? 'enabled' : 'paused'}</td>
                <td class="od-num">${Math.round(r.interval_minutes / 60)} h</td>
                <td>${fmtTs(r.last_scan_at)}</td>
                <td>${fmtTs(r.next_scan_at)}</td>
                <td><button type="button" class="od-btn" data-od-act="unwatch" data-od-id="${r.directory_id}">Remove</button></td></tr>`).join('');
        return rows ? `<div class="od-table-wrap"><table class="od-table"><thead><tr><th>Score</th><th>Directory</th><th>State</th><th class="od-num">Every</th><th>Last scan</th><th>Next scan</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
                    : '<p class="od-muted">Nothing is watched. Open a directory and choose “Watch” to rescan it on a schedule and record added, removed and changed files.</p>';
    }

    function settingsView() {
        const provs = (state.providers || []).map(p => `<tr><td>${esc(p.label)}</td>
            <td><span class="od-status od-st-${p.status === 'ready' ? 'completed' : 'error'}">${esc(p.status)}</span></td>
            <td>${esc(p.key_source || '—')}</td><td>${p.country_filter ? 'yes' : 'no'}</td><td class="od-num">${esc(p.max_page_size)}</td></tr>`).join('');
        const s = state.scoring;
        let scoring = '<p class="od-muted">Loading…</p>';
        if (s) {
            const w = Object.entries(s.weights || {}).map(([k, v]) => `<tr><td>${esc(k.replace(/_/g, ' '))}</td><td class="od-num">+${esc(v)}</td></tr>`).join('');
            const cats = Object.entries(s.categories || {}).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc((v || []).join(' '))}</td></tr>`).join('');
            scoring = `<div class="od-two">
                <div><h4>Weights (score capped at 100)</h4><table class="od-table"><tbody>${w}</tbody></table>
                <p class="od-muted">High ≥ ${esc(s.thresholds && s.thresholds.high)} · Medium ≥ ${esc(s.thresholds && s.thresholds.medium)}</p></div>
                <div><h4>File categories</h4><table class="od-table"><tbody>${cats}</tbody></table>
                <h4>Suspicious name patterns</h4><p class="od-pats">${(s.name_patterns || []).map(p => `<span class="od-tag">${esc(p)}</span>`).join(' ')}</p></div></div>`;
        }
        return `
            <h4>Discovery providers</h4>
            <div class="od-table-wrap"><table class="od-table"><thead><tr><th>Provider</th><th>Status</th><th>Key source</th><th>Country filter</th><th class="od-num">Page size</th></tr></thead><tbody>${provs}</tbody></table></div>
            <p class="od-muted">Provider keys are managed under Settings → API keys (FOFA, ZoomEye, Shodan, Censys). A server environment key is used when you have not saved your own. Censys also needs its organization ID in the server environment.</p>
            <h4>Interest scoring</h4>
            <p class="od-muted">Read-only. The scoring rules are applied server-side; every directory lists the rules that fired. Analysts can override a directory’s class from its detail view.</p>
            ${scoring}`;
    }

    function detailView() {
        const d = state.detail;
        if (!d) return '<p class="od-muted">Loading…</p>';
        const dir = d.directory;
        const reasons = (dir.interest_reasons || []).map(r => `<li><b>+${esc(r.points)}</b> ${esc(r.label)}</li>`).join('') || '<li class="od-muted">No scoring rules fired.</li>';
        const files = (d.files || []).map(f => `<tr class="${f.removed_at ? 'od-removed' : ''}">
            <td>${f.is_dir ? '<i class="fa-regular fa-folder"></i> ' : ''}<span class="od-fname">${esc(f.name)}</span></td><td>${esc(f.extension)}</td>
            <td class="od-num">${esc(fmtSize(f.size))}</td><td>${fmtTs(f.modified_at)}</td><td>${fmtTs(f.first_seen)}</td><td>${f.removed_at ? 'removed ' + fmtTs(f.removed_at) : ''}</td><td>${copyBtn(f.url)}</td></tr>`).join('');
        const src = (d.sources || []).map(s => `<li>${esc(s.provider)} · ${esc(s.source_kind)} · <span class="od-muted">${esc(s.query || '')} · ${fmtTs(s.discovered_at)}</span></li>`).join('') || '<li class="od-muted">None.</li>';
        const changes = (d.changes || []).map(c => `<tr><td>${fmtTs(c.detected_at)}</td><td>${esc(c.change_type)}</td><td class="od-fname">${esc(c.subject)}</td><td class="od-muted">${esc([c.old_value, c.new_value].filter(Boolean).join(' → '))}</td></tr>`).join('');
        const watched = !!d.watch;
        return `
            <button type="button" class="od-back" data-od-act="back">← Back</button>
            <div class="od-row od-between">
                <h3 class="od-dtitle">${urlText(dir.url)}</h3>
                <span>${score(dir.interest_score, dir.effective_class)} ${badge(dir.effective_class)}</span>
            </div>
            <div class="od-meta">
                <span>Status <b>${esc(dir.status)}</b></span><span>Listing <b>${esc(dir.listing_type || '—')}</b> (${esc(dir.listing_confidence == null ? '—' : dir.listing_confidence)}%)</span>
                <span>Server <b>${esc(dir.server || '—')}</b></span><span>IP <b>${esc(dir.ip || '—')}</b></span>
                <span>Files <b>${esc(dir.file_count)}</b></span><span>Subdirs <b>${esc(dir.subdir_count)}</b></span>
                <span>First seen <b>${fmtTs(dir.first_seen)}</b></span><span>Last checked <b>${fmtTs(dir.last_checked)}</b></span>
            </div>
            ${dir.error ? `<div class="od-warn">${esc(dir.error)}</div>` : ''}
            <div class="od-actions">
                <button type="button" class="od-btn" data-od-act="${watched ? 'unwatch' : 'watch'}" data-od-id="${dir.id}">${watched ? 'Stop watching' : 'Watch (daily rescan)'}</button>
                <button type="button" class="od-btn" data-od-act="override" data-od-id="${dir.id}" data-od-val="confirmed_interest" ${dir.override === 'confirmed_interest' ? 'disabled' : ''}>Mark confirmed</button>
                <button type="button" class="od-btn" data-od-act="override" data-od-id="${dir.id}" data-od-val="false_positive" ${dir.override === 'false_positive' ? 'disabled' : ''}>Mark false positive</button>
                ${dir.override ? `<button type="button" class="od-btn" data-od-act="override" data-od-id="${dir.id}" data-od-val="">Clear override</button>` : ''}
            </div>
            <div class="od-two">
                <div><h4>Why this score</h4><ul class="od-list">${reasons}</ul></div>
                <div><h4>Discovered via</h4><ul class="od-list">${src}</ul></div>
            </div>
            <h4>Files (${esc(d.files_total == null ? (d.files || []).length : d.files_total)})</h4>
            ${files ? `<div class="od-table-wrap"><table class="od-table"><thead><tr><th>Name</th><th>Ext</th><th class="od-num">Size</th><th>Modified</th><th>First seen</th><th></th><th></th></tr></thead><tbody>${files}</tbody></table></div>` : '<p class="od-muted">No files recorded.</p>'}
            <h4>Changes</h4>
            ${changes ? `<div class="od-table-wrap"><table class="od-table"><thead><tr><th>When</th><th>Type</th><th>Item</th><th>Detail</th></tr></thead><tbody>${changes}</tbody></table></div>`
                      : '<p class="od-muted">No changes recorded. Watch this directory to track changes between scans.</p>'}`;
    }

    // ----------------------------------------------------------------- render
    function render() {
        const el = pane();
        if (!el) return;
        const keepScroll = el.scrollTop;
        const focus = document.activeElement;
        const fid = focus && focus.dataset ? (focus.dataset.odJf || focus.dataset.odDirf || focus.dataset.odFilef) : null;
        let body;
        if (state.detailId != null) body = detailView();
        else body = ({ overview: overviewView, explorer: explorerView, files: filesView, jobs: jobsView, watchlist: watchlistView, settings: settingsView })[state.view]();
        const nav = state.detailId != null ? '' : `<div class="od-tabs">${VIEWS.map(([k, l, i]) =>
            `<button type="button" class="${state.view === k ? 'active' : ''}" data-od-view="${k}"><i class="fa-solid ${i}"></i> ${l}</button>`).join('')}</div>`;
        el.innerHTML = `<div class="od-wrap">
            <div class="od-header"><div><h2 class="od-title">Open Directory Hunting</h2>
                <p class="od-sub">Find, verify and track exposed web directory listings. Discovered URLs are untrusted: nothing here fetches or opens a file.</p></div></div>
            ${nav}
            ${state.notice ? `<div class="od-note">${esc(state.notice)}</div>` : ''}
            ${state.error ? `<div class="od-warn">${esc(state.error)}</div>` : ''}
            ${body}</div>`;
        el.scrollTop = keepScroll;
        if (fid) {
            const sel = `[data-od-jf="${fid}"],[data-od-dirf="${fid}"],[data-od-filef="${fid}"]`;
            const n = el.querySelector(sel);
            if (n && n !== document.activeElement) { n.focus(); try { n.setSelectionRange(n.value.length, n.value.length); } catch (_) { /* number input */ } }
        }
    }

    // ----------------------------------------------------------------- data
    async function guard(fn) {
        state.error = '';
        try { await fn(); } catch (e) { state.error = e.message || String(e); }
        render();
    }
    const loadProviders = async () => { state.providers = (await api('/status')).providers; };
    const loadOverview = async () => { state.overview = await api('/overview'); };
    const loadDirs = async () => { state.dirs = await api('/directories' + qs({ ...state.dirFilter, limit: 200 })); };
    const loadFiles = async () => { state.files = await api('/files' + qs({ ...state.fileFilter, limit: 300 })); };
    const loadJobs = async () => { state.jobs = await api('/jobs'); };
    const loadWatch = async () => { state.watch = await api('/watchlist'); };
    const loadScoring = async () => { state.scoring = await api('/settings/scoring'); };

    async function loadView() {
        const v = state.view;
        await loadProviders().catch(() => { /* shown by the view that needs it */ });
        if (v === 'overview') await loadOverview();
        else if (v === 'explorer') { await loadDirs(); loadScoreHistogram(); }
        else if (v === 'files') await loadFiles();
        else if (v === 'jobs') { await loadJobs(); startPolling(); }
        else if (v === 'watchlist') await loadWatch();
        else if (v === 'settings') await loadScoring();
    }

    async function openDirectory(id) {
        state.detailId = id; state.detail = null; render();
        const [d, files, changes] = await Promise.all([
            api('/directories/' + id), api(`/directories/${id}/files?limit=500&include_removed=true`), api(`/directories/${id}/changes?limit=100`),
        ]);
        state.detail = { ...d, files: files.items, files_total: files.total, changes: changes.items };
    }

    async function openJob(id) {
        state.activeJob = await api('/jobs/' + id);
        startPolling();
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(async () => {
            const p = pane();
            if (!p || p.style.display === 'none' || state.view !== 'jobs' || state.detailId != null) return stopPolling();
            const active = state.activeJob && ['queued', 'running'].includes(state.activeJob.status);
            const anyRunning = state.jobs && state.jobs.items.some(j => ['queued', 'running'].includes(j.status));
            if (!active && !anyRunning) return stopPolling();
            try {
                await loadJobs();
                if (state.activeJob) state.activeJob = await api('/jobs/' + state.activeJob.id);
                render();
            } catch (_) { /* transient; next tick retries */ }
        }, 3000);
    }
    function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

    async function startJob() {
        const j = state.jobForm;
        const body = { mode: j.mode, query: j.query.trim(), providers: j.mode === 'targeted' ? [] : j.providers };
        if (j.mode === 'targeted' && !body.query) throw new Error('Enter the directory URL to hunt.');
        if (j.mode === 'keyword' && !body.query) throw new Error('Enter a keyword.');
        if (j.mode !== 'targeted' && !body.providers.length) throw new Error('Select at least one ready provider.');
        if (j.country.trim()) body.country = j.country.trim().toUpperCase();
        if (j.max_depth !== '') body.max_depth = Number(j.max_depth);
        if (j.max_dirs !== '') body.max_dirs = Number(j.max_dirs);
        state.busy = true; render();
        try {
            const out = await send('/jobs', 'POST', body);
            state.notice = out.deduplicated ? 'An identical hunt is already running; showing it.' : 'Hunt started.';
            await loadJobs();
            await openJob(out.id);
        } finally { state.busy = false; }
    }

    // ----------------------------------------------------------------- events
    function bind() {
        const el = pane();
        if (!el || el.dataset.odBound) return;
        el.dataset.odBound = '1';
        el.addEventListener('click', e => {
            const t = e.target.closest('[data-od-view],[data-od-act],[data-od-copy],[data-od-open],[data-od-job],[data-od-mode]');
            if (!t) return;
            if (t.dataset.odCopy != null) {
                e.stopPropagation();
                navigator.clipboard && navigator.clipboard.writeText(t.dataset.odCopy).then(() => { t.classList.add('done'); setTimeout(() => t.classList.remove('done'), 900); });
                return;
            }
            if (t.dataset.odView) { state.view = t.dataset.odView; state.notice = ''; stopPolling(); guard(loadView); return; }
            if (t.dataset.odMode) { state.jobForm.mode = t.dataset.odMode; state.jobForm.query = ''; render(); return; }
            if (t.dataset.odOpen && !t.dataset.odAct) { state.notice = ''; guard(() => openDirectory(Number(t.dataset.odOpen))); return; }
            if (t.dataset.odJob) { guard(() => openJob(t.dataset.odJob)); return; }
            const id = t.dataset.odId, act = t.dataset.odAct;
            if (act === 'back') { state.detailId = null; state.detail = null; guard(loadView); }
            else if (act === 'dirs-load') guard(loadDirs);
            else if (act === 'files-load') guard(loadFiles);
            else if (act === 'job-start') guard(startJob);
            else if (act === 'job-close') { state.activeJob = null; render(); }
            else if (act === 'job-cancel') guard(async () => { await send(`/jobs/${id}/cancel`, 'POST'); await openJob(id); await loadJobs(); });
            else if (act === 'watch') guard(async () => { await send(`/directories/${id}/watch`, 'POST', { interval_minutes: 1440, enabled: true }); state.notice = 'Watching; first rescan runs shortly.'; await openDirectory(Number(id)); });
            else if (act === 'unwatch') guard(async () => {
                await send(`/directories/${id}/watch`, 'DELETE');
                if (state.detailId != null) await openDirectory(Number(id)); else await loadWatch();
            });
            else if (act === 'override') guard(async () => { await send(`/directories/${id}/override`, 'POST', { override: t.dataset.odVal || null }); await openDirectory(Number(id)); });
        });
        el.addEventListener('input', e => {
            const t = e.target;
            if (t.dataset.odJf) state.jobForm[t.dataset.odJf] = t.value;
            else if (t.dataset.odDirf) state.dirFilter[t.dataset.odDirf] = t.value;
            else if (t.dataset.odFilef) state.fileFilter[t.dataset.odFilef] = t.value;
        });
        el.addEventListener('change', e => {
            const t = e.target;
            if (t.dataset.odProv) {
                const set = new Set(state.jobForm.providers);
                t.checked ? set.add(t.dataset.odProv) : set.delete(t.dataset.odProv);
                state.jobForm.providers = [...set];
            } else if (t.dataset.odDirf && t.tagName === 'SELECT') { state.dirFilter[t.dataset.odDirf] = t.value; guard(loadDirs); }
        });
        el.addEventListener('keydown', e => {
            if (e.key !== 'Enter') return;
            const t = e.target;
            if (t.dataset.odDirf) guard(loadDirs);
            else if (t.dataset.odFilef) guard(loadFiles);
            else if (t.dataset.odJf) guard(startJob);
        });
    }

    async function init() {
        bind();
        stopPolling();
        render();
        await guard(loadView);
    }
    window.initOpenDir = init;
})();
