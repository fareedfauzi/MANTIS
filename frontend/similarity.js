(function () {
    const API = window.location.protocol === 'file:' ? 'http://127.0.0.1:9999' : window.location.origin;
    const TABS = [
        ['similarity-dashboard', 'Overview', 'fa-chart-line'],
        ['similarity-entities', 'Families', 'fa-layer-group'],
        ['similarity-compare', 'Compare', 'fa-scale-balanced'],
    ];
    let activeTab = 'similarity-dashboard';
    let openFamilyId = null;

    const $ = (id) => document.getElementById(id);
    const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
    const pct = (value) => `${Math.round(Number(value || 0))}%`;
    const when = (iso) => {
        if (!iso) return '';
        const d = new Date(iso);
        return Number.isNaN(d.getTime()) ? esc(iso) : d.toLocaleString();
    };

    function notify(message) {
        if (typeof window.showNotification === 'function') window.showNotification(message);
    }

    async function api(path, options = {}) {
        const init = { ...options, headers: { ...(options.headers || {}) } };
        if (options.body && !(options.body instanceof FormData)) {
            init.headers['Content-Type'] = 'application/json';
            init.body = JSON.stringify(options.body);
        }
        const res = await fetch(`${API}${path}`, { credentials: 'include', ...init });
        const text = await res.text();
        let data = {};
        try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { detail: text }; }
        if (!res.ok) {
            const detail = Array.isArray(data.detail) ? data.detail.map(d => d.msg).join('; ') : data.detail;
            throw new Error(detail || `Request failed (${res.status})`);
        }
        return data;
    }

    // Poll a background ingest/compare job until it finishes.
    async function waitForJob(jobId, onTick) {
        for (;;) {
            const job = await api(`/api/similarity/jobs/${encodeURIComponent(jobId)}`);
            if (onTick) onTick(job);
            if (job.status === 'done' || job.status === 'error') return job;
            await new Promise(r => setTimeout(r, 800));
        }
    }

    function setPane(html) {
        const pane = $('similarity-pane');
        if (pane) pane.innerHTML = html;
    }

    function shell(body) {
        const tabs = TABS.map(([id, label, icon]) => `
            <button class="sim-tab ${id === activeTab ? 'active' : ''}" data-sim-tab="${id}">
                <i class="fa-solid ${icon}"></i> ${label}
            </button>`).join('');
        return `
            <div class="sim-shell">
                <header class="sim-head">
                    <div>
                        <h1><i class="fa-solid fa-fingerprint"></i> Sample Similarity</h1>
                        <p>Compare new samples against malware family profiles built from features. Uploaded files are analysed and deleted; only extracted features are stored.</p>
                    </div>
                    <nav class="sim-tabs">${tabs}</nav>
                </header>
                ${body}
            </div>`;
    }

    const LABEL_CLASS = {
        'VERY STRONG': 'hi', 'STRONG': 'hi', 'LIKELY': 'mid', 'WEAK': 'low',
        'NO MATCH': 'none', 'INSUFFICIENT EVIDENCE': 'none',
    };
    const labelBadge = (label) => `<span class="sim-badge ${LABEL_CLASS[label] || 'none'}">${esc(label || 'NO MATCH')}</span>`;

    const STATUS_TEXT = {
        EMPTY: 'No samples',
        SINGLE: 'Single sample: capped at WEAK',
        PROVISIONAL: 'Provisional: 2 samples, capped at LIKELY',
        DEVELOPING: 'Developing profile',
        ESTABLISHED: 'Established profile',
    };

    // ---------- Overview ----------
    async function renderDashboard() {
        const d = await api('/api/similarity/dashboard');
        const cards = [
            ['Families', d.families],
            ['Stored samples', d.samples],
            ['Comparisons', d.comparisons],
            ['Stored data', `${(Number(d.stored_bytes || 0) / 1024).toFixed(0)} KB`],
        ].map(([k, v]) => `<div class="sim-stat"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('');
        const weights = Object.entries(d.weights || {}).map(([k, v]) =>
            `<li><span>${esc(k.replace(/_/g, ' '))}</span><span class="sim-bar"><i style="width:${v}%"></i></span><b>${v}</b></li>`).join('');
        const recent = (d.recent_comparisons || []).map(c => `
            <li class="sim-row" data-sim-comparison="${esc(c.id)}">
                <span class="sim-row-main">${esc(c.file_name)}</span>
                ${labelBadge(c.best_label)}
                <span class="sim-muted">${when(c.created_at)}</span>
            </li>`).join('');
        setPane(shell(`
            <section class="sim-grid-stats">${cards}</section>
            <section class="sim-two">
                <div class="sim-card">
                    <h2>Scoring weights</h2>
                    <p class="sim-muted">Fixed. A feature that cannot be analysed contributes 0 and is shown as not analysed, instead of re-weighting the others.</p>
                    <ul class="sim-weights">${weights}</ul>
                </div>
                <div class="sim-card">
                    <h2>Recent comparisons</h2>
                    ${recent ? `<ul class="sim-list">${recent}</ul>` : '<p class="sim-muted">No comparisons yet. Run one from the Compare tab.</p>'}
                </div>
            </section>`));
    }

    // ---------- Families ----------
    async function renderFamilies() {
        const data = await api('/api/similarity/families');
        const rows = (data.families || []).map(f => `
            <li class="sim-row" data-sim-family="${esc(f.id)}">
                <span class="sim-row-main"><strong>${esc(f.name)}</strong><small class="sim-muted">${esc(f.description || '')}</small></span>
                <span class="sim-muted">${esc(f.sample_count)} sample(s)</span>
                <span class="sim-status sim-status-${esc(String(f.status || '').toLowerCase())}">${esc(STATUS_TEXT[f.status] || f.status || '')}</span>
            </li>`).join('');
        setPane(shell(`
            <section class="sim-two">
                <div class="sim-card">
                    <h2>New family</h2>
                    <form id="sim-new-family" class="sim-form">
                        <label>Name <input name="name" maxlength="120" required placeholder="e.g. CobaltLoader"></label>
                        <label>Description <input name="description" maxlength="500" placeholder="Optional"></label>
                        <button class="sim-btn primary" type="submit"><i class="fa-solid fa-plus"></i> Create family</button>
                    </form>
                </div>
                <div class="sim-card">
                    <h2>Families</h2>
                    ${rows ? `<ul class="sim-list">${rows}</ul>` : '<p class="sim-muted">No families yet. Create one, then add its samples.</p>'}
                </div>
            </section>
            <section id="sim-family-detail"></section>`));
        $('sim-new-family')?.addEventListener('submit', createFamily);
        if (openFamilyId) await renderFamilyDetail(openFamilyId);
    }

    async function createFamily(e) {
        e.preventDefault();
        const form = new FormData(e.target);
        try {
            const fam = await api('/api/similarity/families', { method: 'POST', body: { name: form.get('name'), description: form.get('description') || '' } });
            notify(`Family "${fam.name}" created`);
            openFamilyId = fam.id;
            await renderFamilies();
        } catch (err) {
            notify(err.message);
        }
    }

    async function renderFamilyDetail(id) {
        const box = $('sim-family-detail');
        if (!box) return;
        const f = await api(`/api/similarity/families/${encodeURIComponent(id)}`);
        const samples = (f.samples || []).map(s => `
            <li class="sim-row">
                <span class="sim-row-main"><code>${esc(s.file_name)}</code><small class="sim-muted">${esc(s.file_type)} · ${esc(s.file_size)} B · entropy ${esc(Number(s.entropy || 0).toFixed(2))}</small></span>
                <span class="sim-hash" title="${esc(s.sha256)}">${esc(String(s.sha256 || '').slice(0, 16))}…</span>
                <button class="sim-btn ghost" data-sim-del-sample="${esc(s.id)}" data-family="${esc(f.id)}"><i class="fa-solid fa-trash"></i></button>
            </li>`).join('');
        const profile = (f.profile || []).map(p => `<li><span class="sim-tier sim-tier-${esc(String(p.tier || '').toLowerCase())}">${esc(p.tier)}</span> ${esc(p.kind)} · ${esc(p.item)} <span class="sim-muted">in ${esc(p.members)} of ${esc(f.sample_count)}</span></li>`).join('');
        box.innerHTML = `
            <div class="sim-card sim-detail">
                <div class="sim-detail-head">
                    <h2>${esc(f.name)}</h2>
                    <span class="sim-status sim-status-${esc(String(f.status || '').toLowerCase())}">${esc(STATUS_TEXT[f.status] || f.status || '')}</span>
                    <button class="sim-btn ghost" data-sim-del-family="${esc(f.id)}"><i class="fa-solid fa-trash"></i> Delete family</button>
                </div>
                <div class="sim-two">
                    <div>
                        <h3>Add samples</h3>
                        <p class="sim-muted">Files are analysed in the background, then deleted. Only features are kept.</p>
                        <form id="sim-add-samples" class="sim-form" data-family="${esc(f.id)}">
                            <input type="file" name="files" multiple required>
                            <button class="sim-btn primary" type="submit"><i class="fa-solid fa-upload"></i> Analyse and add</button>
                        </form>
                        <div id="sim-ingest-progress" class="sim-progress"></div>
                        <h3>Samples (${(f.samples || []).length})</h3>
                        ${samples ? `<ul class="sim-list">${samples}</ul>` : '<p class="sim-muted">No samples yet.</p>'}
                    </div>
                    <div>
                        <h3>Profile</h3>
                        <p class="sim-muted">CORE items appear in most members. VARIABLE items appear in some. Thin families are not judged on single items.</p>
                        ${profile ? `<ul class="sim-plain">${profile}</ul>` : '<p class="sim-muted">Profile needs at least one sample.</p>'}
                    </div>
                </div>
            </div>`;
        $('sim-add-samples')?.addEventListener('submit', addSamples);
    }

    async function addSamples(e) {
        e.preventDefault();
        const famId = e.target.dataset.family;
        const input = e.target.querySelector('input[type=file]');
        if (!input.files.length) return;
        const body = new FormData();
        for (const f of input.files) body.append('files', f, f.name);
        const progress = $('sim-ingest-progress');
        progress.textContent = 'Uploading…';
        try {
            const started = await api(`/api/similarity/families/${encodeURIComponent(famId)}/samples`, { method: 'POST', body });
            const job = await waitForJob(started.job_id, (j) => {
                if (progress) progress.textContent = j.message || 'Analysing…';
            });
            if (job.status === 'error') throw new Error(job.error || job.message || 'Analysis failed');
            notify(job.message || 'Samples added');
            await renderFamilies();
        } catch (err) {
            progress.textContent = '';
            notify(err.message);
        }
    }

    // ---------- Compare ----------
    function renderCompare() {
        setPane(shell(`
            <section class="sim-two">
                <div class="sim-card">
                    <h2>Compare a sample</h2>
                    <p class="sim-muted">The file is analysed, compared against every family profile, then deleted. Only the result is saved.</p>
                    <form id="sim-compare-form" class="sim-form">
                        <input type="file" name="file" required>
                        <button class="sim-btn primary" type="submit"><i class="fa-solid fa-scale-balanced"></i> Compare</button>
                    </form>
                    <div id="sim-compare-progress" class="sim-progress"></div>
                </div>
                <div class="sim-card">
                    <h2>Saved comparisons</h2>
                    <p class="sim-muted" id="sim-saved-list">Loading…</p>
                </div>
            </section>
            <section id="sim-compare-result"></section>`));
        $('sim-compare-form')?.addEventListener('submit', compareSample);
        loadSavedComparisons();
    }

    async function loadSavedComparisons() {
        const box = $('sim-saved-list');
        if (!box) return;
        try {
            const data = await api('/api/similarity/comparisons?limit=20');
            const items = data.comparisons || [];
            box.outerHTML = items.length
                ? `<ul id="sim-saved-list" class="sim-list">${items.map(c => `
                    <li class="sim-row" data-sim-comparison="${esc(c.id)}">
                        <span class="sim-row-main">${esc(c.file_name)}</span>${labelBadge(c.best_label)}
                        <span class="sim-muted">${when(c.created_at)}</span></li>`).join('')}</ul>`
                : '<p id="sim-saved-list" class="sim-muted">No comparisons yet.</p>';
        } catch (err) {
            box.textContent = err.message;
        }
    }

    async function compareSample(e) {
        e.preventDefault();
        const input = e.target.querySelector('input[type=file]');
        if (!input.files.length) return;
        const body = new FormData();
        body.append('file', input.files[0], input.files[0].name);
        const progress = $('sim-compare-progress');
        progress.textContent = 'Uploading…';
        try {
            const started = await api('/api/similarity/compare', { method: 'POST', body });
            const job = await waitForJob(started.job_id, (j) => {
                if (progress) progress.textContent = j.message || 'Analysing…';
            });
            if (job.status === 'error') throw new Error(job.error || job.message || 'Comparison failed');
            progress.textContent = '';
            renderResult(job.result);
            loadSavedComparisons();
        } catch (err) {
            progress.textContent = '';
            notify(err.message);
        }
    }

    function featureRows(features) {
        return Object.entries(features || {}).map(([key, f]) => {
            if (!f.available) {
                return `<div class="sim-feat sim-feat-na"><span>${esc(f.label || key)}</span><em>Not analysed</em><span class="sim-muted">${esc(f.note || '')}</span></div>`;
            }
            return `<div class="sim-feat">
                <span>${esc(f.label || key)}</span>
                <span class="sim-bar"><i style="width:${Math.max(0, Math.min(100, Number(f.score || 0)))}%"></i></span>
                <b>${pct(f.score)}</b>
                <span class="sim-muted">${esc(f.note || '')}</span></div>`;
        }).join('');
    }

    // Per-feature evidence lists (strings, imports, ...) are shown once, under the family.
    function sharedEvidence(features) {
        const rows = Object.values(features || {})
            .filter(f => f.available && Array.isArray(f.evidence) && f.evidence.length)
            .map(f => `<li><span class="sim-muted">${esc(f.label)}:</span> ${f.evidence.slice(0, 8).map(x => `<code>${esc(x)}</code>`).join(' ')}</li>`);
        return rows.length ? `<h4>Shared evidence</h4><ul class="sim-plain">${rows.join('')}</ul>` : '';
    }

    function renderResult(r) {
        const box = $('sim-compare-result');
        if (!box || !r) return;
        const file = r.sample || {};
        const fams = (r.families || []).map(f => `
            <div class="sim-card sim-family-result">
                <div class="sim-detail-head">
                    <h3>${esc(f.name)}</h3>
                    ${labelBadge(f.label)}
                    <span class="sim-muted">evidence ${pct(f.evidence)} · ${pct((f.coverage || 0) * 100)} of weight analysed · ${esc(f.sample_count)} sample(s)</span>
                </div>
                ${f.exact_sha256_member ? '<p class="sim-note">This file is byte-identical to a stored member.</p>' : ''}
                <div class="sim-features">${featureRows(f.features)}</div>
                ${sharedEvidence(f.features)}
            </div>`).join('');
        box.innerHTML = `
            <div class="sim-card">
                <div class="sim-detail-head">
                    <h2>${esc(file.file_name || '')}</h2>${labelBadge(r.best?.label || 'NO MATCH')}
                </div>
                <p class="sim-verdict">${esc(r.verdict || '')}</p>
                <p class="sim-muted">SHA256 <code>${esc(file.sha256 || '')}</code></p>
            </div>
            ${fams}`;
    }

    async function openSavedComparison(id) {
        const r = await api(`/api/similarity/comparisons/${encodeURIComponent(id)}`);
        renderResult(r);
        $('sim-compare-result')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ---------- Routing ----------
    async function open(tab, options = {}) {
        activeTab = TABS.some(t => t[0] === tab) ? tab : 'similarity-dashboard';
        const pane = $('similarity-pane');
        if (pane) pane.style.display = 'flex';
        setPane(shell(`<div class="sim-loading"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading…</div>`));
        try {
            if (activeTab === 'similarity-dashboard') await renderDashboard();
            else if (activeTab === 'similarity-entities') await renderFamilies();
            else renderCompare();
        } catch (err) {
            setPane(shell(`<div class="error-card"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(err.message)}</div>`));
        }
    }

    document.addEventListener('click', async (e) => {
        const tabBtn = e.target.closest('[data-sim-tab]');
        if (tabBtn) {
            const nav = document.querySelector(`.nav-item[data-tab="${tabBtn.dataset.simTab}"]`);
            if (nav) nav.click(); else open(tabBtn.dataset.simTab);
            return;
        }
        const famRow = e.target.closest('[data-sim-family]');
        if (famRow && !e.target.closest('button')) {
            openFamilyId = famRow.dataset.simFamily;
            await renderFamilies();
            return;
        }
        const delFam = e.target.closest('[data-sim-del-family]');
        if (delFam) {
            if (!confirm('Delete this family and all its stored samples and profile?')) return;
            try {
                await api(`/api/similarity/families/${encodeURIComponent(delFam.dataset.simDelFamily)}`, { method: 'DELETE' });
                openFamilyId = null;
                notify('Family deleted');
                await renderFamilies();
            } catch (err) { notify(err.message); }
            return;
        }
        const delSample = e.target.closest('[data-sim-del-sample]');
        if (delSample) {
            if (!confirm('Remove this sample and rebuild the family profile?')) return;
            try {
                await api(`/api/similarity/families/${encodeURIComponent(delSample.dataset.family)}/samples/${encodeURIComponent(delSample.dataset.simDelSample)}`, { method: 'DELETE' });
                notify('Sample removed');
                await renderFamilies();
            } catch (err) { notify(err.message); }
            return;
        }
        const cmp = e.target.closest('[data-sim-comparison]');
        if (cmp) {
            if (activeTab !== 'similarity-compare') {
                const nav = document.querySelector('.nav-item[data-tab="similarity-compare"]');
                if (nav) nav.click();
            }
            await openSavedComparison(cmp.dataset.simComparison);
        }
    });

    window.openSimilarityPane = open;
})();
