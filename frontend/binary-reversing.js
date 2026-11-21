/* MANTIS manual reversing workspace. Uses Binary Lab's existing extraction jobs. */
(function () {
    const pane = document.getElementById('binary-reversing-pane');
    if (!pane) return;
    const state = { jobs: [], job: '', index: 0, data: null, address: '', code: null, view: 'functions', query: '', revision: 0 };
    const esc = value => String(value == null ? '' : value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
    const addr = fn => String(fn.address || fn.entry_point || '');
    const key = value => String(value || '').toLowerCase().replace(/^0x/, '');
    const base = () => `/api/binary-reversing/jobs/${encodeURIComponent(state.job)}/samples/${state.index}`;
    const json = async (url, options) => {
        const response = await fetch(url, options);
        const body = await response.json();
        if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
        return body;
    };
    const message = text => { const el = pane.querySelector('.br-message'); if (el) el.textContent = text || ''; };
    const fnLabel = fn => `${fn.name || 'unnamed'}  ${addr(fn)}`;

    function shell() {
        pane.innerHTML = `<div class="br-shell">
            <header class="br-header"><div><div class="br-eyebrow">MALWARE LAB / MANUAL ANALYSIS</div><h2>Binary Reversing</h2><p>Explore extracted code, trace function calls, and record your findings.</p></div>
            <form class="br-upload"><label class="br-upload-label">New extraction<input type="file" name="files" required></label><button type="submit">Extract binary</button></form></header>
            <div class="br-toolbar"><label>Analysis job <select class="br-jobs" aria-label="Analysis job"></select></label><label>Sample <select class="br-samples" aria-label="Sample"></select></label><span class="br-message" role="status" aria-live="polite"></span></div>
            <div class="br-content"></div></div>`;
        pane.querySelector('.br-jobs').addEventListener('change', event => { state.job = event.target.value; state.index = 0; openWorkspace(); });
        pane.querySelector('.br-samples').addEventListener('change', event => { state.index = Number(event.target.value); openWorkspace(); });
        pane.querySelector('.br-upload').addEventListener('submit', upload);
    }

    async function upload(event) {
        event.preventDefault();
        const file = pane.querySelector('.br-upload input').files[0];
        if (!file) return;
        const form = new FormData();
        form.append('files', file);
        form.append('config', JSON.stringify({generate_workspace: true, analyze_workspace: false, autonomous_investigation: false, threat_attribution_lookup: false, rename_functions: false, rename_variables: false, use_mantis_ai: false}));
        message(`Extracting ${file.name}…`);
        try {
            const job = await json('/api/binary-lab/jobs/upload', {method: 'POST', body: form});
            state.job = job.job_id;
            state.index = 0;
            await loadJobs();
            await openWorkspace();
        } catch (error) { message(error.message); }
    }

    async function loadJobs() {
        const response = await json('/api/binary-lab/jobs?limit=100');
        state.jobs = response.jobs || [];
        const select = pane.querySelector('.br-jobs');
        if (!state.job || !state.jobs.some(job => job.job_id === state.job)) state.job = state.jobs[0]?.job_id || '';
        select.innerHTML = `<option value="">Select a job</option>` + state.jobs.map(job => `<option value="${esc(job.job_id)}">${esc((job.samples || []).map(sample => sample.name).join(', ') || job.job_id)} · ${esc(job.status)}</option>`).join('');
        select.value = state.job;
        populateSamples();
    }

    function populateSamples() {
        const job = state.jobs.find(row => row.job_id === state.job);
        const samples = job?.samples || [];
        if (state.index >= samples.length) state.index = 0;
        pane.querySelector('.br-samples').innerHTML = samples.map((sample, i) => `<option value="${i}">${esc(sample.name)}</option>`).join('');
        pane.querySelector('.br-samples').value = String(state.index);
    }

    async function openWorkspace() {
        const revision = ++state.revision;
        state.data = null; state.code = null; state.address = ''; state.query = ''; state.view = 'functions';
        populateSamples();
        if (!state.job) { pane.querySelector('.br-content').innerHTML = '<div class="br-empty">Upload a binary or choose an existing Binary Lab job to begin.</div>'; return; }
        message('Loading extracted workspace…');
        try {
            const data = await json(base());
            if (revision !== state.revision) return;
            state.data = data;
            message('');
            render();
            if (data.functions.length) await openFunction(addr(data.functions[0]));
        } catch (error) {
            if (revision !== state.revision) return;
            const job = state.jobs.find(row => row.job_id === state.job);
            message('');
            pane.querySelector('.br-content').innerHTML = `<div class="br-empty">${esc(error.message)}${['queued', 'running'].includes(job?.status) ? '<br>Extraction is running. This page will check again shortly.' : ''}<button type="button" class="br-retry">Refresh</button></div>`;
            pane.querySelector('.br-retry').addEventListener('click', openWorkspace);
            if (['queued', 'running'].includes(job?.status)) setTimeout(async () => { if (revision === state.revision) { await loadJobs(); openWorkspace(); } }, 5000);
        }
    }

    function render() {
        if (!state.data) return;
        const data = state.data;
        const view = state.view;
        pane.querySelector('.br-content').innerHTML = `<div class="br-summary"><strong>${esc(data.sample.name)}</strong><span class="br-hash" title="SHA256">${esc(data.sample.sha256 || '')}</span><span>${esc(data.engine.toUpperCase())}</span><span>${data.functions.length} functions</span><span>${data.strings.length} strings</span><span>${data.imports.length} imports</span></div>
            <div class="br-workbench"><aside class="br-sidebar"><div class="br-tabs">${['functions','strings','imports'].map(tab => `<button type="button" class="${view === tab ? 'active' : ''}" data-view="${tab}">${tab}</button>`).join('')}</div>
            <input class="br-search" type="search" aria-label="Filter ${view}" placeholder="Filter ${view}…" value="${esc(state.query)}">
            <div class="br-list dark-scroll"></div></aside>
            <section class="br-main"><div class="br-function"></div></section></div>`;
        pane.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => { state.view = button.dataset.view; state.query = ''; render(); }));
        pane.querySelector('.br-search').addEventListener('input', event => { state.query = event.target.value; renderList(); });
        renderList(); renderFunction();
    }

    function renderList() {
        const list = pane.querySelector('.br-list');
        if (!list || !state.data) return;
        const q = state.query.toLowerCase();
        const rows = state.data[state.view].filter(row => JSON.stringify(row).toLowerCase().includes(q));
        list.innerHTML = rows.slice(0, 1500).map(row => {
            if (state.view === 'functions') return `<button type="button" class="br-row ${key(state.address) === key(addr(row)) ? 'active' : ''}" data-address="${esc(addr(row))}"><strong>${esc(row.name)}</strong><small>${esc(addr(row))} · ${esc(row.size || 0)} bytes${row.triage_score ? ` · score ${esc(row.triage_score)}` : ''}</small></button>`;
            if (state.view === 'strings') return `<div class="br-row"><strong class="br-wrap">${esc(row.text || row.value || row.string || '')}</strong><small>${esc(row.address || '')}</small>${(row.referenced_by || []).slice(0, 5).map(ref => `<button class="br-ref" type="button" data-address="${esc(ref)}">${esc(ref)}</button>`).join('')}</div>`;
            return `<div class="br-row"><strong>${esc(row.name || row.function || '')}</strong><small>${esc(row.module || row.library || '')}</small>${(row.called_by || []).slice(0, 5).map(ref => `<button class="br-ref" type="button" data-address="${esc(ref)}">${esc(ref)}</button>`).join('')}</div>`;
        }).join('') || '<div class="br-list-empty">No matches.</div>';
        if (rows.length > 1500) list.insertAdjacentHTML('beforeend', `<div class="br-list-empty">Showing first 1,500 of ${rows.length}. Narrow the filter.</div>`);
        list.querySelectorAll('[data-address]').forEach(button => button.addEventListener('click', () => openFunction(button.dataset.address)));
    }

    async function openFunction(address) {
        if (!state.data || !address) return;
        state.address = address;
        state.code = null;
        renderList(); renderFunction();
        const revision = state.revision;
        try {
            const code = await json(`${base()}/functions/${encodeURIComponent(address)}`);
            if (revision !== state.revision || state.address !== address) return;
            state.code = code;
            renderFunction();
        } catch (error) { if (revision === state.revision) { message(error.message); renderFunction(); } }
    }

    function renderFunction() {
        const target = pane.querySelector('.br-function');
        if (!target) return;
        const fn = state.data?.functions.find(row => key(addr(row)) === key(state.address));
        if (!fn) { target.innerHTML = '<div class="br-empty">Select a function to inspect its code.</div>'; return; }
        const code = state.code;
        const note = state.data.notes[key(state.address)] || {};
        const xrefs = (title, entries) => `<div class="br-xrefs"><b>${title}</b>${entries.length ? entries.map(item => {
            const found = state.data.functions.find(row => key(addr(row)) === key(item));
            return `<button type="button" data-address="${esc(item)}">${esc(found?.name || item)}</button>`;
        }).join('') : '<span>None exported</span>'}</div>`;
        target.innerHTML = `<div class="br-fn-header"><div><small>${esc(addr(fn))} · ${esc(fn.module || '')}</small><h3>${esc(fn.name)}</h3><div class="br-prototype">${esc(fn.prototype || fn.signature || '')}</div></div><button type="button" class="br-copy" title="Copy function address">Copy address</button></div>
            <div class="br-xref-wrap">${xrefs('Callers', fn.callers || [])}${xrefs('Callees', fn.callees || [])}</div>
            <div class="br-code-grid"><div class="br-code-panel"><div class="br-panel-title">Decompiled code</div><pre><code>${esc(code?.source || (code ? 'No decompiled source was exported for this function.' : 'Loading…'))}</code></pre></div>
            <div class="br-code-panel"><div class="br-panel-title">Assembly</div><pre><code>${esc(code?.assembly || (code ? 'Assembly was not exported for this function.' : 'Loading…'))}</code></pre></div></div>
            <div class="br-notes"><div class="br-panel-title">Analyst notes ${note.updated_by ? `<small>Last edited by ${esc(note.updated_by)}</small>` : ''}</div><textarea aria-label="Function notes" placeholder="Record what this function does, evidence, or follow-up steps…">${esc(note.text || '')}</textarea><button type="button" class="br-save">Save notes</button><span class="br-save-status" aria-live="polite"></span></div>`;
        target.querySelectorAll('[data-address]').forEach(button => button.addEventListener('click', () => openFunction(button.dataset.address)));
        target.querySelector('.br-copy').addEventListener('click', () => navigator.clipboard.writeText(addr(fn)));
        target.querySelector('.br-save').addEventListener('click', async () => {
            const value = target.querySelector('textarea').value;
            const status = target.querySelector('.br-save-status');
            try {
                state.data.notes[key(state.address)] = await json(`${base()}/functions/${encodeURIComponent(state.address)}/note`, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text:value})});
                status.textContent = 'Saved';
            } catch (error) { status.textContent = error.message; }
        });
    }

    window.openBinaryReversing = async function () {
        if (!pane.querySelector('.br-shell')) shell();
        try { await loadJobs(); if (!state.data) await openWorkspace(); }
        catch (error) { message(error.message); }
    };
})();
