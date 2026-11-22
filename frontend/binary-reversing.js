/* MANTIS manual reversing workspace. Uses Binary Lab's existing extraction jobs. */
(function () {
    const pane = document.getElementById('binary-reversing-pane');
    if (!pane) return;
    const state = { jobs: [], job: '', index: 0, data: null, address: '', code: null, view: 'functions', query: '', revision: 0, pollTimer: null, engineStatus: {}, engine: '' };
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
    const active = job => ['queued', 'running', 'cancelling'].includes(job?.status);
    const formatTime = value => {
        if (!value) return 'Unknown time';
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
    };
    const clearPoll = () => { if (state.pollTimer) clearTimeout(state.pollTimer); state.pollTimer = null; };
    function shell() {
        pane.innerHTML = `<div class="br-shell">
            <header class="br-header"><div class="br-eyebrow"><span class="br-eyebrow-mark"></span> MANUAL ANALYSIS</div><p>Explore code, follow function calls, and document your findings.</p></header>
            <div class="br-toolbar">
                <section class="br-start-option" aria-label="Existing analysis">
                    <div class="br-option-heading"><span class="br-option-icon"><i class="fa-solid fa-folder-open"></i></span><div><h3>Open an analysis</h3><p>Continue from a Binary Lab extraction</p></div></div>
                    <div class="br-selects"><label for="br-jobs">Analysis job<select id="br-jobs" class="br-jobs" aria-label="Analysis job"></select></label><label for="br-samples">Sample<select id="br-samples" class="br-samples" aria-label="Sample"></select></label></div>
                </section>
                <form class="br-upload" aria-label="New extraction">
                    <div class="br-option-heading"><span class="br-option-icon"><i class="fa-solid fa-file-code"></i></span><div><h3>Extract a new binary</h3><p>Prepare a workspace for manual reversing</p></div></div>
                    <label class="br-engine-field" for="br-engine"><span>Analysis engine</span><select id="br-engine" class="br-engine" aria-label="Analysis engine" disabled><option value="">Checking installed engines…</option></select><small class="br-engine-hint">Checking IDA and Ghidra availability…</small></label>
                    <div class="br-upload-actions"><label class="br-file-trigger"><input type="file" name="files" required><i class="fa-solid fa-arrow-up-from-bracket"></i><span class="br-picked">Choose a binary file</span></label><button class="br-extract" type="submit" disabled>Start extraction <i class="fa-solid fa-arrow-right"></i></button></div>
                </form>
            </div>
            <div class="br-message" role="status" aria-live="polite"></div>
            <div class="br-content"></div></div>`;
        pane.querySelector('.br-jobs').addEventListener('change', event => {
            state.job = event.target.value;
            state.index = 0;
            if (state.job) openWorkspace();
            else { clearPoll(); state.revision += 1; state.data = null; renderHistory(); }
        });
        pane.querySelector('.br-samples').addEventListener('change', event => { state.index = Number(event.target.value); openWorkspace(); });
        pane.querySelector('.br-upload').addEventListener('submit', upload);
        pane.querySelector('.br-engine').addEventListener('change', event => {
            state.engine = event.target.value;
            updateExtractState();
        });
        pane.querySelector('.br-content').addEventListener('click', async event => {
            if (event.target.closest('.br-history-refresh')) {
                try { await loadJobs(); renderHistory(); } catch (error) { message(error.message); }
                return;
            }
            const deleteButton = event.target.closest('[data-br-delete-job]');
            if (deleteButton) {
                await deleteAnalysis(deleteButton.dataset.brDeleteJob, deleteButton.dataset.brSampleName || 'this analysis');
                return;
            }
            const button = event.target.closest('[data-br-open-job]');
            if (button) {
                state.job = button.dataset.brOpenJob;
                state.index = Number(button.dataset.brSampleIndex || 0);
                pane.querySelector('.br-jobs').value = state.job;
                populateSamples();
                openWorkspace();
                return;
            }
            if (event.target.closest('.br-back-history')) {
                clearPoll();
                state.revision += 1;
                state.job = '';
                state.data = null;
                state.code = null;
                state.address = '';
                pane.querySelector('.br-jobs').value = '';
                populateSamples();
                renderHistory();
            }
        });
        pane.querySelector('.br-upload input').addEventListener('change', event => {
            const file = event.target.files[0];
            pane.querySelector('.br-picked').textContent = file?.name || 'Choose a binary file';
            pane.querySelector('.br-file-trigger').classList.toggle('has-file', !!file);
            updateExtractState();
        });
    }

    function updateExtractState() {
        const file = pane.querySelector('.br-upload input')?.files[0];
        const submit = pane.querySelector('.br-extract');
        if (submit) submit.disabled = !file || !state.engine;
    }

    async function loadEngineStatus() {
        const status = await json('/api/binary-lab/status');
        state.engineStatus = status;
        const idaReady = !!status.ida_available;
        const ghidraReady = !!status.ghidra_available;
        const anyReady = idaReady || ghidraReady;
        const preferred = String(status.disassembler || '').toLowerCase();
        state.engine = preferred === 'auto' && anyReady ? 'auto'
            : preferred === 'ida' && idaReady ? 'ida'
            : preferred === 'ghidra' && ghidraReady ? 'ghidra'
            : idaReady ? 'ida'
            : ghidraReady ? 'ghidra'
            : '';
        const select = pane.querySelector('.br-engine');
        select.innerHTML = `<option value="auto" ${anyReady ? '' : 'disabled'}>Auto (best available)${anyReady ? '' : ' — unavailable'}</option>
            <option value="ida" ${idaReady ? '' : 'disabled'}>IDA Pro (Headless)${idaReady ? '' : ' — not configured'}</option>
            <option value="ghidra" ${ghidraReady ? '' : 'disabled'}>Ghidra (Headless)${ghidraReady ? '' : ' — not configured'}</option>`;
        select.disabled = !anyReady;
        select.value = state.engine;
        const ready = [idaReady ? 'IDA Pro' : '', ghidraReady ? 'Ghidra' : ''].filter(Boolean);
        pane.querySelector('.br-engine-hint').textContent = ready.length
            ? `${ready.join(' and ')} ${ready.length > 1 ? 'are' : 'is'} ready.`
            : 'No analysis engine is configured. Configure IDA or Ghidra in Binary Lab settings.';
        updateExtractState();
    }

    async function upload(event) {
        event.preventDefault();
        const file = pane.querySelector('.br-upload input').files[0];
        if (!file || !state.engine) return;
        const form = new FormData();
        form.append('files', file);
        form.append('config', JSON.stringify({disassembler: state.engine, generate_workspace: true, analyze_workspace: false, autonomous_investigation: false, threat_attribution_lookup: false, rename_functions: false, rename_variables: false, use_mantis_ai: false}));
        const submit = pane.querySelector('.br-extract');
        submit.disabled = true;
        renderUploadProgress(file.name, 0, 'Uploading sample…');
        try {
            const job = await uploadJob(form, file.name);
            state.job = job.job_id;
            state.index = 0;
            pane.querySelector('.br-upload input').value = '';
            pane.querySelector('.br-picked').textContent = 'Choose a binary file';
            pane.querySelector('.br-file-trigger').classList.remove('has-file');
            state.jobs = [job, ...state.jobs.filter(row => row.job_id !== job.job_id)];
            renderJobControls();
            await openWorkspace();
        } catch (error) { message(error.message); }
        finally { updateExtractState(); }
    }

    function uploadJob(form, filename) {
        return new Promise((resolve, reject) => {
            const request = new XMLHttpRequest();
            request.open('POST', '/api/binary-lab/jobs/upload');
            request.responseType = 'json';
            request.upload.addEventListener('progress', event => {
                if (!event.lengthComputable) return;
                const percent = Math.max(0, Math.min(100, Math.round(100 * event.loaded / event.total)));
                renderUploadProgress(filename, percent, percent >= 100 ? 'Upload complete. Starting extraction…' : 'Uploading sample…');
            });
            request.addEventListener('load', () => {
                const body = request.response || {};
                if (request.status >= 200 && request.status < 300) resolve(body);
                else reject(new Error(body.detail || `Upload failed (${request.status})`));
            });
            request.addEventListener('error', () => reject(new Error('Upload failed because the server connection was interrupted.')));
            request.addEventListener('abort', () => reject(new Error('Upload was cancelled.')));
            request.send(form);
        });
    }

    function renderUploadProgress(filename, percent, label) {
        message('');
        pane.querySelector('.br-content').innerHTML = `<section class="br-progress-card" aria-live="polite">
            <div class="br-progress-top"><div><span class="br-progress-kicker">NEW EXTRACTION</span><h3>${esc(filename)}</h3></div><span class="br-status is-running">Uploading</span></div>
            <div class="br-progress-stage"><strong>${esc(label)}</strong><span>${percent}%</span></div>
            <div class="br-progress-track"><span style="width:${percent}%"></span></div>
            <p>The sample is being transferred to MANTIS. Analysis progress will appear here when the job starts.</p>
        </section>`;
    }

    async function loadJobs() {
        const response = await json('/api/binary-lab/jobs?limit=100');
        state.jobs = response.jobs || [];
        renderJobControls();
    }

    function renderJobControls() {
        const select = pane.querySelector('.br-jobs');
        if (state.job && !state.jobs.some(job => job.job_id === state.job)) state.job = '';
        select.innerHTML = `<option value="">${state.jobs.length ? 'Select an analysis' : 'No analyses available'}</option>` + state.jobs.map(job => `<option value="${esc(job.job_id)}">${esc((job.samples || []).map(sample => sample.name).join(', ') || job.job_id)} · ${esc(job.status)}</option>`).join('');
        select.value = state.job;
        populateSamples();
    }

    function renderHistory() {
        const target = pane.querySelector('.br-content');
        if (!target) return;
        const rows = state.jobs.flatMap(job => (job.samples || []).map((sample, index) => ({job, sample, index})));
        const historyRows = rows.length ? rows.map(({job, sample, index}) => {
            const status = sample.status || job.status || 'unknown';
            const stage = sample.stage || job.current_stage || status;
            const detail = sample.message || job.stage_message || '';
            const engine = job.settings?.disassembler || 'auto';
            const isActive = active(job);
            return `<article class="br-history-row">
                <div class="br-history-file"><strong title="${esc(sample.name || '')}">${esc(sample.name || 'Unnamed sample')}</strong><small title="${esc(sample.sha256 || '')}">${esc((sample.sha256 || '').slice(0, 16))}${sample.sha256 ? '…' : ''}</small></div>
                <div class="br-history-meta"><span>${esc(engine.toUpperCase())}</span><span>${esc(formatTime(job.created_at))}</span><span>${esc(stage)}</span></div>
                <div class="br-history-state"><span class="br-status is-${esc(status)}">${esc(status)}</span>${detail ? `<small title="${esc(detail)}">${esc(detail)}</small>` : ''}</div>
                <div class="br-history-actions"><button type="button" class="br-history-open" data-br-open-job="${esc(job.job_id)}" data-br-sample-index="${index}">${isActive ? 'View progress' : status === 'complete' ? 'Open analysis' : 'View details'} <i class="fa-solid fa-arrow-right"></i></button><button type="button" class="br-history-delete" data-br-delete-job="${esc(job.job_id)}" data-br-sample-name="${esc(sample.name || 'this analysis')}" ${isActive ? 'disabled title="Stop the analysis before deleting it"' : 'title="Delete analysis"'} aria-label="Delete analysis for ${esc(sample.name || 'sample')}"><i class="fa-solid fa-trash-can"></i></button></div>
            </article>`;
        }).join('') : '<div class="br-history-empty">No analyzed files yet. Upload a binary to start the first extraction.</div>';
        target.innerHTML = `<section class="br-history br-history-home" aria-label="Analysis history">
            <div class="br-history-head"><div><span>ANALYSIS HISTORY</span><h2>Previously analyzed files</h2><p>Select a completed sample to open its reversing workspace.</p></div><button type="button" class="br-history-refresh"><i class="fa-solid fa-rotate"></i> Refresh</button></div>
            <div class="br-history-list">${historyRows}</div>
        </section>`;
    }

    async function deleteAnalysis(jobId, sampleName) {
        const confirmed = window.mantisConfirm
            ? await window.mantisConfirm({
                title: 'Delete binary analysis',
                message: `Permanently delete ${sampleName}? This removes the extracted workspace, reports, uploaded job copy, and analyst notes. This cannot be undone.`,
                confirmText: 'Delete analysis',
                danger: true,
            })
            : window.confirm(`Permanently delete ${sampleName}? This cannot be undone.`);
        if (!confirmed) return;
        try {
            await json(`/api/binary-lab/jobs/${encodeURIComponent(jobId)}`, {method: 'DELETE'});
            state.jobs = state.jobs.filter(job => job.job_id !== jobId);
            if (state.job === jobId) {
                clearPoll();
                state.revision += 1;
                state.job = '';
                state.data = null;
            }
            renderJobControls();
            renderHistory();
            message(`${sampleName} was deleted.`);
        } catch (error) {
            message(`Delete failed: ${error.message}`);
        }
    }

    function populateSamples() {
        const job = state.jobs.find(row => row.job_id === state.job);
        const samples = job?.samples || [];
        if (state.index >= samples.length) state.index = 0;
        const select = pane.querySelector('.br-samples');
        select.innerHTML = samples.length ? samples.map((sample, i) => `<option value="${i}">${esc(sample.name)}</option>`).join('') : '<option value="">Select a job first</option>';
        select.disabled = !samples.length;
        if (samples.length) select.value = String(state.index);
    }

    async function openWorkspace() {
        clearPoll();
        const revision = ++state.revision;
        state.data = null; state.code = null; state.address = ''; state.query = ''; state.view = 'functions';
        populateSamples();
        if (!state.job) {
            renderHistory();
            return;
        }
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
            if (active(job)) {
                renderAnalysisProgress(job);
                scheduleProgressPoll(revision, job.job_id);
            } else {
                pane.querySelector('.br-content').innerHTML = `<div class="br-empty br-empty-status"><div class="br-empty-icon"><i class="fa-solid fa-circle-exclamation"></i></div><h3>Workspace unavailable</h3><p>${esc(error.message)}</p><button type="button" class="br-retry">Refresh workspace</button></div>`;
                pane.querySelector('.br-retry').addEventListener('click', openWorkspace);
            }
        }
    }

    function progressValue(job) {
        const progress = job?.progress || {};
        const direct = Number(progress.percent);
        if (Number.isFinite(direct)) return Math.max(0, Math.min(100, direct));
        const current = Number(progress.current);
        const total = Number(progress.total);
        if (Number.isFinite(current) && Number.isFinite(total) && total > 0) return Math.max(0, Math.min(100, 100 * current / total));
        const samples = job?.samples || [];
        const finished = samples.filter(sample => ['complete', 'failed', 'cancelled'].includes(sample.status)).length;
        return samples.length && finished ? Math.round(100 * finished / samples.length) : null;
    }

    function renderAnalysisProgress(job) {
        const sample = (job.samples || [])[state.index] || (job.samples || [])[0] || {};
        const progress = job.progress || {};
        const percent = progressValue(job);
        const stage = sample.stage || progress.stage || job.current_stage || job.status || 'Preparing';
        const detail = sample.message || progress.message || job.stage_message || 'Waiting for the analysis engine to report its next step.';
        const events = (job.events || []).filter(event => event.message || event.stage).slice(-4).reverse();
        pane.querySelector('.br-content').innerHTML = `<section class="br-progress-card" aria-live="polite">
            <div class="br-progress-top"><div><span class="br-progress-kicker">ANALYZING SAMPLE</span><h3>${esc(sample.name || job.job_id)}</h3></div><span class="br-status is-${esc(job.status)}">${esc(job.status)}</span></div>
            <div class="br-progress-stage"><strong>${esc(stage)}</strong><span>${percent == null ? 'Working…' : `${Math.round(percent)}%`}</span></div>
            <div class="br-progress-track ${percent == null ? 'is-indeterminate' : ''}"><span${percent == null ? '' : ` style="width:${percent}%"`}></span></div>
            <p>${esc(detail)}</p>
            <div class="br-progress-facts"><span><i class="fa-solid fa-microchip"></i> ${esc((job.settings?.disassembler || 'auto').toUpperCase())}</span><span><i class="fa-regular fa-clock"></i> Started ${esc(formatTime(job.started_at || job.created_at))}</span></div>
            ${events.length ? `<ol class="br-progress-events">${events.map(event => `<li><time>${esc(formatTime(event.time))}</time><span>${esc(event.message || event.stage || event.kind)}</span></li>`).join('')}</ol>` : ''}
        </section>`;
    }

    function scheduleProgressPoll(revision, jobId) {
        clearPoll();
        state.pollTimer = setTimeout(async () => {
            if (revision !== state.revision || jobId !== state.job) return;
            try {
                const job = await json(`/api/binary-lab/jobs/${encodeURIComponent(jobId)}`);
                const index = state.jobs.findIndex(row => row.job_id === jobId);
                if (index >= 0) state.jobs[index] = job;
                else state.jobs.unshift(job);
                const select = pane.querySelector('.br-jobs');
                const option = Array.from(select?.options || []).find(item => item.value === jobId);
                if (option) option.textContent = `${(job.samples || []).map(sample => sample.name).join(', ') || job.job_id} · ${job.status}`;
                if (active(job)) {
                    renderAnalysisProgress(job);
                    scheduleProgressPoll(revision, jobId);
                } else {
                    await loadJobs();
                    if (revision === state.revision && jobId === state.job) openWorkspace();
                }
            } catch (error) {
                message(`Progress update failed: ${error.message}. Retrying…`);
                scheduleProgressPoll(revision, jobId);
            }
        }, 1500);
    }

    function render() {
        if (!state.data) return;
        const data = state.data;
        const view = state.view;
        pane.querySelector('.br-content').innerHTML = `<div class="br-analysis-nav"><button type="button" class="br-back-history"><i class="fa-solid fa-arrow-left"></i> Analysis history</button></div>
            <div class="br-summary"><strong>${esc(data.sample.name)}</strong><span class="br-hash" title="SHA256">${esc(data.sample.sha256 || '')}</span><span>${esc(data.engine.toUpperCase())}</span><span>${data.functions.length} functions</span><span>${data.strings.length} strings</span><span>${data.imports.length} imports</span></div>
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
            <div class="br-code-grid"><div class="br-code-panel"><div class="br-panel-title">Decompiled code</div><pre><code class="language-c">${esc(code?.source || (code ? 'No decompiled source was exported for this function.' : 'Loading…'))}</code></pre></div>
            <div class="br-code-panel"><div class="br-panel-title">Assembly</div><pre><code class="language-x86asm">${esc(code?.assembly || (code ? 'Assembly was not exported for this function.' : 'Loading…'))}</code></pre></div></div>
            <div class="br-notes"><div class="br-panel-title">Analyst notes ${note.updated_by ? `<small>Last edited by ${esc(note.updated_by)}</small>` : ''}</div><textarea aria-label="Function notes" placeholder="Record what this function does, evidence, or follow-up steps…">${esc(note.text || '')}</textarea><button type="button" class="br-save">Save notes</button><span class="br-save-status" aria-live="polite"></span></div>`;
        if (window.hljs) target.querySelectorAll('pre code').forEach(element => window.hljs.highlightElement(element));
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
        clearPoll();
        state.job = '';
        state.index = 0;
        state.data = null;
        state.code = null;
        state.address = '';
        state.revision += 1;
        message('Loading analysis history…');
        pane.querySelector('.br-content').innerHTML = '<div class="br-history-loading"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading analyzed files…</div>';
        try {
            await Promise.all([loadJobs(), loadEngineStatus()]);
            pane.querySelector('.br-jobs').value = '';
            populateSamples();
            message('');
            renderHistory();
        }
        catch (error) {
            message(error.message);
            pane.querySelector('.br-content').innerHTML = '<div class="br-history-empty">Analysis history could not be loaded. Use Refresh after checking the server connection.</div>';
        }
    };
})();
