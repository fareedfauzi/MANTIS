(function () {

    const state = {

        loaded: false, status: {}, settings: {}, jobs: [], selectedJob: '', view: 'new',

        jobTab: 'queue', // 'queue' | 'analysis' | 'functions' | 'variables' | 'ida-log' | 'reports' | 'events'

        activeSampleIndex: 0, catalogs: {}, idaLogs: {},

        analysisMode: 'html', analysisMarkdownCache: {},

        fnFilter: '', fnScoreFilter: 'all',

        varFilter: '', varKindFilter: 'all',

        idaLogFilter: '', idaAutoScroll: true, idaFilterNoise: true,

        poller: null, showArtifacts: false

    };



    async function request(path, options = {}) {

        const response = await fetch(`${API_BASE}${path}`, options);

        const text = await response.text();

        let data = {};

        try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { detail: text }; }

        if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);

        return data;

    }



    const esc = (value) => escapeHtml(value == null ? '' : String(value));

    const fmtBytes = (value) => {

        let size = Number(value || 0);

        for (const unit of ['B', 'KB', 'MB', 'GB']) {

            if (size < 1024 || unit === 'GB') return `${size.toFixed(unit === 'B' ? 0 : 1)} ${unit}`;

            size /= 1024;

        }

        return `${size.toFixed(1)} GB`;

    };

    const checked = (value) => value ? 'checked' : '';

    const field = (id, label, value, type = 'text', extra = '') => `

        <label class="bl-field"><span>${esc(label)}</span><input id="${id}" type="${type}" value="${esc(value)}" ${extra}></label>`;

    const toggle = (id, label, value, hint = '') => `

        <label class="bl-toggle"><input id="${id}" type="checkbox" ${checked(value)}><span class="bl-switch" aria-hidden="true"><i></i></span><span class="bl-toggle-copy"><strong>${esc(label)}</strong>${hint ? `<small>${esc(hint)}</small>` : ''}</span></label>`;



    function shell() {

        const pane = document.getElementById('binary-lab-pane');

        if (!pane) return;

        pane.innerHTML = `

            <div class="bl-shell">

                <header class="bl-hero">

                    <div class="bl-hero-main"><span class="bl-hero-icon"><i class="fa-solid fa-microchip"></i></span><div><span class="bl-kicker">BINARY ANALYSIS ENGINE</span><h1>AI Binary Analysis Lab</h1>

                    <p>Reverse engineer native and managed binaries into reviewable IDBs, source workspaces, and investigation reports.</p></div></div>

                    <div class="bl-status" id="bl-engine-status"></div>

                </header>

                <nav class="bl-tabs">

                    <button data-bl-view="new"><i class="fa-solid fa-plus"></i> New Analysis</button>

                    <button data-bl-view="jobs"><i class="fa-solid fa-list-check"></i> Jobs <span id="bl-job-count"></span></button>

                    <button data-bl-view="settings"><i class="fa-solid fa-sliders"></i> Engine Settings</button>

                </nav>

                <main id="bl-content"></main>

            </div>`;

        pane.querySelectorAll('[data-bl-view]').forEach(button => button.addEventListener('click', () => {

            state.view = button.dataset.blView;

            state.showArtifacts = false;

            render();

            if (state.view === 'jobs') {

                refreshJobs();

            }

        }));

    }



    function renderStatus() {

        const target = document.getElementById('bl-engine-status');

        if (!target) return;

        const disasm = (state.settings.disassembler || 'ida').toLowerCase();

        target.innerHTML = `

            <button class="bl-pill ${state.status.available ? 'ok' : 'bad'}" data-bl-status-settings ${state.status.available ? 'disabled' : ''}><i class="fa-solid fa-${state.status.available ? 'check' : 'triangle-exclamation'}"></i> Engine ${state.status.available ? 'ready' : 'unavailable'}</button>

            <button class="bl-pill ${state.status.ida_available ? 'ok' : 'warn'}" data-bl-status-settings><i class="fa-solid fa-cube"></i> IDA ${state.status.ida_available ? 'ready' : 'configure'}</button>

            <button class="bl-pill ${state.status.ghidra_available ? 'ok' : 'warn'}" data-bl-status-settings><i class="fa-solid fa-dragon"></i> Ghidra ${state.status.ghidra_available ? 'ready' : 'configure'}</button>

            <span class="bl-pill"><i class="fa-solid fa-sliders"></i> Disasm: ${esc(disasm.toUpperCase())}</span>

            <span class="bl-pill"><i class="fa-solid fa-code"></i> Native + .NET</span>`;

        target.querySelectorAll('[data-bl-status-settings]:not([disabled])').forEach(button => button.addEventListener('click', () => {

            state.view = 'settings';

            state.showArtifacts = false;

            render();

        }));

    }



    function optionGrid(prefix = 'bl-run') {

        const s = state.settings;

        return `<div class="bl-option-grid">

            ${toggle(`${prefix}-rename-functions`, 'Rename functions', s.rename_functions, 'LLM-assisted function naming')}

            ${toggle(`${prefix}-rename-address`, 'Include addresses', s.rename_functions_with_address, 'Append original address to names')}

            ${toggle(`${prefix}-rename-variables`, 'Rename variables', s.rename_variables, 'Recover meaningful local names')}

            ${toggle(`${prefix}-workspace`, 'Export AI workspace', s.generate_workspace, 'Code, disassembly, catalogs, AGENTS.md')}

            ${toggle(`${prefix}-analyze`, 'Analyze workspace', s.analyze_workspace, 'Generate autonomous technical report')}

            ${toggle(`${prefix}-autonomous`, 'In-database investigation', s.autonomous_investigation, 'Agent-guided IDA investigation')}

            ${toggle(`${prefix}-attribution`, 'Threat attribution lookup', s.threat_attribution_lookup, 'Automated CTI lookup for hash, IOCs, registry, and threat actor attribution')}

            ${toggle(`${prefix}-recursive`, 'Recursive discovery', s.recursive, 'Scan supported files below directories')}

            ${toggle(`${prefix}-cache`, 'Rename cache', s.use_rename_cache, 'Reuse cross-sample naming consensus')}

        </div>
        <div id="${prefix}-api-workspace-warn" class="bl-api-workspace-warning">
            <i class="fa-solid fa-triangle-exclamation"></i>
            <div>
                <strong>Workspace Analysis with API Provider:</strong> You have selected an API provider. API models analyze aggregated decompilation catalogs and code context up to token limits, but <em>cannot</em> autonomously roam local directories or execute terminal commands like a CLI agent (e.g. Antigravity CLI or Claude Code). For full interactive agentic file inspection, select a CLI provider or run your CLI agent directly inside the generated <code>AI Workspace/</code> directory.
            </div>
        </div>`;

    }



    function runOverrides(prefix = 'bl-run') {

        return {

            disassembler: document.getElementById(`${prefix}-disassembler`)?.value || state.settings.disassembler || 'ida',

            rename_functions: !!document.getElementById(`${prefix}-rename-functions`)?.checked,

            rename_functions_with_address: !!document.getElementById(`${prefix}-rename-address`)?.checked,

            rename_variables: !!document.getElementById(`${prefix}-rename-variables`)?.checked,

            generate_workspace: !!document.getElementById(`${prefix}-workspace`)?.checked,

            analyze_workspace: !!document.getElementById(`${prefix}-analyze`)?.checked,

            autonomous_investigation: !!document.getElementById(`${prefix}-autonomous`)?.checked,

            threat_attribution_lookup: !!document.getElementById(`${prefix}-attribution`)?.checked,

            recursive: !!document.getElementById(`${prefix}-recursive`)?.checked,

            use_rename_cache: !!document.getElementById(`${prefix}-cache`)?.checked,

            dotnet_mode: document.getElementById(`${prefix}-dotnet`)?.value || document.getElementById('bl-run-dotnet')?.value || 'decompile',

            use_mantis_ai: !!document.getElementById(`${prefix}-use-mantis-ai`)?.checked,

            provider: document.getElementById(`${prefix}-provider`)?.value || state.settings.provider || 'OpenAI',

            api_url: document.getElementById(`${prefix}-url`)?.value || '',

            model: document.getElementById(`${prefix}-model`)?.value || '',

            executable: document.getElementById(`${prefix}-executable`)?.value || '',

        };

    }



    function renderNew() {

        const idaOk = !!state.status.ida_available;
        const ghidraOk = !!state.status.ghidra_available;
        let activeDisasm = state.settings.disassembler || 'ida';

        if (idaOk && ghidraOk) {
            // Both configured: allow user to choose, default is IDA Pro
            if (activeDisasm !== 'ghidra') activeDisasm = 'ida';
        } else if (idaOk && !ghidraOk) {
            activeDisasm = 'ida';
        } else if (!idaOk && ghidraOk) {
            activeDisasm = 'ghidra';
        } else {
            activeDisasm = '';
        }

        const disasmReady = (idaOk || ghidraOk);
        const idaActive = (activeDisasm === 'ida');
        const ghidraActive = (activeDisasm === 'ghidra');

        const idaCardHtml = `
            <div class="bl-disasm-card ${idaActive ? 'active' : ''} ${idaOk ? '' : 'disabled'}" data-disasm="ida" role="button" tabindex="${idaOk ? '0' : '-1'}" title="${idaOk ? 'Select IDA Pro as disassembler' : 'IDA Pro is not configured in Settings'}">
                <div class="bl-disasm-radio">
                    <i class="fa-solid fa-${idaActive ? 'circle-dot' : 'circle'}"></i>
                </div>
                <div class="bl-disasm-icon bl-disasm-icon-ida">
                    <i class="fa-solid fa-cube"></i>
                </div>
                <div class="bl-disasm-info">
                    <div class="bl-disasm-title-row">
                        <strong>IDA Pro (Headless)</strong>
                        <span class="bl-status-pill ${idaOk ? 'ready' : 'warn'}">
                            <i class="fa-solid fa-${idaOk ? 'circle-check' : 'circle-exclamation'}"></i> ${idaOk ? 'Ready' : 'Not configured'}
                        </span>
                    </div>
                    <p class="bl-disasm-desc">Hex-Rays decompilation, in-database LLM function/variable renaming, and interactive multi-turn agent investigation.</p>
                    <div class="bl-disasm-features">
                        <span><i class="fa-solid fa-check"></i> In-Database Renaming</span>
                        <span><i class="fa-solid fa-check"></i> Variable Recovery</span>
                        <span><i class="fa-solid fa-check"></i> Live Agent Turns</span>
                    </div>
                </div>
            </div>
        `;

        const ghidraCardHtml = `
            <div class="bl-disasm-card ${ghidraActive ? 'active' : ''} ${ghidraOk ? '' : 'disabled'}" data-disasm="ghidra" role="button" tabindex="${ghidraOk ? '0' : '-1'}" title="${ghidraOk ? 'Select Ghidra as disassembler' : 'Ghidra is not configured in Settings'}">
                <div class="bl-disasm-radio">
                    <i class="fa-solid fa-${ghidraActive ? 'circle-dot' : 'circle'}"></i>
                </div>
                <div class="bl-disasm-icon bl-disasm-icon-ghidra">
                    <i class="fa-solid fa-dragon"></i>
                </div>
                <div class="bl-disasm-info">
                    <div class="bl-disasm-title-row">
                        <strong>Ghidra (Headless)</strong>
                        <span class="bl-status-pill ${ghidraOk ? 'ready' : 'warn'}">
                            <i class="fa-solid fa-${ghidraOk ? 'circle-check' : 'circle-exclamation'}"></i> ${ghidraOk ? 'Ready' : 'Not configured'}
                        </span>
                    </div>
                    <p class="bl-disasm-desc">Automated headless analysis, DecompInterface C decompilation, and native Ghidra Project export (.gpr/.rep).</p>
                    <div class="bl-disasm-features">
                        <span><i class="fa-solid fa-check"></i> Headless Auto-Analysis</span>
                        <span><i class="fa-solid fa-check"></i> C Source Decompile</span>
                        <span><i class="fa-solid fa-check"></i> Ghidra Project (.gpr)</span>
                    </div>
                </div>
            </div>
        `;

        return `<div class="bl-grid">

            <section class="bl-card bl-card-wide">

                <div class="bl-card-head"><div class="bl-card-title"><span class="bl-step">01</span><div><h2>Choose input</h2><p>Upload samples or point MANTIS at a host-accessible path.</p></div></div><i class="fa-solid fa-file-shield"></i></div>

                <div class="bl-source-grid">

                    <label class="bl-drop" id="bl-drop-zone"><input id="bl-files" type="file" multiple><span class="bl-source-icon"><i class="fa-solid fa-cloud-arrow-up"></i></span><strong>Drop binaries here</strong><span>PE, ELF, Mach-O, IDB/I64, Ghidra GZF/GPR, or managed .NET</span><span class="bl-file-action">Browse files</span><small id="bl-file-summary">No files selected</small></label>

                    <div class="bl-path">

                        <div class="bl-path-header">

                            <span class="bl-source-icon"><i class="fa-solid fa-folder-tree"></i></span>

                            <div class="bl-path-copy">

                                <strong>Analyze a local path</strong>

                                <span>File or directory accessible from the MANTIS host</span>

                            </div>

                        </div>

                        <div class="bl-path-field">

                            <span>Host path</span>

                            <div class="bl-input-browse">

                                <input id="bl-path" placeholder="C:\\Samples or /opt/samples">

                                <button type="button" class="btn-secondary bl-browse-btn" id="bl-browse-path" title="Browse for directory"><i class="fa-solid fa-folder-open"></i> Browse</button>

                            </div>

                        </div>

                    </div>

                </div>

            </section>

            <section class="bl-card bl-card-wide">

                <div class="bl-card-head"><div class="bl-card-title"><span class="bl-step">02</span><div><h2>Disassembler Backend</h2><p>Select the reverse engineering engine to disassemble and decompile native binaries.</p></div></div><i class="fa-solid fa-microchip"></i></div>

                <input type="hidden" id="bl-run-disassembler" value="${activeDisasm}">

                <div class="bl-disasm-grid">
                    ${idaCardHtml}
                    ${ghidraCardHtml}
                </div>

                ${!disasmReady ? '<div class="bl-field-warn-text" style="margin-top: 12px;"><i class="fa-solid fa-triangle-exclamation"></i> Neither IDA Pro nor Ghidra is configured in Settings. Please configure an engine in Settings to proceed.</div>' : ''}

            </section>

            <section class="bl-card bl-card-wide">

                <div class="bl-card-head"><div class="bl-card-title"><span class="bl-step">03</span><div><h2>Configure pipeline</h2><p>Select enrichment, decompilation, and intelligence analysis stages.</p></div></div><i class="fa-solid fa-diagram-project"></i></div>

                ${optionGrid()}

            </section>

            <section class="bl-card bl-card-wide">

                <div class="bl-card-head"><div class="bl-card-title"><span class="bl-step">04</span><div><h2>AI Provider & Intelligence</h2><p>Choose the AI model for function renaming, workspace analysis, and threat attribution.</p></div></div><i class="fa-solid fa-wand-magic-sparkles"></i></div>

                <div class="bl-option-grid">${toggle('bl-run-use-mantis-ai', 'Use MANTIS AI settings', state.settings.use_mantis_ai, 'Inherit global MANTIS AI credentials and active provider')}</div>

                <div class="bl-form-grid">

                    <label class="bl-field"><span>Provider</span><select id="bl-run-provider">${providerOptions(state.settings.provider)}</select></label>

                    <label class="bl-field" id="bl-run-field-url"><span>API base URL</span><input id="bl-run-url" type="text" value="${esc(state.settings.api_url)}"></label>

                    <label class="bl-field"><span>Model</span><input id="bl-run-model" list="bl-run-models-list" type="text" value="${esc(state.settings.model)}" placeholder="e.g. gemini-3.8-flash"><datalist id="bl-run-models-list"></datalist></label>

                    <label class="bl-field" id="bl-run-field-executable"><span>CLI executable</span><input id="bl-run-executable" type="text" value="${esc(state.settings.executable)}" placeholder="e.g. agy or claude"></label>

                </div>

                <div class="bl-ai-actions">

                    <button type="button" class="btn-secondary" id="bl-run-test-ai"><i class="fa-solid fa-plug-circle-check"></i> Test Connection</button>

                    <span id="bl-run-test-ai-status" class="bl-ai-status"></span>

                </div>

            </section>

            <section class="bl-card bl-card-wide bl-actions"><div class="bl-ready"><span class="bl-ready-dot ${disasmReady ? '' : 'bl-ready-warn'}"></span><div><strong>${disasmReady ? 'Ready to analyze' : 'Disassembler not configured'}</strong><span id="bl-start-note">${disasmReady ? 'Choose an upload or local path to create a persistent analysis job.' : 'Please configure IDA Pro (idat.exe) or Ghidra in Settings to enable disassembly.'}</span></div></div><button id="bl-start" class="btn-primary bl-start" ${disasmReady ? '' : 'disabled'}><i class="fa-solid fa-play"></i> Start Analysis</button></section>

        </div>`;

    }



    function statusClass(status) {

        return ['complete', 'success'].includes(status) ? 'ok' : ['failed', 'error'].includes(status) ? 'bad' : ['cancelled', 'cancelling', 'interrupted'].includes(status) ? 'warn' : 'run';

    }





    function normalizeStageId(stage) {

        const s = String(stage || '').toLowerCase().trim();

        if (!s) return '';

        if (s.includes('complete') || s.includes('success')) return 'complete';

        if (s.includes('fail') || s.includes('error')) return 'failed';

        if (s.includes('cancel')) return 'cancelled';

        if (s.includes('interrupt')) return 'interrupted';

        if (s.includes('queue')) return 'queued';

        if (s.includes('disasm') || s.includes('opening in ida') || s.includes('scanning') || s.includes('ghidra') || s.includes('decompil') || s.includes('init')) return 'disasm';

        if (s.includes('exporting') || s.includes('workspace written') || (s.includes('workspace') && !s.includes('analyz'))) return 'workspace';

        if (s.includes('renam') || s.includes('functions') || s.includes('variables')) return 'renaming';

        if (s.includes('investigat') || s.includes('analyz')) return 'investigation';

        if (s.includes('attribut')) return 'attribution';

        if (s.includes('report') || s.includes('deliverable') || s.includes('save') || s.includes('saving')) return 'reports';

        return s;

    }



    function stageMeta(stage) {

        const norm = normalizeStageId(stage);

        const map = {

            init: { label: 'Initializing Engine', icon: 'fa-gears', color: '#60a5fa', desc: 'Preparing runtime environment' },

            disasm: { label: 'Disassembling & Decompiling', icon: 'fa-microchip', color: '#38bdf8', desc: 'Running headless IDA Pro / Ghidra analysis' },

            dotnet: { label: 'Decompiling .NET Assemblies', icon: 'fa-cube', color: '#818cf8', desc: 'Running ILSpy export & CIL decompilation' },

            workspace: { label: 'Exporting AI Workspace', icon: 'fa-box-archive', color: '#fbbf24', desc: 'Building context catalogs, source trees & AGENTS.md' },

            renaming: { label: 'AI Semantic Renaming', icon: 'fa-wand-magic-sparkles', color: '#a78bfa', desc: 'LLM recovery of sub_* and local variable names' },

            investigation: { label: 'Autonomous In-Database AI Investigation', icon: 'fa-robot', color: '#f59e0b', desc: 'Multi-turn agent navigating IDA disassembly' },

            attribution: { label: 'Threat Attribution OSINT', icon: 'fa-shield-halved', color: '#ec4899', desc: 'Querying threat framework and IOC intelligence' },

            reports: { label: 'Compiling Reports & Deliverables', icon: 'fa-file-shield', color: '#34d399', desc: 'Building publication-grade HTML & PDF reports' },

            complete: { label: 'Analysis Complete', icon: 'fa-circle-check', color: '#4ade80', desc: 'All analysis stages finished successfully' },

            failed: { label: 'Analysis Failed', icon: 'fa-circle-xmark', color: '#f87171', desc: 'Pipeline encountered an error' },

            cancelled: { label: 'Cancelled', icon: 'fa-ban', color: '#94a3b8', desc: 'Job execution stopped by user' },

            interrupted: { label: 'Interrupted', icon: 'fa-triangle-exclamation', color: '#fb923c', desc: 'Job was interrupted; resume is available' },

            running: { label: 'Running Pipeline', icon: 'fa-circle-notch mantis-spin', color: '#fbbf24', desc: 'Executing analysis pipeline' },

            queued: { label: 'Queued', icon: 'fa-clock', color: '#94a3b8', desc: 'Waiting in engine queue' }

        };

        return map[norm] || map[String(stage || '').toLowerCase()] || { label: stage || 'Running', icon: 'fa-play', color: '#fbbf24', desc: stage || 'Processing' };

    }



    function renderStageStepper(job) {

        const stages = [

            { id: 'disasm', label: 'Disassembly' },

            { id: 'workspace', label: 'AI Workspace' },

            { id: 'renaming', label: 'AI Renaming' },

            { id: 'investigation', label: 'AI Analysis' },

            { id: 'attribution', label: 'Attribution' },

            { id: 'reports', label: 'Deliverables' }

        ];

        const isComplete = ['complete', 'success'].includes(job.status);

        const stageOrder = ['disasm', 'workspace', 'renaming', 'investigation', 'attribution', 'reports', 'complete'];

        const curStageId = normalizeStageId(job.current_stage || job.status);

        const curIdx = isComplete ? 99 : stageOrder.indexOf(curStageId);



        return stages.map((st, i) => {

            const thisIdx = stageOrder.indexOf(st.id);

            const isDone = isComplete || (curIdx > thisIdx);

            const isActive = !isComplete && (curStageId === st.id || (curIdx === -1 && i === 0 && job.status === 'running'));

            const cls = isDone ? 'done' : (isActive ? 'active' : '');

            return `<div class="bl-step-item ${cls}">

                <span class="bl-step-num">${isDone ? '<i class="fa-solid fa-check"></i>' : (i + 1)}</span>

                <span>${st.label}</span>

                ${i < stages.length - 1 ? '<i class="fa-solid fa-chevron-right bl-step-arrow"></i>' : ''}

            </div>`;

        }).join('');

    }

    function jobCard(job) {

        const summary = job.summary || {};

        const sm = stageMeta(job.current_stage || job.status);

        const pills = [];

        pills.push(`<span class="bl-stage-pill ${statusClass(job.status)}"><i class="fa-solid ${sm.icon}"></i> ${esc(sm.label)}</span>`);

        if (job.has_html_report) {

            pills.push('<span class="bl-pill-report"><i class="fa-solid fa-file-code"></i> HTML</span>');

        }

        if (job.has_attribution_report) {

            pills.push('<span class="bl-pill-attr"><i class="fa-solid fa-shield-halved"></i> Attrib</span>');

        }

        return `<article class="bl-job ${state.selectedJob === job.job_id ? 'selected' : ''}" data-job-id="${esc(job.job_id)}">

            <div><span class="bl-state ${statusClass(job.status)}">${esc(job.status)}</span><strong>${esc(job.job_id)}</strong><small>${esc(job.created_at)}</small></div>

            <div class="bl-job-meta">

                <span>${job.samples?.length || 0} sample${job.samples?.length === 1 ? '' : 's'}</span>

                <span>${summary.succeeded || 0} complete</span>

            </div>

            <div class="bl-job-meta" style="margin-top: 5px; flex-wrap: wrap; gap: 4px;">

                ${pills.join(' ')}

            </div>

        </article>`;

    }



    function renderJobs() {

        const selected = state.jobs.find(job => job.job_id === state.selectedJob);

        return `<div class="bl-jobs-layout"><section class="bl-card bl-job-list"><div class="bl-card-head"><div><h2>Analysis Jobs</h2><p>Persistent queue and run history.</p></div><button id="bl-refresh" class="btn-secondary" title="Refresh jobs"><i class="fa-solid fa-rotate"></i></button></div>

            <div>${state.jobs.map(jobCard).join('') || '<div class="bl-empty">No Binary Lab jobs yet.</div>'}</div></section>

            <section class="bl-card bl-job-detail">${selected ? renderJobDetail(selected) : '<div class="bl-empty"><i class="fa-solid fa-arrow-left"></i>Select a job to inspect progress and artifacts.</div>'}</section></div>`;

    }



    function renderJobDetail(job) {

        const events = (job.events || []).slice(-100).reverse();

        const reports = job.reports || [];

        const sm = stageMeta(job.current_stage || job.status);

        const progress = job.progress || null;

        const counts = job.counts || {};



        // Progress bar HTML

        let progressHtml = '';

        if (progress && progress.total) {

            const pct = Math.min(100, Math.max(0, Number(progress.percent || Math.round(100 * (progress.current || 0) / progress.total))));

            progressHtml = `<div class="bl-progress-wrap">

                <div class="bl-progress-head">

                    <span>${esc(progress.message || job.stage_message || sm.desc)}</span>

                    <strong>${pct}% (${progress.current} / ${progress.total})</strong>

                </div>

                <div class="bl-progress-bar">

                    <div class="bl-progress-fill" style="width: ${pct}%"></div>

                </div>

            </div>`;

        } else if (['running', 'queued'].includes(job.status)) {

            progressHtml = `<div class="bl-progress-wrap">

                <div class="bl-progress-head">

                    <span><i class="fa-solid fa-circle-notch mantis-spin"></i> Processing pipeline...</span>

                    <strong>${esc(job.stage_message || sm.desc)}</strong>

                </div>

                <div class="bl-progress-bar">

                    <div class="bl-progress-fill" style="width: 60%; animation: pulse 1.5s infinite;"></div>

                </div>

            </div>`;

        }



        // Active tab content

        let tabContent = '';

        if (state.jobTab === 'queue') {

            tabContent = renderTabQueue(job, reports);

        } else if (state.jobTab === 'analysis') {

            tabContent = renderTabAnalysis(job, reports);

        } else if (state.jobTab === 'functions') {

            tabContent = renderTabFunctions(job);

        } else if (state.jobTab === 'variables') {

            tabContent = renderTabVariables(job);

        } else if (state.jobTab === 'ida-log') {

            tabContent = renderTabIdaLog(job);

        } else if (state.jobTab === 'reports') {

            tabContent = renderTabReports(job, reports);

        } else {

            tabContent = renderTabEvents(events);

        }



        const primarySample = (job.samples || [])[0] || {};

        const primarySampleName = primarySample.name || job.job_id;

        const createdDate = job.created_at ? new Date(job.created_at).toLocaleString() : '';



        return `<div class="bl-job-header-card">

                <div class="bl-job-header-main">

                    <div class="bl-job-title-stack">

                        <div class="bl-job-eyebrow">

                            <span class="bl-job-badge-tag"><i class="fa-solid fa-flask"></i> ANALYSIS JOB</span>

                            <span class="bl-job-id-mono">${esc(job.job_id)}</span>

                            <button type="button" class="bl-btn-icon-copy" title="Copy Job ID" onclick="navigator.clipboard.writeText('${esc(job.job_id)}'); showNotification('Copied Job ID');">

                                <i class="fa-regular fa-copy"></i>

                            </button>

                        </div>

                        <h2 class="bl-job-headline">${esc(primarySampleName)}</h2>

                        <div class="bl-job-meta-row">

                            ${createdDate ? `<span><i class="fa-regular fa-clock"></i> ${esc(createdDate)}</span><span class="bl-dot-sep">·</span>` : ''}

                            <span><i class="fa-solid fa-microchip"></i> ${esc((job.settings?.disassembler || 'IDA').toUpperCase())} Decompiler</span>

                            <span class="bl-dot-sep">·</span>

                            <span><i class="fa-solid fa-layer-group"></i> ${job.samples?.length || 1} Target Sample${(job.samples?.length || 1) > 1 ? 's' : ''}</span>

                            <span class="bl-dot-sep">·</span>

                            <span title="${esc(job.output_root)}"><i class="fa-regular fa-folder"></i> <code>output/${esc(job.job_id)}</code></span>

                        </div>

                    </div>

                    <div class="bl-job-status-group">

                        <span class="bl-state ${statusClass(job.status)}">${esc(job.status.toUpperCase())}</span>

                    </div>

                </div>

            </div>



            <!-- Stage Card & Stepper Banner -->

            <section class="bl-stage-card">

                <div class="bl-stage-main">

                    <div class="bl-stage-indicator">

                        <span class="bl-stage-icon" style="background: ${sm.color}22; color: ${sm.color}; border: 1px solid ${sm.color}55;">

                            <i class="fa-solid ${sm.icon}"></i>

                        </span>

                        <div class="bl-stage-copy">

                            <div class="bl-stage-title-row">

                                <span class="bl-stage-kicker">CURRENT STAGE</span>

                                <span class="bl-stage-badge" style="background: ${sm.color}22; color: ${sm.color}; border: 1px solid ${sm.color}44;">${esc(sm.label)}</span>

                            </div>

                            <strong class="bl-stage-text">${esc(job.stage_message || sm.desc)}</strong>

                        </div>

                    </div>

                    ${progressHtml}

                </div>

                <div class="bl-stepper">

                    ${renderStageStepper(job)}

                </div>

            </section>



            <div class="bl-toolbar">

                ${['queued', 'running', 'cancelling'].includes(job.status) ? '<button id="bl-cancel" class="btn-secondary"><i class="fa-solid fa-stop"></i> Stop</button>' : ''}

                ${['failed', 'cancelled', 'interrupted'].includes(job.status) ? '<button id="bl-resume" class="btn-secondary"><i class="fa-solid fa-forward"></i> Resume</button>' : ''}

                <button id="bl-artifacts" class="btn-secondary ${state.showArtifacts ? 'active' : ''}"><i class="fa-solid fa-${state.showArtifacts ? 'folder-minus' : 'folder-open'}"></i> ${state.showArtifacts ? 'Hide Files' : 'All Files'}</button>

                ${!['queued', 'running', 'cancelling'].includes(job.status) ? `<a class="btn-secondary" href="${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/download" target="_blank" rel="noopener"><i class="fa-solid fa-file-zipper"></i> Download ZIP</a>` : ''}

                ${!['queued', 'running', 'cancelling'].includes(job.status) ? '<button id="bl-delete" class="btn-secondary"><i class="fa-solid fa-trash"></i> Delete</button>' : ''}

            </div>



            <!-- Navigation Tabs -->

            <nav class="bl-detail-tabs">

                <button type="button" class="bl-job-tab-btn ${state.jobTab === 'queue' ? 'active' : ''}" data-bl-job-tab="queue">

                    <i class="fa-solid fa-layer-group"></i> Sample Queue <span class="bl-tab-pill">${job.samples?.length || 0}</span>

                </button>

                <button type="button" class="bl-job-tab-btn ${state.jobTab === 'analysis' ? 'active' : ''}" data-bl-job-tab="analysis">

                    <i class="fa-solid fa-brain"></i> AI Analysis ${reports.some(r => r.is_html) ? '<span class="bl-tab-pill bl-tab-pill-ok">Report Ready</span>' : (['running', 'queued'].includes(job.status) && ['investigation', 'workspace'].includes(normalizeStageId(job.current_stage)) ? '<span class="bl-tab-pill bl-tab-pill-run"><i class="fa-solid fa-circle-notch mantis-spin"></i> Active</span>' : '')}

                </button>

                <button type="button" class="bl-job-tab-btn ${state.jobTab === 'functions' ? 'active' : ''}" data-bl-job-tab="functions">

                    <i class="fa-solid fa-code"></i> Functions <span class="bl-tab-pill" id="bl-tab-fn-pill">${counts.functions || ''}</span>

                </button>

                <button type="button" class="bl-job-tab-btn ${state.jobTab === 'variables' ? 'active' : ''}" data-bl-job-tab="variables">

                    <i class="fa-solid fa-cube"></i> Variables <span class="bl-tab-pill" id="bl-tab-var-pill">${counts.function_variables || ''}</span>

                </button>

                <button type="button" class="bl-job-tab-btn ${state.jobTab === 'reports' ? 'active' : ''}" data-bl-job-tab="reports">

                    <i class="fa-solid fa-file-shield"></i> Deliverables <span class="bl-tab-pill">${reports.length}</span>

                </button>

                <button type="button" class="bl-job-tab-btn ${state.jobTab === 'ida-log' ? 'active' : ''}" data-bl-job-tab="ida-log">

                    <i class="fa-solid fa-terminal"></i> IDA Log Viewer

                </button>

                <button type="button" class="bl-job-tab-btn ${state.jobTab === 'events' ? 'active' : ''}" data-bl-job-tab="events">

                    <i class="fa-solid fa-stream"></i> Event Stream <span class="bl-tab-pill">${events.length}</span>

                </button>

            </nav>



            <div class="bl-tab-content">

                ${tabContent}

            </div>



            <div id="bl-artifact-list"></div>`;

    }



    function renderTabAnalysis(job, reports) {

        const sampleIdx = state.activeSampleIndex || 0;

        const sample = (job.samples || [])[sampleIdx] || (job.samples || [])[0] || {};

        const sampleName = sample.name || '';

        const sampleHash = (sample.sha256 || '').substring(0, 12);



        // Find primary report for active sample (or first HTML report in job)

        let sRep = reports.find(r => r.is_html && (r.path.includes(sampleName) || (sampleHash && r.path.includes(sampleHash))));

        if (!sRep && reports.length) {

            sRep = reports.find(r => r.is_html) || reports[0];

        }



        const isRunning = ['running', 'queued'].includes(job.status);

        const curStageId = normalizeStageId(job.current_stage);

        const isAnalyzing = isRunning && (curStageId === 'investigation' || curStageId === 'renaming' || curStageId === 'workspace');



        if (!sRep && isAnalyzing) {

            return `<div class="bl-analysis-wrap">

                <div class="bl-analysis-running">

                    <div class="bl-analysis-spinner"><i class="fa-solid fa-robot mantis-spin"></i></div>

                    <div class="bl-analysis-running-copy">

                        <h3>Autonomous In-Database AI Investigation In Progress</h3>

                        <p>${esc(job.stage_message || 'The AI agent is actively reverse engineering functions, inspecting decompiled control flow, and discovering capabilities in IDA Pro...')}</p>

                        <div class="bl-analysis-steps">

                            <div class="bl-step-point active"><i class="fa-solid fa-check"></i> Binary Disassembly & Context Catalogs Extracted</div>

                            <div class="bl-step-point active"><i class="fa-solid fa-check"></i> Semantic Function & Variable Recovery Completed</div>

                            <div class="bl-step-point active"><i class="fa-solid fa-circle-notch mantis-spin"></i> Autonomous In-Database Deep Reverse Engineering & Threat Attribution</div>

                            <div class="bl-step-point"><i class="fa-regular fa-circle"></i> Compiling Publication-Grade Technical Research Report</div>

                        </div>

                    </div>

                </div>

            </div>`;

        }



        if (!sRep) {

            return `<div class="bl-empty" style="padding: 40px 20px;">

                <i class="fa-solid fa-brain" style="font-size: 2.5rem; margin-bottom: 12px; color: var(--accent); opacity: 0.8;"></i>

                <h3>No AI Analysis Report Available Yet</h3>

                <p>Run analysis with <strong>Analyze AI Workspace</strong> or <strong>Autonomous AI Investigation</strong> enabled to generate deep technical research reports.</p>

            </div>`;

        }



        const htmlUrl = `${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${sRep.path.split('/').map(encodeURIComponent).join('/')}`;

        const pdfUrl = sRep.pdf_path ? `${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${sRep.pdf_path.split('/').map(encodeURIComponent).join('/')}` : null;

        const mdPath = sRep.md_path || (sRep.path.replace(/\.html?$/i, '.md'));

        const mode = state.analysisMode || 'html';



        return `<div class="bl-analysis-wrap">

            <div class="bl-analysis-toolbar">

                <div class="bl-analysis-header-info">

                    <h3><i class="fa-solid fa-brain" style="color: var(--accent);"></i> AI Malware Analysis & Technical Report</h3>

                    <div class="bl-analysis-pills">

                        <span>Sample: <strong>${esc(sample.name || sRep.title || 'Analyzed Binary')}</strong></span>

                        ${sample.file_type ? `<span>${esc(sample.file_type)}</span>` : ''}

                        ${sRep.has_attribution && sRep.attribution_hypothesis ? `<span class="bl-badge bl-badge-attr" title="Structured Threat Attribution Verified"><i class="fa-solid fa-shield-halved"></i> Threat Attribution: <strong>${esc(sRep.attribution_hypothesis)}</strong> (${esc(sRep.attribution_confidence || 'Moderate')})</span>` : ''}

                    </div>

                </div>

                <div class="bl-analysis-actions">

                    <div class="bl-view-switch">

                        <button type="button" class="bl-switch-btn ${mode === 'html' ? 'active' : ''}" id="bl-switch-html" title="View formatted interactive HTML report"><i class="fa-solid fa-globe"></i> Interactive Report</button>

                        <button type="button" class="bl-switch-btn ${mode === 'md' ? 'active' : ''}" id="bl-switch-md" title="View Markdown technical text"><i class="fa-solid fa-file-lines"></i> Technical Notes (MD)</button>

                    </div>

                    <a class="btn-primary bl-sm-btn" href="${htmlUrl}" target="_blank" title="Open report directly in a new browser tab without downloading"><i class="fa-solid fa-arrow-up-right-from-square"></i> View in Tab</a>

                    <a class="btn-secondary bl-sm-btn" href="${htmlUrl}?download=1" download title="Download HTML report file"><i class="fa-solid fa-download"></i> Download HTML</a>

                    ${pdfUrl ? `<a class="btn-secondary bl-sm-btn" href="${pdfUrl}" target="_blank" title="View PDF directly in browser"><i class="fa-solid fa-file-pdf"></i> View PDF</a>` : ''}

                    ${pdfUrl ? `<a class="btn-secondary bl-sm-btn" href="${pdfUrl}?download=1" download title="Download PDF file"><i class="fa-solid fa-download"></i> Download PDF</a>` : ''}

                </div>

            </div>



            ${mode === 'html' ? `

            <div class="bl-analysis-iframe-container">

                <iframe class="bl-analysis-iframe" src="${htmlUrl}" title="AI Analysis Report" sandbox></iframe>

            </div>` : `

            <div class="bl-analysis-md-container" id="bl-analysis-md-view">

                <div class="bl-empty"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading technical markdown...</div>

            </div>`}

        </div>`;

    }



    function renderTabQueue(job, reports) {

        if (!job.samples?.length) {

            return '<div class="bl-empty"><i class="fa-solid fa-layer-group"></i> No samples in this job queue.</div>';

        }



        return `<div class="bl-queue-container">${job.samples.map((sample, index) => {

            const sampleName = sample.name || '';

            const sampleHash = (sample.sha256 || '').substring(0, 12);

            const isSingleSample = (job.samples || []).length === 1;

            const sHtmlRep = reports.find(r => r.is_html && (r.path.includes(sampleName) || (sampleHash && r.path.includes(sampleHash)) || isSingleSample));

            const sAttrRep = reports.find(r => r.is_attribution && (r.path.includes(sampleName) || (sampleHash && r.path.includes(sampleHash)) || isSingleSample));

            const sampleStage = (sample.status === 'running' && job.current_stage) ? job.current_stage : (sample.stage || sample.status);

            const sampleSm = stageMeta(sampleStage);

            const cnt = sample.counts || job.counts || {};

            const isMalicious = (cnt.triage_flagged || 0) > 0 || (sample.suspicious || false);



            const attrHyp = sample.attribution_hypothesis || sAttrRep?.attribution_hypothesis || (reports.find(r => r.attribution_hypothesis)?.attribution_hypothesis);

            const attrConf = sample.attribution_confidence || sAttrRep?.attribution_confidence || (reports.find(r => r.attribution_confidence)?.attribution_confidence) || 'High';



            return `

            <div class="bl-queue-card">

                <!-- Top Row: File Identity & Badges -->

                <div class="bl-qc-top">

                    <div class="bl-qc-identity">

                        <div class="bl-qc-icon-wrap ${isMalicious ? 'bl-qc-icon-mal' : ''}">

                            <i class="fa-solid ${isMalicious ? 'fa-shield-virus' : 'fa-file-shield'}"></i>

                        </div>

                        <div class="bl-qc-title-box">

                            <div class="bl-qc-name-row">

                                <h3 class="bl-qc-name">${esc(sample.name)}</h3>

                                <span class="bl-qc-tag">${esc(sample.file_type || sample.kind || 'PE Executable')}</span>

                                <span class="bl-qc-size">${fmtBytes(sample.size)}</span>

                            </div>

                            <div class="bl-qc-hashes">

                                ${sample.sha256 ? `

                                <span class="bl-qc-hash-pill" title="Click to copy full SHA-256" onclick="navigator.clipboard.writeText('${esc(sample.sha256)}'); showNotification('Copied SHA-256');">

                                    <span class="bl-hash-label">SHA-256</span>

                                    <code>${esc(sample.sha256.substring(0, 20))}...${esc(sample.sha256.substring(sample.sha256.length - 8))}</code>

                                    <i class="fa-regular fa-copy"></i>

                                </span>` : ''}

                                ${sample.md5 ? `

                                <span class="bl-qc-hash-pill" title="Click to copy full MD5" onclick="navigator.clipboard.writeText('${esc(sample.md5)}'); showNotification('Copied MD5');">

                                    <span class="bl-hash-label">MD5</span>

                                    <code>${esc(sample.md5)}</code>

                                    <i class="fa-regular fa-copy"></i>

                                </span>` : ''}

                            </div>

                        </div>

                    </div>



                    <div class="bl-qc-status-badges">

                        <span class="bl-state ${statusClass(sample.status)}">${esc(sample.status.toUpperCase())}</span>

                        <span class="bl-stage-pill ${statusClass(sample.status)}">

                            <i class="fa-solid ${sampleSm.icon}"></i> ${esc(sampleSm.label)}

                        </span>

                    </div>

                </div>



                <!-- 5 Metrics Tiles Grid -->

                <div class="bl-qc-metrics-grid">

                    <div class="bl-qc-metric-tile bl-qc-quick-tab" data-tab="functions" style="cursor: pointer;" title="Click to inspect functions catalog">

                        <div class="bl-qc-metric-icon"><i class="fa-solid fa-code"></i></div>

                        <div class="bl-qc-metric-data">

                            <span class="bl-qc-metric-val">${cnt.functions || 0}</span>

                            <span class="bl-qc-metric-lbl">Functions</span>

                        </div>

                    </div>

                    <div class="bl-qc-metric-tile bl-qc-quick-tab" data-tab="variables" style="cursor: pointer;" title="Click to inspect variables catalog">

                        <div class="bl-qc-metric-icon"><i class="fa-solid fa-cube"></i></div>

                        <div class="bl-qc-metric-data">

                            <span class="bl-qc-metric-val">${cnt.function_variables || 0}</span>

                            <span class="bl-qc-metric-lbl">Variables</span>

                        </div>

                    </div>

                    <div class="bl-qc-metric-tile">

                        <div class="bl-qc-metric-icon"><i class="fa-solid fa-quote-left"></i></div>

                        <div class="bl-qc-metric-data">

                            <span class="bl-qc-metric-val">${cnt.strings || 0}</span>

                            <span class="bl-qc-metric-lbl">Strings</span>

                        </div>

                    </div>

                    <div class="bl-qc-metric-tile">

                        <div class="bl-qc-metric-icon"><i class="fa-solid fa-arrow-right-to-bracket"></i></div>

                        <div class="bl-qc-metric-data">

                            <span class="bl-qc-metric-val">${cnt.imports || 0}</span>

                            <span class="bl-qc-metric-lbl">Imports</span>

                        </div>

                    </div>

                    <div class="bl-qc-metric-tile ${(cnt.triage_flagged || 0) > 0 ? 'bl-qc-metric-alert' : ''}">

                        <div class="bl-qc-metric-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>

                        <div class="bl-qc-metric-data">

                            <span class="bl-qc-metric-val">${cnt.triage_flagged || 0}</span>

                            <span class="bl-qc-metric-lbl">Suspicious</span>

                        </div>

                    </div>

                </div>



                <!-- Threat Attribution Callout (if available) -->

                ${(sAttrRep || attrHyp) ? `

                <div class="bl-qc-attrib-callout">

                    <div class="bl-qc-attrib-badge">

                        <i class="fa-solid fa-shield-halved"></i> Threat Attribution Assessment

                    </div>

                    <div class="bl-qc-attrib-body">

                        <div>

                            <span class="bl-qc-attrib-label">Attributed Actor / Malware Cluster</span>

                            <strong class="bl-qc-attrib-hyp">${esc(attrHyp || 'Candidate Malware Family')}</strong>

                        </div>

                        <div>

                            <span class="bl-qc-attrib-label">Confidence</span>

                            <span class="bl-conf-pill ${((attrConf || 'high').toLowerCase())}">${esc(attrConf)}</span>

                        </div>

                    </div>

                </div>` : ''}



                <!-- Bottom Actions Bar -->

                <div class="bl-qc-actions">

                    <div class="bl-qc-actions-left">

                        <button type="button" class="btn-secondary bl-sm-btn bl-qc-quick-tab" data-tab="functions">

                            <i class="fa-solid fa-code"></i> Inspect Functions (${cnt.functions || 0})

                        </button>

                        <button type="button" class="btn-secondary bl-sm-btn bl-qc-quick-tab" data-tab="variables">

                            <i class="fa-solid fa-cube"></i> Variables (${cnt.function_variables || 0})

                        </button>

                    </div>

                    <div class="bl-qc-actions-right">

                        ${sHtmlRep ? `

                        <button type="button" class="btn-primary bl-sm-btn bl-view-analysis-btn" data-sample-idx="${index}">

                            <i class="fa-solid fa-brain"></i> AI Analysis

                        </button>

                        <a class="btn-secondary bl-sm-btn" href="${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${sHtmlRep.path.split('/').map(encodeURIComponent).join('/')}" target="_blank">

                            <i class="fa-solid fa-file-code"></i> HTML Report

                        </a>` : ''}

                        ${sAttrRep ? `

                        <a class="btn-secondary bl-sm-btn bl-btn-attr" href="${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${sAttrRep.path.split('/').map(encodeURIComponent).join('/')}" target="_blank">

                            <i class="fa-solid fa-shield-halved"></i> Attribution

                        </a>` : ''}

                        ${sample.status === 'complete' ? `
                        <button type="button" class="btn-secondary bl-sm-btn" data-case-index="${index}">
                            <i class="fa-solid fa-briefcase"></i> Create Case
                        </button>
                        <button type="button" class="btn-primary bl-sm-btn bl-btn-aead" data-aead-hash="${esc(sample.sha256 || sample.name || '')}" title="Run Autonomous AEAD Investigation (Acquire → Enrich → Discover & Pivot → Analyze → Deliver)">
                            <i class="fa-solid fa-wand-magic-sparkles"></i> Run AEAD Investigation
                        </button>` : ''}

                    </div>

                </div>

            </div>`;

        }).join('')}</div>`;

    }



        function renderTabFunctions(job) {

        const cat = state.catalogs[job.job_id];

        if (!cat) {

            loadCatalogs(job.job_id);

            return '<div class="bl-empty"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading function catalog...</div>';

        }

        let funcs = cat.functions || [];

        if (!funcs.length) return '<div class="bl-empty">No analyzed functions available for this job yet.</div>';



        const filterText = (state.fnFilter || '').toLowerCase().trim();

        const scoreFilter = state.fnScoreFilter || 'all';



        const filtered = funcs.filter(f => {

            if (scoreFilter === 'suspicious' && !(f.triage_score > 0)) return false;

            if (scoreFilter === 'renamed' && !f.original_name) return false;

            if (filterText) {

                const combined = `${f.address} ${f.name} ${f.original_name || ''} ${(f.capabilities || []).join(' ')} ${(f.imports_called || []).join(' ')}`.toLowerCase();

                return combined.includes(filterText);

            }

            return true;

        });



        return `<div>

            <div class="bl-tab-search-bar">

                <div class="bl-search-input-wrap">

                    <i class="fa-solid fa-magnifying-glass"></i>

                    <input type="text" id="bl-fn-search" value="${esc(state.fnFilter)}" placeholder="Filter functions by name, address, capability, or imports...">

                </div>

                <select id="bl-fn-score-filter" class="bl-filter-select">

                    <option value="all" ${scoreFilter === 'all' ? 'selected' : ''}>All Functions (${funcs.length})</option>

                    <option value="suspicious" ${scoreFilter === 'suspicious' ? 'selected' : ''}>Suspicious Only (Score > 0)</option>

                    <option value="renamed" ${scoreFilter === 'renamed' ? 'selected' : ''}>AI Renamed Only</option>

                </select>

                <small style="color: var(--text-muted); font-size: .72rem;">Showing ${filtered.length} of ${funcs.length}</small>

            </div>

            <div class="bl-table-wrap">

                <table class="bl-data-table">

                    <thead>

                        <tr>

                            <th>Address</th>

                            <th>Function Name</th>

                            <th>Original Name</th>

                            <th>Size</th>

                            <th>Triage Score</th>

                            <th>Capabilities</th>

                            <th>Imports Called</th>

                            <th>Callers / Callees</th>

                        </tr>

                    </thead>

                    <tbody>

                        ${filtered.slice(0, 300).map(f => {

                            const scoreClass = f.triage_score >= 10 ? 'bl-score-high' : (f.triage_score > 0 ? 'bl-score-med' : 'bl-score-low');

                            return `<tr>

                                <td class="bl-mono bl-nowrap">${esc(f.address)}</td>

                                <td>

                                    <strong>${esc(f.name)}</strong>

                                    ${f.original_name ? '<span class="bl-renamed-tag"><i class="fa-solid fa-wand-magic-sparkles"></i> Renamed</span>' : ''}

                                </td>

                                <td class="bl-nowrap"><span class="bl-mono" style="color: var(--text-muted);">${f.original_name ? esc(f.original_name) : '—'}</span></td>

                                <td class="bl-nowrap">${f.size} B</td>

                                <td class="bl-nowrap"><span class="bl-score-pill ${scoreClass}">${f.triage_score || 0}</span></td>

                                <td>${(f.capabilities || []).map(c => `<span class="bl-cap-tag">${esc(c)}</span>`).join('') || '—'}</td>

                                <td style="max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${esc((f.imports_called || []).join(', '))}">

                                    ${esc((f.imports_called || []).join(', ')) || '—'}

                                </td>

                                <td class="bl-mono bl-nowrap">${(f.callers || []).length} / ${(f.callees || []).length}</td>

                            </tr>`;

                        }).join('')}

                    </tbody>

                </table>

            </div>

        </div>`;

    }



    function renderTabVariables(job) {

        const cat = state.catalogs[job.job_id];

        if (!cat) {

            loadCatalogs(job.job_id);

            return '<div class="bl-empty"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading variables catalog...</div>';

        }

        let vars = cat.variables || [];

        if (!vars.length) return '<div class="bl-empty">No function variable records available for this job yet.</div>';



        const filterText = (state.varFilter || '').toLowerCase().trim();

        const kindFilter = state.varKindFilter || 'all';



        const filtered = vars.filter(v => {

            if (kindFilter === 'arg' && !v.argument) return false;

            if (kindFilter === 'local' && v.argument) return false;

            if (kindFilter === 'renamed' && !v.user_name) return false;

            if (filterText) {

                const combined = `${v.name || ''} ${v.function_name || ''} ${v.function_address || ''} ${v.type || ''} ${v.location || ''}`.toLowerCase();

                return combined.includes(filterText);

            }

            return true;

        });



        return `<div>

            <div class="bl-tab-search-bar">

                <div class="bl-search-input-wrap">

                    <i class="fa-solid fa-magnifying-glass"></i>

                    <input type="text" id="bl-var-search" value="${esc(state.varFilter)}" placeholder="Filter variables by name, function, type, or stack offset...">

                </div>

                <select id="bl-var-kind-filter" class="bl-filter-select">

                    <option value="all" ${kindFilter === 'all' ? 'selected' : ''}>All Variables (${vars.length})</option>

                    <option value="arg" ${kindFilter === 'arg' ? 'selected' : ''}>Parameters / Arguments</option>

                    <option value="local" ${kindFilter === 'local' ? 'selected' : ''}>Local Variables</option>

                    <option value="renamed" ${kindFilter === 'renamed' ? 'selected' : ''}>AI Renamed Only</option>

                </select>

                <small style="color: var(--text-muted); font-size: .72rem;">Showing ${filtered.length} of ${vars.length}</small>

            </div>

            <div class="bl-table-wrap">

                <table class="bl-data-table">

                    <thead>

                        <tr>

                            <th>Function</th>

                            <th>Variable Name</th>

                            <th>Type</th>

                            <th>Location / Offset</th>

                            <th>Kind</th>

                            <th>AI Renamed</th>

                        </tr>

                    </thead>

                    <tbody>

                        ${filtered.slice(0, 300).map(v => {

                            return `<tr>

                                <td>

                                    <strong>${esc(v.function_name || '')}</strong>

                                    <small class="bl-mono" style="display: block; color: var(--text-muted);">${esc(v.function_address || '')}</small>

                                </td>

                                <td><strong>${esc(v.name || '')}</strong></td>

                                <td class="bl-mono" style="color: #cbd5e1;">${esc(v.type || 'unknown')}</td>

                                <td class="bl-mono">${esc(v.location || '—')}</td>

                                <td><span class="bl-badge" style="background: rgba(255,255,255,.07);">${v.argument ? 'Argument' : 'Local'}</span></td>

                                <td>${v.user_name ? '<span class="bl-renamed-tag"><i class="fa-solid fa-wand-magic-sparkles"></i> Yes</span>' : '<span style="color: var(--text-muted);">Default</span>'}</td>

                            </tr>`;

                        }).join('')}

                    </tbody>

                </table>

            </div>

        </div>`;

    }



    function renderTabIdaLog(job) {

        const logData = state.idaLogs[job.job_id];

        if (!logData) {

            loadIdaLog(job.job_id);

            return '<div class="bl-empty"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading IDA / Engine log...</div>';

        }

        const text = logData.content || '';

        const filter = (state.idaLogFilter || '').toLowerCase();

        let lines = text.split('\n');



        // Optional filter for headless Qt plugin import noise

        if (state.idaFilterNoise) {

            lines = lines.filter(l => {

                const low = l.toLowerCase();

                return !(

                    low.includes('pyside6 can only be used from the gui version of ida') ||

                    low.includes('name \'qtwidgets\' is not defined') ||

                    low.includes('_verify_prerequisites()') ||

                    low.includes('from pyqt5 import') ||

                    low.includes('import pyqt5') ||

                    low.includes('import pyside6') ||

                    low.includes('rikugan_plugin.py') ||

                    low.includes('apply_callee_type_ex.py') ||

                    low.includes('comida.py') ||

                    low.includes('auto_re.py') ||

                    low.includes('findfuncmain.py') ||

                    low.includes('idafind.py') ||

                    low.includes('showcomments.py') ||

                    low.includes('cvutils-') ||

                    low.includes('dereferencing')

                );

            });

        }



        const filtered = filter ? lines.filter(l => l.toLowerCase().includes(filter)) : lines;



        const highlighted = filtered.map((line, idx) => {

            let cls = '';

            const low = line.toLowerCase();

            if (low.includes('error') || low.includes('traceback') || low.includes('exception')) cls = 'bl-log-err';

            else if (low.includes('warning')) cls = 'bl-log-warn';

            else if (line.includes('OMNI_EVENT')) cls = 'bl-log-omni';

            return `<div class="${cls}"><span class="bl-log-time" style="user-select: none; margin-right: 8px;">${idx + 1}</span>${esc(line)}</div>`;

        }).join('');



        return `<div>

            <div class="bl-ida-banner">

                <i class="fa-solid fa-circle-info"></i>

                <span><strong>Headless Mode Execution:</strong> IDA Pro runs batch analysis via <code>idat.exe</code> (console mode). Interactive GUI plugins requiring a desktop Qt window (PySide6 / PyQt5) are skipped by IDA and do not affect analysis or Hex-Rays decompilation.</span>

            </div>

            <div class="bl-tab-search-bar">

                <div class="bl-search-input-wrap">

                    <i class="fa-solid fa-magnifying-glass"></i>

                    <input type="text" id="bl-ida-filter" value="${esc(state.idaLogFilter)}" placeholder="Filter IDA / engine log lines...">

                </div>

                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">

                    <label style="display: flex; align-items: center; gap: 5px; font-size: .75rem; color: #bae6fd; cursor: pointer;" title="Hide non-critical Qt GUI plugin startup errors caused by running headlessly">

                        <input type="checkbox" id="bl-ida-filter-noise" ${state.idaFilterNoise ? 'checked' : ''}> Hide GUI Plugin Noise

                    </label>

                    <label style="display: flex; align-items: center; gap: 5px; font-size: .75rem; color: var(--text-muted); cursor: pointer;">

                        <input type="checkbox" id="bl-ida-autoscroll" ${state.idaAutoScroll ? 'checked' : ''}> Auto-scroll

                    </label>

                    <button type="button" class="btn-secondary bl-sm-btn" id="bl-ida-refresh"><i class="fa-solid fa-rotate"></i> Refresh</button>

                    <button type="button" class="btn-secondary bl-sm-btn" id="bl-ida-copy"><i class="fa-regular fa-copy"></i> Copy Log</button>

                </div>

            </div>

            <div class="bl-console dark-scroll" id="bl-ida-log-view">${highlighted || '<span style="color: var(--text-muted);">No log output recorded yet.</span>'}</div>

        </div>`;

    }



    function renderTabReports(job, reports) {

        if (!reports.length) {

            return `<div class="bl-empty" style="padding: 40px 20px;">

                <i class="fa-solid fa-box-open" style="font-size: 2.5rem; margin-bottom: 12px; color: var(--accent); opacity: 0.8;"></i>

                <h3>No Deliverables Available Yet</h3>

                <p>Run analysis with <strong>Analyze AI Workspace</strong> enabled to generate interactive reports, PDFs, and enriched IDB databases.</p>

            </div>`;

        }



        // Collect unique companion files across reports

        const companionsMap = new Map();

        reports.forEach(r => {

            (r.companion_files || []).forEach(comp => {

                if (!companionsMap.has(comp.name)) companionsMap.set(comp.name, comp);

            });

        });

        const allCompanions = Array.from(companionsMap.values());

        const totalCompanions = allCompanions.length;

        const hasAnyAttr = reports.some(r => r.has_attribution);

        const primaryAttr = reports.find(r => r.has_attribution && r.attribution_hypothesis);



        return `<div class="bl-deliverables-portal">

            <!-- Header & Deliverable Stats Banner -->

            <div class="bl-deliv-header">

                <div class="bl-deliv-title-group">

                    <div class="bl-deliv-icon-badge">

                        <i class="fa-solid fa-box-archive"></i>

                    </div>

                    <div>

                        <h2>Intelligence Deliverables & Reports</h2>

                        <p>Publication-grade research dossiers, annotated reverse engineering databases, and threat attribution assessments.</p>

                    </div>

                </div>

                <div class="bl-deliv-stats">

                    <div class="bl-deliv-stat-chip">

                        <span class="bl-deliv-stat-val">${reports.length}</span>

                        <span class="bl-deliv-stat-lbl">Reports</span>

                    </div>

                    <div class="bl-deliv-stat-chip">

                        <span class="bl-deliv-stat-val">${totalCompanions}</span>

                        <span class="bl-deliv-stat-lbl">Databases</span>

                    </div>

                    <div class="bl-deliv-stat-chip bl-stat-accent">

                        <span class="bl-deliv-stat-val"><i class="fa-solid fa-shield-halved"></i></span>

                        <span class="bl-deliv-stat-lbl">${hasAnyAttr ? 'Attributed' : 'Verified'}</span>

                    </div>

                </div>

            </div>



            <!-- Deliverable Dossier Cards (one per sample/report) -->

            ${reports.map((rep, repIdx) => {

                const sampleName = rep.sample_name || rep.name || '';

                const sample = (job.samples || []).find(s => s.name === sampleName || (s.name && rep.path.includes(s.name))) || (job.samples || [])[repIdx] || {};

                const htmlUrl = `${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${rep.path.split('/').map(encodeURIComponent).join('/')}`;

                const pdfUrl = rep.pdf_path ? `${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${rep.pdf_path.split('/').map(encodeURIComponent).join('/')}` : null;

                const mdUrl = rep.md_path ? `${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${rep.md_path.split('/').map(encodeURIComponent).join('/')}` : null;

                const attrUrl = rep.attribution_report_path ? `${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${rep.attribution_report_path.split('/').map(encodeURIComponent).join('/')}` : null;

                const confLower = (rep.attribution_confidence || 'moderate').toLowerCase();



                return `<div class="bl-deliv-hero-card">

                    <!-- Hero Top Header -->

                    <div class="bl-deliv-hero-top">

                        <div class="bl-deliv-hero-meta">

                            <div class="bl-deliv-tag-row">

                                <span class="bl-badge-deliv-target"><i class="fa-solid fa-crosshairs"></i> Target Binary</span>

                                <span class="bl-badge-deliv-fmt">${esc(sample.file_type || sample.kind || 'PE Executable')}</span>

                                ${sample.size ? `<span class="bl-badge-deliv-size">${fmtBytes(sample.size)}</span>` : ''}

                            </div>

                            <h3 class="bl-deliv-hero-title">${esc(rep.title || `${sample.name || 'Binary'} Malware Analysis & Intelligence Report`)}</h3>

                            <div class="bl-deliv-hashes">

                                ${sample.sha256 ? `<span class="bl-hash-tag" title="Click to copy SHA-256" onclick="navigator.clipboard.writeText('${esc(sample.sha256)}'); showNotification('Copied SHA256');"><i class="fa-regular fa-copy"></i> SHA256: <code>${esc(sample.sha256.substring(0, 24))}...</code></span>` : ''}

                                ${sample.md5 ? `<span class="bl-hash-tag" title="Click to copy MD5" onclick="navigator.clipboard.writeText('${esc(sample.md5)}'); showNotification('Copied MD5');"><i class="fa-regular fa-copy"></i> MD5: <code>${esc(sample.md5)}</code></span>` : ''}

                            </div>

                        </div>

                        <div class="bl-deliv-hero-actions">

                            <a class="btn-primary bl-deliv-main-btn" href="${htmlUrl}" target="_blank" title="Open report directly in a new browser tab without downloading">

                                <i class="fa-solid fa-arrow-up-right-from-square"></i> Open in Browser

                            </a>

                            <a class="btn-secondary bl-deliv-dl-btn" href="${htmlUrl}?download=1" download title="Download HTML report to disk">

                                <i class="fa-solid fa-download"></i> Download

                            </a>

                            <button type="button" class="btn-secondary bl-deliv-preview-btn" data-preview-idx="${repIdx}" data-preview-url="${htmlUrl}" title="Toggle interactive preview right below">

                                <i class="fa-solid fa-eye"></i> Quick Preview

                            </button>

                        </div>

                    </div>



                    <!-- Threat Attribution Callout Box -->

                    ${rep.has_attribution ? `

                    <div class="bl-deliv-attrib-box">

                        <div class="bl-deliv-attrib-badge">

                            <i class="fa-solid fa-shield-halved"></i>

                            <span>FAREED FAUZI 6-CATEGORY ATTRIBUTION ASSESSMENT</span>

                        </div>

                        <div class="bl-deliv-attrib-content">

                            <div class="bl-deliv-attrib-actor">

                                <label>Attributed Threat Actor / Tooling Hypothesis</label>

                                <strong>${esc(rep.attribution_hypothesis || 'Unknown Threat Actor / Commodity Tooling')}</strong>

                            </div>

                            <div class="bl-deliv-attrib-confidence">

                                <label>Assessment Confidence</label>

                                <span class="bl-conf-pill ${esc(confLower)}">

                                    <i class="fa-solid ${confLower === 'high' ? 'fa-circle-check' : (confLower === 'moderate' ? 'fa-circle-exclamation' : 'fa-circle-question')}"></i>

                                    ${esc(rep.attribution_confidence || 'MODERATE')}

                                </span>

                            </div>

                        </div>

                    </div>` : ''}



                    <!-- Deliverable Document Formats Grid -->

                    <div class="bl-deliv-formats-grid">

                        <!-- Format 1: Interactive HTML -->

                        <div class="bl-deliv-format-card">

                            <div class="bl-dfc-head">

                                <div class="bl-format-icon html"><i class="fa-solid fa-file-code"></i></div>

                                <span class="bl-dfc-badge-pill html">Interactive HTML</span>

                            </div>

                            <div class="bl-dfc-body">

                                <h4 class="bl-dfc-title">Interactive Omni Report</h4>

                                <p class="bl-dfc-desc">Dynamic web intelligence dossier with call graphs, decompiled syntax, string xrefs, and MITRE ATT&CK.</p>

                            </div>

                            <div class="bl-dfc-meta">

                                <span><i class="fa-regular fa-file"></i> <code>report.html</code></span>

                                <span>·</span>

                                <span>${fmtBytes(rep.size)}</span>

                            </div>

                            <div class="bl-dfc-actions">

                                <a class="btn-primary bl-sm-btn" href="${htmlUrl}" target="_blank" title="View interactive report in browser">

                                    <i class="fa-solid fa-arrow-up-right-from-square"></i> Open in Browser

                                </a>

                                <a class="btn-secondary bl-sm-btn" href="${htmlUrl}?download=1" download title="Download HTML file">

                                    <i class="fa-solid fa-download"></i> Download

                                </a>

                            </div>

                        </div>



                        <!-- Format 2: Vector PDF -->

                        ${pdfUrl ? `

                        <div class="bl-deliv-format-card">

                            <div class="bl-dfc-head">

                                <div class="bl-format-icon pdf"><i class="fa-solid fa-file-pdf"></i></div>

                                <span class="bl-dfc-badge-pill pdf">Vector PDF</span>

                            </div>

                            <div class="bl-dfc-body">

                                <h4 class="bl-dfc-title">Printable Executive Dossier</h4>

                                <p class="bl-dfc-desc">Vector-rendered executive intelligence brief ready for legal forensic records and stakeholder briefings.</p>

                            </div>

                            <div class="bl-dfc-meta">

                                <span><i class="fa-regular fa-file-pdf"></i> <code>report.pdf</code></span>

                                <span>·</span>

                                <span>Publication Grade</span>

                            </div>

                            <div class="bl-dfc-actions">

                                <a class="btn-primary bl-sm-btn" href="${pdfUrl}" target="_blank" title="View PDF directly in browser">

                                    <i class="fa-solid fa-file-pdf"></i> Open in Browser

                                </a>

                                <a class="btn-secondary bl-sm-btn" href="${pdfUrl}?download=1" download title="Download PDF file">

                                    <i class="fa-solid fa-download"></i> Download

                                </a>

                            </div>

                        </div>` : ''}



                        <!-- Format 3: Raw Markdown -->

                        ${mdUrl ? `

                        <div class="bl-deliv-format-card">

                            <div class="bl-dfc-head">

                                <div class="bl-format-icon md"><i class="fa-solid fa-file-lines"></i></div>

                                <span class="bl-dfc-badge-pill md">Markdown</span>

                            </div>

                            <div class="bl-dfc-body">

                                <h4 class="bl-dfc-title">Technical Markdown Notes</h4>

                                <p class="bl-dfc-desc">Structured analyst markdown report with function triage tables and observable IOC indicators.</p>

                            </div>

                            <div class="bl-dfc-meta">

                                <span><i class="fa-regular fa-file-lines"></i> <code>report.md</code></span>

                                <span>·</span>

                                <span>Technical Notes</span>

                            </div>

                            <div class="bl-dfc-actions">

                                <a class="btn-primary bl-sm-btn" href="${mdUrl}" target="_blank" title="View markdown in new browser tab">

                                    <i class="fa-solid fa-arrow-up-right-from-square"></i> Open in Browser

                                </a>

                                <a class="btn-secondary bl-sm-btn" href="${mdUrl}?download=1" download title="Download markdown file">

                                    <i class="fa-solid fa-download"></i> Download

                                </a>

                            </div>

                        </div>` : ''}



                        <!-- Format 4: Threat Attribution Raw Report (if available) -->

                        ${attrUrl ? `

                        <div class="bl-deliv-format-card">

                            <div class="bl-dfc-head">

                                <div class="bl-format-icon attr"><i class="fa-solid fa-shield-halved"></i></div>

                                <span class="bl-dfc-badge-pill attr">Attribution</span>

                            </div>

                            <div class="bl-dfc-body">

                                <h4 class="bl-dfc-title">Attribution Dossier</h4>

                                <p class="bl-dfc-desc">Raw 6-category threat attribution synthesis, IOC lookup records, and diamond model pivots.</p>

                            </div>

                            <div class="bl-dfc-meta">

                                <span><i class="fa-solid fa-shield-halved"></i> <code>threat_attribution_result.md</code></span>

                                <span>·</span>

                                <span>OSINT Synthesis</span>

                            </div>

                            <div class="bl-dfc-actions">

                                <a class="btn-primary bl-sm-btn" href="${attrUrl}" target="_blank" title="View attribution dossier in new browser tab">

                                    <i class="fa-solid fa-arrow-up-right-from-square"></i> Open in Browser

                                </a>

                                <a class="btn-secondary bl-sm-btn" href="${attrUrl}?download=1" download title="Download dossier file">

                                    <i class="fa-solid fa-download"></i> Download

                                </a>

                            </div>

                        </div>` : ''}

                    </div>



                    <!-- Inline Interactive Preview Container -->

                    <div class="bl-deliv-inline-preview" id="bl-deliv-preview-${repIdx}" style="display: none;">

                        <div class="bl-preview-bar">

                            <span><i class="fa-solid fa-eye"></i> Inline Interactive Preview: ${esc(rep.title || rep.name)}</span>

                            <button type="button" class="bl-preview-close-btn" data-close-preview="${repIdx}"><i class="fa-solid fa-xmark"></i> Close Preview</button>

                        </div>

                        <iframe class="bl-deliv-iframe" id="bl-deliv-iframe-${repIdx}" src="about:blank" sandbox></iframe>

                    </div>

                </div>`;

            }).join('')}



            <!-- Enriched IDBs & Reverse Engineering Databases Section -->

            <div class="bl-deliv-companions-section">

                <div class="bl-section-heading">

                    <div class="bl-heading-icon"><i class="fa-solid fa-database"></i></div>

                    <div>

                        <h3>Enriched IDBs & Reverse Engineering Databases</h3>

                        <p>Ready-to-inspect disassembler databases with AI-recovered subroutine names, variables, and type annotations.</p>

                    </div>

                </div>



                <div class="bl-companions-grid">

                    ${allCompanions.map(comp => {

                        const compUrl = `${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${comp.path.split('/').map(encodeURIComponent).join('/')}`;

                        const nameLower = comp.name.toLowerCase();

                        const isYara = nameLower.endsWith('.yar') || nameLower.endsWith('.yara');

                        const isAnalyzed = nameLower.startsWith('analyzed');

                        const isOriginal = nameLower.startsWith('original');

                        const isZip = nameLower.endsWith('.zip');

                        const badgeText = isYara ? 'YARA Rule' : (isAnalyzed ? 'Enriched Database' : (isOriginal ? 'Baseline IDB' : (isZip ? 'Archive' : 'Database')));

                        const descText = isYara 
                            ? 'Production-ready YARA detection rule targeting distinctive indicators, strings, and binary structures.'
                            : (isAnalyzed 
                                ? 'Annotated IDA database with LLM recovered function prototypes, variable names, and triage scores.'
                                : (isOriginal 
                                    ? 'Pristine baseline IDA disassembly database before automated AI enrichment.' 
                                    : 'Reverse engineering database file produced during headless analysis.'));

                        const metaText = isYara 
                            ? `${fmtBytes(comp.size)} · Detection Engineering Signature`
                            : `${fmtBytes(comp.size)} · ${isAnalyzed ? 'IDA Pro Enriched Database' : (isOriginal ? 'Baseline Disassembly Database' : 'Database Archive')}`;

                        const iconClass = isYara ? 'fa-file-shield' : (isZip ? 'fa-file-zipper' : 'fa-database');

                        return `<div class="bl-companion-card ${isZip ? 'is-zip' : (isYara ? 'is-yara' : '')}">

                            <div class="bl-comp-icon">

                                <i class="fa-solid ${iconClass}"></i>

                            </div>

                            <div class="bl-comp-info">

                                <h4><span>${esc(comp.name)}</span> <span class="bl-comp-badge">${badgeText}</span></h4>

                                <p>${descText}</p>

                                <div class="bl-comp-meta">${metaText}</div>

                            </div>

                            <a class="btn-secondary bl-sm-btn" href="${compUrl}" download>

                                <i class="fa-solid fa-download"></i> Download

                            </a>

                        </div>`;

                    }).join('')}



                    <!-- Full Workspace Archive ZIP -->

                    <div class="bl-companion-card is-zip">

                        <div class="bl-comp-icon"><i class="fa-solid fa-file-zipper"></i></div>

                        <div class="bl-comp-info">

                            <h4><span>Full AI Workspace (.ZIP)</span> <span class="bl-comp-badge" style="background: rgba(251, 191, 36, 0.15); color: #fbbf24; border-color: rgba(251, 191, 36, 0.3);">Full Bundle</span></h4>

                            <p>Complete workspace directory with all JSON catalogs, source trees, CFGs, and runbooks.</p>

                            <div class="bl-comp-meta">Direct Engine Export Package</div>

                        </div>

                        <a class="btn-secondary bl-sm-btn" href="${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/download" target="_blank">

                            <i class="fa-solid fa-download"></i> Download ZIP

                        </a>

                    </div>

                </div>

            </div>

        </div>`;

    }



    function renderTabEvents(events) {

        return `<div class="bl-events" style="max-height: 480px;">${events.map(event => {

            const d = event.data || {};

            let msg = event.message || d.message || event.status || event.stage || '';

            if (event.kind === 'ida_log_line' && d.line && d.line.includes('OMNI_EVENT')) {

                try {

                    const parsed = JSON.parse(d.line.split('OMNI_EVENT')[1]);

                    msg = `[${parsed.stage || 'step'}] ${parsed.message || ''} ${parsed.current ? `(${parsed.current}/${parsed.total})` : ''}`;

                } catch (_) {}

            }

            return `<div>

                <time>${esc(event.time)}</time>

                <b>${esc(event.kind)}</b>

                <span>${esc(msg)}</span>

            </div>`;

        }).join('') || '<span>No events recorded yet.</span>'}</div>`;

    }



    async function loadMarkdownReport() {

        if (!state.selectedJob) return;

        const job = state.jobs.find(j => j.job_id === state.selectedJob);

        if (!job) return;

        const reports = job.reports || [];

        const sampleIdx = state.activeSampleIndex || 0;

        const sample = (job.samples || [])[sampleIdx] || (job.samples || [])[0] || {};

        const sampleName = sample.name || '';

        const sampleHash = (sample.sha256 || '').substring(0, 12);



        let sRep = reports.find(r => r.is_html && (r.path.includes(sampleName) || (sampleHash && r.path.includes(sampleHash))));

        if (!sRep && reports.length) sRep = reports.find(r => r.is_html) || reports[0];

        if (!sRep) return;



        const mdRel = sRep.md_path || sRep.path.replace(/\.html?$/i, '.md');

        const container = document.getElementById('bl-analysis-md-view');

        if (!container) return;



        if (state.analysisMarkdownCache[mdRel]) {

            container.innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin: 0;">${esc(state.analysisMarkdownCache[mdRel])}</pre>`;

            return;

        }



        try {

            const res = await fetch(`${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(job.job_id)}/artifacts/${mdRel.split('/').map(encodeURIComponent).join('/')}`);

            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const text = await res.text();

            state.analysisMarkdownCache[mdRel] = text;

            if (state.jobTab === 'analysis' && state.analysisMode === 'md') {

                container.innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin: 0;">${esc(text)}</pre>`;

            }

        } catch (err) {

            if (container) container.innerHTML = `<div class="bl-empty" style="color: #f87171;">Failed to load markdown: ${esc(err.message)}</div>`;

        }

    }



    async function loadCatalogs(jobId, sampleIndex = (state.activeSampleIndex || 0)) {

        try {

            const data = await request(`/api/binary-lab/jobs/${encodeURIComponent(jobId)}/catalogs?sample_index=${encodeURIComponent(sampleIndex)}`);

            state.catalogs[jobId] = data;

            const fnPill = document.getElementById('bl-tab-fn-pill');

            if (fnPill && data.functions) fnPill.textContent = data.functions.length;

            const varPill = document.getElementById('bl-tab-var-pill');

            if (varPill && data.variables) varPill.textContent = data.variables.length;

            if (['functions', 'variables'].includes(state.jobTab)) render();

        } catch (_) {}

    }



    async function loadIdaLog(jobId, sampleIndex = (state.activeSampleIndex || 0)) {

        try {

            const data = await request(`/api/binary-lab/jobs/${encodeURIComponent(jobId)}/ida-log?sample_index=${encodeURIComponent(sampleIndex)}`);

            state.idaLogs[jobId] = data;

            if (state.jobTab === 'ida-log') {

                render();

                if (state.idaAutoScroll) {

                    const el = document.getElementById('bl-ida-log-view');

                    if (el) el.scrollTop = el.scrollHeight;

                }

            }

        } catch (_) {}

    }



    function providerOptions(selected = null) {

        const sel = selected || state.settings.provider || 'OpenAI';

        return (state.settings.providers || []).map(item => {

            const isCli = ['AntigravityCLI', 'ChatGPTAccount', 'ClaudeCode', 'CopilotCLI', 'OpenCode'].includes(item.id);

            const badge = isCli ? ' (CLI / Account)' : '';

            return `<option value="${esc(item.id)}" ${item.id === sel ? 'selected' : ''}>${esc(item.id)}${badge}</option>`;

        }).join('');

    }



    function renderSettings() {

        const s = state.settings;

        return `<form id="bl-settings" class="bl-grid">

            <section class="bl-card bl-card-wide"><div class="bl-card-head"><div><h2>Engine and Disassemblers</h2><p>Runtime paths and execution controls for IDA Pro and Ghidra.</p></div><i class="fa-solid fa-microchip"></i></div>

                <div class="bl-form-grid">

                    <label class="bl-field"><span>Default Disassembler</span><select id="bl-set-disassembler">

                        <option value="ida" ${(s.disassembler || 'ida') === 'ida' ? 'selected' : ''}>IDA Pro (Headless)</option>

                        <option value="ghidra" ${s.disassembler === 'ghidra' ? 'selected' : ''}>Ghidra (Headless)</option>

                        <option value="auto" ${s.disassembler === 'auto' ? 'selected' : ''}>Auto-detect (IDA or Ghidra)</option>

                    </select></label>

                    <label class="bl-field">

                        <span>IDA executable (idat.exe) path</span>

                        <div class="bl-input-browse">

                            <input id="bl-set-ida" type="text" value="${esc(s.ida_path)}" placeholder="e.g. C:\\Program Files\\IDA Pro 9.0\\idat64.exe">

                            <button type="button" class="btn-secondary bl-browse-btn" id="bl-browse-ida" title="Browse for IDA Pro executable"><i class="fa-solid fa-folder-open"></i> Browse</button>

                        </div>

                    </label>

                    <label class="bl-field">

                        <span>Ghidra analyzeHeadless / root path</span>

                        <div class="bl-input-browse">

                            <input id="bl-set-ghidra" type="text" value="${esc(s.ghidra_path)}" placeholder="e.g. C:\\Tools\\ghidra_11.2_PUBLIC or analyzeHeadless.bat">

                            <button type="button" class="btn-secondary bl-browse-btn" id="bl-browse-ghidra-folder" title="Browse for Ghidra installation root folder"><i class="fa-solid fa-folder"></i> Folder</button>

                            <button type="button" class="btn-secondary bl-browse-btn" id="bl-browse-ghidra" title="Browse for analyzeHeadless.bat executable file"><i class="fa-solid fa-file"></i> File</button>

                        </div>

                    </label>

                    <label class="bl-field">

                        <span>GoReSym executable</span>

                        <div class="bl-input-browse">

                            <input id="bl-set-goresym" type="text" value="${esc(s.goresym_path)}" placeholder="e.g. C:\\Tools\\GoReSym.exe">

                            <button type="button" class="btn-secondary bl-browse-btn" id="bl-browse-goresym" title="Browse for GoReSym executable"><i class="fa-solid fa-folder-open"></i> Browse</button>

                        </div>

                    </label>

                    <label class="bl-field">

                        <span>ILSpyCmd (.NET decompiler) binary</span>

                        <div class="bl-input-browse">

                            <input id="bl-set-ilspycmd" type="text" value="${esc(s.ilspycmd_path)}" placeholder="e.g. C:\\Users\\...\\.dotnet\\tools\\ilspycmd.exe or ilspycmd.dll">

                            <button type="button" class="btn-secondary bl-browse-btn" id="bl-browse-ilspycmd" title="Browse for ILSpyCmd binary"><i class="fa-solid fa-folder-open"></i> Browse</button>

                        </div>

                    </label>

                    ${field('bl-set-workers', 'Workers', s.workers, 'number', 'min="1" max="16"')}

                    ${field('bl-set-budget', 'Token budget', s.token_budget, 'number', 'min="0"')}

                </div>

            </section>

            <section class="bl-card bl-card-wide"><div class="bl-card-head"><div><h2>AI Provider</h2><p>Use MANTIS AI credentials or configure a dedicated provider profile.</p></div><i class="fa-solid fa-wand-magic-sparkles"></i></div>

                <div class="bl-option-grid">${toggle('bl-set-use-mantis-ai', 'Use MANTIS AI settings', s.use_mantis_ai, 'Recommended; API keys remain in MANTIS settings')}</div>

                <div class="bl-form-grid">

                    <label class="bl-field"><span>Provider</span><select id="bl-set-provider">${providerOptions()}</select></label>

                    <label class="bl-field" id="bl-set-field-url"><span>API base URL</span><input id="bl-set-url" type="text" value="${esc(s.api_url)}"></label>

                    <label class="bl-field"><span>Model</span><input id="bl-set-model" list="bl-set-models-list" type="text" value="${esc(s.model)}" placeholder="e.g. gemini-3.8-flash"><datalist id="bl-set-models-list"></datalist></label>

                    <label class="bl-field" id="bl-set-field-executable"><span>CLI executable</span><input id="bl-set-executable" type="text" value="${esc(s.executable)}" placeholder="e.g. agy or claude"></label>

                </div>

                <div class="bl-ai-actions">

                    <button type="button" class="btn-secondary" id="bl-set-test-ai"><i class="fa-solid fa-plug-circle-check"></i> Test Connection</button>

                    <span id="bl-set-test-ai-status" class="bl-ai-status"></span>

                </div>

            </section>

            <section class="bl-card bl-card-wide"><div class="bl-card-head"><div><h2>Default Pipeline</h2><p>Applied to each new job and still adjustable before launch.</p></div></div>${optionGrid('bl-set')}<div class="bl-inline-fields"><label class="bl-field"><span>.NET assemblies</span><select id="bl-set-dotnet"><option value="decompile" ${s.dotnet_mode === 'decompile' ? 'selected' : ''}>Decompile and export</option><option value="skip" ${s.dotnet_mode === 'skip' ? 'selected' : ''}>Skip</option></select></label></div></section>

            <section class="bl-card bl-card-wide bl-actions"><span id="bl-settings-note"></span><button class="btn-primary" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save Settings</button></section>

        </form>`;

    }



    function render() {

        document.querySelectorAll('[data-bl-view]').forEach(button => button.classList.toggle('active', button.dataset.blView === state.view));

        const count = document.getElementById('bl-job-count');

        if (count) count.textContent = state.jobs.length ? `(${state.jobs.length})` : '';

        renderStatus();

        const content = document.getElementById('bl-content');

        if (!content) return;

        content.innerHTML = state.view === 'jobs' ? renderJobs() : state.view === 'settings' ? renderSettings() : renderNew();

        bind();

    }



    async function startAnalysis() {

        const button = document.getElementById('bl-start');

        const files = document.getElementById('bl-files')?.files;

        const localPath = document.getElementById('bl-path')?.value.trim();

        if (!state.status.ida_available && !state.status.ghidra_available) {
            return showNotification('Neither IDA Pro nor Ghidra is configured. Please configure an engine under Settings.');
        }

        if ((!files || !files.length) && !localPath) return showNotification('Select files or enter a local path.');

        button.disabled = true;

        button.innerHTML = '<i class="fa-solid fa-circle-notch mantis-spin"></i> Starting';

        try {

            let job;

            const settings = runOverrides();

            if (files?.length) {

                const form = new FormData();

                [...files].forEach(file => form.append('files', file));

                form.append('config', JSON.stringify(settings));

                job = await request('/api/binary-lab/jobs/upload', { method: 'POST', body: form });

            } else {

                job = await request('/api/binary-lab/jobs/path', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: localPath, settings }) });

            }

            state.selectedJob = job.job_id;

            state.showArtifacts = false;

            state.view = 'jobs';

            await refreshJobs();

            showNotification('Binary analysis job started.');

        } catch (error) {

            showNotification(error.message);

            button.disabled = false;

            button.innerHTML = '<i class="fa-solid fa-play"></i> Start Analysis';

        }

    }



    async function saveEngineSettings(event) {

        event.preventDefault();

        const payload = {

            ...state.settings, ...runOverrides('bl-set'),

            ida_path: document.getElementById('bl-set-ida')?.value || '',

            ghidra_path: document.getElementById('bl-set-ghidra')?.value || '',

            disassembler: document.getElementById('bl-set-disassembler')?.value || 'ida',

            goresym_path: document.getElementById('bl-set-goresym')?.value || '',

            ilspycmd_path: document.getElementById('bl-set-ilspycmd')?.value || '',

            workers: Number(document.getElementById('bl-set-workers')?.value || 3),

            token_budget: Number(document.getElementById('bl-set-budget')?.value || 0),

            use_mantis_ai: !!document.getElementById('bl-set-use-mantis-ai')?.checked,

            provider: document.getElementById('bl-set-provider')?.value || 'OpenAI',

            api_url: document.getElementById('bl-set-url')?.value || '',

            model: document.getElementById('bl-set-model')?.value || '',

            executable: document.getElementById('bl-set-executable')?.value || '',

            dotnet_mode: document.getElementById('bl-set-dotnet')?.value || 'decompile'

        };

        try {

            state.settings = await request('/api/binary-lab/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });

            state.status = await request('/api/binary-lab/status');

            render();

            showNotification('Binary Lab settings saved.');

        } catch (error) { showNotification(error.message); }

    }



    async function refreshJobs(force = false) {

        try {

            const data = await request('/api/binary-lab/jobs?limit=100');

            const newJobs = Array.isArray(data.jobs) ? data.jobs : [];

            // Guard: don't wipe existing job list on a single transient read hiccup unless explicitly forced

            if (!force && newJobs.length === 0 && state.jobs.length > 0 && !state._explicitEmptyConfirmed) {

                state._explicitEmptyConfirmed = true;

                return;

            }

            state._explicitEmptyConfirmed = false;

            state.jobs = newJobs;

            if (state.selectedJob && !state.jobs.some(job => job.job_id === state.selectedJob)) {

                state.selectedJob = state.jobs.length > 0 ? state.jobs[0].job_id : '';

            }

            if (!state.selectedJob && state.jobs.length > 0) {

                state.selectedJob = state.jobs[0].job_id;

            }

            if (state.selectedJob) {

                const index = state.jobs.findIndex(job => job.job_id === state.selectedJob);

                if (index >= 0) {

                    try {

                        state.jobs[index] = await request(`/api/binary-lab/jobs/${encodeURIComponent(state.selectedJob)}`);

                    } catch (_) {}

                }

            }

            if (state.view === 'jobs') {

                render();

                if (state.showArtifacts) {

                    await loadArtifacts();

                }

            } else {

                renderStatus();

                const count = document.getElementById('bl-job-count');

                if (count) count.textContent = state.jobs.length ? `(${state.jobs.length})` : '';

            }

        } catch (_) {}

    }



    async function loadArtifacts() {

        if (!state.selectedJob) return;

        const target = document.getElementById('bl-artifact-list');

        if (!target) return;

        try {

            const data = await request(`/api/binary-lab/jobs/${encodeURIComponent(state.selectedJob)}/artifacts`);

            const fileList = Array.isArray(data?.files) ? data.files : (Array.isArray(data?.files?.files) ? data.files.files : (Array.isArray(data) ? data : []));

            const fileIcon = (p) => {

                const lower = (p || '').toLowerCase();

                if (lower.endsWith('.html') || lower.endsWith('.htm')) return 'fa-solid fa-file-code bl-icon-html';

                if (lower.endsWith('.pdf')) return 'fa-solid fa-file-pdf bl-icon-pdf';

                if (lower.includes('threat_attribution')) return 'fa-solid fa-shield-halved bl-icon-attr';

                if (lower.endsWith('.md')) return 'fa-solid fa-file-lines bl-icon-md';

                if (lower.endsWith('.i64') || lower.endsWith('.idb')) return 'fa-solid fa-database';

                return 'fa-regular fa-file';

            };

            target.innerHTML = `<h3 class="bl-subhead">All Job Files (${fileList.length})</h3><div class="bl-artifacts">${fileList.map(file => `<a target="_blank" href="${API_BASE}/api/binary-lab/jobs/${encodeURIComponent(state.selectedJob)}/artifacts/${(file.path || '').split('/').map(encodeURIComponent).join('/')}"><i class="${fileIcon(file.path || '')}"></i><span>${esc(file.path || file.name || '')}</span><small>${fmtBytes(file.size || 0)}</small></a>`).join('') || '<span>No artifacts available yet.</span>'}</div>`;

        } catch (error) { 

            showNotification(error.message); 

        }

    }



    function bind() {

        document.getElementById('bl-start')?.addEventListener('click', startAnalysis);

        document.querySelectorAll('.bl-deliv-preview-btn').forEach(button => button.addEventListener('click', () => {
            const index = button.dataset.previewIdx;
            const preview = document.getElementById(`bl-deliv-preview-${index}`);
            const frame = document.getElementById(`bl-deliv-iframe-${index}`);
            if (!preview || !frame) return;
            const opening = preview.style.display === 'none';
            preview.style.display = opening ? 'block' : 'none';
            frame.src = opening ? (button.dataset.previewUrl || 'about:blank') : 'about:blank';
            button.innerHTML = opening
                ? '<i class="fa-solid fa-eye-slash"></i> Hide Preview'
                : '<i class="fa-solid fa-eye"></i> Quick Preview';
        }));

        document.querySelectorAll('.bl-preview-close-btn').forEach(button => button.addEventListener('click', () => {
            const index = button.dataset.closePreview;
            const preview = document.getElementById(`bl-deliv-preview-${index}`);
            const frame = document.getElementById(`bl-deliv-iframe-${index}`);
            if (preview) preview.style.display = 'none';
            if (frame) frame.src = 'about:blank';
            const toggleBtn = document.querySelector(`.bl-deliv-preview-btn[data-preview-idx="${index}"]`);
            if (toggleBtn) {
                toggleBtn.innerHTML = '<i class="fa-solid fa-eye"></i> Quick Preview';
            }
        }));

        const files = document.getElementById('bl-files');

        const dropZone = document.getElementById('bl-drop-zone');

        const updateFileSummary = () => {

            const summary = document.getElementById('bl-file-summary');

            const count = files?.files?.length || 0;

            if (summary) summary.textContent = count ? `${count} file${count === 1 ? '' : 's'} selected` : 'No files selected';

            dropZone?.classList.toggle('has-files', count > 0);

        };

        files?.addEventListener('change', updateFileSummary);

        ['dragenter', 'dragover'].forEach(name => dropZone?.addEventListener(name, event => {

            event.preventDefault();

            dropZone.classList.add('dragging');

        }));

        ['dragleave', 'drop'].forEach(name => dropZone?.addEventListener(name, event => {

            event.preventDefault();

            dropZone.classList.remove('dragging');

        }));

        dropZone?.addEventListener('drop', event => {

            if (files && event.dataTransfer?.files?.length) {

                files.files = event.dataTransfer.files;

                updateFileSummary();

            }

        });



        // Sync dependent checkboxes for both New Analysis ('bl-run') and Engine Settings ('bl-set')

        const syncDependencies = (prefix) => {

            const functions = document.getElementById(`${prefix}-rename-functions`);

            const addresses = document.getElementById(`${prefix}-rename-address`);

            const variables = document.getElementById(`${prefix}-rename-variables`);

            const workspace = document.getElementById(`${prefix}-workspace`);

            const analyze = document.getElementById(`${prefix}-analyze`);

            const disassembler = document.getElementById(`${prefix}-disassembler`);

            const autonomous = document.getElementById(`${prefix}-autonomous`);

            const isGhidra = (disassembler?.value === 'ghidra');

            // 1. Rename functions (IDA Pro only)
            if (functions) {
                if (isGhidra) {
                    if (functions.checked) functions.dataset.prevChecked = 'true';
                    functions.checked = false;
                    functions.disabled = true;
                    functions.closest('.bl-toggle')?.classList.add('disabled');
                    const hint = functions.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'Unavailable with Ghidra; requires IDA Pro';
                    if (functions.closest('.bl-toggle')) functions.closest('.bl-toggle').title = 'In-database function renaming requires IDA Pro.';
                } else {
                    functions.disabled = false;
                    functions.closest('.bl-toggle')?.classList.remove('disabled');
                    if (functions.dataset.prevChecked === 'true') {
                        functions.checked = true;
                        delete functions.dataset.prevChecked;
                    }
                    const hint = functions.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'LLM-assisted function naming';
                    if (functions.closest('.bl-toggle')) functions.closest('.bl-toggle').title = '';
                }
            }

            // 2. Include addresses (IDA Pro only, requires rename functions)
            if (addresses) {
                if (isGhidra) {
                    addresses.checked = false;
                    addresses.disabled = true;
                    addresses.closest('.bl-toggle')?.classList.add('disabled');
                    const hint = addresses.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'Unavailable with Ghidra';
                } else {
                    addresses.disabled = !functions?.checked;
                    addresses.closest('.bl-toggle')?.classList.toggle('disabled', addresses.disabled);
                    const hint = addresses.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'Append original address to names';
                }
            }

            // 3. Rename variables (IDA Pro only)
            if (variables) {
                if (isGhidra) {
                    if (variables.checked) variables.dataset.prevChecked = 'true';
                    variables.checked = false;
                    variables.disabled = true;
                    variables.closest('.bl-toggle')?.classList.add('disabled');
                    const hint = variables.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'Unavailable with Ghidra; requires IDA Pro';
                    if (variables.closest('.bl-toggle')) variables.closest('.bl-toggle').title = 'In-database variable renaming requires IDA Pro.';
                } else {
                    variables.disabled = false;
                    variables.closest('.bl-toggle')?.classList.remove('disabled');
                    if (variables.dataset.prevChecked === 'true') {
                        variables.checked = true;
                        delete variables.dataset.prevChecked;
                    }
                    const hint = variables.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'Recover meaningful local names';
                    if (variables.closest('.bl-toggle')) variables.closest('.bl-toggle').title = '';
                }
            }

            // 4. In-database investigation (IDA Pro only)
            if (autonomous) {
                if (isGhidra) {
                    if (autonomous.checked) autonomous.dataset.prevChecked = 'true';
                    autonomous.checked = false;
                    autonomous.disabled = true;
                    autonomous.closest('.bl-toggle')?.classList.add('disabled');
                    const hint = autonomous.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'Unavailable with Ghidra Headless; requires IDA Pro';
                    if (autonomous.closest('.bl-toggle')) autonomous.closest('.bl-toggle').title = 'Agent-guided in-database investigation requires IDA Pro.';
                } else {
                    autonomous.disabled = false;
                    autonomous.closest('.bl-toggle')?.classList.remove('disabled');
                    if (autonomous.dataset.prevChecked === 'true') {
                        autonomous.checked = true;
                        delete autonomous.dataset.prevChecked;
                    }
                    const hint = autonomous.closest('.bl-toggle')?.querySelector('small');
                    if (hint) hint.textContent = 'Agent-guided IDA investigation';
                    if (autonomous.closest('.bl-toggle')) autonomous.closest('.bl-toggle').title = '';
                }
            }

            // 5. Workspace analysis requires workspace export
            if (analyze && workspace) {
                analyze.disabled = !workspace.checked;
                analyze.closest('.bl-toggle')?.classList.toggle('disabled', analyze.disabled);
            }

        };

        // Interactive side-by-side Disassembler Cards (IDA Pro vs Ghidra)
        document.querySelectorAll('.bl-disasm-card:not(.disabled)').forEach(card => {
            card.addEventListener('click', () => {
                const disasm = card.dataset.disasm;
                const hiddenInput = document.getElementById('bl-run-disassembler');
                if (!hiddenInput || hiddenInput.value === disasm) return;

                hiddenInput.value = disasm;

                document.querySelectorAll('.bl-disasm-card').forEach(c => {
                    const isActive = (c.dataset.disasm === disasm);
                    c.classList.toggle('active', isActive);
                    const radioIcon = c.querySelector('.bl-disasm-radio i');
                    if (radioIcon) {
                        radioIcon.className = `fa-solid fa-${isActive ? 'circle-dot' : 'circle'}`;
                    }
                });

                hiddenInput.dispatchEvent(new Event('change'));
            });
        });

        ['bl-run', 'bl-set'].forEach(prefix => {

            document.getElementById(`${prefix}-rename-functions`)?.addEventListener('change', () => syncDependencies(prefix));

            document.getElementById(`${prefix}-workspace`)?.addEventListener('change', () => syncDependencies(prefix));

            document.getElementById(`${prefix}-disassembler`)?.addEventListener('change', () => syncDependencies(prefix));

            syncDependencies(prefix);

        });



        // Browse buttons

        document.getElementById('bl-browse-path')?.addEventListener('click', async () => {

            const input = document.getElementById('bl-path');

            const btn = document.getElementById('bl-browse-path');

            if (!input || !btn) return;

            btn.disabled = true;

            try {

                const res = await request(`/api/binary-lab/select-folder?initial=${encodeURIComponent(input.value || '')}`);

                if (!res.cancelled && res.path) {

                    input.value = res.path;

                }

            } catch (err) {

                showNotification(err.message || 'Folder selection failed.');

            } finally {

                btn.disabled = false;

            }

        });



        document.getElementById('bl-browse-ida')?.addEventListener('click', async () => {

            const input = document.getElementById('bl-set-ida');

            const btn = document.getElementById('bl-browse-ida');

            if (!input || !btn) return;

            btn.disabled = true;

            try {

                const res = await request(`/api/binary-lab/select-ida?initial=${encodeURIComponent(input.value || '')}`);

                if (!res.cancelled && res.path) {

                    input.value = res.path;

                }

            } catch (err) {

                showNotification(err.message || 'File selection failed.');

            } finally {

                btn.disabled = false;

            }

        });



        const handleGhidraBrowse = async (mode = 'folder') => {

            const input = document.getElementById('bl-set-ghidra');

            const btn = document.getElementById(mode === 'file' ? 'bl-browse-ghidra' : 'bl-browse-ghidra-folder');

            if (!input || !btn) return;

            btn.disabled = true;

            try {

                const res = await request(`/api/binary-lab/select-ghidra?mode=${mode}&initial=${encodeURIComponent(input.value || '')}`);

                if (!res.cancelled && res.path) {

                    input.value = res.path;

                }

            } catch (err) {

                showNotification(err.message || 'Selection failed.');

            } finally {

                btn.disabled = false;

            }

        };



        document.getElementById('bl-browse-ghidra-folder')?.addEventListener('click', () => handleGhidraBrowse('folder'));

        document.getElementById('bl-browse-ghidra')?.addEventListener('click', () => handleGhidraBrowse('file'));



        document.getElementById('bl-browse-goresym')?.addEventListener('click', async () => {

            const input = document.getElementById('bl-set-goresym');

            const btn = document.getElementById('bl-browse-goresym');

            if (!input || !btn) return;

            btn.disabled = true;

            try {

                const res = await request(`/api/binary-lab/select-goresym?initial=${encodeURIComponent(input.value || '')}`);

                if (!res.cancelled && res.path) {

                    input.value = res.path;

                }

            } catch (err) {

                showNotification(err.message || 'File selection failed.');

            } finally {

                btn.disabled = false;

            }

        });



        document.getElementById('bl-browse-ilspycmd')?.addEventListener('click', async () => {

            const input = document.getElementById('bl-set-ilspycmd');

            const btn = document.getElementById('bl-browse-ilspycmd');

            if (!input || !btn) return;

            btn.disabled = true;

            try {

                const res = await request(`/api/binary-lab/select-ilspycmd?initial=${encodeURIComponent(input.value || '')}`);

                if (!res.cancelled && res.path) {

                    input.value = res.path;

                }

            } catch (err) {

                showNotification(err.message || 'File selection failed.');

            } finally {

                btn.disabled = false;

            }

        });



        const setupProviderControls = (prefix) => {

            const providerSelect = document.getElementById(`${prefix}-provider`);

            const urlInput = document.getElementById(`${prefix}-url`);

            const modelInput = document.getElementById(`${prefix}-model`);

            const exeInput = document.getElementById(`${prefix}-executable`);

            const datalist = document.getElementById(`${prefix}-models-list`);

            const mantisToggle = document.getElementById(`${prefix}-use-mantis-ai`);

            const testBtn = document.getElementById(`${prefix}-test-ai`);

            const statusBadge = document.getElementById(`${prefix}-test-ai-status`);



            if (!providerSelect || !urlInput || !modelInput || !exeInput) return;



            const syncProviderState = (applyDefaults = false) => {

                const providerId = providerSelect.value;

                const provider = (state.settings.providers || []).find(p => p.id === providerId) || {};

                const defaults = provider.defaults || ['', '', ''];

                const models = provider.models || [];

                const isCli = ['AntigravityCLI', 'ChatGPTAccount', 'ClaudeCode', 'CopilotCLI', 'OpenCode'].includes(providerId);



                if (applyDefaults) {

                    if (isCli) {

                        urlInput.value = '';

                        exeInput.value = defaults[2] || '';

                    } else {

                        urlInput.value = defaults[0] || '';

                        exeInput.value = '';

                    }

                    modelInput.value = defaults[1] || '';

                }



                // Disable / enable URL & CLI

                if (isCli) {

                    urlInput.disabled = true;

                    urlInput.placeholder = 'Not applicable (Local CLI / Session)';

                    urlInput.closest('.bl-field')?.classList.add('bl-field-disabled');



                    exeInput.disabled = false;

                    exeInput.placeholder = 'e.g. ' + (defaults[2] || 'agy');

                    exeInput.closest('.bl-field')?.classList.remove('bl-field-disabled');

                } else {

                    urlInput.disabled = false;

                    urlInput.placeholder = defaults[0] || 'https://api.openai.com/v1';

                    urlInput.closest('.bl-field')?.classList.remove('bl-field-disabled');



                    exeInput.disabled = true;

                    exeInput.placeholder = 'Not required for API provider';

                    exeInput.closest('.bl-field')?.classList.add('bl-field-disabled');

                }



                // Update datalist for models

                if (datalist) {

                    datalist.innerHTML = models.map(m => `<option value="${esc(m)}"></option>`).join('');

                }

                updateWorkspaceApiWarning();

            };

            const updateWorkspaceApiWarning = () => {
                const warnEl = document.getElementById(`${prefix}-api-workspace-warn`);
                if (!warnEl) return;
                const analyzeChecked = !!document.getElementById(`${prefix}-analyze`)?.checked;
                const providerId = providerSelect.value;
                const isCli = ['AntigravityCLI', 'ChatGPTAccount', 'ClaudeCode', 'CopilotCLI', 'OpenCode'].includes(providerId);
                warnEl.style.display = (analyzeChecked && !isCli) ? 'flex' : 'none';
            };

            document.getElementById(`${prefix}-analyze`)?.addEventListener('change', updateWorkspaceApiWarning);



            providerSelect.addEventListener('change', () => {

                syncProviderState(true);

                if (statusBadge) statusBadge.innerHTML = '';

            });



            mantisToggle?.addEventListener('change', async (e) => {

                if (statusBadge) statusBadge.innerHTML = '';

                if (e.target.checked) {

                    try {

                        const mantis = await request('/api/ai/settings');

                        const map = {

                            'antigravity': 'AntigravityCLI', 'chatgpt_desktop': 'ChatGPTAccount',

                            'claude_desktop': 'ClaudeCode', 'copilot': 'CopilotCLI', 'opencode': 'OpenCode',

                            'gemini': 'GoogleGemini', 'anthropic': 'Anthropic', 'deepseek': 'DeepSeek',

                            'openai': 'OpenAI', 'openrouter': 'OpenRouter', 'groq': 'Groq',

                            'mistral': 'Mistral', 'ollama': 'Ollama', 'lmstudio': 'LMStudio',

                            'openai_compatible': 'OpenAICompatible'

                        };

                        const targetProv = map[mantis.provider] || 'OpenAI';

                        providerSelect.value = targetProv;

                        syncProviderState(true);

                        if (mantis.model) {

                            modelInput.value = mantis.model;

                        }

                    } catch (_) {}

                }

            });



            syncProviderState(false);



            testBtn?.addEventListener('click', async () => {

                if (!testBtn || !statusBadge) return;

                const origHtml = testBtn.innerHTML;

                testBtn.disabled = true;

                testBtn.innerHTML = '<i class="fa-solid fa-circle-notch mantis-spin"></i> Testing...';

                statusBadge.className = 'bl-ai-status bl-ai-status-testing';

                statusBadge.innerHTML = '<i class="fa-solid fa-circle-notch mantis-spin"></i> Testing connection probe...';



                const payload = {

                    use_mantis_ai: !!mantisToggle?.checked,

                    provider: providerSelect.value || 'OpenAI',

                    api_url: urlInput.value || '',

                    model: modelInput.value || '',

                    executable: exeInput.value || '',

                };



                try {

                    const res = await request('/api/binary-lab/test-provider', {

                        method: 'POST',

                        headers: { 'Content-Type': 'application/json' },

                        body: JSON.stringify(payload)

                    });

                    if (res.ok) {

                        statusBadge.className = 'bl-ai-status bl-ai-status-ok';

                        statusBadge.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${esc(res.message || 'Connection successful')}`;

                        if (res.model && !modelInput.value) {

                            modelInput.value = res.model;

                        }

                        if (Array.isArray(res.available_models) && res.available_models.length > 0 && datalist) {

                            datalist.innerHTML = res.available_models.map(m => `<option value="${esc(m)}"></option>`).join('');

                        }

                    } else {

                        statusBadge.className = 'bl-ai-status bl-ai-status-bad';

                        statusBadge.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> ${esc(res.message || 'Connection failed')}`;

                    }

                } catch (err) {

                    statusBadge.className = 'bl-ai-status bl-ai-status-bad';

                    statusBadge.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> ${esc(err.message || 'Connection probe failed')}`;

                } finally {

                    testBtn.disabled = false;

                    testBtn.innerHTML = origHtml;

                }

            });

        };



        setupProviderControls('bl-run');

        setupProviderControls('bl-set');



        document.getElementById('bl-settings')?.addEventListener('submit', saveEngineSettings);

        document.getElementById('bl-refresh')?.addEventListener('click', () => refreshJobs(true));



                // Job Detail Tabs switching

        document.querySelectorAll('[data-bl-job-tab]').forEach(btn => btn.addEventListener('click', () => {

            state.jobTab = btn.dataset.blJobTab;

            render();

            if (state.selectedJob) {

                if (['functions', 'variables'].includes(state.jobTab) && !state.catalogs[state.selectedJob]) {

                    loadCatalogs(state.selectedJob);

                } else if (state.jobTab === 'ida-log') {

                    loadIdaLog(state.selectedJob);

                } else if (state.jobTab === 'analysis' && state.analysisMode === 'md') {

                    loadMarkdownReport();

                }

            }

        }));



        // Analysis toolbar controls

        document.getElementById('bl-switch-html')?.addEventListener('click', () => {

            state.analysisMode = 'html';

            render();

        });

        document.getElementById('bl-switch-md')?.addEventListener('click', () => {

            state.analysisMode = 'md';

            render();

            loadMarkdownReport();

        });



        // "View AI Analysis" buttons from Sample Queue

        document.querySelectorAll('.bl-qc-quick-tab').forEach(btn => btn.addEventListener('click', () => {

            const tab = btn.dataset.tab;

            if (tab) {

                state.jobTab = tab;

                render();

            }

        }));



        document.querySelectorAll('.bl-view-analysis-btn').forEach(btn => btn.addEventListener('click', () => {

            state.activeSampleIndex = Number(btn.dataset.sampleIdx || 0);

            state.jobTab = 'analysis';

            render();

            if (state.analysisMode === 'md') {

                loadMarkdownReport();

            }

        }));



        // Functions filters

        document.getElementById('bl-fn-search')?.addEventListener('input', (e) => {

            state.fnFilter = e.target.value;

            render();

            const inp = document.getElementById('bl-fn-search');

            if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }

        });

        document.getElementById('bl-fn-score-filter')?.addEventListener('change', (e) => {

            state.fnScoreFilter = e.target.value;

            render();

        });



        // Variables filters

        document.getElementById('bl-var-search')?.addEventListener('input', (e) => {

            state.varFilter = e.target.value;

            render();

            const inp = document.getElementById('bl-var-search');

            if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }

        });

        document.getElementById('bl-var-kind-filter')?.addEventListener('change', (e) => {

            state.varKindFilter = e.target.value;

            render();

        });



        // IDA Log tools

        document.getElementById('bl-ida-filter')?.addEventListener('input', (e) => {

            state.idaLogFilter = e.target.value;

            render();

            const inp = document.getElementById('bl-ida-filter');

            if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }

        });

        document.getElementById('bl-ida-filter-noise')?.addEventListener('change', (e) => {

            state.idaFilterNoise = !!e.target.checked;

            render();

        });



        document.getElementById('bl-ida-autoscroll')?.addEventListener('change', (e) => {

            state.idaAutoScroll = !!e.target.checked;

        });

        document.getElementById('bl-ida-refresh')?.addEventListener('click', () => {

            if (state.selectedJob) loadIdaLog(state.selectedJob);

        });

        document.getElementById('bl-ida-copy')?.addEventListener('click', () => {

            const logData = state.idaLogs[state.selectedJob];

            if (logData && logData.content) {

                navigator.clipboard.writeText(logData.content);

                showNotification('IDA log copied to clipboard.');

            }

        });



        document.querySelectorAll('[data-job-id]').forEach(card => card.addEventListener('click', async () => {

            const jid = card.dataset.jobId;

            if (state.selectedJob !== jid) {

                state.selectedJob = jid;

                state.showArtifacts = false;

            }

            render();

            try {

                const fullJob = await request(`/api/binary-lab/jobs/${encodeURIComponent(jid)}`);

                const index = state.jobs.findIndex(job => job.job_id === jid);

                if (index >= 0) state.jobs[index] = fullJob;

                render();

            } catch (e) {}

        }));



        document.getElementById('bl-cancel')?.addEventListener('click', async () => {

            const btn = document.getElementById('bl-cancel');

            if (btn) btn.disabled = true;

            try {

                await request(`/api/binary-lab/jobs/${encodeURIComponent(state.selectedJob)}/cancel`, { method: 'POST' });

                await refreshJobs();

            } catch (e) {

                showNotification(e.message);

                if (btn) btn.disabled = false;

            }

        });



        document.getElementById('bl-resume')?.addEventListener('click', async () => {

            const btn = document.getElementById('bl-resume');

            if (btn) btn.disabled = true;

            try {

                await request(`/api/binary-lab/jobs/${encodeURIComponent(state.selectedJob)}/resume`, { method: 'POST' });

                await refreshJobs();

            } catch (e) {

                showNotification(e.message);

                if (btn) btn.disabled = false;

            }

        });



        document.getElementById('bl-delete')?.addEventListener('click', async () => {

            const targetJobId = state.selectedJob;

            if (!targetJobId) return;

            if (!confirm('Delete this Binary Lab job and all generated artifacts?')) return;

            const btn = document.getElementById('bl-delete');

            if (btn) {

                btn.disabled = true;

                btn.innerHTML = '<i class="fa-solid fa-circle-notch mantis-spin"></i> Deleting...';

            }

            try {

                // Optimistically remove from state and re-render immediately so the job vanishes right away

                state.jobs = (state.jobs || []).filter(job => job.job_id !== targetJobId);

                state.selectedJob = state.jobs.length > 0 ? state.jobs[0].job_id : '';

                state.showArtifacts = false;

                state._explicitEmptyConfirmed = true;

                render();



                // Delete on server

                await request(`/api/binary-lab/jobs/${encodeURIComponent(targetJobId)}`, { method: 'DELETE' });



                // Synchronize with server

                await refreshJobs(true);

                showNotification('Job deleted successfully.');

            } catch (e) {

                showNotification(e.message || 'Failed to delete job.');

                await refreshJobs(true);

            }

        });



        document.getElementById('bl-artifacts')?.addEventListener('click', async () => {

            state.showArtifacts = !state.showArtifacts;

            const target = document.getElementById('bl-artifact-list');

            const btn = document.getElementById('bl-artifacts');

            if (!state.showArtifacts) {

                if (target) target.innerHTML = '';

                if (btn) btn.innerHTML = '<i class="fa-solid fa-folder-open"></i> All Files';

                btn?.classList.remove('active');

            } else {

                if (btn) {

                    btn.innerHTML = '<i class="fa-solid fa-circle-notch mantis-spin"></i> Loading...';

                    btn.classList.add('active');

                }

                await loadArtifacts();

                if (btn) btn.innerHTML = '<i class="fa-solid fa-folder-minus"></i> Hide Files';

            }

        });



        document.querySelectorAll('[data-case-index]').forEach(button => button.addEventListener('click', async () => {

            const origHtml = button.innerHTML;

            button.disabled = true;

            button.innerHTML = '<i class="fa-solid fa-circle-notch mantis-spin"></i> Creating...';

            try {

                const result = await request(`/api/binary-lab/jobs/${encodeURIComponent(state.selectedJob)}/case`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sample_index: Number(button.dataset.caseIndex) }) });

                showNotification(`Created MANTIS case ${result.case_id}.`);

            } catch (error) { 

                showNotification(error.message); 

            } finally {

                button.disabled = false;

                button.innerHTML = origHtml;

            }

        }));

        document.querySelectorAll('[data-aead-hash]').forEach(button => button.addEventListener('click', async () => {
            const hash = button.dataset.aeadHash;
            if (!hash) return;
            if (window.mantisAI?.runAeadWorkflow) {
                window.mantisAI.runAeadWorkflow(hash, 'hash');
            } else {
                showNotification('MANTIS AI module not ready.');
            }
        }));

    }



    async function load() {

        shell();

        try {

            [state.status, state.settings] = await Promise.all([request('/api/binary-lab/status'), request('/api/binary-lab/settings')]);

            const jobs = await request('/api/binary-lab/jobs?limit=100');

            state.jobs = jobs.jobs || [];

            if (state.jobs.length > 0 && !state.selectedJob) {

                state.selectedJob = state.jobs[0].job_id;

                try {

                    const full = await request(`/api/binary-lab/jobs/${encodeURIComponent(state.selectedJob)}`);

                    state.jobs[0] = full;

                } catch (e) {}

            }

            state.loaded = true;

            render();

        } catch (error) {

            document.getElementById('bl-content').innerHTML = `<div class="bl-error"><i class="fa-solid fa-triangle-exclamation"></i>${esc(error.message)}</div>`;

        }

    }



    window.openBinaryLab = function (view) {

        state.view = view || 'new';

        state.showArtifacts = false;

        if (!state.loaded) {

            load();

        } else {

            refreshJobs();

            render();

        }

        clearInterval(state.poller);

        state.poller = setInterval(() => {

            const pane = document.getElementById('binary-lab-pane');

            if (pane?.style.display !== 'none' && state.jobs.some(job => ['queued', 'running', 'cancelling'].includes(job.status))) refreshJobs().catch(() => {});

        }, 2500);

    };

})();

