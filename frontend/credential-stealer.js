(() => {
    const defaultSearch = { q: '', family: 'all', source_type: 'all', watchlist_only: false };
    const state = {
        initialized: false,
        activeTab: 'overview',
        sourcesSub: 'local',
        selectedParser: '',
        revealAll: false,
        revealedIds: new Set(),
        deletingCredentials: false,
        loadingVaultResults: false,
        localPickerOpen: false,
        searchDraft: { ...defaultSearch },
        filters: { ...defaultSearch, limit: 60, offset: 0 },
        overview: null,
        credsData: { total: 0, items: [] },
        sourcesData: { local: [], telegram: [], settings: {} },
        parsersData: { parsers: [], unparsed_queue: [] },
        watchlistData: { items: [] },
        jobsData: { jobs: [] },
        studioDraft: {
            sample_snippet: '',
            hint_family: '',
            name: '',
            stealer_family: '',
            mode: 'block_regex',
            pattern: '',
            explanation: '',
            test_matches: [],
            model: '',
            warning: '',
        },
        pollTimer: null,
        selectedUploadFiles: [],
        lastUploadResult: null,
        toast: { msg: '', isError: false, expiresAt: 0 },
        deleteMgmt: {
            isOpen: false,
            loading: false,
            deleting: false,
            sources: [],
            selectedKeys: new Set(),
            searchQuery: '',
        },
    };

    const esc = (v) => String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');

    const maskPassword = (pw) => {
        const s = String(pw ?? '');
        if (!s) return '—';
        if (s.length <= 2) return '••••';
        return `${s[0]}${'•'.repeat(Math.min(8, Math.max(3, s.length - 2)))}${s[s.length - 1]}`;
    };

    const api = async (path, opts = {}) => {
        const res = await fetch(path, opts);
        if (!res.ok) {
            let detail = `${res.status} ${res.statusText}`;
            try {
                const j = await res.json();
                detail = j.detail || j.error || detail;
            } catch (_) {}
            throw new Error(detail);
        }
        const ctype = res.headers.get('content-type') || '';
        if (ctype.includes('application/json')) return res.json();
        return res.text();
    };

    const supportedFileTypes = ['.txt', '.log', '.csv', '.zip', '.rar', '.7z'];

    const getUploadLabelText = () => {
        const files = state.selectedUploadFiles || [];
        if (!files.length) return supportedFileTypes.join(', ');
        if (files.length === 1) return files[0].name;
        return `${files.length} files selected (${files[0].name}, ...)`;
    };

    const getAiStatus = () => (
        state.parsersData?.ai_status
        || state.overview?.ai_status
        || state.sourcesData?.ai_status
        || {
            available: false,
            provider: '',
            provider_label: '',
            model: '',
            reason: 'No AI provider is configured in MANTIS AI.',
        }
    );

    const renderToastEl = () => {
        const t = state.toast || {};
        const active = Boolean(t.msg && Date.now() < (t.expiresAt || 0));
        if (!active) {
            return '<div id="cs-status-toast" class="cs-toast"></div>';
        }
        const border = t.isError ? 'rgba(239,68,68,0.45)' : 'rgba(16,185,129,0.42)';
        const color = t.isError ? '#fca5a5' : '#6ee7b7';
        const icon = t.isError ? 'fa-circle-exclamation' : 'fa-circle-check';
        return `<div id="cs-status-toast" class="cs-toast" style="display:flex; border-color:${border}; color:${color};"><i class="fa-solid ${icon}"></i> <span>${esc(t.msg)}</span></div>`;
    };

    const showToast = (msg, isError = false) => {
        const expiresAt = msg ? Date.now() + 7000 : 0;
        state.toast = { msg: msg || '', isError: !!isError, expiresAt };
        const bar = document.getElementById('cs-status-toast');
        if (!bar) return;
        bar.innerHTML = msg
            ? `<i class="fa-solid ${isError ? 'fa-circle-exclamation' : 'fa-circle-check'}"></i> <span>${esc(msg)}</span>`
            : '';
        bar.style.display = msg ? 'flex' : 'none';
        bar.style.borderColor = isError ? 'rgba(239,68,68,0.45)' : 'rgba(16,185,129,0.42)';
        bar.style.color = isError ? '#fca5a5' : '#6ee7b7';
        if (msg) {
            setTimeout(() => {
                if (state.toast.msg === msg && Date.now() >= state.toast.expiresAt) {
                    state.toast = { msg: '', isError: false, expiresAt: 0 };
                    const b = document.getElementById('cs-status-toast');
                    if (b) b.style.display = 'none';
                }
            }, 7100);
        }
    };

    const copyText = async (text, label = 'Copied') => {
        try {
            await navigator.clipboard.writeText(String(text ?? ''));
            showToast(`${label} copied to clipboard.`);
        } catch (err) {
            showToast(`Copy failed: ${err.message}`, true);
        }
    };

    // -----------------------------------------------------------------------
    // Data Loaders
    // -----------------------------------------------------------------------
    const fetchVaultResults = (filters) => {
        const qs = new URLSearchParams(filters);
        return api(`/api/credential-stealer/credentials?${qs.toString()}`);
    };

    let vaultLoadId = 0;
    const loadOverviewAndVault = async () => {
        const loadId = ++vaultLoadId;
        const filters = state.filters;
        const [ov, creds, wl] = await Promise.all([
            api('/api/credential-stealer/overview'),
            fetchVaultResults(filters),
            api('/api/credential-stealer/watchlist'),
        ]);
        if (loadId !== vaultLoadId) return;
        state.overview = ov;
        if (filters === state.filters) state.credsData = creds;
        state.watchlistData = wl;
    };

    const applyVaultFilters = async (filters) => {
        if (state.loadingVaultResults || state.deletingCredentials) return;
        state.loadingVaultResults = true;
        renderActiveSection();
        try {
            const creds = await fetchVaultResults(filters);
            state.filters = filters;
            state.credsData = creds;
        } catch (err) {
            showToast(err.message || 'Could not load credentials.', true);
        } finally {
            state.loadingVaultResults = false;
            if (state.activeTab === 'vault') renderActiveSection();
        }
    };

    const loadSources = async () => {
        state.sourcesData = await api('/api/credential-stealer/sources');
    };

    const loadParsers = async () => {
        state.parsersData = await api('/api/credential-stealer/parsers');
    };

    const loadJobs = async () => {
        state.jobsData = await api('/api/credential-stealer/jobs?limit=30');
        const hasRunning = (state.jobsData.jobs || []).some(j => j.status === 'running');
        if (hasRunning && !state.pollTimer) {
            state.pollTimer = setInterval(async () => {
                try {
                    await loadJobs();
                    const stillRunning = (state.jobsData.jobs || []).some(j => j.status === 'running');
                    if (state.activeTab === 'jobs') renderActiveSection();
                    if (!stillRunning) {
                        clearInterval(state.pollTimer);
                        state.pollTimer = null;
                        await refreshAllData();
                    }
                } catch (_) {}
            }, 2500);
        } else if (!hasRunning && state.pollTimer) {
            clearInterval(state.pollTimer);
            state.pollTimer = null;
        }
    };

    const refreshAllData = async () => {
        await Promise.all([loadOverviewAndVault(), loadSources(), loadParsers(), loadJobs()]);
        renderShell();
    };

    // -----------------------------------------------------------------------
    // Section Renderers
    // -----------------------------------------------------------------------
    const renderVaultSection = () => {
        const families = state.overview?.families || [];
        const creds = state.credsData?.items || [];
        const total = state.credsData?.total || 0;
        const draft = state.searchDraft;
        const busy = state.loadingVaultResults || state.deletingCredentials;
        const hasFilters = state.filters.q || state.filters.family !== 'all'
            || state.filters.source_type !== 'all' || state.filters.watchlist_only;
        const familyOpts = [`<option value="all">All Stealer Families</option>`]
            .concat(families.map(f => `<option value="${esc(f.family)}" ${draft.family === f.family ? 'selected' : ''}>${esc(f.family)} (${f.count})</option>`))
            .join('');

        return `
            <form id="cs-vault-search" class="cs-vault-search" role="search" aria-label="Credential vault">
                <label class="cs-search-label" for="cs-search-input">Search credentials</label>
                <div class="cs-search-row">
                    <div class="cs-search-box">
                        <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
                        <input id="cs-search-input" name="q" type="search" autocomplete="off" spellcheck="false"
                            value="${esc(draft.q)}" placeholder="Domain, URL, username, email, victim IP, or source">
                    </div>
                    <button type="submit" class="cs-btn cs-search-submit" id="cs-search-submit" aria-disabled="${busy}">
                        ${state.loadingVaultResults ? 'Loading&hellip;' : 'Search'}
                    </button>
                </div>
                <div class="cs-search-filters">
                    <label class="cs-filter-field">
                        <span>Stealer Family</span>
                        <select id="cs-filter-family" name="family" class="cs-select">${familyOpts}</select>
                    </label>
                    <label class="cs-filter-field">
                        <span>Source</span>
                        <select id="cs-filter-source" name="source_type" class="cs-select">
                            <option value="all" ${draft.source_type === 'all' ? 'selected' : ''}>All Sources</option>
                            <option value="local" ${draft.source_type === 'local' ? 'selected' : ''}>Local Folder</option>
                            <option value="telegram" ${draft.source_type === 'telegram' ? 'selected' : ''}>Telegram</option>
                            <option value="upload" ${draft.source_type === 'upload' ? 'selected' : ''}>Direct Upload</option>
                        </select>
                    </label>
                    <label class="cs-switch cs-watchlist-filter" title="Filter results to only credentials matching your watchlist targets">
                        <input id="cs-filter-watchlist" name="watchlist_only" type="checkbox" role="switch" ${draft.watchlist_only ? 'checked' : ''}>
                        <span class="cs-switch-track" aria-hidden="true"></span>
                        <span>Watchlist Hits Only</span>
                    </label>
                </div>
            </form>

            <div class="cs-results-bar">
                <div class="cs-results-title" role="status">
                    <strong>${total.toLocaleString()} ${hasFilters ? 'matching' : 'indexed'} ${total === 1 ? 'credential' : 'credentials'}</strong>
                    ${state.filters.q ? `<span title="${esc(state.filters.q)}">Results for &ldquo;${esc(state.filters.q)}&rdquo;</span>` : ''}
                </div>
                <div class="cs-results-actions">
                    <button type="button" id="cs-toggle-reveal-all" class="cs-btn cs-btn-sm ${state.revealAll ? 'cs-btn-primary' : ''}">
                        <i class="fa-solid ${state.revealAll ? 'fa-eye' : 'fa-eye-slash'}"></i> ${state.revealAll ? 'Hide Passwords' : 'Reveal All'}
                    </button>
                    <button type="button" id="cs-btn-export-csv" class="cs-btn cs-btn-sm">
                        <i class="fa-solid fa-file-csv"></i> Export CSV
                    </button>
                    <button type="button" id="cs-btn-delete-mgmt" class="cs-btn cs-btn-sm cs-btn-danger"
                        ${busy || !state.overview?.metrics?.total_credentials ? 'disabled' : ''}
                        title="Manage and selectively delete indexed credentials by source">
                        <i class="fa-solid fa-trash-can"></i> Delete Management
                    </button>
                </div>
            </div>

            <div class="cs-table-wrap">
                <table class="cs-table">
                    <thead>
                        <tr>
                            <th>Target Domain / URL</th>
                            <th>Username / Email</th>
                            <th>Password (Plaintext)</th>
                            <th>Stealer Family</th>
                            <th>Source &amp; Parser</th>
                            <th style="text-align:right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${creds.length ? creds.map(c => {
                            const isRevealed = state.revealAll || state.revealedIds.has(c.id);
                            const pwShown = isRevealed ? c.password_plain : maskPassword(c.password_plain);
                            return `
                                <tr>
                                    <td>
                                        <div class="cs-domain-cell">
                                            <div class="cs-domain-title">
                                                <span>${esc(c.domain || '—')}</span>
                                            </div>
                                            <div class="cs-url-sub" title="${esc(c.url)}">${esc(c.url)}</div>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="cs-mono-cell">
                                            <span class="cs-mono-text" title="${esc(c.username)}">${esc(c.username || '—')}</span>
                                            ${c.username ? `<button type="button" class="cs-icon-mini" data-cs-action="copy-text" data-val="${esc(c.username)}" title="Copy Username"><i class="fa-regular fa-copy"></i></button>` : ''}
                                        </div>
                                    </td>
                                    <td>
                                        <div class="cs-pw-pill">
                                            <span class="cs-mono-text" style="color:${isRevealed ? '#fde047' : '#94a3b8'};">${esc(pwShown)}</span>
                                            <button type="button" class="cs-icon-mini" data-cs-action="toggle-pw" data-id="${c.id}" title="${isRevealed ? 'Hide Password' : 'Reveal Plaintext Password'}">
                                                <i class="fa-solid ${isRevealed ? 'fa-eye-slash' : 'fa-eye'}"></i>
                                            </button>
                                            <button type="button" class="cs-icon-mini" data-cs-action="copy-text" data-val="${esc(c.password_plain)}" title="Copy Plaintext Password">
                                                <i class="fa-regular fa-copy"></i>
                                            </button>
                                        </div>
                                    </td>
                                    <td>
                                        <div style="display:flex; gap:6px; flex-wrap:wrap;">
                                            <span class="cs-badge family">${esc(c.stealer_family || 'Unknown')}</span>
                                        </div>
                                    </td>
                                    <td>
                                        <div style="display:flex; flex-direction:column; gap:3px;">
                                            <span class="cs-badge">${esc(c.source_type)}: ${esc(c.source_name || '—')}</span>
                                            <span style="font:400 0.69rem var(--font-mono); color:#64748b;">${esc(c.parser_name || c.file_name)} ${c.sightings > 1 ? `(&times;${c.sightings})` : ''}</span>
                                        </div>
                                    </td>
                                    <td style="text-align:right;">
                                        <button type="button" class="cs-icon-mini" data-cs-action="del-cred" data-id="${c.id}" title="Delete Record">
                                            <i class="fa-solid fa-trash" style="color:#f87171;"></i>
                                        </button>
                                    </td>
                                </tr>
                            `;
                        }).join('') : `
                            <tr>
                                <td colspan="6">
                                    <div class="cs-empty">
                                        <i class="fa-solid fa-key" style="font-size:1.8rem; margin-bottom:10px; display:block; color:#334155;"></i>
                                        <strong style="color:#cbd5e1;">${hasFilters ? 'No matching credentials' : 'No credentials indexed yet'}</strong><br>
                                        ${hasFilters
                                            ? 'Adjust the query or filters and press Search.'
                                            : 'Add a log source from Sources &amp; Weekly Harvester.'}
                                    </div>
                                </td>
                            </tr>
                        `}
                    </tbody>
                </table>
            </div>

            <div class="cs-pagination">
                <span>Showing ${creds.length ? state.filters.offset + 1 : 0}&ndash;${state.filters.offset + creds.length} of <strong>${total}</strong> indexed credentials</span>
                <div style="display:flex; gap:8px;">
                    <button type="button" id="cs-page-prev" class="cs-btn cs-btn-sm" ${busy || state.filters.offset <= 0 ? 'disabled' : ''}>Prev</button>
                    <button type="button" id="cs-page-next" class="cs-btn cs-btn-sm" ${busy || state.filters.offset + creds.length >= total ? 'disabled' : ''}>Next</button>
                </div>
            </div>
        `;
    };

    const renderWatchlistSection = () => {
        const items = state.watchlistData?.items || [];
        const targetTypes = { domain: 'Domain', email_domain: 'Email Domain', keyword: 'Keyword' };
        return `
            <div class="cs-card cs-watchlist">
                <div class="cs-card-head">
                    <div class="cs-card-title">
                        <div class="cs-card-icon danger"><i class="fa-solid fa-bullseye" aria-hidden="true"></i></div>
                        <div>
                            <h3>Corporate Asset Watchlist</h3>
                            <p>Matching credentials are flagged in the Credential Vault.</p>
                        </div>
                    </div>
                </div>
                <form id="cs-watchlist-form" class="cs-watchlist-form">
                    <label class="cs-filter-field">
                        <span>Target Type</span>
                        <select name="target_type" class="cs-select">
                            ${Object.entries(targetTypes).map(([value, label]) => `<option value="${value}">${label}</option>`).join('')}
                        </select>
                    </label>
                    <label class="cs-filter-field">
                        <span>Target</span>
                        <input name="value" class="cs-input" placeholder="e.g. acme.com" required>
                    </label>
                    <label class="cs-filter-field">
                        <span>Description (optional)</span>
                        <input name="description" class="cs-input">
                    </label>
                    <button type="submit" class="cs-btn cs-btn-primary"><i class="fa-solid fa-plus"></i> Add &amp; Match</button>
                </form>
                <div class="cs-source-list">
                    ${items.length ? items.map(item => `
                        <div class="cs-source-item">
                            <div class="cs-watchlist-target">
                                <strong>${esc(item.value)}</strong>
                                <span class="cs-badge">${esc(targetTypes[item.target_type] || item.target_type)}</span>
                                <span class="cs-badge ${item.hits_count > 0 ? 'hit' : ''}">${item.hits_count} ${item.hits_count === 1 ? 'hit' : 'hits'}</span>
                                ${item.description ? `<div class="cs-source-meta">${esc(item.description)}</div>` : ''}
                            </div>
                            <button type="button" class="cs-btn cs-btn-sm cs-btn-danger" data-cs-action="del-watchlist"
                                data-id="${item.id}" aria-label="Remove ${esc(item.value)}">
                                <i class="fa-solid fa-trash" aria-hidden="true"></i>
                            </button>
                        </div>
                    `).join('') : `
                        <div class="cs-empty-box">
                            <div class="cs-empty-icon"><i class="fa-solid fa-bullseye" aria-hidden="true"></i></div>
                            <span>No watchlist targets configured yet.</span>
                        </div>
                    `}
                </div>
            </div>
        `;
    };

    // ---- Overview tab: charts from /api/credential-stealer/overview (already loaded as state.overview) ----
    const renderOverviewSection = () => {
        const ov = state.overview || {};
        const m = ov.metrics || {};
        const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        return `
            <div class="dc-grid">
                <section class="dc-panel"><h4><i class="fa-solid fa-user-secret"></i> Credentials by stealer family</h4><div class="dc-chart dc-tall" id="cs-chart-families"></div></section>
                <section class="dc-panel"><h4><i class="fa-solid fa-globe"></i> Top domains</h4><div class="dc-chart dc-tall" id="cs-chart-domains"></div></section>
            </div>
            <div class="dc-note">Totals: ${esc(m.total_credentials ?? 0)} credentials · ${esc(m.unique_domains ?? 0)} unique domains · ${esc(m.watchlist_hits ?? 0)} watchlist hits. Charts are drawn from the current vault contents.</div>`;
    };

    const mountOverviewCharts = () => {
        if (!window.MantisCharts) return;
        const ov = state.overview || {};
        const fam = ov.families || [];
        const dom = ov.top_domains || [];
        const famEl = document.getElementById('cs-chart-families');
        if (famEl) window.MantisCharts.doughnut(famEl, {
            labels: fam.map(f => f.family), values: fam.map(f => Number(f.count || 0)),
            emptyText: 'No stealer families recorded yet.',
        });
        const domEl = document.getElementById('cs-chart-domains');
        if (domEl) window.MantisCharts.bar(domEl, {
            labels: dom.map(d => d.domain),
            datasets: [{ label: 'Credentials', data: dom.map(d => Number(d.count || 0)) }],
            horizontal: true, emptyText: 'No domains recorded yet.',
        });
    };

    // ---- Sources tab: three focused sub-tabs (Local Scan / Telegram / Automation) ----
    const renderSourcesTabs = () => {
        const sub = state.sourcesSub || 'local';
        const tabs = [
            ['local', 'fa-solid fa-folder-open', 'Local Scan'],
            ['telegram', 'fa-brands fa-telegram', 'Telegram'],
            ['automation', 'fa-solid fa-calendar-check', 'Automation'],
        ];
        return `<div class="cs-subtabs" role="tablist" aria-label="Sources sections">${tabs.map(([id, icon, label]) => `
            <button type="button" class="cs-subtab${sub === id ? ' active' : ''}" data-cs-subtab="${id}" role="tab" aria-selected="${sub === id}">
                <i class="${icon}" aria-hidden="true"></i><span>${label}</span>
            </button>`).join('')}</div>`;
    };

    const renderParserSelect = () => {
        const parsers = (state.parsersData?.parsers || []).filter(p => Number(p.enabled ?? 1) !== 0);
        const current = state.selectedParser || '';
        return `
            <div class="cs-field" style="margin-bottom:0; flex:1; min-width:220px;">
                <label class="cs-field-label" for="cs-parser-select">Parser</label>
                <select id="cs-parser-select" class="cs-select" style="width:100%;">
                    <option value="">Auto-detect (recommended)</option>
                    ${parsers.map(p => `<option value="${esc(p.name)}" ${current === p.name ? 'selected' : ''}>${esc(p.name)}${Number(p.is_builtin ?? 0) ? '' : ' (custom)'}</option>`).join('')}
                </select>
            </div>`;
    };

    const renderUploadResult = () => {
        const ur = state.lastUploadResult;
        if (!ur) return '';
        const summaries = ur.file_summaries || [];
        const errors = summaries.flatMap(f => f.archive_errors || []);
        const names = summaries.filter(f => !f.archive_errors?.length || f.creds_found || f.unparsed)
            .map(f => f.file_name).join(', ') || 'uploaded files';
        const archiveWarning = errors.length ? `
            <div class="cs-upload-result is-error" role="alert">
                <div class="cs-upload-result-msg">
                    <i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>
                    <span>${errors.map(esc).join('<br>')}</span>
                </div>
                <button type="button" class="cs-icon-mini" data-cs-action="clear-upload-result" title="Dismiss"><i class="fa-solid fa-xmark"></i></button>
            </div>` : '';
        if ((ur.creds_found || 0) > 0) {
            return `${archiveWarning}
                <div class="cs-upload-result">
                    <div class="cs-upload-result-msg">
                        <i class="fa-solid fa-circle-check"></i>
                        <span>Extracted <strong>${ur.creds_found}</strong> credentials (<strong>${ur.creds_new}</strong> new) from <code>${esc(names)}</code>.</span>
                    </div>
                    <div style="display:flex; gap:6px; align-items:center;">
                        <button type="button" class="cs-btn cs-btn-sm cs-btn-primary" data-cs-action="goto-vault"><i class="fa-solid fa-database"></i> View Vault</button>
                        <button type="button" class="cs-icon-mini" data-cs-action="clear-upload-result" title="Dismiss"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                </div>
            `;
        }
        if ((ur.unparsed_files || 0) > 0) {
            return `${archiveWarning}
                <div class="cs-upload-result is-warn">
                    <div class="cs-upload-result-msg">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                        <span><code>${esc(names)}</code> did not match the selected parser or any built-in rule and was queued for <strong>AI Parser Studio</strong>.</span>
                    </div>
                    <div style="display:flex; gap:6px; align-items:center;">
                        <button type="button" class="cs-btn cs-btn-sm cs-btn-ai" data-cs-action="goto-studio-unparsed"><i class="fa-solid fa-wand-magic-sparkles"></i> Open in AI Studio</button>
                        <button type="button" class="cs-icon-mini" data-cs-action="clear-upload-result" title="Dismiss"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                </div>
            `;
        }
        if (archiveWarning) return archiveWarning;
        return `
            <div class="cs-upload-result is-error">
                <div class="cs-upload-result-msg">
                    <i class="fa-solid fa-circle-info"></i>
                    <span>Processed <code>${esc(names)}</code>: 0 credentials found (file empty or no text entries detected).</span>
                </div>
                <button type="button" class="cs-icon-mini" data-cs-action="clear-upload-result" title="Dismiss"><i class="fa-solid fa-xmark"></i></button>
            </div>
        `;
    };

    const renderLocalSourcesList = () => {
        const localSources = state.sourcesData?.local || [];
        return `
            <div class="cs-source-list">
                ${localSources.length ? localSources.map(src => `
                    <div class="cs-source-item">
                        <div>
                            <strong>${esc(src.label)} <span class="cs-badge ${src.status === 'scanning' ? 'syncing' : (src.status === 'error' || src.status === 'unparsed') ? 'error' : 'ready'}">${esc(src.status)}</span>${src.delete_after_parse ? ' <span class="cs-badge" style="color:#f87171; border-color:rgba(239,68,68,0.3); font-size:10px;"><i class="fa-solid fa-trash-can"></i> Auto-Delete</span>' : ''}</strong>
                            <div class="cs-source-meta">${esc(src.folder_path)}</div>
                            <div class="cs-source-meta">${src.files_scanned} files &bull; ${src.total_creds} creds &bull; ${src.last_scanned_at ? 'Last: ' + esc(src.last_scanned_at) : 'Never scanned'}</div>
                        </div>
                        <div style="display:flex; gap:6px; flex-shrink:0;">
                            ${String(src.folder_path || '').startsWith('upload://') ? '' : `<button type="button" class="cs-btn cs-btn-sm" data-cs-action="scan-local" data-id="${src.id}" title="Re-scan folder"><i class="fa-solid fa-rotate"></i></button>`}
                            <button type="button" class="cs-btn cs-btn-sm cs-btn-danger" data-cs-action="del-local" data-id="${src.id}" title="Remove source"><i class="fa-solid fa-trash"></i></button>
                        </div>
                    </div>
                `).join('') : `
                    <div class="cs-empty-box">
                        <div class="cs-empty-icon"><i class="fa-regular fa-folder-open"></i></div>
                        <span>Nothing scanned yet. Upload files above, or scan a folder under <strong>Advanced</strong>.</span>
                    </div>
                `}
            </div>`;
    };

    const renderLocalPane = () => `
        <div class="cs-card">
            <div class="cs-card-head">
                <div class="cs-card-title">
                    <div class="cs-card-icon"><i class="fa-solid fa-file-arrow-up"></i></div>
                    <div>
                        <h3>Upload &amp; Parse</h3>
                        <p>Drop credential logs or archives (${supportedFileTypes.map(ext => `<code>${ext}</code>`).join(', ')}).</p>
                    </div>
                </div>
            </div>

            <label class="cs-dropzone" id="cs-dropzone" for="cs-upload-files-input">
                <i class="fa-solid fa-cloud-arrow-up" aria-hidden="true"></i>
                <strong>Drop files here or click to browse</strong>
                <span class="cs-dropzone-hint">Multiple files allowed</span>
                <span id="cs-upload-file-label" class="cs-file-status">${esc(getUploadLabelText())}</span>
            </label>
            <input id="cs-upload-files-input" type="file" multiple accept="${supportedFileTypes.join(',')}" style="display:none;">

            <div class="cs-form-row" style="align-items:flex-end; gap:10px; flex-wrap:wrap;">
                ${renderParserSelect()}
                <div class="cs-field" style="margin-bottom:0; flex:1; min-width:180px;">
                    <label class="cs-field-label" for="cs-local-label-input">Source label (optional)</label>
                    <input id="cs-local-label-input" class="cs-input" placeholder="e.g. Weekly Dump Oct">
                </div>
                <button type="button" id="cs-upload-files-btn" class="cs-btn cs-btn-primary"><i class="fa-solid fa-bolt"></i> Upload &amp; Parse</button>
            </div>

            ${renderUploadResult()}

            <details class="cs-advanced">
                <summary><i class="fa-solid fa-sliders" aria-hidden="true"></i> Advanced: scan a folder or selected files on disk<i class="fa-solid fa-chevron-down cs-advanced-chevron" aria-hidden="true"></i></summary>
                <div class="cs-advanced-body">
                    <div class="cs-field">
                        <label class="cs-field-label" for="cs-local-path-input">Directory or File Path</label>
                        <div class="cs-input-group">
                            <input id="cs-local-path-input" type="text" placeholder="C:\\Users\\hp\\Downloads\\stealer_logs">
                            <button type="button" id="cs-browse-file-btn" class="cs-group-btn" title="Select a local log or archive"${state.localPickerOpen ? ' disabled' : ''}>
                                <i class="fa-solid fa-file-lines"></i> File...
                            </button>
                            <button type="button" id="cs-browse-folder-btn" class="cs-group-btn" title="Select a local folder"${state.localPickerOpen ? ' disabled' : ''}>
                                <i class="fa-solid fa-folder-tree"></i> Folder...
                            </button>
                        </div>
                    </div>
                    <div class="cs-form-row" style="flex-wrap:wrap; gap:8px;">
                        <label class="cs-switch" title="Scan subdirectories recursively">
                            <input id="cs-local-recursive" type="checkbox" role="switch" checked>
                            <span class="cs-switch-track" aria-hidden="true"></span>
                            <span>Recursive</span>
                        </label>
                        <label class="cs-switch" title="Re-scan automatically during weekly automated harvester runs">
                            <input id="cs-local-weekly" type="checkbox" role="switch" checked>
                            <span class="cs-switch-track" aria-hidden="true"></span>
                            <span>Weekly Sync</span>
                        </label>
                        <label class="cs-switch" title="Automatically delete parsed RAR, ZIP, and .txt files after successful ingestion to save disk space">
                            <input id="cs-local-delete-after" type="checkbox" role="switch">
                            <span class="cs-switch-track" aria-hidden="true"></span>
                            <span style="color:#f87171;"><i class="fa-solid fa-trash-can" style="font-size:10px; margin-right:2px;"></i> Delete After Parse</span>
                        </label>
                        <button type="button" id="cs-local-scan-btn" class="cs-btn cs-btn-primary">
                            <i class="fa-solid fa-play"></i> Scan Path
                        </button>
                    </div>
                </div>
            </details>

            ${renderLocalSourcesList()}
        </div>
    `;

    const renderTelegramPane = () => {
        const tgSources = state.sourcesData?.telegram || [];
        return `
            <div class="cs-card">
                <div class="cs-card-head">
                    <div class="cs-card-title">
                        <div class="cs-card-icon cyan"><i class="fa-brands fa-telegram"></i></div>
                        <div>
                            <h3>Telegram Channels</h3>
                            <p>Reads channel history from the saved cursor and downloads allowed attachments and cloud links.</p>
                        </div>
                    </div>
                </div>

                <div class="cs-field">
                    <label class="cs-field-label" for="cs-tg-username">Channel &amp; Harvest Mode</label>
                    <div class="cs-form-row" style="margin-bottom:0; flex-wrap:wrap; align-items:center;">
                        <input id="cs-tg-username" class="cs-input" style="flex:1; min-width:170px;" placeholder="@channel_username or t.me/channel">
                        <select id="cs-tg-mode" class="cs-select">
                            <option value="all">All (Attachments + Cloud Links)</option>
                            <option value="archives">Archives Only (.zip/.rar/.7z)</option>
                            <option value="links">Cloud Links Only</option>
                            <option value="txt">.txt Logs Only</option>
                        </select>
                        <select id="cs-tg-limit-mode" class="cs-select" title="Choose how many messages to read per sync">
                            <option value="all" selected>All messages (drains the whole backlog)</option>
                            <option value="number">Last N messages</option>
                        </select>
                        <input id="cs-tg-limit" type="number" class="cs-input" style="width:90px;" value="50" min="5" hidden title="Messages per sync">
                        <button type="button" id="cs-tg-add-btn" class="cs-btn cs-btn-primary">
                            <i class="fa-solid fa-plus"></i> Add Channel
                        </button>
                    </div>
                    <p class="cs-field-help">Unlimited means one sync reads until it catches up. The cursor is saved, so a stopped run continues next time.</p>
                </div>

                <div class="cs-field" style="margin-bottom:12px;">
                    <span class="cs-field-label">Cloud resolvers</span>
                    <div class="cs-resolver-strip" style="margin-bottom:0;">
                        <span class="cs-resolver-chip"><span class="cs-dot"></span> Pixeldrain API</span>
                        <span class="cs-resolver-chip"><span class="cs-dot"></span> GoFile</span>
                        <span class="cs-resolver-chip"><span class="cs-dot"></span> MediaFire</span>
                        <span class="cs-resolver-chip"><span class="cs-dot amber"></span> Mega (megadl)</span>
                        <span class="cs-resolver-chip"><span class="cs-dot"></span> Auto-Pass Caption</span>
                    </div>
                </div>

                <div class="cs-source-list">
                    ${tgSources.length ? tgSources.map(ch => `
                        <div class="cs-source-item">
                            <div>
                                <strong>@${esc(ch.username)} <span class="cs-badge" title="Download mode: ${esc(ch.download_mode)}">${esc(ch.download_mode)}</span> <span class="cs-badge ${ch.status === 'syncing' ? 'syncing' : ch.status === 'error' ? 'error' : 'ready'}" title="${esc(ch.status === 'paused' ? 'Backlog remains; the next sync resumes from the saved cursor.' : ch.status === 'syncing' ? 'This channel is being read now.' : ch.status === 'error' ? 'The previous sync failed.' : 'This channel is ready to sync.')}">${esc(ch.status)}</span></strong>
                                <div class="cs-source-meta">${esc(ch.title)} &bull; ${Number(ch.messages_read || 0).toLocaleString()} messages read &bull; ${Number(ch.files_downloaded || 0).toLocaleString()} files downloaded &bull; ${ch.total_creds} creds</div>
                                <div class="cs-source-meta">${ch.last_synced_at ? `Last sync: ${esc(ch.last_synced_at)} (message #${ch.last_message_id})` : 'Never synced'}${ch.status === 'paused' ? ` &bull; ${Number(ch.messages_remaining || 0).toLocaleString()} messages waiting` : ''}</div>
                                ${ch.last_error ? `<div class="cs-source-meta" style="color:#fca5a5;">${esc(ch.last_error)}</div>` : ''}
                            </div>
                            <div style="display:flex; gap:6px; flex-shrink:0;">
                                <button type="button" class="cs-btn cs-btn-sm cs-btn-primary" data-cs-action="sync-tg" data-id="${ch.id}" title="Sync Channel Now"><i class="fa-solid fa-cloud-arrow-down"></i> Sync</button>
                                <button type="button" class="cs-btn cs-btn-sm cs-btn-danger" data-cs-action="del-tg" data-id="${ch.id}" title="Remove Channel"><i class="fa-solid fa-trash"></i></button>
                            </div>
                        </div>
                    `).join('') : `
                        <div class="cs-empty-box">
                            <div class="cs-empty-icon"><i class="fa-brands fa-telegram"></i></div>
                            <span>No Telegram channels monitored yet. Enter a <code>@channel</code> username above to begin.</span>
                        </div>
                    `}
                </div>
            </div>
        `;
    };

    const renderAutomationPane = () => {
        const s = state.sourcesData?.settings || {};
        const aiStatus = getAiStatus();
        const aiAvailable = Boolean(aiStatus.available);
        const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
        return `
            <div class="cs-card">
                <div class="cs-card-head">
                    <div class="cs-card-title">
                        <div class="cs-card-icon cyan"><i class="fa-solid fa-calendar-check"></i></div>
                        <div>
                            <h3>Weekly Automated Harvester</h3>
                            <p>Downloads Telegram drops and re-scans watched folders on a schedule.
                            ${s.last_weekly_run ? `<span style="color:#64748b; font-family:var(--font-mono);">Last run: ${esc(s.last_weekly_run)}</span>` : ''}</p>
                        </div>
                    </div>
                </div>

                <div class="cs-field">
                    <span class="cs-field-label">Schedule</span>
                    <div class="cs-form-row" style="margin-bottom:0; flex-wrap:wrap; align-items:center;">
                        <label class="cs-switch" title="Enable automatic weekly harvesting">
                            <input id="cs-sched-enabled" type="checkbox" role="switch" ${s.weekly_enabled ? 'checked' : ''}>
                            <span class="cs-switch-track" aria-hidden="true"></span>
                            <span>Auto-Sync</span>
                        </label>
                        <select id="cs-sched-day" class="cs-select">
                            ${days.map(d => `<option value="${d}" ${s.weekly_day === d ? 'selected' : ''}>Every ${d}</option>`).join('')}
                        </select>
                        <select id="cs-sched-hour" class="cs-select">
                            ${Array.from({ length: 24 }, (_, h) => `<option value="${h}" ${Number(s.weekly_hour_utc) === h ? 'selected' : ''}>${String(h).padStart(2, '0')}:00 UTC</option>`).join('')}
                        </select>
                        <button type="button" id="cs-sched-save" class="cs-btn cs-btn-primary cs-btn-sm">
                            <i class="fa-solid fa-floppy-disk"></i> Save settings
                        </button>
                    </div>
                </div>

                <div class="cs-field" style="margin-bottom:0;">
                    <span class="cs-field-label">Options</span>
                    <div class="cs-form-row" style="margin-bottom:0; flex-wrap:wrap; gap:14px;">
                        <label class="cs-switch" title="${aiAvailable ? 'Automatically invoke AI Parser Generator when an unrecognized .txt format is encountered' : esc(aiStatus.reason || 'Disabled: No AI provider configured in MANTIS AI')}">
                            <input id="cs-sched-auto-ai" type="checkbox" role="switch" ${aiAvailable && s.auto_ai_parse ? 'checked' : ''} ${aiAvailable ? '' : 'disabled'}>
                            <span class="cs-switch-track" aria-hidden="true"></span>
                            <span>Auto-AI Parse</span>
                        </label>
                        <label class="cs-switch" title="Delete downloaded temporary archives immediately after extraction">
                            <input id="cs-sched-ephemeral" type="checkbox" role="switch" ${s.ephemeral_delete_archives ? 'checked' : ''}>
                            <span class="cs-switch-track" aria-hidden="true"></span>
                            <span>Ephemeral Cleanup</span>
                        </label>
                        <label class="cs-switch" title="Automatically delete parsed RAR, ZIP, and .txt files after scan completes to save disk space">
                            <input id="cs-sched-delete-after" type="checkbox" role="switch" ${s.delete_after_parse ? 'checked' : ''}>
                            <span class="cs-switch-track" aria-hidden="true"></span>
                            <span style="color:#fca5a5;"><i class="fa-solid fa-trash-can" style="font-size:10px; margin-right:2px;"></i> Delete Parsed Files</span>
                        </label>
                        <label class="cs-field">Largest single archive to download
                            <input id="cs-max-archive-mb" type="number" class="cs-input" min="10" max="2048" value="${Number(s.max_archive_mb || 250)}"> MB
                            <small>Largest single archive to download</small>
                        </label>
                        <label class="cs-field">Files per sync before pausing
                            <input id="cs-max-files-sync" type="number" class="cs-input" min="10" max="5000" value="${Number(s.max_files_per_sync || 200)}">
                            <small>Files per sync before pausing</small>
                        </label>
                        <label class="cs-field">Additional file extensions
                            <input id="cs-extra-extensions" class="cs-input" value="${esc((s.extra_extensions || []).join(','))}" placeholder=".json,.sql,.db">
                            <small>Comma separated; included in All mode</small>
                        </label>
                    </div>
                </div>
            </div>
        `;
    };

    const renderSourcesSection = () => {
        const sub = state.sourcesSub || 'local';
        const body = sub === 'telegram' ? renderTelegramPane()
            : sub === 'automation' ? renderAutomationPane()
            : renderLocalPane();
        return renderSourcesTabs() + body;
    };

    const renderStudioSection = () => {
        const unparsed = state.parsersData?.unparsed_queue || [];
        const parsers = state.parsersData?.parsers || [];
        const d = state.studioDraft;
        const aiStatus = getAiStatus();
        const aiAvailable = Boolean(aiStatus.available);

        return `
            <div class="cs-studio-grid">
                <div class="cs-card cs-studio-queue">
                    <div class="cs-card-head">
                        <div class="cs-card-title">
                            <div class="cs-card-icon danger"><i class="fa-solid fa-inbox"></i></div>
                            <div>
                                <h3 id="cs-studio-queue-title">Unrecognized File Queue (${unparsed.length})</h3>
                                <p>Files that didn't match built-in signatures. Load any sample into AI Studio.</p>
                            </div>
                        </div>
                        ${unparsed.length ? `
                            <button type="button" id="cs-unparsed-dismiss-all" class="cs-btn cs-btn-sm" title="Dismiss all unrecognized files from queue">
                                <i class="fa-solid fa-check-double"></i> Dismiss All
                            </button>
                        ` : ''}
                    </div>
                    <div class="cs-source-list cs-studio-queue-list" ${unparsed.length ? 'tabindex="0" role="region" aria-labelledby="cs-studio-queue-title"' : ''}>
                        ${unparsed.length ? unparsed.map(u => `
                            <div class="cs-queue-item">
                                <div class="cs-studio-queue-header">
                                    <div class="cs-studio-queue-meta">
                                        <strong title="${esc(u.file_name)}">${esc(u.file_name)}</strong>
                                        ${u.source_name ? `<div class="cs-studio-queue-path" title="${esc(u.source_name)}">${esc(u.source_name)}</div>` : ''}
                                    </div>
                                    <div class="cs-studio-queue-actions">
                                        <button type="button" class="cs-btn cs-btn-sm cs-btn-ai" data-cs-action="load-unparsed" data-id="${u.id}"><i class="fa-solid fa-wand-magic-sparkles"></i> Load in Studio</button>
                                        <button type="button" class="cs-btn cs-btn-sm" data-cs-action="dismiss-unparsed" data-id="${u.id}" title="Dismiss" aria-label="Dismiss ${esc(u.file_name)}"><i class="fa-solid fa-xmark"></i></button>
                                    </div>
                                </div>
                                <pre class="cs-queue-snippet">${esc(u.sample_snippet)}</pre>
                            </div>
                        `).join('') : `<div class="cs-empty-box"><div class="cs-empty-icon"><i class="fa-solid fa-check"></i></div><span>No unrecognized files waiting in queue.</span></div>`}
                    </div>
                </div>

                <div class="cs-card cs-studio-workbench">
                    <div class="cs-card-head">
                        <div class="cs-card-title">
                            <div class="cs-card-icon purple"><i class="fa-solid fa-wand-magic-sparkles"></i></div>
                            <div>
                                <h3>AI Agent Parser Generator &amp; Test Bench</h3>
                                <p>Synthesizes named-group regexes <code>(?P&lt;url&gt;)</code>, <code>(?P&lt;username&gt;)</code>, <code>(?P&lt;password&gt;)</code> from any raw log sample.</p>
                            </div>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                            ${aiAvailable
                                ? `<span class="cs-badge ready" title="MANTIS AI Provider Active"><i class="fa-solid fa-robot"></i> ${esc(aiStatus.provider_label || aiStatus.provider)} &bull; ${esc(aiStatus.model)}</span>`
                                : `<span class="cs-badge error" title="${esc(aiStatus.reason || 'No AI configured in MANTIS AI')}"><i class="fa-solid fa-ban"></i> AI Disabled (No MANTIS AI)</span>`
                            }
                            <button type="button" id="cs-studio-load-demo" class="cs-btn cs-btn-sm"><i class="fa-solid fa-flask"></i> Load Sample</button>
                        </div>
                    </div>

                    <div style="display:flex; flex-direction:column; gap:12px;">
                        <div class="cs-field" style="margin-bottom:0;">
                            <label class="cs-field-label" for="cs-studio-sample">Raw Log Sample (5&ndash;30 lines)</label>
                            <textarea id="cs-studio-sample" class="cs-textarea" rows="6" placeholder="Paste lines of any unrecognized stealer .txt format here...">${esc(d.sample_snippet)}</textarea>
                        </div>

                        ${!aiAvailable ? `
                            <div class="cs-ai-disabled-banner">
                                <i class="fa-solid fa-triangle-exclamation"></i>
                                <div><strong>AI Agent Parser Disabled</strong> &mdash; ${esc(aiStatus.reason || 'No AI provider is configured in MANTIS AI.')} Configure a provider in <strong>MANTIS AI &rarr; Settings</strong> to enable AI regex synthesis, or write and test a regex pattern manually in the Test Bench below.</div>
                            </div>
                        ` : ''}

                        <div class="cs-form-row cs-studio-controls">
                            <input id="cs-studio-hint" class="cs-input" value="${esc(d.hint_family)}" placeholder="Optional stealer family hint (e.g. CustomPanel, Lumma)" ${aiAvailable ? '' : 'disabled'}>
                            <button type="button" id="cs-studio-ai-btn" class="cs-btn cs-btn-ai" ${aiAvailable ? '' : 'disabled'} title="${aiAvailable ? 'Synthesize regex with MANTIS AI' : esc(aiStatus.reason || 'Disabled: No AI configured in MANTIS AI')}">
                                <i class="fa-solid fa-robot"></i> Generate Parser with AI Agent
                            </button>
                        </div>

                        ${d.warning ? `<div style="padding:9px 12px; border-radius:8px; background:rgba(255,204,0,0.08); border:1px solid rgba(255,204,0,0.28); color:#fde047; font-size:0.77rem;">${esc(d.warning)}</div>` : ''}
                        ${d.explanation ? `<div style="padding:9px 12px; border-radius:8px; background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.26); color:#bae6fd; font-size:0.77rem;"><strong>${esc(d.model || 'Agent')}:</strong> ${esc(d.explanation)}</div>` : ''}

                        <div class="cs-form-row cs-studio-controls">
                            <input id="cs-studio-name" class="cs-input" value="${esc(d.name)}" placeholder="Rule Name (e.g. Custom Logs Format v1)">
                            <input id="cs-studio-family" class="cs-input" value="${esc(d.stealer_family)}" placeholder="Stealer Family Tag">
                            <select id="cs-studio-mode" class="cs-select">
                                <option value="block_regex" ${d.mode === 'block_regex' ? 'selected' : ''}>Multi-line Block (block_regex)</option>
                                <option value="line_regex" ${d.mode === 'line_regex' ? 'selected' : ''}>Single-line (line_regex)</option>
                            </select>
                        </div>

                        <div class="cs-field" style="margin-bottom:0;">
                            <label class="cs-field-label" for="cs-studio-pattern">Generated Python Regex Pattern</label>
                            <textarea id="cs-studio-pattern" class="cs-textarea" rows="3" placeholder="Python regex with (?P<url>...), (?P<username>...), (?P<password>...) named groups...">${esc(d.pattern)}</textarea>
                        </div>

                        <div style="display:flex; gap:10px; flex-wrap:wrap;">
                            <button type="button" id="cs-studio-test-btn" class="cs-btn"><i class="fa-solid fa-vial"></i> Test Pattern</button>
                            <button type="button" id="cs-studio-save-btn" class="cs-btn cs-btn-primary"><i class="fa-solid fa-check-double"></i> Save Parser &amp; Re-parse Queue</button>
                        </div>

                        <div style="margin-top:4px;">
                            <div class="cs-field-label" style="margin-bottom:6px;">
                                Live Extraction Preview (${(d.test_matches || []).length} rows matched)
                            </div>
                            <div class="cs-table-wrap">
                                <table class="cs-table">
                                    <thead>
                                        <tr>
                                            <th>Domain</th>
                                            <th>URL</th>
                                            <th>Username</th>
                                            <th>Plaintext Password</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${(d.test_matches || []).length ? d.test_matches.slice(0, 20).map(m => `
                                            <tr>
                                                <td><strong>${esc(m.domain)}</strong></td>
                                                <td style="font-family:var(--font-mono); font-size:0.74rem; color:#94a3b8;">${esc(m.url)}</td>
                                                <td style="font-family:var(--font-mono);">${esc(m.username)}</td>
                                                <td style="font-family:var(--font-mono); color:#fde047;">${esc(m.password_plain)}</td>
                                            </tr>
                                        `).join('') : `<tr><td colspan="4" class="cs-empty" style="padding:18px;">${aiAvailable ? 'Click <strong>Generate Parser with AI Agent</strong> or <strong>Test Pattern</strong> to preview extracted rows.' : 'Enter a regex pattern above and click <strong>Test Pattern</strong> to preview extracted rows (AI Agent is disabled until MANTIS AI is configured).'}</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="cs-card cs-studio-catalog">
                    <div class="cs-card-head">
                        <div class="cs-card-title">
                            <div class="cs-card-icon cyan"><i class="fa-solid fa-code"></i></div>
                            <div>
                                <h3>Active Parser Catalog (${parsers.length})</h3>
                                <p>Built-in stealer/combo signatures &amp; AI-synthesized custom rules.</p>
                            </div>
                        </div>
                    </div>
                    <div class="cs-source-list" style="margin-top:0;">
                        ${parsers.map(p => `
                            <div class="cs-source-item">
                                <div style="min-width:0; flex:1;">
                                    <strong>
                                        ${esc(p.name)}
                                        <span class="cs-badge family">${esc(p.stealer_family)}</span>
                                        <span class="cs-badge">${p.is_builtin ? 'built-in' : 'AI/custom'}</span>
                                        <span class="cs-badge ready">${p.matches_count || 0} matches</span>
                                    </strong>
                                    <div class="cs-source-meta" style="color:#64748b;">${esc(p.pattern)}</div>
                                </div>
                                ${!p.is_builtin ? `<button type="button" class="cs-btn cs-btn-sm cs-btn-danger" data-cs-action="del-parser" data-id="${p.id}"><i class="fa-solid fa-trash"></i></button>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    };

    const jobWords = { tg_sync: 'Telegram sync', manual_all: 'Full sync (all sources)', weekly_auto: 'Scheduled sync', local_folder: 'Local folder', upload: 'Manual upload' };
    const durationText = (start, end) => {
        const seconds = Math.max(0, Math.floor((Date.parse(end || new Date().toISOString()) - Date.parse(start)) / 1000));
        return Number.isFinite(seconds) ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : 'unknown time';
    };
    const friendlyJobError = text => /MTProto not configured|Telegram.*session|not signed in/i.test(text || '')
        ? 'Telegram is not signed in. Sign in under Settings > Telegram, then sync again.' : text || 'The sync failed. Check the job log.';
    const renderJobsSection = () => {
        const jobs = state.jobsData?.jobs || [];
        return `
            <div class="cs-card">
                <div class="cs-card-head">
                    <div class="cs-card-title">
                        <div class="cs-card-icon emerald"><i class="fa-solid fa-list-check"></i></div>
                        <div>
                            <h3>Ingestion &amp; Harvester Jobs</h3>
                            <p>Live progress and historical execution logs for local folder scans, Telegram downloads, and weekly schedules.</p>
                        </div>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <button type="button" id="cs-jobs-clear" class="cs-btn cs-btn-sm cs-btn-danger" ${!jobs.length ? 'disabled' : ''} title="Clear all job execution logs">
                            <i class="fa-solid fa-trash-can"></i> Clear Logs
                        </button>
                        <button type="button" id="cs-jobs-refresh" class="cs-btn cs-btn-sm"><i class="fa-solid fa-rotate"></i> Refresh</button>
                    </div>
                </div>

                <div class="cs-source-list" style="margin-top:0;">
                    ${jobs.length ? jobs.map(j => {
                        const tgJob = ['tg_sync', 'manual_all', 'weekly_auto'].includes(j.job_type);
                        const done = Number(j.files_processed || 0), total = Number(j.files_total || 0);
                        const files = Number(j.files_downloaded ?? (tgJob ? 0 : j.files_processed) ?? 0);
                        const skipped = Number(j.files_skipped || 0), remaining = Number(j.messages_remaining || 0);
                        const pct = j.status !== 'failed' && total > 0 ? Math.min(100, Math.round(done / total * 100)) : null;
                        const elapsed = durationText(j.started_at, j.status === 'running' ? null : j.finished_at || j.started_at);
                        const neverStarted = j.status === 'failed' && !done && !files;
                        const counters = neverStarted ? 'Messages - · Files -' : `${tgJob ? 'Messages' : 'Items'} ${done} of ${total || '?'} · Files downloaded ${files} · Skipped ${skipped}`;
                        const statusText = j.status === 'running'
                            ? `Reading ${j.source_label || 'source'} — message ${done} of ${total || '?'}, ${files} files downloaded${j.current_file && !/^https?:\/\//i.test(j.current_file) ? ` · Downloading ${j.current_file}` : ''}`
                            : j.status === 'paused' ? `${/disk/i.test(j.error_msg || '') ? 'Paused because free disk space is low.' : `Paused after ${files} files.`} ${remaining} messages queued — the next sync continues here.`
                            : j.status === 'completed' ? `Finished in ${elapsed}. ${files} files, ${Number(j.creds_found || 0).toLocaleString()} credentials (${Number(j.creds_new || 0).toLocaleString()} new).`
                            : j.status === 'failed' ? friendlyJobError(j.error_msg) : `Stopped after ${elapsed}.`;
                        return `
                            <div class="cs-queue-item">
                                <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <strong>${esc(j.source_label || j.id)}</strong>
                                        <span class="cs-badge" title="${esc(jobWords[j.job_type] || 'Ingestion job')}">${esc(jobWords[j.job_type] || j.job_type)}</span>
                                        <span class="cs-badge ${j.status === 'running' ? 'syncing' : j.status === 'failed' ? 'error' : 'ready'}" title="${esc(statusText)}">${esc(j.status)}</span>
                                    </div>
                                    <div style="font:600 0.74rem var(--font-mono); color:#94a3b8;">
                                        ${esc(counters)} &bull; ${j.status === 'running' ? `${elapsed} elapsed` : j.status === 'failed' ? `Failed ${j.finished_at ? esc(new Date(j.finished_at).toLocaleString()) : 'before starting'}` : `${elapsed} total`}
                                    </div>
                                </div>
                                ${['running', 'paused', 'failed'].includes(j.status) ? `
                                    <div class="cs-progress-track" role="progressbar" ${pct === null ? 'aria-label="Progress unknown"' : `aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"`}><div class="cs-progress-fill ${pct === null ? 'is-indeterminate' : ''}" ${pct === null ? '' : `style="width:${pct}%;"`}></div></div>
                                    <div class="cs-job-status" aria-live="polite">${esc(statusText)}</div>
                                ` : ''}
                                ${j.status === 'completed' ? `<div class="cs-job-status" aria-live="polite">${esc(statusText)}</div>` : ''}
                                <details class="cs-job-details"><summary>Job log</summary><div class="cs-job-log">${esc((j.log_lines || []).slice(-12).join('\n'))}</div></details>
                            </div>
                        `;
                    }).join('') : `<div class="cs-empty-box"><div class="cs-empty-icon"><i class="fa-solid fa-clock-rotate-left"></i></div><span>Add a local folder or Telegram channel, then sync. Progress and files captured appear here.</span></div>`}
                </div>
            </div>
        `;
    };

    const openDeleteMgmtModal = async () => {
        state.deleteMgmt.isOpen = true;
        state.deleteMgmt.loading = true;
        state.deleteMgmt.deleting = false;
        state.deleteMgmt.sources = [];
        state.deleteMgmt.selectedKeys = new Set();
        state.deleteMgmt.searchQuery = '';
        renderDeleteMgmtModal();

        try {
            const res = await api('/api/credential-stealer/credentials/sources');
            state.deleteMgmt.sources = res.sources || [];
        } catch (err) {
            showToast(`Failed to load sources: ${err.message}`, true);
        } finally {
            state.deleteMgmt.loading = false;
            renderDeleteMgmtModal();
        }
    };

    const closeDeleteMgmtModal = () => {
        if (state.deleteMgmt.deleting) return;
        state.deleteMgmt.isOpen = false;
        state.deleteMgmt.selectedKeys.clear();
        state.deleteMgmt.searchQuery = '';
        renderDeleteMgmtModal();
    };

    const handleConfirmDelete = async () => {
        if (state.deleteMgmt.deleting || state.deleteMgmt.selectedKeys.size === 0) return;
        const selectedSources = state.deleteMgmt.sources.filter(s => state.deleteMgmt.selectedKeys.has(s.group_key));
        const selectedCredCount = selectedSources.reduce((sum, s) => sum + (s.count || 0), 0);
        const isAllTotalSelected = state.deleteMgmt.sources.length > 0 && selectedSources.length === state.deleteMgmt.sources.length;

        const confirmMsg = isAllTotalSelected
            ? `Permanently delete ALL ${selectedCredCount.toLocaleString()} indexed credentials across all sources?\n\nThis cannot be undone.`
            : `Permanently delete ${selectedCredCount.toLocaleString()} credentials from ${selectedSources.length} selected source(s)?\n\nThis cannot be undone.`;

        let confirmed = false;
        if (window.mantisConfirm) {
            confirmed = await window.mantisConfirm({
                title: 'Batch Delete Credentials',
                message: isAllTotalSelected
                    ? `Permanently delete ALL ${selectedCredCount.toLocaleString()} indexed credentials across all sources?`
                    : `Permanently delete ${selectedCredCount.toLocaleString()} credentials from ${selectedSources.length} selected source(s)?`,
                details: 'This action cannot be undone.',
                confirmText: 'Permanently Delete',
                danger: true,
                icon: 'fa-trash-can'
            });
        } else {
            confirmed = window.confirm(confirmMsg);
        }
        if (!confirmed) return;

        state.deleteMgmt.deleting = true;
        renderDeleteMgmtModal();

        try {
            const rawSources = [];
            selectedSources.forEach(s => {
                if (s.raw_sources && s.raw_sources.length) {
                    rawSources.push(...s.raw_sources);
                }
            });

            const res = await api('/api/credential-stealer/credentials/delete-batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sources: Array.from(state.deleteMgmt.selectedKeys),
                    raw_sources: rawSources,
                    delete_all: isAllTotalSelected,
                }),
            });

            const deleted = res.deleted_count ?? 0;
            state.deleteMgmt.isOpen = false;
            state.deleteMgmt.selectedKeys.clear();
            state.deleteMgmt.sources = [];

            await loadOverviewAndVault();
            renderShell();
            showToast(`Deleted ${deleted.toLocaleString()} credentials.`);
        } catch (err) {
            showToast(`Failed to delete credentials: ${err.message}`, true);
            state.deleteMgmt.deleting = false;
            renderDeleteMgmtModal();
        }
    };

    const renderDeleteMgmtModal = () => {
        const container = document.getElementById('cs-modal-container');
        if (!container) return;
        if (!state.deleteMgmt.isOpen) {
            container.innerHTML = '';
            return;
        }

        const q = (state.deleteMgmt.searchQuery || '').trim().toLowerCase();
        const visibleSources = (state.deleteMgmt.sources || []).filter(s => {
            if (!q) return true;
            return (s.display_name || '').toLowerCase().includes(q) ||
                   (s.group_key || '').toLowerCase().includes(q) ||
                   (s.source_type || '').toLowerCase().includes(q);
        });

        const totalSourcesCount = state.deleteMgmt.sources.length;
        const selectedKeys = state.deleteMgmt.selectedKeys;
        const selectedSources = state.deleteMgmt.sources.filter(s => selectedKeys.has(s.group_key));
        const selectedCredCount = selectedSources.reduce((sum, s) => sum + (s.count || 0), 0);
        const isAllVisibleSelected = visibleSources.length > 0 && visibleSources.every(s => selectedKeys.has(s.group_key));

        const getBadgeInfo = (type) => {
            const t = (type || '').toLowerCase();
            if (t === 'upload') return { label: 'UPLOAD', icon: 'fa-file-arrow-up', badgeClass: 'cs-del-badge-upload' };
            if (t === 'telegram') return { label: 'TELEGRAM', icon: 'fa-brands fa-telegram', badgeClass: 'cs-del-badge-tg' };
            return { label: 'LOCAL', icon: 'fa-folder', badgeClass: 'cs-del-badge-local' };
        };

        let bodyHtml = '';
        if (state.deleteMgmt.loading) {
            bodyHtml = `
                <div class="cs-del-loading">
                    <i class="fa-solid fa-circle-notch fa-spin"></i>
                    <span>Analyzing indexed credential sources...</span>
                </div>
            `;
        } else if (visibleSources.length === 0) {
            bodyHtml = `
                <div class="cs-del-empty">
                    <i class="fa-solid fa-folder-open"></i>
                    <p>${q ? 'No sources match your filter.' : 'No indexed sources found in credentials.'}</p>
                </div>
            `;
        } else {
            bodyHtml = `
                <div class="cs-del-source-list">
                    ${visibleSources.map(s => {
                        const isSelected = selectedKeys.has(s.group_key);
                        const b = getBadgeInfo(s.source_type);
                        return `
                            <div class="cs-del-source-item ${isSelected ? 'selected' : ''}" data-group-key="${esc(s.group_key)}">
                                <label class="cs-del-source-label">
                                    <input type="checkbox" class="cs-del-source-cb" data-group-key="${esc(s.group_key)}" ${isSelected ? 'checked' : ''} ${state.deleteMgmt.deleting ? 'disabled' : ''} />
                                    <span class="cs-del-source-badge ${b.badgeClass}">
                                        <i class="${b.icon}"></i> ${b.label}
                                    </span>
                                    <div class="cs-del-source-info">
                                        <span class="cs-del-source-name" title="${esc(s.display_name)}">${esc(s.display_name)}</span>
                                        ${s.group_key !== s.display_name ? `<span class="cs-del-source-sub" title="${esc(s.group_key)}">${esc(s.group_key)}</span>` : ''}
                                    </div>
                                    <div class="cs-del-source-count">
                                        <strong>${s.count.toLocaleString()}</strong> <small>creds</small>
                                    </div>
                                </label>
                            </div>
                        `;
                    }).join('')}
                </div>
            `;
        }

        container.innerHTML = `
            <div class="cs-modal-backdrop" id="cs-del-backdrop">
                <div class="cs-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="cs-del-modal-title">
                    <div class="cs-modal-header">
                        <div class="cs-modal-header-text">
                            <h2 id="cs-del-modal-title">
                                <i class="fa-solid fa-trash-can" style="color: var(--cs-danger);"></i> Delete Management
                            </h2>
                            <p>Select specific sources to permanently delete their indexed credentials, or select all.</p>
                        </div>
                        <button type="button" class="cs-modal-close" id="cs-del-close-btn" aria-label="Close" ${state.deleteMgmt.deleting ? 'disabled' : ''}>&times;</button>
                    </div>

                    <div class="cs-del-toolbar">
                        <label class="cs-del-select-all-label">
                            <input type="checkbox" id="cs-del-select-all" ${isAllVisibleSelected ? 'checked' : ''} ${visibleSources.length === 0 || state.deleteMgmt.deleting ? 'disabled' : ''} />
                            <span>Select All ${visibleSources.length ? `(${visibleSources.length})` : ''}</span>
                        </label>
                        <div class="cs-del-search-wrap">
                            <i class="fa-solid fa-magnifying-glass"></i>
                            <input type="text" id="cs-del-search-input" placeholder="Filter sources by name or type..." value="${esc(state.deleteMgmt.searchQuery)}" ${state.deleteMgmt.deleting ? 'disabled' : ''} />
                            ${state.deleteMgmt.searchQuery ? `<button type="button" id="cs-del-search-clear" title="Clear search">&times;</button>` : ''}
                        </div>
                        <div class="cs-del-summary-pill">
                            Selected: <strong>${selectedSources.length}</strong> of <strong>${totalSourcesCount}</strong> (${selectedCredCount.toLocaleString()} creds)
                        </div>
                    </div>

                    <div class="cs-modal-body">
                        ${bodyHtml}
                    </div>

                    <div class="cs-modal-footer">
                        <div class="cs-del-footer-left">
                            ${selectedKeys.size > 0 && !state.deleteMgmt.deleting ? `
                                <button type="button" id="cs-del-btn-clear-sel" class="cs-btn cs-btn-sm">
                                    <i class="fa-solid fa-xmark"></i> Deselect All
                                </button>
                            ` : ''}
                        </div>
                        <div class="cs-del-footer-actions">
                            <button type="button" id="cs-del-btn-cancel" class="cs-btn cs-btn-sm" ${state.deleteMgmt.deleting ? 'disabled' : ''}>
                                Cancel
                            </button>
                            <button type="button" id="cs-del-btn-confirm" class="cs-btn cs-btn-sm cs-btn-danger"
                                ${selectedKeys.size === 0 || state.deleteMgmt.deleting ? 'disabled' : ''}>
                                ${state.deleteMgmt.deleting
                                    ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Deleting...'
                                    : `<i class="fa-solid fa-trash"></i> Delete Selected (${selectedCredCount.toLocaleString()} creds)`}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    const renderActiveSection = () => {
        const body = document.getElementById('cs-section-body');
        if (!body) return;
        if (state.activeTab === 'vault') {
            const active = document.activeElement;
            const searchFocus = active?.closest('#cs-vault-search') ? active.id : '';
            const selection = searchFocus === 'cs-search-input' ? [active.selectionStart, active.selectionEnd] : null;
            body.innerHTML = renderVaultSection();
            const field = searchFocus && document.getElementById(searchFocus);
            if (field) {
                field.focus({ preventScroll: true });
                if (selection) field.setSelectionRange(...selection);
            }
        }
        else if (state.activeTab === 'overview') {
            body.innerHTML = renderOverviewSection();
            mountOverviewCharts();
        }
        else if (state.activeTab === 'watchlist') body.innerHTML = renderWatchlistSection();
        else if (state.activeTab === 'sources') body.innerHTML = renderSourcesSection();
        else if (state.activeTab === 'studio') body.innerHTML = renderStudioSection();
        else if (state.activeTab === 'jobs') body.innerHTML = renderJobsSection();
    };

    const renderShell = () => {
        const pane = document.getElementById('credential-stealer-pane');
        if (!pane) return;
        const m = state.overview?.metrics || {};
        const s = state.overview?.settings || {};
        const runningJobs = (state.jobsData?.jobs || []).filter(j => j.status === 'running').length;

        pane.innerHTML = `
            <div class="cs-wrap">
                <header class="cs-hero">
                    <div>
                        <div class="cs-eyebrow"><i class="fa-solid fa-key"></i> Credential Intelligence &bull; Harvester &amp; AI Parser</div>
                        <h1>Credential Stealer</h1>
                        <p>Ingest local <code>.txt</code> folders, automate weekly Telegram &amp; cloud-link drops (Pixeldrain, GoFile, MediaFire, Mega), search plaintext credentials, and synthesize custom regex parsers with AI.</p>
                    </div>
                    <div class="cs-hero-actions">
                        <span class="cs-schedule-pill ${s.weekly_enabled ? '' : 'is-paused'}">
                            <span class="cs-dot ${s.weekly_enabled ? '' : 'amber'}"></span>
                            ${s.weekly_enabled ? `Weekly: ${esc(s.weekly_day || 'Sunday')} ${String(s.weekly_hour_utc ?? 2).padStart(2, '0')}:00 UTC` : 'Weekly Schedule Paused'}
                        </span>
                        <button type="button" id="cs-hero-sync-btn" class="cs-btn cs-btn-primary">
                            <i class="fa-solid fa-rotate"></i> Sync All Sources
                        </button>
                    </div>
                </header>

                ${renderToastEl()}

                <section class="cs-kpis">
                    <div class="cs-kpi">
                        <div class="cs-kpi-body">
                            <span class="cs-kpi-label">Indexed Credentials</span>
                            <strong>${(m.total_credentials ?? 0).toLocaleString()}</strong>
                            <span class="cs-kpi-sub">Plaintext vault records</span>
                        </div>
                        <div class="cs-kpi-icon"><i class="fa-solid fa-key"></i></div>
                    </div>
                    <div class="cs-kpi cyan">
                        <div class="cs-kpi-body">
                            <span class="cs-kpi-label">Unique Domains</span>
                            <strong>${(m.unique_domains ?? 0).toLocaleString()}</strong>
                            <span class="cs-kpi-sub">Normalized target hosts</span>
                        </div>
                        <div class="cs-kpi-icon"><i class="fa-solid fa-globe"></i></div>
                    </div>
                    <div class="cs-kpi danger">
                        <div class="cs-kpi-body">
                            <span class="cs-kpi-label">Watchlist Asset Hits</span>
                            <strong>${(m.watchlist_hits ?? 0).toLocaleString()}</strong>
                            <span class="cs-kpi-sub">Monitored domain alerts</span>
                        </div>
                        <div class="cs-kpi-icon"><i class="fa-solid fa-bullseye"></i></div>
                    </div>
                    <div class="cs-kpi purple">
                        <div class="cs-kpi-body">
                            <span class="cs-kpi-label">Active Parsers</span>
                            <strong>${m.active_parsers ?? 0}</strong>
                            <span class="cs-kpi-sub">${m.pending_unparsed ?? 0} unrecognized queued</span>
                        </div>
                        <div class="cs-kpi-icon"><i class="fa-solid fa-wand-magic-sparkles"></i></div>
                    </div>
                    <div class="cs-kpi emerald">
                        <div class="cs-kpi-body">
                            <span class="cs-kpi-label">Active Sources</span>
                            <strong>${(m.local_sources ?? 0) + (m.tg_sources ?? 0)}</strong>
                            <span class="cs-kpi-sub">${m.local_sources ?? 0} local &bull; ${m.tg_sources ?? 0} Telegram</span>
                        </div>
                        <div class="cs-kpi-icon"><i class="fa-solid fa-tower-broadcast"></i></div>
                    </div>
                </section>

                <div class="cs-tabs-wrap">
                    <nav class="cs-tabs" aria-label="Credential Stealer sections">
                        <button type="button" class="cs-tab-btn ${state.activeTab === 'overview' ? 'active' : ''}" data-cs-tab="overview" aria-current="${state.activeTab === 'overview'}">
                            <i class="fa-solid fa-chart-pie"></i> Overview
                        </button>
                        <button type="button" class="cs-tab-btn ${state.activeTab === 'vault' ? 'active' : ''}" data-cs-tab="vault" aria-current="${state.activeTab === 'vault'}">
                            <i class="fa-solid fa-database"></i> Credential Vault
                            <span class="cs-tab-badge">${m.total_credentials ?? 0}</span>
                        </button>
                        <button type="button" class="cs-tab-btn ${state.activeTab === 'watchlist' ? 'active' : ''}" data-cs-tab="watchlist" aria-current="${state.activeTab === 'watchlist'}">
                            <i class="fa-solid fa-bullseye"></i> Watchlist
                            <span class="cs-tab-badge">${state.watchlistData.items.length}</span>
                        </button>
                        <button type="button" class="cs-tab-btn ${state.activeTab === 'sources' ? 'active' : ''}" data-cs-tab="sources" aria-current="${state.activeTab === 'sources'}">
                            <i class="fa-solid fa-tower-broadcast"></i> Sources &amp; Weekly Harvester
                            <span class="cs-tab-badge">${(m.local_sources ?? 0) + (m.tg_sources ?? 0)}</span>
                        </button>
                        <button type="button" class="cs-tab-btn ${state.activeTab === 'studio' ? 'active' : ''}" data-cs-tab="studio" aria-current="${state.activeTab === 'studio'}">
                            <i class="fa-solid fa-robot"></i> AI Parser Studio
                            ${(m.pending_unparsed ?? 0) > 0 ? `<span class="cs-tab-badge alert">${m.pending_unparsed} queued</span>` : `<span class="cs-tab-badge">${m.active_parsers ?? 0}</span>`}
                        </button>
                        <button type="button" class="cs-tab-btn ${state.activeTab === 'jobs' ? 'active' : ''}" data-cs-tab="jobs" aria-current="${state.activeTab === 'jobs'}">
                            <i class="fa-solid fa-list-check"></i> Ingestion Jobs
                            ${runningJobs > 0 ? `<span class="cs-tab-badge alert">${runningJobs} running</span>` : ''}
                        </button>
                    </nav>
                </div>

                <div id="cs-section-body"></div>
            </div>
            <div id="cs-modal-container"></div>
        `;
        renderActiveSection();
        renderDeleteMgmtModal();
    };

    // -----------------------------------------------------------------------
    // Delegated Event Handlers (CSP-safe)
    // -----------------------------------------------------------------------
    const bindPaneEvents = () => {
        const pane = document.getElementById('credential-stealer-pane');
        if (!pane || pane.dataset.csBound === '1') return;
        pane.dataset.csBound = '1';

        pane.addEventListener('click', async (e) => {
            const subTabBtn = e.target.closest('[data-cs-subtab]');
            if (subTabBtn) {
                state.sourcesSub = subTabBtn.dataset.csSubtab;
                renderActiveSection();
                return;
            }

            const tabBtn = e.target.closest('[data-cs-tab]');
            if (tabBtn) {
                state.activeTab = tabBtn.dataset.csTab;
                if (state.activeTab === 'studio') await loadParsers().catch(() => {});
                else if (state.activeTab === 'sources') {
                    await Promise.all([loadSources().catch(() => {}), loadParsers().catch(() => {})]);
                }
                renderShell();
                pane.querySelector('.cs-tab-btn.active')?.focus({ preventScroll: true });
                return;
            }

            const actionEl = e.target.closest('[data-cs-action]');
            if (actionEl) {
                const act = actionEl.dataset.csAction;
                const id = Number(actionEl.dataset.id || 0);
                if (act === 'copy-text') {
                    await copyText(actionEl.dataset.val || '', 'Credential value');
                } else if (act === 'toggle-pw') {
                    if (state.revealedIds.has(id)) state.revealedIds.delete(id);
                    else state.revealedIds.add(id);
                    renderActiveSection();
                } else if (act === 'del-cred') {
                    await api(`/api/credential-stealer/credentials/${id}`, { method: 'DELETE' });
                    await refreshAllData();
                } else if (act === 'del-watchlist') {
                    try {
                        await api(`/api/credential-stealer/watchlist/${id}`, { method: 'DELETE' });
                        await refreshAllData();
                    } catch (err) {
                        showToast(err.message || 'Could not remove the watchlist target.', true);
                    }
                } else if (act === 'scan-local') {
                    const out = await api(`/api/credential-stealer/sources/local/${id}/scan`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ parser_name: state.selectedParser || null }),
                    });
                    showToast(`Started local folder scan (Job ${out.job_id})`);
                    state.activeTab = 'jobs';
                    await loadJobs();
                    renderShell();
                } else if (act === 'del-local') {
                    await api(`/api/credential-stealer/sources/local/${id}`, { method: 'DELETE' });
                    await refreshAllData();
                } else if (act === 'sync-tg') {
                    const out = await api(`/api/credential-stealer/sources/telegram/${id}/sync`, { method: 'POST' });
                    showToast(`Started Telegram channel sync for @${out.channel}`);
                    state.activeTab = 'jobs';
                    await loadJobs();
                    renderShell();
                } else if (act === 'del-tg') {
                    await api(`/api/credential-stealer/sources/telegram/${id}`, { method: 'DELETE' });
                    await refreshAllData();
                } else if (act === 'load-unparsed') {
                    const qitem = (state.parsersData.unparsed_queue || []).find(u => u.id === id);
                    if (qitem) {
                        state.studioDraft.sample_snippet = qitem.sample_snippet || '';
                        state.studioDraft.hint_family = qitem.file_name || '';
                        const sample = document.getElementById('cs-studio-sample');
                        const hint = document.getElementById('cs-studio-hint');
                        if (hint) hint.value = state.studioDraft.hint_family;
                        if (sample) {
                            sample.value = state.studioDraft.sample_snippet;
                            sample.focus();
                            sample.setSelectionRange(0, 0);
                        }
                        const aiReady = Boolean(getAiStatus().available);
                        showToast(`Loaded snippet from ${qitem.file_name}. ${aiReady ? 'Click "Generate Parser with AI Agent".' : 'MANTIS AI is not configured — test a manual regex below or configure MANTIS AI.'}`);
                    }
                } else if (act === 'dismiss-unparsed') {
                    await api(`/api/credential-stealer/unparsed/${id}`, { method: 'DELETE' });
                    await refreshAllData();
                } else if (act === 'del-parser') {
                    await api(`/api/credential-stealer/parsers/${id}`, { method: 'DELETE' });
                    await refreshAllData();
                } else if (act === 'goto-vault') {
                    state.activeTab = 'vault';
                    renderShell();
                } else if (act === 'goto-studio-unparsed') {
                    const qitem = (state.parsersData?.unparsed_queue || [])[0];
                    if (qitem) {
                        state.studioDraft.sample_snippet = qitem.sample_snippet || '';
                        state.studioDraft.hint_family = qitem.file_name || '';
                    }
                    state.activeTab = 'studio';
                    renderShell();
                } else if (act === 'clear-upload-result') {
                    state.lastUploadResult = null;
                    renderActiveSection();
                }
                return;
            }

            const button = e.target.closest('button');
            const btnId = button?.id;

            if (e.target.id === 'cs-del-backdrop' || e.target.id === 'cs-del-close-btn' || btnId === 'cs-del-btn-cancel') {
                closeDeleteMgmtModal();
                return;
            }
            if (btnId === 'cs-del-btn-clear-sel') {
                state.deleteMgmt.selectedKeys.clear();
                renderDeleteMgmtModal();
                return;
            }
            if (btnId === 'cs-del-search-clear') {
                state.deleteMgmt.searchQuery = '';
                renderDeleteMgmtModal();
                document.getElementById('cs-del-search-input')?.focus();
                return;
            }
            if (btnId === 'cs-del-btn-confirm') {
                await handleConfirmDelete();
                return;
            }

            if (!btnId) return;

            try {
                if (btnId === 'cs-hero-sync-btn') {
                    const out = await api('/api/credential-stealer/sync-all', { method: 'POST' });
                    showToast(`Started Full Sync across ${out.local_count} local & ${out.tg_count} Telegram sources.`);
                    state.activeTab = 'jobs';
                    await loadJobs();
                    renderShell();
                } else if (btnId === 'cs-toggle-reveal-all') {
                    state.revealAll = !state.revealAll;
                    renderActiveSection();
                } else if (btnId === 'cs-btn-delete-mgmt') {
                    if (button.disabled) return;
                    await openDeleteMgmtModal();
                } else if (btnId === 'cs-btn-export-csv') {
                    const res = await fetch('/api/credential-stealer/credentials/export', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(state.filters),
                    });
                    const blob = await res.blob();
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'mantis_stealer_credentials.csv';
                    a.click();
                    URL.revokeObjectURL(a.href);
                } else if (btnId === 'cs-page-prev' || btnId === 'cs-page-next') {
                    const direction = btnId === 'cs-page-prev' ? -1 : 1;
                    const offset = Math.max(0, state.filters.offset + direction * state.filters.limit);
                    await applyVaultFilters({ ...state.filters, offset });
                } else if (btnId === 'cs-browse-file-btn' || btnId === 'cs-browse-folder-btn') {
                    if (state.localPickerOpen) return;
                    const kind = btnId === 'cs-browse-file-btn' ? 'file' : 'folder';
                    const setPickerDisabled = (disabled) => {
                        pane.querySelectorAll('#cs-browse-file-btn, #cs-browse-folder-btn').forEach((picker) => {
                            picker.disabled = disabled;
                        });
                    };
                    state.localPickerOpen = true;
                    setPickerDisabled(true);
                    try {
                        const out = await api(`/api/credential-stealer/browse-${kind}`, { method: 'POST' });
                        if (out.error) {
                            showToast(out.error, true);
                        } else if (out.selected && out.path) {
                            const pathInput = document.getElementById('cs-local-path-input');
                            if (pathInput) pathInput.value = out.path;
                            const labelInput = document.getElementById('cs-local-label-input');
                            if (labelInput && !labelInput.value) {
                                labelInput.value = out.path.split(/[\\/]/).filter(Boolean).pop() || '';
                            }
                        }
                    } finally {
                        state.localPickerOpen = false;
                        setPickerDisabled(false);
                    }
                } else if (btnId === 'cs-local-scan-btn') {
                    const folderPath = document.getElementById('cs-local-path-input')?.value || '';
                    const label = document.getElementById('cs-local-label-input')?.value || '';
                    const recursive = !!document.getElementById('cs-local-recursive')?.checked;
                    const autoWeekly = !!document.getElementById('cs-local-weekly')?.checked;
                    const deleteAfterParse = !!document.getElementById('cs-local-delete-after')?.checked;
                    const out = await api('/api/credential-stealer/sources/local', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            folder_path: folderPath,
                            label,
                            recursive,
                            auto_weekly: autoWeekly,
                            delete_after_parse: deleteAfterParse,
                            parser_name: state.selectedParser || null,
                            background: true,
                        }),
                    });
                    showToast(`Scanning '${out.source?.label}' (Job ${out.job_id})${deleteAfterParse ? ' [Auto-Delete enabled]' : ''}`);
                    state.activeTab = 'jobs';
                    await loadJobs();
                    renderShell();
                } else if (btnId === 'cs-upload-files-btn') {
                    const input = document.getElementById('cs-upload-files-input');
                    const files = input?.files?.length ? Array.from(input.files) : (state.selectedUploadFiles || []);
                    if (!files.length) {
                        showToast('Select one or more log or archive files first.', true);
                        return;
                    }
                    const btn = document.getElementById('cs-upload-files-btn');
                    if (btn) {
                        btn.disabled = true;
                        btn.innerHTML = `<i class="fa-solid fa-circle-notch mantis-spin"></i> Parsing ${esc(files[0].name)}...`;
                    }
                    const uploadLock = csLockDuringUpload(files[0].name, files.reduce((n, f) => n + (f.size || 0), 0));
                    try {
                        const fd = new FormData();
                        for (const f of files) fd.append('files', f);
                        if (state.selectedParser) fd.append('parser_name', state.selectedParser);
                        const out = await api('/api/credential-stealer/sources/upload', { method: 'POST', body: fd });
                        state.selectedUploadFiles = [];
                        state.lastUploadResult = out;
                        await refreshAllData();
                        const hasArchiveErrors = (out.file_summaries || []).some(f => f.archive_errors?.length);
                        if (hasArchiveErrors) {
                            showToast(`Parsed ${out.creds_found || 0} credentials. See the upload results for archive errors.`, true);
                        } else if ((out.creds_found || 0) > 0) {
                            showToast(`Parsed ${out.creds_found} credentials (${out.creds_new} new) from uploaded file(s). Click "View Vault" to inspect.`);
                        } else if ((out.unparsed_files || 0) > 0) {
                            const qitem = (state.parsersData?.unparsed_queue || [])[0];
                            if (qitem) {
                                state.studioDraft.sample_snippet = qitem.sample_snippet || '';
                                state.studioDraft.hint_family = qitem.file_name || '';
                            }
                            showToast(`Uploaded file(s) queued for AI Parser Studio (${out.unparsed_files} unrecognized).`, true);
                        } else {
                            showToast('Upload finished, but 0 credential entries were detected (empty or unsupported file).', true);
                        }
                    } finally {
                        uploadLock.release();
                        const b2 = document.getElementById('cs-upload-files-btn');
                        if (b2) {
                            b2.disabled = false;
                            b2.innerHTML = '<i class="fa-solid fa-bolt"></i> Upload &amp; Parse';
                        }
                    }
                } else if (btnId === 'cs-tg-add-btn') {
                    const username = document.getElementById('cs-tg-username')?.value || '';
                    const mode = document.getElementById('cs-tg-mode')?.value || 'all';
                    const maxMsgs = document.getElementById('cs-tg-limit-mode')?.value === 'number'
                        ? Number(document.getElementById('cs-tg-limit')?.value || 50) : 0;
                    await api('/api/credential-stealer/sources/telegram', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, download_mode: mode, max_messages: maxMsgs }),
                    });
                    await refreshAllData();
                    showToast(`Added Telegram channel @${username.replace(/^@/, '')}`);
                } else if (btnId === 'cs-sched-save') {
                    const payload = {
                        weekly_enabled: !!document.getElementById('cs-sched-enabled')?.checked,
                        weekly_day: document.getElementById('cs-sched-day')?.value || 'Sunday',
                        weekly_hour_utc: Number(document.getElementById('cs-sched-hour')?.value || 2),
                        auto_ai_parse: !!document.getElementById('cs-sched-auto-ai')?.checked,
                        ephemeral_delete_archives: !!document.getElementById('cs-sched-ephemeral')?.checked,
                        delete_after_parse: !!document.getElementById('cs-sched-delete-after')?.checked,
                        max_archive_mb: Number(document.getElementById('cs-max-archive-mb')?.value || 250),
                        max_files_per_sync: Number(document.getElementById('cs-max-files-sync')?.value || 200),
                        extra_extensions: document.getElementById('cs-extra-extensions')?.value || '',
                    };
                    await api('/api/credential-stealer/settings', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload),
                    });
                    await refreshAllData();
                    showToast('Weekly Harvester schedule settings saved.');
                } else if (btnId === 'cs-studio-load-demo') {
                    state.studioDraft.sample_snippet =
                        "[LOG ENTRY #1042]\n" +
                        "TargetSite = https://vpn.acme-corp.com/remote/login\n" +
                        "AccountID = alice.morgan@acme-corp.com\n" +
                        "SecretPass = W1nt3r!2026#Sec\n\n" +
                        "[LOG ENTRY #1043]\n" +
                        "TargetSite = https://sso.partner-bank.io/auth\n" +
                        "AccountID = jdoe_ops\n" +
                        "SecretPass = B@nkVault99";
                    state.studioDraft.hint_family = 'CustomKeyVal';
                    renderActiveSection();
                } else if (btnId === 'cs-studio-ai-btn') {
                    const aiStatus = getAiStatus();
                    if (!aiStatus.available) {
                        showToast(aiStatus.reason || 'AI Agent Parser is disabled because no AI is configured in MANTIS AI.', true);
                        return;
                    }
                    const sample = document.getElementById('cs-studio-sample')?.value || '';
                    const hint = document.getElementById('cs-studio-hint')?.value || '';
                    const btn = document.getElementById('cs-studio-ai-btn');
                    if (btn) {
                        btn.disabled = true;
                        btn.innerHTML = '<i class="fa-solid fa-circle-notch mantis-spin"></i> Synthesizing Regex...';
                    }
                    const out = await api('/api/credential-stealer/parsers/ai-generate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ sample_snippet: sample, hint_family: hint }),
                    });
                    state.studioDraft = {
                        sample_snippet: sample,
                        hint_family: hint,
                        name: out.parser?.name || 'AI Custom Parser',
                        stealer_family: out.parser?.stealer_family || 'Custom',
                        mode: out.parser?.mode || 'block_regex',
                        pattern: out.parser?.pattern || '',
                        explanation: out.parser?.explanation || '',
                        test_matches: out.test_matches || [],
                        model: out.model || '',
                        warning: out.warning || '',
                    };
                    renderActiveSection();
                    showToast(`AI Studio synthesized parser matching ${out.match_count} credential(s).`);
                } else if (btnId === 'cs-studio-test-btn') {
                    const sample = document.getElementById('cs-studio-sample')?.value || '';
                    const pattern = document.getElementById('cs-studio-pattern')?.value || '';
                    const mode = document.getElementById('cs-studio-mode')?.value || 'block_regex';
                    const fam = document.getElementById('cs-studio-family')?.value || 'Custom';
                    state.studioDraft.sample_snippet = sample;
                    state.studioDraft.pattern = pattern;
                    state.studioDraft.mode = mode;
                    state.studioDraft.stealer_family = fam;
                    const out = await api('/api/credential-stealer/parsers/test', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ sample_text: sample, pattern, mode, stealer_family: fam }),
                    });
                    state.studioDraft.test_matches = out.matches || [];
                    renderActiveSection();
                    showToast(`Pattern matched ${out.count} row(s).`);
                } else if (btnId === 'cs-studio-save-btn') {
                    const payload = {
                        name: document.getElementById('cs-studio-name')?.value || 'Custom AI Parser',
                        stealer_family: document.getElementById('cs-studio-family')?.value || 'Custom',
                        mode: document.getElementById('cs-studio-mode')?.value || 'block_regex',
                        pattern: document.getElementById('cs-studio-pattern')?.value || '',
                        sample_text: document.getElementById('cs-studio-sample')?.value || '',
                        description: state.studioDraft.explanation || 'Custom AI Parser',
                        reparse_queue: true,
                    };
                    const out = await api('/api/credential-stealer/parsers', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload),
                    });
                    const rep = out.reparse || {};
                    await refreshAllData();
                    showToast(`Saved parser '${out.parser?.name}'. Re-parsed ${rep.files_reparsed || 0} queued files (+${rep.creds_new || 0} new creds).`);
                } else if (btnId === 'cs-unparsed-dismiss-all') {
                    if (!window.confirm('Dismiss all unrecognized files from the queue?')) return;
                    const out = await api('/api/credential-stealer/unparsed', { method: 'DELETE' });
                    await refreshAllData();
                    showToast(`Dismissed ${out.dismissed_count || 0} unrecognized file(s).`);
                } else if (btnId === 'cs-jobs-clear') {
                    if (button.disabled) return;
                    if (!window.confirm('Clear all ingestion and harvester job execution logs?')) return;
                    const out = await api('/api/credential-stealer/jobs', { method: 'DELETE' });
                    state.jobsData = { jobs: [] };
                    renderActiveSection();
                    showToast(`Cleared ${out.deleted_count || 0} job log(s).`);
                } else if (btnId === 'cs-jobs-refresh') {
                    await loadJobs();
                    renderActiveSection();
                }
            } catch (err) {
                showToast(err.message || 'Action failed', true);
                if (state.activeTab === 'studio') renderActiveSection();
            }
        });

        pane.addEventListener('submit', async (e) => {
            if (e.target.id === 'cs-vault-search') {
                e.preventDefault();
                const form = new FormData(e.target);
                state.searchDraft = {
                    q: form.get('q'),
                    family: form.get('family'),
                    source_type: form.get('source_type'),
                    watchlist_only: form.has('watchlist_only'),
                };
                await applyVaultFilters({ ...state.filters, ...state.searchDraft, q: state.searchDraft.q.trim(), offset: 0 });
            } else if (e.target.id === 'cs-watchlist-form') {
                e.preventDefault();
                const form = e.target;
                const button = form.querySelector('[type="submit"]');
                if (button.disabled) return;
                button.disabled = true;
                try {
                    const out = await api('/api/credential-stealer/watchlist', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(Object.fromEntries(new FormData(form))),
                    });
                    form.reset();
                    await refreshAllData();
                    showToast(`Watchlist rule '${out.value}' saved (${out.hits_count} matching hits flagged).`);
                } catch (err) {
                    showToast(err.message || 'Could not save the watchlist target.', true);
                } finally {
                    button.disabled = false;
                }
            }
        });

        pane.addEventListener('input', (e) => {
            if (e.target.id === 'cs-del-search-input') {
                state.deleteMgmt.searchQuery = e.target.value;
                renderDeleteMgmtModal();
                const input = document.getElementById('cs-del-search-input');
                if (input) {
                    input.focus();
                    input.setSelectionRange(input.value.length, input.value.length);
                }
                return;
            }
            const field = e.target;
            if (field.form?.id === 'cs-vault-search' && field.name) {
                state.searchDraft[field.name] = field.type === 'checkbox' ? field.checked : field.value;
            }
        });

        pane.addEventListener('change', async (e) => {
            if (e.target.id === 'cs-tg-limit-mode') {
                const input = pane.querySelector('#cs-tg-limit');
                if (input) input.hidden = e.target.value !== 'number';
                return;
            }
            if (e.target.id === 'cs-del-select-all') {
                const q = (state.deleteMgmt.searchQuery || '').trim().toLowerCase();
                const visibleSources = (state.deleteMgmt.sources || []).filter(s => {
                    if (!q) return true;
                    return (s.display_name || '').toLowerCase().includes(q) ||
                           (s.group_key || '').toLowerCase().includes(q) ||
                           (s.source_type || '').toLowerCase().includes(q);
                });
                const checked = e.target.checked;
                visibleSources.forEach(s => {
                    if (checked) state.deleteMgmt.selectedKeys.add(s.group_key);
                    else state.deleteMgmt.selectedKeys.delete(s.group_key);
                });
                renderDeleteMgmtModal();
                return;
            }
            if (e.target.classList.contains('cs-del-source-cb')) {
                const key = e.target.dataset.groupKey;
                if (key) {
                    if (e.target.checked) state.deleteMgmt.selectedKeys.add(key);
                    else state.deleteMgmt.selectedKeys.delete(key);
                    renderDeleteMgmtModal();
                }
                return;
            }
            if (e.target.id === 'cs-filter-watchlist') {
                state.searchDraft.watchlist_only = e.target.checked;
                await applyVaultFilters({ ...state.filters, ...state.searchDraft, q: (state.searchDraft.q || '').trim(), offset: 0 });
            } else if (e.target.id === 'cs-filter-family' || e.target.id === 'cs-filter-source') {
                state.searchDraft[e.target.name] = e.target.value;
                await applyVaultFilters({ ...state.filters, ...state.searchDraft, q: (state.searchDraft.q || '').trim(), offset: 0 });
            } else if (e.target.id === 'cs-parser-select') {
                state.selectedParser = e.target.value || '';
            } else if (e.target.id === 'cs-upload-files-input') {
                state.selectedUploadFiles = e.target.files?.length ? Array.from(e.target.files) : [];
                state.lastUploadResult = null;
                const label = document.getElementById('cs-upload-file-label');
                if (label) label.textContent = getUploadLabelText();
                const bigFile = state.selectedUploadFiles.find((f) => (f?.size || 0) > 100 * 1024 * 1024);
                if (bigFile) {
                    const gb = (bigFile.size / (1024 * 1024 * 1024)).toFixed(2);
                    showToast(`Large file (${gb} GB) selected. Tip: stream it from disk instead — open Advanced and use File... to scan it in place, avoiding the browser upload.`);
                }
            }
        });

        pane.addEventListener('dragover', (e) => {
            const dz = e.target.closest('#cs-dropzone');
            if (!dz) return;
            e.preventDefault();
            dz.classList.add('is-dragover');
        });
        pane.addEventListener('dragleave', (e) => {
            const dz = e.target.closest('#cs-dropzone');
            if (dz) dz.classList.remove('is-dragover');
        });
        pane.addEventListener('drop', (e) => {
            const dz = e.target.closest('#cs-dropzone');
            if (!dz) return;
            e.preventDefault();
            dz.classList.remove('is-dragover');
            const dropped = Array.from(e.dataTransfer?.files || []);
            if (!dropped.length) return;
            const input = document.getElementById('cs-upload-files-input');
            try {
                const dt = new DataTransfer();
                dropped.forEach(f => dt.items.add(f));
                input.files = dt.files;
            } catch (_) { /* older browsers: fall back to click-to-browse */ }
            state.selectedUploadFiles = dropped;
            state.lastUploadResult = null;
            const label = document.getElementById('cs-upload-file-label');
            if (label) label.textContent = getUploadLabelText();
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && state.deleteMgmt.isOpen && !state.deleteMgmt.deleting) {
                closeDeleteMgmtModal();
            }
        });
    };

    window.openCredentialStealer = async () => {
        bindPaneEvents();
        const pane = document.getElementById('credential-stealer-pane');
        if (!state.initialized && pane) {
            pane.innerHTML = `<div class="cs-empty"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading Credential Stealer Intelligence...</div>`;
        }
        try {
            await refreshAllData();
            state.initialized = true;
        } catch (err) {
            if (pane) pane.innerHTML = `<div class="cs-empty" style="color:#fca5a5;">Failed to load Credential Stealer module: ${esc(err.message)}</div>`;
        }
    };
})();

// Blocks the whole UI while a log/archive upload is parsing: a full-page overlay
// stops navigation, tab switches and clicks, and beforeunload guards reload/close.
// It also polls the ingestion job so the user sees live progress and credential counts.
function csLockDuringUpload(fileName, postedBytes) {
    let overlay = document.getElementById('cs-upload-lock');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'cs-upload-lock';
        overlay.setAttribute('role', 'alertdialog');
        overlay.setAttribute('aria-live', 'polite');
        overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,0.62);display:flex;align-items:center;justify-content:center;cursor:wait;padding:20px;';
        overlay.innerHTML = ''
            + '<div style="background:#131925;border:1px solid #2a3446;border-radius:12px;padding:22px 26px;color:#e2e8f0;width:min(460px,92vw);font-family:inherit;">'
            + '<div style="display:flex;align-items:center;gap:10px;">'
            + '<i class="fa-solid fa-circle-notch mantis-spin" style="color:#fbbf24;"></i>'
            + '<div id="cs-upload-lock-text" style="font-weight:600;font-size:0.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"></div>'
            + '</div>'
            + '<div style="margin-top:14px;height:8px;border-radius:999px;background:rgba(255,255,255,0.08);overflow:hidden;">'
            + '<div id="cs-upload-lock-bar" style="height:100%;width:6%;border-radius:999px;background:linear-gradient(90deg,#fbbf24,#f59e0b);transition:width 0.4s ease;"></div>'
            + '</div>'
            + '<div id="cs-upload-lock-pct" style="margin-top:8px;font:600 0.82rem/1.3 var(--font-mono,monospace);color:#fbbf24;">Uploading...</div>'
            + '<div id="cs-upload-lock-stats" style="margin-top:4px;font-size:0.79rem;color:#94a3b8;"></div>'
            + '<div style="margin-top:10px;font-size:0.78rem;color:#64748b;">Keep this tab open until parsing finishes. The server keeps working — other tabs stay usable.</div>'
            + '</div>';
        document.body.appendChild(overlay);
    }
    window.addEventListener('beforeunload', csUploadUnloadGuard);

    const txtEl = document.getElementById('cs-upload-lock-text');
    const barEl = document.getElementById('cs-upload-lock-bar');
    const pctEl = document.getElementById('cs-upload-lock-pct');
    const statsEl = document.getElementById('cs-upload-lock-stats');
    if (txtEl) txtEl.textContent = `Parsing ${fileName || 'upload'}`;

    // Phase 1: the bytes are still going up to the server.
    const uploadMb = postedBytes ? (postedBytes / (1024 * 1024)) : 0;
    if (pctEl) pctEl.textContent = uploadMb ? `Uploading ${uploadMb.toFixed(0)} MB...` : 'Uploading...';
    if (statsEl) statsEl.textContent = '';

    let jobId = '';
    let last = { pct: null, creds: 0, file: '' };
    const poll = setInterval(async () => {
        try {
            const res = await fetch('/api/credential-stealer/jobs?limit=5');
            if (!res.ok) return;
            const data = await res.json();
            const job = (data.jobs || []).find(j => j.job_type === 'upload' && j.status === 'running');
            if (!job) return;
            const total = Number(job.files_total || 0);
            const done = Number(job.files_processed || 0);
            const pct = total > 0 ? Math.min(99, Math.round((done / total) * 100)) : null;
            last = { pct, creds: Number(job.creds_found || 0), file: job.current_file || '' };
            if (barEl && pct !== null) barEl.style.width = `${Math.max(6, pct)}%`;
            if (pctEl) {
                pctEl.textContent = pct === null
                    ? 'Uploading...'
                    : `Parsing ${pct}%${total ? ` (${done}/${total} MB)` : ''}`;
            }
            if (statsEl) {
                statsEl.textContent = [
                    last.creds ? `${last.creds.toLocaleString()} credentials found` : '',
                    last.file ? last.file : '',
                ].filter(Boolean).join(' • ');
            }
        } catch (_) { /* polling is best-effort */ }
    }, 1500);

    return {
        release() {
            clearInterval(poll);
            const el = document.getElementById('cs-upload-lock');
            if (el) el.style.display = 'none';
            window.removeEventListener('beforeunload', csUploadUnloadGuard);
        },
    };
}

function csUploadUnloadGuard(e) {
    e.preventDefault();
    e.returnValue = '';
    return '';
}
