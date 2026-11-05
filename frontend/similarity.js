(function () {
    const API = window.location.protocol === 'file:' ? 'http://127.0.0.1:9999' : window.location.origin;
    let activeTab = 'similarity-dashboard';
    let entityCache = [];
    let pickerTargetInput = '';
    let currentSettings = {};
    const SIM_CACHE_TTL_MS = 2 * 60 * 1000;
    const simApiCache = new Map();

    const $ = (id) => document.getElementById(id);
    const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
    const shortHash = (value) => value ? `${String(value).slice(0, 12)}...${String(value).slice(-8)}` : '';
    const pct = (value) => `${Math.round(Number(value || 0))}%`;
    const typeLabel = (type) => type === 'threat_actor' ? 'Threat Actor' : 'Malware Family';
    const niceKey = (key) => String(key || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const newProgressId = () => (window.crypto?.randomUUID?.() || `sim-${Date.now()}-${Math.random().toString(16).slice(2)}`);

    function notify(message) {
        if (typeof window.showNotification === 'function') window.showNotification(message);
        else console.log(message);
    }

    async function api(path, options = {}) {
        const res = await fetch(`${API}${path}`, options);
        let data = {};
        try { data = await res.json(); } catch (e) { data = {}; }
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        return data;
    }

    async function apiCached(path, options = {}) {
        const force = !!options.force;
        const cacheKey = path;
        const cached = simApiCache.get(cacheKey);
        if (!force && cached && (Date.now() - cached.at) < SIM_CACHE_TTL_MS) {
            return cached.data;
        }
        const data = await api(path);
        simApiCache.set(cacheKey, { at: Date.now(), data });
        return data;
    }

    function apiCachedValue(path) {
        const cached = simApiCache.get(path);
        if (cached && (Date.now() - cached.at) < SIM_CACHE_TTL_MS) return cached.data;
        return null;
    }

    function refreshSimilarityStatuses(tab, rerender) {
        Promise.all([
            apiCached('/api/similarity/ida/status').catch(() => null),
            apiCached('/api/similarity/hexrays/status').catch(() => null)
        ]).then(() => {
            if (activeTab === tab) rerender({ skipStatusRefresh: true });
        });
    }

    function clearSimilarityCache() {
        simApiCache.clear();
    }

    function setPane(html) {
        const pane = $('similarity-pane');
        if (pane) pane.innerHTML = html;
    }

    function shell(body) {
        const tabs = [
            ['similarity-dashboard', 'Bảng điều khiển', 'fa-chart-line'],
            ['similarity-entities', 'Thực thể', 'fa-layer-group'],
            ['similarity-create', 'Tạo thực thể', 'fa-plus'],
            ['similarity-compare', 'So sánh mẫu', 'fa-scale-balanced'],
            ['similarity-settings', 'Cài đặt', 'fa-sliders']
        ];
        return `
            <div class="similarity-shell">
                <div class="similarity-toolbar">
                    <div class="similarity-tabs">
                        ${tabs.map(([tab, label, icon]) => `
                            <button class="similarity-tab ${tab === activeTab ? 'active' : ''}" data-sim-tab="${tab}">
                                <i class="fa-solid ${icon}"></i>${esc(label)}
                            </button>
                        `).join('')}
                    </div>
                    <button class="btn-secondary" data-sim-refresh><i class="fa-solid fa-rotate-right"></i> Refresh</button>
                </div>
                ${body}
            </div>
        `;
    }

    function loading(label) {
        return shell(`<div class="similarity-loading"><i class="fa-solid fa-circle-notch mantis-spin"></i> ${esc(label)}</div>`);
    }

    function emptyState(icon, text) {
        return `<div class="similarity-empty"><i class="fa-solid ${icon}"></i>${esc(text)}</div>`;
    }

    function sectionTitle(icon, title, right = '') {
        return `<div class="similarity-section-title"><h3><i class="fa-solid ${icon}"></i>${esc(title)}</h3>${right || ''}</div>`;
    }

    function statusChip(status, label) {
        const cls = status === 'success' || status === true ? 'good' : (status === 'failed' || status === false ? 'bad' : 'warn');
        return `<span class="similarity-chip ${cls}">${esc(label || status || 'unknown')}</span>`;
    }

    function table(headers, rows, emptyText, cols) {
        const body = rows && rows.length
            ? rows.join('')
            : `<tr><td colspan="${cols || headers.length}">${emptyState('fa-magnifying-glass-chart', emptyText)}</td></tr>`;
        return `
            <table class="similarity-table">
                <thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
                <tbody>${body}</tbody>
            </table>
        `;
    }

    function statCard(label, value, icon) {
        return `
            <div class="similarity-stat">
                <div class="similarity-stat-value">${esc(value || 0)}</div>
                <div class="similarity-stat-label"><i class="fa-solid ${icon}"></i> ${esc(label)}</div>
            </div>
        `;
    }

    function valueOf(id, fallback = 0) {
        const el = $(id);
        return Number(el?.value || fallback);
    }

    async function renderDashboard(options = {}) {
        setPane(loading('Đang tải tổng quan...'));
        const data = await apiCached('/api/similarity/dashboard', options);
        const ida = apiCachedValue('/api/similarity/ida/status') || { available: false, enabled: false, reason: 'Đang kiểm tra trạng thái IDA...' };
        const hexrays = apiCachedValue('/api/similarity/hexrays/status') || { available: false, enabled: false, reason: 'Đang kiểm tra trạng thái Hex-Rays...' };
        const latestEntities = (data.latest_entities || []).map(e => `
            <tr data-sim-entity="${esc(e.id)}" style="cursor:pointer;">
                <td><button class="provider-title" data-sim-entity="${esc(e.id)}" style="background:none;border:0;color:var(--text-main);cursor:pointer;padding:0;text-align:left;">${esc(e.name)}</button></td>
                <td>${esc(typeLabel(e.type))}</td>
                <td>${esc(e.sample_count || 0)}</td>
                <td>${esc(e.created_at || '')}</td>
            </tr>
        `);
        const latestComparisons = (data.latest_comparisons || []).map(c => `
            <tr data-sim-comparison="${esc(c.id)}" style="cursor:pointer;">
                <td><button class="provider-title" data-sim-comparison="${esc(c.id)}" style="background:none;border:0;color:var(--text-main);cursor:pointer;padding:0;text-align:left;">${esc(c.file_name || shortHash(c.sha256))}</button></td>
                <td>${pct(c.best_score)}</td>
                <td>${esc(c.compared_at || '')}</td>
            </tr>
        `);
        const healthNotes = [
            (!ida.available || !ida.enabled) ? ida.reason : '',
            (hexrays.enabled && !hexrays.available && hexrays.status !== 'configured') ? hexrays.reason : ''
        ].filter(Boolean).join(' ');
        setPane(shell(`
            <div class="similarity-headline">
                <div>
                    <h3>Tổng quan độ tương đồng</h3>
                    <p>Hồ sơ thực thể cục bộ, lịch sử so sánh và tình trạng bộ trích xuất.</p>
                </div>
                <button class="btn-primary" data-sim-go="similarity-compare"><i class="fa-solid fa-scale-balanced"></i> Compare Sample</button>
            </div>
            <div class="similarity-grid">
                ${statCard('Entities', data.total_entities, 'fa-layer-group')}
                ${statCard('Mẫu đã xử lý', data.total_processed_samples, 'fa-microchip')}
                ${statCard('Họ Mã độc', data.malware_entities, 'fa-bug')}
                ${statCard('Tác nhân đe dọa', data.threat_actor_entities, 'fa-user-secret')}
            </div>
            <div class="similarity-two-col">
                <div class="similarity-panel">
                    ${sectionTitle('fa-clock-rotate-left', 'Thực thể gần nhất')}
                    ${table(['Name', 'Type', 'Samples', 'Created'], latestEntities, 'Chưa có thực thể.')}
                </div>
                <div class="similarity-panel">
                    ${sectionTitle('fa-list-check', 'So sánh gần nhất')}
                    ${table(['Sample', 'Best Score', 'Compared'], latestComparisons, 'Chưa có lịch sử so sánh.')}
                </div>
            </div>
            <div class="similarity-panel">
                ${sectionTitle('fa-heart-pulse', 'Tình trạng xử lý tính năng')}
                <div class="similarity-toggle-row">
                    <span class="similarity-chip ${ida.available ? 'good' : (ida.enabled ? 'bad' : 'warn')}">
                        <i class="fa-solid fa-microchip"></i> IDA code analysis - ${ida.available ? 'available' : (ida.enabled ? 'unavailable' : 'disabled')}
                    </span>
                    <span class="similarity-chip ${hexrays.available ? 'good' : (hexrays.enabled ? 'warn' : '')}">
                        <i class="fa-solid fa-code-branch"></i> Hex-Rays semantic - ${hexrays.available ? 'available' : (hexrays.enabled ? hexrays.status : 'disabled')}
                    </span>
                    ${(data.extractor_health || []).map(r => `
                        <span class="similarity-chip ${r.status === 'success' ? 'good' : (r.status === 'failed' ? 'bad' : 'warn')}" title="${esc((r.detail || '') + ((r.errors || []).length ? ' | ' + (r.errors || []).map(e => `${e.status}: ${e.error} (${e.count})`).join('; ') : ''))}">
                            ${esc(r.extractor)} - ${esc(r.status)} - ${esc(r.count)}
                        </span>
                    `).join('') || '<span class="similarity-chip">No samples processed</span>'}
                </div>
                ${healthNotes ? `<div class="similarity-subtext" style="margin-top:10px;">${esc(healthNotes)}</div>` : ''}
            </div>
        `));
        if (!options.skipStatusRefresh && (!apiCachedValue('/api/similarity/ida/status') || !apiCachedValue('/api/similarity/hexrays/status'))) {
            refreshSimilarityStatuses('similarity-dashboard', renderDashboard);
        }
    }

    async function renderEntities(options = {}) {
        setPane(loading('Đang tải thực thể...'));
        const data = await apiCached('/api/similarity/entities', options);
        entityCache = data.entities || [];
        const rows = entityCache.map(e => `
            <tr>
                <td><button class="provider-title" data-sim-entity="${esc(e.id)}" style="background:none;border:0;color:var(--text-main);cursor:pointer;padding:0;text-align:left;">${esc(e.name)}</button></td>
                <td>${esc(typeLabel(e.type))}</td>
                <td>${esc(e.sample_count || 0)}</td>
                <td>${esc(e.updated_at || '')}</td>
                <td><button class="btn-secondary" data-sim-delete="${esc(e.id)}" title="Xóa thực thể" style="padding:6px 9px;"><i class="fa-solid fa-trash-can"></i></button></td>
            </tr>
        `);
        setPane(shell(`
            <div class="similarity-headline">
                <div>
                    <h3>Tất cả thực thể</h3>
                    <p>${esc(String(entityCache.length))} local profiles available for matching.</p>
                </div>
                <button class="btn-primary" data-sim-go="similarity-create"><i class="fa-solid fa-plus"></i> Create Entity</button>
            </div>
            <div class="similarity-panel">
                ${table(['Name', 'Type', 'Samples', 'Updated', ''], rows, 'Chưa tạo thực thể nào.', 5)}
            </div>
        `));
    }

    async function renderEntityDetail(id) {
        setPane(loading('Đang tải hồ sơ thực thể...'));
        const data = await api(`/api/similarity/entities/${encodeURIComponent(id)}`);
        const e = data.entity || {};
        const stringRows = (data.strings || []).map(s => `
            <tr><td class="similarity-code">${esc(s.normalized_string)}</td><td>${esc(s.category)}</td><td>${pct((s.prevalence || 0) * 100)}</td><td>${Number(s.rarity_weight || 0).toFixed(2)}</td></tr>
        `);
        const importRows = (data.imports || []).map(i => `
            <tr><td class="similarity-code">${esc(i.normalized_import)}</td><td>${pct((i.prevalence || 0) * 100)}</td></tr>
        `);
        const sampleRows = (data.samples || []).map(s => `
            <tr><td class="similarity-code">${esc(shortHash(s.sha256))}</td><td>${esc(s.file_name)}</td><td>${esc(s.file_type)} ${esc(s.architecture || '')}</td><td>${esc(s.processed_at)}</td></tr>
        `);
        const fuzzyRows = (data.fuzzy_hashes || []).slice(0, 40).flatMap(x => {
            const rows = [];
            const tlshText = x.tlsh || `${x.tlsh_status || 'not_present'}${x.tlsh_error ? ` - ${x.tlsh_error}` : ''}`;
            const ssdeepText = x.ssdeep || `${x.ssdeep_status || 'not_present'}${x.ssdeep_error ? ` - ${x.ssdeep_error}` : ''}`;
            rows.push(`<tr><td>TLSH</td><td class="similarity-code">${esc(tlshText)}</td><td>${esc(x.file_name || '')}</td></tr>`);
            rows.push(`<tr><td>ssdeep</td><td class="similarity-code">${esc(ssdeepText)}</td><td>${esc(x.file_name || '')}</td></tr>`);
            return rows;
        });
        const fingerprintRows = [
            ...(data.imphashes || []).map(x => `<tr><td>imphash</td><td class="similarity-code">${esc(x.imphash)}</td><td>${pct((x.prevalence || 0) * 100)}</td></tr>`),
            ...(data.rich_hashes || []).map(x => `<tr><td>Rich</td><td class="similarity-code">${esc(shortHash(x.rich_hash))}</td><td>${pct((x.prevalence || 0) * 100)}</td></tr>`),
            ...fuzzyRows
        ];
        const codeStatusRows = (data.code_profiles || []).map(p => `
            <tr>
                <td>${esc(p.file_name || '')}</td>
                <td>${statusChip(p.status || 'not_run', p.status || 'not_run')}</td>
                <td>${esc(p.meaningful_function_count || 0)} / ${esc(p.function_count || 0)}</td>
                <td class="similarity-code">${esc(p.reason || (p.status ? '' : 'Phân tích code IDA không chạy cho mẫu này.'))}</td>
            </tr>
        `);
        const codeStatusTable = codeStatusRows.length
            ? `<div style="margin-top:14px;">${table(['Sample', 'IDA Status', 'Meaningful / Total Functions', 'Reason'], codeStatusRows, 'Chưa ghi nhận lần trích xuất code nào.')}</div>`
            : '';
        setPane(shell(`
            <div class="similarity-headline">
                <div>
                    <h3>${esc(e.name)}</h3>
                    <p>${esc(typeLabel(e.type))} - ${esc(data.samples?.length || 0)} samples - Created ${esc(e.created_at || '')}</p>
                </div>
                <div class="similarity-action-row" style="margin-top:0;">
                    <button class="btn-secondary" data-sim-go="similarity-entities"><i class="fa-solid fa-arrow-left"></i> Back</button>
                </div>
            </div>
            ${e.type === 'threat_actor' ? '<div class="provider-note"><i class="fa-solid fa-triangle-exclamation"></i> Actor matches are potential relationships only. Malware similarity is not attribution.</div>' : ''}
            <div class="similarity-panel"><div class="similarity-subtext">${esc(e.description || 'Chưa cung cấp mô tả.')}</div></div>
            <div class="similarity-two-col">
                <div class="similarity-panel">
                    ${sectionTitle('fa-pen-to-square', 'Sửa thực thể')}
                    <form class="similarity-form" id="similarity-edit-entity-form" data-entity-id="${esc(e.id)}">
                        <div class="similarity-form-grid">
                            <div class="similarity-field">
                                <label for="sim-edit-name">Entity Name</label>
                                <input id="sim-edit-name" value="${esc(e.name || '')}" required>
                            </div>
                            <div class="similarity-field">
                                <label for="sim-edit-type">Entity Type</label>
                                <select id="sim-edit-type">
                                    <option value="malware" ${e.type === 'malware' ? 'selected' : ''}>Malware Family</option>
                                    <option value="threat_actor" ${e.type === 'threat_actor' ? 'selected' : ''}>Threat Actor</option>
                                </select>
                            </div>
                        </div>
                        <div class="similarity-field" style="margin-top:12px;">
                            <label for="sim-edit-description">Description</label>
                            <textarea id="sim-edit-description">${esc(e.description || '')}</textarea>
                        </div>
                        <div class="similarity-action-row">
                            <button class="btn-primary" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save Entity</button>
                            <span id="sim-edit-status" class="similarity-subtext"></span>
                        </div>
                    </form>
                </div>
                <div class="similarity-panel">
                    ${sectionTitle('fa-file-circle-plus', 'Thêm mẫu')}
                    <form class="similarity-form" id="similarity-add-samples-form" data-entity-id="${esc(e.id)}">
                        <div class="similarity-file">
                            <div class="similarity-field">
                                <label for="sim-add-sample-files">Samples</label>
                                <input id="sim-add-sample-files" name="files" type="file" multiple required>
                            </div>
                        </div>
                        <div class="similarity-action-row">
                            <button class="btn-primary" type="submit"><i class="fa-solid fa-plus"></i> Add Samples</button>
                            <span id="sim-add-samples-status" class="similarity-subtext"></span>
                        </div>
                        <div id="sim-add-samples-progress"></div>
                    </form>
                </div>
            </div>
            <div class="similarity-two-col">
                <div class="similarity-panel">${sectionTitle('fa-quote-left', 'Chuỗi quan trọng')}${table(['String', 'Category', 'Prevalence', 'Rarity'], stringRows, 'Chưa lưu chuỗi quan trọng.')}</div>
                <div class="similarity-panel">${sectionTitle('fa-file-import', 'Imports')}${table(['Import', 'Prevalence'], importRows, 'Chưa lưu import.')}</div>
            </div>
            <div class="similarity-two-col">
                <div class="similarity-panel">${sectionTitle('fa-vial', 'Mẫu')}${table(['SHA256', 'Name', 'Type', 'Processed'], sampleRows, 'Chưa lưu mẫu.')}</div>
                <div class="similarity-panel">${sectionTitle('fa-fingerprint', 'Dấu vân tay')}${table(['Feature', 'Value', 'Prevalence'], fingerprintRows, 'Chưa lưu dấu vân tay.')}</div>
            </div>
            <div class="similarity-panel">
                ${sectionTitle('fa-diagram-project', 'Hồ sơ Code')}
                ${data.code_summary && data.code_summary.sample_count ? `
                    <div class="similarity-grid">
                        ${statCard('Mẫu Code', data.code_summary.sample_count, 'fa-microchip')}
                        ${statCard('Functions', data.code_summary.function_count, 'fa-code')}
                        ${statCard('Hàm duy nhất', data.code_summary.unique_function_count, 'fa-fingerprint')}
                        ${statCard('Mẫu API', data.code_summary.api_pattern_count, 'fa-plug')}
                    </div>
                ` : emptyState('fa-code', 'No IDA-derived code features stored for this entity. Check the per-sample IDA status below for the reason.')}
                ${codeStatusTable}
            </div>
        `));
        $('similarity-edit-entity-form')?.addEventListener('submit', saveEntityEdit);
        $('similarity-add-samples-form')?.addEventListener('submit', addEntitySamples);
    }

    function renderCreate() {
        setPane(shell(`
            <div class="similarity-headline">
                <div>
                    <h3>Tạo thực thể</h3>
                    <p>Thêm hồ sơ họ mã độc hoặc tác nhân đe dọa từ file mẫu cục bộ.</p>
                </div>
            </div>
            <form class="similarity-form" id="similarity-create-form">
                <div class="similarity-form-grid">
                    <div class="similarity-field">
                        <label for="sim-entity-name">Entity Name</label>
                        <input id="sim-entity-name" name="name" required placeholder="DarkGate">
                    </div>
                    <div class="similarity-field">
                        <label for="sim-entity-type">Entity Type</label>
                        <select id="sim-entity-type" name="entity_type">
                            <option value="malware">Malware Family</option>
                            <option value="threat_actor">Threat Actor</option>
                        </select>
                    </div>
                </div>
                <div class="similarity-field" style="margin-top:12px;">
                    <label for="sim-entity-description">Description</label>
                    <textarea id="sim-entity-description" name="description" placeholder="Ngữ cảnh phân tích tùy chọn"></textarea>
                </div>
                <div class="similarity-file" style="margin-top:12px;">
                    <div class="similarity-field">
                        <label for="sim-entity-files">Samples</label>
                        <input id="sim-entity-files" name="files" type="file" multiple required>
                    </div>
                </div>
                <div class="similarity-action-row">
                    <button class="btn-primary" type="submit"><i class="fa-solid fa-plus"></i> Create Entity</button>
                    <span id="sim-create-status" class="similarity-subtext"></span>
                </div>
                <div id="sim-create-progress"></div>
            </form>
        `));
        $('similarity-create-form')?.addEventListener('submit', createEntity);
    }

    const sampleProcessingSteps = [
        ['upload', 'fa-upload', 'Staging uploaded samples'],
        ['hashes', 'fa-fingerprint', 'Calculating MD5, SHA1, and SHA256'],
        ['fuzzy', 'fa-wave-square', 'Generating TLSH and ssdeep fuzzy hashes'],
        ['pe', 'fa-file-code', 'Parsing PE metadata, imports, Rich header, and icon'],
        ['strings', 'fa-quote-left', 'Extracting and scoring strings'],
        ['ida', 'fa-microchip', 'Running IDA code feature analysis when enabled'],
        ['semantic', 'fa-code-branch', 'Running Hex-Rays semantic analysis when enabled'],
        ['database', 'fa-database', 'Finalizing database writes and entity profile']
    ];

    const compareProcessingSteps = [
        ...sampleProcessingSteps.slice(0, -1),
        ['scoring', 'fa-scale-balanced', 'Scoring against stored entity profiles']
    ];

    function startSampleProcessingProgress(host, sampleCount, steps = sampleProcessingSteps, progressId = '') {
        if (!host) return { stop() {} };
        let progressData = { status: 'running', events: [] };
        let index = 0;
        const startedAt = Date.now();
        const phaseIndex = new Map(steps.map(([phase], i) => [phase, i]));
        const fetchProgress = async () => {
            if (!progressId) return;
            try {
                progressData = await api(`/api/similarity/progress/${encodeURIComponent(progressId)}`);
                const events = progressData.events || [];
                const latest = [...events].reverse().find(ev => phaseIndex.has(ev.phase));
                if (latest) index = Math.max(index, phaseIndex.get(latest.phase));
                render(progressData.status === 'done', progressData.status === 'failed');
            } catch (e) {
                // Keep the visible timer running if the progress endpoint is briefly unavailable.
            }
        };
        const renderLog = () => {
            const events = (progressData.events || []).slice(-18).reverse();
            if (!events.length) {
                return '<div class="similarity-progress-log-empty">Waiting for backend phase logs...</div>';
            }
            return `
                <div class="similarity-progress-log">
                    <div class="similarity-progress-log-title"><i class="fa-solid fa-list-ul"></i> Backend processing log</div>
                    ${events.map(ev => `
                        <div class="similarity-progress-log-row ${esc(ev.status || 'running')}">
                            <span class="similarity-progress-log-time">+${esc(ev.elapsed ?? 0)}s</span>
                            <span class="similarity-progress-log-phase">${esc(niceKey(ev.phase))}</span>
                            <span class="similarity-progress-log-message">${ev.sample ? `<b>${esc(ev.sample)}</b> - ` : ''}${esc(ev.message || '')}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        };
        const render = (done = false, failed = false) => {
            const active = done ? steps.length : index;
            const elapsed = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
            const onFinalStep = !done && !failed && active >= steps.length - 1;
            host.innerHTML = `
                <div class="similarity-progress">
                    <div class="similarity-progress-head">
                        <span>${failed ? 'Đã dừng xử lý' : (done ? 'Xử lý hoàn tất' : `Processing ${sampleCount} sample${sampleCount === 1 ? '' : 's'} - ${elapsed}s elapsed`)}</span>
                        ${done || failed ? '' : '<i class="fa-solid fa-circle-notch mantis-spin"></i>'}
                    </div>
                    ${onFinalStep ? '<div class="similarity-progress-note">Still running on the backend. Large samples, IDA code analysis, or Hex-Rays semantic analysis can take a while; the result will appear when the request completes.</div>' : ''}
                    <div class="similarity-progress-grid">
                        ${steps.map(([phase, icon, label], i) => {
                            const phaseEvents = (progressData.events || []).filter(ev => ev.phase === phase);
                            const hasFailed = phaseEvents.some(ev => ev.status === 'failed');
                            const hasDone = phaseEvents.some(ev => ev.status === 'done' || ev.status === 'skipped');
                            const state = failed && i >= active ? 'pending' : (i < active || done ? 'done' : (i === active ? 'active' : 'pending'));
                            const realState = hasFailed ? 'failed' : (hasDone ? 'done' : state);
                            return `
                                <div class="similarity-progress-step ${realState}">
                                    <i class="fa-solid ${icon}"></i>
                                    <span>${esc(label)}</span>
                                </div>
                            `;
                        }).join('')}
                    </div>
                    ${renderLog()}
                </div>
            `;
        };
        render();
        fetchProgress();
        const timer = setInterval(() => {
            index = Math.min(index + 1, steps.length - 1);
            render();
        }, 1800);
        const poller = setInterval(fetchProgress, 1000);
        return {
            stop(done = true) {
                clearInterval(timer);
                clearInterval(poller);
                fetchProgress().finally(() => render(done, !done));
            }
        };
    }

    async function createEntity(e) {
        e.preventDefault();
        const form = e.currentTarget;
        const status = $('sim-create-status');
        const progressHost = $('sim-create-progress');
        const data = new FormData();
        data.append('name', $('sim-entity-name').value.trim());
        data.append('entity_type', $('sim-entity-type').value);
        data.append('description', $('sim-entity-description').value.trim());
        const progressId = newProgressId();
        data.append('progress_id', progressId);
        for (const file of $('sim-entity-files').files || []) data.append('files', file);
        if (!data.get('name') || !$('sim-entity-files').files.length) return;
        form.querySelector('button[type="submit"]').disabled = true;
        const progress = startSampleProcessingProgress(progressHost, $('sim-entity-files').files.length, sampleProcessingSteps, progressId);
        if (status) status.textContent = 'Đang xử lý pipeline tính năng cục bộ...';
        try {
            const out = await api('/api/similarity/entities', { method: 'POST', body: data });
            progress.stop(true);
            clearSimilarityCache();
            notify('Đã tạo thực thể tương đồng');
            await renderEntityDetail(out.entity_id);
        } catch (err) {
            progress.stop(false);
            if (status) status.textContent = err.message;
        } finally {
            form.querySelector('button[type="submit"]').disabled = false;
        }
    }

    async function saveEntityEdit(e) {
        e.preventDefault();
        const form = e.currentTarget;
        const entityId = form.dataset.entityId;
        const status = $('sim-edit-status');
        const button = form.querySelector('button[type="submit"]');
        const payload = {
            name: $('sim-edit-name')?.value.trim() || '',
            entity_type: $('sim-edit-type')?.value || 'malware',
            description: $('sim-edit-description')?.value.trim() || ''
        };
        if (!entityId || !payload.name) return;
        if (button) button.disabled = true;
        if (status) status.textContent = 'Đang lưu thực thể...';
        try {
            await api(`/api/similarity/entities/${encodeURIComponent(entityId)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            clearSimilarityCache();
            notify('Đã cập nhật thực thể tương đồng');
            if (status) status.textContent = 'Đã lưu';
            await renderEntityDetail(entityId);
        } catch (err) {
            if (status) status.textContent = err.message;
        } finally {
            if (button) button.disabled = false;
        }
    }

    async function addEntitySamples(e) {
        e.preventDefault();
        const form = e.currentTarget;
        const entityId = form.dataset.entityId;
        const files = $('sim-add-sample-files')?.files || [];
        const status = $('sim-add-samples-status');
        const progressHost = $('sim-add-samples-progress');
        const button = form.querySelector('button[type="submit"]');
        if (!entityId || !files.length) return;
        const progressId = newProgressId();
        const data = new FormData();
        data.append('progress_id', progressId);
        for (const file of files) data.append('files', file);
        if (button) button.disabled = true;
        const progress = startSampleProcessingProgress(progressHost, files.length, sampleProcessingSteps, progressId);
        if (status) status.textContent = 'Đang thêm mẫu vào thực thể...';
        try {
            const out = await api(`/api/similarity/entities/${encodeURIComponent(entityId)}/samples`, { method: 'POST', body: data });
            progress.stop(true);
            clearSimilarityCache();
            notify(`${out.processed?.length || 0} sample${(out.processed?.length || 0) === 1 ? '' : 's'} added`);
            await renderEntityDetail(entityId);
        } catch (err) {
            progress.stop(false);
            if (status) status.textContent = err.message;
        } finally {
            if (button) button.disabled = false;
        }
    }

    function renderCompare() {
        setPane(shell(`
            <div class="similarity-headline">
                <div>
                    <h3>So sánh mẫu không xác định</h3>
                    <p>Chấm điểm một mẫu cục bộ so với các thực thể đã lưu.</p>
                </div>
            </div>
            <form class="similarity-form" id="similarity-compare-form">
                <div class="similarity-file">
                    <div class="similarity-field">
                        <label for="sim-compare-file">Sample</label>
                        <input id="sim-compare-file" name="files" type="file" required>
                    </div>
                </div>
                <div class="similarity-action-row">
                    <button class="btn-primary" type="submit"><i class="fa-solid fa-scale-balanced"></i> Compare Sample</button>
                    <span id="sim-compare-status" class="similarity-subtext"></span>
                </div>
            </form>
            <div id="sim-compare-progress"></div>
            <div id="sim-compare-results"></div>
        `));
        $('similarity-compare-form')?.addEventListener('submit', compareSample);
    }

    async function compareSample(e) {
        e.preventDefault();
        const form = e.currentTarget;
        const status = $('sim-compare-status');
        const progressHost = $('sim-compare-progress');
        const resultBox = $('sim-compare-results');
        const data = new FormData();
        const file = $('sim-compare-file').files?.[0];
        if (!file) return;
        const progressId = newProgressId();
        data.append('progress_id', progressId);
        data.append('files', file);
        form.querySelector('button[type="submit"]').disabled = true;
        const progress = startSampleProcessingProgress(progressHost, 1, compareProcessingSteps, progressId);
        if (status) status.textContent = 'Đang trích xuất đặc trưng và tính điểm...';
        if (resultBox) resultBox.innerHTML = '';
        try {
            const out = await api('/api/similarity/compare', { method: 'POST', body: data });
            progress.stop(true);
            clearSimilarityCache();
            if (status) status.textContent = `SHA256 ${out.sha256}`;
            if (resultBox) resultBox.innerHTML = renderCompareResults(out);
        } catch (err) {
            progress.stop(false);
            if (status) status.textContent = err.message;
        } finally {
            form.querySelector('button[type="submit"]').disabled = false;
        }
    }

    async function renderSavedComparison(id) {
        activeTab = 'similarity-compare';
        setPane(loading('Đang tải so sánh đã lưu...'));
        const out = await api(`/api/similarity/comparisons/${encodeURIComponent(id)}`);
        setPane(shell(`
            <div class="similarity-headline">
                <div>
                    <h3>So sánh đã lưu</h3>
                    <p>${esc(out.file_name || shortHash(out.sha256))} - ${esc(out.compared_at || '')}</p>
                </div>
                <button class="btn-secondary" data-sim-go="similarity-dashboard"><i class="fa-solid fa-arrow-left"></i> Dashboard</button>
            </div>
            ${renderCompareResults(out)}
        `));
    }

    function renderCompareResults(out) {
        const statuses = (out.extractor_status || []).map(s => statusChip(s.status, s.extractor)).join(' ');
        const matches = out.matches || [];
        const candidates = out.candidate_matches || [];
        const belowOnly = !matches.length && candidates.length;
        const resultRows = matches.length
            ? matches.map((m, i) => renderMatch(m, i)).join('')
            : (belowOnly
                ? `
                    <div class="provider-note" style="margin-top:14px;">
                        <i class="fa-solid fa-circle-info"></i>
                        No entity crossed the ${pct(out.minimum_match_score || 0)} threshold. Showing scored candidates below the threshold.
                    </div>
                    ${candidates.map((m, i) => renderMatch(m, i, true, out.minimum_match_score)).join('')}
                `
                : emptyState('fa-circle-nodes', 'No entity candidates were available to score.'));
        return `
            <div class="similarity-panel" style="margin-top:14px;">
                ${sectionTitle('fa-file-shield', 'Mẫu không xác định')}
                ${out.saved_comparison_id ? `<div class="similarity-subtext" style="margin-bottom:8px;">Saved comparison #${esc(out.saved_comparison_id)} from ${esc(out.compared_at || '')}</div>` : ''}
                <div class="similarity-code">${esc(out.file_name)} - ${esc(out.file_type)} ${esc(out.architecture || '')}</div>
                <div class="similarity-code" style="margin-top:6px;">SHA256 ${esc(out.sha256)}</div>
                <div class="similarity-toggle-row" style="margin-top:12px;">${statuses}</div>
            </div>
            ${resultRows}
        `;
    }

    function renderMatch(m, index, belowThreshold = false, threshold = 0) {
        const featureOrder = ['semantic_code', 'code', 'strings', 'tlsh', 'imports', 'imphash', 'icon', 'rich', 'ssdeep'];
        const bars = featureOrder.map(k => {
            const f = m.features?.[k] || {};
            const weight = Number(m.normalized_weights?.[k] || 0);
            const contribution = f.available ? (Number(f.score || 0) * weight / 100) : 0;
            return `
                <div class="similarity-bar">
                    <span>${esc(niceKey(k))}${weight ? ` (${pct(weight)})` : ''}</span>
                    <div class="similarity-bar-track"><div class="similarity-bar-fill" style="width:${Math.max(0, Math.min(100, Number(f.score || 0)))}%;"></div></div>
                    <span>${f.available ? `${pct(f.score)} / +${contribution.toFixed(1)}` : 'n/a'}</span>
                </div>
            `;
        }).join('');
        const matchedStrings = m.features?.strings?.evidence || [];
        const matchedImports = m.features?.imports?.evidence || [];
        const codeEvidence = m.features?.code?.evidence || {};
        const semanticEvidence = m.features?.semantic_code?.evidence || {};
        const codeComponents = codeEvidence.component_scores || {};
        const semanticComponents = semanticEvidence.component_scores || {};
        return `
            <div class="similarity-match">
                <div class="similarity-match-head">
                    <div>
                        <h3 style="margin:0 0 7px;">${index + 1}. ${esc(m.entity_name)}</h3>
                        <div class="similarity-toggle-row">
                            <span class="similarity-chip">${esc(typeLabel(m.entity_type))}</span>
                            <span class="similarity-chip ${m.confidence === 'HIGH' ? 'good' : (m.confidence === 'LOW' ? 'warn' : '')}">${esc(m.confidence)} confidence</span>
                            <span class="similarity-chip">${esc(m.similarity_label)}</span>
                            ${belowThreshold ? `<span class="similarity-chip warn">below ${pct(threshold || 0)} threshold</span>` : ''}
                        </div>
                    </div>
                    <div class="similarity-score">${pct(m.score)}</div>
                </div>
                <div class="similarity-subtext" style="margin:8px 0 10px;">Feature score / weighted contribution. Contributions add up to the final similarity score.</div>
                <div class="similarity-bars">${bars}</div>
                <div class="provider-note" style="margin-top:12px;"><i class="fa-solid fa-circle-info"></i> ${esc(m.reason || '')}</div>
                <div class="similarity-two-col" style="margin-top:12px;">
                    <div>
                        ${sectionTitle('fa-quote-left', 'Chuỗi khớp')}
                        <div>${matchedStrings.slice(0, 12).map(s => `<div class="similarity-code">match ${esc(s)}</div>`).join('') || '<span class="similarity-chip">none</span>'}</div>
                    </div>
                    <div>
                        ${sectionTitle('fa-file-import', 'Import khớp')}
                        <div>${matchedImports.slice(0, 12).map(s => `<div class="similarity-code">match ${esc(s)}</div>`).join('') || '<span class="similarity-chip">none</span>'}</div>
                    </div>
                </div>
                ${m.features?.code?.available ? `
                    <div style="margin-top:12px;">
                        ${sectionTitle('fa-code', 'Bằng chứng Code')}
                        <div class="similarity-toggle-row" style="margin-bottom:8px;">
                            <span class="similarity-chip">functions ${esc(codeEvidence.functions_matched || 0)} / ${esc(codeEvidence.meaningful_functions || 0)}</span>
                            <span class="similarity-chip">coverage ${pct(codeEvidence.coverage || 0)}</span>
                            ${Object.entries(codeComponents).map(([k, v]) => `<span class="similarity-chip">${esc(niceKey(k))} ${v == null ? 'n/a' : pct(v)}</span>`).join('')}
                        </div>
                        <div>${(codeEvidence.matched_functions || []).slice(0, 8).map(f => `<div class="similarity-code">${esc(f.ida_address || '')} ${esc(shortHash(f.normalized_hash || ''))} ${esc(f.instruction_count || 0)} insn</div>`).join('') || '<span class="similarity-chip">no exact normalized-function matches</span>'}</div>
                    </div>
                ` : ''}
                ${m.features?.semantic_code?.available ? `
                    <div style="margin-top:12px;">
                        ${sectionTitle('fa-code-branch', 'Bằng chứng ngữ nghĩa')}
                        <div class="similarity-toggle-row" style="margin-bottom:8px;">
                            <span class="similarity-chip">semantic functions ${esc(semanticEvidence.semantic_functions_matched || 0)} / ${esc(semanticEvidence.semantic_functions || 0)}</span>
                            <span class="similarity-chip">coverage ${pct(semanticEvidence.semantic_coverage || 0)}</span>
                            ${semanticEvidence.shared_component ? '<span class="similarity-chip warn">shared component</span>' : ''}
                            ${Object.entries(semanticComponents).map(([k, v]) => `<span class="similarity-chip">${esc(niceKey(k))} ${v == null ? 'n/a' : pct(v)}</span>`).join('')}
                        </div>
                        <div>${(semanticEvidence.matched_functions || []).slice(0, 8).map(f => `<div class="similarity-code">${esc(f.ida_address || '')} ${esc(shortHash(f.semantic_fingerprint || ''))} ${esc(f.match_type || '')}</div>`).join('') || '<span class="similarity-chip">no exact semantic-function matches</span>'}</div>
                    </div>
                ` : ''}
            </div>
        `;
    }

    function numberField(id, label, value, attrs = 'min="0" step="1"') {
        return `<div class="similarity-field"><label for="${esc(id)}">${esc(label)}</label><input id="${esc(id)}" type="number" ${attrs} value="${esc(value ?? 0)}"></div>`;
    }

    function checkbox(id, label, checked) {
        return `<label class="similarity-chip similarity-toggle"><input id="${esc(id)}" type="checkbox" ${checked ? 'checked' : ''}> ${esc(label)}</label>`;
    }

    async function renderSettings(options = {}) {
        setPane(loading('Đang tải cài đặt...'));
        const settings = await apiCached('/api/similarity/settings', options);
        const ida = apiCachedValue('/api/similarity/ida/status') || { available: false, enabled: false, reason: 'Đang kiểm tra trạng thái IDA...' };
        const hexrays = apiCachedValue('/api/similarity/hexrays/status') || { available: false, enabled: false, reason: 'Đang kiểm tra trạng thái Hex-Rays...' };
        currentSettings = settings || {};
        const weights = settings.weights || {};
        const codeWeights = settings.code_weights || {};
        const weightFields = ['semantic_code', 'code', 'strings', 'tlsh', 'imports', 'imphash', 'icon', 'rich', 'ssdeep']
            .map(k => numberField(`sim-weight-${k}`, niceKey(k), weights[k] ?? 0)).join('');
        const codeWeightFields = ['functions', 'blocks', 'ngrams', 'api_patterns', 'cfg', 'constants', 'function_strings']
            .map(k => numberField(`sim-code-weight-${k}`, niceKey(k), codeWeights[k] ?? 0)).join('');
        setPane(shell(`
            <div class="similarity-headline">
                <div>
                    <h3>Cài đặt độ tương đồng</h3>
                    <p>Trọng số, khả năng bộ trích xuất, đường dẫn IDA và ngưỡng chấm điểm.</p>
                </div>
                <div class="similarity-toggle-row">
                    <span class="similarity-chip ${ida.available ? 'good' : (ida.enabled ? 'bad' : 'warn')}"><i class="fa-solid fa-microchip"></i> IDA ${ida.available ? 'available' : (ida.enabled ? 'unavailable' : 'disabled')}</span>
                    <span class="similarity-chip ${hexrays.available ? 'good' : (hexrays.enabled ? 'warn' : '')}"><i class="fa-solid fa-code-branch"></i> Hex-Rays ${hexrays.available ? 'available' : (hexrays.enabled ? hexrays.status : 'disabled')}</span>
                </div>
            </div>
            <form class="similarity-form" id="similarity-settings-form">
                <div class="similarity-settings-group">
                    ${sectionTitle('fa-scale-balanced', 'Trọng số bằng chứng')}
                    <div class="similarity-settings-grid">${weightFields}</div>
                </div>
                <div class="similarity-settings-group">
                    ${sectionTitle('fa-code', 'So sánh Code')}
                    ${ida.reason ? `<div class="similarity-subtext" style="margin-bottom:12px;">${esc(ida.reason)}</div>` : ''}
                    <div class="similarity-settings-grid">${codeWeightFields}</div>
                    <div class="similarity-form-grid" style="margin-top:12px;">
                        ${numberField('sim-min-func', 'Lệnh hàm tối thiểu', settings.minimum_function_instructions, 'min="1" step="1"')}
                        ${numberField('sim-ngram-size', 'Kích thước N-Gram gợi nhớ', settings.mnemonic_ngram_size, 'min="2" max="8" step="1"')}
                        ${numberField('sim-ida-timeout', 'Giây chờ IDA', settings.ida_timeout_seconds, 'min="30" step="30"')}
                    </div>
                </div>
                <div class="similarity-settings-group">
                    ${sectionTitle('fa-folder-open', 'File thực thi IDA')}
                    <div class="similarity-form-grid">
                        <div class="similarity-field">
                            <label for="sim-ida-path">IDA 64-bit path</label>
                            <div class="similarity-field-row">
                                <input id="sim-ida-path" value="${esc(settings.ida_path || '')}" placeholder="Chọn ida64.exe" readonly>
                                <button type="button" class="similarity-icon-btn" data-sim-browse-ida="sim-ida-path" title="Browse"><i class="fa-solid fa-folder-open"></i></button>
                            </div>
                        </div>
                        <div class="similarity-field">
                            <label for="sim-ida-path-32">IDA 32-bit path</label>
                            <div class="similarity-field-row">
                                <input id="sim-ida-path-32" value="${esc(settings.ida_path_32 || '')}" placeholder="Chọn ida.exe" readonly>
                                <button type="button" class="similarity-icon-btn" data-sim-browse-ida="sim-ida-path-32" title="Browse"><i class="fa-solid fa-folder-open"></i></button>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="similarity-settings-group">
                    ${sectionTitle('fa-code-branch', 'Phân tích ngữ nghĩa')}
                    ${hexrays.reason ? `<div class="similarity-subtext" style="margin-bottom:12px;">${esc(hexrays.reason)}</div>` : ''}
                    <div class="similarity-form-grid">
                        ${numberField('sim-min-sem-func', 'Lệnh ngữ nghĩa tối thiểu', settings.minimum_semantic_function_instructions, 'min="1" step="1"')}
                        ${numberField('sim-min-sem-match', 'Khớp ngữ nghĩa tối thiểu', settings.minimum_semantic_match, 'min="0" max="100" step="1"')}
                        ${numberField('sim-max-sem-func', 'Số hàm ngữ nghĩa tối đa', settings.maximum_semantic_functions, 'min="1" step="10"')}
                        ${numberField('sim-sem-ngram-size', 'Kích thước N-Gram ngữ nghĩa', settings.semantic_ngram_size, 'min="2" max="8" step="1"')}
                    </div>
                </div>
                <div class="similarity-settings-group">
                    ${sectionTitle('fa-sliders', 'Ngưỡng')}
                    <div class="similarity-form-grid">
                        ${numberField('sim-threshold', 'Ngưỡng StringSifter', settings.stringsifter_threshold, 'min="0" max="1" step="0.05"')}
                        ${numberField('sim-min-len', 'Độ dài chuỗi tối thiểu', settings.minimum_string_length, 'min="1" step="1"')}
                        ${numberField('sim-min-score', 'Điểm khớp tối thiểu', settings.minimum_match_score, 'min="0" max="100" step="1"')}
                        ${numberField('sim-timeout', 'Giây chờ xử lý', settings.processing_timeout_seconds, 'min="5" step="5"')}
                    </div>
                </div>
                <div class="similarity-settings-group">
                    ${sectionTitle('fa-gauge-high', 'Giới hạn thời gian và ứng viên')}
                    <div class="similarity-form-grid">
                        ${numberField('sim-hex-timeout', 'Giây chờ Hex-Rays', settings.hexrays_timeout_seconds, 'min="30" step="30"')}
                        ${numberField('sim-hex-function-timeout', 'Thời gian chờ hàm Hex-Rays', settings.hexrays_function_timeout_seconds, 'min="1" step="1"')}
                        ${numberField('sim-min-block', 'Lệnh block tối thiểu', settings.minimum_block_instructions, 'min="1" step="1"')}
                        ${numberField('sim-min-func-match', 'Khớp hàm tối thiểu', settings.minimum_function_match, 'min="0" max="100" step="1"')}
                        ${numberField('sim-candidate-functions', 'Hàm ứng viên', settings.candidate_functions, 'min="1" max="200" step="1"')}
                        ${numberField('sim-sem-candidate-functions', 'Hàm ứng viên ngữ nghĩa', settings.semantic_candidate_functions, 'min="1" max="200" step="1"')}
                        ${numberField('sim-ida-max-concurrent', 'Số tác vụ IDA đồng thời', settings.ida_max_concurrent_jobs, 'min="1" step="1"')}
                        ${numberField('sim-ida-max-file-mb', 'Dung lượng file IDA tối đa (MB)', Math.round(Number(settings.ida_max_file_size || 104857600) / 1048576), 'min="1" step="1"')}
                    </div>
                </div>
                <div class="similarity-settings-group">
                    ${sectionTitle('fa-toggle-on', 'Tùy chọn xử lý')}
                    <div class="similarity-toggle-row">
                        ${checkbox('sim-history', 'Lưu lịch sử so sánh', settings.store_comparison_history)}
                        ${checkbox('sim-enable-code', 'Bật độ tương đồng code IDA', settings.enable_code_similarity)}
                        ${checkbox('sim-enable-semantic', 'Bật độ tương đồng ngữ nghĩa Hex-Rays', settings.enable_semantic_similarity)}
                        ${checkbox('sim-enable-pseudo', 'Độ tương đồng pseudocode', settings.enable_pseudocode_similarity)}
                        ${checkbox('sim-enable-ast', 'Độ tương đồng AST', settings.enable_ast_similarity)}
                        ${checkbox('sim-enable-micro', 'Độ tương đồng microcode', settings.enable_microcode_similarity)}
                        ${checkbox('sim-store-tokens', 'Lưu token đã chuẩn hóa', settings.store_normalized_tokens)}
                        ${checkbox('sim-exclude-thunks', 'Loại trừ thunks', settings.exclude_thunks)}
                        ${checkbox('sim-downweight-libs', 'Giảm trọng số hàm thư viện', settings.downweight_library_functions)}
                    </div>
                </div>
                <div class="similarity-action-row">
                    <button class="btn-primary" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save Settings</button>
                    <span id="sim-settings-status" class="similarity-subtext"></span>
                </div>
            </form>
            <div id="sim-path-picker"></div>
        `));
        $('similarity-settings-form')?.addEventListener('submit', saveSettings);
        if (!options.skipStatusRefresh && (!apiCachedValue('/api/similarity/ida/status') || !apiCachedValue('/api/similarity/hexrays/status'))) {
            refreshSimilarityStatuses('similarity-settings', renderSettings);
        }
    }

    async function saveSettings(e) {
        e.preventDefault();
        const weights = {};
        ['semantic_code', 'code', 'strings', 'tlsh', 'imports', 'imphash', 'icon', 'rich', 'ssdeep'].forEach(k => {
            weights[k] = valueOf(`sim-weight-${k}`);
        });
        const code_weights = {};
        ['functions', 'blocks', 'ngrams', 'api_patterns', 'cfg', 'constants', 'function_strings'].forEach(k => {
            code_weights[k] = valueOf(`sim-code-weight-${k}`);
        });
        const payload = {
            ...currentSettings,
            weights,
            code_weights,
            stringsifter_threshold: valueOf('sim-threshold', 0.45),
            minimum_string_length: valueOf('sim-min-len', 4),
            minimum_match_score: valueOf('sim-min-score', 35),
            processing_timeout_seconds: valueOf('sim-timeout', 120),
            store_comparison_history: !!$('sim-history')?.checked,
            enable_code_similarity: !!$('sim-enable-code')?.checked,
            enable_semantic_similarity: !!$('sim-enable-semantic')?.checked,
            enable_pseudocode_similarity: !!$('sim-enable-pseudo')?.checked,
            enable_ast_similarity: !!$('sim-enable-ast')?.checked,
            enable_microcode_similarity: !!$('sim-enable-micro')?.checked,
            store_normalized_tokens: !!$('sim-store-tokens')?.checked,
            exclude_thunks: !!$('sim-exclude-thunks')?.checked,
            downweight_library_functions: !!$('sim-downweight-libs')?.checked,
            ida_path: $('sim-ida-path')?.value || '',
            ida_path_32: $('sim-ida-path-32')?.value || '',
            ida_timeout_seconds: valueOf('sim-ida-timeout', 300),
            minimum_function_instructions: valueOf('sim-min-func', 5),
            mnemonic_ngram_size: valueOf('sim-ngram-size', 4),
            minimum_semantic_function_instructions: valueOf('sim-min-sem-func', 10),
            minimum_semantic_match: valueOf('sim-min-sem-match', 60),
            maximum_semantic_functions: valueOf('sim-max-sem-func', 100),
            semantic_ngram_size: valueOf('sim-sem-ngram-size', 4),
            hexrays_timeout_seconds: valueOf('sim-hex-timeout', 120),
            hexrays_function_timeout_seconds: valueOf('sim-hex-function-timeout', 10),
            minimum_block_instructions: valueOf('sim-min-block', 2),
            minimum_function_match: valueOf('sim-min-func-match', 55),
            candidate_functions: valueOf('sim-candidate-functions', 20),
            semantic_candidate_functions: valueOf('sim-sem-candidate-functions', 20),
            ida_max_concurrent_jobs: valueOf('sim-ida-max-concurrent', 1),
            ida_max_file_size: valueOf('sim-ida-max-file-mb', 100) * 1048576
        };
        const status = $('sim-settings-status');
        try {
            await api('/api/similarity/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            clearSimilarityCache();
            if (status) status.textContent = 'Đã lưu';
            notify('Đã lưu cài đặt tương đồng');
        } catch (err) {
            if (status) status.textContent = err.message;
        }
    }

    function pickerHost() {
        let host = $('sim-path-picker');
        if (!host) {
            host = document.createElement('div');
            host.id = 'sim-path-picker';
            document.body.appendChild(host);
        }
        return host;
    }

    async function openPathPicker(inputId) {
        pickerTargetInput = inputId;
        const current = ($(inputId)?.value || '').trim();
        const isWindows = (navigator.platform || '').toLowerCase().includes('win');
        const start = /\.exe$/i.test(current) ? current.replace(/[\\/][^\\/]+$/, '') : (current || (isWindows ? '' : '/'));
        if (isWindows) {
            try {
                const selected = await api(`/api/similarity/select-ida?initial=${encodeURIComponent(start || current || '')}`);
                if (selected && selected.path) {
                    const input = $(inputId);
                    if (input) input.value = selected.path;
                    return;
                }
                if (selected && selected.cancelled) return;
            } catch (err) {
                notify('Trình chọn tệp gốc không khả dụng; dùng trình duyệt thư mục');
            }
        }
        await loadPathPicker(start);
    }

    async function loadPathPicker(path) {
        const host = pickerHost();
        host.innerHTML = `
            <div class="similarity-picker-overlay">
                <div class="similarity-picker">
                    <div class="similarity-picker-head">
                        <h3><i class="fa-solid fa-folder-open"></i> Select IDA Executable</h3>
                        <button class="btn-secondary" data-sim-picker-close><i class="fa-solid fa-xmark"></i></button>
                    </div>
                    <div class="similarity-loading"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading...</div>
                </div>
            </div>
        `;
        try {
            const data = await api(`/api/similarity/browse-path?path=${encodeURIComponent(path || '')}`);
            renderPathPicker(data);
        } catch (err) {
            host.innerHTML = `
                <div class="similarity-picker-overlay">
                    <div class="similarity-picker">
                        <div class="similarity-picker-head">
                            <h3><i class="fa-solid fa-folder-open"></i> Select IDA Executable</h3>
                            <button class="btn-secondary" data-sim-picker-close><i class="fa-solid fa-xmark"></i></button>
                        </div>
                        <div class="similarity-empty">${esc(err.message)}</div>
                    </div>
                </div>
            `;
        }
    }

    function renderPathPicker(data) {
        const host = pickerHost();
        const entries = data.entries || [];
        host.innerHTML = `
            <div class="similarity-picker-overlay">
                <div class="similarity-picker">
                    <div class="similarity-picker-head">
                        <h3><i class="fa-solid fa-folder-open"></i> Select IDA Executable</h3>
                        <button class="btn-secondary" data-sim-picker-close><i class="fa-solid fa-xmark"></i></button>
                    </div>
                    <div class="similarity-picker-path">${esc(data.path || 'Computer')}</div>
                    <div class="similarity-picker-actions">
                        ${data.parent !== null && data.parent !== undefined ? `<button class="btn-secondary" data-sim-path="${esc(data.parent)}"><i class="fa-solid fa-arrow-up"></i> Up</button>` : ''}
                        <button class="btn-secondary" data-sim-path=""><i class="fa-solid fa-hard-drive"></i> Drives</button>
                        <button class="btn-secondary" data-sim-path="C:\\Program Files\\IDA Pro"><i class="fa-solid fa-location-dot"></i> IDA Pro</button>
                    </div>
                    <div class="similarity-picker-list dark-scroll">
                        ${entries.length ? entries.map(e => `
                            <button class="similarity-picker-row ${e.is_dir ? '' : 'is-file'}" ${e.is_dir ? `data-sim-path="${esc(e.path)}"` : `data-sim-pick-path="${esc(e.path)}"`}>
                                <i class="fa-solid ${e.is_dir ? 'fa-folder' : 'fa-file-code'}"></i>
                                <span class="similarity-code">${esc(e.name)}</span>
                            </button>
                        `).join('') : emptyState('fa-folder-open', 'Không tìm thấy file thực thi IDA trong thư mục này.')}
                    </div>
                </div>
            </div>
        `;
    }

    function closePathPicker() {
        const host = $('sim-path-picker');
        if (host) host.innerHTML = '';
    }

    async function open(tab, options = {}) {
        activeTab = tab || activeTab || 'similarity-dashboard';
        try {
            if (activeTab === 'similarity-dashboard') await renderDashboard(options);
            else if (activeTab === 'similarity-entities') await renderEntities(options);
            else if (activeTab === 'similarity-create') renderCreate();
            else if (activeTab === 'similarity-compare') renderCompare();
            else if (activeTab === 'similarity-settings') await renderSettings(options);
        } catch (err) {
            setPane(shell(`<div class="error-card"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(err.message)}</div>`));
        }
    }

    document.addEventListener('click', async (e) => {
        const tab = e.target.closest('[data-sim-tab]')?.dataset.simTab || e.target.closest('[data-sim-go]')?.dataset.simGo;
        if (tab) {
            const nav = document.querySelector(`.nav-item[data-tab="${tab}"]`);
            if (nav) nav.click();
            else open(tab);
            return;
        }
        if (e.target.closest('[data-sim-refresh]')) {
            clearSimilarityCache();
            open(activeTab, { force: true });
            return;
        }
        const browse = e.target.closest('[data-sim-browse-ida]');
        if (browse) {
            await openPathPicker(browse.dataset.simBrowseIda);
            return;
        }
        if (e.target.closest('[data-sim-picker-close]')) {
            closePathPicker();
            return;
        }
        const pathBtn = e.target.closest('[data-sim-path]');
        if (pathBtn) {
            await loadPathPicker(pathBtn.dataset.simPath || '');
            return;
        }
        const pickBtn = e.target.closest('[data-sim-pick-path]');
        if (pickBtn) {
            const input = $(pickerTargetInput);
            if (input) input.value = pickBtn.dataset.simPickPath || '';
            closePathPicker();
            return;
        }
        const comparisonBtn = e.target.closest('[data-sim-comparison]');
        if (comparisonBtn) {
            await renderSavedComparison(comparisonBtn.dataset.simComparison);
            return;
        }
        const entityBtn = e.target.closest('[data-sim-entity]');
        if (entityBtn) {
            await renderEntityDetail(entityBtn.dataset.simEntity);
            return;
        }
        const delBtn = e.target.closest('[data-sim-delete]');
        if (delBtn) {
            if (!confirm('Delete this similarity entity and all derived features?')) return;
            try {
                await api(`/api/similarity/entities/${encodeURIComponent(delBtn.dataset.simDelete)}`, { method: 'DELETE' });
                clearSimilarityCache();
                notify('Đã xóa thực thể tương đồng');
                renderEntities({ force: true });
            } catch (err) {
                notify(err.message);
            }
        }
    });

    window.openSimilarityPane = open;
})();
