(() => {
    'use strict';

    const BASE = location.protocol === 'file:' ? 'http://127.0.0.1:9999' : location.origin;
    const KEY_NAMES = ['vt', 'silentpush', 'driftnet', 'urlscan', 'ha', 'shodan', 'censys', 'etugen', 'zoomeye', 'pulsedive', 'fofa', 'validin', 'netlas', 'abuseipdb', 'dnsdumpster', 'greynoise'];
    const SEED_SOURCES = ['virustotal', 'silentpush', 'driftnet', 'shodan', 'censys', 'fofa', 'zoomeye', 'validin', 'etugen', 'urlscan', 'greynoise', 'ripe', 'crtsh', 'netlas'];
    
    const state = {
        preview: null,
        result: null,
        pane: 'queries',
        seed: '',
        request: null,
        playbooks: {
            q: '',
            engine: 'all',
            category: 'all',
            items: [],
            total: 0,
            aggregates: {},
            loading: false,
            page: 1,
            pageSize: 25
        }
    };

    const id = value => document.getElementById(value);
    const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
    const keys = () => Object.fromEntries(KEY_NAMES.map(name => [`${name}_key`, localStorage.getItem(`ioc_${name}_key`) || '']));
    const providers = () => [...document.querySelectorAll('.infra-provider-check:checked:not(:disabled)')].map(node => node.value);
    const seed = () => (id('ioc-input')?.value || '').trim();

    async function api(path, options = {}) {
        const response = await fetch(BASE + path, { headers: { 'Content-Type': 'application/json' }, ...options });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(body.detail || body.error || `HTTP ${response.status}`);
        return body;
    }

    function status(message, type = '') {
        const node = id('infra-hunt-status');
        if (node) {
            node.className = `infra-hunt-status ${type}`.trim();
            node.innerHTML = message;
            node.style.display = message ? 'block' : 'none';
        }
    }

    function updateButtons() {
        const isBusy = Boolean(state.request);
        const runButton = id('infra-hunt-run');
        runButton.hidden = !state.preview && !state.result;
        runButton.disabled = isBusy || runButton.hidden;
        const searchBtn = id('btn-search');
        if (searchBtn && document.body.classList.contains('infra-hunt-mode')) {
            searchBtn.disabled = isBusy;
            searchBtn.dataset.infraBusy = String(isBusy);
            searchBtn.innerHTML = isBusy
                ? '<i class="fa-solid fa-circle-notch fa-spin" aria-hidden="true"></i> Working&hellip;'
                : '<i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i> Preview hunt';
        }
    }

    function payload(value) {
        return {
            indicator: value || seed(),
            providers: providers(),
            max_signals: Number(id('infra-hunt-signal-count')?.value || 3),
            source_ids: SEED_SOURCES,
            ...keys(),
        };
    }

    function refreshProviderBadges() {
        const localKeys = keys();
        document.querySelectorAll('.infra-hunt-provider[data-provider]').forEach(label => {
            const provider = label.dataset.provider;
            const badge = label.querySelector('em');
            const check = label.querySelector('.infra-provider-check');
            const configured = provider === 'greynoise' || Boolean(localKeys[`${provider}_key`]);
            label.classList.toggle('missing-key', !configured);
            if (check) {
                if (!configured) {
                    check.checked = false;
                    check.disabled = true;
                } else {
                    check.disabled = false;
                    if (check.dataset.userUnchecked !== 'true') {
                        check.checked = true;
                    }
                }
            }
            if (badge) {
                badge.textContent = configured ? (provider === 'greynoise' && !localKeys.greynoise_key ? 'Community' : '') : 'Key required';
                badge.title = configured ? 'Engine ready for queries' : 'Add API key in Settings to enable this engine';
            }
        });
        id('infra-engine-count').textContent = `${providers().length} selected`;
    }

    async function preview() {
        const value = seed();
        if (!value) return status('Enter an infrastructure indicator to preview a hunt.', 'error');
        if (!providers().length) {
            id('infra-engine-count').closest('details').open = true;
            return status('Select at least one expansion engine in Hunt settings.', 'error');
        }

        clearHunt();
        id('infra-hunt-workspace').replaceChildren();
        const request = new AbortController();
        state.request = request;
        updateButtons();
        status('Enriching indicator and preparing queries&hellip;', 'running');

        try {
            const data = await api('/api/infra-hunts/preview', { method: 'POST', body: JSON.stringify(payload(value)), signal: request.signal });
            if (state.request !== request) return;
            state.preview = data;
            state.seed = value;
            state.pane = 'queries';
            renderDashboard(data);
            status('Preview ready. Review the queries or correlate candidates across the selected engines.');
        } catch (error) {
            if (state.request === request) status(`Preview failed: ${esc(error.message)}`, 'error');
        } finally {
            finishRequest(request);
        }
    }

    async function run() {
        const value = seed();
        if (state.request || !state.preview || state.seed !== value) return;
        if (!providers().length) return status('Select at least one expansion engine in Hunt settings.', 'error');

        const request = new AbortController();
        state.request = request;
        updateButtons();
        status('Querying engines and scoring candidates&hellip;', 'running');

        try {
            const data = await api('/api/infra-hunts/run', { method: 'POST', body: JSON.stringify(payload(value)), signal: request.signal });
            if (state.request !== request) return;
            state.result = data;
            state.pane = 'candidates';
            renderDashboard(data, true);
            status('Correlation complete.');
        } catch (error) {
            if (state.request === request) status(`Correlation failed: ${esc(error.message)}`, 'error');
        } finally {
            finishRequest(request);
        }
    }

    function finishRequest(request) {
        if (state.request !== request) return;
        state.request = null;
        updateButtons();
    }

    function getSignalLabel(kind) {
        const mapping = {
            'cert_serial': 'TLS Serial Number',
            'cert_subject_dn': 'Subject Distinguished Name',
            'cert_issuer_dn': 'Issuer Distinguished Name',
            'cert_fingerprint_sha256': 'Cert SHA-256 Fingerprint',
            'cert_fingerprint_sha1': 'Cert SHA-1 Fingerprint',
            'jarm': 'JARM TLS Fingerprint',
            'http_server': 'HTTP Server Header',
            'http_title': 'HTML Page Title',
            'http_status': 'HTTP Response Code',
            'favicon_md5': 'Favicon MD5 Hash',
            'favicon_mmh3': 'Favicon Murmur3 Hash',
            'asn': 'Autonomous System (ASN)',
            'autonomous_system': 'Routing AS Number',
            'port': 'Exposed Service Port',
            'ports': 'Open Ports List',
            'hostname': 'Associated Hostname / PTR',
            'san_domain': 'Subject Alternative Name (SAN)',
            'reverse_dns': 'Reverse DNS Record',
            'ip': 'Host IP Address'
        };
        return mapping[kind] || kind.replaceAll('_', ' ').toUpperCase();
    }

    function renderC2Matches(matches) {
        if (!matches || !matches.length) return '';

        return `
        <div class="infra-c2-alerts">
            ${matches.map(m => `
                <div class="infra-c2-alert-card">
                    <div class="infra-c2-alert-head">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                        <div class="infra-c2-alert-text">
                            <strong>🎯 Threat Attribution Match: ${esc(m.family)}</strong>
                            <span>${esc(m.category)} · Matched via ${esc(m.matched_by)} (<code>${esc(m.matched_value)}</code>)</span>
                            <p>${esc(m.description)}</p>
                        </div>
                        <span class="infra-confidence high">${esc(m.confidence)} CONFIDENCE</span>
                    </div>
                    ${(m.recommended_queries && m.recommended_queries.length) ? `
                        <div class="infra-c2-subqueries">
                            <span class="infra-subqueries-title"><i class="fa-solid fa-crosshairs"></i> Curated ${esc(m.family)} Hunting Queries:</span>
                            <div class="infra-query-deck mini">
                                ${m.recommended_queries.map(rq => renderSingleQueryCard(rq)).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>`;
    }

    function renderSingleQueryCard(item, compactActions = false) {
        const provider = (item.engine || item.provider || '').toLowerCase();
        const isOpenDir = provider === 'etugen' && (
            item.focus === 'open_directory' || 
            (item.query || '').includes('Index of') || 
            (item.query || '').includes('Trashpile') || 
            (item.query || '').includes('.git') || 
            (item.query || '').includes('.bash_history') || 
            item.category === 'Exposed OpenDir / Secrets' ||
            (item.technique || '').toLowerCase().includes('open directory')
        );
        const providerName = isOpenDir ? 'ETUGEN (OPEN-DIR)' : provider.toUpperCase();
        const signals = item.signals || [];
        const strength = item.estimated_strength;
        const extUrl = item.external_url || '';
        const notes = item.notes || '';
        const technique = item.technique || '';
        const family = item.family || '';
        const isEtugen = provider === 'etugen';

        return `
        <article class="infra-query-card ${compactActions ? 'catalog-query-card' : ''}" data-engine="${esc(provider)}">
            <header>
                <div class="infra-engine-info">
                    <span class="infra-engine-badge is-${esc(provider)}">${esc(providerName)}</span>
                    ${isOpenDir ? `<span class="infra-opendir-badge"><i class="fa-solid fa-folder-open"></i> Open-Directory</span>` : ''}
                    ${family ? `<span class="infra-family-badge">${esc(family)}</span>` : ''}
                    ${technique ? `<span class="infra-mode-badge">${esc(technique)}</span>` : (!isOpenDir ? `<span class="infra-mode-badge">${esc((item.mode || 'Search').replaceAll('_', ' '))}</span>` : '')}
                </div>
                ${notes ? `<small class="infra-notes">${esc(notes)}</small>` : strength != null ? `<span class="infra-strength-badge">Signal score <strong>${esc(strength)}</strong></span>` : ''}
            </header>
            <div class="infra-query-body">
                <pre class="infra-query-code"><code>${esc(item.query)}</code></pre>
            </div>
            ${signals.length ? `
            <div class="infra-query-signals">
                <span class="infra-signals-label">Supporting signals</span>
                ${signals.map(s => `<span class="infra-hunt-chip" title="Weight ${esc(s.weight)}"><span>${esc(getSignalLabel(s.kind))}</span> <code>${esc(s.value)}</code></span>`).join('')}
            </div>` : ''}
            <div class="infra-query-actions">
                <button type="button" class="infra-hunt-btn query-copy-btn" data-copy-text="${esc(item.query)}" ${compactActions ? 'data-icon-only' : ''} aria-label="Copy query" title="Copy query">
                    <i class="fa-solid fa-copy" aria-hidden="true"></i>${compactActions ? '' : ' Copy Query'}
                </button>
                ${extUrl ? `
                <a href="${esc(extUrl)}" target="_blank" rel="noopener noreferrer" class="infra-hunt-btn external-link" aria-label="Open query in ${esc(providerName)} (new tab)" title="Open in ${esc(providerName)} (new tab)">
                    <i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i>${compactActions ? '' : ` Open in ${isEtugen ? (isOpenDir ? 'Etugen Trashpile' : 'Etugen Search') : (provider === 'zoomeye' ? 'ZoomEye' : esc(providerName))}`}
                </a>` : ''}
                ${compactActions && item.source_url ? `<a href="${esc(item.source_url)}" target="_blank" rel="noopener noreferrer" class="infra-hunt-btn external-link" aria-label="View fingerprint source (new tab)" title="Fingerprint source"><i class="fa-solid fa-book-open" aria-hidden="true"></i></a>` : ''}
                ${compactActions && item.id ? `<button type="button" class="infra-hunt-btn" data-pb-edit="${esc(item.id)}" aria-label="Edit query" title="Edit query"><i class="fa-solid fa-pen" aria-hidden="true"></i></button>` : ''}
            </div>
        </article>`;
    }

    function renderQueryDeck(queries, c2Matches = []) {
        let alertHtml = renderC2Matches(c2Matches);

        if (!queries || !queries.length) {
            return alertHtml + '<div class="infra-hunt-empty"><i class="fa-solid fa-magnifying-glass-arrow-right" style="font-size:1.8rem;margin-bottom:10px;opacity:.5;"></i><div>No search queries could be composed from the seed signals. Try selecting more engines or using an IP/domain with exposed HTTP/TLS services.</div></div>';
        }

        return alertHtml + `<div class="infra-query-deck">${queries.map(item => renderSingleQueryCard(item)).join('')}</div>`;
    }

    function renderSignalsDeck(features) {
        if (!features || !features.ranked || !features.ranked.length) {
            return '<div class="infra-hunt-empty"><i class="fa-solid fa-fingerprint" style="font-size:1.8rem;margin-bottom:10px;opacity:.5;"></i><div>No distinctive fingerprints or metadata signals extracted from this seed.</div></div>';
        }

        const categories = features.categories || {};
        const catConfig = [
            { id: 'certificates', label: 'TLS & Certificate Fingerprints', icon: 'fa-shield-halved', color: '#4cc9f0' },
            { id: 'web', label: 'Web & Application Signatures', icon: 'fa-globe', color: '#ffd166' },
            { id: 'network', label: 'Network & Autonomous System (ASN)', icon: 'fa-network-wired', color: '#7209b7' },
            { id: 'hosts', label: 'Associated Infrastructure & Hosts', icon: 'fa-server', color: '#06d6a0' }
        ];

        let html = '<div class="infra-signals-grid">';

        catConfig.forEach(cat => {
            const list = categories[cat.id] || [];
            if (!list.length) return;

            html += `
            <div class="infra-signal-category">
                <div class="infra-category-header">
                    <i class="fa-solid ${cat.icon}" style="color: ${cat.color};"></i>
                    <strong>${esc(cat.label)}</strong>
                    <span class="infra-count-badge">${list.length}</span>
                </div>
                <div class="infra-signal-table-wrap" role="region" tabindex="0" aria-label="${esc(cat.label)}">
                    <table class="infra-signal-table">
                        <thead>
                            <tr>
                                <th scope="col" class="signal-name">Fingerprint</th>
                                <th scope="col">Observed value</th>
                                <th scope="col" class="signal-action">Copy</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${list.map(s => {
                                const isDistinctive = s.distinctive || (s.weight && s.weight >= 2);
                                const label = getSignalLabel(s.kind);
                                return `
                                <tr>
                                    <td class="signal-name">
                                        <div class="signal-kind-title">${esc(label)}</div>
                                        <span class="infra-distinct-chip ${isDistinctive ? 'distinctive' : 'context'}">
                                            ${isDistinctive ? 'Distinctive' : 'Contextual'}
                                        </span>
                                    </td>
                                    <td class="signal-val">
                                        <code class="infra-hunt-code">${esc(s.value)}</code>
                                    </td>
                                    <td class="signal-action">
                                        <button type="button" class="infra-hunt-btn mini-btn" data-copy-text="${esc(s.value)}" aria-label="Copy ${esc(label)} value" title="Copy signal value">
                                            <i class="fa-solid fa-copy" aria-hidden="true"></i>
                                        </button>
                                    </td>
                                </tr>`;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
        });

        html += '</div>';
        return html;
    }

    function renderCandidates(candidates, isPreview = false) {
        if (!candidates || !candidates.length) {
            if (isPreview) {
                return `
                <div class="infra-hunt-empty">
                    <i class="fa-solid fa-arrows-split-up-and-left" style="font-size:2rem;margin-bottom:12px;color:var(--accent);opacity:.7;"></i>
                    <h4>Ready to correlate</h4>
                    <p>Use <strong>Correlate candidates</strong> to search the selected engines and score overlapping infrastructure.</p>
                </div>`;
            }
            return `
            <div class="infra-hunt-empty">
                <i class="fa-solid fa-circle-nodes" style="font-size:2rem;margin-bottom:12px;opacity:.5;"></i>
                <h4>No correlated candidates</h4>
                <p>No candidates met the correlation threshold. Open the <strong>Queries</strong> tab to pivot directly in your search engine.</p>
            </div>`;
        }

        return `
        <div class="infra-candidates-wrap">
            <div class="infra-candidates-toolbar">
                <span class="infra-toolbar-title">Correlated infrastructure</span>
                <div class="infra-export-actions">
                    <button id="infra-export-json" class="infra-hunt-btn"><i class="fa-solid fa-file-code"></i> Export JSON</button>
                    <button id="infra-export-csv" class="infra-hunt-btn"><i class="fa-solid fa-file-csv"></i> Export CSV</button>
                </div>
            </div>
            <div class="infra-hunt-table-wrap dark-scroll" role="region" tabindex="0" aria-label="Correlated infrastructure table">
                <table class="infra-hunt-table">
                    <thead>
                        <tr>
                            <th>Candidate Indicator</th>
                            <th>Type</th>
                            <th>Affiliation Score</th>
                            <th>Confidence</th>
                            <th>Observed In</th>
                            <th>Correlated Evidence</th>
                            <th style="text-align:right;">Pivot</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${candidates.map(item => `
                        <tr>
                            <td>
                                <strong class="infra-hunt-code">${esc(item.value)}</strong>
                            </td>
                            <td>
                                <span class="infra-type-badge ${esc(item.value_type)}">${esc((item.value_type || 'node').toUpperCase())}</span>
                            </td>
                            <td class="infra-score">
                                <strong>${esc(item.score)}/100</strong>
                                <div class="infra-score-bar"><i style="width:${Math.max(8, Math.min(100, item.score))}%"></i></div>
                            </td>
                            <td>
                                <span class="infra-confidence ${esc(item.confidence || 'medium')}">${esc((item.confidence || 'medium').toUpperCase())}</span>
                            </td>
                            <td>
                                ${(item.providers || []).map(p => `<span class="infra-hunt-chip">${esc(p)}</span>`).join('')}
                            </td>
                            <td>
                                ${(item.evidence || []).slice(0, 6).map(e => `
                                    <span class="infra-hunt-chip ${e.validation_only ? 'validation' : ''}" title="${esc(e.value || '')}">
                                        ${esc(getSignalLabel(e.kind))} ${e.weight ? (e.weight > 0 ? `+${e.weight}` : e.weight) : ''}
                                    </span>
                                `).join('')}
                            </td>
                            <td style="text-align:right;">
                                <button class="infra-hunt-btn pivot-btn" data-infra-pivot="${esc(item.value)}" title="Pivot and hunt infrastructure for this indicator">
                                    <i class="fa-solid fa-crosshairs"></i> Pivot
                                </button>
                            </td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
        </div>`;
    }

    function getPageNumbers(current, total) {
        if (total <= 7) {
            return Array.from({ length: total }, (_, i) => i + 1);
        }
        const pages = [];
        if (current <= 4) {
            for (let i = 1; i <= 5; i++) pages.push(i);
            pages.push('...');
            pages.push(total);
        } else if (current >= total - 3) {
            pages.push(1);
            pages.push('...');
            for (let i = total - 4; i <= total; i++) pages.push(i);
        } else {
            pages.push(1);
            pages.push('...');
            pages.push(current - 1);
            pages.push(current);
            pages.push(current + 1);
            pages.push('...');
            pages.push(total);
        }
        return pages;
    }

    async function loadPlaybooks() {
        state.playbooks.loading = true;
        const container = id('infra-playbooks-content');
        if (container) {
            container.innerHTML = '<div class="infra-hunt-empty"><i class="fa-solid fa-circle-notch fa-spin" style="font-size:2rem;color:var(--accent);"></i><div style="margin-top:10px;">Loading curated C2 threat playbooks…</div></div>';
        }

        try {
            const limit = state.playbooks.pageSize || 25;
            const page = Math.max(1, state.playbooks.page || 1);
            const offset = (page - 1) * limit;

            const params = new URLSearchParams({
                q: state.playbooks.q,
                engine: state.playbooks.engine,
                category: state.playbooks.category,
                limit: limit,
                offset: offset
            });
            const data = await api(`/api/infra-hunts/playbooks?${params.toString()}`);
            if (container !== id('infra-playbooks-content')) return;
            state.playbooks.items = data.items || [];
            state.playbooks.total = data.total || 0;
            state.playbooks.aggregates = data.aggregates || {};
            renderPlaybooksView();
        } catch (err) {
            if (container) {
                container.innerHTML = `<div class="infra-hunt-empty"><span style="color:#ff8f8f;">Failed to load playbooks: ${esc(err.message)}</span></div>`;
            }
        } finally {
            state.playbooks.loading = false;
        }
    }

    function renderPlaybooksView() {
        const container = id('infra-playbooks-content');
        if (!container) return;

        const { items, total, q, engine, category, aggregates } = state.playbooks;
        const page = Math.max(1, state.playbooks.page || 1);
        const pageSize = state.playbooks.pageSize || 25;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));
        const startItem = total === 0 ? 0 : (page - 1) * pageSize + 1;
        const endItem = Math.min(page * pageSize, total);
        const enginesAgg = aggregates.engines || {};
        const categoriesAgg = aggregates.categories || {};

        const engineOptions = ['all', 'shodan', 'censys', 'netlas', 'urlscan', 'fofa', 'zoomeye', 'validin', 'etugen', 'silentpush'];
        const catOptions = ['all', 'AI Red Team', 'C2 Framework', 'Exposed OpenDir / Secrets', 'Webshell', 'Hacktool', 'Info Stealer', 'RAT', 'Favicon Fingerprint', 'Phishing Framework', 'Banking Trojan', 'APT Infrastructure', 'Ransomware', 'Botnet', 'Tunnel / Proxy'];
        const etugenLabels = [
            'open-dir', 'c2', 'exposed-secrets', 'git-exposure', 'webshell', 'ransomware',
            'botnet', 'rat', 'tunnel', 'phishing', 'exfil', 'history', 'exposed-backup',
            'exposed-database', 'hacktool', 'loader', 'malware', 'miner', 'mitm',
            'active-directory', 'credential-access', 'enumeration', 'exploit',
            'password-cracking', 'privilege-escalation', 'reconnaissance', 'scanner', 'sql-injection'
        ];

        // Engine-specific contextual preset hub
        let enginePresetHubHtml = '';
        if (engine === 'etugen') {
            const highSignalEtugen = [
                { label: 'Open Dirs (port 8000)', query: 'title LIKE "Index of%" AND port:8000', icon: 'fa-folder-open' },
                { label: 'Cobalt Strike', query: 'label:"C2:CobaltStrike"', icon: 'fa-skull-crossbones' },
                { label: 'C2 Teamservers', query: 'label:c2', icon: 'fa-server' },
                { label: 'Exposed Secrets', query: 'label:exposed-secrets', icon: 'fa-key' },
                { label: 'Git Configs', query: 'path LIKE %/.git/config%', icon: 'fa-code-branch' },
                { label: 'Shell History', query: 'filename:.bash_history', icon: 'fa-terminal' },
                { label: 'Supershell C2', query: 'malware:Supershell', icon: 'fa-biohazard' },
                { label: 'Web Shells', query: 'label:webshell', icon: 'fa-file-code' }
            ];
            const currentSelectedLabel = q.startsWith('label:') ? q.replace('label:', '').replace(/"/g, '') : '';
            enginePresetHubHtml = `
                <div class="engine-preset-hub is-etugen">
                    <div class="preset-hub-header">
                        <div class="preset-hub-title">
                            <span class="hub-pill etugen-pill"><i class="fa-solid fa-folder-tree"></i> ETUGEN OPEN-DIR & TRASHPILE HUB</span>
                            <span class="hub-subtitle">Quick pivots into exposed open directories, leaked configs & labeled C2 infrastructure</span>
                        </div>
                        ${q ? `<button type="button" class="preset-reset-btn" id="pb-reset-filter"><i class="fa-solid fa-xmark"></i> Clear Query</button>` : ''}
                    </div>
                    <div class="preset-hub-actions">
                        <div class="preset-hub-quick-chips">
                            ${highSignalEtugen.map(p => `
                                <button type="button" class="preset-chip ${q === p.query ? 'active' : ''}" data-pb-set-q="${esc(p.query)}">
                                    <i class="fa-solid ${p.icon}"></i> ${p.label}
                                </button>
                            `).join('')}
                        </div>
                        <div class="preset-hub-dropdown-row">
                            <span class="dropdown-label"><i class="fa-solid fa-tag"></i> Filter by Threat Label (27 classes):</span>
                            <select id="pb-etugen-label-select" class="preset-select">
                                <option value="">-- Jump to an Etugen Classifier Label --</option>
                                ${etugenLabels.map(l => `<option value="${l}" ${currentSelectedLabel === l ? 'selected' : ''}>${l}</option>`).join('')}
                            </select>
                        </div>
                    </div>
                </div>
            `;
        } else if (engine === 'zoomeye') {
            const zoomeyePresets = [
                { label: 'Open Directories', query: 'title="Index of /"', icon: 'fa-folder-open' },
                { label: 'Cobalt Strike Body', query: 'http.body="Cobalt Strike"', icon: 'fa-skull-crossbones' },
                { label: 'Sliver C2 OpenDir', query: 'http.body="sliver" && title="Index of /"', icon: 'fa-ghost' },
                { label: 'Mythic C2 Portal', query: 'title="Mythic" && http.body="login"', icon: 'fa-shield-halved' },
                { label: 'Havoc C2 OpenDir', query: 'http.body="Havoc" && title="Index of /"', icon: 'fa-dragon' },
                { label: 'Metasploit OpenDir', query: 'title="Index of /" && http.body="metasploit"', icon: 'fa-crosshairs' },
                { label: 'Git Config Leaks', query: 'title="Index of /.git"', icon: 'fa-code-branch' }
            ];
            enginePresetHubHtml = `
                <div class="engine-preset-hub is-zoomeye">
                    <div class="preset-hub-header">
                        <div class="preset-hub-title">
                            <span class="hub-pill zoomeye-pill"><i class="fa-solid fa-eye"></i> ZOOMEYE THREAT HUNTING PRESETS</span>
                            <span class="hub-subtitle">Source-derived & EmbeeResearch signatures (C2 frameworks, TLS, Open-Dirs)</span>
                        </div>
                        ${q ? `<button type="button" class="preset-reset-btn" id="pb-reset-filter"><i class="fa-solid fa-xmark"></i> Clear Query</button>` : ''}
                    </div>
                    <div class="preset-hub-actions">
                        <div class="preset-hub-quick-chips">
                            ${zoomeyePresets.map(p => `
                                <button type="button" class="preset-chip ${q === p.query ? 'active' : ''}" data-pb-set-q="${esc(p.query)}">
                                    <i class="fa-solid ${p.icon}"></i> ${p.label}
                                </button>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        } else if (engine === 'validin') {
            const validinPresets = [
                { label: 'All Validin Pivots', query: '', icon: 'fa-diagram-project' },
                { label: 'Latrodectus DNS', query: 'latrodectus', icon: 'fa-spider' },
                { label: 'Qakbot TLS Certs', query: 'qakbot', icon: 'fa-certificate' },
                { label: 'Cobalt Strike Infra', query: 'cobalt strike', icon: 'fa-skull' },
                { label: 'JA4+ Fingerprints', query: 'ja4', icon: 'fa-fingerprint' },
                { label: 'PrivateLoader DNS', query: 'privateloader', icon: 'fa-download' }
            ];
            enginePresetHubHtml = `
                <div class="engine-preset-hub is-validin">
                    <div class="preset-hub-header">
                        <div class="preset-hub-title">
                            <span class="hub-pill validin-pill"><i class="fa-solid fa-network-wired"></i> VALIDIN DNS & JA4+ PIVOT LIBRARY</span>
                            <span class="hub-subtitle">Advanced Passive DNS graph pivots and JA4 TLS clustering</span>
                        </div>
                        ${q ? `<button type="button" class="preset-reset-btn" id="pb-reset-filter"><i class="fa-solid fa-xmark"></i> Clear Query</button>` : ''}
                    </div>
                    <div class="preset-hub-actions">
                        <div class="preset-hub-quick-chips">
                            ${validinPresets.map(p => `
                                <button type="button" class="preset-chip ${q === p.query ? 'active' : ''}" data-pb-set-q="${esc(p.query)}">
                                    <i class="fa-solid ${p.icon}"></i> ${p.label}
                                </button>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        } else if (engine === 'silentpush') {
            const spPresets = [
                { label: 'All Silent Push Dorks', query: '', icon: 'fa-shield' },
                { label: 'Active Phishing Hubs', query: 'phishing', icon: 'fa-fish' },
                { label: 'Lumma Stealer Feed', query: 'lumma', icon: 'fa-bug' },
                { label: 'Subdomain Takeover', query: 'subdomain', icon: 'fa-arrow-right-arrow-left' },
                { label: 'Age < 7 Days', query: 'age', icon: 'fa-clock' }
            ];
            enginePresetHubHtml = `
                <div class="engine-preset-hub is-silentpush">
                    <div class="preset-hub-header">
                        <div class="preset-hub-title">
                            <span class="hub-pill silentpush-pill"><i class="fa-solid fa-radar"></i> SILENT PUSH PRE-ATTACK QUERIES</span>
                            <span class="hub-subtitle">Domain age, ASN reputation, Bulletproof hosters & phishing infrastructure</span>
                        </div>
                        ${q ? `<button type="button" class="preset-reset-btn" id="pb-reset-filter"><i class="fa-solid fa-xmark"></i> Clear Query</button>` : ''}
                    </div>
                    <div class="preset-hub-actions">
                        <div class="preset-hub-quick-chips">
                            ${spPresets.map(p => `
                                <button type="button" class="preset-chip ${q === p.query ? 'active' : ''}" data-pb-set-q="${esc(p.query)}">
                                    <i class="fa-solid ${p.icon}"></i> ${p.label}
                                </button>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        }

        let paginationHtml = '';
        if (totalPages > 1 || total > 25) {
            const pageNums = getPageNumbers(page, totalPages);
            paginationHtml = `
            <div class="infra-playbook-pagination-bar" id="infra-playbook-pagination">
                <div class="infra-playbook-pagination-info">
                    Showing <strong>${startItem}&ndash;${endItem}</strong> of <strong>${total}</strong> playbooks (Page <strong>${page}</strong> of <strong>${totalPages}</strong>)
                </div>
                <div class="infra-playbook-pagination-controls">
                    <button type="button" class="infra-page-btn" ${page <= 1 ? 'disabled' : ''} data-pb-page="1" title="First page">
                        <i class="fa-solid fa-angles-left"></i>
                    </button>
                    <button type="button" class="infra-page-btn" ${page <= 1 ? 'disabled' : ''} data-pb-page="${page - 1}" title="Previous page">
                        <i class="fa-solid fa-chevron-left"></i> Prev
                    </button>
                    ${pageNums.map(p => {
                        if (p === '...') {
                            return `<span class="infra-page-ellipsis">&hellip;</span>`;
                        }
                        return `<button type="button" class="infra-page-btn ${p === page ? 'active' : ''}" data-pb-page="${p}">${p}</button>`;
                    }).join('')}
                    <button type="button" class="infra-page-btn" ${page >= totalPages ? 'disabled' : ''} data-pb-page="${page + 1}" title="Next page">
                        Next <i class="fa-solid fa-chevron-right"></i>
                    </button>
                    <button type="button" class="infra-page-btn" ${page >= totalPages ? 'disabled' : ''} data-pb-page="${totalPages}" title="Last page">
                        <i class="fa-solid fa-angles-right"></i>
                    </button>
                </div>
                <div class="infra-playbook-pagesize-select">
                    <span>Per page:</span>
                    <select id="infra-playbook-pagesize">
                        <option value="25" ${pageSize === 25 ? 'selected' : ''}>25</option>
                        <option value="50" ${pageSize === 50 ? 'selected' : ''}>50</option>
                        <option value="100" ${pageSize === 100 ? 'selected' : ''}>100</option>
                    </select>
                </div>
            </div>`;
        }

        container.innerHTML = `
        <div class="infra-playbooks-wrap">
            <div class="infra-playbook-toolbar">
                <div class="infra-playbook-search-row">
                    <div class="search-input-wrapper">
                        <i class="fa-solid fa-magnifying-glass search-icon"></i>
                        <input type="text" id="infra-playbook-search-input" placeholder="Search by malware (Cobalt Strike, Havoc, Supershell, Gophish) or query syntax..." value="${esc(q)}" autocomplete="off">
                    </div>
                    <span class="infra-playbook-count-badge"><strong>${total}</strong> queries ${totalPages > 1 ? `&bull; Page ${page} of ${totalPages}` : ''}</span>
                    <button type="button" class="infra-hunt-btn pb-add-query" id="pb-add-query"><i class="fa-solid fa-plus" aria-hidden="true"></i> Add query</button>
                </div>

                <div class="infra-playbook-filters">
                    <div class="filter-group">
                        <span class="filter-caption">TARGET ENGINE</span>
                        <div class="filter-chips" id="infra-playbook-engine-chips">
                            ${engineOptions.map(e => `
                                <button type="button" class="filter-chip ${engine === e ? 'active' : ''}" data-pb-engine="${e}">
                                     ${e === 'all' ? 'All Engines' : e.toUpperCase()} ${e !== 'all' && enginesAgg[e] ? `(${enginesAgg[e]})` : ''}
                                </button>
                            `).join('')}
                        </div>
                    </div>

                    <div class="filter-group pb-category-row">
                        <label class="filter-caption" for="pb-category-select">THREAT CATEGORY</label>
                        <select id="pb-category-select">${[...new Set([...catOptions, ...Object.keys(categoriesAgg)])].map(c => `<option value="${esc(c)}" ${category === c ? 'selected' : ''}>${c === 'all' ? 'All categories' : c}${c !== 'all' && categoriesAgg[c] ? ` (${categoriesAgg[c]})` : ''}</option>`).join('')}</select>
                    </div>

                    ${enginePresetHubHtml}
                </div>
            </div>

            <div class="infra-playbook-cards-grid">
                ${items.length ? items.map(item => renderSingleQueryCard(item, true)).join('') : '<div class="infra-hunt-empty">No C2 playbooks matched this filter. Try a different keyword or category.</div>'}
            </div>

            ${paginationHtml}
        </div>`;

        // Bind filter events
        const searchInput = id('infra-playbook-search-input');
        if (searchInput) {
            let debounceTimer;
            searchInput.oninput = () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    state.playbooks.q = searchInput.value.trim();
                    state.playbooks.page = 1;
                    loadPlaybooks();
                }, 300);
            };
            searchInput.onkeydown = e => {
                if (e.key === 'Enter') {
                    clearTimeout(debounceTimer);
                    state.playbooks.q = searchInput.value.trim();
                    state.playbooks.page = 1;
                    loadPlaybooks();
                }
            };
        }

        container.querySelectorAll('[data-pb-engine]').forEach(btn => {
            btn.onclick = () => {
                state.playbooks.engine = btn.dataset.pbEngine;
                state.playbooks.page = 1;
                // If switching engine, clear query if it's engine-specific label:
                if (state.playbooks.q.startsWith('label:') || state.playbooks.q.startsWith('title LIKE')) {
                    state.playbooks.q = '';
                }
                loadPlaybooks();
            };
        });

        container.querySelectorAll('[data-pb-category]').forEach(btn => {
            btn.onclick = () => {
                state.playbooks.category = btn.dataset.pbCategory;
                state.playbooks.page = 1;
                loadPlaybooks();
            };
        });
        container.querySelector('#pb-category-select')?.addEventListener('change', event => {
            state.playbooks.category = event.target.value;
            state.playbooks.page = 1;
            loadPlaybooks();
        });

        container.querySelectorAll('[data-pb-set-q]').forEach(btn => {
            btn.onclick = () => {
                state.playbooks.q = btn.dataset.pbSetQ;
                state.playbooks.page = 1;
                loadPlaybooks();
            };
        });

        const resetBtn = id('pb-reset-filter');
        if (resetBtn) {
            resetBtn.onclick = () => {
                state.playbooks.q = '';
                state.playbooks.page = 1;
                loadPlaybooks();
            };
        }

        const etugenSelect = id('pb-etugen-label-select');
        if (etugenSelect) {
            etugenSelect.onchange = () => {
                state.playbooks.q = etugenSelect.value ? `label:${etugenSelect.value}` : '';
                state.playbooks.page = 1;
                loadPlaybooks();
            };
        }

        // Bind pagination events
        container.querySelectorAll('[data-pb-page]').forEach(btn => {
            btn.onclick = () => {
                const target = parseInt(btn.dataset.pbPage, 10);
                if (target && target !== state.playbooks.page && target >= 1 && target <= totalPages) {
                    state.playbooks.page = target;
                    loadPlaybooks();
                    const wrap = container.querySelector('.infra-playbooks-wrap');
                    if (wrap) wrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            };
        });

        const pageSizeSelect = id('infra-playbook-pagesize');
        if (pageSizeSelect) {
            pageSizeSelect.onchange = () => {
                state.playbooks.pageSize = parseInt(pageSizeSelect.value, 10) || 25;
                state.playbooks.page = 1;
                loadPlaybooks();
            };
        }

        bindInteractive(container);
        container.querySelector('#pb-add-query')?.addEventListener('click', () => openQueryEditor());
        container.querySelectorAll('[data-pb-edit]').forEach(button => button.addEventListener('click', () => {
            openQueryEditor(state.playbooks.items.find(item => item.id === button.dataset.pbEdit));
        }));
    }

    function openQueryEditor(item = null) {
        let dialog = id('pb-query-dialog');
        if (!dialog) {
            dialog = document.createElement('dialog');
            dialog.id = 'pb-query-dialog';
            dialog.className = 'pb-query-dialog';
            document.body.appendChild(dialog);
        }
        dialog.innerHTML = `<form id="pb-query-form">
            <div class="pb-dialog-head"><div><small>C2 HUNTING CATALOG</small><h3>${item ? 'Edit hunting query' : 'Add hunting query'}</h3></div><button type="button" data-pb-close aria-label="Close editor"><i class="fa-solid fa-xmark"></i></button></div>
            <div class="pb-dialog-fields"><label>Family or tool<input name="family" maxlength="200" required value="${esc(item?.family || '')}"></label>
            <label>Engine<select name="engine" required>${['shodan','censys','netlas','urlscan','fofa','zoomeye','validin','etugen','silentpush'].map(engine => `<option value="${engine}" ${item?.engine === engine ? 'selected' : ''}>${engine.toUpperCase()}</option>`).join('')}</select></label>
            <label>Category<input name="category" maxlength="200" value="${esc(item?.category || '')}" placeholder="C2 Framework"></label>
            <label>Technique<input name="technique" maxlength="200" value="${esc(item?.technique || '')}" placeholder="HTTP fingerprint"></label>
            <label class="pb-full">Query<textarea name="query" maxlength="4000" rows="4" required>${esc(item?.query || '')}</textarea></label>
            <label class="pb-full">Notes<input name="notes" maxlength="200" value="${esc(item?.notes || '')}" placeholder="Optional context"></label></div>
            <p id="pb-dialog-feedback" role="status"></p>
            <div class="pb-dialog-actions">${item ? '<button type="button" data-pb-delete>Delete</button>' : ''}<span></span><button type="button" data-pb-close>Cancel</button><button type="submit">Save query</button></div>
        </form>`;
        dialog.querySelectorAll('[data-pb-close]').forEach(button => button.onclick = () => dialog.close());
        dialog.querySelector('[data-pb-delete]')?.addEventListener('click', async () => {
            if (!confirm('Delete this hunting query?')) return;
            try {
                await api(`/api/infra-hunts/playbooks/${encodeURIComponent(item.id)}`, {method: 'DELETE'});
                dialog.close(); await loadPlaybooks();
            } catch (error) { id('pb-dialog-feedback').textContent = error.message; }
        });
        dialog.querySelector('form').onsubmit = async event => {
            event.preventDefault();
            const form = event.target;
            const payload = Object.fromEntries(new FormData(form));
            try {
                await api(`/api/infra-hunts/playbooks${item ? '/' + encodeURIComponent(item.id) : ''}`, {method: item ? 'PUT' : 'POST', body: JSON.stringify(payload)});
                dialog.close(); state.playbooks.page = 1; await loadPlaybooks();
            } catch (error) { id('pb-dialog-feedback').textContent = error.message; }
        };
        dialog.showModal();
        dialog.querySelector('input[name="family"]').focus();
    }

    function renderDashboard(data, isFullResult = false) {
        const root = id('infra-hunt-workspace');
        if (!root || !data) return;

        const features = data.features || {};
        const queries = data.queries || [];
        const candidates = data.candidates || [];
        const c2Matches = data.c2_matches || [];

        const sigCount = features.count ?? (features.ranked ? features.ranked.length : 0);
        const qCount = queries.length;
        const candCount = candidates.length;
        const tabs = [
            { id: 'queries', label: 'Queries', icon: 'fa-terminal', count: qCount },
            { id: 'signals', label: 'Fingerprints', icon: 'fa-fingerprint', count: sigCount },
            { id: 'candidates', label: 'Candidates', icon: 'fa-network-wired', count: isFullResult ? candCount : null }
        ];

        root.innerHTML = `
            <header class="infra-results-header">
                <h3>Hunt results</h3>
                <code>${esc(state.seed)}</code>
            </header>

            <nav class="infra-hunt-tabs" aria-label="Hunt result views">
                ${tabs.map(t => `
                    <button type="button" class="infra-hunt-tab ${state.pane === t.id ? 'active' : ''}" data-hunt-pane="${t.id}" aria-pressed="${state.pane === t.id}" aria-controls="infra-view-${t.id}">
                        <i class="fa-solid ${t.icon}" aria-hidden="true"></i> ${t.label}${t.count === null ? '' : ` <span class="tab-badge">${esc(t.count)}</span>`}
                    </button>
                `).join('')}
            </nav>

            <div id="infra-view-queries" class="infra-hunt-pane ${state.pane === 'queries' ? 'active' : ''}" data-hunt-body="queries">
                ${renderQueryDeck(queries, c2Matches)}
            </div>

            <div id="infra-view-signals" class="infra-hunt-pane ${state.pane === 'signals' ? 'active' : ''}" data-hunt-body="signals">
                ${renderSignalsDeck(features)}
            </div>

            <div id="infra-view-candidates" class="infra-hunt-pane ${state.pane === 'candidates' ? 'active' : ''}" data-hunt-body="candidates">
                ${renderCandidates(candidates, !isFullResult)}
            </div>

        `;

        root.querySelectorAll('[data-hunt-pane]').forEach(button => {
            button.onclick = () => {
                state.pane = button.dataset.huntPane;
                root.querySelectorAll('[data-hunt-pane]').forEach(node => {
                    const active = node.dataset.huntPane === state.pane;
                    node.classList.toggle('active', active);
                    node.setAttribute('aria-pressed', String(active));
                });
                root.querySelectorAll('[data-hunt-body]').forEach(node => node.classList.toggle('active', node.dataset.huntBody === state.pane));
            };
        });

        bindInteractive(root);
    }

    function openC2HuntingCatalog() {
        if (!id('infra-playbooks-content')) return;
        loadPlaybooks();
    }

    async function copyToClipboard(text) {
        if (!text) return false;
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (_) {}
        try {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-9999px';
            textarea.style.top = '-9999px';
            textarea.setAttribute('readonly', '');
            document.body.appendChild(textarea);
            textarea.select();
            const success = document.execCommand('copy');
            document.body.removeChild(textarea);
            return success;
        } catch (e) {
            return false;
        }
    }

    function bindInteractive(root) {
        root.querySelectorAll('[data-copy-text]').forEach(button => {
            button.onclick = async () => {
                const text = button.dataset.copyText;
                if (!text) return;
                if (!await copyToClipboard(text)) return;
                const originalHtml = button.innerHTML;
                button.innerHTML = button.hasAttribute('data-icon-only')
                    ? '<i class="fa-solid fa-check" aria-hidden="true"></i>'
                    : '<i class="fa-solid fa-check" aria-hidden="true"></i> Copied!';
                button.setAttribute('aria-label', 'Copied query');
                button.title = 'Copied query';
                button.classList.add('copied');
                setTimeout(() => {
                    button.innerHTML = originalHtml;
                    button.setAttribute('aria-label', 'Copy query');
                    button.title = 'Copy query';
                    button.classList.remove('copied');
                }, 1500);
            };
        });

        root.querySelectorAll('[data-infra-pivot]').forEach(btn => {
            btn.onclick = event => {
                event.preventDefault();
                const pivotVal = btn.dataset.infraPivot;
                if (!pivotVal) return;
                const input = id('ioc-input');
                if (input) input.value = pivotVal;
                preview();
            };
        });
    }

    function download(name, text, type) {
        const link = document.createElement('a');
        link.href = URL.createObjectURL(new Blob([text], { type }));
        link.download = name;
        link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 500);
    }

    function exportData(format) {
        const items = state.result?.candidates || [];
        if (!items.length) return;
        if (format === 'json') {
            return download(`infra-hunt-${Date.now()}.json`, JSON.stringify(state.result, null, 2), 'application/json');
        }
        const rows = [
            ['value', 'type', 'score', 'confidence', 'providers', 'evidence'],
            ...items.map(item => [
                item.value,
                item.value_type,
                item.score,
                item.confidence,
                (item.providers || []).join('|'),
                (item.evidence || []).map(e => `${e.kind}:${e.value}`).join('|')
            ])
        ];
        download(`infra-hunt-${Date.now()}.csv`, rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n'), 'text/csv');
    }

    function clearHunt() {
        state.request?.abort();
        state.request = null;
        state.preview = null;
        state.result = null;
        state.seed = '';
        const root = id('infra-hunt-workspace');
        root.replaceChildren(id('infra-hunt-empty').content.cloneNode(true));
        updateButtons();
        status('');
    }

    function invalidatePreview() {
        if (state.request || (state.seed && state.seed !== seed())) clearHunt();
    }

    function isIocSearchActive() {
        const sc = document.querySelector('.search-container');
        if (!sc || sc.style.display === 'none') return false;
        const sv = id('settings-view');
        if (sv && sv.style.display === 'block') return false;
        const hp = id('mantis-home-pane');
        if (hp && hp.style.display === 'flex') return false;
        return true;
    }

    function visible() {
        const searchActive = isIocSearchActive();
        const active = searchActive && Boolean(document.querySelector('.nav-item[data-tab="infra"].active'));
        if (active) {
            refreshProviderBadges();
        }
        const panel = id('infra-hunt-panel');
        if (panel) {
            panel.classList.toggle('active', active);
            if (!active) {
                panel.style.display = 'none';
            } else {
                panel.style.display = 'block';
            }
        }
        document.body.classList.toggle('infra-hunt-mode', active);
        const searchBtn = id('btn-search');
        const input = id('ioc-input');
        if (active) {
            input.placeholder = 'IP, domain, ASN, CIDR, fingerprint, or provider query';
            input.setAttribute('aria-label', 'Infrastructure indicator or provider query');
            if (!searchBtn.dataset.origHtml) searchBtn.dataset.origHtml = searchBtn.innerHTML;
            searchBtn.title = 'Enrich this indicator and preview infrastructure queries';
            updateButtons();
        } else if (searchBtn?.dataset.origHtml) {
            if (searchBtn.dataset.infraBusy === 'true') searchBtn.disabled = false;
            delete searchBtn.dataset.infraBusy;
            searchBtn.innerHTML = searchBtn.dataset.origHtml;
            searchBtn.title = '';
            input.setAttribute('aria-label', 'Indicator or keyword');
        }
    }

    function init() {
        id('infra-hunt-run')?.addEventListener('click', run);
        id('ioc-input')?.addEventListener('input', invalidatePreview);

        id('btn-search')?.addEventListener('click', event => {
            if (document.body.classList.contains('infra-hunt-mode')) {
                event.preventDefault();
                event.stopImmediatePropagation();
                preview();
            }
        }, true);

        id('ioc-input')?.addEventListener('keydown', event => {
            if (event.key === 'Enter' && !event.isComposing && document.body.classList.contains('infra-hunt-mode')) {
                event.preventDefault();
                event.stopImmediatePropagation();
                if (!state.request) preview();
            }
        }, true);

        id('btn-reset')?.addEventListener('click', () => {
            if (document.body.classList.contains('infra-hunt-mode')) clearHunt();
        });

        document.querySelectorAll('[data-infra-example]').forEach(button => {
            button.addEventListener('click', () => {
                const input = id('ioc-input');
                input.value = button.dataset.infraExample;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.focus();
            });
        });

        id('infra-hunt-signal-count')?.addEventListener('change', () => {
            if (seed()) preview();
        });

        document.querySelectorAll('.infra-provider-check').forEach(check => {
            check.addEventListener('change', () => {
                if (!check.checked) {
                    check.dataset.userUnchecked = 'true';
                } else {
                    delete check.dataset.userUnchecked;
                }
                refreshProviderBadges();
                if (seed() && (state.preview || state.request)) {
                    if (providers().length) preview();
                    else clearHunt();
                }
            });
        });

        document.addEventListener('click', event => {
            if (event.target.closest('#infra-export-json')) exportData('json');
            if (event.target.closest('#infra-export-csv')) exportData('csv');
        });

        document.querySelectorAll('.ioc-tab').forEach(tab => tab.addEventListener('click', () => setTimeout(visible)));
        new MutationObserver(visible).observe(document.body, { subtree: false, attributes: true, attributeFilter: ['class'] });
        const searchBox = document.querySelector('.search-container');
        if (searchBox) {
            new MutationObserver(visible).observe(searchBox, { attributes: true, attributeFilter: ['style', 'class'] });
        }
        if (id('settings-view')) {
            new MutationObserver(visible).observe(id('settings-view'), { attributes: true, attributeFilter: ['style', 'class'] });
        }
        const infraNav = document.querySelector('.nav-item[data-tab="infra"]');
        if (infraNav) {
            new MutationObserver(visible).observe(infraNav, { attributes: true, attributeFilter: ['class'] });
        }
        clearHunt();
        refreshProviderBadges();
        visible();
        window.syncInfraHuntVisibility = visible;
        window.runInfraHuntPreview = preview;
    }

    // Available before app.js restores a saved navigation tab on DOMContentLoaded.
    window.openC2HuntingCatalog = openC2HuntingCatalog;
    document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', init) : init();
})();
