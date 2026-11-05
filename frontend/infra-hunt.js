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
        serverProviders: [],
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

    function updateButtons(isBusy = false) {
        const runButton = id('infra-hunt-run');
        if (runButton) runButton.disabled = isBusy || (!state.preview && !state.result);
        const searchBtn = id('btn-search');
        if (searchBtn && document.body.classList.contains('infra-hunt-mode')) {
            searchBtn.disabled = isBusy;
            searchBtn.innerHTML = isBusy
                ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Hunting…'
                : '<i class="fa-solid fa-crosshairs"></i> Săn hạ tầng';
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
            label.classList.toggle('configured', configured);
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
                badge.textContent = configured ? (provider === 'greynoise' && !localKeys.greynoise_key ? 'cộng đồng' : 'sẵn sàng') : 'chưa có khóa';
                badge.title = configured ? 'Engine sẵn sàng để truy vấn' : 'Thêm khóa API trong Cài đặt để bật engine này';
            }
        });
    }

    async function preview() {
        const value = seed();
        if (!value) return status('Nhập seed (IP, tên miền, ASN, CIDR, hoặc dấu vân tay chứng chỉ) để tạo truy vấn.', 'error');
        if (!providers().length) return status('Chọn ít nhất một engine săn tìm.', 'error');

        state.preview = null;
        state.result = null;
        updateButtons(true);
        status('<i class="fa-solid fa-circle-notch fa-spin"></i> Đang làm giàu seed và trích xuất dấu vân tay chính xác cao…', 'running');

        try {
            state.preview = await api('/api/infra-hunts/preview', { method: 'POST', body: JSON.stringify(payload(value)) });
            state.seed = value;
            state.pane = 'queries';
            renderDashboard(state.preview, false);
            const count = state.preview.features?.count || 0;
            const qCount = state.preview.queries?.length || 0;
            const c2Matches = state.preview.c2_matches?.length || 0;
            const matchTxt = c2Matches > 0 ? ` · <span style="color:#ffd166;"><i class="fa-solid fa-triangle-exclamation"></i> ${c2Matches} hồ sơ mối đe dọa C2 khớp</span>` : '';
            status(`<strong>Bộ truy vấn săn sẵn:</strong> Trích xuất ${count} tín hiệu dấu vân tay, tạo ${qCount} truy vấn tìm kiếm chính xác${matchTxt}.`);
        } catch (error) {
            status(`Lỗi săn tìm: ${esc(error.message)}`, 'error');
        } finally {
            updateButtons(false);
        }
    }

    async function run() {
        const value = seed();
        if (!value) return status('Nhập chỉ số seed trước khi tương quan hạ tầng.', 'error');
        if (!providers().length) return status('Chọn ít nhất một engine săn tìm.', 'error');

        updateButtons(true);
        status('<i class="fa-solid fa-circle-notch fa-spin"></i> Đang tương quan hạ tầng, chấm điểm ứng viên và phân tích điểm xoay…', 'running');

        try {
            state.result = await api('/api/infra-hunts/run', { method: 'POST', body: JSON.stringify(payload(value)) });
            state.seed = value;
            state.pane = 'candidates';
            renderDashboard(state.result, true);
            const candidatesCount = state.result.candidates?.length || 0;
            status(`<strong>Tương quan hoàn tất:</strong> Phát hiện ${candidatesCount} nút hạ tầng tương quan.`);
        } catch (error) {
            status(`Lỗi mở rộng: ${esc(error.message)}`, 'error');
        } finally {
            updateButtons(false);
        }
    }

    const stat = (label, value, icon = '') => `
        <div class="infra-hunt-stat">
            <span>${icon ? `<i class="${icon}"></i> ` : ''}${esc(label)}</span>
            <strong>${esc(value ?? 0)}</strong>
        </div>`;

    function getSignalLabel(kind) {
        const mapping = {
            'cert_serial': 'Số serial TLS',
            'cert_subject_dn': 'Tên phân biệt chủ thể',
            'cert_issuer_dn': 'Tên phân biệt tổ chức phát hành',
            'cert_fingerprint_sha256': 'Dấu vân tay Cert SHA-256',
            'cert_fingerprint_sha1': 'Dấu vân tay Cert SHA-1',
            'jarm': 'Dấu vân tay JARM TLS',
            'http_server': 'Header HTTP Server',
            'http_title': 'Tiêu đề trang HTML',
            'http_status': 'Mã phản hồi HTTP',
            'favicon_md5': 'Hash MD5 Favicon',
            'favicon_mmh3': 'Hash Murmur3 Favicon',
            'asn': 'Hệ thống tự trị (ASN)',
            'autonomous_system': 'Số AS định tuyến',
            'port': 'Cổng dịch vụ bị lộ',
            'ports': 'Danh sách cổng mở',
            'hostname': 'Tên máy chủ liên quan / PTR',
            'san_domain': 'Tên thay thế chủ thể (SAN)',
            'reverse_dns': 'Bản ghi DNS ngược',
            'ip': 'Địa chỉ IP máy chủ'
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
                            <strong>🎯 Khớp quy kết mối đe dọa: ${esc(m.family)}</strong>
                            <span>${esc(m.category)} · Khớp qua ${esc(m.matched_by)} (<code>${esc(m.matched_value)}</code>)</span>
                            <p>${esc(m.description)}</p>
                        </div>
                        <span class="infra-confidence high">${esc(m.confidence)} ĐỘ TIN CẬY</span>
                    </div>
                    ${(m.recommended_queries && m.recommended_queries.length) ? `
                        <div class="infra-c2-subqueries">
                            <span class="infra-subqueries-title"><i class="fa-solid fa-crosshairs"></i> Truy vấn săn ${esc(m.family)} được tuyển chọn:</span>
                            <div class="infra-query-deck mini">
                                ${m.recommended_queries.map(rq => renderSingleQueryCard(rq)).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>`;
    }

    function renderSingleQueryCard(item) {
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
        const strength = item.estimated_strength ?? 4;
        const extUrl = item.external_url || '';
        const notes = item.notes || '';
        const technique = item.technique || '';
        const family = item.family || '';
        const isEtugen = provider === 'etugen';

        return `
        <article class="infra-query-card" data-engine="${esc(provider)}">
            <header>
                <div class="infra-engine-info">
                    <span class="infra-engine-badge is-${esc(provider)}">${esc(providerName)}</span>
                    ${isOpenDir ? `<span class="infra-opendir-badge"><i class="fa-solid fa-folder-open"></i> Open-Directory</span>` : ''}
                    ${family ? `<span class="infra-family-badge">${esc(family)}</span>` : ''}
                    ${technique ? `<span class="infra-mode-badge">${esc(technique)}</span>` : (!isOpenDir ? `<span class="infra-mode-badge">${esc((item.mode || 'Search').replaceAll('_', ' '))}</span>` : '')}
                </div>
                <div class="infra-strength-badge" title="Độ cụ thể truy vấn">
                    ${notes ? `<small class="infra-notes">${esc(notes)}</small>` : `Độ đặc trưng: <strong>${esc(strength)}/5</strong>`}
                </div>
            </header>
            <div class="infra-query-body">
                <pre class="infra-query-code"><code>${esc(item.query)}</code></pre>
            </div>
            ${signals.length ? `
            <div class="infra-query-signals">
                <span class="infra-signals-label">Tín hiệu kết hợp:</span>
                ${signals.map(s => `<span class="infra-hunt-chip" title="Weight ${esc(s.weight)}">${esc(getSignalLabel(s.kind))}: <code>${esc(s.value)}</code></span>`).join('')}
            </div>` : ''}
            <div class="infra-query-actions">
                <button class="infra-hunt-btn query-copy-btn" data-copy-text="${esc(item.query)}">
                    <i class="fa-solid fa-copy"></i> Sao chép truy vấn
                </button>
                ${extUrl ? `
                <a href="${esc(extUrl)}" target="_blank" rel="noopener noreferrer" class="infra-hunt-btn external-link">
                    <i class="fa-solid fa-arrow-up-right-from-square"></i> Open in ${isEtugen ? (isOpenDir ? 'Etugen Trashpile' : 'Etugen Search') : (provider === 'zoomeye' ? 'ZoomEye' : esc(providerName))}
                </a>` : ''}
            </div>
        </article>`;
    }

    function renderQueryDeck(queries, c2Matches = []) {
        let alertHtml = renderC2Matches(c2Matches);

        if (!queries || !queries.length) {
            return alertHtml + '<div class="infra-hunt-empty"><i class="fa-solid fa-magnifying-glass-arrow-right" style="font-size:1.8rem;margin-bottom:10px;opacity:.5;"></i><div>Không thể tạo truy vấn từ tín hiệu seed. Hãy chọn thêm engine hoặc dùng IP/domain có HTTP/TLS lộ ra.</div></div>';
        }

        return alertHtml + `<div class="infra-query-deck">${queries.map(item => renderSingleQueryCard(item)).join('')}</div>`;
    }

    function renderSignalsDeck(features) {
        if (!features || !features.ranked || !features.ranked.length) {
            return '<div class="infra-hunt-empty"><i class="fa-solid fa-fingerprint" style="font-size:1.8rem;margin-bottom:10px;opacity:.5;"></i><div>Không trích xuất được dấu vân tay hoặc tín hiệu siêu dữ liệu đặc trưng từ seed này.</div></div>';
        }

        const categories = features.categories || {};
        const catConfig = [
            { id: 'certificates', label: 'Dấu vân tay TLS & Chứng chỉ', icon: 'fa-shield-halved', color: '#4cc9f0' },
            { id: 'web', label: 'Chữ ký Web & Ứng dụng', icon: 'fa-globe', color: '#ffd166' },
            { id: 'network', label: 'Mạng & Hệ thống tự trị (ASN)', icon: 'fa-network-wired', color: '#7209b7' },
            { id: 'hosts', label: 'Hạ tầng & Máy chủ liên kết', icon: 'fa-server', color: '#06d6a0' }
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
                <div class="infra-signal-table-wrap">
                    <table class="infra-signal-table">
                        <thead>
                            <tr>
                                <th>Dấu vân tay / Thuộc tính</th>
                                <th>Giá trị quan sát</th>
                                <th style="text-align:right;">Hành động</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${list.map(s => {
                                const isDistinctive = s.distinctive || (s.weight && s.weight >= 2);
                                return `
                                <tr>
                                    <td class="signal-name">
                                        <div class="signal-kind-title">${esc(getSignalLabel(s.kind))}</div>
                                        <span class="infra-distinct-chip ${isDistinctive ? 'distinctive' : 'context'}">
                                            ${isDistinctive ? 'Độ đặc trưng cao' : 'Ngữ cảnh'}
                                        </span>
                                    </td>
                                    <td class="signal-val">
                                        <code class="infra-hunt-code">${esc(s.value)}</code>
                                    </td>
                                    <td class="signal-action" style="text-align:right;">
                                        <button class="infra-hunt-btn mini-btn" data-copy-text="${esc(s.value)}" title="Sao chép giá trị tín hiệu">
                                            <i class="fa-solid fa-copy"></i>
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
                    <h4>Sẵn sàng chạy tương quan</h4>
                    <p>Nhấp <strong>Tương quan ứng viên</strong> ở trên để truy vấn các engine đang hoạt động, chấm điểm nút hạ tầng chồng lấp và xác định máy chủ C2/staging tương quan.</p>
                </div>`;
            }
            return `
            <div class="infra-hunt-empty">
                <i class="fa-solid fa-circle-nodes" style="font-size:2rem;margin-bottom:12px;opacity:.5;"></i>
                <h4>Không phát hiện cơ sở hạ tầng chồng lấp</h4>
                <p>Không có nút ứng viên nào đáp ứng ngưỡng tương quan. Hãy dùng <strong>Bộ truy vấn săn</strong> để xoay trục trực tiếp trên Shodan, Censys hoặc FOFA.</p>
            </div>`;
        }

        return `
        <div class="infra-candidates-wrap">
            <div class="infra-candidates-toolbar">
                <span class="infra-toolbar-title"><i class="fa-solid fa-server"></i> Nút tương quan (${candidates.length})</span>
                <div class="infra-export-actions">
                    <button id="infra-export-json" class="infra-hunt-btn"><i class="fa-solid fa-file-code"></i> Xuất JSON</button>
                    <button id="infra-export-csv" class="infra-hunt-btn"><i class="fa-solid fa-file-csv"></i> Xuất CSV</button>
                </div>
            </div>
            <div class="infra-hunt-table-wrap dark-scroll">
                <table class="infra-hunt-table">
                    <thead>
                        <tr>
                            <th>Chỉ số ứng viên</th>
                            <th>Loại</th>
                            <th>Điểm liên kết</th>
                            <th>Độ tin cậy</th>
                            <th>Quan sát tại</th>
                            <th>Bằng chứng tương quan</th>
                            <th style="text-align:right;">Xoay trục</th>
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
                                <button class="infra-hunt-btn pivot-btn" data-infra-pivot="${esc(item.value)}" title="Xoay trục và săn tìm cơ sở hạ tầng cho chỉ số này">
                                    <i class="fa-solid fa-crosshairs"></i> Xoay trục
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
            container.innerHTML = '<div class="infra-hunt-empty"><i class="fa-solid fa-circle-notch fa-spin" style="font-size:2rem;color:var(--accent);"></i><div style="margin-top:10px;">Đang tải sách chiến thuật C2…</div></div>';
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
            state.playbooks.items = data.items || [];
            state.playbooks.total = data.total || 0;
            state.playbooks.aggregates = data.aggregates || {};
            renderPlaybooksView();
        } catch (err) {
            if (container) {
                container.innerHTML = `<div class="infra-hunt-empty"><span style="color:#ff8f8f;">Tải sách chiến thuật thất bại: ${esc(err.message)}</span></div>`;
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

        const engineOptions = ['all', 'validin', 'etugen', 'silentpush', 'zoomeye', 'shodan', 'censys', 'netlas', 'urlscan', 'fofa'];
        const catOptions = ['all', 'C2 Framework', 'Exposed OpenDir / Secrets', 'Webshell', 'Hacktool', 'Info Stealer', 'RAT', 'Favicon Fingerprint', 'Phishing Framework', 'Banking Trojan', 'APT Infrastructure', 'Ransomware', 'Botnet', 'Tunnel / Proxy'];
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
                    Hiển thị <strong>${startItem}&ndash;${endItem}</strong> trong <strong>${total}</strong> playbook (Trang <strong>${page}</strong> / <strong>${totalPages}</strong>)
                </div>
                <div class="infra-playbook-pagination-controls">
                    <button type="button" class="infra-page-btn" ${page <= 1 ? 'disabled' : ''} data-pb-page="1" title="Trang đầu">
                        <i class="fa-solid fa-angles-left"></i>
                    </button>
                    <button type="button" class="infra-page-btn" ${page <= 1 ? 'disabled' : ''} data-pb-page="${page - 1}" title="Trang trước">
                        <i class="fa-solid fa-chevron-left"></i> Trước
                    </button>
                    ${pageNums.map(p => {
                        if (p === '...') {
                            return `<span class="infra-page-ellipsis">&hellip;</span>`;
                        }
                        return `<button type="button" class="infra-page-btn ${p === page ? 'active' : ''}" data-pb-page="${p}">${p}</button>`;
                    }).join('')}
                    <button type="button" class="infra-page-btn" ${page >= totalPages ? 'disabled' : ''} data-pb-page="${page + 1}" title="Trang tiếp">
                        Tiếp <i class="fa-solid fa-chevron-right"></i>
                    </button>
                    <button type="button" class="infra-page-btn" ${page >= totalPages ? 'disabled' : ''} data-pb-page="${totalPages}" title="Trang cuối">
                        <i class="fa-solid fa-angles-right"></i>
                    </button>
                </div>
                <div class="infra-playbook-pagesize-select">
                    <span>Mỗi trang:</span>
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
                        <input type="text" id="infra-playbook-search-input" placeholder="Tìm theo mã độc (Cobalt Strike, Havoc, Supershell, Gophish) hoặc cú pháp truy vấn..." value="${esc(q)}" autocomplete="off">
                    </div>
                    <span class="infra-playbook-count-badge">Tìm thấy <strong>${total}</strong> dork được tuyển chọn ${totalPages > 1 ? `&bull; Trang ${page} / ${totalPages}` : ''}</span>
                </div>

                <div class="infra-playbook-filters">
                    <div class="filter-group">
                        <span class="filter-caption">ENGINE MỤC TIÊU</span>
                        <div class="filter-chips" id="infra-playbook-engine-chips">
                            ${engineOptions.map(e => `
                                <button type="button" class="filter-chip ${engine === e ? 'active' : ''}" data-pb-engine="${e}">
                                     ${e === 'all' ? 'Tất cả engine' : (e === 'etugen' ? 'ETUGEN (OPEN-DIR)' : (e === 'silentpush' ? 'SILENT PUSH' : e.toUpperCase()))} ${e !== 'all' && enginesAgg[e] ? `(${enginesAgg[e]})` : ''}
                                </button>
                            `).join('')}
                        </div>
                    </div>

                    <div class="filter-group">
                        <span class="filter-caption">DANH MỤC MỐI ĐE DỌA</span>
                        <div class="filter-chips" id="infra-playbook-cat-chips">
                            ${catOptions.map(c => `
                                <button type="button" class="filter-chip ${category === c ? 'active' : ''}" data-pb-category="${c}">
                                    ${c === 'all' ? 'Tất cả danh mục' : c} ${c !== 'all' && categoriesAgg[c] ? `(${categoriesAgg[c]})` : ''}
                                </button>
                            `).join('')}
                        </div>
                    </div>

                    ${enginePresetHubHtml}
                </div>
            </div>

            <div class="infra-playbook-cards-grid">
                ${items.length ? items.map(item => renderSingleQueryCard(item)).join('') : '<div class="infra-hunt-empty">Không có sách chiến thuật C2 nào khớp. Hãy thử từ khóa hoặc danh mục khác.</div>'}
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

        container.querySelectorAll('[data-pb-set-q]').forEach(btn => {
            btn.onclick = () => {
                state.playbooks.q = btn.dataset.pbSetQ;
                state.playbooks.page = 1;
                loadPlaybooks();
            };
        });

        const labelSelect = id('pb-etugen-label-select');
        if (labelSelect) {
            labelSelect.onchange = () => {
                const val = labelSelect.value;
                state.playbooks.engine = 'etugen';
                state.playbooks.category = 'all';
                state.playbooks.q = val ? (val === 'open-dir' ? 'Index of' : `label:${val}`) : '';
                state.playbooks.page = 1;
                loadPlaybooks();
            };
        }

        const resetBtn = id('pb-reset-filter');
        if (resetBtn) {
            resetBtn.onclick = () => {
                state.playbooks.q = '';
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
    }

    function renderDashboard(data, isFullResult = false) {
        const root = id('infra-hunt-workspace');
        if (!root || !data) return;

        const summary = data.summary || {};
        const features = data.features || {};
        const queries = data.queries || [];
        const candidates = data.candidates || [];
        const c2Matches = data.c2_matches || [];

        const sigCount = features.count ?? (features.ranked ? features.ranked.length : 0);
        const qCount = queries.length;
        const candCount = candidates.length;
        const activeEngines = providers().length;

        const tabs = [
            { id: 'queries', label: 'Bộ truy vấn săn', icon: 'fa-terminal', count: qCount },
            { id: 'signals', label: 'Dấu vân tay & Tín hiệu', icon: 'fa-fingerprint', count: sigCount },
            { id: 'candidates', label: 'Hạ tầng tương quan', icon: 'fa-network-wired', count: candCount },
            { id: 'playbooks', label: 'Thư viện sách chiến thuật C2', icon: 'fa-book-skull', count: '900+' }
        ];

        root.innerHTML = `
            <div class="infra-hunt-summary">
                ${stat('Tín hiệu đặc trưng', sigCount, 'fa-solid fa-fingerprint')}
                ${stat('Truy vấn săn', qCount, 'fa-solid fa-terminal')}
                ${stat('Engine mục tiêu', activeEngines, 'fa-solid fa-satellite-dish')}
                ${stat('Nút tương quan', candCount, 'fa-solid fa-circle-nodes')}
            </div>

            <div class="infra-hunt-tabs">
                ${tabs.map(t => `
                    <button class="infra-hunt-tab ${state.pane === t.id ? 'active' : ''}" data-hunt-pane="${t.id}">
                        <i class="fa-solid ${t.icon}"></i> ${t.label} <span class="tab-badge">${t.count}</span>
                    </button>
                `).join('')}
            </div>

            <div class="infra-hunt-pane ${state.pane === 'queries' ? 'active' : ''}" data-hunt-body="queries">
                ${renderQueryDeck(queries, c2Matches)}
            </div>

            <div class="infra-hunt-pane ${state.pane === 'signals' ? 'active' : ''}" data-hunt-body="signals">
                ${renderSignalsDeck(features)}
            </div>

            <div class="infra-hunt-pane ${state.pane === 'candidates' ? 'active' : ''}" data-hunt-body="candidates">
                ${renderCandidates(candidates, !isFullResult)}
            </div>

            <div class="infra-hunt-pane ${state.pane === 'playbooks' ? 'active' : ''}" data-hunt-body="playbooks">
                <div id="infra-playbooks-content"></div>
            </div>
        `;

        root.querySelectorAll('[data-hunt-pane]').forEach(button => {
            button.onclick = () => {
                state.pane = button.dataset.huntPane;
                root.querySelectorAll('[data-hunt-pane]').forEach(node => node.classList.toggle('active', node.dataset.huntPane === state.pane));
                root.querySelectorAll('[data-hunt-body]').forEach(node => node.classList.toggle('active', node.dataset.huntBody === state.pane));
                if (state.pane === 'playbooks') {
                    loadPlaybooks();
                }
            };
        });

        if (state.pane === 'playbooks') {
            loadPlaybooks();
        }

        bindInteractive(root);
    }

    function openPlaybooksDirectly() {
        state.pane = 'playbooks';
        state.playbooks.page = 1;
        renderDashboard(state.preview || { features: { count: 0 }, queries: [], candidates: [] }, false);
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
                await copyToClipboard(text);
                const originalHtml = button.innerHTML;
                button.innerHTML = '<i class="fa-solid fa-check"></i> Đã sao chép!';
                button.classList.add('copied');
                setTimeout(() => {
                    button.innerHTML = originalHtml;
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

    function invalidatePreview() {
        if (state.preview && state.preview.seed !== seed()) {
            state.preview = null;
            state.result = null;
            updateButtons(false);
            status('Chỉ số thay đổi. Nhấn <strong>Săn hạ tầng</strong> để phân tích.');
        }
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
        const active = searchActive && Boolean(id('ioc-tab-infra')?.classList.contains('active'));
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
        if (active) {
            if (id('ioc-input')) id('ioc-input').placeholder = 'Nhập IP, tên miền, ASN, CIDR, dấu vân tay chứng chỉ hoặc JARM…';
            if (searchBtn) {
                if (!searchBtn.dataset.origHtml) searchBtn.dataset.origHtml = searchBtn.innerHTML;
                searchBtn.innerHTML = '<i class="fa-solid fa-crosshairs"></i> Săn hạ tầng';
                searchBtn.title = 'Xem trước truy vấn và săn tìm cơ sở hạ tầng cho seed này';
            }
        } else if (searchBtn && searchBtn.dataset.origHtml) {
            searchBtn.innerHTML = searchBtn.dataset.origHtml;
            searchBtn.title = '';
        }
    }

    function init() {
        id('infra-hunt-run')?.addEventListener('click', run);
        id('infra-hunt-open-playbooks')?.addEventListener('click', openPlaybooksDirectly);
        id('ioc-input')?.addEventListener('input', invalidatePreview);

        id('btn-search')?.addEventListener('click', event => {
            if (document.body.classList.contains('infra-hunt-mode')) {
                event.preventDefault();
                event.stopImmediatePropagation();
                preview();
            }
        }, true);

        id('ioc-input')?.addEventListener('keydown', event => {
            if (event.key === 'Enter' && document.body.classList.contains('infra-hunt-mode')) {
                event.preventDefault();
                event.stopImmediatePropagation();
                preview();
            }
        }, true);

        id('btn-reset')?.addEventListener('click', () => {
            if (document.body.classList.contains('infra-hunt-mode')) {
                state.preview = null;
                state.result = null;
                updateButtons(false);
                status('');
                const root = id('infra-hunt-workspace');
                if (root) {
                    root.innerHTML = `
                    <div class="infra-hunt-empty">
                        <i class="fa-solid fa-crosshairs" style="font-size:2rem;margin-bottom:10px;opacity:.5;"></i>
                        <h4>Sẵn sàng săn tìm cơ sở hạ tầng</h4>
                        <p>Nhập IP, tên miền, ASN, CIDR, dấu vân tay chứng chỉ hoặc JARM để trích xuất dấu vân tay và tạo truy vấn.</p>
                        <div style="margin-top:14px;">
                            <button id="infra-hunt-quick-pb" class="infra-hunt-btn primary"><i class="fa-solid fa-book-skull"></i> Duyệt sách chiến thuật mối đe dọa C2 (900+)</button>
                        </div>
                    </div>`;
                    id('infra-hunt-quick-pb')?.addEventListener('click', openPlaybooksDirectly);
                }
            }
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
                if (seed() && state.preview) preview();
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
        if (id('ioc-tab-bar')) {
            new MutationObserver(visible).observe(id('ioc-tab-bar'), { subtree: true, attributes: true, attributeFilter: ['class'] });
        }

        // Set initial empty state with quick link to Playbooks
        const root = id('infra-hunt-workspace');
        if (root && !state.preview && !state.result) {
            root.innerHTML = `
            <div class="infra-hunt-empty">
                <i class="fa-solid fa-crosshairs" style="font-size:2rem;margin-bottom:10px;opacity:.5;"></i>
                <h4>Sẵn sàng săn tìm cơ sở hạ tầng</h4>
                <p>Nhập IP, tên miền, ASN, CIDR, dấu vân tay chứng chỉ hoặc JARM để trích xuất dấu vân tay và tạo truy vấn.</p>
                <div style="margin-top:14px;">
                    <button id="infra-hunt-quick-pb" class="infra-hunt-btn primary"><i class="fa-solid fa-book-skull"></i> Duyệt sách chiến thuật mối đe dọa C2 (900+)</button>
                </div>
            </div>`;
            id('infra-hunt-quick-pb')?.addEventListener('click', openPlaybooksDirectly);
        }

        refreshProviderBadges();
        updateButtons(false);
        visible();
        window.syncInfraHuntVisibility = visible;
        window.runInfraHuntPreview = preview;
    }

    document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', init) : init();
})();
