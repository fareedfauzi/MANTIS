/**
 * VirusTotal Threat Monitoring (Livehunt & Retrohunt) Controller
 */
(() => {
    'use strict';

    const BASE = location.protocol === 'file:' ? 'http://127.0.0.1:9999' : location.origin;

    const state = {
        activeTab: 'notifications',
        status: null,
        notifications: [],
        rulesets: [],
        retrohuntJobs: [],
        searchQuery: '',
        pollInterval: null,
        editingRulesetId: null,
    };

    const getVtKey = () => localStorage.getItem('ioc_vt_key') || '';

    async function apiCall(endpoint, method = 'GET', body = null) {
        const key = getVtKey();
        const headers = {
            'Content-Type': 'application/json',
            'x-vt-key': key
        };
        const opts = { method, headers };
        if (body && (method === 'POST' || method === 'PATCH')) {
            opts.body = JSON.stringify({ ...body, vt_key: key });
        }

        const separator = endpoint.includes('?') ? '&' : '?';
        const url = `${BASE}${endpoint}${separator}vt_key=${encodeURIComponent(key)}`;

        const resp = await fetch(url, opts);
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
        }
        return data;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function formatDate(ts) {
        if (!ts) return '-';
        try {
            const date = new Date(typeof ts === 'number' ? ts * 1000 : ts);
            return isNaN(date.getTime()) ? String(ts) : date.toLocaleString();
        } catch {
            return String(ts);
        }
    }

    function timeAgo(ts) {
        if (!ts) return '-';
        try {
            const time = typeof ts === 'number' ? ts * 1000 : new Date(ts).getTime();
            const diff = Math.floor((Date.now() - time) / 1000);
            if (diff < 60) return `${diff}s ago`;
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        } catch {
            return '-';
        }
    }

    /**
     * Extracts true SHA-256 and MD5 from VirusTotal notification items.
     * In VT API, notification IDs are composite (<ruleset_id>-<md5>-<sha256>-<timestamp>).
     */
    function extractSampleHashes(item) {
        const attr = item.attributes || {};
        let sha256 = '';
        let md5 = '';

        // 1. Direct attribute or relationship
        if (attr.sha256 && /^[a-fA-F0-9]{64}$/.test(attr.sha256)) sha256 = attr.sha256.toLowerCase();
        if (item.relationships?.file?.data?.id && /^[a-fA-F0-9]{64}$/.test(item.relationships.file.data.id)) {
            sha256 = item.relationships.file.data.id.toLowerCase();
        }

        // 2. Parse from item.id: <ruleset_id>-<md5>-<sha256>-<timestamp>
        const idStr = String(item.id || '');
        const parts = idStr.split('-');
        for (const part of parts) {
            if (!sha256 && /^[a-fA-F0-9]{64}$/.test(part)) {
                sha256 = part.toLowerCase();
            } else if (!md5 && /^[a-fA-F0-9]{32}$/.test(part)) {
                md5 = part.toLowerCase();
            }
        }

        // 3. Fallback regex search in idStr
        if (!sha256) {
            const m = idStr.match(/[a-fA-F0-9]{64}/);
            if (m) sha256 = m[0].toLowerCase();
        }
        if (!md5) {
            const m = idStr.match(/[a-fA-F0-9]{32}/);
            if (m) md5 = m[0].toLowerCase();
        }

        // 4. Check tags for hashes if still missing
        if (!sha256 && Array.isArray(attr.tags)) {
            for (const t of attr.tags) {
                if (/^[a-fA-F0-9]{64}$/.test(t)) {
                    sha256 = t.toLowerCase();
                    break;
                }
            }
        }

        return { sha256: sha256 || idStr, md5 };
    }

    /**
     * Extracts filename(s) from a VirusTotal sample or notification item.
     * Looks in:
     * - attr.meaningful_name
     * - attr.names (array)
     * - attr.name
     * - attr.file_name
     * - attr.signature_info.original_filename / internal_name
     * - item.relationships.file.data.attributes.*
     */
    function extractSampleFilenames(item) {
        if (!item) return { primary: '', all: [] };
        const attr = item.attributes || {};
        const relFileAttr = item.relationships?.file?.data?.attributes || {};
        const names = [];

        function add(val) {
            if (!val || typeof val !== 'string') return;
            const cleaned = val.trim();
            // Discard hashes or empty values
            if (!cleaned || /^[a-fA-F0-9]{32,64}$/.test(cleaned)) return;
            if (!names.includes(cleaned)) names.push(cleaned);
        }

        add(attr.meaningful_name);
        add(relFileAttr.meaningful_name);

        if (Array.isArray(attr.names)) {
            attr.names.forEach(add);
        }
        if (Array.isArray(relFileAttr.names)) {
            relFileAttr.names.forEach(add);
        }

        add(attr.name);
        add(relFileAttr.name);
        add(attr.file_name);
        add(relFileAttr.file_name);
        add(attr.signature_info?.original_filename);
        add(attr.signature_info?.internal_name);

        return {
            primary: names[0] || '',
            all: names
        };
    }

    /**
     * Converts VT *begin_highlight* and *end_highlight* to styled mark spans.
     */
    function renderSnippetHtml(raw) {
        if (!raw) return '';
        let str = escapeHtml(raw);
        str = str.replace(/\*begin_highlight\*/gi, '<mark class="vt-evidence-mark">');
        str = str.replace(/\*end_highlight\*/gi, '</mark>');
        return str;
    }

    /**
     * Copies text to the user clipboard with visual feedback and toast notification.
     */
    async function copyToClipboard(text, btnEl) {
        if (!text) return;
        let success = false;
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                success = true;
            } else {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.left = '-9999px';
                ta.style.top = '-9999px';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.focus();
                ta.select();
                success = document.execCommand('copy');
                document.body.removeChild(ta);
            }
        } catch (err) {
            console.error('Failed to copy to clipboard:', err);
        }

        if (success) {
            if (typeof showNotification === 'function') {
                showNotification(text.length > 64 ? 'Matched evidence copied to clipboard' : 'Copied to clipboard');
            }
            if (btnEl) {
                const origHtml = btnEl.innerHTML;
                const hasText = btnEl.textContent.trim().length > 0;
                btnEl.classList.add('copied');
                btnEl.innerHTML = hasText 
                    ? '<i class="fa-solid fa-check"></i> Copied!' 
                    : '<i class="fa-solid fa-check"></i>';
                setTimeout(() => {
                    btnEl.innerHTML = origHtml;
                    btnEl.classList.remove('copied');
                }, 1600);
            }
        } else {
            if (typeof showNotification === 'function') {
                showNotification('Could not copy to clipboard');
            }
        }
    }

    // ========================================================================
    // STATUS & QUOTA PROBING
    // ========================================================================

    async function refreshStatus() {
        const key = getVtKey();
        const bannerEl = document.getElementById('vt-status-banner');

        if (!key) {
            if (bannerEl) {
                bannerEl.innerHTML = `
                    <div style="background:rgba(245, 158, 11, 0.12); border:1px solid rgba(245, 158, 11, 0.3); border-radius:8px; padding:12px 16px; font-size:0.85rem; color:#f59e0b; display:flex; justify-content:space-between; align-items:center;">
                        <div><i class="fa-solid fa-key" style="margin-right:8px;"></i> VirusTotal API Key not configured. Please enter your key in Settings.</div>
                        <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('btn-settings').click()">Open Settings</button>
                    </div>
                `;
            }
            return;
        }

        try {
            const res = await apiCall('/api/vt/hunting/status');
            state.status = res;

            if (res.error) {
                if (bannerEl) {
                    bannerEl.innerHTML = `
                        <div style="background:rgba(239, 68, 68, 0.12); border:1px solid rgba(239, 68, 68, 0.3); border-radius:8px; padding:12px 16px; font-size:0.85rem; color:#ef4444; display:flex; align-items:center; gap:10px;">
                            <i class="fa-solid fa-triangle-exclamation" style="font-size:1.1rem;"></i>
                            <div><strong>Livehunt Access Notice:</strong> ${escapeHtml(res.error)}</div>
                        </div>
                    `;
                }
                return;
            }

            if (bannerEl) bannerEl.innerHTML = '';

            // Update stats
            const statRulesets = document.getElementById('vt-stat-rulesets');
            const statNotifs = document.getElementById('vt-stat-notifs');
            const statRetro = document.getElementById('vt-stat-retro');

            if (statRulesets) statRulesets.textContent = res.active_rulesets_count || '0';
            if (statNotifs) statNotifs.textContent = res.unread_notifications_count || '0';
            if (statRetro) statRetro.textContent = res.recent_retrohunt_jobs_count || '0';
        } catch (err) {
            console.error('Failed to probe VT status:', err);
        }
    }

    // ========================================================================
    // NOTIFICATIONS
    // ========================================================================

    async function loadNotifications() {
        const listEl = document.getElementById('vt-notif-list');
        if (!listEl) return;

        listEl.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin" style="font-size:1.5rem; margin-bottom:8px;"></i><div>Fetching Livehunt notifications...</div></div>`;

        try {
            const res = await apiCall('/api/vt/hunting/notifications?limit=40');
            state.notifications = res.data || [];
            renderNotifications();
        } catch (err) {
            listEl.innerHTML = `
                <div class="vt-empty-state">
                    <i class="fa-solid fa-circle-exclamation" style="color:#ef4444;"></i>
                    <div style="font-weight:600; color:#ef4444;">Failed to load Livehunt notifications</div>
                    <div style="font-size:0.82rem; max-width:480px;">${escapeHtml(err.message)}</div>
                </div>
            `;
        }
    }

    function renderNotifications() {
        const listEl = document.getElementById('vt-notif-list');
        const countBadge = document.getElementById('vt-notif-tab-badge');
        if (!listEl) return;

        let items = state.notifications;
        if (state.searchQuery) {
            const q = state.searchQuery.toLowerCase();
            items = items.filter(n => {
                const attr = n.attributes || {};
                const rule = (attr.rule_name || '').toLowerCase();
                const hashes = extractSampleHashes(n);
                const fnInfo = extractSampleFilenames(n);
                const tags = Array.isArray(attr.tags) ? attr.tags.join(' ').toLowerCase() : '';
                const namesStr = fnInfo.all.join(' ').toLowerCase();
                return rule.includes(q) || hashes.sha256.includes(q) || hashes.md5.includes(q) || tags.includes(q) || namesStr.includes(q);
            });
        }

        if (countBadge) {
            countBadge.textContent = state.notifications.length;
        }

        if (items.length === 0) {
            listEl.innerHTML = `
                <div class="vt-empty-state">
                    <i class="fa-solid fa-bell-slash"></i>
                    <div style="font-size:1rem; font-weight:600; color:#fff;">No Livehunt Notifications</div>
                    <div style="font-size:0.84rem; max-width:450px;">
                        ${state.searchQuery ? 'No notifications match your current search query.' : 'When your active YARA rulesets detect new samples uploaded to VirusTotal, matches will appear here in real time.'}
                    </div>
                </div>
            `;
            return;
        }

        listEl.innerHTML = items.map(item => {
            const attr = item.attributes || {};
            const { sha256, md5 } = extractSampleHashes(item);
            const fnInfo = extractSampleFilenames(item);
            const ruleName = attr.rule_name || 'Matched Rule';
            const rulesetName = attr.ruleset_name ? `in ruleset <strong>${escapeHtml(attr.ruleset_name)}</strong>` : '';
            const dateStr = timeAgo(attr.date || attr.creation_date || item.context_attributes?.notification_date);
            const fullDate = formatDate(attr.date || attr.creation_date);
            const snippet = attr.snippet || '';

            // Filter out hashes from tags so tags remain clean
            const rawTags = Array.isArray(attr.tags) ? attr.tags : [];
            const cleanTags = rawTags.filter(t => !/^[a-fA-F0-9]{32,64}$/i.test(t));

            // Detection stats if present
            const stats = attr.last_analysis_stats || {};
            const mal = stats.malicious || 0;
            const total = (stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);

            let detBadge = '';
            if (total > 0) {
                const detClass = mal > 5 ? 'danger' : (mal > 0 ? 'warning' : 'clean');
                detBadge = `<span class="vt-det-pill ${detClass}" title="Detection ratio">${mal}/${total}</span>`;
            }

            const cleanSnippetForCopy = snippet.replace(/\*begin_highlight\*|\*end_highlight\*/gi, '');
            const namesTooltip = fnInfo.all.length > 1 ? `Known aliases:\n${fnInfo.all.join('\n')}` : fnInfo.primary;

            return `
                <div class="vt-notif-card" data-notif-id="${escapeHtml(item.id)}">
                    <div class="vt-notif-head">
                        <div class="vt-notif-title-wrap">
                            <span class="vt-rule-badge"><i class="fa-solid fa-code" style="margin-right:6px;"></i>${escapeHtml(ruleName)}</span>
                            <span class="vt-ruleset-name">${rulesetName}</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:12px;">
                            <div class="vt-notif-time" title="${escapeHtml(fullDate)}"><i class="fa-regular fa-clock"></i> ${dateStr}</div>
                            <button type="button" class="btn btn-sm btn-secondary vt-del-notif" data-id="${escapeHtml(item.id)}" title="Delete notification" style="color:#ef4444; padding:3px 8px;"><i class="fa-solid fa-trash-can"></i></button>
                        </div>
                    </div>
                    <div class="vt-notif-body">
                        ${fnInfo.primary ? `
                            <div class="vt-filename-row" title="${escapeHtml(namesTooltip)}" style="margin-bottom:3px;">
                                <i class="fa-regular fa-file" style="color:var(--accent); font-size:0.88rem; flex-shrink:0;"></i>
                                <span class="vt-filename-text">${escapeHtml(fnInfo.primary)}</span>
                                ${fnInfo.all.length > 1 ? `<span class="vt-filename-badge" title="${escapeHtml(namesTooltip)}">+${fnInfo.all.length - 1} alias${fnInfo.all.length > 2 ? 'es' : ''}</span>` : ''}
                            </div>
                        ` : ''}
                        <div class="vt-notif-hash-row">
                            <strong style="color:var(--text-muted); font-size:0.75rem;">SHA256:</strong>
                            <a href="#" class="vt-hash-link vt-pivot-hash" data-sha="${escapeHtml(sha256)}" title="Investigate in IOC Search">${escapeHtml(sha256)}</a>
                            <button type="button" class="vt-copy-btn icon-only" data-copy="${escapeHtml(sha256)}" title="Copy SHA-256"><i class="fa-regular fa-copy"></i></button>
                            ${md5 ? `<span class="vt-md5-badge vt-copy-btn" data-copy="${escapeHtml(md5)}" title="Click to copy MD5 hash" style="cursor:pointer;"><i class="fa-regular fa-copy" style="font-size:0.65rem; margin-right:3px;"></i>MD5: ${escapeHtml(md5)}</span>` : ''}
                        </div>
                        <div class="vt-notif-meta-pills">
                            ${detBadge}
                            ${cleanTags.slice(0, 5).map(t => `<span class="vt-tag-pill">${escapeHtml(t)}</span>`).join('')}
                        </div>
                        <div class="vt-notif-actions">
                            <button type="button" class="btn btn-sm btn-secondary vt-pivot-hash" data-sha="${escapeHtml(sha256)}" title="Investigate in IOC Search"><i class="fa-solid fa-magnifying-glass"></i> Hash Intel</button>
                            <button type="button" class="btn btn-sm btn-secondary vt-send-downloader" data-sha="${escapeHtml(sha256)}" title="Download sample"><i class="fa-solid fa-download"></i> Download</button>
                        </div>
                    </div>
                    ${snippet ? `
                        <div class="vt-evidence-box">
                            <div class="vt-evidence-head" data-toggle="evidence">
                                <span class="vt-evidence-title"><i class="fa-solid fa-code-compare"></i> YARA Match Evidence</span>
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <button type="button" class="vt-copy-btn vt-copy-evidence" data-copy="${escapeHtml(cleanSnippetForCopy)}" title="Copy raw matched snippet"><i class="fa-regular fa-copy"></i> Copy Evidence</button>
                                    <i class="fa-solid fa-chevron-down vt-evidence-arrow"></i>
                                </div>
                            </div>
                            <div class="vt-evidence-content dark-scroll">
                                <pre class="vt-evidence-pre">${renderSnippetHtml(snippet)}</pre>
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');
    }

    async function deleteSingleNotification(notifId) {
        try {
            await apiCall(`/api/vt/hunting/notifications/${encodeURIComponent(notifId)}`, 'DELETE');
            state.notifications = state.notifications.filter(n => n.id !== notifId);
            renderNotifications();
            refreshStatus();
        } catch (err) {
            alert(`Failed to delete notification: ${err.message}`);
        }
    }

    async function clearAllNotifications() {
        if (!confirm('Are you sure you want to delete all Livehunt notifications?')) return;
        try {
            await apiCall('/api/vt/hunting/notifications/delete-batch', 'POST', { ids: [] });
            state.notifications = [];
            renderNotifications();
            refreshStatus();
        } catch (err) {
            alert(`Failed to clear notifications: ${err.message}`);
        }
    }

    // ========================================================================
    // RULESETS
    // ========================================================================

    async function loadRulesets() {
        const gridEl = document.getElementById('vt-ruleset-grid');
        if (!gridEl) return;

        gridEl.innerHTML = `<div style="grid-column: 1 / -1; text-align:center; padding:40px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin" style="font-size:1.5rem; margin-bottom:8px;"></i><div>Fetching Livehunt rulesets...</div></div>`;

        try {
            const res = await apiCall('/api/vt/hunting/rulesets?limit=40');
            state.rulesets = res.data || [];
            renderRulesets();
        } catch (err) {
            gridEl.innerHTML = `
                <div class="vt-empty-state" style="grid-column: 1 / -1;">
                    <i class="fa-solid fa-circle-exclamation" style="color:#ef4444;"></i>
                    <div style="font-weight:600; color:#ef4444;">Failed to load Livehunt rulesets</div>
                    <div style="font-size:0.82rem; max-width:480px;">${escapeHtml(err.message)}</div>
                </div>
            `;
        }
    }

    function renderRulesets() {
        const gridEl = document.getElementById('vt-ruleset-grid');
        const badgeEl = document.getElementById('vt-ruleset-tab-badge');
        if (!gridEl) return;

        if (badgeEl) badgeEl.textContent = state.rulesets.length;

        if (state.rulesets.length === 0) {
            gridEl.innerHTML = `
                <div class="vt-empty-state" style="grid-column: 1 / -1;">
                    <i class="fa-solid fa-shield-virus"></i>
                    <div style="font-size:1rem; font-weight:600; color:#fff;">No Livehunt Rulesets Configured</div>
                    <div style="font-size:0.84rem; max-width:450px;">
                        Create a YARA ruleset to continuously monitor new samples uploaded to VirusTotal globally.
                    </div>
                    <button type="button" class="btn btn-primary vt-btn-new-ruleset" style="margin-top:8px;">
                        <i class="fa-solid fa-plus"></i> Create Livehunt Ruleset
                    </button>
                </div>
            `;
            return;
        }

        gridEl.innerHTML = state.rulesets.map(item => {
            const attr = item.attributes || {};
            const isEnabled = attr.enabled !== false;
            const matchCount = attr.match_count !== undefined ? attr.match_count : 0;
            const updated = formatDate(attr.modification_date || attr.creation_date);

            return `
                <div class="vt-ruleset-card" data-ruleset-id="${escapeHtml(item.id)}">
                    <div>
                        <div class="vt-ruleset-head">
                            <h4 class="vt-ruleset-name-title">${escapeHtml(attr.name || 'Unnamed Ruleset')}</h4>
                            <label class="vt-switch" title="Toggle Livehunt enabled/disabled">
                                <input type="checkbox" class="vt-toggle-ruleset" data-id="${escapeHtml(item.id)}" ${isEnabled ? 'checked' : ''}>
                                <span class="vt-slider"></span>
                            </label>
                        </div>
                        <div class="vt-ruleset-desc">
                            <span style="color:var(--accent); font-weight:700; font-family:var(--font-mono);">${matchCount}</span> matches recorded
                        </div>
                    </div>
                    <div class="vt-ruleset-footer">
                        <span>Modified: ${escapeHtml(updated)}</span>
                        <div style="display:flex; gap:6px;">
                            <button type="button" class="btn btn-sm btn-secondary vt-edit-ruleset" data-id="${escapeHtml(item.id)}" title="View and edit YARA rule"><i class="fa-solid fa-pen-to-square"></i> Edit</button>
                            <button type="button" class="btn btn-sm btn-secondary vt-del-ruleset" data-id="${escapeHtml(item.id)}" title="Delete ruleset" style="color:#ef4444;"><i class="fa-solid fa-trash-can"></i></button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function toggleRuleset(rulesetId, enabled) {
        try {
            await apiCall(`/api/vt/hunting/rulesets/${encodeURIComponent(rulesetId)}`, 'PATCH', { enabled });
            const item = state.rulesets.find(r => r.id === rulesetId);
            if (item && item.attributes) item.attributes.enabled = enabled;
        } catch (err) {
            alert(`Failed to update ruleset: ${err.message}`);
            renderRulesets();
        }
    }

    async function deleteSingleRuleset(rulesetId) {
        if (!confirm('Are you sure you want to delete this Livehunt ruleset?')) return;
        try {
            await apiCall(`/api/vt/hunting/rulesets/${encodeURIComponent(rulesetId)}`, 'DELETE');
            state.rulesets = state.rulesets.filter(r => r.id !== rulesetId);
            renderRulesets();
            refreshStatus();
        } catch (err) {
            alert(`Failed to delete ruleset: ${err.message}`);
        }
    }

    async function openRulesetModal(rulesetId = null) {
        state.editingRulesetId = rulesetId;
        const modal = document.getElementById('vt-ruleset-modal');
        const titleEl = document.getElementById('vt-ruleset-modal-title');
        const nameInput = document.getElementById('vt-ruleset-name');
        const rulesInput = document.getElementById('vt-ruleset-code');
        const enabledCheck = document.getElementById('vt-ruleset-enabled');

        if (!modal) return;

        if (rulesetId) {
            titleEl.innerHTML = '<i class="fa-solid fa-pen-to-square"></i> Edit Livehunt Ruleset';
            nameInput.value = 'Loading...';
            rulesInput.value = '// Fetching YARA rules from VirusTotal...';

            modal.classList.add('open');

            try {
                const res = await apiCall(`/api/vt/hunting/rulesets/${encodeURIComponent(rulesetId)}`);
                const attr = res.data?.attributes || {};
                nameInput.value = attr.name || '';
                rulesInput.value = attr.rules || '';
                enabledCheck.checked = attr.enabled !== false;
            } catch (err) {
                alert(`Failed to fetch ruleset: ${err.message}`);
                modal.classList.remove('open');
            }
        } else {
            titleEl.innerHTML = '<i class="fa-solid fa-plus"></i> New Livehunt Ruleset';
            nameInput.value = '';
            rulesInput.value = `rule Threat_Detection_Rule {\n    meta:\n        description = "Detects threat activity via VirusTotal Livehunt"\n        author = "MANTIS Hunter"\n        date = "${new Date().toISOString().split('T')[0]}"\n    strings:\n        $s1 = "malicious_string_example" ascii wide\n    condition:\n        uint16(0) == 0x5A4D and any of them\n}`;
            enabledCheck.checked = true;
            modal.classList.add('open');
        }
    }

    async function saveRuleset() {
        const nameInput = document.getElementById('vt-ruleset-name');
        const rulesInput = document.getElementById('vt-ruleset-code');
        const enabledCheck = document.getElementById('vt-ruleset-enabled');
        const saveBtn = document.getElementById('vt-ruleset-save-btn');

        const name = (nameInput?.value || '').trim();
        const rules = (rulesInput?.value || '').trim();
        const enabled = enabledCheck?.checked ?? true;

        if (!name) return alert('Please enter a ruleset name.');
        if (!rules) return alert('Please enter YARA rules content.');

        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

        try {
            if (state.editingRulesetId) {
                await apiCall(`/api/vt/hunting/rulesets/${encodeURIComponent(state.editingRulesetId)}`, 'PATCH', { name, rules, enabled });
            } else {
                await apiCall('/api/vt/hunting/rulesets', 'POST', { name, rules, enabled });
            }
            document.getElementById('vt-ruleset-modal').classList.remove('open');
            await loadRulesets();
            refreshStatus();
        } catch (err) {
            alert(`Error saving ruleset: ${err.message}`);
        } finally {
            saveBtn.disabled = false;
            saveBtn.innerHTML = '<i class="fa-solid fa-check"></i> Save Ruleset';
        }
    }

    // ========================================================================
    // RETROHUNT
    // ========================================================================

    async function loadRetrohuntJobs() {
        const listEl = document.getElementById('vt-retro-list');
        if (!listEl) return;

        listEl.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin" style="font-size:1.5rem; margin-bottom:8px;"></i><div>Fetching Retrohunt jobs...</div></div>`;

        try {
            const res = await apiCall('/api/vt/retrohunt/jobs?limit=20');
            state.retrohuntJobs = res.data || [];
            renderRetrohuntJobs();
            checkRetrohuntPolling();
        } catch (err) {
            listEl.innerHTML = `
                <div class="vt-empty-state">
                    <i class="fa-solid fa-circle-exclamation" style="color:#ef4444;"></i>
                    <div style="font-weight:600; color:#ef4444;">Failed to load Retrohunt jobs</div>
                    <div style="font-size:0.82rem; max-width:480px;">${escapeHtml(err.message)}</div>
                </div>
            `;
        }
    }

    function renderRetrohuntJobs() {
        const listEl = document.getElementById('vt-retro-list');
        const badgeEl = document.getElementById('vt-retro-tab-badge');
        if (!listEl) return;

        if (badgeEl) badgeEl.textContent = state.retrohuntJobs.length;

        if (state.retrohuntJobs.length === 0) {
            listEl.innerHTML = `
                <div class="vt-empty-state">
                    <i class="fa-solid fa-clock-rotate-left"></i>
                    <div style="font-size:1rem; font-weight:600; color:#fff;">No Retrohunt Jobs Executed</div>
                    <div style="font-size:0.84rem; max-width:480px;">
                        Run a Retrohunt to search VirusTotal's multi-petabyte historical sample corpus against your YARA rules.
                    </div>
                    <button type="button" class="btn btn-primary vt-btn-new-retro" style="margin-top:8px;">
                        <i class="fa-solid fa-rocket"></i> Launch Retrohunt Job
                    </button>
                </div>
            `;
            return;
        }

        listEl.innerHTML = state.retrohuntJobs.map(job => {
            const attr = job.attributes || {};
            const status = (attr.status || 'starting').toLowerCase();
            const progress = typeof attr.progress === 'number' ? Math.round(attr.progress) : 0;
            const matches = attr.num_matches || 0;
            const created = formatDate(attr.creation_date);
            const isRunning = status === 'running' || status === 'starting';

            return `
                <div class="vt-job-card" data-job-id="${escapeHtml(job.id)}">
                    <div class="vt-job-head">
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="vt-job-id"><i class="fa-solid fa-crosshairs" style="color:var(--accent); margin-right:6px;"></i>Job #${escapeHtml(job.id)}</span>
                            <span class="vt-job-status-badge ${status}">${escapeHtml(status)}</span>
                        </div>
                        <div style="font-size:0.75rem; color:var(--text-muted);"><i class="fa-regular fa-calendar" style="margin-right:4px;"></i>${escapeHtml(created)}</div>
                    </div>
                    <div class="vt-progress-wrap">
                        <div class="vt-progress-bar-bg">
                            <div class="vt-progress-bar-fill" style="width:${progress}%;"></div>
                        </div>
                        <div class="vt-progress-meta">
                            <span>Progress: <strong>${progress}%</strong></span>
                            <span>Matches: <strong style="color:var(--accent);">${matches}</strong></span>
                        </div>
                    </div>
                    <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid rgba(255,255,255,0.05); padding-top:10px;">
                        <span style="font-size:0.75rem; color:var(--text-muted);">Corpus: ${escapeHtml(attr.corpus || 'main')}</span>
                        <div style="display:flex; gap:8px;">
                            ${matches > 0 ? `
                                <button type="button" class="btn btn-sm btn-primary vt-view-matches" data-id="${escapeHtml(job.id)}" data-matches="${matches}"><i class="fa-solid fa-list-check"></i> View Matches (${matches})</button>
                            ` : ''}
                            ${isRunning ? `
                                <button type="button" class="btn btn-sm btn-secondary vt-abort-job" data-id="${escapeHtml(job.id)}" style="color:#ef4444;"><i class="fa-solid fa-ban"></i> Abort</button>
                            ` : `
                                <button type="button" class="btn btn-sm btn-secondary vt-del-job" data-id="${escapeHtml(job.id)}" style="color:#ef4444;"><i class="fa-solid fa-trash-can"></i></button>
                            `}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function checkRetrohuntPolling() {
        const hasActiveJobs = state.retrohuntJobs.some(j => {
            const s = (j.attributes?.status || '').toLowerCase();
            return s === 'running' || s === 'starting';
        });

        if (hasActiveJobs && !state.pollInterval) {
            state.pollInterval = setInterval(async () => {
                if (state.activeTab === 'retrohunt') {
                    const res = await apiCall('/api/vt/retrohunt/jobs?limit=20').catch(() => null);
                    if (res && res.data) {
                        state.retrohuntJobs = res.data;
                        renderRetrohuntJobs();
                    }
                }
            }, 6000);
        } else if (!hasActiveJobs && state.pollInterval) {
            clearInterval(state.pollInterval);
            state.pollInterval = null;
        }
    }

    async function launchRetrohuntModal() {
        const modal = document.getElementById('vt-retro-modal');
        const codeInput = document.getElementById('vt-retro-code');
        if (!modal) return;

        codeInput.value = `rule Retrohunt_Malware_Search {\n    meta:\n        description = "Historical hunting rule across VirusTotal"\n        date = "${new Date().toISOString().split('T')[0]}"\n    strings:\n        $magic = "MZ"\n        $str = "malicious_payload_marker" ascii wide\n    condition:\n        $magic at 0 and $str\n}`;

        modal.classList.add('open');
    }

    async function submitRetrohuntJob() {
        const codeInput = document.getElementById('vt-retro-code');
        const corpusSelect = document.getElementById('vt-retro-corpus');
        const launchBtn = document.getElementById('vt-retro-launch-btn');

        const rules = (codeInput?.value || '').trim();
        const corpus = (corpusSelect?.value || 'main').trim();

        if (!rules) return alert('Please enter YARA rules for the Retrohunt job.');

        launchBtn.disabled = true;
        launchBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Launching...';

        try {
            await apiCall('/api/vt/retrohunt/jobs', 'POST', { rules, corpus });
            document.getElementById('vt-retro-modal').classList.remove('open');
            await loadRetrohuntJobs();
            refreshStatus();
        } catch (err) {
            alert(`Error launching Retrohunt: ${err.message}`);
        } finally {
            launchBtn.disabled = false;
            launchBtn.innerHTML = '<i class="fa-solid fa-rocket"></i> Launch Retrohunt';
        }
    }

    async function abortJob(jobId) {
        if (!confirm(`Are you sure you want to abort Retrohunt job #${jobId}?`)) return;
        try {
            await apiCall(`/api/vt/retrohunt/jobs/${encodeURIComponent(jobId)}/abort`, 'POST');
            await loadRetrohuntJobs();
        } catch (err) {
            alert(`Failed to abort job: ${err.message}`);
        }
    }

    async function deleteJob(jobId) {
        if (!confirm(`Are you sure you want to delete Retrohunt job #${jobId}?`)) return;
        try {
            await apiCall(`/api/vt/retrohunt/jobs/${encodeURIComponent(jobId)}`, 'DELETE');
            state.retrohuntJobs = state.retrohuntJobs.filter(j => j.id !== jobId);
            renderRetrohuntJobs();
            refreshStatus();
        } catch (err) {
            alert(`Failed to delete job: ${err.message}`);
        }
    }

    async function viewMatches(jobId, matchCount) {
        const modal = document.getElementById('vt-matches-modal');
        const titleEl = document.getElementById('vt-matches-title');
        const listEl = document.getElementById('vt-matches-list');
        const filterInput = document.getElementById('vt-matches-filter');

        if (!modal) return;
        titleEl.textContent = `Matching Samples for Job #${jobId} (${matchCount})`;
        listEl.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin" style="font-size:1.5rem; margin-bottom:8px;"></i><div>Loading matched files...</div></div>`;
        if (filterInput) filterInput.value = '';
        modal.classList.add('open');

        try {
            const res = await apiCall(`/api/vt/retrohunt/jobs/${encodeURIComponent(jobId)}/matches?limit=40`);
            const files = res.data || [];
            if (files.length === 0) {
                listEl.innerHTML = `<div class="vt-empty-state"><i class="fa-solid fa-file-circle-question"></i><div>No matching files returned.</div></div>`;
                return;
            }

            function renderMatchingList(items) {
                if (items.length === 0) {
                    listEl.innerHTML = `<div class="vt-empty-state" style="padding:24px;"><i class="fa-solid fa-filter"></i><div>No matching files match your filter.</div></div>`;
                    return;
                }

                listEl.innerHTML = items.map(f => {
                    const attr = f.attributes || {};
                    const sha = attr.sha256 || f.id || '';
                    const fnInfo = extractSampleFilenames(f);
                    const typeDesc = attr.type_description || 'Unknown file';
                    const size = attr.size ? `${(attr.size / 1024).toFixed(1)} KB` : '';
                    const mal = attr.last_analysis_stats?.malicious || 0;
                    const undetected = attr.last_analysis_stats?.undetected || 0;
                    const harmless = attr.last_analysis_stats?.harmless || 0;
                    const total = mal + undetected + harmless;

                    const namesTooltip = fnInfo.all.length > 1 ? `Known filenames:\n${fnInfo.all.join('\n')}` : fnInfo.primary;

                    return `
                        <div class="vt-match-file-item">
                            <div style="display:flex; flex-direction:column; gap:5px; min-width:0; flex:1;">
                                ${fnInfo.primary ? `
                                    <div class="vt-filename-row" title="${escapeHtml(namesTooltip)}">
                                        <i class="fa-regular fa-file-lines" style="color:var(--accent); font-size:0.9rem; flex-shrink:0;"></i>
                                        <span class="vt-filename-text">${escapeHtml(fnInfo.primary)}</span>
                                        ${fnInfo.all.length > 1 ? `<span class="vt-filename-badge" title="${escapeHtml(namesTooltip)}">+${fnInfo.all.length - 1} alias${fnInfo.all.length > 2 ? 'es' : ''}</span>` : ''}
                                    </div>
                                ` : ''}
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <a href="#" class="vt-hash-link vt-pivot-hash" data-sha="${escapeHtml(sha)}" style="font-size:0.83rem; font-family:var(--font-mono);">${escapeHtml(sha)}</a>
                                    <button type="button" class="vt-copy-btn icon-only" data-copy="${escapeHtml(sha)}" title="Copy SHA-256"><i class="fa-regular fa-copy"></i></button>
                                </div>
                                <div style="font-size:0.75rem; color:var(--text-muted); display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                                    <span class="vt-type-pill">${escapeHtml(typeDesc)}</span>
                                    ${size ? `<span>· ${escapeHtml(size)}</span>` : ''}
                                    ${total > 0 ? `· <span style="font-weight:700; color:${mal > 0 ? '#ef4444' : '#10b981'};">${mal}/${total} detections</span>` : ''}
                                </div>
                            </div>
                            <div style="display:flex; gap:6px; flex-shrink:0; align-items:center;">
                                <button type="button" class="btn btn-sm btn-secondary vt-pivot-hash" data-sha="${escapeHtml(sha)}"><i class="fa-solid fa-magnifying-glass"></i> Hash Intel</button>
                                <button type="button" class="btn btn-sm btn-secondary vt-send-downloader" data-sha="${escapeHtml(sha)}"><i class="fa-solid fa-download"></i> Download</button>
                            </div>
                        </div>
                    `;
                }).join('');
            }

            renderMatchingList(files);

            if (filterInput) {
                filterInput.oninput = (e) => {
                    const q = (e.target.value || '').toLowerCase().trim();
                    if (!q) {
                        renderMatchingList(files);
                        return;
                    }
                    const filtered = files.filter(f => {
                        const attr = f.attributes || {};
                        const sha = (attr.sha256 || f.id || '').toLowerCase();
                        const fnInfo = extractSampleFilenames(f);
                        const namesStr = fnInfo.all.join(' ').toLowerCase();
                        const typeDesc = (attr.type_description || '').toLowerCase();
                        return sha.includes(q) || namesStr.includes(q) || typeDesc.includes(q);
                    });
                    renderMatchingList(filtered);
                };
            }
        } catch (err) {
            listEl.innerHTML = `<div class="vt-empty-state"><i class="fa-solid fa-circle-exclamation" style="color:#ef4444;"></i><div>Failed to load matches: ${escapeHtml(err.message)}</div></div>`;
        }
    }

    // ========================================================================
    // PIVOT INTEGRATIONS
    // ========================================================================

    function pivotToHashIntel(sha256) {
        if (!sha256) return;
        const iocInput = document.getElementById('ioc-input');
        const hashTab = document.getElementById('ioc-tab-hash');
        const searchBtn = document.getElementById('btn-search');
        const navIoc = document.querySelector('.nav-item[data-tab="ioc-search"]');

        if (navIoc) navIoc.click();
        if (hashTab) hashTab.click();
        if (iocInput) iocInput.value = sha256;
        if (searchBtn) searchBtn.click();
    }

    function sendToDownloader(sha256) {
        if (!sha256) return;
        const navDownloader = document.querySelector('.nav-item[data-tab="samples-downloader"]');
        const textarea = document.getElementById('samples-downloader-hashes');

        if (navDownloader) navDownloader.click();
        if (textarea) {
            textarea.value = sha256;
            textarea.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }

    // ========================================================================
    // INITIALIZATION & EVENT LISTENERS
    // ========================================================================

    function switchSubTab(tabName) {
        state.activeTab = tabName;
        document.querySelectorAll('.vt-tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
        document.querySelectorAll('.vt-tab-panel').forEach(p => {
            p.classList.toggle('active', p.id === `vt-panel-${tabName}`);
        });

        if (tabName === 'notifications') {
            loadNotifications();
        } else if (tabName === 'rulesets') {
            loadRulesets();
        } else if (tabName === 'retrohunt') {
            loadRetrohuntJobs();
        }
    }

    window.openVtMonitoring = function() {
        refreshStatus();
        switchSubTab(state.activeTab);
    };

    window.deployRuleToLivehunt = function(ruleText, ruleName = '') {
        const navVt = document.querySelector('.nav-item[data-tab="vt-monitoring"]');
        if (navVt) navVt.click();
        switchSubTab('rulesets');
        openRulesetModal(null);
        setTimeout(() => {
            const nameInput = document.getElementById('vt-ruleset-name');
            const rulesInput = document.getElementById('vt-ruleset-code');
            if (nameInput && ruleName) nameInput.value = ruleName;
            if (rulesInput && ruleText) rulesInput.value = ruleText;
        }, 120);
    };

    window.deployRuleToRetrohunt = function(ruleText) {
        const navVt = document.querySelector('.nav-item[data-tab="vt-monitoring"]');
        if (navVt) navVt.click();
        switchSubTab('retrohunt');
        launchRetrohuntModal();
        setTimeout(() => {
            const codeInput = document.getElementById('vt-retro-code');
            if (codeInput && ruleText) codeInput.value = ruleText;
        }, 120);
    };

    document.addEventListener('DOMContentLoaded', () => {
        // Sub-tabs click
        document.querySelectorAll('.vt-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => switchSubTab(btn.dataset.tab));
        });

        // Search in notifications
        const searchInput = document.getElementById('vt-notif-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                state.searchQuery = e.target.value.trim();
                renderNotifications();
            });
        }

        // Action bar buttons
        document.getElementById('vt-btn-refresh-feed')?.addEventListener('click', () => {
            refreshStatus();
            if (state.activeTab === 'notifications') loadNotifications();
            else if (state.activeTab === 'rulesets') loadRulesets();
            else if (state.activeTab === 'retrohunt') loadRetrohuntJobs();
        });

        document.getElementById('vt-btn-clear-notifs')?.addEventListener('click', clearAllNotifications);
        document.getElementById('vt-btn-new-ruleset')?.addEventListener('click', () => openRulesetModal(null));
        document.getElementById('vt-btn-new-retro')?.addEventListener('click', launchRetrohuntModal);

        // Modal triggers
        document.getElementById('vt-ruleset-save-btn')?.addEventListener('click', saveRuleset);
        document.getElementById('vt-ruleset-cancel-btn')?.addEventListener('click', () => {
            document.getElementById('vt-ruleset-modal').classList.remove('open');
        });
        document.getElementById('vt-ruleset-close-btn')?.addEventListener('click', () => {
            document.getElementById('vt-ruleset-modal').classList.remove('open');
        });

        document.getElementById('vt-retro-launch-btn')?.addEventListener('click', submitRetrohuntJob);
        document.getElementById('vt-retro-cancel-btn')?.addEventListener('click', () => {
            document.getElementById('vt-retro-modal').classList.remove('open');
        });
        document.getElementById('vt-retro-close-btn')?.addEventListener('click', () => {
            document.getElementById('vt-retro-modal').classList.remove('open');
        });

        document.getElementById('vt-matches-close-btn')?.addEventListener('click', () => {
            document.getElementById('vt-matches-modal').classList.remove('open');
        });

        // YARA Workbench quick-deploy integration
        document.getElementById('yara-wb-livehunt')?.addEventListener('click', () => {
            const text = document.getElementById('yara-wb-editor')?.value || '';
            const name = (document.getElementById('yara-wb-filename')?.value || '').replace(/\.ya?r$/, '');
            if (!text.trim()) return alert('Please enter a YARA rule first.');
            window.deployRuleToLivehunt(text, name);
        });

        document.getElementById('yara-wb-retrohunt')?.addEventListener('click', () => {
            const text = document.getElementById('yara-wb-editor')?.value || '';
            if (!text.trim()) return alert('Please enter a YARA rule first.');
            window.deployRuleToRetrohunt(text);
        });

        // Event delegation for dynamic lists
        document.addEventListener('click', (e) => {
            // Copy button click handler
            const copyBtn = e.target.closest('.vt-copy-btn, .copy-btn, [data-copy]');
            if (copyBtn) {
                e.preventDefault();
                e.stopPropagation();
                const textToCopy = copyBtn.dataset.copy || copyBtn.getAttribute('data-copy') || '';
                if (textToCopy) {
                    copyToClipboard(textToCopy, copyBtn);
                }
                return;
            }

            // Toggle evidence accordion
            const evHead = e.target.closest('.vt-evidence-head');
            if (evHead) {
                const box = evHead.closest('.vt-evidence-box');
                if (box) box.classList.toggle('collapsed');
                return;
            }

            // Delete notification
            const delNotifBtn = e.target.closest('.vt-del-notif');
            if (delNotifBtn) {
                deleteSingleNotification(delNotifBtn.dataset.id);
                return;
            }

            // Pivot to hash
            const pivotBtn = e.target.closest('.vt-pivot-hash');
            if (pivotBtn) {
                e.preventDefault();
                pivotToHashIntel(pivotBtn.dataset.sha);
                return;
            }

            // Send to downloader
            const downBtn = e.target.closest('.vt-send-downloader');
            if (downBtn) {
                sendToDownloader(downBtn.dataset.sha);
                return;
            }

            // Edit ruleset
            const editRuleBtn = e.target.closest('.vt-edit-ruleset');
            if (editRuleBtn) {
                openRulesetModal(editRuleBtn.dataset.id);
                return;
            }

            // Delete ruleset
            const delRuleBtn = e.target.closest('.vt-del-ruleset');
            if (delRuleBtn) {
                deleteSingleRuleset(delRuleBtn.dataset.id);
                return;
            }

            // View matches
            const viewMatchBtn = e.target.closest('.vt-view-matches');
            if (viewMatchBtn) {
                viewMatches(viewMatchBtn.dataset.id, viewMatchBtn.dataset.matches);
                return;
            }

            // Abort job
            const abortBtn = e.target.closest('.vt-abort-job');
            if (abortBtn) {
                abortJob(abortBtn.dataset.id);
                return;
            }

            // Delete job
            const delJobBtn = e.target.closest('.vt-del-job');
            if (delJobBtn) {
                deleteJob(delJobBtn.dataset.id);
                return;
            }

            // New ruleset CTA in empty state
            if (e.target.closest('.vt-btn-new-ruleset')) {
                openRulesetModal(null);
                return;
            }

            // New retro CTA in empty state
            if (e.target.closest('.vt-btn-new-retro')) {
                launchRetrohuntModal();
                return;
            }
        });

        // Ruleset toggle change
        document.addEventListener('change', (e) => {
            const toggle = e.target.closest('.vt-toggle-ruleset');
            if (toggle) {
                toggleRuleset(toggle.dataset.id, toggle.checked);
            }
        });
    });
})();
