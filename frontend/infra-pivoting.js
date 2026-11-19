/**
 * MANTIS — Automated Infrastructure Pivoting Frontend Controller
 * Supports Quick, Deep, and Custom bounded graph traversal, interactive
 * force/radial relationship graph, ranked findings, provenance explorer,
 * job cancellation/resumption, and export (JSON / CSV / STIX 2.1).
 */
(() => {
    'use strict';

    const BASE = location.protocol === 'file:' ? 'http://127.0.0.1:9999' : location.origin;
    const KEY_MAP = [
        'vt', 'shodan', 'censys', 'fofa', 'urlscan', 'silentpush',
        'validin', 'netlas', 'greynoise', 'abusech', 'otx'
    ];

    const TYPE_COLORS = {
        seed: '#FFCC00',
        ip: '#38bdf8',
        domain: '#10b981',
        url: '#f472b6',
        hash: '#ef4444',
        certificate: '#a855f7',
        fingerprint: '#fb923c',
        asn: '#64748b',
        whois: '#2dd4bf'
    };

    const state = {
        capabilities: null,
        mode: 'quick',
        drawerOpen: false,
        activeSubtab: 'graph',
        investigation: null,
        pollTimer: null,
        selectedNodeId: null,
        selectedEdgeId: null,
        graphLayout: 'radial', // 'radial' | 'force'
        graphMinConf: 0,
        graphTypeFilter: 'all',
        graphHideNoise: false,
        nodes: [],
        edges: [],
        camera: { x: 0, y: 0, zoom: 1 },
        draggingNode: null,
        panning: false,
        panStart: { x: 0, y: 0 },
        animFrame: null
    };

    const el = (id) => document.getElementById(id);
    const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));

    function getLocalKeys() {
        const out = {};
        KEY_MAP.forEach((k) => {
            out[`${k}_key`] = localStorage.getItem(`ioc_${k}_key`) || '';
        });
        return out;
    }

    async function apiCall(path, options = {}) {
        const res = await fetch(BASE + path, {
            headers: { 'Content-Type': 'application/json' },
            ...options
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(body.detail || body.error || `HTTP ${res.status}`);
        }
        return body;
    }

    function detectIndicatorTypeClient(raw) {
        const text = String(raw || '').trim()
            .replace(/\[\.\]|\(\.\)/g, '.')
            .replace(/^hxxps:\/\//i, 'https://')
            .replace(/^hxxp:\/\//i, 'http://');
        if (!text) return 'AUTO';
        if (/^(cert|certificate|cert_sha256):/i.test(text)) return 'CERTIFICATE';
        if (/^(jarm|ja4x|favicon|ssh|body_hash):/i.test(text)) return 'FINGERPRINT';
        if (/^https?:\/\//i.test(text) || text.includes('/')) return 'URL';
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text) || (text.includes(':') && /^[0-9a-fA-F:]+$/.test(text))) return 'IP';
        if (/^[a-fA-F0-9]{62}$/.test(text)) return 'FINGERPRINT (JARM)';
        if (/^[a-fA-F0-9]{32}$/.test(text)) return 'HASH (MD5)';
        if (/^[a-fA-F0-9]{40}$/.test(text)) return 'HASH (SHA1)';
        if (/^[a-fA-F0-9]{64}$/.test(text)) return 'HASH (SHA256)';
        if (/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$/.test(text)) return 'DOMAIN';
        if (/\s/.test(text) && (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(text) || /https?:\/\//i.test(text) || /\b[a-fA-F0-9]{32,64}\b/.test(text) || /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b/.test(text))) {
            return 'TEXT EXTRACT';
        }
        return 'AUTO';
    }

    // =========================================================================
    // 1. INITIALIZATION & CAPABILITIES LOADING
    // =========================================================================

    async function loadCapabilities() {
        try {
            const data = await apiCall('/api/infra-pivoting/capabilities', {
                method: 'POST',
                body: JSON.stringify(getLocalKeys())
            });
            state.capabilities = data;
            renderMethodsCheckboxes(data.pivot_methods || []);
            renderProvidersCheckboxes(data.providers || []);
            applyPresetValues(state.mode);
        } catch (err) {
            console.error('[InfraPivoting] Failed to load capabilities:', err);
        }
    }

    function renderMethodsCheckboxes(methods) {
        const container = el('ipiv-methods-list');
        if (!container) return;
        container.innerHTML = methods.map((m) => `
            <label class="ipiv-check-pill checked" title="${esc(m.description)}">
                <input type="checkbox" class="ipiv-method-cb" value="${esc(m.id)}" checked />
                <span>${esc(m.label)}</span>
            </label>
        `).join('');

        container.querySelectorAll('.ipiv-method-cb').forEach((cb) => {
            cb.addEventListener('change', () => {
                cb.closest('.ipiv-check-pill')?.classList.toggle('checked', cb.checked);
            });
        });
    }

    function renderProvidersCheckboxes(providers) {
        const container = el('ipiv-providers-list');
        if (!container) return;
        container.innerHTML = providers.map((p) => {
            const dotClass = p.has_key ? 'ready' : (!p.requires_api_key ? 'public' : 'missing');
            const checked = p.ready ? 'checked' : '';
            const pillClass = `ipiv-check-pill ${p.ready ? 'checked' : 'missing-key'}`;
            const methodCount = (p.supported_pivot_methods || []).length;
            const tooltip = `${p.label} — ${p.status_label}\nSupports ${methodCount} pivot methods: ${(p.supported_pivot_methods || []).join(', ')}\nRate limit: ${(p.rate_limit || {}).requests_per_minute || '?'} req/min\n${p.entitlement_notes || ''}`;
            return `
                <label class="${pillClass}" title="${esc(tooltip)}">
                    <input type="checkbox" class="ipiv-provider-cb" value="${esc(p.id)}" ${checked} />
                    <span class="ipiv-prov-status-dot ${dotClass}"></span>
                    <span>${esc(p.label)}</span>
                </label>
            `;
        }).join('');

        container.querySelectorAll('.ipiv-provider-cb').forEach((cb) => {
            cb.addEventListener('change', () => {
                cb.closest('.ipiv-check-pill')?.classList.toggle('checked', cb.checked);
            });
        });
    }

    function applyPresetValues(mode) {
        state.mode = mode;
        document.querySelectorAll('.ipiv-mode-btn').forEach((btn) => {
            btn.classList.toggle('active', btn.dataset.mode === mode);
        });
        const presets = (state.capabilities && state.capabilities.presets) || {
            quick: { max_depth: 1, max_assets: 40, per_pivot_limit: 15, timeout_seconds: 45, api_budget: 16, min_confidence_to_expand: 45 },
            deep: { max_depth: 3, max_assets: 150, per_pivot_limit: 35, timeout_seconds: 180, api_budget: 60, min_confidence_to_expand: 35 },
            custom: { max_depth: 2, max_assets: 80, per_pivot_limit: 25, timeout_seconds: 90, api_budget: 30, min_confidence_to_expand: 40 }
        };
        const p = presets[mode] || presets.quick;
        if (el('ipiv-max-depth')) el('ipiv-max-depth').value = p.max_depth;
        if (el('ipiv-max-assets')) el('ipiv-max-assets').value = p.max_assets;
        if (el('ipiv-per-pivot-limit')) el('ipiv-per-pivot-limit').value = p.per_pivot_limit;
        if (el('ipiv-timeout')) el('ipiv-timeout').value = p.timeout_seconds;
        if (el('ipiv-api-budget')) el('ipiv-api-budget').value = p.api_budget;
        if (el('ipiv-min-conf-expand')) el('ipiv-min-conf-expand').value = p.min_confidence_to_expand;

        if (mode === 'custom' && !state.drawerOpen) {
            toggleConfigDrawer(true);
        }
    }

    function toggleConfigDrawer(forceState) {
        state.drawerOpen = typeof forceState === 'boolean' ? forceState : !state.drawerOpen;
        const drawer = el('ipiv-config-drawer');
        const btn = el('ipiv-btn-toggle-config');
        if (drawer) drawer.style.display = state.drawerOpen ? 'grid' : 'none';
        if (btn) {
            btn.innerHTML = `<i class="fa-solid fa-sliders"></i> Scope & Providers <i class="fa-solid fa-chevron-${state.drawerOpen ? 'up' : 'down'}"></i>`;
        }
    }

    // =========================================================================
    // 2. START, POLL, CANCEL, RESUME INVESTIGATION
    // =========================================================================

    function gatherRunPayload(seedOverride = '') {
        const seedVal = (seedOverride || el('ipiv-seed-input')?.value || '').trim();
        const enabledMethods = [...document.querySelectorAll('.ipiv-method-cb:checked')].map((n) => n.value);
        const selectedProviders = [...document.querySelectorAll('.ipiv-provider-cb:checked')].map((n) => n.value);
        return {
            seed: seedVal,
            mode: state.mode,
            max_depth: Number(el('ipiv-max-depth')?.value || 1),
            max_assets: Number(el('ipiv-max-assets')?.value || 40),
            per_pivot_limit: Number(el('ipiv-per-pivot-limit')?.value || 15),
            timeout_seconds: Number(el('ipiv-timeout')?.value || 45),
            api_budget: Number(el('ipiv-api-budget')?.value || 16),
            min_confidence_to_expand: Number(el('ipiv-min-conf-expand')?.value || 45),
            passive_only: el('ipiv-passive-only') ? el('ipiv-passive-only').checked : true,
            enabled_methods: enabledMethods,
            providers: selectedProviders,
            async_execution: true,
            ...getLocalKeys()
        };
    }

    async function startPivotInvestigation(seedOverride = '') {
        const payload = gatherRunPayload(seedOverride);
        if (!payload.seed) {
            alert('Please enter an IP, domain, URL, file hash, or certificate fingerprint to pivot.');
            return;
        }
        if (seedOverride && el('ipiv-seed-input')) {
            el('ipiv-seed-input').value = seedOverride;
            el('ipiv-detected-type').textContent = detectIndicatorTypeClient(seedOverride);
        }

        const startBtn = el('ipiv-btn-start');
        if (startBtn) startBtn.disabled = true;

        try {
            const inv = await apiCall('/api/infra-pivoting/run', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            state.investigation = inv;
            state.selectedNodeId = inv.assets && inv.assets[0] ? inv.assets[0].asset_id : null;
            renderInvestigationState(inv);
            startPolling(inv.id);
        } catch (err) {
            alert(`Pivot error: ${err.message}`);
        } finally {
            if (startBtn) startBtn.disabled = false;
        }
    }

    function startPolling(invId) {
        stopPolling();
        state.pollTimer = setInterval(async () => {
            try {
                const inv = await apiCall(`/api/infra-pivoting/investigations/${encodeURIComponent(invId)}`);
                state.investigation = inv;
                renderInvestigationState(inv);
                if (inv.status !== 'running' && inv.status !== 'queued') {
                    stopPolling();
                    loadHistoryList();
                }
            } catch (err) {
                console.error('[InfraPivoting] Poll error:', err);
                stopPolling();
            }
        }, 1200);
    }

    function stopPolling() {
        if (state.pollTimer) {
            clearInterval(state.pollTimer);
            state.pollTimer = null;
        }
    }

    async function cancelCurrentInvestigation() {
        if (!state.investigation) return;
        try {
            const inv = await apiCall(`/api/infra-pivoting/investigations/${encodeURIComponent(state.investigation.id)}/cancel`, {
                method: 'POST'
            });
            stopPolling();
            state.investigation = inv;
            renderInvestigationState(inv);
            loadHistoryList();
        } catch (err) {
            alert(`Failed to cancel: ${err.message}`);
        }
    }

    async function resumeInvestigationById(invId) {
        const targetId = invId || (state.investigation && state.investigation.id);
        if (!targetId) return;
        try {
            const inv = await apiCall(`/api/infra-pivoting/investigations/${encodeURIComponent(targetId)}/resume`, {
                method: 'POST',
                body: JSON.stringify(getLocalKeys())
            });
            state.investigation = inv;
            renderInvestigationState(inv);
            startPolling(inv.id);
        } catch (err) {
            alert(`Failed to resume: ${err.message}`);
        }
    }

    async function loadInvestigationById(invId) {
        stopPolling();
        try {
            const inv = await apiCall(`/api/infra-pivoting/investigations/${encodeURIComponent(invId)}`);
            state.investigation = inv;
            if (el('ipiv-seed-input')) {
                el('ipiv-seed-input').value = inv.canonical_seed || inv.seed_value;
                el('ipiv-detected-type').textContent = (inv.seed_type || 'AUTO').toUpperCase();
            }
            state.selectedNodeId = inv.assets && inv.assets[0] ? inv.assets[0].asset_id : null;
            renderInvestigationState(inv);
            if (inv.status === 'running') {
                startPolling(inv.id);
            }
        } catch (err) {
            alert(`Failed to load investigation: ${err.message}`);
        }
    }

    // =========================================================================
    // 3. RENDER PROGRESS, FINDINGS, EVIDENCE & HISTORY
    // =========================================================================

    function renderInvestigationState(inv) {
        if (!inv) return;
        const progCard = el('ipiv-progress-card');
        if (progCard) progCard.style.display = 'flex';

        const isRunning = inv.status === 'running' || inv.status === 'queued';
        if (el('ipiv-btn-cancel')) el('ipiv-btn-cancel').style.display = isRunning ? 'inline-flex' : 'none';
        if (el('ipiv-btn-resume')) el('ipiv-btn-resume').style.display = (!isRunning && inv.can_resume) ? 'inline-flex' : 'none';

        const badge = el('ipiv-status-badge');
        if (badge) {
            badge.className = `ipiv-status-badge ${inv.status}`;
            const icon = isRunning ? 'fa-spinner fa-spin' : (inv.status === 'completed' ? 'fa-circle-check' : 'fa-circle-pause');
            badge.innerHTML = `<i class="fa-solid ${icon}"></i> ${esc(inv.status.toUpperCase())}`;
        }

        const prog = inv.progress || {};
        const assetsCount = (inv.assets || []).length;
        const relsCount = (inv.relationships || []).length;
        const obsCount = (inv.observations || []).length;
        const apiUsed = prog.api_calls_made ?? (inv.api_audit || []).length;
        const apiBudget = prog.api_budget ?? (inv.config || {}).api_budget ?? 16;
        const maxAssets = prog.max_assets ?? (inv.config || {}).max_assets ?? 40;
        const elapsed = prog.elapsed_seconds ?? 0;

        if (el('ipiv-metric-assets')) el('ipiv-metric-assets').textContent = `${assetsCount} / ${maxAssets}`;
        if (el('ipiv-metric-rels')) el('ipiv-metric-rels').textContent = String(relsCount);
        if (el('ipiv-metric-obs')) el('ipiv-metric-obs').textContent = String(obsCount);
        if (el('ipiv-metric-api')) el('ipiv-metric-api').textContent = `${apiUsed} / ${apiBudget}`;
        if (el('ipiv-metric-frontier')) el('ipiv-metric-frontier').textContent = String(inv.frontier_count ?? prog.frontier_remaining ?? 0);
        if (el('ipiv-metric-elapsed')) el('ipiv-metric-elapsed').textContent = `${elapsed}s`;

        const pct = Math.min(100, Math.round((apiUsed / Math.max(1, apiBudget)) * 100));
        if (el('ipiv-budget-bar')) el('ipiv-budget-bar').style.width = `${pct}%`;

        // Update subtab badge counts
        if (el('ipiv-count-graph')) el('ipiv-count-graph').textContent = String(assetsCount);
        if (el('ipiv-count-findings')) el('ipiv-count-findings').textContent = String(assetsCount);
        if (el('ipiv-count-evidence')) el('ipiv-count-evidence').textContent = String(obsCount);
        const threatAssessment = inv.threat_assessment || inv.i2a || {};
        const attrCount = ((threatAssessment.attribution && threatAssessment.attribution.candidates) || []).length;
        const pbCount = (threatAssessment.defensive_playbook || []).length;
        if (el('ipiv-count-attribution')) el('ipiv-count-attribution').textContent = String(attrCount + pbCount);

        // Provider live telemetry pills
        const provStrip = el('ipiv-provider-telemetry');
        if (provStrip && prog.provider_stats) {
            const entries = Object.entries(prog.provider_stats);
            provStrip.innerHTML = entries.map(([pName, st]) => {
                let statusColor = '#34d399';
                let note = `${st.calls} calls (${st.success} hits)`;
                if (st.entitlement_errors > 0) {
                    statusColor = '#f87171';
                    note = `Entitlement / Key Restricted`;
                } else if (st.rate_limited > 0) {
                    statusColor = '#fbbf24';
                    note = `Rate Limited (${st.calls} calls)`;
                }
                return `<span class="ipiv-tag" style="border-color:${statusColor};color:${statusColor};" title="${esc(st.last_error || note)}">
                    <strong>${esc(pName)}</strong>: ${esc(note)}
                </span>`;
            }).join('');
        }

        // Render the three-question assessment and playbook.
        renderThreatAssessmentTriageStrip(inv);
        renderAttributionAndPlaybook(inv);

        // Update Graph Data
        syncGraphFromInvestigation(inv);
        renderInspector();
        renderFindingsTable(inv);
        renderEvidenceTables(inv);
    }

    function renderRoleBadgesHtml(roles) {
        if (!roles || !roles.length) return '';
        return roles.map((r) => {
            const cls = esc(r.badge_class || 'shared');
            const evTitle = esc((r.evidence || []).join(' | '));
            return `<span class="ipiv-role-badge ${cls}" title="${evTitle}">${esc(r.label || r.role)}</span>`;
        }).join(' ');
    }

    function renderThreatAssessmentTriageStrip(inv) {
        const strip = el('ipiv-triage-strip');
        if (!strip) return;
        const threatAssessment = inv.threat_assessment || inv.i2a;
        if (!threatAssessment || !threatAssessment.three_questions || !threatAssessment.three_questions.what) {
            strip.style.display = 'none';
            return;
        }
        strip.style.display = 'grid';
        const q1 = threatAssessment.three_questions.what || {};
        const q2 = threatAssessment.three_questions.connected || {};
        const q3 = threatAssessment.three_questions.who || {};

        const whatBox = el('ipiv-triage-what');
        if (whatBox) {
            const rolesHtml = renderRoleBadgesHtml(q1.roles || []);
            const telem = (q1.native_telemetry || []).slice(0, 4).map((t) => `<span class="ipiv-tag" style="margin:0;">${esc(t)}</span>`).join(' ');
            const firstSeen = q1.first_observed ? `<div style="font-size:0.71rem;color:#94a3b8;">Earliest Observed: <strong style="color:#e2e8f0;">${esc(q1.first_observed.date)}</strong> (${esc(q1.first_observed.source)})</div>` : '';
            const malFams = (q1.malware_families || []).length
                ? `<div style="font-size:0.71rem;color:#fca5a5;">Associated Malware: <strong>${(q1.malware_families || []).map(esc).join(', ')}</strong></div>`
                : '';
            whatBox.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap;">
                    <span class="ipiv-mono" style="font-weight:700;color:#FFCC00;">${esc(q1.defanged || q1.ioc)}</span>
                    <div style="display:flex;gap:4px;flex-wrap:wrap;">${rolesHtml || `<span class="ipiv-type-badge">${esc(q1.type || 'SEED')}</span>`}</div>
                </div>
                ${telem ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:2px;">${telem}</div>` : '<div style="font-size:0.72rem;color:#64748b;">Passive seed telemetry collected.</div>'}
                ${firstSeen}
                ${malFams}
            `;
        }

        const connBox = el('ipiv-triage-connected');
        if (connBox) {
            const tc = Object.entries(q2.type_counts || {}).map(([k, n]) => `${n} ${k.toUpperCase()}`).join(', ');
            const c2List = (q2.c2_candidates || []);
            const payList = (q2.payload_hosts || []);
            const guards = (q2.shared_infra_guards || []);
            connBox.innerHTML = `
                <div>Discovered <strong style="color:#f8fafc;">${q2.total_discovered ?? 0}</strong> linked asset(s) across <strong style="color:#f8fafc;">${q2.total_relationships ?? 0}</strong> edge(s)${tc ? ` (${esc(tc)})` : ''}.</div>
                ${c2List.length ? `<div style="font-size:0.71rem;color:#fca5a5;"><i class="fa-solid fa-crosshairs"></i> <strong>C2 Candidates (${c2List.length}):</strong> <span class="ipiv-mono">${c2List.slice(0, 3).map(esc).join(', ')}</span></div>` : ''}
                ${payList.length ? `<div style="font-size:0.71rem;color:#fcd34d;"><i class="fa-solid fa-file-Arrow-down"></i> <strong>Payload Hosts (${payList.length}):</strong> <span class="ipiv-mono">${payList.slice(0, 3).map(esc).join(', ')}</span></div>` : ''}
                ${guards.length ? `<div style="font-size:0.7rem;color:#94a3b8;"><i class="fa-solid fa-shield-halved" style="color:#f59e0b;"></i> <strong>Shared Infra Guard:</strong> ${esc(guards[0])}</div>` : ''}
            `;
        }

        const whoBox = el('ipiv-triage-who');
        if (whoBox) {
            const top = q3.top_candidate;
            if (top) {
                const tierCls = top.confidence >= 55 ? 'high' : (top.confidence >= 25 ? 'medium' : 'low');
                whoBox.innerHTML = `
                    <div style="display:flex;align-items:center;justify-content:space-between;gap:6px;">
                        <strong style="color:#f8fafc;font-size:0.84rem;">${esc(top.name)} ${top.country ? `<span style="color:#94a3b8;font-size:0.72rem;">(${esc(top.country)})</span>` : ''}</strong>
                        <span class="ipiv-conf-pill ${tierCls}">${top.confidence}% &middot; ${esc(top.confidence_label.toUpperCase())}</span>
                    </div>
                    <div style="font-size:0.71rem;color:#94a3b8;line-height:1.38;">${esc(top.statement.slice(0, 175))}${top.statement.length > 175 ? '…' : ''}</div>
                    <div>
                        <button type="button" class="ipiv-link-btn" id="ipiv-triage-open-attr" style="color:#FFCC00;">
                            View Rarity Breakdown &amp; Defensive Playbook &rarr;
                        </button>
                    </div>
                `;
                el('ipiv-triage-open-attr')?.addEventListener('click', () => switchSubtab('attribution'));
            } else {
                whoBox.innerHTML = `
                    <div style="color:#94a3b8;font-size:0.73rem;">No named APT group reached the multi-dimensional attribution threshold.</div>
                    <div style="font-size:0.69rem;color:#64748b;">An indicator can be malicious or shared infrastructure without being attributable to a specific threat actor.</div>
                    <div>
                        <button type="button" class="ipiv-link-btn" id="ipiv-triage-open-pb" style="color:#FFCC00;">
                            View SOC Defensive Playbook &rarr;
                        </button>
                    </div>
                `;
                el('ipiv-triage-open-pb')?.addEventListener('click', () => switchSubtab('attribution'));
            }
        }
    }

    function renderAttributionAndPlaybook(inv) {
        const attrBox = el('ipiv-attribution-content');
        const pbBox = el('ipiv-playbook-content');
        const threatAssessment = (inv && (inv.threat_assessment || inv.i2a)) || {};
        const attr = threatAssessment.attribution || {};
        const candidates = attr.candidates || [];
        const playbook = threatAssessment.defensive_playbook || [];

        if (attrBox) {
            if (!candidates.length) {
                attrBox.innerHTML = `
                    <div style="background:#080d18;border:1px solid rgba(255,255,255,0.06);border-radius:10px;padding:16px;">
                        <div style="font-size:0.8rem;font-weight:700;color:#e2e8f0;margin-bottom:6px;">
                            <i class="fa-solid fa-scale-balanced" style="color:#FFCC00;"></i> No APT Group Reached Attribution Threshold
                        </div>
                        <div style="font-size:0.75rem;color:#94a3b8;line-height:1.5;">
                            ${esc(attr.note || 'No threat actor reached the evidence threshold.')}
                        </div>
                        <div style="margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,255,255,0.06);">
                            <div style="font-size:0.68rem;font-weight:700;color:#94a3b8;text-transform:uppercase;margin-bottom:6px;">Active Attribution Guard Rails</div>
                            ${(attr.guard_rails_applied || []).map((g) => `<div style="font-size:0.71rem;color:#64748b;margin-bottom:3px;">&bull; ${esc(g)}</div>`).join('')}
                        </div>
                    </div>
                `;
            } else {
                attrBox.innerHTML = candidates.map((c, idx) => {
                    const tierCls = c.confidence >= 55 ? 'high' : (c.confidence >= 25 ? 'medium' : 'low');
                    const dims = c.dimensions || {};
                    const dimKeys = ['reported', 'infrastructure', 'malware', 'ttp', 'victimology', 'operational'];
                    return `
                        <div class="ipiv-actor-card ${idx === 0 ? 'top' : ''}">
                            <div class="ipiv-actor-head">
                                <div>
                                    <span class="ipiv-actor-name">${esc(c.name)}</span>
                                    <span style="font-size:0.72rem;color:#94a3b8;margin-left:6px;">${esc(c.group_id)}${c.country ? ` &middot; ${esc(c.country)}` : ''}</span>
                                    ${(c.aliases && c.aliases.length) ? `<div style="font-size:0.69rem;color:#64748b;margin-top:2px;">Aliases: ${c.aliases.slice(0, 5).map(esc).join(', ')}</div>` : ''}
                                </div>
                                <span class="ipiv-conf-pill ${tierCls}">${c.confidence}% &middot; ${esc(c.confidence_label.toUpperCase())}</span>
                            </div>

                            ${c.capped_reason ? `
                                <div style="font-size:0.71rem;color:#fcd34d;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:6px;padding:5px 8px;">
                                    <i class="fa-solid fa-shield-halved"></i> <strong>Guard Rail Applied:</strong> ${esc(c.capped_reason)}
                                </div>
                            ` : ''}

                            <div class="ipiv-actor-statement">${esc(c.statement)}</div>

                            <div class="ipiv-dim-grid">
                                ${dimKeys.map((dk) => {
                                    const val = dims[dk];
                                    const isAssessed = val !== null && val !== undefined;
                                    const isActive = isAssessed && val > 0;
                                    return `
                                        <div class="ipiv-dim-cell ${isActive ? 'active' : ''}">
                                            <span class="ipiv-dim-lbl">${esc(dk.slice(0, 8))}</span>
                                            <span class="ipiv-dim-val" style="color:${isActive ? '#34d399' : '#64748b'};">${isAssessed ? val : 'N/A'}</span>
                                        </div>
                                    `;
                                }).join('')}
                            </div>

                            <div style="display:flex;flex-direction:column;gap:4px;">
                                ${(c.evidence || []).slice(0, 6).map((ev) => `
                                    <div style="display:flex;align-items:center;justify-content:space-between;font-size:0.72rem;background:#0c1322;padding:5px 8px;border-radius:5px;border:1px solid #1a253a;">
                                        <div>
                                            <span class="ipiv-tag" style="margin:0 4px 0 0;color:#FFCC00;">${esc(ev.dimension)}</span>
                                            <span style="color:#e2e8f0;">${esc(ev.detail)}</span>
                                        </div>
                                        <span class="ipiv-mono" style="font-size:0.7rem;color:#34d399;white-space:nowrap;">+${ev.weight} pts (rarity ${ev.rarity})</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `;
                }).join('');
            }
        }

        if (pbBox) {
            if (!playbook.length) {
                pbBox.innerHTML = `<div style="color:#64748b;font-size:0.8rem;text-align:center;padding:24px;">No defensive actions generated yet.</div>`;
            } else {
                pbBox.innerHTML = playbook.map((act) => `
                    <div class="ipiv-playbook-card ${esc(act.color || 'slate')}">
                        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
                            <span style="font-size:0.8rem;font-weight:700;color:#f8fafc;">
                                <i class="fa-solid ${esc(act.icon || 'fa-shield-halved')}" style="color:#FFCC00;margin-right:5px;"></i>
                                ${esc(act.title)}
                            </span>
                            <span class="ipiv-tag" style="margin:0;">${esc(act.priority)} &middot; ${esc(act.category)}</span>
                        </div>
                        <div style="font-size:0.75rem;color:#cbd5e1;line-height:1.45;">${esc(act.guidance)}</div>
                        ${(act.indicators && act.indicators.length) ? `
                            <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:2px;">
                                ${act.indicators.map((ind) => `<span class="ipiv-tag ipiv-mono" style="margin:0;font-size:0.68rem;">${esc(ind)}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                `).join('');
            }
        }
    }

    function renderFindingsTable(inv) {
        const tbody = el('ipiv-findings-tbody');
        if (!tbody) return;
        const q = (el('ipiv-findings-search')?.value || '').trim().toLowerCase();
        const typeFilter = el('ipiv-findings-type')?.value || 'all';
        const tierFilter = el('ipiv-findings-tier')?.value || 'all';

        const rows = (inv.assets || []).filter((a) => {
            if (typeFilter !== 'all' && a.asset_type !== typeFilter) return false;
            if (tierFilter !== 'all' && a.confidence_tier !== tierFilter) return false;
            if (q && !a.value.toLowerCase().includes(q) && !a.providers.join(' ').toLowerCase().includes(q) && !a.pivot_methods.join(' ').toLowerCase().includes(q)) {
                return false;
            }
            return true;
        });

        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:#64748b;padding:28px;">No infrastructure findings match current filters.</td></tr>`;
            return;
        }

        tbody.innerHTML = rows.map((a) => {
            const penaltiesHtml = (a.penalties || []).map((p) =>
                `<span class="ipiv-tag penalty" title="${esc(p.reason)}">-${p.deduction} ${esc(p.type)}</span>`
            ).join('') + (a.shared_infra_flags || []).map((fl) =>
                `<span class="ipiv-tag penalty">${esc(fl)}</span>`
            ).join('');

            const malEntries = Object.entries(a.maliciousness_context || {});
            const threatHtml = malEntries.length
                ? malEntries.map(([k, v]) => `<span class="ipiv-tag threat">${esc(k)}: ${esc(v)}</span>`).join('')
                : `<span style="color:#64748b;font-size:0.72rem;">Unassessed / Separate</span>`;

            const provHtml = (a.providers || []).map((p) => `<span class="ipiv-tag">${esc(p)}</span>`).join('');
            const methodHtml = (a.pivot_methods || []).map((m) => `<span class="ipiv-tag">${esc(m)}</span>`).join('');
            const dates = [a.first_seen ? `First: ${a.first_seen.slice(0, 10)}` : '', a.last_seen ? `Last: ${a.last_seen.slice(0, 10)}` : ''].filter(Boolean).join('<br>');
            const rolesHtml = renderRoleBadgesHtml(a.roles || []);

            return `
                <tr>
                    <td class="ipiv-mono"><strong>${esc(a.value)}</strong></td>
                    <td>
                        <div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;">
                            <span class="ipiv-tag" style="color:${TYPE_COLORS[a.asset_type] || '#fff'}">${esc(a.asset_type.toUpperCase())}</span>
                            ${rolesHtml}
                        </div>
                    </td>
                    <td class="ipiv-mono">Hop ${a.depth}</td>
                    <td>
                        <div style="display:flex;align-items:center;gap:8px;">
                            <span class="ipiv-conf-pill ${esc(a.confidence_tier)}">${a.relationship_confidence}/100</span>
                            <span style="font-size:0.7rem;color:#94a3b8;">${esc(a.confidence_tier.toUpperCase())}</span>
                        </div>
                    </td>
                    <td>${penaltiesHtml || '<span style="color:#64748b;">None</span>'}</td>
                    <td>${provHtml}</td>
                    <td>${methodHtml}</td>
                    <td>${threatHtml}</td>
                    <td style="font-size:0.7rem;color:#94a3b8;white-space:nowrap;">${dates || '—'}</td>
                    <td style="white-space:nowrap;">
                        <button type="button" class="ipiv-btn-secondary ipiv-act-inspect" data-aid="${esc(a.asset_id)}" title="Inspect in Graph">
                            <i class="fa-solid fa-magnifying-glass"></i>
                        </button>
                        <button type="button" class="ipiv-btn-secondary ipiv-act-pivot" data-val="${esc(a.value)}" title="Launch New Pivot from this Asset">
                            <i class="fa-solid fa-arrows-split-up-and-left"></i> Pivot
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.querySelectorAll('.ipiv-act-inspect').forEach((btn) => {
            btn.addEventListener('click', () => {
                state.selectedNodeId = btn.dataset.aid;
                switchSubtab('graph');
                renderInspector();
                drawGraph();
            });
        });

        tbody.querySelectorAll('.ipiv-act-pivot').forEach((btn) => {
            btn.addEventListener('click', () => {
                startPivotInvestigation(btn.dataset.val);
            });
        });
    }

    function renderEvidenceTables(inv) {
        const obsTbody = el('ipiv-observations-tbody');
        const auditTbody = el('ipiv-audit-tbody');
        const q = (el('ipiv-evidence-search')?.value || '').trim().toLowerCase();

        if (obsTbody) {
            const obsRows = (inv.observations || []).filter((o) => {
                if (!q) return true;
                return (
                    (o.asset_id || '').toLowerCase().includes(q) ||
                    (o.provider || '').toLowerCase().includes(q) ||
                    (o.pivot_method || '').toLowerCase().includes(q) ||
                    (o.summary || '').toLowerCase().includes(q) ||
                    (o.field_value || '').toLowerCase().includes(q)
                );
            });

            obsTbody.innerHTML = obsRows.length ? obsRows.map((o) => `
                <tr>
                    <td><span class="ipiv-tag">${esc(o.provider)}</span></td>
                    <td><span class="ipiv-tag">${esc(o.pivot_method)}</span></td>
                    <td class="ipiv-mono" style="font-size:0.73rem;">${esc(o.related_asset_id)} &rarr; ${esc(o.asset_id)}</td>
                    <td><code>${esc(o.field_name)}</code> = <span class="ipiv-mono">${esc(o.field_value)}</span></td>
                    <td>${esc(o.summary)}</td>
                    <td style="font-size:0.7rem;color:#94a3b8;white-space:nowrap;">${esc((o.last_seen || o.observed_at || '').slice(0, 19))}</td>
                    <td>
                        ${o.raw_ref_id ? `<button type="button" class="ipiv-btn-secondary ipiv-view-raw-btn" data-raw="${esc(o.raw_ref_id)}"><i class="fa-solid fa-code"></i> Raw JSON</button>` : '—'}
                    </td>
                </tr>
            `).join('') : `<tr><td colspan="7" style="text-align:center;color:#64748b;padding:24px;">No evidence observations recorded yet.</td></tr>`;

            obsTbody.querySelectorAll('.ipiv-view-raw-btn').forEach((btn) => {
                btn.addEventListener('click', () => openRawResponseModal(btn.dataset.raw));
            });
        }

        if (auditTbody) {
            const audits = inv.api_audit || [];
            auditTbody.innerHTML = audits.length ? audits.map((a) => {
                const stColor = a.status === 'ok' ? '#34d399' : (a.status === 'empty' ? '#94a3b8' : '#f87171');
                return `
                    <tr>
                        <td><span class="ipiv-tag">${esc(a.provider)}</span></td>
                        <td><span class="ipiv-tag">${esc(a.pivot_method)}</span></td>
                        <td class="ipiv-mono" style="font-size:0.74rem;">${esc(a.query)}</td>
                        <td><span class="ipiv-tag" style="color:${stColor};border-color:${stColor};">${esc(a.status.toUpperCase())}</span></td>
                        <td class="ipiv-mono">${a.latency_ms} ms</td>
                        <td style="color:#fca5a5;font-size:0.73rem;">${esc(a.error_message || '—')}</td>
                        <td>
                            ${a.raw_ref_id ? `<button type="button" class="ipiv-btn-secondary ipiv-view-raw-btn" data-raw="${esc(a.raw_ref_id)}"><i class="fa-solid fa-code"></i> Raw</button>` : '—'}
                        </td>
                    </tr>
                `;
            }).join('') : `<tr><td colspan="7" style="text-align:center;color:#64748b;padding:20px;">No API calls logged.</td></tr>`;

            auditTbody.querySelectorAll('.ipiv-view-raw-btn').forEach((btn) => {
                btn.addEventListener('click', () => openRawResponseModal(btn.dataset.raw));
            });
        }
    }

    async function openRawResponseModal(rawRefId) {
        if (!rawRefId) return;
        try {
            const data = await apiCall(`/api/infra-pivoting/raw/${encodeURIComponent(rawRefId)}`);
            const overlay = el('ipiv-raw-modal-overlay');
            const title = el('ipiv-raw-modal-title');
            const pre = el('ipiv-raw-modal-pre');
            if (title) title.textContent = `Raw Provider Provenance · ${data.provider.toUpperCase()} (${data.query})`;
            if (pre) pre.textContent = JSON.stringify(data.response, null, 2);
            if (overlay) overlay.style.display = 'flex';
        } catch (err) {
            alert(`Could not load raw response: ${err.message}`);
        }
    }

    async function loadHistoryList() {
        const tbody = el('ipiv-history-tbody');
        if (!tbody) return;
        try {
            const data = await apiCall('/api/infra-pivoting/investigations?limit=50');
            const list = data.investigations || [];
            if (el('ipiv-count-history')) el('ipiv-count-history').textContent = String(list.length);
            if (!list.length) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:#64748b;padding:24px;">No saved investigations yet.</td></tr>`;
                return;
            }
            tbody.innerHTML = list.map((item) => {
                const prog = item.progress || {};
                return `
                    <tr>
                        <td class="ipiv-mono"><strong>${esc(item.canonical_seed)}</strong></td>
                        <td><span class="ipiv-tag">${esc((item.seed_type || '').toUpperCase())}</span></td>
                        <td><span class="ipiv-tag">${esc((item.mode || '').toUpperCase())}</span></td>
                        <td><span class="ipiv-status-badge ${esc(item.status)}">${esc(item.status)}</span></td>
                        <td class="ipiv-mono">${prog.assets_discovered ?? 1} assets · ${prog.relationships_mapped ?? 0} edges</td>
                        <td class="ipiv-mono">${prog.api_calls_made ?? 0} calls</td>
                        <td style="font-size:0.72rem;color:#94a3b8;">${esc((item.updated_at || '').slice(0, 19).replace('T', ' '))}</td>
                        <td style="white-space:nowrap;">
                            <button type="button" class="ipiv-btn-secondary ipiv-hist-load" data-id="${esc(item.id)}">
                                <i class="fa-solid fa-folder-open"></i> Load
                            </button>
                            ${item.can_resume ? `<button type="button" class="ipiv-btn-warning ipiv-hist-resume" data-id="${esc(item.id)}"><i class="fa-solid fa-play"></i> Resume</button>` : ''}
                            <button type="button" class="ipiv-btn-secondary ipiv-hist-delete" data-id="${esc(item.id)}" title="Delete">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');

            tbody.querySelectorAll('.ipiv-hist-load').forEach((btn) => {
                btn.addEventListener('click', () => {
                    loadInvestigationById(btn.dataset.id);
                    switchSubtab('graph');
                });
            });
            tbody.querySelectorAll('.ipiv-hist-resume').forEach((btn) => {
                btn.addEventListener('click', () => {
                    resumeInvestigationById(btn.dataset.id);
                    switchSubtab('graph');
                });
            });
            tbody.querySelectorAll('.ipiv-hist-delete').forEach((btn) => {
                btn.addEventListener('click', async () => {
                    await apiCall(`/api/infra-pivoting/investigations/${encodeURIComponent(btn.dataset.id)}`, { method: 'DELETE' });
                    loadHistoryList();
                });
            });
        } catch (err) {
            console.error('[InfraPivoting] Failed to load history:', err);
        }
    }

    // =========================================================================
    // 4. INTERACTIVE RELATIONSHIP GRAPH & INSPECTOR
    // =========================================================================

    function syncGraphFromInvestigation(inv) {
        const canvas = el('ipiv-graph-canvas');
        if (!canvas) return;
        const w = canvas.clientWidth || 800;
        const h = canvas.clientHeight || 520;
        const cx = w / 2;
        const cy = h / 2;

        const existingPositions = new Map(state.nodes.map((n) => [n.id, { x: n.x, y: n.y }]));
        const rawNodes = (inv.graph && inv.graph.nodes) || [];
        const rawEdges = (inv.graph && inv.graph.edges) || [];

        // Filter nodes by user graph controls
        const filteredNodes = rawNodes.filter((n) => {
            if (n.depth === 0) return true;
            if (n.confidence < state.graphMinConf) return false;
            if (state.graphTypeFilter !== 'all' && n.type !== state.graphTypeFilter) return false;
            if (state.graphHideNoise && (n.tier === 'noise' || (n.shared_flags && n.shared_flags.length > 0 && n.confidence < 50))) {
                return false;
            }
            return true;
        });

        const allowedIds = new Set(filteredNodes.map((n) => n.id));
        const byDepth = {};
        filteredNodes.forEach((n) => {
            (byDepth[n.depth] = byDepth[n.depth] || []).push(n);
        });

        state.nodes = filteredNodes.map((n) => {
            const prev = existingPositions.get(n.id);
            if (prev && state.graphLayout === 'force') {
                return { ...n, x: prev.x, y: prev.y, vx: 0, vy: 0 };
            }
            if (n.depth === 0) {
                return { ...n, x: cx, y: cy, vx: 0, vy: 0 };
            }
            const group = byDepth[n.depth] || [n];
            const idx = group.indexOf(n);
            const radius = Math.min(w, h) * 0.16 * n.depth + 35;
            const angle = (2 * Math.PI * idx) / Math.max(1, group.length) - Math.PI / 2;
            return {
                ...n,
                x: cx + radius * Math.cos(angle),
                y: cy + radius * Math.sin(angle),
                vx: 0,
                vy: 0
            };
        });

        state.edges = rawEdges.filter((e) => allowedIds.has(e.source) && allowedIds.has(e.target));
        drawGraph();
    }

    function drawGraph() {
        const canvas = el('ipiv-graph-canvas');
        if (!canvas) return;
        const rect = canvas.parentElement.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
            if (canvas.width !== Math.floor(rect.width) || canvas.height !== Math.floor(rect.height)) {
                canvas.width = Math.floor(rect.width);
                canvas.height = Math.floor(rect.height);
            }
        }
        const ctx = canvas.getContext('2d');
        const w = canvas.width;
        const h = canvas.height;
        ctx.clearRect(0, 0, w, h);

        ctx.save();
        ctx.translate(w / 2 + state.camera.x, h / 2 + state.camera.y);
        ctx.scale(state.camera.zoom, state.camera.zoom);
        ctx.translate(-w / 2, -h / 2);

        // Draw concentric hop depth rings in radial mode
        if (state.graphLayout === 'radial' && state.nodes.length > 0) {
            const cx = w / 2;
            const cy = h / 2;
            for (let d = 1; d <= 3; d++) {
                const r = Math.min(w, h) * 0.16 * d + 35;
                ctx.beginPath();
                ctx.arc(cx, cy, r, 0, Math.PI * 2);
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
                ctx.lineWidth = 1;
                ctx.setLineDash([4, 6]);
                ctx.stroke();
                ctx.setLineDash([]);
            }
        }

        const nodeMap = new Map(state.nodes.map((n) => [n.id, n]));

        // Draw edges
        state.edges.forEach((e) => {
            const s = nodeMap.get(e.source);
            const t = nodeMap.get(e.target);
            if (!s || !t) return;

            const isSelected = state.selectedNodeId === s.id || state.selectedNodeId === t.id;
            ctx.beginPath();
            ctx.moveTo(s.x, s.y);
            ctx.lineTo(t.x, t.y);
            ctx.strokeStyle = isSelected ? 'rgba(255, 204, 0, 0.75)' : 'rgba(148, 163, 184, 0.25)';
            ctx.lineWidth = isSelected ? 2.2 : Math.max(1, (e.confidence_score || 30) / 45);
            ctx.stroke();

            // Relationship label on selected or high-confidence edges
            if (isSelected || state.nodes.length <= 18) {
                const mx = (s.x + t.x) / 2;
                const my = (s.y + t.y) / 2;
                ctx.fillStyle = isSelected ? '#FFCC00' : '#64748b';
                ctx.font = '600 10px "Plus Jakarta Sans", sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText(`${e.relationship_type} (${e.confidence_score}%)`, mx, my - 4);
            }
        });

        // Draw nodes
        state.nodes.forEach((n) => {
            const isSeed = n.depth === 0;
            const isSelected = state.selectedNodeId === n.id;
            const radius = isSeed ? 18 : (n.confidence >= 70 ? 14 : 11);
            const color = isSeed ? TYPE_COLORS.seed : (TYPE_COLORS[n.type] || '#38bdf8');

            if (isSelected || isSeed) {
                ctx.beginPath();
                ctx.arc(n.x, n.y, radius + 5, 0, Math.PI * 2);
                ctx.fillStyle = isSelected ? 'rgba(255, 204, 0, 0.25)' : 'rgba(255, 204, 0, 0.14)';
                ctx.fill();
            }

            ctx.beginPath();
            ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
            ctx.fillStyle = '#090e1a';
            ctx.fill();
            ctx.lineWidth = isSelected ? 3 : 2.2;
            ctx.strokeStyle = isSelected ? '#FFCC00' : color;
            ctx.stroke();

            // Inner core dot
            ctx.beginPath();
            ctx.arc(n.x, n.y, radius * 0.45, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();

            // Node label
            const label = n.label.length > 26 ? n.label.slice(0, 24) + '…' : n.label;
            ctx.font = isSeed ? '700 11px "JetBrains Mono", monospace' : '600 10px "JetBrains Mono", monospace';
            ctx.fillStyle = isSelected ? '#FFCC00' : '#e2e8f0';
            ctx.textAlign = 'center';
            ctx.fillText(label, n.x, n.y + radius + 13);

            // Role badge tag beneath node label on canvas if present
            if (n.roles && n.roles.length > 0) {
                const topRole = n.roles[0];
                const roleColors = {
                    c2: '#fca5a5',
                    payload: '#fcd34d',
                    shared: '#94a3b8',
                    dns: '#7dd3fc',
                    cert: '#d8b4fe'
                };
                ctx.font = '700 8.5px "Plus Jakarta Sans", sans-serif';
                ctx.fillStyle = roleColors[topRole.badge_class] || '#94a3b8';
                ctx.fillText(`[${(topRole.label || topRole.role).toUpperCase()}]`, n.x, n.y + radius + 24);
            }

            if (!isSeed) {
                ctx.font = '700 9px "JetBrains Mono", monospace';
                ctx.fillStyle = n.confidence >= 70 ? '#34d399' : (n.confidence >= 45 ? '#fbbf24' : '#94a3b8');
                ctx.fillText(`${n.confidence}%`, n.x, n.y - radius - 5);
            }
        });

        ctx.restore();
    }

    function renderInspector() {
        const box = el('ipiv-inspector-content');
        if (!box) return;
        const inv = state.investigation;
        if (!inv || !inv.assets || !inv.assets.length) {
            box.innerHTML = `<div style="color:#64748b;font-size:0.78rem;text-align:center;padding:36px 12px;">
                <i class="fa-solid fa-diagram-project" style="font-size:1.5rem;color:#334155;margin-bottom:10px;display:block;"></i>
                Click any node on the graph to inspect its confidence score, attributes, and connected relationships.
            </div>`;
            return;
        }

        const asset = inv.assets.find((a) => a.asset_id === state.selectedNodeId) || inv.assets[0];
        if (!asset) return;

        const isSeed = asset.depth === 0;
        const sb = asset.score_breakdown || {};
        const penalties = asset.penalties || [];
        const flags = asset.shared_infra_flags || [];
        const roles = asset.roles || [];
        const rels = (inv.relationships || []).filter((r) => r.source === asset.asset_id || r.target === asset.asset_id);
        const malEntries = Object.entries(asset.maliciousness_context || {});
        const metaEntries = Object.entries(asset.metadata || {}).filter(([k, v]) => v !== null && v !== undefined && v !== '' && typeof v !== 'object');
        const cleanProviders = (asset.providers || []).filter((p) => p && p !== 'seed');
        const cleanMethods = (asset.pivot_methods || []).filter((m) => m && m !== 'seed');
        const confVal = Number(asset.relationship_confidence ?? 100);
        const barColor = confVal >= 70 ? '#34d399' : (confVal >= 45 ? '#fbbf24' : '#f87171');
        const totalBonus = Number(sb.corroboration_bonus ?? 0) + Number(sb.convergence_bonus ?? 0);
        const defangedVal = asset.defanged || asset.value;

        box.innerHTML = `
            <div class="ipiv-inspector-head">
                <div class="ipiv-inspector-toprow">
                    <div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap;">
                        <span class="ipiv-type-badge">${esc(asset.asset_type.toUpperCase())}</span>
                        <span class="ipiv-hop-badge">${isSeed ? 'ROOT SEED' : `HOP ${asset.depth}`}</span>
                        ${renderRoleBadgesHtml(roles)}
                    </div>
                    <div style="display:flex;gap:4px;">
                        <button type="button" class="ipiv-btn-icon" id="ipiv-inspect-defang-btn" title="Copy Defanged (${esc(defangedVal)})" style="width:26px;height:26px;">
                            <i class="fa-solid fa-shield"></i>
                        </button>
                        <button type="button" class="ipiv-btn-icon" id="ipiv-inspect-copy-btn" title="Copy Raw Value" style="width:26px;height:26px;">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="ipiv-inspector-value">${esc(asset.value)}</div>
                ${roles.length ? `
                    <div style="font-size:0.7rem;color:#94a3b8;line-height:1.35;">
                        ${roles.map((r) => `<div>&bull; <strong style="color:#e2e8f0;">${esc(r.label)}:</strong> ${esc((r.evidence || []).join('; '))}</div>`).join('')}
                    </div>
                ` : ''}
                ${!isSeed ? `
                    <div style="margin-top:6px;">
                        <button type="button" class="ipiv-btn-primary" id="ipiv-inspect-pivot-btn" style="width:100%;justify-content:center;padding:6px 12px;font-size:0.74rem;">
                            <i class="fa-solid fa-arrows-split-up-and-left"></i> Pivot from Asset
                        </button>
                    </div>
                ` : ''}
            </div>

            <div class="ipiv-insp-section">
                <div class="ipiv-insp-section-head">
                    <span>CONFIDENCE</span>
                    <span class="ipiv-conf-pill ${esc(asset.confidence_tier)}">${confVal}% &middot; ${esc(asset.confidence_tier.toUpperCase())}</span>
                </div>
                <div class="ipiv-conf-meter-track">
                    <div class="ipiv-conf-meter-fill" style="width:${Math.max(4, Math.min(100, confVal))}%;background:${barColor};"></div>
                </div>
                ${!isSeed ? `
                    <div class="ipiv-insp-stat-grid">
                        <div class="ipiv-insp-stat-cell">
                            <span class="ipiv-insp-stat-lbl">Base</span>
                            <span class="ipiv-insp-stat-val">${sb.base_score ?? confVal}</span>
                        </div>
                        <div class="ipiv-insp-stat-cell">
                            <span class="ipiv-insp-stat-lbl">Bonus</span>
                            <span class="ipiv-insp-stat-val" style="color:#34d399;">+${totalBonus}</span>
                        </div>
                        <div class="ipiv-insp-stat-cell">
                            <span class="ipiv-insp-stat-lbl">Penalty</span>
                            <span class="ipiv-insp-stat-val" style="color:${(sb.total_penalty ?? 0) > 0 ? '#f87171' : '#94a3b8'};">-${sb.total_penalty ?? 0}</span>
                        </div>
                    </div>
                ` : ''}
                ${(penalties.length || flags.length) ? `
                    <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;">
                        ${flags.map((f) => `<span class="ipiv-penalty-pill">${esc(f)}</span>`).join('')}
                        ${penalties.map((p) => `<span class="ipiv-penalty-pill" title="${esc(p.reason)}">-${p.deduction}: ${esc(p.code || p.reason)}</span>`).join('')}
                    </div>
                ` : ''}
            </div>

            ${(metaEntries.length || malEntries.length) ? `
                <div class="ipiv-insp-section">
                    <div class="ipiv-insp-section-head">
                        <span>ATTRIBUTES & CONTEXT</span>
                    </div>
                    <div class="ipiv-insp-kv-list">
                        ${malEntries.map(([k, v]) => `
                            <div class="ipiv-insp-kv-row">
                                <span class="ipiv-insp-kv-key">${esc(k.replace(/_/g, ' '))}</span>
                                <span class="ipiv-insp-kv-val" style="color:#fbbf24;">${esc(String(v))}</span>
                            </div>
                        `).join('')}
                        ${metaEntries.slice(0, 6).map(([k, v]) => `
                            <div class="ipiv-insp-kv-row">
                                <span class="ipiv-insp-kv-key">${esc(k.replace(/_/g, ' '))}</span>
                                <span class="ipiv-insp-kv-val">${esc(String(v))}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : ''}

            ${(cleanProviders.length || cleanMethods.length) ? `
                <div class="ipiv-insp-section">
                    <div class="ipiv-insp-section-head">
                        <span>SOURCES & METHODS</span>
                    </div>
                    <div style="display:flex;flex-wrap:wrap;gap:4px;">
                        ${cleanProviders.map((p) => `<span class="ipiv-tag" style="margin:0;">${esc(p)}</span>`).join('')}
                        ${cleanMethods.map((m) => `<span class="ipiv-tag" style="margin:0;border-color:rgba(255,204,0,0.45);color:#FFCC00;">${esc(m)}</span>`).join('')}
                    </div>
                </div>
            ` : ''}

            <div class="ipiv-insp-section">
                <div class="ipiv-insp-section-head">
                    <span>CONNECTIONS</span>
                    <span style="color:#e2e8f0;">${rels.length}</span>
                </div>
                ${rels.length ? `
                    <div style="display:flex;flex-direction:column;gap:6px;">
                        ${rels.slice(0, 12).map((r) => {
                            const isOut = r.source === asset.asset_id;
                            const otherId = isOut ? r.target : r.source;
                            const otherVal = otherId.includes(':') ? otherId.split(':').slice(1).join(':') : otherId;
                            return `
                                <div class="ipiv-insp-rel-card" data-target-node="${esc(otherId)}" style="cursor:pointer;" title="Click to inspect ${esc(otherVal)}">
                                    <div class="ipiv-insp-rel-top">
                                        <span class="ipiv-insp-rel-type">${esc(r.relationship_type)}</span>
                                        <span class="ipiv-insp-rel-score">${r.confidence_score}%</span>
                                    </div>
                                    <div class="ipiv-insp-rel-target">${isOut ? '&rarr;' : '&larr;'} ${esc(otherVal)}</div>
                                    <div class="ipiv-insp-rel-desc">${[ ...(r.providers || (r.provider ? [r.provider] : [])), ...(r.pivot_methods || (r.pivot_method ? [r.pivot_method] : [])) ].map(esc).join(' &middot; ')}</div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                ` : `<div style="font-size:0.72rem;color:#64748b;">No connected edges recorded for this node.</div>`}
            </div>
        `;

        el('ipiv-inspect-pivot-btn')?.addEventListener('click', () => {
            startPivotInvestigation(asset.value);
        });
        el('ipiv-inspect-copy-btn')?.addEventListener('click', () => {
            navigator.clipboard?.writeText(asset.value);
        });
        el('ipiv-inspect-defang-btn')?.addEventListener('click', () => {
            navigator.clipboard?.writeText(defangedVal);
        });
        box.querySelectorAll('.ipiv-insp-rel-card[data-target-node]').forEach((card) => {
            card.addEventListener('click', () => {
                const targetId = card.dataset.targetNode;
                if (targetId) {
                    state.selectedNodeId = targetId;
                    renderInspector();
                    drawGraph();
                }
            });
        });
    }

    function bindCanvasEvents() {
        const canvas = el('ipiv-graph-canvas');
        if (!canvas) return;

        const toWorld = (clientX, clientY) => {
            const rect = canvas.getBoundingClientRect();
            const sx = clientX - rect.left;
            const sy = clientY - rect.top;
            const w = canvas.width;
            const h = canvas.height;
            return {
                x: (sx - w / 2 - state.camera.x) / state.camera.zoom + w / 2,
                y: (sy - h / 2 - state.camera.y) / state.camera.zoom + h / 2
            };
        };

        const findNodeAt = (wx, wy) => {
            for (let i = state.nodes.length - 1; i >= 0; i--) {
                const n = state.nodes[i];
                const r = n.depth === 0 ? 20 : 15;
                if (Math.hypot(n.x - wx, n.y - wy) <= r) return n;
            }
            return null;
        };

        canvas.addEventListener('mousedown', (e) => {
            const pt = toWorld(e.clientX, e.clientY);
            const hit = findNodeAt(pt.x, pt.y);
            if (hit) {
                state.selectedNodeId = hit.id;
                state.draggingNode = hit;
                renderInspector();
                drawGraph();
            } else {
                state.panning = true;
                state.panStart = { x: e.clientX - state.camera.x, y: e.clientY - state.camera.y };
            }
        });

        window.addEventListener('mousemove', (e) => {
            if (state.draggingNode) {
                const pt = toWorld(e.clientX, e.clientY);
                state.draggingNode.x = pt.x;
                state.draggingNode.y = pt.y;
                drawGraph();
            } else if (state.panning) {
                state.camera.x = e.clientX - state.panStart.x;
                state.camera.y = e.clientY - state.panStart.y;
                drawGraph();
            }
        });

        window.addEventListener('mouseup', () => {
            state.draggingNode = null;
            state.panning = false;
        });

        canvas.addEventListener('wheel', (e) => {
            e.preventDefault();
            const factor = e.deltaY < 0 ? 1.12 : 0.89;
            state.camera.zoom = Math.max(0.25, Math.min(3.5, state.camera.zoom * factor));
            drawGraph();
        }, { passive: false });
    }

    // =========================================================================
    // 5. SUBTABS, EXPORT & EVENT BINDINGS
    // =========================================================================

    function switchSubtab(tabId) {
        state.activeSubtab = tabId;
        document.querySelectorAll('.ipiv-subtab-btn').forEach((btn) => {
            btn.classList.toggle('active', btn.dataset.subtab === tabId);
        });
        document.querySelectorAll('.ipiv-view-panel').forEach((panel) => {
            panel.classList.toggle('active', panel.id === `ipiv-view-${tabId}`);
        });
        if (tabId === 'graph') {
            setTimeout(drawGraph, 30);
        } else if (tabId === 'history') {
            loadHistoryList();
        }
    }

    function exportCurrentInvestigation(fmt) {
        if (!state.investigation || !state.investigation.id) {
            alert('Run or load an investigation first before exporting.');
            return;
        }
        const url = `${BASE}/api/infra-pivoting/investigations/${encodeURIComponent(state.investigation.id)}/export?format=${encodeURIComponent(fmt)}`;
        window.open(url, '_blank');
    }

    function bindEvents() {
        const seedInput = el('ipiv-seed-input');
        seedInput?.addEventListener('input', () => {
            const badge = el('ipiv-detected-type');
            if (badge) badge.textContent = detectIndicatorTypeClient(seedInput.value);
        });
        seedInput?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                startPivotInvestigation();
            }
        });

        document.querySelectorAll('.ipiv-mode-btn').forEach((btn) => {
            btn.addEventListener('click', () => applyPresetValues(btn.dataset.mode));
        });

        document.querySelectorAll('.ipiv-example-chip').forEach((chip) => {
            chip.addEventListener('click', () => {
                if (seedInput) {
                    seedInput.value = chip.dataset.seed;
                    const badge = el('ipiv-detected-type');
                    if (badge) badge.textContent = detectIndicatorTypeClient(seedInput.value);
                }
            });
        });

        el('ipiv-btn-toggle-config')?.addEventListener('click', () => toggleConfigDrawer());
        el('ipiv-btn-start')?.addEventListener('click', () => startPivotInvestigation());
        el('ipiv-btn-cancel')?.addEventListener('click', cancelCurrentInvestigation);
        el('ipiv-btn-resume')?.addEventListener('click', () => resumeInvestigationById());

        // Quick select buttons for Pivot Methods and Providers
        el('ipiv-methods-all')?.addEventListener('click', () => {
            document.querySelectorAll('.ipiv-method-cb').forEach((cb) => { cb.checked = true; });
        });
        el('ipiv-methods-none')?.addEventListener('click', () => {
            document.querySelectorAll('.ipiv-method-cb').forEach((cb) => { cb.checked = false; });
        });
        el('ipiv-providers-ready')?.addEventListener('click', () => {
            const readySet = new Set((state.capabilities?.providers || []).filter((p) => p.ready).map((p) => p.id));
            document.querySelectorAll('.ipiv-provider-cb').forEach((cb) => {
                cb.checked = readySet.has(cb.value);
            });
        });
        el('ipiv-providers-all')?.addEventListener('click', () => {
            document.querySelectorAll('.ipiv-provider-cb').forEach((cb) => { cb.checked = true; });
        });

        document.querySelectorAll('.ipiv-subtab-btn').forEach((btn) => {
            btn.addEventListener('click', () => switchSubtab(btn.dataset.subtab));
        });

        // Graph controls
        el('ipiv-graph-min-conf')?.addEventListener('input', (e) => {
            state.graphMinConf = Number(e.target.value || 0);
            if (el('ipiv-graph-min-conf-val')) el('ipiv-graph-min-conf-val').textContent = `${state.graphMinConf}%`;
            if (state.investigation) syncGraphFromInvestigation(state.investigation);
        });
        el('ipiv-graph-type-filter')?.addEventListener('change', (e) => {
            state.graphTypeFilter = e.target.value;
            if (state.investigation) syncGraphFromInvestigation(state.investigation);
        });
        el('ipiv-graph-hide-noise')?.addEventListener('change', (e) => {
            state.graphHideNoise = e.target.checked;
            if (state.investigation) syncGraphFromInvestigation(state.investigation);
        });
        el('ipiv-btn-zoom-in')?.addEventListener('click', () => {
            state.camera.zoom = Math.min(3.5, state.camera.zoom * 1.2);
            drawGraph();
        });
        el('ipiv-btn-zoom-out')?.addEventListener('click', () => {
            state.camera.zoom = Math.max(0.25, state.camera.zoom * 0.82);
            drawGraph();
        });
        el('ipiv-btn-zoom-reset')?.addEventListener('click', () => {
            state.camera = { x: 0, y: 0, zoom: 1 };
            if (state.investigation) syncGraphFromInvestigation(state.investigation);
        });

        // Table search & filters
        el('ipiv-findings-search')?.addEventListener('input', () => {
            if (state.investigation) renderFindingsTable(state.investigation);
        });
        el('ipiv-findings-type')?.addEventListener('change', () => {
            if (state.investigation) renderFindingsTable(state.investigation);
        });
        el('ipiv-findings-tier')?.addEventListener('change', () => {
            if (state.investigation) renderFindingsTable(state.investigation);
        });
        el('ipiv-evidence-search')?.addEventListener('input', () => {
            if (state.investigation) renderEvidenceTables(state.investigation);
        });

        // Export buttons
        el('ipiv-export-json')?.addEventListener('click', () => exportCurrentInvestigation('json'));
        el('ipiv-export-csv')?.addEventListener('click', () => exportCurrentInvestigation('csv'));
        el('ipiv-export-stix')?.addEventListener('click', () => exportCurrentInvestigation('stix'));

        // Raw modal close
        el('ipiv-raw-modal-close')?.addEventListener('click', () => {
            if (el('ipiv-raw-modal-overlay')) el('ipiv-raw-modal-overlay').style.display = 'none';
        });
        el('ipiv-raw-modal-overlay')?.addEventListener('click', (e) => {
            if (e.target === el('ipiv-raw-modal-overlay')) el('ipiv-raw-modal-overlay').style.display = 'none';
        });

        bindCanvasEvents();
    }

    let initialized = false;
    window.openInfraPivoting = function (initialSeed = '') {
        if (!initialized) {
            initialized = true;
            bindEvents();
        }
        loadCapabilities();
        loadHistoryList();
        if (initialSeed && el('ipiv-seed-input')) {
            el('ipiv-seed-input').value = initialSeed;
            if (el('ipiv-detected-type')) el('ipiv-detected-type').textContent = detectIndicatorTypeClient(initialSeed);
        }
        setTimeout(drawGraph, 50);
    };
    window.openInfraPivotInvestigation = function (investigationId) {
        if (!initialized) window.openInfraPivoting();
        if (investigationId) return loadInvestigationById(investigationId);
    };
})();
