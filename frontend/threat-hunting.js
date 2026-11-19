/**
 * MANTIS AI Threat Hunting Query Generator
 * 5-Tab Autonomous Workstation (Sources, Findings, Hypotheses, Query Generator, Export)
 */

(function () {
    const PLATFORMS = [
        { id: 'splunk', label: 'Splunk (SPL)' },
        { id: 'sentinel', label: 'Microsoft Sentinel (KQL)' },
        { id: 'defender_xdr', label: 'Microsoft Defender XDR (Advanced Hunting KQL)' },
        { id: 'elastic_kql', label: 'Elastic Security (KQL)' },
        { id: 'elastic_eql', label: 'Elasticsearch (EQL)' },
        { id: 'opensearch_ppl', label: 'Elasticsearch / OpenSearch (PPL)' },
        { id: 'elastic_dsl', label: 'Elasticsearch (Query DSL)' },
        { id: 'crowdstrike_logscale', label: 'CrowdStrike Falcon LogScale (CQL)' },
        { id: 'crowdstrike_aes', label: 'CrowdStrike Falcon AES (CQL)' },
        { id: 'qradar_aql', label: 'IBM QRadar (AQL)' },
        { id: 'sentinelone_dv', label: 'SentinelOne Deep Visibility (PowerQuery)' },
        { id: 'sentinelone_star', label: 'SentinelOne STAR (Rules & Query)' },
        { id: 'google_secops', label: 'Google SecOps (YARA-L 2.0)' },
        { id: 'sumo_logic', label: 'Sumo Logic (Search QL)' },
        { id: 'aws_cloudwatch', label: 'AWS CloudWatch Logs Insights (QL)' }
    ];

    const state = {
        investigationId: null,
        investigations: [],
        activeTab: 'sources',
        ingestedSources: [],
        findings: null,
        hypotheses: [],
        selectedHypothesis: null,
        queries: [],
        currentQuery: null,
        currentVersionDiff: null,
        selectedPlatform: 'splunk',
        selectedMode: 'hunting',
        customSchema: '',
        aiProvider: 'gemini',
        aiModel: 'gemini-2.5-flash',
        isAnalyzing: false,
        isGenerating: false
    };

    let isInitialized = false;

    function init() {
        if (!isInitialized) {
            bindNavigation();
            populatePlatformSelect();
            bindIngestEvents();
            bindActionEvents();
            isInitialized = true;
        }
        loadInvestigations();
        window.initThreatHunting = init;
    }

    function bindNavigation() {
        document.querySelectorAll('.th-nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.getAttribute('data-th-tab');
                switchTab(target);
            });
        });
    }

    function switchTab(tabId) {
        state.activeTab = tabId;
        document.querySelectorAll('.th-nav-tab').forEach(t => {
            t.classList.toggle('active', t.getAttribute('data-th-tab') === tabId);
        });
        document.querySelectorAll('.th-tab-content').forEach(c => {
            c.classList.toggle('active', c.id === `th-tab-${tabId}`);
        });

        if (tabId === 'generator') {
            refreshHypothesisSelect();
        } else if (tabId === 'export') {
            renderExportTab();
        }
    }

    async function loadInvestigations() {
        try {
            const res = await fetch('/api/threat-hunting/investigations');
            if (!res.ok) return;
            const data = await res.json();
            const list = Array.isArray(data) ? data : (data.investigations || []);
            state.investigations = list;

            const select = document.getElementById('th-investigation-select');
            if (!select) return;

            select.innerHTML = list.map(inv => 
                `<option value="${escapeHtml(inv.id)}" ${inv.id === state.investigationId ? 'selected' : ''}>${escapeHtml(inv.title)} (${inv.status || 'draft'})</option>`
            ).join('');

            if (list.length > 0 && !state.investigationId) {
                switchInvestigation(list[0].id);
            } else if (list.length === 0) {
                createNewInvestigation();
            }
        } catch (err) {
            console.error('[TH] Load investigations error:', err);
        }
    }

    async function createNewInvestigation() {
        const title = prompt('Enter investigation title:', `Threat Hunt #${new Date().toISOString().slice(0, 10)}`);
        if (!title) return;

        try {
            const res = await fetch('/api/threat-hunting/investigations', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, description: 'AI Threat Hunting Investigation' })
            });
            if (res.ok) {
                const body = await res.json();
                const inv = body.investigation || body;
                state.investigationId = inv.id;
                await loadInvestigations();
                switchInvestigation(inv.id);
            }
        } catch (err) {
            console.error('[TH] Create investigation error:', err);
        }
    }

    async function switchInvestigation(invId) {
        state.investigationId = invId;
        const select = document.getElementById('th-investigation-select');
        if (select) select.value = invId;

        try {
            const res = await fetch(`/api/threat-hunting/investigations/${invId}`);
            if (!res.ok) return;
            const body = await res.json();
            const data = body.investigation || body;

            const findingsList = Array.isArray(data.findings) ? data.findings : [];
            state.findings = findingsList.length ? { summary: data.summary || '', findings: findingsList, extracted_iocs: [] } : null;
            state.hypotheses = data.hypotheses || [];
            state.queries = data.queries || [];

            renderFindingsTab();
            renderHypothesesTab();
            renderQueriesList();
            renderExportTab();
        } catch (err) {
            console.error('[TH] Switch investigation error:', err);
        }
    }

    function populatePlatformSelect() {
        const sel = document.getElementById('th-platform-select');
        if (!sel) return;
        sel.innerHTML = PLATFORMS.map(p => 
            `<option value="${p.id}" ${p.id === state.selectedPlatform ? 'selected' : ''}>${p.label}</option>`
        ).join('');

        sel.addEventListener('change', (e) => {
            state.selectedPlatform = e.target.value;
        });
    }

    function bindIngestEvents() {
        const fileInput = document.getElementById('th-file-input');
        const dropzone = document.getElementById('th-file-dropzone');

        if (dropzone && fileInput) {
            dropzone.addEventListener('click', () => fileInput.click());
            dropzone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropzone.classList.add('dragover');
            });
            dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
            dropzone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
                if (e.dataTransfer.files.length) {
                    uploadFiles(e.dataTransfer.files);
                }
            });

            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length) {
                    uploadFiles(e.target.files);
                }
            });
        }

        document.getElementById('th-btn-ingest-url')?.addEventListener('click', async () => {
            const input = document.getElementById('th-url-input');
            const url = input ? input.value.trim() : '';
            if (!url) return alert('Please enter a valid report URL');

            if (!state.investigationId) await createNewInvestigation();
            const btn = document.getElementById('th-btn-ingest-url');
            if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Ingesting...';

            try {
                const res = await fetch(`/api/threat-hunting/investigations/${state.investigationId}/ingest/url`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const data = await res.json();
                if (res.ok) {
                    addIngestedSource('url', url, data.chunks_count || 1);
                    if (input) input.value = '';
                } else {
                    alert(`URL Ingestion Error: ${data.detail || data.error || 'Failed to fetch'}`);
                }
            } catch (err) {
                alert(`Network error: ${err.message}`);
            } finally {
                if (btn) btn.innerHTML = '<i class="fa-solid fa-cloud-arrow-down"></i> Ingest URL';
            }
        });

        document.getElementById('th-btn-ingest-text')?.addEventListener('click', async () => {
            const ta = document.getElementById('th-manual-text');
            const content = ta ? ta.value.trim() : '';
            if (!content) return alert('Please paste technical notes or commands');

            if (!state.investigationId) await createNewInvestigation();
            const btn = document.getElementById('th-btn-ingest-text');
            if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Ingesting...';

            try {
                const res = await fetch(`/api/threat-hunting/investigations/${state.investigationId}/ingest/text`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content, source_name: 'Manual Technical Notes' })
                });
                const data = await res.json();
                if (res.ok) {
                    addIngestedSource('text', 'Manual Technical Notes', data.chunks_count || 1);
                    if (ta) ta.value = '';
                } else {
                    alert(`Text Ingestion Error: ${data.detail || data.error}`);
                }
            } catch (err) {
                alert(`Network error: ${err.message}`);
            } finally {
                if (btn) btn.innerHTML = '<i class="fa-solid fa-file-pen"></i> Ingest Text';
            }
        });
    }

    async function uploadFiles(fileList) {
        if (!state.investigationId) await createNewInvestigation();
        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];
            const formData = new FormData();
            formData.append('file', file);

            try {
                const res = await fetch(`/api/threat-hunting/investigations/${state.investigationId}/ingest/file`, {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (res.ok) {
                    addIngestedSource('file', file.name, data.chunks_count || 1);
                } else {
                    alert(`Failed to ingest ${file.name}: ${data.detail || data.error}`);
                }
            } catch (err) {
                console.error('File upload error:', err);
            }
        }
    }

    function addIngestedSource(type, name, chunks) {
        state.ingestedSources.push({ type, name, chunks });
        const container = document.getElementById('th-ingested-sources-list');
        if (!container) return;

        const icon = type === 'url' ? 'fa-globe' : (type === 'file' ? 'fa-file-lines' : 'fa-terminal');
        const item = document.createElement('div');
        item.className = 'th-ingested-item';
        item.innerHTML = `
            <div>
                <i class="fa-solid ${icon}" style="color:var(--th-accent);margin-right:8px;"></i>
                <strong style="color:#f1f5f9;">${escapeHtml(name)}</strong>
            </div>
            <div>
                <span class="th-badge low" style="margin-right:8px;">${chunks} chunks</span>
                <span class="th-badge high"><i class="fa-solid fa-check"></i> Ingested</span>
            </div>
        `;
        container.appendChild(item);
    }

    function bindActionEvents() {
        document.getElementById('th-btn-run-analysis')?.addEventListener('click', runReportAnalysis);
        document.getElementById('th-btn-gen-hypotheses')?.addEventListener('click', runHypothesesGeneration);
        document.getElementById('th-btn-generate-query')?.addEventListener('click', runQueryGeneration);

        // Mode toggles
        document.querySelectorAll('.th-mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const mode = btn.getAttribute('data-th-mode');
                state.selectedMode = mode;
                document.querySelectorAll('.th-mode-btn').forEach(b => b.classList.toggle('active', b === btn));
            });
        });

        // Query improvement actions
        document.querySelectorAll('[data-th-improve]').forEach(btn => {
            btn.addEventListener('click', () => {
                const goal = btn.getAttribute('data-th-improve');
                improveCurrentQuery(goal);
            });
        });

        // Copy query button
        document.getElementById('th-btn-copy-query')?.addEventListener('click', () => {
            const pre = document.getElementById('th-query-output-text');
            const code = pre ? pre.textContent : '';
            const btn = document.getElementById('th-btn-copy-query');
            copyTextRobust(code, btn, '<i class="fa-solid fa-check"></i> Copied!');
        });
    }

    async function runReportAnalysis() {
        if (!state.investigationId) return alert('Select or create an investigation first.');
        const btn = document.getElementById('th-btn-run-analysis');
        if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing Report with AI...';

        try {
            const res = await fetch(`/api/threat-hunting/investigations/${state.investigationId}/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ai_provider: state.aiProvider, ai_model: state.aiModel })
            });
            const data = await res.json();
            if (res.ok) {
                state.findings = {
                    summary: data.summary || '',
                    findings: data.findings || [],
                    extracted_iocs: data.extracted_iocs || [],
                    attribution: data.threat_assessment_attribution || null
                };
                renderFindingsTab();
                switchTab('findings');
            } else {
                alert(`Analysis Error: ${data.detail || data.error}`);
            }
        } catch (err) {
            alert(`Network error: ${err.message}`);
        } finally {
            if (btn) btn.innerHTML = '<i class="fa-solid fa-brain"></i> Analyze Threat Report';
        }
    }

    function renderFindingsTab() {
        const wrap = document.getElementById('th-findings-container');
        if (!wrap) return;
        if (!state.findings) {
            wrap.innerHTML = '<div style="text-align:center;padding:50px;color:#64748b;"><i class="fa-solid fa-microscope fa-3x" style="margin-bottom:12px;"></i><p>No report analysis yet. Ingest sources and click Analyze.</p></div>';
            return;
        }

        const f = state.findings;
        const findings = f.findings || [];
        const iocs = f.extracted_iocs || [];
        const inv = (state.investigations || []).find(i => i.id === state.investigationId);
        const attribution = f.attribution || {};
        const actorCands = (attribution.candidates || []).slice(0, 3);

        const actors = actorCands.map(a =>
            `<span class="th-meta-pill actor"><i class="fa-solid fa-user-secret"></i> ${escapeHtml(a.name || 'Unattributed')}${typeof a.confidence === 'number' ? ` · ${a.confidence}%` : ''}</span>`
        ).join('');
        const mapped = findings.filter(x => x.attack_id);
        const behaviors = findings.filter(x => !x.attack_id);

        let techCards = '';
        mapped.forEach(t => {
            techCards += `
                <div class="th-matrix-card">
                    <div class="th-technique-id">${escapeHtml(t.attack_id || '')} · ${escapeHtml(t.attack_tactic || t.category || 'Unmapped')}</div>
                    <div class="th-technique-name">${escapeHtml(t.attack_technique || t.title || 'Technique')}</div>
                    <div style="font-size:0.75rem;color:#94a3b8;">${escapeHtml(t.description || '')}</div>
                </div>
            `;
        });

        const behaviorRows = behaviors.map(b =>
            `<div class="th-obs-item"><strong>${escapeHtml(b.title || b.category || 'Behaviour')}</strong> — ${escapeHtml(b.description || '')}</div>`
        ).join('');

        const byType = (...types) => iocs.filter(i => types.includes(String(i.type || '').toLowerCase())).map(i => i.value);
        const registryRe = /^(HK(LM|CU|EY|CR|U|CC)\b|.*\\Registry\\)/i;
        const hashes = byType('hash');
        const network = byType('ip', 'domain', 'url');
        const registry = iocs.filter(i => registryRe.test(String(i.value || ''))).map(i => i.value);
        const commandRe = /(\.exe\b|\.dll\b|powershell|cmd\.exe|wmic|rundll32|regsvr32|schtasks|bitsadmin)/i;
        const commands = Array.from(new Set(
            findings.flatMap(x => (x.artifacts || []).map(String)).filter(a => commandRe.test(a))
        )).slice(0, 30);

        const obsList = (items) => items.length
            ? items.map(v => `<div class="th-obs-item">${escapeHtml(v)}</div>`).join('')
            : '<div style="color:#64748b;font-size:0.75rem;">None extracted</div>';

        wrap.innerHTML = `
            <div class="th-findings-header">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                    <div>
                        <h3 style="margin:0 0 6px;color:#f8fafc;font-size:1.1rem;">${escapeHtml(inv?.title || 'Report Analysis')}</h3>
                        <p style="margin:0;color:#94a3b8;font-size:0.84rem;line-height:1.5;">${escapeHtml(f.summary || 'No executive summary was returned for this report.')}</p>
                    </div>
                    <button type="button" class="th-btn-primary" id="th-btn-forward-hypotheses">
                        <i class="fa-solid fa-lightbulb"></i> Formulate Hypotheses
                    </button>
                </div>
                <div class="th-meta-pills">
                    <span class="th-meta-pill"><i class="fa-solid fa-list-check"></i> ${findings.length} finding(s)</span>
                    <span class="th-meta-pill"><i class="fa-solid fa-fingerprint"></i> ${iocs.length} indicator(s)</span>
                    ${actors}
                </div>
                ${attribution.top_candidate ? '' : '<p style="margin:10px 0 0;color:#fbbf24;font-size:0.78rem;"><i class="fa-solid fa-triangle-exclamation"></i> No threat actor reached the attribution threshold for this report.</p>'}
            </div>

            <h4 style="color:#f1f5f9;margin:20px 0 10px;font-size:0.95rem;"><i class="fa-solid fa-network-wired" style="color:var(--th-accent);margin-right:8px;"></i>MITRE ATT&amp;CK Matrix Mapping</h4>
            <div class="th-matrix-grid">${techCards || '<p style="color:#64748b;">No techniques mapped.</p>'}</div>

            ${behaviorRows ? `<h4 style="color:#f1f5f9;margin:20px 0 10px;font-size:0.95rem;"><i class="fa-solid fa-diagram-project" style="color:var(--th-accent);margin-right:8px;"></i>Behaviours Without a Technique ID</h4><div class="th-obs-card"><div class="th-obs-list">${behaviorRows}</div></div>` : ''}

            <h4 style="color:#f1f5f9;margin:20px 0 10px;font-size:0.95rem;"><i class="fa-solid fa-list-check" style="color:var(--th-accent);margin-right:8px;"></i>Technical Observables &amp; Indicators</h4>
            <div class="th-observables-grid">
                <div class="th-obs-card">
                    <strong style="display:block;font-size:0.8rem;color:#FFCC00;margin-bottom:8px;"><i class="fa-solid fa-terminal"></i> Command Lines &amp; Process Arguments</strong>
                    <div class="th-obs-list">${obsList(commands)}</div>
                </div>
                <div class="th-obs-card">
                    <strong style="display:block;font-size:0.8rem;color:#f472b6;margin-bottom:8px;"><i class="fa-solid fa-fingerprint"></i> Hashes &amp; Binary Fingerprints</strong>
                    <div class="th-obs-list">${obsList(hashes)}</div>
                </div>
                <div class="th-obs-card">
                    <strong style="display:block;font-size:0.8rem;color:#4ade80;margin-bottom:8px;"><i class="fa-solid fa-network-wired"></i> Network Indicators (IP / FQDN / C2)</strong>
                    <div class="th-obs-list">${obsList(network)}</div>
                </div>
                <div class="th-obs-card">
                    <strong style="display:block;font-size:0.8rem;color:#fbbf24;margin-bottom:8px;"><i class="fa-solid fa-cubes"></i> Registry Keys &amp; Persistence Artifacts</strong>
                    <div class="th-obs-list">${obsList(registry)}</div>
                </div>
            </div>
        `;

        document.getElementById('th-btn-forward-hypotheses')?.addEventListener('click', runHypothesesGeneration);
    }

    async function runHypothesesGeneration() {
        if (!state.investigationId) return alert('Select or create an investigation first.');
        const btn = document.getElementById('th-btn-gen-hypotheses') || document.getElementById('th-btn-forward-hypotheses');
        if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Formulating Hypotheses...';

        try {
            const res = await fetch(`/api/threat-hunting/investigations/${state.investigationId}/hypotheses`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    findings: (state.findings?.findings) || [],
                    ai_provider: state.aiProvider,
                    ai_model: state.aiModel
                })
            });
            const data = await res.json();
            if (res.ok) {
                state.hypotheses = data.hypotheses;
                renderHypothesesTab();
                switchTab('hypotheses');
            } else {
                alert(`Hypotheses Error: ${data.detail || data.error}`);
            }
        } catch (err) {
            alert(`Network error: ${err.message}`);
        } finally {
            if (btn) btn.innerHTML = '<i class="fa-solid fa-lightbulb"></i> Formulate Hypotheses';
        }
    }

    function renderHypothesesTab() {
        const wrap = document.getElementById('th-hypotheses-container');
        if (!wrap) return;
        if (!state.hypotheses || state.hypotheses.length === 0) {
            wrap.innerHTML = '<div style="text-align:center;padding:50px;color:#64748b;"><i class="fa-solid fa-compass fa-3x" style="margin-bottom:12px;"></i><p>No hypotheses formulated yet. Click "Formulate Hypotheses".</p></div>';
            return;
        }

        wrap.innerHTML = state.hypotheses.map(hyp => {
            const h = hyp.data || hyp;
            return `
                <div class="th-hyp-card">
                    <div class="th-hyp-top">
                        <span class="th-hyp-title"><i class="fa-solid fa-crosshairs" style="color:var(--th-accent);margin-right:8px;"></i>${escapeHtml(h.title || 'Hunting Hypothesis')}</span>
                        <div class="th-hyp-badges">
                            <span class="th-badge high">${escapeHtml(h.severity || 'HIGH')}</span>
                            <span class="th-badge low">${escapeHtml(h.attack_phase || 'Execution')}</span>
                        </div>
                    </div>
                    <div class="th-hyp-desc">${escapeHtml(h.description || '')}</div>
                    <div class="th-hyp-meta-grid">
                        <div class="th-hyp-meta-item">
                            <strong>Required Telemetry</strong>
                            <span>${escapeHtml(h.required_telemetry || 'Process Execution')}</span>
                        </div>
                        <div class="th-hyp-meta-item">
                            <strong>Event IDs</strong>
                            <span>${escapeHtml((h.event_ids || []).join(', ') || '1, 4688')}</span>
                        </div>
                        <div class="th-hyp-meta-item">
                            <strong>Potential FPs</strong>
                            <span>${escapeHtml(h.potential_false_positives || 'Administrative utilities')}</span>
                        </div>
                        <div class="th-hyp-meta-item">
                            <strong>Confidence</strong>
                            <span style="color:#FFCC00;font-weight:700;">${escapeHtml(h.confidence || 'High')}</span>
                        </div>
                    </div>
                    <div style="display:flex;justify-content:flex-end;">
                        <button type="button" class="th-btn-primary" onclick="window.selectHypothesisForGeneration('${escapeHtml(hyp.id)}')">
                            <i class="fa-solid fa-bolt"></i> Generate Queries
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    }

    window.selectHypothesisForGeneration = function (hypId) {
        state.selectedHypothesis = state.hypotheses.find(h => h.id === hypId);
        switchTab('generator');
        const sel = document.getElementById('th-query-hyp-select');
        if (sel) sel.value = hypId;
    };

    function refreshHypothesisSelect() {
        const sel = document.getElementById('th-query-hyp-select');
        if (!sel) return;
        sel.innerHTML = state.hypotheses.map(hyp => {
            const h = hyp.data || hyp;
            return `<option value="${escapeHtml(hyp.id)}" ${state.selectedHypothesis?.id === hyp.id ? 'selected' : ''}>${escapeHtml(h.title || 'Hypothesis')}</option>`;
        }).join('');
    }

    async function runQueryGeneration() {
        if (!state.investigationId) return alert('Select or create an investigation first.');
        const hypSel = document.getElementById('th-query-hyp-select');
        const hypothesisId = hypSel ? hypSel.value : null;

        const customSchema = document.getElementById('th-custom-schema-input')?.value || '';
        const hypothesis = (state.hypotheses || []).find(h => String(h.id) === String(hypothesisId)) || null;
        if (!hypothesis) return alert('Pick a hypothesis first — hypotheses come from the report analysis.');
        const btn = document.getElementById('th-btn-generate-query');
        if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating Query with AI...';

        try {
            const res = await fetch(`/api/threat-hunting/investigations/${state.investigationId}/generate-query`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    hypothesis: hypothesis,
                    hypothesis_id: hypothesisId,
                    platform: state.selectedPlatform,
                    mode: state.selectedMode,
                    schema_target: customSchema,
                    ai_provider: state.aiProvider,
                    ai_model: state.aiModel
                })
            });
            const data = await res.json();
            if (res.ok) {
                state.currentQuery = data.query;
                state.queries.push(data.query);
                displayCurrentQuery(data.query);
                renderQueriesList();
            } else {
                alert(`Query Generation Error: ${data.detail || data.error}`);
            }
        } catch (err) {
            alert(`Network error: ${err.message}`);
        } finally {
            if (btn) btn.innerHTML = '<i class="fa-solid fa-code"></i> Generate Platform Query';
        }
    }

    function displayCurrentQuery(queryObj) {
        const pre = document.getElementById('th-query-output-text');
        if (pre) pre.textContent = queryObj.query_text;

        const badge = document.getElementById('th-query-val-badge');
        if (badge) {
            const status = queryObj.validation_status || 'not_verified';
            badge.textContent = status.toUpperCase();
            badge.className = `th-badge ${status === 'validated' ? 'low' : (status === 'failed' ? 'high' : 'medium')}`;
        }

        const titleSpan = document.getElementById('th-query-platform-title');
        if (titleSpan) {
            const p = PLATFORMS.find(x => x.id === queryObj.platform);
            titleSpan.textContent = p ? p.label : queryObj.platform;
        }

        const diffWrap = document.getElementById('th-diff-output');
        if (diffWrap) diffWrap.style.display = 'none';
    }

    function renderQueriesList() {
        const wrap = document.getElementById('th-queries-history-list');
        if (!wrap) return;
        wrap.innerHTML = state.queries.map(q => {
            const p = PLATFORMS.find(x => x.id === q.platform);
            return `
                <div class="th-ingested-item" style="cursor:pointer;" onclick="window.loadQueryById('${escapeHtml(q.id)}')">
                    <div>
                        <strong style="color:#f1f5f9;">${p ? p.label : q.platform}</strong>
                        <span style="font-size:0.7rem;color:#64748b;margin-left:6px;">(${q.mode || 'hunting'})</span>
                    </div>
                    <span class="th-badge ${q.validation_status === 'validated' ? 'low' : 'medium'}">${escapeHtml(q.validation_status || 'ok')}</span>
                </div>
            `;
        }).join('');
    }

    window.loadQueryById = function (qId) {
        const q = state.queries.find(x => x.id === qId);
        if (q) {
            state.currentQuery = q;
            displayCurrentQuery(q);
        }
    };

    async function improveCurrentQuery(goal) {
        if (!state.currentQuery) return alert('Generate or select a query first.');

        const btn = document.querySelector(`[data-th-improve="${goal}"]`);
        const origText = btn ? btn.innerHTML : '';
        if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Improving...';

        try {
            const res = await fetch(`/api/threat-hunting/queries/${state.currentQuery.id}/improve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    goal: goal,
                    ai_provider: state.aiProvider,
                    ai_model: state.aiModel
                })
            });
            const data = await res.json();
            if (res.ok) {
                state.currentQuery = data.query;
                displayCurrentQuery(data.query);

                // Show diff
                const diffWrap = document.getElementById('th-diff-output');
                if (diffWrap && data.diff) {
                    diffWrap.style.display = 'block';
                    diffWrap.innerHTML = `<strong>Version ${data.version} Diff:</strong><pre style="margin:6px 0 0;">${escapeHtml(data.diff)}</pre>`;
                }
            } else {
                alert(`Query Improvement Error: ${data.detail || data.error}`);
            }
        } catch (err) {
            alert(`Network error: ${err.message}`);
        } finally {
            if (btn) btn.innerHTML = origText;
        }
    }

    function renderExportTab() {
        const listWrap = document.getElementById('th-export-queries-checklist');
        if (!listWrap) return;

        listWrap.innerHTML = state.queries.map(q => {
            const p = PLATFORMS.find(x => x.id === q.platform);
            const pass = q.validation_status === 'validated';
            return `
                <div class="th-check-item">
                    <div>
                        <strong style="color:#f8fafc;">${p ? p.label : q.platform}</strong>
                        <span style="color:#64748b;font-size:0.72rem;margin-left:6px;">${escapeHtml(q.target_query_language || '')}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:10px;">
                        <span class="${pass ? 'th-check-pass' : 'th-check-warn'}">
                            <i class="fa-solid ${pass ? 'fa-circle-check' : 'fa-circle-exclamation'}"></i> ${escapeHtml(q.validation_status || 'not_verified')}
                        </span>
                        <a href="/api/threat-hunting/queries/${q.id}/export/txt" download class="th-btn-secondary" style="padding:2px 8px;font-size:0.72rem;">
                            <i class="fa-solid fa-download"></i> TXT
                        </a>
                    </div>
                </div>
            `;
        }).join('') || '<div style="color:#64748b;font-size:0.8rem;padding:12px;">No queries generated yet.</div>';

        // Bind export download buttons
        if (state.investigationId) {
            document.getElementById('th-btn-export-md')?.setAttribute('href', `/api/threat-hunting/investigations/${state.investigationId}/export/markdown`);
            document.getElementById('th-btn-export-csv')?.setAttribute('href', `/api/threat-hunting/investigations/${state.investigationId}/export/csv`);
            document.getElementById('th-btn-export-zip')?.setAttribute('href', `/api/threat-hunting/investigations/${state.investigationId}/export/zip`);
        }
    }

    function copyTextRobust(text, btnElement, successHtml = '<i class="fa-solid fa-check"></i> Copied!') {
        if (!text || !String(text).trim()) return Promise.resolve(false);
        const str = String(text);
        let copied = false;

        try {
            const ta = document.createElement('textarea');
            ta.value = str;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            ta.style.top = '-9999px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            ta.setSelectionRange(0, str.length);
            copied = document.execCommand('copy');
            document.body.removeChild(ta);
        } catch (e) {
            copied = false;
        }

        if (!copied && navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(str).then(() => {
                if (btnElement) flashSuccess(btnElement, successHtml);
                return true;
            }).catch(() => false);
        }

        if (btnElement && copied) flashSuccess(btnElement, successHtml);
        return Promise.resolve(copied);

        function flashSuccess(btn, html) {
            const orig = btn.innerHTML;
            btn.innerHTML = html;
            setTimeout(() => { btn.innerHTML = orig; }, 1800);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
