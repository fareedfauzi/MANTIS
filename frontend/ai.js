(function () {

    const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:9999' : window.location.origin;

    const state = {

        open: false,

        minimized: false,

        messages: [],

        settings: null,

        actionId: 0,

        actions: new Map(),

        mode: 'assist',

        agentRunId: null,

        agentSessionId: 0,

        agentRunning: false,

        agentStopRequested: false,

        chatRequestId: 0,

        correlationRequestId: 0,

        attributionRequestId: 0,

        correlation: null,

        correlationPayload: null,

        attribution: null,

        attributionPayload: null,

        caseId: null,

        caseState: null,

        caseBusy: false

    };



    function el(tag, attrs = {}, children = []) {

        const node = document.createElement(tag);

        Object.entries(attrs || {}).forEach(([key, value]) => {

            if (key === 'class') node.className = value;

            else if (key === 'text') node.textContent = value;

            else if (key === 'html') node.innerHTML = value;

            else node.setAttribute(key, value);

        });

        (Array.isArray(children) ? children : [children]).filter(Boolean).forEach(child => {

            node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);

        });

        return node;

    }



    async function fetchJson(url, options = {}) {

        const timeoutMs = Number(options.timeoutMs || 45000);

        const controller = new AbortController();

        const timer = timeoutMs > 0 ? setTimeout(() => controller.abort(), timeoutMs) : null;

        const requestOptions = { ...options, signal: options.signal || controller.signal };

        delete requestOptions.timeoutMs;

        try {

            const res = await fetch(url, requestOptions);

            const data = await res.json().catch(() => ({}));

            if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

            return data;

        } catch (e) {

            if (e?.name === 'AbortError') {

                throw new Error(`MANTIS AI request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);

            }

            throw e;

        } finally {

            if (timer) clearTimeout(timer);

        }

    }



    function aiRequestTimeoutMs(extraSeconds = 12) {

        const configured = Number(state.settings?.timeout_seconds || 30);

        return Math.max(15000, Math.min((configured + extraSeconds) * 1000, 150000));

    }



    function notify(message) {

        if (typeof window.showNotification === 'function') window.showNotification(message);

    }



    function aiEsc(value) {

        const d = document.createElement('div');

        d.textContent = value === undefined || value === null ? '' : String(value);

        return d.innerHTML;

    }



    function compactDomContext() {

        if (typeof window.mantisGetState === 'function') return window.mantisGetState();

        const title = document.getElementById('current-tab-title')?.textContent || '';

        const active = document.querySelector('.nav-item.active')?.dataset.tab || '';

        const visible = [...document.querySelectorAll('main [id$="-pane"], #results-container, #settings-view')]

            .find(x => x.offsetParent !== null);

        return {

            page: active,

            title,

            query: { value: document.getElementById('ioc-input')?.value?.trim() || '' },

            visible_text: (visible?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 6000)

        };

    }



    function renderIntelligence(intelligence) {

        if (!intelligence || typeof intelligence !== 'object') return null;

        const facts = Array.isArray(intelligence.facts) ? intelligence.facts.slice(0, 4) : [];

        const gaps = Array.isArray(intelligence.gaps) ? intelligence.gaps.slice(0, 3) : [];

        const pivots = Array.isArray(intelligence.pivot_candidates) ? intelligence.pivot_candidates.slice(0, 3) : [];

        const contradictions = Array.isArray(intelligence.contradictions) ? intelligence.contradictions.slice(0, 4) : [];

        const attribution = intelligence.attribution && typeof intelligence.attribution === 'object' ? intelligence.attribution : null;

        const hypotheses = attribution && Array.isArray(attribution.hypotheses) ? attribution.hypotheses.slice(0, 4) : [];

        const similaritySignals = attribution && Array.isArray(attribution.similarity_signals) ? attribution.similarity_signals.slice(0, 3) : [];

        const workflow = intelligence.workflow && typeof intelligence.workflow === 'object' ? intelligence.workflow : null;

        const report = intelligence.report && typeof intelligence.report === 'object' ? intelligence.report : null;

        const reportHasContent = !!(report && (

            report.executive_summary

            || report.attribution_assessment

            || (Array.isArray(report.key_findings) && report.key_findings.length)

            || (Array.isArray(report.caveats) && report.caveats.length)

            || (Array.isArray(report.recommended_actions) && report.recommended_actions.length)

        ));

        const rawConfidence = intelligence.confidence && typeof intelligence.confidence === 'object' ? intelligence.confidence : null;

        const confidence = rawConfidence && rawConfidence.has_evidence ? rawConfidence : null;

        const memory = intelligence.memory && typeof intelligence.memory === 'object' ? intelligence.memory : null;

        if (!facts.length && !gaps.length && !pivots.length && !contradictions.length && !hypotheses.length && !similaritySignals.length && !workflow && !reportHasContent && !confidence && !memory) return null;

        const box = el('details', { class: 'ai-intel-box' });

        box.appendChild(el('summary', { class: 'ai-intel-title', text: 'Evidence Snapshot' }));

        if (confidence && (confidence.assessment || confidence.caution)) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Confidence' }));

            const item = el('div', { class: 'ai-intel-item' });

            if (confidence.assessment) item.appendChild(el('div', { class: 'ai-intel-statement', text: confidence.assessment }));

            const meta = [

                confidence.source_count ? `${confidence.source_count} sources` : '',

                confidence.external_claim_count ? `${confidence.external_claim_count} claims` : '',

                confidence.technical_observation_count ? `${confidence.technical_observation_count} technical observations` : '',

                confidence.gap_count ? `${confidence.gap_count} gaps` : ''

            ].filter(Boolean).join(' | ');

            if (meta) item.appendChild(el('div', { class: 'ai-intel-meta', text: meta }));

            if (confidence.caution) item.appendChild(el('div', { class: 'ai-intel-meta', text: confidence.caution }));

            section.appendChild(item);

            box.appendChild(section);

        }

        if (memory && memory.updated_at) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Memory' }));

            section.appendChild(el('div', {

                class: 'ai-intel-item',

                text: `Prior structured intelligence for ${memory.artifact_type || 'artifact'}:${memory.artifact_value || ''} from ${memory.updated_at}`

            }));

            box.appendChild(section);

        }

        if (facts.length) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Facts' }));

            facts.forEach(fact => {

                const item = el('div', { class: 'ai-intel-item' });

                item.appendChild(el('div', { class: 'ai-intel-statement', text: fact.statement || fact.value || '' }));

                const meta = [

                    fact.kind || '',

                    fact.category || '',

                    Array.isArray(fact.sources) ? fact.sources.join(', ') : ''

                ].filter(Boolean).join(' | ');

                if (meta) item.appendChild(el('div', { class: 'ai-intel-meta', text: meta }));

                section.appendChild(item);

            });

            box.appendChild(section);

        }

        if (gaps.length) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Source Health' }));

            gaps.forEach(gap => {

                section.appendChild(el('div', {

                    class: 'ai-intel-item ai-intel-gap',

                    text: `${gap.provider || 'Source'}: ${gap.reason || 'No detail'}`

                }));

            });

            box.appendChild(section);

        }

        if (contradictions.length) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Contradictions' }));

            contradictions.forEach(item => {

                const row = el('div', { class: 'ai-intel-item ai-intel-contradiction' });

                row.appendChild(el('div', { class: 'ai-intel-statement', text: item.statement || item.type || '' }));

                const meta = [item.severity || '', item.impact || ''].filter(Boolean).join(' | ');

                if (meta) row.appendChild(el('div', { class: 'ai-intel-meta', text: meta }));

                section.appendChild(row);

            });

            box.appendChild(section);

        }

        if (hypotheses.length) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Attribution Hypotheses' }));

            hypotheses.forEach(hyp => {

                const row = el('div', { class: 'ai-intel-item ai-intel-hypothesis' });

                row.appendChild(el('div', { class: 'ai-intel-statement', text: `${hyp.name || 'Hypothesis'} - ${hyp.score || 0}/100` }));

                row.appendChild(el('div', { class: 'ai-intel-meta', text: `${hyp.type || ''} | ${hyp.band || ''}` }));

                if (Array.isArray(hyp.evidence) && hyp.evidence.length) row.appendChild(el('div', { class: 'ai-intel-meta', text: `Evidence: ${hyp.evidence.join(', ')}` }));

                if (Array.isArray(hyp.caveats) && hyp.caveats.length) row.appendChild(el('div', { class: 'ai-intel-meta', text: hyp.caveats[0] }));

                if (hyp.recommended_next_step) row.appendChild(el('div', { class: 'ai-intel-meta', text: hyp.recommended_next_step }));

                section.appendChild(row);

            });

            if (attribution?.semantics) section.appendChild(el('div', { class: 'ai-intel-meta', text: attribution.semantics }));

            box.appendChild(section);

        }

        if (similaritySignals.length) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Similarity Support' }));

            similaritySignals.forEach(sig => {

                const row = el('div', { class: 'ai-intel-item' });

                row.appendChild(el('div', { class: 'ai-intel-statement', text: `${sig.entity_name || 'Similarity lead'} - ${sig.score || 0}` }));

                const meta = [sig.entity_type || '', sig.label || '', sig.reason || ''].filter(Boolean).join(' | ');

                if (meta) row.appendChild(el('div', { class: 'ai-intel-meta', text: meta }));

                if (sig.caveat) row.appendChild(el('div', { class: 'ai-intel-meta', text: sig.caveat }));

                section.appendChild(row);

            });

            box.appendChild(section);

        }

        if (pivots.length) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Ranked Pivots' }));

            pivots.forEach(pivot => {

                const action = pivot.action || {};

                const item = el('div', { class: 'ai-intel-pivot' });

                item.appendChild(el('div', { class: 'ai-intel-statement', text: `${pivot.score || 0} - ${actionLabel(action)}` }));

                item.appendChild(el('div', { class: 'ai-intel-meta', text: pivot.reason || '' }));

                if (pivot.analyst_value) item.appendChild(el('div', { class: 'ai-intel-meta', text: pivot.analyst_value }));

                if (pivot.next_step) item.appendChild(el('div', { class: 'ai-intel-meta', text: pivot.next_step }));

                section.appendChild(item);

            });

            box.appendChild(section);

        }

        if (workflow) {

            const questions = Array.isArray(workflow.questions)

                ? workflow.questions.slice(0, 3)

                : Array.isArray(workflow.open_questions)

                    ? workflow.open_questions.slice(0, 3)

                    : [];

            const nextSteps = Array.isArray(workflow.next_steps) ? workflow.next_steps.slice(0, 3) : [];

            const change = workflow.change_my_mind && typeof workflow.change_my_mind === 'object' ? workflow.change_my_mind : {};

            if (nextSteps.length) {

                const section = el('div', { class: 'ai-intel-section' });

                section.appendChild(el('div', { class: 'ai-intel-label', text: 'Analyst Next Steps' }));

                nextSteps.forEach(step => {

                    const row = el('div', { class: 'ai-intel-item' });

                    row.appendChild(el('div', { class: 'ai-intel-statement', text: `${step.title || 'step'}: ${step.target || ''}` }));

                    if (step.next_step) row.appendChild(el('div', { class: 'ai-intel-meta', text: step.next_step }));

                    section.appendChild(row);

                });

                box.appendChild(section);

            }

            if (questions.length) {

                const section = el('div', { class: 'ai-intel-section' });

                section.appendChild(el('div', { class: 'ai-intel-label', text: 'Analyst Questions' }));

                questions.forEach(question => section.appendChild(el('div', { class: 'ai-intel-item', text: question })));

                box.appendChild(section);

            }

            const strengthen = Array.isArray(change.would_strengthen) ? change.would_strengthen.slice(0, 2) : [];

            const weaken = Array.isArray(change.would_weaken) ? change.would_weaken.slice(0, 2) : [];

            if (strengthen.length || weaken.length) {

                const section = el('div', { class: 'ai-intel-section' });

                section.appendChild(el('div', { class: 'ai-intel-label', text: 'Change My Mind' }));

                strengthen.forEach(text => section.appendChild(el('div', { class: 'ai-intel-item', text: `Strengthen: ${text}` })));

                weaken.forEach(text => section.appendChild(el('div', { class: 'ai-intel-item', text: `Weaken: ${text}` })));

                box.appendChild(section);

            }

        }

        if (reportHasContent) {

            const section = el('div', { class: 'ai-intel-section' });

            section.appendChild(el('div', { class: 'ai-intel-label', text: 'Report Draft' }));

            const row = el('div', { class: 'ai-intel-item ai-intel-report' });

            if (report.title) row.appendChild(el('div', { class: 'ai-intel-statement', text: report.title }));

            if (report.executive_summary) row.appendChild(el('div', { class: 'ai-intel-meta', text: report.executive_summary }));

            const findings = Array.isArray(report.key_findings) ? report.key_findings.slice(0, 4) : [];

            findings.forEach(item => row.appendChild(el('div', { class: 'ai-intel-meta', text: `Finding: ${item}` })));

            if (report.attribution_assessment) row.appendChild(el('div', { class: 'ai-intel-meta', text: report.attribution_assessment }));

            section.appendChild(row);

            box.appendChild(section);

        }

        return box;

    }



    function sanitizeAssistantNarrative(text, intelligence = null) {

        let value = String(text || '').trim();

        if (!value) return '';

        if (/^\s*\{[\s\S]*"answer"\s*:/.test(value)) return '';

        const jsonStart = value.search(/\n\s*\{[\s\S]*"answer"\s*:/);

        if (jsonStart >= 0) value = value.slice(0, jsonStart).trim();

        if (intelligence && typeof intelligence === 'object') {

            const noisyPrefix = /^(FACT|GAP|CONTRADICTION|ASSESSMENT|CAUTION|HYPOTHESIS|ATTRIBUTION CAVEAT|WHAT WOULD STRENGTHEN|WHAT WOULD WEAKEN|MEMORY):/i;

            value = value

                .split(/\r?\n/)

                .filter(line => !noisyPrefix.test(line.trim()))

                .filter(line => line.trim().toLowerCase() !== 'run')

                .join('\n')

                .replace(/\n{3,}/g, '\n\n')

                .trim();

        }

        return value;

    }



    function cleanNarrativeText(text) {

        return String(text || '')

            .replace(/\*\*/g, '')

            .replace(/^[-*]\s+/, '')

            .trim();

    }



    function normalizeAssistantText(text) {

        let value = String(text || '').trim();

        if (!value) return '';

        try {

            const parsed = JSON.parse(value);

            value = formatStructuredAnswer(parsed);

        } catch (_) {

            if (/^\{[\s\S]+\}$/.test(value) && /'[^']+'\s*:/.test(value)) {

                value = value

                    .replace(/^\{|\}$/g, '')

                    .replace(/'([A-Za-z0-9_ -]+)'\s*:/g, '\n$1:')

                    .replace(/\],\s*/g, '\n')

                    .replace(/\[\s*/g, '')

                    .replace(/'\s*,\s*'/g, '\n- ')

                    .replace(/'/g, '')

                    .replace(/,\s*(?=[A-Za-z_ -]+:)/g, '\n')

                    .trim();

            }

        }

        return value;

    }



    function formatStructuredAnswer(value) {

        if (!value || typeof value !== 'object') return String(value || '');

        const source = value.answer && typeof value.answer === 'object' ? value.answer : value;

        if (typeof source === 'string') return source;

        const labels = {

            assessment: 'Assessment',

            executive_summary: 'Executive Summary',

            key_findings: 'Key Findings',

            observed_facts: 'Observed Facts',

            facts: 'Observed Facts',

            provider_claims: 'Provider Claims',

            analytic_inferences: 'Analytic Inferences',

            inferences: 'Analytic Inferences',

            contradictions: 'Contradictions',

            noise: 'Noise / Discarded Leads',

            discarded_leads: 'Noise / Discarded Leads',

            confidence: 'Confidence',

            recommended_pivots: 'Recommended Passive Pivots',

            next_steps: 'Recommended Passive Pivots',

            do_not_pivot_on: 'Do Not Pivot On',

            unresolved_questions: 'Unresolved Questions',

            open_questions: 'Unresolved Questions',

            provenance: 'Provenance',

            caveats: 'Caveats',

            reporting_guidance: 'Reporting Guidance'

        };

        const keys = Object.keys(labels).concat(Object.keys(source).filter(key => !(key in labels)));

        const lines = [];

        keys.forEach(key => {

            if (!(key in source)) return;

            const item = source[key];

            if (item === null || item === undefined || item === '' || (Array.isArray(item) && !item.length)) return;

            lines.push(labels[key] || key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()));

            if (Array.isArray(item)) {

                item.slice(0, 12).forEach(entry => {

                    const text = typeof entry === 'object'

                        ? (entry.statement || entry.value || entry.name || entry.reason || JSON.stringify(entry))

                        : String(entry);

                    if (text.trim()) lines.push(`- ${text.trim()}`);

                });

            } else if (typeof item === 'object') {

                Object.entries(item).slice(0, 12).forEach(([subKey, subVal]) => {

                    const text = typeof subVal === 'object' ? JSON.stringify(subVal) : String(subVal);

                    if (text.trim()) lines.push(`- ${subKey.replace(/_/g, ' ')}: ${text.trim()}`);

                });

            } else {

                lines.push(String(item).trim());

            }

            lines.push('');

        });

        return lines.join('\n').trim();

    }



    const NARRATIVE_SECTIONS = new Map([

        ['assessment', { label: 'Assessment', icon: 'fa-scale-balanced', tone: 'assessment' }],

        ['executive summary', { label: 'Executive Summary', icon: 'fa-file-lines', tone: 'summary' }],

        ['summary', { label: 'Summary', icon: 'fa-file-lines', tone: 'summary' }],

        ['key findings', { label: 'Key Findings', icon: 'fa-list-check', tone: 'findings' }],

        ['observed facts', { label: 'Observed Facts', icon: 'fa-fingerprint', tone: 'facts' }],

        ['facts', { label: 'Observed Facts', icon: 'fa-fingerprint', tone: 'facts' }],

        ['provider claims', { label: 'Provider Claims', icon: 'fa-tower-broadcast', tone: 'claims' }],

        ['analytic inferences', { label: 'Analytic Inferences', icon: 'fa-brain', tone: 'inferences' }],

        ['inferences', { label: 'Analytic Inferences', icon: 'fa-brain', tone: 'inferences' }],

        ['attribution assessment', { label: 'Attribution Assessment', icon: 'fa-user-secret', tone: 'attribution' }],

        ['attribution hypotheses', { label: 'Attribution Hypotheses', icon: 'fa-user-secret', tone: 'attribution' }],

        ['contradictions', { label: 'Contradictions', icon: 'fa-triangle-exclamation', tone: 'contradictions' }],

        ['noise / discarded leads', { label: 'Noise / Discarded Leads', icon: 'fa-filter-circle-xmark', tone: 'noise' }],

        ['noise/discarded leads', { label: 'Noise / Discarded Leads', icon: 'fa-filter-circle-xmark', tone: 'noise' }],

        ['discarded leads', { label: 'Noise / Discarded Leads', icon: 'fa-filter-circle-xmark', tone: 'noise' }],

        ['confidence', { label: 'Confidence', icon: 'fa-signal', tone: 'confidence' }],

        ['caveats', { label: 'Caveats', icon: 'fa-circle-exclamation', tone: 'caveats' }],

        ['recommended passive pivots', { label: 'Recommended Passive Pivots', icon: 'fa-route', tone: 'pivots' }],

        ['recommended pivots', { label: 'Recommended Passive Pivots', icon: 'fa-route', tone: 'pivots' }],

        ['recommended next steps', { label: 'Recommended Next Steps', icon: 'fa-forward-step', tone: 'next' }],

        ['next steps', { label: 'Recommended Next Steps', icon: 'fa-forward-step', tone: 'next' }],

        ['do not pivot on', { label: 'Do Not Pivot On', icon: 'fa-ban', tone: 'avoid' }],

        ['open questions', { label: 'Open Questions', icon: 'fa-circle-question', tone: 'questions' }],

        ['unresolved questions', { label: 'Open Questions', icon: 'fa-circle-question', tone: 'questions' }],

        ['provenance', { label: 'Provenance', icon: 'fa-code-branch', tone: 'provenance' }],

        ['reporting guidance', { label: 'Reporting Guidance', icon: 'fa-clipboard-check', tone: 'guidance' }]

    ]);



    function normalizeSectionKey(value) {

        return cleanNarrativeText(value)

            .replace(/[:：]$/, '')

            .replace(/\s+/g, ' ')

            .trim()

            .toLowerCase();

    }



    function sectionMeta(title) {

        const key = normalizeSectionKey(title);

        return NARRATIVE_SECTIONS.get(key) || null;

    }



    function isPlainSectionHeading(line) {

        const cleaned = cleanNarrativeText(line).replace(/[:：]$/, '').trim();

        if (!cleaned || cleaned.length > 64) return null;

        const meta = sectionMeta(cleaned);

        if (meta) return meta;

        if (/^[A-Z][A-Za-z0-9 /&-]{2,}$/.test(cleaned) && !/[.!?]$/.test(cleaned) && cleaned.split(/\s+/).length <= 5) {

            return { label: cleaned, icon: 'fa-layer-group', tone: 'generic' };

        }

        return null;

    }



    function renderNarrativeContent(text, role = 'assistant') {

        const isReport = /^MANTIS Intelligence Report/i.test(String(text || '').trim());

        const root = el('div', { class: `ai-msg-text ${role === 'assistant' ? 'ai-narrative' : ''}${isReport ? ' ai-report-narrative' : ''}` });

        const value = normalizeAssistantText(text);

        if (!value || role !== 'assistant') {

            root.textContent = value;

            return root;

        }

        const lines = value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);

        if (!lines.length) return root;

        let currentSection = null;

        let currentList = null;

        let startIndex = 0;

        if (isReport) {

            const title = cleanNarrativeText(lines[0]);

            const reportHead = el('div', { class: 'ai-report-head' });

            reportHead.appendChild(el('div', { class: 'ai-report-kicker', text: 'Analyst Report' }));

            reportHead.appendChild(el('h4', { text: title }));

            reportHead.appendChild(el('div', { class: 'ai-report-subtitle', text: 'Structured from current MANTIS evidence and provider context.' }));

            root.appendChild(reportHead);

            startIndex = 1;

        }

        const ensureSection = (title, meta = null) => {

            const resolved = meta || sectionMeta(title) || { label: cleanNarrativeText(title).replace(/:$/, ''), icon: 'fa-layer-group', tone: 'generic' };

            currentSection = el('section', { class: `ai-narrative-section ai-section-${resolved.tone || 'generic'}` });

            const heading = el('div', { class: 'ai-narrative-heading' });

            heading.innerHTML = `<i class="fa-solid ${resolved.icon || 'fa-layer-group'}"></i><span>${escapeHtml(resolved.label)}</span>`;

            currentSection.appendChild(heading);

            root.appendChild(currentSection);

            currentList = null;

        };

        const appendParagraph = line => {

            const target = currentSection || root;

            target.appendChild(el('p', { class: 'ai-narrative-paragraph', text: cleanNarrativeText(line) }));

            currentList = null;

        };

        lines.slice(startIndex).forEach(line => {

            const heading = line.match(/^\*\*(.+?)\*\*:?$/)

                || line.match(/^#{1,4}\s+(.+)$/)

                || (line.length < 46 ? line.match(/^([A-Za-z][A-Za-z0-9 /&-]+):$/) : null);

            if (heading) {

                ensureSection(heading[1]);

                return;

            }

            const plainHeading = isPlainSectionHeading(line);

            if (plainHeading) {

                ensureSection(line, plainHeading);

                return;

            }

            const numbered = line.match(/^\d+[.)]\s+(.+)$/);

            const bulleted = line.match(/^[-*]\s+(.+)$/);

            if (numbered || bulleted) {

                const target = currentSection || root;

                if (!currentList) {

                    currentList = el(numbered ? 'ol' : 'ul', { class: 'ai-narrative-list' });

                    target.appendChild(currentList);

                }

                currentList.appendChild(el('li', { text: cleanNarrativeText((numbered || bulleted)[1]) }));

                return;

            }

            appendParagraph(line);

        });

        return root;

    }



    function renderMessage(role, text, actions = [], intelligence = null, options = {}) {

        const list = document.getElementById('ai-chat-messages');

        if (!list) return;

        const bubble = el('div', { class: `ai-msg ai-msg-${role}` });

        bubble.appendChild(el('div', { class: 'ai-msg-role', text: role === 'user' ? 'Analyst' : 'MANTIS AI' }));

        const intelBox = role === 'assistant' && !options.skipBrief ? renderIntelligence(intelligence) : null;

        const narrative = role === 'assistant' ? sanitizeAssistantNarrative(text, intelligence) : String(text || '');

        if (narrative) bubble.appendChild(renderNarrativeContent(narrative, role));

        if (intelBox) bubble.appendChild(intelBox);

        if (!intelBox && !narrative) {

            bubble.appendChild(el('div', { class: 'ai-msg-text ai-msg-muted', text: 'No analyst narrative returned.' }));

        }

        if (actions && actions.length) {

            const actionBox = el('div', { class: 'ai-actions' });

            actionBox.appendChild(el('div', { class: 'ai-actions-heading', text: 'Approved Manual Pivots' }));

            actions.forEach(action => {

                const id = `ai-action-${++state.actionId}`;

                state.actions.set(id, action);

                const label = actionLabel(action);

                const card = el('div', { class: 'ai-action-card' });

                const head = el('div', { class: 'ai-action-head' });

                head.innerHTML = `<i class="fa-solid fa-route"></i><span>${escapeHtml(label)}</span>`;

                card.appendChild(head);

                card.appendChild(el('div', { class: 'ai-action-reason', text: action.reason || 'Manual MANTIS pivot' }));

                const btn = el('button', { class: 'btn-primary ai-run-action', 'data-action-id': id });

                btn.innerHTML = '<i class="fa-solid fa-play"></i> Run';

                card.appendChild(btn);

                actionBox.appendChild(card);

            });

            bubble.appendChild(actionBox);

        }

        const rejectedPivots = Array.isArray(options.rejectedPivots) ? options.rejectedPivots : [];

        if (role === 'assistant' && rejectedPivots.length) {

            bubble.appendChild(renderRejectedPivots(rejectedPivots));

        }

        list.appendChild(bubble);

        list.scrollTop = list.scrollHeight;

    }



    function renderRejectedPivots(items) {

        const box = el('details', { class: 'ai-rejected-pivots' });

        box.appendChild(el('summary', { text: `Suppressed Pivot Suggestions (${items.length})` }));

        const body = el('div', { class: 'ai-rejected-body' });

        items.slice(0, 10).forEach(item => {

            const action = item?.action || {};

            const reason = item?.reason || 'Suppressed by MANTIS pivot policy.';

            const tags = Array.isArray(item?.tags) && item.tags.length ? item.tags.join(', ') : '';

            const row = el('div', { class: 'ai-rejected-row' });

            row.appendChild(el('div', { class: 'ai-rejected-title', text: actionLabel(action) }));

            row.appendChild(el('div', { class: 'ai-rejected-reason', text: reason }));

            if (tags) row.appendChild(el('div', { class: 'ai-rejected-tags', text: tags }));

            body.appendChild(row);

        });

        box.appendChild(body);

        return box;

    }



    function renderThinkingMessage(id, label = 'Thinking') {

        const list = document.getElementById('ai-chat-messages');

        if (!list) return null;

        removeThinkingMessage(id);

        const bubble = el('div', { class: 'ai-msg ai-msg-assistant ai-msg-thinking', id });

        bubble.appendChild(el('div', { class: 'ai-msg-role', text: 'MANTIS AI' }));

        const body = el('div', { class: 'ai-typing' });

        body.appendChild(el('span', { class: 'ai-typing-label', text: label }));

        body.appendChild(el('span', { class: 'ai-typing-dots', 'aria-hidden': 'true' }, [

            el('span'),

            el('span'),

            el('span')

        ]));

        bubble.appendChild(body);

        list.appendChild(bubble);

        list.scrollTop = list.scrollHeight;

        return bubble;

    }



    function renderCasePanel(caseState = state.caseState) {

        const box = document.getElementById('ai-case-panel');

        if (!box) return;

        if (!caseState) {

            box.innerHTML = `

                <div class="ai-case-empty">No case synced yet.</div>

                <div class="ai-case-buttons">

                    <button type="button" id="ai-case-sync" class="btn-secondary"><i class="fa-solid fa-arrows-rotate"></i> Sync Case</button>

                    <button type="button" id="ai-case-step" class="btn-secondary" disabled><i class="fa-solid fa-route"></i> Next Step</button>

                    <button type="button" id="ai-case-run-next" class="btn-secondary" disabled><i class="fa-solid fa-play"></i> Run Next</button>

                    <button type="button" id="ai-case-report" class="btn-secondary" disabled><i class="fa-solid fa-file-lines"></i> Case Report</button>

                </div>

            `;

            return;

        }

        const root = caseState.root || {};

        const assessment = caseState.assessment || {};

        const next = caseState.next_step || {};

        const sources = Array.isArray(next.recommended_sources) ? next.recommended_sources : [];

        const timeline = Array.isArray(caseState.timeline) ? caseState.timeline.slice(0, 6) : [];

        box.innerHTML = `

            <div class="ai-case-head">

                <div>

                    <div class="ai-case-kicker">AEAD Case</div>

                    <div class="ai-case-title">${escapeHtml(root.type || 'context')}: ${escapeHtml(root.value || 'current evidence')}</div>

                </div>

                <b>${escapeHtml(assessment.confidence || 'insufficient_evidence')}</b>

            </div>

            <div class="ai-case-metrics">

                <span><b>${escapeHtml(assessment.source_count || 0)}</b> Sources</span>

                <span><b>${escapeHtml(assessment.observation_count || 0)}</b> Observations</span>

                <span><b>${escapeHtml(assessment.claim_count || 0)}</b> Claims</span>

                <span><b>${escapeHtml(assessment.relationship_count || 0)}</b> Links</span>

                <span><b>${escapeHtml(assessment.rejected_pivot_count || 0)}</b> Suppressed</span>

            </div>

            ${assessment.assessment_text ? `<div class="ai-case-assessment-text"><div class="ai-case-label">AI Assessment</div><div>${escapeHtml(assessment.assessment_text)}</div></div>` : ''}

            <div class="ai-case-next">

                <div class="ai-case-label">Next</div>

                <div>${escapeHtml(next.reason || 'Sync evidence, then request the next AEAD step.')}</div>

                ${sources.length ? `<div class="ai-case-source-row">${sources.map(src => `<span title="${escapeHtml(src.reason || '')}">${escapeHtml(src.label || src.source_id)}</span>`).join('')}</div>` : ''}

            </div>

            <div class="ai-case-buttons">

                <button type="button" id="ai-case-sync" class="btn-secondary"><i class="fa-solid fa-arrows-rotate"></i> Sync Case</button>

                <button type="button" id="ai-case-step" class="btn-secondary"><i class="fa-solid fa-route"></i> Next Step</button>

                <button type="button" id="ai-case-run-next" class="btn-secondary"><i class="fa-solid fa-play"></i> Run Next</button>

                <button type="button" id="ai-case-assess" class="btn-secondary"><i class="fa-solid fa-scale-balanced"></i> Assess</button>

                <button type="button" id="ai-case-report" class="btn-secondary"><i class="fa-solid fa-file-lines"></i> Report</button>

                <button type="button" id="ai-case-export-workspace" class="btn-secondary"><i class="fa-solid fa-box-archive"></i> Export AI Workspace</button>

                <button type="button" id="ai-case-export" class="btn-secondary"><i class="fa-solid fa-download"></i> Export MD</button>

                <button type="button" id="ai-case-export-json" class="btn-secondary"><i class="fa-solid fa-code"></i> Export JSON</button>

            </div>

            <details class="ai-case-timeline">

                <summary>Timeline (${timeline.length})</summary>

                <div>

                    ${timeline.map(item => `

                        <div class="ai-case-event">

                            <b>${escapeHtml(item.phase || '')}</b>

                            <span>${escapeHtml(item.title || '')}</span>

                            ${item.detail ? `<small>${escapeHtml(item.detail)}</small>` : ''}

                        </div>

                    `).join('') || '<div class="ai-case-empty">No timeline entries.</div>'}

                </div>

            </details>

            <details id="ai-case-related-ui" class="ai-case-timeline">

                <summary>Cross-Case Memory</summary>

                <div id="ai-case-related-content" style="padding: 0.5rem; text-align: center;">

                    <button type="button" id="ai-case-load-related" class="btn-secondary"><i class="fa-solid fa-network-wired"></i> Find Related Cases</button>

                </div>

            </details>

        `;

    }



    async function syncCase(note = 'Manual case sync') {

        if (state.caseBusy) return state.caseState;

        state.caseBusy = true;

        try {

            const data = await fetchJson(`${API_BASE}/api/ai/case/sync`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({

                    case_id: state.caseId || '',

                    page_context: compactDomContext(),

                    note

                }),

                timeoutMs: aiRequestTimeoutMs(10)

            });

            state.caseId = data.case_id || state.caseId;

            state.caseState = data;

            renderCasePanel();

            return data;

        } finally {

            state.caseBusy = false;

        }

    }



    async function planCaseStep() {

        const data = await fetchJson(`${API_BASE}/api/ai/case/step`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({

                case_id: state.caseId || '',

                page_context: compactDomContext()

            }),

            timeoutMs: aiRequestTimeoutMs(12)

        });

        state.caseId = data.case_id || state.caseId;

        state.caseState = data;

        renderCasePanel();

        const next = data.next_step || {};

        const sources = (next.recommended_sources || []).map(src => src.label || src.source_id).filter(Boolean).join(', ');

        renderMessage('assistant', `AEAD next step: ${next.reason || 'Assess current case state.'}${sources ? `\n\nRecommended sources: ${sources}` : ''}`, next.action ? [next.action] : []);

    }



    function caseProviderKeys() {

        const local = name => localStorage.getItem(name) || '';

        const input = (id, storageKey = '') => document.getElementById(id)?.value?.trim() || (storageKey ? local(storageKey) : '');

        return {

            vt_key: local('ioc_vt_key'),

            abusech_key: input('abusech-key', 'ioc_abusech_key') || local('ioc_tf_key'),

            malshare_key: input('malshare-key', 'ioc_malshare_key'),

            otx_key: input('otx-key', 'ioc_otx_key'),

            triage_key: input('triage-key', 'ioc_triage_key'),

            tip_key: input('tip-key', 'ioc_tip_key'),

            rwlive_key: input('rwlive-key', 'ioc_rwlive_key'),

            cb_key: input('cb-key', 'ioc_cb_key'),

            ransomlook_key: input('ransomlook-key', 'ioc_ransomlook_key'),

            threatbook_key: local('ioc_threatbook_key'),

            silentpush_key: local('ioc_silentpush_key'),

            driftnet_key: local('ioc_driftnet_key'),

            urlscan_key: local('ioc_urlscan_key'),

            ha_key: local('ioc_ha_key'),

            shodan_key: local('ioc_shodan_key'),

            censys_key: local('ioc_censys_key'),

            etugen_key: local('ioc_etugen_key'),

            fofa_key: local('ioc_fofa_key'),

            validin_key: local('ioc_validin_key'),

            pulsedive_key: local('ioc_pulsedive_key'),

            dnsdumpster_key: local('ioc_dnsdumpster_key'),

            twitter_key: local('ioc_twitter_key'),

            github_key: local('ioc_github_key'),

            abuseipdb_key: local('ioc_abuseipdb_key'),

            greynoise_key: local('ioc_greynoise_key'),

            leakix_key: local('ioc_leakix_key'),

            phishstats_key: local('ioc_phishstats_key')

        };

    }



    function githubReposForCase() {

        const repos = localStorage.getItem('ioc_github_repos') || 'mthcht/ThreatHunting-Keywords\nmthcht/ThreatIntel-Reports\nalexander-hanel/APTnotes-md\nblackorbird/APT_REPORT\nThreatLabz/ransomware_notes';

        return repos.split('\n').map(item => item.trim()).filter(Boolean);

    }



    async function runCaseNextSource() {

        if (!state.caseId) await syncCase('Source execution requested.');

        const data = await fetchJson(`${API_BASE}/api/ai/case/run-next`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({

                case_id: state.caseId || '',

                page_context: compactDomContext(),

                keys: caseProviderKeys(),

                github_repos: githubReposForCase(),

                max_sources: 1

            }),

            timeoutMs: aiRequestTimeoutMs(20)

        });

        state.caseId = data.case_id || state.caseId;

        state.caseState = data;

        renderCasePanel();

        const executions = Array.isArray(data.executions) ? data.executions : [];

        const summary = executions.map(item => `${item.source_id}: ${item.status}${item.count !== undefined ? ` (${item.count})` : ''}${item.error ? ` - ${item.error}` : ''}`).join('\n');

        renderMessage('assistant', summary ? `AEAD source execution completed:\n${summary}` : 'No source was executed. The case may be ready for assessment.');

    }



    async function generateCaseAssessment() {

        if (!state.caseId) await syncCase('Assessment requested.');

        renderMessage('assistant', 'Generating final case assessment...');

        const data = await fetchJson(`${API_BASE}/api/ai/case/${state.caseId}/assess`, {

            method: 'POST',

            timeoutMs: aiRequestTimeoutMs(60)

        });

        state.caseId = data.case_id || state.caseId;

        state.caseState = data;

        renderCasePanel();

        renderMessage('assistant', 'Assessment generated and added to case panel.');

    }



    async function draftCaseReport() {

        if (!state.caseId) await syncCase('Report requested.');

        if (!state.caseId) throw new Error('No MANTIS AI case is available.');

        const data = await fetchJson(`${API_BASE}/api/ai/case/${encodeURIComponent(state.caseId)}/report`, {

            timeoutMs: aiRequestTimeoutMs(12)

        });

        state.caseState = data.case || state.caseState;

        renderCasePanel();

        renderMessage('assistant', data.report || 'No case report returned.', [], state.caseState?.intelligence || null, { skipBrief: true });

    }



    async function loadRelatedCases() {

        if (!state.caseId) return;

        const box = document.getElementById('ai-case-related-content');

        if (!box) return;

        box.innerHTML = '<div class="ai-case-empty"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</div>';

        try {

            const data = await fetchJson(`${API_BASE}/api/ai/case/${encodeURIComponent(state.caseId)}/related`);

            const related = data.related_cases || [];

            if (!related.length) {

                box.innerHTML = '<div class="ai-case-empty">No correlated cases found.</div>';

                return;

            }

            let html = '';

            related.forEach(item => {

                html += `

                    <div class="ai-case-event" style="margin-bottom: 0.5rem; text-align: left;">

                        <b>Case:</b> ${escapeHtml(item.case_id)}<br>

                        <b>Target:</b> <code>${escapeHtml(item.root_type)}:${escapeHtml(item.root_value)}</code><br>

                        <b>Overlap:</b> <code>${escapeHtml(item.match_value)}</code> (${escapeHtml(item.match_type)})

                    </div>

                `;

            });

            box.innerHTML = html;

        } catch (e) {

            box.innerHTML = `<div class="ai-case-empty" style="color:var(--text-error);">Error: ${escapeHtml(e.message)}</div>`;

        }

    }



    function removeThinkingMessage(id) {

        if (!id) return;

        document.getElementById(id)?.remove();

    }



    function actionLabel(action) {

        const labels = {

            lookup_hash: 'Hash Lookup',

            lookup_domain: 'Domain Lookup',

            lookup_ip: 'IP Lookup',

            lookup_url: 'URL Lookup',

            keyword_search: 'Keyword Search',

            infra_search: 'Infra Search',

            search_cti_articles: 'Search CTI Articles',

            search_threat_actor: 'Search Threat Actor',

            search_malware: 'Search Malware & Tools',

            search_yara: 'Search YARA Rules'

        };

        const arg = Object.values(action?.arguments || {}).find(Boolean) || '';

        return `${labels[action?.tool] || action?.tool || 'Pivot'}${arg ? `: ${arg}` : ''}`;

    }



    function setBusy(isBusy) {

        const send = document.getElementById('ai-send');

        const input = document.getElementById('ai-input');

        if (send) send.disabled = isBusy;

        if (input) input.disabled = isBusy;

        document.querySelectorAll('#ai-summary, #ai-pivots, #ai-report').forEach(btn => { btn.disabled = isBusy; });

        document.getElementById('mantis-ai-panel')?.classList.toggle('ai-busy', !!isBusy);

        const status = document.getElementById('ai-status');

        if (status) status.textContent = state.settings?.available ? 'Ready' : 'Not configured';

    }



    function updateContextNotice() {

        const notice = document.getElementById('ai-context-notice');

        if (!notice) return;

        const ctx = compactDomContext();

        const meta = ctx?.context_meta || {};

        if (meta.omitted_raw_result || meta.backend_truncated || ctx?.truncated) {

            const providers = meta.providers_in_snapshot !== undefined ? `${meta.providers_in_snapshot} provider snapshot(s)` : 'compact evidence snapshot';

            notice.style.display = 'block';

            notice.textContent = `AI context: using ${providers}; full downloadable JSON is not sent to the model.`;

        } else {

            notice.style.display = 'none';

            notice.textContent = '';

        }

    }



    function setMode(mode) {

        state.mode = mode === 'agent' ? 'agent' : 'assist';

        document.querySelectorAll('[data-ai-mode]').forEach(btn => {

            btn.classList.toggle('active', btn.dataset.aiMode === state.mode);

        });

        const controls = document.getElementById('ai-agent-controls');

        if (controls) controls.style.display = state.mode === 'agent' ? 'block' : 'none';

    }



    async function askAI(operation, text) {

        const prompt = text || '';

        if (!prompt.trim()) return;

        updateContextNotice();

        const requestId = ++state.chatRequestId;

        const thinkingId = `ai-thinking-${requestId}`;

        state.messages.push({ role: 'user', content: prompt });

        renderMessage('user', prompt);

        renderThinkingMessage(thinkingId, operation === 'draft_report' ? 'Drafting report' : 'Thinking');

        setBusy(true);

        try {

            const data = await fetchJson(`${API_BASE}/api/ai/chat`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({

                    operation,

                    messages: state.messages.slice(-10),

                    page_context: compactDomContext()

                }),

                timeoutMs: aiRequestTimeoutMs(15)

            });

            if (requestId !== state.chatRequestId) {

                removeThinkingMessage(thinkingId);

                return;

            }

            removeThinkingMessage(thinkingId);

            const answer = data.answer || 'No response.';

            state.messages.push({ role: 'assistant', content: answer });

            renderMessage('assistant', answer, data.proposed_actions || [], data.intelligence || null, {

                skipBrief: operation === 'draft_report',

                rejectedPivots: data.rejected_pivots || []

            });

            syncCase(`AI ${operation} response completed.`).catch(err => console.debug('MANTIS AI case sync skipped:', err));

        } catch (e) {

            if (requestId !== state.chatRequestId) {

                removeThinkingMessage(thinkingId);

                return;

            }

            removeThinkingMessage(thinkingId);

            renderMessage('assistant', e.message || 'MANTIS AI is unavailable.');

        } finally {

            removeThinkingMessage(thinkingId);

            if (requestId === state.chatRequestId) setBusy(false);

        }

    }



    async function runAction(id, button) {

        const action = state.actions.get(id);

        if (!action) return;

        if (button) button.disabled = true;

        try {

            renderMessage('assistant', `Running approved action: ${actionLabel(action)}.`);

            const data = await fetchJson(`${API_BASE}/api/ai/tool/execute`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ ...action, page: compactDomContext().page || '' })

            });

            if (typeof window.mantisRunApprovedAction !== 'function') {

                throw new Error('MANTIS action bridge is unavailable.');

            }

            await window.mantisRunApprovedAction(data.frontend_action || {});

            notify('Approved MANTIS action started');

            renderMessage('assistant', `Action started in MANTIS: ${actionLabel(data.action || action)}.`);

            minimizePanel();

        } catch (e) {

            renderMessage('assistant', `Action failed: ${e.message}`);

        } finally {

            if (button) button.disabled = false;

        }

    }



    function renderAgentTrace(run) {

        const box = document.getElementById('ai-agent-trace');

        if (!box) return;

        const steps = (run?.steps || []).slice(-20);

        box.innerHTML = steps.map(step => `

            <div class="ai-agent-step ai-agent-step-${step.status || 'pending'}">

                <div class="ai-agent-step-head">

                    <span>${step.step || ''}. ${escapeHtml(step.title || step.tool || 'Step')}</span>

                    <b>${escapeHtml(step.status || '')}</b>

                </div>

                ${step.artifact ? `<div class="ai-agent-step-artifact">${escapeHtml(step.artifact)}</div>` : ''}

                ${step.reason ? `<div class="ai-agent-step-reason">${escapeHtml(step.reason)}</div>` : ''}

                ${step.objective ? `<div class="ai-agent-step-reason">${escapeHtml(step.objective)}</div>` : ''}

                ${step.next_step ? `<div class="ai-agent-step-reason">${escapeHtml(step.next_step)}</div>` : ''}

                ${step.source ? `<div class="ai-agent-step-reason">Source: ${escapeHtml(step.source)}</div>` : ''}

                ${step.detail ? `<div class="ai-agent-step-reason">${escapeHtml(step.detail)}</div>` : ''}

                ${step.agent_plan?.hypotheses?.length ? `<div class="ai-agent-step-reason">Hypotheses: ${escapeHtml(step.agent_plan.hypotheses.map(h => `${h.name || 'unknown'} ${h.band || ''}`).join(' | '))}</div>` : ''}

                ${step.agent_plan?.review_items?.length ? `<div class="ai-agent-step-reason">Review: ${escapeHtml(step.agent_plan.review_items.map(x => x.title || x.type || '').filter(Boolean).join(' | '))}</div>` : ''}

                ${step.error ? `<div class="ai-agent-step-error">${escapeHtml(step.error)}</div>` : ''}

            </div>

        `).join('') || '<div class="ai-agent-empty">No agent steps yet.</div>';

        const status = document.getElementById('ai-agent-run-status');

        if (status) {

            const bits = [

                run?.status || 'idle',

                `${run?.lookups_used || 0}/${run?.limits?.max_lookups || 0} lookups`,

                `depth ${run?.depth || 0}/${run?.limits?.max_depth || 0}`

            ];

            status.textContent = bits.join(' · ');

        }

    }



    function escapeHtml(value) {

        return String(value || '').replace(/[&<>"']/g, ch => ({

            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'

        }[ch]));

    }



    function agentLimits() {

        return {

            max_lookups: Number(document.getElementById('ai-agent-max-lookups')?.value || 20),

            max_depth: Number(document.getElementById('ai-agent-max-depth')?.value || 5),

            max_pivots_per_step: Number(document.getElementById('ai-agent-max-pivots')?.value || 3),

            max_runtime_seconds: Number(document.getElementById('ai-agent-max-runtime')?.value || 600)

        };

    }



    async function startAgent(goalText = '') {

        if (state.agentRunning) return;

        const sessionId = ++state.agentSessionId;

        state.agentRunning = true;

        state.agentStopRequested = false;

        const startBtn = document.getElementById('ai-agent-start');

        const stopBtn = document.getElementById('ai-agent-stop');

        if (startBtn) startBtn.disabled = true;

        if (stopBtn) stopBtn.disabled = false;

        renderMessage('assistant', 'Agent investigation started. I will run only backend-validated passive MANTIS actions and stop on limits or your Stop command.');

        try {

            let run = await fetchJson(`${API_BASE}/api/ai/agent/start`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({

                    page_context: compactDomContext(),

                    goal: goalText || document.getElementById('ai-input')?.value?.trim() || 'Investigate current MANTIS findings',

                    limits: agentLimits()

                }),

                timeoutMs: aiRequestTimeoutMs(20)

            });

            if (sessionId !== state.agentSessionId) return;

            state.agentRunId = run.agent_run_id;

            renderAgentTrace(run);

            await continueAgent(run, sessionId, run.agent_run_id);

        } catch (e) {

            if (sessionId !== state.agentSessionId) return;

            renderMessage('assistant', `Agent could not start: ${e.message}`);

        } finally {

            if (sessionId === state.agentSessionId) {

                state.agentRunning = false;

                if (startBtn) startBtn.disabled = false;

                if (stopBtn) stopBtn.disabled = true;

            }

        }

    }



    async function continueAgent(run, sessionId, runId) {

        let current = run;

        while (sessionId === state.agentSessionId && current && current.status === 'running' && current.next_action && !state.agentStopRequested) {

            const label = actionLabel(current.next_action);

            renderMessage('assistant', `Agent running: ${label}\nReason: ${current.next_action.reason || 'Selected as the next passive pivot.'}`);

            let lastStatus = 'complete';

            let lastError = '';

            try {

                if (typeof window.mantisRunApprovedAction === 'function') {

                    await window.mantisRunApprovedAction(current.frontend_action || {});

                } else {

                    throw new Error('MANTIS action bridge is unavailable.');

                }

                await new Promise(resolve => setTimeout(resolve, 250));

            } catch (e) {

                lastStatus = 'failed';

                lastError = e.message || 'Action failed';

            }

            current = await fetchJson(`${API_BASE}/api/ai/agent/next`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({

                    agent_run_id: runId,

                    latest_context: compactDomContext(),

                    last_status: lastStatus,

                    last_error: lastError

                }),

                timeoutMs: aiRequestTimeoutMs(20)

            });

            if (sessionId !== state.agentSessionId || runId !== state.agentRunId) return;

            renderAgentTrace(current);

        }

        if (sessionId !== state.agentSessionId || runId !== state.agentRunId) return;

        if (state.agentStopRequested && runId) {

            current = await fetchJson(`${API_BASE}/api/ai/agent/stop`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ agent_run_id: runId, reason: 'Analyst clicked Stop.' }),

                timeoutMs: aiRequestTimeoutMs(10)

            });

            if (sessionId !== state.agentSessionId || runId !== state.agentRunId) return;

            renderAgentTrace(current);

        }

        if (current?.status !== 'running') {

            const label = current?.status === 'completed' ? 'Agent complete' : current?.status === 'failed' ? 'Agent failed' : 'Agent stopped';

            const summary = normalizeAssistantText(current?.final_summary || '');

            renderMessage('assistant', `${label}: ${current?.stop_reason || 'No stop reason recorded.'}${summary ? `\n\n${summary}` : ''}`, current?.manual_suggestions || []);

        }

    }



    async function stopAgent() {

        state.agentStopRequested = true;

        if (!state.agentRunId) return;

        try {

            const run = await fetchJson(`${API_BASE}/api/ai/agent/stop`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ agent_run_id: state.agentRunId, reason: 'Analyst clicked Stop.' }),

                timeoutMs: aiRequestTimeoutMs(10)

            });

            if (run.agent_run_id !== state.agentRunId) return;

            renderAgentTrace(run);

            renderMessage('assistant', `Stop requested: ${run.stop_reason || 'Agent stopped.'}`);

        } catch (e) {

            renderMessage('assistant', `Stop failed: ${e.message}`);

        }

    }



    function parseEntityText(text, fallbackId) {

        const raw = String(text || '').trim();

        if (!raw) return null;

        try {

            const parsed = JSON.parse(raw);

            return {

                id: parsed.id || parsed.label || fallbackId,

                label: parsed.label || parsed.id || fallbackId,

                type: parsed.type || 'artifact',

                data: parsed.data || parsed

            };

        } catch (e) {

            return {

                id: fallbackId,

                label: fallbackId,

                type: 'artifact',

                data: { visible_text: raw }

            };

        }

    }



    async function compareCorrelation() {

        const requestId = ++state.correlationRequestId;

        const current = compactDomContext();

        const otherText = document.getElementById('ai-correlation-input')?.value || '';

        const other = parseEntityText(otherText, 'comparison_entity');

        const button = document.getElementById('ai-correlation-run');

        const resultBox = document.getElementById('ai-correlation-result');

        if (!other) {

            if (resultBox) {

                resultBox.innerHTML = '<div class="ai-agent-empty ai-tool-hint">Paste a second artifact, JSON result, domain, hash, or campaign note first.</div>';

            }

            renderMessage('assistant', 'Paste another artifact, sample summary, JSON result, domain, hash, or campaign note to compare with the current page.');

            return;

        }

        const payload = {

            correlation_id: state.correlation?.correlation_id || '',

            entities: [

                { id: 'current_page', label: current.title || current.page || 'Current MANTIS page', type: current.page || 'current', data: current },

                other

            ]

        };

        state.correlationPayload = payload;

        const oldHtml = button?.innerHTML || '';

        if (button) {

            button.disabled = true;

            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Comparing...';

        }

        if (resultBox) resultBox.innerHTML = '<div class="ai-tool-loading"><span>Comparing relationship</span><b></b><b></b><b></b></div>';

        try {

            const result = await fetchJson(`${API_BASE}/api/ai/correlation/compare`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify(payload),

                timeoutMs: aiRequestTimeoutMs(20)

            });

            if (requestId !== state.correlationRequestId) {

                if (resultBox && /Comparing relationship/i.test(resultBox.textContent || '')) {

                    resultBox.innerHTML = '<div class="ai-agent-empty ai-tool-hint">A newer correlation request replaced this one.</div>';

                }

                return;

            }

            state.correlation = result;

            renderCorrelation(result);

            renderMessage('assistant', correlationSummaryText(result));

        } catch (e) {

            if (requestId !== state.correlationRequestId) return;

            if (resultBox) resultBox.innerHTML = `<div class="ai-agent-empty ai-agent-step-error">${escapeHtml(e.message || 'Correlation failed')}</div>`;

            renderMessage('assistant', `Correlation failed: ${e.message}`);

        } finally {

            if (requestId === state.correlationRequestId && button) {

                button.disabled = false;

                button.innerHTML = oldHtml || '<i class="fa-solid fa-code-compare"></i> Compare Relationship';

            }

        }

    }



    async function assessAttribution() {

        const requestId = ++state.attributionRequestId;

        const current = compactDomContext();

        const namesText = document.getElementById('ai-attribution-candidates')?.value || '';

        const candidateNames = namesText.split(/[,;\n]/).map(x => x.trim()).filter(Boolean).slice(0, 10);

        const button = document.getElementById('ai-attribution-run');

        const resultBox = document.getElementById('ai-attribution-result');

        const payload = {

            attribution_id: state.attribution?.attribution_id || '',

            activity: {

                id: 'current_activity',

                label: current.title || current.page || 'Current MANTIS page',

                type: current.page || 'activity',

                data: current

            },

            candidate_names: candidateNames,

            limit: 10

        };

        state.attributionPayload = payload;

        const oldHtml = button?.innerHTML || '';

        if (button) {

            button.disabled = true;

            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Assessing...';

        }

        if (resultBox) {

            resultBox.innerHTML = `<div class="ai-tool-loading"><span>${candidateNames.length ? 'Assessing attribution evidence' : 'Finding candidate actors and malware'}</span><b></b><b></b><b></b></div>`;

        }

        try {

            const result = await fetchJson(`${API_BASE}/api/ai/attribution/assess`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify(payload),

                timeoutMs: aiRequestTimeoutMs(20)

            });

            if (requestId !== state.attributionRequestId) {

                if (resultBox && /Assessing attribution|Looking for candidate/i.test(resultBox.textContent || '')) {

                    resultBox.innerHTML = '<div class="ai-agent-empty ai-tool-hint">A newer attribution request replaced this one.</div>';

                }

                return;

            }

            state.attribution = result;

            renderAttribution(result);

            renderMessage('assistant', attributionSummaryText(result));

        } catch (e) {

            if (requestId !== state.attributionRequestId) return;

            if (resultBox) resultBox.innerHTML = `<div class="ai-agent-empty ai-agent-step-error">${escapeHtml(e.message || 'Attribution assessment failed')}</div>`;

            renderMessage('assistant', `Attribution assessment failed: ${e.message}`);

        } finally {

            if (requestId === state.attributionRequestId && button) {

                button.disabled = false;

                button.innerHTML = oldHtml || '<i class="fa-solid fa-scale-balanced"></i> Assess Evidence';

            }

        }

    }



    function attributionSummaryText(result) {

        const lines = ['Attribution assessment'];

        (result.ranking || []).slice(0, 5).forEach((item, idx) => {

            lines.push(`${idx + 1}. ${item.candidate_name}: ${item.score}/100 ${item.assessment}`);

        });

        lines.push('', result.score_semantics || 'Scores are evidence alignment, not probability.');

        if (result.ai_explanation) lines.push('', result.ai_explanation);

        return lines.filter(Boolean).join('\n');

    }



    function renderAttribution(result) {

        const box = document.getElementById('ai-attribution-result');

        if (!box) return;

        const ranking = result.ranking || [];

        const top = ranking[0] || null;

        box.innerHTML = `

            <div class="ai-correlation-card ai-tool-result-card">

                <div class="ai-tool-result-head">

                    <div>

                        <div class="ai-tool-result-kicker">Attribution</div>

                        <div class="ai-correlation-title">Evidence Alignment</div>

                    </div>

                    ${top ? `<div class="ai-tool-result-score">${escapeHtml(String(top.score || 0))}<span>/100</span></div>` : ''}

                </div>

                <div class="ai-correlation-reason">${escapeHtml(result.score_semantics || 'Scores are evidence alignment, not probability.')}</div>

                <div class="ai-attribution-list">

                    ${ranking.map(renderAttributionCandidate).join('') || '<div class="ai-agent-empty">No attribution candidates scored.</div>'}

                </div>

            </div>

        `;

    }



    function renderAttributionCandidate(item, index) {

        const categories = item.categories || {};

        const categoryRows = Object.entries(categories)

            .filter(([category, detail]) => (detail.score || 0) > 0 || ['MALWARE', 'CONFIGURATION', 'PROTOCOL', 'INFRASTRUCTURE', 'DEVELOPER_ARTIFACT'].includes(category))

            .map(([category, detail]) => `

                <div class="ai-score-row">

                    <div class="ai-score-row-top">

                        <span>${escapeHtml(category.replace(/_/g, ' '))}</span>

                        <b>${escapeHtml(String(detail.score || 0))}/${escapeHtml(String(detail.cap || 0))}</b>

                    </div>

                    <div class="ai-score-meter"><span style="width:${Math.max(0, Math.min(100, detail.cap ? Math.round(((detail.score || 0) / detail.cap) * 100) : 0))}%"></span></div>

                </div>

            `).join('');

        const evidence = item.supporting_evidence || [];

        const contradictions = item.contradictions || [];

        const missing = item.missing_evidence || [];

        const claims = item.external_attribution_claims || [];

        return `

            <div class="ai-attribution-candidate ${index === 0 ? 'is-top' : ''}">

                <div class="ai-attribution-rank">

                    <span><em>${index + 1}</em>${escapeHtml(item.candidate_name || '')}</span>

                    <b>${escapeHtml(String(item.score || 0))}<small>/100</small></b>

                </div>

                <div class="ai-attribution-summary">${escapeHtml(item.score_label || 'Attribution Evidence Score')} - ${escapeHtml(item.assessment || '')}</div>

                <div class="ai-score-grid">${categoryRows}</div>

                <details class="ai-evidence-details">

                    <summary>Supporting Evidence (${evidence.length})</summary>

                    <div class="ai-evidence-list">

                        ${evidence.slice(0, 12).map(item => renderEvidenceItem(item, 'attribution')).join('') || '<div class="ai-agent-empty">No scored supporting evidence.</div>'}

                    </div>

                </details>

                ${contradictions.length ? `

                    <details class="ai-evidence-details">

                        <summary>Contradictions (${contradictions.length})</summary>

                        <div class="ai-evidence-list">${contradictions.map(item => renderEvidenceItem(item, 'attribution')).join('')}</div>

                    </details>

                ` : ''}

                ${missing.length ? `<div class="ai-attribution-note"><b>Missing</b>${escapeHtml(missing.slice(0, 3).join(' '))}</div>` : ''}

                ${claims.length ? `<div class="ai-attribution-note"><b>Claims</b>${escapeHtml(claims.map(c => c.source || c.reference || 'source').slice(0, 3).join(', '))}</div>` : ''}

            </div>

        `;

    }



    function correlationSummaryText(result) {

        const counts = result.counts || {};

        const lines = [

            `Relationship: ${result.relationship || 'UNKNOWN'}`,

            result.assessment_reason || '',

            `Strong: ${counts.STRONG || 0} · Supporting: ${counts.SUPPORTING || 0} · Weak: ${counts.WEAK || 0} · Contradicting: ${counts.CONTRADICTING || 0}`,

        ];

        if (result.cluster_candidate?.suggested) {

            lines.push(`Possible Cluster Relationship: ${result.cluster_candidate.cluster_id}`);

        }

        if (result.ai_explanation) lines.push('', result.ai_explanation);

        return lines.filter(Boolean).join('\n');

    }



    function renderCorrelation(result) {

        const box = document.getElementById('ai-correlation-result');

        if (!box) return;

        const counts = result.counts || {};

        const evidence = result.evidence || [];

        const ctiRefs = result.cti_references || [];

        const relationship = String(result.relationship || 'UNKNOWN');

        box.innerHTML = `

            <div class="ai-correlation-card ai-tool-result-card">

                <div class="ai-tool-result-head">

                    <div>

                        <div class="ai-tool-result-kicker">Correlation</div>

                        <div class="ai-correlation-title">${escapeHtml(relationship.replace(/_/g, ' '))}</div>

                    </div>

                    <div class="ai-relationship-pill ai-relationship-${escapeHtml(relationship.toLowerCase().replace(/[^a-z0-9]+/g, '-'))}">${escapeHtml(relationship.split(/[_\s-]+/)[0] || 'Result')}</div>

                </div>

                <div class="ai-correlation-reason">${escapeHtml(result.assessment_reason || '')}</div>

                <div class="ai-correlation-counts">

                    <span class="is-strong"><b>${counts.STRONG || 0}</b><small>Strong</small></span>

                    <span class="is-supporting"><b>${counts.SUPPORTING || 0}</b><small>Supporting</small></span>

                    <span class="is-weak"><b>${counts.WEAK || 0}</b><small>Weak</small></span>

                    <span class="is-contradicting"><b>${counts.CONTRADICTING || 0}</b><small>Contradicting</small></span>

                </div>

                ${result.cluster_candidate?.suggested ? `<div class="ai-cluster-pill">Possible Cluster Relationship · ${escapeHtml(result.cluster_candidate.cluster_id)}</div>` : ''}

                <details class="ai-evidence-details" ${evidence.length ? 'open' : ''}>

                    <summary>${evidence.length ? `Evidence (${evidence.length})` : 'Evidence'}</summary>

                    <div class="ai-evidence-list">

                        ${evidence.slice(0, 40).map(item => renderEvidenceItem(item, 'correlation')).join('') || '<div class="ai-agent-empty">No meaningful overlap found.</div>'}

                    </div>

                </details>

                ${ctiRefs.length ? `

                    <details class="ai-evidence-details">

                        <summary>Local CTI References (${ctiRefs.length})</summary>

                        <div class="ai-evidence-list">

                            ${ctiRefs.map(renderCtiReference).join('')}

                        </div>

                    </details>

                ` : ''}

            </div>

        `;

    }



    function renderCtiReference(ref) {

        const articles = ref.articles || [];

        return `

            <div class="ai-evidence-item">

                <div class="ai-evidence-head">

                    <span>${escapeHtml(ref.artifact || '')}</span>

                    <b>CTI_REFERENCE</b>

                </div>

                <div class="ai-evidence-meta">${escapeHtml(ref.note || '')}</div>

                ${articles.map(article => `

                    <div class="ai-evidence-meta">

                        ${escapeHtml(article.source || 'Local CTI')} - ${escapeHtml(article.title || 'Untitled')}

                        ${article.published ? ` (${escapeHtml(article.published)})` : ''}

                    </div>

                `).join('')}

            </div>

        `;

    }



    function renderEvidenceItem(item, scope = 'correlation') {

        const sources = (item.sources || []).join(', ');

        const mark = item.analyst_mark ? ` · ${item.analyst_mark}` : '';

        return `

            <div class="ai-evidence-item ai-evidence-${escapeHtml(item.strength || '').toLowerCase()}">

                <div class="ai-evidence-head">

                    <span>${escapeHtml(item.strength || '')}${mark}</span>

                    <b>${escapeHtml(item.category || '')}</b>

                </div>

                <div class="ai-evidence-value">${escapeHtml(item.type || '')}: ${escapeHtml(item.value || '')}</div>

                <div class="ai-evidence-meta">Entities: ${escapeHtml((item.entities || []).join(' ↔ '))}</div>

                <div class="ai-evidence-meta">Sources: ${escapeHtml(sources || 'MANTIS')}</div>

                ${item.first_seen || item.last_seen ? `<div class="ai-evidence-meta">Time: ${escapeHtml(item.first_seen || '?')} → ${escapeHtml(item.last_seen || '?')}</div>` : ''}

                <div class="ai-evidence-actions">

                    <button class="btn-secondary ai-evidence-mark" data-evidence-scope="${escapeHtml(scope)}" data-evidence-id="${escapeHtml(item.id)}" data-mark="relevant">Relevant</button>

                    <button class="btn-secondary ai-evidence-mark" data-evidence-scope="${escapeHtml(scope)}" data-evidence-id="${escapeHtml(item.id)}" data-mark="not_relevant">Not Relevant</button>

                    <button class="btn-secondary ai-evidence-mark" data-evidence-scope="${escapeHtml(scope)}" data-evidence-id="${escapeHtml(item.id)}" data-mark="false_positive">False Positive</button>

                </div>

            </div>

        `;

    }



    async function markEvidence(evidenceId, mark, scope = 'correlation') {

        const isAttribution = scope === 'attribution';

        const runId = isAttribution ? state.attribution?.attribution_id : state.correlation?.correlation_id;

        if (!runId) return;

        const note = mark === 'false_positive' ? (prompt('Optional note for this evidence item:') || '') : '';

        try {

            await fetchJson(`${API_BASE}/api/ai/correlation/mark`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ correlation_id: runId, evidence_id: evidenceId, mark, note })

            });

            if (isAttribution && state.attributionPayload) {

                const payload = { ...state.attributionPayload, attribution_id: runId };

                state.attributionPayload = payload;

                const result = await fetchJson(`${API_BASE}/api/ai/attribution/assess`, {

                    method: 'POST',

                    headers: { 'Content-Type': 'application/json' },

                    body: JSON.stringify(payload)

                });

                state.attribution = result;

                renderAttribution(result);

            } else if (state.correlationPayload) {

                const payload = { ...state.correlationPayload, correlation_id: runId };

                state.correlationPayload = payload;

                const result = await fetchJson(`${API_BASE}/api/ai/correlation/compare`, {

                    method: 'POST',

                    headers: { 'Content-Type': 'application/json' },

                    body: JSON.stringify(payload)

                });

                state.correlation = result;

                renderCorrelation(result);

            }

        } catch (e) {

            renderMessage('assistant', `Could not mark evidence: ${e.message}`);

        }

    }



    const DEFAULT_PROVIDERS = [

        { id: 'antigravity', label: 'SSO Antigravity (agy CLI)', endpoint: '', model: 'gemini-3.8-flash-low', api_key_required: false, adapter: 'antigravity' },

        { id: 'chatgpt_desktop', label: 'ChatGPT Desktop / Account (Sign-in)', endpoint: '', model: 'auto', api_key_required: false, adapter: 'chatgpt_account' },

        { id: 'claude_desktop', label: 'Claude Desktop / Claude Code CLI', endpoint: '', model: 'sonnet', api_key_required: false, adapter: 'claude_code' },

        { id: 'deepseek', label: 'DeepSeek', endpoint: 'https://api.deepseek.com/chat/completions', model: 'deepseek-chat', api_key_required: true, adapter: 'openai_compatible' },

        { id: 'anthropic', label: 'Anthropic Claude', endpoint: 'https://api.anthropic.com/v1/messages', model: 'claude-3-5-sonnet-latest', api_key_required: true, adapter: 'anthropic' },

        { id: 'gemini', label: 'Google Gemini', endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent', model: 'gemini-1.5-flash', api_key_required: true, adapter: 'gemini' },

        { id: 'openai', label: 'OpenAI', endpoint: 'https://api.openai.com/v1/chat/completions', model: 'gpt-4o-mini', api_key_required: true, adapter: 'openai_compatible' },

        { id: 'openrouter', label: 'OpenRouter', endpoint: 'https://openrouter.ai/api/v1/chat/completions', model: 'openai/gpt-4o-mini', api_key_required: true, adapter: 'openai_compatible' },

        { id: 'groq', label: 'Groq', endpoint: 'https://api.groq.com/openai/v1/chat/completions', model: 'llama-3.3-70b-versatile', api_key_required: true, adapter: 'openai_compatible' },

        { id: 'together', label: 'Together AI', endpoint: 'https://api.together.xyz/v1/chat/completions', model: 'meta-llama/Llama-3.3-70B-Instruct-Turbo', api_key_required: true, adapter: 'openai_compatible' },

        { id: 'mistral', label: 'Mistral', endpoint: 'https://api.mistral.ai/v1/chat/completions', model: 'mistral-small-latest', api_key_required: true, adapter: 'openai_compatible' },

        { id: 'xai', label: 'xAI', endpoint: 'https://api.x.ai/v1/chat/completions', model: 'grok-2-latest', api_key_required: true, adapter: 'openai_compatible' },

        { id: 'ollama', label: 'Ollama', endpoint: 'http://localhost:11434/api/chat', model: 'llama3.1', api_key_required: false, adapter: 'ollama' },

        { id: 'lmstudio', label: 'LM Studio', endpoint: 'http://localhost:1234/v1/chat/completions', model: 'local-model', api_key_required: false, adapter: 'openai_compatible' },

        { id: 'litellm', label: 'LiteLLM Proxy', endpoint: 'http://localhost:4000/v1/chat/completions', model: 'gpt-4o-mini', api_key_required: false, adapter: 'openai_compatible' },

        { id: 'copilot', label: 'GitHub Copilot CLI', endpoint: '', model: 'default', api_key_required: false, adapter: 'copilot' },

        { id: 'opencode', label: 'OpenCode CLI', endpoint: '', model: 'default', api_key_required: false, adapter: 'opencode' },

        { id: 'azure_openai', label: 'Azure OpenAI', endpoint: 'https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT/chat/completions?api-version=2024-06-01', model: 'YOUR-DEPLOYMENT', api_key_required: true, adapter: 'azure_openai' },

        { id: 'openai_compatible', label: 'Custom OpenAI-compatible', endpoint: 'https://api.openai.com/v1/chat/completions', model: 'gpt-4o-mini', api_key_required: true, adapter: 'openai_compatible' }

    ];



    function getProvidersList() {

        if (Array.isArray(state.settings?.providers) && state.settings.providers.length > 0) {

            return state.settings.providers;

        }

        return DEFAULT_PROVIDERS;

    }



    function renderProviderOptions(selectedId) {

        const select = document.getElementById('ai-provider');

        if (!select) return;

        const providers = getProvidersList();

        const curVal = selectedId || select.value || state.settings?.provider || 'openai_compatible';

        select.innerHTML = providers.map(p => {

            const isCli = ['antigravity', 'claude_code', 'chatgpt_account', 'cli', 'opencode', 'copilot'].includes(p.adapter);

            const badge = isCli ? ' (CLI / Account SSO)' : (p.api_key_required ? '' : ' (local/keyless)');

            return `<option value="${aiEsc(p.id)}">${aiEsc(p.label)}${badge}</option>`;

        }).join('');

        select.value = curVal;

    }



    async function loadSettings() {

        try {

            state.settings = await fetchJson(`${API_BASE}/api/ai/settings`);

            hydrateSettingsForm();

            const status = document.getElementById('ai-status');

            if (status) status.textContent = state.settings.available ? 'Ready' : 'Not configured';

        } catch (e) {

            state.settings = { available: false };

            const status = document.getElementById('ai-status');

            if (status) status.textContent = 'Not configured';

        }

    }



    function hydrateSettingsForm() {

        const s = state.settings || {};

        renderProviderOptions(s.provider || 'openai_compatible');

        const map = {

            'ai-provider': s.provider || 'openai_compatible',

            'ai-endpoint': s.endpoint || '',

            'ai-model': s.model || '',

            'ai-key': s.api_key || '',

            'ai-timeout': s.timeout_seconds || 30,

            'ai-max-tokens': s.max_output_tokens || 2200

        };

        Object.entries(map).forEach(([id, value]) => {

            const input = document.getElementById(id);

            if (!input) return;

            if (input.type === 'checkbox') input.checked = !!value;

            else input.value = value;

        });

        const keyInput = document.getElementById('ai-key');
        if (keyInput) keyInput.dataset.clearApiKey = 'false';

        updateProviderHint();

    }



    function selectedProviderMeta() {

        const id = document.getElementById('ai-provider')?.value || state.settings?.provider || 'openai_compatible';

        const providers = getProvidersList();

        return providers.find(p => p.id === id) || null;

    }



    function updateProviderHint() {

        const meta = selectedProviderMeta();

        const hint = document.getElementById('ai-provider-hint');

        if (!hint || !meta) return;

        const isCli = ['antigravity', 'claude_code', 'chatgpt_account', 'cli', 'opencode', 'copilot'].includes(meta.adapter);

        const keyText = meta.api_key_required ? 'API key required' : (isCli ? 'Uses local CLI / signed-in session (No API key needed)' : 'API key optional / local');

        hint.innerHTML = `<i class="fa-solid fa-circle-info"></i> <strong>${aiEsc(meta.label)}</strong> uses the <code>${aiEsc(meta.adapter || 'openai_compatible')}</code> adapter. ${aiEsc(keyText)}.`;

        const keyInput = document.getElementById('ai-key');

        if (keyInput) {

            keyInput.placeholder = meta.api_key_required ? 'Stored server-side only' : (isCli ? 'Not required (using local CLI / account session)' : 'Optional for this provider');

            keyInput.disabled = isCli;

        }

        const endpointInput = document.getElementById('ai-endpoint');

        if (endpointInput) {

            endpointInput.placeholder = isCli ? 'Not applicable (Local CLI / Session)' : 'https://api.example.com/v1/chat/completions';

            endpointInput.disabled = isCli;

        }

    }



    function applyProviderPreset() {

        const meta = selectedProviderMeta();

        if (!meta) return;

        const endpointInput = document.getElementById('ai-endpoint');

        const modelInput = document.getElementById('ai-model');

        if (endpointInput) endpointInput.value = meta.endpoint || '';

        if (modelInput) modelInput.value = meta.model || '';

        updateProviderHint();

    }



    async function saveSettings() {

        const keyInput = document.getElementById('ai-key');
        const apiKey = keyInput?.value?.trim() || '';

        const payload = {

            enabled: true,

            provider: document.getElementById('ai-provider')?.value || 'openai_compatible',

            endpoint: document.getElementById('ai-endpoint')?.value?.trim() || '',

            model: document.getElementById('ai-model')?.value?.trim() || '',

            api_key: apiKey,

            clear_api_key: keyInput?.dataset.clearApiKey === 'true' || Boolean(state.settings?.api_key_set && !apiKey),

            timeout_seconds: Number(document.getElementById('ai-timeout')?.value || 30),

            max_output_tokens: Number(document.getElementById('ai-max-tokens')?.value || 2200)

        };

        state.settings = await fetchJson(`${API_BASE}/api/ai/settings`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify(payload)

        });

        hydrateSettingsForm();

        notify('MANTIS AI settings saved');

    }



    async function testConnection() {

        const box = document.getElementById('ai-settings-status');

        if (box) box.textContent = 'Testing...';

        try {

            const keyInput = document.getElementById('ai-key');
            await fetchJson(`${API_BASE}/api/ai/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: document.getElementById('ai-provider')?.value || 'openai_compatible',
                    endpoint: document.getElementById('ai-endpoint')?.value?.trim() || '',
                    model: document.getElementById('ai-model')?.value?.trim() || '',
                    api_key: keyInput?.value?.trim() || '',
                    clear_api_key: keyInput?.dataset.clearApiKey === 'true',
                    timeout_seconds: Number(document.getElementById('ai-timeout')?.value || 30),
                    max_output_tokens: Number(document.getElementById('ai-max-tokens')?.value || 2200)
                })
            });

            if (box) box.textContent = 'Connection OK';

        } catch (e) {

            if (box) box.textContent = e.message;

        }

    }



    function injectSettings() {

        const settings = document.getElementById('settings-ai-mount') || document.getElementById('settings-view');

        if (!settings || document.getElementById('mantis-ai-settings')) return;

        const panel = el('div', { id: 'mantis-ai-settings', class: 'ai-settings-card' });

        panel.innerHTML = `

            <div class="ai-settings-head">

                <h3><i class="fa-solid fa-sparkles"></i> MANTIS AI</h3>

                <span id="ai-settings-status"></span>

            </div>

            <div class="ai-settings-grid">

                <label>Provider<select id="ai-provider"></select></label>

                <label>API Endpoint<input type="text" id="ai-endpoint" placeholder="https://api.openai.com/v1/chat/completions"></label>

                <label>Model<input type="text" id="ai-model" placeholder="gpt-4o-mini"></label>

                <label>API Key<input type="password" id="ai-key" placeholder="Stored server-side only" autocomplete="off"></label>

                <label>Timeout Seconds<input type="number" id="ai-timeout" min="5" max="120" step="1"></label>

                <label>Max Output Tokens<input type="number" id="ai-max-tokens" min="128" max="8000" step="128"></label>

            </div>

            <div id="ai-provider-hint" class="ai-provider-hint"></div>

            <div class="ai-settings-actions">

                <button type="button" id="ai-save-settings" class="btn-primary"><i class="fa-solid fa-floppy-disk"></i> Save AI Settings</button>

                <button type="button" id="ai-test-settings" class="btn-secondary"><i class="fa-solid fa-plug-circle-check"></i> Test Connection</button>

                <button type="button" id="ai-clear-key" class="btn-secondary"><i class="fa-solid fa-key"></i> Clear Stored Key</button>

            </div>

        `;

        settings.appendChild(panel);

        renderProviderOptions();

        document.getElementById('ai-provider')?.addEventListener('change', applyProviderPreset);

        document.getElementById('ai-save-settings')?.addEventListener('click', () => saveSettings().catch(e => {

            const box = document.getElementById('ai-settings-status');

            if (box) box.textContent = e.message;

        }));

        document.getElementById('ai-test-settings')?.addEventListener('click', testConnection);

        document.getElementById('ai-clear-key')?.addEventListener('click', () => {
            const keyInput = document.getElementById('ai-key');
            if (!keyInput) return;
            keyInput.value = '';
            keyInput.dataset.clearApiKey = 'true';
            const box = document.getElementById('ai-settings-status');
            if (box) box.textContent = 'Save settings to remove the stored key.';
        });

        document.getElementById('ai-key')?.addEventListener('input', event => {
            if (event.target.value.trim()) event.target.dataset.clearApiKey = 'false';
        });

        hydrateSettingsForm();

    }



    function buildPanel() {

        if (document.getElementById('mantis-ai-panel')) return;

        const backdrop = el('div', { id: 'mantis-ai-backdrop', class: 'mantis-ai-backdrop' });

        document.body.appendChild(backdrop);

        backdrop.addEventListener('click', minimizePanel);



        const panel = el('section', { id: 'mantis-ai-panel', class: 'mantis-ai-panel' });

        panel.innerHTML = `

            <div class="ai-panel-header">

                <div>

                    <h3><i class="fa-solid fa-wand-magic-sparkles"></i> MANTIS AI</h3>

                    <span id="ai-status">Disabled</span>

                </div>

                <div class="ai-panel-tools">

                    <button type="button" id="ai-minimize" title="Minimize"><i class="fa-solid fa-window-minimize"></i></button>

                    <button type="button" id="ai-close" title="Close"><i class="fa-solid fa-xmark"></i></button>

                </div>

            </div>

            <div class="ai-panel-body">

                <aside class="ai-workbench-rail dark-scroll">

                    <div class="ai-quick-actions">

                        <button type="button" id="ai-summary" class="btn-secondary"><i class="fa-solid fa-list-check"></i> Summarize Findings</button>

                        <button type="button" id="ai-pivots" class="btn-secondary"><i class="fa-solid fa-route"></i> Recommend Pivots</button>

                        <button type="button" id="ai-report" class="btn-secondary"><i class="fa-solid fa-file-lines"></i> Draft Report</button>

                    </div>

                    <div id="ai-case-panel" class="ai-case-panel"></div>

                    <div class="ai-mode-row">

                        <button type="button" class="galaxy-subtab active" data-ai-mode="assist">Assist</button>

                        <button type="button" class="galaxy-subtab" data-ai-mode="agent">Agent</button>

                    </div>

                    <div id="ai-agent-controls" class="ai-agent-controls" style="display:none;">

                        <div class="ai-agent-limits">

                            <label>Max Lookups<input id="ai-agent-max-lookups" type="number" min="1" max="50" value="20"></label>

                            <label>Max Depth<input id="ai-agent-max-depth" type="number" min="1" max="8" value="5"></label>

                            <label>Pivots / Step<input id="ai-agent-max-pivots" type="number" min="1" max="5" value="3"></label>

                            <label>Runtime Sec<input id="ai-agent-max-runtime" type="number" min="30" max="1800" value="600"></label>

                        </div>

                        <div class="ai-agent-buttons">

                            <button type="button" id="ai-agent-start" class="btn-primary"><i class="fa-solid fa-play"></i> Start Agent Investigation</button>

                            <button type="button" id="ai-agent-stop" class="btn-secondary" disabled><i class="fa-solid fa-stop"></i> Stop</button>

                        </div>

                        <div id="ai-agent-run-status" class="ai-agent-status">idle</div>

                        <div id="ai-agent-trace" class="ai-agent-trace dark-scroll"></div>

                    </div>

                    <details id="ai-correlation-controls" class="ai-correlation-controls ai-toolbox">

                        <summary><i class="fa-solid fa-code-compare"></i> Correlation</summary>

                        <div class="ai-toolbox-body">

                            <textarea id="ai-correlation-input" rows="3" placeholder="Paste another result, hash, domain, or campaign note..."></textarea>

                            <button type="button" id="ai-correlation-run" class="btn-secondary"><i class="fa-solid fa-code-compare"></i> Compare Relationship</button>

                            <div id="ai-correlation-result"></div>

                        </div>

                    </details>

                    <details id="ai-attribution-controls" class="ai-correlation-controls ai-toolbox">

                        <summary><i class="fa-solid fa-scale-balanced"></i> Attribution</summary>

                        <div class="ai-toolbox-body">

                            <textarea id="ai-attribution-candidates" rows="2" placeholder="Optional actor or cluster names, separated by comma or newline..."></textarea>

                            <button type="button" id="ai-attribution-run" class="btn-secondary"><i class="fa-solid fa-scale-balanced"></i> Assess Evidence</button>

                            <div id="ai-attribution-result"></div>

                        </div>

                    </details>

                </aside>

                <section class="ai-workbench-main">

                    <div id="ai-chat-messages" class="ai-chat-messages dark-scroll"></div>

                    <div id="ai-context-notice" class="ai-context-notice" style="display:none;"></div>

                    <div class="ai-input-row">

                        <textarea id="ai-input" rows="2" placeholder="Ask about the current findings..."></textarea>

                        <button type="button" id="ai-send" class="btn-primary"><i class="fa-solid fa-paper-plane"></i></button>

                    </div>

                </section>

            </div>

        `;

        document.body.appendChild(panel);

        document.getElementById('ai-minimize')?.addEventListener('click', minimizePanel);

        document.getElementById('ai-close')?.addEventListener('click', closePanel);

        document.getElementById('ai-summary')?.addEventListener('click', () => askAI('summarize', 'Summarize the current MANTIS findings. Keep facts, inferences, and suggested gaps separate.'));

        document.getElementById('ai-pivots')?.addEventListener('click', () => askAI('recommend_pivots', 'Recommend the best next pivots from the current MANTIS evidence. Give reasons and propose manual MANTIS actions only.'));

        document.getElementById('ai-report')?.addEventListener('click', () => askAI('draft_report', 'Draft an analyst-ready intelligence report from the current MANTIS evidence. Keep claims, proof, caveats, and next steps separate.'));

        renderCasePanel();

        document.querySelectorAll('[data-ai-mode]').forEach(btn => btn.addEventListener('click', () => setMode(btn.dataset.aiMode)));

        document.getElementById('ai-agent-start')?.addEventListener('click', () => startAgent());

        document.getElementById('ai-agent-stop')?.addEventListener('click', stopAgent);

        document.getElementById('ai-send')?.addEventListener('click', () => {

            const input = document.getElementById('ai-input');

            const text = input?.value || '';

            if (input) input.value = '';

            if (state.mode === 'agent') {

                startAgent(text);

            } else {

                askAI('chat', text);

            }

        });

        document.getElementById('ai-input')?.addEventListener('keydown', e => {

            if (e.key === 'Enter' && !e.shiftKey) {

                e.preventDefault();

                document.getElementById('ai-send')?.click();

            }

        });

        document.addEventListener('click', e => {

            const btn = e.target.closest('.ai-run-action');

            if (btn) runAction(btn.dataset.actionId, btn);

            const correlationBtn = e.target.closest('#ai-correlation-run');

            if (correlationBtn) {

                e.preventDefault();

                compareCorrelation();

            }

            const attributionBtn = e.target.closest('#ai-attribution-run');

            if (attributionBtn) {

                e.preventDefault();

                assessAttribution();

            }

            const markBtn = e.target.closest('.ai-evidence-mark');

            if (markBtn) markEvidence(markBtn.dataset.evidenceId, markBtn.dataset.mark, markBtn.dataset.evidenceScope || 'correlation');

            const caseSync = e.target.closest('#ai-case-sync');

            if (caseSync) {

                e.preventDefault();

                syncCase('Analyst synced current evidence.').catch(err => renderMessage('assistant', `Case sync failed: ${err.message}`));

            }

            const caseStep = e.target.closest('#ai-case-step');

            if (caseStep) {

                e.preventDefault();

                planCaseStep().catch(err => renderMessage('assistant', `Case step failed: ${err.message}`));

            }

            const caseRunNext = e.target.closest('#ai-case-run-next');

            if (caseRunNext) {

                e.preventDefault();

                caseRunNext.disabled = true;

                runCaseNextSource()

                    .catch(err => renderMessage('assistant', `Case source execution failed: ${err.message}`))

                    .finally(() => { caseRunNext.disabled = false; });

            }

            const caseAssess = e.target.closest('#ai-case-assess');

            if (caseAssess) {

                e.preventDefault();

                caseAssess.disabled = true;

                generateCaseAssessment()

                    .catch(err => renderMessage('assistant', `Case assessment failed: ${err.message}`))

                    .finally(() => { caseAssess.disabled = false; });

            }

            const caseReport = e.target.closest('#ai-case-report');

            if (caseReport) {

                e.preventDefault();

                draftCaseReport().catch(err => renderMessage('assistant', `Case report failed: ${err.message}`));

            }

            const caseExport = e.target.closest('#ai-case-export');

            if (caseExport) {

                e.preventDefault();

                if (state.caseId) {

                    window.open(`${API_BASE}/api/ai/case/${encodeURIComponent(state.caseId)}/export`, '_blank');

                }

            }

            const caseWorkspaceExport = e.target.closest('#ai-case-export-workspace');

            if (caseWorkspaceExport) {

                if (!state.caseId) toast('Sync a case first.', 'error');

                else {

                    window.open(`${API_BASE}/api/ai/case/${encodeURIComponent(state.caseId)}/export-workspace`, '_blank');

                    toast('MANTIS AI workspace export started.', 'success');

                }

            }

            const caseExportJson = e.target.closest('#ai-case-export-json');

            if (caseExportJson) {

                e.preventDefault();

                if (state.caseId) {

                    window.open(`${API_BASE}/api/ai/case/${encodeURIComponent(state.caseId)}/export-json`, '_blank');

                }

            }

            const caseRelated = e.target.closest('#ai-case-load-related');

            if (caseRelated) {

                e.preventDefault();

                loadRelatedCases().catch(err => renderMessage('assistant', `Failed to load related cases: ${err.message}`));

            }

        });

        renderMessage('assistant', 'Open a MANTIS result and ask about the current findings. I will propose actions, but you approve every MANTIS search.');

    }



    function syncPanelState() {

        document.body.classList.toggle('ai-panel-open', state.open && !state.minimized);

        document.body.classList.toggle('ai-panel-minimized', state.open && state.minimized);

    }



    function closePanel() {

        state.open = false;

        state.minimized = false;

        syncPanelState();

    }



    function minimizePanel() {

        if (!state.open) return;

        state.minimized = true;

        syncPanelState();

    }



    function togglePanel() {

        if (state.open && !state.minimized) {

            closePanel();

        } else {

            openPanel();

        }

    }



    function openPanel() {

        state.open = true;

        state.minimized = false;

        syncPanelState();

        updateContextNotice();

        loadSettings();

    }



    function showReportViewerModal(caseId, htmlContent, filename, indicator) {

        let viewer = document.getElementById('report-viewer-modal');

        if (!viewer) {

            viewer = el('div', { id: 'report-viewer-modal', class: 'report-viewer-overlay' });

            document.body.appendChild(viewer);

        }

        viewer.style.display = 'flex';

        viewer.innerHTML = `

            <div class="report-viewer-header">

                <div class="report-viewer-title">

                    <i class="fa-solid fa-file-shield" style="color:var(--accent); font-size:18px;"></i>

                    <span>MANTIS AEAD Threat Intelligence Report — <span style="font-family:var(--font-mono);">${escapeHtml(indicator)}</span></span>

                </div>

                <div class="report-viewer-actions">

                    <button type="button" class="btn btn-secondary" id="report-modal-open-tab"><i class="fa-solid fa-up-right-from-square"></i> Open in New Tab</button>

                    <a class="btn btn-secondary" id="report-modal-download" href="#" download="${escapeHtml(filename || 'mantis_report.html')}"><i class="fa-solid fa-download"></i> Download HTML</a>

                    <button type="button" class="btn btn-secondary" id="report-modal-close"><i class="fa-solid fa-xmark"></i> Close</button>

                </div>

            </div>

            <iframe class="report-viewer-frame" id="report-viewer-iframe" sandbox="allow-same-origin allow-scripts allow-modals allow-downloads"></iframe>

        `;



        const iframe = document.getElementById('report-viewer-iframe');

        if (iframe) {

            iframe.srcdoc = htmlContent;

        }



        const blob = new Blob([htmlContent], { type: 'text/html' });

        const blobUrl = URL.createObjectURL(blob);

        const dlBtn = document.getElementById('report-modal-download');

        if (dlBtn) dlBtn.href = blobUrl;



        document.getElementById('report-modal-open-tab')?.addEventListener('click', () => {

            window.open(`${API_BASE}/api/ai/case/${encodeURIComponent(caseId)}/report-html`, '_blank');

        });



        document.getElementById('report-modal-close')?.addEventListener('click', () => {

            viewer.style.display = 'none';

            URL.revokeObjectURL(blobUrl);

        });

    }



    async function runAeadWorkflow(explicitTarget = null, explicitType = null) {
        let val = (typeof explicitTarget === 'string' ? explicitTarget : '').trim();
        if (!val) {
            const input = document.getElementById('ioc-input');
            val = (input?.value || '').trim();
        } else {
            const input = document.getElementById('ioc-input');
            if (input) input.value = val;
        }
        if (!val) {

            if (typeof showNotification === 'function') {

                showNotification('Please enter an indicator in the search box.');

            } else {

                alert('Please enter an indicator in the search box.');

            }

            input?.focus();

            return;

        }



        const searchBtn = document.getElementById('btn-search');

        const aiSearchBtn = document.getElementById('btn-ai-search');

        if (searchBtn) searchBtn.disabled = true;

        if (aiSearchBtn) aiSearchBtn.disabled = true;



        let overlay = document.getElementById('aead-overlay');

        if (!overlay) {

            overlay = el('div', { id: 'aead-overlay', class: 'aead-overlay' });

            document.body.appendChild(overlay);

        }

        overlay.style.display = 'flex';

        overlay.innerHTML = `

            <div class="aead-modal">

                <div class="aead-modal-header">

                    <div class="aead-modal-header-left">

                        <i class="fa-solid fa-wand-magic-sparkles brand-icon"></i>

                        <div>

                            <h3>MANTIS AEAD Autonomous Investigation</h3>

                            <p>Target: <span style="color:#fff; font-family:var(--font-mono);">${escapeHtml(val)}</span></p>

                        </div>

                    </div>

                    <div class="aead-modal-header-right" style="display:flex; align-items:center; gap:8px;">

                        <button type="button" id="aead-btn-stop" class="btn-aead-stop" title="Halt investigation early">

                            <i class="fa-solid fa-hand"></i> Stop

                        </button>

                        <button type="button" id="aead-btn-minimize" class="btn-aead-icon-btn" title="Minimize investigation to floating widget">

                            <i class="fa-solid fa-window-minimize" style="margin-top:-6px;"></i>

                        </button>

                    </div>

                </div>

                <div class="aead-modal-body">

                    <div class="aead-step-list">

                        <div id="aead-step-acquire" class="aead-step-item active">

                            <div class="aead-step-icon"><i class="fa-solid fa-cloud-arrow-down"></i></div>

                            <div class="aead-step-content">

                                <strong>1. Acquire</strong>

                                <span id="aead-desc-acquire">Streaming OSINT sources to provider cards...</span>

                            </div>

                        </div>

                        <div id="aead-step-enrich" class="aead-step-item">

                            <div class="aead-step-icon"><i class="fa-solid fa-filter"></i></div>

                            <div class="aead-step-content">

                                <strong>2. Enrich</strong>

                                <span id="aead-desc-enrich">Normalizing telemetry & tagging benign/shared noise...</span>

                            </div>

                        </div>

                        <div id="aead-step-discover" class="aead-step-item">

                            <div class="aead-step-icon"><i class="fa-solid fa-compass"></i></div>

                            <div class="aead-step-content">

                                <strong>3. Discover &amp; Pivot</strong>

                                <span id="aead-desc-discover">Autonomous bounded investigation across passive providers...</span>

                            </div>

                        </div>

                        <div id="aead-step-analyze" class="aead-step-item">

                            <div class="aead-step-icon"><i class="fa-solid fa-brain"></i></div>

                            <div class="aead-step-content">

                                <strong>4. Analyze</strong>

                                <span id="aead-desc-analyze">Correlating evidence & formulating calibrated hypotheses...</span>

                            </div>

                        </div>

                        <div id="aead-step-deliver" class="aead-step-item">

                            <div class="aead-step-icon"><i class="fa-solid fa-file-shield"></i></div>

                            <div class="aead-step-content">

                                <strong>5. Deliver</strong>

                                <span id="aead-desc-deliver">Compiling evidence-backed threat intelligence report...</span>

                            </div>

                        </div>

                    </div>

                    <div id="aead-live-preview-box" class="aead-preview-container" style="display:none;"></div>

                    <div id="aead-live-log-box" style="padding:10px 14px; background:rgba(0,0,0,0.35); border:1px solid rgba(255,255,255,0.06); border-radius:6px; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:11px; max-height:120px; overflow-y:auto; color:var(--cyan); line-height:1.5;">

                        <i class="fa-solid fa-circle-notch mantis-spin" style="margin-right:6px;"></i> Initiating multi-source telemetry acquisition...

                    </div>

                    <div id="aead-actions-box" style="display:none;"></div>

                </div>

            </div>

        `;



        let isMinimized = false;

        let isStopped = false;

        const abortController = new AbortController();

        let autoOpenTimer = null;

        let completedResult = null;



        let pipWidget = document.getElementById('aead-floating-widget');

        if (!pipWidget) {

            pipWidget = el('div', { id: 'aead-floating-widget', class: 'aead-floating-widget', style: 'display:none;' });

            document.body.appendChild(pipWidget);

        }



        function updatePipState(stageText, isReady = false) {

            if (!pipWidget) return;

            pipWidget.innerHTML = `

                <div class="aead-floating-widget-icon">

                    <i class="fa-solid ${isReady ? 'fa-check' : 'fa-wand-magic-sparkles mantis-pulse'}" style="color:${isReady ? 'var(--success)' : 'var(--accent)'};"></i>

                </div>

                <div class="aead-floating-widget-content">

                    <div class="aead-floating-widget-title">

                        <span>MANTIS AEAD</span>

                        <span class="aead-pip-badge ${isReady ? 'stage-ready' : ''}">${escapeHtml(stageText)}</span>

                    </div>

                    <div class="aead-floating-widget-desc" title="${escapeHtml(val)}">Target: ${escapeHtml(val)}</div>

                </div>

                <div class="aead-pip-actions">

                    ${isReady ? `<button type="button" id="aead-pip-view" class="btn btn-primary" style="padding:4px 10px; font-size:11px; border-radius:12px; gap:4px;"><i class="fa-solid fa-file-shield"></i> View</button>` : ''}

                    <button type="button" id="aead-pip-restore" class="btn-aead-pip-btn" title="Expand investigation modal">

                        <i class="fa-solid fa-up-right-and-down-left-from-center"></i>

                    </button>

                    <button type="button" id="aead-pip-close" class="btn-aead-pip-btn" title="Dismiss">

                        <i class="fa-solid fa-xmark"></i>

                    </button>

                </div>

            `;



            document.getElementById('aead-pip-restore')?.addEventListener('click', (e) => {

                e.stopPropagation();

                restoreModal();

            });



            document.getElementById('aead-pip-view')?.addEventListener('click', (e) => {

                e.stopPropagation();

                if (completedResult) {

                    pipWidget.style.display = 'none';

                    showReportViewerModal(completedResult.case_id, completedResult.html, completedResult.filename, val);

                } else {

                    restoreModal();

                }

            });



            document.getElementById('aead-pip-close')?.addEventListener('click', (e) => {

                e.stopPropagation();

                pipWidget.style.display = 'none';

                if (!completedResult && !isStopped) {

                    isStopped = true;

                    abortController.abort();

                }

            });



            pipWidget.onclick = () => {

                if (completedResult) {

                    pipWidget.style.display = 'none';

                    showReportViewerModal(completedResult.case_id, completedResult.html, completedResult.filename, val);

                } else {

                    restoreModal();

                }

            };

        }



        function minimizeModal() {

            isMinimized = true;

            overlay.style.display = 'none';

            pipWidget.style.display = 'flex';

        }



        function restoreModal() {

            isMinimized = false;

            pipWidget.style.display = 'none';

            overlay.style.display = 'flex';

        }



        const minimizeBtn = document.getElementById('aead-btn-minimize');

        if (minimizeBtn) {

            minimizeBtn.addEventListener('click', minimizeModal);

        }



        const stopBtn = document.getElementById('aead-btn-stop');

        if (stopBtn) {

            stopBtn.addEventListener('click', () => {

                if (pipWidget) pipWidget.style.display = 'none';

                if (isStopped) {

                    if (autoOpenTimer) clearTimeout(autoOpenTimer);

                    overlay.style.display = 'none';

                    return;

                }

                isStopped = true;

                if (autoOpenTimer) clearTimeout(autoOpenTimer);

                abortController.abort();

                stopBtn.innerHTML = '<i class="fa-solid fa-xmark"></i> Dismiss';

                stopBtn.classList.add('dismiss');

                const logBox = document.getElementById('aead-live-log-box');

                if (logBox) {

                    logBox.innerHTML += '<div style="color:var(--amber); margin-top:6px; font-weight:600;"><i class="fa-solid fa-triangle-exclamation"></i> Investigation halted by analyst.</div>';

                    logBox.scrollTop = logBox.scrollHeight;

                }

                const activeStep = overlay.querySelector('.aead-step-item.active');

                if (activeStep) {

                    activeStep.classList.remove('active');

                    activeStep.classList.add('stopped');

                }

                if (searchBtn) searchBtn.disabled = false;

                if (aiSearchBtn) aiSearchBtn.disabled = false;

            });

        }



        try {

            // --- 1. ACQUIRE ---

            updatePipState('1. Acquiring...');

            if (typeof window.performSearch === 'function') {

                await window.performSearch();

            }



            if (isStopped) return;



            const acquireDesc = document.getElementById('aead-desc-acquire');

            if (acquireDesc) acquireDesc.textContent = 'Multi-source telemetry ingested & streamed to cards.';

            document.getElementById('aead-step-acquire')?.classList.remove('active');

            document.getElementById('aead-step-acquire')?.classList.add('done');

            document.getElementById('aead-step-enrich')?.classList.add('active');



            const logBox = document.getElementById('aead-live-log-box');

            if (logBox) {

                logBox.innerHTML = '<div>• [Acquire] Streaming completed. Normalizing telemetry and tagging noise...</div><div><i class="fa-solid fa-circle-notch mantis-spin"></i> [Enrich &amp; Discover] Running bounded autonomous investigation...</div>';

            }



            // --- 2. ENRICH, 3. DISCOVER & PIVOT, 4. ANALYZE, 5. DELIVER ---

            updatePipState('2. Enriching & Pivoting...');
            let activeTab = explicitType || window.currentTab || 'hash';
            if (!explicitType) {
                if (/^[a-fA-F0-9]{32,64}$/.test(val)) {
                    activeTab = 'hash';
                } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) {
                    activeTab = 'ip';
                } else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) {
                    activeTab = 'domain';
                }
            }
            const payload = {
                indicator: val,
                indicator_type: activeTab,

                page_context: compactDomContext(),

                keys: caseProviderKeys(),

                github_repos: githubReposForCase(),

                max_enrich_steps: 3

            };



            const res = await fetchJson(`${API_BASE}/api/ai/case/aead-run`, {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify(payload),

                signal: abortController.signal,

                timeoutMs: aiRequestTimeoutMs(120)

            });



            if (isStopped) return;



            // Step 2. Enrich Done

            const obs = res.case?.observations || [];

            const claims = res.case?.claims || [];

            const noise = obs.filter(o => o.pivot_value === false).length;

            const enrichDesc = document.getElementById('aead-desc-enrich');

            if (enrichDesc) {

                enrichDesc.textContent = `Normalized ${obs.length} observation(s), ${claims.length} claim(s); flagged ${noise} benign/shared noise item(s).`;

            }

            document.getElementById('aead-step-enrich')?.classList.remove('active');

            document.getElementById('aead-step-enrich')?.classList.add('done');



            // Step 3. Discover & Pivot Done

            const pivots = res.pivots_executed || [];

            const discoverDesc = document.getElementById('aead-desc-discover');

            if (discoverDesc) {

                discoverDesc.textContent = pivots.length > 0

                    ? `Executed ${pivots.length} passive pivot(s) within depth/budget bounds.`

                    : 'Evaluated candidate pivots; reached bounded convergence.';

            }

            document.getElementById('aead-step-discover')?.classList.remove('active');

            document.getElementById('aead-step-discover')?.classList.add('done');



            // Step 4. Analyze Done

            const aiAssess = (res.case?.ai_assessment || [{}])[0];

            const hyps = res.hypotheses || [];

            const analyzeDesc = document.getElementById('aead-desc-analyze');

            if (analyzeDesc) {

                analyzeDesc.textContent = `${aiAssess.verdict_label || 'Evaluated'} (${aiAssess.confidence_score || 85}/100) — ${hyps.length} calibrated hypothesis/hypotheses.`;

            }

            document.getElementById('aead-step-analyze')?.classList.remove('active');

            document.getElementById('aead-step-analyze')?.classList.add('done');



            // Step 5. Deliver Done

            const deliverDesc = document.getElementById('aead-desc-deliver');

            if (deliverDesc) {

                deliverDesc.textContent = `Threat intelligence report ready (${res.filename}).`;

            }

            document.getElementById('aead-step-deliver')?.classList.remove('active');

            document.getElementById('aead-step-deliver')?.classList.add('done');



            // Live Preview of Hypotheses & Pivots

            let previewHtml = '';

            if (hyps.length > 0) {

                previewHtml += `

                    <div class="aead-preview-section">

                        <div class="aead-preview-section-title"><i class="fa-solid fa-shield-virus" style="color:var(--accent);"></i> Formulated Threat Hypotheses (${hyps.length})</div>

                        <div class="aead-hypotheses-list">

                `;

                hyps.forEach(h => {

                    const strength = String(h.evidence_strength || 'INSUFFICIENT EVIDENCE').toUpperCase();

                    let badgeCls = 'aead-badge-insufficient';

                    let cardCls = 'strength-insufficient-evidence';

                    if (strength === 'HIGH') { badgeCls = 'aead-badge-high'; cardCls = 'strength-high'; }

                    else if (strength === 'MODERATE') { badgeCls = 'aead-badge-moderate'; cardCls = 'strength-moderate'; }

                    else if (strength === 'LOW') { badgeCls = 'aead-badge-low'; cardCls = 'strength-low'; }



                    const evChips = (h.supporting_evidence_ids || []).map(id => `<span class="aead-evidence-chip">${escapeHtml(id)}</span>`).join(' ');



                    previewHtml += `

                        <div class="aead-hypothesis-card ${cardCls}">

                            <div class="aead-hyp-header">

                                <span class="aead-hyp-name">${escapeHtml(h.name || 'Hypothesis')}</span>

                                <div>

                                    <span class="aead-badge aead-badge-type">${escapeHtml(h.type || 'CLUSTER')}</span>

                                    <span class="aead-badge ${badgeCls}">${escapeHtml(strength)}</span>

                                </div>

                            </div>

                            ${h.summary ? `<div class="aead-hyp-summary">${escapeHtml(h.summary)}</div>` : ''}

                            ${evChips ? `<div class="aead-evidence-chips">${evChips}</div>` : ''}

                        </div>

                    `;

                });

                previewHtml += `</div></div>`;

            }



            if (pivots.length > 0) {

                previewHtml += `

                    <div class="aead-preview-section">

                        <div class="aead-preview-section-title"><i class="fa-solid fa-route" style="color:var(--cyan);"></i> Autonomous Pivots Executed (${pivots.length})</div>

                        <div class="aead-pivots-list">

                `;

                pivots.forEach(p => {

                    previewHtml += `

                        <div class="aead-pivot-item">

                            <div class="aead-pivot-left">

                                <span class="aead-pivot-depth">Depth ${escapeHtml(p.depth || 1)}</span>

                                <span class="aead-pivot-type">${escapeHtml(p.pivot_type || 'pivot')}</span>

                                <span class="aead-pivot-val" title="${escapeHtml(p.value)}">${escapeHtml(p.value)}</span>

                            </div>

                            <span class="aead-pivot-provider">via ${escapeHtml(p.provider || 'OSINT')}</span>

                        </div>

                    `;

                });

                previewHtml += `</div></div>`;

            }



            const previewBox = document.getElementById('aead-live-preview-box');

            if (previewBox && previewHtml) {

                previewBox.innerHTML = previewHtml;

                previewBox.style.display = 'flex';

            }



            // Update log box

            if (logBox && res.logs && res.logs.length) {

                logBox.innerHTML = res.logs.map(l => `<div>• ${escapeHtml(l)}</div>`).join('');

                logBox.scrollTop = logBox.scrollHeight;

            }



            state.caseId = res.case_id || state.caseId;

            state.caseState = res.case || state.caseState;



            // Update action area and stop button

            if (stopBtn) {

                stopBtn.innerHTML = '<i class="fa-solid fa-xmark"></i> Close';

                stopBtn.classList.add('dismiss');

            }



            const actionsBox = document.getElementById('aead-actions-box');

            if (actionsBox) {

                actionsBox.style.display = 'block';

                actionsBox.innerHTML = `

                    <button type="button" id="aead-btn-view-report" class="btn btn-primary" style="width:100%; padding:10px; font-weight:700; display:flex; align-items:center; justify-content:center; gap:8px;">

                        <i class="fa-solid fa-file-shield"></i> Open Threat Intelligence Report

                    </button>

                    <div id="aead-auto-open-notice" style="text-align:center; font-size:10.5px; color:var(--text-muted); margin-top:6px;">Auto-opening report in 2 seconds...</div>

                `;

            }



            completedResult = res;

            updatePipState('Report Ready!', true);



            const openReport = () => {

                if (autoOpenTimer) clearTimeout(autoOpenTimer);

                if (pipWidget) pipWidget.style.display = 'none';

                overlay.style.display = 'none';

                showReportViewerModal(res.case_id, res.html, res.filename, val);

            };



            document.getElementById('aead-btn-view-report')?.addEventListener('click', openReport);

            if (isMinimized) {

                if (typeof showNotification === 'function') {

                    showNotification('✨ Mantis AEAD Investigation complete! Click the widget to view the forensic report.');

                }

            } else {

                autoOpenTimer = setTimeout(openReport, 2200);

            }



        } catch (err) {

            if (isStopped || err?.name === 'AbortError') {

                const logBox = document.getElementById('aead-live-log-box');

                if (logBox) {

                    logBox.innerHTML += '<div style="color:var(--amber); margin-top:6px; font-weight:600;"><i class="fa-solid fa-triangle-exclamation"></i> Investigation halted by analyst.</div>';

                    logBox.scrollTop = logBox.scrollHeight;

                }

                const activeStep = overlay?.querySelector('.aead-step-item.active');

                if (activeStep) {

                    activeStep.classList.remove('active');

                    activeStep.classList.add('stopped');

                }

                if (stopBtn) {

                    stopBtn.innerHTML = '<i class="fa-solid fa-xmark"></i> Dismiss';

                    stopBtn.classList.add('dismiss');

                }

            } else {

                if (overlay) overlay.style.display = 'none';

                if (typeof showNotification === 'function') {

                    showNotification(`AEAD Investigation failed: ${err.message}`);

                } else {

                    alert(`AEAD Investigation failed: ${err.message}`);

                }

            }

        } finally {

            if (searchBtn) searchBtn.disabled = false;

            if (aiSearchBtn) aiSearchBtn.disabled = false;

        }

    }



    window.mantisAI = {

        openPanel,

        runAeadWorkflow,

        showReportViewerModal,

        summarize: () => {

            openPanel();

            return askAI('summarize', 'Summarize the current MANTIS findings. Keep facts, inferences, and suggested gaps separate.');

        },

        recommendPivots: () => {

            openPanel();

            return askAI('recommend_pivots', 'Recommend the best next pivots from the current MANTIS evidence. Give reasons and propose manual MANTIS actions only.');

        },

        draftReport: () => {

            openPanel();

            return askAI('draft_report', 'Draft an analyst-ready intelligence report from the current MANTIS evidence. Keep claims, proof, caveats, and next steps separate.');

        },

        startAgent: (goalText = '') => {

            openPanel();

            setMode('agent');

            return startAgent(goalText);

        },

        focusAssist: () => {

            openPanel();

            setMode('assist');

            setTimeout(() => document.getElementById('ai-input')?.focus(), 80);

        },

        focusCompare: () => {

            openPanel();

            const controls = document.getElementById('ai-correlation-controls');

            if (controls && 'open' in controls) controls.open = true;

            setTimeout(() => document.getElementById('ai-correlation-input')?.focus(), 80);

        },

        focusAttribution: () => {

            openPanel();

            const controls = document.getElementById('ai-attribution-controls');

            if (controls && 'open' in controls) controls.open = true;

            setTimeout(() => document.getElementById('ai-attribution-candidates')?.focus(), 80);

        },

        syncCase,

        planCaseStep,

        runCaseNextSource,

        draftCaseReport,

        reloadSettings: loadSettings,

        ask: (text = '') => {

            openPanel();

            return askAI('chat', text || 'Analyze the current MANTIS findings.');

        }

    };



    document.addEventListener('DOMContentLoaded', () => {

        buildPanel();

        injectSettings();

        loadSettings();

    });

})();

