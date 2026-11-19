/**
 * Country & Industry Reports: CTI articles tagged by the configured AI provider.
 * If AI is not configured or the last call failed, the section is disabled and
 * shows the reason instead of the reports.
 */
(function () {
    const state = {
        view: 'country', days: 30, data: null, detail: null, brief: null,
        status: null, loading: false, tagging: false, error: '', progress: '',
    };

    function pane() { return document.getElementById('intel-reports-pane'); }

    async function post(url, body) {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body || {}),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
        return data;
    }

    async function getStatus(recheck) {
        const res = await fetch('/api/intel-reports/status' + (recheck ? '?recheck=1' : ''));
        return res.json().catch(() => ({ available: false, reason: 'Status unavailable.' }));
    }

    function esc(v) { return escapeHtml(String(v == null ? '' : v)); }

    function chips(rows) {
        if (!rows || !rows.length) return '';
        return rows.map(r => `<span class="ir-chip">${esc(r.name)} <b>${r.articles}</b></span>`).join('');
    }

    function disabledView(status) {
        return `<div class="ir-disabled">
            <i class="fa-solid fa-plug-circle-xmark"></i>
            <div>
                <b>Country &amp; Industry Reports are disabled</b>
                <p>${esc(status.reason || 'AI is not available.')}</p>
                <p class="ir-muted">Configure the AI provider in AI settings (DeepSeek: endpoint, model and API key), then reopen this tab.</p>
                <button type="button" class="ir-btn" data-ir-recheck="1">Check again</button>
            </div></div>`;
    }

    function tagBar() {
        const s = state.status || {};
        const pending = s.untagged || 0;
        const busy = state.tagging ? 'disabled' : '';
        return `<div class="ir-tagbar">
            <span class="ir-muted">${pending} CTI articles in the last 30 days not yet tagged${state.progress ? ` · ${esc(state.progress)}` : ''}</span>
            <button type="button" class="ir-btn" data-ir-tag="1" ${busy || (pending ? '' : 'disabled')}>
                <i class="fa-solid fa-tags"></i> ${state.tagging ? 'Tagging…' : 'Tag articles with AI'}</button>
        </div>`;
    }

    function render() {
        const el = pane();
        if (!el) return;
        if (state.status && !state.status.available) {
            el.innerHTML = `<div class="ir-wrap"><div class="ir-header"><div>
                <h2 class="ir-title">Country &amp; Industry Reports</h2></div></div>${disabledView(state.status)}</div>`;
            return;
        }
        const periods = [30, 90, 365].map(d =>
            `<option value="${d}" ${state.days === d ? 'selected' : ''}>${d === 365 ? 'Last 12 months' : `Last ${d} days`}</option>`).join('');
        let body = '';
        if (state.loading) body = '<div class="ir-empty">Loading…</div>';
        else if (state.error) body = `<div class="ir-error">${esc(state.error)}</div>`;
        else if (state.detail) body = renderDetail(state.detail);
        else if (state.data) body = state.view === 'country' ? renderCountries(state.data) : renderIndustries(state.data);
        el.innerHTML = `
            <div class="ir-wrap">
                <div class="ir-header">
                    <div>
                        <h2 class="ir-title">${state.view === 'country' ? 'Country Reports' : 'Industry Reports'}</h2>
                        <p class="ir-sub">CTI articles tagged by AI by ${state.view === 'country' ? 'country' : 'industry'}.</p>
                    </div>
                    <div class="ir-controls">
                        <div class="ir-seg">
                            <button type="button" data-ir-view="country" class="${state.view === 'country' ? 'active' : ''}">Countries</button>
                            <button type="button" data-ir-view="industry" class="${state.view === 'industry' ? 'active' : ''}">Industries</button>
                        </div>
                        <select id="ir-period" class="ir-select">${periods}</select>
                    </div>
                </div>
                ${tagBar()}
                ${state.detail ? '<button type="button" class="ir-back" data-ir-back="1"><i class="fa-solid fa-arrow-left"></i> Back</button>' : ''}
                ${body}
            </div>`;
    }

    function renderCountries(data) {
        if (!data.countries.length) return `<div class="ir-empty">No tagged articles in this period. ${data.articles_tagged ? '' : 'Run "Tag articles with AI" first.'}</div>`;
        const rows = data.countries.map((c, i) => `
            <tr data-ir-country="${esc(c.code)}">
                <td class="ir-num">${i + 1}</td>
                <td><b>${esc(c.name)}</b> <span class="ir-muted">${esc(c.code)}</span></td>
                <td class="ir-num">${c.articles}</td>
            </tr>`).join('');
        return `<p class="ir-meta">${data.articles_tagged} of ${data.articles_in_window} articles tagged in period</p>
            <div class="ir-table-wrap"><table class="ir-table">
                <thead><tr><th>#</th><th>Country</th><th class="ir-num">Articles</th></tr></thead>
                <tbody>${rows}</tbody></table></div>`;
    }

    function renderIndustries(data) {
        if (!data.industries.length) return `<div class="ir-empty">No tagged articles in this period. ${data.articles_tagged ? '' : 'Run "Tag articles with AI" first.'}</div>`;
        const rows = data.industries.map((s, i) => `
            <tr data-ir-industry="${esc(s.name)}">
                <td class="ir-num">${i + 1}</td>
                <td><b>${esc(s.name)}</b></td>
                <td class="ir-num">${s.articles}</td>
            </tr>`).join('');
        return `<p class="ir-meta">${data.articles_tagged} of ${data.articles_in_window} articles tagged in period</p>
            <div class="ir-table-wrap"><table class="ir-table">
                <thead><tr><th>#</th><th>Industry</th><th class="ir-num">Articles</th></tr></thead>
                <tbody>${rows}</tbody></table></div>`;
    }

    function renderDetail(d) {
        const articles = (d.articles || []).map(a => `
            <li><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.title)}</a>
                <span class="ir-muted">${esc(a.source_id || '')} · ${esc((a.published_at || '').slice(0, 10))}</span></li>`).join('');
        const brief = state.brief
            ? `<div class="ir-brief">${esc(state.brief).replace(/\n/g, '<br>')}</div>`
            : '';
        return `
            <h3 class="ir-detail-title">${esc(d.name)}</h3>
            <div class="ir-stats"><div><b>${d.articles.length}</b><span>Articles</span></div></div>
            <div class="ir-detail-grid">
                <section><h4>Also tagged</h4><div>${chips(d.related) || '<span class="ir-muted">None</span>'}</div></section>
                <section><h4>AI brief</h4>
                    <button type="button" class="ir-btn" data-ir-brief="1" data-kind="${d.code ? 'country' : 'industry'}" data-value="${esc(d.value)}">Generate brief</button>
                    ${brief}</section>
            </div>
            <h4>CTI articles</h4>
            ${articles ? `<ul class="ir-articles">${articles}</ul>` : '<div class="ir-muted">No tagged articles in this period.</div>'}`;
    }

    async function load() {
        state.loading = true; state.error = ''; state.detail = null; state.brief = null; render();
        try {
            const url = state.view === 'country' ? '/api/intel-reports/countries' : '/api/intel-reports/industries';
            state.data = await post(url, { days: state.days });
        } catch (e) {
            state.data = null; state.error = e.message;
        } finally {
            state.loading = false; render();
        }
    }

    async function refreshStatus(recheck) {
        state.status = await getStatus(recheck);
        render();
        return state.status;
    }

    // Tag in batches until nothing is left or a call fails. Each batch is one AI request.
    async function tagAll() {
        if (state.tagging) return;
        state.tagging = true; state.error = ''; state.progress = 'starting…'; render();
        let total = 0;
        try {
            for (let i = 0; i < 200; i++) {
                const r = await post('/api/intel-reports/tag', { days: state.days });
                total += r.tagged || 0;
                state.progress = `tagged ${total}, ${r.remaining} left`;
                if (!r.ok) { state.error = r.error || 'Tagging failed.'; break; }
                if (!r.tagged || r.remaining === 0) break;
                render();
            }
        } catch (e) {
            state.error = e.message;
        } finally {
            state.tagging = false;
            state.progress = '';
            await refreshStatus();
            if (state.status && state.status.available) await load();
        }
    }

    async function openDetail(kind, key) {
        state.loading = true; state.error = ''; state.brief = null; render();
        try {
            const url = kind === 'country'
                ? `/api/intel-reports/country/${encodeURIComponent(key)}`
                : `/api/intel-reports/industry?name=${encodeURIComponent(key)}`;
            state.detail = await post(url, { days: state.days });
            state.detail.value = kind === 'country' ? state.detail.value : key;
        } catch (e) {
            state.error = e.message;
        } finally {
            state.loading = false; render();
        }
    }

    async function generateBrief(kind, value) {
        state.brief = 'Generating…'; render();
        try {
            const r = await post(`/api/intel-reports/brief?kind=${encodeURIComponent(kind)}&value=${encodeURIComponent(value)}`, { days: state.days });
            state.brief = r.brief || 'No brief returned.';
        } catch (e) {
            state.brief = null; state.error = e.message;
        }
        render();
    }

    function bind() {
        const el = pane();
        if (!el || el.dataset.bound) return;
        el.dataset.bound = '1';
        el.addEventListener('click', async e => {
            if (e.target.closest('[data-ir-recheck]')) { const s = await refreshStatus(true); if (s.available) load(); return; }
            if (e.target.closest('[data-ir-tag]')) { tagAll(); return; }
            const b = e.target.closest('[data-ir-brief]');
            if (b) { generateBrief(b.dataset.kind, b.dataset.value); return; }
            const v = e.target.closest('[data-ir-view]');
            if (v) { state.view = v.dataset.irView; state.detail = null; load(); return; }
            if (e.target.closest('[data-ir-back]')) { state.detail = null; state.brief = null; render(); return; }
            const c = e.target.closest('[data-ir-country]');
            if (c) { openDetail('country', c.dataset.irCountry); return; }
            const s = e.target.closest('[data-ir-industry]');
            if (s) { openDetail('industry', s.dataset.irIndustry); }
        });
        el.addEventListener('change', e => {
            if (e.target.id === 'ir-period') { state.days = parseInt(e.target.value, 10) || 30; load(); }
        });
    }

    async function init() {
        bind();
        if (state.loading || state.tagging) { render(); return; }
        const s = await refreshStatus();
        if (s.available) load();
    }

    window.initIntelReports = init;
})();
