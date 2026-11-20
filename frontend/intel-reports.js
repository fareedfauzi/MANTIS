/**
 * Country & Industry Reports: CTI articles tagged by the configured AI provider.
 * If AI is not configured, the section is disabled and shows the reason. A failed
 * AI call is shown as a warning above the reports; the section stays usable.
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
                <p class="ir-muted">Configure MANTIS AI in Settings, then check again.</p>
                <button type="button" class="ir-btn" data-ir-recheck="1">Check again</button>
            </div></div>`;
    }

    function tagBar() {
        const s = state.status || {};
        const pending = s.untagged || 0;
        const busy = state.tagging ? 'disabled' : '';
        return `<div class="ir-tagbar">
            <div class="ir-tagbar-info"><span class="ir-tagbar-icon"><i class="fa-solid fa-tags" aria-hidden="true"></i></span><div><strong>${pending.toLocaleString()} articles awaiting classification</strong><span>CTI articles from the last 30 days${state.progress ? ` · ${esc(state.progress)}` : ''}</span></div></div>
            <button type="button" class="ir-btn" data-ir-tag="1" ${busy || (pending ? '' : 'disabled')}>
                <i class="fa-solid ${state.tagging ? 'fa-spinner fa-spin' : 'fa-wand-magic-sparkles'}" aria-hidden="true"></i> ${state.tagging ? 'Tagging articles…' : 'Tag articles with AI'}</button>
        </div>`;
    }

    function render() {
        const el = pane();
        if (!el) return;
        if (state.status && !state.status.available) {
            el.innerHTML = `<div class="ir-wrap"><div class="ir-header"><div>
                <span class="ir-kicker">THREAT INTELLIGENCE / REPORTS</span><h2 class="ir-title">Country &amp; Industry Reports</h2></div></div>${disabledView(state.status)}</div>`;
            return;
        }
        const warn = state.status && state.status.last_error
            ? `<div class="ir-warn"><i class="fa-solid fa-triangle-exclamation"></i>
                <span>Last AI call failed: ${esc(state.status.last_error)}. Tagging will retry on the next run.</span>
                <button type="button" class="ir-btn" data-ir-recheck="1">Check again</button></div>` : '';
        const periods = [30, 90, 365].map(d =>
            `<option value="${d}" ${state.days === d ? 'selected' : ''}>${d === 365 ? 'Last 12 months' : `Last ${d} days`}</option>`).join('');
        let body = '';
        if (state.loading) body = '<div class="ir-empty"><i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Loading reports…</div>';
        else if (state.detail) body = `${state.error ? `<div class="ir-error">${esc(state.error)}</div>` : ''}${renderDetail(state.detail)}`;
        else if (state.error) body = `<div class="ir-error">${esc(state.error)}</div>`;
        else if (state.data) body = state.view === 'country' ? renderCountries(state.data) : renderIndustries(state.data);
        el.innerHTML = `
            <div class="ir-wrap">${warn}
                <div class="ir-header">
                    <div>
                        <span class="ir-kicker">THREAT INTELLIGENCE / REPORTS</span>
                        <h2 class="ir-title">${state.view === 'country' ? 'Country Reports' : 'Industry Reports'}</h2>
                        <p class="ir-sub">Explore CTI reporting by ${state.view === 'country' ? 'country' : 'industry'} from your collected articles.</p>
                    </div>
                    <div class="ir-controls">
                        <div class="ir-seg" role="group" aria-label="Report type">
                            <button type="button" data-ir-view="country" aria-pressed="${state.view === 'country'}" class="${state.view === 'country' ? 'active' : ''}">Countries</button>
                            <button type="button" data-ir-view="industry" aria-pressed="${state.view === 'industry'}" class="${state.view === 'industry' ? 'active' : ''}">Industries</button>
                        </div>
                        <label class="ir-period-label"><span class="ir-sr-only">Time period</span><select id="ir-period" class="ir-select">${periods}</select></label>
                    </div>
                </div>
                ${tagBar()}
                ${state.detail ? '<button type="button" class="ir-back" data-ir-back="1"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i> Back to reports</button>' : ''}
                ${body}
            </div>`;
    }

    function renderCountries(data) {
        return renderRankings(data, 'country');
    }

    function renderIndustries(data) {
        return renderRankings(data, 'industry');
    }

    function renderRankings(data, kind) {
        const isCountry = kind === 'country';
        const entries = isCountry ? (data.countries || []) : (data.industries || []);
        const tagged = Number(data.articles_tagged) || 0;
        const total = Number(data.articles_in_window) || 0;
        const coverage = total ? Math.min(100, Math.round(tagged / total * 100)) : 0;
        const label = isCountry ? 'Countries' : 'Industries';
        const max = Math.max(1, ...entries.map(item => Number(item.articles) || 0));
        const stats = `<div class="ir-summary" aria-label="Report coverage">
            <div class="ir-summary-card"><span>Tagged articles</span><strong>${tagged.toLocaleString()} <small>/ ${total.toLocaleString()}</small></strong><div class="ir-coverage-track"><span style="width:${coverage}%"></span></div><small>${coverage}% coverage in this period</small></div>
            <div class="ir-summary-card"><span>${label} identified</span><strong>${entries.length.toLocaleString()}</strong><small>From tagged CTI articles</small></div></div>`;
        if (!entries.length) return stats + `<div class="ir-empty">No ${label.toLowerCase()} found for this period. ${tagged ? 'Try another date range.' : 'Tag your CTI articles to build these reports.'}</div>`;
        const rows = entries.map((item, i) => {
            const count = Number(item.articles) || 0;
            const key = isCountry ? `data-ir-country="${esc(item.code)}"` : `data-ir-industry="${esc(item.name)}"`;
            return `<tr ${key} tabindex="0" role="button" aria-label="Open ${esc(item.name)} report, ${count} articles">
                <td class="ir-rank"><span>${String(i + 1).padStart(2, '0')}</span></td>
                <td><div class="ir-row-name"><b>${esc(item.name)}</b>${isCountry ? `<span class="ir-code">${esc(item.code)}</span>` : ''}</div>
                    <div class="ir-row-track"><span style="width:${Math.max(2, count / max * 100)}%"></span></div></td>
                <td class="ir-count"><span>${count.toLocaleString()}</span><i class="fa-solid fa-chevron-right" aria-hidden="true"></i></td>
            </tr>`;
        }).join('');
        return `${stats}<section class="ir-list-section" aria-label="${label} by article count"><div class="ir-list-heading"><div><span class="ir-kicker">REPORT INDEX</span><h3>${label} by article count</h3></div><span class="ir-list-hint">Select a row to view tagged articles <i class="fa-solid fa-arrow-right" aria-hidden="true"></i></span></div>
            <div class="ir-table-wrap"><table class="ir-table"><thead><tr><th scope="col">Rank</th><th scope="col">${isCountry ? 'Country' : 'Industry'}</th><th scope="col" class="ir-count">Articles</th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
    }

    function renderDetail(d) {
        const articles = (d.articles || []).map(a => {
            const url = /^https?:\/\//i.test(a.url || '') ? a.url : '';
            return `<li><div class="ir-article-main">${url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(a.title)} <i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i></a>` : `<span>${esc(a.title)}</span>`}
                <span class="ir-article-source">${esc(a.source_id || 'CTI article')} ${a.published_at ? `· ${esc(a.published_at.slice(0, 10))}` : ''}</span></div></li>`;
        }).join('');
        const brief = state.brief
            ? `<div class="ir-brief">${esc(state.brief).replace(/\n/g, '<br>')}</div>`
            : '';
        return `
            <div class="ir-detail-heading"><div><span class="ir-kicker">${d.code ? 'COUNTRY REPORT' : 'INDUSTRY REPORT'}</span><h3 class="ir-detail-title">${esc(d.name)}</h3></div><div class="ir-detail-count"><strong>${(d.articles || []).length.toLocaleString()}</strong><span>Tagged articles</span></div></div>
            <div class="ir-detail-grid">
                <section><h4>Also tagged</h4><div>${chips(d.related) || '<span class="ir-muted">No related tags</span>'}</div></section>
                <section><div class="ir-section-head"><h4>Intelligence brief</h4><button type="button" class="ir-btn ir-btn-outline" data-ir-brief="1" data-kind="${d.code ? 'country' : 'industry'}" data-value="${esc(d.value)}"><i class="fa-solid fa-wand-magic-sparkles" aria-hidden="true"></i> Generate brief</button></div>
                    ${brief}</section>
            </div>
            <section class="ir-article-section"><div class="ir-list-heading"><div><span class="ir-kicker">SOURCE MATERIAL</span><h4>CTI articles</h4></div><span class="ir-list-hint">${(d.articles || []).length} articles in this period</span></div>
            ${articles ? `<ul class="ir-articles">${articles}</ul>` : '<div class="ir-empty">No tagged articles in this period.</div>'}</section>`;
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
        state.error = '';
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
        el.addEventListener('keydown', e => {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            const row = e.target.closest('tr[data-ir-country], tr[data-ir-industry]');
            if (!row || e.target !== row) return;
            e.preventDefault();
            if (row.dataset.irCountry) openDetail('country', row.dataset.irCountry);
            else openDetail('industry', row.dataset.irIndustry);
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
