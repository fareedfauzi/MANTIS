/**
 * Country & Industry Reports: ransomware victim rollups by country and sector,
 * with local CTI articles matched to the selected country or industry.
 */
(function () {
    const state = { view: 'country', days: 365, data: null, detail: null, loading: false, error: '' };

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

    function esc(v) { return escapeHtml(String(v == null ? '' : v)); }

    function countBars(rows, max) {
        if (!rows || !rows.length) return '<span class="ir-muted">None</span>';
        return rows.map(r => `<span class="ir-chip">${esc(r.name)} <b>${r.count}</b></span>`).join('');
    }

    function render() {
        const el = pane();
        if (!el) return;
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
                        <p class="ir-sub">Ransomware victims and related CTI reporting, by ${state.view === 'country' ? 'country' : 'industry'}.</p>
                    </div>
                    <div class="ir-controls">
                        <div class="ir-seg">
                            <button type="button" data-ir-view="country" class="${state.view === 'country' ? 'active' : ''}">Countries</button>
                            <button type="button" data-ir-view="industry" class="${state.view === 'industry' ? 'active' : ''}">Industries</button>
                        </div>
                        <select id="ir-period" class="ir-select">${periods}</select>
                    </div>
                </div>
                ${state.detail ? '<button type="button" class="ir-back" data-ir-back="1"><i class="fa-solid fa-arrow-left"></i> Back</button>' : ''}
                ${body}
            </div>`;
    }

    function renderCountries(data) {
        if (!data.countries.length) return '<div class="ir-empty">No country-tagged victims in this period.</div>';
        const rows = data.countries.map((c, i) => `
            <tr data-ir-country="${esc(c.country_code || c.key)}">
                <td class="ir-num">${i + 1}</td>
                <td><b>${esc(c.name)}</b> ${c.country_code ? `<span class="ir-muted">${esc(c.country_code)}</span>` : ''}</td>
                <td class="ir-num">${c.count}</td>
                <td>${countBars(c.top_groups)}</td>
                <td>${countBars(c.top_sectors)}</td>
            </tr>`).join('');
        return `<p class="ir-meta">${data.total_victims} victims in period</p>
            <div class="ir-table-wrap"><table class="ir-table">
                <thead><tr><th>#</th><th>Country</th><th class="ir-num">Victims</th><th>Top groups</th><th>Top sectors</th></tr></thead>
                <tbody>${rows}</tbody></table></div>`;
    }

    function renderIndustries(data) {
        if (!data.industries.length) return '<div class="ir-empty">No sector-tagged victims in this period.</div>';
        const rows = data.industries.map((s, i) => `
            <tr data-ir-industry="${esc(s.name)}">
                <td class="ir-num">${i + 1}</td>
                <td><b>${esc(s.name)}</b></td>
                <td class="ir-num">${s.count}</td>
                <td>${countBars(s.top_groups)}</td>
                <td>${countBars(s.top_countries)}</td>
            </tr>`).join('');
        return `<p class="ir-meta">${data.total_victims} victims in period</p>
            <div class="ir-table-wrap"><table class="ir-table">
                <thead><tr><th>#</th><th>Industry</th><th class="ir-num">Victims</th><th>Top groups</th><th>Top countries</th></tr></thead>
                <tbody>${rows}</tbody></table></div>`;
    }

    function renderDetail(d) {
        const victims = (d.recent_victims || []).map(v => `
            <tr>
                <td>${esc(v.name)}</td><td>${esc(v.group)}</td><td>${esc(v.country)}</td>
                <td>${esc(v.sector)}</td><td>${esc((v.discovered_at || v.published_at || '').slice(0, 10))}</td>
            </tr>`).join('');
        const articles = (d.cti_articles || []).map(a => `
            <li><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.title)}</a>
                <span class="ir-muted">${esc(a.source || '')} · matched "${esc(a.matched_on)}"</span></li>`).join('');
        const stats = d.victims != null ? `<div class="ir-stats"><div><b>${d.victims}</b><span>Victims</span></div></div>` : '';
        const label = d.name || d.code;
        return `
            <h3 class="ir-detail-title">${esc(label)}</h3>
            ${stats}
            <div class="ir-detail-grid">
                <section><h4>Top groups</h4><div>${countBars(d.top_groups)}</div></section>
                <section><h4>${d.code ? 'Top sectors' : 'Top countries'}</h4><div>${countBars(d.top_sectors || d.top_countries)}</div></section>
            </div>
            <h4>Recent victims</h4>
            ${victims ? `<div class="ir-table-wrap"><table class="ir-table"><thead><tr><th>Victim</th><th>Group</th><th>Country</th><th>Sector</th><th>Date</th></tr></thead><tbody>${victims}</tbody></table></div>` : '<div class="ir-muted">No victims in this period.</div>'}
            <h4>CTI articles</h4>
            ${articles ? `<ul class="ir-articles">${articles}</ul>` : '<div class="ir-muted">No matching local CTI articles.</div>'}`;
    }

    async function load() {
        state.loading = true; state.error = ''; state.detail = null; render();
        try {
            const url = state.view === 'country' ? '/api/intel-reports/countries' : '/api/intel-reports/industries';
            state.data = await post(url, { days: state.days });
        } catch (e) {
            state.data = null; state.error = e.message;
        } finally {
            state.loading = false; render();
        }
    }

    async function openDetail(kind, key) {
        state.loading = true; state.error = ''; render();
        try {
            if (kind === 'country') {
                state.detail = await post(`/api/intel-reports/country/${encodeURIComponent(key)}`, { days: state.days });
            } else {
                state.detail = await post(`/api/intel-reports/industry?name=${encodeURIComponent(key)}`, { days: state.days });
            }
        } catch (e) {
            state.error = e.message;
        } finally {
            state.loading = false; render();
        }
    }

    function bind() {
        const el = pane();
        if (!el || el.dataset.bound) return;
        el.dataset.bound = '1';
        el.addEventListener('click', e => {
            const v = e.target.closest('[data-ir-view]');
            if (v) { state.view = v.dataset.irView; state.detail = null; load(); return; }
            if (e.target.closest('[data-ir-back]')) { state.detail = null; render(); return; }
            const c = e.target.closest('[data-ir-country]');
            if (c) { openDetail('country', c.dataset.irCountry); return; }
            const s = e.target.closest('[data-ir-industry]');
            if (s) { openDetail('industry', s.dataset.irIndustry); }
        });
        el.addEventListener('change', e => {
            if (e.target.id === 'ir-period') { state.days = parseInt(e.target.value, 10) || 365; load(); }
        });
    }

    function init() {
        bind();
        if (!state.data && !state.loading) load();
        else render();
    }

    window.initIntelReports = init;
})();
