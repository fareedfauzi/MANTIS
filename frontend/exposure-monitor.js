(() => {
    'use strict';
    const base = location.protocol === 'file:' ? 'http://127.0.0.1:9999' : location.origin;
    const root = () => document.getElementById('exposure-monitor-workspace');
    const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const recentProfiles = ['hak5-cloud-c2', 'gophish', 'evilginx', 'nessus', 'acunetix', 'openvas', 'nexpose', 'burp-enterprise', 'laplas-clipper', 'amadey', 'risepro', 'immortal-dropper', 'shadow-c2', 'geacon-pro', 'locust', 'pikvm', 'artex', 'cyberstrikeai', 'pentagi', 'strix', 'scopeweaver', 'agent-zero', 'redamon', 'cairn', 'xalgorix', 'decepticon', 'cyberstrike', 'redcell'];
    const state = { tools: [], filter: '', category: 'all', country: 'all', selected: '', mode: 'hosts', detail: null, busy: '', editing: null, shodanDepth: '1' };
    const modal = () => document.getElementById('exposure-modal-overlay');
    let modalTrigger = null;

    async function request(path, options = {}) {
        const response = await fetch(base + path, {headers: {'Content-Type': 'application/json'}, ...options});
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.detail || result.error || `HTTP ${response.status}`);
        return result;
    }

    function date(value) {
        if (!value) return 'Not checked';
        const time = new Date(value);
        return Number.isFinite(time.getTime()) ? time.toLocaleString() : value;
    }

    function filters() {
        return state.tools.filter(tool =>
            (state.category === 'all' || tool.category === state.category) &&
            (state.country === 'all' || (tool.countries || []).includes(state.country)) &&
            `${tool.name} ${tool.description} ${tool.category}`.toLowerCase().includes(state.filter.toLowerCase()));
    }

    function card(tool) {
        const configured = tool.providers.filter(provider => localStorage.getItem(`ioc_${provider}_key`)?.trim());
        const count = tool.count === null ? '—' : tool.count.toLocaleString();
        const shodan = tool.provider_status?.shodan;
        return `<article class="exposure-card">
            <div class="exposure-card-top"><span class="exposure-type">${escape(tool.category)}</span><span class="exposure-date">${escape(date(tool.observed_at))}</span></div>
            <h3>${escape(tool.name)}</h3><p>${escape(tool.description)}</p>
            <div class="exposure-metrics"><div><strong>${count}</strong><span>Saved host leads</span></div><div><strong>${tool.new_count == null ? '-' : tool.new_count}</strong><span>New since comparable check</span></div></div>
            ${shodan?.total > shodan?.returned ? `<div class="exposure-total-note" title="Shodan total match count across all queries vs downloaded rows in this sample"><i class="fa-solid fa-circle-info"></i> Shodan reports ${Number(shodan.total).toLocaleString()} total matches worldwide across ${shodan.queries_run || 1} queries. Retrieved ${Number(shodan.returned).toLocaleString()} rows (${shodan.pages_fetched || 1} page${(shodan.pages_fetched || 1) === 1 ? '' : 's'}); deduped into ${Number(tool.count || 0).toLocaleString()} unique host leads.</div>` : ''}
            <div class="exposure-card-footer">
                <div class="exposure-providers">${tool.providers.map(provider => `<span class="${configured.includes(provider) ? 'ready' : 'missing'}">${escape(provider)}</span>`).join('')}</div>
                <div class="exposure-actions">
                    <button type="button" class="exposure-icon-btn" data-exposure-detail="${escape(tool.id)}" title="View evidence" aria-label="View evidence"><i class="fa-solid fa-eye"></i></button>
                    <button type="button" class="exposure-icon-btn" data-exposure-queries="${escape(tool.id)}" title="View queries" aria-label="View queries"><i class="fa-solid fa-code"></i></button>
                    <button type="button" class="exposure-icon-btn exposure-btn-refresh" data-exposure-refresh="${escape(tool.id)}" ${state.busy ? 'disabled' : ''} title="${state.busy === tool.id ? 'Checking providers…' : 'Check providers'}" aria-label="Check providers"><i class="fa-solid fa-arrows-rotate ${state.busy === tool.id ? 'mantis-spin' : ''}"></i></button>
                </div>
            </div>
        </article>`;
    }

    function render() {
        const target = root();
        if (!target) return;
        const categories = [...new Set(state.tools.map(tool => tool.category))].sort();
        const countries = [...new Set(state.tools.flatMap(tool => tool.countries || []))].sort();
        const listed = filters();
        const missing = recentProfiles.filter(id => !state.tools.some(tool => tool.id === id));
        target.innerHTML = `<section class="exposure-view">
            <header class="exposure-heading"><div><span class="exposure-kicker">INFRASTRUCTURE INTELLIGENCE</span><h2>C2 &amp; Attack Tool Exposure</h2>
            <p>Passive search-index observations of C2, security tools and AI red-team consoles. A match is an investigation lead, not proof of malicious use.</p></div>
            <span class="exposure-scope">Curated profiles · On-demand checks</span></header>
            ${missing.length ? `<div class="exposure-stale" role="status"><i class="fa-solid fa-circle-info" aria-hidden="true"></i><span>The running backend has an older Exposure catalog. Restart MANTIS to load the newest profiles; ${state.tools.length} are available right now.</span></div>` : ''}
            <div class="exposure-toolbar"><label><i class="fa-solid fa-magnifying-glass"></i><input id="exposure-filter" type="search" placeholder="Search tools" value="${escape(state.filter)}"></label>
            <select id="exposure-category" aria-label="Tool category"><option value="all">All categories</option>${categories.map(value => `<option value="${escape(value)}" ${state.category === value ? 'selected' : ''}>${escape(value)}</option>`).join('')}</select>
            <select id="exposure-country" aria-label="Observed country"><option value="all">All countries</option>${countries.map(value => `<option value="${escape(value)}" ${state.country === value ? 'selected' : ''}>${escape(value)}</option>`).join('')}</select>
            <select id="exposure-depth" aria-label="Shodan scan depth" title="Control how many result pages to retrieve from Shodan (Page 1 = 100 results per query, 0 query credits)">
                <option value="1" ${state.shodanDepth === '1' ? 'selected' : ''}>Quick (Page 1 · ~100/query)</option>
                <option value="5" ${state.shodanDepth === '5' ? 'selected' : ''}>Deep (5 Pages · ~500/query)</option>
                <option value="10" ${state.shodanDepth === '10' ? 'selected' : ''}>Extended (10 Pages · ~1,000/query)</option>
                <option value="100" ${state.shodanDepth === '100' ? 'selected' : ''}>Full Harvest (All available pages)</option>
            </select>
            <span class="exposure-result-count">${listed.length} profiles</span></div>
            <div class="exposure-grid">${listed.map(card).join('') || '<div class="exposure-empty">No tools match these filters.</div>'}</div>
            <div id="exposure-feedback" role="status" aria-live="polite"></div>
        </section>`;
        target.querySelector('#exposure-filter').addEventListener('input', event => {
            state.filter = event.target.value;
            const matches = filters();
            target.querySelector('.exposure-grid').innerHTML = matches.map(card).join('') || '<div class="exposure-empty">No profiles match these filters.</div>';
            target.querySelector('.exposure-result-count').textContent = `${matches.length} profiles`;
        });
        target.querySelector('#exposure-category').onchange = event => { state.category = event.target.value; render(); };
        target.querySelector('#exposure-country').onchange = event => { state.country = event.target.value; render(); };
        target.querySelector('#exposure-depth').onchange = event => { state.shodanDepth = event.target.value; };
    }

    function renderDetail() {
        const tool = state.tools.find(item => item.id === state.selected);
        const data = state.detail;
        if (!tool) return;
        document.getElementById('exposure-modal-title').textContent = tool.name;
        if (state.mode === 'queries') {
            const queries = Array.isArray(tool.queries) ? tool.queries : Object.entries(tool.queries || {}).map(([provider, query]) => ({id: provider, provider, query}));
            document.getElementById('exposure-modal-subtitle').textContent = `${tool.category} · Curated passive search queries`;
            document.getElementById('exposure-modal-count').textContent = `${queries.length} provider quer${queries.length === 1 ? 'y' : 'ies'}`;
            const copy = document.getElementById('exposure-copy-all');
            copy.disabled = !queries.length;
            copy.setAttribute('aria-label', 'Copy all hunting queries');
            const edit = queries.find(item => item.id === state.editing);
            document.getElementById('exposure-modal-body').innerHTML = `<div class="exposure-modal-summary"><p>These are the exact searches used by Check providers. Changes are saved locally and apply on the next check.</p></div>
                <div class="exposure-query-toolbar"><button type="button" data-exposure-add>+ Add query</button></div>
                ${state.editing !== null ? `<form id="exposure-query-form" class="exposure-query-form">
                    <label>Provider<select name="provider" required>${['shodan','fofa','censys','zoomeye','validin'].map(provider => `<option value="${provider}" ${edit?.provider === provider ? 'selected' : ''}>${provider.toUpperCase()}</option>`).join('')}</select></label>
                    <label>Search query<textarea name="query" rows="3" maxlength="4000" required>${escape(edit?.query || '')}</textarea></label>
                    <div><button type="submit">Save query</button><button type="button" data-exposure-cancel>Cancel</button></div>
                </form>` : ''}
                <div class="exposure-query-list">${queries.map(item => `<article class="exposure-query-card"><div class="exposure-query-card-head"><span>${escape(item.provider)}</span><div><button type="button" data-exposure-edit="${escape(item.id)}" aria-label="Edit ${escape(item.provider)} query" title="Edit query"><i class="fa-solid fa-pen"></i></button><button type="button" data-exposure-delete="${escape(item.id)}" aria-label="Delete ${escape(item.provider)} query" title="Delete query"><i class="fa-solid fa-trash"></i></button></div></div><code>${escape(item.query)}</code></article>`).join('')
                    || '<div class="exposure-empty">No queries for this profile. Add one to start hunting.</div>'}</div>`;
            return;
        }
        document.getElementById('exposure-copy-all').setAttribute('aria-label', 'Copy all host leads');
        document.getElementById('exposure-modal-subtitle').textContent = data?.observed_at
            ? `Checked ${date(data.observed_at)} · ${tool.category}` : `${tool.category} · No saved check`;
        document.getElementById('exposure-copy-all').disabled = !data?.hosts?.length;
        document.getElementById('exposure-modal-count').textContent = data
            ? `${data.hosts.length} host lead${data.hosts.length === 1 ? '' : 's'} in saved sample` : 'Loading saved evidence…';
        const body = document.getElementById('exposure-modal-body');
        if (!data) { body.innerHTML = '<div class="exposure-empty">Loading saved evidence…</div>'; return; }
        const statuses = Object.entries(data.provider_status || {}).map(([provider, info]) =>
            `<span class="exposure-provider-state ${['ok', 'error'].includes(info.status) ? info.status : 'missing'}">${escape(provider)} · ${escape(info.status)}${info.returned != null ? ` (${info.returned}${info.total > info.returned ? ` of ${info.total} indexed${info.queries_run > 1 ? ', summed' : ''}` : ''})` : ''}${info.message ? ` · ${escape(info.message)}` : ''}</span>`).join('');
        const shodan = data.provider_status?.shodan;
        const canFetchMore = shodan?.status === 'ok' && shodan.total > shodan.returned && localStorage.getItem('ioc_shodan_key')?.trim();
        body.innerHTML = `<div class="exposure-modal-summary"><p>${escape(data.note || 'No provider check has been saved yet.')}</p>
            ${statuses ? `<div class="exposure-provider-states">${statuses}</div>` : ''}
            ${canFetchMore ? `
                <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
                    <button type="button" class="exposure-more-button" data-exposure-more="${escape(tool.id)}"><i class="fa-solid fa-layer-group"></i> Fetch 10 Shodan Pages (~1,000 leads)</button>
                    <button type="button" class="exposure-more-button" data-exposure-all="${escape(tool.id)}" style="background: rgba(234, 179, 8, 0.15); border-color: rgba(234, 179, 8, 0.4); color: #facc15;"><i class="fa-solid fa-cloud-arrow-down"></i> Fetch ALL Available Pages (up to 100 pages)</button>
                </div>
            ` : ''}</div>
            <div class="exposure-hosts">${(data.hosts || []).map(host => `<article class="exposure-host">
                <div class="exposure-host-main"><strong>${escape(host.value)}${host.port ? `:${host.port}` : ''}</strong>
                ${host.new ? '<span class="exposure-new">New</span>' : ''}<span class="exposure-confidence">${escape(host.confidence)}</span></div>
                <div class="exposure-host-meta">${[host.country, host.service, host.title, host.last_seen ? `Seen ${host.last_seen}` : ''].filter(Boolean).map(value => `<span>${escape(value)}</span>`).join('')}</div>
                <div class="exposure-host-sources">${[...new Set((host.evidence || []).map(e => e.provider))].map(provider => `<span>${escape(provider)}</span>`).join('')}</div>
            </article>`).join('') || '<div class="exposure-empty">No host observations returned by the configured providers.</div>'}</div>
        `;
    }

    function closeModal(restoreFocus = true) {
        if (modal()?.style.display !== 'flex') return;
        modal().style.display = 'none';
        state.selected = '';
        state.detail = null;
        document.getElementById('exposure-modal-feedback').textContent = '';
        if (restoreFocus && modalTrigger?.isConnected) modalTrigger.focus();
        modalTrigger = null;
    }

    function openModal() {
        if (!modal()) return;
        modal().style.display = 'flex';
        document.getElementById('exposure-modal-feedback').textContent = '';
        renderDetail();
        document.getElementById('exposure-modal-body').scrollTop = 0;
        document.getElementById('exposure-modal-close').focus();
    }

    async function copyAll() {
        if (state.mode === 'queries') {
            const source = state.tools.find(item => item.id === state.selected)?.queries || [];
            const queries = Array.isArray(source) ? source : Object.entries(source).map(([provider, query]) => ({provider, query}));
            if (queries.length) await copyText(queries.map(item => `${item.provider}: ${item.query}`).join('\n'), `Copied ${queries.length} hunting quer${queries.length === 1 ? 'y' : 'ies'}`);
            return;
        }
        const hosts = state.detail?.hosts || [];
        if (!hosts.length) return;
        const values = hosts.map(host => host.port
            ? `${host.value.includes(':') ? `[${host.value}]` : host.value}:${host.port}`
            : host.value).join('\n');
        await copyText(values, `Copied ${hosts.length} host lead${hosts.length === 1 ? '' : 's'}`);
    }

    async function copyText(values, message) {
        const feedback = document.getElementById('exposure-modal-feedback');
        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(values);
            } else {
                const input = document.createElement('textarea');
                input.value = values;
                input.style.position = 'fixed';
                input.style.opacity = '0';
                document.body.appendChild(input);
                input.select();
                const copied = document.execCommand('copy');
                input.remove();
                if (!copied) throw new Error('Clipboard unavailable');
            }
            feedback.textContent = message;
        } catch (_) {
            feedback.textContent = 'Copy failed. Check clipboard permission.';
        }
    }

    async function open() {
        if (!root()) return;
        closeModal(false);
        state.selected = '';
        state.detail = null;
        root().innerHTML = '<div class="exposure-empty exposure-loading">Loading exposure catalog…</div>';
        try {
            state.tools = (await request('/api/exposure-monitor')).tools || [];
            if (root()?.querySelector('.exposure-loading')) render();
        } catch (error) {
            if (root()?.querySelector('.exposure-loading')) root().innerHTML = `<div class="exposure-empty">Could not load Exposure Monitor: ${escape(error.message)}</div>`;
        }
    }

    async function show(toolId, trigger, mode = 'hosts') {
        modalTrigger = trigger;
        state.selected = toolId;
        state.mode = mode;
        state.editing = null;
        state.detail = null;
        openModal();
        if (mode === 'queries') return;
        try {
            const detail = await request(`/api/exposure-monitor/${encodeURIComponent(toolId)}`);
            if (state.selected === toolId && modal()?.style.display === 'flex') {
                state.detail = detail;
                renderDetail();
            }
        } catch (error) {
            if (state.selected === toolId) document.getElementById('exposure-modal-body').innerHTML = `<div class="exposure-empty">Could not load evidence: ${escape(error.message)}</div>`;
        }
    }

    async function refresh(toolId, shodanPages = null) {
        if (state.busy) return;
        state.busy = toolId;
        render();
        const pages = shodanPages ? parseInt(shodanPages, 10) : (parseInt(state.shodanDepth || '1', 10) || 1);
        const status = root()?.querySelector('#exposure-feedback');
        if (status) status.textContent = `Checking ${state.tools.find(item => item.id === toolId)?.name || toolId} (Shodan scan depth: ${pages} page${pages === 1 ? '' : 's'})…`;
        const keyNames = ['shodan', 'fofa', 'censys', 'zoomeye', 'validin'];
        const payload = {tool_id: toolId, shodan_pages: pages, ...Object.fromEntries(keyNames.map(name => [`${name}_key`, localStorage.getItem(`ioc_${name}_key`) || '']))};
        try {
            const data = await request('/api/exposure-monitor/refresh', {method: 'POST', body: JSON.stringify(payload)});
            state.tools = (await request('/api/exposure-monitor')).tools || [];
            if (!root()?.querySelector('.exposure-view') || document.getElementById('exposure-monitor-pane')?.style.display === 'none') { state.busy = ''; return; }
            state.selected = toolId;
            state.mode = 'hosts';
            state.detail = data;
            state.busy = '';
            render();
            modalTrigger = [...root().querySelectorAll('[data-exposure-refresh]')].find(button => button.dataset.exposureRefresh === toolId);
            openModal();
        } catch (error) {
            state.busy = '';
            if (!root()?.querySelector('.exposure-view')) return;
            render();
            root().querySelector('#exposure-feedback').textContent = error.message;
        }
    }

    document.addEventListener('click', event => {
        if (event.target.closest('#exposure-modal-close')) return closeModal();
        if (event.target.closest('#exposure-copy-all')) return copyAll();
        const more = event.target.closest('[data-exposure-more]');
        if (more) return refresh(more.dataset.exposureMore, 10);
        const allPages = event.target.closest('[data-exposure-all]');
        if (allPages) return refresh(allPages.dataset.exposureAll, 100);
        if (modal()?.contains(event.target) && state.mode === 'queries') {
            if (event.target.closest('[data-exposure-add]')) { state.editing = ''; renderDetail(); return; }
            if (event.target.closest('[data-exposure-cancel]')) { state.editing = null; renderDetail(); return; }
            const edit = event.target.closest('[data-exposure-edit]');
            if (edit) { state.editing = edit.dataset.exposureEdit; renderDetail(); return; }
            const remove = event.target.closest('[data-exposure-delete]');
            if (remove) {
                if (!confirm('Delete this hunting query?')) return;
                request(`/api/exposure-monitor/${encodeURIComponent(state.selected)}/queries/${encodeURIComponent(remove.dataset.exposureDelete)}`, {method:'DELETE'})
                    .then(reloadQueries).catch(error => { document.getElementById('exposure-modal-feedback').textContent = error.message; });
                return;
            }
        }
        if (event.target === modal()) return closeModal();
        const target = root();
        if (!target || !target.contains(event.target)) return;
        const button = event.target.closest('button');
        if (!button) return;
        if (button.dataset.exposureRefresh) return refresh(button.dataset.exposureRefresh);
        if (button.dataset.exposureQueries) return show(button.dataset.exposureQueries, button, 'queries');
        if (button.dataset.exposureDetail) return show(button.dataset.exposureDetail, button);
    });
    async function reloadQueries() {
        state.tools = (await request('/api/exposure-monitor')).tools || [];
        state.editing = null;
        render();
        renderDetail();
        document.getElementById('exposure-modal-feedback').textContent = 'Query changes saved';
    }
    document.addEventListener('submit', async event => {
        if (event.target.id !== 'exposure-query-form') return;
        event.preventDefault();
        const form = event.target;
        const payload = {provider: form.elements.provider.value, query: form.elements.query.value.trim()};
        const path = `/api/exposure-monitor/${encodeURIComponent(state.selected)}/queries${state.editing ? '/' + encodeURIComponent(state.editing) : ''}`;
        try {
            await request(path, {method: state.editing ? 'PUT' : 'POST', body: JSON.stringify(payload)});
            await reloadQueries();
        } catch (error) { document.getElementById('exposure-modal-feedback').textContent = error.message; }
    });
    modal()?.addEventListener('keydown', event => {
        if (event.key === 'Escape') { event.stopPropagation(); closeModal(); }
        if (event.key !== 'Tab') return;
        const focusable = [...modal().querySelectorAll('button:not(:disabled), a[href]')]
            .filter(element => element.getClientRects().length);
        if (!focusable.length) return;
        const first = focusable[0], last = focusable.at(-1);
        if (event.shiftKey ? document.activeElement === first : document.activeElement === last) {
            event.preventDefault();
            (event.shiftKey ? last : first).focus();
        }
    });
    const pane = document.getElementById('exposure-monitor-pane');
    if (pane) new MutationObserver(() => {
        if (pane.style.display === 'none') closeModal(false);
    }).observe(pane, {attributes: true, attributeFilter: ['style']});
    window.openExposureMonitor = open;
})();
