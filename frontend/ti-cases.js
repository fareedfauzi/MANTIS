/* TI Case Manager. Shares the existing MANTIS navigation and IOC Search. */
(() => {
    const pane = document.getElementById('ti-cases-pane');
    if (!pane) return;
    const state = { page: 'cases', offset: 0, query: '', caseId: null, caseTab: 'overview', role: 'analyst' };
    const esc = value => String(value ?? '').replace(/[&<>"']/g, char =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
    const list = value => (value || []).join(', ');
    const array = value => String(value || '').split(/[,\n]/).map(s => s.trim()).filter(Boolean);
    const date = value => value ? new Date(value).toLocaleString() : '—';
    const api = async (path, options = {}) => {
        const response = await fetch('/api/ti' + path, {
            credentials: 'same-origin', ...options,
            headers: { ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...(options.headers || {}) }
        });
        if (!response.ok) {
            let problem;
            try { problem = await response.json(); } catch {}
            throw Error(typeof problem?.detail === 'string' ? problem.detail : `Request failed (${response.status})`);
        }
        return response.json();
    };
    const json = (method, path, body) => api(path, { method, body: JSON.stringify(body) });
    const notice = message => { const el = pane.querySelector('.ti-notice'); if (el) el.textContent = message; };
    const action = (label, name, id = '', variant = '') =>
        `<button type="button" class="ti-btn ${variant}" data-action="${name}" data-id="${esc(id)}">${esc(label)}</button>`;
    const chips = values => (values || []).map(v => `<span class="ti-chip">${esc(v)}</span>`).join('') || '—';
    const rowEmpty = label => `<tr><td colspan="8" class="ti-empty">${esc(label)}</td></tr>`;

    function markdown(source) {
        // Escape HTML first: the preview never interprets analyst-supplied HTML.
        let text = esc(source || '');
        const blocks = [];
        text = text.replace(/```([^\n]*)\n([\s\S]*?)```/g, (_, lang, code) => {
            blocks.push(`<pre><code class="ti-mono">${code}</code></pre>`);
            return `\u0001${blocks.length - 1}\u0001`;
        });
        text = text.replace(/^\|(.+)\|\n\|[\s:|-]+\|\n((?:\|.*\|\n?)*)/gm, (_, header, body) => {
            const cells = line => line.split('|').map(s => s.trim()).filter((_, i, arr) => i > 0 && i < arr.length - 1);
            return '<table><thead><tr>' + cells('|' + header + '|').map(x => `<th>${x}</th>`).join('') +
                '</tr></thead><tbody>' + body.trim().split('\n').map(line =>
                    '<tr>' + cells(line).map(x => `<td>${x}</td>`).join('') + '</tr>').join('') + '</tbody></table>';
        });
        text = text.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, label, url) =>
            `<a href="${url.replace(/&amp;/g, '&amp;')}" target="_blank" rel="noopener noreferrer">${label}</a>`);
        text = text.replace(/^### (.+)$/gm, '<h4>$1</h4>').replace(/^## (.+)$/gm, '<h3>$1</h3>')
            .replace(/^# (.+)$/gm, '<h2>$1</h2>').replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/`([^`\n]+)`/g, '<code>$1</code>').replace(/\n/g, '<br>');
        return text.replace(/\u0001(\d+)\u0001/g, (_, i) => blocks[Number(i)]);
    }

    function frame(title, controls, body) {
        pane.innerHTML = `<div class="ti-shell"><header class="ti-head"><div><span class="ti-kicker">INTERNAL THREAT INTELLIGENCE</span>
            <h2>${esc(title)}</h2></div><div class="ti-actions">${controls}</div></header>
            <div class="ti-notice" role="status"></div>${body}</div>`;
    }

    async function cases() {
        const params = new URLSearchParams({ q: state.query, status: state.status || '', tag: state.tag || '',
            limit: '50', offset: String(state.offset) });
        const data = await api('/cases?' + params);
        if (state.page !== 'cases') return;
        frame('Cases', action('New case', 'new-case', '', 'primary'), `
          <div class="ti-toolbar"><input id="ti-search" placeholder="Search case name or IOC" value="${esc(state.query)}">
          <select id="ti-status"><option value="">All statuses</option>${['Open','Investigating','Closed'].map(s =>
            `<option ${state.status === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
          <input id="ti-tag" placeholder="Tag" value="${esc(state.tag || '')}">
          ${action('Search', 'search')}</div>
          <div class="ti-table-wrap"><table><thead><tr><th>Case ID</th><th>Case name</th><th>Status</th><th>Tags</th><th>IOCs</th><th>Created by</th><th>Updated</th><th></th></tr></thead>
          <tbody>${data.items.map(c => `<tr><td class="ti-mono">${esc(c.case_id)}</td><td><strong>${esc(c.name)}</strong></td>
          <td><span class="ti-status">${esc(c.status)}</span></td><td>${chips(c.tags)}</td><td>${c.ioc_count}</td>
          <td>${esc(c.created_by)}</td><td>${date(c.updated_at)}</td><td>${action('Open','view-case',c.id)}</td></tr>`).join('') || rowEmpty('No cases found')}</tbody></table></div>
          <div class="ti-pagination">${action('Previous','previous', '', state.offset ? '' : 'disabled')} <span>${data.total} cases · ${state.offset + 1}–${Math.min(state.offset + 50, data.total)}</span>
          ${action('Next','next', '', state.offset + 50 < data.total ? '' : 'disabled')}</div>`);
    }

    async function registry() {
        const params = new URLSearchParams({ q: state.query, type: state.type || '', assessment: state.assessment || '',
            tag: state.tag || '', limit: '50', offset: String(state.offset) });
        const data = await api('/iocs?' + params);
        if (state.page !== 'iocs') return;
        frame('IOC Registry', action('Import IOCs','import') + action('New IOC','new-ioc','','primary'), `
          <div class="ti-toolbar"><input id="ti-search" placeholder="Search IOC or description" value="${esc(state.query)}">
          <select id="ti-type"><option value="">All types</option>${['ip','domain','url','md5','sha1','sha256','email','filename','mutex','registry','other'].map(t =>
            `<option value="${t}" ${state.type === t ? 'selected' : ''}>${t}</option>`).join('')}</select>
          <select id="ti-assessment"><option value="">All assessments</option>${['Malicious','Suspicious','Benign','Unknown'].map(v =>
            `<option ${state.assessment === v ? 'selected' : ''}>${v}</option>`).join('')}</select>
          <input id="ti-tag" placeholder="Tag" value="${esc(state.tag || '')}">${action('Search','search')}</div>
          <div class="ti-table-wrap"><table><thead><tr><th>IOC</th><th>Type</th><th>Assessment</th><th>Confidence</th><th>Cases</th><th>Tags</th><th>Updated</th><th></th></tr></thead>
          <tbody>${data.items.map(i => `<tr><td class="ti-mono ti-value">${esc(i.value)}</td><td>${esc(i.type)}</td>
          <td>${esc(i.assessment)}</td><td>${esc(i.confidence)}</td><td>${i.case_count}</td><td>${chips(i.tags)}</td>
          <td>${date(i.updated_at)}</td><td>${action('Edit','edit-ioc',i.id)} ${action('Link case','link-ioc-case',i.id)} ${state.role === 'admin' ? action('Delete','delete-ioc',i.id,'danger') : ''}</td></tr>`).join('') || rowEmpty('No indicators found')}</tbody></table></div>
          <div class="ti-pagination">${action('Previous','previous','',state.offset ? '' : 'disabled')} <span>${data.total} IOCs</span>
          ${action('Next','next','',state.offset + 50 < data.total ? '' : 'disabled')}</div>`);
    }

    async function caseView(id) {
        state.caseId = Number(id);
        const c = await api('/cases/' + id);
        if (state.page !== 'detail' || state.caseId !== Number(id)) return;
        const tabs = ['overview','iocs','samples','ttps','references','related'];
        const tabsHtml = tabs.map(t => `<button class="ti-tab ${state.caseTab === t ? 'active' : ''}" data-action="tab" data-id="${t}">${t === 'ttps' ? 'TTPs' : t[0].toUpperCase() + t.slice(1)}</button>`).join('');
        let body = '';
        if (state.caseTab === 'overview') body = `<div class="ti-card"><h3>Overview</h3><p>${esc(c.description || 'No description')}</p>
            <div class="ti-meta">Status: ${esc(c.status)} · Created by ${esc(c.created_by)} on ${date(c.created_at)} · Updated by ${esc(c.updated_by)} on ${date(c.updated_at)}</div>
            <div class="ti-tags">${chips(c.tags)}</div><h3>Investigation notes</h3>
            <div class="ti-markdown">${markdown(c.notes || 'No notes yet.')}</div></div>`;
        if (state.caseTab === 'iocs') body = `<div class="ti-card"><div class="ti-row"><h3>Indicators (${c.iocs.length})</h3>${action('Add IOC','add-case-ioc')}</div>
            <div class="ti-table-wrap"><table><thead><tr><th>Value</th><th>Type</th><th>Assessment</th><th>Note</th><th></th></tr></thead><tbody>
            ${c.iocs.map(i => `<tr><td class="ti-mono ti-value">${esc(i.value)}</td><td>${esc(i.type)}</td><td>${esc(i.assessment)}</td>
            <td>${esc(i.note)}</td><td>${action('Edit','edit-ioc',i.id)} ${action('Unlink','unlink-ioc',i.id)}</td></tr>`).join('') || rowEmpty('No IOCs linked')}</tbody></table></div></div>`;
        if (state.caseTab === 'samples') body = `<div class="ti-card"><div class="ti-row"><h3>Malware samples</h3>
            <div>${action('Upload','upload-sample')} ${action('Link local hash','link-sample')} ${action('MWDB','mwdb-settings')}</div></div>
            <input type="file" id="ti-sample-file" hidden><div class="ti-table-wrap"><table><thead><tr><th>SHA256</th><th>Name</th><th>Source</th><th>Size</th><th></th></tr></thead><tbody>
            ${c.samples.map(s => `<tr><td class="ti-mono ti-value">${esc(s.sha256)}</td><td>${esc(s.filename)}</td><td>${esc(s.source)}</td>
            <td>${esc(s.size)}</td><td>${action('Download','download-sample',s.source + ':' + s.sha256)} ${action('Unlink','unlink-sample',s.source + ':' + s.sha256)}</td></tr>`).join('') || rowEmpty('No samples linked')}</tbody></table></div></div>`;
        if (state.caseTab === 'ttps' || state.caseTab === 'references') {
            const key = state.caseTab, values = key === 'ttps' ? c.ttps : c.references;
            body = `<div class="ti-card"><div class="ti-row"><h3>${key === 'ttps' ? 'MITRE ATT&CK TTPs' : 'References'}</h3>${action('Edit','edit-case')}</div>
                <ul>${values.map(v => `<li class="ti-mono">${esc(v)}</li>`).join('') || '<li>None recorded</li>'}</ul></div>`;
        }
        if (state.caseTab === 'related') body = `<div class="ti-card"><div class="ti-row"><h3>Related cases</h3>${action('Link case','link-case')}</div>
            ${c.related_cases.map(r => `<div class="ti-row"><span>${action('Open','view-case',r.id)} ${esc(r.name)} · ${esc(r.reason)}</span>
            ${action('Unlink','unlink-case',r.id)}</div>`).join('') || '<p>No related cases.</p>'}</div>`;
        frame(`${c.case_id} · ${c.name}`, action('Back to cases','back') + action('Edit case','edit-case') +
            (state.role === 'admin' ? action('Delete case','delete-case','','danger') : ''),
            `<div class="ti-tabs">${tabsHtml}</div>${body}<div class="ti-card"><details><summary>Activity history</summary>
            ${c.activity.map(a => `<p class="ti-meta">${date(a.created_at)} · ${esc(a.actor)} · ${esc(a.action)} ${esc(a.details)}</p>`).join('')}</details></div>`);
        state.case = c;
    }

    function dialog(title, fields, submit) {
        let dlg = document.getElementById('ti-global-dialog');
        if (!dlg) { dlg = document.createElement('dialog'); dlg.id = 'ti-global-dialog'; dlg.className = 'ti-dialog'; document.body.appendChild(dlg); }
        dlg.innerHTML = `<form method="dialog" id="ti-form"><h3>${esc(title)}</h3>${fields}
            <footer><button value="cancel" class="ti-btn">Cancel</button><button type="submit" value="save" class="ti-btn primary">Save</button></footer></form>`;
        dlg.showModal();
        dlg.querySelector('form').addEventListener('submit', async event => {
            if (event.submitter?.value === 'cancel') return;
            event.preventDefault();
            const button = event.submitter; button.disabled = true;
            try { await submit(new FormData(event.target)); dlg.close(); await refresh(); }
            catch (error) { dlg.querySelector('h3').textContent = error.message; button.disabled = false; }
        });
    }
    const field = (label, name, value = '', kind = 'text') =>
        `<label class="ti-field">${esc(label)}<${kind === 'textarea' ? 'textarea' : 'input'} name="${name}"
        ${kind === 'textarea' ? '' : `type="${kind}" value="${esc(value)}"`}> ${kind === 'textarea' ? esc(value) + '</textarea>' : ''}</label>`;
    function caseForm(c) {
        dialog(c ? 'Edit case' : 'New case', field('Case name','name',c?.name || '') +
            field('Description','description',c?.description || '', 'textarea') +
            `<label class="ti-field">Status<select name="status">${['Open','Investigating','Closed'].map(v =>
                `<option ${c?.status === v ? 'selected' : ''}>${v}</option>`).join('')}</select></label>` +
            `<label class="ti-field">Markdown notes (tables, links, code blocks)<div class="ti-format">
            ${['**Bold**','[Link](https://)','| Column | Column |','```code```'].map(x =>
                `<button type="button" class="ti-btn" data-insert="${esc(x)}">${esc(x)}</button>`).join('')}</div>
            <textarea name="notes" rows="9">${esc(c?.notes || '')}</textarea></label>` +
            field('Tags (comma separated)','tags',list(c?.tags)) + field('MITRE ATT&CK TTPs (comma separated)','ttps',list(c?.ttps)) +
            field('References (one URL per line)','references',(c?.references || []).join('\n'),'textarea'),
            async form => {
                const body = Object.fromEntries(form.entries());
                body.tags = array(body.tags); body.ttps = array(body.ttps); body.references = array(body.references);
                const result = await json(c ? 'PUT' : 'POST', c ? '/cases/' + c.id : '/cases', body);
                state.caseId = result.id; state.page = 'detail';
            });
    }
    function iocForm(i) {
        dialog(i ? 'Edit IOC' : 'New IOC', field('IOC value','value',i?.value || '') +
            field('Type (auto, ip, domain, url, hash, email, filename, mutex, registry, other)','type',i?.type || 'auto') +
            field('Description / analyst notes','description',i?.description || '', 'textarea') +
            `<label class="ti-field">Assessment<select name="assessment">${['Unknown','Malicious','Suspicious','Benign'].map(v =>
                `<option ${i?.assessment === v ? 'selected' : ''}>${v}</option>`).join('')}</select></label>` +
            `<label class="ti-field">Confidence<select name="confidence">${['Low','Medium','High'].map(v =>
                `<option ${i?.confidence === v ? 'selected' : ''}>${v}</option>`).join('')}</select></label>` +
            field('First seen (ISO date)','first_seen',i?.first_seen || '') + field('Last seen (ISO date)','last_seen',i?.last_seen || '') +
            field('Tags','tags',list(i?.tags)) + field('References','references',(i?.references || []).join('\n'),'textarea'),
            async form => {
                const body = Object.fromEntries(form.entries());
                body.tags = array(body.tags); body.references = array(body.references);
                await json(i ? 'PUT' : 'POST', i ? '/iocs/' + i.id : '/iocs', body);
            });
    }
    async function refresh() {
        try {
            if (state.page === 'detail') return await caseView(state.caseId);
            if (state.page === 'cases') return await cases();
            return await registry();
        } catch (error) { frame('TI Case Manager', action('Retry','retry'), `<p class="ti-error">${esc(error.message)}</p>`); }
    }
    function open(page) { state.page = page; state.caseId = null; state.offset = 0; state.query = ''; refresh(); }

    document.addEventListener('click', event => {
        const insert = event.target.closest('[data-insert]');
        if (insert) {
            const box = document.querySelector('#ti-global-dialog textarea[name=notes]'), at = box.selectionStart;
            box.setRangeText(insert.dataset.insert, at, box.selectionEnd, 'end'); box.focus(); return;
        }
    });
    pane.addEventListener('click', async event => {
        const button = event.target.closest('[data-action]');
        if (!button || button.classList.contains('disabled')) return;
        const { action: name, id } = button.dataset;
        try {
            if (name === 'search') { state.query = pane.querySelector('#ti-search')?.value || ''; state.status = pane.querySelector('#ti-status')?.value || '';
                state.type = pane.querySelector('#ti-type')?.value || ''; state.assessment = pane.querySelector('#ti-assessment')?.value || '';
                state.tag = pane.querySelector('#ti-tag')?.value || ''; state.offset = 0; return refresh(); }
            if (name === 'previous' || name === 'next') { state.offset += name === 'next' ? 50 : -50; return refresh(); }
            if (name === 'retry') return refresh();
            if (name === 'back') { state.page = 'cases'; state.caseId = null; return refresh(); }
            if (name === 'view-case') { state.page = 'detail'; state.caseTab = 'overview'; return caseView(id); }
            if (name === 'tab') { state.caseTab = id; return refresh(); }
            if (name === 'new-case') return caseForm();
            if (name === 'edit-case') return caseForm(state.case);
            if (name === 'new-ioc') return iocForm();
            if (name === 'edit-ioc') return iocForm(await api('/iocs/' + id));
            if (name === 'link-ioc-case') {
                const available = await api('/cases?limit=100');
                return dialog('Link IOC to case', `<label class="ti-field">Case<select name="case_id">${available.items.map(c =>
                    `<option value="${c.id}">${esc(c.case_id + ' · ' + c.name)}</option>`).join('')}</select></label>` +
                    field('Case note','note','','textarea'), async form => {
                    await json('POST','/cases/' + form.get('case_id') + '/iocs',{ioc_id:Number(id),note:form.get('note')});
                });
            }
            if (name === 'delete-ioc' && confirm('Delete this IOC from the shared registry and all linked cases?')) {
                await api('/iocs/' + id, { method: 'DELETE' }); return refresh(); }
            if (name === 'delete-case' && confirm('Delete this case? Shared IOCs and samples remain in their repositories.')) {
                await api('/cases/' + state.caseId, { method: 'DELETE' }); state.page = 'cases'; return refresh(); }
            if (name === 'add-case-ioc') return dialog('Add IOC to case', field('IOC value','value') + field('Case note','note','', 'textarea'),
                async form => { await json('POST', '/cases/' + state.caseId + '/iocs', Object.fromEntries(form.entries())); });
            if (name === 'unlink-ioc' && confirm('Unlink IOC from this case?')) {
                await api('/cases/' + state.caseId + '/iocs/' + id, { method: 'DELETE' }); return refresh(); }
            if (name === 'link-case') return dialog('Link related case', field('Other case numeric ID','related_id') + field('Reason','reason'),
                async form => { await json('POST', '/cases/' + state.caseId + '/relations',
                    { related_id: Number(form.get('related_id')), reason: form.get('reason') }); });
            if (name === 'unlink-case') { await api('/cases/' + state.caseId + '/relations/' + id, { method: 'DELETE' }); return refresh(); }
            if (name === 'upload-sample') return pane.querySelector('#ti-sample-file').click();
            if (name === 'link-sample') return dialog('Link Malware Repository sample', field('SHA256','sha256'),
                async form => { await api('/cases/' + state.caseId + '/samples/' + encodeURIComponent(form.get('sha256')), { method:'POST' }); });
            if (name === 'unlink-sample') { const [source, sha] = id.split(':');
                await api('/cases/' + state.caseId + '/samples/' + source + '/' + sha, { method:'DELETE' }); return refresh(); }
            if (name === 'download-sample') { const [source, sha] = id.split(':');
                const url = source === 'mwdb' ? `/api/ti/cases/${state.caseId}/mwdb/${sha}/download` :
                    `/api/ti/cases/${state.caseId}/samples/${sha}/download`;
                const response = await fetch(url); if (!response.ok) throw Error('Download unavailable');
                const blob = await response.blob(), link = document.createElement('a'); link.href = URL.createObjectURL(blob);
                link.download = source === 'mwdb' ? sha + '.bin' : sha + '.zip'; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 30000); return; }
            if (name === 'mwdb-settings') {
                dialog('Link MWDB sample', field('SHA256','sha256') +
                    '<button type="button" class="ti-btn" id="ti-mwdb-preview">Search MWDB</button><div id="ti-mwdb-result" class="ti-meta"></div>',
                    async form => { await api('/cases/' + state.caseId + '/mwdb/' + encodeURIComponent(form.get('sha256').trim()),{method:'POST'}); });
                document.getElementById('ti-mwdb-preview').onclick = async () => {
                    const output = document.getElementById('ti-mwdb-result');
                    try { const sha = document.querySelector('#ti-global-dialog input[name=sha256]').value.trim();
                        const result = await api('/mwdb/search/' + encodeURIComponent(sha));
                        output.textContent = [result.metadata.file_name, result.metadata.file_type, result.metadata.file_size + ' bytes'].filter(Boolean).join(' · ');
                    } catch (error) { output.textContent = error.message; }
                };
                return;
            }
            if (name === 'import') return dialog('Bulk IOC import', field('Paste one IOC per line','text','','textarea') +
                '<label class="ti-field">TXT or CSV file<input type="file" name="file" accept=".txt,.csv"></label>',
                async form => { const file = form.get('file'); if (!file?.size) form.delete('file');
                    const result = await api('/iocs/import',{method:'POST',body:form}); notice(`Imported ${result.imported} IOCs`); });
        } catch (error) { notice(error.message); }
    });
    pane.addEventListener('change', async event => {
        if (event.target.id !== 'ti-sample-file' || !event.target.files[0]) return;
        try { const body = new FormData(); body.append('file',event.target.files[0]);
            await api('/cases/' + state.caseId + '/samples',{method:'POST',body}); refresh(); }
        catch (error) { notice(error.message); }
    });
    fetch('/api/auth/me').then(r => r.ok ? r.json() : null).then(data => { state.role = data?.user?.role || 'analyst'; }).catch(() => {});

    async function lookupAndRender(wrapper, value, type) {
        if (!['ip','domain','url','hash','md5','sha1','sha256','email'].includes(type)) return;
        const params = new URLSearchParams({value, type});
        let match = null, error = '';
        try { match = (await api('/iocs/lookup?' + params)).match; }
        catch (exc) { error = exc.message; }
        if (!wrapper.isConnected) return;
        wrapper.querySelector('.ti-search-card')?.remove();
        const card = document.createElement('section');
        // Keep the internal result visible while external provider tabs switch cards.
        card.className = 'ti-search-card';
        card.innerHTML = `<div class="card-header"><h3><i class="fa-solid fa-folder-open"></i> Internal Threat Intelligence</h3></div>
          <div class="card-body"><div class="ti-row"><span>${error ? esc(error) : match ? `${esc(match.assessment)} · ${esc(match.confidence)} confidence` : 'No internal record'}</span>
          <button type="button" class="ti-btn primary ti-add-search">Add to TI Case</button></div>
          ${match ? `<p>${esc(match.description || 'No analyst notes')}</p><p class="ti-meta">First seen: ${esc(match.first_seen || '—')} · Last seen: ${esc(match.last_seen || '—')}</p>
             <div>${chips(match.tags)}</div><div>${match.related_cases.map(c => `<button class="ti-btn ti-open-case" data-id="${c.id}">${esc(c.name)}</button>`).join('')}</div>
             <div>${(match.references || []).map(r => `<span class="ti-mono">${esc(r)}</span>`).join('<br>')}</div>` : ''}</div>`;
        wrapper.insertBefore(card, wrapper.querySelector('.pending-intel-card') || null);
        card.querySelector('.ti-add-search').onclick = () => addFromSearch(value, type);
        card.querySelectorAll('.ti-open-case').forEach(button => button.onclick = () => {
            document.querySelector('.nav-item[data-tab="ti-cases"]')?.click();
            state.page = 'detail'; state.caseTab = 'overview'; caseView(button.dataset.id);
        });
    }
    async function addFromSearch(value, type) {
        try {
            const data = await api('/cases?limit=100');
            const options = data.items.map(c => `<option value="${c.id}">${esc(c.case_id + ' · ' + c.name)}</option>`).join('');
            dialog('Add to TI Case', `<label class="ti-field">Case<select name="case_id"><option value="">Create a new case</option>${options}</select></label>` +
                field('New case name (if creating)','name') + field('IOC value','value',value) +
                field('Notes for this case','note','','textarea') + field('References (one per line)','references','','textarea'),
                async form => {
                    const caseId = form.get('case_id') || (await json('POST','/cases',{name:form.get('name')})).id;
                    await json('POST','/cases/' + caseId + '/iocs', {value:form.get('value'), type, note:form.get('note'),
                        references:array(form.get('references'))});
                });
        } catch (error) { alert(error.message); }
    }
    async function configureMwdb() {
        try {
            const config = await api('/mwdb/config');
            dialog('MWDB connection', field('MWDB HTTPS URL','url',config.url) +
                field('API key (leave blank to keep saved key)','api_key','','password'),
                async form => { await json('PUT','/mwdb/config',Object.fromEntries(form.entries())); });
        } catch (error) { alert(error.message); }
    }
    document.getElementById('ti-mwdb-config')?.addEventListener('click', configureMwdb);
    window.tiCases = { open, lookupAndRender, configureMwdb };
})();
