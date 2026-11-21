/* TI Case Manager. Shares the existing MANTIS navigation and IOC Search. */
(() => {
    const pane = document.getElementById('ti-cases-pane');
    if (!pane) return;
    const state = { page: 'cases', offset: 0, query: '', caseId: null, role: 'analyst', notesMode: 'split', notesEditing: false, noteDraft: null };
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

    function fallbackMarkdown(source) {
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
        text = text.replace(/^(?:[-*] .+(?:\n|$))+/gm, lines =>
            '<ul>' + lines.trim().split('\n').map(line => {
                const task = line.match(/^[-*] \[([ xX])\] (.*)$/);
                return task ? `<li><input type="checkbox" disabled ${task[1].toLowerCase() === 'x' ? 'checked' : ''}> ${task[2]}</li>`
                    : `<li>${line.slice(2)}</li>`;
            }).join('') + '</ul>');
        text = text.replace(/^###### (.+)$/gm, '<h6>$1</h6>').replace(/^##### (.+)$/gm, '<h5>$1</h5>')
            .replace(/^#### (.+)$/gm, '<h4>$1</h4>').replace(/^### (.+)$/gm, '<h3>$1</h3>')
            .replace(/^## (.+)$/gm, '<h2>$1</h2>').replace(/^# (.+)$/gm, '<h1>$1</h1>')
            .replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>')
            .replace(/^(?:---|\*\*\*)$/gm, '<hr>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/\*(.+?)\*/g, '<em>$1</em>')
            .replace(/~~(.+?)~~/g, '<del>$1</del>')
            .replace(/`([^`\n]+)`/g, '<code>$1</code>').replace(/\n/g, '<br>');
        return text.replace(/\u0001(\d+)\u0001/g, (_, i) => blocks[Number(i)]);
    }

    let markdownLoader;
    function loadMarkdown() {
        if (window.marked) return Promise.resolve();
        if (!markdownLoader) markdownLoader = new Promise(resolve => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/marked/marked.min.js';
            script.onload = resolve;
            script.onerror = resolve;
            document.head.appendChild(script);
        });
        return markdownLoader;
    }

    function markdown(source) {
        if (!window.marked) return fallbackMarkdown(source);
        // Marked handles GFM tables and fenced code; escaping first prevents raw HTML in case notes.
        const doc = new DOMParser().parseFromString(window.marked.parse(esc(source || ''), { gfm: true, breaks: true }), 'text/html');
        const allowed = new Set(['P','BR','H1','H2','H3','H4','H5','H6','UL','OL','LI','STRONG','EM','DEL',
            'BLOCKQUOTE','PRE','CODE','TABLE','THEAD','TBODY','TR','TH','TD','HR','A','IMG','INPUT']);
        function clean(node) {
            for (const child of [...node.childNodes]) {
                if (child.nodeType === Node.TEXT_NODE) continue;
                if (child.nodeType !== Node.ELEMENT_NODE || !allowed.has(child.tagName)) {
                    child.replaceWith(document.createTextNode(child.textContent || ''));
                    continue;
                }
                const href = child.tagName === 'A' ? child.getAttribute('href') : null;
                const src = child.tagName === 'IMG' ? child.getAttribute('src') : null;
                const alt = child.tagName === 'IMG' ? child.getAttribute('alt') : null;
                const codeClass = child.tagName === 'CODE' ? child.getAttribute('class') : null;
                const checked = child.tagName === 'INPUT' && child.hasAttribute('checked');
                for (const attribute of [...child.attributes]) child.removeAttribute(attribute.name);
                if (child.tagName === 'INPUT') {
                    child.type = 'checkbox'; child.disabled = true; child.checked = checked;
                }
                if (child.tagName === 'CODE' && /^language-[a-z0-9_-]{1,24}$/i.test(codeClass || '')) child.className = codeClass;
                if (child.tagName === 'IMG' && src) {
                    try {
                        const url = new URL(src);
                        if (url.protocol === 'https:') {
                            child.src = url.href; child.alt = alt || ''; child.loading = 'lazy';
                            child.referrerPolicy = 'no-referrer';
                        } else { child.remove(); continue; }
                    } catch { child.remove(); continue; }
                }
                if (child.tagName === 'A') {
                    if (href) {
                        try {
                            const url = new URL(href, location.origin);
                            if (['http:', 'https:'].includes(url.protocol)) {
                                child.href = url.href; child.target = '_blank'; child.rel = 'noopener noreferrer';
                            }
                        } catch {}
                    }
                }
                clean(child);
            }
        }
        clean(doc.body);
        return doc.body.innerHTML;
    }

    function frame(title, controls, body) {
        pane.innerHTML = `<div class="ti-shell"><header class="ti-head"><div><span class="ti-kicker">TEAM INTELLIGENCE</span>
            <h2>${esc(title)}</h2></div><div class="ti-actions">${controls}</div></header>
            <nav class="ti-workspace-nav" aria-label="TI Case Manager views">
                <button type="button" class="${state.page === 'cases' || state.page === 'detail' ? 'active' : ''}" data-action="view-page" data-id="cases"><i class="fa-solid fa-folder-open"></i> Cases</button>
                <button type="button" class="${state.page === 'iocs' ? 'active' : ''}" data-action="view-page" data-id="iocs"><i class="fa-solid fa-list-check"></i> IOC Registry</button>
            </nav>
            <div class="ti-notice" role="status">${esc(state.flash || '')}</div>${body}</div>`;
        state.flash = '';
    }

    async function cases() {
        const params = new URLSearchParams({ q: state.query, status: state.status || '', tag: state.tag || '',
            limit: '50', offset: String(state.offset) });
        const data = await api('/cases?' + params);
        if (state.page !== 'cases') return;
        frame('Cases', action('New case', 'new-case', '', 'primary'), `
          <div class="ti-toolbar"><input id="ti-search" placeholder="Search case ID, name or IOC" value="${esc(state.query)}">
          <select id="ti-status"><option value="">All statuses</option>${['Open','Investigating','Closed'].map(s =>
            `<option ${state.status === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
          <input id="ti-tag" placeholder="Tag" value="${esc(state.tag || '')}">
          ${action('Search', 'search')}</div>
          <div class="ti-table-wrap"><table><thead><tr><th>Case ID</th><th>Case name</th><th>Status</th><th>Tags</th><th>IOCs</th><th>Created by</th><th>Updated</th><th></th></tr></thead>
          <tbody>${data.items.map(c => `<tr><td class="ti-mono">${esc(c.case_id)}</td><td><strong>${esc(c.name)}</strong></td>
          <td><span class="ti-status">${esc(c.status)}</span></td><td>${chips(c.tags)}</td><td>${c.ioc_count}</td>
          <td>${esc(c.created_by)}</td><td>${date(c.updated_at)}</td><td>${action('Open','view-case',c.id)}</td></tr>`).join('') || rowEmpty('No cases found')}</tbody></table></div>
          <div class="ti-pagination">${action('Previous','previous', '', state.offset ? '' : 'disabled')} <span>${data.total} cases${data.total ? ` · ${state.offset + 1}-${Math.min(state.offset + 50, data.total)}` : ''}</span>
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
        state.case = c;
        const noteEditor = state.notesEditing
            ? `<div class="ti-note-tools"><div class="ti-format">
                ${[['bold','Bold'],['italic','Italic'],['heading','Heading'],['list','List'],['quote','Quote'],['link','Link'],
                    ['image','Image'],['code','Code block'],['table','Table'],['strike','Strike'],['rule','Rule']].map(([key,label]) =>
                    `<button type="button" class="ti-btn" data-mark="${key}">${label}</button>`).join('')}
                </div><div class="ti-view-switch">${['write','split','preview'].map(mode => `<button type="button" data-action="notes-mode" data-id="${mode}" class="${state.notesMode === mode ? 'active' : ''}">${mode}</button>`).join('')}</div></div>
                <div class="ti-note-workspace ti-mode-${state.notesMode}">
                    <textarea id="ti-notes-input" spellcheck="false" placeholder="Write investigation notes in Markdown…">${esc(state.noteDraft ?? c.notes ?? '')}</textarea>
                    <div class="ti-markdown ti-note-preview"></div>
                </div><div class="ti-editor-footer"><span>Markdown: headings, lists, tables, links, and fenced code</span><div>${action('Cancel','cancel-notes')} ${action('Save notes','save-notes','','primary')}</div></div>`
            : '<div class="ti-markdown ti-note-preview"></div>';
        frame(`${c.case_id} · ${c.name}`, action('Back to cases','back') + action('Edit details','edit-case') +
            (state.role === 'admin' ? action('Delete case','delete-case','','danger') : ''),
            `<div class="ti-case-meta"><span class="ti-status">${esc(c.status)}</span><span>Created by ${esc(c.created_by)} · ${date(c.created_at)}</span><span>Updated by ${esc(c.updated_by)} · ${date(c.updated_at)}</span><div>${chips(c.tags)}</div></div>
            <section class="ti-card"><div class="ti-row"><h3>Investigation notes</h3>${state.notesEditing ? '' : action('Edit notes','edit-notes')}</div>
                <p class="ti-description">${esc(c.description || 'Add a short description of this investigation.')}</p>${noteEditor}</section>
            <section class="ti-card"><div class="ti-row"><div><h3>Indicators <span class="ti-count">${c.iocs.length}</span></h3><p class="ti-section-hint">Shared IOC records with notes specific to this case</p></div>
                <div>${action('Bulk add','import-case')} ${action('Add IOC','add-case-ioc','','primary')}</div></div>
                <div class="ti-table-wrap"><table><thead><tr><th>Value</th><th>Type</th><th>Assessment</th><th>Confidence</th><th>Case note</th><th></th></tr></thead>
                <tbody>${c.iocs.map(i => `<tr><td class="ti-mono ti-value">${esc(i.value)}</td><td>${esc(i.type)}</td><td>${esc(i.assessment)}</td><td>${esc(i.confidence)}</td><td>${esc(i.note || '—')}</td><td class="ti-cell-actions">${action('Case note','edit-ioc-note',i.id)} ${action('Edit IOC','edit-ioc',i.id)} ${action('Unlink','unlink-ioc',i.id)}</td></tr>`).join('') || '<tr><td colspan="6" class="ti-empty">No indicators linked. Add one or paste a list.</td></tr>'}</tbody></table></div></section>
            <section class="ti-card"><div class="ti-row"><div><h3>Malware samples <span class="ti-count">${c.samples.length}</span></h3></div>
                <div>${action('Upload','upload-sample')} ${action('Link repository hash','link-sample')} ${action('Link MWDB sample','mwdb-settings')}</div></div>
                <input type="file" id="ti-sample-file" hidden><div class="ti-table-wrap"><table><thead><tr><th>SHA256</th><th>File</th><th>Source</th><th>Size</th><th></th></tr></thead>
                <tbody>${c.samples.map(s => `<tr><td class="ti-mono ti-value">${esc(s.sha256)}</td><td>${esc(s.filename)}</td><td>${esc(s.source)}</td><td>${esc(s.size)}</td>
                <td class="ti-cell-actions">${action('Download','download-sample',s.source + ':' + s.sha256)} ${action('Unlink','unlink-sample',s.source + ':' + s.sha256)}</td></tr>`).join('') || '<tr><td colspan="5" class="ti-empty">No samples linked.</td></tr>'}</tbody></table></div></section>
            <div class="ti-detail-grid">
                <section class="ti-card"><div class="ti-row"><h3>MITRE ATT&CK TTPs</h3>${action('Edit','edit-ttps')}</div><div class="ti-tags">${chips(c.ttps)}</div></section>
                <section class="ti-card"><div class="ti-row"><h3>References</h3>${action('Edit','edit-references')}</div>
                    <ul class="ti-references">${c.references.map(v => `<li>${/^https?:\/\//i.test(v) ? `<a href="${esc(v)}" target="_blank" rel="noopener noreferrer">${esc(v)}</a>` : esc(v)}</li>`).join('') || '<li>No references yet.</li>'}</ul></section>
            </div>
            <section class="ti-card"><div class="ti-row"><h3>Related cases</h3>${action('Link case','link-case')}</div>
                ${c.related_cases.map(r => `<div class="ti-related-row"><button class="ti-related-link" type="button" data-action="view-case" data-id="${r.id}">${esc(r.name)}</button><span>${esc(r.reason)}</span>${action('Unlink','unlink-case',r.id)}</div>`).join('') || '<p class="ti-section-hint">No related cases.</p>'}</section>
            <details class="ti-activity"><summary>Activity history</summary>
                ${c.activity.map(a => `<p class="ti-meta">${date(a.created_at)} · ${esc(a.actor)} · ${esc(a.action)} ${esc(a.details)}</p>`).join('') || '<p>No activity recorded.</p>'}</details>`);
        renderNotesPreview();
        loadMarkdown().then(() => { if (state.page === 'detail' && state.caseId === c.id) renderNotesPreview(); });
        const editor = pane.querySelector('#ti-notes-input'), preview = pane.querySelector('.ti-note-preview');
        if (editor && preview) {
            let syncing = false;
            const sync = (from, to) => {
                if (syncing) return;
                syncing = true;
                const range = from.scrollHeight - from.clientHeight;
                to.scrollTop = (range ? from.scrollTop / range : 0) * (to.scrollHeight - to.clientHeight);
                requestAnimationFrame(() => { syncing = false; });
            };
            editor.addEventListener('scroll', () => sync(editor, preview));
            preview.addEventListener('scroll', () => sync(preview, editor));
        }
    }

    let mermaidLoader, mermaidSequence = 0;
    function loadMermaid() {
        if (window.mermaid) return Promise.resolve(true);
        if (!mermaidLoader) mermaidLoader = new Promise(resolve => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js';
            script.onload = () => resolve(true);
            script.onerror = () => resolve(false);
            document.head.appendChild(script);
        });
        return mermaidLoader;
    }
    async function renderMermaid(preview, sequence) {
        const diagrams = [...preview.querySelectorAll('pre code.language-mermaid')];
        if (!diagrams.length || !await loadMermaid() || sequence !== mermaidSequence) return;
        window.mermaid.initialize({startOnLoad: false, theme: 'dark', securityLevel: 'strict'});
        for (const [index, block] of diagrams.entries()) {
            if (sequence !== mermaidSequence || !block.isConnected) return;
            try {
                const {svg} = await window.mermaid.render('ti_mermaid_' + sequence + '_' + index, block.textContent);
                if (sequence !== mermaidSequence || !block.isConnected) return;
                const container = document.createElement('div');
                container.className = 'ti-diagram';
                container.innerHTML = svg;
                block.closest('pre').replaceWith(container);
            } catch { /* Keep the original code block when a diagram is invalid. */ }
        }
    }
    function renderNotesPreview() {
        const preview = pane.querySelector('.ti-note-preview');
        if (!preview) return;
        preview.innerHTML = markdown(pane.querySelector('#ti-notes-input')?.value ?? state.case?.notes ?? '') || '<p class="ti-section-hint">No investigation notes yet.</p>';
        const sequence = ++mermaidSequence;
        if (window.hljs) preview.querySelectorAll('pre code:not(.language-mermaid)').forEach(block => {
            try { window.hljs.highlightElement(block); } catch {}
        });
        renderMermaid(preview, sequence);
    }

    function dialog(title, fields, submit) {
        let dlg = document.getElementById('ti-global-dialog');
        if (!dlg) { dlg = document.createElement('dialog'); dlg.id = 'ti-global-dialog'; dlg.className = 'ti-dialog'; document.body.appendChild(dlg); }
        dlg.innerHTML = `<form id="ti-form"><header><h3>${esc(title)}</h3><button type="button" class="ti-dialog-close" aria-label="Close">&times;</button></header>
            <div class="ti-dialog-body">${fields}</div><p class="ti-dialog-error" role="alert"></p>
            <footer><button type="button" class="ti-btn ti-cancel">Cancel</button><button type="submit" class="ti-btn primary">Save</button></footer></form>`;
        dlg.showModal();
        const caseFilter = dlg.querySelector('.ti-case-filter');
        if (caseFilter) {
            let revision = 0;
            caseFilter.addEventListener('keydown', event => { if (event.key === 'Enter') event.preventDefault(); });
            caseFilter.addEventListener('input', async () => {
                const current = ++revision, query = caseFilter.value.trim();
                try {
                    const result = await api('/cases?' + new URLSearchParams({q: query, limit: '100'}));
                    if (current !== revision || !dlg.open) return;
                    const select = dlg.querySelector('.ti-case-select');
                    const previous = select.value, exclude = Number(select.dataset.exclude);
                    select.innerHTML = (select.dataset.allowNew ? '<option value="">Create a new case</option>' : '<option value="">Select a case</option>') +
                        result.items.filter(c => c.id !== exclude).map(c =>
                            `<option value="${c.id}">${esc(c.case_id + ' · ' + c.name)}</option>`).join('');
                    select.value = previous;
                    if (select.selectedIndex < 0) select.selectedIndex = 0;
                } catch (error) { dlg.querySelector('.ti-dialog-error').textContent = error.message; }
            });
        }
        dlg.querySelectorAll('.ti-dialog-close, .ti-cancel').forEach(button => button.addEventListener('click', () => dlg.close()));
        dlg.querySelector('form').addEventListener('submit', async event => {
            event.preventDefault();
            const button = dlg.querySelector('button[type="submit"]'); button.disabled = true;
            try { await submit(new FormData(event.target)); dlg.close(); await refresh(); }
            catch (error) { dlg.querySelector('.ti-dialog-error').textContent = error.message; button.disabled = false; }
        });
    }
    const field = (label, name, value = '', kind = 'text') =>
        `<label class="ti-field">${esc(label)}${kind === 'textarea'
            ? `<textarea name="${name}">${esc(value)}</textarea>`
            : `<input name="${name}" type="${kind}" value="${esc(value)}">`}</label>`;
    const casePicker = (items, name = 'case_id', exclude = 0, allowNew = false) =>
        `<label class="ti-field">Find case<input type="search" class="ti-case-filter" placeholder="Search by name or TI-000001"></label>
        <label class="ti-field">Case<select class="ti-case-select" data-exclude="${exclude}" ${allowNew ? 'data-allow-new="true"' : 'required'} name="${name}">
        <option value="">${allowNew ? 'Create a new case' : 'Select a case'}</option>
        ${items.filter(c => c.id !== exclude).map(c =>
            `<option value="${c.id}">${esc(c.case_id + ' · ' + c.name)}</option>`).join('')}</select></label>`;
    function caseForm(c) {
        dialog(c ? 'Edit case details' : 'New case', field('Case name','name',c?.name || '') +
            field('Description','description',c?.description || '', 'textarea') +
            `<label class="ti-field">Status<select name="status">${['Open','Investigating','Closed'].map(v =>
                `<option ${c?.status === v ? 'selected' : ''}>${v}</option>`).join('')}</select></label>` +
            field('Tags (comma separated)','tags',list(c?.tags)),
            async form => {
                const body = Object.fromEntries(form.entries());
                body.tags = array(body.tags);
                const result = await json(c ? 'PATCH' : 'POST', c ? '/cases/' + c.id : '/cases', body);
                state.caseId = result.id; state.page = 'detail';
            });
    }
    function iocForm(i) {
        dialog(i ? 'Edit IOC' : 'New IOC', field('IOC value','value',i?.value || '') +
            `<label class="ti-field">Type<select name="type">${['auto','ip','domain','url','md5','sha1','sha256','email','filename','mutex','registry','other'].map(kind =>
                `<option value="${kind}" ${(i?.type || 'auto') === kind ? 'selected' : ''}>${kind === 'auto' ? 'Detect automatically' : kind}</option>`).join('')}</select></label>` +
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
    function open(page = 'cases') { state.page = page; state.caseId = null; state.notesEditing = false; state.noteDraft = null; state.offset = 0; state.query = ''; refresh(); }

    pane.addEventListener('input', event => {
        if (event.target.id === 'ti-notes-input') { state.noteDraft = event.target.value; renderNotesPreview(); }
    });
    pane.addEventListener('keydown', event => {
        if (event.key === 'Enter' && event.target.id === 'ti-search') {
            event.preventDefault(); pane.querySelector('[data-action="search"]')?.click();
        }
        if (event.key === 'Tab' && event.target.id === 'ti-notes-input') {
            event.preventDefault();
            const start = event.target.selectionStart;
            event.target.setRangeText('    ', start, event.target.selectionEnd, 'end');
            state.noteDraft = event.target.value; renderNotesPreview();
        }
    });
    pane.addEventListener('click', async event => {
        const format = event.target.closest('[data-mark]');
        if (format) {
            const box = pane.querySelector('#ti-notes-input');
            if (!box) return;
            const snippets = {
                bold: ['**','**','bold text'], italic: ['*','*','italic text'],
                heading: ['## ','','Heading'], link: ['[','](https://example.com)','link text'],
                code: ['```\n','\n```','code'], table: ['| Column | Column |\n| --- | --- |\n| ',' | value |','value'],
                list: ['- ','','item'], quote: ['> ','','quoted text'], strike: ['~~','~~','text'],
                image: ['![','](https://example.com/image.png)','alt text'],
                rule: ['\n---\n','','']
            };
            const [before, after, example] = snippets[format.dataset.mark] || ['', '', ''];
            const start = box.selectionStart, end = box.selectionEnd;
            const value = box.value.slice(start, end) || example;
            box.setRangeText(before + value + after, start, end, 'end');
            box.setSelectionRange(start + before.length, start + before.length + value.length);
            box.focus(); state.noteDraft = box.value; renderNotesPreview();
            return;
        }
        const button = event.target.closest('[data-action]');
        if (!button || button.classList.contains('disabled')) return;
        const { action: name, id } = button.dataset;
        try {
            if (name === 'search') { state.query = pane.querySelector('#ti-search')?.value || ''; state.status = pane.querySelector('#ti-status')?.value || '';
                state.type = pane.querySelector('#ti-type')?.value || ''; state.assessment = pane.querySelector('#ti-assessment')?.value || '';
                state.tag = pane.querySelector('#ti-tag')?.value || ''; state.offset = 0; return refresh(); }
            if (name === 'previous' || name === 'next') { state.offset += name === 'next' ? 50 : -50; return refresh(); }
            if (name === 'retry') return refresh();
            if (name === 'view-page') {
                state.page = id; state.notesEditing = false; state.noteDraft = null; state.caseId = null;
                state.offset = 0; state.query = ''; state.tag = ''; state.status = ''; state.type = ''; state.assessment = '';
                return refresh();
            }
            if (name === 'back') { state.page = 'cases'; state.caseId = null; state.notesEditing = false; state.noteDraft = null; return refresh(); }
            if (name === 'view-case') { state.page = 'detail'; state.notesEditing = false; state.noteDraft = null; return caseView(id); }
            if (name === 'edit-notes') { state.notesEditing = true; return caseView(state.caseId); }
            if (name === 'cancel-notes') { state.notesEditing = false; state.noteDraft = null; return caseView(state.caseId); }
            if (name === 'notes-mode') {
                state.notesMode = id;
                const editor = pane.querySelector('.ti-note-workspace');
                editor.className = 'ti-note-workspace ti-mode-' + id;
                pane.querySelectorAll('.ti-view-switch button').forEach(tab => tab.classList.toggle('active', tab.dataset.id === id));
                return renderNotesPreview();
            }
            if (name === 'save-notes') {
                const notes = pane.querySelector('#ti-notes-input').value;
                await json('PATCH', '/cases/' + state.caseId, {notes});
                state.notesEditing = false;
                state.noteDraft = null;
                return refresh();
            }
            if (name === 'new-case') return caseForm();
            if (name === 'edit-case') return caseForm(state.case);
            if (name === 'new-ioc') return iocForm();
            if (name === 'edit-ioc') return iocForm(await api('/iocs/' + id));
            if (name === 'edit-ioc-note') {
                const linked = state.case.iocs.find(i => i.id === Number(id));
                return dialog('Case note · ' + linked.value, field('Note for this case only','note',linked.note,'textarea'),
                    async form => { await json('PUT', '/cases/' + state.caseId + '/iocs/' + id + '/note',
                        {note: form.get('note')}); });
            }
            if (name === 'link-ioc-case') {
                const available = await api('/cases?limit=100');
                return dialog('Link IOC to case', casePicker(available.items, 'case_id') +
                    field('Case note','note','','textarea'), async form => {
                    await json('POST','/cases/' + form.get('case_id') + '/iocs',{ioc_id:Number(id),note:form.get('note')});
                });
            }
            if (name === 'delete-ioc' && confirm('Delete this IOC from the shared registry and all linked cases?')) {
                await api('/iocs/' + id, { method: 'DELETE' }); return refresh(); }
            if (name === 'delete-case' && confirm('Delete this case? Shared IOCs and samples remain in their repositories.')) {
                await api('/cases/' + state.caseId, { method: 'DELETE' }); state.page = 'cases'; return refresh(); }
            if (name === 'add-case-ioc') return dialog('Link an indicator', field('IOC value','value') +
                '<p class="ti-help">An existing IOC is linked automatically. Its global assessment stays intact.</p>' +
                field('Description for a new IOC (optional)','description','','textarea') +
                `<div class="ti-form-grid"><label class="ti-field">Assessment<select name="assessment">
                    ${['Unknown','Malicious','Suspicious','Benign'].map(value => `<option>${value}</option>`).join('')}</select></label>
                    <label class="ti-field">Confidence<select name="confidence">
                    ${['Low','Medium','High'].map(value => `<option>${value}</option>`).join('')}</select></label></div>` +
                field('Note for this case (optional)','note','', 'textarea'),
                async form => { await json('POST', '/cases/' + state.caseId + '/iocs', Object.fromEntries(form.entries())); });
            if (name === 'import-case' || name === 'import') {
                const caseId = name === 'import-case' ? state.caseId : null;
                return dialog(caseId ? 'Bulk add indicators to this case' : 'Bulk import indicators',
                    '<p class="ti-help">Paste one IOC per line, or upload TXT/CSV. Existing records are reused.</p>' +
                    field('Indicators','text','','textarea') +
                    '<label class="ti-field">TXT or CSV file<input type="file" name="file" accept=".txt,.csv"></label>',
                    async form => {
                        if (!form.get('file')?.size) form.delete('file');
                        if (caseId) form.set('case_id', String(caseId));
                        const result = await api('/iocs/import',{method:'POST',body:form});
                        const count = result.rejected?.length || 0;
                        state.flash = `${result.imported} indicators ${caseId ? 'linked to this case' : 'imported'}${count ? `; ${count} rejected` : ''}.`;
                    });
            }
            if (name === 'unlink-ioc' && confirm('Unlink IOC from this case?')) {
                await api('/cases/' + state.caseId + '/iocs/' + id, { method: 'DELETE' }); return refresh(); }
            if (name === 'link-case') {
                const available = await api('/cases?limit=100');
                return dialog('Link related case', casePicker(available.items, 'related_id', state.caseId) + field('Reason','reason'),
                async form => { await json('POST', '/cases/' + state.caseId + '/relations',
                    { related_id: Number(form.get('related_id')), reason: form.get('reason') }); });
            }
            if (name === 'edit-ttps' || name === 'edit-references') {
                const isTtp = name === 'edit-ttps';
                return dialog(isTtp ? 'Edit MITRE ATT&CK TTPs' : 'Edit references',
                    field(isTtp ? 'Technique IDs (one per line)' : 'Reference URLs (one per line)',
                        'items', (isTtp ? state.case.ttps : state.case.references).join('\n'), 'textarea'),
                    async form => {
                        await json('PATCH', '/cases/' + state.caseId,
                            {[isTtp ? 'ttps' : 'references']: array(form.get('items'))});
                    });
            }
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
          ${match ? `<p>${esc(match.description || 'No global analyst description')}</p><p class="ti-meta">First seen: ${esc(match.first_seen || '-')} · Last seen: ${esc(match.last_seen || '-')}</p>
             <div>${chips(match.tags)}</div><div>${match.related_cases.map(c => `<div class="ti-search-related"><button class="ti-btn ti-open-case" data-id="${c.id}">${esc(c.name)}</button>${c.note ? `<span>${esc(c.note)}</span>` : ''}</div>`).join('')}</div>
             <div class="ti-search-refs">${(match.references || []).map(r => /^https?:\/\//i.test(r) ?
                `<a href="${esc(r)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a>` : `<span class="ti-mono">${esc(r)}</span>`).join('')}</div>` : ''}</div>`;
        wrapper.insertBefore(card, wrapper.querySelector('.pending-intel-card') || null);
        card.querySelector('.ti-add-search').onclick = () => addFromSearch(value, type, wrapper);
        card.querySelectorAll('.ti-open-case').forEach(button => button.onclick = () => {
            document.querySelector('.nav-item[data-tab="ti-cases"]')?.click();
            state.page = 'detail'; state.notesEditing = false; state.noteDraft = null; caseView(button.dataset.id);
        });
    }
    async function addFromSearch(value, type, wrapper) {
        try {
            const data = await api('/cases?limit=100');
            dialog('Add to TI Case', casePicker(data.items, 'case_id', 0, true) +
                field('New case name (if creating)','name') + field('IOC value','value',value) +
                field('Notes for this case','note','','textarea') + field('References (one per line)','references','','textarea'),
                async form => {
                    const caseId = form.get('case_id') || (await json('POST','/cases',{name:form.get('name')})).id;
                    await json('POST','/cases/' + caseId + '/iocs', {value:form.get('value'), type, note:form.get('note'),
                        references:array(form.get('references'))});
                    await lookupAndRender(wrapper, value, type);
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
