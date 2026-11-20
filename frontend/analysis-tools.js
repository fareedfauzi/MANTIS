/* Analysis Tools installer: lives in Settings -> Analysis Tools (admin only).
 * Binary Lab and Similarity both use these tools, so the install lives in
 * Settings. Renders into #settings-analysis-tools-mount. */
(function () {
    const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[ch]));

    async function request(path, options = {}) {
        const response = await fetch(`${API_BASE}${path}`, options);
        const text = await response.text();
        let data = {};
        try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { detail: text }; }
        if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
        return data;
    }

    let toolsPollTimer = null;
    let lastData = null;

    const fmtMb = (bytes) => {
        const n = Number(bytes) || 0;
        return n >= 1024 * 1024 * 1024 ? `${(n / 1024 / 1024 / 1024).toFixed(2)} GB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
    };

    const toolStatusLabel = (item) => {
        if (item.installed && item.status !== 'downloading') return 'Installed';
        switch (item.status) {
            case 'queued': return 'Queued';
            case 'downloading': return item.total ? `Downloading ${fmtMb(item.downloaded)} of ${fmtMb(item.total)}` : `Downloading ${fmtMb(item.downloaded)}`;
            case 'verifying': return 'Verifying checksum';
            case 'extracting': return 'Extracting';
            case 'done': return 'Installed';
            case 'error': return `Failed: ${item.error}`;
            default: return item.installed ? 'Installed' : 'Not installed';
        }
    };

    const toolRowHtml = (item, locked) => {
        const pct = item.total ? Math.min(100, Math.round((item.downloaded / item.total) * 100)) : 0;
        const busy = ['downloading', 'verifying', 'extracting', 'queued'].includes(item.status);
        const width = item.status === 'done' || (item.installed && !busy) ? 100 : (busy && item.status !== 'downloading' ? 100 : pct);
        const bar = busy || item.status === 'error' ? `<div class="bl-progress"><div class="bl-progress-bar ${item.status === 'error' ? 'is-error' : ''} ${item.status !== 'downloading' && item.status !== 'error' ? 'is-indeterminate' : ''}" style="width:${width}%"></div></div>` : '';
        let action = '';
        if (item.source === 'pinned') {
            action = item.installed ? '' : `<button type="button" class="btn-secondary bl-tool-install" data-tool="${esc(item.id)}" ${locked ? 'disabled' : ''}><i class="fa-solid fa-download"></i> Install (${fmtMb(item.size)})</button>`;
        }
        return `<div class="bl-tool-row" data-tool-row="${esc(item.id)}">
            <div class="bl-tool-head"><strong>${esc(item.label)}</strong><span class="bl-tool-status">${esc(toolStatusLabel(item))}</span></div>
            <div class="bl-tool-meta">${esc(item.needed_by)}${item.source === 'pinned' ? ` · ${fmtMb(item.size)} download` : ''}</div>
            ${bar}
            ${action}
        </div>`;
    };

    const renderToolsCard = (data) => {
        const locked = !!data.running;
        const missing = data.tools.filter(t => t.source === 'pinned' && !t.installed).map(t => t.id);
        const rows = data.tools.filter(t => t.source === 'pinned').map(t => toolRowHtml(t, locked)).join('');
        const ida = data.tools.find(t => t.source === 'user_link' || t.source === 'local_locate');
        const idaBusy = ['downloading', 'extracting', 'queued'].includes(ida.status);
        const isWin = data.platform === 'windows';
        const idaBody = isWin ? `
                <div class="bl-tool-meta">${ida.location ? `Located: <code>${esc(ida.location)}</code>` : 'Not located yet. Point MANTIS at your existing IDA Pro installation folder (the one containing idat64.exe). Nothing is copied.'}</div>
                <div class="bl-tool-link"><button type="button" class="btn-secondary" id="bl-tools-ida-locate" ${locked ? 'disabled' : ''}><i class="fa-solid fa-folder-open"></i> ${ida.installed ? 'Change IDA folder' : 'Locate IDA Pro folder'}</button></div>`
            : `
                <div class="bl-tool-meta">Needs your licensed IDA Pro for Linux. Paste your personal https download link, or upload your own zip. It is placed in the tools folder.</div>
                ${idaBusy || ida.status === 'error' ? `<div class="bl-progress"><div class="bl-progress-bar ${ida.status === 'error' ? 'is-error' : ''} ${ida.status === 'downloading' ? '' : 'is-indeterminate'}" style="width:${ida.status === 'downloading' && ida.total ? Math.round(ida.downloaded / ida.total * 100) : 100}%"></div></div>` : ''}
                <div class="bl-tool-link"><input id="bl-tools-ida-url" type="url" placeholder="https://.../ida-pro-linux.zip" ${locked ? 'disabled' : ''}>
                <button type="button" class="btn-secondary" id="bl-tools-ida-install" ${locked ? 'disabled' : ''}><i class="fa-solid fa-download"></i> Download IDA</button></div>
                <div class="bl-tool-link"><span class="bl-tool-meta">or</span><input id="bl-tools-ida-file" type="file" accept=".zip,application/zip" ${locked ? 'disabled' : ''}>
                <button type="button" class="btn-secondary" id="bl-tools-ida-upload" ${locked ? 'disabled' : ''}><i class="fa-solid fa-upload"></i> Upload IDA zip</button></div>`;
        return `<section class="bl-card bl-card-wide" id="bl-tools-card"><div class="bl-card-head"><div><h2>Analysis Tools</h2><p>Download the runtimes and engines Binary Lab needs. Admin only. Disk free: ${fmtMb(data.disk_free)}.</p></div><i class="fa-solid fa-download"></i></div>
            <div class="bl-tools-list">${rows}</div>
            <div class="bl-tool-row" data-tool-row="ida">
                <div class="bl-tool-head"><strong>${esc(ida.label)}</strong><span class="bl-tool-status">${esc(ida.installed && !idaBusy ? 'Installed' : toolStatusLabel(ida))}</span></div>
                ${idaBody}
            </div>
            <div class="bl-tool-actions"><button type="button" class="btn-primary" id="bl-tools-install-missing" ${locked || !missing.length ? 'disabled' : ''}><i class="fa-solid fa-cloud-arrow-down"></i> Install all missing</button>
            <span class="bl-tool-error" id="bl-tools-error">${data.phase === 'error' ? 'Install stopped with an error; see the failed row.' : ''}</span></div>
        </section>`;
    };

    async function startToolsInstall(payload) {
        const err = document.getElementById('bl-tools-error');
        try {
            await request('/api/binary-lab/tools/install', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            if (err) err.textContent = '';
            await refreshToolsCard();
        } catch (e) {
            if (err) err.textContent = e.message;
        }
    }

    async function locateIdaFolder() {
        const err = document.getElementById('bl-tools-error');
        try {
            const currentPath = lastData?.tools?.find(t => t.id === 'ida')?.location || '';
            const current = currentPath ? currentPath.replace(/[\\/][^\\/]*$/, '') : '';
            const picked = await request(`/api/binary-lab/tools/ida-browse?initial=${encodeURIComponent(current)}`);
            if (picked.cancelled || !picked.path) return;
            const st = await request('/api/binary-lab/tools/ida-locate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: picked.path }) });
            if (err) err.textContent = '';
            const ida = (st.tools || []).find(t => t.id === 'ida');
            window.dispatchEvent(new CustomEvent('analysis-tools-changed', { detail: { ida_path: ida?.location || '' } }));
            await refreshToolsCard();
        } catch (e) {
            if (err) err.textContent = e.message;
        }
    }

    async function uploadIdaZip(file) {
        const err = document.getElementById('bl-tools-error');
        const form = new FormData();
        form.append('file', file, file.name);
        try {
            const response = await fetch(`${API_BASE}/api/binary-lab/tools/ida-upload`, { method: 'POST', body: form });
            const text = await response.text();
            let data = {};
            try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { detail: text }; }
            if (!response.ok) throw new Error(data.detail || `Upload failed (${response.status})`);
            if (err) err.textContent = '';
            await refreshToolsCard();
        } catch (e) {
            if (err) err.textContent = e.message;
        }
    }

    async function refreshToolsCard() {
        clearTimeout(toolsPollTimer);
        const mount = document.getElementById('settings-analysis-tools-mount');
        if (!mount) return;
        let data;
        try { data = await request('/api/binary-lab/tools'); } catch (e) {
            mount.innerHTML = `<section class="bl-card bl-card-wide"><div class="bl-card-head"><div><h2>Analysis Tools</h2><p>${esc(e.message)}</p></div></div></section>`;
            return;
        }
        lastData = data;
        mount.innerHTML = renderToolsCard(data);
        document.querySelectorAll('.bl-tool-install').forEach(btn => btn.addEventListener('click', () => startToolsInstall({ tools: [btn.dataset.tool] })));
        document.getElementById('bl-tools-install-missing')?.addEventListener('click', () => startToolsInstall({ tools: data.tools.filter(t => t.source === 'pinned' && !t.installed).map(t => t.id) }));
        document.getElementById('bl-tools-ida-locate')?.addEventListener('click', locateIdaFolder);
        document.getElementById('bl-tools-ida-upload')?.addEventListener('click', () => {
            const file = document.getElementById('bl-tools-ida-file')?.files?.[0];
            if (!file) { document.getElementById('bl-tools-error').textContent = 'Choose your IDA Pro for Linux .zip first.'; return; }
            uploadIdaZip(file);
        });
        document.getElementById('bl-tools-ida-install')?.addEventListener('click', () => {
            const url = document.getElementById('bl-tools-ida-url')?.value.trim();
            if (!url) { document.getElementById('bl-tools-error').textContent = 'Paste your IDA download link first.'; return; }
            startToolsInstall({ tools: [], ida_url: url });
        });
        if (data.running) toolsPollTimer = setTimeout(refreshToolsCard, 800);
    }


    window.refreshAnalysisTools = refreshToolsCard;
})();
