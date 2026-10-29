(() => {
    const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
    const MAX_HASHES = 50;

    const escapeText = (value) => String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    const hashType = (hash) => ({ 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' }[hash.length] || 'Unknown');
    const pause = (milliseconds) => new Promise(resolve => setTimeout(resolve, milliseconds));

    const createDownloader = (config) => {
        const id = (suffix) => `${config.prefix}-${suffix}`;
        const byId = (suffix) => document.getElementById(id(suffix));
        let directoryHandle = null;
        let bound = false;
        let running = false;
        let records = new Map();

        const parseHashes = () => {
            const tokens = (byId('hashes')?.value || '')
                .split(/[\s,;]+/)
                .map(value => value.trim().toLowerCase())
                .filter(Boolean);
            const unique = [...new Set(tokens)];
            const allValid = unique.filter(value => HASH_RE.test(value));
            return {
                valid: allValid.slice(0, MAX_HASHES),
                invalid: unique.filter(value => !HASH_RE.test(value)),
                overLimit: allValid.length > MAX_HASHES,
            };
        };

        const updateStartState = () => {
            const start = byId('start');
            if (!start) return;
            const parsed = parseHashes();
            const consent = !!byId('consent')?.checked;
            start.disabled = running || !directoryHandle || !consent || !parsed.valid.length || parsed.invalid.length > 0 || parsed.overLimit;
        };

        const updateInputSummary = () => {
            const summary = byId('input-summary');
            if (!summary) return;
            const parsed = parseHashes();
            const parts = [`${parsed.valid.length} valid hash${parsed.valid.length === 1 ? '' : 'es'}`];
            if (parsed.invalid.length) parts.push(`${parsed.invalid.length} invalid`);
            if (parsed.overLimit) parts.push(`maximum ${MAX_HASHES} per batch`);
            summary.textContent = parts.join(' · ');
            summary.classList.toggle('has-error', parsed.invalid.length > 0 || parsed.overLimit);
            updateStartState();
        };

        const statusLabel = (status) => ({
            queued: 'Queued',
            processing: 'Downloading',
            success: 'Success',
            failed: 'Failed',
        }[status] || status);

        const renderTable = () => {
            const body = byId('table-body');
            const counts = byId('counts');
            if (!body || !counts) return;
            const rows = [...records.values()];
            if (!rows.length) {
                body.innerHTML = '<tr><td colspan="4" class="samples-downloader-empty">No download attempts yet.</td></tr>';
                counts.textContent = 'Waiting for input';
                byId('copy-failed').disabled = true;
                byId('copy-success').disabled = true;
                return;
            }
            body.innerHTML = rows.map(row => `
                <tr>
                    <td><code>${escapeText(row.hash)}</code></td>
                    <td>${escapeText(row.type)}</td>
                    <td><span class="samples-download-status" data-state="${escapeText(row.status)}">${escapeText(statusLabel(row.status))}</span></td>
                    <td>${escapeText(row.detail || '')}</td>
                </tr>
            `).join('');
            const success = rows.filter(row => row.status === 'success').length;
            const failed = rows.filter(row => row.status === 'failed').length;
            const active = rows.filter(row => row.status === 'processing' || row.status === 'queued').length;
            byId('copy-failed').disabled = failed === 0;
            byId('copy-success').disabled = success === 0;
            counts.textContent = `${success} successful · ${failed} failed · ${active} pending`;
        };

        const copyResults = async (status) => {
            const hashes = [...records.values()]
                .filter(row => row.status === status)
                .map(row => row.hash);
            if (!hashes.length) return;
            try {
                await navigator.clipboard.writeText(hashes.join('\n'));
                showNotification(`Copied ${hashes.length} ${status} hash${hashes.length === 1 ? '' : 'es'}.`);
            } catch (error) {
                showNotification(`Could not copy results: ${error.message}`);
            }
        };

        const setRecord = (hash, status, detail) => {
            records.set(hash, { hash, type: hashType(hash), status, detail });
            renderTable();
        };

        const responseError = async (response) => {
            const payload = await response.json().catch(() => ({}));
            const detail = payload.detail;
            if (typeof detail === 'string') return detail;
            if (detail && typeof detail === 'object') return detail.message || JSON.stringify(detail);
            return `Download failed (HTTP ${response.status})`;
        };

        const saveBlob = async (filename, blob) => {
            if (!directoryHandle) throw new Error('Select a destination folder first.');
            if (directoryHandle.queryPermission) {
                let permission = await directoryHandle.queryPermission({ mode: 'readwrite' });
                if (permission !== 'granted' && directoryHandle.requestPermission) {
                    permission = await directoryHandle.requestPermission({ mode: 'readwrite' });
                }
                if (permission !== 'granted') throw new Error('Write permission to the destination folder was denied.');
            }
            const fileHandle = await directoryHandle.getFileHandle(filename, { create: true });
            const writable = await fileHandle.createWritable();
            try {
                await writable.write(blob);
                await writable.close();
            } catch (error) {
                await writable.abort().catch(() => {});
                throw error;
            }
        };

        const directPayload = (hash) => config.requiresKey
            ? { file_hash: hash, vt_key: localStorage.getItem('ioc_vt_key') || '' }
            : { file_hash: hash };

        const downloadDirect = async (hashes) => {
            let cursor = 0;
            let fatal = '';
            const worker = async () => {
                while (cursor < hashes.length) {
                    if (fatal) {
                        const skipped = hashes[cursor++];
                        setRecord(skipped, 'failed', `Skipped: ${fatal}`);
                        continue;
                    }
                    const hash = hashes[cursor++];
                    setRecord(hash, 'processing', `Requesting sample from ${config.provider}`);
                    try {
                        const response = await fetch(`${API_BASE}${config.directEndpoint}`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(directPayload(hash)),
                        });
                        if (!response.ok) {
                            const message = await responseError(response);
                            if ([401, 403, 429].includes(response.status)) fatal = message;
                            throw new Error(message);
                        }
                        const blob = await response.blob();
                        await saveBlob(`${hash}.bin`, blob);
                        setRecord(hash, 'success', `${blob.size.toLocaleString()} bytes saved`);
                    } catch (error) {
                        setRecord(hash, 'failed', error.message || 'Sample missing or unavailable');
                    }
                }
            };
            const workerCount = Math.min(2, hashes.length);
            await Promise.all(Array.from({ length: workerCount }, () => worker()));
        };

        const archiveFilename = (response) => {
            const disposition = response.headers.get('Content-Disposition') || '';
            const match = disposition.match(/filename="?([^";]+)"?/i);
            if (match) return match[1];
            const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '_');
            return `${config.archivePrefix}_samples_${stamp}.zip`;
        };

        const downloadZip = async (hashes) => {
            if (hashes[0]) setRecord(hashes[0], 'processing', 'Building encrypted archive');
            const payload = { hashes, password: 'infected' };
            if (config.requiresKey) payload.vt_key = localStorage.getItem('ioc_vt_key') || '';
            const response = await fetch(`${API_BASE}${config.zipEndpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!response.ok) {
                const errorPayload = await response.json().catch(() => ({}));
                const detail = errorPayload.detail;
                const failedRows = Array.isArray(detail?.failed) ? detail.failed : [];
                if (failedRows.length) {
                    const failedMap = new Map(failedRows.map(([hash, status]) => [hash, Number(status || 0)]));
                    for (const hash of hashes) {
                        setRecord(hash, 'processing', `Checking sample in ${config.provider}`);
                        await pause(120);
                        const status = failedMap.get(hash);
                        const message = status === 404
                            ? `Sample missing in ${config.provider}`
                            : `${config.provider} download failed (HTTP ${status || 'unknown'})`;
                        setRecord(hash, 'failed', message);
                    }
                }
                const error = new Error(typeof detail === 'string' ? detail : (detail?.message || `Download failed (HTTP ${response.status})`));
                error.recordsUpdated = failedRows.length > 0;
                throw error;
            }

            const failedPairs = (response.headers.get(config.failedHeader) || '')
                .split(';')
                .filter(Boolean)
                .map(value => value.split(':'));
            const failed = new Map(failedPairs.map(([hash, status]) => [hash, Number(status || 0)]));
            const blob = await response.blob();
            await saveBlob(archiveFilename(response), blob);

            for (const hash of hashes) {
                setRecord(hash, 'processing', `Finalizing sample from ${config.provider}`);
                await pause(120);
                if (failed.has(hash)) {
                    const status = failed.get(hash);
                    setRecord(hash, 'failed', status === 404 ? `Sample missing in ${config.provider}` : `${config.provider} download failed (HTTP ${status || 'unknown'})`);
                } else {
                    setRecord(hash, 'success', 'Added to encrypted ZIP (password: infected)');
                }
            }
        };

        const startDownload = async () => {
            if (running) return;
            const parsed = parseHashes();
            if (!directoryHandle || !parsed.valid.length || parsed.invalid.length || parsed.overLimit) return;

            running = true;
            records = new Map(parsed.valid.map(hash => [hash, { hash, type: hashType(hash), status: 'queued', detail: 'Waiting' }]));
            renderTable();
            updateStartState();
            const progress = byId('progress');
            if (progress) progress.textContent = 'Download in progress. Do not close this page.';

            try {
                const mode = document.querySelector(`input[name="${config.modeName}"]:checked`)?.value || 'direct';
                if (mode === 'zip') await downloadZip(parsed.valid);
                else await downloadDirect(parsed.valid);
                const failures = [...records.values()].filter(row => row.status === 'failed').length;
                showNotification(failures ? `Download finished with ${failures} failed sample(s).` : 'All samples downloaded successfully.');
            } catch (error) {
                if (!error.recordsUpdated) {
                    records.forEach((row, hash) => {
                        if (row.status !== 'success') setRecord(hash, 'failed', error.message || 'Download failed');
                    });
                }
                showNotification(`${config.provider} download error: ${error.message}`, 7000);
            } finally {
                running = false;
                if (progress) progress.textContent = '';
                updateStartState();
            }
        };

        const selectFolder = async () => {
            if (!window.showDirectoryPicker) {
                showNotification('Folder selection requires a Chromium-based browser in a secure context (HTTPS or localhost).', 7000);
                return;
            }
            try {
                directoryHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
                byId('folder-name').textContent = directoryHandle.name;
                updateStartState();
            } catch (error) {
                if (error.name !== 'AbortError') showNotification(`Could not open folder: ${error.message}`);
            }
        };

        const clearDownloader = () => {
            if (running) return;
            const input = byId('hashes');
            if (input) input.value = '';
            records.clear();
            renderTable();
            updateInputSummary();
        };

        const bind = () => {
            if (bound) return;
            bound = true;
            byId('hashes')?.addEventListener('input', updateInputSummary);
            byId('consent')?.addEventListener('change', updateStartState);
            document.querySelectorAll(`input[name="${config.modeName}"]`).forEach(input => input.addEventListener('change', updateStartState));
            byId('folder')?.addEventListener('click', selectFolder);
            byId('start')?.addEventListener('click', startDownload);
            byId('clear')?.addEventListener('click', clearDownloader);
            byId('copy-failed')?.addEventListener('click', () => copyResults('failed'));
            byId('copy-success')?.addEventListener('click', () => copyResults('success'));
            updateInputSummary();
            renderTable();
        };

        return () => {
            bind();
            if (!window.showDirectoryPicker) {
                const folderName = byId('folder-name');
                if (folderName) folderName.textContent = 'Folder selection unavailable in this browser/context';
            }
        };
    };

    window.openSamplesDownloader = createDownloader({
        prefix: 'samples-downloader',
        provider: 'VirusTotal',
        requiresKey: true,
        directEndpoint: '/api/vt/download',
        zipEndpoint: '/api/vt/download/zip',
        failedHeader: 'X-VT-Failed-Samples',
        archivePrefix: 'vt',
        modeName: 'samples-output-mode',
    });
})();
