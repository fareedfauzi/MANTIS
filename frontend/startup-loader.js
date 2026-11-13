// First-run data loader: shows a progress bar per dataset that is still
// downloading (YARA rules, MISP galaxies, PoC index, ...). Standalone so it
// works even if app.js fails to load. Dismissible; never blocks the app.
(function () {
    'use strict';

    const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:9999' : window.location.origin;
    const POLL_MS = 1500;
    const STATE_LABEL = {
        waiting: 'Waiting',
        running: 'Downloading',
        done: 'Ready',
        skipped: 'Cached',
        error: 'Failed',
    };

    let overlay = null;
    let timer = null;
    let dismissed = false;

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function fmtBytes(n) {
        if (n == null) return '';
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(0) + ' KB';
        return (n / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function ensureOverlay() {
        if (overlay) return overlay;
        overlay = el('div', 'startup-loader');
        overlay.setAttribute('role', 'status');
        overlay.setAttribute('aria-live', 'polite');

        const card = el('div', 'startup-loader-card');
        const head = el('div', 'startup-loader-head');
        head.appendChild(el('h2', null, 'Preparing threat-intel data'));
        const close = el('button', 'startup-loader-close', 'Continue anyway');
        close.type = 'button';
        close.addEventListener('click', dismiss);
        head.appendChild(close);
        card.appendChild(head);

        card.appendChild(el('p', 'startup-loader-note',
            'First start downloads reference datasets. Search works now; results grow as each dataset finishes.'));

        const list = el('div', 'startup-loader-list');
        card.appendChild(list);
        overlay.appendChild(card);
        overlay._list = list;
        document.body.appendChild(overlay);
        return overlay;
    }

    function renderTask(task) {
        const row = el('div', 'startup-loader-row state-' + task.state);
        const top = el('div', 'startup-loader-top');
        top.appendChild(el('span', 'startup-loader-label', task.label));
        top.appendChild(el('span', 'startup-loader-badge', STATE_LABEL[task.state] || task.state));
        row.appendChild(top);

        const bar = el('div', 'startup-loader-bar');
        const fill = el('div', 'startup-loader-fill');
        let pct;
        if (task.state === 'done' || task.state === 'skipped') pct = 100;
        else if (task.state === 'error') pct = 100;
        else if (task.state === 'waiting') pct = 0; // not started yet: empty bar, no animation
        else if (task.total && task.total > 0) pct = Math.min(100, Math.round((task.done / task.total) * 100));
        else pct = null; // running with unknown total: indeterminate
        if (pct == null) {
            fill.classList.add('indeterminate');
        } else {
            fill.style.width = pct + '%';
        }
        bar.appendChild(fill);
        row.appendChild(bar);

        let detail = task.message || '';
        if (task.state === 'running' && task.total) {
            const counts = task.unit === 'bytes'
                ? fmtBytes(task.done) + ' / ' + fmtBytes(task.total)
                : task.done + ' / ' + task.total;
            detail = counts + (task.message ? ' · ' + task.message : '');
        }
        row.appendChild(el('div', 'startup-loader-detail', detail));
        return row;
    }

    function render(snapshot) {
        const ov = ensureOverlay();
        const list = ov._list;
        list.replaceChildren(...snapshot.tasks.map(renderTask));
    }

    function dismiss() {
        dismissed = true;
        if (timer) clearInterval(timer);
        timer = null;
        if (overlay) overlay.remove();
        overlay = null;
    }

    async function poll() {
        try {
            const res = await fetch(API_BASE + '/api/meta/startup-progress', { cache: 'no-store' });
            if (!res.ok) return;
            const data = await res.json();
            const tasks = data.tasks || [];
            if (data.ready) {
                // Keep showing the final state briefly, then close.
                if (overlay) render(data);
                setTimeout(dismiss, 1500);
                if (timer) clearInterval(timer);
                timer = null;
                return;
            }
            if (!tasks.length) return;
            render(data);
        } catch (_) {
            // Server still starting; try again on the next tick.
        }
    }

    function start() {
        poll();
        timer = setInterval(() => { if (!dismissed) poll(); }, POLL_MS);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
