/*
 * MANTIS dashboard charts
 * Small Chart.js panels placed beside existing lists. Every chart is built from
 * live API data; empty data renders an explicit empty state, never sample values.
 * Usage: window.MantisCharts.bar(container, { labels, datasets, ... })
 */
(function () {
    'use strict';

    const PALETTE = ['#FFCC00', '#38bdf8', '#34d399', '#f43f5e', '#a78bfa', '#fb923c', '#94a3b8', '#e879f9'];
    const registry = new WeakMap();

    function esc(v) {
        return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function baseOptions(extra) {
        return Object.assign({
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { labels: { color: '#cbd5e1', boxWidth: 10, font: { size: 11 } } } },
            scales: {
                x: { ticks: { color: '#94a3b8', maxRotation: 0, autoSkip: true, font: { size: 10 } }, grid: { color: 'rgba(148,163,184,0.08)' } },
                y: { beginAtZero: true, ticks: { color: '#94a3b8', precision: 0, font: { size: 10 } }, grid: { color: 'rgba(148,163,184,0.08)' } },
            },
        }, extra || {});
    }

    function empty(container, message) {
        destroy(container);
        container.innerHTML = `<div class="dc-empty">${esc(message)}</div>`;
    }

    function destroy(container) {
        const old = registry.get(container);
        if (old) { old.destroy(); registry.delete(container); }
        if (container.querySelector('canvas')) container.innerHTML = '';
    }

    function mount(container, type, data, options) {
        if (!window.Chart) { empty(container, 'Chart library failed to load.'); return null; }
        destroy(container);
        const canvas = document.createElement('canvas');
        container.appendChild(canvas);
        const chart = new window.Chart(canvas, { type, data, options: options || baseOptions() });
        registry.set(container, chart);
        return chart;
    }

    function colorize(datasets) {
        return datasets.map((d, i) => Object.assign({
            backgroundColor: PALETTE[i % PALETTE.length],
            borderColor: PALETTE[i % PALETTE.length],
            borderWidth: 1,
        }, d));
    }

    function bar(container, { labels, datasets, horizontal = false, stacked = false, emptyText = 'No data for this period.' }) {
        const total = datasets.reduce((n, d) => n + d.data.reduce((a, b) => a + (Number(b) || 0), 0), 0);
        if (!labels.length || total === 0) return empty(container, emptyText);
        const opts = baseOptions({ indexAxis: horizontal ? 'y' : 'x' });
        if (stacked) { opts.scales.x.stacked = true; opts.scales.y.stacked = true; }
        if (datasets.length === 1) opts.plugins.legend.display = false;
        return mount(container, 'bar', { labels, datasets: colorize(datasets) }, opts);
    }

    function line(container, { labels, datasets, emptyText = 'No data for this period.' }) {
        const total = datasets.reduce((n, d) => n + d.data.reduce((a, b) => a + (Number(b) || 0), 0), 0);
        if (!labels.length || total === 0) return empty(container, emptyText);
        const ds = colorize(datasets).map(d => Object.assign({ fill: false, tension: 0.25, pointRadius: 2, borderWidth: 2 }, d, { backgroundColor: d.borderColor }));
        return mount(container, 'line', { labels, datasets: ds }, baseOptions());
    }

    function doughnut(container, { labels, values, emptyText = 'No data.' }) {
        const total = values.reduce((a, b) => a + (Number(b) || 0), 0);
        if (!labels.length || total === 0) return empty(container, emptyText);
        const opts = baseOptions({ scales: undefined, cutout: '62%' });
        opts.plugins.legend.position = 'right';
        return mount(container, 'doughnut', {
            labels,
            datasets: [{ data: values, backgroundColor: labels.map((_, i) => PALETTE[i % PALETTE.length]), borderColor: '#0b1120', borderWidth: 2 }],
        }, opts);
    }

    window.MantisCharts = { bar, line, doughnut, destroy, esc, PALETTE };
})();
