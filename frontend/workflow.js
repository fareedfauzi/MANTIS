/*
 * MANTIS workflow layer.
 *
 * Small, self-contained UX helpers loaded after app.js. They only read and
 * decorate existing DOM (they never replace app.js handlers, so every tab and
 * search path keeps working):
 *   1. Sidebar "Jump to a tool" filter (press "/" to focus, Esc to clear).
 *   2. IOC Search: clickable example indicators per indicator type.
 *   3. IOC Search: collapsible source selector with a "N of M selected" count.
 */
(function () {
    'use strict';

    // ---------------------------------------------------------------- 1. nav filter
    function initNavFilter() {
        const input = document.getElementById('nav-filter');
        const menu = document.querySelector('.sidebar .nav-menu');
        if (!input || !menu) return;

        const emptyMsg = document.createElement('div');
        emptyMsg.className = 'nav-filter-empty';
        emptyMsg.textContent = 'No tools match.';
        emptyMsg.hidden = true;
        menu.appendChild(emptyMsg);

        const leafText = el => (el.querySelector('span')?.textContent || el.textContent || '').trim().toLowerCase();

        function clearFilter() {
            menu.querySelectorAll('.nav-item, .nav-group, .nav-section-label').forEach(el => {
                el.style.display = '';
            });
            menu.querySelectorAll('.nav-group.nav-filter-open').forEach(g => g.classList.remove('nav-filter-open'));
            emptyMsg.hidden = true;
        }

        function applyFilter(q) {
            if (!q) { clearFilter(); return; }

            // Leaf items (non-group) and group parents.
            const groups = Array.from(menu.querySelectorAll(':scope > .nav-group'));
            const topItems = Array.from(menu.querySelectorAll(':scope > .nav-item'));
            let visibleCount = 0;

            topItems.forEach(item => {
                const match = leafText(item).includes(q);
                item.style.display = match ? '' : 'none';
                if (match) visibleCount++;
            });

            groups.forEach(group => {
                const parent = group.querySelector(':scope > .nav-parent');
                const subs = Array.from(group.querySelectorAll(':scope > .nav-submenu > .nav-subitem'));
                const parentMatch = parent ? leafText(parent).includes(q) : false;
                let anySub = false;
                subs.forEach(sub => {
                    const m = parentMatch || leafText(sub).includes(q);
                    sub.style.display = m ? '' : 'none';
                    if (m) anySub = true;
                });
                const show = parentMatch || anySub;
                group.style.display = show ? '' : 'none';
                group.classList.toggle('nav-filter-open', show);
                if (show) visibleCount++;
            });

            // Section labels: show only if something under them is visible.
            let label = null;
            let labelHasItems = false;
            const flush = () => { if (label) label.style.display = labelHasItems ? '' : 'none'; };
            Array.from(menu.children).forEach(el => {
                if (el.classList.contains('nav-section-label')) {
                    flush();
                    label = el; labelHasItems = false;
                } else if (el.style.display !== 'none' && el !== emptyMsg) {
                    labelHasItems = true;
                }
            });
            flush();
            // Nested labels (MISP / Malpedia inside a submenu) are noise while filtering.
            menu.querySelectorAll('.nav-submenu .nav-section-label').forEach(el => { el.style.display = 'none'; });

            emptyMsg.hidden = visibleCount > 0;
        }

        input.addEventListener('input', () => applyFilter(input.value.trim().toLowerCase()));
        input.addEventListener('keydown', e => {
            if (e.key === 'Escape') {
                input.value = '';
                applyFilter('');
                input.blur();
            } else if (e.key === 'Enter') {
                const first = Array.from(menu.querySelectorAll('.nav-item:not(.nav-parent)'))
                    .find(el => el.style.display !== 'none' && el.offsetParent !== null);
                if (first) { first.click(); }
            }
        });

        // Picking a leaf tool while filtered: reset the filter so the full menu is back.
        menu.addEventListener('click', e => {
            const leaf = e.target.closest('.nav-item:not(.nav-parent)');
            if (leaf && input.value) {
                input.value = '';
                setTimeout(() => clearFilter(), 0);
            }
        });

        document.addEventListener('keydown', e => {
            if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
            const t = e.target;
            if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable || t.tagName === 'SELECT')) return;
            const sidebar = document.getElementById('sidebar');
            if (sidebar && sidebar.classList.contains('collapsed')) return;
            e.preventDefault();
            input.focus();
            input.select();
        });
    }

    // ---------------------------------------------------- 2. IOC example indicators
    // Benign, well-known examples only. Filling one does NOT start a search.
    const IOC_EXAMPLES = {
        auto: [
            ['IP', '8.8.8.8'],
            ['Domain', 'example.com'],
            ['MD5', 'd41d8cd98f00b204e9800998ecf8427e'],
            ['URL', 'https://example.com/login'],
            ['Keyword', 'cobalt strike']
        ],
        hash: [
            ['MD5', 'd41d8cd98f00b204e9800998ecf8427e'],
            ['SHA-256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
        ],
        domain: [['Domain', 'example.com'], ['Domain', 'github.com']],
        ip: [['IPv4', '8.8.8.8'], ['IPv6', '2001:4860:4860::8888']],
        url: [['URL', 'https://example.com/login']],
        keyword: [['Tag', 'cobalt strike'], ['Keyword', 'lockbit']],
        infra: [['ASN', 'AS13335'], ['CIDR', '8.8.8.0/24']]
    };

    function initIocExamples() {
        const box = document.getElementById('ioc-examples');
        const input = document.getElementById('ioc-input');
        if (!box || !input) return;

        function currentType() {
            const active = document.querySelector('.ioc-tab.active');
            return (active && active.dataset.iocTab) || 'auto';
        }

        function render() {
            const type = currentType();
            const items = IOC_EXAMPLES[type] || IOC_EXAMPLES.auto;
            box.innerHTML = '';
            const lead = document.createElement('span');
            lead.className = 'ioc-examples-lead';
            lead.textContent = 'Try:';
            box.appendChild(lead);
            items.forEach(([kind, value]) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'ioc-example';
                b.title = `Fill ${kind} example (does not search)`;
                b.innerHTML = `<small></small><code></code>`;
                b.querySelector('small').textContent = kind;
                b.querySelector('code').textContent = value;
                b.addEventListener('click', () => {
                    input.value = value;
                    input.dispatchEvent(new Event('input', { bubbles: true }));
                    input.focus();
                });
                box.appendChild(b);
            });
        }

        // Type changes come through the existing .ioc-tab click handler in app.js.
        document.addEventListener('click', e => {
            if (e.target.closest && e.target.closest('.ioc-tab')) setTimeout(render, 0);
        });
        render();
    }

    // ------------------------------------------------ 3. collapsible source selector
    function initSourceSelector() {
        const panel = document.getElementById('source-selector-panel');
        const header = panel && panel.querySelector('.source-selector-header');
        const list = document.getElementById('source-checkboxes');
        if (!panel || !header || !list) return;

        const titleWrap = document.createElement('div');
        titleWrap.className = 'source-selector-title';

        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'source-toggle';

        const summary = document.createElement('span');
        summary.className = 'source-summary';

        const label = header.firstElementChild; // the existing <span> with the "Sources" text
        header.insertBefore(titleWrap, header.firstChild);
        titleWrap.appendChild(toggle);
        if (label) titleWrap.appendChild(label);
        titleWrap.appendChild(summary);

        const stored = localStorage.getItem('mantis.sourcesExpanded');
        // Default: collapsed. Users who opened it keep it open.
        let expanded = stored === '1';

        function setExpanded(v) {
            expanded = v;
            panel.classList.toggle('sources-collapsed', !expanded);
            toggle.setAttribute('aria-expanded', String(expanded));
            toggle.innerHTML = `<i class="fa-solid fa-chevron-${expanded ? 'down' : 'right'}"></i>`;
            toggle.title = expanded ? 'Hide source list' : 'Show source list';
            localStorage.setItem('mantis.sourcesExpanded', expanded ? '1' : '0');
        }

        function updateSummary() {
            const boxes = Array.from(list.querySelectorAll('input[type=checkbox]'));
            const total = boxes.length;
            const on = boxes.filter(b => b.checked).length;
            summary.textContent = total ? `${on} of ${total} selected` : '';
        }

        toggle.addEventListener('click', () => setExpanded(!expanded));
        list.addEventListener('change', updateSummary);
        new MutationObserver(updateSummary).observe(list, { childList: true, subtree: true });

        // "All" / "None" buttons flip checkboxes programmatically; re-count after they run.
        header.addEventListener('click', () => setTimeout(updateSummary, 0));

        setExpanded(expanded);
        updateSummary();
    }

    function init() {
        initNavFilter();
        initIocExamples();
        initSourceSelector();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
