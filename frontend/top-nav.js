// Top navigation: moves the existing sidebar nodes (and their click handlers)
// into horizontal top-level menus with dropdown panels. Node identity is kept,
// so app.js handlers attached to .nav-item / .nav-parent / .settings-nav-item
// keep working without changes.
(function () {
    const GROUPS = [
        { id: 'ioc', label: 'IOC Search', icon: 'fa-magnifying-glass-chart', tabs: ['ioc-search', 'history'] },
        { id: 'threat-intel', label: 'Threat Intelligence', icon: 'fa-sun', tabs: ['todays-intel', 'ransom-overview', 'cti', 'intel-reports', 'poc-index', 'osv-malicious'] },
        { id: 'threat', label: 'Threat Knowledge', icon: 'fa-user-secret', tabs: ['ta', 'mwtools'] },
        { id: 'infra', label: 'C2 and Infrastructure', icon: 'fa-network-wired', tabs: ['infra', 'infra-pivoting', 'opendir', 'c2-hunting-catalog', 'exposure-monitor', 'data-feeds', 'infra-history'] },
        { id: 'hunting-detection', label: 'Hunting & Detection', icon: 'fa-crosshairs', tabs: ['hunting-library', 'sigma-rules', 'yara-explorer'] },
        { id: 'monitor', label: 'Monitor', icon: 'fa-tower-broadcast', tabs: ['x-monitor', 'breach-watcher', 'tg-channel-mon'] },
        { id: 'credential-stealer', label: 'Credential Stealer', icon: 'fa-key', tabs: ['credential-stealer'], direct: true },
        { id: 'ti-cases', label: 'TI Case Manager', icon: 'fa-folder-tree', tabs: ['ti-cases'], direct: true },
        { id: 'lab', label: 'Malware Lab', icon: 'fa-flask', tabs: ['binary-lab', 'binary-reversing', 'malware-db', 'samples-downloader', 'similarity-dashboard'] },
        { id: 'telegram', label: 'Telegram Toolkit', icon: 'fa-paper-plane', tabs: ['tg-info', 'tg-invest'] },
        { id: 'discord-c2', label: 'Discord C2 Dump', icon: 'fa-discord', iconStyle: 'fa-brands', tabs: ['discord-c2-dump'], direct: true },
        { id: 'drawer', label: 'Drawer and Viewer', icon: 'fa-compass-drafting', tabs: ['diagram-draw', 'flowchart-draw', 'mindmap-draw', 'mapchart-draw', 'mermaid-draw', 'chart-creator', 'markdown-draw'] },
    ];

    const bar = document.getElementById('top-nav');
    const sidebar = document.getElementById('sidebar');
    if (!bar || !sidebar) return;

    // Top-level entries (direct children of .nav-menu, or inside wrappers).
    const holderFor = (tab) => {
        const el = sidebar.querySelector(`[data-tab="${tab}"]`);
        if (!el) { console.warn('top-nav: no sidebar entry for', tab); return null; }
        return el.closest('.nav-group') || el;
    };

    // Brand (MANTIS title, also the home link) stays on the left.
    const brand = sidebar.querySelector('.sidebar-header');
    if (brand) bar.appendChild(brand);

    const mobileToggle = document.createElement('button');
    mobileToggle.type = 'button';
    mobileToggle.className = 'top-nav-toggle btn-secondary';
    mobileToggle.textContent = 'Menu';
    mobileToggle.setAttribute('aria-expanded', 'false');
    mobileToggle.setAttribute('aria-controls', 'main-navigation');
    brand?.appendChild(mobileToggle);
    mobileToggle.addEventListener('click', () => {
        mobileToggle.setAttribute('aria-expanded', String(bar.classList.toggle('mobile-open')));
    });

    const menu = document.createElement('nav');
    menu.className = 'top-nav-menu';
    menu.id = 'main-navigation';
    menu.setAttribute('aria-label', 'Main navigation');
    bar.appendChild(menu);

    const wraps = [];
    GROUPS.forEach((g) => {
        if (g.direct) {
            const holder = holderFor(g.tabs[0]);
            if (holder) {
                holder.classList.add('top-menu-direct');
                holder.setAttribute('role', 'button');
                holder.setAttribute('tabindex', '0');
                holder.setAttribute('title', g.label);
                let iconEl = holder.querySelector('i');
                if (!iconEl && g.icon) {
                    iconEl = document.createElement('i');
                    iconEl.className = `${g.iconStyle || 'fa-solid'} ${g.icon}`;
                    holder.insertBefore(iconEl, holder.firstChild);
                } else if (iconEl && g.icon) {
                    iconEl.className = `${g.iconStyle || 'fa-solid'} ${g.icon}`;
                }
                let span = holder.querySelector('span');
                if (!span) {
                    span = document.createElement('span');
                    holder.appendChild(span);
                }
                span.textContent = g.label;
                holder.addEventListener('keydown', (event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        holder.click();
                    }
                });
                menu.appendChild(holder);
            }
            return;
        }
        const wrap = document.createElement('div');
        wrap.className = 'top-menu';
        wrap.dataset.topMenu = g.id;

        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'top-menu-trigger';
        trigger.title = g.label;
        trigger.setAttribute('aria-haspopup', 'true');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.innerHTML = `<i class="fa-solid ${g.icon}"></i><span>${g.label}</span><i class="fa-solid fa-chevron-right top-menu-caret" aria-hidden="true"></i>`;

        const panel = document.createElement('div');
        panel.className = 'top-menu-panel';
        g.tabs.forEach((tab) => {
            const holder = holderFor(tab);
            if (holder) panel.appendChild(holder);
        });
        panel.querySelectorAll('.nav-parent[role="button"]').forEach(parent => {
            parent.addEventListener('keydown', event => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    parent.click();
                }
            });
        });

        wrap.append(trigger, panel);
        menu.appendChild(wrap);
        wraps.push(wrap);
    });

    // Settings: the existing sidebar footer (gear button + settings list) becomes the last top item.
    const settingsFooter = sidebar.querySelector('.sidebar-footer');
    if (settingsFooter) {
        settingsFooter.classList.add('top-menu-settings');
        menu.appendChild(settingsFooter);
    }

    // Remove the now-empty sidebar shell pieces only from layout (kept in DOM for compatibility).
    const setHasActive = (el, has) => {
        if (el.classList.contains('has-active') !== has) el.classList.toggle('has-active', has);
    };
    const syncActive = () => {
        wraps.forEach((wrap) => {
            const panel = wrap.querySelector('.top-menu-panel');
            setHasActive(wrap, !!panel.querySelector('.nav-item.active'));
            panel.querySelectorAll('.nav-group > .nav-parent[role="button"]').forEach(parent => {
                parent.setAttribute('aria-expanded', String(parent.parentElement.classList.contains('expanded')));
            });
        });
        if (settingsFooter) {
            setHasActive(settingsFooter, !!(settingsFooter.querySelector('.settings-nav-item.active, .settings-nav-route.active') ||
                settingsFooter.querySelector('#btn-settings.active')));
            settingsFooter.querySelector('#btn-settings')?.setAttribute('aria-expanded',
                String(settingsFooter.classList.contains('settings-expanded')));
        }
    };

    const closeAll = (keepFooter = false) => {
        wraps.forEach((wrap) => {
            wrap.classList.remove('open');
            wrap.querySelector('.top-menu-trigger').setAttribute('aria-expanded', 'false');
        });
        if (settingsFooter && !keepFooter) settingsFooter.classList.remove('settings-expanded');
    };

    // Capture phase: runs before item handlers, so it sees every click, including
    // the settings button, which stops propagation in app.js.
    document.addEventListener('click', (e) => {
        if (e.target.closest('.top-menu-direct')) {
            closeAll();
            bar.classList.remove('mobile-open');
            mobileToggle.setAttribute('aria-expanded', 'false');
            return;
        }
        const trigger = e.target.closest('.top-menu-trigger');
        if (trigger) {
            const wrap = trigger.parentElement;
            const willOpen = !wrap.classList.contains('open');
            closeAll(true);
            if (settingsFooter) settingsFooter.classList.remove('settings-expanded');
            if (willOpen) {
                wrap.classList.add('open');
                trigger.setAttribute('aria-expanded', 'true');
            }
            e.preventDefault();
            e.stopPropagation();
            return;
        }
        if (e.target.closest('#btn-settings')) {
            // app.js toggles settings-expanded on this click; just close the other menus.
            wraps.forEach((wrap) => wrap.classList.remove('open'));
            return;
        }
        // Keep the sidebar group open when navigating between its pages.
        if (e.target.closest('.top-menu-panel')) return;

        const inPanel = e.target.closest('.settings-nav');
        if (inPanel) {
            // Parent entries toggle their own submenu; leaves close the menu.
            const leaf = e.target.closest('.nav-item, .settings-nav-item');
            if (leaf && !leaf.classList.contains('nav-parent') && leaf.dataset.tab !== 'tg-auth-settings') {
                closeAll();
                bar.classList.remove('mobile-open');
                mobileToggle.setAttribute('aria-expanded', 'false');
            }
            return;
        }
    }, true);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeAll();
    });

    // Keep the trigger highlight in sync with whichever page is active.
    const observer = new MutationObserver(syncActive);
    wraps.forEach((wrap) => observer.observe(wrap.querySelector('.top-menu-panel'),
        { attributes: true, subtree: true, attributeFilter: ['class'] }));
    if (settingsFooter) observer.observe(settingsFooter, { attributes: true, subtree: true, attributeFilter: ['class'] });
    syncActive();
})();
