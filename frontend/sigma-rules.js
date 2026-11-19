/**
 * MANTIS SIGMA Rules Workstation & Detection Suite
 * Implements: Stats, Rules Explorer, Emerging Threats, MITRE ATT&CK Matrix,
 * Query Converter (11 targets), and Detection Lab Sandbox.
 */

(function () {
    // State management
    const state = {
        activeTab: 'sigma-rules', // sigma-rules, sigma-stats, sigma-emerging, sigma-mitre, sigma-convert
        repos: [],
        selectedRepos: new Set(),
        searchQuery: '',
        levelFilter: '',
        statusFilter: '',
        categoryFilter: '',
        currentPage: 1,
        pageSize: 24,
        totalPages: 1,
        totalRules: 0,
        rules: [],
        
        // Modal state
        currentModalRule: null,
        modalMode: 'view', // 'view', 'edit', 'create'

        // Convert state
        convertTarget: 'splunk',
        convertRuleYaml: '',
        convertMode: 'standard', // 'standard', 'ai', 'ai_repair'
        convertAIProvider: '',
        convertAIModel: '',
        lastConversionData: null,
        aiProviders: [],

        // Emerging state
        emergingCategory: 'all',
        emergingQuery: ''
    };

    // DOM Elements Cache
    let dom = {};

    function init() {
        cacheDom();
        bindEvents();
        loadRepositories();
    }

    function cacheDom() {
        dom.pane = document.getElementById('sigma-pane');
        dom.tabs = document.querySelectorAll('.sigma-nav-tab');
        dom.views = document.querySelectorAll('.sigma-view');
        dom.syncBtn = document.getElementById('sigma-btn-sync');
        
        // Stats elements
        dom.statTotalRules = document.getElementById('sigma-stat-total-rules');
        dom.statTotalRepos = document.getElementById('sigma-stat-total-repos');
        dom.statTotalTactics = document.getElementById('sigma-stat-total-tactics');
        dom.statEmergingCount = document.getElementById('sigma-stat-emerging-count');
        dom.severityBars = document.getElementById('sigma-severity-bars');
        dom.statusBars = document.getElementById('sigma-status-bars');
        dom.statsReposGrid = document.getElementById('sigma-stats-repos-grid');
        dom.topAuthorsList = document.getElementById('sigma-top-authors-list');
        dom.topProductsList = document.getElementById('sigma-top-products-list');
        dom.topTechniquesList = document.getElementById('sigma-top-techniques-list');

        // Rules Explorer elements
        dom.reposFilterBar = document.getElementById('sigma-repos-filter-bar');
        dom.searchInput = document.getElementById('sigma-search-input');
        dom.levelSelect = document.getElementById('sigma-filter-level');
        dom.statusSelect = document.getElementById('sigma-filter-status');
        dom.categorySelect = document.getElementById('sigma-filter-category');
        dom.rulesGrid = document.getElementById('sigma-rules-grid');
        dom.paginationBar = document.getElementById('sigma-pagination-bar');
        dom.paginationInfo = document.getElementById('sigma-pagination-info');
        dom.paginationControls = document.getElementById('sigma-pagination-controls');

        // Emerging elements
        dom.emergingNav = document.getElementById('sigma-emerging-nav');
        dom.emergingSearch = document.getElementById('sigma-emerging-search');
        dom.emergingGrid = document.getElementById('sigma-emerging-grid');

        // MITRE elements
        dom.mitreGrid = document.getElementById('sigma-mitre-grid');

        // Convert elements
        dom.convertRuleSelect = document.getElementById('sigma-convert-rule-select');
        dom.convertInput = document.getElementById('sigma-convert-input');
        dom.convertTargetTabs = document.getElementById('sigma-convert-target-tabs');
        dom.convertOutput = document.getElementById('sigma-convert-output');
        dom.convertCopyBtn = document.getElementById('sigma-btn-copy-query');
        dom.convertModeSelector = document.getElementById('sigma-convert-mode-selector');
        dom.convertAIControls = document.getElementById('sigma-convert-ai-controls');
        dom.convertAIPanelBadgeTitle = document.getElementById('sigma-ai-panel-badge-title');
        dom.convertAIPanelDesc = document.getElementById('sigma-ai-panel-desc');
        dom.convertAIProviderSelect = document.getElementById('sigma-convert-ai-provider');
        dom.convertAIModelInput = document.getElementById('sigma-convert-ai-model');
        dom.convertRunBtn = document.getElementById('sigma-btn-run-convert');
        dom.convertRepairBtn = document.getElementById('sigma-btn-repair-with-ai');
        dom.convertValBadge = document.getElementById('sigma-convert-val-badge');
        dom.convertValBanner = document.getElementById('sigma-convert-val-banner');
        dom.convertValText = document.getElementById('sigma-convert-val-text');
        dom.convertToggleBreakdownBtn = document.getElementById('sigma-btn-toggle-breakdown');
        dom.convertBreakdownDrawer = document.getElementById('sigma-convert-breakdown');
        dom.convertBreakdownContent = document.getElementById('sigma-convert-breakdown-content');
        dom.convertBreakdownCloseBtn = document.getElementById('sigma-breakdown-close-btn');
        dom.convertDiffPane = document.getElementById('sigma-convert-diff-pane');
        dom.convertDiffOutput = document.getElementById('sigma-convert-diff-output');
        dom.convertDiffCloseBtn = document.getElementById('sigma-diff-close-btn');

        // Modal elements
        dom.modalOverlay = document.getElementById('sigma-rule-modal-overlay');
        dom.modalCloseBtn = document.getElementById('sigma-btn-modal-close');
        dom.modalViewToggle = document.getElementById('sigma-btn-modal-view');
        dom.modalEditToggle = document.getElementById('sigma-btn-modal-edit');
        dom.modalTitle = document.getElementById('sigma-modal-title');
        dom.modalLeftMeta = document.getElementById('sigma-modal-left-meta');
        dom.modalCode = document.getElementById('sigma-modal-code');
        dom.modalCodeView = document.getElementById('sigma-modal-code-view');
        dom.modalCodeHl = document.getElementById('sigma-modal-code-hl');
        dom.modalCopyBtn = document.getElementById('sigma-btn-modal-copy');
        dom.modalDeleteBtn = document.getElementById('sigma-btn-modal-delete');
        dom.modalSaveBtn = document.getElementById('sigma-btn-modal-save');
        dom.modalSendConvertBtn = document.getElementById('sigma-btn-modal-send-convert');
        dom.btnAutoStatus = document.getElementById('sigma-btn-auto-status');
        dom.btnCustomRulesPill = document.getElementById('sigma-filter-custom-pill');
    }

    function bindEvents() {
        // Tab switching
        dom.tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.getAttribute('data-tab');
                switchSubTab(target);
            });
        });

        // Repository Sync button
        dom.syncBtn?.addEventListener('click', () => {
            syncRepositories();
        });

        // Explorer search & filters
        let debounceTimer;
        dom.searchInput?.addEventListener('input', (e) => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                state.searchQuery = e.target.value.trim();
                state.currentPage = 1;
                loadRules();
            }, 300);
        });

        dom.levelSelect?.addEventListener('change', (e) => {
            state.levelFilter = e.target.value;
            state.currentPage = 1;
            loadRules();
        });

        dom.statusSelect?.addEventListener('change', (e) => {
            state.statusFilter = e.target.value;
            state.currentPage = 1;
            loadRules();
        });

        dom.categorySelect?.addEventListener('change', (e) => {
            state.categoryFilter = e.target.value;
            state.currentPage = 1;
            loadRules();
        });

        // Emerging filters
        dom.emergingNav?.querySelectorAll('.sigma-emerging-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                dom.emergingNav.querySelectorAll('.sigma-emerging-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.emergingCategory = btn.getAttribute('data-cat');
                loadEmergingThreats();
            });
        });

        dom.emergingSearch?.addEventListener('input', (e) => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                state.emergingQuery = e.target.value.trim();
                loadEmergingThreats();
            }, 300);
        });

        // Convert target switching
        dom.convertTargetTabs?.querySelectorAll('.sigma-target-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                dom.convertTargetTabs.querySelectorAll('.sigma-target-tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.convertTarget = btn.getAttribute('data-target');
                if (state.convertMode === 'standard') {
                    runConversion();
                } else if (dom.convertOutput) {
                    dom.convertOutput.textContent = `// Target changed to [${state.convertTarget.toUpperCase()}]. Click "Convert" to run ${state.convertMode === 'ai' ? 'AI Conversion' : 'AI-Assisted Repair'}.`;
                }
            });
        });

        function updateAIModeUI() {
            if (!dom.convertAIControls) return;
            if (state.convertMode === 'ai') {
                dom.convertAIControls.style.display = 'flex';
                if (dom.convertAIPanelBadgeTitle) dom.convertAIPanelBadgeTitle.textContent = 'AI Conversion Engine';
                if (dom.convertAIPanelDesc) dom.convertAIPanelDesc.textContent = 'Translates Sigma detection rules into platform-native query dialects using LLM reasoning with semantic field mapping.';
                loadAIProviders();
            } else if (state.convertMode === 'ai_repair') {
                dom.convertAIControls.style.display = 'flex';
                if (dom.convertAIPanelBadgeTitle) dom.convertAIPanelBadgeTitle.textContent = 'AI-Assisted Repair Engine';
                if (dom.convertAIPanelDesc) dom.convertAIPanelDesc.textContent = 'Dual-stage pipeline: diagnoses pySigma baseline conversion failure and automatically repairs missing field mappings and syntax errors.';
                loadAIProviders();
            } else {
                dom.convertAIControls.style.display = 'none';
            }
        }

        // Conversion mode selector
        dom.convertModeSelector?.querySelectorAll('.sigma-mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                dom.convertModeSelector.querySelectorAll('.sigma-mode-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.convertMode = btn.getAttribute('data-mode') || 'standard';
                updateAIModeUI();
                // Never auto-convert on mode switch - user must click "Convert" button
            });
        });

        // Convert Run button
        dom.convertRunBtn?.addEventListener('click', () => {
            runConversion();
        });

        // Repair with AI button
        dom.convertRepairBtn?.addEventListener('click', () => {
            state.convertMode = 'ai_repair';
            dom.convertModeSelector?.querySelectorAll('.sigma-mode-btn').forEach(b => {
                b.classList.toggle('active', b.getAttribute('data-mode') === 'ai_repair');
            });
            updateAIModeUI();
            if (dom.convertOutput) {
                dom.convertOutput.textContent = `// Switched to AI-Assisted Repair mode. Click "Convert" to run repair pipeline.`;
            }
        });

        // AI Provider select
        dom.convertAIProviderSelect?.addEventListener('change', (e) => {
            state.convertAIProvider = e.target.value;
            const prov = state.aiProviders.find(p => p.id === state.convertAIProvider);
            if (prov && prov.model && dom.convertAIModelInput) {
                dom.convertAIModelInput.value = prov.model;
                state.convertAIModel = prov.model;
            }
        });

        // AI Model input
        dom.convertAIModelInput?.addEventListener('input', (e) => {
            state.convertAIModel = e.target.value.trim();
        });

        // Toggle breakdown drawer
        dom.convertToggleBreakdownBtn?.addEventListener('click', () => {
            if (dom.convertBreakdownDrawer) {
                const isHidden = dom.convertBreakdownDrawer.style.display === 'none' || !dom.convertBreakdownDrawer.style.display;
                dom.convertBreakdownDrawer.style.display = isHidden ? 'block' : 'none';
            }
        });

        // Close breakdown drawer
        dom.convertBreakdownCloseBtn?.addEventListener('click', () => {
            if (dom.convertBreakdownDrawer) dom.convertBreakdownDrawer.style.display = 'none';
        });

        // Close diff pane
        dom.convertDiffCloseBtn?.addEventListener('click', () => {
            if (dom.convertDiffPane) dom.convertDiffPane.style.display = 'none';
        });

        dom.convertRuleSelect?.addEventListener('change', (e) => {
            const val = e.target.value;
            if (val) {
                const [rep, f] = val.split('::');
                fetchRuleAndSet(rep, f, 'convert');
            }
        });

        dom.convertInput?.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                // Only auto-convert while typing in standard pySigma mode, never in AI mode!
                if (state.convertMode === 'standard') {
                    runConversion();
                }
            }, 600);
        });

        dom.convertCopyBtn?.addEventListener('click', () => {
            const text = dom.convertOutput ? dom.convertOutput.textContent : '';
            copyTextRobust(text, dom.convertCopyBtn, '<i class="fa-solid fa-check"></i> Copied!');
        });

        // Modal bindings
        dom.modalCloseBtn?.addEventListener('click', closeModal);
        dom.modalOverlay?.addEventListener('click', (e) => {
            if (e.target === dom.modalOverlay) closeModal();
        });

        dom.modalViewToggle?.addEventListener('click', () => setModalMode('view'));
        dom.modalEditToggle?.addEventListener('click', () => setModalMode('edit'));

                dom.modalCopyBtn?.addEventListener('click', () => {
            const text = (dom.modalCode && dom.modalCode.value) || 
                         (state.currentModalRule && state.currentModalRule.raw_yaml) || 
                         (dom.modalCodeHl && dom.modalCodeHl.textContent) || '';
            copyTextRobust(text, dom.modalCopyBtn, '<i class="fa-solid fa-check"></i> Copied!');
        });

        dom.modalCode?.addEventListener('input', () => {
            if (state.currentModalRule) {
                state.currentModalRule.raw_yaml = dom.modalCode.value;
            }
            if (dom.modalCodeHl) {
                dom.modalCodeHl.innerHTML = highlightYamlCode(dom.modalCode.value);
            }
        });

        dom.modalSaveBtn?.addEventListener('click', saveModalRule);
        dom.modalDeleteBtn?.addEventListener('click', deleteModalRule);

        dom.modalSendConvertBtn?.addEventListener('click', () => {
            const yml = (dom.modalCode && dom.modalCode.value) || (state.currentModalRule && state.currentModalRule.raw_yaml) || '';
            closeModal();
            switchSubTab('sigma-convert');
            dom.convertInput.value = yml;
            runConversion();
        });

        dom.btnCustomRulesPill?.addEventListener('click', () => {
            state.selectedRepos.clear();
            state.selectedRepos.add('custom');
            document.querySelectorAll('.sigma-repo-chip').forEach(c => {
                c.classList.toggle('active', c.getAttribute('data-repo') === 'custom');
            });
            state.currentPage = 1;
            loadRules();
        });

        dom.btnAutoStatus?.addEventListener('click', () => {
            showAutoUpdateStatusModal();
        });
    }

    // -------------------------------------------------------------
    // NAVIGATION & TAB SWITCHING
    // -------------------------------------------------------------
    function switchSubTab(tabId) {
        state.activeTab = tabId;
        dom.tabs.forEach(t => {
            if (t.getAttribute('data-tab') === tabId) {
                t.classList.add('active');
            } else {
                t.classList.remove('active');
            }
        });

        dom.views.forEach(v => {
            if (v.id === `sigma-view-${tabId.replace('sigma-', '')}`) {
                v.classList.add('active');
            } else {
                v.classList.remove('active');
            }
        });

        // Trigger view loads
        if (tabId === 'sigma-rules') {
            loadRules();
        } else if (tabId === 'sigma-stats') {
            loadStats();
        } else if (tabId === 'sigma-emerging') {
            loadEmergingThreats();
        } else if (tabId === 'sigma-mitre') {
            loadMitreMatrix();
        } else if (tabId === 'sigma-convert') {
            if (!dom.convertInput.value.trim() && state.rules.length > 0) {
                // Preload first rule if empty
                const first = state.rules[0];
                fetchRuleAndSet(first.repo_id, first.filename, 'convert');
            } else if (state.convertMode === 'standard') {
                runConversion();
            }
        }
    }

    // Global open function called by app.js tab switcher
    window.openSigmaTab = function (tabId) {
        ['ioc-search-pane', 'history-pane', 'welcome-overlay', 'm-home-hud', 'mantis-home-pane'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = 'none';
        });
        const contentHeader = document.querySelector('.content-header');
        if (contentHeader) contentHeader.style.display = 'none';
        const pane = document.getElementById('sigma-pane');
        if (pane) pane.style.display = 'flex';
        switchSubTab(tabId || 'sigma-rules');
    };

    // -------------------------------------------------------------
    // DATA FETCHING: REPOSITORIES
    // -------------------------------------------------------------
    async function loadRepositories() {
        try {
            const res = await fetch('/api/sigma/repos');
            const data = await res.json();
            state.repos = data;

            // Render repo filter pills
            renderRepoPills();
            populateRuleSelects();
            loadRules();
        } catch (err) {
            console.error('Error loading Sigma repositories:', err);
        }
    }

    function renderRepoPills() {
        if (!dom.reposFilterBar) return;
        dom.reposFilterBar.innerHTML = '<span class="sigma-repos-label"><i class="fa-solid fa-database"></i> Repositories:</span>';

        state.repos.forEach(repo => {
            const pill = document.createElement('div');
            pill.className = `sigma-repo-pill ${state.selectedRepos.has(repo.id) ? 'active' : ''}`;
            pill.textContent = `${repo.name} (${repo.count})`;
            pill.addEventListener('click', () => {
                if (state.selectedRepos.has(repo.id)) {
                    state.selectedRepos.delete(repo.id);
                } else {
                    state.selectedRepos.add(repo.id);
                }
                pill.classList.toggle('active');
                state.currentPage = 1;
                loadRules();
            });
            dom.reposFilterBar.appendChild(pill);
        });

        // Select All / Clear All
        const actions = document.createElement('div');
        actions.style.marginLeft = 'auto';
        actions.innerHTML = `
            <button type="button" class="pill-action" id="sigma-pill-select-all">Select All</button>
            <span style="color: #475569; margin: 0 4px;">|</span>
            <button type="button" class="pill-action" id="sigma-pill-clear-all">Clear All</button>
        `;
        dom.reposFilterBar.appendChild(actions);

        actions.querySelector('#sigma-pill-select-all').addEventListener('click', () => {
            state.repos.forEach(r => state.selectedRepos.add(r.id));
            dom.reposFilterBar.querySelectorAll('.sigma-repo-pill').forEach(p => p.classList.add('active'));
            state.currentPage = 1;
            loadRules();
        });

        actions.querySelector('#sigma-pill-clear-all').addEventListener('click', () => {
            state.selectedRepos.clear();
            dom.reposFilterBar.querySelectorAll('.sigma-repo-pill').forEach(p => p.classList.remove('active'));
            state.currentPage = 1;
            loadRules();
        });
    }

    async function syncRepositories() {
        if (!dom.syncBtn) return;
        const orig = dom.syncBtn.innerHTML;
        dom.syncBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Syncing All...';
        dom.syncBtn.disabled = true;

        if (typeof window.showStartupProgress === 'function') {
            window.showStartupProgress();
        }

        try {
            await fetch('/api/sigma/repos/sync-all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            await loadRepositories();
            await loadRules();
            dom.syncBtn.innerHTML = '<i class="fa-solid fa-check"></i> Synced!';
            setTimeout(() => {
                dom.syncBtn.innerHTML = orig;
                dom.syncBtn.disabled = false;
            }, 2000);
        } catch (err) {
            console.error('Error syncing Sigma repos:', err);
            dom.syncBtn.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Error';
            setTimeout(() => {
                dom.syncBtn.innerHTML = orig;
                dom.syncBtn.disabled = false;
            }, 2000);
        }
    }

    // -------------------------------------------------------------
    // DATA FETCHING: RULES EXPLORER
    // -------------------------------------------------------------
    async function loadRules() {
        if (!dom.rulesGrid) return;
        dom.rulesGrid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: #94a3b8;"><i class="fa-solid fa-spinner fa-spin fa-2x"></i><p style="margin-top:10px;">Loading detection signatures...</p></div>';

        const params = new URLSearchParams({
            q: state.searchQuery,
            level: state.levelFilter,
            status: state.statusFilter,
            category: state.categoryFilter,
            page: state.currentPage,
            page_size: state.pageSize
        });

        if (state.selectedRepos.size > 0) {
            params.set('repos', Array.from(state.selectedRepos).join(','));
        }

        try {
            const res = await fetch(`/api/sigma/rules?${params.toString()}`);
            const data = await res.json();
            state.rules = data.rules || [];
            state.totalRules = data.total_count || 0;
            state.totalPages = data.total_pages || 1;
            state.currentPage = data.page || 1;

            renderRulesGrid();
            renderPagination();
            populateRuleSelects();
        } catch (err) {
            console.error('Error loading Sigma rules:', err);
            dom.rulesGrid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: #f87171;"><i class="fa-solid fa-triangle-exclamation fa-2x"></i><p style="margin-top:10px;">Failed to load rules.</p></div>';
        }
    }

    function renderRulesGrid() {
        if (!dom.rulesGrid) return;
        if (state.rules.length === 0) {
            dom.rulesGrid.innerHTML = `
                <div style="grid-column: 1/-1; text-align: center; padding: 60px; background: #0f172a; border: 1px dashed #334155; border-radius: 12px;">
                    <i class="fa-solid fa-folder-open fa-3x" style="color: #64748b; margin-bottom: 12px;"></i>
                    <h3 style="color: #f1f5f9; margin: 0 0 6px 0;">No Detection Rules Found</h3>
                    <p style="color: #94a3b8; margin: 0;">Try adjusting your search criteria, clearing repository filters, or create a new custom rule.</p>
                </div>
            `;
            return;
        }

        dom.rulesGrid.innerHTML = '';
        state.rules.forEach(rule => {
            const card = document.createElement('div');
            card.className = 'sigma-rule-card';
            
            // Badges
            const levelClass = rule.level || 'medium';
            const statusText = rule.status || 'stable';
            
            // Format tags
            let tagsHtml = '';
            if (rule.cves && rule.cves.length > 0) {
                rule.cves.slice(0, 2).forEach(cve => {
                    tagsHtml += `<span class="sigma-card-tag cve"><i class="fa-solid fa-bug"></i> ${escapeHtml(cve)}</span>`;
                });
            }
            if (rule.mitre_techniques && rule.mitre_techniques.length > 0) {
                rule.mitre_techniques.slice(0, 2).forEach(tec => {
                    tagsHtml += `<span class="sigma-card-tag mitre"><i class="fa-solid fa-bullseye"></i> ${escapeHtml(tec)}</span>`;
                });
            }
            if (rule.is_ransomware) {
                tagsHtml += `<span class="sigma-card-tag" style="color:#f43f5e; border-color: rgba(244,63,94,0.3);"><i class="fa-solid fa-skull"></i> Ransomware</span>`;
            }
            if (rule.is_lolbas) {
                tagsHtml += `<span class="sigma-card-tag" style="color:#FFCC00; border-color: rgba(56,189,248,0.3);"><i class="fa-solid fa-screwdriver-wrench"></i> LOLBAS</span>`;
            }

            card.innerHTML = `
                <div>
                    <div class="sigma-card-top">
                        <h4 class="sigma-rule-card-title">${escapeHtml(rule.title)}</h4>
                        <div class="sigma-card-badges">
                            <span class="sigma-badge ${levelClass}">${escapeHtml(rule.level)}</span>
                            <span class="sigma-badge status">${escapeHtml(statusText)}</span>
                        </div>
                    </div>
                    <p class="sigma-rule-card-desc">${escapeHtml(rule.description || 'No description provided for this detection signature.')}</p>
                    <div class="sigma-card-meta-row">
                        <span class="sigma-card-repo-pill"><i class="fa-solid fa-layer-group"></i> ${escapeHtml(rule.repo_name)}</span>
                        <span class="sigma-card-logsource"><i class="fa-solid fa-desktop"></i> ${escapeHtml(rule.logsource.product)} / ${escapeHtml(rule.logsource.category)}</span>
                    </div>
                    <div class="sigma-card-tags">${tagsHtml}</div>
                </div>
                <div class="sigma-card-footer">
                    <span><i class="fa-solid fa-user-pen"></i> ${escapeHtml(rule.author || 'Community')}</span>
                    <button type="button" class="sigma-card-inspect-btn" title="Inspect & Edit Rule" aria-label="Inspect & Edit Rule">
                        <i class="fa-solid fa-arrow-right"></i>
                    </button>
                </div>
            `;

            card.addEventListener('click', () => {
                openViewModal(rule.repo_id, rule.filename);
            });

            // Make MITRE & CVE tag pills clickable to filter rules
            card.querySelectorAll('.sigma-card-tag.mitre, .sigma-card-tag.cve').forEach(el => {
                el.style.cursor = 'pointer';
                el.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const tagVal = el.textContent.trim();
                    state.searchQuery = tagVal;
                    state.currentPage = 1;
                    if (dom.searchInput) dom.searchInput.value = tagVal;
                    loadRules();
                });
            });

            dom.rulesGrid.appendChild(card);
        });
    }

    function renderPagination() {
        if (!dom.paginationBar || !dom.paginationControls) return;
        if (state.totalRules === 0) {
            dom.paginationBar.style.display = 'none';
            return;
        }

        dom.paginationBar.style.display = 'flex';
        const start = (state.currentPage - 1) * state.pageSize + 1;
        const end = Math.min(state.currentPage * state.pageSize, state.totalRules);
        dom.paginationInfo.textContent = `Showing ${start}-${end} of ${state.totalRules} rules`;

        dom.paginationControls.innerHTML = '';

        // Prev btn
        const prevBtn = document.createElement('button');
        prevBtn.className = 'sigma-page-btn';
        prevBtn.innerHTML = '<i class="fa-solid fa-chevron-left"></i> Prev';
        prevBtn.disabled = state.currentPage <= 1;
        prevBtn.addEventListener('click', () => {
            if (state.currentPage > 1) {
                state.currentPage--;
                loadRules();
            }
        });
        dom.paginationControls.appendChild(prevBtn);

        // Page buttons (current, +/- 2)
        const startPage = Math.max(1, state.currentPage - 2);
        const endPage = Math.min(state.totalPages, state.currentPage + 2);

        for (let p = startPage; p <= endPage; p++) {
            const pBtn = document.createElement('button');
            pBtn.className = `sigma-page-btn ${p === state.currentPage ? 'active' : ''}`;
            pBtn.textContent = p;
            pBtn.addEventListener('click', () => {
                state.currentPage = p;
                loadRules();
            });
            dom.paginationControls.appendChild(pBtn);
        }

        // Next btn
        const nextBtn = document.createElement('button');
        nextBtn.className = 'sigma-page-btn';
        nextBtn.innerHTML = 'Next <i class="fa-solid fa-chevron-right"></i>';
        nextBtn.disabled = state.currentPage >= state.totalPages;
        nextBtn.addEventListener('click', () => {
            if (state.currentPage < state.totalPages) {
                state.currentPage++;
                loadRules();
            }
        });
        dom.paginationControls.appendChild(nextBtn);
    }

    // -------------------------------------------------------------
    // DATA FETCHING: STATS VIEW
    // -------------------------------------------------------------
    async function loadStats() {
        try {
            const res = await fetch('/api/sigma/stats');
            const data = await res.json();

            // Metric numbers
            if (dom.statTotalRules) dom.statTotalRules.textContent = Number(data.total_rules).toLocaleString();
            if (dom.statTotalRepos) dom.statTotalRepos.textContent = Object.keys(data.repo_counts || {}).length;
            if (dom.statTotalTactics) dom.statTotalTactics.textContent = Object.keys(data.tactic_counts || {}).length;
            if (dom.statEmergingCount) dom.statEmergingCount.textContent = (data.emerging_summary?.total_emerging || 0).toLocaleString();

            // Severity Bars
            if (dom.severityBars) {
                dom.severityBars.innerHTML = '';
                const levels = ['critical', 'high', 'medium', 'low', 'informational'];
                const total = Math.max(1, data.total_rules);
                levels.forEach(lvl => {
                    const count = data.level_counts[lvl] || 0;
                    const pct = Math.round((count / total) * 100);
                    const item = document.createElement('div');
                    item.className = 'sigma-dist-item';
                    item.innerHTML = `
                        <div class="sigma-dist-labels">
                            <span class="sigma-dist-name">${lvl}</span>
                            <span class="sigma-dist-val">${count} (${pct}%)</span>
                        </div>
                        <div class="sigma-progress-track">
                            <div class="sigma-progress-bar ${lvl}" style="width: ${pct}%"></div>
                        </div>
                    `;
                    dom.severityBars.appendChild(item);
                });
            }

            // Status Bars
            if (dom.statusBars) {
                dom.statusBars.innerHTML = '';
                const statuses = ['stable', 'test', 'experimental'];
                const total = Math.max(1, data.total_rules);
                statuses.forEach(st => {
                    const count = data.status_counts[st] || 0;
                    const pct = Math.round((count / total) * 100);
                    const item = document.createElement('div');
                    item.className = 'sigma-dist-item';
                    item.innerHTML = `
                        <div class="sigma-dist-labels">
                            <span class="sigma-dist-name">${st}</span>
                            <span class="sigma-dist-val">${count} (${pct}%)</span>
                        </div>
                        <div class="sigma-progress-track">
                            <div class="sigma-progress-bar ${st}" style="width: ${pct}%"></div>
                        </div>
                    `;
                    dom.statusBars.appendChild(item);
                });
            }

            // Repos Grid in Stats
            if (dom.statsReposGrid) {
                dom.statsReposGrid.innerHTML = '';
                state.repos.forEach(repo => {
                    const count = data.repo_counts[repo.id] || 0;
                    const card = document.createElement('div');
                    card.className = 'sigma-repo-card';
                    card.setAttribute('title', `Click to explore ${count.toLocaleString()} rules in ${repo.name}`);
                    card.innerHTML = `
                        <div class="sigma-repo-info">
                            <h5><i class="fa-solid fa-folder-open" style="font-size:0.8rem; color:#FFCC00; margin-right:7px; opacity:0.85;"></i>${escapeHtml(repo.name)}</h5>
                            <p title="${escapeHtml(repo.description || '')}">${escapeHtml(repo.description || '')}</p>
                        </div>
                        <span class="sigma-repo-badge">
                            <span class="sigma-repo-badge-count">${count.toLocaleString()}</span>
                            <span class="sigma-repo-badge-label">rules</span>
                        </span>
                    `;
                    card.addEventListener('click', () => {
                        state.selectedRepos.clear();
                        state.selectedRepos.add(repo.id);
                        switchSubTab('sigma-rules');
                        renderRepoPills();
                        state.currentPage = 1;
                        loadRules();
                    });
                    dom.statsReposGrid.appendChild(card);
                });
            }

            // Top Authors
            if (dom.topAuthorsList) {
                dom.topAuthorsList.innerHTML = '';
                (data.top_authors || []).slice(0, 6).forEach(author => {
                    const li = document.createElement('li');
                    li.style.cssText = 'display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid #1e293b; font-size:0.8rem;';
                    li.innerHTML = `<span style="color:#cbd5e1;">${escapeHtml(author.name)}</span> <span style="font-weight:600; color:#FFCC00;">${author.count} rules</span>`;
                    dom.topAuthorsList.appendChild(li);
                });
            }

            // Top Products
            if (dom.topProductsList) {
                dom.topProductsList.innerHTML = '';
                (data.top_products || []).slice(0, 6).forEach(prod => {
                    const li = document.createElement('li');
                    li.style.cssText = 'display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid #1e293b; font-size:0.8rem;';
                    li.innerHTML = `<span style="color:#cbd5e1; text-transform:capitalize;">${escapeHtml(prod.name)}</span> <span style="font-weight:600; color:#34d399;">${prod.count} rules</span>`;
                    dom.topProductsList.appendChild(li);
                });
            }

            // Top Techniques
            if (dom.topTechniquesList) {
                dom.topTechniquesList.innerHTML = '';
                (data.top_techniques || []).slice(0, 6).forEach(tec => {
                    const li = document.createElement('li');
                    li.style.cssText = 'display:flex; justify-content:space-between; padding:6px 8px; border-bottom:1px solid #1e293b; font-size:0.8rem; cursor:pointer; border-radius:4px;';
                    li.title = `Filter rules by ${tec.id}`;
                    li.innerHTML = `
                        <span>
                            <strong style="color:#fbbf24;">${escapeHtml(tec.id)}</strong>
                            <span style="color:#94a3b8; margin-left:6px;">${escapeHtml(tec.name)}</span>
                        </span>
                        <span style="font-weight:600; color:#FFCC00;">${tec.count}</span>
                    `;
                    li.addEventListener('click', () => {
                        state.searchQuery = tec.id;
                        state.currentPage = 1;
                        if (dom.searchInput) dom.searchInput.value = tec.id;
                        switchSubTab('sigma-rules');
                    });
                    dom.topTechniquesList.appendChild(li);
                });
            }

        } catch (err) {
            console.error('Error loading Sigma stats:', err);
        }
    }

    // -------------------------------------------------------------
    // DATA FETCHING: EMERGING THREATS
    // -------------------------------------------------------------
    async function loadEmergingThreats() {
        if (!dom.emergingGrid) return;
        dom.emergingGrid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: #94a3b8;"><i class="fa-solid fa-spinner fa-spin fa-2x"></i><p style="margin-top:10px;">Loading emerging threats & exploits...</p></div>';

        try {
            const params = new URLSearchParams({
                category: state.emergingCategory,
                q: state.emergingQuery
            });
            const res = await fetch(`/api/sigma/emerging?${params.toString()}`);
            const data = await res.json();

            // Update badge counts on nav pills
            if (data.counts && dom.emergingNav) {
                Object.keys(data.counts).forEach(k => {
                    const countEl = dom.emergingNav.querySelector(`[data-cat="${k}"] .sigma-emerging-count`);
                    if (countEl) countEl.textContent = data.counts[k];
                });
            }

            const rules = data.rules || [];
            if (rules.length === 0) {
                dom.emergingGrid.innerHTML = `
                    <div style="grid-column: 1/-1; text-align: center; padding: 50px; background: #0f172a; border: 1px dashed #334155; border-radius: 12px;">
                        <i class="fa-solid fa-shield-virus fa-3x" style="color: #64748b; margin-bottom: 12px;"></i>
                        <h4 style="color: #f1f5f9; margin: 0 0 6px 0;">No Matching Emerging Threat Rules</h4>
                        <p style="color: #94a3b8; margin: 0;">Try searching for a different CVE, threat actor, or malware family.</p>
                    </div>
                `;
                return;
            }

            dom.emergingGrid.innerHTML = '';
            rules.forEach(rule => {
                const card = document.createElement('div');
                card.className = 'sigma-rule-card';

                // Classification highlight
                let threatBadge = '';
                if (rule.cves && rule.cves.length > 0) {
                    threatBadge = `<span class="sigma-badge" style="background:rgba(239,68,68,0.2); color:#f87171; border:1px solid #ef4444;"><i class="fa-solid fa-bug"></i> ${rule.cves.join(', ')}</span>`;
                } else if (rule.is_ransomware) {
                    threatBadge = `<span class="sigma-badge" style="background:rgba(244,63,94,0.2); color:#fb7185; border:1px solid #f43f5e;"><i class="fa-solid fa-skull"></i> Ransomware</span>`;
                } else if (rule.is_apt) {
                    threatBadge = `<span class="sigma-badge" style="background:rgba(168,85,247,0.2); color:#c084fc; border:1px solid #a855f7;"><i class="fa-solid fa-user-secret"></i> APT Group</span>`;
                } else {
                    threatBadge = `<span class="sigma-badge" style="background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid #f59e0b;"><i class="fa-solid fa-fire"></i> High Severity</span>`;
                }

                card.innerHTML = `
                    <div>
                        <div class="sigma-card-top">
                            <h4 class="sigma-rule-card-title">${escapeHtml(rule.title)}</h4>
                            <div class="sigma-card-badges">
                                ${threatBadge}
                            </div>
                        </div>
                        <p class="sigma-rule-card-desc">${escapeHtml(rule.description || 'Detection signature targeting high-risk emerging adversary activity.')}</p>
                        <div class="sigma-card-meta-row">
                            <span class="sigma-card-repo-pill">${escapeHtml(rule.repo_name)}</span>
                            <span class="sigma-card-logsource">${escapeHtml(rule.logsource.product)} / ${escapeHtml(rule.logsource.category)}</span>
                            <span class="sigma-badge ${rule.level}">${escapeHtml(rule.level)}</span>
                        </div>
                    </div>
                    <div class="sigma-card-footer">
                        <span><i class="fa-regular fa-clock"></i> ${escapeHtml(rule.date || 'Active')}</span>
                        <div style="display:flex; gap:10px;">
                            <button type="button" class="sigma-card-inspect-btn btn-inspect" title="Inspect & Edit Rule" aria-label="Inspect & Edit Rule">
                                <i class="fa-solid fa-arrow-right"></i>
                            </button>
                        </div>
                    </div>
                `;

                card.querySelector('.btn-inspect').addEventListener('click', (e) => {
                    e.stopPropagation();
                    openViewModal(rule.repo_id, rule.filename);
                });

                card.addEventListener('click', () => {
                    openViewModal(rule.repo_id, rule.filename);
                });

                dom.emergingGrid.appendChild(card);
            });

        } catch (err) {
            console.error('Error loading emerging threats:', err);
        }
    }

    // -------------------------------------------------------------
    // DATA FETCHING: MITRE ATT&CK MATRIX
    // -------------------------------------------------------------
    async function loadMitreMatrix() {
        if (!dom.mitreGrid) return;
        dom.mitreGrid.innerHTML = '<div style="padding: 40px; color: #94a3b8;"><i class="fa-solid fa-spinner fa-spin"></i> Loading MITRE ATT&CK matrix...</div>';

        try {
            const res = await fetch('/api/sigma/mitre');
            const data = await res.json();
            const tactics = data.tactics || [];

            dom.mitreGrid.innerHTML = '';
            tactics.forEach(tac => {
                const col = document.createElement('div');
                col.className = 'sigma-mitre-col';

                col.innerHTML = `
                    <div class="sigma-mitre-col-header">
                        <h4>${escapeHtml(tac.name)}</h4>
                        <span class="tac-count">${tac.rule_count} rules · ${tac.techniques_count} tech</span>
                    </div>
                    <div class="sigma-mitre-cells"></div>
                `;

                const cellsContainer = col.querySelector('.sigma-mitre-cells');
                if (tac.techniques.length === 0) {
                    cellsContainer.innerHTML = '<span style="font-size: 0.72rem; color: #475569; padding: 10px 4px; text-align: center;">No rules mapped</span>';
                } else {
                    tac.techniques.forEach(tec => {
                        const cell = document.createElement('div');
                        cell.className = `sigma-mitre-cell ${tec.count > 0 ? 'highlight' : ''}`;
                        cell.innerHTML = `
                            <div class="sigma-mitre-cell-top">
                                <span class="sigma-mitre-tid">${escapeHtml(tec.id)}</span>
                                <span class="sigma-mitre-tcount">${tec.count}</span>
                            </div>
                            <div class="sigma-mitre-tname">${escapeHtml(tec.name)}</div>
                        `;

                        cell.addEventListener('click', () => {
                            // Filter rules explorer to this technique
                            state.searchQuery = tec.id;
                            state.currentPage = 1;
                            if (dom.searchInput) dom.searchInput.value = tec.id;
                            switchSubTab('sigma-rules');
                        });

                        cellsContainer.appendChild(cell);
                    });
                }

                dom.mitreGrid.appendChild(col);
            });

        } catch (err) {
            console.error('Error loading MITRE matrix:', err);
        }
    }

    // -------------------------------------------------------------
    // CONVERTER LOGIC (10+ TARGETS & AI-POWERED ENGINE)
    // -------------------------------------------------------------
    async function loadAIProviders() {
        if (state.aiProviders.length > 0) return;
        try {
            const res = await fetch('/api/ai/settings');
            if (!res.ok) return;
            const data = await res.json();
            const providers = data.providers || [];
            state.aiProviders = providers;
            state.convertAIProvider = data.provider || (providers[0] ? providers[0].id : '');
            state.convertAIModel = data.model || (providers[0] ? providers[0].model : '');

            if (dom.convertAIProviderSelect) {
                dom.convertAIProviderSelect.innerHTML = providers.map(p => 
                    `<option value="${escapeHtml(p.id)}" ${p.id === state.convertAIProvider ? 'selected' : ''}>${escapeHtml(p.label || p.id)}</option>`
                ).join('');
            }
            if (dom.convertAIModelInput && state.convertAIModel) {
                dom.convertAIModelInput.value = state.convertAIModel;
            }
        } catch (err) {
            console.error('Error loading AI providers for Sigma:', err);
        }
    }

    async function runConversion() {
        if (!dom.convertOutput) return;
        const yamlText = dom.convertInput ? dom.convertInput.value.trim() : '';
        if (!yamlText) {
            dom.convertOutput.textContent = '// Enter a valid Sigma YAML rule on the left, or select a preloaded rule to generate target queries.';
            if (dom.convertValBadge) dom.convertValBadge.style.display = 'none';
            if (dom.convertValBanner) dom.convertValBanner.style.display = 'none';
            if (dom.convertRepairBtn) dom.convertRepairBtn.style.display = 'none';
            if (dom.convertToggleBreakdownBtn) dom.convertToggleBreakdownBtn.style.display = 'none';
            if (dom.convertDiffPane) dom.convertDiffPane.style.display = 'none';
            return;
        }

        const mode = state.convertMode || 'standard';
        const target = state.convertTarget || 'splunk';
        const modeLabel = mode === 'ai' ? 'AI Conversion' : (mode === 'ai_repair' ? 'AI-Assisted Repair' : 'Standard pySigma');

        dom.convertOutput.textContent = `// [${modeLabel.toUpperCase()}] Generating query for ${target.toUpperCase()}...`;
        if (dom.convertRunBtn) dom.convertRunBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Converting...';

        try {
            const payload = {
                content: yamlText,
                target: target,
                mode: mode,
                provider: state.convertAIProvider || undefined,
                model: state.convertAIModel || undefined
            };

            const res = await fetch('/api/sigma/convert', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            state.lastConversionData = data;

            if (!data.success) {
                dom.convertOutput.textContent = `/* Conversion Error (${modeLabel}): \n${data.error || 'Failed to translate Sigma rule.'} */`;
                renderValidationStatus({ status: 'Failed', summary: data.error || 'Conversion failed.' });
                if (mode === 'standard' && dom.convertRepairBtn) {
                    dom.convertRepairBtn.style.display = 'inline-flex';
                }
                return;
            }

            if (target === 'all' && mode === 'standard') {
                let out = '';
                const conversions = data.conversions || {};
                Object.keys(conversions).forEach(k => {
                    const c = conversions[k];
                    out += `======================================================\n`;
                    out += `// TARGET: ${k.toUpperCase()}\n`;
                    out += `======================================================\n`;
                    if (c && c.success) {
                        out += `${c.query || 'No query generated.'}\n\n`;
                    } else {
                        out += `/* Conversion Error: ${c?.error || 'Failed to translate rule.'} */\n\n`;
                    }
                });
                dom.convertOutput.textContent = out;
                if (dom.convertValBadge) dom.convertValBadge.style.display = 'none';
                if (dom.convertValBanner) dom.convertValBanner.style.display = 'none';
            } else {
                dom.convertOutput.textContent = data.query || 'No query generated.';
                
                // Render deterministic validation
                if (data.validation) {
                    renderValidationStatus(data.validation, data);
                } else {
                    if (dom.convertValBadge) dom.convertValBadge.style.display = 'none';
                    if (dom.convertValBanner) dom.convertValBanner.style.display = 'none';
                }

                // Render diff if AI repair
                if (data.mode === 'ai_repair' && data.diff) {
                    renderDiff(data.diff);
                } else if (dom.convertDiffPane) {
                    dom.convertDiffPane.style.display = 'none';
                }

                // Render breakdown content
                renderBreakdown(data);
            }

        } catch (err) {
            console.error('Error running conversion:', err);
            dom.convertOutput.textContent = `/* Error connecting to converter engine: ${err.message} */`;
            renderValidationStatus({ status: 'Failed', summary: err.message });
        } finally {
            if (dom.convertRunBtn) dom.convertRunBtn.innerHTML = '<i class="fa-solid fa-play"></i> Convert';
        }
    }

    function renderValidationStatus(val, data) {
        if (!dom.convertValBadge || !dom.convertValBanner) return;
        const status = val.status || 'Validated';
        const isOk = status === 'Validated';
        const isWarn = status === 'Warning';
        const isFail = status === 'Failed';

        dom.convertValBadge.className = `sigma-val-badge ${status.toLowerCase()}`;
        dom.convertValBadge.innerHTML = isOk 
            ? '<i class="fa-solid fa-circle-check"></i> Validated' 
            : (isWarn 
                ? '<i class="fa-solid fa-triangle-exclamation"></i> Warning' 
                : '<i class="fa-solid fa-circle-xmark"></i> Failed');
        dom.convertValBadge.style.display = 'inline-flex';

        if (dom.convertValText) {
            let cleanSummary = (val.summary || '').trim();
            cleanSummary = cleanSummary.replace(/^(validated|warning|failed|validation failed|fully validated):\s*/i, '');
            const scoreText = val.score !== undefined ? ` [Coverage: ${Math.round(val.score * 100)}%]` : '';
            dom.convertValText.innerHTML = `<strong>${escapeHtml(status)}:</strong> ${escapeHtml(cleanSummary)}${scoreText}`;
        }
        dom.convertValBanner.style.display = 'flex';

        // Show "Repair with AI" if there are issues or warnings and we are in standard mode
        if (dom.convertRepairBtn) {
            if ((isFail || isWarn) && state.convertMode === 'standard') {
                dom.convertRepairBtn.style.display = 'inline-flex';
            } else {
                dom.convertRepairBtn.style.display = 'none';
            }
        }
    }

    function renderDiff(diffText) {
        if (!dom.convertDiffPane || !dom.convertDiffOutput) return;
        if (!diffText || !diffText.trim()) {
            dom.convertDiffPane.style.display = 'none';
            return;
        }

        const lines = diffText.split('\n');
        const formatted = lines.map(line => {
            if (line.startsWith('+') && !line.startsWith('+++')) {
                return `<div class="sigma-diff-line-add">${escapeHtml(line)}</div>`;
            } else if (line.startsWith('-') && !line.startsWith('---')) {
                return `<div class="sigma-diff-line-del">${escapeHtml(line)}</div>`;
            } else {
                return `<div>${escapeHtml(line)}</div>`;
            }
        }).join('');

        dom.convertDiffOutput.innerHTML = formatted;
        dom.convertDiffPane.style.display = 'block';
    }

    function renderBreakdown(data) {
        if (!dom.convertToggleBreakdownBtn || !dom.convertBreakdownContent) return;
        dom.convertToggleBreakdownBtn.style.display = 'inline-flex';

        let html = '';

        // AI Explanation
        if (data.explanation) {
            html += `
                <div class="sigma-breakdown-section">
                    <div class="sigma-breakdown-section-title"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Translation Explanation</div>
                    <div class="sigma-breakdown-explanation">${escapeHtml(data.explanation)}</div>
                </div>
            `;
        }

        // Selections Coverage
        const selCov = data.validation?.selection_coverage;
        if (selCov && selCov.details && selCov.details.length > 0) {
            html += `
                <div class="sigma-breakdown-section">
                    <div class="sigma-breakdown-section-title"><i class="fa-solid fa-bullseye"></i> Detection Selections Coverage (${selCov.covered}/${selCov.total} Covered)</div>
                    <div class="sigma-selections-grid">
                        ${selCov.details.map(s => `
                            <div class="sigma-selection-card ${s.status}">
                                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
                                    <strong>${escapeHtml(s.selection)}</strong>
                                    <span class="sigma-val-badge ${s.status}" style="font-size: 0.65rem; padding: 1px 6px;">${s.status}</span>
                                </div>
                                <div style="color: #94a3b8; font-size: 0.7rem;">Matches: ${s.matched_count}/${s.total_count}</div>
                                ${s.sample_matches && s.sample_matches.length > 0 ? `<div style="color: #64748b; font-size: 0.68rem; margin-top: 2px;">Terms: ${escapeHtml(s.sample_matches.join(', '))}</div>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        // Field Mappings
        const mappings = data.field_mappings || [];
        if (mappings.length > 0) {
            html += `
                <div class="sigma-breakdown-section">
                    <div class="sigma-breakdown-section-title"><i class="fa-solid fa-arrow-right-arrow-left"></i> Field Mappings</div>
                    <table class="sigma-mappings-table">
                        <thead>
                            <tr><th>Sigma Field</th><th>Target Field</th><th>Description</th></tr>
                        </thead>
                        <tbody>
                            ${mappings.map(m => `
                                <tr>
                                    <td><code>${escapeHtml(m.sigma_field || '')}</code></td>
                                    <td><code style="color: #FFCC00;">${escapeHtml(m.target_field || '')}</code></td>
                                    <td style="color: #94a3b8;">${escapeHtml(m.description || '')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        // Warnings / Limitations
        const warnings = (data.warnings || []).concat(data.validation?.warnings || []);
        const unsupported = data.unsupported_features || [];
        if (warnings.length > 0 || unsupported.length > 0) {
            html += `
                <div class="sigma-breakdown-section">
                    <div class="sigma-breakdown-section-title"><i class="fa-solid fa-triangle-exclamation"></i> Warnings & Assumptions</div>
                    <div class="sigma-breakdown-warnings">
                        <ul style="margin: 0; padding-left: 18px;">
                            ${warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
                            ${unsupported.map(u => `<li><strong>Unsupported feature:</strong> ${escapeHtml(u)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }

        dom.convertBreakdownContent.innerHTML = html || '<div style="color: #64748b; font-size: 0.78rem;">No additional breakdown details available.</div>';
    }

    async function validateRuleText(yamlText) {
        if (!yamlText.trim()) return;
        try {
            const res = await fetch('/api/sigma/validate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: yamlText })
            });
            const data = await res.json();
            if (data.valid) {
                alert('✓ Rule is VALID against standard Sigma specifications.');
            } else {
                alert('✕ Validation Errors:\n\n• ' + data.errors.join('\n• '));
            }
        } catch (err) {
            alert('Error running validation: ' + err.message);
        }
    }

    // -------------------------------------------------------------
    // 2-COLUMN WORKSTATION MODAL LOGIC
    // -------------------------------------------------------------
    async function openViewModal(repoId, filename) {
        try {
            const res = await fetch(`/api/sigma/rule?repo=${encodeURIComponent(repoId)}&path=${encodeURIComponent(filename)}`);
            if (!res.ok) {
                alert(`Rule '${filename}' not found.`);
                return;
            }
            const data = await res.json();
            state.currentModalRule = {
                repo_id: repoId,
                filename: filename,
                metadata: data.metadata || {},
                raw_yaml: data.raw_yaml || ''
            };
            setModalMode('view');
            populateModal();
            dom.modalOverlay?.classList.add('active');
        } catch (err) {
            console.error('Error opening view modal:', err);
        }
    }

    function openCreateModal() {
        const template = `title: New Custom Detection Signature
id: ${generateUuid()}
status: experimental
description: Describe the adversary behavior, LOLBAS technique, or attack vector detected by this rule.
references:
    - https://attack.mitre.org/
author: ${localStorage.getItem('mantis_user') || 'Threat Analyst'}
date: ${new Date().toISOString().split('T')[0]}
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - 'DownloadString'
            - 'Invoke-Expression'
    condition: selection
falsepositives:
    - Legitimate administrative automation scripts.
level: high
`;
        state.currentModalRule = {
            repo_id: 'custom',
            filename: `custom_rule_${Date.now()}.yml`,
            metadata: {
                title: 'New Custom Detection Signature',
                level: 'high',
                status: 'experimental',
                repo_name: 'Custom & Local Rules',
                repo_id: 'custom',
                author: 'Threat Analyst',
                logsource: { product: 'windows', category: 'process_creation', service: '' }
            },
            raw_yaml: template
        };

        setModalMode('create');
        populateModal();
        dom.modalOverlay?.classList.add('active');
    }

    function closeModal() {
        dom.modalOverlay?.classList.remove('active');
        state.currentModalRule = null;
    }

    function setModalMode(mode) {
        state.modalMode = mode;
        if (mode === 'view') {
            dom.modalViewToggle?.classList.add('active');
            dom.modalEditToggle?.classList.remove('active');
            if (dom.modalCodeView) dom.modalCodeView.style.display = 'block';
            if (dom.modalCode) dom.modalCode.style.display = 'none';
            if (dom.modalSaveBtn) dom.modalSaveBtn.style.display = 'none';
            renderModalYaml();
        } else {
            dom.modalViewToggle?.classList.remove('active');
            dom.modalEditToggle?.classList.add('active');
            if (dom.modalCodeView) dom.modalCodeView.style.display = 'none';
            if (dom.modalCode) {
                dom.modalCode.style.display = 'block';
                dom.modalCode.readOnly = false;
                dom.modalCode.value = (state.currentModalRule && state.currentModalRule.raw_yaml) || dom.modalCode.value || '';
                setTimeout(() => dom.modalCode.focus(), 50);
            }
            if (dom.modalSaveBtn) dom.modalSaveBtn.style.display = 'inline-flex';
        }
    }

    function renderModalYaml() {
        const raw = (state.currentModalRule && state.currentModalRule.raw_yaml) || (dom.modalCode && dom.modalCode.value) || '';
        if (dom.modalCodeHl) {
            dom.modalCodeHl.innerHTML = highlightYamlCode(raw);
        }
        if (dom.modalCode) {
            dom.modalCode.value = raw;
        }
    }

    function populateModal() {
        const r = state.currentModalRule;
        if (!r) return;

        const m = r.metadata || {};
        if (dom.modalTitle) dom.modalTitle.textContent = m.title || r.filename;
        renderModalYaml();

        if (dom.modalLeftMeta) {
            let refsHtml = '';
            (m.references || []).forEach(ref => {
                refsHtml += `<a href="${escapeHtml(ref)}" target="_blank" style="display:block; color:#FFCC00; font-size:0.75rem; margin-bottom:3px; word-break:break-all;">${escapeHtml(ref)}</a>`;
            });

            let tagsHtml = '';
            (m.tags || []).forEach(t => {
                tagsHtml += `<span class="sigma-card-tag" style="margin:2px;">${escapeHtml(t)}</span>`;
            });

            dom.modalLeftMeta.innerHTML = `
                <div class="sigma-meta-section">
                    <div class="sigma-meta-label">Collection / Repository</div>
                    <div class="sigma-meta-val"><strong style="color:#FFCC00;">${escapeHtml(m.repo_name || r.repo_id)}</strong></div>
                </div>
                <div class="sigma-meta-section">
                    <div class="sigma-meta-label">File / Identifier</div>
                    <div class="sigma-meta-val" style="font-family:monospace; font-size:0.75rem; color:#94a3b8;">${escapeHtml(r.filename)}</div>
                </div>
                <div class="sigma-meta-section">
                    <div class="sigma-meta-label">Severity & Status</div>
                    <div class="sigma-meta-val" style="display:flex; gap:6px; margin-top:4px;">
                        <span class="sigma-badge ${m.level || 'medium'}">${escapeHtml(m.level || 'medium')}</span>
                        <span class="sigma-badge status">${escapeHtml(m.status || 'stable')}</span>
                    </div>
                </div>
                <div class="sigma-meta-section">
                    <div class="sigma-meta-label">Logsource Target</div>
                    <div class="sigma-meta-val">${escapeHtml(m.logsource?.product || 'windows')} / ${escapeHtml(m.logsource?.category || 'general')}</div>
                </div>
                <div class="sigma-meta-section">
                    <div class="sigma-meta-label">Author & Creation</div>
                    <div class="sigma-meta-val">${escapeHtml(m.author || 'Unknown')} (${escapeHtml(m.date || 'N/A')})</div>
                </div>
                <div class="sigma-meta-section">
                    <div class="sigma-meta-label">Tags & Classifications</div>
                    <div class="sigma-meta-val" style="display:flex; flex-wrap:wrap; margin-top:4px;">${tagsHtml || '<span style="color:#64748b;">No tags defined</span>'}</div>
                </div>
                <div class="sigma-meta-section">
                    <div class="sigma-meta-label">External References</div>
                    <div class="sigma-meta-val">${refsHtml || '<span style="color:#64748b; font-size:0.75rem;">None</span>'}</div>
                </div>
            `;
        }
    }

    async function saveModalRule() {
        const r = state.currentModalRule;
        if (!r) return;
        const yamlContent = dom.modalCode.value;

        try {
            const endpoint = state.modalMode === 'create' ? '/api/sigma/rule/create' : '/api/sigma/rule/save';
            const body = {
                content: yamlContent,
                repo: r.repo_id,
                filename: r.filename
            };

            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            const data = await res.json();
            if (!res.ok || !data.success) {
                alert(`Save Failed:\n${data.detail || data.message || 'Validation error'}`);
                return;
            }

            alert('✓ Rule successfully validated and saved to repository.');
            closeModal();
            loadRepositories();
        } catch (err) {
            alert('Error saving rule: ' + err.message);
        }
    }

    async function deleteModalRule() {
        const r = state.currentModalRule;
        if (!r) return;

        if (!confirm(`Are you sure you want to permanently delete '${r.filename}'?\n\nThis will record the rule in tombstones so it will never be re-synced.`)) {
            return;
        }

        try {
            const res = await fetch('/api/sigma/rule', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    repo: r.repo_id,
                    filename: r.filename
                })
            });

            const data = await res.json();
            if (data.success) {
                alert(`Rule '${r.filename}' deleted and permanently registered in tombstones.`);
                closeModal();
                loadRepositories();
            } else {
                alert('Delete failed: ' + (data.message || 'Unknown error'));
            }
        } catch (err) {
            alert('Error deleting rule: ' + err.message);
        }
    }

    // -------------------------------------------------------------
    // UTILITY HELPERS
    // -------------------------------------------------------------
    function populateRuleSelects() {
        if (!dom.convertRuleSelect) return;
        
        let options = '<option value="">-- Choose a preloaded Sigma Rule --</option>';
        state.rules.forEach(r => {
            options += `<option value="${r.repo_id}::${r.filename}">${escapeHtml(r.title)} (${r.repo_id})</option>`;
        });

        if (dom.convertRuleSelect) dom.convertRuleSelect.innerHTML = options;
    }

    async function fetchRuleAndSet(repoId, filename, target) {
        try {
            const res = await fetch(`/api/sigma/rule?repo=${encodeURIComponent(repoId)}&path=${encodeURIComponent(filename)}`);
            const data = await res.json();
            if (data.raw_yaml) {
                if (target === 'convert' && dom.convertInput) {
                    dom.convertInput.value = data.raw_yaml;
                    if (state.convertMode === 'standard') {
                        runConversion();
                    } else if (dom.convertOutput) {
                        dom.convertOutput.textContent = `// Rule loaded. Click "Convert" to run ${state.convertMode === 'ai' ? 'AI Conversion' : 'AI-Assisted Repair'}.`;
                    }
                }
            }
        } catch (err) {
            console.error('Error fetching rule YAML:', err);
        }
    }

    function generateUuid() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    function escapeHtml(text) {
        if (!text) return '';
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function copyTextRobust(text, btnElement, successHtml = '<i class="fa-solid fa-check"></i> Copied!') {
        if (!text || !String(text).trim()) {
            if (btnElement) {
                const orig = btnElement.innerHTML;
                btnElement.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Empty';
                setTimeout(() => { btnElement.innerHTML = orig; }, 1500);
            }
            return Promise.resolve(false);
        }

        const str = String(text);
        let copied = false;

        // 1. Synchronously execute execCommand('copy') FIRST to guarantee user gesture transient activation
        try {
            const ta = document.createElement('textarea');
            ta.value = str;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.top = '0';
            ta.style.left = '-9999px';
            ta.style.width = '2em';
            ta.style.height = '2em';
            ta.style.padding = '0';
            ta.style.border = 'none';
            ta.style.outline = 'none';
            ta.style.boxShadow = 'none';
            ta.style.background = 'transparent';
            ta.style.opacity = '0';
            ta.style.zIndex = '-1';
            document.body.appendChild(ta);
            ta.focus({ preventScroll: true });
            ta.select();
            ta.setSelectionRange(0, str.length);
            copied = document.execCommand('copy');
            document.body.removeChild(ta);
        } catch (err) {
            console.warn('[SIGMA] Synchronous execCommand copy attempt failed:', err);
            copied = false;
        }

        // 2. If modern navigator.clipboard is available, also attempt it for maximum fidelity
        if (!copied && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            return navigator.clipboard.writeText(str).then(() => {
                if (btnElement) flashSuccess(btnElement, successHtml);
                return true;
            }).catch(err => {
                console.error('[SIGMA] Both execCommand and navigator.clipboard failed:', err);
                if (btnElement) flashError(btnElement);
                return false;
            });
        }

        if (btnElement) {
            if (copied) {
                flashSuccess(btnElement, successHtml);
            } else {
                flashError(btnElement);
            }
        }
        return Promise.resolve(copied);

        function flashSuccess(btn, html) {
            const orig = btn.innerHTML;
            btn.innerHTML = html;
            btn.classList.add('btn-copied-flash');
            setTimeout(() => {
                btn.innerHTML = orig;
                btn.classList.remove('btn-copied-flash');
            }, 1800);
        }

        function flashError(btn) {
            const orig = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Copy Error';
            setTimeout(() => { btn.innerHTML = orig; }, 1800);
        }
    }

    function highlightYamlCode(rawYaml) {
        if (!rawYaml) return '';

        // If window.hljs is available and supports yaml:
        if (window.hljs && typeof window.hljs.highlight === 'function') {
            try {
                if (typeof window.hljs.getLanguage === 'function' && window.hljs.getLanguage('yaml')) {
                    return window.hljs.highlight(rawYaml, { language: 'yaml' }).value;
                } else if (typeof window.hljs.highlightAuto === 'function') {
                    return window.hljs.highlightAuto(rawYaml).value;
                }
            } catch (e) {
                console.warn('[SIGMA] hljs highlighting error, falling back to tokenizer:', e);
            }
        }

        // Resilient fallback YAML syntax tokenizer
        const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return rawYaml.split('\n').map(line => {
            const commentIdx = line.indexOf('#');
            let codePart = line;
            let commentPart = '';
            if (commentIdx !== -1) {
                const prefix = line.slice(0, commentIdx);
                const sQuotes = (prefix.match(/'/g) || []).length;
                const dQuotes = (prefix.match(/"/g) || []).length;
                if (sQuotes % 2 === 0 && dQuotes % 2 === 0) {
                    codePart = line.slice(0, commentIdx);
                    commentPart = `<span class="hljs-comment">${esc(line.slice(commentIdx))}</span>`;
                }
            }

            let formatted = esc(codePart);
            if (formatted.includes(':')) {
                formatted = formatted.replace(/^(\s*)([-]\s+)?([a-zA-Z0-9_\-\.\/\|]+)(\s*:)(.*)$/, (m, indent, dash, key, colon, rest) => {
                    let out = indent;
                    if (dash) out += `<span class="hljs-bullet">${dash}</span>`;
                    if (key.includes('|')) {
                        const parts = key.split('|');
                        out += `<span class="hljs-attr">${parts[0]}</span><span class="hljs-keyword">|${parts.slice(1).join('|')}</span>`;
                    } else {
                        out += `<span class="hljs-attr">${key}</span>`;
                    }
                    out += `<span style="color:#64748b;">${colon}</span>`;

                    let val = rest;
                    val = val.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, '<span class="hljs-string">$1</span>');
                    val = val.replace(/\b(true|false|yes|no|null|None|True|False)\b/g, '<span class="hljs-literal">$1</span>');
                    val = val.replace(/\b(\d+(\.\d+)?|0x[0-9a-fA-F]+)\b/g, '<span class="hljs-number">$1</span>');
                    val = val.replace(/(\s+)([|>][+-]?)$/, '$1<span class="hljs-symbol">$2</span>');
                    out += val;
                    return out;
                });
            } else if (/^\s*-\s+/.test(codePart)) {
                formatted = formatted.replace(/^(\s*-\s+)(.*)$/, (m, dash, val) => {
                    let out = `<span class="hljs-bullet">${dash}</span>`;
                    val = val.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, '<span class="hljs-string">$1</span>');
                    val = val.replace(/\b(true|false|yes|no|null|None|True|False)\b/g, '<span class="hljs-literal">$1</span>');
                    val = val.replace(/\b(\d+(\.\d+)?|0x[0-9a-fA-F]+)\b/g, '<span class="hljs-number">$1</span>');
                    return out + val;
                });
            }

            return formatted + commentPart;
        }).join('\n');
    }

    async function showAutoUpdateStatusModal() {
        try {
            const res = await fetch('/api/meta/auto-update-status');
            const data = await res.json();
            const lastIso = data.last_run_iso ? new Date(data.last_run_iso).toLocaleString() : 'Not run yet';
            const nextIso = data.next_scheduled_iso ? new Date(data.next_scheduled_iso).toLocaleString() : 'In 7 days';
            
            const msg = `MANTIS AUTOMATIC DATA UPDATER\n------------------------------------\n` +
                        `• Schedule: Startup Check + Every 7 Days Recurring\n` +
                        `• Status: ${data.status.toUpperCase()}\n` +
                        `• Interval: ${data.interval_days} Days\n` +
                        `• Last Run: ${lastIso}\n` +
                        `• Next Due: ${nextIso}\n` +
                        `• Updating Now: ${data.is_currently_updating ? 'YES' : 'NO'}\n\n` +
                        `Would you like to trigger a full dataset update right now across all 6 SIGMA repos, YARA rules, PoC Index, and threat feeds?`;
            
            if (confirm(msg)) {
                const triggerRes = await fetch('/api/meta/auto-update-now', { method: 'POST' });
                const triggerData = await triggerRes.json();
                alert(triggerData.message || 'Auto-update initiated in background thread.');
            }
        } catch (err) {
            alert('Failed to retrieve auto-update status: ' + err.message);
        }
    }

    // Auto-initialize when DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
