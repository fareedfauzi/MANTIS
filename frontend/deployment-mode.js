// MANTIS Deployment Mode & Server Staging Controller
(function () {
    let deploymentState = null;

    async function fetchDeploymentConfig() {
        try {
            const res = await fetch('/api/config/deployment');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            deploymentState = await res.json();
            window.MANTIS_DEPLOYMENT = deploymentState;
            applyModeClasses();
            renderDeploymentPanel();
            enhanceFeatureViews();
            return deploymentState;
        } catch (err) {
            console.warn('[DeploymentMode] Failed to fetch deployment config:', err);
            return null;
        }
    }

    function isServerMode() {
        return deploymentState && deploymentState.mode === 'server';
    }
    window.isServerMode = isServerMode;

    function applyModeClasses() {
        if (!deploymentState) return;
        const isServer = deploymentState.mode === 'server';
        document.body.classList.toggle('mantis-server-mode', isServer);
        document.body.classList.toggle('mantis-workstation-mode', !isServer);

        // In Workstation Mode: Hide Deployment Mode and Users & Team buttons
        const deployBtn = document.getElementById('settings-nav-deployment') || document.querySelector('[data-settings-section="deployment"]');
        if (deployBtn) {
            deployBtn.style.display = isServer ? '' : 'none';
        }

        if (window.MantisAuth?.syncUserRoleUI) {
            window.MantisAuth.syncUserRoleUI();
        }

        // Update any mode badge in top-nav if present
        const badge = document.getElementById('top-nav-deployment-badge');
        if (badge) {
            badge.textContent = isServer ? 'Team Server' : 'Workstation';
            badge.className = `deployment-mode-pill ${isServer ? 'pill-server' : 'pill-workstation'}`;
        }
    }

    async function setDeploymentMode(newMode) {
        try {
            const res = await fetch('/api/config/deployment/mode', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: newMode })
            });
            if (!res.ok) throw new Error(`Failed to change mode (HTTP ${res.status})`);
            deploymentState = await res.json();
            window.MANTIS_DEPLOYMENT = deploymentState;
            applyModeClasses();
            renderDeploymentPanel();
            enhanceFeatureViews();

            if (typeof window.showToast === 'function') {
                window.showToast(`MANTIS switched to ${newMode.toUpperCase()} mode.`, false);
            } else if (typeof window.showNotification === 'function') {
                window.showNotification(`MANTIS switched to ${newMode.toUpperCase()} mode.`);
            }
        } catch (err) {
            console.error('[DeploymentMode] Error setting mode:', err);
            alert(`Error updating deployment mode: ${err.message}`);
        }
    }

    function renderDeploymentPanel() {
        const mount = document.getElementById('settings-deployment-mount');
        if (!mount || !deploymentState) return;

        const isServer = deploymentState.mode === 'server';
        const tools = deploymentState.tools || {};
        const staging = deploymentState.staging || {};
        const samples = staging.samples || [];
        const stealerLogs = staging.stealer_logs || [];

        const toolHtml = (key, name, icon) => {
            const t = tools[key] || { found: false, path: '', source: 'not_found' };
            const statusClass = t.found ? 'tool-detected' : 'tool-missing';
            const statusLabel = t.found ? 'Auto-detected' : 'Not configured';
            return `
                <div class="deploy-tool-card ${statusClass}">
                    <div class="deploy-tool-head">
                        <i class="fa-solid ${icon}"></i>
                        <span class="deploy-tool-name">${name}</span>
                        <span class="deploy-tool-badge">${statusLabel}</span>
                    </div>
                    <div class="deploy-tool-path" title="${t.path || 'Drop executable into backend/data/tools/' + key + '/'}">
                        ${t.found ? t.path : `<em>Search path: data/tools/${key}/ or system PATH</em>`}
                    </div>
                    ${t.source ? `<div class="deploy-tool-source">Source: <code>${t.source}</code></div>` : ''}
                </div>
            `;
        };

        mount.innerHTML = `
            <div class="deploy-container">
                <div class="deploy-hero">
                    <div class="deploy-hero-title">
                        <i class="fa-solid fa-server"></i>
                        <div>
                            <h3>Deployment Mode & Infrastructure</h3>
                            <p>Configure MANTIS for an analyst workstation or a shared internal team server.</p>
                        </div>
                    </div>
                    <div class="deploy-active-badge ${isServer ? 'badge-server' : 'badge-workstation'}">
                        <i class="fa-solid ${isServer ? 'fa-network-wired' : 'fa-laptop'}"></i>
                        <span>Active: ${isServer ? 'Team Server' : 'Local Workstation'}</span>
                    </div>
                </div>

                <div class="deploy-modes-grid">
                    <div class="deploy-mode-card ${!isServer ? 'active-mode' : ''}" id="btn-select-workstation">
                        <div class="mode-card-header">
                            <i class="fa-solid fa-laptop"></i>
                            <h4>Workstation Mode</h4>
                            ${!isServer ? '<span class="mode-check"><i class="fa-solid fa-check"></i> Current</span>' : ''}
                        </div>
                        <p class="mode-desc">Single-user local machine setup. Windows GUI file and folder picker dialogs are enabled for Binary Lab, Binary Similarity, and Credential Stealer.</p>
                        <div class="mode-features">
                            <div><i class="fa-solid fa-check"></i> OS folder pickers enabled</div>
                            <div><i class="fa-solid fa-check"></i> Binds to localhost (127.0.0.1)</div>
                            <div><i class="fa-solid fa-check"></i> Automatic browser launch</div>
                        </div>
                        ${isServer ? '<button type="button" class="btn-secondary deploy-switch-btn" data-set-mode="workstation">Switch to Workstation</button>' : '<div class="mode-active-text"><i class="fa-solid fa-circle-check"></i> Active on this machine</div>'}
                    </div>

                    <div class="deploy-mode-card ${isServer ? 'active-mode' : ''}" id="btn-select-server">
                        <div class="mode-card-header">
                            <i class="fa-solid fa-network-wired"></i>
                            <h4>Team Server Mode</h4>
                            ${isServer ? '<span class="mode-check"><i class="fa-solid fa-check"></i> Current</span>' : ''}
                        </div>
                        <p class="mode-desc">Multi-user internal server setup (Linux/Windows). Host GUI pickers are disabled to prevent server freezing. Files are handled via Web Upload and server drop directories.</p>
                        <div class="mode-features">
                            <div><i class="fa-solid fa-check"></i> Headless: no GUI dialog hangs</div>
                            <div><i class="fa-solid fa-check"></i> Auto-discovers IDA/Ghidra in <code>data/tools/</code></div>
                            <div><i class="fa-solid fa-check"></i> Shared staging drop folders active</div>
                        </div>
                        ${!isServer ? '<button type="button" class="btn-primary deploy-switch-btn" data-set-mode="server">Switch to Team Server</button>' : '<div class="mode-active-text"><i class="fa-solid fa-circle-check"></i> Active on this server</div>'}
                    </div>
                </div>

                <div class="deploy-section-header">
                    <h4><i class="fa-solid fa-microchip"></i> Reverse Engineering Tools (Auto-Discovery)</h4>
                    <span class="deploy-section-sub">Tools placed in <code>backend/data/tools/&lt;tool_name&gt;</code> or system PATH are automatically detected with no manual path entry needed.</span>
                </div>
                <div class="deploy-tools-grid">
                    ${toolHtml('ida', 'IDA Pro (idat64 / ida64)', 'fa-bug')}
                    ${toolHtml('ghidra', 'Ghidra (analyzeHeadless)', 'fa-dragon')}
                    ${toolHtml('goresym', 'GoReSym (Symbol Recovery)', 'fa-cube')}
                    ${toolHtml('ilspycmd', 'ILSpyCmd (.NET Decompiler)', 'fa-file-code')}
                </div>

                <div class="deploy-section-header" style="margin-top: 28px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; width:100%;">
                        <div>
                            <h4><i class="fa-solid fa-folder-tree"></i> Shared Server Staging Drop Zones</h4>
                            <span class="deploy-section-sub">Analysts can drop files here directly (via SFTP / SMB mount) and select them from web dropdowns.</span>
                        </div>
                        <button type="button" class="btn-secondary" id="deploy-refresh-staging-btn" style="padding: 6px 12px; font-size: 0.85rem;">
                            <i class="fa-solid fa-rotate"></i> Refresh Staging
                        </button>
                    </div>
                </div>

                <div class="deploy-staging-grid">
                    <div class="deploy-staging-card">
                        <div class="staging-card-title">
                            <i class="fa-solid fa-virus"></i>
                            <div>
                                <strong>Malware Samples Drop Zone</strong>
                                <span class="staging-path">backend/data/staging/samples/</span>
                            </div>
                            <span class="staging-count">${samples.length} sample(s)</span>
                        </div>
                        <div class="staging-items-list dark-scroll">
                            ${samples.length ? samples.map(s => `<div class="staging-item"><i class="fa-solid fa-file-binary"></i> <span class="staging-item-name">${s.name}</span> <span class="staging-item-size">${(s.size_bytes / 1024).toFixed(1)} KB</span></div>`).join('') : '<div class="staging-empty">No samples dropped yet. Copy binaries into <code>backend/data/staging/samples/</code></div>'}
                        </div>
                    </div>

                    <div class="deploy-staging-card">
                        <div class="staging-card-title">
                            <i class="fa-solid fa-key"></i>
                            <div>
                                <strong>Credential Stealer Logs Drop Zone</strong>
                                <span class="staging-path">backend/data/staging/stealer_logs/</span>
                            </div>
                            <span class="staging-count">${stealerLogs.length} item(s)</span>
                        </div>
                        <div class="staging-items-list dark-scroll">
                            ${stealerLogs.length ? stealerLogs.map(l => `<div class="staging-item"><i class="fa-solid ${l.is_dir ? 'fa-folder' : 'fa-file-zipper'}"></i> <span class="staging-item-name">${l.name}</span> <span class="staging-item-size">${l.is_dir ? 'folder' : (l.size_bytes / (1024 * 1024)).toFixed(1) + ' MB'}</span></div>`).join('') : '<div class="staging-empty">No log folders dropped yet. Copy logs or archives into <code>backend/data/staging/stealer_logs/</code></div>'}
                        </div>
                    </div>
                </div>
            </div>
        `;

        mount.querySelectorAll('[data-set-mode]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const mode = e.currentTarget.dataset.setMode;
                if (confirm(`Switch deployment mode to ${mode.toUpperCase()}?`)) {
                    setDeploymentMode(mode);
                }
            });
        });

        mount.querySelector('#deploy-refresh-staging-btn')?.addEventListener('click', () => {
            fetchDeploymentConfig();
        });
    }

    // Enhance Credential Stealer and Binary Lab with server drop-down pickers
    async function enhanceFeatureViews() {
        if (!deploymentState) return;

        // --- 1. Credential Stealer Staging Selector ---
        const csPathInput = document.getElementById('cs-local-path-input');
        if (csPathInput) {
            let csDropdown = document.getElementById('cs-server-staging-select');
            if (!csDropdown) {
                csDropdown = document.createElement('select');
                csDropdown.id = 'cs-server-staging-select';
                csDropdown.className = 'cs-staging-select';
                csDropdown.style.cssText = 'margin-top: 8px; width: 100%; padding: 8px 12px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: var(--text-color); font-size: 0.85rem; outline: none; display: none;';
                csPathInput.parentElement?.appendChild(csDropdown);

                csDropdown.addEventListener('change', () => {
                    if (csDropdown.value) {
                        csPathInput.value = csDropdown.value;
                        const labelInput = document.getElementById('cs-local-label-input');
                        if (labelInput && !labelInput.value) {
                            labelInput.value = csDropdown.selectedOptions[0]?.text?.replace(/^\[[^\]]+\]\s*/, '') || '';
                        }
                    }
                });
            }

            const logs = deploymentState.staging?.stealer_logs || [];
            if (isServerMode()) {
                csDropdown.style.display = 'block';
                csDropdown.innerHTML = `<option value="">-- Or select from Server Staging (data/staging/stealer_logs) --</option>` +
                    logs.map(l => `<option value="${l.path}">[${l.is_dir ? 'DIR' : 'FILE'}] ${l.name}</option>`).join('');
            } else {
                csDropdown.style.display = logs.length ? 'block' : 'none';
                if (logs.length) {
                    csDropdown.innerHTML = `<option value="">-- Optional: Select from Server Staging (${logs.length} items available) --</option>` +
                        logs.map(l => `<option value="${l.path}">[${l.is_dir ? 'DIR' : 'FILE'}] ${l.name}</option>`).join('');
                }
            }
        }

        // --- 2. Binary Lab Staging Selector & Auto-detected Tools ---
        const blPathInput = document.getElementById('bl-path') || document.querySelector('.bl-target-input');
        if (blPathInput) {
            let blDropdown = document.getElementById('bl-server-staging-select');
            if (!blDropdown) {
                blDropdown = document.createElement('select');
                blDropdown.id = 'bl-server-staging-select';
                blDropdown.className = 'bl-staging-select';
                blDropdown.style.cssText = 'margin-top: 8px; width: 100%; padding: 8px 12px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: var(--text-color); font-size: 0.85rem; outline: none; display: none;';
                blPathInput.parentElement?.appendChild(blDropdown);

                blDropdown.addEventListener('change', () => {
                    if (blDropdown.value) {
                        blPathInput.value = blDropdown.value;
                    }
                });
            }

            const samples = deploymentState.staging?.samples || [];
            if (isServerMode()) {
                blDropdown.style.display = 'block';
                blDropdown.innerHTML = `<option value="">-- Select from Server Staging (data/staging/samples) --</option>` +
                    samples.map(s => `<option value="${s.path}">${s.name} (${(s.size_bytes / 1024).toFixed(1)} KB)</option>`).join('');
            } else {
                blDropdown.style.display = samples.length ? 'block' : 'none';
                if (samples.length) {
                    blDropdown.innerHTML = `<option value="">-- Optional: Select from Server Staging (${samples.length} items available) --</option>` +
                        samples.map(s => `<option value="${s.path}">${s.name} (${(s.size_bytes / 1024).toFixed(1)} KB)</option>`).join('');
                }
            }
        }
    }

    // Init on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', fetchDeploymentConfig);
    } else {
        fetchDeploymentConfig();
    }

    // Expose controller
    window.DeploymentMode = {
        fetch: fetchDeploymentConfig,
        setMode: setDeploymentMode,
        isServer: isServerMode,
        getState: () => deploymentState
    };
})();
