// MANTIS Multi-User Authentication & Personal API Key Manager
(function () {
    let currentUser = null;
    let authInitialized = false;
    let sessionToken = localStorage.getItem('mantis_token') || sessionStorage.getItem('mantis_token') || null;

    // Mapping between backend provider keys and localStorage keys
    const PROVIDER_KEY_MAP = {
        'virustotal': 'ioc_vt_key',
        'otx': 'ioc_otx_key',
        'abuseipdb': 'ioc_abuseipdb_key',
        'threatcluster': 'ioc_threatcluster_key',
        'shodan': 'ioc_shodan_key',
        'censys': 'ioc_censys_key',
        'greynoise': 'ioc_greynoise_key',
        'urlscan': 'ioc_urlscan_key',
        'fofa': 'ioc_fofa_key',
        'zoomeye': 'ioc_zoomeye_key',
        'validin': 'ioc_validin_key',
        'netlas': 'ioc_netlas_key',
        'etugen': 'ioc_etugen_key',
        'pulsedive': 'ioc_pulsedive_key',
        'silentpush': 'ioc_silentpush_key',
        'driftnet': 'ioc_driftnet_key',
        'triage': 'ioc_triage_key',
        'hybrid_analysis': 'ioc_ha_key',
        'malshare': 'ioc_malshare_key',
        'cybercure': 'ioc_cb_key',
        'ransomware_live': 'ioc_rwlive_key',
        'threatbook': 'ioc_threatbook_key',
        'github': 'ioc_github_key',
        'twitter': 'ioc_twitter_key',
        'leaklookup': 'ioc_leaklookup_key',
        'leakix': 'ioc_leakix_key',
        'phishstats': 'ioc_phishstats_key',
        'dnsdumpster': 'ioc_dnsdumpster_key',
        'misp_key': 'ioc_misp_key',
        'misp_url': 'ioc_misp_url'
    };

    function syncUserRoleUI() {
        const usersNavBtn = document.getElementById('settings-nav-users');
        const deployNavBtn = document.getElementById('settings-nav-deployment') || document.querySelector('[data-settings-section="deployment"]');

        const isWorkstation = (currentUser && currentUser.mode === 'workstation') ||
                              (currentUser && currentUser.id === 'workstation_user') ||
                              (window.MANTIS_DEPLOYMENT && window.MANTIS_DEPLOYMENT.mode === 'workstation') ||
                              document.body.classList.contains('mantis-workstation-mode');

        const isServerAdmin = !isWorkstation && !!(currentUser && currentUser.role === 'admin');

        // Workstation mode: hide both Users & Team and Deployment Mode
        if (usersNavBtn) {
            usersNavBtn.style.display = isServerAdmin ? '' : 'none';
        }
        if (deployNavBtn) {
            deployNavBtn.style.display = isWorkstation ? 'none' : '';
        }

        if (document.body) {
            document.body.classList.toggle('mantis-workstation-mode', isWorkstation);
            document.body.classList.toggle('mantis-server-mode', !isWorkstation);
            document.body.classList.toggle('mantis-user-admin', isServerAdmin);
            document.body.classList.toggle('mantis-user-analyst', !isServerAdmin && !isWorkstation);
        }

        if (isServerAdmin) {
            renderUserManagementInSettings();
        } else {
            const usersPanel = document.getElementById('settings-section-users');
            const deployPanel = document.getElementById('settings-section-deployment');
            if ((usersPanel && usersPanel.classList.contains('active')) ||
                (isWorkstation && deployPanel && deployPanel.classList.contains('active'))) {
                if (typeof window.openSettingsSection === 'function') {
                    window.openSettingsSection('api');
                }
            }
        }
    }

    async function checkAuth() {
        try {
            const res = await fetch('/api/auth/me');
            if (res.status === 401) {
                // Server mode and unauthenticated
                currentUser = null;
                syncUserRoleUI();
                showLoginModal();
                return null;
            }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            currentUser = data.user;
            hideLoginModal();
            renderUserNavPill();
            syncUserRoleUI();
            await syncUserApiKeys();
            return currentUser;
        } catch (err) {
            console.warn('[Auth] Error checking authentication:', err);
            return null;
        }
    }

    async function login(username, password) {
        const errorEl = document.getElementById('login-modal-error');
        if (errorEl) { errorEl.style.display = 'none'; errorEl.textContent = ''; }

        try {
            const res = await (originalFetch || window.fetch)('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || 'Login failed.');
            }

            if (data.token) {
                sessionToken = data.token;
                localStorage.setItem('mantis_token', data.token);
                sessionStorage.setItem('mantis_token', data.token);
            }

            currentUser = data.user;
            hideLoginModal();
            renderUserNavPill();
            syncUserRoleUI();
            await syncUserApiKeys();

            if (typeof window.showToast === 'function') {
                window.showToast(`Logged in as ${currentUser.username} (${currentUser.role}).`, false);
            }
            return data;
        } catch (err) {
            if (errorEl) {
                errorEl.textContent = err.message || 'Login failed. Please check credentials.';
                errorEl.style.display = 'block';
            }
            throw err;
        }
    }

    async function logout() {
        try {
            await (originalFetch || window.fetch)('/api/auth/logout', { method: 'POST' });
        } catch (e) {
            // ignore
        }
        sessionToken = null;
        localStorage.removeItem('mantis_token');
        sessionStorage.removeItem('mantis_token');
        currentUser = null;
        syncUserRoleUI();
        window.location.reload();
    }

    async function syncUserApiKeys() {
        if (!currentUser) return;
        try {
            const res = await fetch('/api/user/keys');
            if (!res.ok) return;
            const data = await res.json();
            const keys = data.keys || {};

            // Update user indicators in settings
            const userBanner = document.getElementById('settings-user-key-banner');
            if (userBanner) {
                userBanner.innerHTML = `
                    <div class="user-key-active-notice">
                        <i class="fa-solid fa-shield-halved"></i>
                        <span>Logged in as <strong>${currentUser.username}</strong> (${currentUser.role}). Personal keys are encrypted with AES-256-GCM.</span>
                    </div>
                `;
            }
        } catch (err) {
            console.warn('[Auth] Error fetching user keys:', err);
        }
    }

    async function savePersonalKey(provider, rawKey) {
        if (!currentUser) return;
        try {
            const res = await fetch('/api/user/keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, key: rawKey })
            });
            if (!res.ok) throw new Error('Failed to save key');

            // Also keep in localStorage for seamless client-side query building
            const localKey = PROVIDER_KEY_MAP[provider.toLowerCase()];
            if (localKey) {
                if (rawKey) {
                    localStorage.setItem(localKey, rawKey);
                } else {
                    localStorage.removeItem(localKey);
                }
            }
        } catch (err) {
            console.warn(`[Auth] Could not save personal key for ${provider}:`, err);
        }
    }

    function renderUserNavPill() {
        const topNav = document.getElementById('top-nav');
        if (!topNav) return;

        let wrap = document.getElementById('top-nav-user-wrap');
        if (!wrap) {
            wrap = document.createElement('div');
            wrap.id = 'top-nav-user-wrap';
            wrap.className = 'top-nav-user-wrap';
            topNav.appendChild(wrap);
        }

        const isWorkstation = !currentUser || currentUser.mode === 'workstation' || currentUser.id === 'workstation_user';
        if (isWorkstation) {
            // In Workstation Mode (single analyst), keep the collapsed icon rail clean and uncluttered
            wrap.innerHTML = '';
            wrap.style.display = 'none';
            return;
        }

        // Team Server Mode: render rail-compatible user badge
        wrap.style.display = 'flex';
        wrap.innerHTML = `
            <div class="top-nav-user-item" title="Logged in as ${currentUser.username} (${currentUser.role})">
                <i class="fa-solid fa-circle-user user-nav-icon"></i>
                <div class="user-nav-details">
                    <span class="user-nav-name">${currentUser.username}</span>
                    <span class="user-role-badge">${currentUser.role}</span>
                </div>
                <button type="button" class="user-logout-btn" id="btn-top-logout" title="Log out">
                    <i class="fa-solid fa-right-from-bracket"></i>
                </button>
            </div>
        `;
        wrap.querySelector('#btn-top-logout')?.addEventListener('click', async (e) => {
            e.stopPropagation();
            let confirmed = false;
            if (window.mantisConfirm) {
                confirmed = await window.mantisConfirm({
                    title: 'Confirm Logout',
                    message: 'Are you sure you want to log out from this MANTIS session?',
                    confirmText: 'Log Out',
                    danger: false,
                    icon: 'fa-right-from-bracket'
                });
            } else {
                confirmed = confirm('Log out from MANTIS?');
            }
            if (confirmed) logout();
        });

        // Clicking the user profile item opens Users & Team for admin, or API keys for analyst
        wrap.querySelector('.top-nav-user-item')?.addEventListener('click', (e) => {
            if (e.target.closest('#btn-top-logout')) return;
            const isAdmin = !!(currentUser && (currentUser.role === 'admin' || currentUser.id === 'workstation_user'));
            if (typeof window.openSettingsSection === 'function') {
                window.openSettingsSection(isAdmin ? 'users' : 'api');
            }
        });
    }

    function initLoginForm() {
        const form = document.getElementById('mantis-login-form');
        if (form && !form.dataset.bound) {
            form.dataset.bound = 'true';
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const u = document.getElementById('login-username')?.value || '';
                const p = document.getElementById('login-password')?.value || '';
                const btn = document.getElementById('login-submit-btn');
                if (btn) btn.disabled = true;
                try {
                    await login(u, p);
                } finally {
                    if (btn) btn.disabled = false;
                }
            });
        }
    }

    function showLoginModal() {
        let modal = document.getElementById('mantis-login-overlay');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'mantis-login-overlay';
            modal.className = 'mantis-login-overlay';
            modal.innerHTML = `
                <div class="login-card">
                    <div class="login-header">
                        <div class="login-logo">
                            <img src="android-chrome-192x192.png" alt="MANTIS" class="login-mantis-logo">
                        </div>
                        <h2>MANTIS</h2>
                        <p class="login-subtitle">Multi-sources Analysis &amp; Threat Intelligence Search</p>
                    </div>
                    <form id="mantis-login-form" class="login-form">
                        <div id="login-modal-error" class="login-error" style="display:none;"></div>
                        <div class="login-field">
                            <label for="login-username"><i class="fa-solid fa-user"></i> Username</label>
                            <input type="text" id="login-username" required autocomplete="username" placeholder="Enter username" autofocus>
                        </div>
                        <div class="login-field">
                            <label for="login-password"><i class="fa-solid fa-lock"></i> Password</label>
                            <input type="password" id="login-password" required autocomplete="current-password" placeholder="Enter password">
                        </div>
                        <button type="submit" class="btn-primary login-btn" id="login-submit-btn">
                            <i class="fa-solid fa-right-to-bracket"></i> Sign In to MANTIS
                        </button>
                        <div class="login-footer">
                            <span><i class="fa-solid fa-terminal"></i> Administrator password is generated in server console on startup</span>
                        </div>
                    </form>
                </div>
            `;
            document.body.appendChild(modal);
        }

        initLoginForm();
        modal.style.display = 'flex';
    }

    function hideLoginModal() {
        const modal = document.getElementById('mantis-login-overlay');
        if (modal) modal.style.display = 'none';
    }

    async function renderUserManagementInSettings() {
        let mount = document.getElementById('settings-users-mount');
        if (!mount) return;

        const isAdmin = !!(currentUser && (currentUser.role === 'admin' || currentUser.id === 'workstation_user'));
        if (!isAdmin) {
            mount.innerHTML = '';
            return;
        }

        try {
            const res = await fetch('/api/auth/users');
            if (!res.ok) return;
            const data = await res.json();
            const users = data.users || [];

            mount.innerHTML = `
                <div class="users-mgmt-box">
                    <div class="users-mgmt-header">
                        <div>
                            <h4><i class="fa-solid fa-users-gear"></i> Team Analyst Accounts</h4>
                            <p>Manage team member access. Each analyst maintains their own encrypted API key vault.</p>
                        </div>
                        <div style="display:flex; gap:8px;">
                            <button type="button" class="btn-secondary" id="btn-show-change-pw" style="padding: 6px 14px; font-size: 0.85rem;">
                                <i class="fa-solid fa-key"></i> Change My Password
                            </button>
                            <button type="button" class="btn-primary" id="btn-show-add-user" style="padding: 6px 14px; font-size: 0.85rem;">
                                <i class="fa-solid fa-user-plus"></i> Add New Analyst
                            </button>
                        </div>
                    </div>

                    <!-- Change Admin Password Form -->
                    <div id="change-pw-form-container" class="user-form-card" style="display:none; background: rgba(56,189,248,0.06); border-color: rgba(56,189,248,0.25);">
                        <h5 class="user-form-title" style="color:#38bdf8;"><i class="fa-solid fa-lock"></i> Change Admin Password (Persisted to .env)</h5>
                        <div class="user-form-row">
                            <div class="user-form-col">
                                <label for="self-current-password">Current Password</label>
                                <input type="password" id="self-current-password" class="user-form-input" placeholder="Current password">
                            </div>
                            <div class="user-form-col">
                                <label for="self-new-password">New Password</label>
                                <input type="password" id="self-new-password" class="user-form-input" placeholder="Min 8 characters">
                            </div>
                            <div class="user-form-col">
                                <label for="self-confirm-password">Confirm New Password</label>
                                <input type="password" id="self-confirm-password" class="user-form-input" placeholder="Repeat password">
                            </div>
                            <div class="user-form-col-btn">
                                <button type="button" class="btn-primary user-form-submit-btn" id="btn-submit-change-pw">
                                    <i class="fa-solid fa-floppy-disk"></i> Update Password
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Create Analyst Account Form -->
                    <div id="add-user-form-container" class="user-form-card" style="display:none;">
                        <h5 class="user-form-title"><i class="fa-solid fa-user-plus"></i> Create Analyst Account</h5>
                        <div class="user-form-row">
                            <div class="user-form-col">
                                <label for="new-user-username">Username</label>
                                <input type="text" id="new-user-username" class="user-form-input" placeholder="e.g. analyst1" autocomplete="off">
                            </div>
                            <div class="user-form-col">
                                <label for="new-user-password">Password</label>
                                <input type="password" id="new-user-password" class="user-form-input" placeholder="Min 8 characters" autocomplete="new-password">
                            </div>
                            <div class="user-form-col-role">
                                <label for="new-user-role">Role</label>
                                <select id="new-user-role" class="user-form-select">
                                    <option value="analyst">Analyst</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </div>
                            <div class="user-form-col-btn">
                                <button type="button" class="btn-primary user-form-submit-btn" id="btn-submit-create-user">
                                    <i class="fa-solid fa-plus"></i> Create Account
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="users-table-wrap">
                        <table class="users-table">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                    <th>Last Login</th>
                                    <th style="text-align:right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${users.map(u => `
                                    <tr>
                                        <td><strong>${u.username}</strong></td>
                                        <td><span class="user-role-tag ${u.role === 'admin' ? 'role-admin' : 'role-analyst'}">${u.role}</span></td>
                                        <td><span class="user-status-dot"></span> Active</td>
                                        <td>${new Date(u.created_at * 1000).toLocaleDateString()}</td>
                                        <td>${u.last_login ? new Date(u.last_login * 1000).toLocaleString() : '<em>Never</em>'}</td>
                                        <td style="text-align:right;">
                                            ${u.id !== currentUser.id ? `
                                                <button type="button" class="btn-secondary btn-reset-user-pw" data-uid="${u.id}" data-uname="${u.username}" title="Reset Password" style="padding:3px 8px; font-size:0.75rem; color:#38bdf8; margin-right:4px;"><i class="fa-solid fa-key"></i></button>
                                                <button type="button" class="btn-secondary btn-del-user" data-uid="${u.id}" data-uname="${u.username}" title="Delete User" style="padding:3px 8px; font-size:0.75rem; color:#f87171;"><i class="fa-solid fa-trash"></i></button>
                                            ` : '<span style="font-size:0.75rem; color:var(--text-muted);">(You)</span>'}
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            mount.querySelector('#btn-show-change-pw')?.addEventListener('click', () => {
                const form = mount.querySelector('#change-pw-form-container');
                if (form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
            });

            mount.querySelector('#btn-submit-change-pw')?.addEventListener('click', async () => {
                const cur = mount.querySelector('#self-current-password')?.value || '';
                const nw = mount.querySelector('#self-new-password')?.value || '';
                const cnf = mount.querySelector('#self-confirm-password')?.value || '';

                if (!cur || !nw) { alert('Current and new password are required.'); return; }
                if (nw.length < 8) { alert('New password must be at least 8 characters long.'); return; }
                if (nw !== cnf) { alert('New password and confirm password do not match.'); return; }

                try {
                    const resp = await fetch('/api/auth/password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ current_password: cur, new_password: nw })
                    });
                    const d = await resp.json();
                    if (!resp.ok) throw new Error(d.detail || 'Failed to update password');
                    if (d.token) {
                        sessionToken = d.token;
                        localStorage.setItem('mantis_token', d.token);
                        sessionStorage.setItem('mantis_token', d.token);
                    }
                    alert(d.message || 'Password changed successfully!');
                    const form = mount.querySelector('#change-pw-form-container');
                    if (form) {
                        form.style.display = 'none';
                        mount.querySelector('#self-current-password').value = '';
                        mount.querySelector('#self-new-password').value = '';
                        mount.querySelector('#self-confirm-password').value = '';
                    }
                } catch (err) {
                    alert(`Error: ${err.message}`);
                }
            });

            mount.querySelectorAll('.btn-reset-user-pw').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    const uid = e.currentTarget.dataset.uid;
                    const uname = e.currentTarget.dataset.uname;
                    const newPw = prompt(`Enter new password for analyst '${uname}' (min 8 characters):`);
                    if (!newPw) return;
                    if (newPw.length < 8) { alert('Password must be at least 8 characters long.'); return; }

                    try {
                        const resp = await fetch(`/api/auth/users/${uid}/password`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ new_password: newPw })
                        });
                        const d = await resp.json();
                        if (!resp.ok) throw new Error(d.detail || 'Failed to reset password');
                        alert(d.message || `Password for '${uname}' reset successfully.`);
                    } catch (err) {
                        alert(`Error: ${err.message}`);
                    }
                });
            });

            mount.querySelector('#btn-show-add-user')?.addEventListener('click', () => {
                const form = mount.querySelector('#add-user-form-container');
                if (form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
            });

            mount.querySelector('#btn-submit-create-user')?.addEventListener('click', async () => {
                const u = mount.querySelector('#new-user-username')?.value.trim();
                const p = mount.querySelector('#new-user-password')?.value;
                const r = mount.querySelector('#new-user-role')?.value || 'analyst';
                if (!u || !p) { alert('Username and password are required.'); return; }

                try {
                    const resp = await fetch('/api/auth/users', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: u, password: p, role: r })
                    });
                    const d = await resp.json();
                    if (!resp.ok) throw new Error(d.detail || 'Failed to create user');
                    alert(`Created user '${u}' successfully.`);
                    renderUserManagementInSettings();
                } catch (err) {
                    alert(`Error: ${err.message}`);
                }
            });

            mount.querySelectorAll('.btn-del-user').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    const uid = e.currentTarget.dataset.uid;
                    const uname = e.currentTarget.dataset.uname;
                    let confirmed = false;
                    if (window.mantisConfirm) {
                        confirmed = await window.mantisConfirm({
                            title: 'Delete User Account',
                            message: `Are you sure you want to permanently delete user account '${uname}'? This cannot be undone.`,
                            confirmText: 'Delete User',
                            danger: true,
                            icon: 'fa-user-xmark'
                        });
                    } else {
                        confirmed = confirm(`Are you sure you want to delete user account '${uname}'?`);
                    }
                    if (confirmed) {
                        try {
                            const resp = await fetch(`/api/auth/users/${uid}`, { method: 'DELETE' });
                            if (!resp.ok) throw new Error('Deletion failed');
                            renderUserManagementInSettings();
                        } catch (err) {
                            if (window.mantisAlert) {
                                window.mantisAlert({ title: 'User Deletion Error', message: err.message, type: 'error' });
                            } else {
                                alert(err.message);
                            }
                        }
                    }
                });
            });
        } catch (err) {
            console.warn('[Auth] Error rendering user management:', err);
        }
    }

    // Intercept fetch calls to handle Bearer token authorization and 401s in server mode
    const originalFetch = window.fetch;
    window.fetch = async function (resource, init = {}) {
        const options = { ...init };
        const token = sessionToken || localStorage.getItem('mantis_token') || sessionStorage.getItem('mantis_token');

        if (token) {
            const headers = new Headers(options.headers || {});
            if (!headers.has('Authorization')) {
                headers.set('Authorization', `Bearer ${token}`);
            }
            options.headers = headers;
        }

        if (!options.credentials) {
            options.credentials = 'same-origin';
        }

        const response = await originalFetch.call(this, resource, options);

        if (response.status === 401 && window.isServerMode?.()) {
            const url = typeof resource === 'string' ? resource : (resource?.url || '');
            if (!url.includes('/api/auth/login')) {
                sessionToken = null;
                localStorage.removeItem('mantis_token');
                sessionStorage.removeItem('mantis_token');
                currentUser = null;
                showLoginModal();
            }
        }
        return response;
    };

    // Auto-hook settings API key inputs so changes save to personal user vault
    function hookApiKeyInputs() {
        document.querySelectorAll('input[id$="-key"], input[id^="ioc-"]').forEach(input => {
            input.addEventListener('change', (e) => {
                const val = e.target.value.trim();
                let prov = e.target.id.replace(/-key$/, '').replace(/^ioc-/, '');
                savePersonalKey(prov, val);
                if (e.target.id === 'ai-key' && window.mantisAI?.saveSettings) {
                    window.mantisAI.saveSettings().catch(() => {});
                }
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            initLoginForm();
            checkAuth();
            hookApiKeyInputs();
        });
    } else {
        initLoginForm();
        checkAuth();
        hookApiKeyInputs();
    }

    window.MantisAuth = {
        checkAuth,
        login,
        logout,
        savePersonalKey,
        getUser: () => currentUser,
        isAdmin: () => !!(currentUser && (currentUser.role === 'admin' || currentUser.id === 'workstation_user')),
        syncUserRoleUI
    };
})();
