// MANTIS Multi-User Authentication & Personal API Key Manager
(function () {
    let currentUser = null;
    let authInitialized = false;

    // Mapping between backend provider keys and localStorage keys
    const PROVIDER_KEY_MAP = {
        'virustotal': 'ioc_vt_key',
        'otx': 'ioc_otx_key',
        'abuseipdb': 'ioc_abuseipdb_key',
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

    async function checkAuth() {
        try {
            const res = await fetch('/api/auth/me');
            if (res.status === 401) {
                // Server mode and unauthenticated
                currentUser = null;
                showLoginModal();
                return null;
            }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            currentUser = data.user;
            hideLoginModal();
            renderUserNavPill();
            await syncUserApiKeys();
            if (currentUser.role === 'admin') {
                renderUserManagementInSettings();
            }
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
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || 'Login failed.');
            }

            currentUser = data.user;
            hideLoginModal();
            renderUserNavPill();
            await syncUserApiKeys();

            if (typeof window.showToast === 'function') {
                window.showToast(`Logged in as ${currentUser.username} (${currentUser.role}).`, false);
            }
            // Trigger refresh of settings if open
            if (currentUser.role === 'admin') {
                renderUserManagementInSettings();
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
            await fetch('/api/auth/logout', { method: 'POST' });
        } catch (e) {
            // ignore
        }
        currentUser = null;
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
        wrap.querySelector('#btn-top-logout')?.addEventListener('click', (e) => {
            e.stopPropagation();
            if (confirm('Log out from MANTIS?')) logout();
        });
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
                        <div class="login-logo"><i class="fa-solid fa-shield-halved"></i></div>
                        <h2>MANTIS Security Workbench</h2>
                        <p>Team Server Authentication Required</p>
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
                            <i class="fa-solid fa-right-to-bracket"></i> Sign In to Workbench
                        </button>
                        <div class="login-footer">
                            <span>Default admin account: <code>admin</code> / <code>mantis2026!</code></span>
                        </div>
                    </form>
                </div>
            `;
            document.body.appendChild(modal);

            document.getElementById('mantis-login-form')?.addEventListener('submit', async (e) => {
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
        modal.style.display = 'flex';
    }

    function hideLoginModal() {
        const modal = document.getElementById('mantis-login-overlay');
        if (modal) modal.style.display = 'none';
    }

    async function renderUserManagementInSettings() {
        let mount = document.getElementById('settings-users-mount');
        if (!mount) return;

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
                        <button type="button" class="btn-primary" id="btn-show-add-user" style="padding: 6px 14px; font-size: 0.85rem;">
                            <i class="fa-solid fa-user-plus"></i> Add New Analyst
                        </button>
                    </div>

                    <div id="add-user-form-container" style="display:none; margin-bottom: 20px; padding: 16px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px;">
                        <h5 style="margin-top:0; margin-bottom:12px; color:var(--text-color);"><i class="fa-solid fa-user-plus"></i> Create Analyst Account</h5>
                        <div style="display:grid; grid-template-columns: 1fr 1fr 120px 100px; gap: 10px; align-items: flex-end;">
                            <div>
                                <label style="display:block; font-size:0.8rem; color:var(--text-muted); margin-bottom:4px;">Username</label>
                                <input type="text" id="new-user-username" style="width:100%; padding:6px 10px; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.15); border-radius:4px; color:#fff;" placeholder="e.g. analyst1">
                            </div>
                            <div>
                                <label style="display:block; font-size:0.8rem; color:var(--text-muted); margin-bottom:4px;">Password</label>
                                <input type="password" id="new-user-password" style="width:100%; padding:6px 10px; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.15); border-radius:4px; color:#fff;" placeholder="Min 6 characters">
                            </div>
                            <div>
                                <label style="display:block; font-size:0.8rem; color:var(--text-muted); margin-bottom:4px;">Role</label>
                                <select id="new-user-role" style="width:100%; padding:6px 8px; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.15); border-radius:4px; color:#fff;">
                                    <option value="analyst">Analyst</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </div>
                            <div>
                                <button type="button" class="btn-primary" id="btn-submit-create-user" style="width:100%; padding:6px 0;">Create</button>
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
                                            ${u.id !== currentUser.id ? `<button type="button" class="btn-secondary btn-del-user" data-uid="${u.id}" data-uname="${u.username}" style="padding:3px 8px; font-size:0.75rem; color:#f87171;"><i class="fa-solid fa-trash"></i></button>` : '<span style="font-size:0.75rem; color:var(--text-muted);">(You)</span>'}
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

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
                    if (confirm(`Are you sure you want to delete user account '${uname}'?`)) {
                        try {
                            const resp = await fetch(`/api/auth/users/${uid}`, { method: 'DELETE' });
                            if (!resp.ok) throw new Error('Deletion failed');
                            renderUserManagementInSettings();
                        } catch (err) {
                            alert(err.message);
                        }
                    }
                });
            });
        } catch (err) {
            console.warn('[Auth] Error rendering user management:', err);
        }
    }

    // Intercept fetch calls to handle 401 Unauthorized automatically in server mode
    const originalFetch = window.fetch;
    window.fetch = async function (...args) {
        const response = await originalFetch.apply(this, args);
        if (response.status === 401 && window.isServerMode?.()) {
            const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
            if (!url.includes('/api/auth/login')) {
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
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            checkAuth();
            hookApiKeyInputs();
        });
    } else {
        checkAuth();
        hookApiKeyInputs();
    }

    window.MantisAuth = {
        checkAuth,
        login,
        logout,
        savePersonalKey,
        getUser: () => currentUser
    };
})();
