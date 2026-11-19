// MANTIS Custom Dialog & Confirmation System
(function () {
    let activeResolve = null;
    let overlayEl = null;

    function ensureOverlay() {
        if (overlayEl && document.body.contains(overlayEl)) return overlayEl;

        overlayEl = document.createElement('div');
        overlayEl.id = 'mantis-dialog-root';
        overlayEl.className = 'mantis-dialog-overlay';
        overlayEl.setAttribute('role', 'dialog');
        overlayEl.setAttribute('aria-modal', 'true');
        document.body.appendChild(overlayEl);

        // Escape key listener
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && overlayEl && overlayEl.classList.contains('active')) {
                closeDialog(false);
            }
        });

        return overlayEl;
    }

    function closeDialog(result) {
        if (!overlayEl) return;
        overlayEl.classList.remove('active');
        if (activeResolve) {
            const res = activeResolve;
            activeResolve = null;
            setTimeout(() => res(result), 150);
        }
    }

    /**
     * Display a clean, custom confirmation modal.
     * @param {Object|string} options - Configuration object or prompt message string.
     * @returns {Promise<boolean>}
     */
    function mantisConfirm(options) {
        return new Promise((resolve) => {
            activeResolve = resolve;
            const root = ensureOverlay();

            let opts = {};
            if (typeof options === 'string') {
                opts = {
                    title: 'Confirm Action',
                    message: options,
                    confirmText: 'Confirm',
                    cancelText: 'Cancel',
                    danger: /delete|remove|clear|wipe|destroy|terminate/i.test(options)
                };
            } else {
                opts = Object.assign({
                    title: 'Confirm Action',
                    message: 'Are you sure you want to proceed?',
                    details: null,
                    confirmText: 'Confirm',
                    cancelText: 'Cancel',
                    danger: false,
                    icon: null
                }, options || {});
            }

            const isDanger = !!opts.danger;
            const iconClass = opts.icon || (isDanger ? 'fa-triangle-exclamation' : 'fa-circle-question');
            const iconBoxClass = isDanger ? 'mantis-dialog-icon-danger' : 'mantis-dialog-icon-warning';

            root.innerHTML = `
                <div class="mantis-dialog-card" id="mantis-dialog-card">
                    <div class="mantis-dialog-header">
                        <div class="mantis-dialog-icon-box ${iconBoxClass}">
                            <i class="fa-solid ${iconClass}"></i>
                        </div>
                        <div class="mantis-dialog-title-wrap">
                            <h3 class="mantis-dialog-title">${opts.title}</h3>
                            <p class="mantis-dialog-subtitle">MANTIS Security Action</p>
                        </div>
                    </div>

                    <div class="mantis-dialog-body">
                        <div>${opts.message}</div>
                        ${opts.details ? `<div class="mantis-dialog-details">${opts.details}</div>` : ''}
                    </div>

                    <div class="mantis-dialog-footer">
                        <button type="button" class="mantis-dialog-btn mantis-dialog-btn-cancel" id="mantis-dialog-btn-cancel">
                            ${opts.cancelText}
                        </button>
                        <button type="button" class="mantis-dialog-btn ${isDanger ? 'mantis-dialog-btn-danger' : 'mantis-dialog-btn-primary'}" id="mantis-dialog-btn-confirm">
                            ${opts.confirmText}
                        </button>
                    </div>
                </div>
            `;

            const cancelBtn = root.querySelector('#mantis-dialog-btn-cancel');
            const confirmBtn = root.querySelector('#mantis-dialog-btn-confirm');
            const card = root.querySelector('#mantis-dialog-card');

            cancelBtn.addEventListener('click', () => closeDialog(false));
            confirmBtn.addEventListener('click', () => closeDialog(true));

            // Prevent backdrop click when clicking inside card
            card.addEventListener('click', (e) => e.stopPropagation());
            root.addEventListener('click', () => closeDialog(false));

            // Trigger animation
            requestAnimationFrame(() => {
                root.classList.add('active');
                confirmBtn.focus();
            });
        });
    }

    /**
     * Display a clean, custom alert modal.
     * @param {Object|string} options - Configuration object or alert message string.
     * @returns {Promise<void>}
     */
    function mantisAlert(options) {
        return new Promise((resolve) => {
            activeResolve = resolve;
            const root = ensureOverlay();

            let opts = {};
            if (typeof options === 'string') {
                const isErr = /error|failed|invalid/i.test(options);
                opts = {
                    title: isErr ? 'Notice / Error' : 'Notice',
                    message: options,
                    type: isErr ? 'error' : 'info',
                    buttonText: 'OK'
                };
            } else {
                opts = Object.assign({
                    title: 'Notice',
                    message: '',
                    type: 'info',
                    buttonText: 'OK'
                }, options || {});
            }

            const iconMap = {
                error: { icon: 'fa-circle-xmark', box: 'mantis-dialog-icon-danger' },
                warning: { icon: 'fa-triangle-exclamation', box: 'mantis-dialog-icon-warning' },
                success: { icon: 'fa-circle-check', box: 'mantis-dialog-icon-success' },
                info: { icon: 'fa-circle-info', box: 'mantis-dialog-icon-info' }
            };

            const cfg = iconMap[opts.type] || iconMap.info;

            root.innerHTML = `
                <div class="mantis-dialog-card" id="mantis-dialog-card">
                    <div class="mantis-dialog-header">
                        <div class="mantis-dialog-icon-box ${cfg.box}">
                            <i class="fa-solid ${cfg.icon}"></i>
                        </div>
                        <div class="mantis-dialog-title-wrap">
                            <h3 class="mantis-dialog-title">${opts.title}</h3>
                            <p class="mantis-dialog-subtitle">MANTIS Notification</p>
                        </div>
                    </div>

                    <div class="mantis-dialog-body">
                        <div>${opts.message}</div>
                    </div>

                    <div class="mantis-dialog-footer">
                        <button type="button" class="mantis-dialog-btn mantis-dialog-btn-primary" id="mantis-dialog-btn-ok">
                            ${opts.buttonText}
                        </button>
                    </div>
                </div>
            `;

            const okBtn = root.querySelector('#mantis-dialog-btn-ok');
            const card = root.querySelector('#mantis-dialog-card');

            okBtn.addEventListener('click', () => closeDialog(true));
            card.addEventListener('click', (e) => e.stopPropagation());
            root.addEventListener('click', () => closeDialog(true));

            requestAnimationFrame(() => {
                root.classList.add('active');
                okBtn.focus();
            });
        });
    }

    // Expose globally
    window.mantisConfirm = mantisConfirm;
    window.mantisAlert = mantisAlert;
    window.MantisDialog = {
        confirm: mantisConfirm,
        alert: mantisAlert
    };
})();
