document.addEventListener('DOMContentLoaded', function () {
    if (!window.fluentAuthPasskey) {
        return;
    }

    const config = window.fluentAuthPasskey;

    addStyles();

    function isSupported() {
        return !!(window.PublicKeyCredential && navigator.credentials);
    }

    function base64UrlToBuffer(value) {
        value = value.replace(/-/g, '+').replace(/_/g, '/');
        const padding = value.length % 4;
        if (padding) {
            value += '='.repeat(4 - padding);
        }

        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes.buffer;
    }

    function bufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        bytes.forEach((byte) => {
            binary += String.fromCharCode(byte);
        });

        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function request(action, data) {
        const body = new FormData();
        body.append('action', action);
        body.append('_nonce', config.nonce);

        Object.keys(data || {}).forEach((key) => {
            body.append(key, data[key]);
        });

        return fetch(config.ajax_url, {
            method: 'POST',
            credentials: 'same-origin',
            body
        }).then((response) => {
            return response.json().then((json) => {
                if (!response.ok) {
                    throw json;
                }

                return json;
            });
        });
    }

    function prepareCreationOptions(options) {
        options.challenge = base64UrlToBuffer(options.challenge);
        options.user.id = base64UrlToBuffer(options.user.id);

        if (options.excludeCredentials) {
            options.excludeCredentials = options.excludeCredentials.map((credential) => {
                credential.id = base64UrlToBuffer(credential.id);
                return credential;
            });
        }

        return options;
    }

    function prepareRequestOptions(options) {
        options.challenge = base64UrlToBuffer(options.challenge);

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map((credential) => {
                credential.id = base64UrlToBuffer(credential.id);
                return credential;
            });
        }

        return options;
    }

    function serializeCredential(credential) {
        const response = credential.response;
        const data = {
            id: credential.id,
            rawId: bufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {}
        };

        if (response.clientDataJSON) {
            data.response.clientDataJSON = bufferToBase64Url(response.clientDataJSON);
        }

        if (response.attestationObject) {
            data.response.attestationObject = bufferToBase64Url(response.attestationObject);
        }

        if (response.authenticatorData) {
            data.response.authenticatorData = bufferToBase64Url(response.authenticatorData);
        }

        if (response.signature) {
            data.response.signature = bufferToBase64Url(response.signature);
        }

        if (response.userHandle) {
            data.response.userHandle = bufferToBase64Url(response.userHandle);
        }

        if (response.getTransports) {
            data.response.transports = response.getTransports();
        }

        return data;
    }

    function getMessageTarget(element) {
        const wrapper = element.closest('.fls_passkey_login_wrap') || element.closest('.fls_passkey_manager');
        return wrapper ? wrapper.querySelector('.fls_passkey_message, .fls_passkey_messages') : null;
    }

    function setMessage(element, message, type) {
        const target = getMessageTarget(element);
        if (!target) {
            return;
        }

        target.className = target.className.replace(/\s?fls_passkey_(error|success)/g, '');
        target.classList.add(type === 'success' ? 'fls_passkey_success' : 'fls_passkey_error');
        target.textContent = message || '';
    }

    function getLoginValue(button) {
        const form = button.closest('form');
        if (!form) {
            return '';
        }

        const field = form.querySelector('input[name="log"], #user_login');
        return field ? field.value : '';
    }

    function focusLoginField(button) {
        const form = button.closest('form');
        if (!form) {
            return;
        }

        const field = form.querySelector('input[name="log"], #user_login');
        if (field) {
            field.focus();
        }
    }

    function getRedirectValue(button) {
        const form = button.closest('form');
        if (!form) {
            return '';
        }

        const redirectField = form.querySelector('input[name="force_redirect_to"], input[name="redirect_to"]');
        return redirectField ? redirectField.value : '';
    }

    function handlePasskeyLogin(event) {
        event.preventDefault();

        const button = event.currentTarget;
        if (!isSupported()) {
            setMessage(button, config.i18n.notSupported, 'error');
            return;
        }

        if (config.available !== 'yes') {
            setMessage(button, config.i18n.notAvailable, 'error');
            return;
        }

        button.disabled = true;
        setMessage(button, '', 'success');

        const login = getLoginValue(button);
        const redirectTo = getRedirectValue(button);

        if (!login.trim()) {
            setMessage(button, config.i18n.usernameRequired, 'error');
            focusLoginField(button);
            button.disabled = false;
            return;
        }

        request('fls_passkey_login_options', {
            login
        }).then((options) => {
            const challengeToken = options.challengeToken;
            const publicKey = prepareRequestOptions(options.publicKey);
            return navigator.credentials.get({ publicKey }).then((credential) => {
                const payload = serializeCredential(credential);
                payload.challengeToken = challengeToken;

                return request('fls_passkey_login_verify', {
                    login,
                    redirect_to: redirectTo,
                    payload: JSON.stringify(payload)
                });
            });
        }).then((response) => {
            if (response.redirect) {
                window.location.href = response.redirect;
                return;
            }

            window.location.reload();
        }).catch((error) => {
            setMessage(button, error.message || config.i18n.loginFailed, 'error');
        }).finally(() => {
            button.disabled = false;
        });
    }

    function renderCredentials(manager, credentials) {
        const list = manager.querySelector('.fls_passkey_list');
        if (!list) {
            return;
        }

        syncPasswordConfirmation(manager, credentials);

        if (!credentials || !credentials.length) {
            list.innerHTML = '<p>' + config.i18n.emptyPasskeys + '</p>';
            return;
        }

        list.innerHTML = credentials.map((credential) => {
            const lastUsed = credential.last_used_at ? credential.last_used_at : config.i18n.never;
            const created = credential.created_at ? credential.created_at : '-';
            return '<div class="fls_passkey_item" data-id="' + credential.id + '">'
                + '<div class="fls_passkey_item_details">'
                + '<strong class="fls_passkey_name">' + escapeHtml(credential.name) + '</strong><br>'
                + '<small>' + escapeHtml(config.i18n.created) + ': ' + escapeHtml(created) + '</small><br>'
                + '<small>' + escapeHtml(config.i18n.lastUsed) + ': ' + escapeHtml(lastUsed) + '</small>'
                + '</div>'
                + '<div class="fls_passkey_actions">'
                + '<button type="button" class="button fls_passkey_rename" data-id="' + credential.id + '" data-name="' + escapeAttr(credential.name) + '">' + escapeHtml(config.i18n.rename) + '</button>'
                + '<button type="button" class="button fls_passkey_delete" data-id="' + credential.id + '">' + escapeHtml(config.i18n.remove) + '</button>'
                + '</div>'
                + '</div>';
        }).join('');
    }

    function syncPasswordConfirmation(manager, credentials) {
        const confirm = manager ? manager.querySelector('.fls_passkey_confirm') : null;
        if (!confirm) {
            return;
        }

        const hasPasskeys = !!(credentials && credentials.length);
        confirm.hidden = !hasPasskeys;

        if (!hasPasskeys) {
            const passwordField = confirm.querySelector('.fls_passkey_current_password, input[name="current_password"]');
            if (passwordField) {
                passwordField.value = '';
            }
        }
    }

    function loadCredentialList(manager) {
        return request('fls_passkey_list').then((response) => {
            renderCredentials(manager, response.credentials);
        });
    }

    function handlePasskeyRegistration(event) {
        event.preventDefault();

        const button = event.currentTarget;
        const manager = button.closest('.fls_passkey_manager');

        if (!isSupported()) {
            setMessage(button, config.i18n.notSupported, 'error');
            return;
        }

        if (config.available !== 'yes') {
            setMessage(button, config.i18n.notAvailable, 'error');
            return;
        }

        button.disabled = true;
        setMessage(button, '', 'success');

        const passkeyName = window.prompt(config.i18n.renamePasskey, '');
        if (passkeyName === null) {
            button.disabled = false;
            return;
        }

        if (!passkeyName.trim()) {
            setMessage(button, config.i18n.nameRequired, 'error');
            button.disabled = false;
            return;
        }

        request('fls_passkey_register_options').then((options) => {
            const challengeToken = options.challengeToken;
            const publicKey = prepareCreationOptions(options.publicKey);
            return navigator.credentials.create({ publicKey }).then((credential) => {
                const payload = serializeCredential(credential);
                payload.challengeToken = challengeToken;
                payload.name = passkeyName.trim();

                return request('fls_passkey_register_verify', {
                    payload: JSON.stringify(payload)
                });
            });
        }).then((response) => {
            setMessage(button, response.message || config.i18n.passkeyRegistered, 'success');
            renderCredentials(manager, response.credentials);
        }).catch((error) => {
            setMessage(button, error.message || config.i18n.registerFailed, 'error');
        }).finally(() => {
            button.disabled = false;
        });
    }

    function handlePasskeyRename(event) {
        const button = event.target.closest('.fls_passkey_rename');
        if (!button) {
            return;
        }

        event.preventDefault();

        const manager = button.closest('.fls_passkey_manager');
        const name = window.prompt(config.i18n.renamePasskey, button.dataset.name || '');
        if (name === null) {
            return;
        }

        if (!name.trim()) {
            setMessage(button, config.i18n.nameRequired, 'error');
            return;
        }

        button.disabled = true;

        request('fls_passkey_rename', {
            credential_id: button.dataset.id,
            name: name.trim()
        }).then((response) => {
            setMessage(button, response.message, 'success');
            renderCredentials(manager, response.credentials);
        }).catch((error) => {
            setMessage(button, error.message || config.i18n.renameFailed, 'error');
        }).finally(() => {
            button.disabled = false;
        });
    }

    function handlePasskeyDelete(event) {
        const button = event.target.closest('.fls_passkey_delete');
        if (!button) {
            return;
        }

        event.preventDefault();
        if (!window.confirm(config.i18n.confirmDelete)) {
            return;
        }

        const manager = button.closest('.fls_passkey_manager');
        const data = {
            credential_id: button.dataset.id
        };

        if (config.delete_requires_password === 'yes') {
            const passwordField = manager ? manager.querySelector('.fls_passkey_current_password, input[name="current_password"]') : null;
            const password = passwordField ? passwordField.value : '';
            if (!password) {
                setMessage(button, config.i18n.passwordRequired, 'error');
                if (passwordField) {
                    passwordField.focus();
                }
                return;
            }

            data.current_password = password;
        }

        button.disabled = true;

        request('fls_passkey_delete', data).then((response) => {
            setMessage(button, response.message, 'success');
            const passwordField = manager ? manager.querySelector('.fls_passkey_current_password, input[name="current_password"]') : null;
            if (passwordField) {
                passwordField.value = '';
            }
            renderCredentials(manager, response.credentials);
        }).catch((error) => {
            setMessage(button, error.message || config.i18n.registerFailed, 'error');
        }).finally(() => {
            button.disabled = false;
        });
    }

    function escapeHtml(value) {
        const div = document.createElement('div');
        div.textContent = value;
        return div.innerHTML;
    }

    function escapeAttr(value) {
        return escapeHtml(value).replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    function addStyles() {
        if (document.getElementById('fls-passkey-styles')) {
            return;
        }

        const style = document.createElement('style');
        style.id = 'fls-passkey-styles';
        style.textContent = ''
            + '.fls_passkey_login_wrap{margin:12px 0;text-align:center;}'
            + '.fls_passkey_login_btn{width:100%;display:flex!important;align-items:center;justify-content:center;gap:6px;}'
            + '.fls_passkey_message,.fls_passkey_messages{font-size:13px;margin-top:8px;}'
            + '.fls_passkey_error{color:#b32d2e;}'
            + '.fls_passkey_success{color:#008a20;}'
            + '.fls_passkey_manager_header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;}'
            + '.fls_passkey_confirm[hidden]{display:none!important;}'
            + '.fls_passkey_confirm{margin:12px 0;}'
            + '.fls_passkey_confirm label{display:block;font-weight:600;margin-bottom:4px;}'
            + '.fls_passkey_item{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid #dcdcde;}'
            + '.fls_passkey_item_details{min-width:0;}'
            + '.fls_passkey_actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end;}';
        document.head.appendChild(style);
    }

    document.querySelectorAll('.fls_passkey_login_btn').forEach((button) => {
        button.addEventListener('click', handlePasskeyLogin);
    });

    document.querySelectorAll('.fls_passkey_manager').forEach((manager) => {
        manager.addEventListener('click', handlePasskeyDelete);
        manager.addEventListener('click', handlePasskeyRename);

        const registerButton = manager.querySelector('.fls_passkey_register');
        if (registerButton) {
            registerButton.addEventListener('click', handlePasskeyRegistration);
        }

        loadCredentialList(manager).catch(() => {
            renderCredentials(manager, []);
        });
    });
});
