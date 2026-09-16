require('./login_helper.scss');
require('./magic_url.scss');

/*
 * Everything the login screens run in the browser.
 *
 * Two things pushed this into one file. The first is a bug: the second factor forms are
 * delivered to the front end as a string of HTML and installed with innerHTML, and
 * innerHTML never executes a <script>. Every ceremony that lived in an inline script
 * beside its markup therefore worked on wp-login.php, which renders server side, and
 * was inert through the [fluent_auth_login] shortcode - a passkey challenge arrived
 * with nothing on it a user could operate.
 *
 * The second is ordering. The passkey button and the magic link both move themselves
 * into the login form on DOMContentLoaded, and while they were separate bundles which
 * one landed first came down to which <script> tag the parser reached first. That is
 * what the separator between them needed a setTimeout to work around. Here the order is
 * just the order `start()` calls them in.
 *
 * So the markup now carries data only - a <script type="application/json"> island,
 * which innerHTML does preserve, because it is parsed as an element and read with
 * textContent rather than run - and all the behaviour is here, loaded once and re-bound
 * as often as the page needs.
 *
 * Google One Tap is deliberately not here; it needs Google's own SDK, and that should
 * only be fetched on pages that actually offer it.
 */

const config = () => window.fluentAuthPublic || {};

/* ------------------------------------------------------------------- small helpers */

const byId = (id) => document.getElementById(id);

/**
 * Reads one of the JSON islands the PHP prints beside a form. Null rather than a throw:
 * an absent island just means this page is not that kind of screen.
 */
function readConfig(id) {
    const el = byId(id);

    if (!el) {
        return null;
    }

    try {
        return JSON.parse(el.textContent);
    } catch (e) {
        return null;
    }
}

/**
 * Marks an element as wired, so a second pass leaves it alone. The challenge form is
 * re-scanned every time one replaces another in place, and binding twice would run the
 * ceremony twice.
 */
function claim(el) {
    if (!el || el.dataset.flsBound === 'yes') {
        return false;
    }

    el.dataset.flsBound = 'yes';

    return true;
}

function setText(el, text) {
    if (el) {
        el.textContent = text || '';
    }
}

/**
 * requestSubmit() so the form's own submit handler still runs; click() is the fallback
 * for browsers without it.
 */
function submitVia(form, button) {
    if (form.requestSubmit) {
        form.requestSubmit(button);
    } else {
        button.click();
    }
}

/**
 * The one way this file talks to the server.
 *
 * Resolves {ok, data} rather than the body alone, because fetch() only rejects on a
 * network failure: a 422 carrying "you are trying too much" arrives looking exactly like
 * a success, and every caller here has to tell them apart. Content-Type is left unset on
 * purpose so the browser writes the multipart boundary itself.
 */
function send(url, body) {
    return fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        body
    }).then((response) => response.json()
        .catch(() => ({}))
        .then((data) => ({ok: response.ok, data})));
}

/**
 * The same call for the endpoints that take a bare action and a few fields.
 */
function post(url, action, payload) {
    const body = new FormData();

    body.append('action', action);

    Object.keys(payload || {}).forEach((key) => body.append(key, payload[key]));

    return send(url, body);
}

/* --------------------------------------------------------------- WebAuthn helpers */

function toBuffer(value) {
    const normalised = String(value).replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalised.padEnd(normalised.length + ((4 - (normalised.length % 4)) % 4), '=');
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

function toBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Whether the browser can run a ceremony of this kind: 'get' to prove a credential,
 * 'create' to make one. Old browsers, webviews and any page served over plain http
 * answer no, and every caller treats that as "offer the password instead".
 */
function webAuthnSupports(kind) {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials[kind]);
}

/**
 * The options a challenge was issued with, as the browser wants them. Copied rather
 * than edited in place so a retry after a cancelled prompt still has the base64 it
 * started from.
 */
function decodeRequestOptions(options) {
    const decoded = JSON.parse(JSON.stringify(options || {}));

    decoded.challenge = toBuffer(decoded.challenge);
    decoded.allowCredentials = (decoded.allowCredentials || []).map((item) => ({
        ...item,
        id: toBuffer(item.id)
    }));

    return decoded;
}

function decodeCreationOptions(options) {
    const decoded = JSON.parse(JSON.stringify(options || {}));

    decoded.challenge = toBuffer(decoded.challenge);
    decoded.user.id = toBuffer(decoded.user.id);
    decoded.excludeCredentials = (decoded.excludeCredentials || []).map((item) => ({
        ...item,
        id: toBuffer(item.id)
    }));

    return decoded;
}

function assertionPayload(credential) {
    return JSON.stringify({
        rawId: toBase64Url(credential.rawId),
        clientDataJSON: toBase64Url(credential.response.clientDataJSON),
        authenticatorData: toBase64Url(credential.response.authenticatorData),
        signature: toBase64Url(credential.response.signature),
        userHandle: credential.response.userHandle
            ? toBase64Url(credential.response.userHandle)
            : ''
    });
}

/* --------------------------------------------------------- the plugin's ajax forms */

function clearErrors() {
    document.querySelectorAll('.error.text-danger').forEach((el) => {
        el.parentNode.parentNode.classList.remove('is-error');
        el.remove();
    });
}

function toggleLoading(button) {
    if (button) {
        button.classList.toggle('fls_loading');
        button.disabled = !button.disabled;
    }
}

function showError(form, message) {
    const el = document.createElement('div');
    el.classList.add('error', 'text-danger');
    el.innerHTML = message;
    form.appendChild(el);
}

function showFieldErrors(response) {
    Object.keys(response).forEach((property) => {
        const field = byId('flt_' + property);

        if (!field) {
            return;
        }

        const el = document.createElement('div');
        el.classList.add('error', 'text-danger');
        el.innerHTML = Object.values(response[property])[0];
        field.parentNode.insertBefore(el, field.nextSibling);
        field.parentNode.parentNode.classList.add('is-error');
    });
}

/**
 * Posts one of the plugin's own forms to admin-ajax and routes the reply. `callback`
 * takes over the success case where a form needs something other than handleSuccess().
 */
function submitForm(form, submitBtnId, action, callback, errorCallback) {
    const submitBtn = byId(submitBtnId);
    const settings = config();

    toggleLoading(submitBtn);
    clearErrors();

    const data = new FormData(form);

    data.append('action', action);
    data.append('_nonce', settings.fls_login_nonce);
    data.append('_is_fls_form', 'yes');

    send(settings.ajax_url, data).then(({ok, data: response}) => {
        toggleLoading(submitBtn);

        if (ok) {
            if (callback) {
                callback(response);
            } else {
                handleSuccess(response, form);
            }

            return;
        }

        let message = response.error;

        if (!message && response.message) {
            message = response.message;
        } else if (message && response.data && response.data.status === 403) {
            message = response.message;
        }

        if (message) {
            showError(form, message);
        } else {
            showFieldErrors(response);
        }

        if (errorCallback) {
            errorCallback(response);
        }
    }).catch(() => {
        /*
         * A dropped connection, which the XHR this replaced did not handle at all - it
         * left the button spinning with nothing said. There is no server message to
         * quote here, so the form says the one true thing and stays usable.
         */
        toggleLoading(submitBtn);
        showError(form, (config().i18n || {}).network_error || 'Network error. Please try again.');

        if (errorCallback) {
            errorCallback({});
        }
    });
}

/*
 * Recovery codes are shown once and never again, so this stops on the way out rather
 * than following response.redirect straight past them. The continue button carries the
 * redirect, so leaving is still one click - it just has to be a click.
 */
function showRecoveryCodes(response, form) {
    const panel = document.createElement('div');
    panel.style.cssText = 'margin-top:16px;padding:14px;border-left:4px solid #00a32a;background:#f6f7f7;';

    const intro = document.createElement('p');
    intro.style.cssText = 'margin:0 0 10px;';
    intro.textContent = response.recovery_message || '';
    panel.appendChild(intro);

    const box = document.createElement('textarea');
    box.readOnly = true;
    box.rows = response.recovery_codes.length;
    box.style.cssText = 'width:100%;font-family:Menlo,Consolas,monospace;letter-spacing:2px;';
    // textContent, not innerHTML: nothing here is meant to be markup.
    box.textContent = response.recovery_codes.join('\n');
    box.addEventListener('click', () => box.select());
    panel.appendChild(box);

    const go = document.createElement('button');
    go.type = 'button';
    go.className = 'button button-primary button-large';
    go.style.cssText = 'display:block;width:100%;margin-top:12px;cursor:pointer;';
    go.textContent = response.recovery_continue || 'Continue';
    go.addEventListener('click', () => {
        window.location.href = response.redirect;
    });
    panel.appendChild(go);

    form.innerHTML = '';
    form.appendChild(panel);
    go.focus();
}

function handleSuccess(response, form) {
    if (response.recovery_codes && response.recovery_codes.length && response.redirect) {
        showRecoveryCodes(response, form);
        return;
    }

    if (response.load_2fa) {
        /*
         * innerHTML does not run <script>, which is the whole reason the ceremonies
         * live in this file. The JSON islands inside the markup survive it - they are
         * elements, not code - so re-binding is all it takes to bring the form that just
         * landed to life.
         */
        byId('fls_login_form').innerHTML = response.two_fa_form;
        initChallenge();
        return;
    }

    if (response.redirect) {
        window.location.href = response.redirect;
        return;
    }

    if (response.message) {
        const el = document.createElement('div');
        el.classList.add('success', 'text-success', 'fls-text-success');
        el.innerHTML = response.message;
        form.appendChild(el);
        form.reset();
        return;
    }

    window.location.reload();
}

/* -------------------------------------------------- the passkey second factor form */

function initPasskeyChallenge() {
    const settings = readConfig('fls_passkey_config');
    const form = byId('fls_2fa_form');
    const startButton = byId('fls_passkey_start');

    if (!settings || !form || !startButton || !claim(startButton)) {
        return;
    }

    const responseField = byId('fls_passkey_response');
    const status = byId('fls_passkey_status');
    const submit = byId('fls_2fa_confirm');
    const messages = settings.messages || {};
    let busy = false;

    if (!webAuthnSupports('get')) {
        startButton.disabled = true;
        setText(status, messages.unsupported);
        return;
    }

    function run() {
        if (busy) {
            return;
        }

        busy = true;
        startButton.disabled = true;
        setText(status, messages.prompting);

        navigator.credentials.get({publicKey: decodeRequestOptions(settings.options)})
            .then((credential) => {
                setText(status, messages.verifying);
                responseField.value = assertionPayload(credential);
                submitVia(form, submit);
            })
            .catch(() => {
                busy = false;
                startButton.disabled = false;
                setText(status, messages.cancelled);
            });
    }

    startButton.addEventListener('click', run);

    /*
     * Offered rather than forced. Calling this on load would raise the operating
     * system's prompt before the user has looked at the page, and on a shared machine
     * that is a fingerprint request nobody asked for.
     */
    setTimeout(run, 150);
}

/* ------------------------------------------------------- first time 2FA enrollment */

function initEnrollment() {
    const settings = readConfig('fls_enroll_config');
    const form = byId('fls_2fa_form');
    const pane = byId('fls_enroll_passkey');

    if (!settings || !form || !pane || !claim(pane)) {
        return;
    }

    const appPane = byId('fls_enroll_app');
    const startButton = byId('fls_enroll_passkey_start');
    const status = byId('fls_enroll_passkey_status');
    const credentialField = byId('fls_enroll_credential');
    const transportField = byId('fls_enroll_transports');
    const submit = byId('fls_2fa_confirm');
    const showApp = byId('fls_enroll_show_app');
    const showPasskeyWrap = byId('fls_enroll_show_passkey_wrap');
    const showPasskey = byId('fls_enroll_show_passkey');
    const codeField = byId('fls_enroll_code');
    const messages = settings.messages || {};
    let busy = false;

    /*
     * No WebAuthn at all: the app is the only route, and the passkey offer never
     * appears. This is the branch that keeps the requirement from being a dead end on
     * an old or locked down browser.
     */
    if (!webAuthnSupports('create')) {
        return;
    }

    const show = (which) => {
        pane.style.display = which === 'passkey' ? '' : 'none';
        appPane.style.display = which === 'passkey' ? 'none' : '';
    };

    /*
     * Clearing these is what keeps the app fallback usable. The field is only emptied by
     * the create() catch, so a credential the *server* rejects - a challenge that
     * expired, an authenticator it would not verify - stays in the form. The user then
     * switches to the app, types a correct code, and verifyProof() sees a credential
     * still sitting there and takes the passkey branch again, failing the same way every
     * time. With this the only route to a session, that is not a wrong answer: it is an
     * account that cannot be signed into until somebody thinks to reload.
     */
    const clearCredential = () => {
        credentialField.value = '';
        transportField.value = '';
    };

    if (showApp) {
        showApp.addEventListener('click', (event) => {
            event.preventDefault();
            clearCredential();
            show('app');
        });
    }

    // Belt and braces: typing a code is an unambiguous statement of which route is being
    // taken, whichever pane happens to be on screen.
    if (codeField) {
        codeField.addEventListener('input', clearCredential);
    }

    if (showPasskey) {
        showPasskey.addEventListener('click', (event) => {
            event.preventDefault();
            show('passkey');
        });
    }

    /*
     * A platform authenticator - Touch ID, Windows Hello, an Android screen lock - is
     * the case where a passkey is both possible and easier than anything else, so it
     * leads. Without one a passkey may still work from a security key or a phone, so the
     * offer stays reachable by link rather than leading.
     */
    if (showPasskeyWrap) {
        showPasskeyWrap.style.display = '';
    }

    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then((available) => {
            if (available) {
                show('passkey');
            }
        })
        .catch(() => {
            // Left on the authenticator app, which always works.
        });

    startButton.addEventListener('click', () => {
        if (busy) {
            return;
        }

        busy = true;
        startButton.disabled = true;
        setText(status, messages.prompting);

        navigator.credentials.create({publicKey: decodeCreationOptions(settings.options)})
            .then((credential) => {
                setText(status, messages.saving);

                const transports = credential.response.getTransports
                    ? credential.response.getTransports()
                    : [];

                transportField.value = JSON.stringify(transports || []);
                credentialField.value = JSON.stringify({
                    rawId: toBase64Url(credential.rawId),
                    clientDataJSON: toBase64Url(credential.response.clientDataJSON),
                    attestationObject: toBase64Url(credential.response.attestationObject)
                });

                submitVia(form, submit);
            })
            .catch(() => {
                busy = false;
                startButton.disabled = false;
                clearCredential();
                setText(status, messages.cancelled);
            });
    });
}

/* -------------------------------------------- the passkey button on the login form */

function initPasskeyLogin() {
    const settings = readConfig('fls_passkey_login_config');
    const wrap = byId('fls_passkey_login');
    const button = byId('fls_passkey_login_button');

    if (!settings || !wrap || !button || !claim(button)) {
        return false;
    }

    const status = byId('fls_passkey_login_status');
    const messages = settings.messages || {};
    let busy = false;

    /*
     * Hidden until the browser has been asked, rather than shown and then withdrawn.
     * Somewhere without WebAuthn should see the ordinary password form and no sign that
     * something was missing.
     */
    if (!webAuthnSupports('get')) {
        return false;
    }

    wrap.style.display = '';

    /*
     * wp-login.php only. `login_form` fires between the password field and the submit
     * button, so on that page the block has to be moved down past it. A wp_login_form()
     * form gives us a hook that is already at the bottom, so there is nothing to move.
     */
    const loginForm = settings.move ? byId('loginform') : null;

    if (loginForm) {
        loginForm.appendChild(wrap);
    }

    const reset = (message) => {
        busy = false;
        button.disabled = false;
        setText(status, message);
    };

    function run() {
        if (busy) {
            return;
        }

        busy = true;
        button.disabled = true;
        setText(status, messages.prompting);

        const send = (action, payload) => post(settings.ajaxUrl, action, {
            _nonce: settings.nonce,
            ...payload
        });

        send(settings.challenge, {}).then(({data: result}) => {
            if (!result || !result.success) {
                reset(messages.failed);
                return;
            }

            const options = decodeRequestOptions(result.data.options);

            /*
             * Left empty on purpose - see PasskeyLogin. The authenticator is being asked
             * what it holds for this site, not to answer for a credential the page has
             * already named.
             */
            delete options.allowCredentials;

            return navigator.credentials.get({publicKey: options})
                .then((credential) => {
                    setText(status, messages.verifying);

                    return send(settings.verify, {
                        token: result.data.token,
                        redirect_to: settings.redirectTo,
                        webauthn_response: assertionPayload(credential)
                    });
                })
                .then(({data: verified}) => {
                    if (verified && verified.success && verified.data && verified.data.redirect) {
                        window.location.href = verified.data.redirect;
                        return;
                    }

                    reset(verified && verified.data && verified.data.message
                        ? verified.data.message
                        : messages.failed);
                });
        }).catch(() => {
            /*
             * A cancelled prompt, a browser that found nothing to offer and a network
             * failure all arrive here. None of them is worth an alarming message: the
             * password form is still on the page underneath, and "try again or use your
             * password" is the only useful thing to say about any of them.
             */
            reset(messages.cancelled);
        });
    }

    button.addEventListener('click', run);

    return true;
}

/* ------------------------------------------------------------------- magic login */

function initMagicLogin(passkeyButtonShowing) {
    const settings = config().magic;
    const magicLogin = byId('fls_magic_login');

    /*
     * Every login view loads this script, but only the ones carrying the magic form have
     * anything for it to do.
     */
    if (!settings || !magicLogin || !claim(magicLogin)) {
        return;
    }

    const loginForm = byId('loginform');
    const initialWrapper = document.querySelector('.fls_magic_initial');
    const formWrapper = document.querySelector('.fls_magic_login_form');
    const showMagic = document.querySelector('.fls_magic_show_btn');
    const showRegular = document.querySelector('.fls_magic_show_regular');
    const logon = byId('fls_magic_logon');
    const nonceField = byId('fls_magic_logon_nonce');

    const openMagic = () => {
        if (initialWrapper) {
            initialWrapper.style.display = 'none';
        }

        if (formWrapper) {
            formWrapper.style.display = 'block';
        }

        if (loginForm) {
            loginForm.classList.add('showing_magic_form');
        }
    };

    if (loginForm) {
        /*
         * Appended after the passkey button, which start() has already placed, so the
         * alternatives read in the order the settings screen lists them.
         */
        loginForm.appendChild(magicLogin);

        loginForm.addEventListener('submit', function (e) {
            if (this.classList.contains('showing_magic_form')) {
                e.preventDefault();
                return false;
            }
        });

        if (settings.is_primary) {
            openMagic();
        }
    }

    magicLogin.style.display = 'block';

    /*
     * The passkey button opens the run of alternatives with a separator of its own, and
     * this block prints one for the case where that button never appears. Exactly one of
     * them should be on the page, and it is the lower one that goes.
     */
    if (passkeyButtonShowing) {
        const duplicate = magicLogin.querySelector('.fls_or_wrap');

        if (duplicate) {
            duplicate.style.display = 'none';
        }
    }

    if (showMagic) {
        showMagic.addEventListener('click', (e) => {
            e.preventDefault();
            openMagic();
        });
    }

    if (showRegular) {
        showRegular.addEventListener('click', (e) => {
            e.preventDefault();

            if (initialWrapper) {
                initialWrapper.style.display = 'block';
            }

            if (formWrapper) {
                formWrapper.style.display = 'none';
            }

            if (loginForm) {
                loginForm.classList.remove('showing_magic_form');
            }

            const password = byId('user_pass');

            if (password) {
                password.disabled = false;
            }
        });
    }

    if (logon) {
        // Enter in the email field would submit the password form behind this one.
        logon.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                return false;
            }
        });
    }

    const submitButton = byId('fls_magic_submit');

    if (!submitButton) {
        return;
    }

    const setSuccess = (data) => {
        const panel = document.createElement('div');
        panel.className = 'login_magic_success';

        const icon = document.createElement('div');
        icon.className = 'login_success_icon';
        const img = document.createElement('img');
        img.src = settings.success_icon;
        icon.appendChild(img);

        const heading = document.createElement('div');
        heading.className = 'login_success_heading';
        const h3 = document.createElement('h3');
        // textContent throughout: this is a server message, not markup.
        h3.textContent = data.heading || '';
        heading.appendChild(h3);

        const message = document.createElement('div');
        message.className = 'login_success_message';
        const p = document.createElement('p');
        p.textContent = data.message || '';
        message.appendChild(p);

        panel.append(icon, heading, message);

        formWrapper.innerHTML = '';
        formWrapper.appendChild(panel);
    };

    const redirectTarget = () => {
        const fromLogin = loginForm ? loginForm.querySelector('input[name=redirect_to]') : null;

        if (fromLogin && fromLogin.value) {
            return fromLogin.value;
        }

        const fromMagic = magicLogin.querySelector('input[name=redirect_to]');

        return fromMagic ? fromMagic.value : '';
    };

    submitButton.addEventListener('click', (e) => {
        e.preventDefault();

        if (!logon.value) {
            window.alert(settings.empty_text);
            return;
        }

        const previous = submitButton.textContent;
        submitButton.dataset.prevText = previous;
        submitButton.classList.add('fls_loading');
        submitButton.textContent = settings.wait_text;
        submitButton.disabled = true;

        post(config().ajax_url, 'fls_magic_send_magic_email', {
            email: logon.value,
            redirect_to: redirectTarget(),
            _nonce: nonceField ? nonceField.value : ''
        }).then(({ok, data}) => {
            if (ok) {
                setSuccess(data);
                return;
            }

            // Rate limited, unknown address, magic login switched off: the endpoint
            // says which, and saying it is more use than a generic failure.
            window.alert(data.message || settings.empty_text);
        }).catch(() => {
            window.alert(settings.empty_text);
        }).finally(() => {
            submitButton.classList.remove('fls_loading');
            submitButton.textContent = previous;
            submitButton.disabled = false;
        });
    });
}

/* --------------------------------------------------------------- the lockout help */

/**
 * The wp-config line that lifts a second factor, shown only after a wait.
 *
 * Offering it the moment the challenge appears would teach every user that the way past
 * a second factor is to edit a file. The delay is the whole point of the feature, so the
 * server sets it and this only honours it.
 */
function initLockoutHelp() {
    const help = byId('fls_lockout_help');

    if (!help || !claim(help)) {
        return;
    }

    const delay = parseInt(help.dataset.flsDelay, 10);

    window.setTimeout(() => {
        help.style.display = '';
    }, isNaN(delay) ? 0 : delay);
}

/* ------------------------------------------------------------------- the challenge */

/**
 * Everything that has to run again when a form is swapped in after load. Safe to call
 * as often as the page likes: each initialiser claims its own root element and returns
 * early once it has wired it.
 */
function initChallenge() {
    const form = byId('fls_2fa_form');

    if (form && claim(form)) {
        form.addEventListener('submit', (event) => {
            event.preventDefault();
            submitForm(form, 'fls_2fa_confirm', 'fluent_auth_2fa_verify');
        });
    }

    initPasskeyChallenge();
    initEnrollment();
    initLockoutHelp();
}

/* ------------------------------------------------------------------ the shortcodes */

function initShortcodeForms() {
    /*
     * Scoped to the shortcode's own wrapper, and deliberately so. This file is loaded on
     * wp-login.php too, where `loginform` is core's real login form - binding to it there
     * would quietly turn every sign in on the site into an admin-ajax POST to a handler
     * meant only for the shortcode, which refuses outright when the front end forms are
     * switched off.
     */
    const loginForm = document.querySelector('#fls_login_form #loginform');
    const registrationForm = byId('flsRegistrationForm');
    const resetPasswordForm = byId('flsResetPasswordForm');

    if (loginForm && claim(loginForm)) {
        const i18n = config().i18n || {};
        const login = loginForm.querySelector('#user_login');
        const password = loginForm.querySelector('#user_pass');

        if (login && i18n.Username_or_Email) {
            login.placeholder = i18n.Username_or_Email;
        }

        if (password && i18n.Password) {
            password.placeholder = i18n.Password;
        }

        loginForm.addEventListener('submit', (event) => {
            event.preventDefault();
            submitForm(loginForm, 'wp-submit', 'fluent_auth_login');
        });
    }

    if (registrationForm && claim(registrationForm)) {
        registrationForm.addEventListener('submit', (event) => {
            event.preventDefault();

            const verifyBtn = byId('fls_verification_submit');
            toggleLoading(verifyBtn);

            submitForm(registrationForm, 'fls_submit', 'fluent_auth_signup', (response) => {
                toggleLoading(verifyBtn);

                if (!response.verifcation_html) {
                    handleSuccess(response, registrationForm);
                    return;
                }

                const el = document.createElement('div');
                el.innerHTML = response.verifcation_html;
                registrationForm.appendChild(el);

                registrationForm.querySelectorAll('.fls_registration_fields')
                    .forEach((fields) => {
                        fields.style.display = 'none';
                    });
            }, () => toggleLoading(verifyBtn));
        });
    }

    if (resetPasswordForm && claim(resetPasswordForm)) {
        resetPasswordForm.addEventListener('submit', (event) => {
            event.preventDefault();
            submitForm(resetPasswordForm, 'fls_reset_pass', 'fluent_auth_rp');
        });
    }

    const toggles = {
        fls_show_signup: '.fls_registration_wrapper',
        fls_show_reset_password: '.fls_reset_pass_wrapper',
        fls_show_login: '.fls_login_wrapper'
    };

    Object.keys(toggles).forEach((id) => {
        const trigger = byId(id);

        if (!trigger || !claim(trigger)) {
            return;
        }

        trigger.addEventListener('click', function (event) {
            event.preventDefault();
            this.parentNode.parentNode.classList.toggle('hide');
            document.querySelector(toggles[id]).classList.toggle('hide');
        });
    });
}

/* ------------------------------------------------------------------------- startup */

/**
 * The order here is the order the alternatives appear under the password form, which is
 * the whole reason these share a file.
 */
function start() {
    initShortcodeForms();
    initChallenge();

    const passkeyButtonShowing = initPasskeyLogin();

    initMagicLogin(passkeyButtonShowing);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
} else {
    start();
}
