require('./login_helper.scss');
document.addEventListener('DOMContentLoaded', () => {
    const registrationForm = document.getElementById('flsRegistrationForm');
    const resetPasswordForm = document.getElementById('flsResetPasswordForm');
    const loginForm = document.getElementById('loginform');


    function setPlaceHolders() {
        const userNameField = document.getElementById('user_login');
        if (userNameField) {
            userNameField.placeholder = window.fluentAuthPublic.i18n.Username_or_Email;
        }

        const userPassField = document.getElementById('user_pass');
        if (userPassField) {
            userPassField.placeholder = window.fluentAuthPublic.i18n.Password;
        }
    }

    setPlaceHolders();


    function toggleLoading(submitBtn) {
        if(submitBtn) {
            submitBtn.classList.toggle('fls_loading');
            submitBtn.disabled = !submitBtn.disabled;
        }
    }

    if (registrationForm) {
        registrationForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const submitBtn = document.getElementById('fls_verification_submit');
            toggleLoading(submitBtn);

            handleFormSubmission(registrationForm, 'fls_submit', 'fluent_auth_signup', function (response) {
                toggleLoading(submitBtn);
                if (response.verifcation_html) {
                    let html = response.verifcation_html;

                    // append html to registrationForm dom
                    let el = document.createElement("div");
                    el.innerHTML = html;
                    registrationForm.appendChild(el);

                    let regFields = registrationForm.getElementsByClassName('fls_registration_fields');
                    // hide regFields with css hidden inline css
                    for (let i = 0; i < regFields.length; i++) {
                        regFields[i].style.display = 'none';
                    }
                } else {
                    handleSuccess(response, registrationForm);
                }
            }, function (errors) {
                toggleLoading(submitBtn);
            });
        });
    }

    if (resetPasswordForm) {
        resetPasswordForm.addEventListener('submit', (event) => {
            event.preventDefault();
            handleFormSubmission(resetPasswordForm, 'fls_reset_pass', 'fluent_auth_rp');
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', (event) => {
            event.preventDefault();
            handleFormSubmission(loginForm, 'wp-submit', 'fluent_auth_login');
        });
    }

    function init2FaForm() {
        const twoFaForm = document.getElementById('fls_2fa_form');
        if (twoFaForm) {
            twoFaForm.addEventListener('submit', (event) => {
                event.preventDefault();
                handleFormSubmission(twoFaForm, 'fls_2fa_confirm', 'fluent_auth_2fa_verify');
            });
        }
    }

    init2FaForm();

    if (document.getElementById('fls_show_signup')) {
        document.getElementById('fls_show_signup').addEventListener('click', function (event) {
            fsToggleForms(event, this, '.fls_registration_wrapper');
        });
    }

    if (document.getElementById('fls_show_reset_password')) {
        document.getElementById('fls_show_reset_password').addEventListener('click', function (event) {
            fsToggleForms(event, this, '.fls_reset_pass_wrapper');
        });
    }

    if (document.getElementById('fls_show_login')) {
        document.getElementById('fls_show_login').addEventListener('click', function (event) {
            fsToggleForms(event, this, '.fls_login_wrapper');
        });
    }

    function handleFormSubmission(form, submitBtnId, action, callback, errorCallback) {
        const submitBtn = document.getElementById(submitBtnId);
        toggleLoading(submitBtn);

        document.querySelectorAll('.error.text-danger').forEach(e => {
            e.parentNode.parentNode.classList.remove('is-error');
            e.remove();
        });

        const data = new FormData(form);

        data.append('action', action);
        data.append('_nonce', window.fluentAuthPublic.fls_login_nonce);
        data.append('_is_fls_form', 'yes');

        const request = new XMLHttpRequest();

        const reqUrl = window.fluentAuthPublic.ajax_url;

        request.open('POST', reqUrl, true);
        request.responseType = 'json';

        request.onload = function () {
            toggleLoading(submitBtn);
            if (this.status === 200) {
                if (callback) {
                    callback(this.response);
                    return;
                }
                handleSuccess(this.response, form);
            } else {
                let genericError = this.response.error;
                if (!genericError && this.response.message) {
                    genericError = this.response.message;
                } else if (genericError && this.response.data.status === 403) {
                    genericError = this.response.message;
                }

                if (genericError) {
                    let el = document.createElement("div");
                    el.classList.add('error', 'text-danger');
                    el.innerHTML = genericError;
                    form.appendChild(el);
                } else {
                    for (const property in this.response) {
                        const field = document.getElementById('flt_' + property);
                        if (field) {
                            let el = document.createElement("div");
                            el.classList.add('error', 'text-danger');
                            el.innerHTML = Object.values(this.response[property])[0];
                            field.parentNode.insertBefore(el, field.nextSibling);
                            field.parentNode.parentNode.classList.add('is-error');
                        }
                    }
                }

                if(errorCallback) {
                    errorCallback(this.response);
                }
            }
        };

        request.send(data);
    }

    /*
     * Recovery codes are shown once and never again, so this stops on the way out
     * rather than following response.redirect straight past them. The continue button
     * carries the redirect, so leaving is still one click - it just has to be a click.
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
            document.getElementById('fls_login_form').innerHTML = response.two_fa_form;
            setTimeout(() => {
                init2FaForm();
            }, 200);
        } else if (response.redirect) {
            window.location.href = response.redirect;
            return;
        } else if (response.message) {
            let el = document.createElement("div");
            el.classList.add('success', 'text-success', 'fls-text-success');
            el.innerHTML = response.message;
            form.appendChild(el);
            form.reset();
        } else {
            window.location.reload();
            return;
        }
    }

    function fsToggleForms(event, that, target) {
        event.preventDefault();
        that.parentNode.parentNode.classList.toggle('hide');
        document.querySelector(target).classList.toggle('hide');
    }
});
