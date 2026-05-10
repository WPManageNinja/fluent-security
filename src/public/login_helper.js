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

    function initPasswordReveal() {
        const wrappers = document.querySelectorAll('.fls_login_wrapper .fls_password_wrap, .fls_registration_wrapper .fls_password_wrap, .fls_auth_wrapper .fls_password_wrap');

        wrappers.forEach((wrapper) => {
            const input = wrapper.querySelector('input[type="password"], input[type="text"]');
            const button = wrapper.querySelector('.fls_password_toggle');

            if (!input || !button || button.dataset.flsPasswordToggleBound === 'yes') {
                return;
            }

            button.dataset.flsPasswordToggleBound = 'yes';

            button.addEventListener('click', () => {
                const shouldShow = input.type === 'password';
                input.type = shouldShow ? 'text' : 'password';
                button.setAttribute('aria-pressed', shouldShow ? 'true' : 'false');
                button.setAttribute('aria-label', shouldShow ? button.dataset.hideLabel : button.dataset.showLabel);
                button.classList.toggle('is-visible', shouldShow);
            });

            const form = wrapper.closest('form');
            if (form) {
                form.addEventListener('submit', () => {
                    input.type = 'password';
                    button.setAttribute('aria-pressed', 'false');
                    button.setAttribute('aria-label', button.dataset.showLabel);
                    button.classList.remove('is-visible');
                });
            }
        });
    }

    initPasswordReveal();


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
                handleFormSubmission(twoFaForm, 'fls_2fa_confirm', 'fluent_auth_2fa_email');
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

        form.querySelectorAll('.error.text-danger').forEach(e => {
            const fieldGroup = e.closest('.fls_field_group');
            if (fieldGroup) {
                fieldGroup.classList.remove('is-error');
            }
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
                const response = this.response || {};
                const hasFieldErrors = response.errors && renderFieldErrors(response.errors, form);
                let genericError = response.error;

                if (!genericError && !hasFieldErrors && response.message) {
                    genericError = response.message;
                } else if (genericError && response.data && response.data.status === 403) {
                    genericError = response.message;
                }

                if (genericError) {
                    renderFormError(genericError, form);
                }

                if(errorCallback) {
                    errorCallback(response);
                }
            }
        };

        request.send(data);
    }

    function renderFieldErrors(errors, form) {
        let hasRenderedError = false;

        Object.keys(errors).forEach((property) => {
            const field = getFieldByErrorKey(property, form);

            if (!field) {
                return;
            }

            let el = document.createElement("div");
            el.classList.add('error', 'text-danger');
            el.innerHTML = getErrorMessage(errors[property]);

            const inputWrap = field.closest('.fs_input_wrap') || field.parentNode;
            inputWrap.parentNode.insertBefore(el, inputWrap.nextSibling);

            const fieldGroup = field.closest('.fls_field_group');
            if (fieldGroup) {
                fieldGroup.classList.add('is-error');
            }

            hasRenderedError = true;
        });

        return hasRenderedError;
    }

    function getFieldByErrorKey(property, form) {
        const fieldIds = {
            first_name: 'fls_first_name',
            last_name: 'fls_last_name',
            username: 'fls_reg_username',
            email: 'fls_reg_email',
            password: 'fls_reg_password',
            user_login: 'fls_email',
        };

        return form.querySelector('#' + (fieldIds[property] || 'flt_' + property));
    }

    function getErrorMessage(error) {
        if (Array.isArray(error)) {
            return error[0];
        }

        if (error && typeof error === 'object') {
            return Object.values(error)[0];
        }

        return error;
    }

    function renderFormError(message, form) {
        let el = document.createElement("div");
        el.classList.add('error', 'text-danger');
        el.innerHTML = message;
        form.appendChild(el);
    }

    function handleSuccess(response, form) {
        if (response.load_2fa) {
            document.getElementById('fls_login_form').innerHTML = response.two_fa_form;
            setTimeout(() => {
                init2FaForm();
                initPasswordReveal();
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
