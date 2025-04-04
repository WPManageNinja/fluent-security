require('./magic_url.scss');

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginform');

    const initialWrapper = document.querySelector('.fls_magic_initial');
    const magicFormWrapper = document.querySelector('.fls_magic_login_form');

    const magicBtnShow = document.querySelector('.fls_magic_show_btn');

    if(loginForm) {
        loginForm.appendChild(document.getElementById('fls_magic_login'));
        loginForm.addEventListener('submit', function(e) {
            if (this.classList.contains('showing_magic_form')) {
                e.preventDefault();
                return false;
            }
        });

        if(window.fls_magic_login_vars.is_primary) {
            initialWrapper.style.display = 'none';
            magicFormWrapper.style.display = 'block';
            loginForm.classList.add('showing_magic_form');
        }
    }

    document.getElementById('fls_magic_login').style.display = 'block';

    if(magicBtnShow) {
        magicBtnShow.addEventListener('click', function(e) {
            e.preventDefault();
            initialWrapper.style.display = 'none';
            magicFormWrapper.style.display = 'block';
            loginForm.classList.add('showing_magic_form');
        });
    }

    const magicShowRegular = document.querySelector('.fls_magic_show_regular');

    if(magicShowRegular) {
        magicShowRegular.addEventListener('click', function(e) {
            e.preventDefault();
            initialWrapper.style.display = 'block';
            magicFormWrapper.style.display = 'none';
            loginForm.classList.remove('showing_magic_form');

            const passWordField = document.getElementById('user_pass');
            if (passWordField) {
                passWordField.disabled = false;
            }
        });
    }

    document.getElementById('fls_magic_logon').addEventListener('keyup', function(e) {
        if (e.keyCode === 13) {
            e.preventDefault();
            return false;
        }
    });

    function setSuccess(data) {
        let html = '<div class="login_magic_success">';
        html += '<div class="login_success_icon"><img src="' + window.fls_magic_login_vars.success_icon + '" /></div>';
        html += '<div class="login_success_heading"><h3>' + data.heading + '</h3></div>';
        html += '<div class="login_success_message"><p>' + data.message + '</p></div>';
        html += '</div>';
        magicFormWrapper.innerHTML = html;
    }


    function showAjaxLoading() {
        const submitbtn = document.getElementById('fls_magic_submit');
        submitbtn.dataset.prevText = submitbtn.textContent;
        submitbtn.classList.add('fls_loading');
        submitbtn.innerHTML = window.fls_magic_login_vars.wait_text;
        submitbtn.disabled = true;
    }

    function removeAjaxLoading() {
        const submitbtn = document.getElementById('fls_magic_submit');
        if(submitbtn) {
            submitbtn.innerHTML = submitbtn.dataset.prevText;
            submitbtn.disabled = false;
        }
    }

    document.getElementById('fls_magic_submit').addEventListener('click', function(e) {
        e.preventDefault();
        const loginValue = document.getElementById('fls_magic_logon').value;
        if (!loginValue) {
            alert(window.fls_magic_login_vars.empty_text);
            return;
        }
        showAjaxLoading();

        let redirectTo = '';

        if(loginForm) {
            redirectTo = document.querySelector('#loginform').querySelector('input[name=redirect_to]').value;
        }
        if (!redirectTo && document.querySelector('#fls_magic_login') && document.querySelector('#fls_magic_login').querySelector('input[name=redirect_to]')) {
            redirectTo = document.querySelector('#fls_magic_login').querySelector('input[name=redirect_to]').value;
        }

        const data = new FormData;
        data.append('action', 'fls_magic_send_magic_email');
        data.append('email', loginValue);
        data.append('redirect_to', redirectTo);
        data.append('_nonce', document.getElementById('fls_magic_logon_nonce').value);

        const request = new XMLHttpRequest();

        request.open('POST', window.fls_magic_login_vars.ajaxurl, true);
        request.responseType = 'json';

        request.onload = function () {
            console.log(this.response);
            if (this.status === 200) {
                setSuccess(this.response);
            } else {
                alert(this.response.message);
            }

            removeAjaxLoading();
        };
        request.send(data);
    });

});
