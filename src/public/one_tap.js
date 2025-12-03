document.addEventListener('DOMContentLoaded', function () {
    if (typeof window.fluentOneTapConfig === 'undefined') {
        return;
    }

    const config = window.fluentOneTapConfig;

    function handleCredentialResponse(response) {
        // send ajax request to the server with the credential
        const xhr = new XMLHttpRequest();
        xhr.open('POST', config.ajax_url, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        xhr.onreadystatechange = function () {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                if (xhr.status === 200) {
                    const res = JSON.parse(xhr.responseText);
                    window.location.href = res.redirect_url || window.location.href;
                } else {
                    let message = 'An error occurred during the login process. Please try again.';
                    const res = JSON.parse(xhr.responseText);
                    if (res && res.message) {
                        message = res.message;
                    }
                    alert(message);
                }
            }
        };

        const params = new URLSearchParams();
        params.append('action', 'fluent_security_google_one_tap_login');
        params.append('mode', config.mode);
        params.append('current_url', window.location.href);
        params.append('credential', response.credential);
        xhr.send(params.toString());
    }

    const dataConfig = {
        client_id: config.client_id,
        callback: handleCredentialResponse
    };

    window.google.accounts.id.initialize(dataConfig);

    if (config.mode === 'global') {
        window.google.accounts.id.prompt();
    }

    let buttonWrappers = document.querySelectorAll('.fs_auth_google_wrapper');

    if (buttonWrappers.length) {
        buttonWrappers.forEach(function (wrapper) {
            // Create a container for the button if it doesn't exist
            // wrapper.innerHTML = ''; // Clear any existing button
            window.google.accounts.id.renderButton(
                wrapper,
                {
                    theme: 'outline',
                    size: 'large',
                    text: 'continue_with',
                    type: 'standard',
                    shape: 'rectangular'
                }  // customization attributes
            );
        });
    }

});
