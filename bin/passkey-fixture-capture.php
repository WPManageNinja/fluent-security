<?php
/**
 * Plugin Name: FluentAuth passkey fixture capture
 * Description: Development only. Records what a real authenticator emits, so the
 *              WebAuthn verification tests can run against devices rather than against
 *              bytes this codebase generated for itself.
 *
 * Drop into wp-content/mu-plugins/ on an https development site, visit
 * Tools -> Passkey capture, run both ceremonies and save the JSON it prints into
 * tests/fixtures/webauthn/. Remove the file afterwards - it deliberately performs
 * ceremonies without storing anything, which is useful for capture and useless as a
 * security feature.
 */

defined('ABSPATH') or die;

add_action('admin_menu', function () {
    add_management_page(
        'Passkey capture',
        'Passkey capture',
        'manage_options',
        'fls-passkey-capture',
        'fls_passkey_capture_page'
    );
});

function fls_passkey_capture_page()
{
    if (!current_user_can('manage_options')) {
        return;
    }

    $rpId = wp_parse_url(home_url(), PHP_URL_HOST);
    $nonce = wp_create_nonce('fls_passkey_capture');
    ?>
    <div class="wrap">
        <h1>Passkey capture</h1>
        <p>
            Relying party: <code><?php echo esc_html($rpId); ?></code> &middot;
            Origin: <code><?php echo esc_html(home_url()); ?></code>
        </p>
        <p>
            Run <strong>Register</strong> first, then <strong>Authenticate</strong> with the same
            device. Give the result a label that names the authenticator and browser, then save it
            into <code>tests/fixtures/webauthn/</code>.
        </p>

        <p>
            <label>Label <input type="text" id="fls-label" class="regular-text"
                                placeholder="macOS Touch ID, Safari 18"/></label>
        </p>

        <p>
            <button class="button button-primary" id="fls-register">1. Register</button>
            <button class="button" id="fls-authenticate" disabled>2. Authenticate</button>
            <button class="button" id="fls-copy" disabled>Copy JSON</button>
        </p>

        <textarea id="fls-output" rows="22" style="width:100%;font-family:monospace;font-size:12px;"></textarea>
    </div>

    <script>
        (function () {
            var rpId = <?php echo wp_json_encode($rpId); ?>;
            var origin = window.location.origin;
            var nonce = <?php echo wp_json_encode($nonce); ?>;
            var userId = <?php echo (int)get_current_user_id(); ?>;
            var captured = {label: '', rpId: rpId, origin: origin, userVerification: 'required'};

            function toBuffer(value) {
                var s = String(value).replace(/-/g, '+').replace(/_/g, '/');
                var pad = s.length % 4;
                if (pad) { s += new Array(5 - pad).join('='); }
                var bin = window.atob(s), out = new Uint8Array(bin.length);
                for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
                return out;
            }

            function toB64u(buffer) {
                var bytes = new Uint8Array(buffer), bin = '';
                for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
                return window.btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            }

            function randomChallenge() {
                var bytes = new Uint8Array(32);
                window.crypto.getRandomValues(bytes);
                return bytes;
            }

            function render() {
                captured.label = document.getElementById('fls-label').value || 'unnamed authenticator';
                document.getElementById('fls-output').value = JSON.stringify(captured, null, 2);
            }

            var userHandle = toBuffer(nonce.slice(0, 22) + 'AA');

            document.getElementById('fls-register').addEventListener('click', function () {
                var challenge = randomChallenge();

                navigator.credentials.create({
                    publicKey: {
                        challenge: challenge,
                        rp: {id: rpId, name: 'Fixture capture'},
                        user: {id: userHandle, name: 'fixture-' + userId, displayName: 'Fixture'},
                        pubKeyCredParams: [{type: 'public-key', alg: -7}, {type: 'public-key', alg: -257}],
                        attestation: 'none',
                        timeout: 120000,
                        authenticatorSelection: {residentKey: 'preferred', userVerification: 'required'}
                    }
                }).then(function (credential) {
                    captured.userHandle = toB64u(userHandle);
                    captured.transports = credential.response.getTransports
                        ? credential.response.getTransports() : [];
                    captured.registration = {
                        challenge: toB64u(challenge),
                        response: {
                            rawId: toB64u(credential.rawId),
                            clientDataJSON: toB64u(credential.response.clientDataJSON),
                            attestationObject: toB64u(credential.response.attestationObject)
                        }
                    };
                    document.getElementById('fls-authenticate').disabled = false;
                    render();
                }).catch(function (error) {
                    window.alert(error);
                });
            });

            document.getElementById('fls-authenticate').addEventListener('click', function () {
                var challenge = randomChallenge();

                navigator.credentials.get({
                    publicKey: {
                        challenge: challenge,
                        rpId: rpId,
                        timeout: 120000,
                        userVerification: 'required',
                        allowCredentials: [{
                            type: 'public-key',
                            id: toBuffer(captured.registration.response.rawId)
                        }]
                    }
                }).then(function (credential) {
                    captured.assertion = {
                        challenge: toB64u(challenge),
                        response: {
                            rawId: toB64u(credential.rawId),
                            clientDataJSON: toB64u(credential.response.clientDataJSON),
                            authenticatorData: toB64u(credential.response.authenticatorData),
                            signature: toB64u(credential.response.signature),
                            userHandle: credential.response.userHandle
                                ? toB64u(credential.response.userHandle) : ''
                        }
                    };
                    document.getElementById('fls-copy').disabled = false;
                    render();
                }).catch(function (error) {
                    window.alert(error);
                });
            });

            document.getElementById('fls-copy').addEventListener('click', function () {
                render();
                document.getElementById('fls-output').select();
                document.execCommand('copy');
            });

            document.getElementById('fls-label').addEventListener('input', render);
        })();
    </script>
    <?php
}
